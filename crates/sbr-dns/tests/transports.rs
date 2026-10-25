//! Transports against real servers running in-process: UDP and TCP built
//! from hickory-proto, DoT over tokio-rustls, DoH on hyper (HTTP/2), all
//! with a self-signed certificate.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use http_body_util::{BodyExt, Full};
use sbr_config::Options;
use sbr_core::dns::Dns;
use sbr_core::router::RuleSets;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Metadata, Network, Outbound, PacketConn, Stream};
use sbr_dns::{DnsRouter, msg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// What the test server saw.
#[derive(Default)]
struct Stats {
    queries: AtomicUsize,
    tcp_conns: AtomicUsize,
}

/// `<n>.test` → 10.0.0.<n>; `big.test` → 60 records; `slow.test` answers
/// after 300 ms; `ttl1.test` has TTL 1; everything else NXDOMAIN.
async fn answer(req: &Message, stats: &Stats) -> Message {
    stats.queries.fetch_add(1, Ordering::SeqCst);
    let q = &req.queries[0];
    let name = q.name().to_ascii().to_ascii_lowercase();
    let mut m = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
    m.metadata.recursion_available = true;
    m.queries = req.queries.clone();
    let a = |ip: [u8; 4], ttl| Record::from_rdata(q.name().clone(), ttl, RData::A(A(ip.into())));
    if u16::from(q.query_type()) != 1 {
        return m;
    }
    match name.as_str() {
        "big.test." => {
            for i in 0..60 {
                m.add_answer(a([10, 1, 0, i], 300));
            }
        }
        "slow.test." => {
            tokio::time::sleep(Duration::from_millis(300)).await;
            m.add_answer(a([10, 2, 0, 1], 300));
        }
        "ttl1.test." => {
            m.add_answer(a([10, 3, 0, stats.queries.load(Ordering::SeqCst) as u8], 1));
        }
        n => match n.strip_suffix(".test.").and_then(|n| n.parse::<u8>().ok()) {
            Some(i) => {
                m.add_answer(a([10, 0, 0, i], 300));
            }
            None => m.metadata.response_code = hickory_proto::op::ResponseCode::NXDomain,
        },
    }
    m
}

async fn udp_server(stats: Arc<Stats>) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            let req = Message::from_vec(&buf[..n]).unwrap();
            let (sock, stats) = (sock.clone(), stats.clone());
            tokio::spawn(async move {
                let mut resp = answer(&req, &stats).await;
                let mut raw = resp.to_vec().unwrap();
                if raw.len() > 512 {
                    resp.answers.clear();
                    resp.metadata.truncation = true;
                    raw = resp.to_vec().unwrap();
                }
                sock.send_to(&raw, from).await.unwrap();
            });
        }
    });
    addr
}

/// Length-prefixed DNS on any stream; answers concurrently and out of order.
async fn serve_stream<S: AsyncRead + AsyncWrite + Send + 'static>(s: S, stats: Arc<Stats>) {
    stats.tcp_conns.fetch_add(1, Ordering::SeqCst);
    let (mut r, w) = tokio::io::split(s);
    let w = Arc::new(tokio::sync::Mutex::new(w));
    loop {
        let Ok(len) = r.read_u16().await else { return };
        let mut buf = vec![0u8; len as usize];
        if r.read_exact(&mut buf).await.is_err() {
            return;
        }
        let req = Message::from_vec(&buf).unwrap();
        let (w, stats) = (w.clone(), stats.clone());
        tokio::spawn(async move {
            let raw = answer(&req, &stats).await.to_vec().unwrap();
            let mut out = (raw.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&raw);
            let _ = w.lock().await.write_all(&out).await;
        });
    }
}

async fn tcp_server(stats: Arc<Stats>, tls: Option<tokio_rustls::TlsAcceptor>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let (stats, tls) = (stats.clone(), tls.clone());
            tokio::spawn(async move {
                match tls {
                    Some(t) => serve_stream(t.accept(s).await.unwrap(), stats).await,
                    None => serve_stream(s, stats).await,
                }
            });
        }
    });
    addr
}

struct Cert {
    pem: String,
    acceptor: tokio_rustls::TlsAcceptor,
}

fn cert(alpn: &[&str]) -> Cert {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into(), "dns.test".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![ck.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into()),
        )
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Cert {
        pem: ck.cert.pem(),
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(cfg)),
    }
}

async fn doh_server(stats: Arc<Stats>, acceptor: tokio_rustls::TlsAcceptor) -> SocketAddr {
    use hyper::service::service_fn;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let (stats, acceptor) = (stats.clone(), acceptor.clone());
            tokio::spawn(async move {
                stats.tcp_conns.fetch_add(1, Ordering::SeqCst);
                let tls = acceptor.accept(s).await.unwrap();
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let stats = stats.clone();
                    async move {
                        assert_eq!(req.uri().path(), "/dns-query");
                        let raw = if req.method() == hyper::Method::GET {
                            let q = req.uri().query().unwrap().strip_prefix("dns=").unwrap().to_owned();
                            use base64::Engine;
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(q).unwrap()
                        } else {
                            assert_eq!(req.headers()["content-type"], "application/dns-message");
                            req.into_body().collect().await.unwrap().to_bytes().to_vec()
                        };
                        let m = Message::from_vec(&raw).unwrap();
                        assert_eq!(m.metadata.id, 0, "RFC 8484: ID 0");
                        let resp = answer(&m, &stats).await.to_vec().unwrap();
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .header("content-type", "application/dns-message")
                                .body(Full::new(Bytes::from(resp)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    addr
}

/// A minimal direct dialer, standing in for the engine's outbounds.
struct Direct;

struct Udp(UdpSocket);

impl PacketConn for Udp {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send_to(buf, dest.socket_addr().unwrap()).await.map(|_| ()) })
    }
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(async move {
            let (n, a) = self.0.recv_from(buf).await?;
            Ok((n, a.into()))
        })
    }
}

impl Outbound for Direct {
    fn tag(&self) -> &str {
        "direct"
    }
    fn kind(&self) -> &'static str {
        "direct"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move { Ok(Box::new(TcpStream::connect(dest.socket_addr().unwrap()).await?) as Stream) })
    }
    fn connect_udp<'a>(&'a self, _: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move { Ok(Box::new(Udp(UdpSocket::bind("127.0.0.1:0").await?)) as BoxPacketConn) })
    }
}

fn router(dns: &str) -> DnsRouter {
    let o = Options::parse(&format!(r#"{{"dns":{dns}}}"#)).unwrap();
    DnsRouter::new(
        o.dns.as_ref().unwrap(),
        &RuleSets::default(),
        &|_| Arc::new(Direct),
        &|p| std::fs::read(p),
    )
    .unwrap()
}

fn meta(network: Network) -> Metadata {
    Metadata::new(
        "in".into(),
        "test",
        network,
        "127.0.0.1:1".parse().unwrap(),
        "127.0.0.1:53".parse::<SocketAddr>().unwrap().into(),
    )
}

async fn ask(r: &DnsRouter, name: &str, network: Network) -> Message {
    let q = msg::encode(&msg::query(name, 1).unwrap()).unwrap();
    msg::decode(&r.exchange(&q, &meta(network)).await.unwrap()).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn udp_with_tcp_fallback_on_truncation() {
    let stats = Arc::new(Stats::default());
    let addr = udp_server(stats.clone()).await;
    // The TCP fallback goes to the same address and port.
    let tl = TcpListener::bind(addr).await.unwrap();
    let tstats = stats.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = tl.accept().await.unwrap();
            tokio::spawn(serve_stream(s, tstats.clone()));
        }
    });
    let r = router(&format!(
        r#"{{"servers":[{{"type":"udp","server":"127.0.0.1","server_port":{}}}]}}"#,
        addr.port()
    ));
    assert_eq!(r.lookup("7.test", None).await.unwrap(), [ip("10.0.0.7")]);
    let m = ask(&r, "big.test", Network::Tcp).await;
    assert_eq!(m.answers.len(), 60, "truncated UDP answer retried over TCP");
    assert_eq!(stats.tcp_conns.load(Ordering::SeqCst), 1);
    // Answering a UDP client, the router itself truncates to 512 bytes.
    let m = ask(&r, "big.test", Network::Udp).await;
    assert!(m.metadata.truncation);
    assert!(msg::encode(&m).unwrap().len() <= 512);
    let m = ask(&r, "nope.example", Network::Udp).await;
    assert_eq!(msg::rcode(&m), 3);
}

#[tokio::test]
async fn tcp_pipelines_on_one_connection() {
    let stats = Arc::new(Stats::default());
    let addr = tcp_server(stats.clone(), None).await;
    let r = router(&format!(
        r#"{{"servers":[{{"type":"tcp","server":"127.0.0.1","server_port":{}}}]}}"#,
        addr.port()
    ));
    // Warm the connection, then fire 20 queries at once.
    assert_eq!(r.lookup("1.test", None).await.unwrap(), [ip("10.0.0.1")]);
    let all = futures_join(&r, 2..22).await;
    for (i, got) in (2..22).zip(all) {
        assert_eq!(got, [IpAddr::from([10, 0, 0, i])]);
    }
    assert_eq!(stats.tcp_conns.load(Ordering::SeqCst), 1, "pipelined on one connection");
}

async fn futures_join(r: &DnsRouter, range: std::ops::Range<u8>) -> Vec<Vec<IpAddr>> {
    let mut set = tokio::task::JoinSet::new();
    for i in range.clone() {
        let r = r.clone();
        set.spawn(async move { (i, r.lookup(&format!("{i}.test"), None).await.unwrap()) });
    }
    let mut out = set.join_all().await;
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, v)| v).collect()
}

#[tokio::test]
async fn coalescing_cache_and_expiry() {
    let stats = Arc::new(Stats::default());
    let addr = udp_server(stats.clone()).await;
    let r = router(&format!(
        r#"{{"servers":[{{"type":"udp","server":"127.0.0.1","server_port":{}}}],"strategy":"ipv4_only"}}"#,
        addr.port()
    ));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let r = r.clone();
        set.spawn(async move { r.lookup("slow.test", None).await.unwrap() });
    }
    for got in set.join_all().await {
        assert_eq!(got, [ip("10.2.0.1")]);
    }
    assert_eq!(
        stats.queries.load(Ordering::SeqCst),
        1,
        "16 lookups, one upstream query"
    );
    assert_eq!(r.lookup("slow.test", None).await.unwrap(), [ip("10.2.0.1")]);
    let m = ask(&r, "slow.test", Network::Udp).await;
    assert!(m.answers[0].ttl <= 300 && m.answers[0].ttl > 290, "TTL counts down");
    assert_eq!(stats.queries.load(Ordering::SeqCst), 1, "cache hits");

    r.lookup("ttl1.test", None).await.unwrap();
    r.lookup("ttl1.test", None).await.unwrap();
    assert_eq!(stats.queries.load(Ordering::SeqCst), 2);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    r.lookup("ttl1.test", None).await.unwrap();
    assert_eq!(stats.queries.load(Ordering::SeqCst), 3, "expired entry refetched");
}

#[tokio::test]
async fn optimistic_serves_stale_and_refreshes() {
    let stats = Arc::new(Stats::default());
    let addr = udp_server(stats.clone()).await;
    let r = router(&format!(
        r#"{{"servers":[{{"type":"udp","server":"127.0.0.1","server_port":{}}}],"strategy":"ipv4_only","optimistic":true}}"#,
        addr.port()
    ));
    let first = r.lookup("ttl1.test", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let stale = r.lookup("ttl1.test", None).await.unwrap();
    assert_eq!(stale, first, "expired entry served as is");
    for _ in 0..50 {
        if stats.queries.load(Ordering::SeqCst) == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(stats.queries.load(Ordering::SeqCst), 2, "refreshed in the background");
    let fresh = r.lookup("ttl1.test", None).await.unwrap();
    assert_ne!(fresh, first);
}

#[tokio::test]
async fn dns_over_tls() {
    let stats = Arc::new(Stats::default());
    let c = cert(&[]);
    let addr = tcp_server(stats.clone(), Some(c.acceptor)).await;
    let r = router(&format!(
        r#"{{"servers":[{{"type":"tls","server":"127.0.0.1","server_port":{},
             "tls":{{"server_name":"dns.test","certificate":{}}}}}]}}"#,
        addr.port(),
        serde_json::to_string(&c.pem).unwrap()
    ));
    let all = futures_join(&r, 1..9).await;
    assert_eq!(all[0], [ip("10.0.0.1")]);
    assert_eq!(all[7], [ip("10.0.0.8")]);

    // The wrong name fails verification.
    let bad = router(&format!(
        r#"{{"servers":[{{"type":"tls","server":"127.0.0.1","server_port":{},
             "tls":{{"server_name":"other.test","certificate":{}}}}}]}}"#,
        addr.port(),
        serde_json::to_string(&c.pem).unwrap()
    ));
    assert!(bad.lookup("1.test", None).await.is_err());
    let insecure = router(&format!(
        r#"{{"servers":[{{"type":"tls","server":"127.0.0.1","server_port":{},"tls":{{"insecure":true}}}}]}}"#,
        addr.port()
    ));
    assert_eq!(insecure.lookup("3.test", None).await.unwrap(), [ip("10.0.0.3")]);
}

#[tokio::test]
async fn dns_over_https_post_get_and_domain_resolver() {
    let stats = Arc::new(Stats::default());
    let c = cert(&["h2"]);
    let addr = doh_server(stats.clone(), c.acceptor).await;
    let pem = serde_json::to_string(&c.pem).unwrap();
    // The DoH server is addressed by name, resolved through a hosts server.
    let r = router(&format!(
        r#"{{"servers":[
            {{"type":"https","tag":"doh","server":"localhost","server_port":{port},"domain_resolver":"hosts",
              "tls":{{"certificate":{pem}}}}},
            {{"type":"https","tag":"doh-get","server":"127.0.0.1","server_port":{port},"method":"GET",
              "tls":{{"server_name":"localhost","certificate":{pem}}}}},
            {{"type":"hosts","tag":"hosts","predefined":{{"localhost":"127.0.0.1"}}}}
        ],
        "rules":[{{"domain_suffix":"get.test","server":"doh-get"}}],
        "final":"doh","strategy":"ipv4_only"}}"#,
        port = addr.port()
    ));
    let all = futures_join(&r, 1..11).await;
    assert_eq!(all[9], [ip("10.0.0.10")]);
    assert_eq!(stats.tcp_conns.load(Ordering::SeqCst), 1, "one HTTP/2 connection");
    let m = ask(&r, "5.get.test", Network::Tcp).await;
    assert_eq!(msg::rcode(&m), 3, "GET reaches the server (NXDOMAIN for this name)");
    assert_eq!(stats.tcp_conns.load(Ordering::SeqCst), 2);
}

/// The first TLS record a server named by `dns` (with `{port}`) receives.
async fn client_hello(dns: &str) -> Vec<u8> {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let r = router(&dns.replace("{port}", &l.local_addr().unwrap().port().to_string()));
    let server = async {
        let (mut s, _) = l.accept().await.unwrap();
        let mut hdr = [0u8; 5];
        s.read_exact(&mut hdr).await.unwrap();
        let mut msg = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
        s.read_exact(&mut msg).await.unwrap();
        msg
    };
    // The lookup itself never completes usefully; only its hello matters.
    tokio::select! {
        msg = server => msg,
        _ = r.lookup("1.test", None) => panic!("lookup ended before its ClientHello arrived"),
    }
}

fn extension_types(msg: &[u8]) -> Vec<u16> {
    let b = &msg[4..];
    let mut p = 2 + 32;
    p += 1 + b[p] as usize;
    p += 2 + u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 1 + b[p] as usize;
    p += 2;
    let mut out = Vec::new();
    while p + 4 <= b.len() {
        out.push(u16::from_be_bytes([b[p], b[p + 1]]));
        p += 4 + u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
    }
    out
}

/// DoH imitates Chrome unless `utls` is disabled; DoT keeps rustls unless
/// `utls` is enabled. Chrome is recognisable by its Trust Anchor IDs
/// extension (0xca34), Firefox by record_size_limit (0x001c); rustls sends
/// neither.
#[tokio::test]
async fn doh_and_dot_client_hellos() {
    let doh = |tls: &str| {
        format!(r#"{{"servers":[{{"type":"https","server":"127.0.0.1","server_port":{{port}},"tls":{{{tls}}}}}]}}"#)
    };
    let dot = |tls: &str| {
        format!(r#"{{"servers":[{{"type":"tls","server":"127.0.0.1","server_port":{{port}},"tls":{{{tls}}}}}]}}"#)
    };
    let chrome = extension_types(&client_hello(&doh("")).await);
    assert!(chrome.contains(&0xca34), "DoH defaults to Chrome: {chrome:04x?}");
    let rustls = extension_types(&client_hello(&doh(r#""utls":{"enabled":false}"#)).await);
    assert!(!rustls.contains(&0xca34) && !rustls.contains(&0x001c), "{rustls:04x?}");
    let plain_dot = extension_types(&client_hello(&dot("")).await);
    assert!(
        !plain_dot.contains(&0xca34) && !plain_dot.contains(&0x001c),
        "{plain_dot:04x?}"
    );
    let firefox_dot = extension_types(
        &client_hello(&dot(
            r#""enabled":true,"utls":{"enabled":true,"fingerprint":"firefox"}"#,
        ))
        .await,
    );
    assert!(firefox_dot.contains(&0x001c), "{firefox_dot:04x?}");
}

#[tokio::test]
async fn fails_over_to_the_next_upstream_and_skips_the_dead_one() {
    let stats = Arc::new(Stats::default());
    let good = udp_server(stats.clone()).await;
    // A server that swallows every query, like a resolver the current path
    // can't reach.
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    let r = router(&format!(
        r#"{{"servers":[
            {{"type":"udp","tag":"dead","server":"127.0.0.1","server_port":{dead_port}}},
            {{"type":"local","tag":"local"}},
            {{"type":"udp","tag":"good","server":"127.0.0.1","server_port":{}}}
        ],"final":"dead","timeout":"20s"}}"#,
        good.port()
    ));
    let start = std::time::Instant::now();
    assert_eq!(r.lookup("7.test", None).await.unwrap(), [ip("10.0.0.7")]);
    let first = start.elapsed();
    assert!(
        first < Duration::from_secs(10),
        "fails over after the short attempt, not the 20 s timeout: {first:?}"
    );
    // The dead server is now skipped: the next query goes straight to `good`.
    let start = std::time::Instant::now();
    assert_eq!(r.lookup("8.test", None).await.unwrap(), [ip("10.0.0.8")]);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "cooling server skipped: {:?}",
        start.elapsed()
    );
    drop(dead);
}
