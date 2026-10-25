//! Failover under post-handshake blocking: a local "censor" in front of a
//! real outbound freezes, resets or black-holes flows after their handshake,
//! the way TSPU, Iran and the GFW do, and `urltest` must notice and move.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use common::{bulk_echo, echo, port, socks_connect, start};
use sbr_engine::Instance;
use sbr_engine::fetch::{HttpClient, Target};
use sbr_engine::health::{PROOF_BYTES, STALL, Verdict};
use sbr_engine::sbr_core::Destination;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PASS: u8 = 0;
const FREEZE: u8 = 1;
const RESET: u8 = 2;
const BLACKHOLE: u8 = 3;
/// Downstream bytes per flow before the censor freezes it (TSPU: ~16–20 KB).
const FREEZE_AT: usize = 16 * 1024;

/// A TCP middlebox. Its mode applies to flows opened after it is set.
struct Censor {
    port: u16,
    mode: Arc<AtomicU8>,
}

impl Censor {
    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }
}

async fn censor(upstream: u16) -> Censor {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let mode = Arc::new(AtomicU8::new(PASS));
    let m = mode.clone();
    tokio::spawn(async move {
        loop {
            let (c, _) = l.accept().await.unwrap();
            let mode = m.load(Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(s) = TcpStream::connect(("127.0.0.1", upstream)).await else {
                    return;
                };
                let _ = flow(c, s, mode).await;
            });
        }
    });
    Censor { port, mode }
}

async fn flow(mut c: TcpStream, mut s: TcpStream, mode: u8) -> std::io::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    match mode {
        PASS => {
            tokio::io::copy_bidirectional(&mut c, &mut s).await?;
        }
        FREEZE => {
            // Forward until FREEZE_AT bytes went downstream, then drop
            // everything both ways without closing anything.
            let (mut cr, mut cw) = c.into_split();
            let (mut sr, mut sw) = s.into_split();
            let frozen = Arc::new(AtomicU8::new(0));
            let f = frozen.clone();
            let up = tokio::spawn(async move {
                let mut b = vec![0u8; 16 * 1024];
                while let Ok(n) = cr.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    if f.load(Ordering::SeqCst) == 0 && sw.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
                std::future::pending::<()>().await;
                drop(sw);
            });
            let mut down = 0;
            while let Ok(n) = sr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if down < FREEZE_AT {
                    let k = n.min(FREEZE_AT - down);
                    cw.write_all(&buf[..k]).await?;
                    down += k;
                    if down == FREEZE_AT {
                        frozen.store(1, Ordering::SeqCst);
                    }
                }
            }
            std::future::pending::<()>().await;
            drop((cw, up));
        }
        _ => {
            // Let the proxy handshake through (the CONNECT and its reply).
            let n = c.read(&mut buf).await?;
            s.write_all(&buf[..n]).await?;
            let n = s.read(&mut buf).await?;
            c.write_all(&buf[..n]).await?;
            loop {
                let n = c.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                if mode == RESET {
                    #[allow(deprecated)] // Linger 0 is the point: drop sends RST.
                    c.set_linger(Some(Duration::ZERO))?;
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

/// An HTTP CONNECT proxy that waits `delay` before connecting.
async fn connect_proxy(delay: Duration) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let line = String::from_utf8_lossy(&head);
                let target = line.split(' ').nth(1).unwrap().to_owned();
                tokio::time::sleep(delay).await;
                let Ok(mut up) = TcpStream::connect(target).await else {
                    return;
                };
                if s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    port
}

/// Keep-alive HTTP server: `/big` is 256 KiB (the data probe's target).
async fn web() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let body = vec![b'x'; 256 * 1024];
                let mut pending = Vec::new();
                let mut b = [0u8; 4096];
                loop {
                    let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&b[..n]),
                        }
                        continue;
                    };
                    let head: Vec<u8> = pending.drain(..end + 4).collect();
                    let r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                    let mut out = r.into_bytes();
                    if !head.starts_with(b"HEAD") {
                        out.extend_from_slice(&body);
                    }
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// Sends sixteen 16 KiB TLS application-data records once poked.
async fn tls_records() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 1];
                if s.read(&mut b).await.unwrap_or(0) == 0 {
                    return;
                }
                for _ in 0..16 {
                    let mut rec = vec![0x17, 3, 3, 0x40, 0];
                    rec.resize(5 + 16384, 0xaa);
                    if s.write_all(&rec).await.is_err() {
                        return;
                    }
                }
                while s.read(&mut b).await.unwrap_or(0) > 0 {}
            });
        }
    });
    addr
}

/// `a`: 32 KiB now. `b`: 1 MiB now. `w`: 100 bytes after 10 s (a long poll).
async fn bursty() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 1];
                while s.read(&mut b).await.unwrap_or(0) > 0 {
                    let n = match b[0] {
                        b'a' => 32 * 1024,
                        b'b' => 1 << 20,
                        _ => {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            100
                        }
                    };
                    if s.write_all(&vec![7u8; n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn api(addr: SocketAddr, path: &str) -> Value {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    serde_json::from_str(body).unwrap_or(Value::Null)
}

async fn until<F: AsyncFn() -> bool>(limit: Duration, f: F) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f().await {
            return Some(start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Group `auto` over `a` (behind a censor, fast) and `b` (slower), probing a
/// local URL; waits until `a` is selected.
async fn setup() -> (Instance, Censor, SocketAddr) {
    let web = web().await;
    let a = censor(connect_proxy(Duration::ZERO).await).await;
    let b = connect_proxy(Duration::from_millis(150)).await;
    let cfg = format!(
        r#"{{"log":{{"level":"warn"}},
        "inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[
            {{"type":"urltest","tag":"auto","outbounds":["a","b"],"url":"http://127.0.0.1:{web}/big","interval":"10m"}},
            {{"type":"http","tag":"a","server":"127.0.0.1","server_port":{}}},
            {{"type":"http","tag":"b","server":"127.0.0.1","server_port":{b}}}],
        "experimental":{{"clash_api":{{"external_controller":"127.0.0.1:0"}}}}}}"#,
        a.port
    );
    let i = start(&cfg).await;
    let ctl = i.clash_api.unwrap();
    let ready = until(Duration::from_secs(10), async || {
        let v = api(ctl, "/proxies/auto").await;
        v["now"] == "a" && api(ctl, "/proxies/b").await["history"][0]["delay"].is_u64()
    })
    .await;
    assert!(ready.is_some(), "a selected at start");
    // Let the start-up data probes finish.
    tokio::time::sleep(Duration::from_millis(500)).await;
    (i, a, ctl)
}

async fn degraded(ctl: SocketAddr, limit: Duration) -> (Option<Duration>, Value) {
    let t = until(limit, async || api(ctl, "/proxies/a").await["degraded"] == true).await;
    (t, api(ctl, "/proxies/a").await)
}

/// Reads until EOF or error; returns the byte count.
async fn drain(mut s: TcpStream) -> usize {
    let mut b = vec![0u8; 64 * 1024];
    let mut n = 0;
    while let Ok(k) = s.read(&mut b).await {
        if k == 0 {
            break;
        }
        n += k;
    }
    n
}

async fn works_through_b(i: &Instance, ctl: SocketAddr) {
    let target = echo().await;
    let c = socks_connect(port(i, "in"), target).await;
    bulk_echo(c, 1 << 20).await;
    let c = socks_connect(port(i, "in"), target).await;
    let v = api(ctl, "/connections").await;
    let chains: Vec<&Value> = v["connections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| &c["chains"][0])
        .collect();
    assert!(chains.iter().all(|c| *c == "b"), "new connections avoid a: {chains:?}");
    drop(c);
}

#[tokio::test]
async fn freeze_mid_transfer_is_detected_and_switched() {
    let (i, a, ctl) = setup().await;
    a.set(FREEZE);
    let records = tls_records().await;
    let mut c = socks_connect(port(&i, "in"), records).await;
    c.write_all(b"g").await.unwrap();
    let reader = tokio::spawn(drain(c));

    // Silence mid-record for STALL asks for a data probe; the probe freezes
    // too and gives up after PROBE_GAP.
    let bound = STALL + sbr_engine::fetch::PROBE_GAP + Duration::from_secs(6);
    let (t, v) = degraded(ctl, bound).await;
    assert!(t.is_some(), "freeze not detected within {bound:?}: {v}");
    assert!(t.unwrap() >= STALL, "not before the stall threshold");
    assert_eq!(v["reason"], "frozen", "{v}");
    assert_eq!(v["alive"], false);
    assert!(v["retry_in"].as_u64().unwrap() > 100, "{v}");
    assert_eq!(api(ctl, "/proxies/auto").await["now"], "b");

    // The frozen connection is closed, so the app retries on the new path.
    let got = tokio::time::timeout(Duration::from_secs(3), reader)
        .await
        .expect("frozen connection closed")
        .unwrap();
    assert!(got < FREEZE_AT, "{got}");
    works_through_b(&i, ctl).await;
    i.shutdown();
}

#[tokio::test]
async fn reset_after_handshake_is_detected_at_once() {
    let (i, a, ctl) = setup().await;
    a.set(RESET);
    let target = echo().await;
    let mut c = socks_connect(port(&i, "in"), target).await;
    c.write_all(b"hello").await.unwrap();
    let mut b = [0u8; 5];
    assert!(c.read_exact(&mut b).await.is_err(), "reset reaches the client");
    // One reset asks for a data probe, which is reset as well.
    let (t, v) = degraded(ctl, Duration::from_secs(5)).await;
    assert!(t.is_some(), "{v}");
    assert_eq!(v["reason"], "reset", "{v}");
    assert_eq!(api(ctl, "/proxies/auto").await["now"], "b");
    works_through_b(&i, ctl).await;
    i.shutdown();
}

#[tokio::test]
async fn blackhole_after_handshake_degrades_on_a_burst() {
    let (i, a, ctl) = setup().await;
    a.set(BLACKHOLE);
    let mut readers = Vec::new();
    for _ in 0..3 {
        let mut c = socks_connect(port(&i, "in"), echo().await).await;
        c.write_all(b"anyone?").await.unwrap();
        readers.push(tokio::spawn(drain(c)));
    }
    // The data probe sees nothing at all, which proves nothing; the three
    // unanswered destinations do.
    let bound = STALL + Duration::from_secs(5);
    let (t, v) = degraded(ctl, bound).await;
    assert!(t.is_some(), "{v}");
    assert_eq!(v["reason"], "no_response", "{v}");
    assert_eq!(api(ctl, "/proxies/auto").await["now"], "b");
    for r in readers {
        let n = tokio::time::timeout(Duration::from_secs(3), r)
            .await
            .expect("closed")
            .unwrap();
        assert_eq!(n, 0);
    }
    works_through_b(&i, ctl).await;
    i.shutdown();
}

#[tokio::test]
async fn healthy_idle_then_burst_and_long_poll_are_not_flagged() {
    let (i, _a, ctl) = setup().await;
    let server = bursty().await;
    let mut c = socks_connect(port(&i, "in"), server).await;
    let mut buf = vec![0u8; 1 << 20];
    c.write_all(b"a").await.unwrap();
    c.read_exact(&mut buf[..32 * 1024]).await.unwrap();
    // Idle past the stall threshold with nothing outstanding, then a burst.
    tokio::time::sleep(STALL + Duration::from_secs(2)).await;
    c.write_all(b"b").await.unwrap();
    c.read_exact(&mut buf).await.unwrap();
    // A long poll: the reply comes after more than STALL. It triggers a data
    // probe, which passes.
    c.write_all(b"w").await.unwrap();
    c.read_exact(&mut buf[..100]).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let v = api(ctl, "/proxies/a").await;
    assert_eq!(v["degraded"], false, "{v}");
    assert_eq!(v["reason"], Value::Null);
    assert_eq!(api(ctl, "/proxies/auto").await["now"], "a");
    i.shutdown();
}

/// A TLS server answering pipelined requests with small 404s, like a
/// REALITY fallback site; after `limit` responses it goes silent.
async fn fallback_site(limit: usize) -> u16 {
    let (cert, key) = common::self_signed();
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_slice_iter(cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut t) = acceptor.accept(s).await else { return };
                let mut pending = Vec::new();
                let mut b = [0u8; 4096];
                let mut served = 0;
                loop {
                    let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match t.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&b[..n]),
                        }
                        continue;
                    };
                    pending.drain(..end + 4);
                    if served == limit {
                        std::future::pending::<()>().await;
                    }
                    served += 1;
                    let r = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 19\r\n\r\n404 page not found\n";
                    if t.write_all(r).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn data_probe_of_own_server_pipelines_past_the_threshold() {
    let i = start(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}]}"#).await;
    let direct = i.engine.outbound("direct").unwrap().clone();
    let http = HttpClient::new(None);
    let target = |p: u16| Target::Server(Destination::from_host_port("127.0.0.1", p));

    let site = fallback_site(usize::MAX).await;
    assert_eq!(http.data_probe(direct.as_ref(), &target(site)).await, Verdict::Pass);

    // Answers stop after ~10 KB: frozen mid-transfer.
    let site = fallback_site(100).await;
    let t = Instant::now();
    assert_eq!(http.data_probe(direct.as_ref(), &target(site)).await, Verdict::Frozen);
    assert!(t.elapsed() < sbr_engine::fetch::PROBE_GAP + Duration::from_secs(2));

    // Not a TLS server: nothing to conclude.
    let plain = echo().await;
    assert_eq!(
        http.data_probe(direct.as_ref(), &target(plain.port())).await,
        Verdict::Inconclusive
    );
    let closed = common::free_port();
    assert_eq!(
        http.data_probe(direct.as_ref(), &target(closed)).await,
        Verdict::Inconclusive
    );
    const { assert!(PROOF_BYTES > 100 * 120, "the limit above is below the threshold") };
    i.shutdown();
}
