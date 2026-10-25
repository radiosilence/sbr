//! DNS through the whole engine: hijack-dns over SOCKS5 UDP with DNS rules,
//! FakeIP answers turning back into domains for TCP and UDP, and outbounds
//! resolving through `route.default_domain_resolver`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sbr_dns::msg;
use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn start(json: &str) -> Instance {
    let o = Options::parse(json).unwrap();
    Instance::start(&o, Settings::default()).await.unwrap()
}

fn port(i: &Instance, tag: &str) -> u16 {
    i.listening.iter().find(|(t, _)| t == tag).unwrap().1.port()
}

/// An upstream DNS server: every A query gets 10.53.0.1, and is counted.
async fn upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        loop {
            let (n, from) = sock.recv_from(&mut b).await.unwrap();
            c.fetch_add(1, Ordering::SeqCst);
            let q = msg::decode(&b[..n]).unwrap();
            let r = msg::addresses(&q, &["10.53.0.1".parse().unwrap()], 60);
            sock.send_to(&msg::encode(&r).unwrap(), from).await.unwrap();
        }
    });
    (addr, count)
}

/// A SOCKS5 UDP association: (control connection, relay address).
async fn associate(proxy: u16) -> (TcpStream, SocketAddr) {
    let mut ctrl = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    ctrl.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    ctrl.read_exact(&mut r).await.unwrap();
    ctrl.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut rep = [0u8; 10];
    ctrl.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    (
        ctrl,
        SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([rep[8], rep[9]]))),
    )
}

fn wrap(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let IpAddr::V4(ip) = dst.ip() else { unreachable!() };
    let mut p = vec![0, 0, 0, 1];
    p.extend_from_slice(&ip.octets());
    p.extend_from_slice(&dst.port().to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// Ask `name` through hijack-dns; `None` if nothing came back.
async fn ask(u: &UdpSocket, relay: SocketAddr, name: &str, qtype: u16) -> Option<msg::Message> {
    let mut q = msg::query(name, qtype).unwrap();
    q.metadata.id = 0x7777;
    u.send_to(
        &wrap("192.0.2.53:53".parse().unwrap(), &msg::encode(&q).unwrap()),
        relay,
    )
    .await
    .unwrap();
    let mut b = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_millis(1500), u.recv(&mut b))
        .await
        .ok()?
        .unwrap();
    let m = msg::decode(&b[10..n]).unwrap();
    assert_eq!(m.metadata.id, 0x7777);
    Some(m)
}

#[tokio::test]
async fn hijack_dns_with_rules() {
    let (up, count) = upstream().await;
    let i = start(&format!(
        r#"{{"inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0}}],
            "outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"direct","tag":"dns-out"}}],
            "dns":{{
                "servers":[{{"type":"udp","tag":"up","server":"127.0.0.1","server_port":{},"detour":"dns-out"}}],
                "rules":[
                    {{"domain_suffix":"test","server":"up"}},
                    {{"domain":"blocked.example","action":"reject"}},
                    {{"action":"predefined","rcode":"NXDOMAIN"}}
                ]
            }},
            "route":{{"rules":[{{"action":"sniff"}},{{"protocol":"dns","action":"hijack-dns"}}]}}}}"#,
        up.port()
    ))
    .await;
    let (_ctrl, relay) = associate(port(&i, "in")).await;
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let m = ask(&u, relay, "www.a.test", 1).await.unwrap();
    assert_eq!(
        msg::answer_addrs(&m),
        [IpAddr::from([10, 53, 0, 1])],
        "*.test goes upstream"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let m = ask(&u, relay, "www.a.test", 1).await.unwrap();
    assert_eq!(msg::answer_addrs(&m), [IpAddr::from([10, 53, 0, 1])]);
    assert_eq!(count.load(Ordering::SeqCst), 1, "second answer from the cache");

    let m = ask(&u, relay, "example.com", 1).await.unwrap();
    assert_eq!(msg::rcode(&m), 3, "everything else: predefined NXDOMAIN");
    let m = ask(&u, relay, "blocked.example", 1).await.unwrap();
    assert_eq!(msg::rcode(&m), 5, "reject: REFUSED");
    assert_eq!(count.load(Ordering::SeqCst), 1, "neither reached upstream");
}

#[tokio::test]
async fn fakeip_restores_domains_for_tcp_and_udp() {
    // TCP and UDP echo on loopback, reachable as echo.test via the hosts server.
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tport = tl.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tl.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let ue = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uport = ue.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        loop {
            let (n, from) = ue.recv_from(&mut b).await.unwrap();
            ue.send_to(&b[..n], from).await.unwrap();
        }
    });

    let i = start(
        r#"{"inbounds":[{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0}],
            "outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],
            "dns":{
                "servers":[
                    {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"},
                    {"type":"hosts","tag":"hosts","predefined":{"echo.test":"127.0.0.1"}}
                ],
                "rules":[{"query_type":"A","server":"fake"}],
                "final":"hosts"
            },
            "route":{
                "rules":[
                    {"action":"sniff"},
                    {"protocol":"dns","action":"hijack-dns"},
                    {"domain":"echo.test","outbound":"direct"},
                    {"ip_cidr":"198.18.0.0/15","outbound":"block"}
                ],
                "final":"block",
                "default_domain_resolver":"hosts"
            }}"#,
    )
    .await;
    let proxy = port(&i, "in");
    let (_ctrl, relay) = associate(proxy).await;
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let m = ask(&u, relay, "echo.test", 1).await.unwrap();
    let fake = msg::answer_addrs(&m)[0];
    assert_eq!(fake, IpAddr::from([198, 18, 0, 2]));
    let IpAddr::V4(fake4) = fake else { unreachable!() };

    // TCP to the fake address: routed as echo.test (direct), which resolves
    // through the hosts server to the loopback echo.
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&fake4.octets());
    req.extend_from_slice(&tport.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "connected");
    s.write_all(b"through fakeip").await.unwrap();
    let mut got = [0u8; 14];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"through fakeip");

    // An address in the range with no mapping is refused.
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    s.read_exact(&mut r).await.unwrap();
    s.write_all(&[5, 1, 0, 1, 198, 18, 7, 7, 0, 80]).await.unwrap();
    s.read_exact(&mut rep).await.unwrap();
    assert_ne!(rep[1], 0, "unmapped fake address refused");

    // UDP to the fake address: same domain, and replies come back from the
    // fake address the client used.
    let u2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fake_dst = SocketAddr::new(fake, uport);
    u2.send_to(&wrap(fake_dst, b"udp via fakeip"), relay).await.unwrap();
    let mut b = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(3), u2.recv(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[10..n], b"udp via fakeip");
    assert_eq!(
        &b[4..10],
        &wrap(fake_dst, b"")[4..10],
        "reply source is the fake address"
    );
}

#[tokio::test]
async fn resolve_action_and_domain_resolver() {
    let (up, _) = upstream().await;
    // `resolve` with a named server fills destination addresses for ip_cidr.
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tport = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = target.accept().await.unwrap();
            let _ = s.write_all(b"ok").await;
        }
    });
    let i = start(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
            "outbounds":[{{"type":"block","tag":"block"}},
                         {{"type":"direct","tag":"local","domain_resolver":"hosts"}}],
            "dns":{{"servers":[
                {{"type":"udp","tag":"up","server":"127.0.0.1","server_port":{}}},
                {{"type":"hosts","tag":"hosts","predefined":{{"svc.test":"127.0.0.1"}}}}
            ]}},
            "route":{{"rules":[
                {{"action":"resolve","server":"up"}},
                {{"ip_cidr":"10.53.0.0/16","outbound":"local","override_address":"svc.test"}}
            ],"final":"block"}}}}"#,
        up.port()
    ))
    .await;
    // up says 10.53.0.1 → ip_cidr hits → "local", which resolves svc.test via hosts.
    let mut s = TcpStream::connect(("127.0.0.1", port(&i, "in"))).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let host = b"anything.example";
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&tport.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    let mut got = [0u8; 2];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ok");
}
