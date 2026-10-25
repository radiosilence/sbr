//! TUN end to end on a real kernel interface, through both TCP stacks
//! (`system`: the kernel via NAT; `gvisor`: sbr's userspace TCP). Needs root
//! and /dev/net/tun; skips (passes with a note) otherwise.
//!
//! Each test gets its own interface and routed /24 so they can run in
//! parallel in one network namespace.

#[path = "common/soak.rs"]
mod soak;

use std::net::SocketAddr;
use std::time::Duration;

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn can_tun() -> bool {
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc_geteuid() } == 0;
    root && std::path::Path::new("/dev/net/tun").exists()
}

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// A TCP echo server on loopback.
async fn tcp_echo() -> u16 {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tcp.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

async fn udp_echo() -> u16 {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = [0u8; 65535];
        loop {
            let (n, from) = udp.recv_from(&mut b).await.unwrap();
            udp.send_to(&b[..n], from).await.unwrap();
        }
    });
    port
}

/// A tun inbound on `sbrt<n>` (172.19.<n>.1/30) routing 198.18.<n>.0/24,
/// whose traffic is redirected to loopback.
fn config(n: u8, stack: &str, mtu: u32, extra_rules: &str) -> String {
    format!(
        r#"{{
        "inbounds": [{{
            "type": "tun", "tag": "tun-in", "interface_name": "sbrt{n}",
            "address": ["172.19.{n}.1/30"], "mtu": {mtu}, "stack": "{stack}",
            "auto_route": true, "route_address": ["198.18.{n}.0/24"]
        }}],
        "outbounds": [{{"type": "direct", "tag": "direct"}}, {{"type": "block", "tag": "block"}}],
        "route": {{"rules": [
            {extra_rules}
            {{"ip_cidr": "198.18.{n}.0/24", "action": "route-options", "override_address": "127.0.0.1"}}
        ]}}
    }}"#
    )
}

async fn start(cfg: &str) -> Instance {
    Instance::start(&Options::parse(cfg).unwrap(), Settings::default())
        .await
        .unwrap()
}

async fn connect(n: u8, port: u16) -> TcpStream {
    tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((format!("198.18.{n}.1").as_str(), port)),
    )
    .await
    .expect("connect timed out")
    .unwrap()
}

async fn echo_bytes(s: &mut TcpStream, len: usize) {
    let data: Vec<u8> = (0..len as u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    let (mut r, mut w) = s.split();
    let send = async {
        w.write_all(&data).await.unwrap();
    };
    let recv = async {
        let mut got = vec![0u8; data.len()];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(send, recv) })
        .await
        .expect("echo timed out");
    assert!(got == data, "TCP payload corrupted through the TUN");
}

async fn end_to_end(n: u8, stack: &str) {
    if !can_tun() {
        eprintln!("skipping: needs root and /dev/net/tun");
        return;
    }
    let tcp_port = tcp_echo().await;
    let udp_port = udp_echo().await;
    let instance = start(&config(
        n,
        stack,
        9000,
        r#"{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"},
           {"domain": "blocked.test", "action": "reject"},"#,
    ))
    .await;

    // TCP: 4 MB, byte-exact; then several connections at once.
    let mut s = connect(n, tcp_port).await;
    echo_bytes(&mut s, 4_000_000).await;
    drop(s);
    let mut conns = Vec::new();
    for _ in 0..16 {
        conns.push(tokio::spawn(async move {
            let mut s = connect(n, tcp_port).await;
            echo_bytes(&mut s, 256 << 10).await;
        }));
    }
    for c in conns {
        c.await.unwrap();
    }

    // Half-close: the app shuts down its write side and still gets the
    // whole echo, then EOF.
    let mut s = connect(n, tcp_port).await;
    s.write_all(&[7u8; 100_000]).await.unwrap();
    s.shutdown().await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut got))
        .await
        .expect("half-close echo timed out")
        .unwrap();
    assert_eq!(got.len(), 100_000);

    // UDP: echo, and the reply must come from the address we sent to
    // (override_address undone), or a connected socket would drop it.
    let u = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    u.connect((format!("198.18.{n}.1").as_str(), udp_port)).await.unwrap();
    for size in [1, 1400, 8000] {
        let msg = vec![size as u8; size];
        u.send(&msg).await.unwrap();
        let mut b = vec![0u8; 65535];
        let got = tokio::time::timeout(Duration::from_secs(3), u.recv(&mut b))
            .await
            .expect("udp echo timed out")
            .unwrap();
        assert_eq!(&b[..got], &msg[..]);
    }

    // DNS hijack: a query to an address with no server gets answered.
    let d = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let q = b"\x77\x77\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01";
    let dns: SocketAddr = format!("198.18.{n}.53:53").parse().unwrap();
    d.send_to(q, dns).await.unwrap();
    let mut b = [0u8; 512];
    let (got, from) = tokio::time::timeout(Duration::from_secs(3), d.recv_from(&mut b))
        .await
        .expect("dns timed out")
        .unwrap();
    assert_eq!(from, dns);
    assert_eq!(&b[..2], b"\x77\x77");
    assert_eq!(&b[got - 4..got], &[127, 0, 0, 1]);

    // Sniffing: the HTTP Host decides, even though the IP would be allowed.
    let mut s = connect(n, tcp_port).await;
    s.write_all(b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
        .await
        .unwrap();
    let mut b = [0u8; 64];
    let r = tokio::time::timeout(Duration::from_secs(3), s.read(&mut b))
        .await
        .expect("rejected connection hung");
    match stack {
        // The userspace stack resets a refused connection, as a server
        // refusing it would; the kernel stack can only close.
        "gvisor" => assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::ConnectionReset),
        _ => assert_eq!(r.unwrap_or(0), 0, "sniffed domain must be rejected"),
    }

    instance.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_system_stack_end_to_end() {
    end_to_end(10, "system").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_userspace_stack_end_to_end() {
    end_to_end(11, "gvisor").await;
}

/// At MTU 1280 the kernel fragments large datagrams into the TUN, and
/// replies larger than the MTU must come back fragmented. This is the
/// nested-VPN case (OpenVPN or WireGuard over UDP inside the tunnel). TCP
/// at the same MTU must segment correctly in both directions.
async fn fragments_at_small_mtu(n: u8, stack: &str) {
    if !can_tun() {
        eprintln!("skipping: needs root and /dev/net/tun");
        return;
    }
    let udp_port = udp_echo().await;
    let tcp_port = tcp_echo().await;
    let instance = start(&config(n, stack, 1280, "")).await;
    let u = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    u.connect((format!("198.18.{n}.1").as_str(), udp_port)).await.unwrap();
    for size in [1200, 1253, 3000, 20000, 65000] {
        let msg: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        u.send(&msg).await.unwrap();
        let mut b = vec![0u8; 65535];
        let got = tokio::time::timeout(Duration::from_secs(3), u.recv(&mut b))
            .await
            .unwrap_or_else(|_| panic!("{size}-byte echo timed out"))
            .unwrap();
        assert_eq!(&b[..got], &msg[..], "{size}-byte echo corrupted");
    }
    let mut s = connect(n, tcp_port).await;
    echo_bytes(&mut s, 2_000_000).await;
    instance.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_system_stack_fragments_at_small_mtu() {
    fragments_at_small_mtu(12, "system").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_userspace_stack_fragments_at_small_mtu() {
    fragments_at_small_mtu(13, "gvisor").await;
}

/// A connection opened through one instance gets a reset, not silence,
/// from the next: an app holding a socket across a tunnel restart learns
/// at once that it is dead instead of waiting out its own timeouts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_userspace_stack_resets_connections_from_before_a_restart() {
    if !can_tun() {
        eprintln!("skipping: needs root and /dev/net/tun");
        return;
    }
    let n = 14;
    let tcp_port = tcp_echo().await;
    let cfg = config(n, "gvisor", 1500, "");
    let first = start(&cfg).await;
    let mut s = connect(n, tcp_port).await;
    echo_bytes(&mut s, 1000).await;
    first.shutdown();
    // The interface goes away with the instance; give the kernel a moment.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = start(&cfg).await;
    let r = tokio::time::timeout(Duration::from_secs(5), async {
        // The first write may be accepted before the reset arrives.
        for _ in 0..50 {
            s.write_all(b"still there?").await?;
            let mut b = [0u8; 16];
            match tokio::time::timeout(Duration::from_millis(100), s.read(&mut b)).await {
                Ok(Err(e)) => return Err(e),
                Ok(Ok(0)) => return Ok(()),
                _ => {}
            }
        }
        Ok(())
    })
    .await
    .expect("the stale connection hung instead of being reset");
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::ConnectionReset);
    second.shutdown();
}

/// TUN to engine to a local echo at the MTU the user's profile uses. See
/// `common/soak.rs` for how to run it.
async fn soak(n: u8, stack: &str) {
    if !can_tun() {
        eprintln!("skipping: needs root and /dev/net/tun");
        return;
    }
    let tcp_port = tcp_echo().await;
    let instance = start(&config(n, stack, 1280, "")).await;
    let s = connect(n, tcp_port).await;
    soak::soak_echo(&format!("tun {stack}"), s, soak::soak_bytes(), 4).await;
    instance.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: moves 128 MiB"]
async fn soak_tun() {
    soak(15, "system").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: moves 128 MiB"]
async fn soak_tun_userspace() {
    soak(16, "gvisor").await;
}
