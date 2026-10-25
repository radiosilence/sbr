//! TUN end to end on a real kernel interface. Needs root and /dev/net/tun;
//! skips (passes with a note) otherwise.

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_system_stack_end_to_end() {
    if !can_tun() {
        eprintln!("skipping: needs root and /dev/net/tun");
        return;
    }
    // Local services the tunnel's traffic gets redirected to.
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tcp.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = [0u8; 65535];
        loop {
            let (n, from) = udp.recv_from(&mut b).await.unwrap();
            udp.send_to(&b[..n], from).await.unwrap();
        }
    });

    let cfg = r#"{
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": "sbrt0",
            "address": ["172.19.0.1/30"], "mtu": 9000,
            "auto_route": true, "route_address": ["198.18.99.0/24"]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
        "route": {"rules": [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"domain": "blocked.test", "action": "reject"},
            {"ip_cidr": "198.18.99.0/24", "action": "route-options", "override_address": "127.0.0.1"}
        ]}
    }"#;
    let instance = Instance::start(&Options::parse(cfg).unwrap(), Settings::default())
        .await
        .unwrap();

    // TCP: 4 MB through the kernel NAT, byte-exact.
    let mut s = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(("198.18.99.1", tcp_port)))
        .await
        .expect("connect timed out")
        .unwrap();
    let data: Vec<u8> = (0..4_000_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    let (mut r, mut w) = s.split();
    let send = async {
        w.write_all(&data).await.unwrap();
    };
    let recv = async {
        let mut got = vec![0u8; data.len()];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(send, recv) })
        .await
        .unwrap();
    assert!(got == data, "TCP payload corrupted through the TUN");
    drop(s);

    // UDP: echo, and the reply must come from the address we sent to
    // (override_address undone), or a connected socket would drop it.
    let u = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    u.connect(("198.18.99.1", udp_port)).await.unwrap();
    for size in [1, 1400, 8000] {
        let msg = vec![size as u8; size];
        u.send(&msg).await.unwrap();
        let mut b = vec![0u8; 65535];
        let n = tokio::time::timeout(Duration::from_secs(3), u.recv(&mut b))
            .await
            .expect("udp echo timed out")
            .unwrap();
        assert_eq!(&b[..n], &msg[..]);
    }

    // DNS hijack: a query to an address with no server gets answered.
    let d = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let q = b"\x77\x77\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01";
    d.send_to(q, "198.18.99.53:53").await.unwrap();
    let mut b = [0u8; 512];
    let (n, from) = tokio::time::timeout(Duration::from_secs(3), d.recv_from(&mut b))
        .await
        .expect("dns timed out")
        .unwrap();
    assert_eq!(from, "198.18.99.53:53".parse::<SocketAddr>().unwrap());
    assert_eq!(&b[..2], b"\x77\x77");
    assert_eq!(&b[n - 4..n], &[127, 0, 0, 1]);

    // Sniffing: the HTTP Host decides, even though the IP would be allowed.
    let mut s = TcpStream::connect(("198.18.99.1", tcp_port)).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
        .await
        .unwrap();
    let mut b = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut b))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "sniffed domain must be rejected");

    instance.shutdown();
}

/// At MTU 1280 the kernel fragments large datagrams into the TUN, and
/// replies larger than the MTU must come back fragmented. This is the
/// nested-VPN case (OpenVPN or WireGuard over UDP inside the tunnel).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_udp_fragments_at_small_mtu() {
    if !can_tun() {
        eprintln!("skipping: needs root and /dev/net/tun");
        return;
    }
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = [0u8; 65535];
        loop {
            let (n, from) = udp.recv_from(&mut b).await.unwrap();
            udp.send_to(&b[..n], from).await.unwrap();
        }
    });
    let cfg = r#"{
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": "sbrt1",
            "address": ["172.19.1.1/30"], "mtu": 1280,
            "auto_route": true, "route_address": ["198.18.98.0/24"]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [
            {"ip_cidr": "198.18.98.0/24", "action": "route-options", "override_address": "127.0.0.1"}
        ]}
    }"#;
    let instance = Instance::start(&Options::parse(cfg).unwrap(), Settings::default())
        .await
        .unwrap();
    let u = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    u.connect(("198.18.98.1", udp_port)).await.unwrap();
    for size in [1200, 1253, 3000, 20000, 65000] {
        let msg: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        u.send(&msg).await.unwrap();
        let mut b = vec![0u8; 65535];
        let n = tokio::time::timeout(Duration::from_secs(3), u.recv(&mut b))
            .await
            .unwrap_or_else(|_| panic!("{size}-byte echo timed out"))
            .unwrap();
        assert_eq!(&b[..n], &msg[..], "{size}-byte echo corrupted");
    }
    instance.shutdown();
}
