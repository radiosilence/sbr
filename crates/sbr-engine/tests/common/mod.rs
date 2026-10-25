//! Shared helpers for the e2e and interop tests.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// TCP echo server; returns its address.
pub async fn echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// UDP echo server; returns its address.
pub async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) = s.recv_from(&mut buf).await.unwrap();
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    addr
}

pub async fn start(json: &str) -> Instance {
    let o = Options::parse(json).unwrap();
    Instance::start(&o, Settings::default()).await.unwrap()
}

pub fn port(i: &Instance, tag: &str) -> u16 {
    i.listening.iter().find(|(t, _)| t == tag).unwrap().1.port()
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// SOCKS5 CONNECT through a no-auth proxy.
pub async fn socks_connect(proxy: u16, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let mut req = vec![5, 1, 0];
    push_addr(&mut req, target);
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "socks reply");
    s
}

fn push_addr(b: &mut Vec<u8>, a: SocketAddr) {
    match a.ip() {
        std::net::IpAddr::V4(ip) => {
            b.push(1);
            b.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            b.push(4);
            b.extend_from_slice(&ip.octets());
        }
    }
    b.extend_from_slice(&a.port().to_be_bytes());
}

/// A SOCKS5 UDP association with a no-auth proxy.
pub struct SocksUdp {
    _ctrl: TcpStream,
    sock: UdpSocket,
    relay: SocketAddr,
}

impl SocksUdp {
    pub async fn new(proxy: u16) -> Self {
        let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await.unwrap();
        s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0);
        let relay = SocketAddr::from(([rep[4], rep[5], rep[6], rep[7]], u16::from_be_bytes([rep[8], rep[9]])));
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Self { _ctrl: s, sock, relay }
    }

    pub async fn send(&self, to: SocketAddr, payload: &[u8]) {
        let mut b = vec![0, 0, 0];
        push_addr(&mut b, to);
        b.extend_from_slice(payload);
        self.sock.send_to(&b, self.relay).await.unwrap();
    }

    /// Returns (payload, source) or None on timeout.
    pub async fn recv(&self, timeout: Duration) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65536];
        let (n, _) = tokio::time::timeout(timeout, self.sock.recv_from(&mut buf))
            .await
            .ok()?
            .unwrap();
        let b = &buf[..n];
        assert_eq!(b[3], 1, "expected IPv4 source");
        let from = SocketAddr::from(([b[4], b[5], b[6], b[7]], u16::from_be_bytes([b[8], b[9]])));
        Some((b[10..].to_vec(), from))
    }

    /// Send datagrams of various sizes and expect each one echoed back
    /// byte-exact (with retries: it's UDP).
    pub async fn echo_check(&self, target: SocketAddr, sizes: &[usize]) {
        for (i, &size) in sizes.iter().enumerate() {
            let payload: Vec<u8> = (0..size).map(|j| (i * 31 + j * 7) as u8).collect();
            let mut ok = false;
            for _ in 0..5 {
                self.send(target, &payload).await;
                if let Some((got, from)) = self.recv(Duration::from_secs(2)).await {
                    assert_eq!(from, target);
                    assert_eq!(got, payload, "datagram of {size} bytes");
                    ok = true;
                    break;
                }
            }
            assert!(ok, "no echo for a {size}-byte datagram");
        }
    }
}

/// The sing-box binary for interop tests: `$SBR_SING_BOX`, else `sing-box`
/// on `PATH`. `None` means skip.
pub fn sing_box() -> Option<PathBuf> {
    let cand = std::env::var_os("SBR_SING_BOX").map(PathBuf::from).or_else(|| {
        std::env::var_os("PATH").and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("sing-box"))
                .find(|f| f.is_file())
        })
    })?;
    cand.is_file().then_some(cand)
}

pub struct SingBox {
    child: Child,
    _dir: PathBuf,
}

impl SingBox {
    /// Start sing-box with `config` and wait until `ready_port` accepts TCP
    /// (or just a moment, for UDP-only servers, when it is `None`).
    pub async fn start(bin: &std::path::Path, config: &str, ready_port: Option<u16>) -> Self {
        let dir = std::env::temp_dir().join(format!("sbr-interop-{}-{}", std::process::id(), free_port()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, config).unwrap();
        let child = Command::new(bin)
            .args(["run", "-c"])
            .arg(&path)
            .arg("-D")
            .arg(&dir)
            .stdout(Stdio::null())
            .stderr(if std::env::var_os("SBR_SING_BOX_LOG").is_some() {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .spawn()
            .unwrap();
        let sb = Self { child, _dir: dir };
        match ready_port {
            Some(p) => {
                for _ in 0..200 {
                    if TcpStream::connect(("127.0.0.1", p)).await.is_ok() {
                        return sb;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                panic!("sing-box did not come up on {p}");
            }
            None => tokio::time::sleep(Duration::from_millis(700)).await,
        }
        sb
    }
}

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

/// Push `len` pseudo-random bytes through `s` (an echo path) and compare.
pub async fn bulk_echo(s: TcpStream, len: usize) {
    let data: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let (mut r, mut w) = s.into_split();
    let expect = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&data).await.unwrap();
        w
    });
    let mut got = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(60), r.read_exact(&mut got))
        .await
        .expect("bulk echo timed out")
        .unwrap();
    let _w = writer.await.unwrap();
    assert!(got == expect, "bulk echo of {len} bytes differs");
}
