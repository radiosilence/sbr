//! Client-side throughput of TLS proxy protocols, sbr vs sing-box.
//!
//!     cargo run --release -p sbr-engine --example proxy_bench -- /path/to/sing-box [streams] [seconds]
//!
//! A sing-box *server* runs vless+tls, trojan+tls and vmess inbounds (direct
//! outbound). The same client config is fed to sbr and to a second sing-box
//! process; a load generator pushes data through each client's SOCKS inbound
//! to a local sink, for upload and download. Everything is loopback and shares
//! the machine's cores, so treat the numbers as relative.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, KeyPair};
use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// Upload sink on one port, download source (writes forever) on another.
async fn sink_and_source() -> (SocketAddr, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 256 * 1024];
                while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
            });
        }
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let buf = vec![0x5au8; 256 * 1024];
                while s.write_all(&buf).await.is_ok() {}
            });
        }
    });
    (sink, source)
}

async fn socks(proxy: u16, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let std::net::IpAddr::V4(ip) = target.ip() else {
        unreachable!()
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "socks connect failed");
    s
}

fn cpu_seconds() -> f64 {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
    t(u.ru_utime) + t(u.ru_stime)
}

/// (Gbit/s, process CPU-seconds per GB) over `secs` across `streams` connections.
async fn blast(proxy: u16, target: SocketAddr, streams: usize, secs: u64, upload: bool) -> (f64, f64) {
    let mut conns = Vec::new();
    for _ in 0..streams {
        conns.push(socks(proxy, target).await);
    }
    let total = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let start = Instant::now();
    let cpu = cpu_seconds();
    let tasks: Vec<_> = conns
        .into_iter()
        .map(|mut s| {
            let total = total.clone();
            tokio::spawn(async move {
                let mut buf = vec![0xa5u8; 256 * 1024];
                while Instant::now() < deadline {
                    let n = if upload {
                        s.write_all(&buf).await.map(|_| buf.len())
                    } else {
                        s.read(&mut buf).await
                    };
                    match n {
                        Ok(0) | Err(_) => break,
                        Ok(n) => total.fetch_add(n as u64, Ordering::Relaxed),
                    };
                }
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    let bytes = total.load(Ordering::Relaxed) as f64;
    (
        bytes * 8.0 / start.elapsed().as_secs_f64() / 1e9,
        (cpu_seconds() - cpu) / (bytes / 1e9),
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn spawn(bin: &Path, cfg: &serde_json::Value, name: &str, port: u16) -> Proc {
    let path = std::env::temp_dir().join(format!("sbr-proxy-bench-{name}.json"));
    std::fs::write(&path, serde_json::to_vec(cfg).unwrap()).unwrap();
    let child = Command::new(bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Proc(child)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bin = Path::new(
        args.get(1)
            .expect("usage: proxy_bench /path/to/sing-box [streams] [seconds]"),
    );
    let streams: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);

    let dir = std::env::temp_dir();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["example.com".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let (cert_path, key_path) = (dir.join("sbr-bench-cert.pem"), dir.join("sbr-bench-key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let server_tls = json!({"enabled": true, "certificate_path": cert_path, "key_path": key_path});
    let client_tls = json!({"enabled": true, "server_name": "example.com",
                            "certificate": cert.pem().lines().collect::<Vec<_>>()});

    let (vless_s, trojan_s, vmess_s) = (free_port(), free_port(), free_port());
    let server = json!({
        "log": {"level": "error"},
        "inbounds": [
            {"type": "vless", "listen": "127.0.0.1", "listen_port": vless_s, "users": [{"uuid": UUID}], "tls": server_tls},
            {"type": "trojan", "listen": "127.0.0.1", "listen_port": trojan_s, "users": [{"password": "pw"}], "tls": server_tls},
            {"type": "vmess", "listen": "127.0.0.1", "listen_port": vmess_s, "users": [{"uuid": UUID}]},
        ],
        "outbounds": [{"type": "direct"}],
    });
    let _server = spawn(bin, &server, "server", vmess_s).await;

    let protos = ["vless+tls", "trojan+tls", "vmess-aes128gcm"];
    let ports: Vec<u16> = protos.iter().map(|_| free_port()).collect();
    let client = json!({
        "log": {"level": "error"},
        "inbounds": protos.iter().zip(&ports).map(|(p, port)|
            json!({"type": "mixed", "tag": p, "listen": "127.0.0.1", "listen_port": port})).collect::<Vec<_>>(),
        "outbounds": [
            {"type": "vless", "tag": "vless+tls", "server": "127.0.0.1", "server_port": vless_s, "uuid": UUID, "tls": client_tls},
            {"type": "trojan", "tag": "trojan+tls", "server": "127.0.0.1", "server_port": trojan_s, "password": "pw", "tls": client_tls},
            {"type": "vmess", "tag": "vmess-aes128gcm", "server": "127.0.0.1", "server_port": vmess_s, "uuid": UUID, "security": "aes-128-gcm"},
        ],
        "route": {"rules": protos.iter().map(|p| json!({"inbound": p, "outbound": p})).collect::<Vec<_>>()},
    });
    let (sink, source) = sink_and_source().await;
    println!("{streams} streams x {secs}s, loopback, sing-box server; Gbit/s");
    println!(
        "{:<18} {:>12} {:>12} {:>12} {:>12} {:>14} {:>14}",
        "", "sbr up", "sing-box up", "sbr down", "sing-box down", "sbr up cpu/GB", "sbr down cpu/GB"
    );

    let sbr = Instance::start(&Options::from_value(client.clone()).unwrap(), Settings::default())
        .await
        .unwrap();
    let mut results = Vec::new();
    for port in &ports {
        let up = blast(*port, sink, streams, secs, true).await;
        let down = blast(*port, source, streams, secs, false).await;
        results.push((up, down));
    }
    sbr.shutdown();
    // Let sbr's listeners close before sing-box binds the same ports.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let _sb = spawn(bin, &client, "client", ports[0]).await;
    for (i, port) in ports.iter().enumerate() {
        let (up, _) = blast(*port, sink, streams, secs, true).await;
        let (down, _) = blast(*port, source, streams, secs, false).await;
        let ((su, suc), (sd, sdc)) = results[i];
        println!(
            "{:<18} {:>12.2} {:>12.2} {:>12.2} {:>12.2} {:>14.3} {:>14.3}",
            protos[i], su, up, sd, down, suc, sdc
        );
    }
}
