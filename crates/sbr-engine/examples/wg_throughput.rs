//! WireGuard throughput: sbr vs sing-box as clients of the same sing-box
//! WireGuard peer on loopback.
//!
//!     cargo run --release -p sbr-engine --example wg_throughput -- /path/to/sing-box [streams] [seconds]
//!
//! The sing-box binary must be built with `with_wireguard`. Path:
//! client -> socks (client core) -> WireGuard -> sing-box peer -> direct -> sink/source.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SERVER_PRIV: &str = "UMw/nn/aarRTT0YpX2vhoKkkVyMMaRm//ZIp0NtcDVA=";
const SERVER_PUB: &str = "86aLVfau2HFqXMvhQCqNmZpmsBj+sA2NWZP18Q5d2is=";
const CLIENT_PRIV: &str = "wB84HEwMuUsqfS3lzc0uVwGCRj1/AazY6Z6ixqVOEGo=";
const CLIENT_PUB: &str = "fy+4MMVWHzNXfR+K+VPZ5qH2sA0M/HYanok123jxshI=";

async fn sink() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 256 * 1024];
                while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
            });
        }
    });
    a
}

async fn source() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let buf = vec![0x5au8; 256 * 1024];
                while s.write_all(&buf).await.is_ok() {}
            });
        }
    });
    a
}

async fn socks(proxy: u16, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let mut req = vec![5, 1, 0, 1, 10, 66, 0, 1];
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    s
}

async fn run(streams: Vec<TcpStream>, secs: u64, upload: bool) -> f64 {
    let total = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let start = Instant::now();
    let tasks: Vec<_> = streams
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
                        Ok(n) if n > 0 => total.fetch_add(n as u64, Ordering::Relaxed),
                        _ => break,
                    };
                }
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    total.load(Ordering::Relaxed) as f64 * 8.0 / start.elapsed().as_secs_f64() / 1e9
}

fn free_port(udp: bool) -> u16 {
    if udp {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}

fn spawn_sing_box(bin: &str, name: &str, cfg: &str) -> Child {
    let path = std::env::temp_dir().join(format!("sbr-wg-bench-{name}.json"));
    std::fs::write(&path, cfg).unwrap();
    Command::new(bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .spawn()
        .unwrap()
}

async fn wait_tcp(port: u16) {
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("nothing listening on {port}");
}

async fn measure(name: &str, proxy: u16, n: usize, secs: u64, sink: SocketAddr, source: SocketAddr) {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(socks(proxy, sink.port()).await);
    }
    let up = run(v, secs, true).await;
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(socks(proxy, source.port()).await);
    }
    let down = run(v, secs, false).await;
    println!("  {name:<9} upload {up:>6.2} Gbit/s   download {down:>6.2} Gbit/s");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bin = args
        .get(1)
        .expect("usage: wg_throughput /path/to/sing-box [streams] [seconds]")
        .clone();
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
    let (sink, source) = (sink().await, source().await);

    let wg_port = free_port(true);
    let server = format!(
        r#"{{"log":{{"level":"error"}},
        "endpoints":[{{"type":"wireguard","tag":"wg","address":["10.66.0.1/32"],"private_key":"{SERVER_PRIV}","listen_port":{wg_port},
            "peers":[{{"public_key":"{CLIENT_PUB}","allowed_ips":["10.66.0.2/32"]}}]}}],
        "outbounds":[{{"type":"direct"}}]}}"#
    );
    let mut server = spawn_sing_box(&bin, "server", &server);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client_port = free_port(false);
    let client = format!(
        r#"{{"log":{{"level":"error"}},
        "inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":{client_port}}}],
        "endpoints":[{{"type":"wireguard","tag":"wg","address":["10.66.0.2/32"],"private_key":"{CLIENT_PRIV}",
            "peers":[{{"address":"127.0.0.1","port":{wg_port},"public_key":"{SERVER_PUB}","allowed_ips":["0.0.0.0/0"]}}]}}],
        "route":{{"final":"wg"}}}}"#
    );
    println!("WireGuard via a sing-box peer, {n} stream(s), {secs}s per direction");

    let i = Instance::start(&Options::parse(&client).unwrap(), Settings::default())
        .await
        .unwrap();
    measure("sbr", client_port, n, secs, sink, source).await;
    i.shutdown();
    tokio::time::sleep(Duration::from_millis(300)).await;
    if std::env::var_os("SBR_BENCH_ONLY").is_some() {
        server.kill().unwrap();
        server.wait().unwrap();
        return;
    }

    let mut sb = spawn_sing_box(&bin, "client", &client);
    wait_tcp(client_port).await;
    measure("sing-box", client_port, n, secs, sink, source).await;
    sb.kill().unwrap();
    sb.wait().unwrap();
    server.kill().unwrap();
    server.wait().unwrap();
}
