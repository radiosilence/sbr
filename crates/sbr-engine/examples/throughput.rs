//! Loopback throughput: client -> sbr (socks5) -> outbound -> sink.
//!
//!     cargo run --release -p sbr-engine --example throughput -- [streams] [seconds] [/path/to/sing-box]
//!
//! Reports raw loopback as a baseline so the number means something on any box.
//! Given a sing-box binary, runs the identical config through it too.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sbr_engine::sbr_config::Options;

use sbr_engine::{Instance, Settings};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::relay::tcprelay::proxy_listener::ProxyListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

async fn ss_server(method: &str, key: &str) -> u16 {
    let cfg = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        key,
        method.parse().unwrap(),
    )
    .unwrap();
    let l = ProxyListener::bind(Context::new_shared(ServerType::Server), &cfg)
        .await
        .unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let Ok(addr) = s.handshake().await else {
                    return;
                };
                let mut r = TcpStream::connect(addr.to_string()).await.unwrap();
                r.set_nodelay(true).unwrap();
                let _ =
                    tokio::io::copy_bidirectional_with_sizes(&mut s, &mut r, 64 * 1024, 64 * 1024)
                        .await;
            });
        }
    });
    port
}

async fn socks(proxy: u16, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let mut req = vec![5, 1, 0, 1];
    let std::net::IpAddr::V4(ip) = target.ip() else {
        unreachable!()
    };
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    s
}

async fn blast(streams: Vec<TcpStream>, secs: u64) -> f64 {
    let total = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let start = Instant::now();
    let tasks: Vec<_> = streams
        .into_iter()
        .map(|mut s| {
            let total = total.clone();
            tokio::spawn(async move {
                let buf = vec![0xa5u8; 256 * 1024];
                while Instant::now() < deadline {
                    s.write_all(&buf).await.unwrap();
                    total.fetch_add(buf.len() as u64, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    total.load(Ordering::Relaxed) as f64 * 8.0 / start.elapsed().as_secs_f64() / 1e9
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let target = sink().await;

    let mut raw = Vec::new();
    for _ in 0..n {
        let s = TcpStream::connect(target).await.unwrap();
        s.set_nodelay(true).unwrap();
        raw.push(s);
    }
    println!("{n} streams, {secs}s each, upload direction");
    println!(
        "  raw loopback                       {:>7.2} Gbit/s",
        blast(raw, secs).await
    );

    let key = "Ixi/xBrzF3Nnrel2vh8Dsg==";
    let method = "2022-blake3-aes-128-gcm";
    let ss = ss_server(method, key).await;
    let (p1, p2) = (free_port(), free_port());
    let cfg = format!(
        r#"{{
        "log":{{"level":"error"}},
        "inbounds":[{{"type":"mixed","tag":"direct-in","listen":"127.0.0.1","listen_port":{p1}}},
                    {{"type":"mixed","tag":"ss-in","listen":"127.0.0.1","listen_port":{p2}}}],
        "outbounds":[{{"type":"direct","tag":"direct"}},
                     {{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":{ss},"method":"{method}","password":"{key}"}}],
        "route":{{"rules":[{{"inbound":"ss-in","outbound":"ss"}}],"final":"direct"}}
    }}"#
    );
    let i = Instance::start(&Options::parse(&cfg).unwrap(), Settings::default())
        .await
        .unwrap();
    run_pair("sbr", p1, p2, n, secs, target).await;
    i.shutdown();

    if let Some(bin) = args.get(3) {
        let path = std::env::temp_dir().join("sbr-bench-config.json");
        std::fs::write(&path, &cfg).unwrap();
        let mut child = std::process::Command::new(bin)
            .args(["run", "-c"])
            .arg(&path)
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", p2)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        run_pair("sing-box", p1, p2, n, secs, target).await;
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

async fn run_pair(name: &str, p1: u16, p2: u16, n: usize, secs: u64, target: SocketAddr) {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(socks(p1, target).await);
    }
    println!(
        "  {name:<9} socks -> direct            {:>7.2} Gbit/s",
        blast(v, secs).await
    );
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(socks(p2, target).await);
    }
    println!(
        "  {name:<9} socks -> ss-2022 -> ss     {:>7.2} Gbit/s",
        blast(v, secs).await
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
