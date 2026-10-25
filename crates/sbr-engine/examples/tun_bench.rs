//! TUN throughput: app → TUN → system stack → engine → loopback sink.
//! Needs root. Optionally runs the identical config through sing-box.
//!
//!     cargo run --release -p sbr-engine --example tun_bench -- [streams] [seconds] [/path/to/sing-box]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn config(iface: &str, net: &str) -> String {
    format!(
        r#"{{
        "log": {{"level": "error"}},
        "inbounds": [{{"type": "tun", "tag": "tun-in", "interface_name": "{iface}", "address": ["{net}.1/30"],
                      "mtu": 9000, "auto_route": true, "route_address": ["198.18.99.0/24"], "stack": "system"}}],
        "outbounds": [{{"type": "direct", "tag": "direct"}}],
        "route": {{"rules": [{{"ip_cidr": "198.18.99.0/24", "action": "route-options", "override_address": "127.0.0.1"}}]}}
    }}"#
    )
}

fn cpu_secs(pid: u32) -> f64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let f: Vec<&str> = s.rsplit(')').next().unwrap_or("").split_whitespace().collect();
    let tick = 100.0;
    (f.get(11).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0)
        + f.get(12).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0))
        / tick
}

async fn blast(port: u16, n: usize, secs: u64) -> f64 {
    let total = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let start = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..n {
        let mut s = TcpStream::connect(("198.18.99.1", port)).await.unwrap();
        s.set_nodelay(true).unwrap();
        let total = total.clone();
        tasks.push(tokio::spawn(async move {
            let buf = vec![0x5au8; 256 * 1024];
            while Instant::now() < deadline {
                s.write_all(&buf).await.unwrap();
                total.fetch_add(buf.len() as u64, Ordering::Relaxed);
            }
        }));
    }
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

    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = sink.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 256 * 1024];
                while matches!(s.read(&mut b).await, Ok(n) if n > 0) {}
            });
        }
    });

    println!("{n} streams × {secs}s upload through TUN (system stack), sink on loopback");
    let me = std::process::id();
    let i = Instance::start(
        &Options::parse(&config("sbrb0", "172.19.0")).unwrap(),
        Settings::default(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let c0 = cpu_secs(me);
    let g = blast(port, n, secs).await;
    // In-process: CPU includes the load generator and sink too.
    println!(
        "  sbr       {g:>6.2} Gbit/s   (process CPU incl. client+sink: {:.1}s)",
        cpu_secs(me) - c0
    );
    i.shutdown();
    tokio::time::sleep(Duration::from_millis(300)).await;

    if let Some(bin) = args.get(3) {
        let path = std::env::temp_dir().join("sbr-tun-bench.json");
        // Different interface/subnet; same routes (ours went away with sbrb0).
        std::fs::write(&path, config("sbrb1", "172.20.0")).unwrap();
        let mut child = std::process::Command::new(bin)
            .args(["run", "-c"])
            .arg(&path)
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let c0 = cpu_secs(child.id());
        let g = blast(port, n, secs).await;
        println!(
            "  sing-box  {g:>6.2} Gbit/s   (sing-box process CPU: {:.1}s)",
            cpu_secs(child.id()) - c0
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
