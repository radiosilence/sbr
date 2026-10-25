//! TUN throughput: app ⇄ TUN ⇄ stack ⇄ engine ⇄ loopback, for both TCP
//! stacks, upload (app writes to a sink) and download (a source writes to
//! the app). Needs root on Linux. Optionally runs the same configs through
//! sing-box.
//!
//!     cargo run --release -p sbr-engine --example tun_bench -- [streams] [seconds] [/path/to/sing-box]
//!
//! `SBR_BENCH_MTU` sets the TUN MTU (default 9000).
//!
//! CPU is reported per GB moved, both for this process (which includes the
//! in-process load generator and sink, identical across stacks) and for the
//! whole machine from /proc/stat (which also counts the kernel's softirq
//! work for the kernel stack).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn config(iface: &str, net: &str, stack: &str) -> String {
    let mtu = std::env::var("SBR_BENCH_MTU").unwrap_or_else(|_| "9000".into());
    format!(
        r#"{{
        "log": {{"level": "error"}},
        "inbounds": [{{"type": "tun", "tag": "tun-in", "interface_name": "{iface}", "address": ["{net}.1/30"],
                      "mtu": {mtu}, "auto_route": true, "route_address": ["198.18.99.0/24"], "stack": "{stack}"}}],
        "outbounds": [{{"type": "direct", "tag": "direct"}}],
        "route": {{"rules": [{{"ip_cidr": "198.18.99.0/24", "action": "route-options", "override_address": "127.0.0.1"}}]}}
    }}"#
    )
}

fn proc_cpu(pid: u32) -> f64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let f: Vec<&str> = s.rsplit(')').next().unwrap_or("").split_whitespace().collect();
    (f.get(11).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0)
        + f.get(12).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0))
        / 100.0
}

/// Busy CPU-seconds across the machine (everything but idle and iowait).
fn machine_cpu() -> f64 {
    let s = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let v: Vec<f64> = s
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    let total: f64 = v.iter().sum();
    let idle = v.get(3).copied().unwrap_or(0.0) + v.get(4).copied().unwrap_or(0.0);
    (total - idle) / 100.0
}

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Up,
    Down,
}

/// Returns bytes moved and seconds taken.
async fn blast(port: u16, n: usize, secs: u64, dir: Dir) -> (u64, f64) {
    let total = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let start = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..n {
        let mut s = TcpStream::connect(("198.18.99.1", port)).await.unwrap();
        s.set_nodelay(true).unwrap();
        let total = total.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0x5au8; 256 * 1024];
            if dir == Dir::Down {
                s.write_all(b"d").await.unwrap();
            }
            while Instant::now() < deadline {
                let n = match dir {
                    Dir::Up => {
                        s.write_all(&buf).await.unwrap();
                        buf.len()
                    }
                    Dir::Down => match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    },
                };
                total.fetch_add(n as u64, Ordering::Relaxed);
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    (total.load(Ordering::Relaxed), start.elapsed().as_secs_f64())
}

/// A sink for uploads; a connection that sends "d" first gets a stream of
/// bytes instead.
async fn serve() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 256 * 1024];
                let Ok(n) = s.read(&mut b).await else { return };
                if n > 0 && b[0] == b'd' {
                    while s.write_all(&b).await.is_ok() {}
                } else {
                    while matches!(s.read(&mut b).await, Ok(n) if n > 0) {}
                }
            });
        }
    });
    port
}

fn report(who: &str, bytes: u64, secs: f64, proc: Option<f64>, machine: f64) {
    let gb = bytes as f64 / 1e9;
    let proc = proc.map_or(String::new(), |p| format!("  process {:.2} s/GB", p / gb));
    println!(
        "  {who:<22} {:>6.2} Gbit/s{proc}  machine {:.2} s/GB",
        bytes as f64 * 8.0 / secs / 1e9,
        machine / gb
    );
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let port = serve().await;
    let me = std::process::id();
    let mtu = std::env::var("SBR_BENCH_MTU").unwrap_or_else(|_| "9000".into());
    println!("{n} streams × {secs}s through the TUN at MTU {mtu}, server on loopback");

    let mut k = 0;
    for stack in ["system", "gvisor"] {
        for dir in [Dir::Up, Dir::Down] {
            k += 1;
            let i = Instance::start(
                &Options::parse(&config(&format!("sbrb{k}"), &format!("172.20.{k}"), stack)).unwrap(),
                Settings::default(),
            )
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            let (p0, m0) = (proc_cpu(me), machine_cpu());
            let (bytes, t) = blast(port, n, secs, dir).await;
            let label = format!("sbr {stack} {}", if dir == Dir::Up { "up" } else { "down" });
            report(&label, bytes, t, Some(proc_cpu(me) - p0), machine_cpu() - m0);
            i.shutdown();
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    if let Some(bin) = args.get(3) {
        for stack in ["system", "gvisor"] {
            for dir in [Dir::Up, Dir::Down] {
                k += 1;
                let path = std::env::temp_dir().join("sbr-tun-bench.json");
                std::fs::write(&path, config(&format!("sbrb{k}"), &format!("172.20.{k}"), stack)).unwrap();
                let mut child = std::process::Command::new(bin)
                    .args(["run", "-c"])
                    .arg(&path)
                    .spawn()
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(2)).await;
                let m0 = machine_cpu();
                let (bytes, t) = blast(port, n, secs, dir).await;
                let label = format!("sing-box {stack} {}", if dir == Dir::Up { "up" } else { "down" });
                report(&label, bytes, t, None, machine_cpu() - m0);
                child.kill().unwrap();
                child.wait().unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
}
