//! WireGuard throughput: sbr vs sing-box as clients of the same sing-box
//! WireGuard peer on loopback.
//!
//!     cargo run --release -p sbr-engine --example wg_throughput -- /path/to/sing-box [streams] [seconds] [runs]
//!
//! The sing-box binary must be built with `with_wireguard`. Path:
//! client -> socks (client core) -> WireGuard -> sing-box peer -> direct -> sink/source.
//!
//! Each client core runs in its own process (sbr re-executes this binary), so
//! the CPU time reported is the client's alone, as CPU-seconds per GB moved.
//! Runs alternate between cores, back to back.
//!
//! `SBR_BENCH_THREADS=1,0` measures sbr once per listed runtime: `1` is the
//! current-thread runtime (the iOS default), `0` the multi-thread default, `n`
//! a pool of n workers. `SBR_BENCH_ONLY=1` skips sing-box.

use std::net::SocketAddr;
use std::path::PathBuf;
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

/// Returns bytes moved and the seconds it took.
async fn run(streams: Vec<TcpStream>, secs: u64, upload: bool) -> (u64, f64) {
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
    (total.load(Ordering::Relaxed), start.elapsed().as_secs_f64())
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

fn write_config(name: &str, cfg: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sbr-wg-bench-{name}.json"));
    std::fs::write(&path, cfg).unwrap();
    path
}

fn spawn_sing_box(bin: &str, name: &str, cfg: &str) -> Child {
    Command::new(bin)
        .args(["run", "-c"])
        .arg(write_config(name, cfg))
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

/// CPU seconds (user + system) the process has used so far.
fn cpu_seconds(pid: u32) -> f64 {
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // utime and stime are fields 14 and 15, counted from the pid.
        let rest = &stat[stat.rfind(')').unwrap() + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        let ticks = f[11].parse::<f64>().unwrap() + f[12].parse::<f64>().unwrap();
        return ticks / 100.0;
    }
    // BSD ps prints [hh:]mm:ss.cc.
    let out = Command::new("ps")
        .args(["-o", "cputime=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .split(':')
        .fold(0.0, |acc, part| acc * 60.0 + part.parse::<f64>().unwrap())
}

/// Gbit/s and client CPU-seconds per GB, upload then download.
struct Sample {
    up: (f64, f64),
    down: (f64, f64),
}

async fn one_direction(pid: u32, proxy: u16, n: usize, secs: u64, port: u16, upload: bool) -> (f64, f64) {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(socks(proxy, port).await);
    }
    let cpu0 = cpu_seconds(pid);
    let (bytes, elapsed) = run(v, secs, upload).await;
    let cpu = cpu_seconds(pid) - cpu0;
    (bytes as f64 * 8.0 / elapsed / 1e9, cpu / (bytes as f64 / 1e9))
}

/// Child mode: the sbr client on the requested runtime, until killed.
fn client_main(cfg: &str, threads: usize) {
    let mut b = match threads {
        1 => tokio::runtime::Builder::new_current_thread(),
        0 => tokio::runtime::Builder::new_multi_thread(),
        n => {
            let mut b = tokio::runtime::Builder::new_multi_thread();
            b.worker_threads(n);
            b
        }
    };
    let rt = b.enable_all().build().unwrap();
    let text = std::fs::read_to_string(cfg).unwrap();
    rt.block_on(async {
        let _i = Instance::start(&Options::parse(&text).unwrap(), Settings::default())
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });
}

fn main() {
    if let Some(cfg) = std::env::var_os("SBR_WG_CLIENT") {
        let threads = std::env::var("SBR_WG_THREADS")
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        return client_main(cfg.to_str().unwrap(), threads);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(bench());
}

async fn bench() {
    let args: Vec<String> = std::env::args().collect();
    let bin = args
        .get(1)
        .expect("usage: wg_throughput /path/to/sing-box [streams] [seconds] [runs]")
        .clone();
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
    let runs: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);
    let threads: Vec<usize> = std::env::var("SBR_BENCH_THREADS")
        .unwrap_or_else(|_| "0".into())
        .split(',')
        .map(|t| t.trim().parse().unwrap())
        .collect();
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
    let client_cfg = write_config("client", &client);
    println!("WireGuard via a sing-box peer, {n} stream(s), {secs}s per direction, {runs} run(s)");
    println!(
        "  {:<10} {:>8} {:>9}   {:>8} {:>9}",
        "client", "up Gb/s", "up s/GB", "dn Gb/s", "dn s/GB"
    );

    let mut cores: Vec<(String, Option<usize>)> = threads.iter().map(|t| (format!("sbr-t{t}"), Some(*t))).collect();
    if std::env::var_os("SBR_BENCH_ONLY").is_none() {
        cores.push(("sing-box".into(), None));
    }
    let mut results: Vec<Vec<Sample>> = cores.iter().map(|_| Vec::new()).collect();
    for _ in 0..runs {
        for (i, (name, threads)) in cores.iter().enumerate() {
            let mut child = match threads {
                Some(t) => Command::new(std::env::current_exe().unwrap())
                    .env("SBR_WG_CLIENT", &client_cfg)
                    .env("SBR_WG_THREADS", t.to_string())
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap(),
                None => spawn_sing_box(&bin, "client", &client),
            };
            wait_tcp(client_port).await;
            let pid = child.id();
            let up = one_direction(pid, client_port, n, secs, sink.port(), true).await;
            let down = one_direction(pid, client_port, n, secs, source.port(), false).await;
            println!(
                "  {name:<10} {:>8.2} {:>9.2}   {:>8.2} {:>9.2}",
                up.0, up.1, down.0, down.1
            );
            results[i].push(Sample { up, down });
            child.kill().unwrap();
            child.wait().unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
    if runs > 1 {
        println!("  min-max over {runs} runs:");
        let range = |v: &mut dyn Iterator<Item = f64>| {
            let (lo, hi) = v.fold((f64::MAX, f64::MIN), |(lo, hi), x| (lo.min(x), hi.max(x)));
            format!("{lo:.2}-{hi:.2}")
        };
        for ((name, _), r) in cores.iter().zip(&results) {
            println!(
                "  {name:<10} up {} Gb/s, {} s/GB   down {} Gb/s, {} s/GB",
                range(&mut r.iter().map(|s| s.up.0)),
                range(&mut r.iter().map(|s| s.up.1)),
                range(&mut r.iter().map(|s| s.down.0)),
                range(&mut r.iter().map(|s| s.down.1)),
            );
        }
    }
    server.kill().unwrap();
    server.wait().unwrap();
}
