//! hysteria2 client throughput and CPU: sbr vs sing-box, same server.
//!
//!     cargo run --release -p sbr-engine --example quic_throughput -- /path/to/sing-box [streams] [seconds]
//!
//! sing-box (built with `-tags with_quic`) runs the hysteria2 server. Each
//! client runs as its own process from **the same config file** (socks in,
//! hysteria2 out): sing-box itself, and this example re-executed as an sbr
//! instance. Upload goes client -> socks -> hysteria2 -> server -> sink, and
//! throughput is what the sink receives. CPU is user+system time from
//! `/proc/<pid>/stat` over the measured interval.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn sink(total: Arc<AtomicU64>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let total = total.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 256 * 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    total.fetch_add(n as u64, Ordering::Relaxed);
                }
            });
        }
    });
    a
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

/// utime + stime in seconds (USER_HZ is 100 on Linux).
fn cpu_secs(pid: u32) -> f64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    // Fields after the parenthesised comm; utime/stime are 14th/15th overall.
    let rest = &stat[stat.rfind(')').unwrap() + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    (f[11].parse::<f64>().unwrap() + f[12].parse::<f64>().unwrap()) / 100.0
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_tcp(port: u16) {
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("client on {port} did not come up");
}

struct Result {
    gbps: f64,
    client_cpu: f64,
    server_cpu: f64,
}

async fn run(
    client_pid: u32,
    server_pid: u32,
    port: u16,
    n: usize,
    secs: u64,
    target: SocketAddr,
    total: &AtomicU64,
) -> Result {
    wait_tcp(port).await;
    let mut streams = Vec::new();
    for _ in 0..n {
        streams.push(socks(port, target).await);
    }
    // Warm-up: let the congestion controller open up before measuring.
    let warm = Instant::now() + Duration::from_secs(1);
    let deadline = warm + Duration::from_secs(secs);
    let tasks: Vec<_> = streams
        .into_iter()
        .map(|mut s| {
            tokio::spawn(async move {
                let buf = vec![0xa5u8; 64 * 1024];
                while Instant::now() < deadline {
                    if s.write_all(&buf).await.is_err() {
                        break;
                    }
                }
            })
        })
        .collect();
    tokio::time::sleep_until(warm.into()).await;
    let (b0, c0, s0, t0) = (
        total.load(Ordering::Relaxed),
        cpu_secs(client_pid),
        cpu_secs(server_pid),
        Instant::now(),
    );
    tokio::time::sleep_until(deadline.into()).await;
    let (b1, c1, s1, t1) = (
        total.load(Ordering::Relaxed),
        cpu_secs(client_pid),
        cpu_secs(server_pid),
        Instant::now(),
    );
    for t in tasks {
        let _ = t.await;
    }
    Result {
        gbps: (b1 - b0) as f64 * 8.0 / (t1 - t0).as_secs_f64() / 1e9,
        client_cpu: c1 - c0,
        server_cpu: s1 - s0,
    }
}

fn sbr_client(config: &str) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let o = sbr_engine::sbr_config::Options::parse(&std::fs::read_to_string(config).unwrap()).unwrap();
        let _i = sbr_engine::Instance::start(&o, sbr_engine::Settings::default())
            .await
            .unwrap();
        std::future::pending::<()>().await
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--sbr-client") {
        return sbr_client(&args[2]);
    }
    tokio::runtime::Runtime::new().unwrap().block_on(bench(args));
}

async fn bench(args: Vec<String>) {
    let Some(sing_box) = args.get(1).cloned() else {
        eprintln!("usage: quic_throughput /path/to/sing-box [streams] [seconds]");
        std::process::exit(2);
    };
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);

    let dir = std::env::temp_dir().join(format!("sbr-quic-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();

    let total = Arc::new(AtomicU64::new(0));
    let target = sink(total.clone()).await;
    let hy_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server_cfg = dir.join("server.json");
    std::fs::write(
        &server_cfg,
        format!(
            r#"{{"log":{{"level":"error"}},
            "inbounds":[{{"type":"hysteria2","listen":"127.0.0.1","listen_port":{hy_port},"users":[{{"password":"bench"}}],
                "tls":{{"enabled":true,"alpn":["h3"],"certificate_path":{cert:?},"key_path":{key:?}}}}}],
            "outbounds":[{{"type":"direct"}}]}}"#
        ),
    )
    .unwrap();
    let server = Kill(
        Command::new(&sing_box)
            .args(["run", "-c"])
            .arg(&server_cfg)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    let socks_port = free_port();
    let client_cfg = dir.join("client.json");
    std::fs::write(
        &client_cfg,
        format!(
            r#"{{"log":{{"level":"error"}},
            "inbounds":[{{"type":"mixed","listen":"127.0.0.1","listen_port":{socks_port}}}],
            "outbounds":[{{"type":"hysteria2","tag":"hy2","server":"127.0.0.1","server_port":{hy_port},"password":"bench",
                "tls":{{"enabled":true,"server_name":"localhost","certificate":{}}}}}]}}"#,
            serde_json::to_string(&ck.cert.pem()).unwrap()
        ),
    )
    .unwrap();

    println!("hysteria2 upload, {n} streams x {secs}s, loopback, same sing-box server");
    println!("  client     throughput   client CPU   server CPU   client CPU-s per GB");
    let exe = std::env::current_exe().unwrap();
    let clients: [(&str, Command); 2] = [
        ("sbr", {
            let mut c = Command::new(&exe);
            c.arg("--sbr-client").arg(&client_cfg);
            c
        }),
        ("sing-box", {
            let mut c = Command::new(&sing_box);
            c.args(["run", "-c"]).arg(&client_cfg);
            c
        }),
    ];
    for (name, mut cmd) in clients {
        let child = Kill(cmd.stdout(Stdio::null()).spawn().unwrap());
        let r = run(child.0.id(), server.0.id(), socks_port, n, secs, target, &total).await;
        let gb = r.gbps * secs as f64 / 8.0;
        println!(
            "  {name:<9} {:>7.2} Gbit/s   {:>6.2} s     {:>6.2} s     {:>6.2}",
            r.gbps,
            r.client_cpu,
            r.server_cpu,
            r.client_cpu / gb
        );
        drop(child);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}
