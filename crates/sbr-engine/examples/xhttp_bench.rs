//! XHTTP throughput against plain VLESS + REALITY + Vision, both served by
//! one Xray-core process on loopback, with sbr as the client in-process.
//!
//!     cargo run --release -p sbr-engine --example xhttp_bench -- <xray> [streams] [seconds] [rounds]
//!
//! Each round measures every path back to back, upload then download. The
//! traffic inside the tunnel is plain TCP, so Vision pads the first packets
//! and then forwards inside REALITY's TLS like any other VLESS stream.
//! Client CPU is this process's user+system time over the measured interval.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sbr_engine::sbr_config::Options;
use sbr_engine::sbr_core::{Destination, Outbound};
use sbr_engine::{Engine, Settings};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "6f1c2a8e-0b7d-4c55-9e3a-2d4b8f9a1c70";
const SNI: &str = "www.example.com";
const SHORT_ID: &str = "a1b2c3d4e5f60718";

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn cpu_secs() -> f64 {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
    t(u.ru_utime) + t(u.ru_stime)
}

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Up,
    Down,
}

async fn target(dir: Dir, total: Arc<AtomicU64>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let total = total.clone();
            tokio::spawn(async move {
                let mut buf = vec![0x5au8; 256 * 1024];
                match dir {
                    Dir::Up => {
                        while let Ok(n) = s.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            total.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                    Dir::Down => while s.write_all(&buf[..64 * 1024]).await.is_ok() {},
                }
            });
        }
    });
    a
}

/// Returns (Gbit/s, client CPU seconds per GB).
async fn measure(out: &Arc<dyn Outbound>, n: usize, secs: u64, dir: Dir) -> (f64, f64) {
    let up_total = Arc::new(AtomicU64::new(0));
    let down_total = Arc::new(AtomicU64::new(0));
    let t = target(dir, up_total.clone()).await;
    let warm = Instant::now() + Duration::from_secs(1);
    let deadline = warm + Duration::from_secs(secs);
    let mut tasks = Vec::new();
    for _ in 0..n {
        let mut s = out.connect(&Destination::from(t)).await.expect("connect");
        let down = down_total.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0xa5u8; 256 * 1024];
            // Dir::Down: the target only writes once it has the VLESS request.
            if dir == Dir::Down && s.write_all(b"go").await.is_err() {
                return;
            }
            while Instant::now() < deadline {
                match dir {
                    Dir::Up => {
                        if s.write_all(&buf[..64 * 1024]).await.is_err() {
                            break;
                        }
                    }
                    Dir::Down => match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            down.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    },
                }
            }
        }));
    }
    let bytes = || match dir {
        Dir::Up => up_total.load(Ordering::Relaxed),
        Dir::Down => down_total.load(Ordering::Relaxed),
    };
    tokio::time::sleep_until(warm.into()).await;
    let (b0, c0, t0) = (bytes(), cpu_secs(), Instant::now());
    tokio::time::sleep_until(deadline.into()).await;
    let (b1, c1, t1) = (bytes(), cpu_secs(), Instant::now());
    for t in tasks {
        t.abort();
    }
    let gb = (b1 - b0) as f64 / 1e9;
    (gb * 8.0 / (t1 - t0).as_secs_f64(), (c1 - c0) / gb.max(1e-9))
}

fn x25519(bin: &str) -> (String, String) {
    let out = Command::new(bin).arg("x25519").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let field = |pred: &dyn Fn(&str) -> bool| {
        text.lines()
            .find(|l| pred(&l.to_ascii_lowercase()))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap()
    };
    (field(&|l| l.starts_with("private")), field(&|l| l.contains("public")))
}

async fn dest() -> SocketAddr {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let ck = rcgen::generate_simple_self_signed(vec![SNI.into()]).unwrap();
    let certs = CertificateDer::pem_slice_iter(ck.cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(ck.signing_key.serialize_pem().as_bytes()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut t) = acceptor.accept(s).await {
                    let mut b = [0u8; 4096];
                    while matches!(t.read(&mut b).await, Ok(n) if n > 0) {}
                }
            });
        }
    });
    a
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(bench(args));
}

async fn bench(args: Vec<String>) {
    let xray = args
        .get(1)
        .expect("usage: xhttp_bench <xray> [streams] [seconds] [rounds]")
        .clone();
    let n: usize = args.get(2).map_or(4, |s| s.parse().unwrap());
    let secs: u64 = args.get(3).map_or(5, |s| s.parse().unwrap());
    let rounds: usize = args.get(4).map_or(3, |s| s.parse().unwrap());
    let (private, public) = x25519(&xray);
    let dest = dest().await;
    let (vision_port, xhttp_port) = (free_port(), free_port());
    let reality = json!({
        "dest": dest.to_string(), "serverNames": [SNI], "privateKey": private, "shortIds": [SHORT_ID],
    });
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": vision_port, "protocol": "vless",
             "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": reality}},
            {"listen": "127.0.0.1", "port": xhttp_port, "protocol": "vless",
             "settings": {"clients": [{"id": UUID}], "decryption": "none"},
             "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/xh"},
                                "security": "reality", "realitySettings": reality}},
        ],
        "outbounds": [{"protocol": "freedom",
                       "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}],
    });
    let dir = std::env::temp_dir().join(format!("sbr-xhttp-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("xray.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let _xray = Kill(
        Command::new(&xray)
            .args(["run", "-c"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for port in [vision_port, xhttp_port] {
        for _ in 0..400 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    let tls = json!({
        "enabled": true, "server_name": SNI,
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {"enabled": true, "public_key": public, "short_id": SHORT_ID},
    });
    let vless = |tag: &str, port: u16, extra: Value| {
        let mut o = json!({
            "type": "vless", "tag": tag, "server": "127.0.0.1", "server_port": port, "uuid": UUID, "tls": tls,
        });
        for (k, v) in extra.as_object().unwrap() {
            o[k] = v.clone();
        }
        o
    };
    let mut paths = vec![(
        "vision",
        vless("vision", vision_port, json!({"flow": "xtls-rprx-vision"})),
    )];
    for mode in ["stream-one", "stream-up", "packet-up"] {
        paths.push((
            mode,
            vless(
                mode,
                xhttp_port,
                json!({"transport": {"type": "xhttp", "path": "/xh", "mode": mode}}),
            ),
        ));
    }
    let opts =
        Options::from_value(json!({"outbounds": paths.iter().map(|(_, o)| o.clone()).collect::<Vec<_>>()})).unwrap();
    let engine = Engine::new(&opts, &Settings::default()).unwrap();

    println!("{n} streams, {secs} s, {rounds} rounds; Gbit/s (client CPU s/GB)");
    for round in 0..rounds {
        for (tag, _) in &paths {
            let out = engine.outbound(tag).unwrap().clone();
            let (up, upc) = measure(&out, n, secs, Dir::Up).await;
            let (down, downc) = measure(&out, n, secs, Dir::Down).await;
            println!("round {round} {tag:<11} up {up:6.2} ({upc:.2})  down {down:6.2} ({downc:.2})");
        }
    }
}
