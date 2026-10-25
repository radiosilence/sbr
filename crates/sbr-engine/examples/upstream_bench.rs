//! sbr vs sing-box as clients of the servers jaritanet runs, on loopback:
//! Xray-core (VLESS + REALITY + Vision) and apernet hysteria2 (salamander,
//! userpass).
//!
//!     cargo run --release -p sbr-engine --example upstream_bench -- \
//!         <xray> <hysteria> <sing-box> [streams] [seconds] [rounds]
//!
//! Both clients run as their own process from **the same config file**
//! (mixed in, one outbound): sing-box itself, and this example re-executed as
//! an sbr instance. Each round runs sbr then sing-box back to back, for
//! upload and download. Vision is measured with plain inner TCP (padding,
//! then ordinary TLS) and with TLS 1.3 inside (Vision's direct copy, the
//! path HTTPS takes), over REALITY and over plain TLS: sing-box strips
//! X25519MLKEM768 from REALITY ClientHellos, which XTLS/REALITY servers
//! refuse, so the TLS inbound is where the two clients can be compared.
//! Client CPU is `ps` user+system time over the measured interval.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "6f1c2a8e-0b7d-4c55-9e3a-2d4b8f9a1c70";
const SNI: &str = "www.microsoft.com";

fn cpu_secs(pid: u32) -> f64 {
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    // [[dd-]hh:]mm:ss.cc
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let (days, rest) = s
        .split_once('-')
        .map_or((0.0, s.as_str()), |(d, r)| (d.parse().unwrap(), r));
    rest.split(':')
        .fold(0.0, |acc, part| acc * 60.0 + part.parse::<f64>().unwrap_or(0.0))
        + days * 86400.0
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
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
    for _ in 0..400 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("nothing listening on {port}");
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Up,
    Down,
}

/// Sink for uploads, source for downloads; optionally TLS. Counts what
/// the server side receives (upload).
async fn target(dir: Dir, tls: Option<tokio_rustls::TlsAcceptor>, total: Arc<AtomicU64>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let (tls, total) = (tls.clone(), total.clone());
            tokio::spawn(async move {
                let mut s: Box<dyn Io> = match tls {
                    Some(t) => match t.accept(s).await {
                        Ok(t) => Box::new(t),
                        Err(_) => return,
                    },
                    None => Box::new(s),
                };
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

async fn socks(proxy: u16, target: SocketAddr) -> Option<TcpStream> {
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
    s.read_exact(&mut rep).await.ok()?;
    (rep[1] == 0).then_some(s)
}

struct Tls {
    acceptor: tokio_rustls::TlsAcceptor,
    connector: tokio_rustls::TlsConnector,
}

fn inner_tls() -> Tls {
    let ck = rcgen::generate_simple_self_signed(vec!["inner.test".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let certs = CertificateDer::pem_slice_iter(ck.cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(ck.signing_key.serialize_pem().as_bytes()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Tls {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server)),
        connector: tokio_rustls::TlsConnector::from(Arc::new(client)),
    }
}

struct Sample {
    gbps: f64,
    cpu_per_gb: f64,
}

#[allow(clippy::too_many_arguments)]
async fn measure(
    client_pid: u32,
    port: u16,
    n: usize,
    secs: u64,
    dir: Dir,
    target: SocketAddr,
    tls: Option<&tokio_rustls::TlsConnector>,
    up_total: &AtomicU64,
) -> Option<Sample> {
    wait_tcp(port).await;
    let down_total = Arc::new(AtomicU64::new(0));
    let warm = Instant::now() + Duration::from_secs(1);
    let deadline = warm + Duration::from_secs(secs);
    let mut tasks = Vec::new();
    for _ in 0..n {
        let s = socks(port, target).await?;
        let mut s: Box<dyn Io> = match tls {
            Some(c) => Box::new(c.connect(ServerName::try_from("inner.test").unwrap(), s).await.unwrap()),
            None => Box::new(s),
        };
        let down = down_total.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0xa5u8; 256 * 1024];
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
    let (b0, c0, t0) = (bytes(), cpu_secs(client_pid), Instant::now());
    tokio::time::sleep_until(deadline.into()).await;
    let (b1, c1, t1) = (bytes(), cpu_secs(client_pid), Instant::now());
    for t in tasks {
        t.abort();
    }
    let gb = (b1 - b0) as f64 / 1e9;
    Some(Sample {
        gbps: gb * 8.0 / (t1 - t0).as_secs_f64(),
        cpu_per_gb: (c1 - c0) / gb,
    })
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

fn xray_keys(bin: &str) -> (String, String) {
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

/// A dest that answers nothing useful: Xray only needs it to complete its
/// handshake probes, and no client here is unauthenticated.
async fn dest() -> SocketAddr {
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

/// Xray with two VLESS + Vision inbounds: REALITY (jaritanet's) and plain
/// TLS with a pinned certificate, the same Vision path for clients whose
/// REALITY the server refuses. Returns both client outbounds.
async fn start_xray(bin: &str, dir: &Path) -> (Kill, String, String) {
    let (private_key, public_key) = xray_keys(bin);
    let dest = dest().await;
    let port = free_port();
    let tls_port = free_port();
    let ck = rcgen::generate_simple_self_signed(vec!["vision.test".into()]).unwrap();
    let (cert, key) = (dir.join("xray-cert.pem"), dir.join("xray-key.pem"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
    let cfg = serde_json::json!({
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": tls_port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID, "email": "admin", "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                "certificates": [{"certificateFile": cert, "keyFile": key}]}},
        }, {
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID, "email": "admin", "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "show": false, "dest": dest.to_string(), "xver": 0, "serverNames": [SNI],
                "privateKey": private_key, "shortIds": ["a1b2c3d4e5f60718"]}},
            "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true},
        }],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"network": "tcp,udp", "outboundTag": "direct"}]},
    });
    let path = dir.join("xray.json");
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let child = Kill(
        Command::new(bin)
            .args(["run", "-c"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_tcp(port).await;
    wait_tcp(tls_port).await;
    let reality = serde_json::json!({
        "type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": port, "uuid": UUID,
        "flow": "xtls-rprx-vision",
        "tls": {"enabled": true, "server_name": SNI, "utls": {"enabled": true, "fingerprint": "chrome"},
                "reality": {"enabled": true, "public_key": public_key, "short_id": "a1b2c3d4e5f60718"}},
    });
    let tls = serde_json::json!({
        "type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": tls_port, "uuid": UUID,
        "flow": "xtls-rprx-vision",
        "tls": {"enabled": true, "server_name": "vision.test", "certificate": ck.cert.pem()},
    });
    (child, reality.to_string(), tls.to_string())
}

async fn start_hysteria(bin: &str, dir: &Path) -> (Kill, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["www.bing.com".into()]).unwrap();
    let (cert, key) = (dir.join("hy-cert.pem"), dir.join("hy-key.pem"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
    let port = free_udp_port();
    let cfg = format!(
        "listen: 127.0.0.1:{port}\ntls:\n  cert: {}\n  key: {}\nobfs:\n  type: salamander\n  salamander:\n    password: obfs-bench\nauth:\n  type: userpass\n  userpass:\n    admin: bench-password\n",
        cert.display(),
        key.display()
    );
    let path = dir.join("hysteria.yaml");
    std::fs::write(&path, cfg).unwrap();
    let child = Kill(
        Command::new(bin)
            .args(["server", "--disable-update-check", "-l", "error", "-c"])
            .arg(&path)
            .env("HYSTERIA_DISABLE_UPDATE_CHECK", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(800)).await;
    let outbound = serde_json::json!({
        "type": "hysteria2", "tag": "proxy", "server": "127.0.0.1", "server_port": port,
        "password": "admin:bench-password", "obfs": {"type": "salamander", "password": "obfs-bench"},
        "tls": {"enabled": true, "server_name": "www.bing.com", "certificate": ck.cert.pem()},
    });
    (child, outbound.to_string())
}

async fn bench(args: Vec<String>) {
    if args.len() < 4 {
        eprintln!("usage: upstream_bench <xray> <hysteria> <sing-box> [streams] [seconds] [rounds]");
        std::process::exit(2);
    }
    let (xray, hysteria, sing_box) = (&args[1], &args[2], &args[3]);
    let n: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(4);
    let secs: u64 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(5);
    let rounds: usize = args.get(6).and_then(|s| s.parse().ok()).unwrap_or(3);

    let dir = std::env::temp_dir().join(format!("sbr-upstream-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (_xray, reality, vless_tls) = start_xray(xray, &dir).await;
    let (_hy, hy2) = start_hysteria(hysteria, &dir).await;
    let tls = inner_tls();
    let exe = std::env::current_exe().unwrap();

    println!("{n} streams x {secs}s, loopback, {rounds} rounds; Gbit/s and client CPU-s per GB (min-max)");
    let cases: [(&str, &str, bool); 5] = [
        ("xray reality+vision, plain", &reality, false),
        ("xray reality+vision, TLS", &reality, true),
        ("xray tls+vision, plain", &vless_tls, false),
        ("xray tls+vision, TLS", &vless_tls, true),
        ("apernet hysteria2", &hy2, false),
    ];
    for (label, outbound, inner) in cases {
        for dir_ in [Dir::Up, Dir::Down] {
            let up_total = Arc::new(AtomicU64::new(0));
            let acceptor = inner.then(|| tls.acceptor.clone());
            let target = target(dir_, acceptor, up_total.clone()).await;
            let mut samples: [Vec<Sample>; 2] = [Vec::new(), Vec::new()];
            for _ in 0..rounds {
                for (i, name) in ["sbr", "sing-box"].into_iter().enumerate() {
                    let port = free_port();
                    let cfg_path = dir.join(format!("client-{port}.json"));
                    std::fs::write(
                        &cfg_path,
                        format!(
                            r#"{{"log":{{"level":"error"}},"inbounds":[{{"type":"mixed","listen":"127.0.0.1","listen_port":{port}}}],"outbounds":[{outbound}]}}"#
                        ),
                    )
                    .unwrap();
                    let mut cmd = if name == "sbr" {
                        let mut c = Command::new(&exe);
                        c.arg("--sbr-client").arg(&cfg_path);
                        c
                    } else {
                        let mut c = Command::new(sing_box);
                        c.args(["run", "-c"]).arg(&cfg_path);
                        c
                    };
                    let child = Kill(cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
                    let connector = inner.then_some(&tls.connector);
                    if let Some(s) = measure(child.0.id(), port, n, secs, dir_, target, connector, &up_total).await {
                        samples[i].push(s);
                    }
                    drop(child);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
            let range = |v: &[Sample], f: fn(&Sample) -> f64| {
                if v.is_empty() {
                    return "refused".to_string();
                }
                let xs: Vec<f64> = v.iter().map(f).collect();
                let (lo, hi) = xs.iter().fold((f64::MAX, f64::MIN), |(a, b), &x| (a.min(x), b.max(x)));
                format!("{lo:.2}-{hi:.2}")
            };
            println!(
                "{label:<26} {:<4}  sbr {:>11} Gbit/s {:>11} s/GB   sing-box {:>11} Gbit/s {:>11} s/GB",
                if dir_ == Dir::Up { "up" } else { "down" },
                range(&samples[0], |s| s.gbps),
                range(&samples[0], |s| s.cpu_per_gb),
                range(&samples[1], |s| s.gbps),
                range(&samples[1], |s| s.cpu_per_gb),
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
