//! Interop with a real sing-box server: sing-box runs the trojan / vless /
//! vmess / http inbounds over every transport we claim, sbr is the client.
//! Every case pushes 1 MiB through a TCP echo and back, byte-exact, and
//! (where the protocol carries UDP) a set of datagrams through a UDP echo.
//!
//! Needs a sing-box binary: `$SBR_SINGBOX_BIN` or `$SBR_SING_BOX`, else the
//! path below (REALITY needs one built with `with_utls`). Without one the
//! tests print a note and pass.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PublicKeyData};
use sbr_engine::sbr_config::Options;
use sbr_engine::sbr_core::{Destination, Outbound};
use sbr_engine::{Engine, Settings};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const DEFAULT_BIN: &str =
    "/tmp/claude-0/-home-user-sbr/f8826c5d-a757-5d8c-a19d-5dec2bf91f74/scratchpad/ref/sing-box-bin";
const DEFAULT_UTLS_BIN: &str =
    "/tmp/claude-0/-home-user-sbr/f8826c5d-a757-5d8c-a19d-5dec2bf91f74/scratchpad/ref/sing-box-utls";
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "trojan-password";
const MIB: usize = 1024 * 1024;

fn singbox() -> Option<PathBuf> {
    let p = std::env::var_os("SBR_SINGBOX_BIN")
        .or_else(|| std::env::var_os("SBR_SING_BOX"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BIN));
    if p.exists() {
        Some(p)
    } else {
        eprintln!(
            "note: sing-box binary not found at {}; skipping interop test",
            p.display()
        );
        None
    }
}

struct Pki {
    dir: PathBuf,
    ca_pem: String,
    cert_path: PathBuf,
    key_path: PathBuf,
    leaf_sha256: String,
    spki_sha256: String,
    client_cert_path: PathBuf,
    client_key_path: PathBuf,
}

fn b64sha256(b: &[u8]) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b);
    base64::engine::general_purpose::STANDARD.encode(d.as_ref())
}

fn pki(name: &str) -> Pki {
    let dir = std::env::temp_dir().join(format!("sbr-singbox-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["example.com".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client = CertificateParams::new(vec!["client".to_owned()])
        .unwrap()
        .signed_by(&client_key, &issuer)
        .unwrap();

    let write = |n: &str, s: &str| {
        let p = dir.join(n);
        std::fs::write(&p, s).unwrap();
        p
    };
    write("ca.pem", &ca.pem());
    Pki {
        ca_pem: ca.pem(),
        cert_path: write("cert.pem", &leaf.pem()),
        key_path: write("key.pem", &leaf_key.serialize_pem()),
        leaf_sha256: b64sha256(leaf.der()),
        spki_sha256: b64sha256(&leaf_key.subject_public_key_info()),
        client_cert_path: write("client.pem", &client.pem()),
        client_key_path: write("client-key.pem", &client_key.serialize_pem()),
        dir,
    }
}

impl Pki {
    fn server_tls(&self) -> Value {
        json!({
            "enabled": true,
            "server_name": "example.com",
            "certificate_path": self.cert_path,
            "key_path": self.key_path,
        })
    }
    fn client_tls(&self) -> Value {
        json!({
            "enabled": true,
            "server_name": "example.com",
            "certificate": self.ca_pem.lines().collect::<Vec<_>>(),
        })
    }
}

struct SingBox(Child);

impl Drop for SingBox {
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

async fn start_singbox(bin: &Path, dir: &Path, inbounds: Vec<Value>) -> SingBox {
    try_start_singbox(bin, dir, inbounds)
        .await
        .expect("sing-box failed to start")
}

/// `None` if sing-box exits or doesn't listen (e.g. a port picked by
/// `free_port` was taken by a parallel test in the meantime).
async fn try_start_singbox(bin: &Path, dir: &Path, inbounds: Vec<Value>) -> Option<SingBox> {
    let ports: Vec<u16> = inbounds
        .iter()
        .map(|i| i["listen_port"].as_u64().unwrap() as u16)
        .collect();
    let cfg = json!({
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "outbounds": [{"type": "direct"}],
    });
    let path = dir.join(format!("server-{}.json", ports[0]));
    std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    let child = Command::new(bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut sb = SingBox(child);
    for p in ports {
        let mut ok = false;
        for _ in 0..200 {
            if sb.0.try_wait().ok().flatten().is_some() {
                return None;
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", p)).await.is_ok() {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if !ok {
            return None;
        }
    }
    // Still running: it owns the ports, not some other process.
    tokio::time::sleep(Duration::from_millis(50)).await;
    sb.0.try_wait().ok().flatten().is_none().then_some(sb)
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    a
}

async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) = s.recv_from(&mut buf).await.unwrap();
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    a
}

fn pattern(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Push `size` bytes through and compare what comes back.
async fn tcp_roundtrip(out: &Arc<dyn Outbound>, echo: SocketAddr, size: usize) -> Result<(), String> {
    let s = out
        .connect(&Destination::from(echo))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (mut r, mut w) = tokio::io::split(s);
    let data = Arc::new(pattern(size, size as u64 + 7));
    let d = data.clone();
    let writer = tokio::spawn(async move {
        // Varied write sizes exercise the framings' edges.
        let sizes = [1usize, 100, 16 * 1024, 64 * 1024, 3000, 15000, 15001, 40000];
        let mut off = 0;
        let mut i = 0;
        while off < d.len() {
            let n = sizes[i % sizes.len()].min(d.len() - off);
            w.write_all(&d[off..off + n]).await?;
            off += n;
            i += 1;
        }
        w.flush().await?;
        Ok::<_, std::io::Error>(w)
    });
    let mut got = vec![0u8; size];
    tokio::time::timeout(Duration::from_secs(30), r.read_exact(&mut got))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|e| format!("read: {e}"))?;
    let _w = writer.await.unwrap().map_err(|e| format!("write: {e}"))?;
    if got != *data {
        let first = got.iter().zip(data.iter()).position(|(a, b)| a != b);
        return Err(format!("data mismatch at {first:?}"));
    }
    Ok(())
}

async fn udp_roundtrip(out: &Arc<dyn Outbound>, echo: SocketAddr) -> Result<(), String> {
    let dest = Destination::from(echo);
    let c = out.connect_udp(&dest).await.map_err(|e| format!("udp connect: {e}"))?;
    let mut buf = vec![0u8; 65536];
    for (i, size) in [1usize, 64, 512, 1200, 1400, 4096, 8000, 1, 1300]
        .into_iter()
        .enumerate()
    {
        let p = pattern(size, i as u64 + 99);
        c.send_to(&p, &dest).await.map_err(|e| format!("udp send: {e}"))?;
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), c.recv_from(&mut buf))
            .await
            .map_err(|_| format!("udp recv timed out (packet {i}, {size} bytes)"))?
            .map_err(|e| format!("udp recv: {e}"))?;
        if buf[..n] != p[..] {
            return Err(format!("udp packet {i} mismatch ({n} vs {size} bytes)"));
        }
        if from.port != echo.port() {
            return Err(format!("udp reply from {from}, expected {echo}"));
        }
    }
    Ok(())
}

struct Case {
    name: String,
    inbound: Value,
    outbound: Value,
    udp: bool,
}

/// Run every case against one sing-box process.
async fn run(name: &str, build: impl FnOnce(&Pki) -> Vec<Case>) {
    let Some(bin) = singbox() else { return };
    let pki = pki(name);
    let mut cases = build(&pki);
    let mut outbounds = Vec::new();
    let mut sb = None;
    for _attempt in 0..3 {
        let mut inbounds = Vec::new();
        outbounds.clear();
        for c in &mut cases {
            let port = free_port();
            c.inbound["listen"] = json!("127.0.0.1");
            c.inbound["listen_port"] = json!(port);
            c.outbound["tag"] = json!(c.name);
            c.outbound["server"] = json!("127.0.0.1");
            c.outbound["server_port"] = json!(port);
            inbounds.push(c.inbound.clone());
            outbounds.push(c.outbound.clone());
        }
        sb = try_start_singbox(&bin, &pki.dir, inbounds).await;
        if sb.is_some() {
            break;
        }
    }
    let _sb = sb.expect("sing-box failed to start");
    let opts = Options::from_value(json!({ "outbounds": outbounds })).unwrap();
    let engine = Engine::new(&opts, &Settings::default()).unwrap();
    let (techo, uecho) = (tcp_echo().await, udp_echo().await);

    let mut failures = Vec::new();
    for c in &cases {
        let out = engine.outbound(&c.name).unwrap().clone();
        let started = std::time::Instant::now();
        let mut r = tcp_roundtrip(&out, techo, MIB).await;
        if r.is_ok() {
            // A second connection: pooled transports (gRPC/HTTP2) reuse theirs.
            r = tcp_roundtrip(&out, techo, 64 * 1024).await;
        }
        if r.is_ok() && c.udp {
            r = udp_roundtrip(&out, uecho).await;
        }
        match r {
            Ok(()) => eprintln!("ok   {:<40} {:>6} ms", c.name, started.elapsed().as_millis()),
            Err(e) => {
                eprintln!("FAIL {:<40} {e}", c.name);
                failures.push(format!("{}: {e}", c.name));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&pki.dir);
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
}

/// The transports to cross with each protocol: (name, transport, tls).
fn transports() -> Vec<(&'static str, Option<Value>, bool)> {
    vec![
        ("tcp", None, false),
        ("tls", None, true),
        ("ws", Some(json!({"type": "ws", "path": "/ws"})), false),
        ("ws-tls", Some(json!({"type": "ws", "path": "/ws"})), true),
        (
            "ws-ed-path",
            Some(json!({"type": "ws", "path": "/ed", "max_early_data": 2048})),
            true,
        ),
        (
            "ws-ed-header",
            Some(
                json!({"type": "ws", "path": "/ed", "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}),
            ),
            false,
        ),
        (
            "httpupgrade",
            Some(json!({"type": "httpupgrade", "path": "/up", "host": "example.com"})),
            false,
        ),
        (
            "httpupgrade-tls",
            Some(json!({"type": "httpupgrade", "path": "/up"})),
            true,
        ),
        (
            "grpc",
            Some(json!({"type": "grpc", "service_name": "TunService"})),
            false,
        ),
        (
            "grpc-tls",
            Some(json!({"type": "grpc", "service_name": "TunService"})),
            true,
        ),
        (
            "http",
            Some(json!({"type": "http", "path": "/h", "host": ["example.com"]})),
            false,
        ),
        (
            "http-tls",
            Some(json!({"type": "http", "path": "/h", "host": ["example.com"]})),
            true,
        ),
    ]
}

fn cross(pki: &Pki, proto: &str, inbound: Value, outbound: Value, udp: bool) -> Vec<Case> {
    transports()
        .into_iter()
        // sing-box's httpupgrade server flushes `101` before hijacking, and
        // Go's HTTP server may have read ahead a byte by then; its trojan
        // server then rejects the short first read ("bad request size").
        // A server-side race, independent of the client.
        .filter(|(t, _, _)| !(proto == "trojan" && t.starts_with("httpupgrade")))
        .map(|(tname, transport, tls)| {
            let mut i = inbound.clone();
            let mut o = outbound.clone();
            if let Some(t) = &transport {
                i["transport"] = t.clone();
                o["transport"] = t.clone();
            }
            if tls {
                i["tls"] = pki.server_tls();
                o["tls"] = pki.client_tls();
            }
            Case {
                name: format!("{proto}-{tname}"),
                inbound: i,
                outbound: o,
                udp,
            }
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_interop() {
    run("trojan", |pki| {
        cross(
            pki,
            "trojan",
            json!({"type": "trojan", "users": [{"password": PASSWORD}]}),
            json!({"type": "trojan", "password": PASSWORD}),
            true,
        )
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_interop() {
    run("vless", |pki| {
        let mut cases = cross(
            pki,
            "vless",
            json!({"type": "vless", "users": [{"uuid": UUID}]}),
            json!({"type": "vless", "uuid": UUID}),
            true,
        );
        // Plain VLESS UDP (no XUDP).
        cases.push(Case {
            name: "vless-tls-udp-plain".into(),
            inbound: json!({"type": "vless", "users": [{"uuid": UUID}], "tls": pki.server_tls()}),
            outbound: json!({"type": "vless", "uuid": UUID, "packet_encoding": "", "tls": pki.client_tls()}),
            udp: true,
        });
        cases
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vmess_interop() {
    run("vmess", |pki| {
        let inbound = json!({"type": "vmess", "users": [{"uuid": UUID, "alterId": 0}]});
        let mut cases = cross(
            pki,
            "vmess",
            inbound.clone(),
            json!({"type": "vmess", "uuid": UUID, "security": "aes-128-gcm"}),
            true,
        );
        for (name, extra) in [
            ("vmess-chacha", json!({"security": "chacha20-poly1305"})),
            ("vmess-none", json!({"security": "none"})),
            ("vmess-zero", json!({"security": "zero"})),
            ("vmess-auto", json!({"security": "auto"})),
            (
                "vmess-padding",
                json!({"security": "aes-128-gcm", "global_padding": true}),
            ),
            (
                "vmess-authlen",
                json!({"security": "aes-128-gcm", "authenticated_length": true}),
            ),
            (
                "vmess-chacha-pad-authlen",
                json!({"security": "chacha20-poly1305", "global_padding": true, "authenticated_length": true}),
            ),
            (
                "vmess-xudp",
                json!({"security": "aes-128-gcm", "packet_encoding": "xudp"}),
            ),
        ] {
            let mut o = json!({"type": "vmess", "uuid": UUID});
            for (k, v) in extra.as_object().unwrap() {
                o[k] = v.clone();
            }
            cases.push(Case {
                name: name.into(),
                inbound: inbound.clone(),
                outbound: o,
                udp: true,
            });
        }
        cases
    })
    .await;
}

/// Vision with TLS inside the tunnel: exercises padding and the switch to
/// direct (raw) mode in both directions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_vision_interop() {
    let Some(bin) = singbox() else { return };
    let pki = pki("vision");
    let port = free_port();
    let inbound = json!({
        "type": "vless", "listen": "127.0.0.1", "listen_port": port,
        "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}],
        "tls": pki.server_tls(),
    });
    let _sb = start_singbox(&bin, &pki.dir, vec![inbound]).await;
    vision_checks(&pki, port, pki.client_tls()).await;
    let _ = std::fs::remove_dir_all(&pki.dir);
}

/// Plain, XUDP and inner-TLS (direct mode) traffic through VLESS Vision.
async fn vision_checks(pki: &Pki, port: u16, tls: Value) {
    let opts = Options::from_value(json!({"outbounds": [{
        "type": "vless", "tag": "vision", "server": "127.0.0.1", "server_port": port,
        "uuid": UUID, "flow": "xtls-rprx-vision", "tls": tls,
    }]}))
    .unwrap();
    let engine = Engine::new(&opts, &Settings::default()).unwrap();
    let out = engine.outbound("vision").unwrap().clone();

    // Plain bytes inside: padding only, never direct.
    tcp_roundtrip(&out, tcp_echo().await, MIB).await.unwrap();
    // XUDP over Vision.
    udp_roundtrip(&out, udp_echo().await).await.unwrap();
    inner_tls_roundtrips(&out, pki).await;
}

async fn inner_tls_roundtrips(out: &Arc<dyn Outbound>, pki: &Pki) {
    // TLS 1.3 inside: goes direct after the inner handshake.
    let inner = inner_tls_echo(pki).await;
    for size in [MIB, 100, 20000] {
        let s = out.connect(&Destination::from(inner)).await.unwrap();
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(
            rustls::pki_types::CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes()).map(|c| c.unwrap()),
        );
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect("example.com".try_into().unwrap(), s)
            .await
            .unwrap();
        let (mut r, mut w) = tokio::io::split(tls);
        let data = pattern(size, 5);
        let d2 = data.clone();
        let wt = tokio::spawn(async move {
            for c in d2.chunks(7000) {
                w.write_all(c).await.unwrap();
            }
            w.flush().await.unwrap();
            w
        });
        let mut got = vec![0u8; size];
        tokio::time::timeout(Duration::from_secs(30), r.read_exact(&mut got))
            .await
            .expect("vision inner TLS read timed out")
            .unwrap();
        let _w = wt.await.unwrap();
        assert!(got == data, "vision inner TLS data mismatch ({size} bytes)");
    }
}

fn singbox_utls() -> Option<PathBuf> {
    let p = std::env::var_os("SBR_SINGBOX_UTLS_BIN")
        .or_else(|| std::env::var_os("SBR_SING_BOX"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_UTLS_BIN));
    if p.exists() {
        Some(p)
    } else {
        eprintln!(
            "note: sing-box (with_utls) not found at {}; skipping REALITY test",
            p.display()
        );
        None
    }
}

/// VLESS over REALITY, with and without Vision. The REALITY "cover" site is
/// a local TLS 1.3 server: nothing leaves the machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_reality_interop() {
    let Some(bin) = singbox_utls() else { return };
    let pki = pki("reality");
    let keys = Command::new(&bin)
        .args(["generate", "reality-keypair"])
        .output()
        .unwrap();
    let keys = String::from_utf8(keys.stdout).unwrap();
    let field = |k: &str| {
        keys.lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim().to_owned())
            .unwrap()
    };
    let (private_key, public_key) = (field("PrivateKey:"), field("PublicKey:"));
    let cover = inner_tls_echo(&pki).await;
    let short_id = "0123abcd";
    let server_tls = json!({
        "enabled": true, "server_name": "example.com",
        "reality": {"enabled": true, "handshake": {"server": "127.0.0.1", "server_port": cover.port()},
                    "private_key": private_key, "short_id": [short_id], "max_time_difference": "1m"},
    });
    let client_tls = |fp: &str| {
        json!({
            "enabled": true, "server_name": "example.com",
            "utls": {"enabled": true, "fingerprint": fp},
            "reality": {"enabled": true, "public_key": public_key, "short_id": short_id},
        })
    };
    let (plain_port, vision_port) = (free_port(), free_port());
    let inbounds = vec![
        json!({"type": "vless", "listen": "127.0.0.1", "listen_port": plain_port,
               "users": [{"uuid": UUID}], "tls": server_tls.clone()}),
        json!({"type": "vless", "listen": "127.0.0.1", "listen_port": vision_port,
               "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}], "tls": server_tls}),
    ];
    let _sb = start_singbox(&bin, &pki.dir, inbounds).await;

    for fp in ["chrome", "firefox", "safari"] {
        let opts = Options::from_value(json!({"outbounds": [{
            "type": "vless", "tag": "reality", "server": "127.0.0.1", "server_port": plain_port,
            "uuid": UUID, "tls": client_tls(fp),
        }]}))
        .unwrap();
        let engine = Engine::new(&opts, &Settings::default()).unwrap();
        let out = engine.outbound("reality").unwrap().clone();
        tcp_roundtrip(&out, tcp_echo().await, MIB)
            .await
            .unwrap_or_else(|e| panic!("reality {fp}: {e}"));
        udp_roundtrip(&out, udp_echo().await)
            .await
            .unwrap_or_else(|e| panic!("reality {fp} udp: {e}"));
    }
    vision_checks(&pki, vision_port, client_tls("chrome")).await;
    let _ = std::fs::remove_dir_all(&pki.dir);
}

/// TLS 1.3 echo server for traffic inside the tunnel.
async fn inner_tls_echo(pki: &Pki) -> SocketAddr {
    use rustls::pki_types::pem::PemObject;
    let certs = rustls::pki_types::CertificateDer::pem_file_iter(&pki.cert_path)
        .unwrap()
        .map(|c| c.unwrap())
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&pki.key_path).unwrap();
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
                let Ok(tls) = acceptor.accept(s).await else { return };
                let (mut r, mut w) = tokio::io::split(tls);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    a
}

/// TLS client options against sing-box: pinning, client certs, version
/// caps, uTLS, ClientHello fragmentation, ECH, and the HTTP proxy over TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_options_interop() {
    let ech = singbox().and_then(|bin| {
        let out = Command::new(bin)
            .args(["generate", "ech-keypair", "example.com"])
            .output()
            .ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        let split = text.find("-----BEGIN ECH KEYS-----")?;
        Some((text[..split].to_owned(), text[split..].to_owned()))
    });
    run("tlsopts", move |pki| {
        let trojan_in = json!({"type": "trojan", "users": [{"password": PASSWORD}], "tls": pki.server_tls()});
        let trojan_out = |tls: Value| json!({"type": "trojan", "password": PASSWORD, "tls": tls});
        let tls_with = |extra: Value| {
            let mut t = pki.client_tls();
            for (k, v) in extra.as_object().unwrap() {
                t[k] = v.clone();
            }
            t
        };
        let mut cases = vec![
            Case {
                name: "tls-pin-cert".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(json!({"enabled": true, "server_name": "example.com", "certificate_sha256": [pki.leaf_sha256]})),
                udp: false,
            },
            Case {
                name: "tls-pin-pubkey".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(json!({"enabled": true, "server_name": "example.com", "certificate_public_key_sha256": [pki.spki_sha256]})),
                udp: false,
            },
            Case {
                name: "tls-insecure".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(json!({"enabled": true, "insecure": true})),
                udp: false,
            },
            Case {
                name: "tls-max-1.2".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(tls_with(json!({"max_version": "1.2"}))),
                udp: false,
            },
            Case {
                name: "tls-utls-alpn".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(tls_with(json!({"utls": {"enabled": true, "fingerprint": "chrome"}}))),
                udp: false,
            },
            Case {
                name: "tls-disable-sni".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(tls_with(json!({"disable_sni": true}))),
                udp: false,
            },
            Case {
                name: "tls-fragment".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(tls_with(json!({"fragment": true, "fragment_fallback_delay": "5ms"}))),
                udp: false,
            },
            Case {
                name: "tls-record-fragment".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(tls_with(json!({"record_fragment": true}))),
                udp: false,
            },
            Case {
                name: "tls-both-fragment".into(),
                inbound: trojan_in.clone(),
                outbound: trojan_out(tls_with(json!({"fragment": true, "record_fragment": true, "fragment_fallback_delay": "5ms"}))),
                udp: false,
            },
            Case {
                name: "tls-client-cert".into(),
                inbound: {
                    let mut i = trojan_in.clone();
                    i["tls"]["client_authentication"] = json!("require-and-verify");
                    i["tls"]["client_certificate_path"] = json!(pki.dir.join("ca.pem"));
                    i
                },
                outbound: trojan_out(tls_with(json!({
                    "client_certificate_path": pki.client_cert_path,
                    "client_key_path": pki.client_key_path,
                }))),
                udp: false,
            },
            Case {
                name: "http-proxy-tls".into(),
                inbound: json!({"type": "http", "users": [{"username": "u", "password": "p"}], "tls": pki.server_tls()}),
                outbound: json!({"type": "http", "username": "u", "password": "p", "tls": pki.client_tls()}),
                udp: false,
            },
        ];
        if let Some((config, keys)) = &ech {
            let mut i = trojan_in.clone();
            i["tls"]["ech"] = json!({"enabled": true, "key": keys.lines().collect::<Vec<_>>()});
            cases.push(Case {
                name: "tls-ech".into(),
                inbound: i,
                outbound: trojan_out(tls_with(json!({"ech": {"enabled": true, "config": config.lines().collect::<Vec<_>>()}}))),
                udp: false,
            });
        }
        cases
    })
    .await;
}
