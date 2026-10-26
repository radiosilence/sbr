//! Interop with the server software the user's gateway runs
//! (`radiosilence/jaritanet`, `packages/vpn/src/{xray,hysteria,singbox}.ts`),
//! as opposed to sing-box servers:
//!
//! - Xray-core: VLESS + REALITY + `xtls-rprx-vision`, `dest` on loopback with
//!   `xver: 1` (PROXY protocol v1), several `serverNames`, one 8-byte shortId,
//!   a guest blackhole keyed on `email`, and `sniffing.routeOnly`.
//! - apernet hysteria2: one process per port, salamander obfs, a self-signed
//!   ECDSA P-256 certificate pinned as the client's only trust anchor, and
//!   `userpass` auth (client password `name:password`).
//!
//! The client outbounds are built the way `singbox.ts::buildProfile` builds
//! them. Binaries come from `$SBR_XRAY` / `$SBR_HYSTERIA` (and `$SBR_SING_BOX`
//! for the Shadowsocks exit), else `PATH`; a missing one skips its tests.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sbr_engine::sbr_config::Options;
use sbr_engine::sbr_core::{Destination, Outbound};
use sbr_engine::{Engine, Settings};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MIB: usize = 1024 * 1024;
const ADMIN_UUID: &str = "6f1c2a8e-0b7d-4c55-9e3a-2d4b8f9a1c70";
const GUEST_UUID: &str = "0d9e7b3a-5c21-4f86-a1e4-7b2c9d6e8f13";
const WRONG_UUID: &str = "11111111-2222-4333-8444-555555555555";
const ADMIN: &str = "admin";
const HY2_PASSWORD: &str = "Q7pX2mVt9sKc4LwR8nYb3HdJ6fGz1aEu";
const OBFS_PASSWORD: &str = "obfs9Kd2Lm7Qx4Rt1Vw8Zy3Bn6Cp5Hs0J";
/// hysteria.ts `sni` default.
const HY2_SNI: &str = "www.bing.com";
/// Borrowed identities, as in `XrayConfSchema.serverNames`.
const SERVER_NAMES: [&str; 3] = ["www.microsoft.com", "www.apple.com", "gateway.example.net"];
/// Every profile offers X25519MLKEM768, which XTLS/REALITY servers require
/// since 2026-09-08 (`ios` is Apple's current stack, not uTLS `HelloIOS_14`).
const FINGERPRINTS: [&str; 4] = ["chrome", "firefox", "safari", "ios"];

/// xray.ts `GUEST_DENY_CIDRS`.
const GUEST_DENY_CIDRS: [&str; 10] = [
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
    "127.0.0.0/8",
    "0.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
];

fn find_bin(env: &str, name: &str) -> Option<PathBuf> {
    let p = std::env::var_os(env).map(PathBuf::from).or_else(|| {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|d| d.join(name))
            .find(|f| f.is_file())
    });
    match p {
        Some(p) if p.is_file() => Some(p),
        _ => {
            eprintln!("SKIP: no {name} binary (set {env} or put it on PATH)");
            None
        }
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "sbr-upstream-{name}-{}-{}",
        std::process::id(),
        common::free_port()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn log_stdio() -> Stdio {
    if std::env::var_os("SBR_UPSTREAM_LOG").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

/// Push `size` bytes through an echo path in varied write sizes and compare.
async fn roundtrip<S: AsyncRead + AsyncWrite + Send + 'static>(s: S, size: usize) -> Result<(), String> {
    let (mut r, mut w) = tokio::io::split(s);
    let data = Arc::new(pattern(size, size as u64 + 7));
    let d = data.clone();
    let writer = tokio::spawn(async move {
        let sizes = [1usize, 100, 16 * 1024, 64 * 1024, 3000, 15000, 15001, 40000];
        let (mut off, mut i) = (0, 0);
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

async fn tcp_roundtrip(out: &Arc<dyn Outbound>, echo: SocketAddr, size: usize) -> Result<(), String> {
    let s = out
        .connect(&Destination::from(echo))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    roundtrip(s, size).await
}

async fn udp_roundtrip(out: &Arc<dyn Outbound>, echo: SocketAddr, sizes: &[usize]) -> Result<(), String> {
    let dest = Destination::from(echo);
    let c = out.connect_udp(&dest).await.map_err(|e| format!("udp connect: {e}"))?;
    let mut buf = vec![0u8; 65536];
    for (i, &size) in sizes.iter().enumerate() {
        let p = pattern(size, i as u64 + 99);
        // UDP: a lost datagram is retried, a wrong one is a failure.
        let mut ok = false;
        for _ in 0..3 {
            c.send_to(&p, &dest)
                .await
                .map_err(|e| format!("udp send ({size} bytes): {e}"))?;
            let Ok(r) = tokio::time::timeout(Duration::from_secs(3), c.recv_from(&mut buf)).await else {
                continue;
            };
            let (n, from) = r.map_err(|e| format!("udp recv: {e}"))?;
            if buf[..n] != p[..] {
                return Err(format!("udp packet {i} mismatch ({n} vs {size} bytes)"));
            }
            if from.port != echo.port() {
                return Err(format!("udp reply from {from}, expected {echo}"));
            }
            ok = true;
            break;
        }
        if !ok {
            return Err(format!("udp packet {i} ({size} bytes) never echoed"));
        }
    }
    Ok(())
}

/// A connection the server should refuse: it must end (error or EOF, no
/// data) promptly rather than hang.
async fn expect_refused(out: &Arc<dyn Outbound>, echo: SocketAddr) -> Result<String, String> {
    let fut = async {
        let mut s = match out.connect(&Destination::from(echo)).await {
            Ok(s) => s,
            Err(e) => return Ok(format!("connect: {e}")),
        };
        if let Err(e) = s.write_all(b"hello?").await {
            return Ok(format!("write: {e}"));
        }
        let _ = s.flush().await;
        let mut b = [0u8; 64];
        match s.read(&mut b).await {
            Ok(0) => Ok("eof".to_string()),
            Ok(n) => Err(format!("got {n} bytes back from a refused connection")),
            Err(e) => Ok(format!("read: {e}")),
        }
    };
    tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .map_err(|_| "refused connection hung".to_string())?
}

fn rustls_server(cert_pem: &str, key_pem: &str) -> tokio_rustls::TlsAcceptor {
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

fn rustls_client(root_pem: &str) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(root_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

/// TLS echo server for traffic inside the tunnel: TLS 1.3 inside is what
/// makes Vision switch to direct copy.
async fn inner_tls_echo(cert_pem: &str, key_pem: &str) -> SocketAddr {
    let acceptor = rustls_server(cert_pem, key_pem);
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

/// A server-first protocol (SMTP-like): greets, then echoes.
async fn banner_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                if s.write_all(b"220 ready\r\n").await.is_err() {
                    return;
                }
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    a
}

// ---------------------------------------------------------------------------
// Xray

/// The REALITY `dest`: Traefik's role in jaritanet. Expects a PROXY v1
/// header (xver 1), then TLS, then answers any HTTP request with [`DEST_BODY`].
struct Dest {
    addr: SocketAddr,
    cert_pem: String,
    /// Every PROXY header received, in order.
    proxy_headers: Arc<Mutex<Vec<String>>>,
}

const DEST_BODY: &str = "jaritanet ingress";

async fn dest_site() -> Dest {
    let mut params =
        rcgen::CertificateParams::new(SERVER_NAMES.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, SERVER_NAMES[0]);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let acceptor = rustls_server(&cert.pem(), &key.serialize_pem());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let proxy_headers = Arc::new(Mutex::new(Vec::new()));
    let headers = proxy_headers.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let headers = headers.clone();
            tokio::spawn(async move {
                // Byte at a time so no TLS byte is consumed with the header.
                let mut line = Vec::new();
                while !line.ends_with(b"\r\n") && line.len() < 108 {
                    let mut b = [0u8; 1];
                    if s.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    line.push(b[0]);
                }
                let line = String::from_utf8_lossy(&line).trim_end().to_string();
                let ok = line.starts_with("PROXY ");
                headers.lock().unwrap().push(line);
                if !ok {
                    return;
                }
                let Ok(mut tls) = acceptor.accept(s).await else { return };
                let mut req = Vec::new();
                let mut b = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{DEST_BODY}",
                    DEST_BODY.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Dest {
        addr,
        cert_pem: cert.pem(),
        proxy_headers,
    }
}

struct Xray {
    _proc: Proc,
    _dir: PathBuf,
    port: u16,
    public_key: String,
    short_id: String,
    dest: Dest,
}

fn xray_keys(bin: &Path) -> (String, String) {
    let out = Command::new(bin).arg("x25519").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let field = |pred: &dyn Fn(&str) -> bool| {
        text.lines()
            .find(|l| pred(&l.to_ascii_lowercase()))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_else(|| panic!("unexpected `xray x25519` output"))
    };
    // "PrivateKey:" and "Password (PublicKey):" since 25.x; "Private key:" /
    // "Public key:" before.
    let private = field(&|l| l.starts_with("private"));
    let public = field(&|l| l.contains("public"));
    (private, public)
}

/// xray.ts `createXray`, on loopback.
async fn start_xray(bin: &Path) -> Xray {
    let (private_key, public_key) = xray_keys(bin);
    let short_id = "a1b2c3d4e5f60718".to_string();
    let dest = dest_site().await;
    let dir = temp_dir("xray");
    for _ in 0..3 {
        let port = common::free_port();
        let dest_s = dest.addr.to_string();
        let xver = if dest_s.starts_with("127.") || dest_s.starts_with("localhost:") || dest_s.starts_with("[::1]:") {
            1
        } else {
            0
        };
        let config = json!({
            "log": {"loglevel": if std::env::var_os("SBR_UPSTREAM_LOG").is_some() { "debug" } else { "warning" }},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {"id": ADMIN_UUID, "email": ADMIN, "flow": "xtls-rprx-vision"},
                        {"id": GUEST_UUID, "email": "guest", "flow": "xtls-rprx-vision"},
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "dest": dest_s,
                        "xver": xver,
                        "serverNames": SERVER_NAMES,
                        "privateKey": private_key,
                        "shortIds": [short_id],
                    },
                },
                "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true},
            }],
            "outbounds": [
                // Xray 26 freedom blackholes private and loopback targets for
                // vless inbounds by default, and the echo servers here are on
                // loopback. jaritanet sets no such rule, so on the gateway the
                // profile's `127.0.0.1` DNS server is refused over REALITY.
                {"protocol": "freedom", "tag": "direct",
                 "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
                {"protocol": "blackhole", "tag": "block"},
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"user": ["guest"], "ip": GUEST_DENY_CIDRS, "outboundTag": "block"},
                    {"network": "tcp,udp", "outboundTag": "direct"},
                ],
            },
        });
        let path = dir.join(format!("xray-{port}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let child = Command::new(bin)
            .arg("run")
            .arg("-c")
            .arg(&path)
            .stdout(log_stdio())
            .stderr(log_stdio())
            .spawn()
            .unwrap();
        let mut p = Proc(child);
        let mut up = false;
        for _ in 0..200 {
            if p.0.try_wait().ok().flatten().is_some() {
                break;
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        if up && p.0.try_wait().ok().flatten().is_none() {
            return Xray {
                _proc: p,
                _dir: dir,
                port,
                public_key,
                short_id,
                dest,
            };
        }
    }
    panic!("xray failed to start");
}

impl Xray {
    /// singbox.ts `reality()`.
    fn outbound(&self, tag: &str, uuid: &str, sni: &str, fingerprint: &str) -> Value {
        json!({
            "type": "vless",
            "tag": tag,
            "server": "127.0.0.1",
            "server_port": self.port,
            "uuid": uuid,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": true,
                "server_name": sni,
                "utls": {"enabled": true, "fingerprint": fingerprint},
                "reality": {"enabled": true, "public_key": self.public_key, "short_id": self.short_id},
            },
        })
    }
}

fn engine(outbounds: Vec<Value>) -> Engine {
    let opts = Options::from_value(json!({ "outbounds": outbounds })).unwrap();
    Engine::new(&opts, &Settings::default()).unwrap()
}

/// TLS 1.3 inside the tunnel: Vision pads the inner handshake, then both
/// sides switch to direct copy (Xray splices). Also a second TLS session on
/// the same outbound, and a server-first protocol.
async fn vision_paths(out: &Arc<dyn Outbound>) -> Result<(), String> {
    let inner = rcgen::generate_simple_self_signed(vec!["inner.test".into()]).unwrap();
    let (cert, key) = (inner.cert.pem(), inner.signing_key.serialize_pem());
    let echo = inner_tls_echo(&cert, &key).await;
    let connector = rustls_client(&cert);
    for size in [MIB, 64 * 1024] {
        let s = out
            .connect(&Destination::from(echo))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let tls = connector
            .connect(ServerName::try_from("inner.test").unwrap(), s)
            .await
            .map_err(|e| format!("inner TLS handshake: {e}"))?;
        roundtrip(tls, size).await.map_err(|e| format!("inner TLS: {e}"))?;
    }

    let mut s = out
        .connect(&Destination::from(banner_echo().await))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut greet = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut greet))
        .await
        .map_err(|_| "server-first greeting timed out".to_string())?
        .map_err(|e| format!("server-first read: {e}"))?;
    if &greet != b"220 ready\r\n" {
        return Err(format!("server-first greeting {greet:?}"));
    }
    roundtrip(s, 256 * 1024).await.map_err(|e| format!("server-first: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_vless_reality_vision() {
    let Some(bin) = find_bin("SBR_XRAY", "xray") else {
        return;
    };
    let xray = start_xray(&bin).await;
    let (techo, uecho) = (common::echo().await, common::udp_echo().await);

    let mut outbounds = Vec::new();
    for (i, fp) in FINGERPRINTS.iter().enumerate() {
        let sni = SERVER_NAMES[i % SERVER_NAMES.len()];
        outbounds.push(xray.outbound(&format!("reality-{fp}"), ADMIN_UUID, sni, fp));
    }
    // XUDP is the default packet encoding; "" is plain VLESS UDP (no flow).
    let mut plain_udp = xray.outbound("reality-udp-plain", ADMIN_UUID, SERVER_NAMES[0], "chrome");
    plain_udp["packet_encoding"] = json!("");
    outbounds.push(plain_udp);
    let engine = engine(outbounds);

    let udp_sizes = [1usize, 64, 512, 1200, 1400, 4000, 8000, 1, 1300];
    let mut failures = Vec::new();
    for fp in FINGERPRINTS {
        let out = engine.outbound(&format!("reality-{fp}")).unwrap().clone();
        let r = async {
            tcp_roundtrip(&out, techo, MIB).await?;
            tcp_roundtrip(&out, techo, 64 * 1024).await?;
            vision_paths(&out).await?;
            udp_roundtrip(&out, uecho, &udp_sizes)
                .await
                .map_err(|e| format!("xudp: {e}"))
        }
        .await;
        match r {
            Ok(()) => eprintln!("ok   reality {fp}"),
            Err(e) => failures.push(format!("reality {fp}: {e}")),
        }
    }
    let out = engine.outbound("reality-udp-plain").unwrap().clone();
    if let Err(e) = udp_roundtrip(&out, uecho, &udp_sizes).await {
        failures.push(format!("plain VLESS UDP over a Vision user: {e}"));
    }
    // Like Xray's own client, Vision refuses QUIC so clients fall back to TCP.
    let vision = engine
        .outbound(&format!("reality-{}", FINGERPRINTS[0]))
        .unwrap()
        .clone();
    let quic = Destination::from(SocketAddr::new(uecho.ip(), 443));
    if vision.connect_udp(&quic).await.is_ok() {
        failures.push("Vision carried UDP/443".into());
    }
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
}

/// An engine with a SOCKS inbound in front of `outbound`: soaks go through
/// the relay, where the real traffic goes.
async fn relay_to(outbound: Value) -> (sbr_engine::Instance, u16) {
    let opts = Options::from_value(json!({
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [outbound],
    }))
    .unwrap();
    let i = sbr_engine::Instance::start(&opts, Settings::default()).await.unwrap();
    let port = common::port(&i, "in");
    (i, port)
}

/// HTTPS through Vision, which goes direct after the inner handshake: the
/// phone's main path. See `common/soak.rs` for how to run it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: moves 128 MiB"]
async fn soak_xray_vless_reality_vision() {
    let Some(bin) = find_bin("SBR_XRAY", "xray") else {
        return;
    };
    let xray = start_xray(&bin).await;
    let (_i, proxy) = relay_to(xray.outbound("reality", ADMIN_UUID, SERVER_NAMES[0], "chrome")).await;
    let inner = rcgen::generate_simple_self_signed(vec!["inner.test".into()]).unwrap();
    let (cert, key) = (inner.cert.pem(), inner.signing_key.serialize_pem());
    let s = common::soak::socks5(proxy, inner_tls_echo(&cert, &key).await).await;
    let tls = rustls_client(&cert)
        .connect(ServerName::try_from("inner.test").unwrap(), s)
        .await
        .unwrap();
    common::soak::soak_echo("vless+reality+vision", tls, common::soak::soak_bytes(), 3).await;
}

/// Wrong credentials fail promptly and cleanly, and the guest blackhole
/// (keyed on the client's `email`) holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_rejections() {
    let Some(bin) = find_bin("SBR_XRAY", "xray") else {
        return;
    };
    let xray = start_xray(&bin).await;
    let techo = common::echo().await;

    let mut wrong_key = xray.outbound("wrong-key", ADMIN_UUID, SERVER_NAMES[0], "chrome");
    let (_, other_public) = xray_keys(&bin);
    wrong_key["tls"]["reality"]["public_key"] = json!(other_public);
    let mut wrong_sid = xray.outbound("wrong-sid", ADMIN_UUID, SERVER_NAMES[0], "chrome");
    wrong_sid["tls"]["reality"]["short_id"] = json!("0011223344556677");
    let engine = engine(vec![
        xray.outbound("wrong-uuid", WRONG_UUID, SERVER_NAMES[0], "chrome"),
        xray.outbound("wrong-sni", ADMIN_UUID, "not-listed.example.org", "chrome"),
        wrong_key,
        wrong_sid,
        xray.outbound("guest", GUEST_UUID, SERVER_NAMES[1], "chrome"),
        xray.outbound("admin", ADMIN_UUID, SERVER_NAMES[1], "chrome"),
    ]);
    for tag in ["wrong-uuid", "wrong-sni", "wrong-key", "wrong-sid", "guest"] {
        let out = engine.outbound(tag).unwrap().clone();
        let how = expect_refused(&out, techo)
            .await
            .unwrap_or_else(|e| panic!("{tag}: {e}"));
        eprintln!("ok   {tag} refused ({how})");
    }
    // The server is still healthy for a valid client afterwards.
    let out = engine.outbound("admin").unwrap().clone();
    tcp_roundtrip(&out, techo, 64 * 1024).await.unwrap();
}

/// REALITY behind a filter that resets the borrowed SNI: Xray accepts the
/// ClientHello split across records and segments, and the automatic mode
/// finds that split on its own. Also the configured form, unfiltered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_reality_fragmented_client_hello() {
    let Some(bin) = find_bin("SBR_XRAY", "xray") else {
        return;
    };
    let xray = start_xray(&bin).await;
    let techo = common::echo().await;
    let censor = common::sni_censor::start(
        ([127, 0, 0, 1], xray.port).into(),
        SERVER_NAMES[0],
        common::sni_censor::Records::Joined,
    )
    .await;
    let mut auto = xray.outbound("auto", ADMIN_UUID, SERVER_NAMES[0], "chrome");
    auto["server_port"] = json!(censor.port);
    auto["tls"]["fragment_fallback_delay"] = json!("50ms");
    let mut both = xray.outbound("both", ADMIN_UUID, SERVER_NAMES[1], "firefox");
    both["tls"]["fragment"] = json!(true);
    both["tls"]["record_fragment"] = json!(true);
    both["tls"]["fragment_fallback_delay"] = json!("20ms");
    let mut split = xray.outbound("split", ADMIN_UUID, SERVER_NAMES[0], "chrome");
    split["server_port"] = json!(censor.port);
    split["tls"]["fragment_split"] = json!({"pieces": "3-5", "delay": "5-15"});
    let engine = engine(vec![auto, both, split]);

    let out = engine.outbound("auto").unwrap().clone();
    tcp_roundtrip(&out, techo, MIB).await.unwrap();
    vision_paths(&out).await.unwrap();
    assert_eq!(censor.resets(), 2, "unsplit, then records only");
    let out = engine.outbound("both").unwrap().clone();
    tcp_roundtrip(&out, techo, MIB).await.unwrap();
    vision_paths(&out).await.unwrap();
    let out = engine.outbound("split").unwrap().clone();
    tcp_roundtrip(&out, techo, MIB).await.unwrap();
    vision_paths(&out).await.unwrap();
    assert_eq!(censor.resets(), 2, "fragment_split passes the filter");
}

async fn probe_dest(port: u16, sni: &str, root_pem: &str) -> Result<String, String> {
    let s = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let name = ServerName::try_from(sni.to_string()).unwrap();
    let mut tls = rustls_client(root_pem)
        .connect(name, s)
        .await
        .map_err(|e| format!("probe TLS: {e}"))?;
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {sni}\r\n\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    let resp = String::from_utf8_lossy(&resp).to_string();
    if !resp.ends_with(DEST_BODY) {
        return Err(format!("probe got {resp:?}"));
    }
    Ok(resp)
}

/// An unauthenticated probe reaches `dest` (with the PROXY header xray.ts
/// configures for a loopback dest), before, during and after sbr clients
/// use the inbound: sbr never leaves the server answering probes wrongly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_reality_fallback() {
    let Some(bin) = find_bin("SBR_XRAY", "xray") else {
        return;
    };
    let xray = start_xray(&bin).await;
    let techo = common::echo().await;
    let root = xray.dest.cert_pem.clone();

    for sni in SERVER_NAMES {
        probe_dest(xray.port, sni, &root)
            .await
            .unwrap_or_else(|e| panic!("probe {sni}: {e}"));
    }
    {
        let headers = xray.dest.proxy_headers.lock().unwrap();
        let mut relayed = 0;
        for h in headers.iter() {
            let f: Vec<&str> = h.split(' ').collect();
            assert!(
                f.len() == 6 && f[0] == "PROXY" && f[1] == "TCP4" && f[2] == "127.0.0.1",
                "malformed PROXY header {h:?}"
            );
            // Relayed clients name the inbound they dialled. The rest are
            // Xray's own start-up probes of dest (post-handshake record
            // lengths), which name dest itself.
            if f[5] == xray.port.to_string() {
                relayed += 1;
            } else {
                assert_eq!(f[5], xray.dest.addr.port().to_string(), "PROXY header {h:?}");
            }
        }
        assert!(relayed >= SERVER_NAMES.len(), "PROXY headers {headers:?}");
    }

    let mut outbounds = Vec::new();
    for fp in FINGERPRINTS {
        outbounds.push(xray.outbound(fp, ADMIN_UUID, SERVER_NAMES[2], fp));
    }
    let engine = Arc::new(engine(outbounds));
    // Probes while sbr clients are mid-transfer.
    let bulk: Vec<_> = FINGERPRINTS
        .iter()
        .map(|fp| {
            let out = engine.outbound(fp).unwrap().clone();
            tokio::spawn(async move { tcp_roundtrip(&out, techo, 4 * MIB).await })
        })
        .collect();
    for sni in SERVER_NAMES {
        probe_dest(xray.port, sni, &root)
            .await
            .unwrap_or_else(|e| panic!("probe {sni} during sbr traffic: {e}"));
    }
    for (fp, b) in FINGERPRINTS.iter().zip(bulk) {
        b.await.unwrap().unwrap_or_else(|e| panic!("{fp}: {e}"));
    }
    // An SNI outside serverNames is a probe too, and still reaches dest.
    probe_dest(xray.port, SERVER_NAMES[0], &root).await.unwrap();
    let s = TcpStream::connect(("127.0.0.1", xray.port)).await.unwrap();
    let off_list = rustls_client(&root)
        .connect(ServerName::try_from("not-listed.example.org").unwrap(), s)
        .await;
    // dest's certificate doesn't cover that name: the handshake reaching
    // dest and failing verification is the expected outcome.
    let err = off_list.expect_err("off-list SNI unexpectedly verified").to_string();
    assert!(err.contains("certificate") || err.contains("Certificate"), "{err}");
}

// ---------------------------------------------------------------------------
// hysteria2

struct Hysteria {
    _procs: Vec<Proc>,
    _dir: PathBuf,
    ports: Vec<u16>,
    cert_pem: String,
    obfs: bool,
}

/// The pinned self-signed certificate hysteria.ts mints with `@pulumi/tls`:
/// ECDSA P-256, CN and SAN = sni, server-auth key usages, not a CA.
fn hy2_cert() -> (String, String) {
    let mut p = rcgen::CertificateParams::new(vec![HY2_SNI.to_string()]).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, HY2_SNI);
    p.is_ca = rcgen::IsCa::ExplicitNoCa;
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    p.not_after = rcgen::date_time_ymd(2036, 1, 1);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = p.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

/// hysteria.ts `createHysteria`: one process per port, same config.
/// `obfs: false` drops Salamander, leaving plain QUIC with a readable SNI.
async fn start_hysteria(bin: &Path, nports: usize, obfs: bool) -> Hysteria {
    let dir = temp_dir("hy2");
    let (cert, key) = hy2_cert();
    std::fs::write(dir.join("cert.pem"), &cert).unwrap();
    std::fs::write(dir.join("key.pem"), &key).unwrap();
    let mut procs = Vec::new();
    let mut ports = Vec::new();
    while ports.len() < nports {
        let port = common::free_udp_port();
        let obfs = if obfs {
            format!("obfs:\n  type: salamander\n  salamander:\n    password: {OBFS_PASSWORD}\n")
        } else {
            String::new()
        };
        let config = format!(
            "listen: 127.0.0.1:{port}\ntls:\n  cert: {cert}\n  key: {key}\n{obfs}auth:\n  type: userpass\n  userpass:\n    {ADMIN}: {HY2_PASSWORD}\n    other: {OBFS_PASSWORD}\n",
            cert = dir.join("cert.pem").display(),
            key = dir.join("key.pem").display(),
        );
        let path = dir.join(format!("config-{port}.yaml"));
        std::fs::write(&path, config).unwrap();
        let mut child = Command::new(bin)
            .args(["server", "--disable-update-check", "-l", "info", "-c"])
            .arg(&path)
            .env("HYSTERIA_DISABLE_UPDATE_CHECK", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let echo = std::env::var_os("SBR_UPSTREAM_LOG").is_some();
            let mut tx = Some(tx);
            for line in std::io::BufReader::new(stderr).lines().map_while(Result::ok) {
                if echo {
                    eprintln!("hysteria: {line}");
                }
                if line.contains("server up and running")
                    && let Some(tx) = tx.take()
                {
                    let _ = tx.send(());
                }
            }
        });
        let mut p = Proc(child);
        let up = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(10)).is_ok())
            .await
            .unwrap();
        if up && p.0.try_wait().ok().flatten().is_none() {
            procs.push(p);
            ports.push(port);
        } else {
            let _ = p.0.kill();
        }
        assert!(procs.len() + 5 > ports.len(), "hysteria failed to start");
    }
    Hysteria {
        _procs: procs,
        _dir: dir,
        ports,
        cert_pem: cert,
        obfs,
    }
}

impl Hysteria {
    /// singbox.ts `hy2()`.
    fn outbound(&self, tag: &str, port: u16, password: &str) -> Value {
        let mut o = json!({
            "type": "hysteria2",
            "tag": tag,
            "server": "127.0.0.1",
            "server_port": port,
            "password": password,
            "obfs": {"type": "salamander", "password": OBFS_PASSWORD},
            "tls": {"enabled": true, "server_name": HY2_SNI, "certificate": self.cert_pem},
        });
        if !self.obfs {
            o.as_object_mut().unwrap().remove("obfs");
        }
        o
    }
}

fn hy2_password() -> String {
    format!("{ADMIN}:{HY2_PASSWORD}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_apernet() {
    let Some(bin) = find_bin("SBR_HYSTERIA", "hysteria") else {
        return;
    };
    let hy = start_hysteria(&bin, 3, true).await;
    let (techo, uecho) = (common::echo().await, common::udp_echo().await);
    let engine = engine(
        hy.ports
            .iter()
            .map(|&p| hy.outbound(&format!("hy2-gw-{p}"), p, &hy2_password()))
            .collect(),
    );
    // hysteria's MaxUDPSize (4096) bounds the server's whole downlink message,
    // header included, so a 4096-byte payload is never echoed. Anything over
    // ~1200 is fragmented (the server's max_datagram_frame_size is 1200).
    let udp_sizes = [1usize, 64, 512, 1100, 1200, 1300, 1400, 2000, 3000, 4000, 1];
    let mut failures = Vec::new();
    for &p in &hy.ports {
        let out = engine.outbound(&format!("hy2-gw-{p}")).unwrap().clone();
        let r = async {
            tcp_roundtrip(&out, techo, MIB).await?;
            tcp_roundtrip(&out, techo, 64 * 1024).await?;
            udp_roundtrip(&out, uecho, &udp_sizes).await
        }
        .await;
        match r {
            Ok(()) => eprintln!("ok   hy2 port {p}"),
            Err(e) => failures.push(format!("hy2 port {p}: {e}")),
        }
    }
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
}

/// See `common/soak.rs` for how to run it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: moves 128 MiB"]
async fn soak_hysteria2_apernet() {
    let Some(bin) = find_bin("SBR_HYSTERIA", "hysteria") else {
        return;
    };
    let hy = start_hysteria(&bin, 1, true).await;
    let (_i, proxy) = relay_to(hy.outbound("hy2", hy.ports[0], &hy2_password())).await;
    let s = common::soak::socks5(proxy, common::echo().await).await;
    common::soak::soak_echo("hysteria2", s, common::soak::soak_bytes(), 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_apernet_rejections() {
    let Some(bin) = find_bin("SBR_HYSTERIA", "hysteria") else {
        return;
    };
    let hy = start_hysteria(&bin, 1, true).await;
    let techo = common::echo().await;
    let port = hy.ports[0];
    let mut wrong_obfs = hy.outbound("wrong-obfs", port, &hy2_password());
    wrong_obfs["obfs"]["password"] = json!("not-the-obfs-password");
    wrong_obfs["tls"]["handshake_timeout"] = json!("3s");
    let other = rcgen::generate_simple_self_signed(vec![HY2_SNI.into()]).unwrap();
    let mut wrong_cert = hy.outbound("wrong-cert", port, &hy2_password());
    wrong_cert["tls"]["certificate"] = json!(other.cert.pem());
    let engine = engine(vec![
        // userpass: the bare password, without `name:`, must fail.
        hy.outbound("bare-password", port, HY2_PASSWORD),
        hy.outbound("wrong-password", port, &format!("{ADMIN}:nope")),
        hy.outbound("wrong-user", port, &format!("nobody:{HY2_PASSWORD}")),
        wrong_obfs,
        wrong_cert,
        hy.outbound("ok", port, &hy2_password()),
    ]);
    for tag in [
        "bare-password",
        "wrong-password",
        "wrong-user",
        "wrong-obfs",
        "wrong-cert",
    ] {
        let out = engine.outbound(tag).unwrap().clone();
        let how = expect_refused(&out, techo)
            .await
            .unwrap_or_else(|e| panic!("{tag}: {e}"));
        eprintln!("ok   {tag} refused ({how})");
        let r = tokio::time::timeout(
            Duration::from_secs(15),
            out.connect_udp(&Destination::from(common::udp_echo().await)),
        )
        .await
        .unwrap_or_else(|_| panic!("{tag}: UDP connect hung"));
        assert!(r.is_err(), "{tag}: UDP connect succeeded");
    }
    let out = engine.outbound("ok").unwrap().clone();
    tcp_roundtrip(&out, techo, 64 * 1024).await.unwrap();
}

/// apernet hysteria without obfs behind an SNI-filtering censor: quic-go's
/// server must accept the scrambled ClientHello, and the censor must block
/// the unsplit one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_apernet_sni_censor() {
    let Some(bin) = find_bin("SBR_HYSTERIA", "hysteria") else {
        return;
    };
    let hy = start_hysteria(&bin, 1, false).await;
    let (techo, uecho) = (common::echo().await, common::udp_echo().await);
    let upstream = SocketAddr::from(([127, 0, 0, 1], hy.ports[0]));
    let open = common::censor::start(upstream, HY2_SNI).await;
    let shut = common::censor::start(upstream, HY2_SNI).await;
    let mut plain = hy.outbound("unsplit", shut.addr.port(), &hy2_password());
    plain["disable_client_hello_scrambling"] = json!(true);
    plain["tls"]["handshake_timeout"] = json!("3s");
    let engine = engine(vec![hy.outbound("scrambled", open.addr.port(), &hy2_password()), plain]);
    let out = engine.outbound("scrambled").unwrap().clone();
    tcp_roundtrip(&out, techo, MIB).await.unwrap();
    udp_roundtrip(&out, uecho, &[1, 1200, 3000]).await.unwrap();
    assert!(open.inspected.load(std::sync::atomic::Ordering::Relaxed) > 0);
    assert!(!open.blocked.load(std::sync::atomic::Ordering::Relaxed));
    let out = engine.outbound("unsplit").unwrap().clone();
    assert!(tcp_roundtrip(&out, techo, 1024).await.is_err());
    assert!(shut.blocked.load(std::sync::atomic::Ordering::Relaxed));
}

/// A NAT between client and server: each client address gets its own
/// upstream socket, so the server sees a new address when the client moves.
/// `cut` blackholes every client address seen so far, as losing Wi-Fi does.
struct Nat {
    addr: SocketAddr,
    clients: Arc<Mutex<Vec<(SocketAddr, bool)>>>,
}

impl Nat {
    async fn start(server: SocketAddr) -> Self {
        let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let clients: Arc<Mutex<Vec<(SocketAddr, bool)>>> = Arc::default();
        let (f, c) = (front.clone(), clients.clone());
        tokio::spawn(async move {
            let mut ups: std::collections::HashMap<SocketAddr, Arc<tokio::net::UdpSocket>> = Default::default();
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = f.recv_from(&mut buf).await {
                let alive = {
                    let mut c = c.lock().unwrap();
                    match c.iter().find(|e| e.0 == from) {
                        Some(e) => e.1,
                        None => {
                            c.push((from, true));
                            true
                        }
                    }
                };
                if !alive {
                    continue;
                }
                let up = match ups.get(&from) {
                    Some(u) => u.clone(),
                    None => {
                        let u = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        u.connect(server).await.unwrap();
                        let (u2, f2, c2) = (u.clone(), f.clone(), c.clone());
                        tokio::spawn(async move {
                            let mut b = vec![0u8; 65536];
                            while let Ok(n) = u2.recv(&mut b).await {
                                if c2.lock().unwrap().iter().any(|e| e.0 == from && e.1) {
                                    let _ = f2.send_to(&b[..n], from).await;
                                }
                            }
                        });
                        ups.insert(from, u.clone());
                        u
                    }
                };
                let _ = up.send(&buf[..n]).await;
            }
        });
        Self { addr, clients }
    }

    fn cut(&self) {
        for e in self.clients.lock().unwrap().iter_mut() {
            e.1 = false;
        }
    }

    fn seen(&self) -> usize {
        self.clients.lock().unwrap().len()
    }
}

/// Roaming: a stream opened before the client's path dies keeps flowing
/// after `network_migrate` moves the QUIC connection to a new socket, with
/// the old path blackholed, salamander on and no new handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_apernet_migration() {
    let Some(bin) = find_bin("SBR_HYSTERIA", "hysteria") else {
        return;
    };
    let hy = start_hysteria(&bin, 1, true).await;
    let nat = Nat::start(SocketAddr::from(([127, 0, 0, 1], hy.ports[0]))).await;
    let engine = engine(vec![hy.outbound("hy2", nat.addr.port(), &hy2_password())]);
    let out = engine.outbound("hy2").unwrap().clone();
    let s = out.connect(&Destination::from(common::echo().await)).await.unwrap();
    let (mut r, mut w) = tokio::io::split(s);
    let data = pattern(MIB, 3);
    let mut got = vec![0u8; MIB];
    w.write_all(&data[..64 * 1024]).await.unwrap();
    r.read_exact(&mut got[..64 * 1024]).await.unwrap();
    let before = nat.seen();
    assert!(before >= 1);

    nat.cut();
    engine.network_migrate().await;
    assert_eq!(
        nat.seen(),
        2 * before,
        "every connection should have moved to a new socket"
    );
    let writer = tokio::spawn(async move {
        w.write_all(&data).await.unwrap();
        (w, data)
    });
    tokio::time::timeout(Duration::from_secs(15), r.read_exact(&mut got))
        .await
        .expect("stream stalled after migration")
        .unwrap();
    let (_w, data) = writer.await.unwrap();
    assert!(got == data, "data mismatch after migration");
    // The same QUIC connection carries new streams too.
    tcp_roundtrip(&out, common::echo().await, 64 * 1024).await.unwrap();
    assert_eq!(nat.seen(), 2 * before, "no reconnect");
}

// ---------------------------------------------------------------------------
// The whole profile

/// A Shadowsocks server standing in for an exit (sing-box, since sbr has no
/// Shadowsocks inbound). `None` when sing-box is missing.
async fn ss_exit(dir: &Path) -> Option<(Proc, u16)> {
    let bin = find_bin("SBR_SING_BOX", "sing-box")?;
    for _ in 0..3 {
        let port = common::free_port();
        let cfg = json!({
            "log": {"level": "warn"},
            "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
                          "method": "aes-256-gcm", "password": "exit-password"}],
            "outbounds": [{"type": "direct"}],
        });
        let path = dir.join(format!("ss-{port}.json"));
        std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
        let child = Command::new(&bin)
            .args(["run", "-c"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(log_stdio())
            .spawn()
            .unwrap();
        let mut p = Proc(child);
        for _ in 0..200 {
            if p.0.try_wait().ok().flatten().is_some() {
                break;
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return Some((p, port));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    panic!("sing-box (shadowsocks exit) failed to start");
}

/// Answers every request with 204: the urltest target, reached through
/// each member rather than at a third party.
async fn generate_204() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut b = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                }
                let _ = s
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    a
}

/// `singbox.ts::buildProfile` for an admin on one node, against loopback
/// servers: per-SNI REALITY and per-port hy2 leaves in one urltest, the
/// `entry-select` / `exit-select` axes, a Shadowsocks exit detoured through
/// `entry-select`, and the DNS and route sections. The tun inbound is
/// replaced by `mixed` (no root needed); `sbr check` covers the tun fields.
fn profile(xray: &Xray, hy: &Hysteria, exit_port: Option<u16>, probe: SocketAddr, dir: &Path) -> Value {
    let node = "gw";
    let mut outbounds = Vec::new();
    let mut leaves = Vec::new();
    for sni in SERVER_NAMES {
        let tag = format!("reality-{node}-{}", sni.split('.').nth(1).unwrap_or(sni));
        outbounds.push(xray.outbound(&tag, ADMIN_UUID, sni, "chrome"));
        leaves.push(tag);
    }
    for &p in &hy.ports {
        let tag = format!("hy2-{node}-{p}");
        outbounds.push(hy.outbound(&tag, p, &hy2_password()));
        leaves.push(tag);
    }
    // hy2 first, as in `entryTags`.
    leaves.rotate_left(SERVER_NAMES.len());
    outbounds.push(json!({
        "type": "urltest", "tag": "auto", "outbounds": leaves,
        "url": format!("http://{probe}/generate_204"),
        "interval": "10m", "idle_timeout": "30m", "tolerance": 100,
    }));
    let mut entry = vec!["auto".to_string()];
    entry.extend(leaves.iter().cloned());
    outbounds.push(json!({"type": "selector", "tag": "entry-select", "outbounds": entry, "default": "auto"}));
    let final_tag = if let Some(port) = exit_port {
        outbounds.push(json!({
            "type": "shadowsocks", "tag": "exit-home", "server": "127.0.0.1", "server_port": port,
            "method": "aes-256-gcm", "password": "exit-password", "detour": "entry-select",
        }));
        outbounds.push(
            json!({"type": "selector", "tag": "exit-direct", "outbounds": ["entry-select"], "default": "entry-select"}),
        );
        outbounds.push(json!({"type": "selector", "tag": "exit-select", "outbounds": ["exit-direct", "exit-home"], "default": "exit-direct"}));
        "exit-select"
    } else {
        "entry-select"
    };
    json!({
        "log": {"level": "info", "timestamp": true},
        "experimental": {"cache_file": {"enabled": true, "store_dns": true, "path": dir.join("cache.db")}},
        "dns": {
            "servers": [
                {"type": "udp", "tag": "gw-cache", "server": "127.0.0.1", "detour": "entry-select"},
                {"type": "https", "tag": "cf-doh", "server": "1.1.1.1", "detour": "entry-select"},
                {"type": "udp", "tag": "ts-dns", "server": "100.100.100.100", "detour": "entry-select"},
            ],
            "rules": [{"domain_suffix": ["tail0000.ts.net"], "server": "ts-dns"}],
            "final": "gw-cache",
            "strategy": "ipv4_only",
            "optimistic": {"enabled": true, "timeout": "3d"},
        },
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": outbounds,
        "route": {
            "default_domain_resolver": "gw-cache",
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_cidr": ["100.64.0.0/10", "fd7a:115c:a1e0::/48"], "outbound": "entry-select"},
            ],
            "final": final_tag,
            "auto_detect_interface": true,
        },
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jaritanet_profile() {
    let Some(xbin) = find_bin("SBR_XRAY", "xray") else {
        return;
    };
    let Some(hbin) = find_bin("SBR_HYSTERIA", "hysteria") else {
        return;
    };
    let xray = start_xray(&xbin).await;
    let hy = start_hysteria(&hbin, 3, true).await;
    let dir = temp_dir("profile");
    let exit = ss_exit(&dir).await;
    let probe = generate_204().await;
    let cfg = profile(&xray, &hy, exit.as_ref().map(|e| e.1), probe, &dir);
    let opts = Options::from_value(cfg).unwrap();
    let inst = sbr_engine::Instance::start(&opts, Settings::default()).await.unwrap();
    let socks = common::port(&inst, "mixed-in");
    let (techo, uecho) = (common::echo().await, common::udp_echo().await);

    // Default path: exit-select → exit-direct → entry-select → auto.
    let auto = inst.engine.groups().urltest("auto").unwrap().clone();
    let delays = tokio::time::timeout(Duration::from_secs(30), auto.url_test(true))
        .await
        .expect("urltest hung");
    let leaves = 3 + SERVER_NAMES.len();
    assert_eq!(delays.len(), leaves, "urltest reached {delays:?}");
    common::bulk_echo(common::socks_connect(socks, techo).await, MIB).await;
    common::SocksUdp::new(socks)
        .await
        .echo_check(uecho, &[1, 512, 1200, 1400, 3000])
        .await;

    // Every leaf through entry-select, and every leaf under the exit.
    let entry = inst.engine.outbound("entry-select").unwrap().clone();
    let entry_group = entry.as_group().unwrap();
    let mut tags: Vec<String> = entry_group.members().iter().map(|m| m.tag().to_string()).collect();
    tags.retain(|t| t != "auto");
    for tag in &tags {
        assert!(entry_group.select(tag), "select {tag}");
        if let Some(exit_sel) = exit.as_ref().and(inst.engine.outbound("exit-select")) {
            let g = exit_sel.as_group().unwrap();
            assert!(g.select("exit-direct"));
            common::bulk_echo(common::socks_connect(socks, techo).await, 256 * 1024).await;
            assert!(g.select("exit-home"));
            common::bulk_echo(common::socks_connect(socks, techo).await, 256 * 1024).await;
            common::SocksUdp::new(socks).await.echo_check(uecho, &[1, 1200]).await;
            assert!(g.select("exit-direct"));
        } else {
            common::bulk_echo(common::socks_connect(socks, techo).await, 256 * 1024).await;
        }
        common::SocksUdp::new(socks).await.echo_check(uecho, &[1, 1400]).await;
        eprintln!("ok   profile via {tag}");
    }
    drop(inst);
    let _ = std::fs::remove_dir_all(&dir);
}
