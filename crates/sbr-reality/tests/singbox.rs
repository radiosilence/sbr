//! Interop with a real sing-box REALITY server (VLESS inbound).
//!
//! sing-box's REALITY `handshake.server` points at local rustls servers (one
//! per TLS 1.3 cipher suite, since REALITY mirrors the cover site's choice),
//! so no internet is needed. Raw VLESS over our REALITY stream reaches a local
//! echo server. Skips (passes) when the sing-box binary is absent; set
//! `SBR_SING_BOX` to point at one.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::{CryptoProvider, aws_lc_rs as provider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sbr_reality::{Fingerprint, RealityConfig, RealityStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

const SNI: &str = "reality.test";
const UUID: &str = "41fe9881-4fc4-4757-8d3b-0337b1a17bda";
const SHORT_ID: &str = "0123456789abcdef";

/// A sing-box binary built with `-tags with_utls` (REALITY needs it).
fn sing_box() -> Option<PathBuf> {
    const REF: &str = "/tmp/claude-0/-home-user-sbr/f8826c5d-a757-5d8c-a19d-5dec2bf91f74/scratchpad/ref";
    let candidates: Vec<PathBuf> = match std::env::var_os("SBR_SING_BOX") {
        Some(p) => vec![p.into()],
        None => vec![
            format!("{REF}/sing-box-utls").into(),
            format!("{REF}/sing-box-bin").into(),
        ],
    };
    for p in candidates {
        let Ok(out) = std::process::Command::new(&p).arg("version").output() else {
            continue;
        };
        if String::from_utf8_lossy(&out.stdout).contains("with_utls") {
            return Some(p);
        }
        println!("{} lacks the with_utls build tag", p.display());
    }
    None
}

/// A TLS 1.3 "cover site" that completes handshakes and then idles.
async fn cover_site(suite: rustls::SupportedCipherSuite) -> SocketAddr {
    let ck = rcgen::generate_simple_self_signed(vec![SNI.into()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    // Prefer the hybrid group so offering it is exercised end to end.
    let kx_groups = vec![
        provider::kx_group::X25519MLKEM768,
        provider::kx_group::X25519,
        provider::kx_group::SECP256R1,
    ];
    let p = CryptoProvider {
        cipher_suites: vec![suite],
        kx_groups,
        ..provider::default_provider()
    };
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut sink = [0u8; 4096];
                    while matches!(tls.read(&mut sink).await, Ok(n) if n > 0) {}
                }
            });
        }
    });
    addr
}

async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct SingBox {
    _child: Child,
    _dir: PathBuf,
    /// One inbound per cover site, in `cover` order.
    ports: Vec<u16>,
    public_key: String,
}

async fn start_sing_box(bin: &PathBuf, covers: &[SocketAddr]) -> SingBox {
    let out = std::process::Command::new(bin)
        .args(["generate", "reality-keypair"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_string())
            .expect("keypair output")
    };
    let (private_key, public_key) = (field("PrivateKey:"), field("PublicKey:"));

    let ports: Vec<u16> = covers.iter().map(|_| free_port()).collect();
    let inbounds: Vec<String> = covers
        .iter()
        .zip(&ports)
        .enumerate()
        .map(|(i, (cover, port))| {
            format!(
                r#"{{"type":"vless","tag":"in{i}","listen":"127.0.0.1","listen_port":{port},
                "users":[{{"uuid":"{UUID}"}}],
                "tls":{{"enabled":true,"server_name":"{SNI}","reality":{{"enabled":true,
                  "handshake":{{"server":"127.0.0.1","server_port":{cp}}},
                  "private_key":"{private_key}","short_id":["{SHORT_ID}"],"max_time_difference":"1m"}}}}}}"#,
                cp = cover.port()
            )
        })
        .collect();
    let config = format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{}],"outbounds":[{{"type":"direct"}}]}}"#,
        inbounds.join(",")
    );
    let dir = std::env::temp_dir().join(format!("sbr-reality-{}-{}", std::process::id(), ports[0]));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, config).unwrap();
    let child = Command::new(bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for port in &ports {
        let mut ok = false;
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", *port)).await.is_ok() {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ok, "sing-box did not start listening on {port}");
    }
    SingBox {
        _child: child,
        _dir: dir,
        ports,
        public_key,
    }
}

fn vless_request(dest: SocketAddr) -> Vec<u8> {
    let hex: String = UUID.chars().filter(|c| *c != '-').collect();
    let mut req = vec![0u8]; // version
    req.extend((0..16).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()));
    req.push(0); // addons
    req.push(1); // TCP
    req.extend_from_slice(&dest.port().to_be_bytes());
    let SocketAddr::V4(v4) = dest else { unreachable!() };
    req.push(1); // IPv4
    req.extend_from_slice(&v4.ip().octets());
    req
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed) ^ (i >> 10) as u8)
        .collect()
}

/// VLESS request + 1 MiB through REALITY, echoed back byte-exactly.
async fn vless_round_trip<S: AsyncRead + AsyncWrite + Unpin>(tls: RealityStream<S>, echo: SocketAddr, seed: u8) {
    let data = pattern(1 << 20, seed);
    let (mut r, mut w) = tokio::io::split(tls);
    let writer = async {
        let mut first = vless_request(echo);
        first.extend_from_slice(&data[..1000]);
        w.write_all(&first).await.unwrap();
        for chunk in data[1000..].chunks(33_333) {
            w.write_all(chunk).await.unwrap();
        }
        w.flush().await.unwrap();
        w
    };
    let reader = async {
        let mut hdr = [0u8; 2];
        r.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], 0, "VLESS response version");
        let mut addons = vec![0u8; hdr[1] as usize];
        r.read_exact(&mut addons).await.unwrap();
        let mut got = vec![0u8; data.len()];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (mut w, got) = tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(writer, reader) })
        .await
        .expect("round trip timed out");
    assert!(got == data, "echoed data differs");
    w.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sing_box_reality_vless() {
    let Some(bin) = sing_box() else {
        println!("skipping: sing-box binary not found (set SBR_SING_BOX)");
        return;
    };
    let suites = [
        provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
        provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
        provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    let mut covers = Vec::new();
    for s in suites {
        covers.push(cover_site(s).await);
    }
    let echo = echo_server().await;
    let sb = start_sing_box(&bin, &covers).await;

    let cases = [
        (Fingerprint::Chrome, true),
        (Fingerprint::Chrome, false),
        (Fingerprint::Firefox, true),
        (Fingerprint::Safari, true),
        (Fingerprint::Ios, true),
    ];
    let mut seed = 0u8;
    for (i, port) in sb.ports.iter().enumerate() {
        for (fp, pq) in cases {
            let mut cfg = RealityConfig::new(SNI, &sb.public_key, SHORT_ID).unwrap();
            cfg.fingerprint = fp;
            cfg.post_quantum = pq;
            let tcp = TcpStream::connect(("127.0.0.1", *port)).await.unwrap();
            let tls = sbr_reality::connect(tcp, &cfg)
                .await
                .unwrap_or_else(|e| panic!("REALITY handshake {fp:?} pq={pq} via cover {i}: {e}"));
            assert_eq!(tls.cipher_suite().id(), u16::from(suites[i].suite()));
            let hybrid = fp == Fingerprint::Chrome && pq;
            assert_eq!(tls.key_exchange_group(), if hybrid { 0x11ec } else { 0x001d });
            seed = seed.wrapping_add(1);
            vless_round_trip(tls, echo, seed).await;
            println!(
                "ok: {fp:?} pq={pq} {:?} group={:#06x}",
                suites[i].suite(),
                if hybrid { 0x11ec } else { 0x1d }
            );
        }
    }

    // Wrong credentials: the server forwards us to the cover site, whose real
    // certificate must be rejected cleanly.
    let other = std::process::Command::new(&bin)
        .args(["generate", "reality-keypair"])
        .output()
        .unwrap();
    let other = String::from_utf8(other.stdout).unwrap();
    let wrong_key = other
        .lines()
        .find_map(|l| l.strip_prefix("PublicKey:"))
        .unwrap()
        .trim()
        .to_string();
    for (key, short_id) in [
        (wrong_key.as_str(), SHORT_ID),
        (sb.public_key.as_str(), "0123456789abcdee"),
    ] {
        let cfg = RealityConfig::new(SNI, key, short_id).unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", sb.ports[0])).await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(10), sbr_reality::connect(tcp, &cfg))
            .await
            .expect("must fail promptly, not hang")
            .err()
            .expect("wrong credentials must not authenticate");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        println!("ok: rejected ({err})");
    }
}
