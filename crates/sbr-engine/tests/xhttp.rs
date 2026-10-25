//! XHTTP interop against a real Xray-core server (`$SBR_XRAY`, else `xray`
//! on PATH; the tests skip without one): every mode over HTTP/1.1 and
//! HTTP/2 with TLS, HTTP/2 over REALITY, HTTP/3, and cleartext HTTP/1.1, with VLESS
//! TCP and UDP through each.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sbr_engine::sbr_config::Options;
use sbr_engine::sbr_core::{Destination, Outbound};
use sbr_engine::{Engine, Settings};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const MIB: usize = 1024 * 1024;
const UUID: &str = "6f1c2a8e-0b7d-4c55-9e3a-2d4b8f9a1c70";
const SNI: &str = "xhttp.test";
const REALITY_SNI: &str = "www.example.com";
const SHORT_ID: &str = "a1b2c3d4e5f60718";
const MODES: [&str; 3] = ["packet-up", "stream-up", "stream-one"];

fn find_xray() -> Option<PathBuf> {
    let p = std::env::var_os("SBR_XRAY").map(PathBuf::from).or_else(|| {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|d| d.join("xray"))
            .find(|f| f.is_file())
    });
    match p {
        Some(p) if p.is_file() => Some(p),
        _ => {
            eprintln!("SKIP: no xray binary (set SBR_XRAY or put it on PATH)");
            None
        }
    }
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

fn x25519(bin: &Path) -> (String, String) {
    let out = Command::new(bin).arg("x25519").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let field = |pred: &dyn Fn(&str) -> bool| {
        text.lines()
            .find(|l| pred(&l.to_ascii_lowercase()))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_else(|| panic!("unexpected `xray x25519` output"))
    };
    (field(&|l| l.starts_with("private")), field(&|l| l.contains("public")))
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

/// Push `size` bytes through an echo in varied write sizes and compare.
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
    tokio::time::timeout(Duration::from_secs(60), r.read_exact(&mut got))
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
        let mut ok = false;
        for _ in 0..3 {
            c.send_to(&p, &dest)
                .await
                .map_err(|e| format!("udp send ({size} bytes): {e}"))?;
            let Ok(r) = tokio::time::timeout(Duration::from_secs(3), c.recv_from(&mut buf)).await else {
                continue;
            };
            let (n, _) = r.map_err(|e| format!("udp recv: {e}"))?;
            if buf[..n] != p[..] {
                return Err(format!("udp packet {i} mismatch ({n} vs {size} bytes)"));
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

struct Xray {
    _proc: Proc,
    _dir: PathBuf,
    /// Inbound ports by name: `tls`, `reality`, `plain`, `custom`, `h3`.
    ports: Vec<(&'static str, u16)>,
    public_key: String,
    cert_pem: String,
}

impl Xray {
    fn port(&self, name: &str) -> u16 {
        self.ports.iter().find(|(n, _)| *n == name).unwrap().1
    }
}

/// Server options of the `custom` inbound: everything moved off its default.
fn custom_server_settings() -> Value {
    json!({
        "path": "/c",
        "sessionIDPlacement": "header",
        "seqPlacement": "query",
        "seqKey": "n",
        "xPaddingObfsMode": true,
        "xPaddingPlacement": "cookie",
        "xPaddingKey": "pad",
        "xPaddingMethod": "tokenish",
        "xPaddingBytes": "200-400",
        "serverMaxHeaderBytes": 65536,
    })
}

/// The REALITY `dest`: a site with a certificate for the borrowed name and
/// a browser's ALPN, which the REALITY server mirrors.
async fn reality_dest() -> SocketAddr {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let ck = rcgen::generate_simple_self_signed(vec![REALITY_SNI.into()]).unwrap();
    let certs = CertificateDer::pem_slice_iter(ck.cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(ck.signing_key.serialize_pem().as_bytes()).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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

async fn start_xray(bin: &Path) -> Xray {
    let (private_key, public_key) = x25519(bin);
    let cert = rcgen::generate_simple_self_signed(vec![SNI.into()]).unwrap();
    let (cert_pem, key_pem) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let dir = std::env::temp_dir().join(format!("sbr-xhttp-{}-{}", std::process::id(), common::free_port()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    let dest = reality_dest().await;

    for _ in 0..3 {
        let ports = vec![
            ("tls", common::free_port()),
            ("reality", common::free_port()),
            ("plain", common::free_port()),
            ("custom", common::free_port()),
            ("h3", common::free_udp_port()),
        ];
        let tls_settings = json!({
            "alpn": ["h2", "http/1.1"],
            "certificates": [{"certificateFile": cert_path, "keyFile": key_path}],
        });
        let inbound = |port: u16, stream: Value| {
            json!({
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": stream,
            })
        };
        let config = json!({
            "log": {"loglevel": if std::env::var_os("SBR_UPSTREAM_LOG").is_some() { "debug" } else { "warning" }},
            "inbounds": [
                inbound(ports[0].1, json!({
                    "network": "xhttp", "xhttpSettings": {"path": "/xh"},
                    "security": "tls", "tlsSettings": tls_settings,
                })),
                inbound(ports[1].1, json!({
                    "network": "xhttp", "xhttpSettings": {"path": "/xh"},
                    "security": "reality",
                    "realitySettings": {
                        "dest": dest.to_string(),
                        "serverNames": [REALITY_SNI],
                        "privateKey": private_key,
                        "shortIds": [SHORT_ID],
                    },
                })),
                inbound(ports[2].1, json!({"network": "xhttp", "xhttpSettings": {"path": "/xh"}})),
                inbound(ports[3].1, json!({
                    "network": "xhttp", "xhttpSettings": custom_server_settings(),
                    "security": "tls", "tlsSettings": tls_settings,
                })),
                inbound(ports[4].1, json!({
                    "network": "xhttp", "xhttpSettings": {"path": "/xh"},
                    "security": "tls",
                    "tlsSettings": {
                        "alpn": ["h3"],
                        "certificates": [{"certificateFile": cert_path, "keyFile": key_path}],
                    },
                })),
            ],
            "outbounds": [
                {"protocol": "freedom", "tag": "direct",
                 "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
            ],
        });
        let path = dir.join("xray.json");
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
            let mut all = true;
            // The HTTP/3 inbound listens on UDP only.
            for (_, port) in ports.iter().filter(|(n, _)| *n != "h3") {
                all &= TcpStream::connect(("127.0.0.1", *port)).await.is_ok();
            }
            if all {
                up = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if up && p.0.try_wait().ok().flatten().is_none() {
            return Xray {
                _proc: p,
                _dir: dir,
                ports,
                public_key,
                cert_pem,
            };
        }
    }
    panic!("xray failed to start");
}

#[derive(Clone, Copy)]
enum Sec {
    TlsH2,
    TlsH1,
    Reality,
    Plain,
    TlsH3,
}

impl Sec {
    fn name(self) -> &'static str {
        match self {
            Sec::TlsH2 => "tls-h2",
            Sec::TlsH1 => "tls-h1",
            Sec::Reality => "reality-h2",
            Sec::Plain => "plain-h1",
            Sec::TlsH3 => "tls-h3",
        }
    }
}

fn tls_json(x: &Xray, sec: Sec) -> Option<Value> {
    match sec {
        Sec::TlsH2 => Some(json!({"enabled": true, "server_name": SNI, "certificate": x.cert_pem})),
        Sec::TlsH1 => Some(json!({
            "enabled": true, "server_name": SNI, "certificate": x.cert_pem, "alpn": ["http/1.1"],
        })),
        Sec::Reality => Some(json!({
            "enabled": true,
            "server_name": REALITY_SNI,
            "utls": {"enabled": true, "fingerprint": "chrome"},
            "reality": {"enabled": true, "public_key": x.public_key, "short_id": SHORT_ID},
        })),
        Sec::TlsH3 => Some(json!({
            "enabled": true, "server_name": SNI, "certificate": x.cert_pem, "alpn": ["h3"],
        })),
        Sec::Plain => None,
    }
}

fn outbound(x: &Xray, tag: &str, sec: Sec, inbound: &str, transport: Value) -> Value {
    let mut o = json!({
        "type": "vless",
        "tag": tag,
        "server": "127.0.0.1",
        "server_port": x.port(inbound),
        "uuid": UUID,
        "transport": transport,
    });
    if let Some(t) = tls_json(x, sec) {
        o["tls"] = t;
    }
    o
}

fn engine(outbounds: Vec<Value>) -> Engine {
    let opts = Options::from_value(json!({ "outbounds": outbounds })).unwrap();
    Engine::new(&opts, &Settings::default()).unwrap()
}

const UDP_SIZES: [usize; 6] = [1, 64, 512, 1200, 1400, 8000];

async fn exercise(out: &Arc<dyn Outbound>, techo: SocketAddr, uecho: SocketAddr, size: usize) -> Result<(), String> {
    tcp_roundtrip(out, techo, size).await?;
    // Several connections at once share XMUX slots.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let out = out.clone();
        set.spawn(async move { tcp_roundtrip(&out, techo, 64 * 1024).await });
    }
    while let Some(r) = set.join_next().await {
        r.unwrap().map_err(|e| format!("parallel: {e}"))?;
    }
    udp_roundtrip(out, uecho, &UDP_SIZES)
        .await
        .map_err(|e| format!("xudp: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_xhttp_modes() {
    let Some(bin) = find_xray() else { return };
    let x = start_xray(&bin).await;
    let (techo, uecho) = (common::echo().await, common::udp_echo().await);

    let mut cases = Vec::new();
    for sec in [Sec::TlsH2, Sec::TlsH1, Sec::Reality, Sec::Plain, Sec::TlsH3] {
        let inbound = match sec {
            Sec::Reality => "reality",
            Sec::TlsH3 => "h3",
            Sec::Plain => "plain",
            _ => "tls",
        };
        for mode in MODES.iter().copied().chain(["auto"]) {
            let tag = format!("{}-{mode}", sec.name());
            cases.push((
                tag.clone(),
                outbound(
                    &x,
                    &tag,
                    sec,
                    inbound,
                    json!({"type": "xhttp", "path": "/xh", "mode": mode}),
                ),
            ));
        }
    }
    let engine = engine(cases.iter().map(|(_, o)| o.clone()).collect());

    let mut failures = Vec::new();
    for (tag, _) in &cases {
        let out = engine.outbound(tag).unwrap().clone();
        let t = Instant::now();
        match exercise(&out, techo, uecho, MIB).await {
            Ok(()) => eprintln!("ok   {tag} ({:?})", t.elapsed()),
            Err(e) => {
                eprintln!("FAIL {tag}: {e}");
                failures.push(format!("{tag}: {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
}

/// Non-default placements, padding and data in headers or cookies; plain
/// VLESS UDP; `extra`; and a separate download endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_xhttp_options() {
    let Some(bin) = find_xray() else { return };
    let x = start_xray(&bin).await;
    let (techo, uecho) = (common::echo().await, common::udp_echo().await);

    let mut custom = custom_server_settings();
    custom["type"] = json!("xhttp");
    let mut cases: Vec<(String, Value, usize)> = Vec::new();
    for mode in MODES {
        let mut t = custom.clone();
        t["mode"] = json!(mode);
        let tag = format!("custom-{mode}");
        cases.push((tag.clone(), outbound(&x, &tag, Sec::TlsH2, "custom", t), MIB));
    }
    for placement in ["header", "cookie"] {
        let mut t = custom.clone();
        t["mode"] = json!("packet-up");
        t["uplinkDataPlacement"] = json!(placement);
        t["scMaxEachPostBytes"] = json!(6000);
        t["scMinPostsIntervalMs"] = json!(5);
        // The server's `auto` placement reads `X-Data`; a client with cookie
        // placement defaults to `x_data`, as in Xray, so the key is set.
        t["uplinkDataKey"] = json!("X-Data");
        let tag = format!("data-in-{placement}");
        cases.push((tag.clone(), outbound(&x, &tag, Sec::TlsH2, "custom", t), 128 * 1024));
    }
    // Xray share links carry everything but host, path and mode in `extra`.
    let mut extra = custom_server_settings();
    extra.as_object_mut().unwrap().remove("path");
    cases.push((
        "extra".into(),
        outbound(
            &x,
            "extra",
            Sec::TlsH2,
            "custom",
            json!({"type": "xhttp", "path": "/c", "mode": "packet-up", "extra": extra}),
        ),
        MIB,
    ));
    // Upload over HTTP/1.1, download over HTTP/2, same server.
    for mode in ["packet-up", "stream-up"] {
        let tag = format!("download-settings-{mode}");
        let o = outbound(
            &x,
            &tag,
            Sec::TlsH1,
            "tls",
            json!({
                "type": "xhttp", "path": "/xh", "mode": mode,
                "downloadSettings": {
                    "server": "127.0.0.1",
                    "server_port": x.port("tls"),
                    "tls": tls_json(&x, Sec::TlsH2),
                    "transport": {"type": "xhttp", "path": "/xh"},
                },
            }),
        );
        cases.push((tag, o, MIB));
    }
    let mut plain_udp = outbound(
        &x,
        "plain-udp",
        Sec::Reality,
        "reality",
        json!({"type": "xhttp", "path": "/xh"}),
    );
    plain_udp["packet_encoding"] = json!("");
    let mut outbounds: Vec<Value> = cases.iter().map(|(_, o, _)| o.clone()).collect();
    outbounds.push(plain_udp);
    let engine = engine(outbounds);

    let mut failures = Vec::new();
    for (tag, _, size) in &cases {
        let out = engine.outbound(tag).unwrap().clone();
        match exercise(&out, techo, uecho, *size).await {
            Ok(()) => eprintln!("ok   {tag}"),
            Err(e) => {
                eprintln!("FAIL {tag}: {e}");
                failures.push(format!("{tag}: {e}"));
            }
        }
    }
    let out = engine.outbound("plain-udp").unwrap().clone();
    match udp_roundtrip(&out, uecho, &UDP_SIZES).await {
        Ok(()) => eprintln!("ok   plain VLESS UDP"),
        Err(e) => failures.push(format!("plain VLESS UDP: {e}")),
    }
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
}

/// A wrong path is refused by the server (404) and surfaces as an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_xhttp_wrong_path() {
    let Some(bin) = find_xray() else { return };
    let x = start_xray(&bin).await;
    let techo = common::echo().await;
    let engine = engine(vec![outbound(
        &x,
        "wrong",
        Sec::TlsH2,
        "tls",
        json!({"type": "xhttp", "path": "/nope", "mode": "stream-up"}),
    )]);
    let out = engine.outbound("wrong").unwrap().clone();
    let r = tokio::time::timeout(Duration::from_secs(10), tcp_roundtrip(&out, techo, 1024))
        .await
        .expect("refused connection hung");
    assert!(r.is_err(), "wrong path should fail");
}
