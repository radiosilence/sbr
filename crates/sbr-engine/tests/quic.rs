//! hysteria2 and TUIC against a real sing-box server.
//!
//! Needs a sing-box built with `-tags with_quic`: set `SING_BOX` to its
//! path (or have `sing-box` on `PATH`). Without one, every test prints why
//! and passes.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use sbr_engine::outbound::{BuildContext, build_all};
use sbr_engine::sbr_config::Options;
use sbr_engine::sbr_core::dns::SystemDns;
use sbr_engine::sbr_core::{Destination, Outbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const PASSWORD: &str = "correct horse";
const UUID: &str = "2dd61d93-75d8-4da4-ac0e-6aece7eac365";

fn sing_box() -> Option<PathBuf> {
    let bin = std::env::var_os("SING_BOX").map(PathBuf::from).or_else(|| {
        std::env::var_os("PATH")?
            .to_str()?
            .split(':')
            .map(|d| PathBuf::from(d).join("sing-box"))
            .find(|p| p.is_file())
    });
    if bin.is_none() {
        eprintln!("SKIP: no sing-box binary (set SING_BOX=/path/to/sing-box built with -tags with_quic)");
    }
    bin
}

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Cert {
    pem: String,
    cert_path: PathBuf,
    key_path: PathBuf,
}

fn cert(dir: &std::path::Path) -> Cert {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let pem = ck.cert.pem();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, &pem).unwrap();
    std::fs::write(&key_path, ck.signing_key.serialize_pem()).unwrap();
    Cert {
        pem,
        cert_path,
        key_path,
    }
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Starts sing-box with one inbound (`inbound` is the JSON object minus
/// listen/tls) and returns it with the client-side certificate PEM.
/// `None` means skip.
fn start_server(inbound: &str, port: u16) -> Option<(Server, String)> {
    let bin = sing_box()?;
    let dir = std::env::temp_dir().join(format!("sbr-quic-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let c = cert(&dir);
    let cfg = format!(
        r#"{{"log":{{"level":"info"}},
            "inbounds":[{{{inbound},"listen":"127.0.0.1","listen_port":{port},
                "tls":{{"enabled":true,"alpn":["h3"],"certificate_path":{:?},"key_path":{:?}}}}}],
            "outbounds":[{{"type":"direct"}}]}}"#,
        c.cert_path, c.key_path
    );
    let path = dir.join("server.json");
    std::fs::write(&path, cfg).unwrap();
    let mut child = Command::new(&bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait for "sing-box started"; keep draining stderr afterwards so the
    // server never blocks on a full pipe.
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if std::env::var_os("SBR_TEST_SERVER_LOG").is_some() {
                eprintln!("[sing-box] {line}");
            }
            if line.contains("QUIC is not included") || line.contains("FATAL") {
                if let Some(t) = tx.take() {
                    let _ = t.send(Err(line));
                }
            } else if line.contains("started")
                && let Some(t) = tx.take()
            {
                let _ = t.send(Ok(()));
            }
        }
    });
    let server = Server { child, dir };
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => Some((server, c.pem)),
        Ok(Err(line)) if line.contains("QUIC is not included") => {
            eprintln!("SKIP: sing-box was built without with_quic");
            None
        }
        other => panic!("sing-box failed to start: {other:?}"),
    }
}

fn outbound(json: &str) -> Arc<dyn Outbound> {
    let o = Options::parse(&format!(
        r#"{{"outbounds":[{json},{{"type":"direct","tag":"direct"}}]}}"#
    ))
    .unwrap();
    let ctx = BuildContext {
        dns: Arc::new(SystemDns),
    };
    build_all(&o.outbounds, &ctx).unwrap().remove(0)
}

fn tls(pem: &str) -> String {
    format!(
        r#""tls":{{"enabled":true,"server_name":"localhost","alpn":["h3"],"certificate":{}}}"#,
        serde_json::to_string(pem).unwrap()
    )
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = s.recv_from(&mut buf).await.unwrap();
            s.send_to(&buf[..n], from).await.unwrap();
        }
    });
    addr
}

/// Pushes 1 MiB (+ an odd tail) through and compares byte for byte.
async fn tcp_roundtrip(out: &dyn Outbound) {
    let echo = tcp_echo().await;
    let s = out.connect(&Destination::from(echo)).await.unwrap();
    let data: Vec<u8> = (0..(1 << 20) + 4093).map(|i: u32| (i * 7 + i / 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(s);
    let send = data.clone();
    let writer = tokio::spawn(async move {
        for chunk in send.chunks(60_000) {
            w.write_all(chunk).await.unwrap();
        }
        w.flush().await.unwrap();
        w
    });
    let mut got = vec![0u8; data.len()];
    tokio::time::timeout(Duration::from_secs(20), r.read_exact(&mut got))
        .await
        .expect("TCP round trip timed out")
        .unwrap();
    assert!(got == data, "1 MiB must come back intact");
    let mut w = writer.await.unwrap();
    w.shutdown().await.unwrap();
}

/// A small datagram, then one far above the path MTU (fragmented).
async fn udp_roundtrip(out: &dyn Outbound) {
    let echo = udp_echo().await;
    let dest = Destination::from(echo);
    let pc = out.connect_udp(&dest).await.unwrap();
    let mut buf = vec![0u8; 65535];
    for size in [5usize, 3000, 4000] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
        // UDP: retry a few times rather than flake on a dropped datagram.
        let mut ok = false;
        for _ in 0..5 {
            pc.send_to(&payload, &dest).await.unwrap();
            if let Ok(r) = tokio::time::timeout(Duration::from_secs(2), pc.recv_from(&mut buf)).await {
                let (n, from) = r.unwrap();
                assert_eq!(from, dest);
                assert_eq!(&buf[..n], &payload[..], "{size}-byte datagram");
                ok = true;
                break;
            }
        }
        assert!(ok, "no echo for a {size}-byte datagram");
    }
}

fn hy2_inbound(extra: &str) -> String {
    format!(r#""type":"hysteria2","users":[{{"password":"{PASSWORD}"}}]{extra}"#)
}

#[tokio::test(flavor = "multi_thread")]
async fn hysteria2_tcp_and_udp() {
    let port = free_udp_port();
    let Some((_server, pem)) = start_server(&hy2_inbound(""), port) else {
        return;
    };
    let out = outbound(&format!(
        r#"{{"type":"hysteria2","tag":"hy2","server":"127.0.0.1","server_port":{port},"password":"{PASSWORD}",{}}}"#,
        tls(&pem)
    ));
    tcp_roundtrip(out.as_ref()).await;
    udp_roundtrip(out.as_ref()).await;
    // A second stream reuses the connection.
    tcp_roundtrip(out.as_ref()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hysteria2_salamander_brutal_and_hopping() {
    let port = free_udp_port();
    let obfs = r#","obfs":{"type":"salamander","password":"cry me a river"}"#;
    let Some((_server, pem)) = start_server(&hy2_inbound(obfs), port) else {
        return;
    };
    let out = outbound(&format!(
        r#"{{"type":"hysteria2","tag":"hy2","server":"127.0.0.1","server_ports":["{port}:{port}"],"hop_interval":"5s",
            "up_mbps":500,"down_mbps":500,"password":"{PASSWORD}"{obfs},{}}}"#,
        tls(&pem)
    ));
    tcp_roundtrip(out.as_ref()).await;
    udp_roundtrip(out.as_ref()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hysteria2_over_detour() {
    // QUIC over the detour's PacketConn instead of a system socket.
    let port = free_udp_port();
    let Some((_server, pem)) = start_server(&hy2_inbound(""), port) else {
        return;
    };
    let out = outbound(&format!(
        r#"{{"type":"hysteria2","tag":"hy2","server":"127.0.0.1","server_port":{port},"password":"{PASSWORD}","detour":"direct",{}}}"#,
        tls(&pem)
    ));
    tcp_roundtrip(out.as_ref()).await;
    udp_roundtrip(out.as_ref()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hysteria2_wrong_password() {
    let port = free_udp_port();
    let Some((_server, pem)) = start_server(&hy2_inbound(""), port) else {
        return;
    };
    let out = outbound(&format!(
        r#"{{"type":"hysteria2","tag":"hy2","server":"127.0.0.1","server_port":{port},"password":"wrong",{}}}"#,
        tls(&pem)
    ));
    let err = out
        .connect(&Destination::from_host_port("127.0.0.1", 9))
        .await
        .err()
        .expect("wrong password must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert!(err.to_string().contains("authentication failed"), "{err}");
}

fn tuic_inbound(password: &str) -> String {
    format!(r#""type":"tuic","users":[{{"uuid":"{UUID}","password":"{password}"}}],"zero_rtt_handshake":true"#)
}

#[tokio::test(flavor = "multi_thread")]
async fn tuic_relay_modes() {
    let port = free_udp_port();
    let Some((_server, pem)) = start_server(&tuic_inbound(PASSWORD), port) else {
        return;
    };
    for (mode, cc) in [
        (r#""udp_relay_mode":"native""#, "cubic"),
        (r#""udp_relay_mode":"quic""#, "bbr"),
        (r#""udp_over_stream":true"#, "new_reno"),
    ] {
        let out = outbound(&format!(
            r#"{{"type":"tuic","tag":"tuic","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}","password":"{PASSWORD}",
                "congestion_control":"{cc}",{mode},"heartbeat":"3s",{}}}"#,
            tls(&pem)
        ));
        tcp_roundtrip(out.as_ref()).await;
        udp_roundtrip(out.as_ref()).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tuic_zero_rtt() {
    let port = free_udp_port();
    let Some((_server, pem)) = start_server(&tuic_inbound(PASSWORD), port) else {
        return;
    };
    let out = outbound(&format!(
        r#"{{"type":"tuic","tag":"tuic","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}","password":"{PASSWORD}",
            "zero_rtt_handshake":true,"idle_timeout":"1s",{}}}"#,
        tls(&pem)
    ));
    // The first connection gets a session ticket; once it idles out, the
    // next one resumes with 0-RTT.
    tcp_roundtrip(out.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(1600)).await;
    tcp_roundtrip(out.as_ref()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tuic_wrong_password() {
    let port = free_udp_port();
    let Some((_server, pem)) = start_server(&tuic_inbound(PASSWORD), port) else {
        return;
    };
    let out = outbound(&format!(
        r#"{{"type":"tuic","tag":"tuic","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}","password":"wrong",{}}}"#,
        tls(&pem)
    ));
    let echo = tcp_echo().await;
    // TUIC has no auth response: the server closes the connection.
    let res = async {
        let mut s = out.connect(&Destination::from(echo)).await?;
        s.write_all(b"hello").await?;
        let mut b = [0u8; 5];
        s.read_exact(&mut b).await?;
        std::io::Result::Ok(())
    };
    let r = tokio::time::timeout(Duration::from_secs(10), res)
        .await
        .expect("must not hang");
    assert!(r.is_err(), "wrong TUIC password must not relay");
}
