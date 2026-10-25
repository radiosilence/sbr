//! ClientHello fragmentation against a model SNI filter
//! (`common/sni_censor.rs`): the automatic mode, configured fragmentation,
//! and the `route-options` form for connections routed `direct`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::sni_censor::{self, Records};
use common::{echo, port, socks_connect, start};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sbr_engine::sbr_config::Options;
use sbr_engine::sbr_core::Destination;
use sbr_engine::{Engine, Settings};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NAME: &str = "blocked.example";

/// Automatic levels are process-wide per network (`network_changed`), so
/// these tests run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn acceptor() -> tokio_rustls::TlsAcceptor {
    let c = rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
    let certs = CertificateDer::pem_slice_iter(c.cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(c.signing_key.serialize_pem().as_bytes()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

/// An HTTP CONNECT proxy over TLS (the `http` outbound's server).
async fn https_proxy() -> SocketAddr {
    let acceptor = acceptor();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut t) = acceptor.accept(s).await else { return };
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if t.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let line = String::from_utf8_lossy(&head);
                let target = line.split_whitespace().nth(1).unwrap().to_owned();
                let Ok(mut up) = TcpStream::connect(target).await else {
                    return;
                };
                t.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut t, &mut up).await;
            });
        }
    });
    addr
}

/// A TLS echo server for `NAME`.
async fn tls_echo() -> SocketAddr {
    let acceptor = acceptor();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(t) = acceptor.accept(s).await else { return };
                let (mut r, mut w) = tokio::io::split(t);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

fn engine(censor_port: u16, tls: Value) -> Engine {
    let mut t = json!({"enabled": true, "server_name": NAME, "insecure": true, "fragment_fallback_delay": "50ms"});
    t.as_object_mut().unwrap().extend(tls.as_object().unwrap().clone());
    let opts = Options::from_value(json!({"outbounds": [{
        "type": "http", "tag": "out", "server": "127.0.0.1", "server_port": censor_port, "tls": t,
    }]}))
    .unwrap();
    Engine::new(&opts, &Settings::default()).unwrap()
}

async fn echo_through(e: &Engine, target: SocketAddr) -> std::io::Result<()> {
    let mut s = e.outbound("out").unwrap().connect(&Destination::from(target)).await?;
    let msg = vec![7u8; 64 * 1024];
    s.write_all(&msg).await?;
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got))
        .await
        .map_err(|_| std::io::Error::other("echo timed out"))??;
    assert!(got == msg);
    Ok(())
}

#[tokio::test]
async fn auto_splits_records_when_the_filter_reads_one_record() {
    let _serial = SERIAL.lock().await;
    let c = sni_censor::start(https_proxy().await, NAME, Records::First).await;
    let e = engine(c.port, json!({}));
    let target = echo().await;
    // The first connection is reset once, retried with split records, and
    // succeeds without the caller seeing the reset.
    echo_through(&e, target).await.unwrap();
    assert_eq!((c.resets(), c.passed()), (1, 1));
    // Later connections start split.
    for _ in 0..3 {
        echo_through(&e, target).await.unwrap();
    }
    assert_eq!((c.resets(), c.passed()), (1, 4));
}

#[tokio::test]
async fn auto_splits_segments_when_the_filter_joins_records() {
    let _serial = SERIAL.lock().await;
    let c = sni_censor::start(https_proxy().await, NAME, Records::Joined).await;
    let e = engine(c.port, json!({}));
    let target = echo().await;
    echo_through(&e, target).await.unwrap();
    assert_eq!((c.resets(), c.passed()), (2, 1), "records first, then segments");
    echo_through(&e, target).await.unwrap();
    assert_eq!((c.resets(), c.passed()), (2, 2));
    // A network change starts over.
    e.network_changed();
    echo_through(&e, target).await.unwrap();
    assert_eq!((c.resets(), c.passed()), (4, 3));
}

#[tokio::test]
async fn auto_off_or_configured_fragmentation_never_escalates() {
    let _serial = SERIAL.lock().await;
    let target = echo().await;
    let c = sni_censor::start(https_proxy().await, NAME, Records::First).await;
    let e = engine(c.port, json!({"disable_auto_fragment": true}));
    for _ in 0..2 {
        let err = echo_through(&e, target).await.unwrap_err();
        assert!(!err.to_string().contains("retrying"), "{err}");
    }
    assert_eq!((c.resets(), c.passed()), (2, 0));

    // Explicit record fragmentation is not raised to segments.
    let c = sni_censor::start(https_proxy().await, NAME, Records::Joined).await;
    let e = engine(c.port, json!({"record_fragment": true}));
    assert!(echo_through(&e, target).await.is_err());
    assert_eq!((c.resets(), c.passed()), (1, 0));
    let e = engine(c.port, json!({"fragment": true}));
    echo_through(&e, target).await.unwrap();
    assert_eq!((c.resets(), c.passed()), (1, 1));
}

#[tokio::test]
async fn auto_ignores_servers_that_answer() {
    let _serial = SERIAL.lock().await;
    // A server that answers with garbage is not SNI filtering.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
        }
    });
    let e = engine(p, json!({}));
    let target = echo().await;
    assert!(echo_through(&e, target).await.is_err());
    assert!(echo_through(&e, target).await.is_err());
}

/// sing-box `route-options` `tls_record_fragment` on a `direct` route: the
/// app's own ClientHello is split.
#[tokio::test]
async fn route_options_fragment_direct_connections() {
    let _serial = SERIAL.lock().await;
    let c = sni_censor::start(tls_echo().await, NAME, Records::First).await;
    let target: SocketAddr = ([127, 0, 0, 1], c.port).into();
    let connector = {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert))
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
    };
    for (fragment, ok) in [(false, false), (true, true)] {
        let rules = if fragment {
            json!([{"inbound": ["in"], "action": "route-options", "tls_record_fragment": true}])
        } else {
            json!([])
        };
        let cfg = json!({
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": rules, "final": "direct"},
        });
        let i = start(&cfg.to_string()).await;
        let s = socks_connect(port(&i, "in"), target).await;
        let r = connector.connect(ServerName::try_from(NAME).unwrap(), s).await;
        match r {
            Ok(mut t) => {
                assert!(ok, "handshake passed the filter without fragmentation");
                t.write_all(b"ping").await.unwrap();
                let mut b = [0u8; 4];
                t.read_exact(&mut b).await.unwrap();
                assert_eq!(&b, b"ping");
            }
            Err(e) => assert!(!ok, "fragmented handshake failed: {e}"),
        }
    }
    assert_eq!((c.resets(), c.passed()), (1, 1));
}

#[derive(Debug)]
struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
