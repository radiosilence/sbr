//! Record layer and handshake against rustls (REALITY check bypassed, since
//! rustls is an ordinary TLS server), plus ClientHello fingerprint checks.
//! The REALITY path itself is covered by `tests/singbox.rs`.

use std::sync::Arc;

use aws_lc_rs::{aead, agreement, hmac};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs as provider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, SupportedCipherSuite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::hello::{GREASE, SESSION_ID_OFFSET};
use crate::keys::{hkdf_expand, hkdf_extract};

const SNI: &str = "reality.test";

fn test_config(fp: Fingerprint, pq: bool) -> RealityConfig {
    let server = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
    RealityConfig {
        server_name: SNI.into(),
        public_key: server.compute_public_key().unwrap().as_ref().try_into().unwrap(),
        short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        fingerprint: fp,
        alpn: Vec::new(),
        post_quantum: pq,
    }
}

fn server_config(suite: SupportedCipherSuite, group: &'static dyn SupportedKxGroup) -> Arc<ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec![SNI.into()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let p = CryptoProvider {
        cipher_suites: vec![suite],
        kx_groups: vec![group],
        ..provider::default_provider()
    };
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.send_tls13_tickets = 2;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

/// Echo server; after `key_update_after` bytes it rotates its keys and asks
/// us to do the same.
async fn rustls_echo(cfg: Arc<ServerConfig>, key_update_after: Option<usize>) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await.unwrap();
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0;
        let mut updated = false;
        loop {
            let n = tls.read(&mut buf).await.unwrap();
            if n == 0 {
                tls.shutdown().await.unwrap();
                return;
            }
            tls.write_all(&buf[..n]).await.unwrap();
            total += n;
            if let Some(after) = key_update_after
                && !updated
                && total >= after
            {
                tls.get_mut().1.refresh_traffic_keys().unwrap();
                updated = true;
            }
        }
    });
    addr
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + i / 251) as u8).collect()
}

/// Sends `data` while reading the echo back, then half-closes and expects EOF.
async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(tls: RealityStream<S>, data: &[u8]) -> Vec<u8> {
    let (mut r, mut w) = tokio::io::split(tls);
    let writer = async {
        // Odd write sizes exercise record splitting and batching.
        for chunk in data.chunks(40_000 + 7) {
            w.write_all(chunk).await.unwrap();
        }
        w.flush().await.unwrap();
        w
    };
    let reader = async {
        let mut got = Vec::with_capacity(data.len());
        let mut buf = vec![0u8; 20_000];
        while got.len() < data.len() {
            let n = r.read(&mut buf).await.unwrap();
            assert!(n > 0, "early EOF after {} bytes", got.len());
            got.extend_from_slice(&buf[..n]);
        }
        got
    };
    let (mut w, got) = tokio::join!(writer, reader);
    w.shutdown().await.unwrap();
    let mut rest = Vec::new();
    r.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    got
}

async fn run(fp: Fingerprint, pq: bool, suite: SupportedCipherSuite, group: &'static dyn SupportedKxGroup) {
    let addr = rustls_echo(server_config(suite, group), Some(300_000)).await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = reality_handshake(tcp, &test_config(fp, pq), true).await.unwrap();
    assert_eq!(tls.cipher_suite().id(), u16::from(suite.suite()));
    assert_eq!(tls.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(tls.key_exchange_group(), u16::from(group.name()));
    // Also rotate our own keys mid-stream.
    tls.refresh_traffic_keys();
    let data = pattern(1 << 20);
    let got = round_trip(tls, &data).await;
    assert!(got == data, "echo mismatch for {fp:?} pq={pq} {:?}", suite.suite());
}

#[tokio::test]
async fn rustls_interop_suites_and_groups() {
    let suites = [
        provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
        provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
        provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    for suite in suites {
        run(Fingerprint::Chrome, true, suite, provider::kx_group::X25519MLKEM768).await;
        run(Fingerprint::Chrome, false, suite, provider::kx_group::X25519).await;
        run(Fingerprint::Firefox, false, suite, provider::kx_group::SECP256R1).await;
        run(Fingerprint::Safari, false, suite, provider::kx_group::X25519).await;
        run(Fingerprint::Ios, false, suite, provider::kx_group::X25519).await;
    }
}

#[tokio::test]
async fn ordinary_tls_server_is_rejected() {
    let cfg = server_config(
        provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
        provider::kx_group::X25519,
    );
    let addr = rustls_echo(cfg, None).await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let err = connect(tcp, &test_config(Fingerprint::Chrome, true))
        .await
        .err()
        .expect("must fail");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
}

#[tokio::test]
async fn server_close_notify_reads_as_eof() {
    let cfg = server_config(
        provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
        provider::kx_group::X25519,
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await.unwrap();
        tls.write_all(b"bye").await.unwrap();
        tls.shutdown().await.unwrap();
        // Keep TCP open: EOF must come from close_notify alone.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = reality_handshake(tcp, &test_config(Fingerprint::Chrome, true), true)
        .await
        .unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(2), tls.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"bye");
}

/// `cargo test --release -p sbr-reality -- --ignored --nocapture bulk_throughput`
/// Upload and download through rustls (which costs as much CPU as we do).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn bulk_throughput() {
    const TOTAL: usize = 2 << 30;
    for upload in [true, false] {
        let cfg = server_config(
            provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
            provider::kx_group::X25519,
        );
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = l.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            if upload {
                while tls.read(&mut buf).await.unwrap() > 0 {}
                tls.shutdown().await.unwrap();
            } else {
                for _ in 0..TOTAL / buf.len() {
                    tls.write_all(&buf).await.unwrap();
                }
                tls.shutdown().await.unwrap();
            }
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = reality_handshake(tcp, &test_config(Fingerprint::Chrome, false), true)
            .await
            .unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let start = std::time::Instant::now();
        if upload {
            for _ in 0..TOTAL / buf.len() {
                tls.write_all(&buf).await.unwrap();
            }
            tls.shutdown().await.unwrap();
            // Wait for the server to have read everything.
            tls.read_to_end(&mut Vec::new()).await.unwrap();
        } else {
            let mut n = 0;
            loop {
                let m = tls.read(&mut buf).await.unwrap();
                if m == 0 {
                    break;
                }
                n += m;
            }
            assert_eq!(n, TOTAL);
        }
        let secs = start.elapsed().as_secs_f64();
        let dir = if upload { "upload" } else { "download" };
        println!("{dir}: {:.2} Gbit/s", TOTAL as f64 * 8.0 / secs / 1e9);
    }
}

// ---- ClientHello inspection -------------------------------------------------

struct ParsedHello {
    msg: Vec<u8>,
    record_version: u16,
    random: [u8; 32],
    session_id: Vec<u8>,
    suites: Vec<u16>,
    exts: Vec<(u16, Vec<u8>)>,
}

impl ParsedHello {
    fn ext(&self, ty: u16) -> &[u8] {
        &self
            .exts
            .iter()
            .find(|e| e.0 == ty)
            .unwrap_or_else(|| panic!("missing ext {ty:#06x}"))
            .1
    }
    fn types(&self) -> Vec<u16> {
        self.exts.iter().map(|e| e.0).collect()
    }
}

fn u16s(b: &[u8]) -> Vec<u16> {
    b.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// Captures the ClientHello our client sends.
async fn capture(cfg: &RealityConfig) -> ParsedHello {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let cfg = cfg.clone();
    let task = tokio::spawn(async move { connect(client, &cfg).await.err() });
    let mut hdr = [0u8; 5];
    server.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 22);
    let mut msg = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
    server.read_exact(&mut msg).await.unwrap();
    drop(server);
    assert!(task.await.unwrap().is_some());

    assert_eq!(msg[0], 1);
    assert_eq!(u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize, msg.len() - 4);
    let b = &msg[4..];
    assert_eq!(&b[..2], &[3, 3]);
    let random: [u8; 32] = b[2..34].try_into().unwrap();
    let sid_len = b[34] as usize;
    let session_id = b[35..35 + sid_len].to_vec();
    let mut p = 35 + sid_len;
    let n = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    let suites = u16s(&b[p + 2..p + 2 + n]);
    p += 2 + n;
    assert_eq!(&b[p..p + 2], &[1, 0]);
    p += 2;
    let n = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    assert_eq!(p + n, b.len());
    let mut exts = Vec::new();
    while p < b.len() {
        let ty = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        exts.push((ty, b[p + 4..p + 4 + l].to_vec()));
        p += 4 + l;
    }
    ParsedHello {
        record_version: u16::from_be_bytes([hdr[1], hdr[2]]),
        msg,
        random,
        session_id,
        suites,
        exts,
    }
}

fn key_share_groups(h: &ParsedHello) -> Vec<(u16, usize)> {
    let ks = h.ext(0x0033);
    let mut out = Vec::new();
    let mut p = 2;
    while p < ks.len() {
        let g = u16::from_be_bytes([ks[p], ks[p + 1]]);
        let l = u16::from_be_bytes([ks[p + 2], ks[p + 3]]) as usize;
        out.push((g, l));
        p += 4 + l;
    }
    out
}

#[tokio::test]
async fn chrome_fingerprint() {
    let cfg = test_config(Fingerprint::Chrome, true);
    let h = capture(&cfg).await;
    assert_eq!(h.record_version, 0x0301);
    assert_eq!(h.session_id.len(), 32);

    // Cipher suites: GREASE then Chrome's list.
    assert!(is_grease(h.suites[0]));
    assert_eq!(
        &h.suites[1..],
        &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
            0x002f, 0x0035
        ]
    );

    // GREASE extensions pinned first (empty) and last (one zero byte), distinct.
    let types = h.types();
    let (first, last) = (types[0], *types.last().unwrap());
    assert!(is_grease(first) && is_grease(last) && first != last);
    assert!(h.exts[0].1.is_empty());
    assert_eq!(h.exts.last().unwrap().1, vec![0]);
    let mut middle: Vec<u16> = types[1..types.len() - 1].to_vec();
    assert!(!middle.iter().any(|&t| is_grease(t)));
    middle.sort_unstable();
    let mut expected = vec![
        0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b,
        0x44cd, 0xca34, 0xfe0d,
    ];
    expected.sort_unstable();
    assert_eq!(middle, expected);
    assert!(!types.contains(&0x0015), "Chrome sends no padding");

    // Groups and key shares: the group GREASE is shared by both.
    let groups = u16s(&h.ext(0x000a)[2..]);
    assert!(is_grease(groups[0]));
    assert_eq!(&groups[1..], &[0x11ec, 0x001d, 0x0017, 0x0018]);
    let shares = key_share_groups(&h);
    assert_eq!(shares, vec![(groups[0], 1), (0x11ec, 1184 + 32), (0x001d, 32)]);

    let versions = u16s(&h.ext(0x002b)[1..]);
    assert!(is_grease(versions[0]));
    assert_eq!(&versions[1..], &[0x0304, 0x0303]);
    let sigalgs = u16s(&h.ext(0x000d)[2..]);
    assert!(is_grease(sigalgs[0]));
    assert_eq!(&sigalgs[1..], CHROME_SIGALGS_EXPECTED);
    assert_eq!(h.ext(0xca34).len(), 186);
    assert_eq!(h.ext(0x0010), b"\x00\x0c\x02h2\x08http/1.1");
    assert_eq!(h.ext(0x44cd), b"\x00\x03\x02h2");
    assert_eq!(h.ext(0x001b), &[2, 0, 2]);
    assert_eq!(h.ext(0x0000), b"\x00\x0f\x00\x00\x0creality.test");
    assert_eq!(h.ext(0x002d), &[1, 1]);
    assert_eq!(h.ext(0x0005), &[1, 0, 0, 0, 0]);
    assert_eq!(h.ext(0xff01), &[0]);
    let ech = h.ext(0xfe0d);
    assert_eq!(&ech[..5], &[0, 0, 1, 0, 1]); // outer, HKDF-SHA256, AES-128-GCM
    assert_eq!(&ech[6..8], &[0, 32]);
    let payload_len = u16::from_be_bytes([ech[40], ech[41]]);
    assert!([144, 176, 208, 240].contains(&payload_len));
    assert_eq!(ech.len(), 42 + payload_len as usize);

    // Chrome permutes extensions per connection; 16! orders, so two captures
    // agreeing on all of them would mean no shuffle at all.
    let mut orders = std::collections::HashSet::new();
    for _ in 0..4 {
        let h = capture(&cfg).await;
        orders.insert(
            h.types()
                .iter()
                .filter(|t| !is_grease(**t))
                .copied()
                .collect::<Vec<_>>(),
        );
    }
    assert!(orders.len() > 1, "extension order is not randomized");
}

const CHROME_SIGALGS_EXPECTED: &[u16] = &[
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

#[tokio::test]
async fn chrome_without_post_quantum_and_custom_alpn() {
    let mut cfg = test_config(Fingerprint::Chrome, false);
    cfg.alpn = vec!["http/1.1".into()];
    let h = capture(&cfg).await;
    assert_eq!(&u16s(&h.ext(0x000a)[2..])[1..], &[0x001d, 0x0017, 0x0018]);
    assert_eq!(
        key_share_groups(&h).iter().map(|s| s.0).skip(1).collect::<Vec<_>>(),
        vec![0x001d]
    );
    assert_eq!(h.ext(0x0010), b"\x00\x09\x08http/1.1");
}

#[tokio::test]
async fn apple_and_firefox_fingerprints() {
    // Apple: fixed order, GREASE first and last, no padding (the hello is
    // over 512 bytes with ML-KEM); Safari and iOS share the stack.
    for fp in [Fingerprint::Safari, Fingerprint::Ios] {
        let h = capture(&test_config(fp, true)).await;
        let t = h.types();
        assert_eq!(t.len(), 15);
        assert!(is_grease(t[0]) && is_grease(t[14]));
        assert_eq!(
            &t[1..14],
            &[
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b
            ]
        );
        assert!(is_grease(h.suites[0]));
        assert_eq!(&h.suites[1..4], &[0x1302, 0x1303, 0x1301]);
        assert_eq!(h.suites.len(), 21);
        assert_eq!(u16s(&h.ext(0x002b)[1..])[1..], [0x0304, 0x0303]);
        assert_eq!(
            &u16s(&h.ext(0x000a)[2..])[1..],
            &[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
        );
        assert_eq!(
            key_share_groups(&h).iter().skip(1).copied().collect::<Vec<_>>(),
            vec![(0x11ec, 1216), (0x001d, 32)]
        );
        assert_eq!(h.ext(0x001b), &[2, 0, 1]);
    }

    let ff = capture(&test_config(Fingerprint::Firefox, true)).await;
    assert_eq!(
        ff.types(),
        vec![
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b, 0x000d, 0x001c,
            0x001b, 0xfe0d
        ]
    );
    assert!(!ff.suites.iter().any(|&s| is_grease(s)));
    assert_eq!(
        key_share_groups(&ff),
        vec![(0x11ec, 1184 + 32), (0x001d, 32), (0x0017, 65)]
    );
    // The standalone X25519 share is the hybrid's X25519 half.
    let ks = ff.ext(0x0033);
    let hybrid_x = &ks[2 + 4 + 1184..2 + 4 + 1184 + 32];
    let x = &ks[2 + 4 + 1216 + 4..2 + 4 + 1216 + 4 + 32];
    assert_eq!(hybrid_x, x);
    assert_eq!(ff.ext(0x001c), &[0x40, 0x01]);
    assert_eq!(ff.ext(0x001b), &[6, 0, 1, 0, 2, 0, 3]);
}

#[tokio::test]
async fn ip_server_name_sends_no_sni() {
    let mut cfg = test_config(Fingerprint::Chrome, true);
    cfg.server_name = "127.0.0.1".into();
    let h = capture(&cfg).await;
    assert!(!h.types().contains(&0x0000));
}

/// Plays the server side of REALITY (metacubex/utls `reality.go`): recover
/// the auth key from the X25519 share and open the session_id.
#[tokio::test]
async fn session_id_opens_like_the_server() {
    let server = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
    let mut cfg = test_config(Fingerprint::Chrome, true);
    cfg.public_key = server.compute_public_key().unwrap().as_ref().try_into().unwrap();
    cfg.short_id = parse_short_id("a1b2c3").unwrap();
    let h = capture(&cfg).await;

    let ks = h.ext(0x0033);
    let mut p = 2;
    let mut x25519 = None;
    while p < ks.len() {
        let g = u16::from_be_bytes([ks[p], ks[p + 1]]);
        let l = u16::from_be_bytes([ks[p + 2], ks[p + 3]]) as usize;
        if g == 0x001d {
            x25519 = Some(ks[p + 4..p + 4 + l].to_vec());
        }
        p += 4 + l;
    }
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, x25519.unwrap());
    let prk = agreement::agree(&server, peer, (), |ss| {
        Ok(hkdf_extract(hmac::HMAC_SHA256, &h.random[..20], ss))
    })
    .unwrap();
    let mut key = [0u8; 32];
    hkdf_expand(hmac::HMAC_SHA256, prk.as_ref(), &[b"REALITY"], &mut key);

    let mut aad = h.msg.clone();
    aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].fill(0);
    let mut sid = h.session_id.clone();
    let k = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
    let nonce = aead::Nonce::try_assume_unique_for_key(&h.random[20..]).unwrap();
    let plain = k
        .open_in_place(nonce, aead::Aad::from(&aad), &mut sid)
        .expect("server can open the session_id");
    assert_eq!(&plain[..4], &[1, 8, 1, 0]);
    let t = u32::from_be_bytes(plain[4..8].try_into().unwrap()) as u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(now.abs_diff(t) < 5);
    assert_eq!(&plain[8..16], &[0xa1, 0xb2, 0xc3, 0, 0, 0, 0, 0]);
    let _ = GREASE;
}

#[test]
fn config_parsing() {
    assert!(parse_public_key("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0").is_ok());
    assert!(parse_public_key("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0=").is_err());
    assert!(parse_public_key("AAAA").is_err());
    assert_eq!(parse_short_id("").unwrap(), [0; 8]);
    assert_eq!(
        parse_short_id("0123456789abcdef").unwrap(),
        [1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    );
    assert!(parse_short_id("abc").is_err());
    assert!(parse_short_id("0123456789abcdef00").is_err());
    assert!(parse_short_id("zz").is_err());
    assert!("edge".parse::<Fingerprint>().is_err());
    assert_eq!("".parse::<Fingerprint>().unwrap(), Fingerprint::Chrome);
}
