//! Ordinary TLS ([`connect_tls`]) against rustls servers, and the JA3/JA4
//! fingerprints of every profile against the real browsers'.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use md5::{Digest as _, Md5};
use rustls::compress::{CertCompressor, CompressionFailed, CompressionLevel};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs as provider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{CertificateCompressionAlgorithm, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

const NAME: &str = "parrot.test";

struct Pki {
    roots: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivatePkcs8KeyDer<'static>,
    /// A client certificate the server could ask for.
    client_roots: Arc<RootCertStore>,
}

fn pki() -> Pki {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![NAME.to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
    let roots = Arc::new(roots);
    Pki {
        client_roots: roots.clone(),
        roots,
        chain: vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(ca.der().to_vec()),
        ],
        key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
    }
}

fn verifier(roots: &Arc<RootCertStore>) -> Arc<dyn ServerCertVerifier> {
    rustls::client::WebPkiServerVerifier::builder_with_provider(roots.clone(), Arc::new(provider::default_provider()))
        .build()
        .unwrap()
}

fn client(fp: Fingerprint, pki: &Pki) -> TlsConfig {
    TlsConfig {
        server_name: ServerName::try_from(NAME).unwrap(),
        sni: true,
        fingerprint: fp,
        alpn: Vec::new(),
        post_quantum: true,
        verifier: verifier(&pki.roots),
    }
}

fn server(
    pki: &Pki,
    groups: Vec<&'static dyn SupportedKxGroup>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ServerConfig {
    let p = CryptoProvider {
        kx_groups: groups,
        ..provider::default_provider()
    };
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.chain.clone(), PrivateKeyDer::Pkcs8(pki.key.clone_key()))
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg.send_tls13_tickets = 2;
    cfg
}

/// Accepts one connection and echoes until EOF. The server's error, if any,
/// comes back through the handle.
async fn echo(cfg: ServerConfig) -> (std::net::SocketAddr, tokio::task::JoinHandle<Result<(), String>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
            .accept(tcp)
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = tls.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                tls.shutdown().await.map_err(|e| e.to_string())?;
                return Ok(());
            }
            tls.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
            // tokio-rustls may keep records it could not write yet; without a
            // flush they wait for the next read, which never comes once the
            // client has sent everything.
            tls.flush().await.map_err(|e| e.to_string())?;
        }
    });
    (addr, h)
}

async fn echo_1mib(tls: &mut TlsStream<TcpStream>) {
    let data: Vec<u8> = (0..1 << 20).map(|i: usize| (i * 7 + i / 509) as u8).collect();
    let (mut r, mut w) = tokio::io::split(tls);
    let writer = async {
        w.write_all(&data).await.unwrap();
        w.flush().await.unwrap();
    };
    let reader = async {
        let mut got = vec![0u8; data.len()];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let ((), got) = tokio::join!(writer, reader);
    assert!(got == data, "echo mismatch");
}

#[tokio::test]
async fn webpki_verified_round_trip_every_profile() {
    let pki = pki();
    for fp in [
        Fingerprint::Chrome,
        Fingerprint::Firefox,
        Fingerprint::Safari,
        Fingerprint::Ios,
    ] {
        let groups = vec![provider::kx_group::X25519MLKEM768, provider::kx_group::X25519];
        let (addr, srv) = echo(server(&pki, groups, &[&rustls::version::TLS13])).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect_tls(tcp, &client(fp, &pki)).await.unwrap();
        assert_eq!(tls.alpn_protocol(), Some(&b"h2"[..]), "{fp:?}");
        assert_eq!(tls.key_exchange_group(), 0x11ec, "{fp:?}");
        echo_1mib(&mut tls).await;
        tls.shutdown().await.unwrap();
        srv.await.unwrap().unwrap();
    }
}

/// Certificate compressors for the test servers. rustls' own (its `brotli`
/// and `zlib` features) would be unified into every rustls server in a
/// workspace test build, and REALITY servers fail when their handshake
/// target compresses its chain.
#[derive(Debug)]
struct Compressor(CertificateCompressionAlgorithm, &'static AtomicUsize);

impl CertCompressor for Compressor {
    fn compress(&self, input: Vec<u8>, _: CompressionLevel) -> Result<Vec<u8>, CompressionFailed> {
        use std::io::Write as _;
        self.1.fetch_add(1, Ordering::Relaxed);
        let mut out = Vec::new();
        match self.0 {
            CertificateCompressionAlgorithm::Brotli => {
                let params = brotli::enc::BrotliEncoderParams::default();
                brotli::BrotliCompress(&mut &input[..], &mut out, &params).map_err(|_| CompressionFailed)?;
            }
            _ => {
                let mut z = flate2::write::ZlibEncoder::new(&mut out, flate2::Compression::default());
                z.write_all(&input).map_err(|_| CompressionFailed)?;
                z.finish().map_err(|_| CompressionFailed)?;
            }
        }
        Ok(out)
    }
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        self.0
    }
}

/// Chrome offers brotli and Apple zlib (RFC 8879); servers that support it
/// (Google, Cloudflare) compress, so the chain must decompress and verify.
#[tokio::test]
async fn compressed_certificate_chains_verify() {
    static BROTLI: AtomicUsize = AtomicUsize::new(0);
    static ZLIB: AtomicUsize = AtomicUsize::new(0);
    static BROTLI_C: Compressor = Compressor(CertificateCompressionAlgorithm::Brotli, &BROTLI);
    static ZLIB_C: Compressor = Compressor(CertificateCompressionAlgorithm::Zlib, &ZLIB);
    let pki = pki();
    for (fp, counter) in [(Fingerprint::Chrome, &BROTLI), (Fingerprint::Safari, &ZLIB)] {
        let mut cfg = server(&pki, vec![provider::kx_group::X25519], &[&rustls::version::TLS13]);
        cfg.cert_compressors = vec![&BROTLI_C, &ZLIB_C];
        cfg.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
        let (addr, srv) = echo(cfg).await;
        let before = counter.load(Ordering::Relaxed);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect_tls(tcp, &client(fp, &pki)).await.unwrap();
        assert_eq!(
            counter.load(Ordering::Relaxed),
            before + 1,
            "{fp:?}: chain not compressed"
        );
        echo_1mib(&mut tls).await;
        tls.shutdown().await.unwrap();
        srv.await.unwrap().unwrap();
    }
}

/// A server without our key share groups asks again (HelloRetryRequest).
#[tokio::test]
async fn hello_retry_request() {
    let pki = pki();
    for (fp, group, id) in [
        (Fingerprint::Chrome, provider::kx_group::SECP256R1, 0x0017),
        (Fingerprint::Chrome, provider::kx_group::SECP384R1, 0x0018),
        (Fingerprint::Safari, provider::kx_group::SECP384R1, 0x0018),
        (Fingerprint::Firefox, provider::kx_group::SECP384R1, 0x0018),
    ] {
        let (addr, srv) = echo(server(&pki, vec![group], &[&rustls::version::TLS13])).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect_tls(tcp, &client(fp, &pki)).await.unwrap();
        assert_eq!(tls.key_exchange_group(), id);
        echo_1mib(&mut tls).await;
        tls.shutdown().await.unwrap();
        srv.await.unwrap().unwrap();
    }
}

/// A browser without a client certificate answers CertificateRequest with
/// an empty Certificate; a server that only prefers client auth carries on.
#[tokio::test]
async fn optional_client_auth_gets_an_empty_certificate() {
    let pki = pki();
    let p = Arc::new(provider::default_provider());
    let cv = rustls::server::WebPkiClientVerifier::builder_with_provider(pki.client_roots.clone(), p.clone())
        .allow_unauthenticated()
        .build()
        .unwrap();
    let mut cfg = ServerConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(cv)
        .with_single_cert(pki.chain.clone(), PrivateKeyDer::Pkcs8(pki.key.clone_key()))
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let (addr, srv) = echo(cfg).await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = connect_tls(tcp, &client(Fingerprint::Chrome, &pki)).await.unwrap();
    echo_1mib(&mut tls).await;
    tls.shutdown().await.unwrap();
    srv.await.unwrap().unwrap();
}

#[tokio::test]
async fn bad_certificates_are_rejected() {
    let pki = pki();
    let other = pki_other_ca();
    // Wrong name, then an unknown CA.
    let mut wrong_name = client(Fingerprint::Chrome, &pki);
    wrong_name.server_name = ServerName::try_from("other.test").unwrap();
    let mut wrong_ca = client(Fingerprint::Chrome, &pki);
    wrong_ca.verifier = verifier(&other);
    for cfg in [wrong_name, wrong_ca] {
        let (addr, srv) = echo(server(
            &pki,
            vec![provider::kx_group::X25519],
            &[&rustls::version::TLS13],
        ))
        .await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect_tls(tcp, &cfg).await.err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(srv.await.unwrap().is_err());
    }
}

fn pki_other_ca() -> Arc<RootCertStore> {
    pki().roots
}

#[tokio::test]
async fn tls12_only_server_is_unsupported() {
    let pki = pki();
    let (addr, _srv) = echo(server(
        &pki,
        vec![provider::kx_group::X25519],
        &[&rustls::version::TLS12],
    ))
    .await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let err = connect_tls(tcp, &client(Fingerprint::Chrome, &pki))
        .await
        .err()
        .expect("must fail");
    assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
}

#[tokio::test]
async fn shadowtls_style_session_id_hook() {
    let pki = pki();
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
    let cfg = client(Fingerprint::Chrome, &pki);
    let task = tokio::spawn(async move {
        let fill = |m: &mut [u8]| {
            assert!(m[39..71].iter().all(|&b| b == 0));
            m[39..71].fill(0x42);
        };
        connect_tls_with_session_id(client_io, &cfg, Some(&fill)).await.err()
    });
    let mut hdr = [0u8; 5];
    server_io.read_exact(&mut hdr).await.unwrap();
    let mut msg = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
    server_io.read_exact(&mut msg).await.unwrap();
    drop(server_io);
    assert!(task.await.unwrap().is_some());
    assert_eq!(msg[38], 32);
    assert_eq!(&msg[39..71], &[0x42; 32]);
}

// ---- JA3 / JA4 ---------------------------------------------------------------

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn u16s(b: &[u8]) -> Vec<u16> {
    b.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

/// (cipher suites, extensions) of a ClientHello handshake message.
fn parse(msg: &[u8]) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
    let b = &msg[4..];
    let mut p = 2 + 32;
    p += 1 + b[p] as usize;
    let n = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    let suites = u16s(&b[p + 2..p + 2 + n]);
    p += 2 + n;
    p += 1 + b[p] as usize;
    p += 2;
    let mut exts = Vec::new();
    while p < b.len() {
        let ty = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        exts.push((ty, b[p + 4..p + 4 + l].to_vec()));
        p += 4 + l;
    }
    (suites, exts)
}

fn hex12(s: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, s.as_bytes());
    d.as_ref()[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn join(v: impl IntoIterator<Item = u16>, sep: &str, hex: bool) -> String {
    v.into_iter()
        .map(|x| if hex { format!("{x:04x}") } else { x.to_string() })
        .collect::<Vec<_>>()
        .join(sep)
}

/// JA4 (FoxIO, `technical_details/JA4.md`) of a TCP ClientHello.
fn ja4(msg: &[u8]) -> String {
    let (suites, exts) = parse(msg);
    let ext = |t: u16| exts.iter().find(|e| e.0 == t).map(|e| &e.1[..]);
    let suites: Vec<u16> = suites.into_iter().filter(|&s| !is_grease(s)).collect();
    let types: Vec<u16> = exts.iter().map(|e| e.0).filter(|&t| !is_grease(t)).collect();
    let version = ext(0x002b)
        .map(|v| u16s(&v[1..]).into_iter().filter(|&v| !is_grease(v)).max().unwrap())
        .unwrap_or(0x0303);
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        _ => "00",
    };
    let alpn = ext(0x0010).map_or("00".to_owned(), |a| {
        let first = &a[3..3 + a[2] as usize];
        format!("{}{}", first[0] as char, *first.last().unwrap() as char)
    });
    let a = format!(
        "t{version}{}{:02}{:02}{alpn}",
        if ext(0).is_some() { 'd' } else { 'i' },
        suites.len().min(99),
        types.len().min(99)
    );
    let mut sorted = suites.clone();
    sorted.sort_unstable();
    let b = hex12(&join(sorted, ",", true));
    let mut e: Vec<u16> = types.into_iter().filter(|&t| t != 0 && t != 0x0010).collect();
    e.sort_unstable();
    let mut c = join(e, ",", true);
    if let Some(s) = ext(0x000d) {
        let algs = u16s(&s[2..]).into_iter().filter(|&a| !is_grease(a));
        c = format!("{c}_{}", join(algs, ",", true));
    }
    format!("{a}_{b}_{}", hex12(&c))
}

/// JA3 (Salesforce): `version,ciphers,extensions,groups,point_formats`,
/// GREASE removed, MD5. `sorted` sorts the extensions first ("JA3N"), the
/// stable form for clients that permute their extensions.
fn ja3(msg: &[u8], sorted: bool) -> String {
    let (suites, exts) = parse(msg);
    let ext = |t: u16| exts.iter().find(|e| e.0 == t).map(|e| &e.1[..]);
    let mut types: Vec<u16> = exts.iter().map(|e| e.0).filter(|&t| !is_grease(t)).collect();
    if sorted {
        types.sort_unstable();
    }
    let groups = ext(0x000a).map_or(Vec::new(), |g| u16s(&g[2..]));
    let formats = ext(0x000b).map_or(Vec::new(), |f| f[1..].iter().map(|&x| u16::from(x)).collect());
    let s = format!(
        "771,{},{},{},{}",
        join(suites.into_iter().filter(|&s| !is_grease(s)), "-", false),
        join(types, "-", false),
        join(groups.into_iter().filter(|&g| !is_grease(g)), "-", false),
        join(formats, "-", false)
    );
    Md5::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// The worked examples in the JA4 specification, so the implementation
/// above is checked against the source before it checks us.
#[test]
fn ja4_matches_the_specification_examples() {
    assert_eq!(
        hex12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"),
        "8daaf6152771"
    );
    assert_eq!(
        hex12(
            "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        ),
        "e5627efa2ab1"
    );
    assert_eq!(
        hex12("0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"),
        "6d807ffa2a79"
    );
}

async fn hello_of(cfg: &TlsConfig) -> Vec<u8> {
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
    let cfg = cfg.clone();
    let task = tokio::spawn(async move { connect_tls(client_io, &cfg).await.err() });
    let mut hdr = [0u8; 5];
    server_io.read_exact(&mut hdr).await.unwrap();
    let mut msg = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
    server_io.read_exact(&mut msg).await.unwrap();
    drop(server_io);
    assert!(task.await.unwrap().is_some());
    msg
}

/// Expected values come from ClientHellos the real clients sent to a local
/// listener on macOS 27 (October 2026), fingerprinted with the functions
/// above (and cross-checked with an independent Python implementation):
///
/// - Chrome 155.0.8059.86, headless, fresh profile, `https://localhost/`.
/// - Apple URLSession on macOS 27 (the Network.framework stack Safari and
///   iOS apps use), `https://localhost/`.
///
/// Chrome permutes its extensions, so its plain JA3 changes per connection
/// (two real Chrome hellos gave b9e32dd5… and 20ec948c…); JA3N and JA4
/// sort and are stable.
///
/// Firefox is not captured from the browser. Its values are what Xray-core
/// 26.10.21 (uTLS `HelloFirefox_148`) sent with `"fingerprint": "firefox"`,
/// fingerprinted the same way; Xray's `safari` (uTLS `HelloSafari_26_3`)
/// gave exactly the Apple values above.
///
/// Both Xray 26.10.21 and sing-box 1.14.4 send
/// t13d1516h2_8daaf6152771_d8a2da3f94cd for `chrome`: Chrome 133, without
/// Trust Anchor IDs or the GREASE and ML-DSA signature algorithms of the
/// current browser. sing-box's `firefox` and `safari` are Firefox 120
/// (t13d1715h2_5b57614c22b0_5c2c66f702b0) and Safari 16
/// (t13d2014h2_a09f3c656075_14788d8d241b).
#[tokio::test]
async fn ja3_ja4_match_the_real_browsers() {
    let pki = pki();
    let mut cfg = client(Fingerprint::Chrome, &pki);
    cfg.server_name = ServerName::try_from("localhost").unwrap();

    let chrome = hello_of(&cfg).await;
    assert_eq!(ja4(&chrome), "t13d1517h2_8daaf6152771_cb7bf5808d99");
    assert_eq!(ja3(&chrome, true), "bd4930bd9b000ee684830e44bab76fdf");
    let mut ja3s = std::collections::HashSet::new();
    for _ in 0..4 {
        ja3s.insert(ja3(&hello_of(&cfg).await, false));
    }
    assert!(ja3s.len() > 1, "Chrome's JA3 must vary with the extension order");

    for fp in [Fingerprint::Safari, Fingerprint::Ios] {
        cfg.fingerprint = fp;
        let apple = hello_of(&cfg).await;
        assert_eq!(ja4(&apple), "t13d2013h2_a09f3c656075_7f0f34a4126d", "{fp:?}");
        assert_eq!(ja3(&apple, false), "ecdf4f49dd59effc439639da29186671", "{fp:?}");
    }

    cfg.fingerprint = Fingerprint::Firefox;
    let ff = hello_of(&cfg).await;
    assert_eq!(ja4(&ff), "t13d1715h2_5b57614c22b0_a54fffd0eb61");
    assert_eq!(ja3(&ff, false), "7704a11cf87dfcf33080b90ce11d5527");
}
