//! TLS client built from sing-box's outbound `tls` object
//! (`common/tls/std_client.go`, `utls_client.go`).
//!
//! Three handshakes:
//! - **Browser** (the default): `sbr-reality`'s TLS 1.3 client with a
//!   browser's ClientHello (`utls.fingerprint`, Chrome when unset) and rustls
//!   certificate verification. rustls' own ClientHello is distinctive on the
//!   wire, and a censor can block a fingerprint that few real clients send;
//!   a browser's is the most common one there is.
//! - **Rustls**: when `utls.enabled` is explicitly false, or when the config
//!   needs what the browser client lacks (TLS 1.2 via `max_version`, client
//!   certificates, ECH). Those are refused instead when `utls` is enabled.
//! - **REALITY**: `sbr-reality` with the REALITY handshake.

mod conn;
mod io;
mod verify;

use std::io as stdio;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::{EchConfig, EchMode};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sbr_config::TlsOutbound;
use sbr_core::Stream;

pub use conn::TlsConn;
pub(crate) use io::rand_u32;
pub use io::{FRAGMENT_FALLBACK_DELAY, FragmentOptions, TlsIo};

/// A client TLS connection over the dialed stream.
pub type TlsStream = tokio_rustls::client::TlsStream<TlsIo>;

/// sing-box `C.TCPTimeout`, its default handshake timeout.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How an outbound wraps its server connection in TLS.
#[derive(Clone)]
pub enum TlsClient {
    Rustls(Arc<RustlsClient>),
    Reality(Arc<RealityClient>),
    Browser(Arc<BrowserClient>),
}

/// The browser fingerprint `t` asks for, or `None` for rustls (see
/// [`TlsOutbound::browser_fingerprint`]). Errors name the `tls.*` field.
pub fn browser_fingerprint(t: &TlsOutbound) -> Result<Option<sbr_reality::Fingerprint>, String> {
    t.browser_fingerprint(true)?
        .map(|fp| fp.parse().map_err(|e| format!("tls.utls.fingerprint: {e}")))
        .transpose()
}

/// `insecure`, pins, a configured CA, or the webpki roots.
pub fn server_verifier(
    t: &TlsOutbound,
    base: Option<&std::path::Path>,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let pinned = !t.certificate_sha256.is_empty() || !t.certificate_public_key_sha256.is_empty();
    let ca = inline_or_file(&t.certificate, &t.certificate_path, base)?;
    if pinned && ca.is_some() {
        return Err(invalid(
            "tls.certificate_sha256: conflicts with certificate or certificate_path",
        ));
    }
    if t.insecure || pinned {
        let v = verify::Pinned::new(
            &t.certificate_sha256,
            &t.certificate_public_key_sha256,
            t.insecure && !pinned,
            &provider,
        )?;
        return Ok(Arc::new(v));
    }
    let mut roots = RootCertStore::empty();
    match &ca {
        Some(pem) => {
            for c in CertificateDer::pem_slice_iter(pem) {
                let c = c.map_err(|e| invalid(format!("tls.certificate: {e}")))?;
                roots.add(c).map_err(|e| invalid(format!("tls.certificate: {e}")))?;
            }
            if roots.is_empty() {
                return Err(invalid("tls.certificate: no certificate found"));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let v = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|e| invalid(format!("tls.certificate: {e}")))?;
    Ok(v)
}

fn parse_server_name(t: &TlsOutbound, server: &str) -> Result<ServerName<'static>, String> {
    let name = t.server_name.clone().unwrap_or_else(|| server.to_owned());
    let name = name.trim_start_matches('[').trim_end_matches(']').to_owned();
    ServerName::try_from(name.clone()).map_err(|_| invalid(format!("tls.server_name: invalid name {name:?}")))
}

/// Ordinary TLS with a browser's ClientHello.
pub struct BrowserClient {
    config: sbr_reality::TlsConfig,
    alpn_configured: bool,
    handshake_timeout: Duration,
    fragment: Option<FragmentOptions>,
}

impl BrowserClient {
    pub fn new(
        t: &TlsOutbound,
        server: &str,
        base: Option<&std::path::Path>,
        fingerprint: sbr_reality::Fingerprint,
    ) -> Result<Self, String> {
        Ok(Self {
            config: sbr_reality::TlsConfig {
                server_name: parse_server_name(t, server)?,
                sni: !t.disable_sni,
                fingerprint,
                alpn: browser_alpn(t.alpn.clone()),
                post_quantum: true,
                verifier: server_verifier(t, base)?,
            },
            alpn_configured: !t.alpn.is_empty(),
            handshake_timeout: t
                .handshake_timeout
                .filter(|d| !d.is_zero())
                .unwrap_or(HANDSHAKE_TIMEOUT),
            fragment: fragment_options(t),
        })
    }

    pub fn config(&self) -> &sbr_reality::TlsConfig {
        &self.config
    }

    async fn connect(&self, io: Stream, fd: Option<i32>) -> stdio::Result<TlsConn> {
        let io = TlsIo::new(io, fd, self.fragment);
        match tokio::time::timeout(self.handshake_timeout, sbr_reality::connect_tls(io, &self.config)).await {
            Ok(r) => Ok(TlsConn::Browser(Box::new(r?))),
            Err(_) => Err(stdio::Error::new(stdio::ErrorKind::TimedOut, "TLS handshake timed out")),
        }
    }
}

/// Browsers widen a lone `h2` to `h2, http/1.1`, as sing-box's uTLS client
/// does; empty keeps the fingerprint's own list.
fn browser_alpn(alpn: Vec<String>) -> Vec<String> {
    if alpn == ["h2"] {
        vec!["h2".into(), "http/1.1".into()]
    } else {
        alpn
    }
}

pub struct RealityClient {
    config: sbr_reality::RealityConfig,
    alpn_configured: bool,
    handshake_timeout: Duration,
    fragment: Option<FragmentOptions>,
}

impl RealityClient {
    fn new(t: &TlsOutbound, server: &str) -> Result<Self, String> {
        let r = t.reality.as_ref().expect("reality options");
        let name = t.server_name.clone().unwrap_or_else(|| server.to_owned());
        let mut config = sbr_reality::RealityConfig::new(name, &r.public_key, &r.short_id)
            .map_err(|e| format!("tls.reality: {e}"))?;
        if let Some(u) = t.utls.as_ref().filter(|u| u.enabled) {
            config.fingerprint = u
                .fingerprint
                .as_deref()
                .unwrap_or_default()
                .parse()
                .map_err(|e| format!("tls.utls.fingerprint: {e}"))?;
        }
        config.alpn = t.alpn.clone();
        Ok(Self {
            config,
            alpn_configured: !t.alpn.is_empty(),
            handshake_timeout: t
                .handshake_timeout
                .filter(|d| !d.is_zero())
                .unwrap_or(HANDSHAKE_TIMEOUT),
            fragment: fragment_options(t),
        })
    }

    async fn connect(&self, io: Stream, fd: Option<i32>) -> stdio::Result<TlsConn> {
        let io = TlsIo::new(io, fd, self.fragment);
        match tokio::time::timeout(self.handshake_timeout, sbr_reality::connect(io, &self.config)).await {
            Ok(r) => Ok(TlsConn::Browser(Box::new(r?))),
            Err(_) => Err(stdio::Error::new(
                stdio::ErrorKind::TimedOut,
                "REALITY handshake timed out",
            )),
        }
    }
}

fn fragment_options(t: &TlsOutbound) -> Option<FragmentOptions> {
    (t.fragment || t.record_fragment).then(|| FragmentOptions {
        split_packet: t.fragment,
        split_record: t.record_fragment,
        fallback_delay: t
            .fragment_fallback_delay
            .filter(|d| !d.is_zero())
            .unwrap_or(FRAGMENT_FALLBACK_DELAY),
    })
}

pub struct RustlsClient {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    /// `alpn` as configured (transports may substitute a default).
    alpn_configured: bool,
    handshake_timeout: Duration,
    fragment: Option<FragmentOptions>,
}

fn invalid(msg: impl Into<String>) -> String {
    msg.into()
}

fn read_file(base: Option<&std::path::Path>, path: &str) -> Result<Vec<u8>, String> {
    let p = std::path::Path::new(path);
    let p = match base {
        Some(b) if p.is_relative() => b.join(p),
        _ => p.to_path_buf(),
    };
    std::fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))
}

fn inline_or_file(
    inline: &Option<String>,
    path: &Option<String>,
    base: Option<&std::path::Path>,
) -> Result<Option<Vec<u8>>, String> {
    match (inline, path) {
        (Some(s), _) => Ok(Some(s.as_bytes().to_vec())),
        (None, Some(p)) => read_file(base, p).map(Some),
        (None, None) => Ok(None),
    }
}

impl TlsClient {
    /// Build from options. `server` is the outbound's `server`, used when
    /// `server_name` is unset. Errors name the offending `tls.*` field.
    pub fn new(t: &TlsOutbound, server: &str, base: Option<&std::path::Path>) -> Result<Self, String> {
        if t.reality.as_ref().is_some_and(|r| r.enabled) {
            return Ok(Self::Reality(Arc::new(RealityClient::new(t, server)?)));
        }
        if let Some(fp) = browser_fingerprint(t)? {
            return Ok(Self::Browser(Arc::new(BrowserClient::new(t, server, base, fp)?)));
        }
        Ok(Self::Rustls(Arc::new(RustlsClient::new(t, server, base)?)))
    }

    /// The same client with `alpn` as default ALPN when the config set none
    /// (what sing-box's v2ray transports do: `h2` for gRPC/HTTP, `http/1.1`
    /// for WebSocket).
    pub fn with_default_alpn(&self, alpn: &[&str]) -> Self {
        match self {
            Self::Rustls(c) if !c.alpn_configured => {
                let mut config = (*c.config).clone();
                config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
                Self::Rustls(Arc::new(RustlsClient {
                    config: Arc::new(config),
                    server_name: c.server_name.clone(),
                    alpn_configured: true,
                    handshake_timeout: c.handshake_timeout,
                    fragment: c.fragment,
                }))
            }
            Self::Browser(c) if !c.alpn_configured => {
                let mut config = c.config.clone();
                config.alpn = browser_alpn(alpn.iter().map(|s| s.to_string()).collect());
                Self::Browser(Arc::new(BrowserClient {
                    config,
                    alpn_configured: true,
                    handshake_timeout: c.handshake_timeout,
                    fragment: c.fragment,
                }))
            }
            Self::Reality(c) if !c.alpn_configured => {
                let mut config = c.config.clone();
                config.alpn = alpn.iter().map(|s| s.to_string()).collect();
                Self::Reality(Arc::new(RealityClient {
                    config,
                    alpn_configured: true,
                    handshake_timeout: c.handshake_timeout,
                    fragment: c.fragment,
                }))
            }
            other => other.clone(),
        }
    }

    /// The configured or derived SNI / verification name.
    pub fn server_name(&self) -> Option<String> {
        match self {
            Self::Rustls(c) => Some(match &c.server_name {
                ServerName::DnsName(d) => d.as_ref().to_owned(),
                ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
                _ => return None,
            }),
            Self::Reality(c) => Some(c.config.server_name.clone()),
            Self::Browser(c) => Some(match &c.config.server_name {
                ServerName::DnsName(d) => d.as_ref().to_owned(),
                ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
                _ => return None,
            }),
        }
    }

    /// Handshake over `io`. `fd` is the raw socket when `io` was dialed
    /// directly (used by `fragment` to wait for ACKs).
    pub async fn connect(&self, io: Stream, fd: Option<i32>) -> stdio::Result<TlsConn> {
        match self {
            Self::Rustls(c) => Ok(TlsConn::Rustls(Box::new(c.connect(io, fd).await?))),
            Self::Reality(c) => c.connect(io, fd).await,
            Self::Browser(c) => c.connect(io, fd).await,
        }
    }
}

impl RustlsClient {
    fn new(t: &TlsOutbound, server: &str, base: Option<&std::path::Path>) -> Result<Self, String> {
        let server_name = parse_server_name(t, server)?;

        // `utls` never reaches rustls: it selects the browser client.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

        let versions = versions(t)?;
        let builder = ClientConfig::builder_with_provider(provider.clone());
        let builder = match &t.ech {
            Some(e) if e.enabled => {
                let pem = inline_or_file(&e.config, &e.config_path, base)?.ok_or_else(|| {
                    invalid("tls.ech.config: fetching ECH configs from DNS is not supported by sbr yet; set config")
                })?;
                let list = ech_config_list(&pem)?;
                let cfg = EchConfig::new(
                    EchConfigListBytes::from(list),
                    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
                )
                .map_err(|e| invalid(format!("tls.ech.config: {e}")))?;
                if !versions.contains(&&rustls::version::TLS13) {
                    return Err(invalid("tls.ech: requires TLS 1.3"));
                }
                builder
                    .with_ech(EchMode::from(cfg))
                    .map_err(|e| invalid(format!("tls.ech: {e}")))?
            }
            _ => builder
                .with_protocol_versions(&versions)
                .map_err(|e| invalid(format!("tls: {e}")))?,
        };

        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(server_verifier(t, base)?);

        let cert = inline_or_file(&t.client_certificate, &t.client_certificate_path, base)?;
        let key = inline_or_file(&t.client_key, &t.client_key_path, base)?;
        let mut config = match (cert, key) {
            (Some(cert), Some(key)) => {
                let chain = CertificateDer::pem_slice_iter(&cert)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| invalid(format!("tls.client_certificate: {e}")))?;
                let key = PrivateKeyDer::from_pem_slice(&key).map_err(|e| invalid(format!("tls.client_key: {e}")))?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|e| invalid(format!("tls.client_certificate: {e}")))?
            }
            (None, None) => builder.with_no_client_auth(),
            _ => {
                return Err(invalid(
                    "tls.client_certificate: client certificate and client key must be provided together",
                ));
            }
        };
        config.enable_sni = !t.disable_sni;
        config.alpn_protocols = t.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let fragment = fragment_options(t);
        Ok(Self {
            config: Arc::new(config),
            server_name,
            alpn_configured: !t.alpn.is_empty(),
            handshake_timeout: t
                .handshake_timeout
                .filter(|d| !d.is_zero())
                .unwrap_or(HANDSHAKE_TIMEOUT),
            fragment,
        })
    }

    async fn connect(&self, io: Stream, fd: Option<i32>) -> stdio::Result<TlsStream> {
        let io = TlsIo::new(io, fd, self.fragment);
        let connector = tokio_rustls::TlsConnector::from(self.config.clone());
        match tokio::time::timeout(self.handshake_timeout, connector.connect(self.server_name.clone(), io)).await {
            Ok(r) => r,
            Err(_) => Err(stdio::Error::new(stdio::ErrorKind::TimedOut, "TLS handshake timed out")),
        }
    }
}

fn versions(t: &TlsOutbound) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, String> {
    // rustls implements TLS 1.2 and 1.3 only; a lower minimum is moot.
    let rank = |v: &str| match v {
        "1.0" => 0,
        "1.1" => 1,
        "1.2" => 2,
        _ => 3,
    };
    let min = t.min_version.as_deref().map_or(0, rank);
    let max = t.max_version.as_deref().map_or(3, rank);
    if max < 2 {
        return Err(invalid("tls.max_version: TLS 1.0/1.1 are not supported by sbr"));
    }
    if min > max {
        return Err(invalid("tls.min_version: greater than max_version"));
    }
    let mut v = Vec::new();
    if max >= 3 {
        v.push(&rustls::version::TLS13);
    }
    if min <= 2 {
        v.push(&rustls::version::TLS12);
    }
    Ok(v)
}

/// The `ECH CONFIGS` PEM block sing-box uses (`sing-box generate ech-keypair`).
fn ech_config_list(pem: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let text = std::str::from_utf8(pem).map_err(|_| invalid("tls.ech.config: invalid ECH configs pem"))?;
    let body = text
        .split("-----BEGIN ECH CONFIGS-----")
        .nth(1)
        .and_then(|r| r.split("-----END ECH CONFIGS-----").next())
        .ok_or_else(|| invalid("tls.ech.config: invalid ECH configs pem"))?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| invalid("tls.ech.config: invalid ECH configs pem"))
}
