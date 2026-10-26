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
//!   ECH configs come from the config or from DNS ([`ech`]); a server's
//!   `retry_configs` get one fresh connection ([`EchRetry`]).
//! - **REALITY**: `sbr-reality` with the REALITY handshake.
//!
//! All three can fragment the ClientHello ([`Fragment`]).

mod conn;
pub(crate) mod ech;
mod io;
pub(crate) mod verify;

use std::io as stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use rustls::client::EchMode;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};
use sbr_config::TlsOutbound;
use sbr_core::Stream;
use sbr_core::dns::Dns;
use tracing::{info, warn};

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
    fragment: Arc<Fragment>,
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
            fragment: Arc::new(Fragment::new(t)),
        })
    }

    pub fn config(&self) -> &sbr_reality::TlsConfig {
        &self.config
    }

    async fn connect(&self, io: TlsIo) -> stdio::Result<TlsConn> {
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
    fragment: Arc<Fragment>,
}

impl RealityClient {
    fn new(t: &TlsOutbound, server: &str) -> Result<Self, String> {
        let r = t.reality.as_ref().expect("reality options");
        // sing-box refuses ECH and disable_sni with REALITY; a server cannot
        // accept a ClientHello without SNI or below TLS 1.3 either.
        let refused = [
            (
                t.disable_sni,
                "tls.disable_sni: not supported with REALITY, which authenticates by SNI",
            ),
            (
                t.ech.as_ref().is_some_and(|e| e.enabled),
                "tls.ech: not supported with REALITY",
            ),
            (
                t.max_version.as_deref().is_some_and(|v| v != "1.3"),
                "tls.max_version: REALITY needs TLS 1.3",
            ),
        ];
        if let Some((_, why)) = refused.iter().find(|(hit, _)| *hit) {
            return Err(invalid(*why));
        }
        // sing-box accepts these and ignores them: the REALITY check replaces
        // certificate verification, and a REALITY server never asks for a
        // client certificate. Configs sing-box runs keep working here.
        let ignored = [
            ("insecure", t.insecure),
            ("certificate", t.certificate.is_some() || t.certificate_path.is_some()),
            ("certificate_sha256", !t.certificate_sha256.is_empty()),
            (
                "certificate_public_key_sha256",
                !t.certificate_public_key_sha256.is_empty(),
            ),
            (
                "client_certificate",
                t.client_certificate.is_some() || t.client_certificate_path.is_some(),
            ),
            ("client_key", t.client_key.is_some() || t.client_key_path.is_some()),
        ]
        .iter()
        .filter(|(_, set)| *set)
        .map(|(name, _)| format!("tls.{name}"))
        .collect::<Vec<_>>();
        if !ignored.is_empty() {
            warn!(server, fields = %ignored.join(", "), "ignored with REALITY");
        }
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
            fragment: Arc::new(Fragment::new(t)),
        })
    }

    async fn connect(&self, io: TlsIo) -> stdio::Result<TlsConn> {
        match tokio::time::timeout(self.handshake_timeout, sbr_reality::connect(io, &self.config)).await {
            Ok(r) => Ok(TlsConn::Browser(Box::new(r?))),
            Err(_) => Err(stdio::Error::new(
                stdio::ErrorKind::TimedOut,
                "REALITY handshake timed out",
            )),
        }
    }
}

/// Bumped on every network change: automatic fragmentation levels belong to
/// the network they were reached on.
static NETWORK_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Forget every outbound's automatic fragmentation level (see
/// `Engine::network_changed`).
pub fn network_changed() {
    NETWORK_EPOCH.fetch_add(1, Ordering::Relaxed);
}

/// The highest automatic level: records and TCP segments.
const AUTO_MAX: u8 = 2;

/// ClientHello fragmentation for one outbound, shared by its ALPN variants.
///
/// `fragment` / `record_fragment` or `fragment_split` as configured apply
/// to every handshake. With none set, the automatic mode (an sbr extension, on unless
/// `disable_auto_fragment`) starts unfragmented and steps up when a
/// handshake is reset or closed before the server sent a byte, which is how
/// SNI filtering by the GFW and most DPI vendors looks from the client:
/// first to split TLS records (free; defeats filters that do not reassemble
/// records), then to split records and TCP segments as well (costs
/// `fragment_fallback_delay` per handshake where ACKs cannot be observed).
/// The level is kept until the network changes.
pub struct Fragment {
    configured: Option<FragmentOptions>,
    auto: bool,
    fallback_delay: Duration,
    /// The automatic level in the low byte, the network epoch above it.
    state: AtomicU64,
}

impl Fragment {
    pub fn new(t: &TlsOutbound) -> Self {
        let fallback_delay = t
            .fragment_fallback_delay
            .filter(|d| !d.is_zero())
            .unwrap_or(FRAGMENT_FALLBACK_DELAY);
        Self {
            configured: FragmentOptions::configured(
                t.fragment,
                t.record_fragment,
                t.fragment_split,
                t.fragment_fallback_delay,
            ),
            auto: !t.disable_auto_fragment,
            fallback_delay,
            state: AtomicU64::new(NETWORK_EPOCH.load(Ordering::Relaxed) << 8),
        }
    }

    fn watching(&self) -> bool {
        self.auto && self.configured.is_none()
    }

    /// The automatic level on the current network.
    pub fn level(&self) -> u8 {
        let s = self.state.load(Ordering::Relaxed);
        if s >> 8 == NETWORK_EPOCH.load(Ordering::Relaxed) {
            s as u8
        } else {
            0
        }
    }

    pub fn options(&self, level: u8) -> Option<FragmentOptions> {
        self.configured.or(match level {
            0 => None,
            l => Some(FragmentOptions {
                split_packet: l >= 2,
                split_record: true,
                fallback_delay: self.fallback_delay,
                split: None,
            }),
        })
    }

    /// A handshake at `from` was cut before the server answered. True when
    /// the level is now above `from` (raised here or by a concurrent
    /// handshake), so a retry is worth making.
    pub fn escalate(&self, from: u8, server: &str) -> bool {
        if !self.watching() {
            return false;
        }
        let epoch = NETWORK_EPOCH.load(Ordering::Relaxed);
        let mut s = self.state.load(Ordering::Relaxed);
        loop {
            let level = if s >> 8 == epoch { s as u8 } else { 0 };
            if level > from {
                return true;
            }
            if from >= AUTO_MAX {
                return false;
            }
            let next = from + 1;
            let new = epoch << 8 | u64::from(next);
            match self
                .state
                .compare_exchange(s, new, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => {
                    let how = if next == 1 {
                        "TLS records"
                    } else {
                        "TLS records and TCP segments"
                    };
                    info!(
                        server,
                        "ClientHello cut before the server answered: splitting it across {how}"
                    );
                    return true;
                }
                Err(now) => s = now,
            }
        }
    }
}

/// A rustls config and the ECHConfigList it offers.
type EchConfigFor = (Arc<[u8]>, Arc<ClientConfig>);

pub struct RustlsClient {
    base: Arc<RustlsBase>,
    alpn: Vec<Vec<u8>>,
    /// The config without ECH; with ECH, one per ECHConfigList.
    config: Arc<ClientConfig>,
    ech: Option<Arc<ech::EchSource>>,
    ech_config: std::sync::Mutex<Option<EchConfigFor>>,
    server_name: ServerName<'static>,
    /// `alpn` as configured (transports may substitute a default).
    alpn_configured: bool,
    handshake_timeout: Duration,
    fragment: Arc<Fragment>,
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
    /// `server_name` is unset; `dns` looks up ECH configs that the options
    /// leave to DNS. Errors name the offending `tls.*` field.
    pub fn new(
        t: &TlsOutbound,
        server: &str,
        base: Option<&std::path::Path>,
        dns: &Arc<dyn Dns>,
    ) -> Result<Self, String> {
        if t.reality.as_ref().is_some_and(|r| r.enabled) {
            return Ok(Self::Reality(Arc::new(RealityClient::new(t, server)?)));
        }
        if let Some(fp) = browser_fingerprint(t)? {
            return Ok(Self::Browser(Arc::new(BrowserClient::new(t, server, base, fp)?)));
        }
        Ok(Self::Rustls(Arc::new(RustlsClient::new(t, server, base, dns)?)))
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
                    base: c.base.clone(),
                    alpn: config.alpn_protocols.clone(),
                    config: Arc::new(config),
                    ech: c.ech.clone(),
                    ech_config: Default::default(),
                    server_name: c.server_name.clone(),
                    alpn_configured: true,
                    handshake_timeout: c.handshake_timeout,
                    fragment: c.fragment.clone(),
                }))
            }
            Self::Browser(c) if !c.alpn_configured => {
                let mut config = c.config.clone();
                config.alpn = browser_alpn(alpn.iter().map(|s| s.to_string()).collect());
                Self::Browser(Arc::new(BrowserClient {
                    config,
                    alpn_configured: true,
                    handshake_timeout: c.handshake_timeout,
                    fragment: c.fragment.clone(),
                }))
            }
            Self::Reality(c) if !c.alpn_configured => {
                let mut config = c.config.clone();
                config.alpn = alpn.iter().map(|s| s.to_string()).collect();
                Self::Reality(Arc::new(RealityClient {
                    config,
                    alpn_configured: true,
                    handshake_timeout: c.handshake_timeout,
                    fragment: c.fragment.clone(),
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
    ///
    /// A handshake cut before the server's first byte raises the automatic
    /// fragmentation level; the error is then a [`Retry`], and a fresh
    /// connection is worth trying (`ServerDialer::tls` does).
    pub async fn connect(&self, io: Stream, fd: Option<i32>) -> stdio::Result<TlsConn> {
        let frag = self.fragment();
        let level = frag.level();
        let io = TlsIo::new(io, fd, frag.options(level));
        if !frag.watching() {
            return self.handshake(io).await;
        }
        let cut = Arc::new(AtomicBool::new(false));
        match self.handshake(io.watch_cut(cut.clone())).await {
            Err(e) if cut.load(Ordering::Relaxed) && frag.escalate(level, &self.server_name().unwrap_or_default()) => {
                Err(stdio::Error::new(e.kind(), Retry(e)))
            }
            r => r,
        }
    }

    async fn handshake(&self, io: TlsIo) -> stdio::Result<TlsConn> {
        match self {
            Self::Rustls(c) => Ok(TlsConn::Rustls(Box::new(c.connect(io).await?))),
            Self::Reality(c) => c.connect(io).await,
            Self::Browser(c) => c.connect(io).await,
        }
    }

    pub fn fragment(&self) -> &Fragment {
        match self {
            Self::Rustls(c) => &c.fragment,
            Self::Reality(c) => &c.fragment,
            Self::Browser(c) => &c.fragment,
        }
    }
}

/// What every rustls config of one outbound shares.
struct RustlsBase {
    versions: Vec<&'static SupportedProtocolVersion>,
    verifier: Arc<dyn ServerCertVerifier>,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    enable_sni: bool,
}

impl RustlsBase {
    fn build(&self, alpn: &[Vec<u8>], ech: Option<&[u8]>) -> Result<ClientConfig, String> {
        // `utls` never reaches rustls: it selects the browser client.
        let builder = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let builder = match ech {
            Some(list) => {
                let cfg = ech::parse(list).map_err(|e| invalid(format!("tls.ech.config: {e}")))?;
                builder
                    .with_ech(EchMode::from(cfg))
                    .map_err(|e| invalid(format!("tls.ech: {e}")))?
            }
            None => builder
                .with_protocol_versions(&self.versions)
                .map_err(|e| invalid(format!("tls: {e}")))?,
        };
        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(self.verifier.clone());
        let mut config = match &self.client_auth {
            Some((chain, key)) => builder
                .with_client_auth_cert(chain.clone(), key.clone_key())
                .map_err(|e| invalid(format!("tls.client_certificate: {e}")))?,
            None => builder.with_no_client_auth(),
        };
        config.enable_sni = self.enable_sni;
        config.alpn_protocols = alpn.to_vec();
        Ok(config)
    }
}

impl RustlsClient {
    fn new(t: &TlsOutbound, server: &str, base: Option<&std::path::Path>, dns: &Arc<dyn Dns>) -> Result<Self, String> {
        let server_name = parse_server_name(t, server)?;
        let versions = versions(t)?;
        let cert = inline_or_file(&t.client_certificate, &t.client_certificate_path, base)?;
        let key = inline_or_file(&t.client_key, &t.client_key_path, base)?;
        let client_auth = match (cert, key) {
            (Some(cert), Some(key)) => {
                let chain = CertificateDer::pem_slice_iter(&cert)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| invalid(format!("tls.client_certificate: {e}")))?;
                let key = PrivateKeyDer::from_pem_slice(&key).map_err(|e| invalid(format!("tls.client_key: {e}")))?;
                Some((chain, key))
            }
            (None, None) => None,
            _ => {
                return Err(invalid(
                    "tls.client_certificate: client certificate and client key must be provided together",
                ));
            }
        };
        let ech = match &t.ech {
            Some(e) if e.enabled => {
                if !versions.contains(&&rustls::version::TLS13) {
                    return Err(invalid("tls.ech: requires TLS 1.3"));
                }
                let name = match &server_name {
                    ServerName::DnsName(d) => d.as_ref().to_owned(),
                    _ => String::new(),
                };
                Some(Arc::new(ech::EchSource::new(e, &name, base, dns)?))
            }
            _ => None,
        };
        let rb = RustlsBase {
            versions,
            verifier: server_verifier(t, base)?,
            client_auth,
            enable_sni: !t.disable_sni,
        };
        let alpn: Vec<Vec<u8>> = t.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let config = Arc::new(rb.build(&alpn, None)?);
        Ok(Self {
            base: Arc::new(rb),
            alpn,
            config,
            ech,
            ech_config: Default::default(),
            server_name,
            alpn_configured: !t.alpn.is_empty(),
            handshake_timeout: t
                .handshake_timeout
                .filter(|d| !d.is_zero())
                .unwrap_or(HANDSHAKE_TIMEOUT),
            fragment: Arc::new(Fragment::new(t)),
        })
    }

    /// The config offering ECH with `src`'s current list.
    async fn ech_config(&self, src: &ech::EchSource) -> stdio::Result<Arc<ClientConfig>> {
        let list = src.list().await?;
        let mut cached = self.ech_config.lock().unwrap();
        if let Some((l, c)) = &*cached
            && Arc::ptr_eq(l, &list)
        {
            return Ok(c.clone());
        }
        let config = Arc::new(self.base.build(&self.alpn, Some(&list)).map_err(stdio::Error::other)?);
        *cached = Some((list, config.clone()));
        Ok(config)
    }

    async fn connect(&self, io: TlsIo) -> stdio::Result<TlsStream> {
        let config = match &self.ech {
            Some(src) => self.ech_config(src).await?,
            None => self.config.clone(),
        };
        let connector = tokio_rustls::TlsConnector::from(config);
        match tokio::time::timeout(self.handshake_timeout, connector.connect(self.server_name.clone(), io)).await {
            Ok(Err(e)) => match (&self.ech, ech::retry_configs(&e)) {
                (Some(src), Some(list)) => {
                    src.retry_with(list);
                    Err(stdio::Error::new(e.kind(), EchRetry(e)))
                }
                _ => Err(e),
            },
            Ok(r) => r,
            Err(_) => Err(stdio::Error::new(stdio::ErrorKind::TimedOut, "TLS handshake timed out")),
        }
    }
}

/// The server rejected ECH and sent `retry_configs`, which the client now
/// offers: one fresh connection is worth trying (RFC 9849 §6.1.6).
#[derive(Debug)]
pub struct EchRetry(pub stdio::Error);

impl std::fmt::Display for EchRetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server rejected ECH and sent retry_configs")
    }
}

impl std::error::Error for EchRetry {}

impl EchRetry {
    pub fn is(e: &stdio::Error) -> bool {
        e.get_ref().is_some_and(|r| r.is::<EchRetry>())
    }
}

/// A handshake failed in a way a retry with more fragmentation may fix.
#[derive(Debug)]
pub struct Retry(pub stdio::Error);

impl std::fmt::Display for Retry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (retrying with the ClientHello fragmented)", self.0)
    }
}

impl std::error::Error for Retry {}

impl Retry {
    pub fn is(e: &stdio::Error) -> bool {
        e.get_ref().is_some_and(|r| r.is::<Retry>())
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

#[cfg(test)]
mod tests {
    use sbr_config::{Ech, Reality};

    use super::*;

    fn reality() -> TlsOutbound {
        TlsOutbound {
            enabled: true,
            server_name: Some("www.example.com".into()),
            reality: Some(Reality {
                enabled: true,
                public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into(),
                short_id: "0123456789abcdef".into(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn reality_refuses_fields_it_cannot_honour() {
        assert!(RealityClient::new(&reality(), "203.0.113.1").is_ok());
        let cases = [
            (
                "tls.disable_sni",
                TlsOutbound {
                    disable_sni: true,
                    ..reality()
                },
            ),
            (
                "tls.ech",
                TlsOutbound {
                    ech: Some(Ech {
                        enabled: true,
                        ..Default::default()
                    }),
                    ..reality()
                },
            ),
            (
                "tls.max_version",
                TlsOutbound {
                    max_version: Some("1.2".into()),
                    ..reality()
                },
            ),
        ];
        for (field, t) in cases {
            let err = RealityClient::new(&t, "203.0.113.1").err().expect(field);
            assert!(err.starts_with(field), "{err}");
        }
        let mut t = reality();
        t.max_version = Some("1.3".into());
        t.min_version = Some("1.2".into());
        t.insecure = true;
        t.certificate_sha256 = vec!["AAAA".into()];
        assert!(RealityClient::new(&t, "203.0.113.1").is_ok(), "ignored like sing-box");
    }
}
