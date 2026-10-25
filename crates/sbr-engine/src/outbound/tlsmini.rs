//! A minimal TLS client for the protocols that drive the handshake
//! themselves (ShadowTLS, AnyTLS). Supports `server_name`, `disable_sni`,
//! `insecure`, `alpn`, `min_version`/`max_version`, a pinned
//! `certificate`/`certificate_path` and `utls`; everything else in `tls` is
//! refused at build time rather than ignored.
//!
//! The handshake is a browser's (`sbr-reality`, [`TlsClient::browser`])
//! unless [`crate::tls::browser_fingerprint`] picks rustls.

use std::cell::RefCell;
use std::io;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret, SupportedKxGroup,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, NamedGroup, SignatureScheme};
use sbr_config::TlsOutbound;

#[derive(Clone)]
pub struct TlsClient {
    pub server_name: ServerName<'static>,
    versions: Vec<&'static rustls::SupportedProtocolVersion>,
    verifier: Arc<dyn ServerCertVerifier>,
    alpn: Vec<Vec<u8>>,
    enable_sni: bool,
    config: Arc<ClientConfig>,
    /// Browser-fingerprinted TLS 1.3, when chosen over rustls.
    pub browser: Option<sbr_reality::TlsConfig>,
}

fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}

impl TlsClient {
    /// `server` is the outbound's server address, the SNI fallback.
    pub fn new(t: &TlsOutbound, server: &str) -> Result<Self, String> {
        if t.reality.as_ref().is_some_and(|r| r.enabled) {
            return Err("tls.reality: not supported by sbr yet".into());
        }
        if t.ech.as_ref().is_some_and(|e| e.enabled) {
            return Err("tls.ech: not supported by sbr yet".into());
        }
        if t.client_certificate.is_some() || t.client_certificate_path.is_some() {
            return Err("tls.client_certificate: not supported by sbr yet".into());
        }
        if !t.certificate_sha256.is_empty() || !t.certificate_public_key_sha256.is_empty() {
            return Err("tls certificate pinning: not supported by sbr yet".into());
        }
        if t.fragment || t.record_fragment {
            return Err("tls.fragment: not supported by sbr yet".into());
        }
        let fingerprint = crate::tls::browser_fingerprint(t)?;
        let version = |v: &str| match v {
            "1.3" => 13,
            "1.2" => 12,
            _ => 10,
        };
        let min = t.min_version.as_deref().map_or(12, version).max(12);
        let max = t.max_version.as_deref().map_or(13, version);
        let mut versions = Vec::new();
        if max >= 13 {
            versions.push(&rustls::version::TLS13);
        }
        if min <= 12 && max >= 12 {
            versions.push(&rustls::version::TLS12);
        }
        if versions.is_empty() {
            return Err("tls: no usable version (sbr supports TLS 1.2 and 1.3)".into());
        }

        let verifier: Arc<dyn ServerCertVerifier> = if t.insecure {
            Arc::new(Insecure)
        } else {
            let mut roots = rustls::RootCertStore::empty();
            let pem = match (&t.certificate, &t.certificate_path) {
                (Some(pem), _) => Some(pem.as_bytes().to_vec()),
                (None, Some(path)) => {
                    Some(std::fs::read(path).map_err(|e| format!("tls.certificate_path: {path}: {e}"))?)
                }
                (None, None) => None,
            };
            match pem {
                Some(pem) => {
                    for cert in CertificateDer::pem_slice_iter(&pem) {
                        let cert = cert.map_err(|e| format!("tls.certificate: {e}"))?;
                        roots.add(cert).map_err(|e| format!("tls.certificate: {e}"))?;
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .map_err(|e| format!("tls: {e}"))?
        };
        let name = t.server_name.clone().unwrap_or_else(|| server.to_owned());
        let server_name = ServerName::try_from(name.trim_start_matches('[').trim_end_matches(']').to_owned())
            .map_err(|e| format!("tls.server_name: {e}"))?;
        let alpn: Vec<Vec<u8>> = t.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let enable_sni = !t.disable_sni;
        let config = build(provider(), &versions, &verifier, &alpn, enable_sni)?;
        let browser = fingerprint.map(|fingerprint| sbr_reality::TlsConfig {
            server_name: server_name.clone(),
            sni: enable_sni,
            fingerprint,
            alpn: t.alpn.clone(),
            post_quantum: true,
            verifier: verifier.clone(),
        });
        Ok(Self {
            server_name,
            versions,
            verifier,
            alpn,
            enable_sni,
            config,
            browser,
        })
    }

    fn build(&self, provider: Arc<CryptoProvider>) -> Result<Arc<ClientConfig>, String> {
        build(provider, &self.versions, &self.verifier, &self.alpn, self.enable_sni)
    }

    pub fn config(&self) -> Arc<ClientConfig> {
        self.config.clone()
    }

    pub fn supports_tls13(&self) -> bool {
        self.versions
            .iter()
            .any(|v| v.version == rustls::ProtocolVersion::TLSv1_3)
    }

    /// A config whose randomness and X25519 key come from the thread-local
    /// [`Scripted`] state while a `ClientConnection` is being created. Used
    /// to rebuild a ClientHello byte-for-byte with a chosen session id.
    pub fn scripted_config(&self) -> Result<Arc<ClientConfig>, String> {
        static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
        let p = P
            .get_or_init(|| {
                let base = rustls::crypto::aws_lc_rs::default_provider();
                Arc::new(CryptoProvider {
                    kx_groups: vec![&SCRIPTED_X25519],
                    secure_random: &SCRIPTED_RANDOM,
                    ..base
                })
            })
            .clone();
        self.build(p)
    }
}

fn build(
    provider: Arc<CryptoProvider>,
    versions: &[&'static rustls::SupportedProtocolVersion],
    verifier: &Arc<dyn ServerCertVerifier>,
    alpn: &[Vec<u8>],
    enable_sni: bool,
) -> Result<Arc<ClientConfig>, String> {
    let mut c = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| format!("tls: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    c.alpn_protocols = alpn.to_vec();
    c.enable_sni = enable_sni;
    // Every connection is a fresh handshake: no tickets to correlate.
    c.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(c))
}

#[derive(Debug)]
struct Insecure;

impl ServerCertVerifier for Insecure {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    // `insecure` skips the certificate check only; the handshake signature is
    // still verified against the presented key, as in the shared TLS layer.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Deterministic ClientHello support. `ClientConnection::new` builds the
/// ClientHello synchronously, so a thread-local script set around that call
/// cannot leak into another connection.
#[derive(Default)]
pub struct Scripted {
    /// Record mode: every fill is appended here.
    pub recorded: Option<Vec<Vec<u8>>>,
    /// Replay mode: fills are served from here, in order.
    pub replay: Option<std::collections::VecDeque<Vec<u8>>>,
    pub x25519_secret: Option<[u8; 32]>,
}

thread_local! {
    static SCRIPT: RefCell<Option<Scripted>> = const { RefCell::new(None) };
}

/// Run `f` with `script` installed; returns the script afterwards.
pub fn with_script<R>(script: Scripted, f: impl FnOnce() -> R) -> (R, Scripted) {
    SCRIPT.with(|s| *s.borrow_mut() = Some(script));
    let r = f();
    let script = SCRIPT.with(|s| s.borrow_mut().take()).unwrap_or_default();
    (r, script)
}

fn os_random(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
    use aws_lc_rs::rand::SecureRandom as _;
    aws_lc_rs::rand::SystemRandom::new()
        .fill(buf)
        .map_err(|_| GetRandomFailed)
}

#[derive(Debug)]
struct ScriptedRandom;
static SCRIPTED_RANDOM: ScriptedRandom = ScriptedRandom;

impl SecureRandom for ScriptedRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        SCRIPT.with(|s| {
            let mut s = s.borrow_mut();
            let Some(s) = s.as_mut() else { return os_random(buf) };
            if let Some(replay) = s.replay.as_mut()
                && let Some(next) = replay.pop_front()
                && next.len() == buf.len()
            {
                buf.copy_from_slice(&next);
                return Ok(());
            }
            os_random(buf)?;
            if let Some(rec) = s.recorded.as_mut() {
                rec.push(buf.to_vec());
            }
            Ok(())
        })
    }
}

#[derive(Debug)]
struct ScriptedX25519;
static SCRIPTED_X25519: ScriptedX25519 = ScriptedX25519;

impl SupportedKxGroup for ScriptedX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = SCRIPT.with(|s| s.borrow().as_ref().and_then(|s| s.x25519_secret));
        let secret = match secret {
            Some(k) => k,
            None => {
                let mut k = [0u8; 32];
                os_random(&mut k).map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
                k
            }
        };
        let secret = x25519_dalek::StaticSecret::from(secret);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Ok(Box::new(X25519Kx { secret, public }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Kx {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for X25519Kx {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

pub fn tls_err(e: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
