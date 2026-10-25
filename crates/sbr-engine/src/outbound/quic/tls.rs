//! The rustls client config QUIC needs (TLS 1.3 only, ALPN, optional custom
//! roots and client certificate), built from the shared `tls` object.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sbr_config::TlsOutbound;

pub(crate) struct QuicTls {
    pub config: Arc<ClientConfig>,
    /// SNI / verification name. An IP literal verifies against IP SANs.
    pub server_name: String,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn read(inline: &Option<String>, path: &Option<String>, what: &str) -> Result<Option<Vec<u8>>, String> {
    match (inline, path) {
        (Some(s), _) => Ok(Some(s.as_bytes().to_vec())),
        (None, Some(p)) => std::fs::read(p).map(Some).map_err(|e| format!("read {what} {p}: {e}")),
        (None, None) => Ok(None),
    }
}

/// `server` is the outbound's server address, the default server name.
pub(crate) fn client_config(
    t: &TlsOutbound,
    server: &str,
    default_alpn: &[&str],
    early_data: bool,
) -> Result<QuicTls, String> {
    let unsupported = |what: &str| Err(format!("tls.{what}: not supported by sbr for QUIC yet"));
    if t.utls.as_ref().is_some_and(|u| u.enabled) {
        return unsupported("utls");
    }
    if t.reality.as_ref().is_some_and(|r| r.enabled) {
        return Err("tls.reality: not supported by QUIC".into());
    }
    if t.ech.as_ref().is_some_and(|e| e.enabled) {
        return unsupported("ech");
    }
    if t.fragment || t.record_fragment {
        return Err("tls.fragment: not supported by QUIC".into());
    }
    if !t.certificate_sha256.is_empty() {
        return unsupported("certificate_sha256");
    }
    if !t.certificate_public_key_sha256.is_empty() {
        return unsupported("certificate_public_key_sha256");
    }
    // QUIC is TLS 1.3 only (RFC 9001); a max below it can never work.
    if t.max_version.as_deref().is_some_and(|v| v != "1.3") {
        return Err("tls.max_version: QUIC requires TLS 1.3".into());
    }

    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?;
    let verifier: Arc<dyn ServerCertVerifier> = if t.insecure {
        Arc::new(NoVerify(provider.clone()))
    } else if let Some(pem) = read(&t.certificate, &t.certificate_path, "certificate")? {
        // sing-box: a configured certificate replaces the system roots.
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(&pem) {
            roots
                .add(c.map_err(|e| format!("tls.certificate: {e}"))?)
                .map_err(|e| format!("tls.certificate: {e}"))?;
        }
        if roots.is_empty() {
            return Err("tls.certificate: no PEM certificate found".into());
        }
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| e.to_string())?
    } else {
        Arc::new(rustls_platform_verifier::Verifier::new(provider.clone()).map_err(|e| e.to_string())?)
    };
    let builder = builder.dangerous().with_custom_certificate_verifier(verifier);
    let cert = read(&t.client_certificate, &t.client_certificate_path, "client_certificate")?;
    let key = read(&t.client_key, &t.client_key_path, "client_key")?;
    let mut config = match (cert, key) {
        (Some(cert), Some(key)) => {
            let chain = CertificateDer::pem_slice_iter(&cert)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("tls.client_certificate: {e}"))?;
            let key = PrivateKeyDer::from_pem_slice(&key).map_err(|e| format!("tls.client_key: {e}"))?;
            builder.with_client_auth_cert(chain, key).map_err(|e| e.to_string())?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => return Err("tls: client_certificate and client_key must be set together".into()),
    };
    config.alpn_protocols = if t.alpn.is_empty() {
        default_alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
    } else {
        t.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
    };
    config.enable_sni = !t.disable_sni;
    config.enable_early_data = early_data;
    let server_name = t.server_name.clone().unwrap_or_else(|| server.to_owned());
    ServerName::try_from(server_name.as_str()).map_err(|e| format!("tls.server_name {server_name:?}: {e}"))?;
    Ok(QuicTls {
        config: Arc::new(config),
        server_name,
    })
}

/// `insecure: true`. Signatures are still checked so the handshake keeps
/// its integrity against a passive attacker; only the chain is not.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
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

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
