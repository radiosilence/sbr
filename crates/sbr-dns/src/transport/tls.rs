//! rustls (aws-lc-rs) client setup for DoT and DoH.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sbr_config::TlsOutbound;
use sbr_core::Stream;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub(crate) struct Tls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl Tls {
    /// `host` is the server address, the SNI unless `server_name` overrides it.
    /// `default_alpn` applies when the config sets none. `read` loads
    /// `certificate_path`.
    pub fn new(
        t: &TlsOutbound,
        host: &str,
        default_alpn: &[&str],
        read: &dyn Fn(&str) -> io::Result<Vec<u8>>,
    ) -> Result<Self, String> {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let versions: Vec<&'static rustls::SupportedProtocolVersion> =
            match (t.min_version.as_deref(), t.max_version.as_deref()) {
                (Some("1.3"), _) => vec![&rustls::version::TLS13],
                (_, Some("1.0" | "1.1")) => return Err("TLS max_version below 1.2 is not supported".into()),
                (_, Some("1.2")) => vec![&rustls::version::TLS12],
                _ => vec![&rustls::version::TLS13, &rustls::version::TLS12],
            };
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&versions)
            .map_err(|e| e.to_string())?;
        let mut config = if t.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            let pem = match (&t.certificate, &t.certificate_path) {
                (Some(p), _) => Some(p.as_bytes().to_vec()),
                (None, Some(path)) => Some(read(path).map_err(|e| format!("{path}: {e}"))?),
                (None, None) => None,
            };
            match pem {
                // A configured certificate replaces the system roots, like sing-box.
                Some(pem) => {
                    for c in CertificateDer::pem_slice_iter(&pem) {
                        let c = c.map_err(|e| format!("certificate: {e}"))?;
                        roots.add(c).map_err(|e| format!("certificate: {e}"))?;
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        config.alpn_protocols = if t.alpn.is_empty() {
            default_alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
        } else {
            t.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
        };
        config.enable_sni = !t.disable_sni;
        let name = t.server_name.as_deref().unwrap_or(host);
        let server_name = match name.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(name.to_owned()).map_err(|e| format!("server_name {name:?}: {e}"))?,
        };
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    /// Handshake over `s`; returns the stream and the negotiated ALPN.
    pub async fn connect(&self, s: Stream) -> io::Result<(Stream, Option<Vec<u8>>)> {
        let tls = self.connector.connect(self.server_name.clone(), s).await?;
        let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        Ok((Box::new(tls), alpn))
    }
}

/// `insecure`: accept any certificate, but still check handshake signatures
/// so the session is at least bound to the presented key.
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
