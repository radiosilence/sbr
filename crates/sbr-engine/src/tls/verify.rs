//! Certificate checks that replace chain validation: `insecure`, and
//! sing-box's `certificate_sha256` / `certificate_public_key_sha256` pins.
//! Handshake signatures are still verified, so a pin really binds the key.

use std::sync::Arc;

use aws_lc_rs::digest;
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

#[derive(Debug)]
pub struct Pinned {
    cert: Vec<[u8; 32]>,
    public_key: Vec<[u8; 32]>,
    accept_any: bool,
    algs: WebPkiSupportedAlgorithms,
}

fn hashes(list: &[String], field: &str) -> Result<Vec<[u8; 32]>, String> {
    list.iter()
        .map(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| format!("tls.{field}: expected base64 SHA-256, got {s:?}"))
        })
        .collect()
}

impl Pinned {
    pub fn new(
        cert: &[String],
        public_key: &[String],
        accept_any: bool,
        p: &Arc<CryptoProvider>,
    ) -> Result<Self, String> {
        Ok(Self {
            cert: hashes(cert, "certificate_sha256")?,
            public_key: hashes(public_key, "certificate_public_key_sha256")?,
            accept_any,
            algs: p.signature_verification_algorithms,
        })
    }
}

fn sha256(b: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, b)
        .as_ref()
        .try_into()
        .expect("32 bytes")
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.accept_any {
            return Ok(ServerCertVerified::assertion());
        }
        let h = sha256(end_entity);
        if self.cert.contains(&h) {
            return Ok(ServerCertVerified::assertion());
        }
        let spki =
            subject_public_key_info(end_entity).ok_or_else(|| Error::General("parse leaf certificate".into()))?;
        let pk = sha256(spki);
        if self.public_key.contains(&pk) {
            return Ok(ServerCertVerified::assertion());
        }
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        Err(Error::General(format!(
            "unrecognized peer certificate: sha256 {}, public key sha256 {}",
            b64(&h),
            b64(&pk)
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// One DER TLV: (tag, whole element, contents).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = len << 8 | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((tag, b.get(..end)?, b.get(hdr..end)?))
}

/// The DER `SubjectPublicKeyInfo` of an X.509 certificate: what Go's
/// `x509.MarshalPKIXPublicKey` produces for the leaf's key.
pub(crate) fn subject_public_key_info(cert: &[u8]) -> Option<&[u8]> {
    let (_, _, cert) = tlv(cert)?; // Certificate SEQUENCE
    let (_, _, mut tbs) = tlv(cert)?; // TBSCertificate SEQUENCE
    // [0] version (optional), serial, signature alg, issuer, validity, subject, SPKI.
    if tbs.first() == Some(&0xa0) {
        let (_, whole, _) = tlv(tbs)?;
        tbs = &tbs[whole.len()..];
    }
    for _ in 0..5 {
        let (_, whole, _) = tlv(tbs)?;
        tbs = &tbs[whole.len()..];
    }
    let (tag, whole, _) = tlv(tbs)?;
    (tag == 0x30).then_some(whole)
}
