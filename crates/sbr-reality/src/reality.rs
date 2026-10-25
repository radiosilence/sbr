//! The REALITY-specific parts, following sing-box `common/tls/reality_client.go`
//! and the server in `metacubex/utls` `reality.go` (from XTLS/REALITY).
//!
//! Client side:
//! 1. `auth_key = HKDF-SHA256(ikm = X25519(client X25519 share, server public key),
//!    salt = ClientHello.random[..20], info = "REALITY")`, 32 bytes.
//! 2. session_id plaintext (16 bytes): `[1, 8, 1, 0]` (client version 1.8.1,
//!    reserved), u32 BE unix time, 8-byte short_id. Sealed with AES-256-GCM
//!    under `auth_key`, nonce `random[20..]`, AAD the whole ClientHello message
//!    with the session_id still zeroed. Ciphertext + tag fill the 32 bytes.
//! 3. The server answers authenticated clients with a throwaway ed25519
//!    certificate whose signature field is `HMAC-SHA512(auth_key, ed25519 public key)`.

use std::io;

use aws_lc_rs::{aead, agreement, hmac};

use crate::hello::SESSION_ID_OFFSET;
use crate::keys::{hkdf_expand, hkdf_extract};

/// Client version advertised in the session_id (what sing-box sends).
const CLIENT_VERSION: [u8; 3] = [1, 8, 1];

pub(crate) struct AuthKey([u8; 32]);

impl AuthKey {
    pub(crate) fn derive(
        share: &agreement::PrivateKey,
        server_public: &[u8; 32],
        random: &[u8; 32],
    ) -> io::Result<Self> {
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, server_public);
        let shared = agreement::agree(share, peer, (), |ss| {
            Ok(hkdf_extract(hmac::HMAC_SHA256, &random[..20], ss))
        })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid REALITY public key"))?;
        // HKDF-Expand(prk, "REALITY", 32): a single HMAC block.
        let mut key = [0u8; 32];
        hkdf_expand(hmac::HMAC_SHA256, shared.as_ref(), &[b"REALITY"], &mut key);
        Ok(Self(key))
    }

    /// Writes the sealed session_id into `hello` (whose session_id is zero).
    pub(crate) fn seal_session_id(&self, hello: &mut [u8], random: &[u8; 32], short_id: &[u8; 8], unix_time: u32) {
        let mut sid = [0u8; 32];
        sid[..3].copy_from_slice(&CLIENT_VERSION);
        sid[4..8].copy_from_slice(&unix_time.to_be_bytes());
        sid[8..16].copy_from_slice(short_id);
        debug_assert!(hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].iter().all(|&b| b == 0));
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &self.0).expect("32-byte key"));
        let nonce = aead::Nonce::try_assume_unique_for_key(&random[20..]).expect("12-byte nonce");
        let (plain, tag_out) = sid.split_at_mut(16);
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(&*hello), plain)
            .expect("small input");
        tag_out.copy_from_slice(tag.as_ref());
        hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(&sid);
    }

    /// True if `leaf` is the server's REALITY certificate for this auth key.
    /// Returns the ed25519 public key on success, for CertificateVerify.
    pub(crate) fn verify_certificate(&self, leaf: &[u8]) -> Option<[u8; 32]> {
        let (pubkey, signature) = parse_ed25519_cert(leaf)?;
        let expected = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, &self.0), &pubkey);
        // Constant-time compare via hmac::verify semantics.
        if signature.len() == 64
            && aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_ref(), signature).is_ok()
        {
            Some(pubkey)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for AuthKey {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// Minimal DER walk: returns (tag, content, rest).
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&l0, rest) = rest.split_first()?;
    let (len, rest) = if l0 < 0x80 {
        (l0 as usize, rest)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// Extracts (ed25519 subject public key, signatureValue) from an X.509 cert.
/// Anything else (another key type, malformed DER) is `None`.
fn parse_ed25519_cert(cert: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (0x30, cert, _) = der(cert)? else { return None };
    let (0x30, tbs, rest) = der(cert)? else { return None };
    let (0x30, _sig_alg, rest) = der(rest)? else {
        return None;
    };
    let (0x03, sig, _) = der(rest)? else { return None };
    let (&0, signature) = sig.split_first()? else {
        return None;
    };

    let mut t = tbs;
    if t.first() == Some(&0xa0) {
        t = der(t)?.2; // [0] version
    }
    let (0x02, _, t) = der(t)? else { return None }; // serial
    let (0x30, _, t) = der(t)? else { return None }; // signature
    let (0x30, _, t) = der(t)? else { return None }; // issuer
    let (0x30, _, t) = der(t)? else { return None }; // validity
    let (0x30, _, t) = der(t)? else { return None }; // subject
    let (0x30, spki, _) = der(t)? else { return None };
    let (0x30, alg, rest) = der(spki)? else { return None };
    let (0x06, oid, _) = der(alg)? else { return None };
    if oid != OID_ED25519 {
        return None;
    }
    let (0x03, key, _) = der(rest)? else { return None };
    let (&0, key) = key.split_first()? else { return None };
    Some((key.try_into().ok()?, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate as the REALITY server builds it: Go `x509.CreateCertificate`
    /// over an empty template with an ed25519 key, then the last 64 bytes
    /// (the signature) replaced by the HMAC.
    fn reality_cert(pubkey: &[u8; 32], sig: &[u8; 64]) -> Vec<u8> {
        let mut tbs = vec![
            0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        ];
        tbs.extend_from_slice(&[0x30, 0x00]); // issuer
        tbs.extend_from_slice(&[0x30, 0x1e]); // validity
        tbs.extend_from_slice(&[0x17, 0x0d]);
        tbs.extend_from_slice(b"010101000000Z");
        tbs.extend_from_slice(&[0x17, 0x0d]);
        tbs.extend_from_slice(b"010101000000Z");
        tbs.extend_from_slice(&[0x30, 0x00]); // subject
        tbs.extend_from_slice(&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
        tbs.extend_from_slice(pubkey);
        let mut body = vec![0x30, tbs.len() as u8];
        body.extend_from_slice(&tbs);
        body.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00]);
        body.extend_from_slice(sig);
        let mut cert = vec![0x30, 0x81, body.len() as u8];
        cert.extend_from_slice(&body);
        cert
    }

    #[test]
    fn verifies_hmac_certificate() {
        let server = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_pub: [u8; 32] = server.compute_public_key().unwrap().as_ref().try_into().unwrap();
        let client = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let random = [7u8; 32];
        let auth = AuthKey::derive(&client, &server_pub, &random).unwrap();

        let ed_pub = [9u8; 32];
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, auth.bytes()), &ed_pub);
        let cert = reality_cert(&ed_pub, tag.as_ref().try_into().unwrap());
        assert_eq!(auth.verify_certificate(&cert), Some(ed_pub));

        let mut bad = cert.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(auth.verify_certificate(&bad), None);
        assert_eq!(auth.verify_certificate(&cert[..cert.len() - 1]), None);
    }
}
