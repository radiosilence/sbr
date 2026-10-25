//! TLS 1.3 key schedule (RFC 8446 §7) and the record protection keys.
//!
//! HKDF is written out over HMAC instead of using `aws_lc_rs::hkdf` because the
//! schedule needs the raw extracted secrets (for chaining and for the RFC 8448
//! test vectors), which `hkdf::Prk` deliberately does not expose. Only the
//! handshake runs this code; the bulk path only touches [`RecordKey`].

use aws_lc_rs::{aead, digest, hmac};

pub(crate) const MAX_HASH_LEN: usize = 48;
pub(crate) const TAG_LEN: usize = 16;

/// A TLS 1.3 cipher suite this client can negotiate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    pub(crate) fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// IANA code point.
    pub fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    pub(crate) fn hash(self) -> &'static digest::Algorithm {
        match self {
            Self::Aes256GcmSha384 => &digest::SHA384,
            _ => &digest::SHA256,
        }
    }

    pub(crate) fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Aes256GcmSha384 => hmac::HMAC_SHA384,
            _ => hmac::HMAC_SHA256,
        }
    }

    pub(crate) fn hash_len(self) -> usize {
        self.hash().output_len()
    }

    fn aead(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &aead::AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }

    /// AES-GCM has a per-key record limit (RFC 8446 §5.5); ChaCha20 does not.
    pub(crate) fn needs_rekey(self) -> bool {
        !matches!(self, Self::Chacha20Poly1305Sha256)
    }
}

/// A secret of the suite's hash length. Zeroed on drop.
#[derive(Clone)]
pub(crate) struct Secret {
    buf: [u8; MAX_HASH_LEN],
    len: usize,
}

impl Secret {
    pub(crate) fn zero(len: usize) -> Self {
        Self {
            buf: [0; MAX_HASH_LEN],
            len,
        }
    }

    pub(crate) fn from_slice(b: &[u8]) -> Self {
        let mut s = Self::zero(b.len());
        s.buf[..b.len()].copy_from_slice(b);
        s
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best effort; the AEAD keys live inside aws-lc, which zeroes its own.
        self.buf.fill(0);
        std::hint::black_box(&self.buf);
    }
}

pub(crate) fn hkdf_extract(alg: hmac::Algorithm, salt: &[u8], ikm: &[u8]) -> Secret {
    let tag = hmac::sign(&hmac::Key::new(alg, salt), ikm);
    Secret::from_slice(tag.as_ref())
}

/// HKDF-Expand (RFC 5869) with `info` given as concatenated parts.
pub(crate) fn hkdf_expand(alg: hmac::Algorithm, prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
    let key = hmac::Key::new(alg, prk);
    let mut prev: Option<hmac::Tag> = None;
    let mut counter = 1u8;
    let mut pos = 0;
    while pos < out.len() {
        let mut ctx = hmac::Context::with_key(&key);
        if let Some(p) = &prev {
            ctx.update(p.as_ref());
        }
        for part in info {
            ctx.update(part);
        }
        ctx.update(&[counter]);
        let t = ctx.sign();
        let n = (out.len() - pos).min(t.as_ref().len());
        out[pos..pos + n].copy_from_slice(&t.as_ref()[..n]);
        pos += n;
        counter += 1;
        prev = Some(t);
    }
}

/// HKDF-Expand with info = HkdfLabel (RFC 8446 §7.1).
pub(crate) fn hkdf_expand_label(alg: hmac::Algorithm, secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    debug_assert!(label.len() + 6 <= 255 && context.len() <= 255);
    let len = (out.len() as u16).to_be_bytes();
    let label_len = [(6 + label.len()) as u8];
    let ctx_len = [context.len() as u8];
    hkdf_expand(
        alg,
        secret,
        &[&len, &label_len, b"tls13 ", label, &ctx_len, context],
        out,
    );
}

pub(crate) fn derive_secret(suite: CipherSuite, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Secret {
    let mut out = Secret::zero(suite.hash_len());
    hkdf_expand_label(suite.hmac(), secret, label, transcript_hash, out.as_mut());
    out
}

/// The parts of the key schedule the client needs, without PSK.
pub(crate) struct KeySchedule {
    pub(crate) suite: CipherSuite,
    /// Handshake secret, then master secret once `into_master` ran.
    secret: Secret,
}

impl KeySchedule {
    /// Early secret (no PSK) → Handshake Secret.
    pub(crate) fn handshake(suite: CipherSuite, shared_secret: &[u8]) -> Self {
        let hl = suite.hash_len();
        let zeros = [0u8; MAX_HASH_LEN];
        let early = hkdf_extract(suite.hmac(), &zeros[..hl], &zeros[..hl]);
        let empty_hash = digest::digest(suite.hash(), b"");
        let derived = derive_secret(suite, early.as_ref(), b"derived", empty_hash.as_ref());
        let secret = hkdf_extract(suite.hmac(), derived.as_ref(), shared_secret);
        Self { suite, secret }
    }

    #[cfg(test)]
    pub(crate) fn current_secret(&self) -> &[u8] {
        self.secret.as_ref()
    }

    /// `c hs traffic` / `s hs traffic` (or `c ap traffic` / `s ap traffic` after
    /// `into_master`), over the transcript hash given.
    pub(crate) fn traffic_secrets(&self, client_label: &[u8], server_label: &[u8], hash: &[u8]) -> (Secret, Secret) {
        (
            derive_secret(self.suite, self.secret.as_ref(), client_label, hash),
            derive_secret(self.suite, self.secret.as_ref(), server_label, hash),
        )
    }

    /// Handshake Secret → Master Secret.
    pub(crate) fn into_master(self) -> Self {
        let hl = self.suite.hash_len();
        let empty_hash = digest::digest(self.suite.hash(), b"");
        let derived = derive_secret(self.suite, self.secret.as_ref(), b"derived", empty_hash.as_ref());
        let zeros = [0u8; MAX_HASH_LEN];
        let secret = hkdf_extract(self.suite.hmac(), derived.as_ref(), &zeros[..hl]);
        Self {
            suite: self.suite,
            secret,
        }
    }
}

/// verify_data = HMAC(finished_key, transcript_hash).
pub(crate) fn finished_verify_data(suite: CipherSuite, base_key: &[u8], hash: &[u8]) -> hmac::Tag {
    let mut fk = Secret::zero(suite.hash_len());
    hkdf_expand_label(suite.hmac(), base_key, b"finished", b"", fk.as_mut());
    hmac::sign(&hmac::Key::new(suite.hmac(), fk.as_ref()), hash)
}

pub(crate) fn next_traffic_secret(suite: CipherSuite, secret: &Secret) -> Secret {
    let mut out = Secret::zero(suite.hash_len());
    hkdf_expand_label(suite.hmac(), secret.as_ref(), b"traffic upd", b"", out.as_mut());
    out
}

/// One direction of record protection: AEAD key, static IV and sequence number.
pub(crate) struct RecordKey {
    pub(crate) suite: CipherSuite,
    key: aead::LessSafeKey,
    iv: [u8; 12],
    pub(crate) seq: u64,
    /// Kept so KeyUpdate can derive the next generation.
    pub(crate) secret: Secret,
}

impl RecordKey {
    pub(crate) fn new(suite: CipherSuite, secret: Secret) -> Self {
        let mut key = [0u8; 32];
        let key = &mut key[..suite.aead().key_len()];
        hkdf_expand_label(suite.hmac(), secret.as_ref(), b"key", b"", key);
        let mut iv = [0u8; 12];
        hkdf_expand_label(suite.hmac(), secret.as_ref(), b"iv", b"", &mut iv);
        let unbound = aead::UnboundKey::new(suite.aead(), key).expect("key length matches the suite");
        key.fill(0);
        Self {
            suite,
            key: aead::LessSafeKey::new(unbound),
            iv,
            seq: 0,
            secret,
        }
    }

    /// The next generation after a KeyUpdate.
    pub(crate) fn updated(&self) -> Self {
        Self::new(self.suite, next_traffic_secret(self.suite, &self.secret))
    }

    fn nonce(&mut self) -> aead::Nonce {
        let mut n = self.iv;
        for (a, b) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *a ^= b;
        }
        self.seq = self.seq.wrapping_add(1);
        aead::Nonce::assume_unique_for_key(n)
    }

    /// Seals `in_out` (inner plaintext incl. content type) with `header` as AAD
    /// and returns the tag to append.
    pub(crate) fn seal(&mut self, header: [u8; 5], in_out: &mut [u8]) -> [u8; TAG_LEN] {
        let nonce = self.nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(header), in_out)
            .expect("record sizes are bounded");
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        out
    }

    /// Opens a record body (ciphertext + tag) in place. Returns the plaintext
    /// length (the inner plaintext, content type and padding included).
    pub(crate) fn open(&mut self, header: [u8; 5], in_out: &mut [u8]) -> Result<usize, ()> {
        let nonce = self.nonce();
        self.key
            .open_in_place(nonce, aead::Aad::from(header), in_out)
            .map(|p| p.len())
            .map_err(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn iv(&self) -> &[u8] {
        &self.iv
    }
}

#[cfg(test)]
mod tests {
    //! RFC 8448 §3 "Simple 1-RTT Handshake" (TLS_AES_128_GCM_SHA256, x25519).
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const CLIENT_HELLO: &str = "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";
    const SERVER_HELLO: &str = "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";
    const SHARED: &str =
        "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d";

    #[test]
    fn rfc8448_simple_1rtt() {
        let suite = CipherSuite::Aes128GcmSha256;
        let ks = KeySchedule::handshake(suite, &h(SHARED));
        assert_eq!(
            ks.current_secret(),
            h("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac")
        );
        let mut tr = digest::Context::new(suite.hash());
        tr.update(&h(CLIENT_HELLO));
        tr.update(&h(SERVER_HELLO));
        let hash = tr.clone().finish();
        let (c, s) = ks.traffic_secrets(b"c hs traffic", b"s hs traffic", hash.as_ref());
        assert_eq!(
            c.as_ref(),
            h("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21")
        );
        assert_eq!(
            s.as_ref(),
            h("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38")
        );
        let sk = RecordKey::new(suite, s);
        assert_eq!(sk.iv(), h("5d 31 3e b2 67 12 76 ee 13 00 0b 30"));
        let ck = RecordKey::new(suite, c.clone());
        assert_eq!(ck.iv(), h("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f"));

        let master = ks.into_master();
        assert_eq!(
            master.current_secret(),
            h("18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19")
        );

        // Client Finished over the RFC transcript through server Finished.
        let through_sf =
            h("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
        let (cap, sap) = master.traffic_secrets(b"c ap traffic", b"s ap traffic", &through_sf);
        assert_eq!(
            cap.as_ref(),
            h("9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5")
        );
        assert_eq!(
            sap.as_ref(),
            h("a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43")
        );
        let sk = RecordKey::new(suite, sap);
        assert_eq!(sk.iv(), h("cf 78 2b 88 dd 83 54 9a ad f1 e9 84"));
        let ck = RecordKey::new(suite, cap);
        assert_eq!(ck.iv(), h("5b 78 92 3d ee 08 57 90 33 e5 23 d9"));
        let cfin = finished_verify_data(suite, c.as_ref(), &through_sf);
        assert_eq!(
            cfin.as_ref(),
            h("a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61")
        );
    }

    #[test]
    fn rfc8448_application_records() {
        let suite = CipherSuite::Aes128GcmSha256;
        let payload: Vec<u8> = (0u8..0x32).collect();
        // Client's first application record (seq 0 under c ap traffic).
        let c_ap = Secret::from_slice(&h(
            "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5",
        ));
        let expected = h("17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b
            98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4");
        let mut w = RecordKey::new(suite, c_ap);
        let hdr = [0x17, 3, 3, 0, 0x43];
        let mut rec = payload.clone();
        rec.push(0x17);
        let tag = w.seal(hdr, &mut rec);
        rec.extend_from_slice(&tag);
        assert_eq!(&expected[5..], &rec[..]);
        // Followed by close_notify at seq 1.
        let mut alert = vec![1, 0, 0x15];
        let tag = w.seal([0x17, 3, 3, 0, 0x13], &mut alert);
        alert.extend_from_slice(&tag);
        assert_eq!(alert, h("c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3"));

        // Server's application record: seq 1, after its NewSessionTicket.
        let s_ap = Secret::from_slice(&h(
            "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43",
        ));
        let mut r = RecordKey::new(suite, s_ap);
        r.seq = 1;
        let mut srec = h("17 03 03 00 43 2e 93 7e 11 ef 4a c7 40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36 e3
            0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2 ab f3 32 54 0d d0 32 e1 67 c2 95 5d");
        let n = r.open(hdr, &mut srec[5..]).unwrap();
        assert_eq!(&srec[5..5 + n - 1], &payload[..]);
        assert_eq!(srec[5 + n - 1], 0x17);
        // A replay at the next sequence number fails.
        let mut again = expected.clone();
        assert!(r.open(hdr, &mut again[5..]).is_err());
    }

    #[test]
    fn rfc8448_resumption_traffic_update_label() {
        // RFC 8446 §7.2: application_traffic_secret_N+1 = HKDF-Expand-Label(.., "traffic upd", "", Hash.length)
        let suite = CipherSuite::Aes128GcmSha256;
        let s = Secret::from_slice(&[7u8; 32]);
        let n = next_traffic_secret(suite, &s);
        let mut manual = [0u8; 32];
        hkdf_expand_label(suite.hmac(), s.as_ref(), b"traffic upd", b"", &mut manual);
        assert_eq!(n.as_ref(), manual);
        assert_ne!(n.as_ref(), s.as_ref());
    }
}
