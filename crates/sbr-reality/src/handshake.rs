//! The TLS 1.3 client handshake (RFC 8446 §2: 1-RTT, HelloRetryRequest, no
//! PSK) with two ways to authenticate the server: REALITY's certificate HMAC,
//! or ordinary certificate verification through a rustls verifier.

use std::future::poll_fn;
use std::io;
use std::io::Read as _;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::{agreement, constant_time, digest, kem, signature};
use rustls::client::danger::ServerCertVerifier;
use rustls::internal::msgs::codec::{Codec, Reader as RustlsReader};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::RealityConfig;
use crate::hello::{
    CERT_COMPRESSION_BROTLI, CERT_COMPRESSION_ZLIB, CERT_COMPRESSION_ZSTD, GROUP_X25519, GROUP_X25519_MLKEM768, Hello, HelloParams, KeyShares,
    MLKEM768_CIPHERTEXT_LEN, SESSION_ID_OFFSET, ecdh_alg,
};
use crate::keys::{CipherSuite, KeySchedule, RecordKey, finished_verify_data};
use crate::reality::AuthKey;
use crate::record::{
    CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, HandshakeBuf, MAX_PLAINTEXT, RawRecord,
    ReadBuf, alert_error, invalid, seal_record,
};
use crate::stream::TlsStream;

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
    0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_REQUEST: u8 = 13;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_COMPRESSED_CERTIFICATE: u8 = 25;
const HS_MESSAGE_HASH: u8 = 254;

const SCHEME_ED25519: u16 = 0x0807;

/// RFC 8879 §4: bound the decompressed chain (BoringSSL uses the same 128 KiB idea).
const MAX_CERT_CHAIN: usize = 1 << 17;

/// The ChangeCipherSpec record a middlebox-compatible client sends once.
const CCS_RECORD: [u8; 6] = [CT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1];

/// How the server is authenticated.
pub(crate) enum Auth<'a> {
    Reality {
        cfg: &'a RealityConfig,
        /// Tests only: run the TLS handshake against an ordinary server.
        skip_verify: bool,
    },
    Verify {
        verifier: &'a dyn ServerCertVerifier,
        name: &'a ServerName<'static>,
        /// Fills the 32-byte session id of the first ClientHello, given the
        /// whole message with the session id zeroed (ShadowTLS v3).
        session_id: Option<&'a crate::SessionIdFn>,
    },
}

/// Cursor over a handshake message body.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(invalid("truncated TLS handshake message"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> io::Result<usize> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize)
    }
    fn vec8(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn vec24(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
}

async fn next_record<S: AsyncRead + Unpin>(io: &mut S, rb: &mut ReadBuf) -> io::Result<RawRecord> {
    loop {
        if let Some(r) = rb.next()? {
            return Ok(r);
        }
        let n = poll_fn(|cx| rb.poll_fill(io, cx)).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed during TLS handshake",
            ));
        }
    }
}

struct ServerHello<'a> {
    random: &'a [u8],
    session_id: &'a [u8],
    suite: u16,
    version: Option<u16>,
    /// ServerHello: (group, key_exchange). HelloRetryRequest: (selected group, empty).
    key_share: Option<(u16, &'a [u8])>,
    cookie: Option<&'a [u8]>,
}

fn parse_server_hello(body: &[u8]) -> io::Result<ServerHello<'_>> {
    let mut r = Reader(body);
    let _legacy_version = r.u16()?;
    let random = r.take(32)?;
    let session_id = r.vec8()?;
    let suite = r.u16()?;
    if r.u8()? != 0 {
        return Err(invalid("ServerHello selected compression"));
    }
    let hrr = random == HRR_RANDOM;
    let mut sh = ServerHello {
        random,
        session_id,
        suite,
        version: None,
        key_share: None,
        cookie: None,
    };
    if r.0.is_empty() {
        return Ok(sh);
    }
    let mut exts = Reader(r.vec16()?);
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let mut data = Reader(exts.vec16()?);
        match ty {
            0x002b => sh.version = Some(data.u16()?),
            0x0033 if hrr => sh.key_share = Some((data.u16()?, &[])),
            0x0033 => {
                let group = data.u16()?;
                sh.key_share = Some((group, data.vec16()?));
            }
            0x002c => sh.cookie = Some(data.vec16()?),
            _ => {}
        }
    }
    Ok(sh)
}

fn shared_secret(keys: &KeyShares, group: u16, peer: &[u8]) -> io::Result<Vec<u8>> {
    let bad = || invalid("invalid server key share");
    let not_offered = || invalid("server chose a group we did not offer");
    let ecdh = |key: &agreement::PrivateKey, alg: &'static agreement::Algorithm, peer: &[u8]| {
        agreement::agree(key, agreement::UnparsedPublicKey::new(alg, peer), bad(), |s| {
            Ok(s.to_vec())
        })
    };
    match group {
        GROUP_X25519 => ecdh(keys.x25519.as_ref().ok_or_else(not_offered)?, &agreement::X25519, peer),
        GROUP_X25519_MLKEM768 => {
            let (dk, xk) = keys.mlkem.as_ref().ok_or_else(not_offered)?;
            if peer.len() != MLKEM768_CIPHERTEXT_LEN + 32 {
                return Err(bad());
            }
            let (ct, x) = peer.split_at(MLKEM768_CIPHERTEXT_LEN);
            let ss = dk.decapsulate(kem::Ciphertext::from(ct)).map_err(|_| bad())?;
            // draft-kwiatkowski-tls-ecdhe-mlkem: ML-KEM secret first.
            let mut out = ss.as_ref().to_vec();
            out.extend_from_slice(&ecdh(xk, &agreement::X25519, x)?);
            Ok(out)
        }
        g => {
            let (_, k) = keys.ecdh.iter().find(|(kg, _)| *kg == g).ok_or_else(not_offered)?;
            ecdh(k, ecdh_alg(g).ok_or_else(not_offered)?, peer)
        }
    }
}

/// What EncryptedExtensions told us.
#[derive(Default)]
struct Negotiated {
    alpn: Option<Vec<u8>>,
    /// The server sent ALPS: we owe it our (empty) application settings.
    alps: bool,
    record_size_limit: Option<u16>,
}

fn parse_encrypted_extensions(ee_body: &[u8], hello: &Hello) -> io::Result<Negotiated> {
    let mut n = Negotiated::default();
    let mut r = Reader(ee_body);
    let mut exts = Reader(r.vec16()?);
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let data = exts.vec16()?;
        match ty {
            0x0010 => {
                let mut list = Reader(Reader(data).vec16()?);
                let proto = list.vec8()?.to_vec();
                if !list.0.is_empty() || !hello.offers_alpn(&proto) {
                    return Err(invalid("server selected an ALPN protocol we did not offer"));
                }
                n.alpn = Some(proto);
            }
            0x44cd => {
                if !hello.offers_alps() {
                    return Err(invalid("server sent ALPS we did not offer"));
                }
                n.alps = true;
            }
            0x001c => {
                let l = Reader(data).u16()?;
                if l < 64 {
                    return Err(invalid("invalid record_size_limit"));
                }
                n.record_size_limit = Some(l);
            }
            _ => {}
        }
    }
    if n.alps && n.alpn.as_deref() != Some(b"h2") {
        return Err(invalid("server sent ALPS without negotiating h2"));
    }
    Ok(n)
}

/// The certificate_list of a TLS 1.3 Certificate body: (certificates, leaf OCSP response).
fn parse_certificates(body: &[u8]) -> io::Result<(Vec<CertificateDer<'static>>, Vec<u8>)> {
    let mut r = Reader(body);
    if !r.vec8()?.is_empty() {
        return Err(invalid("server Certificate with a request context"));
    }
    let mut list = Reader(r.vec24()?);
    let mut certs = Vec::new();
    let mut ocsp = Vec::new();
    while !list.0.is_empty() {
        let der = list.vec24()?;
        let mut exts = Reader(list.vec16()?);
        while !exts.0.is_empty() {
            let ty = exts.u16()?;
            let mut data = Reader(exts.vec16()?);
            // status_request on the leaf: CertificateStatus { ocsp(1), response<1..2^24-1> }.
            if ty == 0x0005 && certs.is_empty() && data.u8()? == 1 {
                ocsp = data.vec24()?.to_vec();
            }
        }
        certs.push(CertificateDer::from(der.to_vec()));
    }
    if certs.is_empty() {
        return Err(invalid("server sent no certificate"));
    }
    Ok((certs, ocsp))
}

/// RFC 8879 CompressedCertificate → the Certificate body it stands for.
fn decompress_certificate(body: &[u8], hello: &Hello) -> io::Result<Vec<u8>> {
    let mut r = Reader(body);
    let alg = r.u16()?;
    let len = r.u24()?;
    let data = r.vec24()?;
    if !hello.offers_compression(alg) {
        return Err(invalid(
            "server compressed its certificate with an algorithm we did not offer",
        ));
    }
    if len > MAX_CERT_CHAIN {
        return Err(invalid("compressed certificate too large"));
    }
    let mut out = Vec::with_capacity(len);
    let limit = len as u64 + 1;
    let res = match alg {
        CERT_COMPRESSION_BROTLI => brotli_decompressor::Decompressor::new(data, 4096)
            .take(limit)
            .read_to_end(&mut out),
        CERT_COMPRESSION_ZLIB => flate2::read::ZlibDecoder::new(data).take(limit).read_to_end(&mut out),
        CERT_COMPRESSION_ZSTD => ruzstd::decoding::StreamingDecoder::new(data)
            .map_err(io::Error::other)
            .and_then(|d| d.take(limit).read_to_end(&mut out)),
        _ => return Err(invalid("unsupported certificate compression")),
    };
    if res.is_err() || out.len() != len {
        return Err(invalid("bad compressed certificate"));
    }
    Ok(out)
}

fn handshake_msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(ty);
    m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    m.extend_from_slice(body);
    m
}

fn plaintext_record(out: &mut Vec<u8>, version: [u8; 2], msg: &[u8]) {
    out.extend_from_slice(&[CT_HANDSHAKE, version[0], version[1]]);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
}

/// Reads the next ServerHello-shaped message from plaintext records.
async fn read_server_hello<S: AsyncRead + Unpin>(
    io: &mut S,
    rb: &mut ReadBuf,
    hs: &mut HandshakeBuf,
    allow_ccs: bool,
) -> io::Result<Vec<u8>> {
    loop {
        if let Some(m) = hs.next_message()? {
            if m[0] != HS_SERVER_HELLO {
                return Err(invalid("expected ServerHello"));
            }
            return Ok(m);
        }
        let rec = next_record(io, rb).await?;
        match rec.typ {
            CT_HANDSHAKE => hs.push(rb.body(&rec)),
            // A middlebox-compatible server may send its CCS right after HelloRetryRequest.
            CT_CHANGE_CIPHER_SPEC if allow_ccs && rb.body(&rec) == [1] => {}
            CT_ALERT => return Err(alert_error(rb.body(&rec))),
            _ => return Err(invalid("expected ServerHello")),
        }
    }
}

/// TLS 1.3, and nothing after the ServerHello in its record (a TLS 1.2
/// server's flight continues there, so the version is checked first).
fn check_version(sh: &ServerHello<'_>, hs: &HandshakeBuf) -> io::Result<()> {
    match sh.version {
        Some(0x0304) if hs.is_empty() => Ok(()),
        Some(0x0304) => Err(invalid("handshake data after ServerHello in the same record")),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "server negotiated TLS 1.2 or older; sbr's browser-fingerprint TLS speaks TLS 1.3 only \
             (set tls.utls.enabled to false, or tls.max_version to \"1.2\", to use rustls)",
        )),
    }
}

pub(crate) async fn handshake<S>(mut io: S, p: &HelloParams<'_>, auth: Auth<'_>) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hello = Hello::new(p)?;
    let mut keys = KeyShares::generate(&hello.initial_share_groups(), hello.grease_group(), hello.reuse_x25519())?;
    let fill_session_id = matches!(
        auth,
        Auth::Reality { .. }
            | Auth::Verify {
                session_id: Some(_),
                ..
            }
    );
    if fill_session_id {
        hello.session_id = [0; 32];
    }
    let mut ch = hello.encode(&keys.public, None);
    let reality_auth = match &auth {
        Auth::Reality { cfg, .. } => {
            let x25519 = keys
                .x25519
                .as_ref()
                .ok_or_else(|| io::Error::other("fingerprint offers no X25519 key share"))?;
            let a = AuthKey::derive(x25519, &cfg.public_key, &hello.random)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            a.seal_session_id(&mut ch, &hello.random, &cfg.short_id, now);
            Some(a)
        }
        Auth::Verify {
            session_id: Some(f), ..
        } => {
            f(&mut ch);
            None
        }
        Auth::Verify { .. } => None,
    };
    hello
        .session_id
        .copy_from_slice(&ch[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32]);

    // Browsers put 0x0301 on the first ClientHello record.
    let mut out = Vec::with_capacity(crate::record::MAX_WRITE_RECORD);
    plaintext_record(&mut out, [3, 1], &ch);
    io.write_all(&out).await?;
    io.flush().await?;
    out.clear();

    let mut rb = ReadBuf::new();
    let mut hs = HandshakeBuf::default();
    let mut sh_msg = read_server_hello(&mut io, &mut rb, &mut hs, false).await?;
    let mut sh = parse_server_hello(&sh_msg[4..])?;
    let mut sent_ccs = false;
    // (transcript prefix, first suite) after a HelloRetryRequest.
    let mut retried: Option<(Vec<u8>, u16)> = None;
    if sh.random == HRR_RANDOM {
        if reality_auth.is_some() {
            // A REALITY server never asks for a retry: every profile offers X25519.
            return Err(invalid("server sent HelloRetryRequest; not a REALITY server"));
        }
        check_version(&sh, &hs)?;
        if sh.session_id != hello.session_id {
            return Err(invalid("HelloRetryRequest session_id mismatch"));
        }
        let suite = CipherSuite::from_id(sh.suite)
            .filter(|_| hello.offers_suite(sh.suite))
            .ok_or_else(|| invalid("server chose an unsupported cipher suite"))?;
        match sh.key_share {
            Some((g, _)) => {
                if !hello.supports_group(g) || keys.public.iter().any(|s| s.0 == g) {
                    return Err(invalid("HelloRetryRequest selected an invalid group"));
                }
                keys = KeyShares::generate(&[g], 0, false)?;
            }
            // A cookie-only retry keeps the shares.
            None if sh.cookie.is_some() => {}
            None => return Err(invalid("HelloRetryRequest without key_share or cookie")),
        }
        // RFC 8446 §4.4.1: the first ClientHello is replaced by its hash.
        let h = digest::digest(suite.hash(), &ch);
        let mut prefix = handshake_msg(HS_MESSAGE_HASH, h.as_ref());
        prefix.extend_from_slice(&sh_msg);
        ch = hello.encode(&keys.public, sh.cookie);
        retried = Some((prefix, sh.suite));
        // BoringSSL sends its one compatibility CCS before the second ClientHello.
        out.extend_from_slice(&CCS_RECORD);
        plaintext_record(&mut out, [3, 3], &ch);
        io.write_all(&out).await?;
        io.flush().await?;
        out.clear();
        sent_ccs = true;
        sh_msg = read_server_hello(&mut io, &mut rb, &mut hs, true).await?;
        sh = parse_server_hello(&sh_msg[4..])?;
        if sh.random == HRR_RANDOM {
            return Err(invalid("second HelloRetryRequest"));
        }
    }
    check_version(&sh, &hs)?;
    if sh.session_id != hello.session_id {
        return Err(invalid("ServerHello session_id mismatch"));
    }
    if retried.as_ref().is_some_and(|r| r.1 != sh.suite) {
        return Err(invalid("ServerHello cipher suite differs from HelloRetryRequest"));
    }
    let suite = CipherSuite::from_id(sh.suite)
        .filter(|_| hello.offers_suite(sh.suite))
        .ok_or_else(|| invalid("server chose an unsupported cipher suite"))?;
    let (group, peer_share) = sh.key_share.ok_or_else(|| invalid("ServerHello without key_share"))?;
    let shared = shared_secret(&keys, group, peer_share)?;
    drop(keys);

    let mut transcript = digest::Context::new(suite.hash());
    if let Some((prefix, _)) = &retried {
        transcript.update(prefix);
    }
    transcript.update(&ch);
    transcript.update(&sh_msg);
    let schedule = KeySchedule::handshake(suite, &shared);
    let (c_hs, s_hs) = schedule.traffic_secrets(b"c hs traffic", b"s hs traffic", transcript.clone().finish().as_ref());
    let mut s_key = RecordKey::new(suite, s_hs.clone());
    let mut c_key = RecordKey::new(suite, c_hs.clone());

    #[derive(PartialEq)]
    enum Expect {
        EncryptedExtensions,
        Certificate,
        CertificateVerify,
        Finished,
    }
    let mut expect = Expect::EncryptedExtensions;
    let mut negotiated = Negotiated::default();
    let mut seen_ccs = false;
    let mut cert_requested = false;
    // REALITY: Some(ed25519 key) once the REALITY certificate checked out.
    let mut reality_key: Option<[u8; 32]> = None;
    let mut leaf: Option<CertificateDer<'static>> = None;
    loop {
        let Some(msg) = hs.next_message()? else {
            let rec = next_record(&mut io, &mut rb).await?;
            match rec.typ {
                // Middlebox-compatibility CCS: once, plaintext, before Finished.
                CT_CHANGE_CIPHER_SPEC if !seen_ccs && rb.body(&rec) == [1] => seen_ccs = true,
                CT_APPLICATION_DATA => {
                    let (ty, range) = rb.open(&mut s_key, &rec)?;
                    match ty {
                        CT_HANDSHAKE if !range.is_empty() => hs.push(rb.slice(range)),
                        CT_ALERT => return Err(alert_error(rb.slice(range))),
                        _ => return Err(invalid("unexpected record during TLS handshake")),
                    }
                }
                CT_ALERT => return Err(alert_error(rb.body(&rec))),
                _ => return Err(invalid("unexpected record during TLS handshake")),
            }
            continue;
        };
        let body = &msg[4..];
        match (&expect, msg[0]) {
            (Expect::EncryptedExtensions, HS_ENCRYPTED_EXTENSIONS) => {
                negotiated = parse_encrypted_extensions(body, &hello)?;
                expect = Expect::Certificate;
            }
            (Expect::Certificate, HS_CERTIFICATE_REQUEST) if !cert_requested => {
                // Like a browser without a client certificate: answer with an
                // empty Certificate. The request context must be empty here.
                if !Reader(body).vec8()?.is_empty() {
                    return Err(invalid("CertificateRequest with a context during the handshake"));
                }
                cert_requested = true;
            }
            (Expect::Certificate, HS_CERTIFICATE | HS_COMPRESSED_CERTIFICATE) => {
                match &auth {
                    Auth::Reality { .. } if msg[0] == HS_CERTIFICATE => {
                        let mut r = Reader(body);
                        let _context = r.vec8()?;
                        let mut list = Reader(r.vec24()?);
                        reality_key = reality_auth
                            .as_ref()
                            .and_then(|a| a.verify_certificate(list.vec24().ok()?));
                    }
                    // A real site behind the REALITY server (we were not
                    // authenticated) may compress its chain. It is not REALITY
                    // either way; keep the transcript going to finish the handshake.
                    Auth::Reality { .. } => {}
                    Auth::Verify { verifier, name, .. } => {
                        let decompressed;
                        let cert_body = if msg[0] == HS_COMPRESSED_CERTIFICATE {
                            decompressed = decompress_certificate(body, &hello)?;
                            &decompressed[..]
                        } else {
                            body
                        };
                        let (mut certs, ocsp) = parse_certificates(cert_body)?;
                        let end = certs.remove(0);
                        verifier
                            .verify_server_cert(&end, &certs, name, &ocsp, UnixTime::now())
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        leaf = Some(end);
                    }
                }
                expect = Expect::CertificateVerify;
            }
            (Expect::CertificateVerify, HS_CERTIFICATE_VERIFY) => {
                let hash = transcript.clone().finish();
                let mut signed = Vec::with_capacity(64 + 34 + hash.as_ref().len());
                signed.extend_from_slice(&[0x20; 64]);
                signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
                signed.extend_from_slice(hash.as_ref());
                match &auth {
                    Auth::Reality { .. } => {
                        if let Some(pk) = reality_key {
                            let mut r = Reader(body);
                            let scheme = r.u16()?;
                            let sig = r.vec16()?;
                            let ok = scheme == SCHEME_ED25519
                                && signature::UnparsedPublicKey::new(&signature::ED25519, &pk)
                                    .verify(&signed, sig)
                                    .is_ok();
                            if !ok {
                                // The certificate carried our HMAC but the transcript
                                // signature is wrong: tampering, not a fallback site.
                                return Err(invalid("REALITY CertificateVerify signature invalid"));
                            }
                        }
                    }
                    Auth::Verify { verifier, .. } => {
                        let dss = rustls::DigitallySignedStruct::read(&mut RustlsReader::init(body))
                            .map_err(|_| invalid("malformed CertificateVerify"))?;
                        let leaf = leaf
                            .as_ref()
                            .ok_or_else(|| invalid("CertificateVerify before Certificate"))?;
                        verifier
                            .verify_tls13_signature(&signed, leaf, &dss)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    }
                }
                expect = Expect::Finished;
            }
            (Expect::Finished, HS_FINISHED) => {
                let expected = finished_verify_data(suite, s_hs.as_ref(), transcript.clone().finish().as_ref());
                if constant_time::verify_slices_are_equal(expected.as_ref(), body).is_err() {
                    return Err(invalid("server Finished verify_data mismatch"));
                }
                transcript.update(&msg);
                break;
            }
            _ => return Err(invalid("unexpected TLS handshake message")),
        }
        transcript.update(&msg);
    }
    if !hs.is_empty() {
        return Err(invalid("handshake data after server Finished in the same record"));
    }

    // Application secrets cover the transcript up to the server Finished.
    let server_done = transcript.clone().finish();
    let master = schedule.into_master();
    let (c_ap, s_ap) = master.traffic_secrets(b"c ap traffic", b"s ap traffic", server_done.as_ref());
    // Chrome sends its compatibility CCS right before its second flight.
    if !sent_ccs {
        out.extend_from_slice(&CCS_RECORD);
    }
    if negotiated.alps {
        // ClientEncryptedExtensions with application_settings and no settings.
        let m = handshake_msg(HS_ENCRYPTED_EXTENSIONS, &[0, 4, 0x44, 0xcd, 0, 0]);
        transcript.update(&m);
        seal_record(&mut c_key, &mut out, CT_HANDSHAKE, &m);
    }
    if cert_requested {
        let m = handshake_msg(HS_CERTIFICATE, &[0, 0, 0, 0]);
        transcript.update(&m);
        seal_record(&mut c_key, &mut out, CT_HANDSHAKE, &m);
    }
    let fin = finished_verify_data(suite, c_hs.as_ref(), transcript.finish().as_ref());
    seal_record(
        &mut c_key,
        &mut out,
        CT_HANDSHAKE,
        &handshake_msg(HS_FINISHED, fin.as_ref()),
    );
    io.write_all(&out).await?;
    io.flush().await?;
    out.clear();

    if let Auth::Reality { skip_verify, .. } = auth
        && reality_key.is_none()
        && !skip_verify
    {
        // Like sing-box: a real certificate means the server did not accept
        // us (wrong key, short_id, time or SNI) and proxied a real site. The
        // handshake above completed like a browser's; send nothing else.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY verification failed: server presented a non-REALITY certificate",
        ));
    }
    // RFC 8449: the limit counts the inner content type byte.
    let max_fragment = negotiated
        .record_size_limit
        .map_or(MAX_PLAINTEXT, |l| (l as usize - 1).min(MAX_PLAINTEXT));
    Ok(TlsStream::new(
        io,
        rb,
        RecordKey::new(suite, s_ap),
        RecordKey::new(suite, c_ap),
        out,
        negotiated.alpn,
        group,
        max_fragment,
    ))
}
