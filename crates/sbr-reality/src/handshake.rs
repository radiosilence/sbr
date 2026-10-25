//! The TLS 1.3 client handshake (RFC 8446 §2, 1-RTT, no PSK, no HRR) with the
//! REALITY session_id and certificate check spliced in.

use std::future::poll_fn;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::{agreement, constant_time, digest, kem, signature};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::RealityConfig;
use crate::hello::{
    self, GROUP_P256, GROUP_X25519, GROUP_X25519_MLKEM768, HelloParams, KeyShares, MLKEM768_CIPHERTEXT_LEN,
    SESSION_ID_OFFSET,
};
use crate::keys::{CipherSuite, KeySchedule, RecordKey, finished_verify_data};
use crate::reality::AuthKey;
use crate::record::{
    CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, HandshakeBuf, RawRecord, ReadBuf, alert_error,
    invalid, seal_record,
};
use crate::stream::RealityStream;

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
    0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_REQUEST: u8 = 13;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_COMPRESSED_CERTIFICATE: u8 = 25;

const SCHEME_ED25519: u16 = 0x0807;

#[derive(Clone, Copy, Default)]
pub(crate) struct Options {
    /// Tests only: run the TLS handshake against an ordinary server.
    pub(crate) skip_reality_verify: bool,
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
    key_share: Option<(u16, &'a [u8])>,
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
    let mut sh = ServerHello {
        random,
        session_id,
        suite,
        version: None,
        key_share: None,
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
            0x0033 => {
                let group = data.u16()?;
                sh.key_share = Some((group, data.vec16()?));
            }
            _ => {}
        }
    }
    Ok(sh)
}

fn shared_secret(keys: &KeyShares, group: u16, peer: &[u8]) -> io::Result<Vec<u8>> {
    let bad = || invalid("invalid server key share");
    let ecdh = |key: &agreement::PrivateKey, alg: &'static agreement::Algorithm, peer: &[u8]| {
        agreement::agree(key, agreement::UnparsedPublicKey::new(alg, peer), bad(), |s| {
            Ok(s.to_vec())
        })
    };
    match group {
        GROUP_X25519 => ecdh(&keys.x25519, &agreement::X25519, peer),
        GROUP_X25519_MLKEM768 => {
            let (dk, xk) = keys
                .mlkem
                .as_ref()
                .ok_or_else(|| invalid("server chose a group we did not offer"))?;
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
        GROUP_P256 => {
            let k = keys
                .p256
                .as_ref()
                .ok_or_else(|| invalid("server chose a group we did not offer"))?;
            ecdh(k, &agreement::ECDH_P256, peer)
        }
        _ => Err(invalid("server chose a group we did not offer")),
    }
}

fn parse_alpn(ee_body: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut r = Reader(ee_body);
    let mut exts = Reader(r.vec16()?);
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let data = exts.vec16()?;
        if ty == 0x0010 {
            let mut list = Reader(Reader(data).vec16()?);
            return Ok(Some(list.vec8()?.to_vec()));
        }
    }
    Ok(None)
}

fn leaf_certificate(body: &[u8]) -> io::Result<&[u8]> {
    let mut r = Reader(body);
    let _context = r.vec8()?;
    let mut list = Reader(r.vec24()?);
    list.vec24()
}

fn handshake_msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(ty);
    m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    m.extend_from_slice(body);
    m
}

pub(crate) async fn handshake<S>(mut io: S, cfg: &RealityConfig, opts: Options) -> io::Result<RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ch = hello::build(&HelloParams {
        fingerprint: cfg.fingerprint,
        server_name: &cfg.server_name,
        alpn: &cfg.alpn,
        post_quantum: cfg.post_quantum,
    })?;
    let auth = AuthKey::derive(&ch.keys.x25519, &cfg.public_key, &ch.random)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    auth.seal_session_id(&mut ch.msg, &ch.random, &cfg.short_id, now);

    // Browsers put 0x0301 on the ClientHello record.
    let mut out = Vec::with_capacity(crate::record::MAX_WRITE_RECORD);
    out.extend_from_slice(&[CT_HANDSHAKE, 3, 1]);
    out.extend_from_slice(&(ch.msg.len() as u16).to_be_bytes());
    out.extend_from_slice(&ch.msg);
    io.write_all(&out).await?;
    io.flush().await?;
    out.clear();

    let mut rb = ReadBuf::new();
    let mut hs = HandshakeBuf::default();

    // ServerHello, in plaintext records.
    let sh_msg = loop {
        if let Some(m) = hs.next_message()? {
            break m;
        }
        let rec = next_record(&mut io, &mut rb).await?;
        match rec.typ {
            CT_HANDSHAKE => hs.push(rb.body(&rec)),
            CT_ALERT => return Err(alert_error(rb.body(&rec))),
            _ => return Err(invalid("expected ServerHello")),
        }
    };
    if sh_msg[0] != 2 {
        return Err(invalid("expected ServerHello"));
    }
    let sh = parse_server_hello(&sh_msg[4..])?;
    if sh.random == HRR_RANDOM {
        // A REALITY server never asks for a retry: every profile offers X25519.
        return Err(invalid("server sent HelloRetryRequest; not a REALITY server"));
    }
    if sh.version != Some(0x0304) {
        return Err(invalid("server did not negotiate TLS 1.3"));
    }
    if sh.session_id != &ch.msg[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32] {
        return Err(invalid("ServerHello session_id mismatch"));
    }
    let suite = CipherSuite::from_id(sh.suite).ok_or_else(|| invalid("server chose an unsupported cipher suite"))?;
    let (group, peer_share) = sh.key_share.ok_or_else(|| invalid("ServerHello without key_share"))?;
    let shared = shared_secret(&ch.keys, group, peer_share)?;
    drop(ch.keys);
    if !hs.is_empty() {
        return Err(invalid("handshake data after ServerHello in the same record"));
    }

    let mut transcript = digest::Context::new(suite.hash());
    transcript.update(&ch.msg);
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
    let mut alpn = None;
    let mut seen_ccs = false;
    // Some(ed25519 key) once the REALITY certificate checked out.
    let mut reality_key: Option<[u8; 32]> = None;
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
                alpn = parse_alpn(body)?;
                expect = Expect::Certificate;
            }
            (Expect::Certificate, HS_CERTIFICATE) => {
                let leaf = leaf_certificate(body)?;
                reality_key = auth.verify_certificate(leaf);
                expect = Expect::CertificateVerify;
            }
            // A real site behind the REALITY server (we were not
            // authenticated) may compress its chain. It is not REALITY either
            // way; keep the transcript going to finish the handshake.
            (Expect::Certificate, HS_COMPRESSED_CERTIFICATE) => expect = Expect::CertificateVerify,
            (Expect::Certificate, HS_CERTIFICATE_REQUEST) => {
                return Err(invalid("server requested a client certificate"));
            }
            (Expect::CertificateVerify, HS_CERTIFICATE_VERIFY) => {
                if let Some(pk) = reality_key {
                    let mut r = Reader(body);
                    let scheme = r.u16()?;
                    let sig = r.vec16()?;
                    let hash = transcript.clone().finish();
                    let mut signed = Vec::with_capacity(64 + 34 + hash.as_ref().len());
                    signed.extend_from_slice(&[0x20; 64]);
                    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
                    signed.extend_from_slice(hash.as_ref());
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

    let hash = transcript.finish();
    let master = schedule.into_master();
    let (c_ap, s_ap) = master.traffic_secrets(b"c ap traffic", b"s ap traffic", hash.as_ref());
    let fin = finished_verify_data(suite, c_hs.as_ref(), hash.as_ref());
    // Chrome sends its compatibility CCS right before Finished.
    out.extend_from_slice(&[CT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]);
    seal_record(
        &mut c_key,
        &mut out,
        CT_HANDSHAKE,
        &handshake_msg(HS_FINISHED, fin.as_ref()),
    );
    io.write_all(&out).await?;
    io.flush().await?;
    out.clear();

    if reality_key.is_none() && !opts.skip_reality_verify {
        // Like sing-box: a real certificate means the server did not accept
        // us (wrong key, short_id, time or SNI) and proxied a real site. The
        // handshake above completed like a browser's; send nothing else.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY verification failed: server presented a non-REALITY certificate",
        ));
    }
    Ok(RealityStream::new(
        io,
        rb,
        RecordKey::new(suite, s_ap),
        RecordKey::new(suite, c_ap),
        out,
        alpn,
        group,
    ))
}
