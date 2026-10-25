//! VMess client, AEAD header only (`alter_id` 0), after sing-vmess.
//!
//! Body securities: `aes-128-gcm`, `chacha20-poly1305` (chunked, length
//! masked with SHAKE128, optional global padding or authenticated length),
//! and `none`/`zero` (raw stream for TCP, length-prefixed chunks for UDP).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{AES_128_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::digest;
use sbr_config::{PacketEncoding, VmessOutbound};
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Outbound, Stream};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::proto::{Framing, PacketHandle, StreamPacketConn, put_vmess_addr};
use super::vless::parse_uuid;
use super::{BuildContext, Upstream};
use crate::transport::ProxyDialer;

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const CMD_MUX: u8 = 3;

const SEC_AES128GCM: u8 = 3;
const SEC_CHACHA: u8 = 4;
const SEC_NONE: u8 = 5;

const OPT_CHUNK_STREAM: u8 = 1;
const OPT_CHUNK_MASKING: u8 = 4;
const OPT_GLOBAL_PADDING: u8 = 8;
const OPT_AUTH_LENGTH: u8 = 16;

const TAG: usize = 16;
/// sing-vmess `WriteChunkSize`; its reader rejects chunks over 16 KiB.
const MAX_CHUNK: usize = 15000;

pub struct Vmess {
    tag: String,
    cmd_key: [u8; 16],
    security: u8,
    global_padding: bool,
    auth_length: bool,
    xudp: bool,
    dialer: ProxyDialer,
    tcp: bool,
    udp: bool,
}

impl Vmess {
    pub fn new(tag: String, c: &VmessOutbound, upstream: Upstream, ctx: &BuildContext) -> Result<Self, String> {
        let dialer = ProxyDialer::new(&c.common, upstream, ctx.base_dir.as_deref())?;
        let security = match c.security.as_str() {
            // sing-box: `auto` over TLS is `zero`; otherwise AES-GCM where
            // the CPU has it (all of sbr's targets).
            "auto" if c.common.tls().is_some() => SEC_NONE,
            "auto" => SEC_AES128GCM,
            "aes-128-gcm" => SEC_AES128GCM,
            "chacha20-poly1305" => SEC_CHACHA,
            "none" | "zero" => SEC_NONE,
            other => return Err(format!("security: unsupported {other:?}")),
        };
        let xudp = match c.packet_encoding {
            PacketEncoding::Xudp => true,
            PacketEncoding::None => false,
            PacketEncoding::PacketAddr => return Err("packet_encoding: packetaddr is not supported by sbr yet".into()),
        };
        let uuid = parse_uuid(&c.uuid);
        let mut ctx = md5::Md5::default();
        md5::Digest::update(&mut ctx, uuid);
        md5::Digest::update(&mut ctx, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let cmd_key: [u8; 16] = md5::Digest::finalize(ctx).into();
        Ok(Self {
            tag,
            cmd_key,
            security,
            global_padding: c.global_padding,
            auth_length: c.authenticated_length,
            xudp,
            dialer,
            tcp: c.common.tcp(),
            udp: c.common.udp(),
        })
    }

    async fn open(&self, command: u8, dest: &Destination) -> io::Result<VmessStream<Stream>> {
        let s = self.dialer.connect().await?;
        Ok(VmessStream::new(s, self, command, dest))
    }
}

fn disabled(net: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("{net} is disabled by `network`"))
}

impl Outbound for Vmess {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "vmess"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if !self.tcp {
                return Err(disabled("tcp"));
            }
            Ok(Box::new(self.open(CMD_TCP, dest).await?) as Stream)
        })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            if !self.udp {
                return Err(disabled("udp"));
            }
            let conn = if self.xudp {
                StreamPacketConn::new(Box::new(self.open(CMD_MUX, dest).await?), Framing::Xudp, dest.clone())
            } else {
                // One VMess chunk per datagram, to the first destination only
                // (as sing-box's VMess packet conn does).
                StreamPacketConn::new(
                    Box::new(self.open(CMD_UDP, dest).await?),
                    Framing::Message,
                    dest.clone(),
                )
            };
            Ok(Box::new(PacketHandle(conn)) as BoxPacketConn)
        })
    }
}

// ---- crypto helpers -------------------------------------------------------

fn sha256(b: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, b).as_ref().try_into().unwrap()
}

/// HMAC over the hash at `level` of the chain (0 = SHA-256), block size 64.
fn nested(level: usize, keys: &[&[u8]], msg: &[&[u8]]) -> [u8; 32] {
    if level == 0 {
        let mut ctx = digest::Context::new(&digest::SHA256);
        for m in msg {
            ctx.update(m);
        }
        return ctx.finish().as_ref().try_into().unwrap();
    }
    let key = keys[level - 1];
    let hashed;
    let key = if key.len() > 64 {
        hashed = nested(level - 1, keys, &[key]);
        &hashed[..]
    } else {
        key
    };
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let mut inner_msg: Vec<&[u8]> = vec![&ipad];
    inner_msg.extend_from_slice(msg);
    let inner = nested(level - 1, keys, &inner_msg);
    nested(level - 1, keys, &[&opad, &inner])
}

/// sing-vmess `KDF`: HMAC-SHA256 keyed "VMess AEAD KDF", re-keyed by
/// nesting HMACs with `salt` and each `path` element.
fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = vec![b"VMess AEAD KDF", salt.as_bytes()];
    keys.extend_from_slice(path);
    nested(keys.len(), &keys, &[key])
}

fn md5(b: &[u8]) -> [u8; 16] {
    let mut ctx = md5::Md5::default();
    md5::Digest::update(&mut ctx, b);
    md5::Digest::finalize(ctx).into()
}

fn aead(security: u8, key16: &[u8]) -> LessSafeKey {
    let k = match security {
        SEC_CHACHA => {
            // sing-vmess `GenerateChacha20Poly1305Key`.
            let mut k = [0u8; 32];
            let a = md5(key16);
            k[..16].copy_from_slice(&a);
            k[16..].copy_from_slice(&md5(&a));
            UnboundKey::new(&CHACHA20_POLY1305, &k)
        }
        _ => UnboundKey::new(&AES_128_GCM, key16),
    };
    LessSafeKey::new(k.expect("valid key length"))
}

fn gcm(key16: &[u8]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key16).expect("16-byte key"))
}

fn seal(key: &LessSafeKey, nonce: [u8; 12], aad: &[u8], buf: &mut Vec<u8>, start: usize) {
    let mut tail = buf.split_off(start);
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut tail)
        .expect("seal");
    buf.extend_from_slice(&tail);
}

fn shake(seed: &[u8]) -> sha3::Shake128Reader {
    let mut h = sha3::Shake128::default();
    h.update(seed);
    h.finalize_xof()
}

fn next_u16(r: &mut sha3::Shake128Reader) -> u16 {
    let mut b = [0u8; 2];
    r.read(&mut b);
    u16::from_be_bytes(b)
}

fn fnv1a(b: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for x in b {
        h ^= *x as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    aws_lc_rs::rand::fill(&mut b).expect("system RNG");
    b
}

/// AEAD auth ID: AES-128-ECB(KDF(key), time ‖ random ‖ crc32).
fn auth_id(cmd_key: &[u8; 16], now: u64) -> [u8; 16] {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&now.to_be_bytes());
    b[8..12].copy_from_slice(&random::<4>());
    let crc = crc32fast::hash(&b[..12]);
    b[12..].copy_from_slice(&crc.to_be_bytes());
    let k = kdf(cmd_key, "AES Auth ID Encryption", &[]);
    let c = aes::Aes128::new_from_slice(&k[..16]).expect("16-byte key");
    let mut block = aes::Block::from(b);
    c.encrypt_block(&mut block);
    block.into()
}

/// Per-direction chunk codec state.
struct Codec {
    option: u8,
    body: Option<LessSafeKey>,
    nonce: [u8; 16],
    count: u16,
    mask: Option<sha3::Shake128Reader>,
    /// Authenticated length: key and its own counter (nonce base = request nonce).
    len_key: Option<(LessSafeKey, [u8; 16], u16)>,
}

impl Codec {
    fn new(
        security: u8,
        option: u8,
        key: &[u8; 16],
        nonce: &[u8; 16],
        req_key: &[u8; 16],
        req_nonce: &[u8; 16],
    ) -> Self {
        let chunked = option & OPT_CHUNK_STREAM != 0;
        let mask = (chunked && option & (OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING) != 0 && option & OPT_AUTH_LENGTH == 0
            || option & OPT_GLOBAL_PADDING != 0)
            .then(|| shake(nonce));
        let len_key = (option & OPT_AUTH_LENGTH != 0).then(|| {
            let k = kdf(req_key, "auth_len", &[]);
            (aead(security, &k[..16]), *req_nonce, 0u16)
        });
        Self {
            option,
            body: (security != SEC_NONE).then(|| aead(security, key)),
            nonce: *nonce,
            count: 0,
            mask,
            len_key,
        }
    }

    fn chunked(&self) -> bool {
        self.option & OPT_CHUNK_STREAM != 0
    }

    fn next_nonce(base: &[u8; 16], count: &mut u16) -> [u8; 12] {
        let mut n = [0u8; 12];
        n.copy_from_slice(&base[..12]);
        n[..2].copy_from_slice(&count.to_be_bytes());
        *count = count.wrapping_add(1);
        n
    }

    fn padding_len(&mut self) -> usize {
        match (&mut self.mask, self.option & OPT_GLOBAL_PADDING != 0) {
            (Some(m), true) => (next_u16(m) % 64) as usize,
            _ => 0,
        }
    }

    /// Append one encoded chunk carrying `data` to `out`.
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) {
        if !self.chunked() {
            out.extend_from_slice(data);
            return;
        }
        let tag = if self.body.is_some() { TAG } else { 0 };
        let padding = self.padding_len();
        let size = data.len() + tag + padding;
        if let Some((k, base, count)) = &mut self.len_key {
            let start = out.len();
            out.extend_from_slice(&((size - TAG) as u16).to_be_bytes());
            let n = Self::next_nonce(base, count);
            seal(k, n, &[], out, start);
        } else {
            let mut len = size as u16;
            if self.option & OPT_CHUNK_MASKING != 0
                && let Some(m) = &mut self.mask
            {
                len ^= next_u16(m);
            }
            out.extend_from_slice(&len.to_be_bytes());
        }
        let start = out.len();
        out.extend_from_slice(data);
        if let Some(k) = &self.body {
            let n = Self::next_nonce(&self.nonce, &mut self.count);
            seal(k, n, &[], out, start);
        }
        if padding > 0 {
            let at = out.len();
            out.resize(at + padding, 0);
            let _ = aws_lc_rs::rand::fill(&mut out[at..]);
        }
    }

    /// Bytes of the length field.
    fn len_size(&self) -> usize {
        if self.len_key.is_some() { 2 + TAG } else { 2 }
    }

    /// Decode a length field: (sealed size incl. tag, padding).
    fn decode_len(&mut self, b: &[u8]) -> io::Result<(usize, usize)> {
        let padding = self.padding_len();
        let size = if let Some((k, base, count)) = &mut self.len_key {
            let mut tmp = [0u8; 2 + TAG];
            tmp.copy_from_slice(&b[..2 + TAG]);
            let n = Self::next_nonce(base, count);
            let plain = k
                .open_in_place(Nonce::assume_unique_for_key(n), Aad::empty(), &mut tmp)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess: bad chunk length"))?;
            u16::from_be_bytes([plain[0], plain[1]]) as usize + TAG
        } else {
            let mut len = u16::from_be_bytes([b[0], b[1]]);
            if self.option & OPT_CHUNK_MASKING != 0
                && let Some(m) = &mut self.mask
            {
                len ^= next_u16(m);
            }
            len as usize
        };
        if size < padding {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "vmess: bad chunk length"));
        }
        Ok((size - padding, padding))
    }

    /// Open a chunk in place; returns the plaintext length.
    fn open(&mut self, chunk: &mut [u8]) -> io::Result<usize> {
        match &self.body {
            None => Ok(chunk.len()),
            Some(k) => {
                let n = Self::next_nonce(&self.nonce, &mut self.count);
                k.open_in_place(Nonce::assume_unique_for_key(n), Aad::empty(), chunk)
                    .map(|p| p.len())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess: chunk authentication failed"))
            }
        }
    }
}

enum ReadState {
    /// Response header: waiting for its encrypted length.
    RespLen,
    RespBody(usize),
    /// Chunk length field.
    Len,
    /// Chunk body (sealed size) and padding to skip after it.
    Body(usize, usize),
    /// Plaintext ready at `rbuf[start..end]`.
    Plain(usize, usize),
    /// `none` over TCP: raw bytes.
    Raw,
    Eof,
}

pub struct VmessStream<S> {
    inner: S,
    wcodec: Codec,
    rcodec: Codec,
    header: Option<Vec<u8>>,
    wbuf: Vec<u8>,
    wpos: usize,
    /// The reader sent the request (client silent so far): it flushes.
    read_flushes: bool,
    resp_key: [u8; 16],
    resp_nonce: [u8; 16],
    rstate: ReadState,
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    /// Max plaintext per chunk.
    chunk: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> VmessStream<S> {
    fn new(inner: S, v: &Vmess, command: u8, dest: &Destination) -> Self {
        let req_key: [u8; 16] = random();
        let req_nonce: [u8; 16] = random();
        let security = v.security;
        let mut option = match security {
            SEC_NONE if command == CMD_UDP => OPT_CHUNK_STREAM,
            SEC_NONE => 0,
            _ => {
                let mut o = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING;
                if v.global_padding {
                    o |= OPT_GLOBAL_PADDING;
                }
                if v.auth_length {
                    o |= OPT_AUTH_LENGTH;
                }
                o
            }
        };
        if security == SEC_NONE {
            option &= OPT_CHUNK_STREAM;
        }
        let resp_header: u8 = random::<1>()[0];

        // Request header (plaintext), then its AEAD envelope.
        let padding = (crate::tls::rand_u32() % 16) as usize;
        let mut h = Vec::with_capacity(64 + 260);
        h.push(1);
        h.extend_from_slice(&req_nonce);
        h.extend_from_slice(&req_key);
        h.push(resp_header);
        h.push(option);
        h.push((padding as u8) << 4 | security);
        h.push(0);
        h.push(command);
        if command != CMD_MUX {
            put_vmess_addr(&mut h, dest);
        }
        h.extend_from_slice(&random::<16>()[..padding]);
        let fnv = fnv1a(&h);
        h.extend_from_slice(&fnv.to_be_bytes());

        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let aid = auth_id(&v.cmd_key, now);
        let conn_nonce: [u8; 8] = random();
        let path: [&[u8]; 2] = [&aid, &conn_nonce];
        let len_key = kdf(&v.cmd_key, "VMess Header AEAD Key_Length", &path);
        let len_iv = kdf(&v.cmd_key, "VMess Header AEAD Nonce_Length", &path);
        let hdr_key = kdf(&v.cmd_key, "VMess Header AEAD Key", &path);
        let hdr_iv = kdf(&v.cmd_key, "VMess Header AEAD Nonce", &path);
        let mut wire = Vec::with_capacity(16 + 18 + 8 + h.len() + TAG + MAX_CHUNK + 64);
        wire.extend_from_slice(&aid);
        let start = wire.len();
        wire.extend_from_slice(&(h.len() as u16).to_be_bytes());
        seal(
            &gcm(&len_key[..16]),
            len_iv[..12].try_into().unwrap(),
            &aid,
            &mut wire,
            start,
        );
        wire.extend_from_slice(&conn_nonce);
        let start = wire.len();
        wire.extend_from_slice(&h);
        seal(
            &gcm(&hdr_key[..16]),
            hdr_iv[..12].try_into().unwrap(),
            &aid,
            &mut wire,
            start,
        );

        let resp_key: [u8; 16] = sha256(&req_key)[..16].try_into().unwrap();
        let resp_nonce: [u8; 16] = sha256(&req_nonce)[..16].try_into().unwrap();
        let rcodec = Codec::new(security, option, &resp_key, &resp_nonce, &req_key, &req_nonce);
        Self {
            inner,
            wcodec: Codec::new(security, option, &req_key, &req_nonce, &req_key, &req_nonce),
            rstate: ReadState::RespLen,
            rcodec,
            header: Some(wire),
            wbuf: Vec::new(),
            wpos: 0,
            resp_key,
            read_flushes: false,
            resp_nonce,
            rbuf: vec![0; 32 * 1024],
            rpos: 0,
            rend: 0,
            chunk: if command == CMD_UDP {
                u16::MAX as usize - TAG - 64
            } else {
                MAX_CHUNK
            },
        }
    }

    fn poll_flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }

    /// Ensure `n` buffered bytes; `Ok(false)` on EOF before any of them.
    fn poll_fill(&mut self, cx: &mut Context<'_>, n: usize) -> Poll<io::Result<bool>> {
        while self.rend - self.rpos < n {
            if self.rpos > 0 {
                self.rbuf.copy_within(self.rpos..self.rend, 0);
                self.rend -= self.rpos;
                self.rpos = 0;
            }
            if self.rbuf.len() < n {
                self.rbuf.resize(n, 0);
            }
            let mut rb = ReadBuf::new(&mut self.rbuf[self.rend..]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let got = rb.filled().len();
            if got == 0 {
                if self.rend == self.rpos {
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.rend += got;
        }
        Poll::Ready(Ok(true))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(h) = this.header.take() {
            // Nothing written yet but the caller reads: send the header alone.
            this.wbuf = h;
            this.wpos = 0;
            this.read_flushes = true;
        }
        if this.read_flushes && this.wpos < this.wbuf.len() {
            // Push the request out, but don't wait on writability here: the
            // write side may live in another task (split streams), and a
            // socket keeps one write wakeup, so only one side may wait on it.
            // Once the writer has written, flushing is its job.
            if let Poll::Ready(r) = this.poll_flush_wbuf(cx) {
                r?;
                if let Poll::Ready(Err(e)) = Pin::new(&mut this.inner).poll_flush(cx) {
                    return Poll::Ready(Err(e));
                }
            }
        }
        loop {
            match this.rstate {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::RespLen => {
                    if !ready!(this.poll_fill(cx, 2 + TAG))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let k = kdf(&this.resp_key, "AEAD Resp Header Len Key", &[]);
                    let iv = kdf(&this.resp_nonce, "AEAD Resp Header Len IV", &[]);
                    let b = &mut this.rbuf[this.rpos..this.rpos + 2 + TAG];
                    let p = gcm(&k[..16])
                        .open_in_place(
                            Nonce::assume_unique_for_key(iv[..12].try_into().unwrap()),
                            Aad::empty(),
                            b,
                        )
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess: bad response header"))?;
                    let len = u16::from_be_bytes([p[0], p[1]]) as usize;
                    this.rpos += 2 + TAG;
                    this.rstate = ReadState::RespBody(len);
                }
                ReadState::RespBody(len) => {
                    if !ready!(this.poll_fill(cx, len + TAG))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let k = kdf(&this.resp_key, "AEAD Resp Header Key", &[]);
                    let iv = kdf(&this.resp_nonce, "AEAD Resp Header IV", &[]);
                    let b = &mut this.rbuf[this.rpos..this.rpos + len + TAG];
                    gcm(&k[..16])
                        .open_in_place(
                            Nonce::assume_unique_for_key(iv[..12].try_into().unwrap()),
                            Aad::empty(),
                            b,
                        )
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess: bad response header"))?;
                    this.rpos += len + TAG;
                    this.rstate = if this.rcodec.chunked() {
                        ReadState::Len
                    } else {
                        ReadState::Raw
                    };
                }
                ReadState::Raw => {
                    if this.rpos < this.rend {
                        let n = (this.rend - this.rpos).min(out.remaining());
                        out.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
                        this.rpos += n;
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.inner).poll_read(cx, out);
                }
                ReadState::Len => {
                    let ls = this.rcodec.len_size();
                    if !ready!(this.poll_fill(cx, ls))? {
                        this.rstate = ReadState::Eof;
                        continue;
                    }
                    let (size, padding) = this.rcodec.decode_len(&this.rbuf[this.rpos..this.rpos + ls])?;
                    this.rpos += ls;
                    if size == 0 {
                        this.rstate = ReadState::Eof;
                        continue;
                    }
                    this.rstate = ReadState::Body(size, padding);
                }
                ReadState::Body(size, padding) => {
                    if !ready!(this.poll_fill(cx, size + padding))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let start = this.rpos;
                    let n = this.rcodec.open(&mut this.rbuf[start..start + size])?;
                    this.rpos += size + padding;
                    if n == 0 {
                        // An empty AEAD chunk marks the end of the stream.
                        this.rstate = ReadState::Eof;
                        continue;
                    }
                    this.rstate = ReadState::Plain(start, start + n);
                }
                ReadState::Plain(s, e) => {
                    let n = (e - s).min(out.remaining());
                    out.put_slice(&this.rbuf[s..s + n]);
                    this.rstate = if s + n == e {
                        ReadState::Len
                    } else {
                        ReadState::Plain(s + n, e)
                    };
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.read_flushes = false;
        ready!(this.poll_flush_wbuf(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(h) = this.header.take() {
            this.wbuf = h;
        }
        if !this.wcodec.chunked() {
            if this.wbuf.is_empty() {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            this.wbuf.extend_from_slice(buf);
            if let Poll::Ready(Err(e)) = this.poll_flush_wbuf(cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        // Encode up to ~64 KiB of chunks per call into the reused buffer.
        let mut taken = 0;
        while taken < buf.len() && taken < 64 * 1024 {
            let n = (buf.len() - taken).min(this.chunk);
            this.wcodec.encode(&buf[taken..taken + n], &mut this.wbuf);
            taken += n;
        }
        if let Poll::Ready(Err(e)) = this.poll_flush_wbuf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(taken))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_wbuf(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(h) = this.header.take() {
            this.wbuf = h;
        }
        ready!(this.poll_flush_wbuf(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC-SHA256 at level 1 must match a direct HMAC.
    #[test]
    fn kdf_level_one_is_hmac() {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, b"VMess AEAD KDF");
        let want = aws_lc_rs::hmac::sign(&key, b"payload");
        assert_eq!(nested(1, &[b"VMess AEAD KDF"], &[b"payload"]), want.as_ref());
    }

    #[test]
    fn fnv() {
        assert_eq!(fnv1a(b""), 0x811c9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c292c);
    }
}
