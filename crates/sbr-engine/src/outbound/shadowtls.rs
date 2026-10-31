//! ShadowTLS client, protocol versions 1, 2 and 3 (sing-shadowtls).
//!
//! The ShadowTLS server relays a genuine TLS handshake between us and a
//! camouflage server, then switches to proxying. The outbound ignores the
//! requested destination: it is a transport for the protocol layered on
//! top (`detour`), usually shadowsocks.
//!
//! - v1: real handshake, then the raw stream.
//! - v2: the client HMACs everything the server sent during the handshake
//!   and prefixes its first write with the tag; data travels in TLS
//!   application-data records.
//! - v3: the ClientHello session id carries an HMAC of the ClientHello; the
//!   server tags and XOR-masks its handshake records so we can tell it apart
//!   from a hijacker; data records carry a chained 4-byte HMAC.
//!
//! The camouflage handshake is a browser's (`sbr-reality`) unless the `tls`
//! options pick rustls (see `tlsmini`); a censor sees a browser talking to
//! the camouflage site. Either way the handshake reads exactly one record
//! at a time ([`Tap`]), so no byte that belongs to the post-handshake
//! protocol is consumed by the TLS client.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use aws_lc_rs::{constant_time, digest, hmac};
use rustls::ClientConnection;
use sbr_config::ShadowTlsOutbound;
use sbr_core::{BoxFuture, Destination, Outbound, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::Upstream;
use super::tlsmini::{Scripted, TlsClient, tls_err, with_script};
use crate::transport::Prefixed;

const HEADER: usize = 5;
const HMAC_LEN: usize = 4;
const MAX_PLAINTEXT: usize = 16384;
const APPLICATION_DATA: u8 = 23;
const HANDSHAKE: u8 = 22;
const ALERT: u8 = 21;
const SERVER_HELLO: u8 = 2;
/// Offsets inside a record (header included).
const SERVER_RANDOM: usize = HEADER + 1 + 3 + 2;
const SESSION_ID_LEN: usize = SERVER_RANDOM + 32;

pub struct ShadowTls {
    tag: String,
    server: Destination,
    version: u8,
    password: String,
    tls: TlsClient,
    upstream: Upstream,
}

impl ShadowTls {
    pub fn new(tag: String, c: &ShadowTlsOutbound, upstream: Upstream) -> Result<Self, String> {
        let tls = TlsClient::new(&c.tls, &c.server.server)?;
        // The server reads the ClientHello as one record and checks its HMAC.
        if tls.fragment.is_some() {
            return Err("tls.fragment: not supported by sbr's shadowtls".into());
        }
        if c.version == 3 && !tls.supports_tls13() {
            return Err("shadowtls v3 needs TLS 1.3 enabled".into());
        }
        Ok(Self {
            tag,
            server: Destination::from_host_port(&c.server.server, c.server.server_port),
            version: c.version,
            password: c.password.clone(),
            tls,
            upstream,
        })
    }

    fn key(&self) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, self.password.as_bytes())
    }

    /// A ClientConnection whose ClientHello session id is
    /// `random[28] || HMAC(password, ClientHello with those 4 bytes zeroed)[..4]`.
    ///
    /// rustls has no hook for the session id, so the ClientHello is built
    /// twice from the same scripted randomness and key share: once to learn
    /// its bytes, once with the session id fill replaced by ours. Returns the
    /// connection and the ClientHello record to send.
    fn v3_client(&self) -> io::Result<(ClientConnection, Vec<u8>)> {
        let cfg = self.tls.scripted_config().map_err(io::Error::other)?;
        let mut secret = [0u8; 32];
        fill_random(&mut secret);
        let script = Scripted {
            recorded: Some(Vec::new()),
            replay: None,
            x25519_secret: Some(secret),
        };
        let name = self.tls.server_name.clone();
        let (c1, script) = with_script(script, || ClientConnection::new(cfg.clone(), name.clone()));
        let mut hello = Vec::new();
        c1.map_err(tls_err)?.write_tls(&mut hello)?;
        if hello.len() < SESSION_ID_LEN + 33
            || hello[0] != HANDSHAKE
            || hello[HEADER] != 1
            || hello[SESSION_ID_LEN] != 32
        {
            return Err(io::Error::other("shadowtls: unexpected ClientHello layout"));
        }
        let sid_at = SESSION_ID_LEN + 1;
        let old: Vec<u8> = hello[sid_at..sid_at + 32].to_vec();
        let mut sid = [0u8; 32];
        fill_random(&mut sid[..28]);
        let mut h = hmac::Context::with_key(&self.key());
        h.update(&hello[HEADER..sid_at]);
        h.update(&sid);
        h.update(&hello[sid_at + 32..]);
        sid[28..].copy_from_slice(&h.sign().as_ref()[..HMAC_LEN]);

        let mut fills = script.recorded.unwrap_or_default();
        let at = fills
            .iter()
            .position(|f| *f == old)
            .ok_or_else(|| io::Error::other("shadowtls: session id not found in ClientHello randomness"))?;
        fills[at] = sid.to_vec();
        let script = Scripted {
            recorded: None,
            replay: Some(fills.into()),
            x25519_secret: Some(secret),
        };
        let (c2, _) = with_script(script, || ClientConnection::new(cfg, name));
        let mut c2 = c2.map_err(tls_err)?;
        let mut hello2 = Vec::new();
        c2.write_tls(&mut hello2)?;
        hello[sid_at..sid_at + 32].copy_from_slice(&sid);
        if hello2 != hello {
            return Err(io::Error::other("shadowtls: could not reproduce the ClientHello"));
        }
        Ok((c2, hello2))
    }
}

impl ShadowTls {
    async fn connect_browser(&self, cfg: &sbr_reality::TlsConfig, s: Stream) -> io::Result<Stream> {
        match self.version {
            1 => browser_handshake(cfg, s, None, |_| Ok(())).await,
            2 => {
                let mut h = hmac::Context::with_key(&self.key());
                let s = browser_handshake(cfg, s, None, |rec: &mut Vec<u8>| {
                    h.update(rec);
                    Ok(())
                })
                .await?;
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&h.sign().as_ref()[..8]);
                Ok(Box::new(Framed::new(s, Mode::V2 { prefix: Some(prefix) })) as Stream)
            }
            _ => {
                let mut st = V3Handshake {
                    key: self.key(),
                    password: self.password.as_bytes().to_vec(),
                    server_random: None,
                    read_hmac: None,
                    mask: Vec::new(),
                    tls13: false,
                    authorized: false,
                };
                let key = self.key();
                let sid = move |hello: &mut [u8]| v3_session_id(&key, hello);
                let s = browser_handshake(cfg, s, Some(&sid), |rec: &mut Vec<u8>| st.on_record(rec)).await?;
                self.v3_framed(s, st)
            }
        }
    }

    fn v3_framed(&self, s: Stream, st: V3Handshake) -> io::Result<Stream> {
        let (Some(random), true) = (st.server_random, st.authorized) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "shadowtls: traffic hijacked",
            ));
        };
        let tagged = |suffix: &[u8]| {
            let mut h = hmac::Context::with_key(&self.key());
            h.update(&random);
            h.update(suffix);
            h
        };
        Ok(Box::new(Framed::new(
            s,
            Mode::V3 {
                add: tagged(b"C"),
                verify: tagged(b"S"),
                ignore: st.read_hmac,
            },
        )) as Stream)
    }
}

fn fill_random(buf: &mut [u8]) {
    use aws_lc_rs::rand::SecureRandom;
    aws_lc_rs::rand::SystemRandom::new().fill(buf).expect("system RNG");
}

/// Drive the handshake one record at a time. `first` is already-encoded
/// output to send before anything else.
async fn handshake(
    conn: &mut ClientConnection,
    s: &mut Stream,
    first: Vec<u8>,
    mut on_record: impl FnMut(&mut Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    let mut out = first;
    loop {
        while conn.wants_write() {
            conn.write_tls(&mut out)?;
        }
        if !out.is_empty() {
            s.write_all(&out).await?;
            s.flush().await?;
            out.clear();
        }
        if !conn.is_handshaking() {
            return Ok(());
        }
        let mut rec = vec![0u8; HEADER];
        s.read_exact(&mut rec).await?;
        let len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        rec.resize(HEADER + len, 0);
        s.read_exact(&mut rec[HEADER..]).await?;
        on_record(&mut rec)?;
        let mut rd = &rec[..];
        while !rd.is_empty() {
            conn.read_tls(&mut rd)?;
            conn.process_new_packets().map_err(tls_err)?;
        }
    }
}

/// Go's `isServerHelloSupportTLS13`: a supported_versions extension = 0x0304.
fn server_hello_is_tls13(rec: &[u8]) -> bool {
    let Some(rest) = rec.get(SESSION_ID_LEN..) else {
        return false;
    };
    let Some((&sid_len, rest)) = rest.split_first() else {
        return false;
    };
    // session id, cipher suite (2), compression (1), extensions length (2)
    let Some(mut ext) = rest.get(sid_len as usize + 3 + 2..) else {
        return false;
    };
    while ext.len() >= 4 {
        let ty = u16::from_be_bytes([ext[0], ext[1]]);
        let len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        let Some(body) = ext.get(4..4 + len) else { return false };
        if ty == 43 {
            return len == 2 && body == [3, 4];
        }
        ext = &ext[4 + len..];
    }
    false
}

/// `streamWrapper` from sing-shadowtls: recognise the ShadowTLS server's
/// tagging of handshake records and undo it.
struct V3Handshake {
    key: hmac::Key,
    password: Vec<u8>,
    server_random: Option<[u8; 32]>,
    read_hmac: Option<hmac::Context>,
    mask: Vec<u8>,
    tls13: bool,
    authorized: bool,
}

impl V3Handshake {
    fn on_record(&mut self, rec: &mut Vec<u8>) -> io::Result<()> {
        match rec[0] {
            HANDSHAKE => {
                // Seed once, on the first ServerHello (HelloRetryRequest-safe).
                if rec.len() > SERVER_RANDOM + 32 && rec[HEADER] == SERVER_HELLO && self.read_hmac.is_none() {
                    let mut random = [0u8; 32];
                    random.copy_from_slice(&rec[SERVER_RANDOM..SERVER_RANDOM + 32]);
                    let mut h = hmac::Context::with_key(&self.key);
                    h.update(&random);
                    self.read_hmac = Some(h);
                    let mut d = digest::Context::new(&digest::SHA256);
                    d.update(&self.password);
                    d.update(&random);
                    self.mask = d.finish().as_ref().to_vec();
                    self.server_random = Some(random);
                    // Strict mode: sing-shadowtls authorizes a TLS 1.2
                    // ServerHello without proof, which would let a hijacker
                    // relaying to any TLS 1.2 server see the tunnel start. sbr
                    // offers TLS 1.3 for v3, so a real server answers with it.
                    self.tls13 = server_hello_is_tls13(rec);
                }
            }
            APPLICATION_DATA => {
                self.authorized = false;
                if rec.len() > HEADER + HMAC_LEN
                    && let Some(h) = self.read_hmac.as_mut()
                {
                    h.update(&rec[HEADER + HMAC_LEN..]);
                    if constant_time::verify_slices_are_equal(
                        &h.clone().sign().as_ref()[..HMAC_LEN],
                        &rec[HEADER..HEADER + HMAC_LEN],
                    )
                    .is_err()
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "shadow-tls v3: hmac mismatch, possible data corruption",
                        ));
                    }
                    for (i, b) in rec[HEADER + HMAC_LEN..].iter_mut().enumerate() {
                        *b ^= self.mask[i % self.mask.len()];
                    }
                    rec.drain(HEADER..HEADER + HMAC_LEN);
                    let len = (rec.len() - HEADER) as u16;
                    rec[3..5].copy_from_slice(&len.to_be_bytes());
                    self.authorized = self.tls13;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Hands the TLS client one whole server record at a time, after `on_record`
/// has seen (and possibly rewritten) it. Reads from `inner` exactly the
/// bytes of the current record, so nothing past the handshake is consumed.
struct Tap<'a, F> {
    inner: &'a mut Stream,
    rec: Vec<u8>,
    /// Bytes of `rec` filled from `inner`; `rec` is complete when it holds
    /// a header and the body that header announces.
    filled: usize,
    /// Read position once the record is complete and processed.
    pos: Option<usize>,
    on_record: F,
}

impl<'a, F: FnMut(&mut Vec<u8>) -> io::Result<()>> Tap<'a, F> {
    fn new(inner: &'a mut Stream, on_record: F) -> Self {
        Self {
            inner,
            rec: vec![0; HEADER],
            filled: 0,
            pos: None,
            on_record,
        }
    }
}

impl<F: FnMut(&mut Vec<u8>) -> io::Result<()> + Unpin> AsyncRead for Tap<'_, F> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(pos) = this.pos {
                if pos < this.rec.len() {
                    let n = (this.rec.len() - pos).min(buf.remaining());
                    buf.put_slice(&this.rec[pos..pos + n]);
                    this.pos = Some(pos + n);
                    return Poll::Ready(Ok(()));
                }
                this.rec.clear();
                this.rec.resize(HEADER, 0);
                this.filled = 0;
                this.pos = None;
            }
            let mut rb = ReadBuf::new(&mut this.rec[this.filled..]);
            ready!(Pin::new(&mut *this.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                // EOF: clean only between records.
                return if this.filled == 0 {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            this.filled += n;
            if this.filled == HEADER && this.rec.len() == HEADER {
                let len = u16::from_be_bytes([this.rec[3], this.rec[4]]) as usize;
                this.rec.resize(HEADER + len, 0);
            }
            if this.filled == this.rec.len() && this.rec.len() > HEADER {
                (this.on_record)(&mut this.rec)?;
                this.pos = Some(0);
            }
        }
    }
}

impl<F: Unpin> AsyncWrite for Tap<'_, F> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The camouflage handshake with a browser ClientHello. Returns the stream
/// with any bytes the TLS client read past the handshake put back in front.
async fn browser_handshake(
    cfg: &sbr_reality::TlsConfig,
    mut s: Stream,
    session_id: Option<&sbr_reality::SessionIdFn>,
    on_record: impl FnMut(&mut Vec<u8>) -> io::Result<()> + Unpin + Send,
) -> io::Result<Stream> {
    let rest = {
        let tap = Tap::new(&mut s, on_record);
        let mut tls = sbr_reality::connect_tls_with_session_id(tap, cfg, session_id).await?;
        let mut rest = tls.take_buffered();
        let tap = tls.get_mut();
        if let Some(pos) = tap.pos {
            rest.extend_from_slice(&tap.rec[pos..]);
        }
        rest
    };
    Ok(if rest.is_empty() {
        s
    } else {
        Box::new(Prefixed::new(rest, s))
    })
}

/// ShadowTLS v3 session id: `random[28] || HMAC(password, ClientHello with
/// those 4 bytes zeroed)[..4]`, written into `hello` (session id at byte 39).
fn v3_session_id(key: &hmac::Key, hello: &mut [u8]) {
    const SID: usize = 39;
    fill_random(&mut hello[SID..SID + 28]);
    let tag = hmac::sign(key, hello);
    hello[SID + 28..SID + 32].copy_from_slice(&tag.as_ref()[..HMAC_LEN]);
}

impl Outbound for ShadowTls {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "shadowtls"
    }

    fn connect<'a>(&'a self, _dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            let mut s = self.upstream.connect(&self.server).await?;
            if let Some(cfg) = &self.tls.browser {
                return self.connect_browser(cfg, s).await;
            }
            match self.version {
                1 => {
                    let mut c =
                        ClientConnection::new(self.tls.config(), self.tls.server_name.clone()).map_err(tls_err)?;
                    handshake(&mut c, &mut s, Vec::new(), |_| Ok(())).await?;
                    Ok(s)
                }
                2 => {
                    let mut c =
                        ClientConnection::new(self.tls.config(), self.tls.server_name.clone()).map_err(tls_err)?;
                    let mut h = hmac::Context::with_key(&self.key());
                    handshake(&mut c, &mut s, Vec::new(), |rec| {
                        h.update(rec);
                        Ok(())
                    })
                    .await?;
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&h.sign().as_ref()[..8]);
                    Ok(Box::new(Framed::new(s, Mode::V2 { prefix: Some(prefix) })) as Stream)
                }
                _ => {
                    let (mut c, hello) = self.v3_client()?;
                    let mut st = V3Handshake {
                        key: self.key(),
                        password: self.password.as_bytes().to_vec(),
                        server_random: None,
                        read_hmac: None,
                        mask: Vec::new(),
                        tls13: false,
                        authorized: false,
                    };
                    handshake(&mut c, &mut s, hello, |rec| st.on_record(rec)).await?;
                    self.v3_framed(s, st)
                }
            }
        })
    }
}

// One per connection; boxing would only add an indirection per record.
#[allow(clippy::large_enum_variant)]
enum Mode {
    /// Plain application-data records; the first write carries the
    /// handshake tag.
    V2 { prefix: Option<[u8; 8]> },
    /// Records carry a chained HMAC. Server records that still verify under
    /// the handshake chain (`ignore`, e.g. session tickets) are skipped.
    V3 {
        add: hmac::Context,
        verify: hmac::Context,
        ignore: Option<hmac::Context>,
    },
}

/// Post-handshake framing over the raw stream.
struct Framed {
    inner: Stream,
    mode: Mode,
    rbuf: Box<[u8]>,
    /// Unparsed bytes are `rbuf[rhead..rfill]`.
    rhead: usize,
    rfill: usize,
    /// Payload ready for the reader: `rbuf[pstart..pend]`.
    pstart: usize,
    pend: usize,
    wbuf: Vec<u8>,
    wpos: usize,
}

/// Longest record body a v3 server sends: its own frames are a TLS
/// plaintext record plus the tag, and the records it forwards from the
/// cover server are TLS ciphertext, at most 2^14 + 2048 bytes even under
/// TLS 1.2 (RFC 5246 §6.2.3). v2 relays whatever the server wraps, so it
/// keeps the full 16-bit length.
const V3_MAX_RECORD: usize = MAX_PLAINTEXT + 2048;

impl Framed {
    fn new(inner: Stream, mode: Mode) -> Self {
        // Two records, so one can be parsed while the next arrives. The ring
        // is cycled through in any long transfer, after which all of it stays
        // committed for the connection's life.
        let rbuf = 2 * (HEADER + Self::max_record(&mode));
        Self {
            inner,
            mode,
            rbuf: vec![0u8; rbuf].into_boxed_slice(),
            rhead: 0,
            rfill: 0,
            pstart: 0,
            pend: 0,
            wbuf: Vec::with_capacity(MAX_PLAINTEXT + 64),
            wpos: 0,
        }
    }

    fn max_record(mode: &Mode) -> usize {
        match mode {
            Mode::V2 { .. } => u16::MAX as usize,
            Mode::V3 { .. } => V3_MAX_RECORD,
        }
    }

    fn poll_fill(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<()>> {
        while self.rfill - self.rhead < need {
            if self.rhead + need > self.rbuf.len() {
                self.rbuf.copy_within(self.rhead..self.rfill, 0);
                self.rfill -= self.rhead;
                self.rhead = 0;
            }
            let mut rb = ReadBuf::new(&mut self.rbuf[self.rfill..]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.rfill += n;
        }
        Poll::Ready(Ok(()))
    }

    /// Parse the next record into the payload window. Returns false for a
    /// record that carries nothing for the reader.
    fn take_record(&mut self, len: usize) -> io::Result<bool> {
        let rec_start = self.rhead;
        let rec = &self.rbuf[rec_start..rec_start + HEADER + len];
        self.rhead += HEADER + len;
        let body = rec_start + HEADER;
        match &mut self.mode {
            Mode::V2 { .. } => {
                if rec[0] != APPLICATION_DATA {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("shadowtls: unexpected TLS record type {}", rec[0]),
                    ));
                }
                (self.pstart, self.pend) = (body, body + len);
            }
            Mode::V3 { verify, ignore, .. } => {
                match rec[0] {
                    APPLICATION_DATA => {}
                    ALERT => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "shadowtls: remote alert",
                        ));
                    }
                    t => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("shadowtls: unexpected TLS record type {t}"),
                        ));
                    }
                }
                if rec[1] != 3 || rec[2] != 3 || len < HMAC_LEN {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "shadowtls: bad record"));
                }
                let tag = &rec[HEADER..HEADER + HMAC_LEN];
                let data = &rec[HEADER + HMAC_LEN..];
                if let Some(ig) = ignore.as_mut() {
                    ig.update(data);
                    if constant_time::verify_slices_are_equal(&ig.clone().sign().as_ref()[..HMAC_LEN], tag).is_ok() {
                        return Ok(false);
                    }
                    *ignore = None;
                }
                verify.update(data);
                let sum = verify.clone().sign();
                let sum = &sum.as_ref()[..HMAC_LEN];
                verify.update(sum);
                if constant_time::verify_slices_are_equal(sum, tag).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "shadowtls: application data verification failed",
                    ));
                }
                (self.pstart, self.pend) = (body + HMAC_LEN, body + len);
            }
        }
        Ok(self.pend > self.pstart)
    }

    fn encode(&mut self, data: &[u8]) -> usize {
        self.wbuf.clear();
        self.wpos = 0;
        match &mut self.mode {
            Mode::V2 { prefix } => {
                let p = prefix.take();
                let room = MAX_PLAINTEXT - p.map_or(0, |p| p.len());
                let n = data.len().min(room);
                let len = (n + p.map_or(0, |p| p.len())) as u16;
                self.wbuf.extend_from_slice(&[APPLICATION_DATA, 3, 3]);
                self.wbuf.extend_from_slice(&len.to_be_bytes());
                if let Some(p) = p {
                    self.wbuf.extend_from_slice(&p);
                }
                self.wbuf.extend_from_slice(&data[..n]);
                n
            }
            Mode::V3 { add, .. } => {
                let n = data.len().min(MAX_PLAINTEXT);
                add.update(&data[..n]);
                let sum = add.clone().sign();
                let sum = &sum.as_ref()[..HMAC_LEN];
                add.update(sum);
                self.wbuf.extend_from_slice(&[APPLICATION_DATA, 3, 3]);
                self.wbuf.extend_from_slice(&((n + HMAC_LEN) as u16).to_be_bytes());
                self.wbuf.extend_from_slice(sum);
                self.wbuf.extend_from_slice(&data[..n]);
                n
            }
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Framed {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pstart < this.pend {
                let n = (this.pend - this.pstart).min(buf.remaining());
                buf.put_slice(&this.rbuf[this.pstart..this.pstart + n]);
                this.pstart += n;
                return Poll::Ready(Ok(()));
            }
            match ready!(this.poll_fill(cx, HEADER)) {
                Ok(()) => {}
                // EOF between records is a clean close.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && this.rfill == this.rhead => {
                    return Poll::Ready(Ok(()));
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
            let h = &this.rbuf[this.rhead..];
            let len = u16::from_be_bytes([h[3], h[4]]) as usize;
            if len > Self::max_record(&this.mode) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "shadowtls: record too long",
                )));
            }
            ready!(this.poll_fill(cx, HEADER + len))?;
            this.take_record(len)?;
        }
    }
}

impl AsyncWrite for Framed {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = this.encode(buf);
        // The record is ours now; push what the socket takes without waiting.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_detection() {
        // record header + type/len/version + random + sid(0) + suite + comp + ext(supported_versions)
        let mut r = vec![22, 3, 3, 0, 0, 2, 0, 0, 0, 3, 3];
        r.extend_from_slice(&[0u8; 32]);
        r.push(0); // session id length
        r.extend_from_slice(&[0x13, 0x01, 0]);
        r.extend_from_slice(&[0, 6, 0, 43, 0, 2, 3, 4]);
        assert!(server_hello_is_tls13(&r));
        let n = r.len();
        r[n - 1] = 3;
        assert!(!server_hello_is_tls13(&r));
    }
}
