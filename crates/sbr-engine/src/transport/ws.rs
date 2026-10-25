//! V2Ray WebSocket transport (sing-box `transport/v2raywebsocket`): binary
//! frames over an HTTP/1.1 upgrade, with Xray-style early data ("ed") carried
//! in the request path or a header.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use base64::Engine as _;
use sbr_core::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ServerDialer;
use super::prefixed::{head_end, split_path};
use crate::httpx::MAX_HEAD;

pub struct WsClient {
    dialer: ServerDialer,
    params: Arc<Params>,
}

struct Params {
    path: String,
    query: Option<String>,
    host: String,
    /// Extra headers (Host and Sec-WebSocket-Protocol removed).
    headers: Vec<(String, String)>,
    protocol: Option<String>,
    max_early_data: usize,
    early_header: Option<String>,
}

impl WsClient {
    pub fn new(
        dialer: ServerDialer,
        path: Option<&str>,
        headers: &[(String, String)],
        max_early_data: u32,
        early_header: Option<&str>,
    ) -> Self {
        let (path, query) = split_path(path);
        let mut host = dialer.server_authority();
        let mut protocol = None;
        let mut extra = Vec::new();
        let mut has_ua = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("host") {
                host = v.clone();
            } else if k.eq_ignore_ascii_case("sec-websocket-protocol") {
                protocol = Some(v.clone());
            } else {
                has_ua |= k.eq_ignore_ascii_case("user-agent");
                extra.push((k.clone(), v.clone()));
            }
        }
        if !has_ua {
            extra.push(("User-Agent".into(), "Go-http-client/1.1".into()));
        }
        Self {
            dialer,
            params: Arc::new(Params {
                path,
                query,
                host,
                headers: extra,
                protocol,
                max_early_data: max_early_data as usize,
                early_header: early_header.map(str::to_owned),
            }),
        }
    }

    pub async fn connect(&self) -> io::Result<Stream> {
        let s = self.dialer.connect().await?;
        let mut ws = WsStream::new(s, self.params.clone());
        if self.params.max_early_data == 0 {
            // Upgrade now, like sing-box does without early data.
            std::future::poll_fn(|cx| ws.poll_open(cx, Side::Read)).await?;
        }
        Ok(Box::new(ws))
    }
}

impl Params {
    fn request(&self, early: &[u8]) -> Vec<u8> {
        let mut key = [0u8; 16];
        aws_lc_rs::rand::fill(&mut key).expect("system RNG");
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut path = self.path.clone();
        let mut protocol = self.protocol.clone();
        let mut early_hdr = None;
        if !early.is_empty() {
            let ed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(early);
            match &self.early_header {
                None => path.push_str(&ed),
                Some(h) if h.eq_ignore_ascii_case("sec-websocket-protocol") => protocol = Some(ed),
                Some(h) => early_hdr = Some((h.clone(), ed)),
            }
        }
        let mut r = format!("GET {path}");
        if let Some(q) = &self.query {
            r.push('?');
            r.push_str(q);
        }
        r.push_str(" HTTP/1.1\r\nHost: ");
        r.push_str(&self.host);
        r.push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
        r.push_str(&b64.encode(key));
        r.push_str("\r\n");
        if let Some(p) = protocol {
            r.push_str(&format!("Sec-WebSocket-Protocol: {p}\r\n"));
        }
        for (k, v) in self.headers.iter().chain(early_hdr.iter()) {
            r.push_str(&format!("{k}: {v}\r\n"));
        }
        r.push_str("\r\n");
        r.into_bytes()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Read,
    Write,
}

enum State {
    /// Upgrade not sent yet (early-data mode waits for the first write).
    Lazy,
    /// Request queued in `wbuf`; waiting for `101`.
    Requested,
    Open,
}

/// Read buffer size; also the most we pull per read while parsing headers.
const RBUF: usize = 16 * 1024;

pub struct WsStream<S> {
    inner: S,
    params: Arc<Params>,
    state: State,
    rbuf: Vec<u8>,
    rpos: usize,
    /// Payload bytes left in the current frame.
    left: u64,
    /// Current frame carries data (binary/continuation) rather than junk.
    data: bool,
    eof: bool,
    closing: bool,
    /// Who reads the upgrade response, and who waits for it.
    driver: Option<Side>,
    waiter: Option<std::task::Waker>,
    wbuf: Vec<u8>,
    wpos: usize,
    /// The write side is waiting for the socket to take `wbuf`. A socket
    /// keeps one write wakeup, so the read side must not poll it then: with
    /// the halves in two tasks, the writer would never be woken.
    writer_parked: bool,
    rng: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
    fn new(inner: S, params: Arc<Params>) -> Self {
        Self {
            inner,
            params,
            state: State::Lazy,
            rbuf: Vec::new(),
            rpos: 0,
            left: 0,
            data: false,
            eof: false,
            closing: false,
            driver: None,
            waiter: None,
            wbuf: Vec::new(),
            wpos: 0,
            writer_parked: false,
            rng: (u64::from(crate::tls::rand_u32()) << 32 | u64::from(crate::tls::rand_u32())) | 1,
        }
    }

    fn mask_key(&mut self) -> [u8; 4] {
        // xorshift64: masking keys only need to be unpredictable to
        // intermediaries, not cryptographically strong.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng as u32).to_ne_bytes()
    }

    /// Push out `wbuf`. From the read side this is best effort and yields
    /// to a parked writer (`Pending` without polling the socket).
    fn poll_flush_wbuf(&mut self, cx: &mut Context<'_>, side: Side) -> Poll<io::Result<()>> {
        if side == Side::Read && self.writer_parked {
            return Poll::Pending;
        }
        let r = self.poll_write_wbuf(cx);
        if side == Side::Write {
            self.writer_parked = r.is_pending();
        }
        r
    }

    fn poll_write_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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

    /// Make sure `n` unread bytes are buffered. `Ok(false)` on clean EOF.
    fn poll_fill(&mut self, cx: &mut Context<'_>, n: usize) -> Poll<io::Result<bool>> {
        while self.rbuf.len() - self.rpos < n {
            if self.rpos > 0 {
                self.rbuf.drain(..self.rpos);
                self.rpos = 0;
            }
            let start = self.rbuf.len();
            self.rbuf.resize(start.max(RBUF).max(n), 0);
            let mut rb = ReadBuf::new(&mut self.rbuf[start..]);
            let r = Pin::new(&mut self.inner).poll_read(cx, &mut rb);
            let got = rb.filled().len();
            self.rbuf.truncate(start + got);
            ready!(r)?;
            if got == 0 {
                return Poll::Ready(Ok(false));
            }
        }
        Poll::Ready(Ok(true))
    }

    /// Drive the upgrade to completion. With the stream split across two
    /// tasks, only one of them (the first to need it) reads the response;
    /// the other parks its waker here, since a socket remembers a single
    /// reader wakeup.
    fn poll_open(&mut self, cx: &mut Context<'_>, side: Side) -> Poll<io::Result<()>> {
        let r = self.poll_open_inner(cx, side);
        if r.is_ready() {
            self.driver = None;
            if let Some(w) = self.waiter.take() {
                w.wake();
            }
        }
        r
    }

    fn poll_open_inner(&mut self, cx: &mut Context<'_>, side: Side) -> Poll<io::Result<()>> {
        loop {
            match self.state {
                State::Open => return Poll::Ready(Ok(())),
                State::Lazy => {
                    self.wbuf = self.params.request(&[]);
                    self.state = State::Requested;
                }
                State::Requested => {
                    match self.poll_flush_wbuf(cx, side) {
                        Poll::Ready(r) => {
                            r?;
                            if let Poll::Ready(Err(e)) = Pin::new(&mut self.inner).poll_flush(cx) {
                                return Poll::Ready(Err(e));
                            }
                        }
                        // The reader goes on to wait for the response; the
                        // writer (or this task's write wakeup) finishes this.
                        Poll::Pending if side == Side::Read => {}
                        Poll::Pending => return Poll::Pending,
                    }
                    match self.driver {
                        None => self.driver = Some(side),
                        Some(d) if d != side => {
                            self.waiter = Some(cx.waker().clone());
                            return Poll::Pending;
                        }
                        Some(_) => {}
                    }
                    let end = loop {
                        if let Some(end) = head_end(&self.rbuf[self.rpos..]) {
                            break end;
                        }
                        if self.rbuf.len() - self.rpos > MAX_HEAD {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "websocket: response head too large",
                            )));
                        }
                        let want = self.rbuf.len() - self.rpos + 1;
                        if !ready!(self.poll_fill(cx, want))? {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "websocket: connection closed during upgrade",
                            )));
                        }
                    };
                    let head = &self.rbuf[self.rpos..self.rpos + end];
                    let status = crate::httpx::status_code(head);
                    if status != Some(101) {
                        let line = String::from_utf8_lossy(head.split(|b| *b == b'\r').next().unwrap_or_default());
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("websocket: unexpected response: {line}"),
                        )));
                    }
                    self.rpos += end;
                    self.state = State::Open;
                }
            }
        }
    }

    /// Queue one masked frame.
    fn frame(&mut self, opcode: u8, payload: &[u8]) {
        let key = self.mask_key();
        let len = payload.len();
        self.wbuf.reserve(14 + len);
        self.wbuf.push(0x80 | opcode);
        if len < 126 {
            self.wbuf.push(0x80 | len as u8);
        } else if len < 65536 {
            self.wbuf.push(0x80 | 126);
            self.wbuf.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            self.wbuf.push(0x80 | 127);
            self.wbuf.extend_from_slice(&(len as u64).to_be_bytes());
        }
        self.wbuf.extend_from_slice(&key);
        let start = self.wbuf.len();
        self.wbuf.extend_from_slice(payload);
        mask(&mut self.wbuf[start..], key);
    }
}

/// XOR with the repeating 4-byte key, eight bytes at a time.
fn mask(data: &mut [u8], key: [u8; 4]) {
    let k = u64::from_ne_bytes([key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3]]);
    let (chunks, rest) = data.as_chunks_mut::<8>();
    for c in chunks {
        *c = (u64::from_ne_bytes(*c) ^ k).to_ne_bytes();
    }
    for (i, b) in rest.iter_mut().enumerate() {
        *b ^= key[i & 3];
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_open(cx, Side::Read))?;
        // Pongs/close replies queued by earlier reads; best effort.
        if this.wpos < this.wbuf.len() {
            let _ = this.poll_flush_wbuf(cx, Side::Read)?;
        }
        loop {
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.left > 0 {
                let buffered = this.rbuf.len() - this.rpos;
                if !this.data {
                    if buffered == 0 && !ready!(this.poll_fill(cx, 1))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let n = (this.rbuf.len() - this.rpos).min(this.left as usize);
                    this.rpos += n;
                    this.left -= n as u64;
                    continue;
                }
                let want = (this.left.min(out.remaining() as u64)) as usize;
                if buffered > 0 {
                    let n = want.min(buffered);
                    out.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
                    this.rpos += n;
                    this.left -= n as u64;
                    return Poll::Ready(Ok(()));
                }
                // Large frame: read straight into the caller's buffer.
                let mut limited = out.take(want);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
                let n = limited.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                // SAFETY: `limited` initialised the first `n` unfilled bytes of `out`.
                unsafe { out.assume_init(n) };
                out.advance(n);
                this.left -= n as u64;
                return Poll::Ready(Ok(()));
            }

            // Frame header.
            if !ready!(this.poll_fill(cx, 2))? {
                return Poll::Ready(Ok(())); // clean EOF between frames
            }
            let b0 = this.rbuf[this.rpos];
            let b1 = this.rbuf[this.rpos + 1];
            let ext = match b1 & 0x7f {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let masked = b1 & 0x80 != 0;
            let hdr = 2 + ext + if masked { 4 } else { 0 };
            if !ready!(this.poll_fill(cx, hdr))? {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            let h = &this.rbuf[this.rpos..this.rpos + hdr];
            let len = match ext {
                2 => u16::from_be_bytes([h[2], h[3]]) as u64,
                8 => u64::from_be_bytes(h[2..10].try_into().unwrap()),
                _ => (b1 & 0x7f) as u64,
            };
            if masked {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "websocket: masked frame from server",
                )));
            }
            let opcode = b0 & 0x0f;
            this.rpos += hdr;
            match opcode {
                0x0 | 0x2 => {
                    this.data = true;
                    this.left = len;
                }
                0x8..=0xa => {
                    if len > 125 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "websocket: control frame too large",
                        )));
                    }
                    let len = len as usize;
                    if !ready!(this.poll_fill(cx, len))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let payload: [u8; 125] = {
                        let mut p = [0u8; 125];
                        p[..len].copy_from_slice(&this.rbuf[this.rpos..this.rpos + len]);
                        p
                    };
                    this.rpos += len;
                    match opcode {
                        // Answer only the latest ping while a reply is still
                        // unsent (RFC 6455 5.5.3), so a peer that pings and
                        // never reads cannot grow the write buffer.
                        0x9 if this.wpos == this.wbuf.len() => this.frame(0xa, &payload[..len]),
                        0x8 => {
                            // Echo the close (RFC 6455 5.5.1) and report EOF.
                            let code = if len >= 2 { &payload[..2] } else { &[0x03, 0xe8][..] };
                            this.frame(0x8, code);
                            this.eof = true;
                        }
                        _ => {}
                    }
                    if this.wpos < this.wbuf.len() {
                        let _ = this.poll_flush_wbuf(cx, Side::Read)?;
                    }
                }
                _ => {
                    this.data = false;
                    this.left = len;
                }
            }
        }
    }
}

/// Frames larger than this are split; keeps one write's buffering bounded.
const MAX_FRAME: usize = 64 * 1024;

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if matches!(this.state, State::Lazy) {
            let n = buf.len().min(this.params.max_early_data);
            this.wbuf = this.params.request(&buf[..n]);
            this.wpos = 0;
            this.state = State::Requested;
            if n > 0 {
                // The early bytes ride in the request: start sending it, but
                // leave the response to whoever needs it next. Not parked:
                // this call returns, so the reader may keep pushing.
                if let Poll::Ready(Err(e)) = this.poll_write_wbuf(cx) {
                    return Poll::Ready(Err(e));
                }
                return Poll::Ready(Ok(n));
            }
        }
        ready!(this.poll_open(cx, Side::Write))?;
        ready!(this.poll_flush_wbuf(cx, Side::Write))?;
        let n = buf.len().min(MAX_FRAME);
        this.frame(0x2, &buf[..n]);
        // Push it out now if the socket takes it; otherwise flush, the next
        // write or the reader will. Not parked: this call returns.
        if let Poll::Ready(Err(e)) = this.poll_write_wbuf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_wbuf(cx, Side::Write))?;
        let r = Pin::new(&mut this.inner).poll_flush(cx);
        this.writer_parked = r.is_pending();
        r
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, State::Lazy) {
            return Pin::new(&mut this.inner).poll_shutdown(cx);
        }
        ready!(this.poll_flush_wbuf(cx, Side::Write))?;
        if !this.eof && !this.closing {
            // Normal closure; the peer answers with its own close frame.
            this.frame(0x8, &1000u16.to_be_bytes());
            this.closing = true;
            ready!(this.poll_flush_wbuf(cx, Side::Write))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_roundtrip() {
        let key = [1, 2, 3, 4];
        let orig: Vec<u8> = (0..37u8).collect();
        let mut d = orig.clone();
        mask(&mut d, key);
        for (i, (a, b)) in d.iter().zip(&orig).enumerate() {
            assert_eq!(*a, b ^ key[i % 4]);
        }
        mask(&mut d, key);
        assert_eq!(d, orig);
    }

    /// Minimal echo server: answer the upgrade, then send every client
    /// frame's payload back as one unmasked binary frame.
    async fn echo_server(mut s: tokio::io::DuplexStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(s.read_u8().await.unwrap());
        }
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();
        let (mut r, mut w) = tokio::io::split(s);
        loop {
            let Ok(b0) = r.read_u8().await else { return };
            let b1 = r.read_u8().await.unwrap();
            let len = match b1 & 0x7f {
                126 => r.read_u16().await.unwrap() as usize,
                127 => r.read_u64().await.unwrap() as usize,
                n => n as usize,
            };
            let mut key = [0u8; 4];
            r.read_exact(&mut key).await.unwrap();
            let mut p = vec![0u8; len];
            r.read_exact(&mut p).await.unwrap();
            mask(&mut p, key);
            if b0 & 0x0f != 0x2 {
                continue;
            }
            let mut f = vec![0x82];
            if len < 126 {
                f.push(len as u8);
            } else if len < 65536 {
                f.push(126);
                f.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                f.push(127);
                f.extend_from_slice(&(len as u64).to_be_bytes());
            }
            f.extend_from_slice(&p);
            w.write_all(&f).await.unwrap();
        }
    }

    /// Split across a reader task and a writer task over a congested
    /// socket: the reader must never take the write wakeup the writer is
    /// waiting on, or the writer sleeps forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn split_halves_keep_their_wakeups() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(echo_server(server));
        let params = Arc::new(Params {
            path: "/".into(),
            query: None,
            host: "example.com".into(),
            headers: Vec::new(),
            protocol: None,
            max_early_data: 0,
            early_header: None,
        });
        let mut ws = WsStream::new(client, params);
        std::future::poll_fn(|cx| ws.poll_open(cx, Side::Read)).await.unwrap();
        let data: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
        let (mut r, mut w) = tokio::io::split(ws);
        let send = data.clone();
        let writer = tokio::spawn(async move {
            for c in send.chunks(40_000) {
                w.write_all(c).await.unwrap();
            }
            w.flush().await.unwrap();
            w
        });
        let mut got = vec![0u8; data.len()];
        tokio::time::timeout(std::time::Duration::from_secs(10), r.read_exact(&mut got))
            .await
            .expect("websocket echo stalled")
            .unwrap();
        assert!(got == data);
        drop(writer.await.unwrap());
    }
}
