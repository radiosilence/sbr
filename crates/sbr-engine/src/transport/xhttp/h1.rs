//! HTTP/1.1 for XHTTP, as Go's `http.Transport` with `DisableKeepAlives`
//! does it: every streaming request on its own connection (`Connection:
//! close`, chunked request bodies), and packet-up POSTs pipelined on reused
//! connections whose responses are read and dropped.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use bytes::{Buf, BytesMut};
use sbr_core::Stream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};

use super::super::ServerDialer;
use crate::httpx::MAX_HEAD;

/// One XMUX slot's idle upload connections.
#[derive(Default)]
pub struct H1Conn {
    idle: Mutex<Vec<Upload>>,
    dead: AtomicBool,
}

/// An upload connection. Its socket closes only once both halves are gone,
/// so dropping it also stops the task reading its responses.
struct Upload {
    w: WriteHalf<Stream>,
    dead: Arc<AtomicBool>,
    _reader: super::AbortOnDrop,
}

impl H1Conn {
    pub fn is_closed(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }
    pub fn mark_closed(&self) {
        self.dead.store(true, Ordering::Relaxed);
    }

    /// Write one complete request, reusing an idle connection when one is
    /// alive. A failed write on a reused connection retries on another.
    pub async fn post(&self, dialer: &ServerDialer, request: &[u8]) -> io::Result<()> {
        loop {
            let reused = {
                let mut idle = self.idle.lock().unwrap();
                idle.retain(|u| !u.dead.load(Ordering::Relaxed));
                idle.pop()
            };
            let fresh = reused.is_none();
            let mut up = match reused {
                Some(u) => u,
                None => {
                    let s = dialer.connect().await?;
                    let (r, w) = tokio::io::split(s);
                    let dead = Arc::new(AtomicBool::new(false));
                    let reader = super::AbortOnDrop(tokio::spawn(drain_responses(r, dead.clone())));
                    Upload {
                        w,
                        dead,
                        _reader: reader,
                    }
                }
            };
            let w = &mut up.w;
            match async {
                // In pieces, so the deadline is on progress rather than the
                // whole request.
                for piece in request.chunks(16 * 1024) {
                    super::progress("upload", w.write_all(piece)).await?;
                }
                super::progress("upload", w.flush()).await
            }
            .await
            {
                Ok(()) => {
                    self.idle.lock().unwrap().push(up);
                    return Ok(());
                }
                Err(e) if fresh => return Err(e),
                Err(_) => up.dead.store(true, Ordering::Relaxed),
            }
        }
    }
}

/// Read pipelined responses off an upload connection and drop them. A
/// non-200 status or EOF retires the connection.
async fn drain_responses(mut r: ReadHalf<Stream>, dead: Arc<AtomicBool>) {
    let mut resp = H1Response::new_pipelined(&mut r);
    let mut buf = vec![0u8; 4096];
    loop {
        match resp.read(&mut buf).await {
            Ok(0) => {
                if !resp.next_response() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    dead.store(true, Ordering::Relaxed);
}

/// Go's `textproto.CanonicalMIMEHeaderKey`.
fn canonical(k: &str) -> String {
    let mut out = String::with_capacity(k.len());
    let mut upper = true;
    for c in k.chars() {
        out.push(if upper {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        });
        upper = c == '-';
    }
    out
}

pub enum BodyKind {
    None,
    Length(usize),
    Chunked,
}

/// A request head in the order Go's `Request.write` produces: Host,
/// User-Agent, Connection, the body framing, then the rest sorted.
pub fn head(
    method: &str,
    path_query: &str,
    host: &str,
    headers: &[(String, String)],
    body: BodyKind,
    close: bool,
) -> Vec<u8> {
    let mut out = format!("{method} {path_query} HTTP/1.1\r\nHost: {host}\r\n");
    let ua = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map_or("Go-http-client/1.1", |(_, v)| v.as_str());
    if !ua.is_empty() {
        out.push_str(&format!("User-Agent: {ua}\r\n"));
    }
    if close {
        out.push_str("Connection: close\r\n");
    }
    match body {
        BodyKind::None => {}
        BodyKind::Length(n) => out.push_str(&format!("Content-Length: {n}\r\n")),
        BodyKind::Chunked => out.push_str("Transfer-Encoding: chunked\r\n"),
    }
    let mut rest: Vec<(String, &str)> = headers
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("user-agent") && !k.eq_ignore_ascii_case("host"))
        .map(|(k, v)| (canonical(k), v.as_str()))
        .collect();
    rest.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in rest {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Dial and send a request head; the caller streams the body (if any).
pub async fn open(dialer: &ServerDialer, head: &[u8]) -> io::Result<(ReadHalf<Stream>, WriteHalf<Stream>)> {
    let mut s = dialer.connect().await?;
    s.write_all(head).await?;
    s.flush().await?;
    Ok(tokio::io::split(s))
}

/// A chunked request body.
pub struct ChunkedWriter<W> {
    inner: W,
    wbuf: Vec<u8>,
    wpos: usize,
    finished: bool,
}

impl<W: AsyncWrite + Unpin> ChunkedWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            wbuf: Vec::new(),
            wpos: 0,
            finished: false,
        }
    }

    fn poll_flush_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ChunkedWriter<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_flush_buf(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(64 * 1024);
        this.wbuf.extend_from_slice(format!("{n:x}\r\n").as_bytes());
        this.wbuf.extend_from_slice(&buf[..n]);
        this.wbuf.extend_from_slice(b"\r\n");
        if let Poll::Ready(Err(e)) = this.poll_flush_buf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_buf(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_buf(cx))?;
        if !this.finished {
            this.finished = true;
            this.wbuf.extend_from_slice(b"0\r\n\r\n");
            ready!(this.poll_flush_buf(cx))?;
        }
        // The connection stays open: the response may still be streaming.
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum St {
    Head,
    ChunkSize,
    Data(u64),
    DataEnd,
    Trailer,
    Length(u64),
    Eof,
    Done,
}

/// A response: checks for 200, then yields the body (chunked, sized or
/// until EOF).
pub struct H1Response<R> {
    r: R,
    buf: BytesMut,
    st: St,
    /// Responses to pipelined requests follow one another.
    pipelined: bool,
}

impl<R: AsyncRead + Unpin> H1Response<R> {
    pub fn new(r: R) -> Self {
        Self {
            r,
            buf: BytesMut::new(),
            st: St::Head,
            pipelined: false,
        }
    }

    fn new_pipelined(r: R) -> Self {
        Self {
            pipelined: true,
            ..Self::new(r)
        }
    }

    /// After one pipelined response ended: start the next; `false` at EOF.
    fn next_response(&mut self) -> bool {
        if self.st == St::Done && self.pipelined {
            self.st = St::Head;
            return true;
        }
        false
    }

    /// Read more into `buf`; `false` at EOF.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut tmp = [0u8; 8192];
        let mut rb = ReadBuf::new(&mut tmp);
        ready!(Pin::new(&mut self.r).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        self.buf.extend_from_slice(&tmp[..n]);
        Poll::Ready(Ok(n > 0))
    }

    fn parse_head(&mut self) -> io::Result<bool> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut res = httparse::Response::new(&mut headers);
        let n = match res.parse(&self.buf) {
            Ok(httparse::Status::Complete(n)) => n,
            Ok(httparse::Status::Partial) => {
                if self.buf.len() > MAX_HEAD {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "xhttp: response head too large",
                    ));
                }
                return Ok(false);
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("xhttp: bad response: {e}"),
                ));
            }
        };
        if res.code != Some(200) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("xhttp: unexpected status: {:?}", res.code),
            ));
        }
        let mut st = if self.pipelined { St::Length(0) } else { St::Eof };
        for h in res.headers.iter() {
            if h.name.eq_ignore_ascii_case("transfer-encoding")
                && std::str::from_utf8(h.value).is_ok_and(|v| v.to_ascii_lowercase().contains("chunked"))
            {
                st = St::ChunkSize;
                break;
            }
            if h.name.eq_ignore_ascii_case("content-length") {
                let len = std::str::from_utf8(h.value)
                    .ok()
                    .and_then(|v| v.trim().parse().ok())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xhttp: bad content-length"))?;
                st = St::Length(len);
            }
        }
        self.buf.advance(n);
        self.st = st;
        Ok(true)
    }

    fn line(&mut self) -> Option<BytesMut> {
        let i = self.buf.windows(2).position(|w| w == b"\r\n")?;
        let line = self.buf.split_to(i);
        self.buf.advance(2);
        Some(line)
    }

    /// Body bytes, from `buf` first, else straight from the socket.
    fn poll_body(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>, limit: u64) -> Poll<io::Result<usize>> {
        let want = (out.remaining() as u64).min(limit) as usize;
        if !self.buf.is_empty() {
            let n = want.min(self.buf.len());
            out.put_slice(&self.buf[..n]);
            self.buf.advance(n);
            return Poll::Ready(Ok(n));
        }
        let dst = out.initialize_unfilled_to(want);
        let mut rb = ReadBuf::new(dst);
        ready!(Pin::new(&mut self.r).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        out.advance(n);
        Poll::Ready(Ok(n))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for H1Response<R> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.st {
                St::Head => {
                    if !this.parse_head()? && !ready!(this.poll_fill(cx))? {
                        return Poll::Ready(if this.pipelined && this.buf.is_empty() {
                            this.st = St::Done;
                            this.pipelined = false;
                            Ok(())
                        } else {
                            Err(io::ErrorKind::UnexpectedEof.into())
                        });
                    }
                }
                St::ChunkSize => match this.line() {
                    Some(line) => {
                        let s = std::str::from_utf8(&line).unwrap_or("");
                        let hex = s.split(';').next().unwrap_or("").trim();
                        let n = u64::from_str_radix(hex, 16)
                            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "xhttp: bad chunk size"))?;
                        this.st = if n == 0 { St::Trailer } else { St::Data(n) };
                    }
                    None => {
                        if this.buf.len() > 1024 {
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "xhttp: bad chunk")));
                        }
                        if !ready!(this.poll_fill(cx))? {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                    }
                },
                St::Data(left) | St::Length(left) if left > 0 => {
                    let n = ready!(this.poll_body(cx, out, left))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let left = left - n as u64;
                    this.st = match this.st {
                        St::Data(_) if left == 0 => St::DataEnd,
                        St::Data(_) => St::Data(left),
                        _ if left == 0 => St::Done,
                        _ => St::Length(left),
                    };
                    return Poll::Ready(Ok(()));
                }
                St::Length(_) => this.st = St::Done,
                St::Data(_) => this.st = St::DataEnd,
                St::DataEnd => {
                    if this.buf.len() >= 2 {
                        this.buf.advance(2);
                        this.st = St::ChunkSize;
                    } else if !ready!(this.poll_fill(cx))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                }
                St::Trailer => match this.line() {
                    Some(l) if l.is_empty() => this.st = St::Done,
                    Some(_) => {}
                    None => {
                        if !ready!(this.poll_fill(cx))? {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                    }
                },
                St::Eof => {
                    let n = ready!(this.poll_body(cx, out, u64::MAX))?;
                    if n == 0 {
                        this.st = St::Done;
                    }
                    return Poll::Ready(Ok(()));
                }
                St::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_all(input: &[u8]) -> io::Result<Vec<u8>> {
        // Feed a byte at a time to cover every partial state.
        let (mut a, b) = tokio::io::duplex(1);
        let data = input.to_vec();
        tokio::spawn(async move {
            for c in data {
                if a.write_all(&[c]).await.is_err() {
                    return;
                }
            }
        });
        let mut r = H1Response::new(b);
        let mut out = Vec::new();
        r.read_to_end(&mut out).await?;
        Ok(out)
    }

    #[tokio::test]
    async fn chunked_and_sized() {
        let got = read_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n1;x=y\r\n!\r\n0\r\nT: v\r\n\r\n",
        )
        .await
        .unwrap();
        assert_eq!(got, b"hello!");
        let got = read_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef")
            .await
            .unwrap();
        assert_eq!(got, b"abc");
        assert!(read_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await.is_err());
    }

    #[tokio::test]
    async fn chunked_writer_frames() {
        let (a, mut b) = tokio::io::duplex(1 << 16);
        let mut w = ChunkedWriter::new(a);
        w.write_all(b"hi").await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
        let mut out = Vec::new();
        b.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"2\r\nhi\r\n0\r\n\r\n");
    }

    #[test]
    fn head_order() {
        let h = head(
            "POST",
            "/p/s/0",
            "example.com",
            &[("x-foo".into(), "1".into()), ("User-Agent".into(), "ua".into())],
            BodyKind::Length(3),
            false,
        );
        assert_eq!(
            String::from_utf8(h).unwrap(),
            "POST /p/s/0 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ua\r\nContent-Length: 3\r\nX-Foo: 1\r\n\r\n"
        );
    }
}
