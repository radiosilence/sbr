//! Small stream helpers shared by the transports.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::httpx::MAX_HEAD;

/// A stream with bytes already read off it (e.g. after an HTTP head).
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// End of an HTTP head in `buf`, if complete.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Read a response head. Returns (status, head, bytes after the head).
pub async fn read_response<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<(u16, Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        if let Some(end) = head_end(&buf) {
            let rest = buf.split_off(end);
            let status = crate::httpx::status_code(&buf)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad HTTP response"))?;
            return Ok((status, buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response head too large",
            ));
        }
        let start = buf.len();
        buf.resize(start + 2048, 0);
        let n = s.read(&mut buf[start..]).await?;
        buf.truncate(start + n);
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
}

/// Value of header `name` (case-insensitive) in a response head.
pub fn header<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// `path` as sing-box normalises it: leading `/`, query kept separate.
pub fn split_path(path: Option<&str>) -> (String, Option<String>) {
    let p = path.unwrap_or_default();
    let (p, q) = match p.split_once('?') {
        Some((p, q)) => (p, Some(q.to_owned())),
        None => (p, None),
    };
    let p = if p.starts_with('/') {
        p.to_owned()
    } else {
        format!("/{p}")
    };
    (p, q)
}
