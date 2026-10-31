//! The session connection under every sing-mux protocol: the protocol
//! request ahead of the first write, then, with padding, the first
//! [`PADDED`] records each way framed as `[u16 len][u16 pad][data][pad]`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use sbr_core::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// sing-mux `kFirstPaddings`.
pub const PADDED: u32 = 16;

pub const PROTOCOL_SMUX: u8 = 0;
pub const PROTOCOL_YAMUX: u8 = 1;
pub const PROTOCOL_H2MUX: u8 = 2;

/// `[version][protocol]`, and with padding (version 1) `[1][u16 n][n zeros]`
/// with n in 256..768.
pub fn request(protocol: u8, padding: bool) -> Vec<u8> {
    if !padding {
        return vec![0, protocol];
    }
    let n = fastrand::usize(256..768);
    let mut r = Vec::with_capacity(5 + n);
    r.extend_from_slice(&[1, protocol, 1]);
    r.extend_from_slice(&(n as u16).to_be_bytes());
    r.resize(5 + n, 0);
    r
}

pub struct SessionConn {
    inner: Stream,
    /// The protocol request, until the first write sends it.
    request: Option<Vec<u8>>,
    /// A write in progress: the encoded bytes, how far they got, and the
    /// caller's byte count to report once they are all out.
    out: Vec<u8>,
    out_pos: usize,
    out_n: usize,
    writes_padded: u32,
    reads_padded: u32,
    padding: bool,
    /// Read state: data bytes left in the current padded record, then
    /// padding bytes to skip, and a partial record header.
    data_left: usize,
    skip_left: usize,
    hdr: [u8; 4],
    hdr_len: usize,
}

impl SessionConn {
    pub fn new(inner: Stream, protocol: u8, padding: bool) -> Self {
        Self {
            inner,
            request: Some(request(protocol, padding)),
            out: Vec::new(),
            out_pos: 0,
            out_n: 0,
            writes_padded: if padding { 0 } else { PADDED },
            reads_padded: if padding { 0 } else { PADDED },
            padding,
            data_left: 0,
            skip_left: 0,
            hdr: [0; 4],
            hdr_len: 0,
        }
    }

    fn poll_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SessionConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.out.is_empty() {
            ready!(this.poll_out(cx))?;
            return Poll::Ready(Ok(this.out_n));
        }
        let request = this.request.take();
        if request.is_none() && this.writes_padded >= PADDED {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.out = request.unwrap_or_default();
        let n = if this.writes_padded < PADDED {
            let n = buf.len().min(u16::MAX as usize);
            let pad = fastrand::usize(256..768);
            this.out.extend_from_slice(&(n as u16).to_be_bytes());
            this.out.extend_from_slice(&(pad as u16).to_be_bytes());
            this.out.extend_from_slice(&buf[..n]);
            this.out.resize(this.out.len() + pad, 0);
            this.writes_padded += 1;
            n
        } else {
            this.out.extend_from_slice(buf);
            buf.len()
        };
        this.out_n = n;
        ready!(this.poll_out(cx))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_out(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_out(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for SessionConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.padding || buf.remaining() == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        loop {
            if this.data_left > 0 {
                let want = this.data_left.min(buf.remaining());
                let mut sub = ReadBuf::new(buf.initialize_unfilled_to(want));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                buf.advance(n);
                this.data_left -= n;
                return Poll::Ready(Ok(()));
            }
            while this.skip_left > 0 {
                let mut scratch = [0u8; 1024];
                let want = this.skip_left.min(scratch.len());
                let mut sub = ReadBuf::new(&mut scratch[..want]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.skip_left -= n;
            }
            if this.reads_padded >= PADDED {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            while this.hdr_len < 4 {
                let mut sub = ReadBuf::new(&mut this.hdr[this.hdr_len..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(if this.hdr_len == 0 {
                        Ok(())
                    } else {
                        Err(io::ErrorKind::UnexpectedEof.into())
                    });
                }
                this.hdr_len += n;
            }
            this.hdr_len = 0;
            this.reads_padded += 1;
            this.data_left = u16::from_be_bytes([this.hdr[0], this.hdr[1]]) as usize;
            this.skip_left = u16::from_be_bytes([this.hdr[2], this.hdr[3]]) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn padded_records_round_trip() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut w = SessionConn::new(Box::new(a), PROTOCOL_SMUX, true);
        let mut msgs = Vec::new();
        for i in 0..20u8 {
            let m = vec![i; 100 + i as usize];
            w.write_all(&m).await.unwrap();
            msgs.extend_from_slice(&m);
        }
        w.flush().await.unwrap();
        drop(w);
        // The peer strips the request, then reads the same framing.
        let mut b: Stream = Box::new(b);
        let mut req = [0u8; 5];
        b.read_exact(&mut req).await.unwrap();
        assert_eq!(&req[..3], &[1, PROTOCOL_SMUX, 1]);
        let skip = u16::from_be_bytes([req[3], req[4]]) as usize;
        assert!((256..768).contains(&skip));
        let mut junk = vec![0u8; skip];
        b.read_exact(&mut junk).await.unwrap();
        let mut r = SessionConn::new(b, PROTOCOL_SMUX, true);
        r.request = None;
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, msgs);
    }

    #[test]
    fn plain_request() {
        assert_eq!(request(PROTOCOL_H2MUX, false), vec![0, 2]);
    }
}
