//! HTTP/2 plumbing for the `grpc` and `http` transports: one pooled
//! connection per outbound carrying many streams (Go's `http2.Transport`
//! does the same), and a stream adapter with optional gun framing (the
//! gRPC-without-gRPC "Tun" service that sing-box and Xray speak).

use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll, ready};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use super::ServerDialer;

/// Per-stream receive window. Go uses 4 MiB; this is plenty for one stream
/// at LAN speed and bounds per-connection memory on iOS.
const STREAM_WINDOW: u32 = 2 * 1024 * 1024;
const CONN_WINDOW: u32 = 8 * 1024 * 1024;
/// Most bytes queued per write before backpressure.
const MAX_WRITE: usize = 64 * 1024;

pub struct H2Pool {
    dialer: ServerDialer,
    conn: Mutex<Option<SendRequest<Bytes>>>,
}

impl H2Pool {
    pub fn new(dialer: ServerDialer) -> Self {
        Self {
            dialer,
            conn: Mutex::new(None),
        }
    }

    async fn dial(&self) -> io::Result<SendRequest<Bytes>> {
        let s = self.dialer.connect().await?;
        let (send, conn) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONN_WINDOW)
            .max_frame_size(64 * 1024)
            .enable_push(false)
            .handshake::<_, Bytes>(s)
            .await
            .map_err(h2_err)?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "h2 transport connection closed");
            }
        });
        Ok(send)
    }

    /// Open a stream: request headers go out now, the response is awaited
    /// lazily by the first read.
    pub async fn open(&self, req: http::Request<()>, gun: bool) -> io::Result<H2Stream> {
        for attempt in 0..2 {
            let cached = self.conn.lock().unwrap().clone();
            let fresh = cached.is_none();
            let send = match cached {
                Some(s) => s,
                None => {
                    let s = self.dial().await?;
                    *self.conn.lock().unwrap() = Some(s.clone());
                    s
                }
            };
            let result = async {
                let mut send = send.ready().await?;
                send.send_request(req.clone(), false)
            }
            .await;
            match result {
                Ok((resp, stream)) => return Ok(H2Stream::new(resp, stream, gun)),
                Err(e) => {
                    *self.conn.lock().unwrap() = None;
                    if fresh || attempt == 1 {
                        return Err(h2_err(e));
                    }
                    // The pooled connection died; retry once on a new one.
                }
            }
        }
        unreachable!()
    }
}

fn h2_err(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io().unwrap()
    } else {
        io::Error::other(e)
    }
}

enum Recv {
    Response(ResponseFuture),
    Body(RecvStream),
    Done,
}

pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: Recv,
    /// Current received DATA chunk.
    rcur: Bytes,
    /// Bytes queued for sending (framed, if gun).
    pending: BytesMut,
    gun: bool,
    /// gun read state: payload bytes left in the current message, bytes to
    /// skip after it, and a partially read message header.
    msg_left: usize,
    msg_skip: usize,
    hdr: [u8; 16],
    hdr_len: usize,
    closed: bool,
}

impl H2Stream {
    fn new(resp: ResponseFuture, send: SendStream<Bytes>, gun: bool) -> Self {
        Self {
            send,
            recv: Recv::Response(resp),
            rcur: Bytes::new(),
            pending: BytesMut::new(),
            gun,
            msg_left: 0,
            msg_skip: 0,
            hdr: [0; 16],
            hdr_len: 0,
            closed: false,
        }
    }

    /// Next chunk of the response body; `Ok(false)` at EOF.
    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if !self.rcur.is_empty() {
                return Poll::Ready(Ok(true));
            }
            match &mut self.recv {
                Recv::Response(f) => {
                    let resp = ready!(Pin::new(f).poll(cx)).map_err(h2_err)?;
                    if resp.status() != http::StatusCode::OK {
                        self.recv = Recv::Done;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("unexpected status: {}", resp.status()),
                        )));
                    }
                    self.recv = Recv::Body(resp.into_body());
                }
                Recv::Body(b) => match ready!(b.poll_data(cx)) {
                    Some(Ok(d)) => {
                        let _ = b.flow_control().release_capacity(d.len());
                        self.rcur = d;
                    }
                    Some(Err(e)) if e.reason() == Some(h2::Reason::NO_ERROR) => {
                        self.recv = Recv::Done;
                        return Poll::Ready(Ok(false));
                    }
                    Some(Err(e)) => return Poll::Ready(Err(h2_err(e))),
                    None => {
                        self.recv = Recv::Done;
                        return Poll::Ready(Ok(false));
                    }
                },
                Recv::Done => return Poll::Ready(Ok(false)),
            }
        }
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let cap = self.send.capacity();
            if cap == 0 {
                self.send.reserve_capacity(self.pending.len());
                match ready!(self.send.poll_capacity(cx)) {
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Poll::Ready(Err(h2_err(e))),
                    None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                }
            }
            let chunk = self.pending.split_to(cap.min(self.pending.len())).freeze();
            self.send.send_data(chunk, false).map_err(h2_err)?;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.gun {
            if !ready!(this.poll_chunk(cx))? {
                return Poll::Ready(Ok(()));
            }
            let n = this.rcur.len().min(out.remaining());
            out.put_slice(&this.rcur[..n]);
            this.rcur.advance(n);
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.msg_left > 0 {
                if !ready!(this.poll_chunk(cx))? {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                let n = this.rcur.len().min(out.remaining()).min(this.msg_left);
                out.put_slice(&this.rcur[..n]);
                this.rcur.advance(n);
                this.msg_left -= n;
                return Poll::Ready(Ok(()));
            }
            if this.msg_skip > 0 {
                if !ready!(this.poll_chunk(cx))? {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                let n = this.rcur.len().min(this.msg_skip);
                this.rcur.advance(n);
                this.msg_skip -= n;
                continue;
            }
            // Message header: 5-byte gRPC prefix, protobuf tag 0x0A, varint length.
            if !ready!(this.poll_chunk(cx))? {
                if this.hdr_len == 0 {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            while this.hdr_len < this.hdr.len() && !this.rcur.is_empty() {
                this.hdr[this.hdr_len] = this.rcur[0];
                this.rcur.advance(1);
                this.hdr_len += 1;
                if this.hdr_len > 6 && this.hdr[this.hdr_len - 1] & 0x80 == 0 {
                    break;
                }
            }
            let h = &this.hdr[..this.hdr_len];
            if h.len() > 6 && h[h.len() - 1] & 0x80 == 0 {
                let msg_len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
                let bad = || Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "gun: bad message")));
                // The message length is 32 bits, so a longer varint is malformed
                // (and would overflow the shifts below).
                if h.len() - 6 > 5 {
                    return bad();
                }
                let mut len = 0usize;
                for (i, b) in h[6..].iter().enumerate() {
                    len |= ((b & 0x7f) as usize) << (7 * i);
                }
                let Some(used) = len.checked_add(1 + (h.len() - 6)).filter(|u| *u <= msg_len) else {
                    return bad();
                };
                if h[5] != 0x0a {
                    return bad();
                }
                this.msg_left = len;
                this.msg_skip = msg_len - used;
                this.hdr_len = 0;
            } else if this.hdr_len == this.hdr.len() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "gun: bad varint")));
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_WRITE);
        if this.gun {
            let mut varint = [0u8; 10];
            let mut v = n;
            let mut vl = 0;
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    varint[vl] = b;
                    vl += 1;
                    break;
                }
                varint[vl] = b | 0x80;
                vl += 1;
            }
            this.pending.reserve(6 + vl + n);
            this.pending.put_u8(0);
            this.pending.put_u32((1 + vl + n) as u32);
            this.pending.put_u8(0x0a);
            this.pending.put_slice(&varint[..vl]);
        } else {
            this.pending.reserve(n);
        }
        this.pending.put_slice(&buf[..n]);
        if let Poll::Ready(Err(e)) = this.poll_flush_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_pending(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        if !this.closed {
            this.closed = true;
            this.send.send_data(Bytes::new(), true).map_err(h2_err)?;
        }
        Poll::Ready(Ok(()))
    }
}
