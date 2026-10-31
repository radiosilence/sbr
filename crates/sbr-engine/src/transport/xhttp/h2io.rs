//! HTTP/2 for XHTTP: one lazily dialed connection per XMUX slot, a response
//! body reader and a request body writer.

use std::future::{Future as _, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::OnceCell;
use tracing::debug;

use super::super::ServerDialer;

/// Go's `http2.Transport` defaults are 4 MiB per stream and 1 GiB per
/// connection. The connection window is what the server may park unread
/// across all streams; with XMUX opening several connections it is kept to
/// 4 MiB where memory is capped (the iOS extension's ~50 MB).
const STREAM_WINDOW: u32 = if crate::MOBILE { 2 } else { 4 } * 1024 * 1024;
const CONN_WINDOW: u32 = if crate::MOBILE { 4 } else { 16 } * 1024 * 1024;
const MAX_WRITE: usize = 64 * 1024;

pub fn h2_err(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io().unwrap()
    } else {
        io::Error::other(e)
    }
}

#[derive(Default)]
pub struct H2Conn {
    send: OnceCell<SendRequest<Bytes>>,
    dead: Arc<AtomicBool>,
}

impl H2Conn {
    pub fn is_closed(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    async fn dial(
        &self,
        dialer: &ServerDialer,
        keepalive: Option<std::time::Duration>,
    ) -> io::Result<SendRequest<Bytes>> {
        let s = dialer
            .connect()
            .await
            .inspect_err(|_| self.dead.store(true, Ordering::Relaxed))?;
        let (send, mut conn) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONN_WINDOW)
            .max_frame_size(64 * 1024)
            .max_header_list_size(crate::transport::MAX_RESPONSE_HEADERS)
            .enable_push(false)
            .handshake::<_, Bytes>(s)
            .await
            .map_err(|e| {
                self.dead.store(true, Ordering::Relaxed);
                h2_err(e)
            })?;
        let dead = self.dead.clone();
        let ping = keepalive.and_then(|p| conn.ping_pong().map(|pp| (pp, p)));
        tokio::spawn(async move {
            let r = match ping {
                // Only when configured (`xmux.hKeepAlivePeriod`): pings wake
                // the radio even when the connection is idle.
                Some((mut pp, period)) => {
                    let pinger = async move {
                        loop {
                            tokio::time::sleep(period).await;
                            if pp.ping(h2::Ping::opaque()).await.is_err() {
                                break;
                            }
                        }
                    };
                    tokio::select! {
                        r = &mut conn => r,
                        () = pinger => Ok(()),
                    }
                }
                None => conn.await,
            };
            if let Err(e) = r {
                debug!(error = %e, "xhttp h2 connection closed");
            }
            dead.store(true, Ordering::Relaxed);
        });
        Ok(send)
    }

    /// Send request headers (dialing first if this slot has no connection
    /// yet). With `end`, the request has no body.
    pub async fn request(
        &self,
        dialer: &ServerDialer,
        keepalive: Option<std::time::Duration>,
        req: http::Request<()>,
        end: bool,
    ) -> io::Result<(ResponseFuture, SendStream<Bytes>)> {
        let send = self
            .send
            .get_or_try_init(|| self.dial(dialer, keepalive))
            .await?
            .clone();
        let r = async {
            let mut send = send.ready().await?;
            send.send_request(req, end)
        }
        .await;
        r.map_err(|e| {
            self.dead.store(true, Ordering::Relaxed);
            h2_err(e)
        })
    }
}

/// Write `data` as the whole request body, waiting for flow-control
/// capacity so the caller learns when it has been handed to the connection.
pub async fn send_body(send: &mut SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    if data.is_empty() {
        return send.send_data(Bytes::new(), true).map_err(h2_err);
    }
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
            .map_err(h2_err)?;
        if cap == 0 {
            continue;
        }
        let chunk = data.split_to(cap.min(data.len()));
        send.send_data(chunk, data.is_empty()).map_err(h2_err)?;
    }
    Ok(())
}

/// Wait for a response, check it is 200, then read and discard its body
/// (stream-up's upload response carries only padding).
pub async fn drain(resp: ResponseFuture) -> io::Result<()> {
    let resp = resp.await.map_err(h2_err)?;
    if resp.status() != http::StatusCode::OK {
        return Err(io::Error::other(format!("xhttp: bad status code: {}", resp.status())));
    }
    let mut body = resp.into_body();
    while let Some(d) = body.data().await {
        let d = d.map_err(h2_err)?;
        let _ = body.flow_control().release_capacity(d.len());
    }
    Ok(())
}

enum Recv {
    Response(ResponseFuture),
    Body(RecvStream),
    Done,
}

/// A download: the body of a 200 response.
pub struct H2Down {
    recv: Recv,
    cur: Bytes,
}

impl H2Down {
    pub fn new(resp: ResponseFuture) -> Self {
        Self {
            recv: Recv::Response(resp),
            cur: Bytes::new(),
        }
    }
}

impl AsyncRead for H2Down {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.cur.is_empty() {
                let n = this.cur.len().min(out.remaining());
                out.put_slice(&this.cur[..n]);
                this.cur.advance(n);
                return Poll::Ready(Ok(()));
            }
            match &mut this.recv {
                Recv::Response(f) => {
                    let resp = ready!(Pin::new(f).poll(cx)).map_err(h2_err)?;
                    if resp.status() != http::StatusCode::OK {
                        this.recv = Recv::Done;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("xhttp: unexpected status: {}", resp.status()),
                        )));
                    }
                    this.recv = Recv::Body(resp.into_body());
                }
                Recv::Body(b) => match ready!(b.poll_data(cx)) {
                    Some(Ok(d)) => {
                        let _ = b.flow_control().release_capacity(d.len());
                        this.cur = d;
                    }
                    Some(Err(e)) if e.reason() == Some(h2::Reason::NO_ERROR) => this.recv = Recv::Done,
                    Some(Err(e)) => return Poll::Ready(Err(h2_err(e))),
                    None => this.recv = Recv::Done,
                },
                Recv::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// An upload: a streaming request body.
pub struct H2Up {
    send: SendStream<Bytes>,
    pending: BytesMut,
    closed: bool,
}

impl H2Up {
    pub fn new(send: SendStream<Bytes>) -> Self {
        Self {
            send,
            pending: BytesMut::new(),
            closed: false,
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

impl AsyncWrite for H2Up {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_WRITE);
        this.pending.extend_from_slice(&buf[..n]);
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
