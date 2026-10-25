//! HTTP/3 for XHTTP (`alpn: ["h3"]`): one QUIC connection per XMUX slot,
//! dialed on first use through the shared QUIC dialer and closed by
//! [`quic::watch`] once no request has used it for [`IDLE`].

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::{RequestStream, SendRequest};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::OnceCell;

use crate::outbound::quic::{self, Dialer, Tuning, Usage, UseGuard, io_err};

type Send3 = SendRequest<h3_quinn::OpenStreams, Bytes>;
type ReqSend = RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ReqRecv = RequestStream<h3_quinn::RecvStream, Bytes>;
type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// quic-go's default idle timeout, which the Xray server applies.
const IDLE: Duration = Duration::from_secs(30);
/// Xray `net.QuicgoH3KeepAlivePeriod`. The watcher closes a connection
/// [`IDLE`] after its last request, which bounds the pings an idle
/// connection sends.
const KEEP_ALIVE: Duration = Duration::from_secs(10);
const STREAM_WINDOW: u64 = 4 << 20;
const CONN_WINDOW: u64 = 16 << 20;

struct Session {
    send: Send3,
    usage: Arc<Usage>,
    _endpoint: quinn::Endpoint,
}

#[derive(Default)]
pub struct H3Conn {
    session: OnceCell<Session>,
    dead: Arc<AtomicBool>,
}

impl H3Conn {
    pub fn is_closed(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    async fn dial(&self, dialer: &Dialer, keepalive: Option<Duration>) -> io::Result<Session> {
        let t = quic::transport(
            &sbr_config::QuicOptions {
                idle_timeout: Some(IDLE),
                ..Default::default()
            },
            Tuning {
                stream_window: STREAM_WINDOW,
                conn_window: CONN_WINDOW,
                keep_alive: Some(keepalive.unwrap_or(KEEP_ALIVE)),
                incoming_uni: 16,
            },
            Arc::new(quinn::congestion::BbrConfig::default()),
        );
        let r = async {
            let (endpoint, connecting) = dialer.start(t).await?;
            let conn = tokio::time::timeout(dialer.handshake_timeout, connecting)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "xhttp: QUIC handshake timed out"))?
                .map_err(io_err)?;
            let (mut driver, send) = h3::client::builder()
                .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
                .await
                .map_err(io_err)?;
            let dead = self.dead.clone();
            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                dead.store(true, Ordering::Relaxed);
            });
            let usage = Arc::new(Usage::default());
            let (dead, watched) = (self.dead.clone(), conn.clone());
            let u = usage.clone();
            tokio::spawn(async move {
                quic::watch(watched, u, IDLE, None).await;
                dead.store(true, Ordering::Relaxed);
            });
            Ok(Session {
                send,
                usage,
                _endpoint: endpoint,
            })
        }
        .await;
        if r.is_err() {
            self.dead.store(true, Ordering::Relaxed);
        }
        r
    }

    /// Another use of the live connection.
    pub fn guard(&self) -> Option<UseGuard> {
        self.session.get()?.usage.acquire()
    }

    /// Send request headers; the guard keeps the connection open while the
    /// request runs.
    pub async fn request(
        &self,
        dialer: &Dialer,
        keepalive: Option<Duration>,
        req: http::Request<()>,
    ) -> io::Result<(ReqSend, ReqRecv, UseGuard)> {
        let s = self.session.get_or_try_init(|| self.dial(dialer, keepalive)).await?;
        let guard = s.usage.acquire().ok_or_else(|| {
            self.dead.store(true, Ordering::Relaxed);
            io_err("xhttp: QUIC connection closing")
        })?;
        let mut send = s.send.clone();
        let stream = send.send_request(req).await.map_err(|e| {
            self.dead.store(true, Ordering::Relaxed);
            io_err(e)
        })?;
        let (tx, rx) = stream.split();
        Ok((tx, rx, guard))
    }
}

async fn next_chunk(mut rx: ReqRecv, first: bool) -> (ReqRecv, io::Result<Option<Bytes>>) {
    if first {
        match rx.recv_response().await {
            Ok(r) if r.status() == http::StatusCode::OK => {}
            Ok(r) => {
                let e = io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("xhttp: unexpected status: {}", r.status()),
                );
                return (rx, Err(e));
            }
            Err(e) => return (rx, Err(io_err(e))),
        }
    }
    let r = match rx.recv_data().await {
        Ok(Some(mut b)) => Ok(Some(b.copy_to_bytes(b.remaining()))),
        Ok(None) => Ok(None),
        Err(e) => Err(io_err(e)),
    };
    (rx, r)
}

/// Check for 200 and discard the body.
pub async fn drain(rx: ReqRecv) -> io::Result<()> {
    let (mut rx, mut r) = next_chunk(rx, true).await;
    while let Some(_) = r? {
        (rx, r) = next_chunk(rx, false).await;
    }
    Ok(())
}

pub struct H3Down {
    fut: Option<BoxFut<(ReqRecv, io::Result<Option<Bytes>>)>>,
    cur: Bytes,
    _guard: UseGuard,
}

impl H3Down {
    pub fn new(rx: ReqRecv, guard: UseGuard) -> Self {
        Self {
            fut: Some(Box::pin(next_chunk(rx, true))),
            cur: Bytes::new(),
            _guard: guard,
        }
    }
}

impl AsyncRead for H3Down {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.cur.is_empty() {
                let n = this.cur.len().min(out.remaining());
                out.put_slice(&this.cur[..n]);
                this.cur.advance(n);
                return Poll::Ready(Ok(()));
            }
            let Some(f) = this.fut.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            let (rx, r) = ready!(f.as_mut().poll(cx));
            match r {
                Ok(Some(b)) => {
                    this.cur = b;
                    this.fut = Some(Box::pin(next_chunk(rx, false)));
                }
                Ok(None) => this.fut = None,
                Err(e) => {
                    this.fut = None;
                    return Poll::Ready(Err(e));
                }
            }
        }
    }
}

/// A streaming request body; one write in flight at a time.
pub struct H3Up {
    tx: Option<ReqSend>,
    fut: Option<BoxFut<(ReqSend, io::Result<()>)>>,
    finished: bool,
    _guard: UseGuard,
}

impl H3Up {
    pub fn new(tx: ReqSend, guard: UseGuard) -> Self {
        Self {
            tx: Some(tx),
            fut: None,
            finished: false,
            _guard: guard,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(f) = self.fut.as_mut() {
            let (tx, r) = ready!(f.as_mut().poll(cx));
            self.fut = None;
            self.tx = Some(tx);
            r?;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H3Up {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(mut tx) = this.tx.take() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let n = buf.len().min(64 * 1024);
        let data = Bytes::copy_from_slice(&buf[..n]);
        this.fut = Some(Box::pin(async move {
            let r = tx.send_data(data).await.map_err(io_err);
            (tx, r)
        }));
        if let Poll::Ready(Err(e)) = this.poll_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_pending(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        if !this.finished {
            this.finished = true;
            if let Some(mut tx) = this.tx.take() {
                this.fut = Some(Box::pin(async move {
                    let r = tx.finish().await.map_err(io_err);
                    (tx, r)
                }));
            }
            ready!(this.poll_pending(cx))?;
        }
        Poll::Ready(Ok(()))
    }
}

/// One packet-up POST: headers, the whole body, end of stream.
pub async fn post(
    conn: &H3Conn,
    dialer: &Dialer,
    keepalive: Option<Duration>,
    req: http::Request<()>,
    body: Bytes,
) -> io::Result<(ReqRecv, UseGuard)> {
    let (mut tx, rx, guard) = conn.request(dialer, keepalive, req).await?;
    if !body.is_empty() {
        tx.send_data(body).await.map_err(io_err)?;
    }
    tx.finish().await.map_err(io_err)?;
    Ok((rx, guard))
}
