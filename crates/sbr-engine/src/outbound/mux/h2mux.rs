//! sing-mux h2mux: an HTTP/2 connection whose streams are `CONNECT`
//! requests to `localhost`, each answered `200` and then carried as a byte
//! stream in both directions.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use h2::client::SendRequest;
use tracing::debug;

use super::conn::SessionConn;
use crate::transport::h2::H2Stream;

const STREAM_WINDOW: u32 = 256 * 1024;
const CONN_WINDOW: u32 = if crate::MOBILE { 4 } else { 16 } * 1024 * 1024;
/// Streams per session, so full stream windows fit in `CONN_WINDOW`'s
/// worth of unread data per session.
pub const MAX_STREAMS: usize = (CONN_WINDOW / STREAM_WINDOW) as usize;

pub struct Session {
    send: SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
    driver: tokio::task::JoinHandle<()>,
    open: Arc<AtomicUsize>,
}

impl Session {
    pub async fn new(conn: SessionConn) -> io::Result<Self> {
        let (send, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONN_WINDOW)
            .max_concurrent_streams(0)
            .max_send_buffer_size(64 * 1024)
            .enable_push(false)
            .handshake::<_, Bytes>(conn)
            .await
            .map_err(h2_err)?;
        let closed = Arc::new(AtomicBool::new(false));
        let c = closed.clone();
        let driver = tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!(error = %e, "h2mux: session ended");
            }
            c.store(true, Ordering::Release);
        });
        Ok(Self {
            send,
            closed,
            driver,
            open: Arc::default(),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn can_take_new(&self) -> bool {
        !self.is_closed() && self.open.load(Ordering::Acquire) < MAX_STREAMS
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.driver.abort();
    }

    /// The request goes out now; its response is awaited by the first read,
    /// as sing-mux's late connection does.
    pub async fn open(&self) -> io::Result<H2Stream> {
        let mut send = self.send.clone().ready().await.map_err(h2_err)?;
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("localhost")
            .body(())
            .expect("static request");
        let (resp, stream) = send.send_request(req, false).map_err(h2_err)?;
        Ok(H2Stream::new(resp, stream, false))
    }

    /// Counts streams against `MAX_STREAMS`; the caller holds the guard for
    /// the stream's life.
    pub fn track(&self) -> OpenGuard {
        self.open.fetch_add(1, Ordering::AcqRel);
        OpenGuard(self.open.clone())
    }
}

pub struct OpenGuard(Arc<AtomicUsize>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn h2_err(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io().unwrap()
    } else {
        io::Error::other(format!("h2mux: {e}"))
    }
}
