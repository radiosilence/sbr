//! smux (sagernet/smux, version 1) and yamux (hashicorp/yamux) client
//! sessions: one reader task per session, streams with byte-bounded
//! receive queues, writes serialised through the session writer.
//!
//! smux v1 has no flow control: a session-wide byte budget is the receive
//! limit, and when it is spent the reader stops, stalling every stream (as
//! xtaci/smux does with `MaxReceiveBuffer`). yamux's per-stream window is
//! fixed by the protocol at 256 KiB, so the session caps its streams instead.
//!
//! A received frame is read into the session's buffer and handed to its
//! stream as `Bytes`; while earlier frames are still queued that buffer is a
//! fresh allocation, so a busy stream costs one allocation per frame.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Semaphore;
use tracing::debug;

use super::conn::SessionConn;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Smux,
    Yamux,
}

const MAX_FRAME: usize = 32 * 1024;
/// Bytes a session may hold unread across its streams.
const SESSION_BUDGET: usize = if crate::MOBILE { 4 } else { 16 } * 1024 * 1024;
const YAMUX_WINDOW: u32 = 256 * 1024;
/// hashicorp's `StreamOpenTimeout`, as sing-mux sets it: a stream whose
/// open is not acknowledged in time means the session is dead.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

const SMUX_VERSION: u8 = 1;
const SMUX_SYN: u8 = 0;
const SMUX_FIN: u8 = 1;
const SMUX_PSH: u8 = 2;
const SMUX_NOP: u8 = 3;

const YAMUX_DATA: u8 = 0;
const YAMUX_WINDOW_UPDATE: u8 = 1;
const YAMUX_PING: u8 = 2;
const YAMUX_GO_AWAY: u8 = 3;
const FLAG_SYN: u16 = 1;
const FLAG_ACK: u16 = 2;
const FLAG_FIN: u16 = 4;
const FLAG_RST: u16 = 8;

/// Most concurrent streams per session.
pub fn max_streams(proto: Proto) -> usize {
    match proto {
        Proto::Smux => 1024,
        Proto::Yamux => SESSION_BUDGET / YAMUX_WINDOW as usize,
    }
}

fn header(out: &mut Vec<u8>, proto: Proto, kind: u8, flags: u16, id: u32, len: u32) {
    match proto {
        Proto::Smux => {
            out.extend_from_slice(&[SMUX_VERSION, kind]);
            out.extend_from_slice(&(len as u16).to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        Proto::Yamux => {
            out.extend_from_slice(&[0, kind]);
            out.extend_from_slice(&flags.to_be_bytes());
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
}

/// A decoded frame header.
#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub flags: u16,
    pub id: u32,
    /// Payload length, or for yamux window updates, pings and go-aways the
    /// header's value field (no payload follows).
    pub len: u32,
}

pub fn decode(proto: Proto, h: &[u8]) -> io::Result<Header> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("{proto:?}: {m}"));
    match proto {
        Proto::Smux => {
            if h[0] != SMUX_VERSION {
                return Err(bad("unsupported version"));
            }
            Ok(Header {
                kind: h[1],
                flags: 0,
                len: u16::from_le_bytes([h[2], h[3]]) as u32,
                id: u32::from_le_bytes([h[4], h[5], h[6], h[7]]),
            })
        }
        Proto::Yamux => {
            if h[0] != 0 {
                return Err(bad("unsupported version"));
            }
            if h[1] > YAMUX_GO_AWAY {
                return Err(bad("unknown frame type"));
            }
            Ok(Header {
                kind: h[1],
                flags: u16::from_be_bytes([h[2], h[3]]),
                id: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
                len: u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
            })
        }
    }
}

#[derive(Default)]
struct StreamState {
    queue: VecDeque<Bytes>,
    eof: bool,
    error: Option<String>,
    read_waker: Option<Waker>,
    /// yamux: what the peer may still send, what it may receive, read
    /// bytes not yet granted back, and whether it acknowledged the open.
    recv_window: u32,
    send_window: u32,
    consumed: u32,
    acked: bool,
    write_waker: Option<Waker>,
}

impl StreamState {
    fn fail(&mut self, e: &str) {
        self.error.get_or_insert_with(|| e.to_owned());
        self.wake();
    }

    fn wake(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
}

type Shared = Arc<Mutex<StreamState>>;

pub struct Session {
    proto: Proto,
    writer: tokio::sync::Mutex<WriteHalf<SessionConn>>,
    streams: Mutex<HashMap<u32, Shared>>,
    next_id: AtomicU32,
    closed: AtomicBool,
    /// yamux: the server said go away; no new streams.
    draining: AtomicBool,
    reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// smux: bytes queued unread, across streams.
    budget: Semaphore,
    ping_pending: AtomicBool,
}

impl Session {
    pub fn new(conn: SessionConn, proto: Proto) -> Arc<Self> {
        let (r, w) = tokio::io::split(conn);
        let s = Arc::new(Self {
            proto,
            writer: tokio::sync::Mutex::new(w),
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            reader: Mutex::new(None),
            budget: Semaphore::new(SESSION_BUDGET),
            ping_pending: AtomicBool::new(false),
        });
        let t = tokio::spawn(s.clone().read_loop(r));
        *s.reader.lock().unwrap() = Some(t);
        s
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn can_take_new(&self) -> bool {
        !self.is_closed()
            && !self.draining.load(Ordering::Acquire)
            && self.streams.lock().unwrap().len() < max_streams(self.proto)
    }

    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(t) = self.reader.lock().unwrap().take() {
            t.abort();
        }
        self.fail_all();
    }

    fn fail_all(&self) {
        for (_, s) in self.streams.lock().unwrap().drain() {
            s.lock().unwrap().fail("mux: session closed");
        }
    }

    async fn write(&self, frame: &[u8]) -> io::Result<()> {
        let mut w = self.writer.lock().await;
        let r = async {
            w.write_all(frame).await?;
            w.flush().await
        }
        .await;
        drop(w);
        if r.is_err() {
            self.close();
        }
        r
    }

    async fn control(&self, kind: u8, flags: u16, id: u32, value: u32) -> io::Result<()> {
        let mut f = Vec::with_capacity(12);
        header(&mut f, self.proto, kind, flags, id, value);
        self.write(&f).await
    }

    /// Open a stream; its SYN is on the wire when this returns.
    pub async fn open(self: &Arc<Self>) -> io::Result<FrameStream> {
        if !self.can_take_new() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "mux: session is closing"));
        }
        // smux clients use odd IDs from 3, yamux from 1.
        let id = match self.proto {
            Proto::Smux => self.next_id.fetch_add(2, Ordering::AcqRel) + 2,
            Proto::Yamux => self.next_id.fetch_add(2, Ordering::AcqRel),
        };
        if id > u32::MAX - 2 {
            self.draining.store(true, Ordering::Release);
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "mux: stream IDs exhausted"));
        }
        let state: Shared = Arc::new(Mutex::new(StreamState {
            recv_window: YAMUX_WINDOW,
            send_window: YAMUX_WINDOW,
            ..Default::default()
        }));
        self.streams.lock().unwrap().insert(id, state.clone());
        let mut syn = Vec::with_capacity(12);
        match self.proto {
            Proto::Smux => header(&mut syn, self.proto, SMUX_SYN, 0, id, 0),
            Proto::Yamux => header(&mut syn, self.proto, YAMUX_WINDOW_UPDATE, FLAG_SYN, id, 0),
        }
        // Waiting for the writer is bounded (a dead connection holds it
        // forever); the write itself is not, since half a frame would
        // corrupt the session.
        let r = match tokio::time::timeout(OPEN_TIMEOUT, self.writer.lock()).await {
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "mux: session writer stalled")),
            Ok(mut w) => {
                let r = async {
                    w.write_all(&syn).await?;
                    w.flush().await
                }
                .await;
                drop(w);
                if r.is_err() {
                    self.close();
                }
                r
            }
        };
        if let Err(e) = r {
            self.streams.lock().unwrap().remove(&id);
            return Err(e);
        }
        if self.proto == Proto::Yamux {
            let me = Arc::downgrade(self);
            let st = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(OPEN_TIMEOUT).await;
                if !st.lock().unwrap().acked
                    && let Some(s) = me.upgrade()
                    && s.streams.lock().unwrap().contains_key(&id)
                {
                    debug!("yamux: stream open not acknowledged, closing session");
                    s.close();
                }
            });
        }
        Ok(FrameStream {
            session: self.clone(),
            id,
            state,
            chunk: Bytes::new(),
            write: None,
            wbuf: None,
            fin_sent: false,
        })
    }

    async fn read_loop(self: Arc<Self>, r: ReadHalf<SessionConn>) {
        let mut r = BufReader::with_capacity(16 * 1024, r);
        let res = match self.proto {
            Proto::Smux => self.read_smux(&mut r).await,
            Proto::Yamux => self.read_yamux(&mut r).await,
        };
        if let Err(e) = res
            && !self.is_closed()
        {
            debug!(error = %e, proto = ?self.proto, "mux: session ended");
        }
        self.closed.store(true, Ordering::Release);
        self.fail_all();
    }

    fn stream(&self, id: u32) -> Option<Shared> {
        self.streams.lock().unwrap().get(&id).cloned()
    }

    async fn read_smux<R: AsyncRead + Unpin>(&self, r: &mut R) -> io::Result<()> {
        let mut buf = BytesMut::new();
        loop {
            let mut h = [0u8; 8];
            if r.read(&mut h[..1]).await? == 0 {
                return Ok(());
            }
            r.read_exact(&mut h[1..]).await?;
            let h = decode(Proto::Smux, &h)?;
            match h.kind {
                SMUX_NOP | SMUX_SYN => {}
                SMUX_FIN => {
                    if let Some(s) = self.stream(h.id) {
                        let mut s = s.lock().unwrap();
                        s.eof = true;
                        s.wake();
                    }
                }
                SMUX_PSH => {
                    let len = h.len as usize;
                    if len == 0 {
                        continue;
                    }
                    buf.resize(len, 0);
                    r.read_exact(&mut buf[..len]).await?;
                    let data = buf.split_to(len).freeze();
                    let Some(s) = self.stream(h.id) else { continue };
                    // Waiting here is the session-wide backpressure.
                    self.budget
                        .acquire_many(len as u32)
                        .await
                        .map_err(|_| io::Error::other("closed"))?
                        .forget();
                    let mut s = s.lock().unwrap();
                    if s.error.is_some() {
                        self.budget.add_permits(len);
                        continue;
                    }
                    s.queue.push_back(data);
                    s.wake();
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "smux: unknown command")),
            }
        }
    }

    async fn read_yamux<R: AsyncRead + Unpin>(self: &Arc<Self>, r: &mut R) -> io::Result<()> {
        let mut buf = BytesMut::new();
        loop {
            let mut h = [0u8; 12];
            if r.read(&mut h[..1]).await? == 0 {
                return Ok(());
            }
            r.read_exact(&mut h[1..]).await?;
            let h = decode(Proto::Yamux, &h)?;
            match h.kind {
                YAMUX_DATA | YAMUX_WINDOW_UPDATE => {
                    let s = self.stream(h.id);
                    if h.flags & FLAG_SYN != 0 && s.is_none() {
                        // The server never opens streams to a client.
                        let me = self.clone();
                        tokio::spawn(async move { me.control(YAMUX_WINDOW_UPDATE, FLAG_RST, h.id, 0).await });
                    }
                    let data = if h.kind == YAMUX_DATA && h.len > 0 {
                        let len = h.len as usize;
                        if len > YAMUX_WINDOW as usize {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "yamux: frame over window"));
                        }
                        buf.resize(len, 0);
                        r.read_exact(&mut buf[..len]).await?;
                        Some(buf.split_to(len).freeze())
                    } else {
                        None
                    };
                    let Some(s) = s else { continue };
                    let mut s = s.lock().unwrap();
                    if h.flags & FLAG_ACK != 0 {
                        s.acked = true;
                    }
                    if h.kind == YAMUX_WINDOW_UPDATE {
                        s.send_window = s.send_window.saturating_add(h.len);
                    }
                    if let Some(d) = data {
                        let n = d.len() as u32;
                        if n > s.recv_window {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "yamux: peer exceeded window",
                            ));
                        }
                        s.recv_window -= n;
                        s.queue.push_back(d);
                    }
                    if h.flags & FLAG_FIN != 0 {
                        s.eof = true;
                    }
                    if h.flags & FLAG_RST != 0 {
                        s.fail("yamux: stream reset by peer");
                    }
                    s.wake();
                }
                YAMUX_PING => {
                    if h.flags & FLAG_SYN != 0 && !self.ping_pending.swap(true, Ordering::AcqRel) {
                        let me = self.clone();
                        tokio::spawn(async move {
                            let _ = me.control(YAMUX_PING, FLAG_ACK, 0, h.len).await;
                            me.ping_pending.store(false, Ordering::Release);
                        });
                    }
                }
                _ => self.draining.store(true, Ordering::Release), // go away
            }
        }
    }
}

type WriteFut = Pin<Box<dyn Future<Output = (io::Result<()>, Vec<u8>)> + Send>>;

pub struct FrameStream {
    session: Arc<Session>,
    id: u32,
    state: Shared,
    chunk: Bytes,
    write: Option<(WriteFut, usize)>,
    wbuf: Option<Vec<u8>>,
    fin_sent: bool,
}

impl FrameStream {
    fn start(&mut self, kind: u8, flags: u16, data: &[u8]) {
        let mut buf = self.wbuf.take().unwrap_or_default();
        buf.clear();
        header(&mut buf, self.session.proto, kind, flags, self.id, data.len() as u32);
        buf.extend_from_slice(data);
        let session = self.session.clone();
        let fut = async move {
            let r = session.write(&buf).await;
            (r, buf)
        };
        self.write = Some((Box::pin(fut), data.len()));
    }

    fn poll_done(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some((fut, n)) = self.write.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        let (r, buf) = ready!(fut.as_mut().poll(cx));
        let n = *n;
        self.write = None;
        self.wbuf = Some(buf);
        Poll::Ready(r.map(|_| n))
    }

    /// Account for `n` bytes the application consumed.
    fn consumed(&self, s: &mut StreamState, n: usize) {
        match self.session.proto {
            Proto::Smux => self.session.budget.add_permits(n),
            Proto::Yamux => {
                s.consumed += n as u32;
                if s.consumed >= YAMUX_WINDOW / 2 && !s.eof && s.error.is_none() {
                    let delta = std::mem::take(&mut s.consumed);
                    s.recv_window += delta;
                    let (session, id) = (self.session.clone(), self.id);
                    tokio::spawn(async move { session.control(YAMUX_WINDOW_UPDATE, 0, id, delta).await });
                }
            }
        }
    }
}

impl AsyncRead for FrameStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.chunk.is_empty() {
            let state = this.state.clone();
            let mut s = state.lock().unwrap();
            match s.queue.pop_front() {
                Some(c) => this.chunk = c,
                None if s.eof => return Poll::Ready(Ok(())),
                None if s.error.is_some() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        s.error.clone().unwrap_or_default(),
                    )));
                }
                None => {
                    s.read_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
        let n = this.chunk.len().min(buf.remaining());
        buf.put_slice(&this.chunk.split_to(n));
        let state = this.state.clone();
        this.consumed(&mut state.lock().unwrap(), n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FrameStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write.is_some() {
            return this.poll_done(cx);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut n = buf.len().min(MAX_FRAME);
        {
            let mut s = this.state.lock().unwrap();
            if let Some(e) = &s.error {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e.clone())));
            }
            if this.fin_sent {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if this.session.proto == Proto::Yamux {
                if s.send_window == 0 {
                    s.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                n = n.min(s.send_window as usize);
                s.send_window -= n as u32;
            }
        }
        let kind = match this.session.proto {
            Proto::Smux => SMUX_PSH,
            Proto::Yamux => YAMUX_DATA,
        };
        this.start(kind, 0, &buf[..n]);
        this.poll_done(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.get_mut().poll_done(cx))?;
        Poll::Ready(Ok(()))
    }

    /// yamux half-closes with FIN. smux v1's FIN closes both directions, so
    /// a shutdown sends nothing there (sing-mux gives smux streams no
    /// CloseWrite) and the FIN goes out when the stream is dropped.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_done(cx))?;
        if this.session.proto == Proto::Yamux && !this.fin_sent && !this.session.is_closed() {
            this.fin_sent = true;
            this.start(YAMUX_WINDOW_UPDATE, FLAG_FIN, &[]);
            ready!(this.poll_done(cx))?;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for FrameStream {
    fn drop(&mut self) {
        let removed = self.session.streams.lock().unwrap().remove(&self.id).is_some();
        let (eof, unread) = {
            let mut s = self.state.lock().unwrap();
            let unread: usize = s.queue.drain(..).map(|b| b.len()).sum::<usize>() + self.chunk.len();
            (s.eof, unread)
        };
        if self.session.proto == Proto::Smux {
            self.session.budget.add_permits(unread);
        }
        if !removed || self.session.is_closed() {
            return;
        }
        // yamux: a stream dropped before the peer finished is reset, so the
        // server stops sending into it.
        let frame = match self.session.proto {
            Proto::Smux => Some((SMUX_FIN, 0)),
            Proto::Yamux if !eof => Some((YAMUX_WINDOW_UPDATE, FLAG_RST)),
            Proto::Yamux if !self.fin_sent => Some((YAMUX_WINDOW_UPDATE, FLAG_FIN)),
            Proto::Yamux => None,
        };
        let in_flight = self.write.take();
        let (session, id) = (self.session.clone(), self.id);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Some((f, _)) = in_flight {
                    let _ = f.await;
                }
                if let Some((kind, flags)) = frame {
                    let _ = session.control(kind, flags, id, 0).await;
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_round_trip() {
        for proto in [Proto::Smux, Proto::Yamux] {
            let mut b = Vec::new();
            header(
                &mut b,
                proto,
                2,
                if proto == Proto::Yamux { FLAG_FIN } else { 0 },
                7,
                300,
            );
            assert_eq!(b.len(), if proto == Proto::Smux { 8 } else { 12 });
            let h = decode(proto, &b).unwrap();
            assert_eq!((h.kind, h.id, h.len), (2, 7, 300));
        }
        // xtaci/smux: [ver][cmd][len LE][sid LE].
        let mut b = Vec::new();
        header(&mut b, Proto::Smux, SMUX_PSH, 0, 3, 5);
        assert_eq!(b, [1, 2, 5, 0, 3, 0, 0, 0]);
        // hashicorp/yamux: [ver][type][flags BE][id BE][len BE].
        let mut b = Vec::new();
        header(&mut b, Proto::Yamux, YAMUX_WINDOW_UPDATE, FLAG_SYN, 1, 0);
        assert_eq!(b, [0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn bad_headers_are_refused() {
        assert!(decode(Proto::Smux, &[2, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode(Proto::Yamux, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode(Proto::Yamux, &[0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
