//! sing-mux (sing-box `multiplex`): application streams carried inside a
//! few long-lived proxy connections. A session is a connection through the
//! wrapped outbound to `sp.mux.sing-box.arpa:444`, which the server
//! recognises; each stream on it opens with `[u16 flags][socks address]`
//! and the server answers with a status byte before any data.
//!
//! Sessions are chosen as sing-mux's `Client.selectSession` does, except
//! that one with no streams for `IDLE_TIMEOUT` is closed: hashicorp yamux
//! servers ping idle sessions every 30 s, an idle smux session dies
//! silently behind NAT, and the h2mux server closes idle ones after 30 s
//! anyway.

mod conn;
mod frames;
mod h2mux;

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use sbr_config::Multiplex;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Host, Outbound, PacketConn, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf, ReadHalf, WriteHalf};
use tracing::debug;

use super::idle::Idle;
use super::proto::{HeaderStream, Response, put_socks_addr, read_socks_addr};
use conn::SessionConn;
use frames::Proto;

/// sing-mux `TCPTimeout`: dialing a session, and opening a stream.
const TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Under the h2mux server's own 30 s idle close, so a stream is never sent
/// into a session the server is about to close.
const H2_IDLE_TIMEOUT: Duration = Duration::from_secs(25);
const SESSION_HOST: &str = "sp.mux.sing-box.arpa";
const SESSION_PORT: u16 = 444;
const BRUTAL_HOST: &str = "_BrutalBwExchange";
/// Longest error message accepted in a stream or brutal response.
const MAX_MESSAGE: usize = 1024;

const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Protocol {
    Smux,
    Yamux,
    H2Mux,
}

impl Protocol {
    fn id(self) -> u8 {
        match self {
            Self::Smux => conn::PROTOCOL_SMUX,
            Self::Yamux => conn::PROTOCOL_YAMUX,
            Self::H2Mux => conn::PROTOCOL_H2MUX,
        }
    }
}

enum Sess {
    Frames(Arc<frames::Session>),
    H2(h2mux::Session),
}

struct Entry {
    sess: Sess,
    /// Streams open on this session, as sing-mux counts them.
    idle: Arc<Idle>,
}

impl Entry {
    fn is_closed(&self) -> bool {
        match &self.sess {
            Sess::Frames(s) => s.is_closed(),
            Sess::H2(s) => s.is_closed(),
        }
    }

    fn can_take_new(&self) -> bool {
        match &self.sess {
            Sess::Frames(s) => s.can_take_new(),
            Sess::H2(s) => s.can_take_new(),
        }
    }

    fn close(&self) {
        match &self.sess {
            Sess::Frames(s) => s.close(),
            Sess::H2(s) => s.close(),
        }
    }

    async fn open(&self) -> io::Result<Stream> {
        Ok(match &self.sess {
            Sess::Frames(s) => Box::new(s.open().await?),
            Sess::H2(s) => {
                let guard = s.track();
                Box::new(Guarded {
                    s: Box::new(s.open().await?),
                    _guard: guard,
                })
            }
        })
    }
}

struct Client {
    inner: Arc<dyn Outbound>,
    protocol: Protocol,
    padding: bool,
    max_connections: usize,
    min_streams: usize,
    max_streams: usize,
    /// Brutal `(send, receive)` in bytes per second.
    brutal: Option<(u64, u64)>,
    sessions: Mutex<Vec<Arc<Entry>>>,
    /// Serialises session creation, as sing-mux's client lock does.
    dialing: tokio::sync::Mutex<()>,
    /// Session dials finished, and the last one that failed.
    dials_done: AtomicU64,
    failure: Mutex<Option<(u64, io::ErrorKind, String)>>,
}

pub struct Mux {
    client: Arc<Client>,
    tcp: bool,
    udp: bool,
}

impl Mux {
    pub fn new(inner: Arc<dyn Outbound>, m: &Multiplex, tcp: bool, udp: bool) -> Self {
        let protocol = match m.protocol.as_deref() {
            Some("smux") => Protocol::Smux,
            Some("yamux") => Protocol::Yamux,
            _ => Protocol::H2Mux,
        };
        Self {
            client: Arc::new(Client {
                inner,
                protocol,
                padding: m.padding,
                max_connections: m.max_connections as usize,
                min_streams: m.min_streams as usize,
                max_streams: m.max_streams as usize,
                brutal: m.brutal.map(|(up, down)| (up as u64 * 125_000, down as u64 * 125_000)),
                sessions: Mutex::new(Vec::new()),
                dialing: tokio::sync::Mutex::new(()),
                dials_done: AtomicU64::new(0),
                failure: Mutex::new(None),
            }),
            tcp,
            udp,
        }
    }
}

impl Client {
    /// sing-mux `selectSession`.
    fn select(&self, sessions: &[Arc<Entry>]) -> Option<Arc<Entry>> {
        if self.brutal.is_some() {
            return sessions.iter().find(|e| e.can_take_new()).cloned();
        }
        let best = sessions
            .iter()
            .filter(|e| e.can_take_new())
            .min_by_key(|e| e.idle.users())?;
        let streams = best.idle.users();
        let take = streams == 0
            || if self.max_connections > 0 {
                sessions.len() >= self.max_connections || streams < self.min_streams
            } else {
                self.max_streams > 0 && streams < self.max_streams
            };
        take.then(|| best.clone())
    }

    /// A session with a stream counted against it.
    async fn offer(self: &Arc<Self>) -> io::Result<StreamGuard> {
        let seen = self.dials_done.load(Ordering::Acquire);
        let _dialing = self.dialing.lock().await;
        let picked = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|e| {
                let closed = e.is_closed();
                if closed {
                    e.close();
                }
                !closed
            });
            let picked = self.select(&sessions);
            // Counted under the lock the idle close takes, so a session is
            // never closed between being picked and being used.
            if let Some(e) = &picked {
                e.idle.acquire();
            }
            picked
        };
        let entry = match picked {
            Some(e) => e,
            None => {
                // A dial that failed while this caller waited answers it too,
                // so queued connects on a dead path don't each wait a timeout.
                if let Some((n, kind, msg)) = &*self.failure.lock().unwrap()
                    && *n > seen
                {
                    return Err(io::Error::new(*kind, msg.clone()));
                }
                let r = tokio::time::timeout(TIMEOUT, self.new_session())
                    .await
                    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "mux: session dial timed out")));
                let n = self.dials_done.fetch_add(1, Ordering::AcqRel) + 1;
                let e = match r {
                    Ok(e) => e,
                    Err(e) => {
                        *self.failure.lock().unwrap() = Some((n, e.kind(), e.to_string()));
                        return Err(e);
                    }
                };
                e.idle.acquire();
                self.sessions.lock().unwrap().push(e.clone());
                e
            }
        };
        Ok(StreamGuard {
            entry,
            client: Arc::downgrade(self),
        })
    }

    async fn new_session(&self) -> io::Result<Arc<Entry>> {
        let dest = Destination::new(Host::Domain(SESSION_HOST.into()), SESSION_PORT);
        let raw = self.inner.connect(&dest).await?;
        let conn = SessionConn::new(raw, self.protocol.id(), self.padding);
        let sess = match self.protocol {
            Protocol::Smux => Sess::Frames(frames::Session::new(conn, Proto::Smux)),
            Protocol::Yamux => Sess::Frames(frames::Session::new(conn, Proto::Yamux)),
            Protocol::H2Mux => Sess::H2(h2mux::Session::new(conn).await?),
        };
        let entry = Arc::new(Entry {
            sess,
            idle: Arc::default(),
        });
        if let Some((send, receive)) = self.brutal
            && let Err(e) = brutal_exchange(&entry, send, receive).await
        {
            entry.close();
            return Err(io::Error::new(e.kind(), format!("mux: brutal exchange: {e}")));
        }
        Ok(entry)
    }

    /// A raw stream on some session, trying once more if the session fails
    /// to open one, as sing-mux's `openStream` does. A session that failed is
    /// left to its own checks (closed, draining, unacknowledged SYN), which
    /// keep the retry from picking it again.
    async fn open_stream(self: &Arc<Self>) -> io::Result<Stream> {
        let mut last = None;
        for _ in 0..2 {
            // A failed dial is final: a second one would fail the same way.
            let guard = self.offer().await?;
            // Not cancelled by a timeout: a frame half written would corrupt
            // the session. A failure leaves the session to its own checks
            // (closed, SYN not acknowledged, idle), since other streams on
            // it may be fine.
            match guard.entry.open().await {
                Ok(s) => return Ok(Box::new(Guarded { s, _guard: guard })),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("mux: no session")))
    }

    async fn stream(self: &Arc<Self>, flags: u16, dest: &Destination) -> io::Result<Stream> {
        let raw = self.open_stream().await?;
        let mut header = Vec::with_capacity(2 + 1 + 1 + 255 + 2);
        header.extend_from_slice(&flags.to_be_bytes());
        put_socks_addr(&mut header, dest);
        Ok(Box::new(StatusStream::new(HeaderStream::new(
            raw,
            header,
            Response::None,
        ))))
    }
}

impl Drop for Client {
    /// Idle sessions close now; busy ones when their last stream ends.
    fn drop(&mut self) {
        for e in self.sessions.get_mut().unwrap().drain(..) {
            if e.idle.users() == 0 {
                e.close();
            }
        }
    }
}

/// sing-mux `brutalExchange`: tell the server what we can receive. The
/// client side of TCP Brutal (a Linux congestion control module) is not
/// set: the wrapped outbound does not expose its socket.
async fn brutal_exchange(entry: &Entry, send: u64, receive: u64) -> io::Result<()> {
    let raw = entry.open().await?;
    let mut header = vec![0, 0];
    put_socks_addr(&mut header, &Destination::new(Host::Domain(BRUTAL_HOST.into()), 0));
    let mut s = StatusStream::new(HeaderStream::new(raw, header, Response::None));
    tokio::time::timeout(TIMEOUT, async {
        s.write_all(&receive.to_be_bytes()).await?;
        s.flush().await?;
        if s.read_u8().await? == 0 {
            return Err(io::Error::other(format!("remote: {}", read_message(&mut s).await?)));
        }
        let server_receive = s.read_u64().await?;
        debug!(send = send.min(server_receive), "mux: brutal speed agreed");
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out"))?
}

/// The length prefix of a sing `varbin` string at the start of `b`:
/// `Ok(Some((length, prefix bytes)))`, `Ok(None)` while incomplete, or the
/// reason it is refused (more than 3 bytes, or over `MAX_MESSAGE`).
fn varbin_len(b: &[u8]) -> Result<Option<(usize, usize)>, &'static str> {
    let mut len = 0usize;
    for (i, &byte) in b.iter().enumerate().take(3) {
        len |= ((byte & 0x7f) as usize) << (7 * i);
        if byte & 0x80 == 0 {
            return if len > MAX_MESSAGE {
                Err("mux: error message too long")
            } else {
                Ok(Some((len, i + 1)))
            };
        }
    }
    if b.len() >= 3 {
        Err("mux: malformed error response")
    } else {
        Ok(None)
    }
}

/// sing `varbin` string: uvarint length, then bytes.
async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<String> {
    let mut prefix = Vec::with_capacity(3);
    let len = loop {
        prefix.push(r.read_u8().await?);
        match varbin_len(&prefix) {
            Ok(Some((len, _))) => break len,
            Ok(None) => continue,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    };
    let mut b = vec![0u8; len];
    r.read_exact(&mut b).await?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Counts a stream against its session until dropped; the last one out
/// starts the session's idle close.
struct StreamGuard {
    entry: Arc<Entry>,
    client: Weak<Client>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        if !self.entry.idle.release() {
            return;
        }
        let Some(client) = self.client.upgrade() else {
            self.entry.close();
            return;
        };
        let (entry, client) = (Arc::downgrade(&self.entry), Arc::downgrade(&client));
        let timeout = match self.entry.sess {
            Sess::H2(_) => H2_IDLE_TIMEOUT,
            Sess::Frames(_) => IDLE_TIMEOUT,
        };
        self.entry.idle.arm(timeout, move || {
            let Some(e) = entry.upgrade() else { return };
            if let Some(c) = client.upgrade() {
                let mut sessions = c.sessions.lock().unwrap();
                if e.idle.users() > 0 {
                    return;
                }
                sessions.retain(|x| !Arc::ptr_eq(x, &e));
            }
            e.close();
        });
    }
}

/// A stream that holds `_guard` for as long as it lives.
struct Guarded<G> {
    s: Stream,
    _guard: G,
}

impl<G: Unpin> AsyncRead for Guarded<G> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_read(cx, buf)
    }
}

impl<G: Unpin> AsyncWrite for Guarded<G> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.s).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_shutdown(cx)
    }
}

/// Strips the server's stream response (`0`, or `1` and a message) before
/// the first data.
struct StatusStream<S> {
    inner: S,
    /// Response bytes read so far: status, then the message's length
    /// varint and the message itself.
    resp: Vec<u8>,
    done: bool,
}

impl<S> StatusStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            resp: Vec::new(),
            done: false,
        }
    }
}

/// The error a complete response carries, `Ok(None)` for success, or
/// `Err(())` while more bytes are needed.
fn parse_response(b: &[u8]) -> Result<Option<String>, ()> {
    match b.first() {
        None => Err(()),
        Some(0) => Ok(None),
        Some(_) => match varbin_len(&b[1..]) {
            Err(e) => Ok(Some(e.into())),
            Ok(None) => Err(()),
            Ok(Some((len, n))) => {
                let msg = b.get(1 + n..1 + n + len).ok_or(())?;
                Ok(Some(String::from_utf8_lossy(msg).into_owned()))
            }
        },
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for StatusStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while !this.done {
            // One byte at a time: nothing past the response is consumed.
            let mut b = [0u8; 1];
            let mut rb = ReadBuf::new(&mut b);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.resp.push(b[0]);
            match parse_response(&this.resp) {
                Err(()) => continue,
                Ok(None) => {
                    this.done = true;
                    this.resp = Vec::new();
                }
                Ok(Some(e)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("mux: remote: {e}"),
                    )));
                }
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StatusStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// UDP over a mux stream, full-cone: every packet is
/// `[socks address][u16 length][payload]` (sing-mux packet-addr mode).
struct MuxPacket {
    reader: tokio::sync::Mutex<BufReader<ReadHalf<Stream>>>,
    writer: tokio::sync::Mutex<(WriteHalf<Stream>, Vec<u8>)>,
}

impl MuxPacket {
    async fn send(&self, payload: &[u8], dest: &Destination) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"));
        }
        let mut w = self.writer.lock().await;
        let (half, buf) = &mut *w;
        buf.clear();
        put_socks_addr(buf, dest);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(payload);
        half.write_all(buf).await?;
        half.flush().await
    }

    async fn recv(&self, out: &mut [u8]) -> io::Result<(usize, Destination)> {
        let mut r = self.reader.lock().await;
        loop {
            let from = read_socks_addr(&mut *r).await?;
            let len = r.read_u16().await? as usize;
            if len > out.len() {
                // Too big for the caller: skip it, keep the framing.
                let skipped = tokio::io::copy(&mut (&mut *r).take(len as u64), &mut tokio::io::sink()).await?;
                if skipped < len as u64 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                continue;
            }
            r.read_exact(&mut out[..len]).await?;
            return Ok((len, from));
        }
    }
}

struct MuxPacketHandle(MuxPacket);

impl PacketConn for MuxPacketHandle {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.0.send(buf, dest))
    }
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(self.0.recv(buf))
    }
}

fn disabled(net: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("{net} is disabled by `network`"))
}

impl Outbound for Mux {
    fn tag(&self) -> &str {
        self.client.inner.tag()
    }

    fn kind(&self) -> &'static str {
        self.client.inner.kind()
    }

    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if !self.tcp {
                return Err(disabled("tcp"));
            }
            self.client.stream(0, dest).await
        })
    }

    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            if !self.udp {
                return Err(disabled("udp"));
            }
            let s = self.client.stream(FLAG_UDP | FLAG_ADDR, dest).await?;
            let (r, w) = tokio::io::split(s);
            Ok(Box::new(MuxPacketHandle(MuxPacket {
                reader: tokio::sync::Mutex::new(BufReader::with_capacity(16 * 1024, r)),
                writer: tokio::sync::Mutex::new((w, Vec::with_capacity(2048))),
            })) as BoxPacketConn)
        })
    }

    fn probe_rtt(&self) -> Option<BoxFuture<'_, io::Result<Duration>>> {
        self.client.inner.probe_rtt()
    }

    fn network_changed(&self) {
        for e in self.client.sessions.lock().unwrap().drain(..) {
            e.close();
        }
        self.client.inner.network_changed();
    }
}

/// Fuzzing entry point: `data[0]` picks smux or yamux and padding, the rest
/// is everything the server sends to a client session with one stream open.
#[doc(hidden)]
pub async fn fuzz_session(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let (proto, id) = match sel & 1 {
        0 => (Proto::Smux, conn::PROTOCOL_SMUX),
        _ => (Proto::Yamux, conn::PROTOCOL_YAMUX),
    };
    let _ = parse_response(rest);
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (mut sr, mut sw) = tokio::io::split(server);
    let input = rest.to_vec();
    tokio::spawn(async move {
        let _ = sw.write_all(&input).await;
    });
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut sr, &mut tokio::io::sink()).await;
    });
    let session = frames::Session::new(SessionConn::new(Box::new(client), id, sel & 2 != 0), proto);
    let Ok(s) = session.open().await else { return };
    let mut s = StatusStream::new(s);
    let _ = s.write_all(b"hello").await;
    let mut buf = [0u8; 4096];
    while let Ok(n) = s.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
    session.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses() {
        assert_eq!(parse_response(&[]), Err(()));
        assert_eq!(parse_response(&[0]), Ok(None));
        assert_eq!(parse_response(&[1]), Err(()));
        assert_eq!(parse_response(&[1, 2, b'n']), Err(()));
        assert_eq!(parse_response(&[1, 2, b'n', b'o']), Ok(Some("no".into())));
        // A length over the cap is refused without waiting for the bytes.
        assert_eq!(
            parse_response(&[1, 0xff, 0x7f]),
            Ok(Some("mux: error message too long".into()))
        );
    }
}
