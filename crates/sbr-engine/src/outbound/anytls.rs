//! AnyTLS client (sing-anytls, protocol version 2).
//!
//! A session is one TLS connection carrying many streams as frames
//! `cmd(1) stream(4) length(2) data`. The first packets of a session are
//! shaped by a padding scheme (sizes per packet, "c" checkpoints, waste
//! frames) that the server may replace. Finished sessions return to an idle
//! pool and are reused, most recent first.
//!
//! Power: the pool has no periodic check. One task sleeps until the oldest
//! surplus idle session expires and exits once only `min_idle_session`
//! sessions remain, so an idle pool costs no wakeups.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use bytes::{Bytes, BytesMut};
use md5::Digest as _;
use sbr_config::AnyTlsOutbound;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Outbound, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::debug;

use super::Upstream;
use super::tlsmini::TlsClient;
use crate::socks5;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const PROTOCOL_VERSION: u32 = 2;
const FRAME_OVERHEAD: usize = 7;
const MAX_FRAME: usize = 0xffff;
/// Bounds on a padding scheme, which the server may replace at any time: it
/// must not be able to make the client upload unbounded padding. The default
/// scheme pads 8 packets with at most 4 ranges each.
const MAX_PADDING_PACKETS: u32 = 64;
const MAX_PADDING_RANGES: usize = 16;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_IDLE_INTERVAL: Duration = Duration::from_secs(5);
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(3);
/// Frames buffered per stream before the session reader waits (backpressure).
const STREAM_QUEUE: usize = 32;

pub const DEFAULT_PADDING_SCHEME: &str = "stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

/// `-1` marks a "c" checkpoint.
const CHECK: i64 = -1;

pub struct Padding {
    md5_hex: String,
    stop: u32,
    records: HashMap<u32, Vec<(i64, i64)>>,
}

impl Padding {
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut kv = HashMap::new();
        for line in text.split('\n') {
            if let Some((k, v)) = line.split_once('=') {
                kv.insert(k, v);
            }
        }
        if kv.is_empty() {
            return None;
        }
        // Go converts with an unchecked uint32 cast: negative means "never stop".
        let stop: i64 = kv.get("stop")?.parse().ok()?;
        let mut records = HashMap::new();
        for (k, v) in &kv {
            let Ok(n) = k.parse::<u32>() else { continue };
            if n.to_string() != *k {
                continue;
            }
            let mut ranges = Vec::new();
            for item in v.split(',') {
                if item == "c" {
                    ranges.push((CHECK, CHECK));
                    continue;
                }
                let Some((a, b)) = item.split_once('-') else { continue };
                let (Ok(mut a), Ok(mut b)) = (a.parse::<i64>(), b.parse::<i64>()) else {
                    continue;
                };
                if a > b {
                    std::mem::swap(&mut a, &mut b);
                }
                if a <= 0 || b > MAX_FRAME as i64 {
                    continue;
                }
                if ranges.len() < MAX_PADDING_RANGES {
                    ranges.push((a, b));
                }
            }
            if !ranges.is_empty() {
                records.insert(n, ranges);
            }
        }
        Some(Self {
            md5_hex: hex(&md5::Md5::digest(raw)),
            stop: (stop as u32).min(MAX_PADDING_PACKETS),
            records,
        })
    }

    fn sizes(&self, packet: u32) -> Vec<i64> {
        let Some(ranges) = self.records.get(&packet) else {
            return Vec::new();
        };
        ranges
            .iter()
            .map(|&(a, b)| match (a, b) {
                (CHECK, _) => CHECK,
                (a, b) if b > a => a + (random_u64() % (b - a) as u64) as i64,
                (a, _) => a,
            })
            .collect()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random_u64() -> u64 {
    use aws_lc_rs::rand::SecureRandom;
    let mut b = [0u8; 8];
    aws_lc_rs::rand::SystemRandom::new().fill(&mut b).expect("system RNG");
    u64::from_le_bytes(b)
}

fn frame_header(buf: &mut Vec<u8>, cmd: u8, stream: u32, len: usize) {
    buf.push(cmd);
    buf.extend_from_slice(&stream.to_be_bytes());
    buf.extend_from_slice(&(len as u16).to_be_bytes());
}

/// Sorted `key=value` lines, as Go's `settings.Bytes`.
fn settings(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut v: Vec<_> = pairs.to_vec();
    v.sort();
    v.iter()
        .map(|(k, val)| format!("{k}={val}"))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn parse_settings(b: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(b)
        .split('\n')
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect()
}

type Tls = TlsStream<Stream>;

struct Writer {
    w: WriteHalf<Tls>,
    /// The settings frame, sent in front of the first request.
    pending: Option<Vec<u8>>,
    send_padding: bool,
    packet_count: u32,
    record: Vec<u8>,
}

impl Writer {
    /// `writeLocked`: flush the pending settings together with `data`.
    async fn write(&mut self, data: &[u8], padding: &Padding) -> io::Result<()> {
        match self.pending.take() {
            Some(mut p) => {
                p.extend_from_slice(data);
                self.write_packet(&p, padding).await
            }
            None => self.write_packet(data, padding).await,
        }
    }

    /// `writePacketLocked`, flushed: tokio-rustls accepts plaintext while the
    /// socket is full and keeps the sealed records until the next write or
    /// flush. Nothing else flushes the session (`AnyStream::poll_flush` only
    /// waits for its own write), so without this the tail of an upload could
    /// sit in rustls indefinitely.
    async fn write_packet(&mut self, data: &[u8], padding: &Padding) -> io::Result<()> {
        self.shape_packet(data, padding).await?;
        self.w.flush().await
    }

    /// Shape one logical packet by the padding scheme.
    async fn shape_packet(&mut self, mut data: &[u8], padding: &Padding) -> io::Result<()> {
        if !self.send_padding {
            return self.w.write_all(data).await;
        }
        self.packet_count += 1;
        if self.packet_count >= padding.stop {
            self.send_padding = false;
            return self.w.write_all(data).await;
        }
        for size in padding.sizes(self.packet_count) {
            if size == CHECK {
                if data.is_empty() {
                    return Ok(());
                }
                continue;
            }
            let size = size as usize;
            if data.len() > size {
                self.w.write_all(&data[..size]).await?;
                data = &data[size..];
                continue;
            }
            self.record.clear();
            if !data.is_empty() {
                self.record.extend_from_slice(data);
                data = &[];
                let mut remaining = size - self.record.len();
                while remaining > FRAME_OVERHEAD {
                    let waste = (remaining - FRAME_OVERHEAD).min(MAX_FRAME);
                    frame_header(&mut self.record, CMD_WASTE, 0, waste);
                    self.record.resize(self.record.len() + waste, 0);
                    remaining -= FRAME_OVERHEAD + waste;
                }
            } else {
                let mut remaining = size;
                while remaining > 0 {
                    let waste = remaining.min(MAX_FRAME);
                    frame_header(&mut self.record, CMD_WASTE, 0, waste);
                    self.record.resize(self.record.len() + waste, 0);
                    remaining -= waste;
                }
            }
            let rec = std::mem::take(&mut self.record);
            let r = self.w.write_all(&rec).await;
            self.record = rec;
            r?;
        }
        if !data.is_empty() {
            self.w.write_all(data).await?;
        }
        Ok(())
    }
}

enum Event {
    Data(Bytes),
    Error(String),
}

struct Session {
    pool: Weak<Pool>,
    writer: tokio::sync::Mutex<Writer>,
    streams: Mutex<HashMap<u32, mpsc::Sender<Event>>>,
    next_id: AtomicU32,
    peer_version: AtomicU32,
    /// Frames received so far: the stream-open watchdog compares it.
    frames: AtomicU64,
    /// A heartbeat reply is queued; further requests are answered by it.
    heart_pending: AtomicBool,
    closed: AtomicBool,
    reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Session {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(t) = self.reader.lock().unwrap().take() {
            t.abort();
        }
        for (_, tx) in self.streams.lock().unwrap().drain() {
            let _ = tx.try_send(Event::Error("anytls: session closed".into()));
        }
    }

    fn padding(&self) -> Arc<Padding> {
        match self.pool.upgrade() {
            Some(p) => p.padding.read().unwrap().clone(),
            None => Arc::new(Padding::parse(DEFAULT_PADDING_SCHEME.as_bytes()).expect("default scheme")),
        }
    }

    async fn write_control(&self, cmd: u8, stream: u32, data: &[u8]) -> io::Result<()> {
        let mut f = Vec::with_capacity(FRAME_OVERHEAD + data.len());
        frame_header(&mut f, cmd, stream, data.len());
        f.extend_from_slice(data);
        let padding = self.padding();
        let r = self.writer.lock().await.write(&f, &padding).await;
        if r.is_err() {
            self.close();
        }
        r
    }

    async fn read_loop(self: Arc<Self>, r: ReadHalf<Tls>) {
        let mut r = tokio::io::BufReader::with_capacity(16 * 1024, r);
        let mut buf = BytesMut::new();
        let res: io::Result<()> = async {
            loop {
                let mut h = [0u8; FRAME_OVERHEAD];
                r.read_exact(&mut h).await?;
                self.frames.fetch_add(1, Ordering::Relaxed);
                let id = u32::from_be_bytes([h[1], h[2], h[3], h[4]]);
                let len = u16::from_be_bytes([h[5], h[6]]) as usize;
                buf.resize(len, 0);
                r.read_exact(&mut buf[..len]).await?;
                let data = buf.split_to(len).freeze();
                match h[0] {
                    CMD_PSH => {
                        if len == 0 {
                            continue;
                        }
                        let tx = self.streams.lock().unwrap().get(&id).cloned();
                        if let Some(tx) = tx {
                            // Waiting here is the backpressure, as in sing-anytls.
                            let _ = tx.send(Event::Data(data)).await;
                        }
                    }
                    CMD_SYNACK => {
                        if len > 0
                            && let Some(tx) = self.streams.lock().unwrap().get(&id).cloned()
                        {
                            let msg = String::from_utf8_lossy(&data).into_owned();
                            let _ = tx.try_send(Event::Error(format!("anytls: remote: {msg}")));
                        }
                    }
                    CMD_FIN => {
                        // Dropping the sender is EOF for the stream.
                        self.streams.lock().unwrap().remove(&id);
                    }
                    CMD_SERVER_SETTINGS => {
                        if let Some(v) = parse_settings(&data).get("v").and_then(|v| v.parse::<u32>().ok())
                            && v > 0
                        {
                            self.peer_version.store(v, Ordering::Relaxed);
                        }
                    }
                    CMD_UPDATE_PADDING_SCHEME => {
                        if len > 0 {
                            match (Padding::parse(&data), self.pool.upgrade()) {
                                (Some(p), Some(pool)) => {
                                    debug!(md5 = %p.md5_hex, "anytls: padding scheme updated");
                                    *pool.padding.write().unwrap() = Arc::new(p);
                                }
                                (None, _) => debug!("anytls: invalid padding scheme from server"),
                                _ => {}
                            }
                        }
                    }
                    CMD_ALERT => {
                        if len > 0 {
                            return Err(io::Error::other(format!(
                                "anytls: alert from peer: {}",
                                String::from_utf8_lossy(&data)
                            )));
                        }
                    }
                    // One reply in flight at most: a server that floods
                    // requests and stops reading must not pile up tasks.
                    CMD_HEART_REQUEST if !self.heart_pending.swap(true, Ordering::AcqRel) => {
                        let me = self.clone();
                        tokio::spawn(async move {
                            let _ = me.write_control(CMD_HEART_RESPONSE, id, &[]).await;
                            me.heart_pending.store(false, Ordering::Release);
                        });
                    }
                    // SYN, SETTINGS (server side only), WASTE, HEART_RESPONSE: ignore.
                    _ => {}
                }
            }
        }
        .await;
        if let Err(e) = res
            && !self.is_closed()
        {
            debug!(error = %e, "anytls: session ended");
        }
        // Not via close(): our own JoinHandle must not abort us mid-cleanup.
        self.closed.store(true, Ordering::Release);
        for (_, tx) in self.streams.lock().unwrap().drain() {
            let _ = tx.try_send(Event::Error("anytls: session closed".into()));
        }
        if let Some(pool) = self.pool.upgrade() {
            pool.forget(&self);
        }
    }

    /// Arm sing-anytls' stream-open watchdog: from the second stream of a
    /// session on, the peer must say something within 3 s.
    fn arm_open_timeout(self: &Arc<Self>, id: u32) {
        if id < 2 || self.peer_version.load(Ordering::Relaxed) < PROTOCOL_VERSION {
            return;
        }
        let seen = self.frames.load(Ordering::Relaxed);
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(STREAM_OPEN_TIMEOUT).await;
            if let Some(s) = me.upgrade()
                && s.frames.load(Ordering::Relaxed) == seen
            {
                debug!("anytls: stream open timed out, closing session");
                s.close();
            }
        });
    }
}

struct Pool {
    server: Destination,
    tls: TlsClient,
    upstream: Upstream,
    password: [u8; 32],
    metadata: String,
    padding: RwLock<Arc<Padding>>,
    idle_timeout: Duration,
    min_idle: usize,
    /// Most recently idled first.
    idle: Mutex<Vec<(Arc<Session>, Instant)>>,
    reaper: AtomicBool,
}

impl Pool {
    fn take_idle(&self) -> Option<Arc<Session>> {
        let mut idle = self.idle.lock().unwrap();
        while !idle.is_empty() {
            let (s, _) = idle.remove(0);
            if !s.is_closed() {
                return Some(s);
            }
        }
        None
    }

    fn forget(&self, s: &Arc<Session>) {
        self.idle.lock().unwrap().retain(|(x, _)| !Arc::ptr_eq(x, s));
    }

    /// A stream finished; park its session if nothing else uses it.
    fn release(self: &Arc<Self>, s: &Arc<Session>) {
        if s.is_closed() || !s.streams.lock().unwrap().is_empty() {
            return;
        }
        {
            let mut idle = self.idle.lock().unwrap();
            if idle.iter().any(|(x, _)| Arc::ptr_eq(x, s)) {
                return;
            }
            idle.insert(0, (s.clone(), Instant::now()));
        }
        self.schedule_reaper();
    }

    fn schedule_reaper(self: &Arc<Self>) {
        if self.idle.lock().unwrap().len() <= self.min_idle || self.reaper.swap(true, Ordering::AcqRel) {
            return;
        }
        let pool = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(p) = pool.upgrade() else { return };
                // The oldest surplus session decides the next wakeup.
                let next = {
                    let mut idle = p.idle.lock().unwrap();
                    let now = Instant::now();
                    let mut expired = Vec::new();
                    while idle.len() > p.min_idle {
                        let (s, since) = idle.last().unwrap();
                        if now.duration_since(*since) < p.idle_timeout && !s.is_closed() {
                            break;
                        }
                        expired.push(idle.pop().unwrap().0);
                    }
                    let next = if idle.len() > p.min_idle {
                        idle.last().map(|(_, since)| *since + p.idle_timeout)
                    } else {
                        None
                    };
                    if next.is_none() {
                        p.reaper.store(false, Ordering::Release);
                    }
                    drop(idle);
                    for s in expired {
                        s.close();
                    }
                    next
                };
                let Some(next) = next else { return };
                drop(p);
                tokio::time::sleep_until(next.into()).await;
            }
        });
    }

    async fn new_session(self: &Arc<Self>) -> io::Result<Arc<Session>> {
        let s = self.upstream.connect(&self.server).await?;
        let tls = TlsConnector::from(self.tls.config())
            .connect(self.tls.server_name.clone(), s)
            .await?;
        let padding = self.padding.read().unwrap().clone();
        let (r, mut w) = tokio::io::split(tls);
        // Authentication: sha256(password), padding length, zeros.
        let pad = (padding.sizes(0).first().copied().filter(|s| *s > 0).unwrap_or(0) as usize).min(u16::MAX as usize);
        let mut req = Vec::with_capacity(32 + 2 + pad);
        req.extend_from_slice(&self.password);
        req.extend_from_slice(&(pad as u16).to_be_bytes());
        req.resize(req.len() + pad, 0);
        w.write_all(&req).await?;
        let s = settings(&[
            ("v", &PROTOCOL_VERSION.to_string()),
            ("client", &self.metadata),
            ("padding-md5", &padding.md5_hex),
        ]);
        let mut pending = Vec::with_capacity(FRAME_OVERHEAD + s.len());
        frame_header(&mut pending, CMD_SETTINGS, 0, s.len());
        pending.extend_from_slice(&s);
        let session = Arc::new(Session {
            pool: Arc::downgrade(self),
            writer: tokio::sync::Mutex::new(Writer {
                w,
                pending: Some(pending),
                send_padding: true,
                packet_count: 0,
                record: Vec::new(),
            }),
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(0),
            peer_version: AtomicU32::new(0),
            frames: AtomicU64::new(0),
            heart_pending: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            reader: Mutex::new(None),
        });
        debug!(server = %self.server, "anytls: new session");
        let task = tokio::spawn(session.clone().read_loop(r));
        *session.reader.lock().unwrap() = Some(task);
        Ok(session)
    }
}

pub struct AnyTls {
    tag: String,
    pool: Arc<Pool>,
}

impl AnyTls {
    pub fn new(tag: String, c: &AnyTlsOutbound, upstream: Upstream) -> Result<Self, String> {
        let tls = TlsClient::new(&c.tls, &c.server.server)?;
        let mut password = [0u8; 32];
        password.copy_from_slice(digest::digest(&digest::SHA256, c.password.as_bytes()).as_ref());
        // sing-anytls falls back to the defaults below its 5 s minimum.
        let idle_timeout = c
            .idle_session_timeout
            .filter(|d| *d > MIN_IDLE_INTERVAL)
            .unwrap_or(DEFAULT_IDLE_TIMEOUT);
        Ok(Self {
            tag,
            pool: Arc::new(Pool {
                server: Destination::from_host_port(&c.server.server, c.server.server_port),
                tls,
                upstream,
                password,
                metadata: c.client_metadata.clone().unwrap_or_default(),
                padding: RwLock::new(Arc::new(
                    Padding::parse(DEFAULT_PADDING_SCHEME.as_bytes()).expect("default scheme"),
                )),
                idle_timeout,
                min_idle: c.min_idle_session as usize,
                idle: Mutex::new(Vec::new()),
                reaper: AtomicBool::new(false),
            }),
        })
    }

    fn open(&self, session: &Arc<Session>, dest: &Destination) -> io::Result<AnyStream> {
        let id = session.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        {
            let mut streams = session.streams.lock().unwrap();
            if session.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "anytls: session closed",
                ));
            }
            streams.insert(id, tx);
        }
        let mut addr = Vec::with_capacity(32);
        socks5::write_addr(&mut addr, dest)?;
        Ok(AnyStream {
            session: session.clone(),
            pool: self.pool.clone(),
            id,
            rx,
            chunk: Bytes::new(),
            request: Some(addr),
            write: None,
            wbuf: Some(Vec::with_capacity(MAX_FRAME + FRAME_OVERHEAD)),
            fin_sent: false,
        })
    }
}

impl Outbound for AnyTls {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "anytls"
    }

    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if let Some(s) = self.pool.take_idle() {
                match self.open(&s, dest) {
                    Ok(st) => return Ok(Box::new(st) as Stream),
                    Err(_) => s.close(),
                }
            }
            let s = self.pool.new_session().await?;
            Ok(Box::new(self.open(&s, dest)?) as Stream)
        })
    }

    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            // sing-box: UDP over AnyTLS is UoT v2.
            let s = self.connect(&super::uot::request_destination(2)).await?;
            Ok(Box::new(super::uot::UotConn::new(s, 2, dest)?) as BoxPacketConn)
        })
    }
}

type WriteFut = Pin<Box<dyn Future<Output = (io::Result<()>, Vec<u8>)> + Send>>;

/// One stream. The request (SYN + destination) goes out lazily with the
/// first read or write, like sing-anytls.
struct AnyStream {
    session: Arc<Session>,
    pool: Arc<Pool>,
    id: u32,
    rx: mpsc::Receiver<Event>,
    chunk: Bytes,
    /// Encoded destination, until the request is sent.
    request: Option<Vec<u8>>,
    /// In-flight write and the byte count it reports when done.
    write: Option<(WriteFut, usize)>,
    wbuf: Option<Vec<u8>>,
    fin_sent: bool,
}

impl AnyStream {
    /// Start a write of `data` (may be empty: request only).
    fn start_write(&mut self, data: &[u8]) -> usize {
        let mut buf = self.wbuf.take().unwrap_or_default();
        buf.clear();
        let request = self.request.take();
        let n = data.len().min(MAX_FRAME);
        if n > 0 {
            frame_header(&mut buf, CMD_PSH, self.id, n);
            buf.extend_from_slice(&data[..n]);
        }
        let session = self.session.clone();
        let id = self.id;
        let fut = async move {
            let padding = session.padding();
            let mut w = session.writer.lock().await;
            let mut r = Ok(());
            if let Some(addr) = request {
                let mut req = Vec::with_capacity(2 * FRAME_OVERHEAD + addr.len());
                frame_header(&mut req, CMD_SYN, id, 0);
                frame_header(&mut req, CMD_PSH, id, addr.len());
                req.extend_from_slice(&addr);
                session.arm_open_timeout(id);
                r = if w.pending.is_some() {
                    // New session: settings + SYN + destination as one record.
                    w.write(&req, &padding).await
                } else {
                    match w.write_packet(&req[..FRAME_OVERHEAD], &padding).await {
                        Ok(()) => w.write_packet(&req[FRAME_OVERHEAD..], &padding).await,
                        e => e,
                    }
                };
            }
            if r.is_ok() && !buf.is_empty() {
                r = w.write(&buf, &padding).await;
            }
            drop(w);
            if r.is_err() {
                session.close();
            }
            (r, buf)
        };
        self.write = Some((Box::pin(fut), n));
        n
    }

    fn poll_write_done(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some((fut, n)) = self.write.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        let (r, buf) = ready!(fut.as_mut().poll(cx));
        let n = *n;
        self.write = None;
        self.wbuf = Some(buf);
        Poll::Ready(r.map(|_| n))
    }
}

impl AsyncRead for AnyStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.request.is_some() && this.write.is_none() {
            this.start_write(&[]);
        }
        // Drive a request-only write started by a read.
        if this.write.as_ref().is_some_and(|(_, n)| *n == 0) {
            ready!(this.poll_write_done(cx))?;
        }
        loop {
            if !this.chunk.is_empty() {
                let n = this.chunk.len().min(buf.remaining());
                buf.put_slice(&this.chunk.split_to(n));
                return Poll::Ready(Ok(()));
            }
            match ready!(this.rx.poll_recv(cx)) {
                Some(Event::Data(b)) => this.chunk = b,
                Some(Event::Error(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
                }
                None => return Poll::Ready(Ok(())), // FIN
            }
        }
    }
}

impl AsyncWrite for AnyStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.session.is_closed() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "anytls: session closed")));
        }
        if let Some((_, n)) = &this.write {
            let request_only = *n == 0;
            let done = ready!(this.poll_write_done(cx))?;
            // A data write in flight is this very call, re-polled.
            if !request_only {
                return Poll::Ready(Ok(done));
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.start_write(buf);
        this.poll_write_done(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write.is_some() {
            ready!(this.poll_write_done(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    /// AnyTLS has no half-close: FIN ends both directions. sing-box closes a
    /// stream whose upload finished for the same reason, so do we.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write.is_some() {
            ready!(this.poll_write_done(cx))?;
        }
        if !this.fin_sent {
            this.fin_sent = true;
            let removed = this.session.streams.lock().unwrap().remove(&this.id).is_some();
            if this.request.is_none() && removed && !this.session.is_closed() {
                let (session, id) = (this.session.clone(), this.id);
                let fut = async move { (session.write_control(CMD_FIN, id, &[]).await, Vec::new()) };
                this.write = Some((Box::pin(fut), 0));
                ready!(this.poll_write_done(cx))?;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for AnyStream {
    fn drop(&mut self) {
        let removed = self.session.streams.lock().unwrap().remove(&self.id).is_some();
        let notify = self.request.is_none() && !self.fin_sent && removed && !self.session.is_closed();
        self.fin_sent = true;
        let (session, pool, id) = (self.session.clone(), self.pool.clone(), self.id);
        let in_flight = self.write.take();
        if notify || in_flight.is_some() {
            // Let an in-flight write finish (it holds the writer), then FIN.
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    if let Some((f, _)) = in_flight {
                        let _ = f.await;
                    }
                    if notify {
                        let _ = session.write_control(CMD_FIN, id, &[]).await;
                    }
                    pool.release(&session);
                });
                return;
            }
        }
        pool.release(&session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session write must put everything on the wire by itself: with the
    /// socket full, tokio-rustls accepts the plaintext and keeps the sealed
    /// records until someone flushes, and nobody else will.
    #[tokio::test]
    async fn session_write_leaves_nothing_in_rustls() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let (c, s) = tokio::io::duplex(4096);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let server = tokio::spawn(async move { acceptor.accept(s).await.unwrap() });
        let tls = TlsConnector::from(Arc::new(client_cfg))
            .connect(ServerName::try_from("localhost").unwrap(), Box::new(c) as Stream)
            .await
            .unwrap();
        let mut server = server.await.unwrap();
        let (_r, w) = tokio::io::split(tls);
        let mut writer = Writer {
            w,
            pending: None,
            send_padding: true,
            packet_count: 0,
            record: Vec::new(),
        };
        let padding = Padding::parse(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap();
        let data: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
        let len = data.len();
        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; len];
            server.read_exact(&mut got).await.map(|_| got)
        });
        for chunk in data.chunks(MAX_FRAME) {
            writer.write(chunk, &padding).await.unwrap();
        }
        // The writer stays open and idle, as a session between streams does.
        let got = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("written bytes stuck in rustls")
            .unwrap()
            .unwrap();
        assert!(got == data);
        drop(writer);
    }

    #[test]
    fn default_scheme() {
        let p = Padding::parse(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap();
        assert_eq!(p.stop, 8);
        assert_eq!(p.sizes(0), vec![30]);
        let s2 = p.sizes(2);
        assert_eq!(s2.len(), 9);
        assert_eq!(s2[1], CHECK);
        assert!((400..500).contains(&s2[0]));
        assert!(p.sizes(9).is_empty());
        assert_eq!(
            settings(&[("v", "2"), ("client", "x"), ("padding-md5", "y")]),
            b"client=x\npadding-md5=y\nv=2"
        );
    }
}
