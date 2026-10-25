//! XHTTP client (Xray-core `transport/internet/splithttp`), an sbr extension.
//!
//! A proxy connection becomes HTTP requests:
//!
//! - `stream-one`: one request; its body is the upload, its response body
//!   the download.
//! - `stream-up`: a `GET` for the download and a streaming `POST` for the
//!   upload, tied together by a session ID in the URL.
//! - `packet-up`: the same `GET`, with the upload cut into `POST`s that carry
//!   a sequence number, so the server can reorder them. Works through CDNs
//!   and proxies that buffer request bodies.
//!
//! Requests go over HTTP/1.1, or HTTP/2 over TLS or REALITY, on connections
//! chosen by XMUX ([`pool`]). Padding, header defaults and where the
//! session ID and sequence number go follow Xray's `config.go`.

mod browser;
mod h1;
mod h2io;
mod h3io;
mod pool;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use sbr_config::{PaddingMethod, Placement, Range, TlsOutbound, Xhttp, XhttpMode};
use sbr_core::{Destination, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Notify;
use tracing::debug;

use self::browser::{Headers, padding, request_headers, set};
use self::pool::{Pool, PoolConn, Running, Slot, rand_between};
use super::ServerDialer;
use crate::outbound::Upstream;
use crate::outbound::quic::Dialer as QuicDialer;
use crate::tls::TlsClient;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Version {
    H1,
    H2,
    H3,
}

/// Xray `decideHTTPVersion`.
fn decide_version(tls: Option<&TlsOutbound>) -> Version {
    let Some(t) = tls else { return Version::H1 };
    if t.reality.as_ref().is_some_and(|r| r.enabled) {
        return Version::H2;
    }
    match t.alpn.as_slice() {
        [a] if a == "http/1.1" => Version::H1,
        [a] if a == "h3" => Version::H3,
        _ => Version::H2,
    }
}

enum Conn {
    H1(h1::H1Conn),
    H2(h2io::H2Conn),
    H3(h3io::H3Conn),
}

impl PoolConn for Conn {
    fn is_closed(&self) -> bool {
        match self {
            Conn::H1(c) => c.is_closed(),
            Conn::H2(c) => c.is_closed(),
            Conn::H3(c) => c.is_closed(),
        }
    }
}

type SlotRef = Arc<Slot<Conn>>;

/// A request before it is written as HTTP/1.1 or HTTP/2.
struct Req {
    method: String,
    path: String,
    query: String,
    headers: Headers,
    cookies: Vec<(String, String)>,
}

impl Req {
    fn path_query(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        }
    }
}

/// Go's `url.QueryEscape`.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn query_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `q := u.Query(); q.Set(key, value); u.RawQuery = q.Encode()`.
fn query_set(raw: &str, key: &str, value: &str) -> String {
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (query_unescape(k), query_unescape(v)),
            None => (query_unescape(p), String::new()),
        })
        .filter(|(k, _)| k != key)
        .collect();
    pairs.push((key.to_owned(), value.to_owned()));
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Append a path segment, escaping what a path segment cannot hold.
fn append_path(path: &mut String, seg: &str) {
    if !path.ends_with('/') {
        path.push('/');
    }
    for b in seg.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b) {
            path.push(b as char);
        } else {
            path.push_str(&format!("%{b:02X}"));
        }
    }
}

/// Where requests for one direction go, and how they look.
struct Endpoint {
    cfg: Xhttp,
    version: Version,
    dialer: ServerDialer,
    scheme: &'static str,
    host: String,
    path: String,
    query: String,
    keepalive: Option<Duration>,
    /// HTTP/3 only: the QUIC dialer.
    quic: Option<QuicDialer>,
    pool: Pool<Conn>,
}

impl Endpoint {
    fn new(cfg: &Xhttp, dialer: ServerDialer, tls: Option<&TlsOutbound>, path: &str) -> Result<Self, String> {
        let version = decide_version(tls);
        let quic = match (version, tls) {
            (Version::H3, Some(t)) => Some(
                QuicDialer::new(dialer.upstream.clone(), dialer.server.clone(), t, &["h3"], false)
                    .map_err(|e| format!("{path}: {e}"))?,
            ),
            _ => None,
        };
        let dialer = match version {
            Version::H1 => dialer.with_default_alpn(&["http/1.1"]),
            _ => dialer.with_default_alpn(&["h2", "http/1.1"]),
        };
        let host = match &cfg.host {
            Some(h) => h.clone(),
            None => dialer.tls_server_name().unwrap_or_else(|| dialer.server_host()),
        };
        // `GetNormalizedPath` / `GetNormalizedQuery`.
        let (p, q) = cfg.path.split_once('?').unwrap_or((&cfg.path, ""));
        let mut path = if p.starts_with('/') {
            p.to_owned()
        } else {
            format!("/{p}")
        };
        if (cfg.session_id_placement == Placement::Path || cfg.seq_placement == Placement::Path) && !path.ends_with('/')
        {
            path.push('/');
        }
        let keepalive =
            (cfg.xmux.h_keep_alive_period > 0).then(|| Duration::from_secs(cfg.xmux.h_keep_alive_period as u64));
        Ok(Self {
            version,
            scheme: if tls.is_some() { "https" } else { "http" },
            host,
            path,
            query: q.to_owned(),
            keepalive,
            quic,
            pool: Pool::new(&cfg.xmux),
            dialer,
            cfg: cfg.clone(),
        })
    }

    fn new_conn(&self) -> Conn {
        match self.version {
            Version::H1 => Conn::H1(h1::H1Conn::default()),
            Version::H2 => Conn::H2(h2io::H2Conn::default()),
            Version::H3 => Conn::H3(h3io::H3Conn::default()),
        }
    }

    fn slot(&self) -> SlotRef {
        self.pool.get(|| self.new_conn())
    }

    /// `ApplyXPaddingToRequest` with the placement Xray picks: `Referer:
    /// <url>?x_padding=XXX` unless `xPaddingObfsMode` says otherwise.
    fn apply_padding(&self, req: &mut Req) {
        let c = &self.cfg;
        let len = rand_between(c.x_padding_bytes.or(Range::new(100, 1000))).max(0) as usize;
        let (placement, key, header, method) = if c.x_padding_obfs_mode {
            (
                c.x_padding_placement,
                c.x_padding_key.as_str(),
                c.x_padding_header.as_str(),
                c.x_padding_method,
            )
        } else {
            (Placement::QueryInHeader, "x_padding", "Referer", PaddingMethod::RepeatX)
        };
        let raw_url = format!("{}://{}{}", self.scheme, self.host, req.path_query());
        let value = padding(method, len);
        match placement {
            Placement::Header => set(&mut req.headers, header, value),
            Placement::QueryInHeader => {
                let base = raw_url.split_once('?').map_or(raw_url.as_str(), |(b, _)| b);
                set(&mut req.headers, header, format!("{base}?{key}={value}"));
            }
            Placement::Cookie if !value.is_empty() => req.cookies.push((key.to_owned(), value)),
            Placement::Query if !value.is_empty() => req.query = query_set(&req.query, key, &value),
            _ => {}
        }
    }

    /// `ApplyMetaToRequest`.
    fn apply_meta(&self, req: &mut Req, session: &str, seq: &str) {
        let c = &self.cfg;
        for (value, placement, key) in [
            (session, c.session_id_placement, c.session_id_key.as_str()),
            (seq, c.seq_placement, c.seq_key.as_str()),
        ] {
            if value.is_empty() {
                continue;
            }
            match placement {
                Placement::Path => append_path(&mut req.path, value),
                Placement::Query => req.query = query_set(&req.query, key, value),
                Placement::Header => set(&mut req.headers, key, value),
                Placement::Cookie => req.cookies.push((key.to_owned(), value.to_owned())),
                _ => {}
            }
        }
    }

    fn empty_req(&self, method: &str, headers: Headers) -> Req {
        Req {
            method: method.to_owned(),
            path: self.path.clone(),
            query: self.query.clone(),
            headers,
            cookies: Vec::new(),
        }
    }

    /// `FillStreamRequest`: the download `GET`, or a streaming upload.
    fn stream_request(&self, session: &str, upload: bool) -> Req {
        let method = if upload {
            self.cfg.uplink_http_method.as_str()
        } else {
            "GET"
        };
        let mut req = self.empty_req(method, request_headers(&self.cfg.headers));
        self.apply_padding(&mut req);
        self.apply_meta(&mut req, session, "");
        if upload && !self.cfg.no_grpc_header {
            set(&mut req.headers, "Content-Type", "application/grpc");
        }
        req
    }

    /// `FillPacketRequest`: one packet-up upload.
    fn packet_request(&self, session: &str, seq: u64, payload: Bytes) -> (Req, Bytes) {
        let c = &self.cfg;
        let mut headers = request_headers(&c.headers);
        let mut cookies = Vec::new();
        let body = match c.uplink_data_placement {
            Placement::Header | Placement::Cookie => {
                let chunk = match c.uplink_chunk_size {
                    r if r.is_unset() => match c.uplink_data_placement {
                        Placement::Cookie => Range::new(2 * 1024, 3 * 1024),
                        _ => Range::new(3000, 4000),
                    },
                    r if r.from < 64 => Range::new(64, r.to.max(64)),
                    r => r,
                };
                let mut enc = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(&payload)
                    .into_bytes();
                let mut i = 0;
                while !enc.is_empty() {
                    let n = (rand_between(chunk).max(1) as usize).min(enc.len());
                    let part = String::from_utf8(enc.drain(..n).collect()).unwrap_or_default();
                    if c.uplink_data_placement == Placement::Header {
                        set(&mut headers, &format!("{}-{i}", c.uplink_data_key), part);
                    } else {
                        cookies.push((format!("{}_{i}", c.uplink_data_key), part));
                    }
                    i += 1;
                }
                Bytes::new()
            }
            _ => payload,
        };
        let mut req = self.empty_req(&c.uplink_http_method, headers);
        req.cookies = cookies;
        self.apply_padding(&mut req);
        self.apply_meta(&mut req, session, &seq.to_string());
        (req, body)
    }

    fn h2_request(&self, req: &Req, content_length: Option<usize>) -> io::Result<http::Request<()>> {
        let mut b = http::Request::builder().method(req.method.as_str()).uri(format!(
            "{}://{}{}",
            self.scheme,
            self.host,
            req.path_query()
        ));
        let mut ua = false;
        for (k, v) in &req.headers {
            ua |= k.eq_ignore_ascii_case("user-agent");
            if !k.eq_ignore_ascii_case("host") {
                b = b.header(k.as_str(), v.as_str());
            }
        }
        if !ua {
            b = b.header("user-agent", "Go-http-client/2.0");
        }
        if !req.cookies.is_empty() {
            b = b.header("cookie", cookie_header(&req.cookies));
        }
        if let Some(n) = content_length {
            b = b.header("content-length", n);
        }
        b.body(()).map_err(io::Error::other)
    }

    fn h1_head(&self, req: &Req, body: h1::BodyKind, close: bool) -> Vec<u8> {
        let mut headers = req.headers.clone();
        if !req.cookies.is_empty() {
            set(&mut headers, "Cookie", cookie_header(&req.cookies));
        }
        h1::head(&req.method, &req.path_query(), &self.host, &headers, body, close)
    }

    fn h2(slot: &SlotRef) -> &h2io::H2Conn {
        match &slot.conn {
            Conn::H2(c) => c,
            _ => unreachable!("slot version matches its endpoint"),
        }
    }

    fn h3<'a>(&'a self, slot: &'a SlotRef) -> (&'a h3io::H3Conn, &'a QuicDialer) {
        match (&slot.conn, &self.quic) {
            (Conn::H3(c), Some(d)) => (c, d),
            _ => unreachable!("slot version matches its endpoint"),
        }
    }

    /// Open the download. `GET` with no body.
    async fn open_down(&self, slot: &SlotRef, req: Req) -> io::Result<Down> {
        match self.version {
            Version::H2 => {
                let (resp, _) = Self::h2(slot)
                    .request(&self.dialer, self.keepalive, self.h2_request(&req, None)?, true)
                    .await
                    .inspect_err(|_| slot.mark_closed())?;
                Ok(Down::H2(h2io::H2Down::new(resp)))
            }
            Version::H3 => {
                let (c, d) = self.h3(slot);
                let (mut tx, rx, guard) = c
                    .request(d, self.keepalive, self.h2_request(&req, None)?)
                    .await
                    .inspect_err(|_| slot.mark_closed())?;
                let _ = tx.finish().await;
                Ok(Down::H3(h3io::H3Down::new(rx, guard)))
            }
            Version::H1 => {
                let head = self.h1_head(&req, h1::BodyKind::None, true);
                let (r, _w) = h1::open(&self.dialer, &head).await.inspect_err(|_| {
                    if let Conn::H1(c) = &slot.conn {
                        c.mark_closed();
                    }
                })?;
                Ok(Down::H1(h1::H1Response::new(r)))
            }
        }
    }

    /// Open a streaming upload. Returns the writer and the response (to be
    /// read as the download for stream-one, drained for stream-up).
    async fn open_up(&self, slot: &SlotRef, req: Req) -> io::Result<(Up, Down)> {
        match self.version {
            Version::H2 => {
                let (resp, send) = Self::h2(slot)
                    .request(&self.dialer, self.keepalive, self.h2_request(&req, None)?, false)
                    .await
                    .inspect_err(|_| slot.mark_closed())?;
                Ok((Up::H2(h2io::H2Up::new(send)), Down::H2(h2io::H2Down::new(resp))))
            }
            Version::H3 => {
                let (c, d) = self.h3(slot);
                let (tx, rx, guard) = c
                    .request(d, self.keepalive, self.h2_request(&req, None)?)
                    .await
                    .inspect_err(|_| slot.mark_closed())?;
                // One guard per half: the connection lives while either does.
                let guard2 = c
                    .guard()
                    .ok_or_else(|| io::Error::other("xhttp: QUIC connection closing"))?;
                Ok((
                    Up::H3(Box::new(h3io::H3Up::new(tx, guard))),
                    Down::H3(h3io::H3Down::new(rx, guard2)),
                ))
            }
            Version::H1 => {
                let head = self.h1_head(&req, h1::BodyKind::Chunked, true);
                let (r, w) = h1::open(&self.dialer, &head).await?;
                Ok((Up::H1(h1::ChunkedWriter::new(w)), Down::H1(h1::H1Response::new(r))))
            }
        }
    }
}

fn cookie_header(cookies: &[(String, String)]) -> String {
    cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// A configured `xhttp` transport.
pub struct XhttpClient {
    mode: XhttpMode,
    up: Arc<Endpoint>,
    down: Option<Arc<Endpoint>>,
}

impl XhttpClient {
    pub fn new(
        cfg: &Xhttp,
        base: ServerDialer,
        tls: Option<&TlsOutbound>,
        upstream: Upstream,
        base_dir: Option<&std::path::Path>,
    ) -> Result<Self, String> {
        let up = Endpoint::new(cfg, base, tls, "tls")?;
        let down = match &cfg.download {
            None => None,
            Some(d) => {
                let dtls = d.tls.as_ref().filter(|t| t.enabled);
                let client = match dtls {
                    Some(t) => Some(
                        TlsClient::new(t, &d.server.server, base_dir)
                            .map_err(|e| format!("transport.downloadSettings.{e}"))?,
                    ),
                    None => None,
                };
                let dialer = ServerDialer::new(
                    upstream,
                    Destination::from_host_port(&d.server.server, d.server.server_port),
                    client,
                );
                Some(Arc::new(Endpoint::new(
                    &d.xhttp,
                    dialer,
                    dtls,
                    "transport.downloadSettings.tls",
                )?))
            }
        };
        let reality = tls.is_some_and(|t| t.reality.as_ref().is_some_and(|r| r.enabled));
        // Xray `Dial`: `auto` is packet-up, except over REALITY.
        let mode = match cfg.mode {
            XhttpMode::Auto if reality && down.is_some() => XhttpMode::StreamUp,
            XhttpMode::Auto if reality => XhttpMode::StreamOne,
            XhttpMode::Auto => XhttpMode::PacketUp,
            m => m,
        };
        if mode == XhttpMode::StreamOne && down.is_some() {
            return Err("transport.downloadSettings: can not be used in stream-one mode".into());
        }
        Ok(Self {
            mode,
            up: Arc::new(up),
            down,
        })
    }

    pub async fn connect(&self) -> io::Result<Stream> {
        let up = &self.up;
        let slot = up.slot();
        let mut running = vec![Running::new(slot.clone())];
        if self.mode == XhttpMode::StreamOne {
            slot.left_requests.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            let (w, r) = up.open_up(&slot, up.stream_request("", true)).await?;
            return Ok(Box::new(XhttpStream {
                down: r,
                up: w,
                _running: running,
                _tasks: Vec::new(),
            }));
        }
        let session = session_id(&up.cfg);
        let down = self.down.as_ref().unwrap_or(up);
        let dslot = if self.down.is_some() {
            let s = down.slot();
            running.push(Running::new(s.clone()));
            s
        } else {
            slot.clone()
        };
        dslot.left_requests.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let reader = down.open_down(&dslot, down.stream_request(&session, false)).await?;
        let mut tasks = Vec::new();
        let writer = if self.mode == XhttpMode::StreamUp {
            slot.left_requests.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            let (w, resp) = up.open_up(&slot, up.stream_request(&session, true)).await?;
            tasks.push(AbortOnDrop(tokio::spawn(async move {
                let mut resp = resp;
                if let Err(e) = tokio::io::copy(&mut resp, &mut tokio::io::sink()).await {
                    debug!(error = %e, "xhttp stream-up response");
                }
            })));
            w
        } else {
            let max = rand_between(up.cfg.sc_max_each_post_bytes.or(Range::new(1_000_000, 1_000_000))).max(1) as usize;
            let shared = Arc::new(UpShared {
                st: Mutex::new(UpState {
                    buf: BytesMut::new(),
                    cap: max,
                    closed: false,
                    err: None,
                    waker: None,
                }),
                notify: Notify::new(),
            });
            tokio::spawn(packet_uploader(up.clone(), slot.clone(), session, max, shared.clone()));
            Up::Packet(PacketUp { shared })
        };
        Ok(Box::new(XhttpStream {
            down: reader,
            up: writer,
            _running: running,
            _tasks: tasks,
        }))
    }
}

/// `GenerateSessionID`: from `sessionIDTable`, else a UUIDv4.
fn session_id(c: &Xhttp) -> String {
    let len = rand_between(c.session_id_length);
    let table = c.session_id_table.as_bytes();
    if !table.is_empty() && len > 0 {
        return (0..len)
            .map(|_| table[crate::tls::rand_u32() as usize % table.len()] as char)
            .collect();
    }
    let mut b = [0u8; 16];
    aws_lc_rs::rand::fill(&mut b).expect("system RNG");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

struct UpState {
    buf: BytesMut,
    cap: usize,
    closed: bool,
    err: Option<String>,
    waker: Option<Waker>,
}

struct UpShared {
    st: Mutex<UpState>,
    notify: Notify,
}

impl UpShared {
    fn fail(&self, e: String) {
        let mut st = self.st.lock().unwrap();
        st.err.get_or_insert(e);
        if let Some(w) = st.waker.take() {
            w.wake();
        }
    }
}

/// The packet-up upload side: writes are buffered, and a task turns what
/// has accumulated into POSTs, so many small writes become one request.
struct PacketUp {
    shared: Arc<UpShared>,
}

impl AsyncWrite for PacketUp {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut st = self.shared.st.lock().unwrap();
        if let Some(e) = &st.err {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e.clone())));
        }
        if st.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = st.cap.saturating_sub(st.buf.len());
        if room == 0 {
            st.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(buf.len());
        st.buf.extend_from_slice(&buf[..n]);
        drop(st);
        self.shared.notify.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.st.lock().unwrap().closed = true;
        self.shared.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for PacketUp {
    fn drop(&mut self) {
        self.shared.st.lock().unwrap().closed = true;
        self.shared.notify.notify_one();
    }
}

/// Xray `Dial`'s upload goroutine: one POST per batch, at most `max` bytes,
/// no closer together than `scMinPostsIntervalMs`, moving to another XMUX
/// slot when this one's request budget or lifetime runs out.
async fn packet_uploader(ep: Arc<Endpoint>, mut slot: SlotRef, session: String, max: usize, shared: Arc<UpShared>) {
    let interval = ep.cfg.sc_min_posts_interval_ms.or(Range::new(30, 30));
    let mut last: Option<Instant> = None;
    let mut seq: u64 = 0;
    loop {
        let chunk = loop {
            let notified = shared.notify.notified();
            {
                let mut st = shared.st.lock().unwrap();
                if st.err.is_some() {
                    return;
                }
                if !st.buf.is_empty() {
                    let n = st.buf.len().min(max);
                    let chunk = st.buf.split_to(n).freeze();
                    if let Some(w) = st.waker.take() {
                        w.wake();
                    }
                    break chunk;
                }
                if st.closed {
                    return;
                }
            }
            notified.await;
        };
        if interval.from > 0
            && let Some(t) = last
        {
            let wait = Duration::from_millis(rand_between(interval).max(0) as u64);
            tokio::time::sleep_until((t + wait).into()).await;
        }
        last = Some(Instant::now());
        if !slot.take_request() {
            slot = ep.slot();
        }
        let (req, body) = ep.packet_request(&session, seq, chunk);
        seq += 1;
        let r = match &slot.conn {
            Conn::H2(c) => {
                let len = body.len();
                let has_len = len > 0 || matches!(req.method.as_str(), "POST" | "PUT" | "PATCH");
                async {
                    let hreq = ep.h2_request(&req, has_len.then_some(len))?;
                    let (resp, mut send) = c.request(&ep.dialer, ep.keepalive, hreq, body.is_empty()).await?;
                    if !body.is_empty() {
                        h2io::send_body(&mut send, body).await?;
                    }
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        if let Err(e) = h2io::drain(resp).await {
                            shared.fail(format!("xhttp upload: {e}"));
                        }
                    });
                    Ok::<_, io::Error>(())
                }
                .await
            }
            Conn::H3(c) => {
                let len = body.len();
                let has_len = len > 0 || matches!(req.method.as_str(), "POST" | "PUT" | "PATCH");
                async {
                    let hreq = ep.h2_request(&req, has_len.then_some(len))?;
                    let d = ep.quic.as_ref().expect("HTTP/3 endpoint has a QUIC dialer");
                    let (rx, guard) = h3io::post(c, d, ep.keepalive, hreq, body).await?;
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        if let Err(e) = h3io::drain(rx).await {
                            shared.fail(format!("xhttp upload: {e}"));
                        }
                    });
                    Ok::<_, io::Error>(())
                }
                .await
            }
            Conn::H1(c) => {
                let len = body.len();
                let has_len = len > 0 || matches!(req.method.as_str(), "POST" | "PUT" | "PATCH");
                let kind = if has_len {
                    h1::BodyKind::Length(len)
                } else {
                    h1::BodyKind::None
                };
                let mut bytes = ep.h1_head(&req, kind, false);
                bytes.extend_from_slice(&body);
                c.post(&ep.dialer, &bytes).await
            }
        };
        if let Err(e) = r {
            slot.mark_closed();
            debug!(error = %e, "xhttp upload failed");
            shared.fail(format!("xhttp upload: {e}"));
            return;
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Down {
    H1(h1::H1Response<ReadHalf<Stream>>),
    H2(h2io::H2Down),
    H3(h3io::H3Down),
}

impl AsyncRead for Down {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Down::H1(r) => Pin::new(r).poll_read(cx, buf),
            Down::H2(r) => Pin::new(r).poll_read(cx, buf),
            Down::H3(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

enum Up {
    H1(h1::ChunkedWriter<WriteHalf<Stream>>),
    H2(h2io::H2Up),
    H3(Box<h3io::H3Up>),
    Packet(PacketUp),
}

/// One proxy connection over XHTTP.
struct XhttpStream {
    down: Down,
    up: Up,
    _running: Vec<Running<Conn>>,
    _tasks: Vec<AbortOnDrop>,
}

impl AsyncRead for XhttpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().down).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().up {
            Up::H1(w) => Pin::new(w).poll_write(cx, buf),
            Up::H2(w) => Pin::new(w).poll_write(cx, buf),
            Up::H3(w) => Pin::new(w).poll_write(cx, buf),
            Up::Packet(w) => Pin::new(w).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().up {
            Up::H1(w) => Pin::new(w).poll_flush(cx),
            Up::H2(w) => Pin::new(w).poll_flush(cx),
            Up::H3(w) => Pin::new(w).poll_flush(cx),
            Up::Packet(w) => Pin::new(w).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = match &mut self.get_mut().up {
            Up::H1(w) => Pin::new(w).poll_shutdown(cx),
            Up::H2(w) => Pin::new(w).poll_shutdown(cx),
            Up::H3(w) => Pin::new(w).poll_shutdown(cx),
            Up::Packet(w) => Pin::new(w).poll_shutdown(cx),
        };
        ready!(r)?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        assert_eq!(query_set("", "x_padding", "XX"), "x_padding=XX");
        assert_eq!(query_set("b=2&a=1", "x_session", "s s"), "a=1&b=2&x_session=s+s");
        assert_eq!(query_set("a=%41&k=old", "k", "new"), "a=A&k=new");
        let mut p = "/xhttp/".to_string();
        append_path(&mut p, "abc");
        append_path(&mut p, "0");
        assert_eq!(p, "/xhttp/abc/0");
    }

    #[test]
    fn session_ids() {
        let id = session_id(&test_cfg());
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
    }

    fn test_cfg() -> Xhttp {
        let v = serde_json::json!({"outbounds": [{
            "type": "vless", "server": "127.0.0.1", "server_port": 1, "uuid": "x",
            "transport": {"type": "xhttp", "path": "/p"}
        }]});
        let o = sbr_config::Options::from_value(v).unwrap();
        match &o.outbounds[0].kind {
            sbr_config::OutboundKind::Vless(v) => match &v.common.transport {
                Some(sbr_config::Transport::Xhttp(x)) => (**x).clone(),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}
