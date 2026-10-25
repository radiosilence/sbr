//! V2Ray HTTP transport (sing-box `transport/v2rayhttp`): an HTTP/2 stream
//! with TLS, or a raw HTTP/1.1 request/response pair without it; plus the
//! `httpupgrade` transport, which is a bare `Upgrade: websocket` handshake.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use sbr_core::Stream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::ServerDialer;
use super::h2::H2Pool;
use super::prefixed::{Prefixed, head_end, header, read_response, split_path};
use crate::httpx::MAX_HEAD;

pub struct HttpClient {
    mode: Mode,
    path: String,
    hosts: Vec<String>,
    method: String,
    headers: Vec<(String, String)>,
}

enum Mode {
    H1(ServerDialer),
    H2(H2Pool),
}

impl HttpClient {
    pub fn new(
        dialer: ServerDialer,
        host: &[String],
        path: Option<&str>,
        method: Option<&str>,
        headers: &[(String, String)],
    ) -> Self {
        let (p, q) = split_path(path);
        let path = match q {
            Some(q) => format!("{p}?{q}"),
            None => p,
        };
        let mode = if dialer.has_tls() {
            Mode::H2(H2Pool::new(dialer))
        } else {
            Mode::H1(dialer)
        };
        Self {
            mode,
            path,
            hosts: host.to_vec(),
            method: method.unwrap_or("PUT").to_owned(),
            headers: headers.to_vec(),
        }
    }

    fn pick_host(&self) -> Option<&str> {
        match self.hosts.len() {
            0 => None,
            1 => Some(&self.hosts[0]),
            n => Some(&self.hosts[crate::tls::rand_u32() as usize % n]),
        }
    }

    pub async fn connect(&self) -> io::Result<Stream> {
        match &self.mode {
            Mode::H1(d) => {
                let s = d.connect().await?;
                let host = match self.pick_host() {
                    Some(h) => h.to_owned(),
                    None => d.server_host(),
                };
                let mut head = format!("{} {} HTTP/1.1\r\n", self.method, self.path);
                if !self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
                    head.push_str(&format!("Host: {host}\r\n"));
                }
                for (k, v) in &self.headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                Ok(Box::new(Http1Stream {
                    inner: s,
                    head: Some(head.into_bytes()),
                    wbuf: Vec::new(),
                    wpos: 0,
                    response: Response::Pending(Vec::new()),
                    read_flushes: false,
                }))
            }
            Mode::H2(pool) => {
                // v2ray's default Host for HTTP/2 is www.example.com.
                let host = self.pick_host().unwrap_or("www.example.com");
                let mut req = http::Request::builder()
                    .method(self.method.as_str())
                    .uri(format!("https://{host}{}", self.path));
                for (k, v) in &self.headers {
                    if !k.eq_ignore_ascii_case("host") {
                        req = req.header(k.as_str(), v.as_str());
                    }
                }
                let req = req.body(()).map_err(io::Error::other)?;
                Ok(Box::new(pool.open(req, false).await?))
            }
        }
    }
}

enum Response {
    /// Waiting for the response head (partial bytes so far).
    Pending(Vec<u8>),
    /// Bytes read past the head, still to deliver.
    Leftover(Vec<u8>, usize),
    Open,
}

/// HTTP/1.1 tunnel: the request head goes out with the first payload, the
/// response head is consumed by the first read.
struct Http1Stream {
    inner: Stream,
    head: Option<Vec<u8>>,
    wbuf: Vec<u8>,
    wpos: usize,
    response: Response,
    /// The reader sent the request head (nothing written yet): it flushes.
    /// Only one task may wait on the socket's writability.
    read_flushes: bool,
}

impl Http1Stream {
    fn poll_flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf = Vec::new();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Http1Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(h) = this.head.take() {
            this.wbuf = h;
            this.read_flushes = true;
        }
        if this.read_flushes
            && let Poll::Ready(Err(e)) = this.poll_flush_wbuf(cx)
        {
            return Poll::Ready(Err(e));
        }
        loop {
            match &mut this.response {
                Response::Open => return Pin::new(&mut this.inner).poll_read(cx, out),
                Response::Leftover(b, pos) => {
                    let n = (b.len() - *pos).min(out.remaining());
                    out.put_slice(&b[*pos..*pos + n]);
                    *pos += n;
                    if *pos == b.len() {
                        this.response = Response::Open;
                    }
                    return Poll::Ready(Ok(()));
                }
                Response::Pending(buf) => {
                    if let Some(end) = head_end(buf) {
                        let status = crate::httpx::status_code(&buf[..end]);
                        if status != Some(200) {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("v2ray-http: unexpected status: {status:?}"),
                            )));
                        }
                        let rest = buf.split_off(end);
                        this.response = if rest.is_empty() {
                            Response::Open
                        } else {
                            Response::Leftover(rest, 0)
                        };
                        continue;
                    }
                    if buf.len() > MAX_HEAD {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "response head too large",
                        )));
                    }
                    let start = buf.len();
                    buf.resize(start + 2048, 0);
                    let mut rb = ReadBuf::new(&mut buf[start..]);
                    let r = Pin::new(&mut this.inner).poll_read(cx, &mut rb);
                    let n = rb.filled().len();
                    buf.truncate(start + n);
                    ready!(r)?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                }
            }
        }
    }
}

impl AsyncWrite for Http1Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.read_flushes = false;
        if let Some(mut h) = this.head.take() {
            h.extend_from_slice(buf);
            this.wbuf = h;
            this.wpos = 0;
            if let Poll::Ready(Err(e)) = this.poll_flush_wbuf(cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        ready!(this.poll_flush_wbuf(cx))?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.head.is_some() || this.wpos < this.wbuf.len() {
            let first = bufs.iter().find(|b| !b.is_empty()).map_or(&[][..], |b| &b[..]);
            return Pin::new(this).poll_write(cx, first);
        }
        Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_wbuf(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_wbuf(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// A fixed request (the gRPC `Tun` call), rebuilt per stream.
pub struct HttpRequestTemplate {
    uri: http::Uri,
    headers: [(&'static str, &'static str); 3],
}

impl HttpRequestTemplate {
    pub fn grpc(authority: &str, service: &str) -> Self {
        // Go's url.PathEscape.
        let mut escaped = String::new();
        for b in service.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~$&+:=@".contains(&b) {
                escaped.push(b as char);
            } else {
                escaped.push_str(&format!("%{b:02X}"));
            }
        }
        let uri = format!("https://{authority}/{escaped}/Tun")
            .parse()
            .unwrap_or_else(|_| http::Uri::from_static("https://localhost/Tun"));
        Self {
            uri,
            headers: [
                ("content-type", "application/grpc"),
                ("user-agent", "grpc-go/1.48.0"),
                ("te", "trailers"),
            ],
        }
    }

    pub fn build(&self) -> io::Result<http::Request<()>> {
        let mut r = http::Request::builder().method("POST").uri(self.uri.clone());
        for (k, v) in self.headers {
            r = r.header(k, v);
        }
        r.body(()).map_err(io::Error::other)
    }
}

pub struct HttpUpgradeClient {
    dialer: ServerDialer,
    request: Vec<u8>,
}

impl HttpUpgradeClient {
    pub fn new(dialer: ServerDialer, host: Option<&str>, path: Option<&str>, headers: &[(String, String)]) -> Self {
        let host = match host {
            Some(h) => h.to_owned(),
            None => dialer.tls_server_name().unwrap_or_else(|| dialer.server_authority()),
        };
        let (p, q) = split_path(path);
        let mut r = format!("GET {p}");
        if let Some(q) = q {
            r.push('?');
            r.push_str(&q);
        }
        r.push_str(&format!(" HTTP/1.1\r\nHost: {host}\r\n"));
        for (k, v) in headers {
            if !k.eq_ignore_ascii_case("host") {
                r.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        r.push_str("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
        Self {
            dialer,
            request: r.into_bytes(),
        }
    }

    pub async fn connect(&self) -> io::Result<Stream> {
        let mut s = self.dialer.connect().await?;
        s.write_all(&self.request).await?;
        s.flush().await?;
        let (status, head, rest) = read_response(&mut s).await?;
        let upgraded = status == 101
            && header(&head, "connection").is_some_and(|v| v.eq_ignore_ascii_case("upgrade"))
            && header(&head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        if !upgraded {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("v2ray-http-upgrade: unexpected status: {status}"),
            ));
        }
        if rest.is_empty() {
            Ok(s)
        } else {
            Ok(Box::new(Prefixed::new(rest, s)))
        }
    }
}
