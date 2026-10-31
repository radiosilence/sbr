//! A small HTTP/1.1 client that dials through an outbound: remote rule-set
//! downloads, the external UI download, `urltest` probes and data probes.
//!
//! HTTPS is rustls (aws-lc-rs) with the Mozilla roots from `webpki-roots`,
//! or the trust anchors the host passed in `Settings::http_roots`. Kept
//! separate from the protocol TLS layer on purpose: this only ever talks to
//! ordinary web servers.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::http::{HeaderMap, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use sbr_core::{Destination, Outbound};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::health::{PROOF_BYTES, Verdict};

/// sing-box `C.TCPTimeout`.
pub const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Option<Url> {
        let (https, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else {
            (false, s.strip_prefix("http://")?)
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        let authority = authority.rsplit('@').next()?;
        let default = if https { 443 } else { 80 };
        let (host, port) = crate::httpx::split_authority(authority, default)?;
        if host.is_empty() {
            return None;
        }
        let path = path.split('#').next().unwrap_or("");
        let path = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        Some(Url {
            https,
            host: host.to_owned(),
            port,
            path,
        })
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == if self.https { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Resolve a `Location` header against this URL.
    pub fn join(&self, location: &str) -> Option<Url> {
        if location.starts_with("http://") || location.starts_with("https://") {
            return Url::parse(location);
        }
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{}://{rest}", if self.https { "https" } else { "http" }));
        }
        let mut u = self.clone();
        u.path = if location.starts_with('/') {
            location.to_owned()
        } else {
            let base = self.path.split('?').next().unwrap_or("/");
            format!("{}{location}", &base[..base.rfind('/').map_or(0, |i| i + 1)])
        };
        Some(u)
    }
}

pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Clone)]
pub struct HttpClient {
    tls: tokio_rustls::TlsConnector,
    /// For data probes of a leaf's own server, which answers with whatever
    /// certificate its fallback site has. A liveness check, not trust.
    insecure: tokio_rustls::TlsConnector,
    user_agent: Option<&'static str>,
}

/// What a data probe fetches.
#[derive(Debug, Clone)]
pub enum Target {
    /// The urltest `url`: one GET for its first [`PROOF_BYTES`]. Point it at
    /// a file at least that large to make the probe conclusive.
    Url(Url),
    /// A leaf's own server over TLS, with pipelined `GET /` until enough has
    /// arrived; a small fallback page is fetched many times.
    Server(Destination),
}

/// Silence that ends a data probe: data flowed, then stopped mid-transfer.
pub const PROBE_GAP: Duration = Duration::from_secs(5);
/// Pipelined requests per data probe, at most: a 404 page can be ~100 bytes.
const MAX_REQUESTS: usize = 1024;
const BATCH: usize = 64;

impl HttpClient {
    pub fn new(roots: Option<Arc<rustls::RootCertStore>>) -> Self {
        let roots = roots.unwrap_or_else(|| {
            Arc::new(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
        });
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("aws-lc-rs supports the default versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let any = crate::tls::verify::Pinned::new(&[], &[], true, &provider).expect("no pins to parse");
        let mut insecure = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs supports the default versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(any))
            .with_no_client_auth();
        insecure.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
            insecure: tokio_rustls::TlsConnector::from(Arc::new(insecure)),
            user_agent: Some(concat!("sbr/", env!("CARGO_PKG_VERSION"))),
        }
    }

    /// The same client, sending no `User-Agent`: for fetches whose server
    /// should learn nothing about the client (a remote profile).
    pub fn anonymous(&self) -> Self {
        Self {
            user_agent: None,
            ..self.clone()
        }
    }

    /// Pull [`PROOF_BYTES`] through `via` on one connection. Censors that
    /// freeze a flow after its first few kilobytes let a handshake or a
    /// `HEAD` through; this is what they stop.
    pub async fn data_probe(&self, via: &dyn Outbound, target: &Target) -> Verdict {
        let meter = Arc::new(Meter::new());
        let app = AtomicU64::new(0);
        let run = self.data_exchange(via, target, meter.clone(), &app);
        tokio::pin!(run);
        loop {
            let now = Instant::now();
            let end = meter.start + TIMEOUT;
            let next = match meter.last() {
                Some(last) if now >= last + PROBE_GAP => {
                    // Mid-transfer silence. Before any HTTP response bytes it
                    // may be a server that just doesn't speak HTTP.
                    return if app.load(Ordering::Relaxed) > 0 {
                        Verdict::Frozen
                    } else {
                        Verdict::Inconclusive
                    };
                }
                Some(last) => (last + PROBE_GAP).min(end),
                // Look again once data may have started.
                None => (now + PROBE_GAP).min(end),
            };
            // Still moving at the deadline: a slow path, not a frozen one.
            if now >= end {
                return Verdict::Inconclusive;
            }
            tokio::select! {
                r = &mut run => {
                    return match r {
                        Ok(true) => Verdict::Pass,
                        Ok(false) => Verdict::Inconclusive,
                        Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => {
                            Verdict::Reset
                        }
                        Err(_) => Verdict::Inconclusive,
                    };
                }
                _ = tokio::time::sleep_until(next.into()) => {}
            }
        }
    }

    /// Ok(true) once [`PROOF_BYTES`] arrived; Ok(false) if the server closed
    /// or ran out of requests to answer first.
    async fn data_exchange(
        &self,
        via: &dyn Outbound,
        target: &Target,
        meter: Arc<Meter>,
        app: &AtomicU64,
    ) -> io::Result<bool> {
        let (dest, host, path, tls, max) = match target {
            Target::Url(u) => (
                Destination::from_host_port(&u.host, u.port),
                u.host_header(),
                u.path.as_str(),
                u.https.then_some(&self.tls),
                1,
            ),
            Target::Server(d) => (d.clone(), d.to_string(), "/", Some(&self.insecure), MAX_REQUESTS),
        };
        let range = matches!(target, Target::Url(_));
        let stream = Metered {
            inner: via.connect(&dest).await?,
            meter,
        };
        // No User-Agent: a probe to a leaf's own server can reach a site the
        // server fronts for (REALITY's dest), which should not learn sbr is the client.
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\n{}\r\n",
            if range {
                format!("Range: bytes=0-{}\r\n", PROOF_BYTES - 1)
            } else {
                String::new()
            }
        );
        match tls {
            Some(tls) => {
                let name = match &dest.host {
                    sbr_core::Host::Domain(d) => d.to_string(),
                    sbr_core::Host::Ip(ip) => ip.to_string(),
                };
                let name = ServerName::try_from(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                pipeline(tls.connect(name, stream).await?, req.as_bytes(), max, app).await
            }
            None => pipeline(stream, req.as_bytes(), max, app).await,
        }
    }

    /// One request on a fresh connection through `via`. `limit` caps the body.
    pub async fn request(
        &self,
        via: &dyn Outbound,
        method: &str,
        url: &Url,
        headers: &[(&str, &str)],
        limit: usize,
    ) -> io::Result<Response> {
        let stream = via.connect(&Destination::from_host_port(&url.host, url.port)).await?;
        if url.https {
            let name =
                ServerName::try_from(url.host.clone()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let tls = self.tls.connect(name, stream).await?;
            exchange(tls, method, url, self.user_agent, headers, limit).await
        } else {
            exchange(stream, method, url, self.user_agent, headers, limit).await
        }
    }

    /// GET, following up to 5 redirects, failing on a non-2xx/304 status.
    pub async fn get(
        &self,
        via: &dyn Outbound,
        url: &Url,
        headers: &[(&str, &str)],
        limit: usize,
    ) -> io::Result<Response> {
        let mut url = url.clone();
        for _ in 0..=5 {
            let r = tokio::time::timeout(TIMEOUT * 4, self.request(via, "GET", &url, headers, limit))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out"))??;
            if r.status.is_redirection() && r.status != StatusCode::NOT_MODIFIED {
                let next = r
                    .headers
                    .get("location")
                    .and_then(|l| l.to_str().ok())
                    .and_then(|l| url.join(l))
                    .ok_or_else(|| io::Error::other(format!("bad redirect from {}", r.status)))?;
                if url.https && !next.https {
                    return Err(io::Error::other("refusing a redirect from https to http"));
                }
                url = next;
                continue;
            }
            if !(r.status.is_success() || r.status == StatusCode::NOT_MODIFIED) {
                return Err(io::Error::other(format!("unexpected status: {}", r.status)));
            }
            return Ok(r);
        }
        Err(io::Error::other("too many redirects"))
    }

    /// sing-box `urltest.URLTest`: time from dialing to the response head of a
    /// HEAD request (redirects are not followed). In milliseconds, at least 1.
    pub async fn probe(&self, via: &dyn Outbound, url: &Url) -> io::Result<u16> {
        let start = Instant::now();
        tokio::time::timeout(TIMEOUT, self.request(via, "HEAD", url, &[], 0))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "probe timed out"))??;
        Ok(elapsed_ms(start))
    }
}

/// Send `req` up to `max` times on one connection, in batches sized from
/// the responses seen so far, until [`PROOF_BYTES`] of responses arrived.
async fn pipeline<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    req: &[u8],
    max: usize,
    app: &AtomicU64,
) -> io::Result<bool> {
    let mut responses = Responses::default();
    let (mut sent, mut done, mut got) = (1usize, 0usize, 0u64);
    s.write_all(req).await?;
    s.flush().await?;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = s.read(&mut buf).await?;
        if n == 0 {
            return Ok(got >= PROOF_BYTES);
        }
        got += n as u64;
        app.store(got, Ordering::Relaxed);
        if got >= PROOF_BYTES {
            return Ok(true);
        }
        done += responses.feed(&buf[..n])?;
        if done == sent {
            if sent >= max {
                return Ok(false);
            }
            let per = (got / done as u64).max(1);
            let batch = (((PROOF_BYTES - got) / per) as usize + 1).min(BATCH).min(max - sent);
            s.write_all(&req.repeat(batch)).await?;
            s.flush().await?;
            sent += batch;
        }
    }
}

/// Counts complete HTTP/1.1 responses in a byte stream, so pipelined
/// requests can be paced without a full client.
#[derive(Default)]
struct Responses {
    state: Framing,
    line: Vec<u8>,
}

#[derive(Default, Clone, Copy)]
enum Framing {
    #[default]
    Head,
    Body(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkEnd(u8),
    Trailer,
    /// No length: the body runs to EOF.
    UntilClose,
}

impl Responses {
    fn feed(&mut self, mut b: &[u8]) -> io::Result<usize> {
        let mut done = 0;
        while let Some((&c, rest)) = b.split_first() {
            match self.state {
                Framing::Body(n) | Framing::ChunkData(n) => {
                    let k = n.min(b.len() as u64);
                    b = &b[k as usize..];
                    self.state = match (self.state, n - k) {
                        (Framing::Body(_), 0) => {
                            done += 1;
                            Framing::Head
                        }
                        (Framing::Body(_), r) => Framing::Body(r),
                        (_, 0) => Framing::ChunkEnd(2),
                        (_, r) => Framing::ChunkData(r),
                    };
                    continue;
                }
                Framing::ChunkEnd(r) => {
                    self.state = if r == 1 {
                        Framing::ChunkSize
                    } else {
                        Framing::ChunkEnd(r - 1)
                    };
                    b = rest;
                    continue;
                }
                Framing::UntilClose => return Ok(done),
                Framing::Head | Framing::ChunkSize | Framing::Trailer => {}
            }
            b = rest;
            self.line.push(c);
            if self.line.len() > 16 * 1024 {
                return Err(io::Error::other("response head too long"));
            }
            match self.state {
                Framing::Head if self.line.ends_with(b"\r\n\r\n") => {
                    let (state, complete) = head(&self.line)?;
                    self.state = state;
                    done += complete as usize;
                    self.line.clear();
                }
                Framing::ChunkSize if self.line.ends_with(b"\r\n") => {
                    let l = String::from_utf8_lossy(&self.line);
                    let hex = l.trim_end().split(';').next().unwrap_or("").trim();
                    let n = u64::from_str_radix(hex, 16).map_err(|_| io::Error::other("bad chunk size"))?;
                    self.state = if n == 0 {
                        Framing::Trailer
                    } else {
                        Framing::ChunkData(n)
                    };
                    self.line.clear();
                }
                Framing::Trailer if self.line.ends_with(b"\r\n") => {
                    if self.line.len() == 2 {
                        done += 1;
                        self.state = Framing::Head;
                    }
                    self.line.clear();
                }
                _ => {}
            }
        }
        Ok(done)
    }
}

/// The framing that follows a response head, and whether the response is
/// already complete.
fn head(h: &[u8]) -> io::Result<(Framing, bool)> {
    let h = String::from_utf8_lossy(h);
    let mut lines = h.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other("not an HTTP response"))?;
    if (100..200).contains(&status) {
        return Ok((Framing::Head, false));
    }
    if status == 204 || status == 304 {
        return Ok((Framing::Head, true));
    }
    let mut framing = Framing::UntilClose;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
            return Ok((Framing::ChunkSize, false));
        }
        if k.eq_ignore_ascii_case("content-length") {
            let n: u64 = v.parse().map_err(|_| io::Error::other("bad content-length"))?;
            framing = if n == 0 { Framing::Head } else { Framing::Body(n) };
            if n == 0 {
                return Ok((framing, true));
            }
        }
    }
    Ok((framing, false))
}

/// When bytes last arrived below TLS, for telling a stall from a slow path.
struct Meter {
    start: Instant,
    /// Milliseconds after `start`, plus one; 0 before the first byte.
    last: AtomicU64,
}

impl Meter {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn last(&self) -> Option<Instant> {
        match self.last.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(self.start + Duration::from_millis(ms - 1)),
        }
    }
}

struct Metered<S> {
    inner: S,
    meter: Arc<Meter>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            let ms = self.meter.start.elapsed().as_millis() as u64 + 1;
            self.meter.last.store(ms, Ordering::Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
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

pub(crate) fn elapsed_ms(start: Instant) -> u16 {
    start.elapsed().as_millis().clamp(1, u16::MAX as u128) as u16
}

async fn exchange<S>(
    io: S,
    method: &str,
    url: &Url,
    user_agent: Option<&str>,
    headers: &[(&str, &str)],
    limit: usize,
) -> io::Result<Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(io::Error::other)?;
    let driver = tokio::spawn(conn);
    let mut req = Request::builder()
        .method(method)
        .uri(&url.path)
        .header("host", url.host_header())
        .header("connection", "close");
    if let Some(ua) = user_agent {
        req = req.header("user-agent", ua);
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req
        .body(Empty::<Bytes>::new())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let resp = sender.send_request(req).await.map_err(io::Error::other)?;
    let (parts, body) = resp.into_parts();
    let body = if method == "HEAD" {
        Bytes::new()
    } else {
        Limited::new(body, limit)
            .collect()
            .await
            .map_err(|e| io::Error::other(format!("read body: {e}")))?
            .to_bytes()
    };
    driver.abort();
    Ok(Response {
        status: parts.status,
        headers: parts.headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://example.org/a/b.srs?x=1#frag").unwrap();
        assert_eq!(
            (u.https, u.host.as_str(), u.port, u.path.as_str()),
            (true, "example.org", 443, "/a/b.srs?x=1")
        );
        let u = Url::parse("http://[::1]:8080").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("::1", 8080, "/"));
        assert_eq!(u.host_header(), "[::1]:8080");
        assert!(Url::parse("ftp://x").is_none());
        let base = Url::parse("https://a.com/x/y.zip").unwrap();
        assert_eq!(base.join("z.zip").unwrap().path, "/x/z.zip");
        assert_eq!(base.join("/r").unwrap().path, "/r");
        assert_eq!(base.join("https://b.com/q").unwrap().host, "b.com");
    }

    #[test]
    fn counts_pipelined_responses() {
        let mut r = Responses::default();
        let a = b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nnope\n";
        let c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-T: 1\r\n\r\n";
        let e = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
        let all = [&a[..], c, e, a].concat();
        // Byte by byte and all at once agree.
        assert_eq!(r.feed(&all).unwrap(), 4);
        let mut r = Responses::default();
        assert_eq!(all.iter().map(|b| r.feed(&[*b]).unwrap()).sum::<usize>(), 4);
        let mut r = Responses::default();
        assert_eq!(r.feed(b"HTTP/1.1 200 OK\r\n\r\nrest of time").unwrap(), 0);
        assert!(Responses::default().feed(b"SSH-2.0-x\r\n\r\n").is_err());
    }
}
