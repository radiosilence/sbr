//! A small HTTP/1.1 client that dials through an outbound: remote rule-set
//! downloads, the external UI download and `urltest` probes.
//!
//! HTTPS is rustls (aws-lc-rs) with the Mozilla roots from `webpki-roots`,
//! or the trust anchors the host passed in `Settings::http_roots`. Kept
//! separate from the protocol TLS layer on purpose: this only ever talks to
//! ordinary web servers.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::http::{HeaderMap, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use sbr_core::{Destination, Outbound};

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
}

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
        Self {
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
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
            exchange(tls, method, url, headers, limit).await
        } else {
            exchange(stream, method, url, headers, limit).await
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

pub(crate) fn elapsed_ms(start: Instant) -> u16 {
    start.elapsed().as_millis().clamp(1, u16::MAX as u128) as u16
}

async fn exchange<S>(io: S, method: &str, url: &Url, headers: &[(&str, &str)], limit: usize) -> io::Result<Response>
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
        .header("user-agent", concat!("sbr/", env!("CARGO_PKG_VERSION")))
        .header("connection", "close");
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
}
