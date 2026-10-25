//! DNS over HTTPS (RFC 8484) on HTTP/2: one connection per server, one
//! stream per query, message ID 0 as the RFC recommends.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use bytes::Bytes;
use hickory_proto::op::Message;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use sbr_core::BoxFuture;

use super::tls::Tls;
use super::{Remote, Transport};
use crate::msg;

const MIME: &str = "application/dns-message";
/// Largest DNS message.
const MAX_BODY: usize = 65535;

pub(crate) struct Https {
    remote: Remote,
    tls: Tls,
    authority: String,
    path: String,
    get: bool,
    headers: HeaderMap,
    conn: tokio::sync::Mutex<Option<(h2::client::SendRequest<Bytes>, Arc<AtomicBool>)>>,
}

fn h2err(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io().unwrap_or_else(|| io::Error::other("h2 I/O error"))
    } else {
        io::Error::other(e)
    }
}

impl Https {
    /// `authority` is the Host the server expects (its `server_name` or address).
    pub fn new(
        remote: Remote,
        tls: Tls,
        authority: String,
        path: &str,
        get: bool,
        headers: &[(String, String)],
    ) -> Result<Self, String> {
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| format!("header {k:?}: {e}"))?;
            let value = HeaderValue::from_str(v).map_err(|e| format!("header {k:?}: {e}"))?;
            map.append(name, value);
        }
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        // Validate once so per-query URI building cannot fail.
        format!("https://{authority}{path}")
            .parse::<Uri>()
            .map_err(|e| format!("invalid DoH URL: {e}"))?;
        Ok(Self {
            remote,
            tls,
            authority,
            path,
            get,
            headers: map,
            conn: tokio::sync::Mutex::new(None),
        })
    }

    pub fn set_resolver(&mut self, r: Option<super::Resolver>) {
        self.remote.resolver = r;
    }

    async fn sender(&self) -> io::Result<(h2::client::SendRequest<Bytes>, bool)> {
        let mut slot = self.conn.lock().await;
        if let Some((s, dead)) = slot.as_ref()
            && !dead.load(Ordering::Acquire)
        {
            return Ok((s.clone(), true));
        }
        let stream = self.remote.connect().await?;
        let (stream, alpn) = self.tls.connect(stream).await?;
        if alpn.as_deref() != Some(b"h2") {
            return Err(io::Error::other("DoH server did not negotiate HTTP/2"));
        }
        let (send, conn) = h2::client::handshake(stream).await.map_err(h2err)?;
        let dead = Arc::new(AtomicBool::new(false));
        {
            let dead = dead.clone();
            tokio::spawn(async move {
                let _ = conn.await;
                dead.store(true, Ordering::Release);
            });
        }
        *slot = Some((send.clone(), dead));
        Ok((send, false))
    }

    async fn round_trip(&self, send: h2::client::SendRequest<Bytes>, raw: Vec<u8>) -> io::Result<Message> {
        let mut send = send.ready().await.map_err(h2err)?;
        let (method, uri) = if self.get {
            let q = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
            (Method::GET, format!("https://{}{}?dns={q}", self.authority, self.path))
        } else {
            (Method::POST, format!("https://{}{}", self.authority, self.path))
        };
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header(ACCEPT, MIME)
            .body(())
            .map_err(io::Error::other)?;
        if !self.get {
            // Cloudflare answers 400 to a POST without a length.
            req.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(MIME));
            req.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from(raw.len()));
        }
        for (k, v) in &self.headers {
            req.headers_mut().append(k, v.clone());
        }
        let (resp, mut body_tx) = send.send_request(req, self.get).map_err(h2err)?;
        if !self.get {
            body_tx.send_data(Bytes::from(raw), true).map_err(h2err)?;
        }
        let resp = resp.await.map_err(h2err)?;
        if resp.status() != StatusCode::OK {
            return Err(io::Error::other(format!("DoH server answered HTTP {}", resp.status())));
        }
        let mut body = resp.into_body();
        let mut buf = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(h2err)?;
            let _ = body.flow_control().release_capacity(chunk.len());
            if buf.len() + chunk.len() > MAX_BODY {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "DoH response too large"));
            }
            buf.extend_from_slice(&chunk);
        }
        msg::decode(&buf)
    }
}

impl Transport for Https {
    fn exchange<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, io::Result<Message>> {
        Box::pin(async move {
            let raw = super::stream::encode_with_id(query, 0)?;
            let (send, reused) = self.sender().await?;
            match self.round_trip(send, raw.clone()).await {
                // The server may have just closed an idle connection.
                Err(_) if reused => {
                    *self.conn.lock().await = None;
                    let (send, _) = self.sender().await?;
                    self.round_trip(send, raw).await
                }
                r => r,
            }
        })
    }
}
