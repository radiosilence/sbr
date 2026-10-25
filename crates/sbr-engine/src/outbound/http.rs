use std::io;

use base64::Engine as _;
use sbr_config::HttpOutbound;
use sbr_core::{BoxFuture, Destination, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{BuildContext, Upstream};
use crate::httpx;
use crate::tls::TlsClient;
use crate::transport::ServerDialer;
use sbr_core::Outbound;

/// HTTP/1.1 CONNECT client, optionally over TLS (an "HTTPS proxy").
pub struct HttpConnect {
    tag: String,
    extra_headers: String,
    path: Option<String>,
    dialer: ServerDialer,
}

impl HttpConnect {
    pub fn new(tag: String, c: &HttpOutbound, upstream: Upstream, ctx: &BuildContext) -> Result<Self, String> {
        let mut extra = String::new();
        if let Some(u) = &c.username {
            let cred = format!("{u}:{}", c.password.as_deref().unwrap_or_default());
            extra.push_str(&format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64::engine::general_purpose::STANDARD.encode(cred)
            ));
        }
        for (k, v) in &c.headers {
            extra.push_str(&format!("{k}: {v}\r\n"));
        }
        let tls = match c.tls.as_ref().filter(|t| t.enabled) {
            // We speak HTTP/1.1 only, so offer only that unless told otherwise.
            Some(t) => {
                Some(TlsClient::new(t, &c.server.server, ctx.base_dir.as_deref())?.with_default_alpn(&["http/1.1"]))
            }
            None => None,
        };
        let server = Destination::from_host_port(&c.server.server, c.server.server_port);
        Ok(Self {
            tag,
            extra_headers: extra,
            path: c.path.clone(),
            dialer: ServerDialer::new(upstream, server, tls),
        })
    }
}

impl Outbound for HttpConnect {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "http"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            let mut s = self.dialer.connect().await?;
            // Go's `Request.Write` uses the path as the request target when set.
            let target = match &self.path {
                Some(p) if p.starts_with('/') => p.clone(),
                Some(p) => format!("/{p}"),
                None => dest.to_string(),
            };
            let req = format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {dest}\r\n{}\r\n",
                self.extra_headers
            );
            s.write_all(req.as_bytes()).await?;
            s.flush().await?;
            // Read exactly the response head, byte-wise, so no tunnel bytes are consumed.
            let mut head = Vec::with_capacity(256);
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() > httpx::MAX_HEAD {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "proxy response head too large",
                    ));
                }
                head.push(s.read_u8().await?);
            }
            let status = httpx::status_code(&head)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad proxy response"))?;
            if !(200..300).contains(&status) {
                let kind = if status == 407 || status == 403 {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::ConnectionRefused
                };
                return Err(io::Error::new(kind, format!("HTTP proxy replied {status}")));
            }
            Ok(s)
        })
    }
}
