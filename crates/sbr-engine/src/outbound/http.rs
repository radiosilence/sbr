use std::io;

use base64::Engine as _;
use sbr_config::HttpOutbound;
use sbr_core::{BoxFuture, Destination, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Upstream;
use crate::httpx;
use sbr_core::Outbound;

/// HTTP/1.1 CONNECT client (plain; TLS-wrapped proxies come with the TLS layer).
pub struct HttpConnect {
    tag: String,
    server: Destination,
    extra_headers: String,
    upstream: Upstream,
}

impl HttpConnect {
    pub fn new(tag: String, c: &HttpOutbound, upstream: Upstream) -> Self {
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
        Self {
            tag,
            server: Destination::from_host_port(&c.server.server, c.server.server_port),
            extra_headers: extra,
            upstream,
        }
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
            let mut s = self.upstream.connect(&self.server).await?;
            let req = format!("CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n{}\r\n", self.extra_headers);
            s.write_all(req.as_bytes()).await?;
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
