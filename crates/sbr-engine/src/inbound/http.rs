use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use sbr_core::{BoxFuture, Destination, Metadata, Network};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::Context;
use crate::dispatch::{InboundStream, OpenError};
use crate::httpx::{read_request_head, split_authority};

const HOP_BY_HOP: &[&str] = &[
    "proxy-connection",
    "proxy-authorization",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
];

/// The client after the request head. For CONNECT, `200` is sent lazily;
/// for forward requests the rewritten head (plus any early body bytes) is
/// replayed as the first bytes "from the client", so sniffing and the relay
/// see a normal origin-form request.
struct HttpClient {
    s: TcpStream,
    prefix: Vec<u8>,
    pos: usize,
    connect: bool,
    replied: bool,
}

impl InboundStream for HttpClient {
    fn ready(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            if !self.replied {
                self.replied = true;
                if self.connect {
                    self.s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
                }
            }
            Ok(())
        })
    }
    fn fail<'a>(&'a mut self, err: &'a OpenError) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            if self.replied {
                return Ok(());
            }
            self.replied = true;
            let status = match err {
                OpenError::Rejected { drop: true } => return Ok(()),
                OpenError::Rejected { drop: false } => "403 Forbidden",
                OpenError::Io(e) if e.kind() == io::ErrorKind::TimedOut => "504 Gateway Timeout",
                OpenError::Io(_) => "502 Bad Gateway",
            };
            self.s
                .write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await
        })
    }
}

impl AsyncRead for HttpClient {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.s).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpClient {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.s).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_shutdown(cx)
    }
}

pub async fn handle(ctx: &Context, mut s: TcpStream, buf: Vec<u8>) -> io::Result<()> {
    let source = s.peer_addr()?;
    let (buf, head_len) = read_request_head(&mut s, buf).await?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let method = req.method.unwrap_or_default();
    let target = req.path.unwrap_or_default();

    let mut user: Option<Arc<str>> = None;
    if !ctx.users.is_empty() {
        user = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
            .and_then(|h| ctx.check_basic(h.value));
        if user.is_none() {
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"sbr\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(());
        }
    }

    let connect = method.eq_ignore_ascii_case("CONNECT");
    let (destination, mut prefix) = if connect {
        let (h, p) = split_authority(target, 443).ok_or_else(|| bad(target))?;
        (Destination::from_host_port(h, p), Vec::new())
    } else {
        // Absolute-form proxy request: rewrite to origin-form and drop
        // proxy/hop-by-hop headers. `Connection: close` keeps one upstream per
        // client connection, so a keep-alive client can't smuggle a second
        // request to a different host through the first host's route.
        let rest = target.strip_prefix("http://").ok_or_else(|| bad(target))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (h, p) = split_authority(authority, 80).ok_or_else(|| bad(target))?;
        let mut out = Vec::with_capacity(head_len + 32);
        out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
        let mut has_host = false;
        for hd in req.headers.iter() {
            let name = hd.name.to_ascii_lowercase();
            if HOP_BY_HOP.contains(&name.as_str()) {
                continue;
            }
            has_host |= name == "host";
            out.extend_from_slice(hd.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(hd.value);
            out.extend_from_slice(b"\r\n");
        }
        if !has_host {
            out.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
        }
        out.extend_from_slice(b"Connection: close\r\n\r\n");
        (Destination::from_host_port(h, p), out)
    };
    prefix.extend_from_slice(&buf[head_len..]);

    let mut meta = Metadata::new(ctx.tag.clone(), ctx.type_name(), Network::Tcp, source, destination);
    meta.user = user;
    ctx.engine
        .handle_tcp(
            meta,
            HttpClient {
                s,
                prefix,
                pos: 0,
                connect,
                replied: false,
            },
        )
        .await
}

fn bad(target: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsupported request target {target:?}"),
    )
}
