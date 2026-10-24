use std::io;
use std::sync::Arc;

use sbr_core::{Destination, Metadata, Network};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::Context;
use crate::OpenError;
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
    let (destination, forward_head) = if connect {
        let (h, p) = split_authority(target, 443).ok_or_else(|| bad(target))?;
        (Destination::from_host_port(h, p), None)
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
        (Destination::from_host_port(h, p), Some(out))
    };
    let early = buf[head_len..].to_vec();

    let meta = Metadata {
        inbound: ctx.tag.clone(),
        inbound_type: ctx.type_name(),
        network: Network::Tcp,
        source,
        destination,
        user,
    };
    match ctx.engine.open(&meta).await {
        Ok(mut remote) => {
            if let Some(h) = forward_head {
                remote.write_all(&h).await?;
            } else {
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await?;
            }
            if !early.is_empty() {
                remote.write_all(&early).await?;
            }
            ctx.engine.relay(&meta, s, remote).await
        }
        Err(OpenError::Rejected { drop: true }) => Ok(()),
        Err(OpenError::Rejected { drop: false }) => respond(&mut s, "403 Forbidden").await,
        Err(OpenError::Io(e)) => {
            let status = if e.kind() == io::ErrorKind::TimedOut {
                "504 Gateway Timeout"
            } else {
                "502 Bad Gateway"
            };
            respond(&mut s, status).await?;
            Err(e)
        }
    }
}

async fn respond(s: &mut TcpStream, status: &str) -> io::Result<()> {
    s.write_all(
        format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes(),
    )
    .await
}

fn bad(target: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsupported request target {target:?}"),
    )
}
