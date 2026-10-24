//! Minimal HTTP/1.x head handling for the proxy inbound and CONNECT outbound.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_HEAD: usize = 16 * 1024;

pub fn status_code(head: &[u8]) -> Option<u16> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);
    match res.parse(head) {
        Ok(httparse::Status::Complete(_)) => res.code,
        _ => None,
    }
}

/// Read until a complete request head is buffered. Returns the buffer and
/// the head length; anything after it is early payload.
pub async fn read_request_head<R: AsyncRead + Unpin>(
    r: &mut R,
    mut buf: Vec<u8>,
) -> io::Result<(Vec<u8>, usize)> {
    loop {
        {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&buf) {
                Ok(httparse::Status::Complete(n)) => return Ok((buf, n)),
                Ok(httparse::Status::Partial) => {}
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("bad HTTP request: {e}"),
                    ));
                }
            }
        }
        if buf.len() >= MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request head too large",
            ));
        }
        let start = buf.len();
        buf.resize(MAX_HEAD.min(start + 4096), 0);
        let n = r.read(&mut buf[start..]).await?;
        buf.truncate(start + n);
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
}

/// Split `host:port`, `[v6]:port`, or bare host with a default port.
pub fn split_authority(s: &str, default_port: u16) -> Option<(&str, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return Some((host, port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h, p.parse().ok()?)),
        _ if !s.is_empty() => Some((s, default_port)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority() {
        assert_eq!(split_authority("a.com:443", 80), Some(("a.com", 443)));
        assert_eq!(split_authority("a.com", 80), Some(("a.com", 80)));
        assert_eq!(split_authority("[::1]:8080", 80), Some(("::1", 8080)));
        assert_eq!(split_authority("[::1]", 80), Some(("::1", 80)));
        assert_eq!(split_authority("a.com:x", 80), None);
    }
}
