//! What a REALITY client does when the server did not authenticate it and
//! relayed the handshake to its cover site: load the site's front page like
//! the browser the ClientHello imitates, then close (sing-box
//! `realityClientFallback`, Xray spiderX). A client that completes the
//! handshake and closes without a request is easy to single out.
//!
//! Only `server_name` and fixed browser headers are sent.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::hello::Fingerprint;
use crate::stream::TlsStream;

/// Upper bound on the whole exchange, close included.
pub(crate) const TIME_LIMIT: Duration = Duration::from_secs(3);
/// Stop reading the response after this many bytes.
const READ_LIMIT: usize = 256 * 1024;

pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0;
const FRAME_HEADERS: u8 = 1;
const FRAME_RST_STREAM: u8 = 3;
const FRAME_SETTINGS: u8 = 4;
const FRAME_PING: u8 = 6;
const FRAME_GOAWAY: u8 = 7;
const FRAME_WINDOW_UPDATE: u8 = 8;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PRIORITY: u8 = 0x20;
const DEFAULT_MAX_FRAME: usize = 16_384;

/// A browser's first HTTP/2 flight and its navigation request headers.
struct Profile {
    settings: &'static [(u16, u32)],
    window_update: u32,
    /// Chrome marks the request exclusive on stream 0 with weight 256.
    priority: bool,
    pseudo: [&'static str; 4],
    headers: &'static [(&'static str, &'static str)],
}

const CHROME: Profile = Profile {
    settings: &[(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)],
    window_update: 15_663_105,
    priority: true,
    pseudo: [":method", ":authority", ":scheme", ":path"],
    headers: &[
        (
            "sec-ch-ua",
            "\"Google Chrome\";v=\"155\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"155\"",
        ),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"macOS\""),
        ("upgrade-insecure-requests", "1"),
        (
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/155.0.0.0 Safari/537.36",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,\
             application/signed-exchange;v=b3;q=0.7",
        ),
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-user", "?1"),
        ("sec-fetch-dest", "document"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("accept-language", "en-US,en;q=0.9"),
        ("priority", "u=0, i"),
    ],
};

const FIREFOX: Profile = Profile {
    settings: &[(1, 65_536), (2, 0), (4, 131_072), (5, 16_384)],
    window_update: 12_517_377,
    priority: false,
    pseudo: [":method", ":path", ":authority", ":scheme"],
    headers: &[
        (
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("accept-language", "en-US,en;q=0.5"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("upgrade-insecure-requests", "1"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-user", "?1"),
        ("priority", "u=0, i"),
        ("te", "trailers"),
    ],
};

const SAFARI_SETTINGS: &[(u16, u32)] = &[(2, 0), (3, 100), (4, 2_097_152), (9, 1)];
const SAFARI_PSEUDO: [&str; 4] = [":method", ":scheme", ":authority", ":path"];

const SAFARI: Profile = Profile {
    settings: SAFARI_SETTINGS,
    window_update: 10_420_225,
    priority: false,
    pseudo: SAFARI_PSEUDO,
    headers: &[
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("sec-fetch-site", "none"),
        ("accept-encoding", "gzip, deflate, br"),
        ("sec-fetch-mode", "navigate"),
        (
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) \
             Version/27.0 Safari/605.1.15",
        ),
        ("accept-language", "en-US,en;q=0.9"),
        ("priority", "u=0, i"),
        ("sec-fetch-dest", "document"),
    ],
};

const IOS: Profile = Profile {
    settings: SAFARI_SETTINGS,
    window_update: 10_420_225,
    priority: false,
    pseudo: SAFARI_PSEUDO,
    headers: &[
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("sec-fetch-site", "none"),
        ("accept-encoding", "gzip, deflate, br"),
        ("sec-fetch-mode", "navigate"),
        (
            "user-agent",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) \
             Version/27.0 Mobile/15E148 Safari/604.1",
        ),
        ("accept-language", "en-US,en;q=0.9"),
        ("priority", "u=0, i"),
        ("sec-fetch-dest", "document"),
    ],
};

fn profile(fp: Fingerprint) -> &'static Profile {
    match fp {
        Fingerprint::Chrome => &CHROME,
        Fingerprint::Firefox => &FIREFOX,
        Fingerprint::Safari => &SAFARI,
        Fingerprint::Ios => &IOS,
    }
}

/// HPACK integer (RFC 7541 §5.1) with an `n`-bit prefix under `flags`.
fn hpack_int(out: &mut Vec<u8>, n: u32, flags: u8, mut v: usize) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

fn hpack_str(out: &mut Vec<u8>, s: &str) {
    hpack_int(out, 7, 0, s.len());
    out.extend_from_slice(s.as_bytes());
}

/// RFC 7541 Appendix A indices for the names this module sends.
fn static_name(name: &str) -> Option<usize> {
    Some(match name {
        ":authority" => 1,
        "accept-encoding" => 16,
        "accept-language" => 17,
        "accept" => 19,
        "user-agent" => 58,
        _ => return None,
    })
}

/// Header block for `GET /`: static-table entries where they match exactly,
/// literals with incremental indexing otherwise, as browsers encode them
/// (without Huffman coding, which is optional).
fn header_block(p: &Profile, authority: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    let literal = |b: &mut Vec<u8>, name: &str, value: &str| {
        match static_name(name) {
            Some(i) => hpack_int(b, 6, 0x40, i),
            None => {
                b.push(0x40);
                hpack_str(b, name);
            }
        }
        hpack_str(b, value);
    };
    for name in p.pseudo {
        match name {
            ":method" => b.push(0x82),
            ":scheme" => b.push(0x87),
            ":path" => b.push(0x84),
            _ => literal(&mut b, name, authority),
        }
    }
    for (name, value) in p.headers {
        literal(&mut b, name, value);
    }
    b
}

fn frame(out: &mut Vec<u8>, ty: u8, flags: u8, stream: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(ty);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
}

/// The client's first HTTP/2 flight: preface, SETTINGS, WINDOW_UPDATE and
/// the request HEADERS on stream 1.
pub(crate) fn h2_request(fp: Fingerprint, authority: &str) -> Vec<u8> {
    let p = profile(fp);
    let mut out = H2_PREFACE.to_vec();
    let settings: Vec<u8> = p
        .settings
        .iter()
        .flat_map(|(id, v)| id.to_be_bytes().into_iter().chain(v.to_be_bytes()))
        .collect();
    frame(&mut out, FRAME_SETTINGS, 0, 0, &settings);
    frame(&mut out, FRAME_WINDOW_UPDATE, 0, 0, &p.window_update.to_be_bytes());
    let mut headers = Vec::new();
    let mut flags = FLAG_END_STREAM | FLAG_END_HEADERS;
    if p.priority {
        flags |= FLAG_PRIORITY;
        headers.extend_from_slice(&[0x80, 0, 0, 0, 255]);
    }
    headers.extend_from_slice(&header_block(p, authority));
    frame(&mut out, FRAME_HEADERS, flags, 1, &headers);
    out
}

pub(crate) fn http1_request(fp: Fingerprint, host: &str) -> Vec<u8> {
    let mut out = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n").into_bytes();
    for (name, value) in profile(fp).headers {
        // Browsers keep HTTP/1.1 names in their traditional case, except the
        // newer sec-*, priority and te headers.
        if !matches!(*name, "priority" | "te") {
            if name.starts_with("sec-") {
                out.extend_from_slice(name.as_bytes());
            } else {
                for (i, part) in name.split('-').enumerate() {
                    if i > 0 {
                        out.push(b'-');
                    }
                    let mut c = part.chars();
                    out.extend(c.next().map(|f| f.to_ascii_uppercase() as u8));
                    out.extend_from_slice(c.as_str().as_bytes());
                }
            }
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Requests `/` from `authority` over `tls` and reads the response until it
/// ends, the server gives up on the stream, or `READ_LIMIT` is reached. The
/// caller bounds the time. Errors only end the exchange early.
pub(crate) async fn browse<S>(tls: &mut TlsStream<S>, fp: Fingerprint, authority: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let h2 = tls.alpn_protocol() == Some(b"h2");
    let req = if h2 {
        h2_request(fp, authority)
    } else {
        http1_request(fp, authority)
    };
    if tls.write_all(&req).await.is_err() || tls.flush().await.is_err() {
        return;
    }
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 16 * 1024];
    let mut total = 0;
    while total < READ_LIMIT {
        let n = match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        total += n;
        buf.extend_from_slice(&chunk[..n]);
        if !h2 {
            // The status line and headers are enough; a browser leaving the
            // page drops the rest of the body the same way.
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                return;
            }
            continue;
        }
        let mut reply = Vec::new();
        let mut used = 0;
        let mut done = false;
        while let Some(head) = buf.get(used..used + 9) {
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let (ty, flags) = (head[3], head[4]);
            let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            if len > DEFAULT_MAX_FRAME {
                return;
            }
            let Some(payload) = buf.get(used + 9..used + 9 + len) else {
                break;
            };
            match ty {
                FRAME_SETTINGS if flags & FLAG_ACK == 0 => frame(&mut reply, FRAME_SETTINGS, FLAG_ACK, 0, &[]),
                FRAME_PING if flags & FLAG_ACK == 0 => frame(&mut reply, FRAME_PING, FLAG_ACK, 0, payload),
                FRAME_HEADERS | FRAME_DATA if stream == 1 && flags & FLAG_END_STREAM != 0 => done = true,
                FRAME_RST_STREAM | FRAME_GOAWAY => done = true,
                _ => {}
            }
            used += 9 + len;
        }
        buf.drain(..used);
        if !reply.is_empty() && (tls.write_all(&reply).await.is_err() || tls.flush().await.is_err()) {
            return;
        }
        if done {
            return;
        }
    }
}
