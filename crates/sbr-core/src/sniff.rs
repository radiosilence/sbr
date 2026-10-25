//! Protocol sniffers. Each takes the first bytes of a stream or the first
//! datagram and says what it is (and the domain, when the protocol carries one).

use sbr_config::Protocol;

#[derive(Debug, PartialEq, Eq)]
pub enum Sniffed {
    /// Recognised. `domain` when the protocol names one (TLS SNI, HTTP Host).
    Found { protocol: Protocol, domain: Option<String> },
    /// Could be this protocol; need more bytes.
    NeedMore,
    /// Not any enabled protocol.
    Unknown,
}

fn wants(enabled: &[Protocol], p: Protocol) -> bool {
    enabled.is_empty() || enabled.contains(&p)
}

/// Stream sniff over the bytes read so far.
pub fn stream(buf: &[u8], enabled: &[Protocol]) -> Sniffed {
    let mut need_more = false;
    for (p, f) in [
        (Protocol::Tls, tls as fn(&[u8]) -> Sniffed),
        (Protocol::Http, http),
        (Protocol::Ssh, ssh),
        (Protocol::Rdp, rdp),
        (Protocol::Bittorrent, bittorrent_tcp),
        (Protocol::Dns, dns_tcp),
    ] {
        if !wants(enabled, p) {
            continue;
        }
        match f(buf) {
            Sniffed::Unknown => {}
            Sniffed::NeedMore => need_more = true,
            found => return found,
        }
    }
    if need_more { Sniffed::NeedMore } else { Sniffed::Unknown }
}

/// Datagram sniff over one packet.
pub fn packet(buf: &[u8], enabled: &[Protocol]) -> Sniffed {
    for (p, f) in [
        (Protocol::Dns, dns_udp as fn(&[u8]) -> Sniffed),
        (Protocol::Quic, quic),
        (Protocol::Stun, stun),
        (Protocol::Dtls, dtls),
        (Protocol::Ntp, ntp),
        (Protocol::Bittorrent, bittorrent_udp),
    ] {
        if wants(enabled, p)
            && let found @ Sniffed::Found { .. } = f(buf)
        {
            return found;
        }
    }
    Sniffed::Unknown
}

fn found(protocol: Protocol, domain: Option<String>) -> Sniffed {
    Sniffed::Found { protocol, domain }
}

/// TLS ClientHello → SNI. Handles a ClientHello split across records only
/// as far as the first record goes (which is all real clients need).
pub fn tls(b: &[u8]) -> Sniffed {
    if b.is_empty() {
        return Sniffed::NeedMore;
    }
    if b[0] != 0x16 {
        return Sniffed::Unknown;
    }
    if b.len() < 5 {
        return Sniffed::NeedMore;
    }
    if b[1] != 3 {
        return Sniffed::Unknown;
    }
    let rec_len = u16::from_be_bytes([b[3], b[4]]) as usize;
    let Some(rec) = b.get(5..5 + rec_len) else {
        return Sniffed::NeedMore;
    };
    match client_hello_sni(rec) {
        Some(sni) => found(Protocol::Tls, sni),
        None => Sniffed::Unknown,
    }
}

/// Parse a handshake message holding a ClientHello. `Some(None)` = valid
/// ClientHello without SNI. Shared with the QUIC sniffer.
pub fn client_hello_sni(h: &[u8]) -> Option<Option<String>> {
    let mut r = Reader(h);
    if r.u8()? != 1 {
        return None;
    }
    let len = r.u24()?;
    let mut r = Reader(r.take(len.min(r.0.len()))?);
    r.take(2 + 32)?; // version, random
    let sid = r.u8()? as usize;
    r.take(sid)?;
    let cs = r.u16()? as usize;
    r.take(cs)?;
    let cm = r.u8()? as usize;
    r.take(cm)?;
    if r.0.is_empty() {
        return Some(None);
    }
    let ext_len = r.u16()? as usize;
    let mut ext = Reader(r.take(ext_len.min(r.0.len()))?);
    while ext.0.len() >= 4 {
        let ty = ext.u16()?;
        let len = ext.u16()? as usize;
        let body = ext.take(len)?;
        if ty == 0 {
            let mut s = Reader(body);
            let _list = s.u16()?;
            while !s.0.is_empty() {
                let kind = s.u8()?;
                let n = s.u16()? as usize;
                let name = s.take(n)?;
                if kind == 0 {
                    let name = std::str::from_utf8(name).ok()?;
                    return Some(Some(name.trim_end_matches('.').to_ascii_lowercase()));
                }
            }
        }
    }
    Some(None)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }
}

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
    b"PRI ",
];

pub fn http(b: &[u8]) -> Sniffed {
    let prefix_ok = HTTP_METHODS.iter().any(|m| {
        let n = m.len().min(b.len());
        b[..n] == m[..n]
    });
    if !prefix_ok {
        return Sniffed::Unknown;
    }
    if !HTTP_METHODS.iter().any(|m| b.starts_with(m)) {
        return Sniffed::NeedMore;
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(b) {
        Ok(httparse::Status::Complete(_)) => {
            let host = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .map(|h| {
                    let h = h.trim();
                    // strip port, keep bracketed v6 intact
                    let host = if let Some(rest) = h.strip_prefix('[') {
                        rest.split(']').next().unwrap_or(rest)
                    } else {
                        h.rsplit_once(':')
                            .map_or(h, |(a, p)| if p.parse::<u16>().is_ok() { a } else { h })
                    };
                    host.to_ascii_lowercase()
                })
                .filter(|h| !h.is_empty());
            found(Protocol::Http, host)
        }
        Ok(httparse::Status::Partial) if b.len() < 8192 => Sniffed::NeedMore,
        _ => Sniffed::Unknown,
    }
}

fn ssh(b: &[u8]) -> Sniffed {
    let m = b"SSH-2.0-";
    let n = m.len().min(b.len());
    if b[..n] != m[..n] {
        Sniffed::Unknown
    } else if b.len() < m.len() {
        Sniffed::NeedMore
    } else {
        found(Protocol::Ssh, None)
    }
}

fn rdp(b: &[u8]) -> Sniffed {
    // TPKT v3 + X.224 Connection Request (0xe0)
    if b.len() < 6 {
        return if b.first().is_none_or(|&x| x == 3) {
            Sniffed::NeedMore
        } else {
            Sniffed::Unknown
        };
    }
    if b[0] == 3 && b[1] == 0 && b[5] == 0xe0 {
        found(Protocol::Rdp, None)
    } else {
        Sniffed::Unknown
    }
}

fn bittorrent_tcp(b: &[u8]) -> Sniffed {
    let m = b"\x13BitTorrent protocol";
    let n = m.len().min(b.len());
    if b[..n] != m[..n] {
        Sniffed::Unknown
    } else if b.len() < m.len() {
        Sniffed::NeedMore
    } else {
        found(Protocol::Bittorrent, None)
    }
}

fn dns_tcp(b: &[u8]) -> Sniffed {
    if b.len() < 2 + 12 {
        return Sniffed::Unknown; // never block a stream waiting for DNS
    }
    let len = u16::from_be_bytes([b[0], b[1]]) as usize;
    match b.get(2..2 + len) {
        Some(msg) => dns_udp(msg),
        None => Sniffed::Unknown,
    }
}

fn dns_udp(b: &[u8]) -> Sniffed {
    match crate::dns::wire::Query::parse(b) {
        Some(q) if !q.name.is_empty() => found(Protocol::Dns, None),
        _ => Sniffed::Unknown,
    }
}

/// QUIC long-header Initial (v1/v2). SNI needs decrypting the Initial
/// packet; detection is enough for `protocol: quic` rules.
fn quic(b: &[u8]) -> Sniffed {
    if b.len() < 7 || b[0] & 0xc0 != 0xc0 {
        return Sniffed::Unknown;
    }
    let version = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
    let initial = match version {
        1 => (b[0] >> 4) & 0x3 == 0,
        0x6b33_43cf => (b[0] >> 4) & 0x3 == 1,        // v2 renumbers packet types
        v if v & 0x0f0f_0f0f == 0x0a0a_0a0a => false, // version negotiation grease
        0xff00_001d..=0xff00_0020 => (b[0] >> 4) & 0x3 == 0, // drafts
        _ => false,
    };
    if initial && b.len() >= 1200 {
        found(Protocol::Quic, None)
    } else {
        Sniffed::Unknown
    }
}

fn stun(b: &[u8]) -> Sniffed {
    if b.len() >= 20 && b[0] & 0xc0 == 0 && b[4..8] == [0x21, 0x12, 0xa4, 0x42] {
        found(Protocol::Stun, None)
    } else {
        Sniffed::Unknown
    }
}

fn dtls(b: &[u8]) -> Sniffed {
    if b.len() >= 13 && (20..=26).contains(&b[0]) && b[1] == 0xfe && (b[2] == 0xff || b[2] == 0xfd) {
        found(Protocol::Dtls, None)
    } else {
        Sniffed::Unknown
    }
}

fn ntp(b: &[u8]) -> Sniffed {
    // 48-byte header, version 3/4, client mode
    if b.len() >= 48 && matches!((b[0] >> 3) & 7, 3 | 4) && b[0] & 7 == 3 {
        found(Protocol::Ntp, None)
    } else {
        Sniffed::Unknown
    }
}

fn bittorrent_udp(b: &[u8]) -> Sniffed {
    // uTP SYN (version 1, type 4) or a DHT bencoded dict
    if (b.len() >= 20 && b[0] == 0x41) || (b.starts_with(b"d1:") && b.ends_with(b"e")) {
        found(Protocol::Bittorrent, None)
    } else {
        Sniffed::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real ClientHello prefix (curl → example.com), trimmed to the SNI.
    fn client_hello(sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        let name = sni.as_bytes();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn tls_sni() {
        let ch = client_hello("Example.COM");
        assert_eq!(stream(&ch, &[]), found(Protocol::Tls, Some("example.com".into())));
        assert_eq!(stream(&ch[..20], &[]), Sniffed::NeedMore);
        assert_eq!(
            stream(&ch, &[Protocol::Http]),
            Sniffed::Unknown,
            "respects the sniffer list"
        );
    }

    #[test]
    fn http_host() {
        assert_eq!(
            http(b"GET / HTTP/1.1\r\nHost: a.com:8080\r\n\r\n"),
            found(Protocol::Http, Some("a.com".into()))
        );
        assert_eq!(http(b"GET / HTTP/1.1\r\nHo"), Sniffed::NeedMore);
        assert_eq!(http(b"GE"), Sniffed::NeedMore);
        assert_eq!(http(b"\x16\x03"), Sniffed::Unknown);
    }

    #[test]
    fn datagrams() {
        let q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        assert_eq!(packet(q, &[]), found(Protocol::Dns, None));
        let mut stun_pkt = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        stun_pkt.extend_from_slice(&[0; 12]);
        assert_eq!(packet(&stun_pkt, &[]), found(Protocol::Stun, None));
        let mut quic_pkt = vec![0xc3, 0, 0, 0, 1];
        quic_pkt.resize(1200, 0);
        assert_eq!(packet(&quic_pkt, &[]), found(Protocol::Quic, None));
        assert_eq!(packet(b"hello", &[]), Sniffed::Unknown);
    }
}
