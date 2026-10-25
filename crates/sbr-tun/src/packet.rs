//! IPv4/IPv6 + TCP/UDP header access and in-place rewriting with
//! incremental checksum updates (RFC 1624). No allocation on the TCP path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// A parsed view of an IP packet carrying TCP or UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub v6: bool,
    pub proto: u8,
    /// Offset of the transport header.
    pub l4: usize,
    /// Total packet length per the IP header (≤ buffer length).
    pub len: usize,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// TCP flag bits.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

/// IPv6 extension headers walked to reach the transport header.
const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_FRAGMENT: u8 = 44;
const EXT_DEST_OPTS: u8 = 60;
/// Bound on the extension-header walk. Real stacks emit at most two or three.
const MAX_EXT: usize = 8;

/// One fragment of an IP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    pub v6: bool,
    /// The IPv4 protocol, or the Next Header of the IPv6 Fragment header
    /// (meaningful only in the first fragment).
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub id: u32,
    /// Byte offset of this fragment's data within the fragmentable part.
    pub offset: usize,
    pub more: bool,
    /// This fragment's data is `p[start..end]`.
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ip {
    Whole(Parsed),
    Fragment(Fragment),
}

/// A whole TCP or UDP packet; fragments and other protocols are `None`.
pub fn parse(p: &[u8]) -> Option<Parsed> {
    match classify(p)? {
        Ip::Whole(h) => Some(h),
        Ip::Fragment(_) => None,
    }
}

/// Parse a TCP/UDP packet, or identify a fragment of any protocol. IPv6
/// Hop-by-Hop, Routing and Destination Options headers are skipped, and
/// atomic fragments (offset 0, no more) are treated as whole packets
/// (RFC 6946).
pub fn classify(p: &[u8]) -> Option<Ip> {
    let version = p.first()? >> 4;
    let (v6, proto, l4, len, src_ip, dst_ip) = match version {
        4 => {
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            if ihl < 20 || p.len() < ihl {
                return None;
            }
            let len = rd16(p, 2) as usize;
            if len > p.len() || len < ihl {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
            let frag = rd16(p, 6);
            if frag & 0x3fff != 0 {
                return Some(Ip::Fragment(Fragment {
                    v6: false,
                    proto: p[9],
                    src,
                    dst,
                    id: rd16(p, 4) as u32,
                    offset: ((frag & 0x1fff) as usize) * 8,
                    more: frag & 0x2000 != 0,
                    start: ihl,
                    end: len,
                }));
            }
            (false, p[9], ihl, len, src, dst)
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let len = 40 + rd16(p, 4) as usize;
            if len > p.len() {
                return None;
            }
            let src: [u8; 16] = p[8..24].try_into().ok()?;
            let dst: [u8; 16] = p[24..40].try_into().ok()?;
            let (src, dst) = (IpAddr::V6(Ipv6Addr::from(src)), IpAddr::V6(Ipv6Addr::from(dst)));
            let (mut next, mut at) = (p[6], 40);
            let mut hops = 0;
            while next != PROTO_TCP && next != PROTO_UDP {
                hops += 1;
                if hops > MAX_EXT || at + 8 > len {
                    return None;
                }
                match next {
                    EXT_HOP_BY_HOP | EXT_DEST_OPTS => {}
                    // Segments Left > 0 means we are not the final
                    // destination and the pseudo-header address is unknown.
                    EXT_ROUTING if p[at + 3] == 0 => {}
                    EXT_FRAGMENT => {
                        let off_m = rd16(p, at + 2);
                        let (offset, more) = ((off_m & !7) as usize, off_m & 1 != 0);
                        if offset != 0 || more {
                            return Some(Ip::Fragment(Fragment {
                                v6: true,
                                proto: p[at],
                                src,
                                dst,
                                id: u32::from_be_bytes(p[at + 4..at + 8].try_into().ok()?),
                                offset,
                                more,
                                start: at + 8,
                                end: len,
                            }));
                        }
                        next = p[at];
                        at += 8;
                        continue;
                    }
                    _ => return None,
                }
                next = p[at];
                at += (p[at + 1] as usize + 1) * 8;
            }
            (true, next, at, len, src, dst)
        }
        _ => return None,
    };
    let min = if proto == PROTO_TCP { 20 } else { 8 };
    if (proto != PROTO_TCP && proto != PROTO_UDP) || len < l4 + min {
        return None;
    }
    let sport = rd16(p, l4);
    let dport = rd16(p, l4 + 2);
    Some(Ip::Whole(Parsed {
        v6,
        proto,
        l4,
        len,
        src: SocketAddr::new(src_ip, sport),
        dst: SocketAddr::new(dst_ip, dport),
    }))
}

pub fn tcp_flags(p: &[u8], h: &Parsed) -> u8 {
    p[h.l4 + 13]
}

// --- checksum arithmetic -------------------------------------------------

#[inline]
pub(crate) fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m').
#[inline]
fn update(check: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = (!check) as u32;
    for c in old.chunks(2) {
        sum += (!u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])) as u32;
    }
    for c in new.chunks(2) {
        sum += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    !fold(sum)
}

pub(crate) fn sum16(data: &[u8], mut sum: u32) -> u32 {
    let (chunks, rest) = data.as_chunks::<2>();
    for c in chunks {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if let [b] = rest {
        sum += (*b as u32) << 8;
    }
    sum
}

pub(crate) fn rd16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

pub(crate) fn wr16(p: &mut [u8], at: usize, v: u16) {
    p[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// Rewrite source and destination address/port in place, fixing the IPv4
/// header checksum and the TCP/UDP checksum incrementally. Address families
/// must match the packet's.
pub fn rewrite(p: &mut [u8], h: &Parsed, src: SocketAddr, dst: SocketAddr) {
    let (sa, da, alen) = if h.v6 { (8, 24, 16) } else { (12, 16, 4) };
    let ck_at = h.l4 + if h.proto == PROTO_TCP { 16 } else { 6 };
    let mut l4ck = rd16(p, ck_at);
    // UDP over IPv4 may omit its checksum (0): keep it omitted.
    let l4_has_ck = !(h.proto == PROTO_UDP && !h.v6 && l4ck == 0);

    let new_src = ip_bytes(src.ip());
    let new_dst = ip_bytes(dst.ip());
    debug_assert_eq!(src.is_ipv6(), h.v6, "address family must match the packet");

    for (at, new) in [(sa, &new_src[..alen]), (da, &new_dst[..alen])] {
        if p[at..at + alen] != *new {
            if !h.v6 {
                let ipck = update(rd16(p, 10), &p[at..at + alen], new);
                wr16(p, 10, ipck);
            }
            if l4_has_ck {
                l4ck = update(l4ck, &p[at..at + alen], new); // pseudo-header
            }
            p[at..at + alen].copy_from_slice(new);
        }
    }
    for (at, port) in [(h.l4, src.port()), (h.l4 + 2, dst.port())] {
        let old = rd16(p, at);
        if old != port {
            if l4_has_ck {
                l4ck = update(l4ck, &old.to_be_bytes(), &port.to_be_bytes());
            }
            wr16(p, at, port);
        }
    }
    if l4_has_ck {
        if h.proto == PROTO_UDP && l4ck == 0 {
            l4ck = 0xffff;
        }
        wr16(p, ck_at, l4ck);
    }
}

fn ip_bytes(ip: IpAddr) -> [u8; 16] {
    let mut b = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => b[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => b.copy_from_slice(&v6.octets()),
    }
    b
}

/// Build a complete IPv4/IPv6 UDP packet into `out` (cleared first).
/// Families of `src` and `dst` must match.
pub fn build_udp(out: &mut Vec<u8>, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
    out.clear();
    let udp_len = 8 + payload.len();
    let mut pseudo = 0u32;
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + udp_len;
            out.extend_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0]);
            wr_len(out, 2, total as u16);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            let ipck = !fold(sum16(&out[..20], 0));
            wr16(out, 10, ipck);
            pseudo = sum16(&s.octets(), pseudo);
            pseudo = sum16(&d.octets(), pseudo);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&(udp_len as u16).to_be_bytes());
            out.extend_from_slice(&[PROTO_UDP, 64]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            pseudo = sum16(&s.octets(), pseudo);
            pseudo = sum16(&d.octets(), pseudo);
        }
        _ => unreachable!("address family mismatch"),
    }
    pseudo += PROTO_UDP as u32 + udp_len as u32;
    let l4 = out.len();
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst.port().to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let mut ck = !fold(sum16(&out[l4..], pseudo));
    if ck == 0 {
        ck = 0xffff;
    }
    wr16(out, l4 + 6, ck);
}

/// Split a whole packet into fragments of at most `mtu` bytes, acting as
/// the source host (RFC 791 §3.2, RFC 8200 §4.5). Each fragment is written
/// to `out[headroom..]` and handed to `each`. IPv4 options are copied into
/// every fragment and DF is cleared; IPv6 packets must carry no extension
/// headers that belong in the unfragmentable part (none of ours do).
/// Returns false, emitting nothing, when `mtu` is too small to fragment.
pub fn fragment(
    p: &[u8],
    mtu: usize,
    id: u32,
    headroom: usize,
    out: &mut Vec<u8>,
    mut each: impl FnMut(&mut [u8]),
) -> bool {
    let v6 = p[0] >> 4 == 6;
    let (hdr, len) = if v6 {
        (40, 40 + rd16(p, 4) as usize)
    } else {
        (((p[0] & 0x0f) as usize) * 4, rd16(p, 2) as usize)
    };
    let fhdr = if v6 { hdr + 8 } else { hdr };
    if mtu < fhdr + 8 {
        return false;
    }
    let step = (mtu - fhdr) & !7;
    let data = &p[hdr..len];
    let mut off = 0;
    while off < data.len() {
        let n = step.min(data.len() - off);
        let more = (off + n < data.len()) as u16;
        out.clear();
        out.resize(headroom, 0);
        out.extend_from_slice(&p[..hdr]);
        if v6 {
            out.extend_from_slice(&[p[6], 0]);
            out.extend_from_slice(&(off as u16 | more).to_be_bytes());
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.extend_from_slice(&data[off..off + n]);
        let h = &mut out[headroom..];
        if v6 {
            wr16(h, 4, (8 + n) as u16);
            h[6] = EXT_FRAGMENT;
        } else {
            wr16(h, 2, (hdr + n) as u16);
            wr16(h, 4, id as u16);
            wr16(h, 6, more << 13 | (off / 8) as u16);
            wr16(h, 10, 0);
            let ck = !fold(sum16(&h[..hdr], 0));
            wr16(h, 10, ck);
        }
        each(out);
        off += n;
    }
    true
}

fn wr_len(out: &mut [u8], at: usize, v: u16) {
    wr16(out, at, v)
}

/// Full checksum verification, for tests.
pub fn verify(p: &[u8]) -> bool {
    let Some(h) = parse(p) else { return false };
    if !h.v6 && fold(sum16(&p[..h.l4], 0)) != 0xffff {
        return false;
    }
    let mut pseudo = 0u32;
    pseudo = sum16(&ip_bytes(h.src.ip())[..if h.v6 { 16 } else { 4 }], pseudo);
    pseudo = sum16(&ip_bytes(h.dst.ip())[..if h.v6 { 16 } else { 4 }], pseudo);
    pseudo += h.proto as u32 + (h.len - h.l4) as u32;
    fold(sum16(&p[h.l4..h.len], pseudo)) == 0xffff
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP SYN with a valid checksum, built by hand.
    fn tcp_syn(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let mut p = Vec::new();
        build_udp(&mut p, src, dst, &[0u8; 12]); // reuse the IP header builder
        let l4 = if src.is_ipv4() { 20 } else { 40 };
        // turn the UDP packet into a 20-byte TCP header
        if src.is_ipv4() {
            p[9] = PROTO_TCP;
            p[10] = 0;
            p[11] = 0;
            let ck = !fold(sum16(&p[..20], 0));
            wr16(&mut p, 10, ck);
        } else {
            p[6] = PROTO_TCP;
        }
        let tcp = &mut p[l4..];
        tcp[4..8].copy_from_slice(&[0, 0, 0, 1]); // seq
        tcp[8..12].copy_from_slice(&[0; 4]);
        tcp[12] = 5 << 4;
        tcp[13] = SYN;
        tcp[14..16].copy_from_slice(&[0xff, 0xff]);
        tcp[16..20].copy_from_slice(&[0; 4]);
        let mut pseudo = sum16(&ip_bytes(src.ip())[..if src.is_ipv4() { 4 } else { 16 }], 0);
        pseudo = sum16(&ip_bytes(dst.ip())[..if src.is_ipv4() { 4 } else { 16 }], pseudo);
        pseudo += PROTO_TCP as u32 + 20;
        let ck = !fold(sum16(&p[l4..], pseudo));
        wr16(&mut p, l4 + 16, ck);
        p
    }

    #[test]
    fn udp_build_parse_verify() {
        for (s, d) in [("10.0.0.1:53", "172.19.0.1:40000"), ("[fd00::1]:53", "[fd00::2]:40000")] {
            let (s, d): (SocketAddr, SocketAddr) = (s.parse().unwrap(), d.parse().unwrap());
            let mut p = Vec::new();
            build_udp(&mut p, s, d, b"hello world");
            assert!(verify(&p));
            let h = parse(&p).unwrap();
            assert_eq!((h.src, h.dst, h.proto), (s, d, PROTO_UDP));
            assert_eq!(&p[h.l4 + 8..h.len], b"hello world");
        }
    }

    #[test]
    fn rewrite_keeps_checksums_valid() {
        for (s, d, ns, nd) in [
            ("172.19.0.1:51000", "1.2.3.4:443", "172.19.0.2:10001", "172.19.0.1:8000"),
            (
                "[fdfe::1]:51000",
                "[2001:db8::1]:443",
                "[fdfe::2]:10001",
                "[fdfe::1]:8000",
            ),
        ] {
            let (s, d, ns, nd): (SocketAddr, SocketAddr, SocketAddr, SocketAddr) = (
                s.parse().unwrap(),
                d.parse().unwrap(),
                ns.parse().unwrap(),
                nd.parse().unwrap(),
            );
            let mut p = tcp_syn(s, d);
            assert!(verify(&p), "fixture is valid");
            let h = parse(&p).unwrap();
            assert_eq!(tcp_flags(&p, &h), SYN);
            rewrite(&mut p, &h, ns, nd);
            assert!(verify(&p), "incremental update must equal a full recompute");
            let h2 = parse(&p).unwrap();
            assert_eq!((h2.src, h2.dst), (ns, nd));
            // and back again
            rewrite(&mut p, &h2, s, d);
            assert!(verify(&p));
            assert_eq!(p, tcp_syn(s, d));
        }
        // UDP too
        let mut p = Vec::new();
        build_udp(
            &mut p,
            "172.19.0.1:5000".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
            b"q",
        );
        let h = parse(&p).unwrap();
        rewrite(&mut p, &h, "10.0.0.1:1".parse().unwrap(), "9.9.9.9:53".parse().unwrap());
        assert!(verify(&p));
    }

    #[test]
    fn rejects_fragments_and_garbage() {
        let mut p = Vec::new();
        build_udp(&mut p, "1.1.1.1:1".parse().unwrap(), "2.2.2.2:2".parse().unwrap(), b"x");
        p[6] = 0x20; // more fragments
        assert!(parse(&p).is_none());
        assert!(matches!(classify(&p), Some(Ip::Fragment(f)) if f.more && f.offset == 0 && f.start == 20));
        assert!(parse(&[0x45]).is_none());
        assert!(parse(&[]).is_none());
    }

    /// Insert IPv6 extension headers (each `[type, body...]`, 8 bytes) after
    /// the base header of a packet built by `build_udp`/`tcp_syn`.
    fn with_ext(p: &[u8], exts: &[[u8; 8]]) -> Vec<u8> {
        let mut q = p[..40].to_vec();
        let mut next = p[6];
        for e in exts.iter().rev() {
            let mut h = *e;
            std::mem::swap(&mut h[0], &mut next);
            q.splice(40..40, h);
        }
        q[6] = next;
        q.extend_from_slice(&p[40..]);
        let len = q.len() - 40;
        wr16(&mut q, 4, len as u16);
        q
    }

    #[test]
    fn walks_ipv6_extension_headers() {
        let (s, d): (SocketAddr, SocketAddr) =
            ("[fdfe::1]:51000".parse().unwrap(), "[2001:db8::1]:443".parse().unwrap());
        let hbh = [EXT_HOP_BY_HOP, 0, 1, 4, 0, 0, 0, 0];
        let dst = [EXT_DEST_OPTS, 0, 1, 4, 0, 0, 0, 0];
        let routing_done = [EXT_ROUTING, 0, 4, 0, 0, 0, 0, 0];
        let atomic = [EXT_FRAGMENT, 0, 0, 0, 0, 0, 0, 9];
        let mut udp = Vec::new();
        build_udp(&mut udp, s, d, b"payload");
        for base in [tcp_syn(s, d), udp] {
            let mut p = with_ext(&base, &[hbh, routing_done, dst, atomic]);
            assert!(verify(&p));
            let h = parse(&p).expect("walked to the transport header");
            assert_eq!((h.l4, h.src, h.dst), (72, s, d));
            // The rewrite must hit the transport header past the extensions.
            let (ns, nd) = ("[fdfe::2]:10001".parse().unwrap(), "[fdfe::1]:8000".parse().unwrap());
            rewrite(&mut p, &h, ns, nd);
            assert!(verify(&p));
            assert_eq!(&p[40..72], &with_ext(&base, &[hbh, routing_done, dst, atomic])[40..72]);
            let h = parse(&p).unwrap();
            assert_eq!((h.src, h.dst), (ns, nd));
        }
        let syn = tcp_syn(s, d);
        let routing_pending = [EXT_ROUTING, 0, 4, 1, 0, 0, 0, 0];
        assert!(
            parse(&with_ext(&syn, &[routing_pending])).is_none(),
            "not the final destination"
        );
        assert!(
            parse(&with_ext(&syn, &[[59, 0, 0, 0, 0, 0, 0, 0]])).is_none(),
            "unknown header"
        );
        assert!(parse(&with_ext(&syn, &[hbh; MAX_EXT + 1])).is_none(), "walk is bounded");
        let first = [EXT_FRAGMENT, 0, 0, 1, 0, 0, 0, 9];
        assert!(matches!(
            classify(&with_ext(&syn, &[hbh, first])),
            Some(Ip::Fragment(f)) if f.v6 && f.proto == PROTO_TCP && f.id == 9 && f.more && f.start == 56
        ));
    }

    #[test]
    fn fragment_matches_the_original() {
        for (s, d) in [("10.0.0.1:53", "172.19.0.1:40000"), ("[fd00::1]:53", "[fd00::2]:40000")] {
            let mut p = Vec::new();
            let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
            build_udp(&mut p, s.parse().unwrap(), d.parse().unwrap(), &payload);
            let hdr = if p[0] >> 4 == 4 { 20 } else { 40 };
            let mut data = Vec::new();
            let mut out = Vec::new();
            let mut n = 0;
            assert!(fragment(&p, 1280, 0x01020304, 3, &mut out, |f| {
                let f = &f[3..];
                assert!(f.len() <= 1280);
                let Some(Ip::Fragment(fr)) = classify(f) else {
                    panic!("fragment expected")
                };
                assert_eq!(fr.offset, data.len());
                assert_eq!(fr.id, if hdr == 20 { 0x0304 } else { 0x01020304 });
                data.extend_from_slice(&f[fr.start..fr.end]);
                n += 1;
            }));
            assert_eq!(
                n,
                if hdr == 20 { 4 } else { 5 },
                "5008 bytes in 1256 (v4) or 1232 (v6) byte steps"
            );
            assert_eq!(data, &p[hdr..]);
            let fhdr = if hdr == 20 { 20 } else { 48 };
            assert!(!fragment(&p, fhdr + 7, 1, 0, &mut out, |_| panic!()), "MTU too small");
        }
    }
}
