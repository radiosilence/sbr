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

pub fn parse(p: &[u8]) -> Option<Parsed> {
    let version = p.first()? >> 4;
    let (v6, proto, l4, len, src_ip, dst_ip) = match version {
        4 => {
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            if ihl < 20 || p.len() < ihl {
                return None;
            }
            let len = u16::from_be_bytes([p[2], p[3]]) as usize;
            // Fragments: drop (the kernel rarely fragments locally generated
            // traffic at TUN MTU; reassembly isn't worth its cost here).
            let frag = u16::from_be_bytes([p[6], p[7]]);
            if frag & 0x3fff != 0 || len > p.len() || len < ihl {
                return None;
            }
            let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
            let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
            (false, p[9], ihl, len, IpAddr::V4(src), IpAddr::V4(dst))
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let len = 40 + u16::from_be_bytes([p[4], p[5]]) as usize;
            if len > p.len() {
                return None;
            }
            let src: [u8; 16] = p[8..24].try_into().ok()?;
            let dst: [u8; 16] = p[24..40].try_into().ok()?;
            // Extension headers are not walked: TCP/UDP must follow directly.
            (
                true,
                p[6],
                40,
                len,
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
            )
        }
        _ => return None,
    };
    let min = match proto {
        PROTO_TCP => 20,
        PROTO_UDP => 8,
        _ => return None,
    };
    if len < l4 + min {
        return None;
    }
    let sport = u16::from_be_bytes([p[l4], p[l4 + 1]]);
    let dport = u16::from_be_bytes([p[l4 + 2], p[l4 + 3]]);
    Some(Parsed {
        v6,
        proto,
        l4,
        len,
        src: SocketAddr::new(src_ip, sport),
        dst: SocketAddr::new(dst_ip, dport),
    })
}

pub fn tcp_flags(p: &[u8], h: &Parsed) -> u8 {
    p[h.l4 + 13]
}

// --- checksum arithmetic -------------------------------------------------

#[inline]
fn fold(mut sum: u32) -> u16 {
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

fn sum16(data: &[u8], mut sum: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    sum
}

fn rd16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

fn wr16(p: &mut [u8], at: usize, v: u16) {
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
        assert!(parse(&[0x45]).is_none());
        assert!(parse(&[]).is_none());
    }
}
