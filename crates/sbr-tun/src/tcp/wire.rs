//! TCP segment parsing and construction (RFC 9293 header, RFC 7323 window
//! scale and timestamps, RFC 2018 SACK).

use std::net::{IpAddr, SocketAddr};
use std::ops::Range;

use crate::device::HEADROOM;
use crate::packet::{PROTO_TCP, Parsed, rd16, wr16};

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

const OPT_END: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_WS: u8 = 3;
const OPT_SACK_PERM: u8 = 4;
const OPT_SACK: u8 = 5;
const OPT_TS: u8 = 8;

/// Longest option block: the TCP data offset field caps the header at 60.
pub const MAX_OPTS: usize = 40;

/// An incoming segment. `payload` indexes the packet it was parsed from.
#[derive(Debug, Clone, Default)]
pub struct Seg {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub wnd: u16,
    pub mss: Option<u16>,
    pub ws: Option<u8>,
    pub sack_perm: bool,
    /// (TSval, TSecr).
    pub ts: Option<(u32, u32)>,
    pub sacks: [(u32, u32); 4],
    pub nsacks: usize,
    pub payload: Range<usize>,
}

impl Seg {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// Sequence space the segment occupies (SYN and FIN count one each).
    pub fn seq_len(&self) -> u32 {
        (self.payload.len() + self.has(SYN) as usize + self.has(FIN) as usize) as u32
    }

    pub fn sacks(&self) -> &[(u32, u32)] {
        &self.sacks[..self.nsacks]
    }
}

pub fn parse(p: &[u8], h: &Parsed) -> Option<Seg> {
    debug_assert_eq!(h.proto, PROTO_TCP);
    let t = p.get(h.l4..h.len)?;
    if t.len() < 20 {
        return None;
    }
    let doff = ((t[12] >> 4) as usize) * 4;
    if doff < 20 || doff > t.len() {
        return None;
    }
    let mut s = Seg {
        seq: u32::from_be_bytes(t[4..8].try_into().ok()?),
        ack: u32::from_be_bytes(t[8..12].try_into().ok()?),
        flags: t[13],
        wnd: rd16(t, 14),
        payload: h.l4 + doff..h.len,
        ..Seg::default()
    };
    let mut o = &t[20..doff];
    while let [kind, rest @ ..] = o {
        match *kind {
            OPT_END => break,
            OPT_NOP => {
                o = rest;
                continue;
            }
            _ => {}
        }
        let len = *rest.first()? as usize;
        if len < 2 || len > o.len() {
            break;
        }
        let v = &o[2..len];
        match (*kind, len) {
            (OPT_MSS, 4) => s.mss = Some(u16::from_be_bytes([v[0], v[1]])),
            (OPT_WS, 3) => s.ws = Some(v[0].min(14)),
            (OPT_SACK_PERM, 2) => s.sack_perm = true,
            (OPT_TS, 10) => {
                s.ts = Some((
                    u32::from_be_bytes(v[..4].try_into().ok()?),
                    u32::from_be_bytes(v[4..8].try_into().ok()?),
                ))
            }
            (OPT_SACK, _) if (len - 2).is_multiple_of(8) => {
                for b in v.as_chunks::<8>().0.iter().take(4) {
                    s.sacks[s.nsacks] = (
                        u32::from_be_bytes(b[..4].try_into().ok()?),
                        u32::from_be_bytes(b[4..].try_into().ok()?),
                    );
                    s.nsacks += 1;
                }
            }
            _ => {}
        }
        o = &o[len..];
    }
    Some(s)
}

/// Option bytes for one outgoing segment, kept 4-byte aligned.
pub struct Opts {
    buf: [u8; MAX_OPTS],
    len: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            buf: [0; MAX_OPTS],
            len: 0,
        }
    }
}

impl Opts {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn put(&mut self, b: &[u8]) {
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }

    pub fn mss(&mut self, mss: u16) {
        let m = mss.to_be_bytes();
        self.put(&[OPT_MSS, 4, m[0], m[1]]);
    }

    pub fn ws(&mut self, shift: u8) {
        self.put(&[OPT_NOP, OPT_WS, 3, shift]);
    }

    pub fn sack_perm(&mut self) {
        self.put(&[OPT_NOP, OPT_NOP, OPT_SACK_PERM, 2]);
    }

    pub fn ts(&mut self, val: u32, ecr: u32) {
        self.put(&[OPT_NOP, OPT_NOP, OPT_TS, 10]);
        self.put(&val.to_be_bytes());
        self.put(&ecr.to_be_bytes());
    }

    /// As many blocks as fit in the remaining option space.
    pub fn sack(&mut self, blocks: impl Iterator<Item = (u32, u32)>) {
        let room = (MAX_OPTS - self.len).saturating_sub(4) / 8;
        let start = self.len;
        self.put(&[OPT_NOP, OPT_NOP, OPT_SACK, 2]);
        let mut n = 0;
        for (l, r) in blocks.take(room) {
            self.put(&l.to_be_bytes());
            self.put(&r.to_be_bytes());
            n += 1;
        }
        if n == 0 {
            self.len = start;
        } else {
            self.buf[start + 3] = 2 + 8 * n as u8;
        }
    }
}

pub fn ip_header_len(v6: bool) -> usize {
    if v6 { 40 } else { 20 }
}

/// Where the payload starts in an output buffer (which begins with
/// `HEADROOM` bytes for the device).
pub fn payload_offset(v6: bool, opts: &Opts) -> usize {
    HEADROOM + ip_header_len(v6) + 20 + opts.len()
}

pub struct Out<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub wnd: u16,
    pub opts: &'a Opts,
}

/// Write the IP and TCP headers and checksums into `buf`, whose payload
/// (`buf[payload_offset(..)..]`) is already in place. `buf` is exactly the
/// packet plus `HEADROOM`.
pub fn finish(buf: &mut [u8], o: &Out<'_>) {
    let v6 = o.src.is_ipv6();
    let ip_len = ip_header_len(v6);
    let p = &mut buf[HEADROOM..];
    let total = p.len();
    let l4 = ip_len;
    let tcp_len = total - l4;
    let mut pseudo: u32;
    match (o.src.ip(), o.dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            p[..12].copy_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, PROTO_TCP, 0, 0]);
            wr16(p, 2, total as u16);
            p[12..16].copy_from_slice(&s.octets());
            p[16..20].copy_from_slice(&d.octets());
            let ck = !fold(sum_be(&p[..20]));
            wr16(p, 10, ck);
            pseudo = sum_be(&p[12..20]);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            p[..8].copy_from_slice(&[0x60, 0, 0, 0, 0, 0, PROTO_TCP, 64]);
            wr16(p, 4, tcp_len as u16);
            p[8..24].copy_from_slice(&s.octets());
            p[24..40].copy_from_slice(&d.octets());
            pseudo = sum_be(&p[8..40]);
        }
        _ => unreachable!("address family mismatch"),
    }
    pseudo += PROTO_TCP as u32 + tcp_len as u32;
    let t = &mut p[l4..];
    wr16(t, 0, o.src.port());
    wr16(t, 2, o.dst.port());
    t[4..8].copy_from_slice(&o.seq.to_be_bytes());
    t[8..12].copy_from_slice(&o.ack.to_be_bytes());
    t[12] = (((20 + o.opts.len()) / 4) as u8) << 4;
    t[13] = o.flags;
    wr16(t, 14, o.wnd);
    wr16(t, 16, 0);
    wr16(t, 18, 0);
    t[20..20 + o.opts.len()].copy_from_slice(o.opts.as_slice());
    let ck = !fold(pseudo + sum_be(t));
    wr16(t, 16, ck);
}

pub fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// One's-complement sum of `data` as big-endian 16-bit words, unfolded
/// beyond 16 bits. Sums native 32-bit words into a 64-bit accumulator,
/// which vectorises; the result is the same up to a byte swap.
pub fn sum_be(data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<4>();
    let mut acc: u64 = words.iter().map(|w| u32::from_ne_bytes(*w) as u64).sum();
    let mut tail = [0u8; 4];
    tail[..rest.len()].copy_from_slice(rest);
    acc += u32::from_ne_bytes(tail) as u64;
    let mut s = (acc >> 32) + (acc & 0xffff_ffff);
    s = (s >> 32) + (s & 0xffff_ffff);
    let mut t = (s >> 16) + (s & 0xffff);
    t = (t >> 16) + (t & 0xffff);
    t = (t >> 16) + (t & 0xffff);
    let t = t as u16;
    (if cfg!(target_endian = "little") { t.swap_bytes() } else { t }) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{self, verify};

    #[test]
    fn checksum_matches_reference() {
        for len in [0usize, 1, 2, 3, 7, 8, 9, 1500, 9001] {
            let d: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(fold(sum_be(&d)), fold(packet::sum16(&d, 0)), "len {len}");
        }
    }

    #[test]
    fn build_parse_roundtrip() {
        for (src, dst) in [
            ("10.0.0.1:443", "172.19.0.1:50000"),
            ("[2001:db8::1]:443", "[fdfe:dcba:9876::1]:50000"),
        ] {
            let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
            let mut o = Opts::default();
            o.mss(1460);
            o.ws(7);
            o.sack_perm();
            o.ts(123, 456);
            let off = payload_offset(src.is_ipv6(), &o);
            let mut buf = vec![0u8; off + 5];
            buf[off..].copy_from_slice(b"hello");
            finish(
                &mut buf,
                &Out {
                    src,
                    dst,
                    seq: 1000,
                    ack: 2000,
                    flags: SYN | ACK,
                    wnd: 65535,
                    opts: &o,
                },
            );
            let p = &buf[HEADROOM..];
            assert!(verify(p));
            let h = packet::parse(p).unwrap();
            let s = parse(p, &h).unwrap();
            assert_eq!((s.seq, s.ack, s.flags, s.wnd), (1000, 2000, SYN | ACK, 65535));
            assert_eq!((s.mss, s.ws, s.sack_perm, s.ts), (Some(1460), Some(7), true, Some((123, 456))));
            assert_eq!(&p[s.payload.clone()], b"hello");

            let mut o = Opts::default();
            o.ts(1, 2);
            o.sack([(10, 20), (30, 40), (50, 60), (70, 80)].into_iter());
            assert_eq!(o.len(), 12 + 4 + 24, "three blocks fit beside timestamps");
            let off = payload_offset(src.is_ipv6(), &o);
            let mut buf = vec![0u8; off];
            finish(
                &mut buf,
                &Out {
                    src,
                    dst,
                    seq: 1,
                    ack: 2,
                    flags: ACK,
                    wnd: 1,
                    opts: &o,
                },
            );
            let p = &buf[HEADROOM..];
            let s = parse(p, &packet::parse(p).unwrap()).unwrap();
            assert_eq!(s.sacks(), &[(10, 20), (30, 40), (50, 60)]);
        }
    }
}
