//! IP reassembly for the system stack (RFC 791, RFC 8200 §4.5).
//!
//! Fragments are rare on a TUN (the kernel sizes its own traffic to the
//! interface MTU), but a UDP tunnel nested inside ours at MTU 1280 sends
//! datagrams larger than that, and the kernel fragments them. The table is
//! bounded in entries and bytes, and its timeout is enforced lazily when a
//! fragment arrives: there is no timer, so an idle table costs no wakeups.
//!
//! Overlap handling follows RFC 5722 for both families: any overlap
//! abandons the datagram, and fragments for it are then dropped until its
//! deadline. A fragment whose bytes are already present unchanged is a
//! duplicate and is ignored (RFC 8200 permits this).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

use crate::packet::{Fragment, fold, sum16, wr16};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// RFC 791 suggests 15 s and Linux uses 30 s. A nested tunnel gains
    /// nothing from a fragment that late, and a short timeout frees the
    /// memory pinned by lost fragments sooner.
    pub timeout: Duration,
    pub max_datagrams: usize,
    /// Buffer bytes across all pending datagrams. Small next to the ~50 MB
    /// iOS extension limit; at MTU 1280 a typical datagram needs 2–3 KB.
    pub max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_datagrams: 128,
            max_bytes: 2 << 20,
        }
    }
}

/// Ranges per datagram. A 64 KiB datagram at MTU 1280 is 54 fragments, so
/// this only stops tiny-fragment floods from growing `have`.
const MAX_RANGES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    /// IPv4 keys include the protocol (RFC 791); IPv6 keys do not.
    proto: u8,
}

struct Entry {
    /// `base` bytes reserved for headroom and the rebuilt IP header, then
    /// the fragmentable part.
    buf: Vec<u8>,
    /// Received data ranges, sorted and coalesced.
    have: Vec<(usize, usize)>,
    total: Option<usize>,
    /// IPv6: the Next Header from the first fragment.
    next: u8,
    deadline: Instant,
    /// Abandoned: later fragments are dropped until the deadline.
    dead: bool,
}

enum Step {
    Pending,
    Drop,
    Abandon,
    Done,
}

pub struct Reassembler {
    table: FxHashMap<Key, Entry>,
    /// Sum of entry buffer capacities.
    bytes: usize,
    /// No entry expires before this.
    earliest: Option<Instant>,
    headroom: usize,
    limits: Limits,
}

impl Reassembler {
    /// Completed packets are returned with `headroom` spare bytes in front.
    pub fn new(headroom: usize) -> Self {
        Self::with_limits(headroom, Limits::default())
    }

    pub fn with_limits(headroom: usize, limits: Limits) -> Self {
        Self {
            table: FxHashMap::default(),
            bytes: 0,
            earliest: None,
            headroom,
            limits,
        }
    }

    pub fn pending(&self) -> usize {
        self.table.len()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Add fragment `f` of packet `p`. When it completes a datagram, the
    /// whole packet is returned at `buf[headroom..]` with a fresh IP header
    /// (no IPv4 options; IPv6 headers before the Fragment header removed).
    pub fn push(&mut self, p: &[u8], f: &Fragment, now: Instant) -> Option<Vec<u8>> {
        let data = &p[f.start..f.end];
        let end = f.offset + data.len();
        let hdr = if f.v6 { 40 } else { 20 };
        // The rebuilt header's 16-bit length field must hold the result.
        let max = if f.v6 { 65535 } else { 65535 - 20 };
        if data.is_empty() || (f.more && !data.len().is_multiple_of(8)) || end > max {
            return None;
        }
        if self.earliest.is_some_and(|e| now >= e) {
            self.expire(now);
        }
        let key = Key {
            src: f.src,
            dst: f.dst,
            id: f.id,
            proto: if f.v6 { 0 } else { f.proto },
        };
        let mut e = match self.table.remove(&key) {
            Some(e) => e,
            None => {
                while self.table.len() >= self.limits.max_datagrams {
                    self.evict_oldest();
                }
                let deadline = now + self.limits.timeout;
                self.earliest = Some(self.earliest.map_or(deadline, |e| e.min(deadline)));
                Entry {
                    buf: Vec::new(),
                    have: Vec::new(),
                    total: None,
                    next: 0,
                    deadline,
                    dead: false,
                }
            }
        };
        let base = self.headroom + hdr;
        let step = if e.dead {
            Step::Drop
        } else {
            self.add(&mut e, base, f, data, end)
        };
        match step {
            Step::Pending | Step::Drop => {
                self.table.insert(key, e);
                None
            }
            Step::Abandon => {
                self.bytes -= e.buf.capacity();
                e.buf = Vec::new();
                e.have = Vec::new();
                e.dead = true;
                self.table.insert(key, e);
                None
            }
            Step::Done => {
                self.bytes -= e.buf.capacity();
                let mut buf = e.buf;
                let len = buf.len() - base;
                write_header(&mut buf[self.headroom..], f, e.next, len);
                Some(buf)
            }
        }
    }

    fn add(&mut self, e: &mut Entry, base: usize, f: &Fragment, data: &[u8], end: usize) -> Step {
        let off = f.offset;
        for &(s, t) in &e.have {
            if off < t && s < end {
                return if s <= off && end <= t && e.buf[base + off..base + end] == *data {
                    Step::Drop
                } else {
                    Step::Abandon
                };
            }
        }
        if f.more {
            if e.total.is_some_and(|t| end >= t) {
                return Step::Abandon;
            }
        } else {
            if e.total.is_some() || e.have.last().is_some_and(|&(_, t)| t > end) {
                return Step::Abandon;
            }
            e.total = Some(end);
        }
        if base + end > e.buf.len() {
            // Size exactly once the length is known; until then, to this fragment.
            let want = base + e.total.unwrap_or(end);
            let before = e.buf.capacity();
            e.buf.reserve_exact(want - e.buf.len());
            let grown = e.buf.capacity() - before;
            while self.bytes + grown > self.limits.max_bytes && !self.table.is_empty() {
                self.evict_oldest();
            }
            if self.bytes + grown > self.limits.max_bytes {
                self.bytes += grown;
                return Step::Abandon;
            }
            self.bytes += grown;
            e.buf.resize(base + end, 0);
        }
        e.buf[base + off..base + end].copy_from_slice(data);
        if off == 0 {
            e.next = f.proto;
        }
        let i = e.have.partition_point(|&(s, _)| s < off);
        e.have.insert(i, (off, end));
        if i + 1 < e.have.len() && e.have[i + 1].0 == end {
            e.have[i].1 = e.have.remove(i + 1).1;
        }
        if i > 0 && e.have[i - 1].1 == off {
            e.have[i - 1].1 = e.have.remove(i).1;
        }
        if e.have.len() > MAX_RANGES {
            return Step::Abandon;
        }
        match e.total {
            Some(t) if e.have[..] == [(0, t)] => Step::Done,
            _ => Step::Pending,
        }
    }

    fn expire(&mut self, now: Instant) {
        let bytes = &mut self.bytes;
        let mut earliest = None::<Instant>;
        self.table.retain(|_, e| {
            if e.deadline <= now {
                *bytes -= e.buf.capacity();
                return false;
            }
            earliest = Some(earliest.map_or(e.deadline, |x| x.min(e.deadline)));
            true
        });
        self.earliest = earliest;
    }

    fn evict_oldest(&mut self) {
        let Some(key) = self.table.iter().min_by_key(|(_, e)| e.deadline).map(|(k, _)| *k) else {
            return;
        };
        if let Some(e) = self.table.remove(&key) {
            self.bytes -= e.buf.capacity();
        }
    }
}

/// Rebuild the IP header in front of `len` bytes of reassembled data.
fn write_header(h: &mut [u8], f: &Fragment, next: u8, len: usize) {
    match (f.src, f.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            h[..12].copy_from_slice(&[0x45, 0, 0, 0, 0, 0, 0, 0, 64, f.proto, 0, 0]);
            wr16(h, 2, (20 + len) as u16);
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            let ck = !fold(sum16(&h[..20], 0));
            wr16(h, 10, ck);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            h[..4].copy_from_slice(&[0x60, 0, 0, 0]);
            wr16(h, 4, len as u16);
            h[6] = next;
            h[7] = 64;
            h[8..24].copy_from_slice(&s.octets());
            h[24..40].copy_from_slice(&d.octets());
        }
        _ => unreachable!("fragment addresses share a family"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::packet::{Ip, Parsed, build_udp, classify, fragment, parse, rewrite, verify};

    const HR: usize = 4;

    fn udp(src: &str, dst: &str, n: usize) -> (Vec<u8>, Vec<u8>) {
        let payload: Vec<u8> = (0..n).map(|i| (i * 7 + i / 251) as u8).collect();
        let mut p = Vec::new();
        build_udp(&mut p, src.parse().unwrap(), dst.parse().unwrap(), &payload);
        (p, payload)
    }

    /// Fragments of `p` at `mtu`, without headroom.
    fn frags(p: &[u8], mtu: usize, id: u32) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        let mut out = Vec::new();
        assert!(fragment(p, mtu, id, HR, &mut out, |f| v.push(f[HR..].to_vec())));
        v
    }

    fn push(r: &mut Reassembler, p: &[u8], now: Instant) -> Option<Vec<u8>> {
        let Some(Ip::Fragment(f)) = classify(p) else {
            panic!("not a fragment")
        };
        r.push(p, &f, now)
    }

    fn check(whole: &[u8], payload: &[u8]) -> Parsed {
        let p = &whole[HR..];
        assert!(verify(p), "checksums valid after reassembly");
        let h = parse(p).unwrap();
        assert_eq!(&p[h.l4 + 8..h.len], payload);
        assert_eq!(h.len, p.len());
        h
    }

    #[test]
    fn fragments_fit_the_mtu_and_reassemble_in_any_order() {
        for (s, d) in [
            ("10.0.0.1:4500", "172.19.0.1:40000"),
            ("[fd00::1]:4500", "[fd00::2]:40000"),
        ] {
            let (p, payload) = udp(s, d, 3000);
            let fs = frags(&p, 1280, 0xabcd1234);
            assert_eq!(fs.len(), 3);
            for f in &fs {
                assert!(f.len() <= 1280);
                if f[0] >> 4 == 4 {
                    assert_eq!(fold(sum16(&f[..20], 0)), 0xffff, "IPv4 header checksum");
                    assert_eq!(f[6] & 0x40, 0, "DF cleared");
                }
            }
            let now = Instant::now();
            for order in [[0, 1, 2], [2, 0, 1], [1, 2, 0]] {
                let mut r = Reassembler::new(HR);
                assert!(push(&mut r, &fs[order[0]], now).is_none());
                assert!(push(&mut r, &fs[order[1]], now).is_none());
                let whole = push(&mut r, &fs[order[2]], now).expect("complete");
                let h = check(&whole, &payload);
                assert_eq!((h.src, h.dst), (s.parse().unwrap(), d.parse().unwrap()));
                assert_eq!((r.pending(), r.bytes()), (0, 0));
            }
        }
    }

    #[test]
    fn rewrite_after_reassembly_keeps_checksums() {
        for (s, d, ns, mtu) in [
            ("10.0.0.1:4500", "172.19.0.1:40000", "1.2.3.4:5", 576),
            ("[fd00::1]:4500", "[fd00::2]:40000", "[2001:db8::5]:5", 1280),
        ] {
            let (p, payload) = udp(s, d, 2000);
            let mut r = Reassembler::new(HR);
            let now = Instant::now();
            let mut out = None;
            for f in frags(&p, mtu, 7) {
                out = push(&mut r, &f, now);
            }
            let mut whole = out.unwrap();
            let h = check(&whole, &payload);
            rewrite(&mut whole[HR..], &h, ns.parse().unwrap(), h.dst);
            assert!(verify(&whole[HR..]));
            assert_eq!(parse(&whole[HR..]).unwrap().src, ns.parse::<SocketAddr>().unwrap());
        }
    }

    #[test]
    fn exact_duplicates_are_ignored() {
        let (p, payload) = udp("10.0.0.1:1", "10.0.0.2:2", 3000);
        let fs = frags(&p, 1280, 1);
        let mut r = Reassembler::new(HR);
        let now = Instant::now();
        for i in [0, 0, 1, 0, 1] {
            assert!(push(&mut r, &fs[i], now).is_none());
        }
        check(&push(&mut r, &fs[2], now).unwrap(), &payload);
    }

    /// An IPv4 UDP fragment with arbitrary offset and data.
    fn v4_frag(id: u16, offset: usize, more: bool, data: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        wr16(&mut p, 2, (20 + data.len()) as u16);
        wr16(&mut p, 4, id);
        wr16(&mut p, 6, (more as u16) << 13 | (offset / 8) as u16);
        p.extend_from_slice(data);
        p
    }

    #[test]
    fn overlap_abandons_until_the_deadline() {
        let now = Instant::now();
        let mut r = Reassembler::new(HR);
        assert!(push(&mut r, &v4_frag(9, 0, true, &[1; 16]), now).is_none());
        // Same bytes, shifted boundary: still an overlap.
        assert!(push(&mut r, &v4_frag(9, 8, true, &[1; 16]), now).is_none());
        assert_eq!(r.bytes(), 0, "abandoned datagrams hold no buffer");
        // The rest of the datagram cannot resurrect it.
        assert!(push(&mut r, &v4_frag(9, 0, true, &[1; 16]), now).is_none());
        assert!(push(&mut r, &v4_frag(9, 16, false, &[1; 8]), now).is_none());
        assert_eq!(r.pending(), 1);
        // After the deadline the ID is free again.
        let later = now + Limits::default().timeout;
        assert!(push(&mut r, &v4_frag(9, 0, true, &[0; 8]), later).is_none());
        let whole = push(&mut r, &v4_frag(9, 8, false, &[0; 8]), later).expect("fresh datagram");
        assert_eq!(whole.len(), HR + 20 + 16);
    }

    #[test]
    fn same_range_different_bytes_abandons() {
        let now = Instant::now();
        let mut r = Reassembler::new(HR);
        push(&mut r, &v4_frag(3, 0, true, &[1; 8]), now);
        push(&mut r, &v4_frag(3, 0, true, &[2; 8]), now);
        assert!(push(&mut r, &v4_frag(3, 8, false, &[1; 8]), now).is_none());
    }

    #[test]
    fn inconsistent_lengths_abandon() {
        let now = Instant::now();
        let mut r = Reassembler::new(HR);
        push(&mut r, &v4_frag(4, 16, false, &[1; 8]), now);
        // A middle fragment reaching the known end.
        assert!(push(&mut r, &v4_frag(4, 8, true, &[1; 16]), now).is_none());
        assert!(push(&mut r, &v4_frag(4, 0, true, &[1; 8]), now).is_none());
        let mut r = Reassembler::new(HR);
        push(&mut r, &v4_frag(5, 16, true, &[1; 16]), now);
        assert!(
            push(&mut r, &v4_frag(5, 8, false, &[1; 8]), now).is_none(),
            "last ends early"
        );
        assert!(push(&mut r, &v4_frag(5, 0, true, &[1; 8]), now).is_none());
        assert!(push(&mut r, &v4_frag(5, 8, true, &[1; 8]), now).is_none());
        assert!(push(&mut r, &v4_frag(5, 32, false, &[1; 8]), now).is_none());
        assert_eq!(r.bytes(), 0);
    }

    #[test]
    fn malformed_fragments_are_dropped_without_state() {
        let now = Instant::now();
        let mut r = Reassembler::new(HR);
        assert!(
            push(&mut r, &v4_frag(1, 0, true, &[1; 10]), now).is_none(),
            "not a multiple of 8"
        );
        assert!(push(&mut r, &v4_frag(1, 8, true, &[]), now).is_none(), "empty");
        assert!(
            push(&mut r, &v4_frag(1, 65528, false, &[1; 8]), now).is_none(),
            "too long"
        );
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn timeout_is_enforced_on_arrival() {
        let (p, _) = udp("10.0.0.1:1", "10.0.0.2:2", 3000);
        let fs = frags(&p, 1280, 2);
        let now = Instant::now();
        let mut r = Reassembler::new(HR);
        push(&mut r, &fs[0], now);
        push(&mut r, &fs[1], now);
        let bytes = r.bytes();
        assert!(bytes > 2400);
        // The last fragment arrives too late: the datagram is gone and the
        // straggler starts a new one.
        let late = now + Limits::default().timeout;
        assert!(push(&mut r, &fs[2], late).is_none());
        assert_eq!(r.pending(), 1);
        assert_ne!(r.bytes(), bytes);
        // An unrelated fragment, later still, sweeps it.
        let (q, _) = udp("10.0.0.3:1", "10.0.0.2:2", 3000);
        push(&mut r, &frags(&q, 1280, 2)[0], late + Limits::default().timeout);
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn datagram_cap_evicts_the_oldest() {
        let limits = Limits {
            max_datagrams: 2,
            ..Limits::default()
        };
        let mut r = Reassembler::with_limits(HR, limits);
        let (p, payload) = udp("10.0.0.1:1", "10.0.0.2:2", 2000);
        let t = Instant::now();
        let fs: Vec<_> = (1..=3).map(|id| frags(&p, 1280, id)).collect();
        for (i, f) in fs.iter().enumerate() {
            push(&mut r, &f[0], t + Duration::from_millis(i as u64));
        }
        assert_eq!(r.pending(), 2);
        let t = t + Duration::from_millis(10);
        assert!(push(&mut r, &fs[0][1], t).is_none(), "oldest was evicted");
        // That straggler evicted id 2; id 3 survives.
        check(&push(&mut r, &fs[2][1], t).unwrap(), &payload);
    }

    #[test]
    fn byte_cap_evicts_the_oldest() {
        let limits = Limits {
            max_bytes: 6000,
            ..Limits::default()
        };
        let mut r = Reassembler::with_limits(HR, limits);
        let (p, payload) = udp("10.0.0.1:1", "10.0.0.2:2", 4000);
        let a = frags(&p, 1280, 1);
        let b = frags(&p, 1280, 2);
        let t = Instant::now();
        // Last fragments first, so each entry is sized to the full datagram.
        push(&mut r, a.last().unwrap(), t);
        assert!(r.bytes() > 4000 && r.bytes() <= 6000);
        push(&mut r, b.last().unwrap(), t + Duration::from_millis(1));
        assert_eq!(r.pending(), 1, "the first datagram was evicted to make room");
        let mut done = None;
        for f in &b[..b.len() - 1] {
            done = push(&mut r, f, t);
        }
        check(&done.unwrap(), &payload);
        assert_eq!(r.bytes(), 0);
    }

    #[test]
    fn ipv6_headers_before_and_after_the_fragment_header() {
        let (p, payload) = udp("[fd00::1]:4500", "[fd00::2]:40000", 3000);
        // Destination Options in the fragmentable part, before UDP.
        let mut q = p[..40].to_vec();
        q[6] = 60;
        wr16(&mut q, 4, (8 + p.len() - 40) as u16);
        q.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);
        q.extend_from_slice(&p[40..]);
        let now = Instant::now();
        let mut r = Reassembler::new(HR);
        let mut out = None;
        for f in frags(&q, 1280, 77) {
            // Hop-by-Hop in the unfragmentable part, before the Fragment header.
            let mut g = f[..40].to_vec();
            g[6] = 0;
            wr16(&mut g, 4, (8 + f.len() - 40) as u16);
            g.extend_from_slice(&[44, 0, 1, 4, 0, 0, 0, 0]);
            g.extend_from_slice(&f[40..]);
            assert!(out.is_none());
            out = push(&mut r, &g, now);
        }
        let whole = out.unwrap();
        let h = check(&whole, &payload);
        assert_eq!(h.l4, 48, "the Destination Options header is walked");
    }
}
