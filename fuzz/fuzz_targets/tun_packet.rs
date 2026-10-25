//! TUN ingress: header parsing, NAT rewrite and fragment reassembly.
//!
//! The input is split into packets at 0xFF 0x00 0xFF markers so one run can
//! drive the reassembler through a sequence of fragments.
#![no_main]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use sbr_tun::frag::{Limits, Reassembler};
use sbr_tun::packet::{self, Ip};

fn exercise(p: &[u8]) {
    let Some(Ip::Whole(h)) = packet::classify(p) else { return };
    assert!(h.len <= p.len() && h.l4 <= h.len);
    if h.proto == packet::PROTO_TCP {
        let _ = packet::tcp_flags(p, &h);
    }
    let mut copy = p.to_vec();
    let (src, dst): (SocketAddr, SocketAddr) = if h.v6 {
        ("[fd00::1]:1".parse().unwrap(), "[fd00::2]:2".parse().unwrap())
    } else {
        ("10.0.0.1:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap())
    };
    packet::rewrite(&mut copy, &h, src, dst);
    let _ = packet::verify(&copy);
}

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        timeout: Duration::from_secs(5),
        max_datagrams: 8,
        max_bytes: 256 << 10,
    };
    let mut r = Reassembler::with_limits(16, limits);
    let start = Instant::now();
    let mut rest = data;
    let mut i = 0u64;
    loop {
        let (p, more) = match rest.windows(3).position(|w| w == [0xff, 0x00, 0xff]) {
            Some(at) => (&rest[..at], Some(&rest[at + 3..])),
            None => (rest, None),
        };
        match packet::classify(p) {
            Some(Ip::Whole(_)) => exercise(p),
            Some(Ip::Fragment(f)) => {
                assert!(f.start <= f.end && f.end <= p.len());
                // Advance the clock so the expiry paths run too.
                let now = start + Duration::from_millis(i * 700);
                if let Some(whole) = r.push(p, &f, now) {
                    assert!(whole.len() >= 16);
                    exercise(&whole[16..]);
                }
                assert!(r.pending() <= limits.max_datagrams);
            }
            None => {}
        }
        i += 1;
        match more {
            Some(m) => rest = m,
            None => break,
        }
    }
});
