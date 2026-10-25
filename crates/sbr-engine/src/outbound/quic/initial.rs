//! ClientHello scrambling in the client's QUIC Initial packets.
//!
//! Censors in China and Russia decrypt the client's Initial packets (their
//! keys derive from the destination connection ID, RFC 9001 §5.2, so anyone
//! can) and match the TLS SNI against a blocklist. Neither reassembles CRYPTO
//! data across datagrams (Zohaib et al., USENIX Security 2025; FOCI 2026).
//!
//! [`Scramble`] sits between quinn and the UDP socket and rewrites the Initial
//! packets that carry the ClientHello the way quic-go (0.52+) sends them: the
//! SNI is cut in the middle, and its second half goes out last, in its own
//! CRYPTO frame, after the rest of the ClientHello. rustls' default key shares
//! (X25519MLKEM768 plus X25519) make the ClientHello longer than one packet,
//! so the two halves of the name land in different datagrams; a censor that
//! inspects one datagram sees neither the whole name nor a contiguous
//! ClientHello past the cut.
//!
//! The rewrite keeps every packet number, packet length and datagram size,
//! and only moves bytes between the CRYPTO frames of packets quinn already
//! built, so it is invisible to quinn and needs no change to it. Packets it
//! cannot parse, and every packet once the handshake has moved past the
//! Initial space, pass through untouched.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rustls::Side;
use rustls::quic::{DirectionalKeys, Version};

use super::socket::Socket;
use super::{get_varint, put_varint};

/// Datagrams of the first flight held back while waiting for the rest of
/// the ClientHello. quinn emits a whole flight in one burst, so this bound
/// only matters if something unexpected arrives instead.
const MAX_HELD: usize = 6;

pub(crate) struct Scramble {
    inner: Socket,
    /// Set once the client sends a Handshake or 1-RTT packet: from then on
    /// every transmit passes straight through.
    done: AtomicBool,
    state: Mutex<State>,
}

struct State {
    /// Client Initial keys, for the destination connection ID they belong to.
    keys: Option<(Vec<u8>, DirectionalKeys)>,
    largest_pn: Option<u64>,
    /// The ClientHello as far as it has been seen contiguously from offset 0.
    hello: Vec<u8>,
    /// Its length, from the handshake message header.
    hello_len: Option<u64>,
    /// The second half of the SNI, as CRYPTO stream offsets.
    cut: Option<(u64, u64)>,
    /// The ClientHello carries no SNI: nothing to hide.
    no_sni: bool,
    /// Holding the first flight (or the flight after a Retry) until it
    /// contains the whole ClientHello.
    hold: bool,
    held: Vec<Dgram>,
    held_meta: Option<(SocketAddr, Option<EcnCodepoint>, Option<IpAddr>)>,
}

/// One outgoing datagram, with its leading Initial packet opened if it has one.
struct Dgram {
    orig: Vec<u8>,
    initial: Option<Opened>,
}

struct Opened {
    /// The datagram with header protection removed and the Initial's payload
    /// decrypted in place (the AEAD tag bytes are left as they were).
    buf: Vec<u8>,
    pn_offset: usize,
    pn_len: usize,
    pn: u64,
    /// End of the Initial packet (a coalesced packet may follow).
    end: usize,
    /// Plaintext payload length.
    cap: usize,
    frames: Frames,
}

#[derive(Default)]
struct Frames {
    /// ACK and PING frames, kept verbatim and in front.
    control: Vec<u8>,
    crypto: Vec<(u64, Vec<u8>)>,
}

impl Scramble {
    pub(crate) fn new(inner: Socket) -> Arc<Self> {
        Arc::new(Self {
            inner,
            done: AtomicBool::new(false),
            state: Mutex::new(State {
                keys: None,
                largest_pn: None,
                hello: Vec::new(),
                hello_len: None,
                cut: None,
                no_sni: false,
                hold: true,
                held: Vec::new(),
                held_meta: None,
            }),
        })
    }

    fn send_one(&self, t: &Transmit, contents: &[u8]) {
        // Best effort, as UDP: a datagram the kernel refuses is a loss quinn
        // recovers from, while an error would make quinn retry a transmit
        // that has partly gone out.
        let _ = self.inner.try_send(&Transmit {
            destination: t.destination,
            ecn: t.ecn,
            contents,
            segment_size: None,
            src_ip: t.src_ip,
        });
    }
}

impl fmt::Debug for Scramble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scramble")
    }
}

impl AsyncUdpSocket for Scramble {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        if self.done.load(Ordering::Relaxed) {
            return self.inner.try_send(t);
        }
        let mut st = self.state.lock().unwrap();
        let seg = t.segment_size.unwrap_or(t.contents.len()).max(1);
        let mut batch = std::mem::take(&mut st.held);
        for d in t.contents.chunks(seg) {
            let initial = st.open(d);
            if initial.is_none() && moved_on(d) {
                self.done.store(true, Ordering::Relaxed);
            }
            batch.push(Dgram {
                orig: d.to_vec(),
                initial,
            });
        }
        if st.hold && !st.no_sni && !self.done.load(Ordering::Relaxed) && batch.len() < MAX_HELD {
            let complete = st.cut.is_some() && st.hello_len.is_some_and(|n| covers(&batch, n));
            if !complete && batch.iter().any(|d| d.initial.is_some()) {
                st.held = batch;
                st.held_meta = Some((t.destination, t.ecn, t.src_ip));
                return Ok(());
            }
        }
        st.hold = false;
        let meta = st.held_meta.take();
        let out = st.rewrite(batch);
        drop(st);
        let first = match meta {
            Some((destination, ecn, src_ip)) => Transmit {
                destination,
                ecn,
                contents: &[],
                segment_size: None,
                src_ip,
            },
            None => Transmit { contents: &[], ..*t },
        };
        for d in &out {
            self.send_one(&first, d);
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// A Handshake or 1-RTT packet: the Initial space is finished with.
fn moved_on(d: &[u8]) -> bool {
    match d.first() {
        Some(b) if b & 0x80 == 0 => true,
        Some(b) => (b >> 4) & 3 == 2,
        None => false,
    }
}

/// Whether the batch's CRYPTO frames cover `[0, len)`.
fn covers(batch: &[Dgram], len: u64) -> bool {
    let mut segs: Vec<(u64, u64)> = batch
        .iter()
        .filter_map(|d| d.initial.as_ref())
        .flat_map(|o| o.frames.crypto.iter().map(|(off, d)| (*off, off + d.len() as u64)))
        .collect();
    segs.sort_unstable();
    let mut reach = 0;
    for (a, b) in segs {
        if a > reach {
            return false;
        }
        reach = reach.max(b);
    }
    reach >= len
}

impl State {
    /// Decrypts the datagram's leading packet if it is a QUIC v1 client
    /// Initial, and learns the ClientHello from its CRYPTO frames.
    fn open(&mut self, d: &[u8]) -> Option<Opened> {
        // Long header, fixed bit, type Initial, version 1.
        if d.len() < 7 || d[0] & 0xf0 != 0xc0 || d[1..5] != [0, 0, 0, 1] {
            return None;
        }
        let mut i = 5;
        let dcid_len = usize::from(d[i]);
        let dcid = d.get(i + 1..i + 1 + dcid_len)?;
        i += 1 + dcid_len;
        i += 1 + usize::from(*d.get(i)?);
        let (token_len, n) = get_varint(d.get(i..)?)?;
        i += n + usize::try_from(token_len).ok()?;
        let (len, n) = get_varint(d.get(i..)?)?;
        let pn_offset = i + n;
        let end = pn_offset.checked_add(usize::try_from(len).ok()?)?;
        if end > d.len() || pn_offset + 4 + 16 > end {
            return None;
        }
        if self.keys.as_ref().is_none_or(|(c, _)| c != dcid) {
            if self.keys.is_some() {
                // A Retry: the ClientHello goes out again under new keys.
                self.hold = true;
            }
            let keys = initial_suite().keys(dcid, Side::Client, Version::V1).local;
            self.keys = Some((dcid.to_vec(), keys));
        }
        let keys = &self.keys.as_ref()?.1;
        let mut buf = d.to_vec();
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&buf[pn_offset + 4..pn_offset + 20]);
        let (first, rest) = buf.split_at_mut(1);
        keys.header
            .decrypt_in_place(&sample, &mut first[0], &mut rest[pn_offset - 1..pn_offset + 3])
            .ok()?;
        let pn_len = usize::from(buf[0] & 3) + 1;
        let truncated = buf[pn_offset..pn_offset + pn_len]
            .iter()
            .fold(0u64, |a, b| a << 8 | u64::from(*b));
        let pn = decode_pn(self.largest_pn, truncated, pn_len);
        let header_len = pn_offset + pn_len;
        let (header, payload) = buf.split_at_mut(header_len);
        let cap = keys
            .packet
            .decrypt_in_place(pn, header, &mut payload[..end - header_len])
            .ok()?
            .len();
        self.largest_pn = Some(self.largest_pn.map_or(pn, |l| l.max(pn)));
        let frames = parse_frames(&buf[header_len..header_len + cap])?;
        for (off, data) in &frames.crypto {
            self.learn(*off, data);
        }
        Some(Opened {
            buf,
            pn_offset,
            pn_len,
            pn,
            end,
            cap,
            frames,
        })
    }

    fn learn(&mut self, off: u64, data: &[u8]) {
        let have = self.hello.len() as u64;
        if self.cut.is_some() || self.no_sni || off > have || off + data.len() as u64 <= have {
            return;
        }
        self.hello.extend_from_slice(&data[(have - off) as usize..]);
        if let Some(h) = self.hello.get(..4) {
            self.hello_len = Some(4 + (u64::from(h[1]) << 16 | u64::from(h[2]) << 8 | u64::from(h[3])));
        }
        match find_sni(&self.hello) {
            Ok(Some((pos, len))) => {
                let (pos, len) = (pos as u64, len as u64);
                self.cut = Some((pos + len / 2, pos + len));
                self.hello = Vec::new();
            }
            Ok(None) => {
                self.no_sni = true;
                self.hello = Vec::new();
            }
            Err(Incomplete) => {}
        }
    }

    /// The datagrams to send for `batch`, with the ClientHello's CRYPTO data
    /// redistributed when the batch carries the second half of the SNI.
    fn rewrite(&self, batch: Vec<Dgram>) -> Vec<Vec<u8>> {
        let Some(cut) = self.cut else {
            return batch.into_iter().map(|d| d.orig).collect();
        };
        let Some((_, keys)) = &self.keys else {
            return batch.into_iter().map(|d| d.orig).collect();
        };
        let opened: Vec<&Opened> = batch.iter().filter_map(|d| d.initial.as_ref()).collect();
        let caps: Vec<usize> = opened.iter().map(|o| o.cap).collect();
        let control: Vec<&[u8]> = opened.iter().map(|o| o.frames.control.as_slice()).collect();
        let segs: Vec<(u64, &[u8])> = opened
            .iter()
            .flat_map(|o| o.frames.crypto.iter().map(|(off, d)| (*off, d.as_slice())))
            .collect();
        // quic-go's order puts the SNI's tail last, which separates it from
        // the head unless the SNI sits near the end of the ClientHello
        // (rustls shuffles its extensions); then the tail goes first.
        let Some((plain, separated)) = layout(&caps, &control, &segs, cut, false) else {
            return batch.into_iter().map(|d| d.orig).collect();
        };
        let plain = match separated {
            true => plain,
            false => match layout(&caps, &control, &segs, cut, true) {
                Some((p, true)) => p,
                _ => plain,
            },
        };
        let mut plain = plain.into_iter();
        batch
            .into_iter()
            .map(|d| match d.initial {
                Some(o) => seal(o, &plain.next().unwrap(), keys),
                None => d.orig,
            })
            .collect()
    }
}

/// Re-encrypts an opened Initial with a new payload of the same length.
fn seal(o: Opened, plain: &[u8], keys: &DirectionalKeys) -> Vec<u8> {
    let Opened {
        mut buf,
        pn_offset,
        pn_len,
        pn,
        end,
        cap,
        ..
    } = o;
    let header_len = pn_offset + pn_len;
    let (header, payload) = buf.split_at_mut(header_len);
    payload[..cap].copy_from_slice(plain);
    let tag = keys
        .packet
        .encrypt_in_place(pn, header, &mut payload[..cap])
        .expect("Initial AEAD seal");
    payload[cap..end - header_len].copy_from_slice(tag.as_ref());
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&buf[pn_offset + 4..pn_offset + 20]);
    let (first, rest) = buf.split_at_mut(1);
    keys.header
        .encrypt_in_place(&sample, &mut first[0], &mut rest[pn_offset - 1..pn_offset - 1 + pn_len])
        .expect("Initial header protection");
    buf
}

fn initial_suite() -> rustls::quic::Suite {
    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(|s| s.quic_suite())
        .expect("AES-128-GCM supports QUIC")
}

/// RFC 9000 §A.3.
fn decode_pn(largest: Option<u64>, truncated: u64, len: usize) -> u64 {
    let expected = largest.map_or(0, |l| l + 1);
    let win = 1u64 << (len * 8);
    let hwin = win / 2;
    let candidate = (expected & !(win - 1)) | truncated;
    if candidate + hwin <= expected && candidate < (1 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

/// Splits an Initial payload into ACK/PING frames and CRYPTO frames. Any
/// other frame type means the packet is left alone.
fn parse_frames(mut p: &[u8]) -> Option<Frames> {
    let mut f = Frames::default();
    let varint = |p: &mut &[u8]| {
        let (v, n) = get_varint(p)?;
        *p = &p[n..];
        Some(v)
    };
    while let Some(&ty) = p.first() {
        let start = p;
        p = &p[1..];
        match ty {
            0x00 => {}
            0x01 => f.control.push(0x01),
            0x02 | 0x03 => {
                varint(&mut p)?;
                varint(&mut p)?;
                let ranges = varint(&mut p)?;
                varint(&mut p)?;
                for _ in 0..ranges {
                    varint(&mut p)?;
                    varint(&mut p)?;
                }
                if ty == 0x03 {
                    for _ in 0..3 {
                        varint(&mut p)?;
                    }
                }
                f.control.extend_from_slice(&start[..start.len() - p.len()]);
            }
            0x06 => {
                let off = varint(&mut p)?;
                let len = usize::try_from(varint(&mut p)?).ok()?;
                f.crypto.push((off, p.get(..len)?.to_vec()));
                p = &p[len..];
            }
            _ => return None,
        }
    }
    Some(f)
}

fn varint_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// New plaintext payloads, one per packet of `caps` bytes each: the control
/// frames, then the CRYPTO data in offset order with the SNI's tail
/// `[cut.0, cut.1)` held back and sent last (or first, with `tail_first`),
/// then PADDING. Also returns whether no packet carries both halves of the
/// SNI. `None` when the batch does not carry the tail or the frames do not
/// fit.
fn layout(
    caps: &[usize],
    control: &[&[u8]],
    segs: &[(u64, &[u8])],
    cut: (u64, u64),
    tail_first: bool,
) -> Option<(Vec<Vec<u8>>, bool)> {
    let mut segs = segs.to_vec();
    segs.sort_by_key(|s| s.0);
    let mut rest = Vec::new();
    let mut tail = Vec::new();
    for (off, data) in segs {
        let end = off + data.len() as u64;
        let mut at = off;
        for b in [cut.0, cut.1, end] {
            if b <= at || b > end {
                continue;
            }
            let piece = (at, &data[(at - off) as usize..(b - off) as usize]);
            if at >= cut.0 && b <= cut.1 {
                tail.push(piece);
            } else {
                rest.push(piece);
            }
            at = b;
        }
    }
    if tail.is_empty() {
        return None;
    }
    let mut pieces: std::collections::VecDeque<(u64, &[u8])> = match tail_first {
        true => tail.into_iter().chain(rest).collect(),
        false => rest.into_iter().chain(tail).collect(),
    };
    let head_byte = cut.0 - 1;
    let mut separated = true;
    let mut out = Vec::with_capacity(caps.len());
    for (i, &cap) in caps.iter().enumerate() {
        let mut p = Vec::with_capacity(cap);
        p.extend_from_slice(control.get(i).copied().unwrap_or_default());
        if p.len() > cap {
            return None;
        }
        let (mut has_head, mut has_tail) = (false, false);
        while let Some((off, data)) = pieces.pop_front() {
            let room = cap - p.len();
            let head = 1 + varint_len(off) + varint_len(data.len().min(room) as u64);
            if room <= head {
                pieces.push_front((off, data));
                break;
            }
            let n = data.len().min(room - head);
            let end = off + n as u64;
            has_head |= off <= head_byte && head_byte < end;
            has_tail |= off < cut.1 && cut.0 < end;
            p.push(0x06);
            put_varint(&mut p, off);
            put_varint(&mut p, n as u64);
            p.extend_from_slice(&data[..n]);
            if n < data.len() {
                pieces.push_front((end, &data[n..]));
                break;
            }
        }
        separated &= !(has_head && has_tail);
        p.resize(cap, 0);
        out.push(p);
    }
    pieces.is_empty().then_some((out, separated))
}

struct Incomplete;

/// The SNI host name's position and length within a TLS handshake message
/// that starts with a ClientHello, or `None` if it has no SNI.
fn find_sni(h: &[u8]) -> Result<Option<(usize, usize)>, Incomplete> {
    let get = |at: usize, n: usize| h.get(at..at + n).ok_or(Incomplete);
    let u16_at = |at: usize| get(at, 2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])));
    if get(0, 1)?[0] != 1 {
        return Ok(None);
    }
    // type(1) len(3) version(2) random(32)
    let mut i = 38;
    i += 1 + usize::from(get(i, 1)?[0]);
    i += 2 + u16_at(i)?;
    i += 1 + usize::from(get(i, 1)?[0]);
    let ext_end = i + 2 + u16_at(i)?;
    i += 2;
    while i + 4 <= ext_end {
        let ty = u16_at(i)?;
        let len = u16_at(i + 2)?;
        if ty == 0 {
            // server_name_list(2) name_type(1) host_name<2>
            let name_len = u16_at(i + 7)?;
            get(i + 9, name_len)?;
            return Ok((name_len > 0).then_some((i + 9, name_len)));
        }
        i += 4 + len;
    }
    if i > h.len() { Err(Incomplete) } else { Ok(None) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pn_decoding() {
        assert_eq!(decode_pn(None, 0, 1), 0);
        assert_eq!(decode_pn(Some(0), 1, 1), 1);
        assert_eq!(decode_pn(Some(255), 0, 1), 256);
        // RFC 9000 §A.3 example.
        assert_eq!(decode_pn(Some(0xa82f30ea), 0x9b32, 2), 0xa82f9b32);
    }

    #[test]
    fn layout_holds_back_the_sni_tail() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1500).collect();
        let segs = vec![(0, &data[..1100]), (1100, &data[1100..])];
        let (out, separated) = layout(&[1150, 1150], &[&[], &[]], &segs, (100, 110), false).unwrap();
        assert!(separated);
        let mut frames = Vec::new();
        for (i, p) in out.iter().enumerate() {
            assert_eq!(p.len(), 1150);
            for (off, d) in parse_frames(p).unwrap().crypto {
                frames.push((i, off, d));
            }
        }
        // First the head up to the cut, the rest after it, then the cut last.
        assert_eq!((frames[0].0, frames[0].1, frames[0].2.len()), (0, 0, 100));
        assert_eq!(frames[1].1, 110);
        let last = frames.last().unwrap();
        assert_eq!((last.0, last.1, &last.2[..]), (1, 100, &data[100..110]));
        let mut whole = vec![0u8; 1500];
        for (_, off, d) in &frames {
            whole[*off as usize..*off as usize + d.len()].copy_from_slice(d);
        }
        assert_eq!(whole, data);
        assert!(layout(&[1150], &[&[]], &[(0, &data[..50])], (100, 110), false).is_none());
        // Near the end, the tail-last order leaves both halves in the second
        // packet; tail-first separates them.
        let cut = (1480, 1490);
        assert!(!layout(&[1150, 1150], &[&[], &[]], &segs, cut, false).unwrap().1);
        let (out, separated) = layout(&[1150, 1150], &[&[], &[]], &segs, cut, true).unwrap();
        assert!(separated);
        let first = parse_frames(&out[0]).unwrap().crypto;
        assert_eq!((first[0].0, &first[0].1[..]), (1480, &data[1480..1490]));
    }
}
