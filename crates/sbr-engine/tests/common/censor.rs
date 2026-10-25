//! A model of the QUIC SNI filters of the GFW (Zohaib et al., USENIX
//! Security 2025) and Russia's TSPU (FOCI 2026): a UDP relay that decrypts
//! the leading Initial packet of every client datagram and, if that one
//! packet reveals a blocked name, drops it and black-holes the flow from
//! then on (the residual block). "Reveals" is deliberately generous: the
//! name anywhere in the packet's plaintext, or in its CRYPTO frames
//! reassembled by offset. What the model does not do, like the real
//! censors, is reassemble across datagrams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rustls::Side;
use rustls::quic::Version;
use tokio::net::UdpSocket;

pub struct Censor {
    pub addr: SocketAddr,
    /// Client Initial packets decrypted.
    pub inspected: Arc<AtomicUsize>,
    pub blocked: Arc<AtomicBool>,
}

/// Relays to `upstream`, filtering on `name`.
pub async fn start(upstream: SocketAddr, name: &'static str) -> Censor {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = front.local_addr().unwrap();
    let inspected = Arc::new(AtomicUsize::new(0));
    let blocked = Arc::new(AtomicBool::new(false));
    let (i, b) = (inspected.clone(), blocked.clone());
    tokio::spawn(async move {
        let mut flows: HashMap<SocketAddr, (Arc<UdpSocket>, bool)> = HashMap::new();
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, from)) = front.recv_from(&mut buf).await else {
                return;
            };
            let flow = match flows.get_mut(&from) {
                Some(f) => f,
                None => {
                    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    back.connect(upstream).await.unwrap();
                    let (back2, front2) = (back.clone(), front.clone());
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        while let Ok(n) = back2.recv(&mut buf).await {
                            let _ = front2.send_to(&buf[..n], from).await;
                        }
                    });
                    flows.entry(from).or_insert((back, false))
                }
            };
            if flow.1 {
                continue;
            }
            if let Some(plain) = open_initial(&buf[..n]) {
                i.fetch_add(1, Ordering::Relaxed);
                if reveals(&plain, name.as_bytes()) {
                    flow.1 = true;
                    b.store(true, Ordering::Relaxed);
                    continue;
                }
            }
            let _ = flow.0.send(&buf[..n]).await;
        }
    });
    Censor {
        addr,
        inspected,
        blocked,
    }
}

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let first = *b.get(*i)?;
    let len = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3f);
    for x in b.get(*i + 1..*i + len)? {
        v = v << 8 | u64::from(*x);
    }
    *i += len;
    Some(v)
}

/// The plaintext payload of a datagram's leading QUIC v1 client Initial.
fn open_initial(d: &[u8]) -> Option<Vec<u8>> {
    if d.len() < 7 || d[0] & 0xf0 != 0xc0 || d[1..5] != [0, 0, 0, 1] {
        return None;
    }
    let mut i = 5;
    let dcid = d.get(i + 1..i + 1 + usize::from(d[i]))?;
    i += 1 + dcid.len();
    i += 1 + usize::from(*d.get(i)?);
    let token = varint(d, &mut i)? as usize;
    i += token;
    let len = varint(d, &mut i)? as usize;
    let pn_offset = i;
    let end = pn_offset + len;
    if end > d.len() || pn_offset + 20 > end {
        return None;
    }
    let suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()?
        .quic_suite()?;
    let keys = suite.keys(dcid, Side::Server, Version::V1).remote;
    let mut pkt = d[..end].to_vec();
    let sample: Vec<u8> = pkt[pn_offset + 4..pn_offset + 20].to_vec();
    let (first, rest) = pkt.split_at_mut(1);
    keys.header
        .decrypt_in_place(&sample, &mut first[0], &mut rest[pn_offset - 1..pn_offset + 3])
        .ok()?;
    let pn_len = usize::from(pkt[0] & 3) + 1;
    // Client Initial packet numbers stay small; no truncation to undo.
    let pn = pkt[pn_offset..pn_offset + pn_len]
        .iter()
        .fold(0u64, |a, b| a << 8 | u64::from(*b));
    let (header, payload) = pkt.split_at_mut(pn_offset + pn_len);
    Some(keys.packet.decrypt_in_place(pn, header, payload).ok()?.to_vec())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn reveals(plain: &[u8], name: &[u8]) -> bool {
    if contains(plain, name) {
        return true;
    }
    // CRYPTO frames of this one packet, placed by offset.
    let mut stream = Vec::new();
    let mut i = 0;
    while i < plain.len() {
        match plain[i] {
            0x06 => {
                i += 1;
                let (Some(off), Some(len)) = (varint(plain, &mut i), varint(plain, &mut i)) else {
                    break;
                };
                let (off, len) = (off as usize, len as usize);
                let Some(data) = plain.get(i..i + len) else { break };
                if stream.len() < off + len {
                    stream.resize(off + len, 0);
                }
                stream[off..off + len].copy_from_slice(data);
                i += len;
            }
            0x00 | 0x01 => i += 1,
            // ACK and anything else: stop; the ClientHello is in the
            // CRYPTO frames before it in every client we model.
            _ => break,
        }
    }
    contains(&stream, name)
}
