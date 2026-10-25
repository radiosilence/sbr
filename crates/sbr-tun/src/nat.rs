//! TCP NAT table for the system stack.
//!
//! Entries live exactly as long as the connection: `Pending` from the SYN
//! until our listener accepts, `Active` while the engine owns it, `Closed`
//! for a grace period after so trailing FIN/ACKs still translate. There is
//! no idle timeout, so long-lived quiet connections (SSH, push channels)
//! are never cut, and the table never needs a background sweeper: stale
//! slots are reclaimed lazily when the allocator walks over them.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

const PORT_MIN: u16 = 10000;
/// A SYN that never got accepted (outbound connect raced a RST, or the
/// listener backlog overflowed).
const PENDING_TTL: Duration = Duration::from_secs(30);
/// Time to keep translating after the engine closed the connection.
const CLOSED_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Pending,
    Active,
    Closed,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    src: SocketAddr,
    dst: SocketAddr,
    state: State,
    since: Instant,
}

pub struct Nat {
    by_flow: FxHashMap<(SocketAddr, SocketAddr), u16>,
    by_port: Box<[Option<Entry>]>,
    cursor: u16,
    live: usize,
}

impl Default for Nat {
    fn default() -> Self {
        Self {
            by_flow: FxHashMap::default(),
            by_port: vec![None; 65536].into_boxed_slice(),
            cursor: PORT_MIN,
            live: 0,
        }
    }
}

impl Nat {
    /// Port for an outgoing packet of flow `src → dst`; allocates on SYN.
    /// `None` means "not ours" (a stray segment, or the port space is full).
    pub fn outbound(&mut self, src: SocketAddr, dst: SocketAddr, syn_only: bool) -> Option<u16> {
        if let Some(&port) = self.by_flow.get(&(src, dst)) {
            let e = self.by_port[port as usize].as_ref()?;
            // A fresh SYN on a closed flow is a new connection reusing the
            // 4-tuple: give it a new port so it can't collide with the old
            // socket's TIME_WAIT on our side.
            if !(syn_only && e.state == State::Closed) {
                return Some(port);
            }
        }
        if !syn_only {
            return None;
        }
        let port = self.allocate()?;
        self.by_port[port as usize] = Some(Entry {
            src,
            dst,
            state: State::Pending,
            since: Instant::now(),
        });
        self.by_flow.insert((src, dst), port);
        self.live += 1;
        Some(port)
    }

    /// The original flow for a reply leaving our listener towards `port`.
    pub fn inbound(&self, port: u16) -> Option<(SocketAddr, SocketAddr)> {
        self.by_port[port as usize].as_ref().map(|e| (e.src, e.dst))
    }

    /// Our listener accepted the connection from `port`.
    pub fn accept(&mut self, port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let e = self.by_port[port as usize].as_mut()?;
        e.state = State::Active;
        Some((e.src, e.dst))
    }

    /// The engine is done with the connection on `port`.
    pub fn close(&mut self, port: u16) {
        if let Some(e) = self.by_port[port as usize].as_mut() {
            e.state = State::Closed;
            e.since = Instant::now();
        }
    }

    pub fn live(&self) -> usize {
        self.live
    }

    fn allocate(&mut self) -> Option<u16> {
        let now = Instant::now();
        let span = (u16::MAX - PORT_MIN) as usize + 1;
        for _ in 0..span {
            let port = self.cursor;
            self.cursor = if self.cursor == u16::MAX {
                PORT_MIN
            } else {
                self.cursor + 1
            };
            match self.by_port[port as usize] {
                None => return Some(port),
                Some(e) => {
                    let ttl = match e.state {
                        State::Active => continue,
                        State::Pending => PENDING_TTL,
                        State::Closed => CLOSED_TTL,
                    };
                    if now.duration_since(e.since) >= ttl {
                        if self.by_flow.get(&(e.src, e.dst)) == Some(&port) {
                            self.by_flow.remove(&(e.src, e.dst));
                        }
                        self.by_port[port as usize] = None;
                        self.live -= 1;
                        return Some(port);
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lifecycle() {
        let mut n = Nat::default();
        let (s, d) = (a("172.19.0.1:50000"), a("1.1.1.1:443"));
        assert_eq!(n.outbound(s, d, false), None, "no SYN, no entry");
        let p = n.outbound(s, d, true).unwrap();
        assert_eq!(n.outbound(s, d, false), Some(p), "subsequent segments reuse it");
        assert_eq!(n.outbound(s, d, true), Some(p), "SYN retransmit reuses it");
        assert_eq!(n.inbound(p), Some((s, d)));
        assert_eq!(n.accept(p), Some((s, d)));
        n.close(p);
        assert_eq!(n.outbound(s, d, false), Some(p), "trailing FIN/ACK still translate");
        let p2 = n.outbound(s, d, true).unwrap();
        assert_ne!(p, p2, "a new connection on the same tuple gets a new port");
        let other = n.outbound(a("172.19.0.1:50001"), d, true).unwrap();
        assert_ne!(other, p2);
    }
}
