//! TCP NAT table for the system stack.
//!
//! Entries live exactly as long as the connection: `Pending` from the SYN
//! until our listener accepts, `Active` while the engine owns it, `Closed`
//! for a grace period after so trailing FIN/ACKs still translate. A reset
//! from our listener ends the connection on both sides, so its entry goes
//! at once. There is no idle timeout, so long-lived quiet connections (SSH,
//! push channels) are never cut.
//!
//! Storage is sized by live entries. Pending and closed entries expire in
//! the order they were queued, so expiry is amortised constant time on each
//! allocation and the table needs no background sweeper.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

const PORT_MIN: u16 = 10000;
const SPAN: usize = (u16::MAX - PORT_MIN) as usize + 1;
/// A SYN that never got accepted (outbound connect raced a RST, or the
/// listener backlog overflowed).
const PENDING_TTL: Duration = Duration::from_secs(30);
/// Time to keep translating after the engine closed the connection.
const CLOSED_TTL: Duration = Duration::from_secs(60);
/// Pending entries beyond this evict the oldest, so SYNs that never
/// complete cannot hold the port space.
const MAX_PENDING: usize = 4096;
/// Ports tried per allocation before falling back to eviction, bounding the
/// work done under the NAT lock on a crowded table.
const MAX_PROBES: usize = 1024;

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
    /// Distinguishes successive connections that share a port.
    generation: u32,
}

pub struct Nat {
    by_flow: FxHashMap<(SocketAddr, SocketAddr), u16>,
    by_port: FxHashMap<u16, Entry>,
    /// Ports in the order they became pending or closed, with the entry's
    /// generation. An item whose entry has since moved on is skipped.
    pending: VecDeque<(u16, u32)>,
    closed: VecDeque<(u16, u32)>,
    pending_live: usize,
    cursor: u16,
    generation: u32,
}

impl Default for Nat {
    fn default() -> Self {
        Self {
            by_flow: FxHashMap::default(),
            by_port: FxHashMap::default(),
            pending: VecDeque::new(),
            closed: VecDeque::new(),
            pending_live: 0,
            cursor: PORT_MIN,
            generation: 0,
        }
    }
}

impl Nat {
    /// Port for an outgoing packet of flow `src → dst`; allocates on SYN.
    /// `None` means "not ours" (a stray segment, or the port space is full).
    pub fn outbound(&mut self, src: SocketAddr, dst: SocketAddr, syn_only: bool) -> Option<u16> {
        if let Some(&port) = self.by_flow.get(&(src, dst)) {
            let e = self.by_port.get(&port)?;
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
        let now = Instant::now();
        self.expire(now);
        if self.pending_live >= MAX_PENDING {
            let port = self.oldest(State::Pending)?;
            self.remove(port);
        }
        let port = self.allocate()?;
        self.generation = self.generation.wrapping_add(1);
        self.by_port.insert(
            port,
            Entry {
                src,
                dst,
                state: State::Pending,
                since: now,
                generation: self.generation,
            },
        );
        self.by_flow.insert((src, dst), port);
        self.pending.push_back((port, self.generation));
        self.pending_live += 1;
        Some(port)
    }

    /// The original flow for a reply leaving our listener towards `port`.
    /// A reset ends the connection, so with `rst` the entry is released.
    pub fn inbound(&mut self, port: u16, rst: bool) -> Option<(SocketAddr, SocketAddr)> {
        let e = self.by_port.get(&port)?;
        let flow = (e.src, e.dst);
        if rst {
            self.remove(port);
        }
        Some(flow)
    }

    /// Our listener accepted the connection from `port`: the original flow
    /// and the generation to close it with.
    pub fn accept(&mut self, port: u16) -> Option<(SocketAddr, SocketAddr, u32)> {
        let e = self.by_port.get_mut(&port)?;
        if e.state != State::Pending {
            return None;
        }
        e.state = State::Active;
        self.pending_live -= 1;
        Some((e.src, e.dst, e.generation))
    }

    /// The engine is done with the connection `generation` on `port`.
    pub fn close(&mut self, port: u16, generation: u32) {
        let Some(e) = self.by_port.get_mut(&port) else {
            return;
        };
        if e.generation != generation || e.state != State::Active {
            return;
        }
        e.state = State::Closed;
        e.since = Instant::now();
        self.closed.push_back((port, generation));
    }

    pub fn live(&self) -> usize {
        self.by_port.len()
    }

    fn allocate(&mut self) -> Option<u16> {
        if self.by_port.len() < SPAN {
            for _ in 0..MAX_PROBES {
                let port = self.cursor;
                self.cursor = if self.cursor == u16::MAX {
                    PORT_MIN
                } else {
                    self.cursor + 1
                };
                if !self.by_port.contains_key(&port) {
                    return Some(port);
                }
            }
        }
        // Crowded: new connections take precedence over translating the
        // trailing segments of old ones, then over the oldest half-open SYN.
        let port = self.oldest(State::Closed).or_else(|| self.oldest(State::Pending))?;
        self.remove(port);
        Some(port)
    }

    /// Drop pending and closed entries past their time.
    fn expire(&mut self, now: Instant) {
        for (state, ttl) in [(State::Pending, PENDING_TTL), (State::Closed, CLOSED_TTL)] {
            while let Some(port) = self.oldest(state) {
                if now.duration_since(self.by_port[&port].since) < ttl {
                    break;
                }
                self.remove(port);
            }
        }
    }

    /// The oldest entry in `state`, discarding queue items whose entry has
    /// moved on.
    fn oldest(&mut self, state: State) -> Option<u16> {
        let q = match state {
            State::Pending => &mut self.pending,
            State::Closed => &mut self.closed,
            State::Active => return None,
        };
        while let Some(&(port, generation)) = q.front() {
            match self.by_port.get(&port) {
                Some(e) if e.generation == generation && e.state == state => return Some(port),
                _ => {
                    q.pop_front();
                }
            }
        }
        None
    }

    fn remove(&mut self, port: u16) {
        let Some(e) = self.by_port.remove(&port) else {
            return;
        };
        if e.state == State::Pending {
            self.pending_live -= 1;
        }
        if self.by_flow.get(&(e.src, e.dst)) == Some(&port) {
            self.by_flow.remove(&(e.src, e.dst));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn client(i: usize) -> SocketAddr {
        SocketAddr::new([172, 19, (i >> 16) as u8, (i >> 8) as u8].into(), i as u16)
    }

    #[test]
    fn lifecycle() {
        let mut n = Nat::default();
        let (s, d) = (a("172.19.0.1:50000"), a("1.1.1.1:443"));
        assert_eq!(n.outbound(s, d, false), None, "no SYN, no entry");
        let p = n.outbound(s, d, true).unwrap();
        assert_eq!(n.outbound(s, d, false), Some(p), "subsequent segments reuse it");
        assert_eq!(n.outbound(s, d, true), Some(p), "SYN retransmit reuses it");
        assert_eq!(n.inbound(p, false), Some((s, d)));
        let (s2, d2, g) = n.accept(p).unwrap();
        assert_eq!((s2, d2), (s, d));
        assert_eq!(n.accept(p), None, "accepted once");
        n.close(p, g);
        assert_eq!(n.outbound(s, d, false), Some(p), "trailing FIN/ACK still translate");
        let p2 = n.outbound(s, d, true).unwrap();
        assert_ne!(p, p2, "a new connection on the same tuple gets a new port");
        let other = n.outbound(a("172.19.0.1:50001"), d, true).unwrap();
        assert_ne!(other, p2);
    }

    #[test]
    fn listener_reset_releases_the_port() {
        let mut n = Nat::default();
        let (s, d) = (a("172.19.0.1:50000"), a("1.1.1.1:443"));
        let p = n.outbound(s, d, true).unwrap();
        let (.., g) = n.accept(p).unwrap();
        assert_eq!(n.inbound(p, true), Some((s, d)), "the reset itself is translated");
        assert_eq!(n.live(), 0);
        assert_eq!(n.inbound(p, false), None);
        assert_eq!(n.outbound(s, d, false), None);
        // A later close from the engine must not touch whatever reuses the port.
        n.cursor = p;
        let p2 = n.outbound(a("172.19.0.1:50002"), d, true).unwrap();
        assert_eq!(p2, p);
        n.close(p, g);
        assert!(n.accept(p2).is_some(), "the new connection is still pending");
    }

    #[test]
    fn pending_is_capped_by_evicting_the_oldest() {
        let mut n = Nat::default();
        let d = a("1.1.1.1:443");
        let first = n.outbound(client(0), d, true).unwrap();
        for i in 1..MAX_PENDING + 10 {
            n.outbound(client(i), d, true).unwrap();
        }
        assert_eq!(n.pending_live, MAX_PENDING);
        assert_eq!(n.live(), MAX_PENDING);
        assert_eq!(n.outbound(client(0), d, false), None, "the oldest SYN was evicted");
        assert!(n.inbound(first, false) != Some((client(0), d)));
        // Accepted connections leave the pending count and are never evicted.
        let p = n.outbound(client(MAX_PENDING + 9), d, false).unwrap();
        n.accept(p).unwrap();
        for i in 0..2 * MAX_PENDING {
            n.outbound(client(100_000 + i), d, true).unwrap();
        }
        assert_eq!(n.outbound(client(MAX_PENDING + 9), d, false), Some(p));
    }

    #[test]
    fn a_full_table_reclaims_closed_entries_first() {
        let mut n = Nat::default();
        let d = a("1.1.1.1:443");
        let mut closed = None;
        for i in 0..SPAN {
            let p = n.outbound(client(i), d, true).unwrap();
            let (.., g) = n.accept(p).unwrap();
            if i == 1000 {
                n.close(p, g);
                closed = Some(p);
            }
        }
        assert_eq!(n.live(), SPAN);
        let p = n.outbound(client(SPAN), d, true).unwrap();
        assert_eq!(Some(p), closed, "the closed entry made way");
        assert_eq!(n.outbound(client(1000), d, false), None);
        n.accept(p).unwrap();
        assert_eq!(n.outbound(client(SPAN + 1), d, true), None, "every port active");
    }

    #[test]
    fn expiry_follows_queue_order() {
        let mut n = Nat::default();
        let d = a("1.1.1.1:443");
        let p = n.outbound(client(0), d, true).unwrap();
        let q = n.outbound(client(1), d, true).unwrap();
        n.by_port.get_mut(&p).unwrap().since -= PENDING_TTL;
        n.outbound(client(2), d, true).unwrap();
        assert_eq!(n.outbound(client(0), d, false), None, "the stale SYN expired");
        assert_eq!(n.outbound(client(1), d, false), Some(q));
        assert_eq!(n.live(), 2);
    }

    #[test]
    fn an_empty_table_allocates_nothing() {
        let n = Nat::default();
        assert_eq!(n.by_port.capacity(), 0);
        assert_eq!(n.by_flow.capacity(), 0);
    }
}
