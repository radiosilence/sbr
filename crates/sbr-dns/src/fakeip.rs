//! FakeIP allocator: hands out addresses from the configured ranges and
//! remembers which domain each stands for, both ways. In memory only;
//! persisting it across restarts is the cache file's job.
//!
//! Allocation follows sing-box: the first address handed out is
//! `network + 2`, addresses are used in order, and after the last one
//! below the broadcast address it wraps to `network + 2` again, evicting
//! whatever domain held the reused address.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

use ipnet::{Ipv4Net, Ipv6Net};

pub struct FakeIp {
    v4: Option<Range>,
    v6: Option<Range>,
    state: RwLock<State>,
}

#[derive(Clone, Copy)]
struct Range {
    /// network+2 .. broadcast-1, as integers.
    first: u128,
    last: u128,
    net: ipnet::IpNet,
}

#[derive(Default)]
struct State {
    by_addr: HashMap<IpAddr, Arc<str>>,
    by_domain4: HashMap<Arc<str>, Ipv4Addr>,
    by_domain6: HashMap<Arc<str>, Ipv6Addr>,
    /// Last handed out, as an offset from `first`.
    next4: u128,
    next6: u128,
}

impl Range {
    fn v4(n: Ipv4Net) -> Self {
        let net = u32::from(n.network()) as u128;
        let bcast = u32::from(n.broadcast()) as u128;
        Self {
            first: net + 2,
            last: bcast - 1,
            net: n.into(),
        }
    }
    fn v6(n: Ipv6Net) -> Self {
        let net = u128::from(n.network());
        let bcast = u128::from(n.broadcast());
        Self {
            first: net + 2,
            last: bcast - 1,
            net: n.into(),
        }
    }
    fn size(&self) -> u128 {
        self.last - self.first + 1
    }
}

impl FakeIp {
    pub fn new(v4: Option<Ipv4Net>, v6: Option<Ipv6Net>) -> Self {
        Self {
            v4: v4.map(Range::v4),
            v6: v6.map(Range::v6),
            state: RwLock::new(State::default()),
        }
    }

    pub fn has_v4(&self) -> bool {
        self.v4.is_some()
    }

    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.v4.is_some_and(|r| r.net.contains(&ip)) || self.v6.is_some_and(|r| r.net.contains(&ip))
    }

    /// The domain behind a fake address.
    pub fn lookup(&self, ip: IpAddr) -> Option<Arc<str>> {
        self.state.read().unwrap().by_addr.get(&ip.to_canonical()).cloned()
    }

    /// The fake address for `domain` (lowercase, no trailing dot), allocating
    /// one if needed. `None` when the family has no range.
    pub fn allocate(&self, domain: &str, v6: bool) -> Option<IpAddr> {
        let range = if v6 { self.v6? } else { self.v4? };
        {
            let s = self.state.read().unwrap();
            let hit = if v6 {
                s.by_domain6.get(domain).map(|a| IpAddr::V6(*a))
            } else {
                s.by_domain4.get(domain).map(|a| IpAddr::V4(*a))
            };
            if hit.is_some() {
                return hit;
            }
        }
        let mut s = self.state.write().unwrap();
        // Raced with another allocation of the same domain?
        if let Some(a) = if v6 {
            s.by_domain6.get(domain).map(|a| IpAddr::V6(*a))
        } else {
            s.by_domain4.get(domain).map(|a| IpAddr::V4(*a))
        } {
            return Some(a);
        }
        let next = if v6 { &mut s.next6 } else { &mut s.next4 };
        let offset = *next % range.size();
        *next = offset + 1;
        let n = range.first + offset;
        let addr = if v6 {
            IpAddr::V6(Ipv6Addr::from(n))
        } else {
            IpAddr::V4(Ipv4Addr::from(n as u32))
        };
        let domain: Arc<str> = domain.into();
        if let Some(old) = s.by_addr.insert(addr, domain.clone()) {
            // Wrapped around: the old domain loses this address.
            if v6 {
                s.by_domain6.remove(&old);
            } else {
                s.by_domain4.remove(&old);
            }
        }
        match addr {
            IpAddr::V4(a) => {
                s.by_domain4.insert(domain, a);
            }
            IpAddr::V6(a) => {
                s.by_domain6.insert(domain, a);
            }
        }
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_is_stable_and_bidirectional() {
        let f = FakeIp::new(
            Some("198.18.0.0/15".parse().unwrap()),
            Some("fc00::/18".parse().unwrap()),
        );
        let a = f.allocate("a.test", false).unwrap();
        assert_eq!(a, "198.18.0.2".parse::<IpAddr>().unwrap(), "first address is network+2");
        assert_eq!(f.allocate("a.test", false), Some(a), "same domain, same address");
        let b = f.allocate("b.test", false).unwrap();
        assert_eq!(b, "198.18.0.3".parse::<IpAddr>().unwrap());
        assert_eq!(f.lookup(a).as_deref(), Some("a.test"));
        let a6 = f.allocate("a.test", true).unwrap();
        assert_eq!(a6, "fc00::2".parse::<IpAddr>().unwrap());
        assert_eq!(f.lookup(a6).as_deref(), Some("a.test"));
        assert!(f.contains("198.19.255.255".parse().unwrap()));
        assert!(!f.contains("198.20.0.1".parse().unwrap()));
        assert!(f.contains("::ffff:198.18.0.9".parse().unwrap()), "v4-mapped counts");
        assert_eq!(f.lookup("198.18.0.99".parse().unwrap()), None);
    }

    #[test]
    fn wraparound_evicts_oldest() {
        // /29: network .0, broadcast .7, usable .2 ..= .6 (5 addresses).
        let f = FakeIp::new(Some("10.0.0.0/29".parse().unwrap()), None);
        let addrs: Vec<IpAddr> = (0..5).map(|i| f.allocate(&format!("d{i}"), false).unwrap()).collect();
        assert_eq!(addrs.first(), Some(&"10.0.0.2".parse().unwrap()));
        assert_eq!(addrs.last(), Some(&"10.0.0.6".parse().unwrap()));
        let wrapped = f.allocate("d5", false).unwrap();
        assert_eq!(wrapped, "10.0.0.2".parse::<IpAddr>().unwrap(), "wraps to network+2");
        assert_eq!(f.lookup(wrapped).as_deref(), Some("d5"));
        // d0 lost its address and gets a fresh one (evicting d1).
        assert_eq!(f.allocate("d0", false), Some("10.0.0.3".parse().unwrap()));
        assert_eq!(f.lookup("10.0.0.3".parse().unwrap()).as_deref(), Some("d0"));
        assert_eq!(f.allocate("d2", false), Some("10.0.0.4".parse().unwrap()), "untouched");
        assert_eq!(f.allocate("x", true), None, "no IPv6 range");
    }
}
