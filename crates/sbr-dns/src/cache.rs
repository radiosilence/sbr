//! Response cache and in-flight query coalescing.
//!
//! Keys are built on the stack (lowercased wire-format name, type, class,
//! server, client subnet), so a hit costs no allocation besides whatever
//! the caller builds from the shared `Arc` it gets back. Expiry is checked
//! on access; nothing sweeps in the background.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher, RandomState};
use std::io;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::Name;
use ipnet::IpNet;
use lru::LruCache;
use tokio::sync::watch;

/// Max wire length of a name.
const NAME_MAX: usize = 255;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key {
    name: [u8; NAME_MAX],
    len: u8,
    qtype: u16,
    qclass: u16,
    server: u16,
    subnet: Option<IpNet>,
}

impl Key {
    fn new(server: usize, qtype: u16, qclass: u16, subnet: Option<IpNet>) -> Self {
        Self {
            name: [0; NAME_MAX],
            len: 0,
            qtype,
            qclass,
            server: server as u16,
            subnet,
        }
    }

    fn push_label(&mut self, label: &[u8]) -> Option<()> {
        let at = self.len as usize;
        if label.is_empty() || label.len() > 63 || at + 1 + label.len() > NAME_MAX {
            return None;
        }
        self.name[at] = label.len() as u8;
        for (d, s) in self.name[at + 1..].iter_mut().zip(label) {
            *d = s.to_ascii_lowercase();
        }
        self.len += 1 + label.len() as u8;
        Some(())
    }

    pub fn from_name(server: usize, name: &Name, qtype: u16, qclass: u16, subnet: Option<IpNet>) -> Option<Self> {
        let mut k = Self::new(server, qtype, qclass, subnet);
        for l in name.iter() {
            k.push_label(l)?;
        }
        Some(k)
    }

    /// Same key as [`Key::from_name`] for the equivalent name, without
    /// building one.
    pub fn from_str(server: usize, domain: &str, qtype: u16, subnet: Option<IpNet>) -> Option<Self> {
        let mut k = Self::new(server, qtype, 1, subnet);
        for l in domain.trim_end_matches('.').split('.') {
            k.push_label(l.as_bytes())?;
        }
        Some(k)
    }
}

/// A cached response: TTLs in `msg` are as stored; callers rewrite them.
pub struct Hit {
    pub msg: Arc<Message>,
    pub addrs: Arc<[IpAddr]>,
    /// Seconds left (1 for a stale, optimistically served entry).
    pub ttl: u32,
    pub stale: bool,
}

struct Entry {
    msg: Arc<Message>,
    addrs: Arc<[IpAddr]>,
    /// `None`: never expires (`disable_expire`).
    expire: Option<Instant>,
}

pub struct Cache {
    lru: Mutex<LruCache<u64, (Key, Entry)>>,
    hasher: RandomState,
    disable_expire: bool,
    /// `optimistic` timeout: how long past expiry an entry may be served.
    optimistic: Option<Duration>,
}

impl Cache {
    pub fn new(capacity: u32, disable_expire: bool, optimistic: Option<Duration>) -> Self {
        let cap = NonZeroUsize::new((capacity as usize).max(1024)).expect("non-zero");
        Self {
            lru: Mutex::new(LruCache::new(cap)),
            hasher: RandomState::new(),
            disable_expire,
            optimistic,
        }
    }

    fn hash(&self, k: &Key) -> u64 {
        let mut h = self.hasher.build_hasher();
        k.hash(&mut h);
        h.finish()
    }

    pub fn get(&self, k: &Key, now: Instant) -> Option<Hit> {
        let h = self.hash(k);
        let mut lru = self.lru.lock().unwrap();
        let (key, e) = lru.get(&h)?;
        if key != k {
            return None;
        }
        let Some(expire) = e.expire else {
            return Some(Hit {
                msg: e.msg.clone(),
                addrs: e.addrs.clone(),
                ttl: crate::msg::response_ttl(&e.msg),
                stale: false,
            });
        };
        if now < expire {
            let left = (expire - now).as_secs() as u32;
            return Some(Hit {
                msg: e.msg.clone(),
                addrs: e.addrs.clone(),
                ttl: left.max(1),
                stale: false,
            });
        }
        if self.optimistic.is_some_and(|o| now < expire + o) {
            return Some(Hit {
                msg: e.msg.clone(),
                addrs: e.addrs.clone(),
                ttl: 1,
                stale: true,
            });
        }
        lru.pop(&h);
        None
    }

    pub fn put(&self, k: Key, msg: Arc<Message>, ttl: u32, now: Instant) {
        if ttl == 0 {
            return;
        }
        let h = self.hash(&k);
        let addrs: Arc<[IpAddr]> = crate::msg::answer_addrs(&msg).into();
        let expire = (!self.disable_expire).then(|| now + Duration::from_secs(ttl as u64));
        self.lru.lock().unwrap().put(h, (k, Entry { msg, addrs, expire }));
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lru.lock().unwrap().len()
    }
}

/// What a coalesced query produced; errors are shared by kind and text.
pub type Outcome = Result<Arc<Message>, (io::ErrorKind, Arc<str>)>;

/// Queries in flight, keyed like the cache: the first caller (the leader)
/// queries upstream, the rest wait for its outcome.
#[derive(Default)]
pub struct Inflight {
    map: Mutex<HashMap<Key, watch::Receiver<Option<Outcome>>>>,
}

pub enum Join<'a> {
    Lead(Leader<'a>),
    Wait(watch::Receiver<Option<Outcome>>),
}

/// Removes the in-flight entry when the leader finishes or is cancelled;
/// waiters of a cancelled leader see the channel close and retry.
pub struct Leader<'a> {
    owner: &'a Inflight,
    key: Key,
    tx: watch::Sender<Option<Outcome>>,
}

impl Leader<'_> {
    pub fn finish(self, outcome: Outcome) {
        self.tx.send_replace(Some(outcome));
    }
}

impl Drop for Leader<'_> {
    fn drop(&mut self) {
        self.owner.map.lock().unwrap().remove(&self.key);
    }
}

impl Inflight {
    pub fn join(&self, key: &Key) -> Join<'_> {
        let mut map = self.map.lock().unwrap();
        if let Some(rx) = map.get(key) {
            return Join::Wait(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        map.insert(key.clone(), rx);
        Join::Lead(Leader {
            owner: self,
            key: key.clone(),
            tx,
        })
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

/// Wait for a leader. `None`: it gave up without an outcome.
pub async fn wait(mut rx: watch::Receiver<Option<Outcome>>) -> Option<Outcome> {
    rx.wait_for(Option::is_some).await.ok().and_then(|v| v.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg;

    fn answer(ip: &str, ttl: u32) -> Arc<Message> {
        let q = msg::query("a.test", msg::TYPE_A).unwrap();
        Arc::new(msg::addresses(&q, &[ip.parse().unwrap()], ttl))
    }

    #[test]
    fn keys_from_name_and_str_agree() {
        let n = Name::from_ascii("WWW.Example.com.").unwrap();
        let a = Key::from_name(0, &n, 1, 1, None).unwrap();
        let b = Key::from_str(0, "www.example.COM", 1, None).unwrap();
        assert!(a == b);
        assert!(Key::from_str(1, "www.example.com", 1, None).unwrap() != b, "per server");
        assert!(Key::from_str(0, "www.example.com", 28, None).unwrap() != b, "per type");
        let s = Some("1.2.3.0/24".parse().unwrap());
        assert!(Key::from_str(0, "www.example.com", 1, s).unwrap() != b, "per subnet");
        assert!(Key::from_str(0, "a..b", 1, None).is_none());
    }

    #[test]
    fn ttl_expiry_and_remaining() {
        let c = Cache::new(0, false, None);
        let k = Key::from_str(0, "a.test", 1, None).unwrap();
        let t0 = Instant::now();
        c.put(k.clone(), answer("1.1.1.1", 10), 10, t0);
        let hit = c.get(&k, t0 + Duration::from_secs(4)).unwrap();
        assert_eq!(hit.ttl, 6);
        assert!(!hit.stale);
        assert_eq!(&*hit.addrs, &["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert!(c.get(&k, t0 + Duration::from_secs(11)).is_none());
        assert_eq!(c.len(), 0, "expired entries are dropped on access");
        c.put(k.clone(), answer("1.1.1.1", 0), 0, t0);
        assert!(c.get(&k, t0).is_none(), "TTL 0 is not cached");
    }

    #[test]
    fn optimistic_and_disable_expire() {
        let c = Cache::new(0, false, Some(Duration::from_secs(60)));
        let k = Key::from_str(0, "a.test", 1, None).unwrap();
        let t0 = Instant::now();
        c.put(k.clone(), answer("1.1.1.1", 10), 10, t0);
        let hit = c.get(&k, t0 + Duration::from_secs(30)).unwrap();
        assert!(hit.stale);
        assert_eq!(hit.ttl, 1);
        assert!(c.get(&k, t0 + Duration::from_secs(71)).is_none());

        let c = Cache::new(0, true, None);
        c.put(k.clone(), answer("1.1.1.1", 10), 10, t0);
        let hit = c.get(&k, t0 + Duration::from_secs(86400)).unwrap();
        assert!(!hit.stale);
    }

    #[test]
    fn capacity_is_lru() {
        let c = Cache::new(10, false, None); // raised to 1024
        let t0 = Instant::now();
        for i in 0..1100 {
            let k = Key::from_str(0, &format!("h{i}.test"), 1, None).unwrap();
            c.put(k, answer("1.1.1.1", 60), 60, t0);
        }
        assert_eq!(c.len(), 1024);
        assert!(c.get(&Key::from_str(0, "h0.test", 1, None).unwrap(), t0).is_none());
        assert!(c.get(&Key::from_str(0, "h1099.test", 1, None).unwrap(), t0).is_some());
    }

    #[tokio::test]
    async fn inflight_leader_and_waiters() {
        let f = Inflight::default();
        let k = Key::from_str(0, "a.test", 1, None).unwrap();
        let Join::Lead(lead) = f.join(&k) else { panic!() };
        let Join::Wait(rx) = f.join(&k) else { panic!() };
        let w = tokio::spawn(wait(rx));
        lead.finish(Ok(answer("1.1.1.1", 1)));
        assert!(w.await.unwrap().unwrap().is_ok());
        assert_eq!(f.len(), 0);

        // A cancelled leader releases its waiters with no outcome.
        let Join::Lead(lead) = f.join(&k) else { panic!() };
        let Join::Wait(rx) = f.join(&k) else { panic!() };
        drop(lead);
        assert!(wait(rx).await.is_none());
        assert!(matches!(f.join(&k), Join::Lead(_)));
    }
}
