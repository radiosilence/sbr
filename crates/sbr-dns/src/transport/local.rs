//! `local` (the OS resolver) and `hosts`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hickory_proto::op::Message;
use sbr_core::{BoxFuture, Host, Outbound};
use tokio::sync::Semaphore;

use super::{Remote, Transport, Udp};
use crate::msg::{self, TYPE_A, TYPE_AAAA};

/// TTL for answers without one (sing-box `C.DefaultDNSTTL`).
const TTL: u32 = sbr_config::DEFAULT_TTL;

/// How long a getaddrinfo call may take, waiting for a slot included.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// getaddrinfo blocks a thread of the blocking pool, which the iOS extension
/// caps at eight, and cannot be cancelled. Queries from clients and the
/// lookups the engine dials with get separate slots, so a client resolving
/// a flood of unique names neither occupies the whole pool nor delays
/// dialing; the rest of the pool serves other blocking work.
static CLIENT_SLOTS: Semaphore = Semaphore::const_new(3);
static DIAL_SLOTS: Semaphore = Semaphore::const_new(3);

tokio::task_local! {
    static DIALING: ();
}

/// Runs `f` as a lookup for dialing: getaddrinfo calls it makes through
/// `local` use the dial slots.
pub(crate) async fn for_dial<F: Future>(f: F) -> F::Output {
    DIALING.scope((), f).await
}

fn slots() -> &'static Semaphore {
    if DIALING.try_with(|_| ()).is_ok() {
        &DIAL_SLOTS
    } else {
        &CLIENT_SLOTS
    }
}

/// getaddrinfo for `name` on one of `slots`. The slot is held until the call
/// returns, even after the caller has given up on it.
async fn getaddrinfo(name: String, slots: &'static Semaphore, timeout: Duration) -> io::Result<Vec<IpAddr>> {
    let timed_out = || io::Error::new(io::ErrorKind::TimedOut, format!("getaddrinfo {name}: timed out"));
    let deadline = tokio::time::Instant::now() + timeout;
    let Ok(Ok(permit)) = tokio::time::timeout_at(deadline, slots.acquire()).await else {
        return Err(timed_out());
    };
    let lookup = tokio::spawn({
        let name = name.clone();
        async move {
            let _permit = permit;
            tokio::net::lookup_host((name.as_str(), 0))
                .await
                .map(|addrs| addrs.map(|a: SocketAddr| a.ip().to_canonical()).collect())
        }
    });
    match tokio::time::timeout_at(deadline, lookup).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => Err(io::Error::other(e)),
        Err(_) => Err(timed_out()),
    }
}

/// A/AAAA through getaddrinfo (on Apple platforms that is the only resolver
/// a Network Extension may use); other types go to the first `nameserver`
/// in /etc/resolv.conf when there is one, else get an empty answer.
pub(crate) struct Local {
    dialer: Arc<dyn Outbound>,
    fallback: OnceLock<Option<Udp>>,
}

impl Local {
    pub fn new(dialer: Arc<dyn Outbound>) -> Self {
        Self {
            dialer,
            fallback: OnceLock::new(),
        }
    }

    fn fallback(&self) -> Option<&Udp> {
        self.fallback
            .get_or_init(|| {
                let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
                let ip = conf.lines().find_map(|l| {
                    let mut it = l.split_whitespace();
                    (it.next()? == "nameserver").then(|| it.next()?.split('%').next()?.parse::<IpAddr>().ok())?
                })?;
                Some(Udp::new(Remote {
                    host: Host::Ip(ip),
                    port: 53,
                    dialer: self.dialer.clone(),
                    resolver: None,
                }))
            })
            .as_ref()
    }
}

impl Transport for Local {
    fn exchange<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, io::Result<Message>> {
        Box::pin(async move {
            let Some(q) = query.queries.first() else {
                return Ok(msg::status(query, 1));
            };
            let qtype = u16::from(q.query_type());
            if qtype != TYPE_A && qtype != TYPE_AAAA {
                return match self.fallback() {
                    Some(udp) => udp.exchange(query).await,
                    None => Ok(msg::status(query, 0)),
                };
            }
            match getaddrinfo(msg::domain_of(q), slots(), LOOKUP_TIMEOUT).await {
                Ok(ips) => Ok(msg::addresses(query, &ips, TTL)),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => Err(e),
                // getaddrinfo doesn't say why reliably; NXDOMAIN without an
                // SOA is not cached, so a transient failure isn't sticky.
                Err(_) => Ok(msg::status(query, 3)),
            }
        })
    }
}

/// Predefined entries, then hosts files. Unknown names get NXDOMAIN.
pub(crate) struct Hosts {
    table: HashMap<String, Vec<IpAddr>>,
}

impl Hosts {
    /// `files` are (path, contents) pairs already read.
    pub fn new(predefined: &[(String, Vec<IpAddr>)], files: &[String]) -> Self {
        let mut table: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for (name, addrs) in predefined {
            table.insert(name.clone(), addrs.clone());
        }
        let predefined_names: Vec<&String> = predefined.iter().map(|(n, _)| n).collect();
        for text in files {
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or_default();
                let mut it = line.split_whitespace();
                let Some(ip) = it.next().and_then(|s| s.split('%').next()?.parse::<IpAddr>().ok()) else {
                    continue;
                };
                for name in it {
                    let name = name.trim_end_matches('.').to_ascii_lowercase();
                    if predefined_names.contains(&&name) {
                        continue;
                    }
                    let e = table.entry(name).or_default();
                    if !e.contains(&ip) {
                        e.push(ip.to_canonical());
                    }
                }
            }
        }
        Self { table }
    }

    pub fn get(&self, name: &str) -> Option<&[IpAddr]> {
        self.table.get(name).map(Vec::as_slice)
    }
}

impl Transport for Hosts {
    fn exchange<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, io::Result<Message>> {
        Box::pin(async move {
            let Some(q) = query.queries.first() else {
                return Ok(msg::status(query, 1));
            };
            let qtype = u16::from(q.query_type());
            if (qtype == TYPE_A || qtype == TYPE_AAAA)
                && let Some(ips) = self.get(&msg::domain_of(q))
            {
                return Ok(msg::addresses(query, ips, TTL));
            }
            Ok(msg::status(query, 3))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn getaddrinfo_waits_for_a_slot_and_times_out() {
        static SLOTS: Semaphore = Semaphore::const_new(1);
        let lookup = |t| getaddrinfo("localhost".into(), &SLOTS, t);
        assert!(!lookup(LOOKUP_TIMEOUT).await.unwrap().is_empty());
        let held = SLOTS.acquire().await.unwrap();
        let err = lookup(Duration::from_millis(100)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(held);
        assert!(!lookup(LOOKUP_TIMEOUT).await.unwrap().is_empty());
        assert_eq!(SLOTS.available_permits(), 1, "the slot is returned");
    }

    #[tokio::test]
    async fn dial_lookups_use_their_own_slots() {
        assert!(std::ptr::eq(slots(), &CLIENT_SLOTS));
        assert!(std::ptr::eq(for_dial(async { slots() }).await, &DIAL_SLOTS));
    }

    #[test]
    fn hosts_file_and_predefined() {
        let h = Hosts::new(
            &[("router.lan".into(), vec!["10.0.0.1".parse().unwrap()])],
            &["127.0.0.1 localhost Local.Test # comment\n::1 localhost\n10.9.9.9 router.lan\n".into()],
        );
        assert_eq!(h.get("localhost").unwrap().len(), 2);
        assert_eq!(h.get("local.test").unwrap(), &["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            h.get("router.lan").unwrap(),
            &["10.0.0.1".parse::<IpAddr>().unwrap()],
            "predefined wins"
        );
        assert!(h.get("comment").is_none());
    }
}
