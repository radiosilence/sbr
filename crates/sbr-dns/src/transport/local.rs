//! `local` (the OS resolver) and `hosts`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use hickory_proto::op::Message;
use sbr_core::{BoxFuture, Host, Outbound};

use super::{Remote, Transport, Udp};
use crate::msg::{self, TYPE_A, TYPE_AAAA};

/// TTL for answers without one (sing-box `C.DefaultDNSTTL`).
const TTL: u32 = sbr_config::DEFAULT_TTL;

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
            let name = msg::domain_of(q);
            match tokio::net::lookup_host((name.as_str(), 0)).await {
                Ok(addrs) => {
                    let ips: Vec<IpAddr> = addrs.map(|a: SocketAddr| a.ip().to_canonical()).collect();
                    Ok(msg::addresses(query, &ips, TTL))
                }
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
