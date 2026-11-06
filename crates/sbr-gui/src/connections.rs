//! The tunnel's open connections, polled four times a second while the
//! connections page is showing: each with its rate over the last poll and
//! when bytes last moved, the most recently active first. TunnelModel's
//! pollConnections and closeConnection.

use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use koan_kit::app::*;

use crate::ne::{Manager, Status};
use crate::proto::{Connection, Request};
use crate::tunnel::Tunnel;

const POLL: Duration = Duration::from_millis(250);

/// A connection with its rates over the last poll.
#[derive(Clone, Debug, PartialEq)]
pub struct Live {
    pub connection: Connection,
    /// Bytes a second.
    pub up: f64,
    pub down: f64,
    pub last_active: Instant,
}

impl Live {
    pub fn active(&self) -> bool {
        self.up + self.down > 0.0
    }
}

pub struct Connections {
    pub rows: Vec<Live>,
    /// How many the tunnel has open; `rows` holds the newest of them.
    pub total: u64,
    pub error: Option<String>,
    tunnel: Entity<Tunnel>,
    demo: bool,
    /// Polling, while a page shows the list.
    poll: Option<Task<()>>,
}

impl Connections {
    pub fn new(tunnel: Entity<Tunnel>, _: &mut Context<Self>) -> Self {
        Connections {
            rows: Vec::new(),
            total: 0,
            error: None,
            tunnel,
            demo: std::env::var_os("SBR_GUI_DEMO").is_some(),
            poll: None,
        }
    }

    pub fn connected(&self, cx: &App) -> bool {
        self.demo || self.tunnel.read(cx).status == Status::On
    }

    fn manager(&self, cx: &App) -> Option<Rc<Manager>> {
        let t = self.tunnel.read(cx);
        t.manager().filter(|_| t.status == Status::On)
    }

    /// Poll while `shown`; the extension wakes only for these messages.
    pub fn set_shown(&mut self, shown: bool, cx: &mut Context<Self>) {
        if !shown {
            self.poll = None;
            return;
        }
        if self.poll.is_some() {
            return;
        }
        if self.demo {
            self.rows = demo(&HashMap::new());
            self.total = self.rows.len() as u64;
        }
        self.poll = Some(cx.spawn(async move |this, cx| {
            let mut last = Instant::now();
            loop {
                let Ok((manager, demo)) = this.read_with(cx, |c, cx| (c.manager(cx), c.demo)) else {
                    return;
                };
                let snapshot = match (manager, demo) {
                    (_, true) => None,
                    (Some(m), _) => m.send(&Request::Connections {}).await.ok().and_then(|r| r.connections),
                    (None, _) => None,
                };
                let now = Instant::now();
                let dt = now.duration_since(last).as_secs_f64().max(0.001);
                last = now;
                let alive = this.update(cx, |c, cx| {
                    match snapshot {
                        Some(s) => {
                            c.rows = rates(&c.rows, s.connections, dt, now);
                            c.total = s.total;
                        }
                        None if c.demo => {
                            let previous = c.rows.iter().map(|l| (l.connection.id.clone(), l.clone())).collect();
                            c.rows = demo(&previous);
                        }
                        None => {
                            c.rows.clear();
                            c.total = 0;
                        }
                    }
                    cx.notify();
                });
                if alive.is_err() {
                    return;
                }
                cx.background_executor().timer(POLL).await;
            }
        }));
    }

    pub fn close(&mut self, id: String, cx: &mut Context<Self>) {
        self.close_where(|c| c.id == id, cx);
    }

    /// Close every listed connection to `domain` and its subdomains.
    pub fn close_domain(&mut self, domain: &str, cx: &mut Context<Self>) {
        let suffix = format!(".{domain}");
        self.close_where(|c| c.domain.as_deref().is_some_and(|d| d == domain || d.ends_with(&suffix)), cx);
    }

    fn close_where(&mut self, matches: impl Fn(&Connection) -> bool, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .rows
            .iter()
            .filter(|l| matches(&l.connection))
            .map(|l| l.connection.id.clone())
            .collect();
        self.rows.retain(|l| !matches(&l.connection));
        cx.notify();
        let Some(m) = self.manager(cx) else {
            return;
        };
        cx.spawn(async move |this, cx| {
            for id in ids {
                if let Err(e) = m.send(&Request::CloseConnection { id }).await {
                    let _ = this.update(cx, |c, cx| {
                        c.error = Some(e);
                        cx.notify();
                    });
                    return;
                }
            }
        })
        .detach();
    }

    pub fn dismiss_error(&mut self, cx: &mut Context<Self>) {
        self.error = None;
        cx.notify();
    }
}

/// `next` with each connection's rate since the last poll. Rows sort by
/// when bytes last moved, newest first, then by start.
fn rates(previous: &[Live], next: Vec<Connection>, dt: f64, now: Instant) -> Vec<Live> {
    let before: HashMap<&str, &Live> = previous.iter().map(|l| (l.connection.id.as_str(), l)).collect();
    let mut rows: Vec<Live> = next
        .into_iter()
        .map(|c| match before.get(c.id.as_str()) {
            None => Live {
                connection: c,
                up: 0.0,
                down: 0.0,
                last_active: now,
            },
            Some(p) => {
                let up = c.upload.saturating_sub(p.connection.upload);
                let down = c.download.saturating_sub(p.connection.download);
                Live {
                    up: up as f64 / dt,
                    down: down as f64 / dt,
                    last_active: if up + down > 0 { now } else { p.last_active },
                    connection: c,
                }
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        (b.last_active, b.connection.start).cmp(&(a.last_active, a.connection.start))
    });
    rows
}

/// Made-up connections for `SBR_GUI_DEMO`, moving from `previous`.
fn demo(previous: &HashMap<String, Live>) -> Vec<Live> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    let t = now_ms / 250;
    let hosts = [
        ("www.youtube.com", "tcp", Some("tls"), ["hk-01", "auto", "proxy"].as_slice(), "domain_suffix=youtube.com", 2_400_000.0),
        ("api.github.com", "tcp", Some("tls"), ["jp-02", "proxy"].as_slice(), "final", 18_000.0),
        ("dns.google", "udp", Some("dns"), ["direct"].as_slice(), "protocol=dns", 900.0),
        ("fonts.gstatic.com", "tcp", Some("tls"), ["hk-01", "auto", "proxy"].as_slice(), "final", 0.0),
        ("17.253.144.10", "udp", Some("quic"), ["direct"].as_slice(), "ip_is_private=false", 64_000.0),
        ("news.ycombinator.com", "tcp", Some("http"), ["sg-01", "proxy"].as_slice(), "final", 3_000.0),
    ];
    let now = Instant::now();
    hosts
        .iter()
        .enumerate()
        .map(|(i, (host, network, sniffed, chain, rule, rate))| {
            let id = format!("demo-{i}");
            let wave = ((t as f64 / (5.0 + i as f64)).sin() * 0.5 + 0.5).powi(2);
            let down = rate * wave;
            let up = down * 0.08;
            let p = previous.get(&id);
            let (upload, download) = p.map_or((4_000 * i as u64, 90_000 * i as u64), |p| {
                (
                    p.connection.upload + (up * 0.25) as u64,
                    p.connection.download + (down * 0.25) as u64,
                )
            });
            let ip = host.parse::<std::net::IpAddr>().is_ok();
            Live {
                connection: Connection {
                    id,
                    network: (*network).into(),
                    inbound: "tun-in".into(),
                    source: format!("172.19.0.1:{}", 52_000 + i),
                    destination: format!("{host}:443"),
                    domain: (!ip).then(|| (*host).into()),
                    ip: ip.then(|| (*host).into()),
                    sniffed: sniffed.map(Into::into),
                    chain: chain.iter().map(|s| (*s).into()).collect(),
                    rule: (*rule).into(),
                    upload,
                    download,
                    start: now_ms - 1000 * (30 + 400 * i as i64),
                },
                up,
                down,
                last_active: if down > 0.0 { now } else { p.map_or(now, |p| p.last_active) },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(id: &str, up: u64, down: u64, start: i64) -> Connection {
        Connection {
            id: id.into(),
            network: "tcp".into(),
            inbound: "tun".into(),
            source: String::new(),
            destination: String::new(),
            domain: None,
            ip: None,
            sniffed: None,
            chain: Vec::new(),
            rule: String::new(),
            upload: up,
            download: down,
            start,
        }
    }

    #[test]
    fn rates_follow_bytes_and_activity_sorts() {
        let t0 = Instant::now();
        let first = rates(&[], vec![conn("a", 0, 0, 1), conn("b", 0, 0, 2)], 0.25, t0);
        assert!(first.iter().all(|l| l.up == 0.0 && l.down == 0.0));
        let t1 = t0 + Duration::from_millis(250);
        let next = rates(&first, vec![conn("a", 100, 1000, 1), conn("b", 0, 0, 2)], 0.25, t1);
        assert_eq!(next[0].connection.id, "a");
        assert_eq!(next[0].down, 4000.0);
        assert_eq!(next[0].up, 400.0);
        assert_eq!(next[1].last_active, t0);
    }
}
