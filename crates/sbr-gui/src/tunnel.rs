//! The tunnel as the app sees it: the VPN configuration's status, and while
//! it is connected, what the extension reports once a second (throughput,
//! memory, CPU and its groups), kept as a short history for the graphs.
//!
//! The extension only wakes for these messages, so polling stops whenever
//! the tunnel is down.

use std::collections::{BTreeSet, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use koan_kit::app::*;

use crate::ne::{self, Manager, Status};
use crate::proto::{Group, Request, Stats};

/// Seconds of history the graphs show.
pub const HISTORY: usize = 120;
const POLL: Duration = Duration::from_secs(1);

/// One poll's rates.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sample {
    /// Bytes a second.
    pub up: f64,
    pub down: f64,
    /// Share of one core, 0 to 1 and past it.
    pub cpu: f64,
    pub memory: u64,
    pub connections: u64,
}

/// Connects (true) or disconnects (false).
pub type SetOn = Rc<dyn Fn(bool, &mut App)>;

pub struct Tunnel {
    pub status: Status,
    pub stats: Option<Stats>,
    pub groups: Vec<Group>,
    /// Oldest first, at most `HISTORY`.
    pub history: VecDeque<Sample>,
    /// Groups whose latency test is running.
    pub testing: BTreeSet<String>,
    pub error: Option<String>,
    manager: Option<Rc<Manager>>,
    /// Connects and disconnects in place of `set_on`'s own handling, so the
    /// configuration can be installed first (`install::Vpn`).
    pub on_set_on: Option<SetOn>,
    demo: bool,
    _observer: Option<ne::Observer>,
    _tasks: Vec<Task<()>>,
}

impl Tunnel {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let demo = std::env::var_os("SBR_GUI_DEMO").is_some();
        let mut tunnel = Tunnel {
            status: Status::Invalid,
            stats: None,
            groups: Vec::new(),
            history: VecDeque::with_capacity(HISTORY),
            testing: BTreeSet::new(),
            error: None,
            manager: None,
            on_set_on: None,
            demo,
            _observer: None,
            _tasks: Vec::new(),
        };
        if demo {
            tunnel.status = Status::On;
            tunnel.groups = crate::demo::groups();
            tunnel.history = crate::demo::history().into();
        } else {
            tunnel._tasks.push(cx.spawn(async move |this, cx| {
                let Some(id) = ne::tunnel_bundle_id() else {
                    let _ = this.update(cx, |t, cx| {
                        t.error = Some("this build names no tunnel extension".into());
                        cx.notify();
                    });
                    return;
                };
                let loaded = Manager::load(&id).await;
                let _ = this.update(cx, |t, cx| {
                    match loaded {
                        Ok(Some(m)) => t.adopt(Rc::new(m), cx),
                        Ok(None) => {}
                        Err(e) => t.error = Some(e),
                    }
                    cx.notify();
                });
            }));
        }
        tunnel._tasks.push(cx.spawn(async move |this, cx| {
            let mut last: Option<(Stats, Instant)> = None;
            loop {
                cx.background_executor().timer(POLL).await;
                let Ok(next) = this.update(cx, |t, cx| t.poll(cx)) else {
                    return;
                };
                let Some(next) = next else {
                    last = None;
                    continue;
                };
                let (stats, groups) = next.await;
                let now = Instant::now();
                let _ = this.update(cx, |t, cx| {
                    if let Some(stats) = stats {
                        if let Some((prev, at)) = last {
                            let dt = now.duration_since(at).as_secs_f64().max(0.001);
                            t.push(Sample {
                                up: stats.uplink_bytes.wrapping_sub(prev.uplink_bytes) as f64 / dt,
                                down: stats.downlink_bytes.wrapping_sub(prev.downlink_bytes) as f64 / dt,
                                cpu: stats.cpu_time_micros.wrapping_sub(prev.cpu_time_micros) as f64 / 1e6 / dt,
                                memory: stats.memory_footprint,
                                connections: stats.active_connections,
                            });
                        }
                        last = Some((stats, now));
                        t.stats = Some(stats);
                    }
                    if let Some(groups) = groups {
                        t.groups = groups;
                    }
                    cx.notify();
                });
            }
        }));
        tunnel
    }

    pub fn manager(&self) -> Option<Rc<Manager>> {
        self.manager.clone()
    }

    /// The configuration was removed.
    pub fn forget(&mut self, cx: &mut Context<Self>) {
        self.manager = None;
        self._observer = None;
        self.status = Status::Invalid;
        self.groups.clear();
        self.stats = None;
        self.history.clear();
        cx.notify();
    }

    pub fn adopt(&mut self, m: Rc<Manager>, cx: &mut Context<Self>) {
        self.status = m.status();
        let (mut statuses, observer) = m.statuses();
        self._observer = Some(observer);
        self.manager = Some(m);
        self._tasks.push(cx.spawn(async move |this, cx| {
            while let Some(status) = statuses.next().await {
                let _ = this.update(cx, |t, cx| {
                    t.status = status;
                    if status != Status::On {
                        t.groups.clear();
                        t.stats = None;
                        t.history.clear();
                    }
                    cx.notify();
                });
            }
        }));
    }

    fn push(&mut self, sample: Sample) {
        if self.history.len() == HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(sample);
    }

    /// The next poll's requests, or none while the tunnel is down.
    #[allow(clippy::type_complexity)]
    fn poll(
        &mut self,
        _: &mut Context<Self>,
    ) -> Option<std::pin::Pin<Box<dyn Future<Output = (Option<Stats>, Option<Vec<Group>>)>>>> {
        if self.demo {
            let stats = crate::demo::stats(self.stats.as_ref());
            return Some(Box::pin(async move { (Some(stats), None) }));
        }
        if self.status != Status::On {
            return None;
        }
        let m = self.manager.clone()?;
        Some(Box::pin(async move {
            let stats = m.send(&Request::Stats {}).await.ok().and_then(|r| r.stats);
            let groups = m.send(&Request::Groups {}).await.ok().and_then(|r| r.groups);
            (stats, groups)
        }))
    }

    pub fn set_on(&mut self, on: bool, cx: &mut Context<Self>) {
        if self.demo {
            self.status = if on { Status::On } else { Status::Off };
            if !on {
                self.history.clear();
            }
            cx.notify();
            return;
        }
        if let Some(set_on) = self.on_set_on.clone() {
            set_on(on, cx);
            return;
        }
        let Some(m) = &self.manager else {
            self.error = Some("choose a profile first".into());
            cx.notify();
            return;
        };
        if on {
            if let Err(e) = m.start() {
                self.error = Some(e);
            }
        } else {
            m.stop();
        }
        cx.notify();
    }

    pub fn select(&mut self, group: String, member: String, cx: &mut Context<Self>) {
        if self.demo {
            if let Some(g) = self.groups.iter_mut().find(|g| g.tag == group) {
                g.selected = member.clone();
                g.now = member;
            }
            cx.notify();
            return;
        }
        let Some(m) = self.manager.clone() else { return };
        cx.spawn(async move |this, cx| {
            let r = m.send(&Request::Select { group, member }).await;
            let _ = this.update(cx, |t, cx| {
                match r {
                    Ok(r) => t.groups = r.groups.unwrap_or_default(),
                    Err(e) => t.error = Some(e),
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Latency-test a group. The results arrive by polling; the test counts
    /// as running until the group's numbers change or a few seconds pass.
    pub fn url_test(&mut self, group: String, cx: &mut Context<Self>) {
        if !self.testing.insert(group.clone()) {
            return;
        }
        cx.notify();
        let manager = self.manager.clone();
        let before = self.groups.iter().find(|g| g.tag == group).cloned();
        cx.spawn(async move |this, cx| {
            if let Some(m) = &manager {
                let _ = m.send(&Request::UrlTest { group: group.clone() }).await;
            }
            for _ in 0..20 {
                cx.background_executor().timer(Duration::from_millis(300)).await;
                let changed = this
                    .update(cx, |t, _| {
                        if t.demo {
                            crate::demo::test(&mut t.groups, &group);
                        }
                        t.groups.iter().find(|g| g.tag == group) != before.as_ref()
                    })
                    .unwrap_or(true);
                if changed {
                    break;
                }
            }
            let _ = this.update(cx, |t, cx| {
                t.testing.remove(&group);
                cx.notify();
            });
        })
        .detach();
    }

    pub fn dismiss_error(&mut self, cx: &mut Context<Self>) {
        self.error = None;
        cx.notify();
    }
}
