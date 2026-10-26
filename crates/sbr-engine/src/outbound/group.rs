//! `selector` and `urltest` (sing-box `protocol/group`).
//!
//! `urltest` probing differs from sing-box in one deliberate way: without a
//! `url` it does **not** fall back to `https://www.gstatic.com/generate_204`
//! (sbr never contacts third parties unless the config says so). Instead it
//! measures the TCP handshake to each member's own server, through the
//! member's dialer/detour (QUIC protocols report their connection's RTT
//! instead, via `Outbound::probe_rtt`). That ranks servers by network distance but does
//! not prove the proxy protocol works end to end; set `url` to a URL you
//! control for that. Members without a server (`direct`, `block`) are not
//! measured in that mode and are only chosen when nothing else answers.
//!
//! On top of delay, sbr tracks whether each member actually carries data
//! (`crate::health`): members that freeze, reset or black-hole traffic after
//! their handshake are skipped for a back-off period, and the group switches
//! as soon as that is detected instead of at its next interval. Each
//! successful probe is followed by a data probe through the member: a GET of
//! `url`, or with no `url`, a fetch from the member's own server through the
//! member itself.
//!
//! Probing is shaped so it does not stand out on the wire. sing-box probes
//! every member at once, on a fixed period: at start that is one TLS
//! handshake per member to the same server within milliseconds, each with a
//! different SNI, which no browser does and which Russia's 2026 rules count
//! (more than three parallel handshakes to one endpoint). sbr probes members
//! that share a server address one after another with a random gap, servers
//! in parallel, adopts the first member that answers instead of waiting for
//! all of them, and varies each period by up to [`JITTER`] either way.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use sbr_core::{BoxFuture, BoxPacketConn, Destination, Group, Outbound, Stream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::Upstream;
use crate::cache::CacheFile;
use crate::fetch::{HttpClient, Target, Url, elapsed_ms};
use crate::health::{self, Change, Degraded, Finish, Health, Record, Signal, Verdict};
use crate::track::{Conn, Tracker};

/// sing-box defaults.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(180);
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);
const DEFAULT_TOLERANCE: u16 = 50;
const CONCURRENCY: usize = 10;
/// Probe periods vary by this fraction either way.
pub const JITTER: f64 = 0.2;
/// Gap between probes of members on one server address.
pub const PROBE_GAP: std::ops::Range<u64> = 200..1200;

/// `interval`, varied by up to [`JITTER`] either way.
fn jittered(interval: Duration) -> Duration {
    interval.mul_f64(1.0 - JITTER + 2.0 * JITTER * fastrand::f64())
}

/// sing-box `adapter.URLTestHistory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delay {
    pub time: SystemTime,
    pub delay: u16,
}

/// What groups share: the connection registry, the cache file, delay history.
pub struct GroupEnv {
    pub tracker: Arc<Tracker>,
    pub cache: Option<Arc<CacheFile>>,
    pub http: HttpClient,
    history: Mutex<HashMap<String, Delay>>,
    /// How to reach each leaf's own server, for URL-less probing.
    pub(crate) servers: OnceLock<HashMap<String, (Upstream, Destination)>>,
    pub(crate) urltests: OnceLock<HashMap<String, Arc<UrlTest>>>,
    /// Every built outbound, so a leaf can be probed by tag. Weak: groups
    /// hold this environment.
    pub(crate) outbounds: OnceLock<HashMap<String, Weak<dyn Outbound>>>,
    /// What a data probe through each leaf fetches when no `url` applies:
    /// the leaf's own server, reached through the leaf.
    pub(crate) targets: OnceLock<HashMap<String, Destination>>,
    pub health: Health,
    handle: OnceLock<tokio::runtime::Handle>,
    shutdown: watch::Sender<bool>,
}

/// A standalone environment (own registry, no cache file), for outbounds
/// built outside the engine (e.g. DNS server dialers).
impl Default for GroupEnv {
    fn default() -> Self {
        Self::new(Arc::default(), None, HttpClient::new(None))
    }
}

impl GroupEnv {
    pub fn new(tracker: Arc<Tracker>, cache: Option<Arc<CacheFile>>, http: HttpClient) -> Self {
        Self {
            tracker,
            cache,
            http,
            history: Mutex::default(),
            servers: OnceLock::new(),
            urltests: OnceLock::new(),
            outbounds: OnceLock::new(),
            targets: OnceLock::new(),
            health: Health::default(),
            handle: OnceLock::new(),
            shutdown: watch::channel(false).0,
        }
    }

    pub fn history(&self, tag: &str) -> Option<Delay> {
        self.history.lock().unwrap().get(tag).copied()
    }

    fn store(&self, tag: &str, delay: u16) {
        self.history.lock().unwrap().insert(
            tag.to_owned(),
            Delay {
                time: SystemTime::now(),
                delay,
            },
        );
    }

    fn forget(&self, tag: &str) {
        self.history.lock().unwrap().remove(tag);
    }

    pub fn urltest(&self, tag: &str) -> Option<&Arc<UrlTest>> {
        self.urltests.get()?.get(tag)
    }

    pub fn urltests(&self) -> impl Iterator<Item = &Arc<UrlTest>> {
        self.urltests.get().into_iter().flat_map(|m| m.values())
    }

    /// Start background probing (sing-box `PostStart`).
    pub fn start(&self) {
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let _ = self.handle.set(h);
        }
        for g in self.urltests() {
            g.post_start();
        }
    }

    /// Stop every probe loop.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Measure one outbound and record it under its real (leaf) tag.
    /// `url` overrides the URL-less handshake measurement. A successful
    /// measurement starts a data probe in the background.
    pub async fn probe(self: &Arc<Self>, o: &Arc<dyn Outbound>, url: Option<&Url>) -> io::Result<u16> {
        let r = self.measure(o, url).await;
        if r.is_ok() {
            let (env, leaf, url) = (self.clone(), real_leaf(o), url.cloned());
            self.spawn(async move { env.check(leaf, url, false).await });
        }
        r
    }

    async fn measure(&self, o: &Arc<dyn Outbound>, url: Option<&Url>) -> io::Result<u16> {
        let tag = real_tag(o.as_ref());
        let r = match url {
            Some(u) => self.http.probe(o.as_ref(), u).await,
            None => {
                let leaf = real_leaf(o);
                match leaf.probe_rtt() {
                    Some(rtt) => tokio::time::timeout(crate::fetch::TIMEOUT, rtt)
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "probe timed out"))?
                        .map(|d| d.as_millis().clamp(1, u16::MAX as u128) as u16),
                    None => self.handshake(leaf.tag()).await,
                }
            }
        };
        match &r {
            Ok(d) => {
                debug!(outbound = %tag, delay = d, "available");
                self.store(&tag, *d);
            }
            Err(e) => {
                debug!(outbound = %tag, error = %e, "unavailable");
                self.forget(&tag);
            }
        }
        r
    }

    async fn handshake(&self, tag: &str) -> io::Result<u16> {
        let (up, server) = self
            .servers
            .get()
            .and_then(|m| m.get(tag))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "no server to measure; set url"))?;
        let start = Instant::now();
        let s = tokio::time::timeout(crate::fetch::TIMEOUT, up.connect(server))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))??;
        let d = elapsed_ms(start);
        drop(s);
        Ok(d)
    }

    /// Re-evaluate every urltest group that contains `tag`. Repeats while
    /// anything switches, so an outer group sees its inner groups' new picks.
    pub fn recheck_containing(&self, tag: &str) {
        let groups = self.containing(tag);
        for _ in 0..groups.len() {
            if !groups.iter().fold(false, |any, g| g.perform_update_check() | any) {
                break;
            }
        }
    }

    fn containing(&self, tag: &str) -> Vec<&Arc<UrlTest>> {
        self.urltests()
            .filter(|g| contains(g.as_ref(), tag, &mut HashSet::new()))
            .collect()
    }

    fn spawn(&self, f: impl Future<Output = ()> + Send + 'static) {
        if let Some(h) = self
            .handle
            .get()
            .cloned()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
        {
            h.spawn(f);
        }
    }

    fn leaf(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get()?.get(tag)?.upgrade()
    }

    /// Why `tag` (a leaf) is out of selection, if it is.
    pub fn degraded(&self, tag: &str) -> Option<Degraded> {
        self.health.degraded(tag)
    }

    /// A passive signal from a connection carried by `leaf`.
    pub(crate) fn report(self: &Arc<Self>, leaf: &str, signal: Signal, dest: &Destination, conn: Option<u64>) {
        let carrying = signal == Signal::Closed && self.tracker.carrying(leaf, conn);
        let (out, suspects) = self.health.with(leaf, |r| {
            let now = Instant::now();
            if carrying {
                r.carrying(now);
            }
            let out = r.report(now, signal, &dest.to_string(), conn);
            let suspects = out.confirm.then(|| r.suspects().join(", "));
            (out, suspects)
        });
        debug!(outbound = leaf, signal = signal.as_str(), %dest, ignored = out.ignored, "suspect connection");
        if let Some(dests) = suspects {
            debug!(outbound = leaf, %dests, "closed before any data from several destinations; confirming with a probe");
            match self.leaf(leaf) {
                Some(o) => {
                    let url = self.containing(leaf).iter().find_map(|g| g.url.clone());
                    let env = self.clone();
                    self.spawn(async move {
                        if env.measure(&o, url.as_ref()).await.is_ok() {
                            env.check(o, url, true).await;
                        } else {
                            env.probed(o.tag(), Verdict::Unreachable);
                        }
                    });
                }
                None => self.probed(leaf, Verdict::Inconclusive),
            }
        }
        if out.degraded {
            self.on_degraded(leaf);
        }
        if out.probe {
            match self.leaf(leaf) {
                Some(o) => {
                    let url = self.containing(leaf).iter().find_map(|g| g.url.clone());
                    let env = self.clone();
                    self.spawn(async move { env.check(o, url, true).await });
                }
                None => self.probed(leaf, Verdict::Inconclusive),
            }
        }
    }

    /// A stalled connection on `leaf` started receiving again.
    pub(crate) fn retract(&self, leaf: &str, conn: u64) {
        self.health.with(leaf, |r| r.retract(conn));
    }

    /// A relay on `leaf` ended.
    pub(crate) fn finished(self: &Arc<Self>, leaf: &str, conn: &Conn, dest: &Destination) {
        match health::finish(conn) {
            Some(Finish::Proven) => self.health.with(leaf, |r| r.success(Instant::now())),
            Some(Finish::Failed(s)) => self.report(leaf, s, dest, Some(conn.id)),
            None => {}
        }
    }

    /// Data-probe `leaf`. `claimed`: the caller already holds the record's
    /// probe slot. Dropping the future mid-probe releases the slot.
    async fn check(self: &Arc<Self>, leaf: Arc<dyn Outbound>, url: Option<Url>, claimed: bool) {
        let tag = leaf.tag().to_owned();
        let target = match url {
            Some(u) => Some(Target::Url(u)),
            None => self
                .targets
                .get()
                .and_then(|m| m.get(&tag))
                .cloned()
                .map(Target::Server),
        };
        if !claimed && !self.health.with(&tag, Record::begin_probe) {
            return;
        }
        let Some(target) = target else {
            self.probed(&tag, Verdict::Inconclusive);
            return;
        };
        debug!(outbound = %tag, ?target, "data probe started");
        let slot = ProbeSlot {
            health: &self.health,
            tag: &tag,
        };
        let v = self.http.data_probe(leaf.as_ref(), &target).await;
        std::mem::forget(slot);
        debug!(outbound = %tag, verdict = ?v, "data probe");
        self.probed(&tag, v);
    }

    fn probed(self: &Arc<Self>, tag: &str, v: Verdict) {
        match self.health.with(tag, |r| r.probe_done(Instant::now(), v)) {
            Change::Degraded => self.on_degraded(tag),
            Change::Readmitted => {
                info!(outbound = tag, "outbound readmitted");
                self.recheck_containing(tag);
            }
            Change::None => {}
        }
    }

    fn on_degraded(self: &Arc<Self>, tag: &str) {
        let Some(d) = self.health.degraded(tag) else { return };
        let closed = self.tracker.close_broken(tag);
        warn!(
            outbound = tag,
            reason = d.reason.as_str(),
            retry_in = ?d.until.saturating_duration_since(Instant::now()),
            closed,
            "outbound degraded"
        );
        self.recheck_containing(tag);
        // One deadline per demotion, not a polling timer.
        let env = self.clone();
        let tag = tag.to_owned();
        let mut stop = self.shutdown.subscribe();
        self.spawn(async move {
            let due = tokio::select! {
                _ = tokio::time::sleep_until(d.until.into()) => true,
                _ = stop.wait_for(|s| *s) => false,
            };
            if due {
                env.retry(&tag).await;
            }
        });
    }

    /// The back-off for `tag` ran out: probe it again, unless every group
    /// it belongs to is idle (they re-probe due members when next used).
    async fn retry(self: &Arc<Self>, tag: &str) {
        let (idle, url) = {
            let groups = self.containing(tag);
            (
                !groups.is_empty() && !groups.iter().any(|g| g.probing()),
                groups.iter().find_map(|g| g.url.clone()),
            )
        };
        if idle {
            return;
        }
        let Some(o) = self.leaf(tag) else { return };
        if self.measure(&o, url.as_ref()).await.is_ok() {
            self.check(o, url, false).await;
        }
    }

    /// See `Engine::network_changed`.
    pub fn network_changed(&self) {
        self.health.clear();
        for g in self.urltests() {
            g.network_changed();
        }
    }
}

/// Frees a leaf's probe slot if a data probe is dropped before it finishes
/// (a Clash API delay test that timed out).
struct ProbeSlot<'a> {
    health: &'a Health,
    tag: &'a str,
}

impl Drop for ProbeSlot<'_> {
    fn drop(&mut self) {
        self.health.with(self.tag, Record::abort_probe);
    }
}

fn contains(g: &dyn Outbound, tag: &str, seen: &mut HashSet<String>) -> bool {
    let Some(group) = g.as_group() else { return false };
    for m in group.members() {
        if m.tag() == tag || real_tag(m.as_ref()) == tag {
            return true;
        }
        if m.as_group().is_some() && seen.insert(m.tag().to_owned()) && contains(m.as_ref(), tag, seen) {
            return true;
        }
    }
    false
}

/// sing-box `group.RealTag`: the leaf a group currently uses.
pub fn real_tag(o: &dyn Outbound) -> String {
    let mut cur = match o.as_group() {
        Some(g) => g.selected(),
        None => return o.tag().to_owned(),
    };
    for _ in 0..32 {
        let next = match cur.as_group() {
            Some(g) => g.selected(),
            None => break,
        };
        cur = next;
    }
    cur.tag().to_owned()
}

fn real_leaf(o: &Arc<dyn Outbound>) -> Arc<dyn Outbound> {
    let mut cur = o.clone();
    for _ in 0..32 {
        let next = match cur.as_group() {
            Some(g) => g.selected(),
            None => break,
        };
        cur = next;
    }
    cur
}

// ---------------------------------------------------------------------------

pub struct Selector {
    tag: String,
    members: Vec<Arc<dyn Outbound>>,
    selected: AtomicUsize,
    interrupt: bool,
    env: Arc<GroupEnv>,
}

impl Selector {
    /// The cached choice wins over `default`, like sing-box.
    pub fn new(
        tag: String,
        members: Vec<Arc<dyn Outbound>>,
        default: Option<&str>,
        interrupt: bool,
        env: Arc<GroupEnv>,
    ) -> Self {
        let cached = env.cache.as_ref().and_then(|c| c.load_selected(&tag));
        let selected = cached
            .as_deref()
            .and_then(|d| members.iter().position(|m| m.tag() == d))
            .or_else(|| default.and_then(|d| members.iter().position(|m| m.tag() == d)))
            .unwrap_or(0);
        Self {
            tag,
            members,
            selected: AtomicUsize::new(selected),
            interrupt,
            env,
        }
    }

    fn current(&self) -> Arc<dyn Outbound> {
        self.members[self.selected.load(Ordering::Relaxed)].clone()
    }
}

impl Group for Selector {
    fn members(&self) -> Vec<Arc<dyn Outbound>> {
        self.members.clone()
    }
    fn selected(&self) -> Arc<dyn Outbound> {
        self.current()
    }
    fn select(&self, tag: &str) -> bool {
        let Some(i) = self.members.iter().position(|m| m.tag() == tag) else {
            return false;
        };
        if self.selected.swap(i, Ordering::Relaxed) == i {
            return true;
        }
        if let Some(c) = &self.env.cache {
            c.store_selected(&self.tag, tag);
        }
        if self.interrupt {
            let n = self.env.tracker.close_through(&self.tag);
            debug!(group = %self.tag, closed = n, "interrupted existing connections");
        }
        true
    }
}

impl Outbound for Selector {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "selector"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        let member = self.current();
        Box::pin(async move { member.connect(dest).await })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        let member = self.current();
        Box::pin(async move { member.connect_udp(dest).await })
    }
    fn as_group(&self) -> Option<&dyn Group> {
        Some(self)
    }
}

// ---------------------------------------------------------------------------

pub struct UrlTest {
    tag: String,
    members: Vec<Arc<dyn Outbound>>,
    url: Option<Url>,
    interval: Duration,
    tolerance: u16,
    idle_timeout: Duration,
    interrupt: bool,
    env: Arc<GroupEnv>,
    me: Weak<UrlTest>,
    /// `usize::MAX` until the first check picks something.
    selected: AtomicUsize,
    started: AtomicBool,
    looping: AtomicBool,
    checking: tokio::sync::Mutex<()>,
    update: Mutex<()>,
    epoch: Instant,
    /// Milliseconds since `epoch`.
    last_active: AtomicU64,
}

impl UrlTest {
    pub fn new(
        tag: String,
        members: Vec<Arc<dyn Outbound>>,
        cfg: &sbr_config::UrlTest,
        env: Arc<GroupEnv>,
    ) -> Result<Arc<Self>, String> {
        let interval = cfg.interval.filter(|d| !d.is_zero()).unwrap_or(DEFAULT_INTERVAL);
        let idle_timeout = cfg
            .idle_timeout
            .filter(|d| !d.is_zero())
            .unwrap_or(DEFAULT_IDLE_TIMEOUT);
        if interval > idle_timeout {
            return Err("interval must be less or equal than idle_timeout".into());
        }
        let url = match &cfg.url {
            Some(u) => Some(Url::parse(u).ok_or_else(|| format!("invalid url {u:?}"))?),
            None => None,
        };
        Ok(Arc::new_cyclic(|me| Self {
            tag,
            members,
            url,
            interval,
            tolerance: if cfg.tolerance == 0 {
                DEFAULT_TOLERANCE
            } else {
                cfg.tolerance
            },
            idle_timeout,
            interrupt: cfg.interrupt_exist_connections,
            env,
            me: me.clone(),
            selected: AtomicUsize::new(usize::MAX),
            started: AtomicBool::new(false),
            looping: AtomicBool::new(false),
            checking: tokio::sync::Mutex::new(()),
            update: Mutex::new(()),
            epoch: Instant::now(),
            last_active: AtomicU64::new(0),
        }))
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn idle_for(&self) -> Duration {
        Duration::from_millis(self.now_ms().saturating_sub(self.last_active.load(Ordering::Relaxed)))
    }

    fn current(&self) -> Arc<dyn Outbound> {
        match self.selected.load(Ordering::Relaxed) {
            usize::MAX => self.members[self.select().0].clone(),
            i => self.members[i].clone(),
        }
    }

    /// Whether the background probe loop is running (false while idle).
    pub fn probing(&self) -> bool {
        self.looping.load(Ordering::Acquire)
    }

    fn post_start(&self) {
        self.started.store(true, Ordering::Relaxed);
        self.last_active.store(self.now_ms(), Ordering::Relaxed);
        if let Some(me) = self.me.upgrade() {
            tokio::spawn(async move { me.url_test(false).await });
        }
    }

    /// Called on every use. Starts the probe loop if it went idle. While the
    /// group is unused the loop is gone: no timers, no wakeups.
    fn touch(&self) {
        if !self.started.load(Ordering::Relaxed) {
            return;
        }
        if self.looping.swap(true, Ordering::AcqRel) {
            self.last_active.store(self.now_ms(), Ordering::Relaxed);
            return;
        }
        let Some(me) = self.me.upgrade() else { return };
        tokio::spawn(me.probe_loop());
    }

    async fn probe_loop(self: Arc<Self>) {
        let mut stop = self.env.shutdown.subscribe();
        // Resuming after a long idle (the history is stale), or with members
        // whose back-off ran out while the group was idle: check now.
        if self.idle_for() > self.interval || self.members_due() {
            self.last_active.store(self.now_ms(), Ordering::Relaxed);
            self.url_test(false).await;
        }
        loop {
            tokio::select! {
                _ = tokio::time::sleep(jittered(self.interval)) => {}
                _ = stop.wait_for(|s| *s) => return,
            }
            if self.idle_for() > self.idle_timeout {
                debug!(group = %self.tag, "idle, pausing probes");
                self.looping.store(false, Ordering::Release);
                return;
            }
            self.url_test(false).await;
        }
    }

    /// sing-box `Select`: keep the current member unless another beats it by
    /// more than `tolerance`. Returns (index, measured).
    /// Degraded members are skipped while any healthy member has answered.
    fn select(&self) -> (usize, bool) {
        let state: Vec<(Option<Delay>, bool)> = self
            .members
            .iter()
            .map(|m| {
                let t = real_tag(m.as_ref());
                (self.env.history(&t), self.env.health.degraded(&t).is_some())
            })
            .collect();
        let skip_degraded = state.iter().any(|(h, d)| h.is_some() && !d);
        let usable = |i: usize| match state[i] {
            (Some(h), degraded) if !(skip_degraded && degraded) => Some(h),
            _ => None,
        };
        let mut best: Option<(usize, u16)> = None;
        let cur = self.selected.load(Ordering::Relaxed);
        if cur != usize::MAX
            && let Some(h) = usable(cur)
        {
            best = Some((cur, h.delay));
        }
        for i in 0..self.members.len() {
            let Some(h) = usable(i) else {
                continue;
            };
            if best.is_none_or(|(_, d)| d > h.delay.saturating_add(self.tolerance)) {
                best = Some((i, h.delay));
            }
        }
        match best {
            Some((i, _)) => (i, true),
            None => (0, false),
        }
    }

    /// Re-select; true if the group switched.
    pub fn perform_update_check(&self) -> bool {
        let _g = self.update.lock().unwrap();
        let (i, measured) = self.select();
        let cur = self.selected.load(Ordering::Relaxed);
        if cur == usize::MAX || (measured && i != cur) {
            self.selected.store(i, Ordering::Relaxed);
            if cur != usize::MAX {
                info!(group = %self.tag, outbound = self.members[i].tag(), "urltest switched");
                if self.interrupt {
                    self.env.tracker.close_through(&self.tag);
                }
                return true;
            }
        }
        false
    }

    fn network_changed(&self) {
        if !self.started.load(Ordering::Relaxed) {
            return;
        }
        if self.probing() {
            if let Some(me) = self.me.upgrade() {
                self.env.spawn(async move {
                    me.url_test(true).await;
                });
            }
        } else {
            // Stale: the next use re-probes before anything else.
            self.last_active.store(0, Ordering::Relaxed);
        }
    }

    fn members_due(&self) -> bool {
        let now = Instant::now();
        self.members.iter().any(|m| self.env.health.due(m.tag(), now))
    }

    /// Probe all members (recursing into groups) and re-select.
    /// `force` re-probes members whose history is still fresh.
    pub fn url_test(&self, force: bool) -> BoxFuture<'_, HashMap<String, u16>> {
        Box::pin(async move {
            // sing-box returns an empty result when a check is already running;
            // waiting for it instead means a parent group testing this one
            // sees its results (fresh members are then skipped, so it's cheap).
            let _running = self.checking.lock().await;
            // Before the group has picked anything, take the first member
            // that answers rather than waiting for the slowest.
            let first = || {
                if self.selected.load(Ordering::Relaxed) == usize::MAX {
                    self.perform_update_check();
                }
            };
            let r = test_outbounds(
                &self.env,
                &self.members,
                self.url.as_ref(),
                self.interval,
                force,
                &first,
            )
            .await;
            self.perform_update_check();
            r
        })
    }
}

/// sing-box `URLTestOutbounds`. `measured` runs after each member answers.
pub async fn test_outbounds(
    env: &Arc<GroupEnv>,
    outbounds: &[Arc<dyn Outbound>],
    url: Option<&Url>,
    interval: Duration,
    force: bool,
    measured: &(dyn Fn() + Sync),
) -> HashMap<String, u16> {
    let mut seen = HashSet::new();
    let mut groups = Vec::new();
    let mut leaves = Vec::new();
    let mut nested = Vec::new();
    let now = Instant::now();
    let mut stack: Vec<Arc<dyn Outbound>> = outbounds.iter().rev().cloned().collect();
    while let Some(o) = stack.pop() {
        if !seen.insert(o.tag().to_owned()) {
            continue;
        }
        if let Some(u) = env.urltest(o.tag()) {
            groups.push(o.clone());
            nested.push(u.clone());
        } else if let Some(g) = o.as_group() {
            groups.push(o.clone());
            stack.extend(g.members().into_iter().rev());
        } else {
            // Half the interval: a jittered period can be shorter than it.
            let fresh = env
                .history(o.tag())
                .is_some_and(|h| h.time.elapsed().is_ok_and(|e| e < interval / 2));
            if force || !fresh || env.health.due(o.tag(), now) {
                leaves.push(o);
            }
        }
    }
    // One queue per server address, in member order.
    let mut queues: Vec<(String, Vec<Arc<dyn Outbound>>)> = Vec::new();
    for o in leaves {
        let key = env
            .servers
            .get()
            .and_then(|m| m.get(o.tag()))
            .map_or_else(|| o.tag().to_owned(), |(_, d)| format!("{:?}", d.host));
        match queues.iter_mut().find(|(k, _)| *k == key) {
            Some((_, q)) => q.push(o),
            None => queues.push((key, vec![o])),
        }
    }
    let sem = tokio::sync::Semaphore::new(CONCURRENCY);
    let leaf_results = futures_util::future::join_all(queues.iter().map(|(_, q)| async {
        let _p = sem.acquire().await;
        let mut out = Vec::with_capacity(q.len());
        for (i, o) in q.iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(fastrand::u64(PROBE_GAP))).await;
            }
            // The data probe runs inside the check, so a group's check (and
            // its radio use) ends when the last probe does.
            let r = env.measure(o, url).await;
            if r.is_ok() {
                measured();
                env.check(real_leaf(o), url.cloned(), false).await;
            }
            out.push((o.tag().to_owned(), r));
        }
        out
    }));
    let nested_results = futures_util::future::join_all(nested.iter().map(|g| g.url_test(force)));
    let (leaf_results, nested_results) = tokio::join!(leaf_results, nested_results);
    let mut out: HashMap<String, u16> = leaf_results
        .into_iter()
        .flatten()
        .filter_map(|(t, r)| r.ok().map(|d| (t, d)))
        .collect();
    for r in nested_results {
        out.extend(r);
    }
    for g in groups {
        if let Some(h) = env.history(&real_tag(g.as_ref())) {
            out.insert(g.tag().to_owned(), h.delay);
        }
    }
    out
}

impl Group for UrlTest {
    fn members(&self) -> Vec<Arc<dyn Outbound>> {
        self.members.clone()
    }
    fn selected(&self) -> Arc<dyn Outbound> {
        self.current()
    }
    fn select(&self, _: &str) -> bool {
        false
    }
}

/// Forgets a member's delay history when dropped while still armed.
struct ForgetOnDrop<'a>(Option<(&'a GroupEnv, &'a str)>);

impl Drop for ForgetOnDrop<'_> {
    fn drop(&mut self) {
        if let Some((env, tag)) = self.0 {
            env.forget(tag);
        }
    }
}

impl Outbound for UrlTest {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "urltest"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        self.touch();
        let member = self.current();
        Box::pin(async move {
            // sing-box drops the member's history so the next check re-probes
            // it. A connect cut short by the caller's deadline counts too.
            let mut failed = ForgetOnDrop(Some((&self.env, member.tag())));
            let r = member.connect(dest).await;
            if r.is_ok() {
                failed.0 = None;
            }
            r
        })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        self.touch();
        let member = self.current();
        Box::pin(async move { member.connect_udp(dest).await })
    }
    fn as_group(&self) -> Option<&dyn Group> {
        Some(self)
    }
}
