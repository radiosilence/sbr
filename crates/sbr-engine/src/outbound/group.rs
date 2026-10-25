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

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use sbr_core::{BoxFuture, BoxPacketConn, Destination, Group, Outbound, Stream};
use tokio::sync::watch;
use tracing::{debug, info};

use super::Upstream;
use crate::cache::CacheFile;
use crate::fetch::{HttpClient, Url, elapsed_ms};
use crate::track::Tracker;

/// sing-box defaults.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(180);
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);
const DEFAULT_TOLERANCE: u16 = 50;
const CONCURRENCY: usize = 10;

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
        for g in self.urltests() {
            g.post_start();
        }
    }

    /// Stop every probe loop.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Measure one outbound and record it under its real (leaf) tag.
    /// `url` overrides the URL-less handshake measurement.
    pub async fn probe(&self, o: &Arc<dyn Outbound>, url: Option<&Url>) -> io::Result<u16> {
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

    /// Re-evaluate every urltest group that contains `tag` (after a manual probe).
    pub fn recheck_containing(&self, tag: &str) {
        for g in self.urltests() {
            if contains(g.as_ref(), tag, &mut HashSet::new()) {
                g.perform_update_check();
            }
        }
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
        // Resuming after a long idle: the history is stale, check now.
        if self.idle_for() > self.interval {
            self.last_active.store(self.now_ms(), Ordering::Relaxed);
            self.url_test(false).await;
        }
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {}
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
    fn select(&self) -> (usize, bool) {
        let mut best: Option<(usize, u16)> = None;
        let cur = self.selected.load(Ordering::Relaxed);
        if cur != usize::MAX
            && let Some(h) = self.env.history(&real_tag(self.members[cur].as_ref()))
        {
            best = Some((cur, h.delay));
        }
        for (i, m) in self.members.iter().enumerate() {
            let Some(h) = self.env.history(&real_tag(m.as_ref())) else {
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

    pub fn perform_update_check(&self) {
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
            }
        }
    }

    /// Probe all members (recursing into groups) and re-select.
    /// `force` re-probes members whose history is still fresh.
    pub fn url_test(&self, force: bool) -> BoxFuture<'_, HashMap<String, u16>> {
        Box::pin(async move {
            // sing-box returns an empty result when a check is already running;
            // waiting for it instead means a parent group testing this one
            // sees its results (fresh members are then skipped, so it's cheap).
            let _running = self.checking.lock().await;
            let r = test_outbounds(&self.env, &self.members, self.url.as_ref(), self.interval, force).await;
            self.perform_update_check();
            r
        })
    }
}

/// sing-box `URLTestOutbounds`.
pub async fn test_outbounds(
    env: &GroupEnv,
    outbounds: &[Arc<dyn Outbound>],
    url: Option<&Url>,
    interval: Duration,
    force: bool,
) -> HashMap<String, u16> {
    let mut seen = HashSet::new();
    let mut groups = Vec::new();
    let mut leaves = Vec::new();
    let mut nested = Vec::new();
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
            let fresh = env
                .history(o.tag())
                .is_some_and(|h| h.time.elapsed().is_ok_and(|e| e < interval));
            if force || !fresh {
                leaves.push(o);
            }
        }
    }
    let sem = tokio::sync::Semaphore::new(CONCURRENCY);
    let leaf_results = futures_util::future::join_all(leaves.iter().map(|o| async {
        let _p = sem.acquire().await;
        (o.tag().to_owned(), env.probe(o, url).await)
    }));
    let nested_results = futures_util::future::join_all(nested.iter().map(|g| g.url_test(force)));
    let (leaf_results, nested_results) = tokio::join!(leaf_results, nested_results);
    let mut out: HashMap<String, u16> = leaf_results
        .into_iter()
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
            let r = member.connect(dest).await;
            if r.is_err() {
                // sing-box drops the member's history so the next check re-probes it.
                self.env.forget(member.tag());
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
