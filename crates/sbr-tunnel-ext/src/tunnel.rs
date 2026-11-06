//! The tunnel's behaviour, apart from the Objective-C class that NetworkExtension
//! instantiates (`lib.rs`), which forwards each callback here on a thread of
//! its own.
//!
//! Start-up: read the sing-box config (from the Keychain item named by
//! `providerConfiguration["stored"]`, else `providerConfiguration["config"]`,
//! or `config.json` in the App Group named by `providerConfiguration["appGroup"]`),
//! derive the network settings from its `tun` inbound, apply them, find the
//! utun fd NetworkExtension created and start sbr on it. Path changes and
//! wake-ups reset path-bound state; app messages expose groups, selection,
//! stats, connections and reload.
//!
//! With a remote profile, the tunnel refreshes it itself on its interval:
//! downloaded through its own outbounds, validated, then hot-reloaded. A
//! profile that fails validation leaves the running config untouched. The
//! last good download is kept (in the Keychain beside a stored profile, else
//! in the extension's directory), survives restarts, and is what the
//! `profile` request returns for the app to store.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use sbr_apple::api::{Applied, Sbr, StartOptions};
use sbr_message::{
    Connections, Date, Group, PersonalRule, ProfileSecret, ProfileSnapshot, RemoteProfile, Request, Response, Stats,
    StoredProfile,
};

use crate::logs::{self, Level};
use crate::provider::{Provider, ProviderConfig, StopReason};
use crate::rules;
use crate::store::{self, Keychain};
use crate::watch::{MemoryPressure, PathMonitor};

/// The app-chosen state that outlives one config: the remote profile being
/// refreshed, the log level override and the personal rules.
#[derive(Clone, Default)]
struct State {
    remote: Option<RemoteProfile>,
    log_level: Option<String>,
    rules: Vec<PersonalRule>,
}

pub struct Tunnel {
    provider: Provider,
    core: RwLock<Option<Arc<Sbr>>>,
    state: Mutex<State>,
    /// Bumped to cancel the pending refresh.
    refresh: (Mutex<u64>, Condvar),
    heartbeat: Mutex<Option<Arc<AtomicBool>>>,
    memory_pressure: Mutex<Option<MemoryPressure>>,
    path_monitor: Mutex<Option<PathMonitor>>,
    last_path: Mutex<Option<String>>,
    /// This start only erased (`start_option::ERASE`).
    erasing: AtomicBool,
}

const MB: f64 = 1_048_576.0;

impl Tunnel {
    pub fn new(provider: Provider) -> Self {
        Tunnel {
            provider,
            core: RwLock::new(None),
            state: Mutex::new(State::default()),
            refresh: (Mutex::new(0), Condvar::new()),
            heartbeat: Mutex::new(None),
            memory_pressure: Mutex::new(None),
            path_monitor: Mutex::new(None),
            last_path: Mutex::new(None),
            erasing: AtomicBool::new(false),
        }
    }

    fn core(&self) -> Option<Arc<Sbr>> {
        self.core.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn swap_core(&self, new: Option<Sbr>) -> Option<Arc<Sbr>> {
        std::mem::replace(
            &mut *self.core.write().unwrap_or_else(|e| e.into_inner()),
            new.map(Arc::new),
        )
    }

    fn state(&self) -> State {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_state(&self, s: State) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = s;
    }

    pub fn start(self: &Arc<Self>, erase: bool) -> Result<(), String> {
        logs::forward_core_logs();
        logs::tunnel().info(&format!("starting sbr {}", sbr_apple::api::version()));
        if erase {
            self.erasing.store(true, Ordering::SeqCst);
            self.erase();
            return Err("erased".into());
        }
        report_previous_session();
        self.start_inner().inspect_err(|e| {
            logs::tunnel().log(Level::Error, "start failed: ", e);
            logs::append(Level::Error, &format!("start failed: {e}"));
        })
    }

    fn start_inner(self: &Arc<Self>) -> Result<(), String> {
        let pc = self.provider.config();
        let saved = saved_state(&pc);
        let (text, remote) = self.newest(load_configuration(&pc)?, saved.remote, &pc);
        let state = State { remote, ..saved };
        let config = prepared(&text, state.log_level.as_deref(), &state.rules, pc.tun_stack.as_deref());
        self.set_state(state);
        self.provider.set_network_settings(&config)?;
        // The utun exists once the settings are applied.
        let fd = sbr_apple::api::find_tun_fd().ok_or("utun file descriptor not found")?;
        let base_dir = pc
            .app_group
            .as_deref()
            .and_then(store::app_group_dir)
            .or_else(|| store::private_dir().map(Into::into));
        let core = Sbr::start(
            &config,
            StartOptions {
                base_dir,
                tun_fd: Some(fd),
                ..StartOptions::default()
            },
        )?;
        self.swap_core(Some(core));
        self.start_path_monitor();
        self.schedule_refresh(None);
        self.start_heartbeat();
        logs::tunnel().info(&format!("tunnel up on fd {fd}"));
        Ok(())
    }

    pub fn stop(self: &Arc<Self>, reason: StopReason) {
        logs::tunnel().info(&format!("stopping (reason {})", reason.0));
        // An erase-only start: leave nothing behind in the wiped directory.
        if self.erasing.load(Ordering::SeqCst) {
            return;
        }
        self.stop_heartbeat();
        if let Some(path) = store::private_file(HEARTBEAT) {
            let _ = std::fs::remove_file(path);
        }
        // The system stopping us (rather than the user, sleep or an update)
        // reads as "plugin failed" in the app; keep the reason for next start.
        if !reason.is_expected() {
            let mb = self.core().map_or(0, |c| c.stats().memory_footprint) as f64 / MB;
            record_end(&format!(
                "stopped by the system: {} (reason {}) with {mb:.1} MB in use",
                reason.describe(),
                reason.0
            ));
        }
        *self.path_monitor.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.set_state(State::default());
        self.schedule_refresh(None);
        drop(self.swap_core(None));
    }

    pub fn handle_message(self: &Arc<Self>, data: &[u8]) -> Vec<u8> {
        let response = serde_json::from_slice::<Request>(data)
            .map_err(|e| e.to_string())
            .and_then(|r| self.handle(r))
            .unwrap_or_else(|error| Response {
                error: Some(error),
                ..Response::default()
            });
        serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec())
    }

    fn handle(self: &Arc<Self>, request: Request) -> Result<Response, String> {
        match request {
            Request::Logs {} => {
                return Ok(Response {
                    logs: Some(logs::snapshot()),
                    ..Response::default()
                });
            }
            Request::Profile {} => {
                let current = self.state().remote.map(|r| r.url);
                let profile = self
                    .load_snapshot(&self.provider.config())
                    .filter(|s| Some(&s.url) == current.as_ref());
                return Ok(Response {
                    profile,
                    ..Response::default()
                });
            }
            Request::Erase {} => {
                self.erase();
                return Ok(Response::default());
            }
            _ => {}
        }
        let core = self.core().ok_or("sbr is not running")?;
        let groups = |core: &Sbr| Response {
            groups: Some(groups(core)),
            ..Response::default()
        };
        Ok(match request {
            Request::Groups {} => groups(&core),
            Request::Select { group, member } => {
                if !core.select(&group, &member) {
                    return Err(format!("no member {member} in group {group}"));
                }
                groups(&core)
            }
            Request::UrlTest { group } => {
                core.url_test(&group);
                groups(&core)
            }
            Request::Stats {} => Response {
                stats: Some(stats(&core)),
                ..Response::default()
            },
            Request::Connections {} => Response {
                connections: connections(&core),
                ..Response::default()
            },
            Request::CloseConnection { id } => {
                core.close_connection(&id);
                Response {
                    connections: connections(&core),
                    ..Response::default()
                }
            }
            Request::Reload {
                config,
                remote,
                log_level,
                rules,
            } => {
                let pc = self.provider.config();
                let current = self.state();
                let mut saved = match config {
                    None => saved_state(&pc),
                    Some(_) => State {
                        remote,
                        log_level,
                        rules: current.rules.clone(),
                    },
                };
                if let Some(rules) = rules {
                    saved.rules = rules;
                }
                // A copy the tunnel downloaded after the app's wins: the app
                // may not have picked it up yet.
                let text = match config {
                    Some(c) => c,
                    None => load_configuration(&pc)?,
                };
                let (text, latest) = self.newest(text, saved.remote.clone(), &pc);
                self.run(&text, saved.log_level.as_deref(), &saved.rules)?;
                for (domain, subdomains) in rules::changed_domains(&current.rules, &saved.rules) {
                    core.close_domain(&domain, subdomains);
                }
                self.set_state(State {
                    remote: latest,
                    ..saved
                });
                self.schedule_refresh(None);
                groups(&core)
            }
            Request::Logs {} | Request::Profile {} | Request::Erase {} => Response::default(),
        })
    }

    /// Run `config` on the core: validated first, a no-op when unchanged, and
    /// new interface settings applied when its tun inbound asks for them.
    fn run(&self, config: &str, log_level: Option<&str>, rules: &[PersonalRule]) -> Result<(), String> {
        let core = self.core().ok_or("sbr is not running")?;
        let config = prepared(config, log_level, rules, self.provider.config().tun_stack.as_deref());
        if core.apply(&config)? == Applied::NeedsNetworkSettings {
            self.provider.set_network_settings(&config)?;
            core.reload(&config)?;
        }
        Ok(())
    }

    // Remote profile refresh.

    /// Re-arm the refresh timer from the profile's `updated` time: one sleep,
    /// no polling. `retry_in` overrides it after a failed attempt.
    fn schedule_refresh(self: &Arc<Self>, retry_in: Option<Duration>) {
        let generation = {
            let mut g = self.refresh.0.lock().unwrap_or_else(|e| e.into_inner());
            *g += 1;
            self.refresh.1.notify_all();
            *g
        };
        let Some(remote) = self.state().remote else {
            return;
        };
        let interval = Duration::from_secs(remote.refresh_minutes.max(5) as u64 * 60);
        let due = match retry_in {
            Some(d) => SystemTime::now() + d,
            None => remote.updated.map_or(SystemTime::UNIX_EPOCH, Date::to_system_time) + interval,
        };
        let weak = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("sbr-refresh".into())
            .spawn(move || {
                if wait_until(&weak, generation, due)
                    && let Some(t) = weak.upgrade()
                {
                    t.refresh_remote();
                }
            })
            .ok();
    }

    fn refresh_remote(self: &Arc<Self>) {
        let (Some(core), Some(remote)) = (self.core(), self.state().remote) else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        let fetched = core
            .fetch_profile(&remote.url, move |r| {
                let _ = tx.send(r);
            })
            .and_then(|()| rx.recv().unwrap_or_else(|_| Err("cancelled: sbr stopped".into())));
        drop(core);
        let text = match fetched {
            Ok(t) => t,
            Err(e) => {
                logs::tunnel().log(Level::Error, "profile refresh failed: ", &e);
                logs::append(Level::Warn, &format!("profile refresh failed: {e}"));
                self.schedule_refresh(Some(RETRY));
                return;
            }
        };
        let state = self.state();
        if let Err(e) = self.run(&text, state.log_level.as_deref(), &state.rules) {
            // The error can quote the profile; keep it out of the app's log view.
            logs::tunnel().log(Level::Error, "downloaded profile rejected: ", &e);
            logs::append(Level::Warn, "downloaded profile is invalid; keeping the running one");
            self.schedule_refresh(Some(RETRY));
            return;
        }
        let now = Date::now();
        self.save_snapshot(
            &self.provider.config(),
            &ProfileSnapshot {
                url: remote.url.clone(),
                text,
                updated: now,
            },
        );
        {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(r) = s.remote.as_mut().filter(|r| r.url == remote.url) {
                r.updated = Some(now);
            }
        }
        logs::tunnel().info("profile refreshed");
        logs::append(Level::Info, "profile refreshed");
        self.schedule_refresh(None);
    }

    /// `config` for `remote`, or the tunnel's own later download of it.
    fn newest(
        &self,
        config: String,
        remote: Option<RemoteProfile>,
        pc: &ProviderConfig,
    ) -> (String, Option<RemoteProfile>) {
        let Some(mut remote) = remote else {
            return (config, None);
        };
        match self.load_snapshot(pc) {
            Some(snap) if snap.url == remote.url && remote.updated.is_none_or(|u| snap.updated > u) => {
                remote.updated = Some(snap.updated);
                (snap.text, Some(remote))
            }
            _ => (config, Some(remote)),
        }
    }

    fn load_snapshot(&self, pc: &ProviderConfig) -> Option<ProfileSnapshot> {
        if let Some(stored) = &pc.stored {
            // A file left by a build that kept the download on disk.
            if let Some(path) = store::private_file(SNAPSHOT) {
                let _ = std::fs::remove_file(path);
            }
            return Keychain {
                access_group: &stored.access_group,
            }
            .value(ProfileSnapshot::ACCOUNT)
            .ok()
            .flatten();
        }
        let data = std::fs::read(store::private_file(SNAPSHOT)?).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Holds server credentials: in the Keychain with a stored profile, so
    /// erasing the app's items removes it too; otherwise in the private
    /// directory, protected until first unlock and out of backups.
    fn save_snapshot(&self, pc: &ProviderConfig, snapshot: &ProfileSnapshot) {
        if let Some(stored) = &pc.stored {
            let _ = Keychain {
                access_group: &stored.access_group,
            }
            .set_value(ProfileSnapshot::ACCOUNT, snapshot);
            return;
        }
        if let (Some(path), Ok(data)) = (store::private_file(SNAPSHOT), serde_json::to_vec(snapshot)) {
            let _ = store::write_atomic(&path, &data);
        }
    }

    /// Delete everything the extension keeps on disk: the cache file,
    /// rule-sets, the downloaded profile and the session logs. The app stops
    /// the tunnel next.
    fn erase(&self) {
        self.stop_heartbeat();
        let Some(dir) = store::private_dir() else { return };
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            let _ = if p.is_dir() {
                std::fs::remove_dir_all(&p)
            } else {
                std::fs::remove_file(&p)
            };
        }
    }

    /// The device is going to sleep. An idle sbr arms no timers, so there is
    /// nothing to pause.
    pub fn sleep(&self) {
        logs::tunnel().debug("sleep");
    }

    /// Back from sleep: NAT mappings for UDP flows have likely expired and
    /// the path may differ, so drop path-bound state like a network change.
    pub fn wake(self: &Arc<Self>) {
        logs::tunnel().debug("wake");
        if let Some(c) = self.core() {
            c.network_changed();
        }
        // The refresh wait may have been suspended along with the extension.
        self.schedule_refresh(None);
    }

    // Heartbeat and memory pressure.

    fn stop_heartbeat(&self) {
        if let Some(stop) = self.heartbeat.lock().unwrap_or_else(|e| e.into_inner()).take() {
            stop.store(true, Ordering::SeqCst);
        }
        *self.memory_pressure.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Sampled every second, saved every 5 s with the interval's peak memory
    /// and CPU share: iOS kills an extension for memory or CPU without a
    /// report the extension can see, so the next start reports the last beat.
    fn start_heartbeat(self: &Arc<Self>) {
        self.stop_heartbeat();
        let stop = Arc::new(AtomicBool::new(false));
        *self.heartbeat.lock().unwrap_or_else(|e| e.into_inner()) = Some(stop.clone());
        let weak = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("sbr-heartbeat".into())
            .spawn(move || {
                let mut peak = 0u64;
                let mut last_cpu: Option<(u64, Instant)> = None;
                let mut tick = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    if let Some(core) = weak.upgrade().and_then(|t| t.core()) {
                        let s = core.stats();
                        peak = peak.max(s.memory_footprint);
                        if tick.is_multiple_of(5)
                            && let Some(path) = store::private_file(HEARTBEAT)
                        {
                            let now = Instant::now();
                            let cpu = last_cpu.map_or(String::new(), |(micros, at)| {
                                let secs = now.duration_since(at).as_secs_f64().max(0.001);
                                let share = s.cpu_time_us.wrapping_sub(micros) as f64 / 1e6 / secs;
                                format!(", cpu {:.0}%", share * 100.0)
                            });
                            last_cpu = Some((s.cpu_time_us, now));
                            let beat = format!(
                                "{} with {:.1} MB in use (peak {:.1} MB, {:.0} MB left){cpu}, {} tcp",
                                logs::iso8601(SystemTime::now()),
                                s.memory_footprint as f64 / MB,
                                peak as f64 / MB,
                                s.memory_available as f64 / MB,
                                s.active_connections,
                            );
                            let _ = store::write_atomic(&path, beat.as_bytes());
                            save_recent();
                            peak = 0;
                        }
                    }
                    tick += 1;
                    std::thread::sleep(Duration::from_secs(1));
                }
            })
            .ok();
        // The system warns before it kills a process for memory; record when.
        let weak = Arc::downgrade(self);
        let watch = MemoryPressure::watch(move |critical| {
            let level = if critical { "critical" } else { "warning" };
            let mb = weak
                .upgrade()
                .and_then(|t| t.core())
                .map_or(0, |c| c.stats().memory_footprint) as f64
                / MB;
            let line = format!("memory pressure {level} at {mb:.1} MB");
            logs::tunnel().log(Level::Warn, &line, "");
            logs::append(Level::Warn, &line);
            save_recent();
        });
        *self.memory_pressure.lock().unwrap_or_else(|e| e.into_inner()) = Some(watch);
    }

    fn start_path_monitor(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let monitor = PathMonitor::start(move |path| {
            let Some(t) = weak.upgrade() else { return };
            let signature = if path.satisfied {
                path.interfaces.join(",")
            } else {
                "unsatisfied".to_owned()
            };
            let last = t
                .last_path
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .replace(signature.clone());
            // With includeAllNetworks the extension's own sockets are not
            // reliably exempt from its tunnel, so pin them to the physical
            // path, as desktop auto_route does.
            if path.satisfied && t.provider.config().include_all_networks {
                sbr_apple::api::set_default_interface(path.interfaces.first().map(String::as_str));
                if last.is_none()
                    && let Some(c) = t.core()
                {
                    c.network_changed();
                }
            }
            // The first report, or no change.
            let Some(last) = last.filter(|l| *l != signature) else {
                return;
            };
            logs::tunnel().info(&format!("network changed: {last} -> {signature}"));
            if path.satisfied
                && let Some(c) = t.core()
            {
                c.network_migrate();
            }
        });
        *self.path_monitor.lock().unwrap_or_else(|e| e.into_inner()) = Some(monitor);
    }
}

/// After a failed refresh.
const RETRY: Duration = Duration::from_secs(5 * 60);

/// Wait until `due` (wall clock, so time asleep counts) unless the refresh
/// generation moves on first. True when the refresh should run.
fn wait_until(tunnel: &Weak<Tunnel>, generation: u64, due: SystemTime) -> bool {
    loop {
        let Some(t) = tunnel.upgrade() else { return false };
        let (lock, cv) = &t.refresh;
        let g = lock.lock().unwrap_or_else(|e| e.into_inner());
        if *g != generation {
            return false;
        }
        let Ok(left) = due.duration_since(SystemTime::now()) else {
            return true;
        };
        // Re-check the clock at least every minute.
        let (g, _) = cv
            .wait_timeout(g, left.min(Duration::from_secs(60)))
            .unwrap_or_else(|e| e.into_inner());
        if *g != generation {
            return false;
        }
    }
}

fn groups(core: &Sbr) -> Vec<Group> {
    core.groups_json()
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

fn connections(core: &Sbr) -> Option<Connections> {
    core.connections_json(200).and_then(|j| serde_json::from_str(&j).ok())
}

fn stats(core: &Sbr) -> Stats {
    let s = core.stats();
    Stats {
        memory_footprint: s.memory_footprint,
        memory_available: s.memory_available,
        active_connections: s.active_connections,
        udp_sessions: s.udp_sessions,
        uplink_bytes: s.uplink_bytes,
        downlink_bytes: s.downlink_bytes,
        cpu_time_micros: s.cpu_time_us,
    }
}

fn stored_secret(stored: &StoredProfile) -> Result<ProfileSecret, String> {
    Keychain {
        access_group: &stored.access_group,
    }
    .value(&stored.account())?
    .ok_or_else(|| "the profile is not in the Keychain".to_owned())
}

/// The config the provider configuration points at.
fn load_configuration(pc: &ProviderConfig) -> Result<String, String> {
    if let Some(stored) = &pc.stored {
        return stored_secret(stored)?
            .config
            .ok_or_else(|| "the profile has not been downloaded".to_owned());
    }
    if let Some(inline) = &pc.config {
        return Ok(inline.clone());
    }
    if let Some(group) = &pc.app_group {
        return store::load_app_group_config(group);
    }
    Err(r#"no config: set providerConfiguration["stored"], ["config"] or ["appGroup"]"#.into())
}

/// What the app saved in the provider configuration.
fn saved_state(pc: &ProviderConfig) -> State {
    let remote = match &pc.stored {
        Some(stored) => stored_secret(stored).ok().and_then(|s| s.url).map(|url| RemoteProfile {
            url,
            refresh_minutes: stored.refresh_minutes,
            updated: stored.updated,
        }),
        None => pc.remote.clone(),
    };
    State {
        remote,
        log_level: pc.log_level.clone(),
        rules: pc.rules.clone(),
    }
}

/// The config as the tunnel runs it: overrides applied, then the personal
/// rules. A rule naming an outbound the profile lacks is skipped; rules that
/// make the config invalid are dropped as a whole, with a warning.
fn prepared(config: &str, log_level: Option<&str>, rules: &[PersonalRule], stack: Option<&str>) -> String {
    let base = rules::with_overrides(config, log_level, stack);
    let (with_rules, skipped) = rules::apply(rules, &base);
    for r in skipped {
        logs::append(
            Level::Warn,
            &format!(
                "personal rule for {} skipped: no outbound {}",
                r.domains.join(" "),
                r.outbound
            ),
        );
    }
    if with_rules == base {
        return base;
    }
    if let Some(problem) = sbr_apple::api::check(&with_rules) {
        logs::tunnel().log(Level::Error, "personal rules rejected: ", &problem);
        logs::append(Level::Warn, "personal rules are invalid; running without them");
        return base;
    }
    with_rules
}

// The previous session's report.

const SNAPSHOT: &str = "remote-profile.json";
const CRASH: &str = "crash.log";
const HEARTBEAT: &str = "heartbeat";
const END: &str = "end";
const RECENT: &str = "recent.log";

/// The last process's end or crash breadcrumbs, or, if it left none but
/// never stopped cleanly, its last heartbeat: a memory kill leaves no other
/// trace. Then arm the crash file for this process.
fn report_previous_session() {
    let read = |name| store::private_file(name).and_then(|p| std::fs::read_to_string(p).ok());
    let remove = |name| {
        if let Some(p) = store::private_file(name) {
            let _ = std::fs::remove_file(p);
        }
    };
    let mut abnormal = false;
    if let Some(end) = read(END) {
        logs::append(Level::Error, &format!("previous session {end}"));
        remove(END);
        abnormal = true;
    }
    if let Some(path) = store::private_file(CRASH) {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.split('\n').filter(|l| !l.is_empty()).collect();
        let tail = &lines[lines.len().saturating_sub(5)..];
        for line in tail {
            logs::append(Level::Error, &format!("previous session: {line}"));
        }
        let _ = std::fs::remove_file(&path);
        sbr_apple::api::set_crash_file(&path.to_string_lossy());
        abnormal = abnormal || !tail.is_empty();
    }
    if let Some(beat) = read(HEARTBEAT) {
        if !abnormal {
            logs::append(
                Level::Warn,
                &format!("previous session ended without stopping; last seen {beat}"),
            );
        }
        remove(HEARTBEAT);
        abnormal = true;
    }
    // What the tunnel was doing just before, oldest first.
    if abnormal && let Some(text) = read(RECENT) {
        for line in text.split('\n').filter(|l| !l.is_empty()) {
            logs::append(Level::Info, &format!("prev │ {line}"));
        }
    }
    remove(RECENT);
}

fn record_end(text: &str) {
    if let Some(p) = store::private_file(END) {
        let _ = store::write_atomic(&p, text.as_bytes());
    }
    save_recent();
}

/// The last 40 log lines, so an abnormal end can show its lead-up.
fn save_recent() {
    let Some(p) = store::private_file(RECENT) else { return };
    let lines = logs::snapshot();
    let tail = &lines[lines.len().saturating_sub(40)..];
    let _ = store::write_atomic(&p, tail.join("\n").as_bytes());
}
