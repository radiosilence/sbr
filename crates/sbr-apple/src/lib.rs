//! C ABI for Apple platforms (and anything else that links C). The header is
//! `include/sbr.h`; keep the two in sync (`tests/c_abi.rs` checks names and
//! compiles a C program against the staticlib).
//!
//! Sized for the iOS Network Extension (~50 MB jetsam limit): a one-thread
//! runtime, 16 KiB relay buffers and a connection cap, so the worst case
//! stays well below the ceiling. Every entry point catches panics; nothing
//! unwinds into Swift.

mod crash;
mod log;
mod profile;
mod runtime;
mod sys;
mod tun_settings;

use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard};

use sbr_engine::fetch::Url;
use sbr_engine::sbr_config::Options;
use sbr_engine::{Engine, Settings};

use profile::Applied;
use runtime::{Flavor, Running};
use sbr_engine::outbound::group::real_tag;

const MOBILE: bool = cfg!(any(target_os = "ios", target_os = "tvos", target_os = "visionos"));

/// Per-direction relay buffer: 2 × 16 KiB = 32 KiB per TCP connection.
const fn default_relay_buffer() -> usize {
    if MOBILE {
        16 * 1024
    } else {
        sbr_engine::sbr_core::relay::DEFAULT_BUFFER
    }
}

/// 512 connections × 32 KiB = 16 MB of relay buffers at worst. UDP sessions
/// are capped separately at the same number: 512 × 16 KiB reply buffers plus
/// at most 4 MiB queued across them, 12 MB more. Each QUIC connection may
/// also hold 4 MiB received and 4 MiB unacknowledged, and each h2 connection
/// 4 MiB received, against the extension's ~50 MB.
const fn default_max_connections() -> u32 {
    if MOBILE { 512 } else { 0 }
}

/// `SbrStartOptions` in sbr.h. Get one from `sbr_start_options_default`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SbrStartOptions {
    pub base_dir: *const c_char,
    pub tun_fd: i32,
    pub threads: i32,
    pub relay_buffer: u32,
    pub max_connections: u32,
}

/// `SbrRuntimeStats` in sbr.h.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SbrRuntimeStats {
    pub memory_footprint: u64,
    pub memory_available: u64,
    pub active_connections: u64,
    pub udp_sessions: u64,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    pub cpu_time_us: u64,
}

/// What a start needs besides the config; reused by `sbr_reload`.
#[derive(Clone, Debug)]
struct Launch {
    base_dir: Option<PathBuf>,
    tun_fd: Option<i32>,
    flavor: Flavor,
    relay_buffer: usize,
    max_connections: usize,
}

impl Launch {
    fn settings(&self, tun_fd: Option<i32>) -> Settings {
        Settings {
            relay_buffer: self.relay_buffer,
            base_dir: self.base_dir.clone(),
            tun_fd,
            max_connections: self.max_connections,
            ..Settings::default()
        }
    }

    fn start(&self, options: Options) -> Result<Running, String> {
        log::configure(&options.log);
        let tun_fd = self.tun_fd.map(sys::dup_fd).transpose()?;
        Running::start(options, self.settings(tun_fd), self.flavor)
    }
}

pub struct SbrInstance {
    inner: Mutex<Inner>,
}

struct Inner {
    running: Option<Running>,
    launch: Launch,
    /// The text `running` was started from.
    config: String,
    /// What host-originated connections are routed as.
    inbound: (Arc<str>, &'static str),
}

impl SbrInstance {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn engine(&self) -> Option<Arc<Engine>> {
        self.lock().running.as_ref().map(|r| r.engine.clone())
    }

    /// Download `url` through the running engine's routing on its runtime and
    /// hand the result to `reply`. False when nothing is running. `reply` is
    /// dropped uncalled if the engine stops first.
    fn fetch(&self, url: Url, reply: impl FnOnce(Result<String, String>) + Send + 'static) -> bool {
        let (engine, handle, inbound) = {
            let inner = self.lock();
            let Some(r) = inner.running.as_ref() else {
                return false;
            };
            (r.engine.clone(), r.handle.clone(), inner.inbound.clone())
        };
        handle.spawn(async move { reply(profile::fetch(&engine, inbound, &url).await) });
        true
    }
}

impl Inner {
    /// Validate, then restart on `options`. A config that fails validation
    /// leaves the old one running; listeners and the TUN can still fail at
    /// start, and then the instance is left stopped.
    fn swap(&mut self, text: &str, options: Options) -> Result<(), String> {
        self.validate(&options)?;
        let inbound = profile::host_inbound(&options);
        self.running = None;
        self.running = Some(self.launch.start(options)?);
        self.config = text.to_owned();
        self.inbound = inbound;
        Ok(())
    }

    fn validate(&self, options: &Options) -> Result<(), String> {
        Engine::new(options, &self.launch.settings(None))
            .map(drop)
            .map_err(|e| e.to_string())
    }

    /// Run `text` unless it is what is already running.
    fn apply_profile(&mut self, text: &str) -> Result<Applied, String> {
        if self.running.is_some() && text == self.config {
            return Ok(Applied::Unchanged);
        }
        let options = parse(Some(text))?;
        if let Ok(old) = Options::parse(&self.config)
            && profile::network_settings_differ(&old, &options)
        {
            self.validate(&options)?;
            return Ok(Applied::NeedsNetworkSettings);
        }
        self.swap(text, options)?;
        Ok(Applied::Reloaded)
    }
}

/// `SbrFetchCallback` in sbr.h.
pub type FetchFn = unsafe extern "C" fn(context: *mut c_void, profile: *const c_char, error: *const c_char);

/// Calls the host back exactly once: with the result, or with an error if
/// the task is dropped first (the engine stopped or reloaded). The call runs
/// on a thread of its own. A cancellation runs while the runtime is torn
/// down, inside `sbr_stop` or `sbr_reload` with the instance locked, and a
/// result runs on the engine's own threads, so a host calling back into sbr
/// from either would deadlock.
struct Reply {
    callback: FetchFn,
    context: *mut c_void,
    sent: bool,
}

// SAFETY: the host promises `context` may be used from any thread.
unsafe impl Send for Reply {}

impl Reply {
    fn send(&mut self, r: Result<String, String>) {
        self.sent = true;
        let r = r.and_then(|p| CString::new(p).map_err(|_| "profile contains a NUL byte".to_owned()));
        let (profile, error) = match r {
            Ok(p) => (Some(p), None),
            Err(e) => (None, CString::new(e.replace('\0', " ")).ok()),
        };
        let call = Call {
            callback: self.callback,
            context: self.context,
            profile,
            error,
        };
        let mut call = Some(call);
        let spawned = std::thread::Builder::new().name("sbr-reply".into()).spawn({
            let call = call.take();
            move || call.map(Call::run)
        });
        if let Err(e) = spawned {
            // Could not spawn: calling inline is better than never.
            tracing::warn!(error = %e, "profile callback thread");
        }
        if let Some(call) = call {
            call.run();
        }
    }
}

struct Call {
    callback: FetchFn,
    context: *mut c_void,
    profile: Option<CString>,
    error: Option<CString>,
}

// SAFETY: as for `Reply`.
unsafe impl Send for Call {}

impl Call {
    fn run(self) {
        let p = |s: &Option<CString>| s.as_ref().map_or(ptr::null(), |s| s.as_ptr());
        // SAFETY: the host passed a valid callback; the strings outlive the call.
        unsafe { (self.callback)(self.context, p(&self.profile), p(&self.error)) };
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        if !self.sent {
            self.send(Err("cancelled: sbr stopped".to_owned()));
        }
    }
}

/// Run `f`, turning a panic into `default` so nothing unwinds across the ABI.
fn guard<T>(default: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        tracing::error!("internal error: panic in sbr FFI call");
        default
    })
}

unsafe fn str_arg<'a>(p: *const c_char) -> Option<&'a str> {
    // SAFETY: caller passes NULL or a valid NUL-terminated string.
    (!p.is_null())
        .then(|| unsafe { CStr::from_ptr(p) }.to_str().ok())
        .flatten()
}

fn out_string(s: String) -> *mut c_char {
    CString::new(s.replace('\0', " ")).map_or(ptr::null_mut(), CString::into_raw)
}

fn engine_of(p: *mut SbrInstance) -> Option<Arc<Engine>> {
    // SAFETY: caller contract: NULL or a live pointer from sbr_start*.
    unsafe { p.as_ref() }.and_then(SbrInstance::engine)
}

fn parse(json: Option<&str>) -> Result<Options, String> {
    Options::parse(json.ok_or("config is NULL or not UTF-8")?).map_err(|e| e.to_string())
}

/// Static, NUL-terminated; do not free.
#[unsafe(no_mangle)]
pub extern "C" fn sbr_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// # Safety
/// `config_json` must be NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_check(config_json: *const c_char) -> *mut c_char {
    let r = guard(Some("internal error (panic)".to_owned()), || {
        let o = match parse(unsafe { str_arg(config_json) }) {
            Ok(o) => o,
            Err(e) => return Some(e),
        };
        Engine::new(&o, &Settings::default()).err().map(|e| e.to_string())
    });
    r.map_or(ptr::null_mut(), out_string)
}

#[unsafe(no_mangle)]
pub extern "C" fn sbr_start_options_default() -> SbrStartOptions {
    SbrStartOptions {
        base_dir: ptr::null(),
        tun_fd: -1,
        threads: 0,
        relay_buffer: 0,
        max_connections: default_max_connections(),
    }
}

/// `sbr_start_ex` with default options and no TUN fd.
///
/// # Safety
/// String arguments must be NULL or valid C strings; `error_out` must be NULL
/// or a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_start(
    config_json: *const c_char,
    base_dir: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut SbrInstance {
    let o = SbrStartOptions {
        base_dir,
        ..sbr_start_options_default()
    };
    unsafe { sbr_start_ex(config_json, &o, error_out) }
}

/// # Safety
/// `config_json` NULL or a valid C string; `options` NULL or valid (with a
/// NULL or valid `base_dir`); `error_out` NULL or a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_start_ex(
    config_json: *const c_char,
    options: *const SbrStartOptions,
    error_out: *mut *mut c_char,
) -> *mut SbrInstance {
    let r = guard(Err("internal error (panic)".to_owned()), || {
        log::install();
        // SAFETY: NULL or valid per the contract.
        let o = unsafe { options.as_ref() }
            .copied()
            .unwrap_or_else(|| sbr_start_options_default());
        let launch = Launch {
            base_dir: unsafe { str_arg(o.base_dir) }.map(Into::into),
            tun_fd: (o.tun_fd >= 0).then_some(o.tun_fd),
            flavor: Flavor::from_threads(o.threads),
            relay_buffer: match o.relay_buffer {
                0 => default_relay_buffer(),
                // Below a TCP segment or two the relay just burns syscalls.
                n => (n as usize).max(4096),
            },
            max_connections: o.max_connections as usize,
        };
        let text = unsafe { str_arg(config_json) };
        let options = parse(text)?;
        let inbound = profile::host_inbound(&options);
        let running = launch.start(options)?;
        Ok(Box::new(SbrInstance {
            inner: Mutex::new(Inner {
                running: Some(running),
                launch,
                config: text.unwrap_or_default().to_owned(),
                inbound,
            }),
        }))
    });
    match r {
        Ok(b) => Box::into_raw(b),
        Err(e) => {
            if !error_out.is_null() {
                // SAFETY: checked non-null; caller owns the slot.
                unsafe { *error_out = out_string(e) };
            }
            ptr::null_mut()
        }
    }
}

/// # Safety
/// `instance` must be live; `config_json` NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_reload(instance: *mut SbrInstance, config_json: *const c_char) -> *mut c_char {
    let r = guard(Err("internal error (panic)".to_owned()), || {
        // SAFETY: NULL or live per the contract.
        let inst = unsafe { instance.as_ref() }.ok_or("instance is NULL")?;
        let text = unsafe { str_arg(config_json) };
        let options = parse(text)?;
        inst.lock().swap(text.unwrap_or_default(), options)
    });
    r.err().map_or(ptr::null_mut(), out_string)
}

/// Start downloading the profile at `url` (https only) through the running
/// config's route rules, with no identifying headers. Returns 1 if started:
/// `callback` then runs exactly once, on an sbr thread. Returns 0 (and never
/// calls back) when `url` is not https or nothing is running.
///
/// # Safety
/// `instance` must be live; `url` NULL or a valid C string; `callback` and
/// `context` usable from any thread until the call back.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_fetch_profile(
    instance: *mut SbrInstance,
    url: *const c_char,
    callback: Option<FetchFn>,
    context: *mut c_void,
) -> i32 {
    guard(0, || {
        // SAFETY: NULL or live per the contract.
        let (Some(inst), Some(callback)) = (unsafe { instance.as_ref() }, callback) else {
            return 0;
        };
        let Some(url) = unsafe { str_arg(url) }.and_then(Url::parse).filter(|u| u.https) else {
            return 0;
        };
        let reply = Reply {
            callback,
            context,
            sent: false,
        };
        inst.fetch(url, move |r| {
            let mut reply = reply;
            reply.send(r);
        }) as i32
    })
}

/// Run `config_json` unless it is the running config. Returns one of
/// `SBR_PROFILE_*`, or -1 with `error_out` set; on -1 or
/// `SBR_PROFILE_NEEDS_NETWORK_SETTINGS` the running config is untouched.
///
/// # Safety
/// `instance` must be live; `config_json` NULL or a valid C string;
/// `error_out` NULL or a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_apply_profile(
    instance: *mut SbrInstance,
    config_json: *const c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    let r = guard(Err("internal error (panic)".to_owned()), || {
        // SAFETY: NULL or live per the contract.
        let inst = unsafe { instance.as_ref() }.ok_or("instance is NULL")?;
        let text = unsafe { str_arg(config_json) }.ok_or("config is NULL or not UTF-8")?;
        inst.lock().apply_profile(text)
    });
    match r {
        Ok(a) => a as i32,
        Err(e) => {
            if !error_out.is_null() {
                // SAFETY: checked non-null; caller owns the slot.
                unsafe { *error_out = out_string(e) };
            }
            -1
        }
    }
}

/// # Safety
/// `instance` must come from `sbr_start*` and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_stop(instance: *mut SbrInstance) {
    if instance.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: ownership returns to us exactly once.
        drop(unsafe { Box::from_raw(instance) });
    });
}

/// # Safety
/// `instance` must be live; strings NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_select(instance: *mut SbrInstance, group: *const c_char, member: *const c_char) -> i32 {
    guard(0, || {
        let (Some(e), Some(g), Some(m)) = (engine_of(instance), unsafe { str_arg(group) }, unsafe {
            str_arg(member)
        }) else {
            return 0;
        };
        let Some(group) = e.outbound(g).and_then(|o| o.as_group()) else {
            return 0;
        };
        let before = group.selected().tag().to_owned();
        if !group.select(m) {
            return 0;
        }
        // A choice made by hand should take effect now, not when apps next
        // open a connection: close what still runs through the old member.
        if before != m {
            e.tracker.close_through(g);
        }
        1
    })
}

/// # Safety
/// `instance` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_groups(instance: *mut SbrInstance) -> *mut c_char {
    guard(ptr::null_mut(), || {
        let Some(e) = engine_of(instance) else {
            return ptr::null_mut();
        };
        let env = e.groups();
        let delay = |o: &dyn sbr_engine::Outbound| match env.history(&real_tag(o)) {
            Some(h) => h.delay.to_string(),
            None => "null".to_owned(),
        };
        let groups: Vec<String> = e
            .outbounds()
            .iter()
            .filter_map(|o| o.as_group().map(|g| (o, g)))
            .map(|(o, g)| {
                let members: Vec<String> = g
                    .members()
                    .iter()
                    .map(|m| {
                        let d = env.degraded(&real_tag(m.as_ref()));
                        format!(
                            r#"{{"tag":{},"type":{},"delay":{},"degraded":{},"reason":{},"retry_in":{}}}"#,
                            json_str(m.tag()),
                            json_str(m.kind()),
                            delay(m.as_ref()),
                            d.is_some(),
                            d.map_or("null".to_owned(), |d| json_str(d.reason.as_str())),
                            d.map_or("null".to_owned(), |d| d
                                .until
                                .saturating_duration_since(std::time::Instant::now())
                                .as_secs()
                                .to_string()),
                        )
                    })
                    .collect();
                format!(
                    r#"{{"tag":{},"type":{},"selected":{},"now":{},"delay":{},"members":[{}]}}"#,
                    json_str(o.tag()),
                    json_str(o.kind()),
                    json_str(g.selected().tag()),
                    json_str(&real_tag(o.as_ref())),
                    delay(o.as_ref()),
                    members.join(",")
                )
            })
            .collect();
        out_string(format!("[{}]", groups.join(",")))
    })
}

/// Start a latency test of `group` (a urltest, or a selector whose urltest
/// members are tested) and return immediately; poll `sbr_groups` for results.
/// Returns 1 if a test started, 0 if the group is unknown or has nothing to test.
///
/// # Safety
/// `instance` must be live; `group` NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_url_test(instance: *mut SbrInstance, group: *const c_char) -> i32 {
    guard(0, || {
        let Some(tag) = (unsafe { str_arg(group) }) else {
            return 0;
        };
        // SAFETY: caller contract: NULL or a live pointer from sbr_start*.
        let Some(inst) = (unsafe { instance.as_ref() }) else {
            return 0;
        };
        let Some((engine, handle)) = inst
            .lock()
            .running
            .as_ref()
            .map(|r| (r.engine.clone(), r.handle.clone()))
        else {
            return 0;
        };
        let Some(o) = engine.outbound(tag) else { return 0 };
        let Some(g) = o.as_group() else { return 0 };
        let mut tags: Vec<String> = vec![tag.to_owned()];
        tags.extend(
            g.members()
                .iter()
                .filter(|m| m.kind() == "urltest")
                .map(|m| m.tag().to_owned()),
        );
        let env = engine.groups().clone();
        let mut started = 0;
        for t in tags {
            if env.urltest(&t).is_some() {
                let env = env.clone();
                handle.spawn(async move {
                    if let Some(u) = env.urltest(&t) {
                        u.url_test(true).await;
                    }
                });
                started = 1;
            }
        }
        started
    })
}

/// Default and ceiling for `sbr_connections`: each entry is a few hundred
/// bytes of JSON, and the extension has ~50 MB in all.
const CONNECTIONS_LIMIT: usize = 200;

fn connections_json(e: &Engine, limit: usize) -> String {
    use std::sync::atomic::Ordering::Relaxed;
    use std::time::UNIX_EPOCH;
    let t = &e.tracker;
    let all = t.connections();
    let (up, down) = t.totals();
    // `connections()` is in id order, so the newest are at the end.
    let conns: Vec<serde_json::Value> = all
        .iter()
        .rev()
        .take(limit)
        .map(|c| {
            let m = &c.meta;
            serde_json::json!({
                "id": c.uuid(t),
                "network": match m.network {
                    sbr_engine::sbr_core::Network::Tcp => "tcp",
                    sbr_engine::sbr_core::Network::Udp => "udp",
                    sbr_engine::sbr_core::Network::Icmp => "icmp",
                },
                "inbound": format!("{}/{}", m.inbound_type, m.inbound),
                "source": m.source.to_string(),
                "destination": m.destination.to_string(),
                "domain": m.domain(),
                "ip": m.destination_ips().next().map(|ip| ip.to_string()),
                "protocol": m.protocol.map(|p| p.as_str()),
                "chain": c.chain.iter().map(|t| &**t).collect::<Vec<_>>(),
                "rule": e.rule_label(c.rule),
                "upload": c.up.load(Relaxed),
                "download": c.down.load(Relaxed),
                "start": c.start.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64),
            })
        })
        .collect();
    serde_json::json!({
        "total": all.len(),
        "upload_total": up,
        "download_total": down,
        "connections": conns,
    })
    .to_string()
}

/// # Safety
/// `instance` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_connections(instance: *mut SbrInstance, limit: u32) -> *mut c_char {
    guard(ptr::null_mut(), || {
        let Some(e) = engine_of(instance) else {
            return ptr::null_mut();
        };
        let limit = match limit as usize {
            0 => CONNECTIONS_LIMIT,
            n => n.min(CONNECTIONS_LIMIT),
        };
        out_string(connections_json(&e, limit))
    })
}

/// # Safety
/// `instance` must be live; `id` NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_close_connection(instance: *mut SbrInstance, id: *const c_char) -> i32 {
    guard(0, || {
        let (Some(e), Some(id)) = (engine_of(instance), unsafe { str_arg(id) }) else {
            return 0;
        };
        match e.tracker.find(id) {
            Some(c) => {
                c.close();
                1
            }
            None => 0,
        }
    })
}

/// # Safety
/// `instance` must be live; `domain` NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_close_domain(instance: *mut SbrInstance, domain: *const c_char, subdomains: i32) -> i32 {
    guard(0, || {
        let (Some(e), Some(domain)) = (engine_of(instance), unsafe { str_arg(domain) }) else {
            return 0;
        };
        e.tracker
            .close_domain(domain, subdomains != 0)
            .try_into()
            .unwrap_or(i32::MAX)
    })
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// # Safety
/// `instance` must be live; out-pointers NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_stats(instance: *mut SbrInstance, up: *mut u64, down: *mut u64, active: *mut u64) {
    guard((), || {
        let Some(e) = engine_of(instance) else {
            return;
        };
        let (u, d) = e.traffic.snapshot();
        // SAFETY: each pointer is NULL or valid per the contract.
        unsafe {
            for (p, v) in [(up, u), (down, d), (active, e.active_connections() as u64)] {
                if let Some(p) = p.as_mut() {
                    *p = v;
                }
            }
        }
    })
}

/// # Safety
/// `instance` NULL (memory figures only) or live; `out` NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_runtime_stats(instance: *mut SbrInstance, out: *mut SbrRuntimeStats) {
    guard((), || {
        // SAFETY: NULL or valid per the contract.
        let Some(out) = (unsafe { out.as_mut() }) else {
            return;
        };
        let mut s = SbrRuntimeStats {
            memory_footprint: sys::memory_footprint(),
            memory_available: sys::memory_available(),
            cpu_time_us: sys::cpu_time_us(),
            ..Default::default()
        };
        if let Some(e) = engine_of(instance) {
            (s.uplink_bytes, s.downlink_bytes) = e.traffic.snapshot();
            s.active_connections = e.active_connections() as u64;
            s.udp_sessions = e.udp_sessions() as u64;
        }
        *out = s;
    })
}

/// # Safety
/// `instance` must be NULL or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_network_changed(instance: *mut SbrInstance) {
    guard((), || {
        if let Some(e) = engine_of(instance) {
            e.network_changed();
        }
    })
}

/// The default path moved to another network: like `sbr_network_changed`,
/// but hysteria2 connections migrate to the new path instead of dropping.
/// Returns at once; the migration runs on the engine's runtime.
///
/// # Safety
/// `instance` must be NULL or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_network_migrate(instance: *mut SbrInstance) {
    guard((), || {
        // SAFETY: NULL or live per the contract.
        let Some(i) = (unsafe { instance.as_ref() }) else {
            return;
        };
        let running = i.lock().running.as_ref().map(|r| (r.engine.clone(), r.handle.clone()));
        if let Some((engine, handle)) = running {
            handle.spawn(async move { engine.network_migrate().await });
        }
    })
}

/// Record panics and fatal signals to the file at `path` (appended), so the
/// host can report why the previous process died. Returns 0 on success.
///
/// # Safety
/// `path` NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_set_crash_file(path: *const c_char) -> i32 {
    guard(-1, || {
        // SAFETY: NULL or valid per the contract.
        match unsafe { str_arg(path) } {
            Some(p) if crash::install(p).is_ok() => 0,
            _ => -1,
        }
    })
}

/// Pin sbr's own sockets (servers, DNS, probes) to the physical interface
/// `name` (e.g. `en0`, `pdp_ip0`), or unpin with NULL. A Network Extension's
/// sockets bypass its tunnel only by the system's grace; with
/// `includeAllNetworks` that grace isn't guaranteed, and an unpinned socket
/// loops into the tunnel it is carrying. Process-wide, like `auto_route`'s
/// pinning on desktops.
///
/// # Safety
/// `name` NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_set_default_interface(name: *const c_char) {
    guard((), || {
        // SAFETY: NULL or valid per the contract.
        let name = unsafe { str_arg(name) }.filter(|n| !n.is_empty()).map(str::to_owned);
        tracing::info!(interface = name.as_deref().unwrap_or("none"), "outbound sockets bound");
        sbr_engine::sbr_core::dial::set_default_interface(name);
    })
}

/// # Safety
/// `config_json` NULL or a valid C string; `error_out` NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_tun_network_settings(
    config_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    let r = guard(Err("internal error (panic)".to_owned()), || {
        tun_settings::network_settings(&parse(unsafe { str_arg(config_json) })?).map(|v| v.to_string())
    });
    match r {
        Ok(s) => out_string(s),
        Err(e) => {
            if !error_out.is_null() {
                // SAFETY: checked non-null; caller owns the slot.
                unsafe { *error_out = out_string(e) };
            }
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sbr_find_tun_fd() -> i32 {
    guard(-1, || sys::find_utun_fd().unwrap_or(-1))
}

/// # Safety
/// `callback` NULL or a function that stays valid, with `context`, until the
/// next `sbr_set_log_callback`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_set_log_callback(callback: Option<log::LogFn>, context: *mut c_void) {
    guard((), || log::set_callback(callback, context))
}

/// # Safety
/// `s` must be NULL or a string returned by sbr.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: allocated by CString::into_raw in this crate.
        guard((), || drop(unsafe { CString::from_raw(s) }));
    }
}

#[cfg(test)]
mod tests;
