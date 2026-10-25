//! C ABI for Apple platforms (and anything else that links C). The header is
//! `include/sbr.h`; keep the two in sync (`tests/c_abi.rs` checks names and
//! compiles a C program against the staticlib).
//!
//! Sized for the iOS Network Extension (~50 MB jetsam limit): a one-thread
//! runtime, 16 KiB relay buffers and a connection cap, so the worst case
//! stays well below the ceiling. Every entry point catches panics; nothing
//! unwinds into Swift.

mod log;
mod runtime;
mod sys;
mod tun_settings;

use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard};

use sbr_engine::sbr_config::Options;
use sbr_engine::{Engine, Settings};

use runtime::{Flavor, Running};

const MOBILE: bool = cfg!(any(target_os = "ios", target_os = "tvos", target_os = "visionos"));

/// Per-direction relay buffer: 2 × 16 KiB = 32 KiB per TCP connection.
const fn default_relay_buffer() -> usize {
    if MOBILE {
        16 * 1024
    } else {
        sbr_engine::sbr_core::relay::DEFAULT_BUFFER
    }
}

/// 512 connections × 32 KiB = 16 MB of relay buffers at worst, leaving room
/// under the extension's ~50 MB for the binary, TLS state and UDP sessions.
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
}

impl SbrInstance {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn engine(&self) -> Option<Arc<Engine>> {
        self.lock().running.as_ref().map(|r| r.engine.clone())
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
        let running = launch.start(parse(unsafe { str_arg(config_json) })?)?;
        Ok(Box::new(SbrInstance {
            inner: Mutex::new(Inner {
                running: Some(running),
                launch,
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
        let options = parse(unsafe { str_arg(config_json) })?;
        let mut inner = inst.lock();
        // Reject a bad config before touching the running one. Listeners and
        // the TUN can still fail at start; then the instance is left stopped.
        Engine::new(&options, &inner.launch.settings(None)).map_err(|e| e.to_string())?;
        inner.running = None;
        inner.running = Some(inner.launch.start(options)?);
        Ok(())
    });
    r.err().map_or(ptr::null_mut(), out_string)
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
        e.outbound(g).and_then(|o| o.as_group()).is_some_and(|s| s.select(m)) as i32
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
        let groups: Vec<String> = e
            .outbounds()
            .iter()
            .filter_map(|o| o.as_group().map(|g| (o, g)))
            .map(|(o, g)| {
                let members: Vec<String> = g.members().iter().map(|m| json_str(m.tag())).collect();
                format!(
                    r#"{{"tag":{},"type":{},"selected":{},"members":[{}]}}"#,
                    json_str(o.tag()),
                    json_str(o.kind()),
                    json_str(g.selected().tag()),
                    members.join(",")
                )
            })
            .collect();
        out_string(format!("[{}]", groups.join(",")))
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
