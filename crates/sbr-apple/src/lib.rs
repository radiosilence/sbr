//! C ABI for Apple platforms (and anything else that links C).
//!
//! Sized for the iOS Network Extension: a small multi-thread runtime and
//! 16 KiB relay buffers, so ~1k concurrent connections cost ~32 MB worst case
//! rather than blowing through the extension's memory ceiling.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};

pub struct SbrInstance {
    runtime: tokio::runtime::Runtime,
    instance: Option<Instance>,
}

const RELAY_BUFFER: usize = 16 * 1024;

fn worker_threads() -> usize {
    if cfg!(any(
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos"
    )) {
        2
    } else {
        std::thread::available_parallelism().map_or(4, |n| n.get().min(8))
    }
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

/// # Safety
/// `config_json` must be NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_check(config_json: *const c_char) -> *mut c_char {
    let r = catch_unwind(|| {
        let Some(json) = (unsafe { str_arg(config_json) }) else {
            return Some("config is NULL or not UTF-8".to_owned());
        };
        match Options::parse(json) {
            Ok(o) => sbr_engine::Engine::new(&o, &Settings::default())
                .err()
                .map(|e| e.to_string()),
            Err(e) => Some(e.to_string()),
        }
    });
    match r {
        Ok(None) => ptr::null_mut(),
        Ok(Some(e)) => out_string(e),
        Err(_) => out_string("internal error (panic)".into()),
    }
}

/// # Safety
/// String arguments must be NULL or valid C strings; `error_out` must be NULL
/// or a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_start(
    config_json: *const c_char,
    base_dir: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut SbrInstance {
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<Box<SbrInstance>, String> {
        let json = unsafe { str_arg(config_json) }.ok_or("config is NULL or not UTF-8")?;
        let options = Options::parse(json).map_err(|e| e.to_string())?;
        init_logging(&options);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads())
            .thread_name("sbr")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let settings = Settings {
            relay_buffer: RELAY_BUFFER,
            base_dir: unsafe { str_arg(base_dir) }.map(Into::into),
        };
        let instance = runtime
            .block_on(Instance::start(&options, settings))
            .map_err(|e| e.to_string())?;
        Ok(Box::new(SbrInstance {
            runtime,
            instance: Some(instance),
        }))
    }));
    let err = match r {
        Ok(Ok(b)) => return Box::into_raw(b),
        Ok(Err(e)) => e,
        Err(_) => "internal error (panic)".to_owned(),
    };
    if !error_out.is_null() {
        // SAFETY: checked non-null; caller owns the slot.
        unsafe { *error_out = out_string(err) };
    }
    ptr::null_mut()
}

/// # Safety
/// `instance` must come from `sbr_start` and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_stop(instance: *mut SbrInstance) {
    if instance.is_null() {
        return;
    }
    // SAFETY: ownership returns to us exactly once.
    let mut b = unsafe { Box::from_raw(instance) };
    if let Some(i) = b.instance.take() {
        let _g = b.runtime.enter();
        i.shutdown();
    }
    b.runtime
        .shutdown_timeout(std::time::Duration::from_secs(2));
}

fn instance_ref<'a>(p: *mut SbrInstance) -> Option<&'a Instance> {
    // SAFETY: caller contract: NULL or a live pointer from sbr_start.
    unsafe { p.as_ref() }.and_then(|b| b.instance.as_ref())
}

/// # Safety
/// `instance` must be live; strings NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_select(
    instance: *mut SbrInstance,
    group: *const c_char,
    member: *const c_char,
) -> i32 {
    let (Some(i), Some(g), Some(m)) = (instance_ref(instance), unsafe { str_arg(group) }, unsafe {
        str_arg(member)
    }) else {
        return 0;
    };
    i.engine
        .outbound(g)
        .and_then(|o| o.as_selector())
        .is_some_and(|s| s.select(m)) as i32
}

/// # Safety
/// `instance` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_groups(instance: *mut SbrInstance) -> *mut c_char {
    let Some(i) = instance_ref(instance) else {
        return ptr::null_mut();
    };
    let mut out = String::from("[");
    for (n, s) in i
        .engine
        .outbounds()
        .iter()
        .filter_map(|o| o.as_selector().map(|s| (o, s)))
        .enumerate()
    {
        if n > 0 {
            out.push(',');
        }
        let members: Vec<String> = s.1.members().map(json_str).collect();
        out.push_str(&format!(
            r#"{{"tag":{},"type":{},"selected":{},"members":[{}]}}"#,
            json_str(s.0.tag()),
            json_str(s.0.kind()),
            json_str(s.1.selected()),
            members.join(",")
        ));
    }
    out.push(']');
    out_string(out)
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
pub unsafe extern "C" fn sbr_stats(
    instance: *mut SbrInstance,
    up: *mut u64,
    down: *mut u64,
    active: *mut u64,
) {
    let Some(i) = instance_ref(instance) else {
        return;
    };
    let (u, d) = i.engine.traffic.snapshot();
    // SAFETY: each pointer is NULL or valid per the contract.
    unsafe {
        if let Some(p) = up.as_mut() {
            *p = u;
        }
        if let Some(p) = down.as_mut() {
            *p = d;
        }
        if let Some(p) = active.as_mut() {
            *p = i.engine.active_connections() as u64;
        }
    }
}

/// # Safety
/// `s` must be NULL or a string returned by sbr.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbr_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: allocated by CString::into_raw in this crate.
        drop(unsafe { CString::from_raw(s) });
    }
}

fn init_logging(o: &Options) {
    if o.log.disabled {
        return;
    }
    let level = match o.log.level.as_deref() {
        Some("trace") => tracing::Level::TRACE,
        Some("debug") => tracing::Level::DEBUG,
        Some("warn" | "warning") => tracing::Level::WARN,
        Some("error" | "fatal" | "panic") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    // stderr from a Network Extension lands in the unified log (Console.app).
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_over_the_c_abi() {
        let cfg = CString::new(
            r#"{"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}],
                "outbounds":[{"type":"selector","tag":"proxy","outbounds":["a","b"]},{"type":"direct","tag":"a"},{"type":"direct","tag":"b"}]}"#,
        )
        .unwrap();
        unsafe {
            assert!(sbr_check(cfg.as_ptr()).is_null());
            let bad = CString::new(r#"{"outbounds":[{"type":"warp-drive"}]}"#).unwrap();
            let e = sbr_check(bad.as_ptr());
            assert!(
                CStr::from_ptr(e)
                    .to_str()
                    .unwrap()
                    .contains("outbounds[0].type")
            );
            sbr_string_free(e);

            let mut err = ptr::null_mut();
            let i = sbr_start(cfg.as_ptr(), ptr::null(), &mut err);
            assert!(!i.is_null() && err.is_null());
            let (g, m) = (CString::new("proxy").unwrap(), CString::new("b").unwrap());
            assert_eq!(sbr_select(i, g.as_ptr(), m.as_ptr()), 1);
            let groups = sbr_groups(i);
            assert_eq!(
                CStr::from_ptr(groups).to_str().unwrap(),
                r#"[{"tag":"proxy","type":"selector","selected":"b","members":["a","b"]}]"#
            );
            sbr_string_free(groups);
            let mut active = 99;
            sbr_stats(i, ptr::null_mut(), ptr::null_mut(), &mut active);
            assert_eq!(active, 0);
            sbr_stop(i);
        }
    }
}
