//! The unified log, and the last log lines kept in memory for the app.

use std::collections::VecDeque;
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use objc2_foundation::NSBundle;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }

    fn of_core(level: i32) -> Self {
        match level {
            0 => Level::Trace,
            1 => Level::Debug,
            3 => Level::Warn,
            4 => Level::Error,
            _ => Level::Info,
        }
    }
}

// os_log_type_t.
const OS_LOG_TYPE_DEFAULT: u8 = 0x00;
const OS_LOG_TYPE_INFO: u8 = 0x01;
const OS_LOG_TYPE_DEBUG: u8 = 0x02;
const OS_LOG_TYPE_ERROR: u8 = 0x10;

unsafe extern "C" {
    fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
    fn sbr_tunnel_os_log(log: *mut c_void, kind: u8, public_part: *const c_char, private_part: *const c_char);
}

/// An `os_log_t` for one category of the extension's subsystem (its bundle
/// identifier, as Swift's `Logger` used).
pub struct Logger(*mut c_void);

// SAFETY: os_log handles are immutable and usable from any thread.
unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}

impl Logger {
    fn new(category: &str) -> Self {
        let subsystem = NSBundle::mainBundle()
            .bundleIdentifier()
            .map_or_else(|| "sbr".to_owned(), |s| s.to_string());
        let subsystem = CString::new(subsystem).unwrap_or_default();
        let category = CString::new(category).unwrap_or_default();
        // SAFETY: valid C strings; the handle is never released, as Swift's
        // static loggers are not.
        Logger(unsafe { os_log_create(subsystem.as_ptr(), category.as_ptr()) })
    }

    /// Log `public_part` as is and `private_part` redacted (unless a profile
    /// or a debugger allows it), as one message.
    pub fn log(&self, level: Level, public_part: &str, private_part: &str) {
        let kind = match level {
            Level::Trace | Level::Debug => OS_LOG_TYPE_DEBUG,
            Level::Info => OS_LOG_TYPE_INFO,
            // Swift's `Logger.warning` and `.error` are both the error type.
            Level::Warn | Level::Error => OS_LOG_TYPE_ERROR,
        };
        self.raw(kind, public_part, private_part);
    }

    fn raw(&self, kind: u8, public_part: &str, private_part: &str) {
        let c = |s: &str| CString::new(s.replace('\0', " ")).unwrap_or_default();
        let (p, q) = (c(public_part), c(private_part));
        // SAFETY: a handle from os_log_create and two C strings.
        unsafe { sbr_tunnel_os_log(self.0, kind, p.as_ptr(), q.as_ptr()) };
    }

    pub fn info(&self, s: &str) {
        self.log(Level::Info, s, "");
    }

    pub fn debug(&self, s: &str) {
        self.log(Level::Debug, s, "");
    }
}

/// The provider's own messages.
pub fn tunnel() -> &'static Logger {
    static L: OnceLock<Logger> = OnceLock::new();
    L.get_or_init(|| Logger::new("tunnel"))
}

/// The core's messages, forwarded from `sbr-apple`'s log callback.
fn core() -> &'static Logger {
    static L: OnceLock<Logger> = OnceLock::new();
    L.get_or_init(|| Logger::new("core"))
}

/// Send the core's logs to the recent lines and to the unified log. Its
/// messages name destinations, so they are private there.
pub fn forward_core_logs() {
    unsafe extern "C" fn on_log(level: i32, message: *const c_char, _: *mut c_void) {
        if message.is_null() {
            return;
        }
        // SAFETY: sbr passes a valid C string for the duration of the call.
        let message = unsafe { CStr::from_ptr(message) }.to_string_lossy();
        let level = Level::of_core(level);
        append(level, &message);
        let kind = match level {
            Level::Trace | Level::Debug => OS_LOG_TYPE_DEBUG,
            Level::Info => OS_LOG_TYPE_INFO,
            Level::Warn => OS_LOG_TYPE_DEFAULT,
            Level::Error => OS_LOG_TYPE_ERROR,
        };
        core().raw(kind, "", &message);
    }
    sbr_apple::api::set_log_callback(Some(on_log), std::ptr::null_mut());
}

const CAPACITY: usize = 1000;

static RECENT: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Keep a line for the app's log view: memory only, never written to disk
/// except the short tail kept for an abnormal end.
pub fn append(level: Level, message: &str) {
    let line = format!("{} {} {}", clock(SystemTime::now()), level.tag(), message);
    let mut lines = RECENT.lock().unwrap_or_else(|e| e.into_inner());
    lines.push_back(line);
    while lines.len() > CAPACITY {
        lines.pop_front();
    }
}

pub fn snapshot() -> Vec<String> {
    RECENT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect()
}

/// Local time as `HH:mm:ss`.
fn clock(t: SystemTime) -> String {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs()) as libc::time_t;
    // SAFETY: localtime_r writes only into `tm`.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return "--:--:--".into();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// UTC as ISO 8601 (`2026-11-06T15:02:17Z`), as `ISO8601DateFormatter` writes.
pub fn iso8601(t: SystemTime) -> String {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn iso8601_matches_the_formatter() {
        assert_eq!(iso8601(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            iso8601(UNIX_EPOCH + Duration::from_secs(1_793_977_337)),
            "2026-11-06T15:02:17Z"
        );
        assert_eq!(
            iso8601(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29T00:00:00Z"
        );
    }

    #[test]
    fn recent_lines_are_capped() {
        for i in 0..CAPACITY + 5 {
            append(Level::Info, &i.to_string());
        }
        let lines = snapshot();
        assert_eq!(lines.len(), CAPACITY);
        assert!(lines.last().unwrap().ends_with(&format!("info {}", CAPACITY + 4)));
    }
}
