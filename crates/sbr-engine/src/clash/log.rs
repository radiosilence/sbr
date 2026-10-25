//! `/logs`: a tracing layer that fans log lines out to API subscribers.
//! Formatting only happens while someone is subscribed.

use std::fmt::Write;
use std::sync::OnceLock;

use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub level: Level,
    pub message: String,
}

fn sender() -> &'static broadcast::Sender<LogEntry> {
    static TX: OnceLock<broadcast::Sender<LogEntry>> = OnceLock::new();
    TX.get_or_init(|| broadcast::channel(256).0)
}

pub fn subscribe() -> broadcast::Receiver<LogEntry> {
    sender().subscribe()
}

/// Add to the process's tracing subscriber so `/logs` has something to say.
pub fn layer() -> LogLayer {
    LogLayer
}

pub struct LogLayer;

struct Fields {
    message: String,
    rest: String,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.rest, " {}={value:?}", field.name());
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.rest, " {}={value}", field.name());
        }
    }
}

impl<S: Subscriber> tracing_subscriber::Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let tx = sender();
        if tx.receiver_count() == 0 {
            return;
        }
        let mut f = Fields {
            message: String::new(),
            rest: String::new(),
        };
        event.record(&mut f);
        f.message.push_str(&f.rest);
        let _ = tx.send(LogEntry {
            level: *event.metadata().level(),
            message: f.message,
        });
    }
}

/// sing-box `log.FormatLevel`.
pub fn level_name(l: Level) -> &'static str {
    match l {
        Level::TRACE => "trace",
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warn",
        Level::ERROR => "error",
    }
}

/// `?level=` as clash dashboards send it.
pub fn parse_level(s: &str) -> Option<Level> {
    Some(match s {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "" | "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "error" | "fatal" | "panic" | "silent" => Level::ERROR,
        _ => return None,
    })
}

/// Resident memory the OS charges us for: `phys_footprint` on Apple (what
/// jetsam counts in a network extension), RSS on Linux.
pub fn process_memory() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // statm: size resident shared ... in pages.
        let pages = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()))
            .unwrap_or(0);
        pages * 4096
    }
    #[cfg(target_vendor = "apple")]
    {
        unsafe extern "C" {
            fn proc_pid_rusage(pid: libc::c_int, flavor: libc::c_int, buffer: *mut libc::c_void) -> libc::c_int;
        }
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
        // SAFETY: `info` is large enough for the V2 flavor we ask for.
        let r = unsafe { proc_pid_rusage(libc::getpid(), libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast()) };
        if r == 0 {
            // SAFETY: filled by the successful call above.
            unsafe { info.assume_init() }.ri_phys_footprint
        } else {
            0
        }
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        0
    }
}
