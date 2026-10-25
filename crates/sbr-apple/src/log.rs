//! `tracing` → host log callback (Swift forwards it to `Logger`/os_log).
//!
//! One global subscriber for the process, installed on first use. Its level
//! is a reloadable `LevelFilter`, so disabled callsites stay free (tracing
//! caches "never" per callsite) and each `sbr_start`/`sbr_reload` can apply
//! the config's `log.level`.

use std::ffi::{CString, c_char, c_void};
use std::fmt::Write as _;
use std::sync::{OnceLock, RwLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry, reload};

/// `void (*)(int32_t level, const char *message, void *context)`.
pub type LogFn = unsafe extern "C" fn(level: i32, message: *const c_char, context: *mut c_void);

pub const TRACE: i32 = 0;
pub const DEBUG: i32 = 1;
pub const INFO: i32 = 2;
pub const WARN: i32 = 3;
pub const ERROR: i32 = 4;

struct Sink {
    f: LogFn,
    ctx: usize,
}

/// Held for reading while the callback runs, so once `set_callback` returns
/// the old context is never touched again (the host may free it).
static SINK: RwLock<Option<Sink>> = RwLock::new(None);
static LEVEL: OnceLock<reload::Handle<LevelFilter, Registry>> = OnceLock::new();

fn handle() -> &'static reload::Handle<LevelFilter, Registry> {
    LEVEL.get_or_init(|| {
        let (filter, handle) = reload::Layer::new(LevelFilter::INFO);
        // Fails only if the host process already installed a global
        // subscriber; then our events go wherever that one sends them.
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(CallbackLayer)
            .try_init();
        handle
    })
}

pub fn install() {
    handle();
}

pub fn set_callback(f: Option<LogFn>, ctx: *mut c_void) {
    install();
    *SINK.write().unwrap_or_else(|e| e.into_inner()) = f.map(|f| Sink { f, ctx: ctx as usize });
}

/// Apply a sing-box `log` section.
pub fn configure(log: &sbr_engine::sbr_config::LogOptions) {
    let level = if log.disabled {
        LevelFilter::OFF
    } else {
        match log.level.as_deref() {
            Some("trace") => LevelFilter::TRACE,
            Some("debug") => LevelFilter::DEBUG,
            Some("warn" | "warning") => LevelFilter::WARN,
            Some("error" | "fatal" | "panic") => LevelFilter::ERROR,
            _ => LevelFilter::INFO,
        }
    };
    let _ = handle().reload(level);
}

struct CallbackLayer;

impl<S: Subscriber> Layer<S> for CallbackLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Dependencies' chatter (rustls handshakes, h2 frames, events bridged
        // from the `log` crate) would bury sbr's own lines at debug level.
        let meta = event.metadata();
        if *meta.level() > Level::WARN
            && (meta.target() == "log"
                || ["rustls", "h2", "quinn", "hyper"]
                    .iter()
                    .any(|t| meta.target().starts_with(t)))
        {
            return;
        }
        let mut v = Message(String::new());
        event.record(&mut v);
        let level = match *event.metadata().level() {
            Level::TRACE => TRACE,
            Level::DEBUG => DEBUG,
            Level::INFO => INFO,
            Level::WARN => WARN,
            Level::ERROR => ERROR,
        };
        let sink = SINK.read().unwrap_or_else(|e| e.into_inner());
        match &*sink {
            Some(s) => {
                let Ok(msg) = CString::new(v.0.replace('\0', " ")) else {
                    return;
                };
                // SAFETY: the host registered `f` with this context and keeps
                // both valid until it replaces the callback.
                unsafe { (s.f)(level, msg.as_ptr(), s.ctx as *mut c_void) };
            }
            // stderr from a Network Extension lands in the unified log.
            None => eprintln!("{} {}", event.metadata().level(), v.0),
        }
    }
}

/// `message key=value ...`, the shape `tracing_subscriber::fmt` prints.
struct Message(String);

impl Visit for Message {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.insert_str(0, value);
        } else {
            let _ = write!(self.0, " {}={}", field.name(), value);
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.insert_str(0, &format!("{value:?}"));
        } else {
            let _ = write!(self.0, " {}={:?}", field.name(), value);
        }
    }
}
