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

/// A Rust host's log sink: level, then the message split into a public part
/// and a private one (see [`Message`]).
pub type SplitLogFn = Box<dyn Fn(i32, &str, &str) + Send + Sync>;

enum Sink {
    C { f: LogFn, ctx: usize },
    Split(SplitLogFn),
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
    *SINK.write().unwrap_or_else(|e| e.into_inner()) = f.map(|f| Sink::C { f, ctx: ctx as usize });
}

pub fn set_split_callback(f: Option<SplitLogFn>) {
    install();
    *SINK.write().unwrap_or_else(|e| e.into_inner()) = f.map(Sink::Split);
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
        let mut v = Message::default();
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
            Some(Sink::C { f, ctx }) => {
                let Ok(msg) = CString::new(v.joined().replace('\0', " ")) else {
                    return;
                };
                // SAFETY: the host registered `f` with this context and keeps
                // both valid until it replaces the callback.
                unsafe { f(level, msg.as_ptr(), *ctx as *mut c_void) };
            }
            Some(Sink::Split(f)) => f(level, &v.public, &v.private),
            // stderr from a Network Extension lands in the unified log.
            None => eprintln!("{} {}", event.metadata().level(), v.joined()),
        }
    }
}

/// Fields that name no destination, domain, address or error text (tags
/// from the profile, such as `server` and `outbound`, name only its parts), so a
/// host may log them where others can read them (the unified log). Every
/// other field goes in the private part.
const PUBLIC_FIELDS: &[&str] = &[
    "closed",
    "connects_failed",
    "connects_ok",
    "consecutive",
    "down_kib",
    "group",
    "inbound",
    "interface",
    "limit",
    "migrated",
    "outbound",
    "qtype",
    "rcode",
    "reason",
    "retry_in",
    "rule_set",
    "server",
    "tag",
    "tcp",
    "tun_packets_in",
    "tun_read_errors",
    "udp",
    "udp_sessions",
    "udp_sessions_dropped",
    "up_kib",
    "verdict",
];

/// `message key=value ...`, the shape `tracing_subscriber::fmt` prints,
/// with the message and [`PUBLIC_FIELDS`] in `public` and the rest in
/// `private`.
#[derive(Default)]
struct Message {
    public: String,
    private: String,
}

impl Message {
    fn joined(&self) -> String {
        format!("{}{}", self.public, self.private)
    }

    fn field(&mut self, field: &Field, value: std::fmt::Arguments<'_>) {
        if field.name() == "message" {
            self.public.insert_str(0, &value.to_string());
        } else {
            let out = if PUBLIC_FIELDS.contains(&field.name()) {
                &mut self.public
            } else {
                &mut self.private
            };
            let _ = write!(out, " {}={}", field.name(), value);
        }
    }
}

impl Visit for Message {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.field(field, format_args!("{value}"));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.field(field, format_args!("{value:?}"));
    }
}
