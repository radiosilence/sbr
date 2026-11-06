//! The same operations as the C ABI, for Rust hosts such as the packet
//! tunnel provider in `sbr-tunnel-ext`. Every call catches panics, as the C
//! entry points do, because the host is usually an Objective-C callback that
//! must not unwind.

use std::path::PathBuf;
use std::sync::Mutex;

use sbr_engine::fetch::Url;

pub use crate::SbrRuntimeStats as RuntimeStats;
pub use crate::log::LogFn;
pub use crate::profile::Applied;
use crate::{Inner, Launch, SbrInstance, guard, parse};

/// `SbrStartOptions`, with Rust types.
#[derive(Clone, Debug, Default)]
pub struct StartOptions {
    /// Resolves relative paths in the config (cache file, local rule-sets).
    pub base_dir: Option<PathBuf>,
    /// The utun fd from [`find_tun_fd`]; none for no TUN.
    pub tun_fd: Option<i32>,
    /// 0: platform default (1 on iOS/tvOS). 1: single-threaded runtime.
    pub threads: i32,
    /// Per-direction relay buffer; 0: platform default.
    pub relay_buffer: u32,
    /// Connection cap; none: platform default; 0: no cap.
    pub max_connections: Option<u32>,
}

/// A running sbr core. Stopped when dropped.
pub struct Sbr(SbrInstance);

const PANIC: &str = "internal error (panic)";

impl Sbr {
    pub fn start(config: &str, o: StartOptions) -> Result<Self, String> {
        guard(Err(PANIC.to_owned()), || {
            crate::log::install();
            crate::ignore_sigpipe();
            let launch = Launch {
                base_dir: o.base_dir,
                tun_fd: o.tun_fd,
                flavor: crate::runtime::Flavor::from_threads(o.threads),
                relay_buffer: crate::relay_buffer(o.relay_buffer),
                max_connections: o.max_connections.unwrap_or(crate::default_max_connections()) as usize,
            };
            let options = parse(Some(config))?;
            let inbound = crate::profile::host_inbound(&options);
            let running = launch.start(options)?;
            Ok(Sbr(SbrInstance {
                inner: Mutex::new(Inner {
                    running: Some(running),
                    launch,
                    config: config.to_owned(),
                    inbound,
                }),
            }))
        })
    }

    /// Swap in a new config, keeping the TUN fd. An invalid config leaves the
    /// current one running.
    pub fn reload(&self, config: &str) -> Result<(), String> {
        guard(Err(PANIC.to_owned()), || {
            let options = parse(Some(config))?;
            self.0.lock().swap(config, options)
        })
    }

    /// Run `config` unless it is already running; validated first.
    pub fn apply(&self, config: &str) -> Result<Applied, String> {
        guard(Err(PANIC.to_owned()), || self.0.lock().apply_profile(config))
    }

    /// Download the profile at `url` (https only) through the running
    /// config's routing. `reply` runs once on an sbr thread, or is dropped
    /// uncalled if the engine stops first; it must not call back into this
    /// instance while holding up that thread.
    pub fn fetch_profile(
        &self,
        url: &str,
        reply: impl FnOnce(Result<String, String>) + Send + 'static,
    ) -> Result<(), String> {
        guard(Err(PANIC.to_owned()), || {
            let url = Url::parse(url)
                .filter(|u| u.https)
                .ok_or("profile links must use https")?;
            if self.0.fetch(url, reply) {
                Ok(())
            } else {
                Err("sbr is not running".to_owned())
            }
        })
    }

    pub fn select(&self, group: &str, member: &str) -> bool {
        guard(false, || {
            self.0.engine().is_some_and(|e| crate::select(&e, group, member))
        })
    }

    /// The groups as `sbr_groups` returns them.
    pub fn groups_json(&self) -> Option<String> {
        guard(None, || self.0.engine().map(|e| crate::groups_json(&e)))
    }

    pub fn url_test(&self, group: &str) -> bool {
        guard(false, || crate::url_test(&self.0, group))
    }

    /// The newest open connections as `sbr_connections` returns them, at
    /// most `limit` (capped at 200; 0 for the cap).
    pub fn connections_json(&self, limit: usize) -> Option<String> {
        guard(None, || {
            let limit = match limit {
                0 => crate::CONNECTIONS_LIMIT,
                n => n.min(crate::CONNECTIONS_LIMIT),
            };
            self.0.engine().map(|e| crate::connections_json(&e, limit))
        })
    }

    pub fn close_connection(&self, id: &str) -> bool {
        guard(false, || {
            self.0
                .engine()
                .and_then(|e| e.tracker.find(id))
                .map(|c| c.close())
                .is_some()
        })
    }

    /// Close every connection to `domain`, and its subdomains with
    /// `subdomains`. Returns how many closed.
    pub fn close_domain(&self, domain: &str, subdomains: bool) -> usize {
        guard(0, || {
            self.0
                .engine()
                .map_or(0, |e| e.tracker.close_domain(domain, subdomains))
        })
    }

    pub fn stats(&self) -> RuntimeStats {
        guard(RuntimeStats::default(), || crate::runtime_stats(Some(&self.0)))
    }

    /// The default network path changed: drop state bound to the old one.
    pub fn network_changed(&self) {
        guard((), || {
            if let Some(e) = self.0.engine() {
                e.network_changed();
            }
        })
    }

    /// The default path moved to another network: hysteria2 connections
    /// migrate to it, other path-bound state is dropped.
    pub fn network_migrate(&self) {
        guard((), || crate::network_migrate(&self.0))
    }
}

impl Drop for Sbr {
    fn drop(&mut self) {
        // Tear the runtime down here, inside a guard, rather than in the
        // field's own drop.
        guard((), || {
            self.0.lock().running = None;
        });
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// None when the config is valid, otherwise the error (with its JSON path).
pub fn check(config: &str) -> Option<String> {
    guard(Some(PANIC.to_owned()), || crate::check(Some(config)))
}

/// The network settings for the config's `tun` inbound, in the shape
/// `sbr_tun_network_settings` documents in sbr.h.
pub fn tun_network_settings(config: &str) -> Result<serde_json::Value, String> {
    guard(Err(PANIC.to_owned()), || {
        crate::tun_settings::network_settings(&parse(Some(config))?)
    })
}

/// The utun fd NetworkExtension opened for this process.
pub fn find_tun_fd() -> Option<i32> {
    guard(None, crate::sys::find_utun_fd)
}

/// Record panics and fatal signals to the file at `path`, appended.
pub fn set_crash_file(path: &str) -> bool {
    guard(false, || crate::crash::install(path).is_ok())
}

/// Pin sbr's own sockets to a physical interface, or unpin with none.
pub fn set_default_interface(name: Option<&str>) {
    guard((), || crate::set_default_interface(name))
}

/// Receive sbr's logs, as `sbr_set_log_callback`.
pub fn set_log_callback(callback: Option<LogFn>, context: *mut std::ffi::c_void) {
    guard((), || crate::log::set_callback(callback, context))
}
