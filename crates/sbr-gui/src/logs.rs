//! The tunnel's recent log lines, polled from the extension's memory every
//! two seconds while the logs page shows and the tunnel is up, and kept in
//! the app's caches so they outlive the tunnel and the app: the lines
//! before a failure are the useful ones. TunnelModel's pollLogs.

use std::path::PathBuf;
use std::time::Duration;

use koan_kit::app::*;
use objc2_foundation::{NSBundle, NSSearchPathDirectory, NSSearchPathDomainMask, NSSearchPathForDirectoriesInDomains};

use crate::install::{Vpn, VpnEvent};
use crate::ne::Status;
use crate::proto::Request;
use crate::tunnel::Tunnel;

const POLL: Duration = Duration::from_secs(2);

pub struct Logs {
    /// Oldest first.
    pub lines: Vec<String>,
    tunnel: Entity<Tunnel>,
    demo: bool,
    poll: Option<Task<()>>,
    _forget: Subscription,
}

/// Delete the cached lines: TunnelModel's forgetActive and erase do, with
/// the profile or the install they came from.
pub fn remove_cache() {
    if let Some(file) = cache_file() {
        let _ = std::fs::remove_file(file);
    }
}

/// `<caches>/<bundle id>/tunnel-logs.json`.
fn cache_file() -> Option<PathBuf> {
    let dirs = NSSearchPathForDirectoriesInDomains(
        NSSearchPathDirectory::CachesDirectory,
        NSSearchPathDomainMask::UserDomainMask,
        true,
    );
    let caches = PathBuf::from(dirs.firstObject()?.to_string());
    let id = NSBundle::mainBundle()
        .bundleIdentifier()
        .map_or_else(|| "cc.blit.sbr".to_owned(), |s| s.to_string());
    Some(caches.join(id).join("tunnel-logs.json"))
}

impl Logs {
    pub fn new(tunnel: Entity<Tunnel>, vpn: &Entity<Vpn>, cx: &mut Context<Self>) -> Self {
        let demo = std::env::var_os("SBR_GUI_DEMO").is_some();
        let lines = if demo {
            demo_lines()
        } else {
            cache_file()
                .and_then(|f| std::fs::read(f).ok())
                .and_then(|d| serde_json::from_slice(&d).ok())
                .unwrap_or_default()
        };
        let _forget = cx.subscribe(vpn, |logs, _, e: &VpnEvent, cx| match e {
            VpnEvent::ForgotActive => logs.clear(cx),
        });
        Logs {
            lines,
            tunnel,
            demo,
            poll: None,
            _forget,
        }
    }

    pub fn connected(&self, cx: &App) -> bool {
        self.demo || self.tunnel.read(cx).status == Status::On
    }

    pub fn set_shown(&mut self, shown: bool, cx: &mut Context<Self>) {
        if !shown {
            self.poll = None;
            return;
        }
        if self.poll.is_some() || self.demo {
            return;
        }
        self.poll = Some(cx.spawn(async move |this, cx| {
            loop {
                let Ok(manager) = this.read_with(cx, |l, cx| {
                    let t = l.tunnel.read(cx);
                    t.manager().filter(|_| t.status == Status::On)
                }) else {
                    return;
                };
                if let Some(m) = manager
                    && let Ok(Some(lines)) = m.send(&Request::Logs {}).await.map(|r| r.logs)
                {
                    let alive = this.update(cx, |l, cx| {
                        if lines != l.lines {
                            l.lines = lines;
                            l.save();
                            cx.notify();
                        }
                    });
                    if alive.is_err() {
                        return;
                    }
                }
                cx.background_executor().timer(POLL).await;
            }
        }));
    }

    fn save(&self) {
        let Some(file) = cache_file() else {
            return;
        };
        if let (Some(dir), Ok(data)) = (file.parent(), serde_json::to_vec(&self.lines)) {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::write(file, data);
        }
    }

    fn clear(&mut self, cx: &mut Context<Self>) {
        self.lines.clear();
        remove_cache();
        cx.notify();
    }
}

/// How a line reads: an error, a warning, or the rest.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Level {
    Error,
    Warn,
    Other,
}

pub fn level(line: &str) -> Level {
    if line.contains("ERROR") || line.contains(" error ") {
        Level::Error
    } else if line.contains("WARN") || line.contains(" warn ") {
        Level::Warn
    } else {
        Level::Other
    }
}

fn demo_lines() -> Vec<String> {
    [
        "12:00:01 INFO sbr 0.2.8 starting",
        "12:00:01 INFO inbound/tun[tun-in]: started at utun4",
        "12:00:02 INFO outbound/urltest[auto]: hk-01 38ms",
        "12:00:04 WARN outbound/vless[sg-01]: handshake slow: 1.2s",
        "12:00:09 INFO router: api.github.com via jp-02",
        "12:00:15 ERROR outbound/vless[sg-01]: connect: connection refused",
        "12:00:15 INFO failover[proxy]: sg-01 down, retry in 30s",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        assert_eq!(level("12:00 ERROR x"), Level::Error);
        assert_eq!(level("a error b"), Level::Error);
        assert_eq!(level("12:00 WARN x"), Level::Warn);
        assert_eq!(level("12:00 INFO x"), Level::Other);
    }
}
