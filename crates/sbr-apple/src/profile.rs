//! Remote profile refresh from inside the tunnel.
//!
//! The download goes through the engine's own route rules (see
//! `sbr_engine::dispatch::Routed`), so it leaves through the tunnel's
//! outbounds like the device's other traffic: the profile host does not see
//! the device's address unless the rules send it `direct`, and a network
//! that blocks the host cannot block the update. It carries no
//! `User-Agent`. Applying a profile validates it before anything running is
//! touched.

use std::sync::Arc;

use sbr_engine::Engine;
use sbr_engine::fetch::Url;
use sbr_engine::sbr_config::{InboundKind, Options};

use crate::tun_settings;

/// Profiles with inline rule-sets run to a few hundred KiB; anything this
/// large is not a profile.
pub const MAX_SIZE: usize = 8 << 20;

/// The inbound host-originated connections are routed as: the `tun` one,
/// which is where the device's own traffic arrives.
pub fn host_inbound(options: &Options) -> (Arc<str>, &'static str) {
    options
        .inbounds
        .iter()
        .find(|i| matches!(i.kind, InboundKind::Tun(_)))
        .or(options.inbounds.first())
        .map_or(("".into(), "tun"), |i| (i.tag.as_str().into(), i.kind.type_name()))
}

pub async fn fetch(engine: &Engine, inbound: (Arc<str>, &'static str), url: &Url) -> Result<String, String> {
    let via = engine.routed(inbound.0, inbound.1);
    let r = engine
        .http()
        .anonymous()
        .get(&via, url, &[], MAX_SIZE)
        .await
        .map_err(|e| format!("profile download failed: {}", redact(&e)))?;
    String::from_utf8(r.body.to_vec()).map_err(|_| "profile is not UTF-8".to_owned())
}

/// The URL is a credential, and errors from the dial, DNS and TLS layers can
/// name the host (or a redirect target's). Only the HTTP client's own fixed
/// messages pass through; everything else is reduced to its kind.
fn redact(e: &std::io::Error) -> String {
    use std::io::ErrorKind;
    let msg = e.to_string();
    let fixed = msg.starts_with("unexpected status: ")
        || msg.starts_with("bad redirect from ")
        || [
            "too many redirects",
            "refusing a redirect from https to http",
            "HTTP request timed out",
        ]
        .contains(&msg.as_str());
    match e.kind() {
        _ if fixed => msg,
        ErrorKind::PermissionDenied => "rejected by route rules".to_owned(),
        ErrorKind::InvalidData => "TLS or HTTP protocol error".to_owned(),
        kind => kind.to_string(),
    }
}

/// What applying a profile did. Values match `SBR_PROFILE_*` in sbr.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Same text as the running config: nothing restarted.
    Unchanged = 0,
    Reloaded = 1,
    /// Valid, but its tun inbound asks for different interface settings:
    /// the host applies those, then calls `sbr_reload`. Nothing changed yet.
    NeedsNetworkSettings = 2,
}

/// True when `a` and `b` give the TUN different interface settings.
pub fn network_settings_differ(a: &Options, b: &Options) -> bool {
    tun_settings::network_settings(a).ok() != tun_settings::network_settings(b).ok()
}
