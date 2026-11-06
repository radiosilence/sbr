//! The checks and the profile download the C ABI offers, as plain Rust, for
//! an app that links this crate directly (crates/sbr-gui).

use sbr_engine::fetch::Url;
use sbr_engine::sbr_config::{InboundKind, Options};
use sbr_engine::{Engine, Settings};

use crate::profile;

/// Ok when the config parses and an engine can be built from it; otherwise
/// the error, with its JSON path. `sbr_check` in sbr.h.
pub fn check(config: &str) -> Result<(), String> {
    let options = Options::parse(config).map_err(|e| e.to_string())?;
    Engine::new(&options, &Settings::default())
        .map(drop)
        .map_err(|e| e.to_string())
}

/// Options sbr ignores, and setups that send traffic or DNS outside the
/// tunnel. Empty for a config that does not parse. `sbr_check_warnings`.
pub fn warnings(config: &str) -> Vec<String> {
    Options::parse(config).map(|o| o.warnings).unwrap_or_default()
}

/// The config's `tun` inbound sets `strict_route`. False when there is no
/// tun inbound or the config does not parse.
pub fn strict_route(config: &str) -> bool {
    Options::parse(config).is_ok_and(|o| {
        o.inbounds
            .iter()
            .find_map(|i| match &i.kind {
                InboundKind::Tun(t) => Some(t.strict_route),
                _ => None,
            })
            .unwrap_or(false)
    })
}

/// Download a remote profile (https only) with the client the tunnel uses:
/// no `User-Agent`, cookies or cache, and errors that never name the host.
/// Blocks the calling thread. The text is not validated.
pub fn fetch_profile(url: &str) -> Result<String, String> {
    let url = Url::parse(url).ok_or("not a URL")?;
    if !url.https {
        return Err("profile links must use https".into());
    }
    fetch(url)
}

/// Outside a running tunnel there are no route rules to follow: the engine
/// of an empty config dials directly, by whatever route the system gives.
pub(crate) fn fetch(url: Url) -> Result<String, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let options = Options::parse("{}").map_err(|e| e.to_string())?;
        let engine = Engine::new(&options, &Settings::default()).map_err(|e| e.to_string())?;
        let inbound = profile::host_inbound(&options);
        profile::fetch(&engine, inbound, &url).await
    })
}
