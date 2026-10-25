//! `experimental`: the Clash API and the cache file.

use std::time::Duration;

use crate::obj::{Diag, Obj};
use crate::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct Experimental {
    pub clash_api: Option<ClashApiOptions>,
    /// Present only when `enabled`.
    pub cache_file: Option<CacheFileOptions>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClashApiOptions {
    /// `host:port`; empty disables the HTTP server (the clash mode still works).
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub external_ui_download_url: Option<String>,
    pub external_ui_download_detour: Option<String>,
    pub secret: Option<String>,
    pub default_mode: Option<String>,
    pub access_control_allow_origin: Vec<String>,
    pub access_control_allow_private_network: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheFileOptions {
    /// sing-box default `cache.db`, relative to the working directory.
    pub path: Option<String>,
    pub cache_id: Option<String>,
    pub store_fakeip: bool,
    pub store_dns: bool,
    /// Deprecated upstream in favour of `store_dns`, still honoured there.
    pub store_rdrc: bool,
    pub rdrc_timeout: Option<Duration>,
}

pub(crate) fn parse(mut o: Obj, diag: &mut Diag) -> Result<Experimental> {
    let clash_api = match o.raw("clash_api") {
        Some(v) => Some(parse_clash_api(Obj::new(v, "experimental.clash_api")?)?),
        None => None,
    };
    let cache_file = match o.raw("cache_file") {
        Some(v) => parse_cache_file(Obj::new(v, "experimental.cache_file")?, diag)?,
        None => None,
    };
    // Neither can change where traffic goes.
    o.tolerate(diag, &["v2ray_api", "debug"]);
    o.finish()?;
    Ok(Experimental { clash_api, cache_file })
}

fn parse_clash_api(mut o: Obj) -> Result<ClashApiOptions> {
    let c = ClashApiOptions {
        external_controller: o.string("external_controller")?,
        external_ui: o.string("external_ui")?,
        external_ui_download_url: o.string("external_ui_download_url")?,
        external_ui_download_detour: o.string("external_ui_download_detour")?,
        secret: o.string("secret")?,
        default_mode: o.string("default_mode")?,
        access_control_allow_origin: o.list("access_control_allow_origin")?,
        access_control_allow_private_network: o.bool("access_control_allow_private_network")?,
    };
    if let Some(addr) = &c.external_controller
        && split_host_port(addr).is_none()
    {
        return Err(Error::at(
            &o.sub("external_controller"),
            format!("expected host:port, got {addr:?}"),
        ));
    }
    // sing-box refuses these since 1.8 rather than ignoring them.
    for k in ["cache_file", "cache_id", "store_mode", "store_selected", "store_fakeip"] {
        if o.has(k) {
            return Err(Error::at(
                &o.sub(k),
                "deprecated in sing-box 1.8.0; use experimental.cache_file instead",
            ));
        }
    }
    o.finish()?;
    Ok(c)
}

fn parse_cache_file(mut o: Obj, diag: &mut Diag) -> Result<Option<CacheFileOptions>> {
    let enabled = o.bool("enabled")?;
    let c = CacheFileOptions {
        path: o.string("path")?,
        cache_id: o.string("cache_id")?,
        store_fakeip: o.bool("store_fakeip")?,
        store_dns: o.bool("store_dns")?,
        store_rdrc: o.bool("store_rdrc")?,
        rdrc_timeout: o.duration("rdrc_timeout")?,
    };
    // Write batching knobs; sbr writes through.
    o.tolerate(diag, &["buffer_size", "flush_interval"]);
    o.finish()?;
    Ok(enabled.then_some(c))
}

/// `host:port`, `[v6]:port` or `:port` (all interfaces), as Go's `net.Listen` takes it.
pub fn split_host_port(s: &str) -> Option<(&str, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = match host.strip_prefix('[') {
        Some(h) => h.strip_suffix(']')?,
        None if host.contains(':') => return None,
        None => host,
    };
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use crate::Options;

    #[test]
    fn parses_clash_api_and_cache_file() {
        let o = Options::parse(
            r#"{"experimental":{
                "clash_api":{"external_controller":"127.0.0.1:9090","secret":"s","default_mode":"Global",
                             "access_control_allow_origin":"http://x","access_control_allow_private_network":true},
                "cache_file":{"enabled":true,"path":"c.db","cache_id":"id","store_fakeip":true,"store_rdrc":true,"rdrc_timeout":"1h"}}}"#,
        )
        .unwrap();
        let c = o.experimental.clash_api.unwrap();
        assert_eq!(c.external_controller.as_deref(), Some("127.0.0.1:9090"));
        assert_eq!(c.access_control_allow_origin, ["http://x"]);
        let f = o.experimental.cache_file.unwrap();
        assert_eq!(f.path.as_deref(), Some("c.db"));
        assert!(f.store_rdrc && f.store_fakeip);
        assert_eq!(f.rdrc_timeout, Some(std::time::Duration::from_secs(3600)));
    }

    #[test]
    fn rejects_legacy_and_bad_fields() {
        let e = Options::parse(r#"{"experimental":{"clash_api":{"store_selected":true}}}"#).unwrap_err();
        assert!(
            e.to_string().starts_with("experimental.clash_api.store_selected:"),
            "{e}"
        );
        let e = Options::parse(r#"{"experimental":{"clash_api":{"external_controller":"nope"}}}"#).unwrap_err();
        assert!(
            e.to_string().starts_with("experimental.clash_api.external_controller:"),
            "{e}"
        );
        let e = Options::parse(r#"{"experimental":{"cache_file":{"enabled":true,"what":1}}}"#).unwrap_err();
        assert!(e.to_string().starts_with("experimental.cache_file.what:"), "{e}");
        let o = Options::parse(r#"{"experimental":{"cache_file":{"enabled":false}}}"#).unwrap();
        assert!(o.experimental.cache_file.is_none());
        assert_eq!(super::split_host_port(":9090"), Some(("", 9090)));
        assert_eq!(super::split_host_port("[::1]:9090"), Some(("::1", 9090)));
    }
}
