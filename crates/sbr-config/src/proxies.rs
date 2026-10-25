//! ShadowTLS, AnyTLS, and the small shared pieces (`network`, `udp_over_tcp`).

use std::time::Duration;

use serde_json::Value;

use crate::obj::{Diag, Obj};
use crate::tls::parse_tls;
use crate::{Dial, Error, Network, Result, ServerAddr, TlsOutbound, parse_dial, parse_server};

/// sing-box `udp_over_tcp`: `true` or `{"enabled":true,"version":1|2}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpOverTcp {
    /// 1 (legacy) or 2.
    pub version: u8,
}

pub(crate) fn parse_uot(o: &mut Obj, key: &str) -> Result<Option<UdpOverTcp>> {
    let path = o.sub(key);
    match o.raw(key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(b.then_some(UdpOverTcp { version: 2 })),
        Some(v) => {
            let mut u = Obj::new(v, path)?;
            let enabled = u.bool("enabled")?;
            let version: u8 = u.get("version")?;
            let version = match version {
                0 | 2 => 2,
                1 => 1,
                v => return Err(Error::at(&u.sub("version"), format!("unknown UoT version {v}"))),
            };
            u.finish()?;
            Ok(enabled.then_some(UdpOverTcp { version }))
        }
    }
}

/// sing-box `NetworkList`: `"tcp"`, `"udp"` or a list of them. `None` means both.
pub(crate) fn parse_network_list(o: &mut Obj, key: &str) -> Result<Option<Network>> {
    let path = o.sub(key);
    let items: Vec<String> = o.list(key)?;
    let (mut tcp, mut udp) = (false, false);
    for n in &items {
        match n.as_str() {
            "tcp" => tcp = true,
            "udp" => udp = true,
            "" => {}
            other => return Err(Error::at(&path, format!("unknown network: {other}"))),
        }
    }
    Ok(match (tcp, udp) {
        (true, false) => Some(Network::Tcp),
        (false, true) => Some(Network::Udp),
        _ => None,
    })
}

#[derive(Debug, Clone)]
pub struct ShadowTlsOutbound {
    pub server: ServerAddr,
    pub dial: Dial,
    /// 1, 2 or 3.
    pub version: u8,
    pub password: String,
    pub tls: TlsOutbound,
}

fn require_tls(o: &mut Obj, diag: &mut Diag) -> Result<TlsOutbound> {
    match parse_tls(o, "tls", diag)? {
        Some(t) if t.enabled => Ok(t),
        _ => Err(Error::at(&o.sub("tls"), "TLS required")),
    }
}

pub(crate) fn parse_shadowtls(o: &mut Obj, diag: &mut Diag) -> Result<ShadowTlsOutbound> {
    let server = parse_server(o)?;
    let dial = parse_dial(o, diag)?;
    let version: u8 = o.get("version")?;
    let version = match version {
        0 | 1 => 1,
        2 | 3 => version,
        v => return Err(Error::at(&o.sub("version"), format!("unknown protocol version: {v}"))),
    };
    let password = o.string("password")?.unwrap_or_default();
    let mut tls = require_tls(o, diag)?;
    if version == 1 {
        // sing-box pins v1 to TLS 1.2: the protocol relays the raw handshake.
        tls.min_version = Some("1.2".into());
        tls.max_version = Some("1.2".into());
    }
    Ok(ShadowTlsOutbound {
        server,
        dial,
        version,
        password,
        tls,
    })
}

#[derive(Debug, Clone)]
pub struct AnyTlsOutbound {
    pub server: ServerAddr,
    pub dial: Dial,
    pub tls: TlsOutbound,
    pub password: String,
    pub idle_session_check_interval: Option<Duration>,
    pub idle_session_timeout: Option<Duration>,
    pub min_idle_session: u32,
    pub client_metadata: Option<String>,
}

pub(crate) fn parse_anytls(o: &mut Obj, diag: &mut Diag) -> Result<AnyTlsOutbound> {
    let server = parse_server(o)?;
    let dial = parse_dial(o, diag)?;
    if dial.tcp_fast_open {
        return Err(Error::at(
            &o.sub("tcp_fast_open"),
            "tcp_fast_open is not supported with anytls outbound",
        ));
    }
    let tls = require_tls(o, diag)?;
    let min_idle: i64 = o.get("min_idle_session")?;
    Ok(AnyTlsOutbound {
        server,
        dial,
        tls,
        password: o.string("password")?.unwrap_or_default(),
        idle_session_check_interval: o.duration("idle_session_check_interval")?,
        idle_session_timeout: o.duration("idle_session_timeout")?,
        min_idle_session: min_idle.clamp(0, u32::MAX as i64) as u32,
        client_metadata: o.string("client_metadata")?,
    })
}
