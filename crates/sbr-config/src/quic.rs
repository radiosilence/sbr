//! `hysteria2` and `tuic` outbounds, and the QUIC knobs they share
//! (sing-box `option.QUICOptions`).

use std::time::Duration;

use serde_json::Value;

use crate::obj::{Diag, Obj};
use crate::tls::{TlsOutbound, parse_tls};
use crate::{Dial, Error, Network, Result, ServerAddr, parse_dial};

/// sing-box `QUICOptions` (which embeds `HTTP2Options`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicOptions {
    /// QUIC max idle timeout. sbr also closes a connection that has carried
    /// no stream or UDP session for this long.
    pub idle_timeout: Option<Duration>,
    pub keep_alive_period: Option<Duration>,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
    pub max_concurrent_streams: u32,
    pub initial_packet_size: u16,
    pub disable_path_mtu_discovery: bool,
    /// sbr extension, named after quic-go's
    /// `QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING`: send the ClientHello in
    /// the Initial packets unsplit.
    pub disable_client_hello_scrambling: bool,
}

#[derive(Debug, Clone)]
pub struct Hysteria2Outbound {
    /// `server_port` is 0 when only `server_ports` is given.
    pub server: ServerAddr,
    pub dial: Dial,
    /// Inclusive port ranges for port hopping.
    pub server_ports: Vec<(u16, u16)>,
    pub hop_interval: Option<Duration>,
    pub hop_interval_max: Option<Duration>,
    pub up_mbps: u32,
    pub down_mbps: u32,
    /// Salamander obfuscation password.
    pub obfs_salamander: Option<String>,
    pub password: String,
    pub network: Option<Network>,
    pub tls: TlsOutbound,
    pub quic: QuicOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TuicCongestion {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TuicUdpRelay {
    /// QUIC datagrams.
    #[default]
    Native,
    /// One unidirectional stream per packet.
    Quic,
    /// UDP-over-TCP v2 inside a TUIC stream (`udp_over_stream`).
    OverStream,
}

#[derive(Debug, Clone)]
pub struct TuicOutbound {
    pub server: ServerAddr,
    pub dial: Dial,
    pub uuid: [u8; 16],
    pub password: String,
    pub congestion_control: TuicCongestion,
    pub udp_relay: TuicUdpRelay,
    pub zero_rtt_handshake: bool,
    pub heartbeat: Option<Duration>,
    pub network: Option<Network>,
    pub tls: TlsOutbound,
    pub quic: QuicOptions,
}

/// The common QUIC fields, removed from `o`.
fn parse_quic(o: &mut Obj) -> Result<QuicOptions> {
    let q = QuicOptions {
        idle_timeout: o.duration("idle_timeout")?,
        keep_alive_period: o.duration("keep_alive_period")?,
        stream_receive_window: memory_bytes(o, "stream_receive_window")?,
        connection_receive_window: memory_bytes(o, "connection_receive_window")?,
        max_concurrent_streams: o.get("max_concurrent_streams")?,
        initial_packet_size: o.get("initial_packet_size")?,
        disable_path_mtu_discovery: o.bool("disable_path_mtu_discovery")?,
        disable_client_hello_scrambling: o.bool("disable_client_hello_scrambling")?,
    };
    if q.initial_packet_size != 0 && q.initial_packet_size < 1200 {
        return Err(Error::at(
            &o.sub("initial_packet_size"),
            "QUIC requires at least 1200 bytes",
        ));
    }
    Ok(q)
}

/// sing-box `byteformats.MemoryBytes`: an integer, or `"<n><unit>"` with a
/// case-insensitive binary unit (`k`, `kb`, `m`, `mb`, ...).
fn memory_bytes(o: &mut Obj, key: &str) -> Result<Option<u64>> {
    let path = o.sub(key);
    let Some(v) = o.raw(key) else { return Ok(None) };
    let bad = || Error::at(&path, "expected bytes like 8388608 or \"8MB\"");
    let n = match v {
        Value::Number(n) => n.as_u64().ok_or_else(bad)?,
        Value::String(s) => {
            let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(bad)?;
            if split == 0 {
                return Err(bad());
            }
            let n: u64 = s[..split].parse().map_err(|_| bad())?;
            let shift = match s[split..].trim().to_ascii_lowercase().as_str() {
                "b" => 0,
                "k" | "kb" => 10,
                "m" | "mb" => 20,
                "g" | "gb" => 30,
                "t" | "tb" => 40,
                _ => return Err(bad()),
            };
            n.checked_mul(1 << shift).ok_or_else(bad)?
        }
        _ => return Err(bad()),
    };
    Ok(if n == 0 { None } else { Some(n) })
}

/// `network`: a single `"tcp"` / `"udp"` restricts the outbound; both (or
/// absent) means both.
fn parse_network(o: &mut Obj) -> Result<Option<Network>> {
    let path = o.sub("network");
    let list: Vec<String> = o.list("network")?;
    let mut tcp = false;
    let mut udp = false;
    for n in &list {
        match n.as_str() {
            "tcp" => tcp = true,
            "udp" => udp = true,
            other => return Err(Error::at(&path, format!("unknown network {other:?}"))),
        }
    }
    Ok(match (tcp, udp) {
        (true, false) => Some(Network::Tcp),
        (false, true) => Some(Network::Udp),
        _ => None,
    })
}

/// QUIC always needs TLS 1.3; sing-box rejects a disabled `tls`.
fn parse_quic_tls(o: &mut Obj, diag: &mut Diag) -> Result<TlsOutbound> {
    let path = o.sub("tls");
    let tls = parse_tls(o, "tls", diag)?.unwrap_or_default();
    if !tls.enabled {
        return Err(Error::at(&path, "TLS is required"));
    }
    Ok(tls)
}

fn server(o: &mut Obj, port_required: bool) -> Result<ServerAddr> {
    let server: String = o.req("server")?;
    if server.is_empty() {
        return Err(Error::at(&o.sub("server"), "empty server address"));
    }
    let server_port: u16 = if port_required {
        o.req("server_port")?
    } else {
        o.get("server_port")?
    };
    Ok(ServerAddr { server, server_port })
}

/// sing-quic `ParsePorts`: `"start:end"`, with either side optional.
fn port_range(s: &str, path: &str) -> Result<(u16, u16)> {
    let bad = || Error::at(path, format!("bad port range {s:?}"));
    let (a, b) = s.split_once(':').ok_or_else(bad)?;
    let start = if a.is_empty() { 0 } else { a.parse().map_err(|_| bad())? };
    let end = if b.is_empty() {
        u16::MAX
    } else {
        b.parse().map_err(|_| bad())?
    };
    if start > end {
        return Err(bad());
    }
    Ok((start, end))
}

pub(crate) fn parse_hysteria2(o: &mut Obj, diag: &mut Diag) -> Result<Hysteria2Outbound> {
    let ports_path = o.sub("server_ports");
    let ports: Vec<String> = o.list("server_ports")?;
    let server_ports = ports
        .iter()
        .enumerate()
        .map(|(i, p)| port_range(p, &format!("{ports_path}[{i}]")))
        .collect::<Result<Vec<_>>>()?;
    let server = server(o, server_ports.is_empty())?;
    let dial = parse_dial(o, diag)?;
    let hop_interval = o.duration("hop_interval")?;
    let hop_interval_max = o.duration("hop_interval_max")?;
    if !server_ports.is_empty() {
        let (min, max) = match (hop_interval, hop_interval_max) {
            (None, None) => (Duration::from_secs(30), Duration::from_secs(30)),
            (Some(a), None) => (a, a),
            (None, Some(_)) => {
                return Err(Error::at(
                    &o.sub("hop_interval"),
                    "min and max hop interval must both be set",
                ));
            }
            (Some(a), Some(b)) => (a, b),
        };
        if min > max {
            return Err(Error::at(
                &o.sub("hop_interval"),
                "min hop interval must not be greater than max hop interval",
            ));
        }
        if min < Duration::from_secs(5) {
            return Err(Error::at(
                &o.sub("hop_interval"),
                "hop interval must be at least 5 seconds",
            ));
        }
    }
    let mut obfs_salamander = None;
    if let Some(v) = o.raw("obfs") {
        let mut ob = Obj::new(v, o.sub("obfs"))?;
        let ty = ob.string("type")?.unwrap_or_default();
        let password = ob.string("password")?;
        match ty.as_str() {
            "salamander" => {}
            "gecko" => return Err(Error::at(&ob.sub("type"), "gecko obfs is not supported by sbr yet")),
            other => return Err(Error::at(&ob.sub("type"), format!("unknown obfs type: {other:?}"))),
        }
        let password = password.ok_or_else(|| Error::at(&ob.sub("password"), "missing obfs password"))?;
        ob.finish()?;
        obfs_salamander = Some(password);
    }
    let up_mbps: i64 = o.get("up_mbps")?;
    let down_mbps: i64 = o.get("down_mbps")?;
    if up_mbps < 0 || down_mbps < 0 {
        return Err(Error::at(&o.sub("up_mbps"), "bandwidth must not be negative"));
    }
    let h = Hysteria2Outbound {
        server,
        dial,
        server_ports,
        hop_interval,
        hop_interval_max,
        up_mbps: up_mbps.try_into().unwrap_or(u32::MAX),
        down_mbps: down_mbps.try_into().unwrap_or(u32::MAX),
        obfs_salamander,
        password: o.string("password")?.unwrap_or_default(),
        network: parse_network(o)?,
        tls: parse_quic_tls(o, diag)?,
        quic: parse_quic(o)?,
    };
    // Knobs that only change how packets look or how BBR probes, never where
    // traffic goes.
    o.tolerate(diag, &["bbr_profile", "brutal_debug", "disable_chrome_parrot"]);
    if o.has("realm") {
        return Err(Error::at(&o.sub("realm"), "not supported by sbr yet"));
    }
    Ok(h)
}

/// RFC 4122 text form (`8-4-4-4-12`, any case).
fn parse_uuid(s: &str, path: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    // The UUID is the credential: never echo it into errors (they reach logs and the UI).
    let bad = || Error::at(path, "invalid uuid");
    if hex.len() != 32 || s.len() != 36 {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

pub(crate) fn parse_tuic(o: &mut Obj, diag: &mut Diag) -> Result<TuicOutbound> {
    let server = server(o, true)?;
    let dial = parse_dial(o, diag)?;
    let uuid_path = o.sub("uuid");
    let uuid = parse_uuid(&o.string("uuid")?.unwrap_or_default(), &uuid_path)?;
    let cc_path = o.sub("congestion_control");
    let congestion_control = match o.string("congestion_control")?.as_deref() {
        None | Some("cubic") => TuicCongestion::Cubic,
        Some("new_reno") => TuicCongestion::NewReno,
        Some("bbr") => TuicCongestion::Bbr,
        Some(other) => {
            return Err(Error::at(
                &cc_path,
                format!("unknown congestion control algorithm: {other}"),
            ));
        }
    };
    let mode_path = o.sub("udp_relay_mode");
    let mode = o.string("udp_relay_mode")?;
    let over_stream = o.bool("udp_over_stream")?;
    if over_stream && mode.is_some() {
        return Err(Error::at(&mode_path, "udp_over_stream is conflict with udp_relay_mode"));
    }
    let udp_relay = match mode.as_deref() {
        _ if over_stream => TuicUdpRelay::OverStream,
        None | Some("native") => TuicUdpRelay::Native,
        Some("quic") => TuicUdpRelay::Quic,
        Some(other) => return Err(Error::at(&mode_path, format!("unknown udp_relay_mode {other:?}"))),
    };
    Ok(TuicOutbound {
        server,
        dial,
        uuid,
        password: o.string("password")?.unwrap_or_default(),
        congestion_control,
        udp_relay,
        zero_rtt_handshake: o.bool("zero_rtt_handshake")?,
        heartbeat: o.duration("heartbeat")?,
        network: parse_network(o)?,
        tls: parse_quic_tls(o, diag)?,
        quic: parse_quic(o)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(v: &str) -> Obj {
        Obj::new(serde_json::from_str(v).unwrap(), "o").unwrap()
    }

    #[test]
    fn bytes_and_ranges() {
        let mut o = obj(r#"{"a":"8MB","b":1024,"c":"16 kb","d":"x"}"#);
        assert_eq!(memory_bytes(&mut o, "a").unwrap(), Some(8 << 20));
        assert_eq!(memory_bytes(&mut o, "b").unwrap(), Some(1024));
        assert_eq!(memory_bytes(&mut o, "c").unwrap(), Some(16 << 10));
        assert!(memory_bytes(&mut o, "d").is_err());
        assert_eq!(port_range("1000:2000", "p").unwrap(), (1000, 2000));
        assert_eq!(port_range("1000:", "p").unwrap(), (1000, 65535));
        assert!(port_range("1000", "p").is_err());
        assert!(port_range("3:2", "p").is_err());
        assert_eq!(
            parse_uuid("2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365", "u").unwrap()[..2],
            [0x2d, 0xd6]
        );
        assert!(parse_uuid("2DD61D93", "u").is_err());
    }
}
