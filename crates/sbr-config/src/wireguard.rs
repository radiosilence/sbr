//! The `wireguard` endpoint (`endpoints[]`, sing-box 1.11+).

use std::time::Duration;

use base64::Engine as _;
use ipnet::IpNet;

use crate::obj::{Diag, Obj};
use crate::{Dial, Error, Result, parse_dial, prefixes};

/// sing-box's default MTU for the WireGuard device.
pub const WIREGUARD_DEFAULT_MTU: u32 = 1408;

#[derive(Debug, Clone)]
pub struct WireGuardEndpoint {
    pub mtu: u32,
    /// Local tunnel addresses (prefixes; only the address part matters).
    pub address: Vec<IpNet>,
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub peers: Vec<WireGuardPeer>,
    pub udp_timeout: Option<Duration>,
    /// wireguard-go worker count; sbr uses it as a hint (see the engine).
    pub workers: u32,
    pub dial: Dial,
}

#[derive(Debug, Clone)]
pub struct WireGuardPeer {
    /// Server host; `None` for a peer that only ever contacts us.
    pub address: Option<String>,
    pub port: u16,
    pub public_key: [u8; 32],
    pub pre_shared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive_interval: u16,
    /// Bytes 1..4 of every message (Cloudflare WARP client id).
    pub reserved: [u8; 3],
}

fn key32(path: &str, s: &str) -> Result<[u8; 32]> {
    let b = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| Error::at(path, format!("invalid base64 key: {e}")))?;
    b.try_into()
        .map_err(|b: Vec<u8>| Error::at(path, format!("key must be 32 bytes, got {}", b.len())))
}

pub(crate) fn parse_wireguard(o: &mut Obj, diag: &mut Diag) -> Result<WireGuardEndpoint> {
    if o.bool("system")? {
        return Err(Error::at(
            &o.sub("system"),
            "system WireGuard interfaces are not supported by sbr; it always runs userspace",
        ));
    }
    let path = o.sub("private_key");
    let private_key = key32(
        &path,
        &o.string("private_key")?
            .ok_or_else(|| Error::at(&path, "missing private key"))?,
    )?;
    let address = prefixes(o, "address")?;
    let mtu = o
        .opt::<u32>("mtu")?
        .filter(|m| *m != 0)
        .unwrap_or(WIREGUARD_DEFAULT_MTU);
    if !(576..=65535).contains(&mtu) {
        return Err(Error::at(&o.sub("mtu"), format!("invalid MTU {mtu}")));
    }
    let listen_port: u16 = o.get("listen_port")?;
    let udp_timeout = o.duration("udp_timeout")?;
    let workers: i64 = o.get("workers")?;
    // Interface name only matters for `system`; NAT behaviour knobs apply to
    // flows the peer opens towards us, which sbr refuses (see the engine).
    o.tolerate(
        diag,
        &["name", "udp_mapping", "udp_filtering", "udp_nat_max", "on_demand"],
    );
    let dial = parse_dial(o, diag)?;
    if dial.detour.is_some() && listen_port != 0 {
        return Err(Error::at(
            &o.sub("listen_port"),
            "`listen_port` is conflict with `detour`",
        ));
    }
    let mut peers = Vec::new();
    let peers_path = o.sub("peers");
    let raw: Vec<serde_json::Value> = o.get("peers")?;
    for (i, v) in raw.into_iter().enumerate() {
        let mut p = Obj::new(v, format!("{peers_path}[{i}]"))?;
        let pk_path = p.sub("public_key");
        let public_key = key32(&pk_path, &p.string("public_key")?.unwrap_or_default())?;
        let psk_path = p.sub("pre_shared_key");
        let pre_shared_key = p.string("pre_shared_key")?.map(|s| key32(&psk_path, &s)).transpose()?;
        let allowed_ips = prefixes(&mut p, "allowed_ips")?;
        if allowed_ips.is_empty() {
            return Err(Error::at(
                &p.sub("allowed_ips"),
                format!("missing allowed ips for peer {i}"),
            ));
        }
        let reserved_path = p.sub("reserved");
        let reserved_raw: Vec<u8> = p.get("reserved")?;
        let reserved = match reserved_raw.len() {
            0 => [0; 3],
            3 => [reserved_raw[0], reserved_raw[1], reserved_raw[2]],
            n => {
                return Err(Error::at(
                    &reserved_path,
                    format!("invalid reserved value for peer {i}, required 3 bytes, got {n}"),
                ));
            }
        };
        let peer = WireGuardPeer {
            address: p.string("address")?,
            port: p.get("port")?,
            public_key,
            pre_shared_key,
            allowed_ips,
            persistent_keepalive_interval: p.get("persistent_keepalive_interval")?,
            reserved,
        };
        if peer.address.is_some() && peer.port == 0 {
            return Err(Error::at(&p.sub("port"), "missing peer port"));
        }
        p.finish()?;
        peers.push(peer);
    }
    if peers.is_empty() {
        return Err(Error::at(&peers_path, "missing peers"));
    }
    if address.is_empty() {
        return Err(Error::at(&o.sub("address"), "missing local address"));
    }
    Ok(WireGuardEndpoint {
        mtu,
        address,
        private_key,
        listen_port,
        peers,
        udp_timeout,
        workers: workers.clamp(0, 64) as u32,
        dial,
    })
}
