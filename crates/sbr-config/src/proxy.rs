//! V2Ray-family outbounds: `trojan`, `vless`, `vmess`
//! (sing-box `option/{trojan,vless,vmess}.go`).

use crate::obj::{Diag, Obj};
use crate::tls::{Multiplex, TlsOutbound, Transport, parse_multiplex, parse_tls, parse_transport};
use crate::{Dial, Error, Network, Result, ServerAddr, parse_dial, parse_server};

/// Fields every V2Ray-family outbound shares.
#[derive(Debug, Clone)]
pub struct V2rayCommon {
    pub server: ServerAddr,
    pub dial: Dial,
    /// `network`: empty means both TCP and UDP.
    pub network: Vec<Network>,
    pub tls: Option<TlsOutbound>,
    pub transport: Option<Transport>,
}

impl V2rayCommon {
    pub fn tcp(&self) -> bool {
        self.network.is_empty() || self.network.contains(&Network::Tcp)
    }
    pub fn udp(&self) -> bool {
        self.network.is_empty() || self.network.contains(&Network::Udp)
    }
    /// The TLS options if TLS is enabled.
    pub fn tls(&self) -> Option<&TlsOutbound> {
        self.tls.as_ref().filter(|t| t.enabled)
    }
}

#[derive(Debug, Clone)]
pub struct TrojanOutbound {
    pub common: V2rayCommon,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct VlessOutbound {
    pub common: V2rayCommon,
    pub uuid: String,
    /// `""` or `"xtls-rprx-vision"`.
    pub flow: Option<String>,
    pub packet_encoding: PacketEncoding,
}

#[derive(Debug, Clone)]
pub struct VmessOutbound {
    pub common: V2rayCommon,
    pub uuid: String,
    pub security: String,
    pub alter_id: u32,
    pub global_padding: bool,
    pub authenticated_length: bool,
    pub packet_encoding: PacketEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEncoding {
    /// Plain protocol UDP: one destination per connection.
    None,
    PacketAddr,
    Xudp,
}

/// sing-box `NetworkList`: `"tcp"`, `"udp"` or a list of them.
pub(crate) fn parse_network(o: &mut Obj) -> Result<Vec<Network>> {
    let path = o.sub("network");
    let names: Vec<String> = o.list("network")?;
    names
        .into_iter()
        .filter(|n| !n.is_empty())
        .map(|n| match n.as_str() {
            "tcp" => Ok(Network::Tcp),
            "udp" => Ok(Network::Udp),
            other => Err(Error::at(&path, format!("unknown network: {other}"))),
        })
        .collect()
}

fn common(o: &mut Obj, diag: &mut Diag) -> Result<V2rayCommon> {
    let server = parse_server(o)?;
    let dial = parse_dial(o, diag)?;
    let network = parse_network(o)?;
    let tls = parse_tls(o, "tls", diag)?;
    let transport = parse_transport(o, "transport")?;
    if matches!(transport, Some(Transport::Quic)) {
        return Err(Error::at(
            &format!("{}.type", o.sub("transport")),
            "quic transport not supported by sbr yet",
        ));
    }
    let mux = parse_multiplex(o, "multiplex")?;
    reject_multiplex(o, mux)?;
    Ok(V2rayCommon {
        server,
        dial,
        network,
        tls,
        transport,
    })
}

fn reject_multiplex(o: &Obj, m: Option<Multiplex>) -> Result<()> {
    match m {
        Some(m) if m.enabled => Err(Error::at(&o.sub("multiplex"), "not supported by sbr yet")),
        _ => Ok(()),
    }
}

fn packet_encoding(o: &mut Obj, default: PacketEncoding) -> Result<PacketEncoding> {
    let path = o.sub("packet_encoding");
    Ok(match o.opt::<String>("packet_encoding")?.as_deref() {
        None => default,
        Some("") => PacketEncoding::None,
        Some("xudp") => PacketEncoding::Xudp,
        Some("packetaddr") => PacketEncoding::PacketAddr,
        Some(other) => return Err(Error::at(&path, format!("unknown packet encoding: {other}"))),
    })
}

pub(crate) fn parse_trojan(o: &mut Obj, diag: &mut Diag) -> Result<TrojanOutbound> {
    let common = common(o, diag)?;
    let password = o.string("password")?.unwrap_or_default();
    Ok(TrojanOutbound { common, password })
}

pub(crate) fn parse_vless(o: &mut Obj, diag: &mut Diag) -> Result<VlessOutbound> {
    let common = common(o, diag)?;
    let uuid: String = o.req("uuid")?;
    let flow = o.string("flow")?;
    if let Some(f) = &flow
        && f != "xtls-rprx-vision"
    {
        return Err(Error::at(&o.sub("flow"), format!("unsupported flow: {f}")));
    }
    if flow.is_some() && common.tls().is_none() {
        return Err(Error::at(&o.sub("flow"), "xtls-rprx-vision requires tls"));
    }
    if flow.is_some() && common.transport.is_some() {
        return Err(Error::at(
            &o.sub("flow"),
            "xtls-rprx-vision does not work over a v2ray transport",
        ));
    }
    // sing-box: an absent `packet_encoding` means xudp for VLESS.
    let packet_encoding = packet_encoding(o, PacketEncoding::Xudp)?;
    Ok(VlessOutbound {
        common,
        uuid,
        flow,
        packet_encoding,
    })
}

pub(crate) fn parse_vmess(o: &mut Obj, diag: &mut Diag) -> Result<VmessOutbound> {
    let common = common(o, diag)?;
    let uuid: String = o.req("uuid")?;
    let security = o.string("security")?.unwrap_or_else(|| "auto".into());
    match security.as_str() {
        "auto" | "none" | "zero" | "aes-128-gcm" | "chacha20-poly1305" => {}
        "aes-128-cfb" => {
            return Err(Error::at(
                &o.sub("security"),
                "legacy aes-128-cfb is not supported by sbr (use an AEAD security)",
            ));
        }
        other => return Err(Error::at(&o.sub("security"), format!("unknown security: {other}"))),
    }
    let alter_id: u32 = o.get("alter_id")?;
    if alter_id != 0 {
        return Err(Error::at(
            &o.sub("alter_id"),
            "legacy (non-AEAD) VMess headers are not supported by sbr; use alter_id 0",
        ));
    }
    Ok(VmessOutbound {
        common,
        uuid,
        security,
        alter_id,
        global_padding: o.bool("global_padding")?,
        authenticated_length: o.bool("authenticated_length")?,
        packet_encoding: packet_encoding(o, PacketEncoding::None)?,
    })
}
