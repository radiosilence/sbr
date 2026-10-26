//! sing-box compatible configuration.
//!
//! The parser is strict in the same way sing-box is (unknown fields are
//! errors) so a config that loads here means the same thing it means there.
//! Anything sing-box understands that sbr doesn't yet is rejected with the
//! exact JSON path, rather than silently changing routing behaviour. The
//! only exceptions are knobs that cannot change *where* traffic goes; those
//! are accepted and reported in [`Options::warnings`].

mod dns;
mod experimental;
mod obj;
mod proxies;
mod proxy;
mod quic;
mod route;
pub mod srs;
mod tls;
pub mod types;
mod wireguard;
mod xhttp;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use obj::{Diag, Obj};
use serde_json::Value;

pub use dns::*;
pub use experimental::{CacheFileOptions, ClashApiOptions, Experimental, split_host_port};
pub use proxies::{AnyTlsOutbound, ShadowTlsOutbound, UdpOverTcp};
pub use proxy::{PacketEncoding, TrojanOutbound, V2rayCommon, VlessOutbound, VmessOutbound};
pub use quic::{Hysteria2Outbound, QuicOptions, TuicCongestion, TuicOutbound, TuicUdpRelay};
pub use route::*;
pub use srs::parse_rule_set;
pub use tls::{Ech, Multiplex, Reality, TlsOutbound, Transport, Utls};
pub use wireguard::{WIREGUARD_DEFAULT_MTU, WireGuardEndpoint, WireGuardPeer};
pub use xhttp::{PaddingMethod, Placement, Range, Xhttp, XhttpDownload, XhttpMode, Xmux, predefined_table};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{path}: {msg}")]
    At { path: String, msg: String },
}

impl Error {
    pub(crate) fn at(path: &str, msg: impl Into<String>) -> Self {
        Self::At {
            path: path.to_owned(),
            msg: msg.into(),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub log: LogOptions,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub route: RouteOptions,
    /// The `dns` section; `None` means the system resolver.
    pub dns: Option<DnsOptions>,
    /// `experimental`: clash API and cache file.
    pub experimental: Experimental,
    /// Non-fatal notes about accepted-but-ignored settings.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LogOptions {
    pub disabled: bool,
    pub level: Option<String>,
    pub output: Option<String>,
    pub timestamp: bool,
}

#[derive(Debug, Clone)]
pub struct Inbound {
    pub tag: String,
    pub kind: InboundKind,
}

#[derive(Debug, Clone)]
pub enum InboundKind {
    Mixed(ProxyInbound),
    Socks(ProxyInbound),
    Http(ProxyInbound),
    Tun(TunInbound),
}

impl InboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Mixed(_) => "mixed",
            Self::Socks(_) => "socks",
            Self::Http(_) => "http",
            Self::Tun(_) => "tun",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TunInbound {
    pub interface_name: Option<String>,
    pub mtu: Option<u32>,
    /// Interface prefixes, e.g. 172.19.0.1/30 and fdfe:dcba:9876::1/126.
    pub address: Vec<ipnet::IpNet>,
    pub auto_route: bool,
    pub strict_route: bool,
    pub route_address: Vec<ipnet::IpNet>,
    pub route_exclude_address: Vec<ipnet::IpNet>,
    pub loopback_address: Vec<IpAddr>,
    pub udp_timeout: Option<Duration>,
    pub stack: Option<TunStack>,
}

/// sing-box's `stack`. sbr has two TCP implementations, the kernel's (via
/// NAT) and its own userspace one; UDP takes the same path under every
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunStack {
    /// TCP terminated by the kernel.
    System,
    /// TCP terminated by sbr's userspace stack (sing-box: gVisor).
    Gvisor,
    /// sing-box: system TCP with gVisor UDP. sbr runs system TCP.
    Mixed,
}

#[derive(Debug, Clone)]
pub struct Listen {
    pub listen: IpAddr,
    pub listen_port: u16,
    pub tcp_fast_open: bool,
    pub tcp_keep_alive: Option<Duration>,
    pub disable_tcp_keep_alive: bool,
    pub udp_timeout: Option<Duration>,
}

#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct ProxyInbound {
    pub listen: Listen,
    pub users: Vec<User>,
}

#[derive(Debug, Clone)]
pub struct Outbound {
    pub tag: String,
    pub kind: OutboundKind,
}

#[derive(Debug, Clone)]
pub enum OutboundKind {
    Direct(Dial),
    Block,
    Socks(SocksOutbound),
    Http(HttpOutbound),
    Shadowsocks(ShadowsocksOutbound),
    Trojan(TrojanOutbound),
    Vless(VlessOutbound),
    Vmess(VmessOutbound),
    Hysteria2(Hysteria2Outbound),
    Tuic(TuicOutbound),
    Selector(Selector),
    UrlTest(UrlTest),
    ShadowTls(ShadowTlsOutbound),
    AnyTls(AnyTlsOutbound),
    /// From `endpoints[]`; endpoints share the outbound tag namespace and
    /// are appended after the outbounds.
    WireGuard(Box<WireGuardEndpoint>),
}

impl OutboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Direct(_) => "direct",
            Self::Block => "block",
            Self::Socks(_) => "socks",
            Self::Http(_) => "http",
            Self::Shadowsocks(_) => "shadowsocks",
            Self::Trojan(_) => "trojan",
            Self::Vless(_) => "vless",
            Self::Vmess(_) => "vmess",
            Self::Hysteria2(_) => "hysteria2",
            Self::Tuic(_) => "tuic",
            Self::Selector(_) => "selector",
            Self::UrlTest(_) => "urltest",
            Self::ShadowTls(_) => "shadowtls",
            Self::AnyTls(_) => "anytls",
            Self::WireGuard(_) => "wireguard",
        }
    }
}

/// Outbound dialer options shared by every protocol.
#[derive(Debug, Clone, Default)]
pub struct Dial {
    pub detour: Option<String>,
    pub connect_timeout: Option<Duration>,
    pub tcp_fast_open: bool,
    pub tcp_keep_alive: Option<Duration>,
    pub disable_tcp_keep_alive: bool,
    pub bind_interface: Option<String>,
    pub domain_strategy: Option<DomainStrategy>,
    /// DNS server (and query options) for resolving the domains this dialer
    /// connects to.
    pub domain_resolver: Option<DomainResolver>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStrategy {
    #[serde(rename = "")]
    AsIs,
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddr {
    pub server: String,
    pub server_port: u16,
}

#[derive(Debug, Clone)]
pub struct SocksOutbound {
    pub server: ServerAddr,
    pub dial: Dial,
    pub version: String,
    pub username: Option<String>,
    pub password: Option<String>,
    /// `None`: TCP and UDP.
    pub network: Option<Network>,
    pub udp_over_tcp: Option<UdpOverTcp>,
}

#[derive(Debug, Clone)]
pub struct HttpOutbound {
    pub server: ServerAddr,
    pub dial: Dial,
    pub username: Option<String>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub headers: Vec<(String, String)>,
    pub tls: Option<TlsOutbound>,
}

#[derive(Debug, Clone)]
pub struct ShadowsocksOutbound {
    pub server: ServerAddr,
    pub dial: Dial,
    pub method: String,
    pub password: String,
    /// `None`: TCP and UDP.
    pub network: Option<Network>,
    pub udp_over_tcp: Option<UdpOverTcp>,
}

#[derive(Debug, Clone)]
pub struct Selector {
    pub outbounds: Vec<String>,
    pub default: Option<String>,
    pub interrupt_exist_connections: bool,
}

#[derive(Debug, Clone)]
pub struct UrlTest {
    pub outbounds: Vec<String>,
    pub url: Option<String>,
    pub interval: Option<Duration>,
    pub tolerance: u16,
    pub idle_timeout: Option<Duration>,
    pub interrupt_exist_connections: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
    Icmp,
}

impl Options {
    /// Parse a sing-box JSON config (comments allowed).
    pub fn parse(input: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(&types::strip_comments(input))?;
        Self::from_value(value)
    }

    pub fn from_value(value: Value) -> Result<Self> {
        let mut diag = Diag { warnings: Vec::new() };
        let mut root = Obj::new(value, "")?;
        root.raw("$schema");

        let log = match root.raw("log") {
            Some(v) => parse_log(Obj::new(v, "log")?)?,
            None => LogOptions::default(),
        };

        let dns = match root.raw("dns") {
            Some(v) => Some(dns::parse_dns(Obj::new(v, "dns")?, &mut diag)?),
            None => None,
        };
        // Sections that exist in sing-box but that sbr doesn't run yet.
        if root.raw("ntp").is_some() {
            diag.warnings.push("ntp: ignored by sbr".into());
        }
        let experimental = match root.raw("experimental") {
            Some(v) => experimental::parse(Obj::new(v, "experimental")?, &mut diag)?,
            None => Experimental::default(),
        };
        for key in [
            "services",
            "certificate",
            "certificate_providers",
            "http_clients",
            "network_namespaces",
        ] {
            if let Some(v) = root.raw(key)
                && !matches!(&v, Value::Array(a) if a.is_empty())
                && !matches!(&v, Value::Object(o) if o.is_empty())
            {
                return Err(Error::at(key, "not supported by sbr yet"));
            }
        }

        let inbounds = array(root.raw("inbounds"), "inbounds")?
            .into_iter()
            .enumerate()
            .map(|(i, v)| parse_inbound(Obj::new(v, format!("inbounds[{i}]"))?, i, &mut diag))
            .collect::<Result<Vec<_>>>()?;

        let mut outbounds = array(root.raw("outbounds"), "outbounds")?
            .into_iter()
            .enumerate()
            .map(|(i, v)| parse_outbound(Obj::new(v, format!("outbounds[{i}]"))?, i, &mut diag))
            .collect::<Result<Vec<_>>>()?;

        let endpoints = array(root.raw("endpoints"), "endpoints")?
            .into_iter()
            .enumerate()
            .map(|(i, v)| parse_endpoint(Obj::new(v, format!("endpoints[{i}]"))?, i, &mut diag))
            .collect::<Result<Vec<_>>>()?;

        let route = match root.raw("route") {
            Some(v) => route::parse_route(Obj::new(v, "route")?, &mut diag)?,
            None => RouteOptions::default(),
        };
        root.finish()?;

        // sing-box adds an implicit `direct` when there are no outbounds.
        if outbounds.is_empty() {
            outbounds.push(Outbound {
                tag: "direct".into(),
                kind: OutboundKind::Direct(Dial::default()),
            });
        }
        // After the implicit direct: like sing-box, endpoints never become
        // the default outbound.
        outbounds.extend(endpoints);

        if dns.is_none() && inbounds.iter().any(|i| matches!(i.kind, InboundKind::Tun(_))) {
            diag.warnings.push(
                "dns: missing with a tun inbound: server names and hijacked DNS queries go to the system resolver, \
                 which on Apple platforms is the physical network's, outside the tunnel"
                    .into(),
            );
        }
        let options = Options {
            log,
            inbounds,
            outbounds,
            route,
            dns,
            experimental,
            warnings: diag.warnings,
        };
        options.check_references()?;
        Ok(options)
    }

    /// The tag of the outbound used when no rule matches.
    pub fn final_outbound(&self) -> &str {
        self.route.final_outbound.as_deref().unwrap_or(&self.outbounds[0].tag)
    }

    fn check_references(&self) -> Result<()> {
        use std::collections::HashSet;
        let mut tags = HashSet::new();
        for (i, o) in self.outbounds.iter().enumerate() {
            if !tags.insert(o.tag.as_str()) {
                return Err(Error::at(
                    &format!("outbounds[{i}].tag"),
                    format!("duplicate tag {:?}", o.tag),
                ));
            }
        }
        let mut in_tags = HashSet::new();
        for (i, o) in self.inbounds.iter().enumerate() {
            if !in_tags.insert(o.tag.as_str()) {
                return Err(Error::at(
                    &format!("inbounds[{i}].tag"),
                    format!("duplicate tag {:?}", o.tag),
                ));
            }
        }
        let need = |path: String, tag: &str| -> Result<()> {
            if tags.contains(tag) {
                Ok(())
            } else {
                Err(Error::at(&path, format!("outbound not found: {tag}")))
            }
        };
        for (i, o) in self.outbounds.iter().enumerate() {
            let path = format!("outbounds[{i}]");
            let dial = match &o.kind {
                OutboundKind::Direct(d) => Some(d),
                OutboundKind::Socks(s) => Some(&s.dial),
                OutboundKind::Http(s) => Some(&s.dial),
                OutboundKind::Shadowsocks(s) => Some(&s.dial),
                OutboundKind::Trojan(s) => Some(&s.common.dial),
                OutboundKind::Vless(s) => Some(&s.common.dial),
                OutboundKind::Vmess(s) => Some(&s.common.dial),
                OutboundKind::Hysteria2(h) => Some(&h.dial),
                OutboundKind::Tuic(t) => Some(&t.dial),
                OutboundKind::ShadowTls(s) => Some(&s.dial),
                OutboundKind::AnyTls(s) => Some(&s.dial),
                OutboundKind::WireGuard(w) => Some(&w.dial),
                OutboundKind::Selector(g) => {
                    for t in &g.outbounds {
                        need(format!("{path}.outbounds"), t)?;
                    }
                    if let Some(d) = &g.default
                        && !g.outbounds.contains(d)
                    {
                        return Err(Error::at(
                            &format!("{path}.default"),
                            format!("{d} is not in outbounds"),
                        ));
                    }
                    None
                }
                OutboundKind::UrlTest(g) => {
                    for t in &g.outbounds {
                        need(format!("{path}.outbounds"), t)?;
                    }
                    None
                }
                OutboundKind::Block => None,
            };
            if let Some(det) = dial.and_then(|d| d.detour.as_deref()) {
                if det == o.tag {
                    return Err(Error::at(&format!("{path}.detour"), "detour to itself"));
                }
                need(format!("{path}.detour"), det)?;
            }
            if let Some(r) = dial.and_then(|d| d.domain_resolver.as_ref()) {
                self.need_dns_server(&format!("{path}.domain_resolver"), &r.server)?;
            }
        }
        if let Some(r) = &self.route.default_domain_resolver {
            self.need_dns_server("route.default_domain_resolver", &r.server)?;
        }
        if let Some(dns) = &self.dns {
            self.check_dns(dns, &tags, &in_tags)?;
        }
        if let Some(f) = &self.route.final_outbound {
            need("route.final".into(), f)?;
        }
        for rs in &self.route.rule_sets {
            if let RuleSetSource::Remote(r) = &rs.source
                && let Some(d) = &r.download_detour
            {
                need(format!("route.rule_set[{}].download_detour", rs.tag), d)?;
            }
        }
        if let Some(d) = self
            .experimental
            .clash_api
            .as_ref()
            .and_then(|c| c.external_ui_download_detour.as_deref())
        {
            need("experimental.clash_api.external_ui_download_detour".into(), d)?;
        }
        let mut stack: Vec<(&Rule, String)> = self
            .route
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r, format!("route.rules[{i}]")))
            .collect();
        while let Some((rule, path)) = stack.pop() {
            if let RuleAction::Route { outbound, .. } = &rule.action {
                need(format!("{path}.outbound"), outbound)?;
            }
            if let RuleAction::Resolve { server: Some(s), .. } = &rule.action {
                self.need_dns_server(&format!("{path}.server"), s)?;
            }
            if let RuleKind::Logical { rules, .. } = &rule.kind {
                stack.extend(rules.iter().enumerate().map(|(i, r)| (r, format!("{path}.rules[{i}]"))));
            }
            if let RuleKind::Default(m) = &rule.kind {
                for i in &m.inbound {
                    if !in_tags.contains(i.as_str()) {
                        return Err(Error::at(&format!("{path}.inbound"), format!("inbound not found: {i}")));
                    }
                }
                for rs in &m.rule_set {
                    if !self.route.rule_sets.iter().any(|r| &r.tag == rs) {
                        return Err(Error::at(
                            &format!("{path}.rule_set"),
                            format!("rule-set not found: {rs}"),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl Options {
    fn need_dns_server(&self, path: &str, tag: &str) -> Result<()> {
        if self
            .dns
            .as_ref()
            .is_some_and(|d| d.servers.iter().any(|s| s.tag == tag))
        {
            Ok(())
        } else {
            Err(Error::at(path, format!("DNS server not found: {tag}")))
        }
    }

    fn check_dns(
        &self,
        dns: &DnsOptions,
        outbounds: &std::collections::HashSet<&str>,
        inbounds: &std::collections::HashSet<&str>,
    ) -> Result<()> {
        let mut tags = std::collections::HashSet::new();
        for (i, s) in dns.servers.iter().enumerate() {
            let path = format!("dns.servers[{i}]");
            if !tags.insert(s.tag.as_str()) {
                return Err(Error::at(&format!("{path}.tag"), format!("duplicate tag {:?}", s.tag)));
            }
            if let Some(d) = &s.dial.detour
                && !outbounds.contains(d.as_str())
            {
                return Err(Error::at(&format!("{path}.detour"), format!("outbound not found: {d}")));
            }
            if let Some(r) = &s.dial.domain_resolver {
                let rpath = if s.legacy.is_some() {
                    format!("{path}.address_resolver")
                } else {
                    format!("{path}.domain_resolver")
                };
                if r.server == s.tag {
                    return Err(Error::at(&rpath, "resolver is the server itself"));
                }
                self.need_dns_server(&rpath, &r.server)?;
            }
        }
        if let Some(f) = &dns.final_server {
            self.need_dns_server("dns.final", f)?;
        }
        let mut stack: Vec<(&Rule, String)> = Vec::new();
        for (i, r) in dns.rules.iter().enumerate() {
            let path = format!("dns.rules[{i}]");
            if let DnsRuleAction::Route { server, .. } = &r.action {
                self.need_dns_server(&format!("{path}.server"), server)?;
            }
            stack.push((&r.rule, path));
        }
        while let Some((rule, path)) = stack.pop() {
            match &rule.kind {
                RuleKind::Logical { rules, .. } => {
                    stack.extend(rules.iter().enumerate().map(|(i, r)| (r, format!("{path}.rules[{i}]"))));
                }
                RuleKind::Default(m) => {
                    for i in &m.inbound {
                        if !inbounds.contains(i.as_str()) {
                            return Err(Error::at(&format!("{path}.inbound"), format!("inbound not found: {i}")));
                        }
                    }
                    for o in &m.outbound {
                        if o != "any" && !outbounds.contains(o.as_str()) {
                            return Err(Error::at(
                                &format!("{path}.outbound"),
                                format!("outbound not found: {o}"),
                            ));
                        }
                    }
                    for rs in &m.rule_set {
                        if !self.route.rule_sets.iter().any(|r| &r.tag == rs) {
                            return Err(Error::at(
                                &format!("{path}.rule_set"),
                                format!("rule-set not found: {rs}"),
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn array(v: Option<Value>, path: &str) -> Result<Vec<Value>> {
    match v {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a),
        Some(other) => Err(Error::at(path, format!("expected array, got {}", obj::kind(&other)))),
    }
}

fn parse_log(mut o: Obj) -> Result<LogOptions> {
    let log = LogOptions {
        disabled: o.bool("disabled")?,
        level: o.string("level")?,
        output: o.string("output")?,
        timestamp: o.bool("timestamp")?,
    };
    if let Some(l) = &log.level
        && !["trace", "debug", "info", "warn", "warning", "error", "fatal", "panic"].contains(&l.as_str())
    {
        return Err(Error::at("log.level", format!("unknown level {l:?}")));
    }
    o.finish()?;
    Ok(log)
}

fn tag_or_index(o: &mut Obj, i: usize) -> Result<String> {
    Ok(o.string("tag")?.unwrap_or_else(|| i.to_string()))
}

fn parse_listen(o: &mut Obj, diag: &mut Diag) -> Result<Listen> {
    let listen = match o.string("listen")? {
        Some(s) => s
            .parse::<IpAddr>()
            .map_err(|_| Error::at(&o.sub("listen"), format!("invalid address {s:?}")))?,
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let listen_port = o.get("listen_port")?;
    let l = Listen {
        listen,
        listen_port,
        tcp_fast_open: o.bool("tcp_fast_open")?,
        tcp_keep_alive: o.duration("tcp_keep_alive")?,
        disable_tcp_keep_alive: o.bool("disable_tcp_keep_alive")?,
        udp_timeout: o.duration("udp_timeout")?,
    };
    o.tolerate(
        diag,
        &[
            "tcp_multi_path",
            "udp_fragment",
            "reuse_addr",
            "tcp_keep_alive_interval",
            "routing_mark",
            "bind_interface",
        ],
    );
    // Legacy inbound sniff/resolve fields, removed in sing-box 1.13. We refuse
    // them rather than pretend: they changed routing decisions.
    for legacy in [
        "sniff",
        "sniff_override_destination",
        "sniff_timeout",
        "domain_strategy",
        "udp_disable_domain_unmapping",
        "detour",
        "proxy_protocol",
        "netns",
    ] {
        if o.has(legacy) {
            return Err(Error::at(
                &o.sub(legacy),
                "not supported by sbr; use route rule actions instead",
            ));
        }
    }
    Ok(l)
}

fn parse_inbound(mut o: Obj, i: usize, diag: &mut Diag) -> Result<Inbound> {
    let ty: String = o.req("type")?;
    let tag = tag_or_index(&mut o, i)?;
    let kind = match ty.as_str() {
        "mixed" | "socks" | "http" => {
            let listen = parse_listen(&mut o, diag)?;
            let users = o.get("users")?;
            if o.raw("set_system_proxy").is_some() {
                diag.warnings
                    .push(format!("{}.set_system_proxy: ignored by sbr", o.path()));
            }
            if ty == "http" && o.has("tls") {
                return Err(Error::at(&o.sub("tls"), "not supported by sbr yet"));
            }
            let p = ProxyInbound { listen, users };
            match ty.as_str() {
                "mixed" => InboundKind::Mixed(p),
                "socks" => InboundKind::Socks(p),
                _ => InboundKind::Http(p),
            }
        }
        "tun" => InboundKind::Tun(parse_tun(&mut o, diag)?),
        other => {
            return Err(Error::at(
                &o.sub("type"),
                format!("inbound type {other:?} not supported by sbr yet"),
            ));
        }
    };
    o.finish()?;
    Ok(Inbound { tag, kind })
}

pub(crate) fn prefixes(o: &mut Obj, key: &str) -> Result<Vec<ipnet::IpNet>> {
    let path = o.sub(key);
    o.list::<String>(key)?
        .into_iter()
        .map(|s| {
            s.parse::<ipnet::IpNet>()
                .or_else(|_| s.parse::<IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| Error::at(&path, format!("invalid prefix {s:?}")))
        })
        .collect()
}

fn parse_tun(o: &mut Obj, diag: &mut Diag) -> Result<TunInbound> {
    let mut t = TunInbound {
        interface_name: o.string("interface_name")?,
        mtu: o.opt::<u32>("mtu")?.filter(|m| *m != 0),
        address: prefixes(o, "address")?,
        auto_route: o.bool("auto_route")?,
        strict_route: o.bool("strict_route")?,
        route_address: prefixes(o, "route_address")?,
        route_exclude_address: prefixes(o, "route_exclude_address")?,
        loopback_address: o.list("loopback_address")?,
        udp_timeout: match o.raw("udp_timeout") {
            // Legacy integer seconds or a duration string.
            Some(Value::Number(n)) => n.as_u64().map(Duration::from_secs),
            Some(Value::String(s)) if !s.is_empty() => {
                Some(types::parse_duration(&s).map_err(|e| Error::at(&o.sub("udp_timeout"), e))?)
            }
            _ => None,
        },
        stack: match o.string("stack")?.as_deref() {
            None | Some("") => None,
            Some("system") => Some(TunStack::System),
            Some("gvisor") => Some(TunStack::Gvisor),
            Some("mixed") => Some(TunStack::Mixed),
            Some(s) => return Err(Error::at(&o.sub("stack"), format!("unknown stack {s:?}"))),
        },
    };
    // Deprecated split fields, still accepted by sing-box.
    for (legacy, into_route, exclude) in [
        ("inet4_address", false, false),
        ("inet6_address", false, false),
        ("inet4_route_address", true, false),
        ("inet6_route_address", true, false),
        ("inet4_route_exclude_address", false, true),
        ("inet6_route_exclude_address", false, true),
    ] {
        let v = prefixes(o, legacy)?;
        match (into_route, exclude) {
            (true, _) => t.route_address.extend(v),
            (_, true) => t.route_exclude_address.extend(v),
            _ => t.address.extend(v),
        }
    }
    if t.address.is_empty() {
        return Err(Error::at(&o.sub("address"), "missing interface address"));
    }
    for k in [
        "route_address_set",
        "route_exclude_address_set",
        "auto_redirect",
        "netns",
    ] {
        if o.has(k) {
            return Err(Error::at(&o.sub(k), "not supported by sbr yet"));
        }
    }
    o.tolerate(
        diag,
        &[
            "dns_mode",
            "dns_address",
            "iproute2_table_index",
            "iproute2_rule_index",
            "auto_redirect_input_mark",
            "auto_redirect_output_mark",
            "auto_redirect_reset_mark",
            "auto_redirect_tproxy_mark",
            "auto_redirect_nfqueue",
            "auto_redirect_iproute2_fallback_rule_index",
            "exclude_mptcp",
            "include_interface",
            "exclude_interface",
            "include_uid",
            "include_uid_range",
            "exclude_uid",
            "exclude_uid_range",
            "include_android_user",
            "include_package",
            "exclude_package",
            "include_mac_address",
            "exclude_mac_address",
            "udp_mapping",
            "udp_filtering",
            "udp_nat_max",
            "multi_queue",
            "platform",
            "gso",
            "endpoint_independent_nat",
        ],
    );
    Ok(t)
}

pub(crate) fn parse_dial(o: &mut Obj, diag: &mut Diag) -> Result<Dial> {
    let d = Dial {
        detour: o.string("detour")?,
        connect_timeout: o.duration("connect_timeout")?,
        tcp_fast_open: o.bool("tcp_fast_open")?,
        tcp_keep_alive: o.duration("tcp_keep_alive")?,
        disable_tcp_keep_alive: o.bool("disable_tcp_keep_alive")?,
        bind_interface: o.string("bind_interface")?,
        domain_strategy: o.opt("domain_strategy")?,
        domain_resolver: dns::parse_domain_resolver(o, "domain_resolver")?,
    };
    o.tolerate(
        diag,
        &[
            "tcp_multi_path",
            "udp_fragment",
            "reuse_addr",
            "tcp_keep_alive_interval",
            "routing_mark",
            "fallback_delay",
        ],
    );
    Ok(d)
}

pub(crate) fn parse_server(o: &mut Obj) -> Result<ServerAddr> {
    let server: String = o.req("server")?;
    if server.is_empty() {
        return Err(Error::at(&o.sub("server"), "empty server address"));
    }
    let server_port: u16 = o.req("server_port")?;
    Ok(ServerAddr { server, server_port })
}

fn parse_outbound(mut o: Obj, i: usize, diag: &mut Diag) -> Result<Outbound> {
    let ty: String = o.req("type")?;
    let tag = tag_or_index(&mut o, i)?;
    let kind = match ty.as_str() {
        "direct" => {
            for k in ["override_address", "override_port", "proxy_protocol"] {
                if o.has(k) {
                    return Err(Error::at(
                        &o.sub(k),
                        "deprecated in sing-box and not supported by sbr; use route-options",
                    ));
                }
            }
            OutboundKind::Direct(parse_dial(&mut o, diag)?)
        }
        "block" => OutboundKind::Block,
        "socks" => {
            let server = parse_server(&mut o)?;
            let dial = parse_dial(&mut o, diag)?;
            let version = o.string("version")?.unwrap_or_else(|| "5".into());
            if !["4", "4a", "5"].contains(&version.as_str()) {
                return Err(Error::at(&o.sub("version"), format!("unknown version {version:?}")));
            }
            let network = proxies::parse_network_list(&mut o, "network")?;
            let udp_over_tcp = proxies::parse_uot(&mut o, "udp_over_tcp")?;
            OutboundKind::Socks(SocksOutbound {
                server,
                dial,
                version,
                username: o.string("username")?,
                password: o.string("password")?,
                network,
                udp_over_tcp,
            })
        }
        "http" => {
            let server = parse_server(&mut o)?;
            let dial = parse_dial(&mut o, diag)?;
            let headers = parse_headers(&mut o, "headers")?;
            let tls = tls::parse_tls(&mut o, "tls", diag)?;
            // sing-box 1.13 negotiates HTTP/2 CONNECT by default when TLS
            // offers it and falls back to HTTP/1.1; sbr always speaks
            // HTTP/1.1, which every such server also accepts.
            let version: u8 = o.get("version")?;
            let no_fallback = o.bool("disable_version_fallback")?;
            match version {
                0 | 1 => {}
                2 if !no_fallback => {}
                2 | 3 => {
                    return Err(Error::at(
                        &o.sub("version"),
                        "HTTP/2 and HTTP/3 proxies are not supported by sbr yet",
                    ));
                }
                v => return Err(Error::at(&o.sub("version"), format!("unknown HTTP version: {v}"))),
            }
            OutboundKind::Http(HttpOutbound {
                server,
                dial,
                username: o.string("username")?,
                password: o.string("password")?,
                path: o.string("path")?,
                headers,
                tls,
            })
        }
        "shadowsocks" => {
            let server = parse_server(&mut o)?;
            let dial = parse_dial(&mut o, diag)?;
            let method: String = o.req("method")?;
            let password = o.string("password")?.unwrap_or_default();
            let network = proxies::parse_network_list(&mut o, "network")?;
            let udp_over_tcp = proxies::parse_uot(&mut o, "udp_over_tcp")?;
            for k in ["plugin", "plugin_opts", "multiplex"] {
                if o.has(k) {
                    return Err(Error::at(&o.sub(k), "not supported by sbr yet"));
                }
            }
            OutboundKind::Shadowsocks(ShadowsocksOutbound {
                server,
                dial,
                method,
                password,
                network,
                udp_over_tcp,
            })
        }
        "trojan" => OutboundKind::Trojan(proxy::parse_trojan(&mut o, diag)?),
        "vless" => OutboundKind::Vless(proxy::parse_vless(&mut o, diag)?),
        "vmess" => OutboundKind::Vmess(proxy::parse_vmess(&mut o, diag)?),
        "hysteria2" => OutboundKind::Hysteria2(quic::parse_hysteria2(&mut o, diag)?),
        "tuic" => OutboundKind::Tuic(quic::parse_tuic(&mut o, diag)?),
        "shadowtls" => OutboundKind::ShadowTls(proxies::parse_shadowtls(&mut o, diag)?),
        "anytls" => OutboundKind::AnyTls(proxies::parse_anytls(&mut o, diag)?),
        "wireguard" => {
            return Err(Error::at(
                &o.sub("type"),
                "WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead",
            ));
        }
        "selector" => OutboundKind::Selector(Selector {
            outbounds: nonempty(o.req("outbounds")?, &o.sub("outbounds"))?,
            default: o.string("default")?,
            interrupt_exist_connections: o.bool("interrupt_exist_connections")?,
        }),
        "urltest" => OutboundKind::UrlTest(UrlTest {
            outbounds: nonempty(o.req("outbounds")?, &o.sub("outbounds"))?,
            url: o.string("url")?,
            interval: o.duration("interval")?,
            tolerance: o.get("tolerance")?,
            idle_timeout: o.duration("idle_timeout")?,
            interrupt_exist_connections: o.bool("interrupt_exist_connections")?,
        }),
        other => {
            return Err(Error::at(
                &o.sub("type"),
                format!("outbound type {other:?} not supported by sbr yet"),
            ));
        }
    };
    o.finish()?;
    Ok(Outbound { tag, kind })
}

fn nonempty(v: Vec<String>, path: &str) -> Result<Vec<String>> {
    if v.is_empty() {
        Err(Error::at(path, "missing outbounds"))
    } else {
        Ok(v)
    }
}

/// sing-box `HTTPHeader`: `{"Name": "v"}` or `{"Name": ["v1", "v2"]}`.
pub(crate) fn parse_headers(o: &mut Obj, key: &str) -> Result<Vec<(String, String)>> {
    Ok(o.get::<serde_json::Map<String, Value>>(key)?
        .into_iter()
        .flat_map(|(k, v)| match v {
            Value::Array(vs) => vs.into_iter().map(|v| (k.clone(), json_str(v))).collect::<Vec<_>>(),
            v => vec![(k, json_str(v))],
        })
        .collect())
}

fn json_str(v: Value) -> String {
    match v {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

fn parse_endpoint(mut o: Obj, i: usize, diag: &mut Diag) -> Result<Outbound> {
    let ty: String = o.req("type")?;
    let tag = tag_or_index(&mut o, i)?;
    let kind = match ty.as_str() {
        "wireguard" => OutboundKind::WireGuard(Box::new(wireguard::parse_wireguard(&mut o, diag)?)),
        other => {
            return Err(Error::at(
                &o.sub("type"),
                format!("endpoint type {other:?} not supported by sbr yet"),
            ));
        }
    };
    o.finish()?;
    Ok(Outbound { tag, kind })
}
