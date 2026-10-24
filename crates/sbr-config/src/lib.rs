//! sing-box compatible configuration.
//!
//! The parser is strict in the same way sing-box is (unknown fields are
//! errors) so a config that loads here means the same thing it means there.
//! Anything sing-box understands that sbr doesn't yet is rejected with the
//! exact JSON path, rather than silently changing routing behaviour. The
//! only exceptions are knobs that cannot change *where* traffic goes; those
//! are accepted and reported in [`Options::warnings`].

mod obj;
mod route;
pub mod types;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use obj::{Diag, Obj};
use serde_json::Value;

pub use route::*;

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
    Selector(Selector),
    UrlTest(UrlTest),
}

impl OutboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Direct(_) => "direct",
            Self::Block => "block",
            Self::Socks(_) => "socks",
            Self::Http(_) => "http",
            Self::Shadowsocks(_) => "shadowsocks",
            Self::Selector(_) => "selector",
            Self::UrlTest(_) => "urltest",
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

#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone)]
pub struct HttpOutbound {
    pub server: ServerAddr,
    pub dial: Dial,
    pub username: Option<String>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct ShadowsocksOutbound {
    pub server: ServerAddr,
    pub dial: Dial,
    pub method: String,
    pub password: String,
    pub network: Option<Network>,
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
        let mut diag = Diag {
            warnings: Vec::new(),
        };
        let mut root = Obj::new(value, "")?;
        root.raw("$schema");

        let log = match root.raw("log") {
            Some(v) => parse_log(Obj::new(v, "log")?)?,
            None => LogOptions::default(),
        };

        // Sections that exist in sing-box but that sbr doesn't run yet. DNS is
        // the big one: we fall back to the system resolver, which is what
        // sing-box itself does with an empty `dns` block.
        if root.raw("dns").is_some() {
            diag.warnings
                .push("dns: not implemented yet, using the system resolver".into());
        }
        if root.raw("ntp").is_some() {
            diag.warnings.push("ntp: ignored by sbr".into());
        }
        if let Some(exp) = root.raw("experimental") {
            let mut exp = Obj::new(exp, "experimental")?;
            exp.tolerate(
                &mut diag,
                &["cache_file", "clash_api", "v2ray_api", "debug"],
            );
            exp.finish()?;
        }
        for key in [
            "endpoints",
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

        let options = Options {
            log,
            inbounds,
            outbounds,
            route,
            warnings: diag.warnings,
        };
        options.check_references()?;
        Ok(options)
    }

    /// The tag of the outbound used when no rule matches.
    pub fn final_outbound(&self) -> &str {
        self.route
            .final_outbound
            .as_deref()
            .unwrap_or(&self.outbounds[0].tag)
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
        }
        if let Some(f) = &self.route.final_outbound {
            need("route.final".into(), f)?;
        }
        let mut stack: Vec<(&Rule, String)> = self
            .route
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r, format!("route.rules[{i}]")))
            .collect();
        while let Some((rule, path)) = stack.pop() {
            if let RuleAction::Route { outbound } = &rule.action {
                need(format!("{path}.outbound"), outbound)?;
            }
            if let RuleKind::Logical { rules, .. } = &rule.kind {
                stack.extend(
                    rules
                        .iter()
                        .enumerate()
                        .map(|(i, r)| (r, format!("{path}.rules[{i}]"))),
                );
            }
            if let RuleKind::Default(m) = &rule.kind {
                for i in &m.inbound {
                    if !in_tags.contains(i.as_str()) {
                        return Err(Error::at(
                            &format!("{path}.inbound"),
                            format!("inbound not found: {i}"),
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
        Ok(())
    }
}

fn array(v: Option<Value>, path: &str) -> Result<Vec<Value>> {
    match v {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a),
        Some(other) => Err(Error::at(
            path,
            format!("expected array, got {}", obj::kind(&other)),
        )),
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
        && ![
            "trace", "debug", "info", "warn", "warning", "error", "fatal", "panic",
        ]
        .contains(&l.as_str())
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

fn parse_dial(o: &mut Obj, diag: &mut Diag) -> Result<Dial> {
    let d = Dial {
        detour: o.string("detour")?,
        connect_timeout: o.duration("connect_timeout")?,
        tcp_fast_open: o.bool("tcp_fast_open")?,
        tcp_keep_alive: o.duration("tcp_keep_alive")?,
        disable_tcp_keep_alive: o.bool("disable_tcp_keep_alive")?,
        bind_interface: o.string("bind_interface")?,
        domain_strategy: o.opt("domain_strategy")?,
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

fn parse_server(o: &mut Obj) -> Result<ServerAddr> {
    let server: String = o.req("server")?;
    if server.is_empty() {
        return Err(Error::at(&o.sub("server"), "empty server address"));
    }
    let server_port: u16 = o.req("server_port")?;
    Ok(ServerAddr {
        server,
        server_port,
    })
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
                return Err(Error::at(
                    &o.sub("version"),
                    format!("unknown version {version:?}"),
                ));
            }
            if version != "5" {
                return Err(Error::at(
                    &o.sub("version"),
                    "only SOCKS5 is supported by sbr yet",
                ));
            }
            if let Some(n) = o.opt::<String>("network")?
                && n == "udp"
            {
                return Err(Error::at(&o.sub("network"), "UDP not supported by sbr yet"));
            }
            OutboundKind::Socks(SocksOutbound {
                server,
                dial,
                version,
                username: o.string("username")?,
                password: o.string("password")?,
            })
        }
        "http" => {
            let server = parse_server(&mut o)?;
            let dial = parse_dial(&mut o, diag)?;
            let headers = o
                .get::<serde_json::Map<String, Value>>("headers")?
                .into_iter()
                .flat_map(|(k, v)| match v {
                    Value::Array(vs) => vs
                        .into_iter()
                        .map(|v| (k.clone(), json_str(v)))
                        .collect::<Vec<_>>(),
                    v => vec![(k, json_str(v))],
                })
                .collect();
            if o.has("tls") {
                return Err(Error::at(&o.sub("tls"), "not supported by sbr yet"));
            }
            OutboundKind::Http(HttpOutbound {
                server,
                dial,
                username: o.string("username")?,
                password: o.string("password")?,
                path: o.string("path")?,
                headers,
            })
        }
        "shadowsocks" => {
            let server = parse_server(&mut o)?;
            let dial = parse_dial(&mut o, diag)?;
            let method: String = o.req("method")?;
            let password = o.string("password")?.unwrap_or_default();
            let network = match o.string("network")? {
                None => None,
                Some(n) => Some(
                    serde_json::from_value(Value::String(n))
                        .map_err(|e| Error::at(&o.sub("network"), e.to_string()))?,
                ),
            };
            for k in ["plugin", "plugin_opts", "udp_over_tcp", "multiplex"] {
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
            })
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

fn json_str(v: Value) -> String {
    match v {
        Value::String(s) => s,
        other => other.to_string(),
    }
}
