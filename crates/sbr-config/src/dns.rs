//! The `dns` section: servers, rules, cache and FakeIP.
//!
//! Both the sing-box 1.12+ typed servers (`{"type": "udp", "server": ...}`)
//! and the legacy `address` URLs are accepted; legacy servers are converted
//! to the typed form here and flagged so the runtime can keep their old
//! defaults (dialing through the default outbound).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde_json::Value;

use crate::obj::{Diag, Obj};
use crate::route::{Rule, RuleAction, parse_rule_body};
use crate::{Dial, DomainStrategy, Error, RejectMethod, Result, ServerAddr, TlsOutbound, array, parse_dial};

/// sing-box `C.DefaultDNSTTL`.
pub const DEFAULT_TTL: u32 = 600;
/// TTL for predefined records written without one (sing-box `defaultDNSRecordTTL`).
const RECORD_TTL: u32 = 3600;

#[derive(Debug, Clone, Default)]
pub struct DnsOptions {
    pub servers: Vec<DnsServer>,
    pub rules: Vec<DnsRule>,
    /// Default server tag; the first server when unset.
    pub final_server: Option<String>,
    pub strategy: Option<DomainStrategy>,
    pub disable_cache: bool,
    pub disable_expire: bool,
    /// Accepted for compatibility: sbr's cache is always per server, which
    /// is what this option asked for (and what sing-box 1.14 does anyway).
    pub independent_cache: bool,
    /// LRU capacity; values below 1024 are raised to 1024 like sing-box.
    pub cache_capacity: u32,
    /// `optimistic`: serve expired entries for up to this long while
    /// refreshing them in the background.
    pub optimistic: Option<Duration>,
    /// Per-query timeout (default 10s).
    pub timeout: Option<Duration>,
    pub reverse_mapping: bool,
    pub client_subnet: Option<IpNet>,
}

impl DnsOptions {
    /// The tag of the default server.
    pub fn final_server(&self) -> Option<&str> {
        self.final_server
            .as_deref()
            .or_else(|| self.servers.first().map(|s| s.tag.as_str()))
    }
}

#[derive(Debug, Clone)]
pub struct DnsServer {
    pub tag: String,
    pub kind: DnsServerKind,
    /// Dial fields (`detour`, `domain_resolver`, ...). Empty for servers
    /// that never dial (`hosts`, `fakeip`, `rcode`).
    pub dial: Dial,
    /// Set for servers written in the legacy `address` format.
    pub legacy: Option<LegacyServer>,
}

/// Behaviour that only legacy-format servers have.
#[derive(Debug, Clone, Default)]
pub struct LegacyServer {
    /// `strategy`: default domain strategy for queries sent to this server.
    pub strategy: Option<DomainStrategy>,
    /// `client_subnet`, overriding `dns.client_subnet`.
    pub client_subnet: Option<IpNet>,
    /// Legacy servers without `detour` dial through the default outbound.
    pub default_outbound: bool,
}

#[derive(Debug, Clone)]
pub enum DnsServerKind {
    /// The system resolver.
    Local,
    Hosts {
        /// Hosts files; `/etc/hosts` when empty and no `predefined` is set.
        path: Vec<String>,
        predefined: Vec<(String, Vec<IpAddr>)>,
    },
    Udp(ServerAddr),
    Tcp(ServerAddr),
    Tls {
        server: ServerAddr,
        tls: TlsOutbound,
    },
    Https {
        server: ServerAddr,
        tls: TlsOutbound,
        path: String,
        /// `GET` (RFC 8484 `?dns=`) or `POST`.
        get: bool,
        headers: Vec<(String, String)>,
    },
    FakeIp {
        inet4_range: Option<Ipv4Net>,
        inet6_range: Option<Ipv6Net>,
    },
    /// Legacy `rcode://`: answer every query with this response code.
    Rcode(u16),
}

impl DnsServerKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Hosts { .. } => "hosts",
            Self::Udp(_) => "udp",
            Self::Tcp(_) => "tcp",
            Self::Tls { .. } => "tls",
            Self::Https { .. } => "https",
            Self::FakeIp { .. } => "fakeip",
            Self::Rcode(_) => "rcode",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsRule {
    /// Matchers; `rule.action` is always `RuleAction::None`.
    pub rule: Rule,
    pub action: DnsRuleAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRuleAction {
    Route { server: String, options: DnsRouteOptions },
    RouteOptions(DnsRouteOptions),
    Reject { method: RejectMethod, no_drop: bool },
    Predefined(Predefined),
}

/// Options shared by the `route` and `route-options` DNS actions and by
/// `domain_resolver`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsRouteOptions {
    /// Deprecated in sing-box 1.14, still honoured.
    pub strategy: Option<DomainStrategy>,
    pub disable_cache: bool,
    pub disable_optimistic_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub timeout: Option<Duration>,
    pub client_subnet: Option<IpNet>,
    pub remove_client_subnet: bool,
}

/// `domain_resolver` (dial field) and `route.default_domain_resolver`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainResolver {
    pub server: String,
    pub options: DnsRouteOptions,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Predefined {
    pub rcode: u16,
    pub answer: Vec<DnsRecord>,
    pub ns: Vec<DnsRecord>,
    pub extra: Vec<DnsRecord>,
}

/// A record written in zone-file text (`"example.com. IN A 1.2.3.4"`) or as
/// base64 of its wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    Text {
        /// Fully qualified, lowercase, with the trailing dot. A leading `*.`
        /// is a wildcard rewritten to the question name.
        name: String,
        ttl: u32,
        data: RecordData,
    },
    /// Wire-format RR (base64 in the config), decoded by the runtime.
    Wire(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx(u16, String),
    Txt(Vec<String>),
}

impl DnsRecord {
    pub fn record_type(&self) -> Option<u16> {
        match self {
            Self::Text { data, .. } => Some(match data {
                RecordData::A(_) => 1,
                RecordData::Ns(_) => 2,
                RecordData::Cname(_) => 5,
                RecordData::Ptr(_) => 12,
                RecordData::Mx(..) => 15,
                RecordData::Txt(_) => 16,
                RecordData::Aaaa(_) => 28,
            }),
            Self::Wire(_) => None,
        }
    }
}

pub(crate) fn parse_dns(mut o: Obj, diag: &mut Diag) -> Result<DnsOptions> {
    // Legacy top-level fakeip block: only consulted by legacy `fakeip` servers.
    let legacy_fakeip = match o.raw("fakeip") {
        None => None,
        Some(v) => {
            let mut f = Obj::new(v, o.sub("fakeip"))?;
            let enabled = f.bool("enabled")?;
            let inet4_range = prefix_opt(&mut f, "inet4_range")?;
            let inet6_range = prefix_opt(&mut f, "inet6_range")?;
            f.finish()?;
            diag.warnings
                .push("dns.fakeip: legacy FakeIP options are deprecated in sing-box; use a fakeip server".into());
            enabled.then_some((inet4_range, inet6_range))
        }
    };
    let servers = array(o.raw("servers"), &o.sub("servers"))?
        .into_iter()
        .enumerate()
        .map(|(i, v)| parse_server(Obj::new(v, format!("dns.servers[{i}]"))?, i, legacy_fakeip, diag))
        .collect::<Result<Vec<_>>>()?;
    let rules = array(o.raw("rules"), &o.sub("rules"))?
        .into_iter()
        .enumerate()
        .map(|(i, v)| parse_dns_rule(Obj::new(v, format!("dns.rules[{i}]"))?, diag))
        .collect::<Result<Vec<_>>>()?;
    let disable_cache = o.bool("disable_cache")?;
    let disable_expire = o.bool("disable_expire")?;
    let optimistic = match o.raw("optimistic") {
        None | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some(Duration::from_secs(3 * 86400)),
        Some(v) => {
            let mut p = Obj::new(v, o.sub("optimistic"))?;
            let enabled = p.bool("enabled")?;
            let timeout = p.duration("timeout")?;
            p.finish()?;
            enabled.then(|| timeout.unwrap_or(Duration::from_secs(3 * 86400)))
        }
    };
    if optimistic.is_some() && (disable_cache || disable_expire) {
        return Err(Error::at(
            &o.sub("optimistic"),
            "conflicts with disable_cache and disable_expire",
        ));
    }
    let d = DnsOptions {
        servers,
        rules,
        final_server: o.string("final")?,
        strategy: o.opt("strategy")?,
        disable_cache,
        disable_expire,
        independent_cache: o.bool("independent_cache")?,
        cache_capacity: o.get("cache_capacity")?,
        optimistic,
        timeout: o.duration("timeout")?,
        reverse_mapping: o.bool("reverse_mapping")?,
        client_subnet: client_subnet(&mut o, "client_subnet")?,
    };
    o.finish()?;
    Ok(d)
}

fn parse_server(
    mut o: Obj,
    i: usize,
    legacy_fakeip: Option<(Option<IpNet>, Option<IpNet>)>,
    diag: &mut Diag,
) -> Result<DnsServer> {
    let tag = o.string("tag")?.unwrap_or_else(|| i.to_string());
    let ty = o.string("type")?;
    let server = match ty.as_deref() {
        None | Some("legacy") => parse_legacy_server(&mut o, tag, legacy_fakeip, diag)?,
        Some(ty) => parse_typed_server(&mut o, tag, ty, diag)?,
    };
    o.finish()?;
    Ok(server)
}

fn no_dial() -> Dial {
    Dial::default()
}

fn parse_typed_server(o: &mut Obj, tag: String, ty: &str, diag: &mut Diag) -> Result<DnsServer> {
    let (kind, dial) = match ty {
        "local" => {
            let dial = parse_dial(o, diag)?;
            o.tolerate(diag, &["prefer_go"]);
            if o.has("neighbor_domain") {
                return Err(Error::at(&o.sub("neighbor_domain"), "not supported by sbr yet"));
            }
            if dial.detour.is_some() {
                // sbr's local server is the OS resolver (getaddrinfo); it cannot be detoured.
                return Err(Error::at(
                    &o.sub("detour"),
                    "detour on a local server is not supported by sbr yet",
                ));
            }
            (DnsServerKind::Local, dial)
        }
        "hosts" => {
            let path = o.list("path")?;
            let mut predefined = Vec::new();
            if let Some(v) = o.raw("predefined") {
                let ppath = o.sub("predefined");
                let Value::Object(map) = v else {
                    return Err(Error::at(&ppath, "expected object"));
                };
                for (name, addrs) in map {
                    let at = format!("{ppath}.{name}");
                    let addrs: Vec<IpAddr> = match addrs {
                        Value::Array(a) => a
                            .into_iter()
                            .map(|v| serde_json::from_value(v).map_err(|e| Error::at(&at, e.to_string())))
                            .collect::<Result<_>>()?,
                        v => vec![serde_json::from_value(v).map_err(|e| Error::at(&at, e.to_string()))?],
                    };
                    predefined.push((name.trim_end_matches('.').to_ascii_lowercase(), addrs));
                }
            }
            (DnsServerKind::Hosts { path, predefined }, no_dial())
        }
        "udp" | "tcp" | "tls" | "https" => {
            let default_port = match ty {
                "tls" => 853,
                "https" => 443,
                _ => 53,
            };
            let server = server_addr(o, default_port)?;
            let dial = parse_dial(o, diag)?;
            let kind = match ty {
                "udp" => DnsServerKind::Udp(server),
                "tcp" => DnsServerKind::Tcp(server),
                _ => {
                    let tls = dns_tls(o, diag)?;
                    if ty == "tls" {
                        DnsServerKind::Tls { server, tls }
                    } else {
                        let path = o.string("path")?.unwrap_or_else(|| "/dns-query".into());
                        let get = match o.string("method")?.as_deref() {
                            None | Some("POST") | Some("post") => false,
                            Some("GET") | Some("get") => true,
                            Some(m) => return Err(Error::at(&o.sub("method"), format!("unknown method {m:?}"))),
                        };
                        let headers = crate::parse_headers(o, "headers")?;
                        DnsServerKind::Https {
                            server,
                            tls,
                            path,
                            get,
                            headers,
                        }
                    }
                }
            };
            (kind, dial)
        }
        "fakeip" => {
            let inet4_range = prefix_opt(o, "inet4_range")?;
            let inet6_range = prefix_opt(o, "inet6_range")?;
            (fakeip_kind(o, inet4_range, inet6_range)?, no_dial())
        }
        "quic" | "h3" | "dhcp" | "mdns" | "tailscale" | "resolved" | "openconnect" | "openvpn" => {
            return Err(Error::at(
                &o.sub("type"),
                format!("DNS server type {ty:?} not supported by sbr yet"),
            ));
        }
        t => return Err(Error::at(&o.sub("type"), format!("unknown DNS server type {t:?}"))),
    };
    Ok(DnsServer {
        tag,
        kind,
        dial,
        legacy: None,
    })
}

fn fakeip_kind(o: &Obj, v4: Option<IpNet>, v6: Option<IpNet>) -> Result<DnsServerKind> {
    let inet4_range = match v4 {
        None => None,
        Some(IpNet::V4(n)) => Some(n),
        Some(_) => return Err(Error::at(&o.sub("inet4_range"), "expected an IPv4 prefix")),
    };
    let inet6_range = match v6 {
        None => None,
        Some(IpNet::V6(n)) => Some(n),
        Some(_) => return Err(Error::at(&o.sub("inet6_range"), "expected an IPv6 prefix")),
    };
    // Allocation starts at network+2 and stops before the last address.
    if inet4_range.is_some_and(|n| n.prefix_len() > 30) || inet6_range.is_some_and(|n| n.prefix_len() > 126) {
        return Err(Error::at(o.path(), "fakeip range too small"));
    }
    Ok(DnsServerKind::FakeIp {
        inet4_range,
        inet6_range,
    })
}

fn server_addr(o: &mut Obj, default_port: u16) -> Result<ServerAddr> {
    let server: String = o.req("server")?;
    if server.is_empty() {
        return Err(Error::at(&o.sub("server"), "empty server address"));
    }
    let server_port = o.opt::<u16>("server_port")?.filter(|p| *p != 0).unwrap_or(default_port);
    Ok(ServerAddr { server, server_port })
}

/// The DNS transports run their own TLS client (rustls or a browser
/// fingerprint); refuse what it can't honour.
fn dns_tls(o: &mut Obj, diag: &mut Diag) -> Result<TlsOutbound> {
    let path = o.sub("tls");
    let tls = crate::tls::parse_tls(o, "tls", diag)?.unwrap_or_default();
    let unsupported = [
        ("reality", tls.reality.as_ref().is_some_and(|r| r.enabled)),
        ("ech", tls.ech.as_ref().is_some_and(|e| e.enabled)),
        ("fragment", tls.fragment),
        ("record_fragment", tls.record_fragment),
        ("certificate_sha256", !tls.certificate_sha256.is_empty()),
        (
            "certificate_public_key_sha256",
            !tls.certificate_public_key_sha256.is_empty(),
        ),
        (
            "client_certificate",
            tls.client_certificate.is_some() || tls.client_certificate_path.is_some(),
        ),
    ];
    for (k, set) in unsupported {
        if set {
            return Err(Error::at(
                &format!("{path}.{k}"),
                "not supported for DNS servers by sbr yet",
            ));
        }
    }
    Ok(tls)
}

/// Convert a legacy `address` server to the typed form.
fn parse_legacy_server(
    o: &mut Obj,
    tag: String,
    legacy_fakeip: Option<(Option<IpNet>, Option<IpNet>)>,
    diag: &mut Diag,
) -> Result<DnsServer> {
    let apath = o.sub("address");
    let address: String = o.req("address")?;
    diag.warnings.push(format!(
        "{}: legacy DNS server format is deprecated in sing-box 1.12; use typed servers",
        o.path()
    ));
    let resolver = o.string("address_resolver")?;
    let address_strategy: Option<DomainStrategy> = o.opt("address_strategy")?;
    let legacy = LegacyServer {
        strategy: o.opt("strategy")?,
        client_subnet: client_subnet(o, "client_subnet")?,
        default_outbound: false,
    };
    let detour = o.string("detour")?;
    let bad = |msg: &str| Error::at(&apath, format!("{msg}: {address:?}"));
    let (scheme, rest) = match address.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r.to_owned()),
        None => (String::new(), address.clone()),
    };
    let host_port = |rest: &str, default: u16| -> Result<ServerAddr> {
        let authority = rest.split('/').next().unwrap_or_default();
        let (host, port) = split_host_port(authority).ok_or_else(|| bad("invalid server address"))?;
        Ok(ServerAddr {
            server: host,
            server_port: port.unwrap_or(default),
        })
    };
    let kind = match scheme.as_str() {
        "" if address == "local" => DnsServerKind::Local,
        "" if address == "fakeip" => {
            let Some((v4, v6)) = legacy_fakeip else {
                return Err(bad("fakeip server requires dns.fakeip.enabled"));
            };
            fakeip_kind(o, v4, v6)?
        }
        "" | "udp" => DnsServerKind::Udp(host_port(&rest, 53)?),
        "tcp" => DnsServerKind::Tcp(host_port(&rest, 53)?),
        "tls" => DnsServerKind::Tls {
            server: host_port(&rest, 853)?,
            tls: TlsOutbound {
                enabled: true,
                ..TlsOutbound::default()
            },
        },
        "https" => {
            let path = rest.find('/').map(|i| rest[i..].to_owned());
            DnsServerKind::Https {
                server: host_port(&rest, 443)?,
                tls: TlsOutbound {
                    enabled: true,
                    ..TlsOutbound::default()
                },
                path: path.filter(|p| p != "/").unwrap_or_else(|| "/dns-query".into()),
                get: false,
                headers: Vec::new(),
            }
        }
        "rcode" => DnsServerKind::Rcode(match rest.as_str() {
            "success" => 0,
            "format_error" => 1,
            "server_failure" => 2,
            "name_error" => 3,
            "not_implemented" => 4,
            "refused" => 5,
            _ => return Err(bad("unknown rcode")),
        }),
        "quic" | "h3" | "dhcp" => return Err(bad("DNS server scheme not supported by sbr yet")),
        _ => return Err(bad("unknown DNS server address")),
    };
    let dials = !matches!(
        kind,
        DnsServerKind::FakeIp { .. } | DnsServerKind::Rcode(_) | DnsServerKind::Local
    );
    if matches!(kind, DnsServerKind::Local) && detour.is_some() {
        return Err(Error::at(
            &o.sub("detour"),
            "detour on a local server is not supported by sbr yet",
        ));
    }
    let dial = Dial {
        domain_resolver: resolver.map(|server| DomainResolver {
            server,
            options: DnsRouteOptions {
                strategy: address_strategy,
                ..Default::default()
            },
        }),
        detour: detour.clone(),
        ..Dial::default()
    };
    Ok(DnsServer {
        tag,
        kind,
        dial,
        legacy: Some(LegacyServer {
            default_outbound: dials && detour.is_none(),
            ..legacy
        }),
    })
}

/// `host`, `host:port`, `[v6]:port` or a bare IPv6 address.
fn split_host_port(s: &str) -> Option<(String, Option<u16>)> {
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((host.to_owned(), port));
    }
    if s.parse::<Ipv6Addr>().is_ok() {
        return Some((s.to_owned(), None));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Some((h.to_owned(), Some(p.parse().ok()?))),
        None => Some((s.to_owned(), None)),
    }
}

fn parse_dns_rule(mut o: Obj, diag: &mut Diag) -> Result<DnsRule> {
    let (kind, invert) = parse_rule_body(&mut o, true, diag)?;
    let action = parse_dns_action(&mut o)?;
    for k in [
        "match_response",
        "response_rcode",
        "response_answer",
        "response_ns",
        "response_extra",
        "race",
    ] {
        if o.has(k) {
            return Err(Error::at(
                &o.sub(k),
                "response matching (sing-box 1.14) not supported by sbr yet",
            ));
        }
    }
    for k in ["query_client_subnet", "query_dnssec", "preferred_by"] {
        if o.has(k) {
            return Err(Error::at(&o.sub(k), "not supported by sbr yet"));
        }
    }
    o.finish()?;
    Ok(DnsRule {
        rule: Rule {
            kind,
            invert,
            action: RuleAction::None,
        },
        action,
    })
}

fn parse_dns_action(o: &mut Obj) -> Result<DnsRuleAction> {
    let action = o.string("action")?.unwrap_or_else(|| "route".into());
    Ok(match action.as_str() {
        "route" => {
            let server = o
                .string("server")?
                .ok_or_else(|| Error::at(&o.sub("server"), "missing server"))?;
            let options = parse_route_options(o)?;
            if o.has("speculative") {
                return Err(Error::at(&o.sub("speculative"), "not supported by sbr yet"));
            }
            DnsRuleAction::Route { server, options }
        }
        "route-options" => DnsRuleAction::RouteOptions(parse_route_options(o)?),
        "reject" => {
            let method = match o.string("method")?.as_deref() {
                None | Some("default") => RejectMethod::Default,
                Some("drop") => RejectMethod::Drop,
                Some(m) => return Err(Error::at(&o.sub("method"), format!("unknown reject method {m:?}"))),
            };
            let no_drop = o.bool("no_drop")?;
            if method == RejectMethod::Drop && no_drop {
                return Err(Error::at(
                    &o.sub("no_drop"),
                    "no_drop is not available with method drop",
                ));
            }
            DnsRuleAction::Reject { method, no_drop }
        }
        "predefined" => {
            let rcode = match o.raw("rcode") {
                None => 0,
                Some(v) => parse_rcode(&v).ok_or_else(|| Error::at(&o.sub("rcode"), format!("unknown rcode {v}")))?,
            };
            DnsRuleAction::Predefined(Predefined {
                rcode,
                answer: records(o, "answer")?,
                ns: records(o, "ns")?,
                extra: records(o, "extra")?,
            })
        }
        a @ ("evaluate" | "respond") => {
            return Err(Error::at(
                &o.sub("action"),
                format!("action {a:?} not supported by sbr yet"),
            ));
        }
        a => return Err(Error::at(&o.sub("action"), format!("unknown DNS rule action {a:?}"))),
    })
}

fn parse_route_options(o: &mut Obj) -> Result<DnsRouteOptions> {
    let r = DnsRouteOptions {
        strategy: o.opt("strategy")?,
        disable_cache: o.bool("disable_cache")?,
        disable_optimistic_cache: o.bool("disable_optimistic_cache")?,
        rewrite_ttl: o.opt("rewrite_ttl")?,
        timeout: o.duration("timeout")?,
        client_subnet: client_subnet(o, "client_subnet")?,
        remove_client_subnet: o.bool("remove_client_subnet")?,
    };
    if r.client_subnet.is_some() && r.remove_client_subnet {
        return Err(Error::at(
            &o.sub("remove_client_subnet"),
            "conflicts with client_subnet",
        ));
    }
    Ok(r)
}

/// `domain_resolver`: a server tag, or `{"server": ..., <route options>}`.
pub(crate) fn parse_domain_resolver(o: &mut Obj, key: &str) -> Result<Option<DomainResolver>> {
    match o.raw(key) {
        None => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(server)) => Ok(Some(DomainResolver {
            server,
            options: DnsRouteOptions::default(),
        })),
        Some(v) => {
            let mut r = Obj::new(v, o.sub(key))?;
            let server = r.string("server")?;
            let options = parse_route_options(&mut r)?;
            r.finish()?;
            Ok(server.map(|server| DomainResolver { server, options }))
        }
    }
}

/// sing-box `Prefixable`: a prefix, or an address meaning /32 or /128.
fn client_subnet(o: &mut Obj, key: &str) -> Result<Option<IpNet>> {
    let path = o.sub(key);
    Ok(match o.string(key)? {
        None => None,
        Some(s) => Some(
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| Error::at(&path, format!("invalid prefix {s:?}")))?,
        ),
    })
}

fn prefix_opt(o: &mut Obj, key: &str) -> Result<Option<IpNet>> {
    let path = o.sub(key);
    Ok(match o.string(key)? {
        None => None,
        Some(s) => Some(
            s.parse::<IpNet>()
                .map(|n| n.trunc())
                .map_err(|_| Error::at(&path, format!("invalid prefix {s:?}")))?,
        ),
    })
}

fn records(o: &mut Obj, key: &str) -> Result<Vec<DnsRecord>> {
    let path = o.sub(key);
    o.list::<String>(key)?
        .iter()
        .enumerate()
        .map(|(i, s)| parse_record(s).map_err(|e| Error::at(&format!("{path}[{i}]"), e)))
        .collect()
}

/// Query types by name (miekg/dns `StringToType`, the commonly used part) or number.
pub fn parse_query_type(v: &Value) -> Option<u16> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(s) => record_type(s),
        _ => None,
    }
}

fn record_type(s: &str) -> Option<u16> {
    let s = s.to_ascii_uppercase();
    Some(match s.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "HINFO" => 13,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "NAPTR" => 35,
        "DS" => 43,
        "SSHFP" => 44,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "NSEC3" => 50,
        "TLSA" => 52,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "AXFR" => 252,
        "ANY" => 255,
        "CAA" => 257,
        _ => return s.strip_prefix("TYPE")?.parse().ok(),
    })
}

fn parse_rcode(v: &Value) -> Option<u16> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()).filter(|n| *n < 4096),
        Value::String(s) => Some(match s.to_ascii_uppercase().as_str() {
            "NOERROR" => 0,
            "FORMERR" => 1,
            "SERVFAIL" => 2,
            "NXDOMAIN" => 3,
            "NOTIMP" => 4,
            "REFUSED" => 5,
            "YXDOMAIN" => 6,
            "YXRRSET" => 7,
            "NXRRSET" => 8,
            "NOTAUTH" => 9,
            "NOTZONE" => 10,
            _ => return None,
        }),
        _ => None,
    }
}

/// One RR in zone-file syntax: `name [ttl] [class] type rdata`, or base64
/// of its wire form.
pub fn parse_record(s: &str) -> std::result::Result<DnsRecord, String> {
    use base64::Engine;
    if !s.contains(char::is_whitespace)
        && let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(s)
    {
        return Ok(DnsRecord::Wire(raw));
    }
    let tokens = tokenize(s)?;
    let mut it = tokens.into_iter().peekable();
    let name = it.next().ok_or("empty DNS record")?;
    let name = fqdn(&name);
    let mut ttl = RECORD_TTL;
    let mut ty = None;
    for tok in it.by_ref() {
        if let Ok(n) = tok.parse::<u32>() {
            ttl = n;
        } else if tok.eq_ignore_ascii_case("IN") {
        } else if ["CH", "HS", "CS"].iter().any(|c| tok.eq_ignore_ascii_case(c)) {
            return Err(format!("unsupported class {tok}"));
        } else {
            ty = Some(tok.to_ascii_uppercase());
            break;
        }
    }
    let ty = ty.ok_or("missing record type")?;
    let rest: Vec<String> = it.collect();
    let one = |what: &str| -> std::result::Result<&String, String> {
        match rest.as_slice() {
            [x] => Ok(x),
            _ => Err(format!("{ty} record needs one {what}")),
        }
    };
    let data = match ty.as_str() {
        "A" => RecordData::A(one("address")?.parse().map_err(|_| "invalid IPv4 address")?),
        "AAAA" => RecordData::Aaaa(one("address")?.parse().map_err(|_| "invalid IPv6 address")?),
        "CNAME" => RecordData::Cname(fqdn(one("name")?)),
        "NS" => RecordData::Ns(fqdn(one("name")?)),
        "PTR" => RecordData::Ptr(fqdn(one("name")?)),
        "MX" => match rest.as_slice() {
            [p, x] => RecordData::Mx(p.parse().map_err(|_| "invalid MX preference")?, fqdn(x)),
            _ => return Err("MX record needs a preference and a name".into()),
        },
        "TXT" => {
            if rest.is_empty() {
                return Err("TXT record needs text".into());
            }
            RecordData::Txt(rest)
        }
        t => return Err(format!("record type {t} not supported by sbr yet")),
    };
    Ok(DnsRecord::Text { name, ttl, data })
}

fn fqdn(s: &str) -> String {
    let mut s = s.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// Whitespace-separated tokens; double-quoted strings may contain spaces and `\"`.
fn tokenize(s: &str) -> std::result::Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut chars = s.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut tok = String::new();
        if c == '"' {
            chars.next();
            loop {
                match chars.next() {
                    None => return Err("unterminated string".into()),
                    Some('"') => break,
                    Some('\\') => tok.push(chars.next().ok_or("unterminated string")?),
                    Some(c) => tok.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                tok.push(c);
                chars.next();
            }
        }
        out.push(tok);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records() {
        let r = parse_record("localhost. IN A 127.0.0.1").unwrap();
        assert_eq!(
            r,
            DnsRecord::Text {
                name: "localhost.".into(),
                ttl: RECORD_TTL,
                data: RecordData::A(Ipv4Addr::LOCALHOST)
            }
        );
        let r = parse_record("*.Example.com 60 IN TXT \"hello world\" x").unwrap();
        assert_eq!(
            r,
            DnsRecord::Text {
                name: "*.example.com.".into(),
                ttl: 60,
                data: RecordData::Txt(vec!["hello world".into(), "x".into()])
            }
        );
        assert!(parse_record("a. IN A ::1").is_err());
        assert!(parse_record("a. IN LOC 1 2 3").unwrap_err().contains("not supported"));
        assert!(matches!(
            parse_record("AAABAAEAAA4QAAR/AAAB").unwrap(),
            DnsRecord::Wire(_)
        ));
    }

    #[test]
    fn host_port() {
        assert_eq!(split_host_port("1.1.1.1"), Some(("1.1.1.1".into(), None)));
        assert_eq!(
            split_host_port("dns.google:853"),
            Some(("dns.google".into(), Some(853)))
        );
        assert_eq!(split_host_port("[::1]:5353"), Some(("::1".into(), Some(5353))));
        assert_eq!(split_host_port("2001:db8::1"), Some(("2001:db8::1".into(), None)));
        assert_eq!(split_host_port("a:b"), None);
    }

    #[test]
    fn query_types() {
        assert_eq!(parse_query_type(&"https".into()), Some(65));
        assert_eq!(parse_query_type(&32768.into()), Some(32768));
        assert_eq!(parse_query_type(&"TYPE99".into()), Some(99));
        assert_eq!(parse_query_type(&"nope".into()), None);
    }
}
