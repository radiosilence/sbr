use ipnet::IpNet;
use serde_json::Value;

use crate::obj::{Diag, Obj};
use crate::{Error, Network, Result, array};

#[derive(Debug, Clone, Default)]
pub struct RouteOptions {
    pub rules: Vec<Rule>,
    pub rule_sets: Vec<RuleSet>,
    pub final_outbound: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub invert: bool,
    /// `RuleAction::None` for headless rules (inside rule-sets and logical rules).
    pub action: RuleAction,
}

#[derive(Debug, Clone)]
pub enum RuleKind {
    Default(Box<Matchers>),
    Logical { mode: LogicalMode, rules: Vec<Rule> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalMode {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    None,
    Route {
        outbound: String,
    },
    Reject {
        method: RejectMethod,
        no_drop: bool,
    },
    /// Accepted for compatibility; sbr's proxy inbounds already carry the
    /// requested domain, so there is nothing to sniff yet.
    Sniff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectMethod {
    Default,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Default)]
pub struct Matchers {
    pub inbound: Vec<String>,
    pub ip_version: Option<u8>,
    pub network: Vec<Network>,
    pub auth_user: Vec<String>,
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub source_ip_cidr: Vec<IpNet>,
    pub source_ip_is_private: bool,
    pub ip_cidr: Vec<IpNet>,
    pub ip_is_private: bool,
    pub source_port: Vec<u16>,
    pub source_port_range: Vec<PortRange>,
    pub port: Vec<u16>,
    pub port_range: Vec<PortRange>,
    pub rule_set: Vec<String>,
    pub rule_set_ip_cidr_match_source: bool,
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub tag: String,
    pub source: RuleSetSource,
}

#[derive(Debug, Clone)]
pub enum RuleSetSource {
    Inline(Vec<Rule>),
    /// A local `source` (JSON) rule-set file. Loaded by the core at start.
    LocalSource(String),
}

pub(crate) fn parse_route(mut o: Obj, diag: &mut Diag) -> Result<RouteOptions> {
    let rules = parse_rules(o.raw("rules"), &o.sub("rules"), true, diag)?;
    let rule_sets = array(o.raw("rule_set"), &o.sub("rule_set"))?
        .into_iter()
        .enumerate()
        .map(|(i, v)| parse_rule_set(Obj::new(v, format!("route.rule_set[{i}]"))?, diag))
        .collect::<Result<Vec<_>>>()?;
    let final_outbound = o.string("final")?;
    o.tolerate(
        diag,
        &[
            "auto_detect_interface",
            "override_android_vpn",
            "default_interface",
            "default_mark",
            "find_process",
            "find_neighbor",
            "default_domain_resolver",
            "default_network_strategy",
            "default_network_type",
            "default_fallback_network_type",
            "default_fallback_delay",
        ],
    );
    for k in ["geoip", "geosite"] {
        if o.has(k) {
            return Err(Error::at(
                &o.sub(k),
                "removed in sing-box 1.12; migrate to rule_set",
            ));
        }
    }
    o.finish()?;
    Ok(RouteOptions {
        rules,
        rule_sets,
        final_outbound,
    })
}

fn parse_rule_set(mut o: Obj, diag: &mut Diag) -> Result<RuleSet> {
    let ty: String = o.req("type")?;
    let tag: String = o.req("tag")?;
    let source = match ty.as_str() {
        "inline" => {
            RuleSetSource::Inline(parse_rules(o.raw("rules"), &o.sub("rules"), false, diag)?)
        }
        "local" => {
            let format = o.string("format")?;
            let path: String = o.req("path")?;
            let format = format.unwrap_or_else(|| {
                if path.ends_with(".srs") {
                    "binary".into()
                } else {
                    "source".into()
                }
            });
            match format.as_str() {
                "source" => RuleSetSource::LocalSource(path),
                "binary" => {
                    return Err(Error::at(
                        &o.sub("format"),
                        "binary (.srs) rule-sets not supported by sbr yet",
                    ));
                }
                f => return Err(Error::at(&o.sub("format"), format!("unknown format {f:?}"))),
            }
        }
        "remote" => {
            return Err(Error::at(
                &o.sub("type"),
                "remote rule-sets not supported by sbr yet",
            ));
        }
        t => {
            return Err(Error::at(
                &o.sub("type"),
                format!("unknown rule-set type {t:?}"),
            ));
        }
    };
    o.finish()?;
    Ok(RuleSet { tag, source })
}

/// Parse a rule-set source file (`{"version": N, "rules": [...]}`).
pub fn parse_rule_set_source(input: &str) -> Result<Vec<Rule>> {
    let value: Value = serde_json::from_str(&crate::types::strip_comments(input))?;
    let mut o = Obj::new(value, "")?;
    let version: u8 = o.req("version")?;
    if !(1..=4).contains(&version) {
        return Err(Error::at(
            "version",
            format!("unsupported rule-set version {version}"),
        ));
    }
    let mut diag = Diag {
        warnings: Vec::new(),
    };
    let rules = parse_rules(o.raw("rules"), "rules", false, &mut diag)?;
    o.finish()?;
    Ok(rules)
}

fn parse_rules(
    v: Option<Value>,
    path: &str,
    with_action: bool,
    diag: &mut Diag,
) -> Result<Vec<Rule>> {
    array(v, path)?
        .into_iter()
        .enumerate()
        .map(|(i, v)| parse_rule(Obj::new(v, format!("{path}[{i}]"))?, with_action, diag))
        .collect()
}

fn parse_rule(mut o: Obj, with_action: bool, diag: &mut Diag) -> Result<Rule> {
    let ty = o.string("type")?.unwrap_or_else(|| "default".into());
    let invert = o.bool("invert")?;
    let kind = match ty.as_str() {
        "default" => RuleKind::Default(Box::new(parse_matchers(&mut o)?)),
        "logical" => {
            let mode = match o.req::<String>("mode")?.as_str() {
                "and" => LogicalMode::And,
                "or" => LogicalMode::Or,
                m => {
                    return Err(Error::at(
                        &o.sub("mode"),
                        format!("unknown logical mode {m:?}"),
                    ));
                }
            };
            let rules = parse_rules(o.raw("rules"), &o.sub("rules"), false, diag)?;
            if rules.is_empty() {
                return Err(Error::at(&o.sub("rules"), "missing rules"));
            }
            RuleKind::Logical { mode, rules }
        }
        t => {
            return Err(Error::at(
                &o.sub("type"),
                format!("unknown rule type {t:?}"),
            ));
        }
    };
    let action = if with_action {
        parse_action(&mut o, diag)?
    } else {
        RuleAction::None
    };
    o.finish()?;
    Ok(Rule {
        kind,
        invert,
        action,
    })
}

fn parse_action(o: &mut Obj, diag: &mut Diag) -> Result<RuleAction> {
    let action = o.string("action")?.unwrap_or_else(|| "route".into());
    Ok(match action.as_str() {
        "route" => {
            let outbound = o
                .string("outbound")?
                .ok_or_else(|| Error::at(&o.sub("outbound"), "missing outbound"))?;
            RuleAction::Route { outbound }
        }
        "reject" => {
            let method = match o.string("method")?.as_deref() {
                None | Some("default") => RejectMethod::Default,
                Some("drop") => RejectMethod::Drop,
                Some(m) => {
                    return Err(Error::at(
                        &o.sub("method"),
                        format!("unknown reject method {m:?}"),
                    ));
                }
            };
            let no_drop = o.bool("no_drop")?;
            if method == RejectMethod::Drop && no_drop {
                return Err(Error::at(
                    &o.sub("no_drop"),
                    "no_drop is not available with method drop",
                ));
            }
            RuleAction::Reject { method, no_drop }
        }
        "sniff" => {
            o.raw("sniffer");
            o.raw("timeout");
            diag.warnings.push(format!(
                "{}: sniff is a no-op in sbr (no TUN inbound yet)",
                o.path()
            ));
            RuleAction::Sniff
        }
        a @ ("route-options" | "bypass" | "hijack-dns" | "resolve") => {
            return Err(Error::at(
                &o.sub("action"),
                format!("action {a:?} not supported by sbr yet"),
            ));
        }
        a => {
            return Err(Error::at(
                &o.sub("action"),
                format!("unknown rule action {a:?}"),
            ));
        }
    })
}

fn parse_matchers(o: &mut Obj) -> Result<Matchers> {
    let m = Matchers {
        inbound: o.list("inbound")?,
        ip_version: match o.opt::<u8>("ip_version")? {
            None | Some(0) => None,
            Some(v @ (4 | 6)) => Some(v),
            Some(v) => {
                return Err(Error::at(
                    &o.sub("ip_version"),
                    format!("invalid ip version {v}"),
                ));
            }
        },
        network: o.list("network")?,
        auth_user: o.list("auth_user")?,
        domain: o
            .list::<String>("domain")?
            .into_iter()
            .map(|d| d.to_ascii_lowercase())
            .collect(),
        domain_suffix: o
            .list::<String>("domain_suffix")?
            .into_iter()
            .map(|d| d.to_ascii_lowercase())
            .collect(),
        domain_keyword: o
            .list::<String>("domain_keyword")?
            .into_iter()
            .map(|d| d.to_ascii_lowercase())
            .collect(),
        domain_regex: o.list("domain_regex")?,
        source_ip_cidr: cidrs(o, "source_ip_cidr")?,
        source_ip_is_private: o.bool("source_ip_is_private")?,
        ip_cidr: cidrs(o, "ip_cidr")?,
        ip_is_private: o.bool("ip_is_private")?,
        source_port: o.list("source_port")?,
        source_port_range: ranges(o, "source_port_range")?,
        port: o.list("port")?,
        port_range: ranges(o, "port_range")?,
        rule_set: o.list("rule_set")?,
        rule_set_ip_cidr_match_source: o.bool("rule_set_ip_cidr_match_source")?
            | o.bool("rule_set_ipcidr_match_source")?,
    };
    for re in &m.domain_regex {
        // Validated here so config errors surface at load, with a path.
        if re.is_empty() {
            return Err(Error::at(&o.sub("domain_regex"), "empty regex"));
        }
    }
    Ok(m)
}

fn cidrs(o: &mut Obj, key: &str) -> Result<Vec<IpNet>> {
    let path = o.sub(key);
    o.list::<String>(key)?
        .into_iter()
        .map(|s| {
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
                .map(|n| n.trunc())
                .map_err(|_| Error::at(&path, format!("invalid prefix {s:?}")))
        })
        .collect()
}

fn ranges(o: &mut Obj, key: &str) -> Result<Vec<PortRange>> {
    let path = o.sub(key);
    o.list::<String>(key)?
        .into_iter()
        .map(|s| {
            let bad = || Error::at(&path, format!("invalid port range {s:?}"));
            let (a, b) = s.split_once(':').ok_or_else(bad)?;
            let start = if a.is_empty() {
                0
            } else {
                a.parse().map_err(|_| bad())?
            };
            let end = if b.is_empty() {
                u16::MAX
            } else {
                b.parse().map_err(|_| bad())?
            };
            if start > end {
                return Err(bad());
            }
            Ok(PortRange { start, end })
        })
        .collect()
}
