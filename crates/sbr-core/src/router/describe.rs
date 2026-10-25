//! Human-readable rules, in the shape sing-box prints them (`Rule.String()`
//! and `RuleAction.String()`), for the Clash API.

use std::fmt::Write;

use sbr_config::{LogicalMode, Matchers, RejectMethod, Rule, RuleAction, RuleKind};

/// One route rule as dashboards show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleInfo {
    /// `default` or `logical`.
    pub kind: &'static str,
    /// e.g. `domain_suffix=[a.com b.com] port=443`.
    pub payload: String,
    /// e.g. `route(proxy)`, `reject`, `sniff`.
    pub action: String,
}

impl RuleInfo {
    pub fn new(r: &Rule) -> Self {
        Self {
            kind: match r.kind {
                RuleKind::Default(_) => "default",
                RuleKind::Logical { .. } => "logical",
            },
            payload: payload(r),
            action: action(&r.action),
        }
    }
}

fn payload(r: &Rule) -> String {
    let s = match &r.kind {
        RuleKind::Default(m) => matchers(m),
        RuleKind::Logical { mode, rules } => {
            let op = match mode {
                LogicalMode::And => " && ",
                LogicalMode::Or => " || ",
            };
            let parts: Vec<String> = rules.iter().map(|r| format!("({})", payload(r))).collect();
            parts.join(op)
        }
    };
    if r.invert { format!("!({s})") } else { s }
}

fn list<T: std::fmt::Display>(out: &mut Vec<String>, name: &str, v: &[T]) {
    // Big rule-sets would make `/rules` megabytes long; sing-box truncates too.
    const MAX: usize = 4;
    match v {
        [] => {}
        [one] => out.push(format!("{name}={one}")),
        _ => {
            let mut s = format!("{name}=[");
            for (i, x) in v.iter().take(MAX).enumerate() {
                if i > 0 {
                    s.push(' ');
                }
                let _ = write!(s, "{x}");
            }
            if v.len() > MAX {
                let _ = write!(s, " ...{} more", v.len() - MAX);
            }
            s.push(']');
            out.push(s);
        }
    }
}

fn matchers(m: &Matchers) -> String {
    let mut out = Vec::new();
    list(&mut out, "inbound", &m.inbound);
    if let Some(v) = m.ip_version {
        out.push(format!("ip_version={v}"));
    }
    let nets: Vec<&str> = m
        .network
        .iter()
        .map(|n| match n {
            sbr_config::Network::Tcp => "tcp",
            sbr_config::Network::Udp => "udp",
            sbr_config::Network::Icmp => "icmp",
        })
        .collect();
    list(&mut out, "network", &nets);
    list(&mut out, "auth_user", &m.auth_user);
    let protos: Vec<&str> = m.protocol.iter().map(|p| p.as_str()).collect();
    list(&mut out, "protocol", &protos);
    list(&mut out, "domain", &m.domain);
    list(&mut out, "domain_suffix", &m.domain_suffix);
    list(&mut out, "domain_keyword", &m.domain_keyword);
    list(&mut out, "domain_regex", &m.domain_regex);
    list(&mut out, "source_ip_cidr", &m.source_ip_cidr);
    if m.source_ip_is_private {
        out.push("source_ip_is_private=true".into());
    }
    list(&mut out, "ip_cidr", &m.ip_cidr);
    if m.ip_is_private {
        out.push("ip_is_private=true".into());
    }
    list(&mut out, "source_port", &m.source_port);
    let r = |v: &[sbr_config::PortRange]| v.iter().map(|r| format!("{}:{}", r.start, r.end)).collect::<Vec<_>>();
    list(&mut out, "source_port_range", &r(&m.source_port_range));
    list(&mut out, "port", &m.port);
    list(&mut out, "port_range", &r(&m.port_range));
    list(&mut out, "rule_set", &m.rule_set);
    if let Some(c) = &m.clash_mode {
        out.push(format!("clash_mode={c}"));
    }
    out.join(" ")
}

fn action(a: &RuleAction) -> String {
    match a {
        RuleAction::None => String::new(),
        RuleAction::Route { outbound, .. } => format!("route({outbound})"),
        RuleAction::RouteOptions(_) => "route-options".into(),
        RuleAction::Reject { method, .. } => match method {
            RejectMethod::Default => "reject".into(),
            RejectMethod::Drop => "reject(drop)".into(),
        },
        RuleAction::HijackDns => "hijack-dns".into(),
        RuleAction::Sniff { .. } => "sniff".into(),
        RuleAction::Resolve { .. } => "resolve".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_like_sing_box() {
        let o = sbr_config::Options::parse(
            r#"{"outbounds":[{"type":"direct","tag":"d"}],"route":{"rules":[
                {"domain_suffix":["a.com","b.com"],"port":443,"outbound":"d"},
                {"type":"logical","mode":"or","rules":[{"port":53},{"clash_mode":"Direct"}],"action":"reject"},
                {"ip_is_private":true,"invert":true,"action":"sniff"}
            ]}}"#,
        )
        .unwrap();
        let info: Vec<RuleInfo> = o.route.rules.iter().map(RuleInfo::new).collect();
        assert_eq!(info[0].payload, "domain_suffix=[a.com b.com] port=443");
        assert_eq!(info[0].action, "route(d)");
        assert_eq!(info[1].kind, "logical");
        assert_eq!(info[1].payload, "(port=53) || (clash_mode=Direct)");
        assert_eq!(info[2].payload, "!(ip_is_private=true)");
        assert_eq!(info[2].action, "sniff");
    }
}
