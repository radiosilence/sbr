//! What the tunnel does to a profile before running it: the app's log level
//! and tun stack overrides, then the user's personal rules.

use std::collections::BTreeSet;

use sbr_message::PersonalRule;
use serde_json::{Map, Value, json};

/// The config with its `log.level` replaced and every tun inbound's `stack`
/// set; unchanged if neither is given or the config is not plain JSON.
pub fn with_overrides(config: &str, level: Option<&str>, stack: Option<&str>) -> String {
    if level.is_none() && stack.is_none() {
        return config.to_owned();
    }
    let Ok(Value::Object(mut root)) = serde_json::from_str::<Value>(config) else {
        return config.to_owned();
    };
    if let Some(level) = level {
        let log = root.entry("log").or_insert_with(|| Value::Object(Map::new()));
        if !log.is_object() {
            *log = Value::Object(Map::new());
        }
        log["level"] = json!(level);
    }
    if let Some(stack) = stack
        && let Some(Value::Array(inbounds)) = root.get_mut("inbounds")
    {
        for i in inbounds.iter_mut() {
            if i.get("type").and_then(Value::as_str) == Some("tun")
                && let Some(i) = i.as_object_mut()
            {
                i.insert("stack".into(), json!(stack));
            }
        }
    }
    serde_json::to_string(&Value::Object(root)).unwrap_or_else(|_| config.to_owned())
}

/// The sing-box route rule for `r`.
fn route_rule(r: &PersonalRule) -> Value {
    let key = if r.subdomains { "domain_suffix" } else { "domain" };
    json!({ key: r.domains, "action": "route", "outbound": r.outbound })
}

/// Every outbound and endpoint tag in a config.
fn tags(root: &Map<String, Value>) -> BTreeSet<&str> {
    ["outbounds", "endpoints"]
        .iter()
        .filter_map(|k| root.get(*k).and_then(Value::as_array))
        .flatten()
        .filter_map(|o| o.get("tag").and_then(Value::as_str))
        .collect()
}

/// `config` with the enabled `rules` put into `route.rules`, in order, after
/// the last `sniff` or `hijack-dns` rule so they see sniffed domains and DNS
/// is still answered; and the rules left out because the config has no
/// outbound by that tag. Unchanged if there is nothing to insert or the
/// config is not plain JSON.
pub fn apply(rules: &[PersonalRule], config: &str) -> (String, Vec<PersonalRule>) {
    let enabled: Vec<&PersonalRule> = rules.iter().filter(|r| r.enabled && !r.domains.is_empty()).collect();
    if enabled.is_empty() {
        return (config.to_owned(), Vec::new());
    }
    let Ok(Value::Object(mut root)) = serde_json::from_str::<Value>(config) else {
        return (config.to_owned(), Vec::new());
    };
    let known = tags(&root);
    let (usable, skipped): (Vec<&PersonalRule>, Vec<&PersonalRule>) =
        enabled.into_iter().partition(|r| known.contains(r.outbound.as_str()));
    let skipped: Vec<PersonalRule> = skipped.into_iter().cloned().collect();
    if usable.is_empty() {
        return (config.to_owned(), skipped);
    }
    let route = root.entry("route").or_insert_with(|| Value::Object(Map::new()));
    if !route.is_object() {
        *route = Value::Object(Map::new());
    }
    let existing = route
        .as_object_mut()
        .expect("an object")
        .entry("rules")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !existing.is_array() {
        *existing = Value::Array(Vec::new());
    }
    let existing = existing.as_array_mut().expect("an array");
    let at = existing
        .iter()
        .rposition(|r| matches!(r.get("action").and_then(Value::as_str), Some("sniff" | "hijack-dns")))
        .map_or(0, |i| i + 1);
    existing.splice(at..at, usable.into_iter().map(route_rule));
    match serde_json::to_string(&Value::Object(root)) {
        Ok(s) => (s, skipped),
        Err(_) => (config.to_owned(), skipped),
    }
}

/// The domains whose routing differs between two rule lists, as
/// `(domain, subdomains)`, so their open connections can be closed and
/// reopened on the new route.
pub fn changed_domains(old: &[PersonalRule], new: &[PersonalRule]) -> Vec<(String, bool)> {
    fn entries(rules: &[PersonalRule]) -> BTreeSet<(&str, &str, bool)> {
        rules
            .iter()
            .filter(|r| r.enabled)
            .flat_map(|r| {
                r.domains
                    .iter()
                    .map(|d| (d.as_str(), r.outbound.as_str(), r.subdomains))
            })
            .collect()
    }
    let (a, b) = (entries(old), entries(new));
    let mut seen = BTreeSet::new();
    // Ordered by domain, then outbound, as the sets are.
    a.symmetric_difference(&b)
        .filter(|(d, _, s)| seen.insert((*s, *d)))
        .map(|(d, _, s)| ((*d).to_owned(), *s))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(domains: &[&str], outbound: &str, subdomains: bool, enabled: bool) -> PersonalRule {
        PersonalRule {
            id: "00000000-0000-4000-8000-000000000000".into(),
            name: None,
            domains: domains.iter().map(|d| (*d).to_owned()).collect(),
            subdomains,
            outbound: outbound.into(),
            enabled,
        }
    }

    const CONFIG: &str = r#"{"inbounds":[{"type":"tun","tag":"tun-in"},{"type":"mixed"}],
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"proxy"}],
        "route":{"rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"},{"ip_is_private":true,"outbound":"direct"}]}}"#;

    #[test]
    fn overrides_set_level_and_tun_stack() {
        let out: Value = serde_json::from_str(&with_overrides(CONFIG, Some("debug"), Some("gvisor"))).unwrap();
        assert_eq!(out["log"]["level"], "debug");
        assert_eq!(out["inbounds"][0]["stack"], "gvisor");
        assert!(out["inbounds"][1].get("stack").is_none());
    }

    #[test]
    fn no_overrides_leave_the_text_alone() {
        assert_eq!(with_overrides("// comment\n{}", None, None), "// comment\n{}");
        assert_eq!(with_overrides("// comment\n{}", Some("debug"), None), "// comment\n{}");
    }

    #[test]
    fn rules_go_after_the_last_sniff_or_hijack() {
        let rules = [
            rule(&["example.com"], "proxy", true, true),
            rule(&["exact.example"], "direct", false, true),
            rule(&["off.example"], "proxy", true, false),
            rule(&["gone.example"], "missing", true, true),
        ];
        let (out, skipped) = apply(&rules, CONFIG);
        let out: Value = serde_json::from_str(&out).unwrap();
        let r = out["route"]["rules"].as_array().unwrap();
        assert_eq!(r.len(), 5);
        assert_eq!(
            r[2],
            json!({"domain_suffix": ["example.com"], "action": "route", "outbound": "proxy"})
        );
        assert_eq!(
            r[3],
            json!({"domain": ["exact.example"], "action": "route", "outbound": "direct"})
        );
        assert_eq!(r[4]["outbound"], "direct");
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].outbound, "missing");
    }

    #[test]
    fn rules_without_a_route_section_start_one() {
        let (out, _) = apply(
            &[rule(&["a.example"], "direct", true, true)],
            r#"{"outbounds":[{"tag":"direct"}]}"#,
        );
        let out: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(out["route"]["rules"][0]["outbound"], "direct");
    }

    #[test]
    fn nothing_usable_leaves_the_text_alone() {
        let (out, skipped) = apply(&[rule(&["a.example"], "nope", true, true)], CONFIG);
        assert_eq!(out, CONFIG);
        assert_eq!(skipped.len(), 1);
        assert_eq!(apply(&[], CONFIG).0, CONFIG);
    }

    #[test]
    fn changed_domains_are_the_symmetric_difference() {
        let old = [
            rule(&["a.example", "b.example"], "proxy", true, true),
            rule(&["c.example"], "proxy", false, true),
        ];
        let new = [
            rule(&["a.example"], "proxy", true, true),
            rule(&["b.example"], "direct", true, true),
            rule(&["c.example"], "proxy", false, false),
        ];
        assert_eq!(
            changed_domains(&old, &new),
            vec![("b.example".to_owned(), true), ("c.example".to_owned(), false)]
        );
    }
}
