//! Personal rules: routes the user keeps on top of whatever profile runs.
//! The app checks a profile with them applied and the tunnel runs it with
//! them applied, both through `apply` here, so the two cannot disagree.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::PersonalRule;

impl PersonalRule {
    /// A rule routing `domain` and its subdomains through `outbound`.
    pub fn new(domain: String, outbound: String) -> Self {
        PersonalRule {
            id: uuid::Uuid::new_v4().to_string().to_uppercase(),
            name: None,
            domains: vec![domain],
            subdomains: true,
            outbound,
            enabled: true,
        }
    }
}

/// `input` as a rule matches it: lowercased, without a scheme, path, port
/// or trailing dot. None when what is left is not a host name.
pub fn normalize(input: &str) -> Option<String> {
    let mut s = input.trim().to_lowercase();
    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_owned();
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s.truncate(i);
    }
    if let Some(i) = s.rfind(':') {
        s.truncate(i);
    }
    loop {
        if let Some(rest) = s.strip_prefix("*.") {
            s = rest.to_owned();
        } else if let Some(rest) = s.strip_prefix('.') {
            s = rest.to_owned();
        } else {
            break;
        }
    }
    while s.ends_with('.') {
        s.pop();
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.chars().count() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    (!s.is_empty() && s.chars().count() <= 253 && s.split('.').all(label_ok)).then_some(s)
}

/// JSON for `[SbrPersonalRule]`.
pub fn encode(rules: &[PersonalRule]) -> Vec<u8> {
    serde_json::to_vec(rules).unwrap_or_else(|_| b"[]".to_vec())
}

/// Empty for missing or unreadable data.
pub fn decode(data: Option<&[u8]>) -> Vec<PersonalRule> {
    data.and_then(|d| serde_json::from_slice(d).ok()).unwrap_or_default()
}

/// The sing-box route rule for `r`.
pub fn route_rule(r: &PersonalRule) -> Value {
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

/// The config's selector groups and their members, in profile order: what
/// a rule can route through, grouped as the profile groups it.
pub fn selector_groups(config: &str) -> Vec<(String, Vec<String>)> {
    let Ok(Value::Object(root)) = serde_json::from_str::<Value>(config) else {
        return Vec::new();
    };
    root.get("outbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|o| o.get("type").and_then(Value::as_str) == Some("selector"))
        .filter_map(|s| {
            let tag = s.get("tag")?.as_str()?.to_owned();
            let mut seen = BTreeSet::new();
            let members = s
                .get("outbounds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|m| seen.insert(*m))
                .map(str::to_owned)
                .collect();
            Some((tag, members))
        })
        .collect()
}

/// What a rule can route through: the members of the config's selector
/// groups, then the groups themselves, in profile order.
pub fn choices(config: &str) -> Vec<String> {
    let Ok(Value::Object(root)) = serde_json::from_str::<Value>(config) else {
        return Vec::new();
    };
    let selectors: Vec<&Value> = root
        .get("outbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|o| o.get("type").and_then(Value::as_str) == Some("selector"))
        .collect();
    let members = selectors
        .iter()
        .filter_map(|s| s.get("outbounds")?.as_array())
        .flatten()
        .filter_map(Value::as_str);
    let groups = selectors.iter().filter_map(|s| s.get("tag")?.as_str());
    let mut seen = BTreeSet::new();
    members
        .chain(groups)
        .filter(|t| seen.insert(*t))
        .map(str::to_owned)
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
    fn selector_groups_keep_profile_order() {
        let config = r#"{"outbounds":[
            {"type":"selector","tag":"proxy","outbounds":["auto","hk","hk","jp"]},
            {"type":"direct","tag":"direct"},
            {"type":"selector","tag":"streaming","outbounds":["jp","direct"]}]}"#;
        assert_eq!(
            selector_groups(config),
            vec![
                (
                    "proxy".to_owned(),
                    vec!["auto".to_owned(), "hk".to_owned(), "jp".to_owned()]
                ),
                ("streaming".to_owned(), vec!["jp".to_owned(), "direct".to_owned()]),
            ]
        );
        assert!(selector_groups("not json").is_empty());
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

    #[test]
    fn normalizes_like_swift() {
        assert_eq!(
            normalize(" HTTPS://Www.Example.com:443/path?q#f ").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(normalize("*.example.com.").as_deref(), Some("example.com"));
        assert_eq!(normalize(".a_b.example").as_deref(), Some("a_b.example"));
        assert_eq!(normalize("-bad.example"), None);
        assert_eq!(normalize("a..b"), None);
        assert_eq!(normalize("exämple.com"), None);
        assert_eq!(normalize(""), None);
    }

    #[test]
    fn encodes_like_swift() {
        let swift = r#"[{"id":"E621E1F8-C36C-495A-93FC-0C247A3E6E5F","domains":["example.com"],"subdomains":true,"outbound":"hk","enabled":true}]"#;
        let rules = decode(Some(swift.as_bytes()));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, None);
        assert_eq!(String::from_utf8(encode(&rules)).unwrap(), swift);
        assert!(decode(Some(b"nonsense")).is_empty());
        assert!(decode(None).is_empty());
    }

    #[test]
    fn choices_are_selector_members_then_groups() {
        let config = r#"{"outbounds":[{"type":"selector","tag":"proxy","outbounds":["hk","jp"]},
            {"type":"selector","tag":"alt","outbounds":["jp","direct"]},{"type":"direct","tag":"direct"}]}"#;
        assert_eq!(choices(config), ["hk", "jp", "direct", "proxy", "alt"]);
        assert!(choices("nonsense").is_empty());
    }

    #[test]
    fn applies_after_sniff() {
        let config = r#"{"outbounds":[{"type":"direct","tag":"hk"}],"route":{"rules":[{"action":"sniff"},{"action":"hijack-dns","protocol":"dns"},{"domain":["x"],"outbound":"hk"}]}}"#;
        let mut gone = PersonalRule::new("b.example".into(), "missing".into());
        gone.enabled = true;
        let rules = [PersonalRule::new("a.example".into(), "hk".into()), gone.clone()];
        let (out, skipped) = apply(&rules, config);
        assert_eq!(skipped, [gone]);
        let v: Value = serde_json::from_str(&out).unwrap();
        let list = v["route"]["rules"].as_array().unwrap();
        assert_eq!(list.len(), 4);
        assert_eq!(list[2]["domain_suffix"][0], "a.example");
        assert_eq!(list[2]["outbound"], "hk");

        let (out, _) = apply(&rules, r#"{"outbounds":[{"type":"direct","tag":"hk"}]}"#);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["route"]["rules"][0]["action"], "route");
    }
}
