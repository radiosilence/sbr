//! Personal routing rules: domains the user routes through a chosen outbound
//! whatever the profile says. The app stores them (`personalRules` in the
//! user defaults) and hands them to the tunnel in the VPN configuration,
//! which puts them into every config it runs. Encoded as SbrKit's
//! `SbrPersonalRule` (apple/Sources/SbrKit/SbrPersonalRules.swift).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::swift::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PersonalRule {
    pub id: Uuid,
    /// What a rule made from a template is called; none for one domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub domains: Vec<String>,
    /// Match the domains and their subdomains (`domain_suffix`), or the
    /// domains exactly (`domain`).
    pub subdomains: bool,
    /// An outbound or group tag in the profile.
    pub outbound: String,
    pub enabled: bool,
}

impl PersonalRule {
    pub fn new(domain: String, outbound: String) -> Self {
        PersonalRule {
            id: Uuid::new(),
            name: None,
            domains: vec![domain],
            subdomains: true,
            outbound,
            enabled: true,
        }
    }

    /// The sing-box route rule.
    pub fn route_rule(&self) -> Value {
        let key = if self.subdomains { "domain_suffix" } else { "domain" };
        json!({ key: self.domains, "action": "route", "outbound": self.outbound })
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

/// Every outbound and endpoint tag in a config.
fn tags(root: &Map<String, Value>) -> BTreeSet<String> {
    ["outbounds", "endpoints"]
        .iter()
        .filter_map(|k| root.get(*k)?.as_array())
        .flatten()
        .filter_map(|o| o.get("tag")?.as_str().map(str::to_owned))
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

/// `config` with the enabled rules put into `route.rules`, in order, after
/// the last `sniff` or `hijack-dns` rule so they see sniffed domains and DNS
/// is still answered; and the rules left out because the config has no
/// outbound by that tag. Unchanged when there is nothing to insert or the
/// config is not plain JSON.
pub fn apply(rules: &[PersonalRule], config: &str) -> (String, Vec<PersonalRule>) {
    let enabled: Vec<&PersonalRule> = rules.iter().filter(|r| r.enabled && !r.domains.is_empty()).collect();
    let Ok(Value::Object(mut root)) = serde_json::from_str::<Value>(config) else {
        return (config.to_owned(), Vec::new());
    };
    if enabled.is_empty() {
        return (config.to_owned(), Vec::new());
    }
    let tags = tags(&root);
    let (usable, skipped): (Vec<&PersonalRule>, Vec<&PersonalRule>) =
        enabled.into_iter().partition(|r| tags.contains(&r.outbound));
    let skipped = skipped.into_iter().cloned().collect();
    if usable.is_empty() {
        return (config.to_owned(), skipped);
    }
    let route = root.entry("route").or_insert_with(|| Value::Object(Map::new()));
    if !route.is_object() {
        *route = Value::Object(Map::new());
    }
    let existing = route
        .as_object_mut()
        .map(|r| r.entry("rules").or_insert_with(|| Value::Array(Vec::new())))
        .expect("route is an object");
    if !existing.is_array() {
        *existing = Value::Array(Vec::new());
    }
    let list = existing.as_array_mut().expect("rules is an array");
    let at = list
        .iter()
        .rposition(|r| matches!(r.get("action").and_then(Value::as_str), Some("sniff" | "hijack-dns")))
        .map_or(0, |i| i + 1);
    list.splice(at..at, usable.iter().map(|r| r.route_rule()));
    (Value::Object(root).to_string(), skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

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
