//! What the tunnel does to a profile before running it: the app's log level
//! and tun stack overrides, then the user's personal rules.

use serde_json::{Map, Value, json};

pub use sbr_message::rules::{apply, changed_domains};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
