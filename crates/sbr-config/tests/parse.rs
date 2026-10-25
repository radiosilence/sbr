use sbr_config::*;

const CONFIG: &str = r#"
// Typical desktop config, as written for sing-box 1.13.
{
  "$schema": "https://sing-box.sagernet.org/schema.json",
  "log": { "level": "info", "timestamp": true },
  "dns": { "servers": [{ "type": "local" }] },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }
  ],
  "outbounds": [
    { "type": "selector", "tag": "proxy", "outbounds": ["ss", "direct"], "default": "ss" },
    {
      "type": "shadowsocks", "tag": "ss",
      "server": "example.com", "server_port": 8388,
      "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==",
      "connect_timeout": "5s", "tcp_fast_open": true
    },
    { "type": "direct", "tag": "direct" },
    { "type": "block" }
  ],
  "route": {
    "rules": [
      { "action": "sniff" },
      { "ip_is_private": true, "outbound": "direct" },
      { "domain_suffix": ["ads.example", ".doubleclick.net"], "action": "reject" },
      {
        "type": "logical", "mode": "and",
        "rules": [{ "domain_keyword": "google" }, { "port": 443 }],
        "outbound": "proxy"
      },
      { "rule_set": "cn", "outbound": "direct" }
    ],
    "rule_set": [
      { "type": "inline", "tag": "cn", "rules": [{ "domain_suffix": "cn" }, { "ip_cidr": ["1.0.1.0/24", "1.1.1.1"] }] }
    ],
    "final": "proxy",
    "auto_detect_interface": true
  }
}
"#;

#[test]
fn parses_typical_config() {
    let o = Options::parse(CONFIG).unwrap();
    assert_eq!(o.inbounds.len(), 1);
    assert_eq!(o.outbounds.len(), 4);
    assert_eq!(
        o.outbounds[3].tag, "3",
        "untagged outbounds get their index, like sing-box"
    );
    assert_eq!(o.final_outbound(), "proxy");
    assert_eq!(o.route.rules.len(), 5);
    assert!(matches!(
        o.route.rules[2].action,
        RuleAction::Reject {
            method: RejectMethod::Default,
            no_drop: false
        }
    ));
    let OutboundKind::Shadowsocks(ss) = &o.outbounds[1].kind else {
        panic!()
    };
    assert_eq!(ss.dial.connect_timeout, Some(std::time::Duration::from_secs(5)));
    assert!(o.warnings.iter().any(|w| w.starts_with("dns")));
    assert!(o.warnings.iter().any(|w| w.contains("auto_detect_interface")));
}

fn err(json: &str) -> String {
    Options::parse(json).unwrap_err().to_string()
}

#[test]
fn rejects_unknown_fields_with_path() {
    let e = err(r#"{"outbounds":[{"type":"direct","tag":"d","bogus":1}]}"#);
    assert_eq!(e, "outbounds[0].bogus: unknown field, or not supported by sbr yet");
}

#[test]
fn rejects_unsupported_protocols_loudly() {
    let e = err(r#"{"outbounds":[{"type":"vmess","tag":"v"}]}"#);
    assert!(e.contains("outbounds[0].type") && e.contains("vmess"), "{e}");
}

#[test]
fn rejects_unsupported_matchers() {
    let e = err(
        r#"{"outbounds":[{"type":"direct","tag":"d"}],"route":{"rules":[{"process_name":"curl","outbound":"d"}]}}"#,
    );
    assert!(e.starts_with("route.rules[0].process_name"), "{e}");
}

#[test]
fn checks_references() {
    let e = err(r#"{"outbounds":[{"type":"direct","tag":"d"}],"route":{"rules":[{"port":1,"outbound":"nope"}]}}"#);
    assert_eq!(e, "route.rules[0].outbound: outbound not found: nope");
    let e = err(r#"{"outbounds":[{"type":"direct","tag":"d"},{"type":"direct","tag":"d"}]}"#);
    assert!(e.contains("duplicate"), "{e}");
    let e = err(r#"{"outbounds":[{"type":"direct","tag":"d","detour":"d"}]}"#);
    assert!(e.contains("itself"), "{e}");
}

#[test]
fn implicit_direct() {
    let o = Options::parse("{}").unwrap();
    assert_eq!(o.final_outbound(), "direct");
}

#[test]
fn rule_set_source() {
    let rules =
        parse_rule_set_source(r#"{"version":3,"rules":[{"domain":["a.com"]},{"ip_cidr":"10.0.0.0/8"}]}"#).unwrap();
    assert_eq!(rules.len(), 2);
}

#[test]
fn tun_inbound_and_actions() {
    let o = Options::parse(
        r#"{
        "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],
                     "mtu":9000,"auto_route":true,"strict_route":true,"stack":"mixed","inet4_route_address":"0.0.0.0/1",
                     "platform":{"http_proxy":{"enabled":false}}}],
        "outbounds":[{"type":"direct","tag":"d"}],
        "route":{"rules":[
            {"inbound":"tun-in","action":"sniff","sniffer":["tls","http"],"timeout":"300ms"},
            {"protocol":"dns","action":"hijack-dns"},
            {"protocol":"quic","action":"reject"},
            {"action":"route-options","override_address":"127.0.0.1"},
            {"action":"resolve","strategy":"prefer_ipv4"},
            {"port":443,"outbound":"d","override_port":8443}
        ]}
    }"#,
    )
    .unwrap();
    let InboundKind::Tun(t) = &o.inbounds[0].kind else {
        panic!()
    };
    assert_eq!(t.address.len(), 2);
    assert_eq!(t.route_address.len(), 1, "legacy inet4_route_address merges");
    assert!(o.warnings.iter().any(|w| w.contains("stack")));
    assert!(matches!(&o.route.rules[0].action, RuleAction::Sniff { sniffers, .. } if sniffers.len() == 2));
    assert_eq!(o.route.rules[1].action, RuleAction::HijackDns);
    assert!(
        matches!(&o.route.rules[5].action, RuleAction::Route { options, .. } if options.override_port == Some(8443))
    );
}
