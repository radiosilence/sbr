use super::*;
use crate::{Destination, Host};

fn router(json: &str) -> Router {
    let o = sbr_config::Options::parse(json).unwrap();
    let tags: Vec<String> = o.outbounds.iter().map(|o| o.tag.clone()).collect();
    Router::new(
        &o.route.rules,
        &o.route.rule_sets,
        o.final_outbound(),
        |t| tags.iter().position(|x| x == t),
        |_| Err(std::io::ErrorKind::NotFound.into()),
    )
    .unwrap()
}

fn meta(dest: &str, port: u16) -> Metadata {
    Metadata::new(
        "in".into(),
        "mixed",
        Network::Tcp,
        "192.168.1.10:50000".parse().unwrap(),
        Destination::from_host_port(dest, port),
    )
}

fn go(outbound: usize) -> Action {
    Action::Route {
        outbound,
        options: RouteOptions::default(),
    }
}

const OUTS: &str =
    r#""outbounds":[{"type":"direct","tag":"a"},{"type":"direct","tag":"b"},{"type":"direct","tag":"c"}]"#;

#[test]
fn groups_or_within_and_across() {
    let r = router(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in"}}],{OUTS},"route":{{"rules":[
            {{"domain_suffix":"x.com","ip_cidr":"10.0.0.0/8","port":[443,8443],"outbound":"b"}}
        ]}}}}"#
    ));
    assert_eq!(r.route(&meta("www.x.com", 443)), go(1));
    assert_eq!(
        r.route(&meta("10.2.3.4", 8443)),
        go(1),
        "ip_cidr ORs with domain_suffix"
    );
    assert_eq!(r.route(&meta("www.x.com", 80)), go(0), "port group must also hit");
    assert_eq!(r.route(&meta("y.com", 443)), go(0));
}

#[test]
fn first_match_wins_and_reject() {
    let r = router(&format!(
        r#"{{{OUTS},"route":{{"rules":[
            {{"action":"sniff"}},
            {{"domain_keyword":"ads","action":"reject","method":"drop"}},
            {{"domain_keyword":"ads","outbound":"c"}},
            {{"ip_is_private":true,"outbound":"b"}}
        ],"final":"c"}}}}"#
    ));
    assert_eq!(r.len(), 4);
    assert_eq!(
        r.route(&meta("ads.example", 80)),
        Action::Reject {
            drop: true,
            no_drop: false
        }
    );
    assert_eq!(r.route(&meta("127.0.0.1", 80)), go(1));
    assert_eq!(r.route(&meta("1.1.1.1", 80)), go(2));
    assert_eq!(
        r.route(&meta("example.com", 80)),
        go(2),
        "domains never match ip_is_private"
    );
}

#[test]
fn invert_and_logical() {
    let r = router(&format!(
        r#"{{{OUTS},"route":{{"rules":[
            {{"type":"logical","mode":"or","rules":[{{"port":22}},{{"domain":"ssh.host"}}],"invert":true,"outbound":"b"}}
        ]}}}}"#
    ));
    assert_eq!(r.route(&meta("example.com", 443)), go(1));
    assert_eq!(r.route(&meta("example.com", 22)), go(0));
    assert_eq!(r.route(&meta("ssh.host", 443)), go(0));
}

#[test]
fn rule_set_merges_with_outer_groups() {
    let r = router(&format!(
        r#"{{{OUTS},"route":{{
            "rule_set":[
                {{"type":"inline","tag":"one","rules":[{{"domain_suffix":"google.com"}}]}},
                {{"type":"inline","tag":"many","rules":[{{"domain":"a.com"}},{{"ip_cidr":"8.8.8.0/24"}}]}},
                {{"type":"inline","tag":"lan","rules":[{{"ip_cidr":"192.168.0.0/16"}}]}}
            ],
            "rules":[
                {{"rule_set":"one","port":443,"outbound":"b"}},
                {{"rule_set":"many","outbound":"c"}},
                {{"rule_set":"lan","rule_set_ip_cidr_match_source":true,"port":53,"outbound":"b"}}
            ]
        }}}}"#
    ));
    assert_eq!(r.route(&meta("mail.google.com", 443)), go(1));
    assert_eq!(r.route(&meta("mail.google.com", 80)), go(0));
    assert_eq!(r.route(&meta("8.8.8.8", 80)), go(2));
    assert_eq!(r.route(&meta("a.com", 80)), go(2));
    // source 192.168.1.10 is in `lan`, matched against the *source* address
    assert_eq!(r.route(&meta("9.9.9.9", 53)), go(1));
}

#[test]
fn inbound_and_user() {
    let r = router(
        r#"{"inbounds":[{"type":"mixed","tag":"in"},{"type":"socks","tag":"other"}],
            "outbounds":[{"type":"direct","tag":"a"},{"type":"direct","tag":"b"}],
            "route":{"rules":[{"inbound":"other","outbound":"b"},{"auth_user":"bob","outbound":"b"}]}}"#,
    );
    let mut m = meta("x.com", 1);
    assert_eq!(r.route(&m), go(0));
    m.user = Some("bob".into());
    assert_eq!(r.route(&m), go(1));
    m.user = None;
    m.inbound = "other".into();
    assert_eq!(r.route(&m), go(1));
    let _ = Host::Ip([1, 1, 1, 1].into());
}

#[test]
fn stepper_sniff_options_protocol() {
    let r = router(&format!(
        r#"{{{OUTS},"route":{{"rules":[
            {{"action":"sniff"}},
            {{"protocol":"dns","action":"hijack-dns"}},
            {{"action":"route-options","override_port":53}},
            {{"domain_suffix":"sniffed.test","outbound":"b"}}
        ]}}}}"#
    ));
    let mut m = meta("10.0.0.1", 443);
    assert!(matches!(r.next(&m, 0), Some((0, Action::Sniff { .. }))));
    m.protocol = Some(Protocol::Dns);
    assert_eq!(r.route(&m), Action::HijackDns);
    m.protocol = Some(Protocol::Tls);
    m.sniffed_domain = Some("www.sniffed.test".into());
    let Action::Route { outbound: 1, options } = r.route(&m) else {
        panic!("{:?}", r.route(&m))
    };
    assert_eq!(
        options.override_port,
        Some(53),
        "route-options fold into the final route"
    );
    // resolve-style: ip_cidr matches resolved addresses of a domain destination
    let r = router(&format!(
        r#"{{{OUTS},"route":{{"rules":[{{"ip_cidr":"9.9.9.0/24","outbound":"c"}}]}}}}"#
    ));
    let mut m = meta("dns.quad9.net", 443);
    assert_eq!(r.route(&m), go(0));
    m.destination_addresses.push("9.9.9.9".parse().unwrap());
    assert_eq!(r.route(&m), go(2));
}

#[test]
fn clash_mode_matcher() {
    let r = router(&format!(
        r#"{{{OUTS},"route":{{"rules":[
            {{"clash_mode":"direct","outbound":"b"}},
            {{"clash_mode":"Global","outbound":"c"}}
        ]}}}}"#
    ));
    let m = meta("x.com", 443);
    assert_eq!(r.clash_mode().current(), "Rule");
    assert_eq!(r.clash_mode().list(), ["Rule", "direct", "Global"].map(String::from));
    assert_eq!(r.route(&m), go(0));
    assert_eq!(
        r.clash_mode().set("GLOBAL").as_deref(),
        Some("Global"),
        "case-insensitive"
    );
    assert_eq!(r.route(&m), go(2));
    assert_eq!(r.clash_mode().set("Direct").as_deref(), Some("direct"));
    assert_eq!(r.route(&m), go(1), "rule value compares case-insensitively");
    assert_eq!(r.clash_mode().set("nope"), None);
    assert_eq!(r.clash_mode().current(), "direct");
}

fn router_with(json: &str, load: impl Fn(&str) -> std::io::Result<Vec<u8>>) -> Router {
    let o = sbr_config::Options::parse(json).unwrap();
    let tags: Vec<String> = o.outbounds.iter().map(|o| o.tag.clone()).collect();
    Router::new(
        &o.route.rules,
        &o.route.rule_sets,
        o.final_outbound(),
        |t| tags.iter().position(|x| x == t),
        load,
    )
    .unwrap()
}

#[test]
fn rule_sets_hot_swap() {
    let r = router_with(
        &format!(
            r#"{{{OUTS},"route":{{
            "rule_set":[{{"type":"remote","tag":"r","url":"https://x/r.srs"}}],
            "rules":[{{"rule_set":"r","outbound":"b"}}]}}}}"#
        ),
        |_| unreachable!("remote sets are not loaded from disk"),
    );
    assert_eq!(r.route(&meta("a.com", 1)), go(0), "not downloaded yet: matches nothing");
    let rules = sbr_config::parse_rule_set_source(r#"{"version":2,"rules":[{"domain":"a.com"}]}"#).unwrap();
    r.update_rule_set("r", &rules).unwrap();
    assert_eq!(r.route(&meta("a.com", 1)), go(1));
    let rules = sbr_config::parse_rule_set_source(r#"{"version":2,"rules":[{"domain":"b.com"}]}"#).unwrap();
    r.update_rule_set("r", &rules).unwrap();
    assert_eq!(r.route(&meta("a.com", 1)), go(0));
    assert_eq!(r.route(&meta("b.com", 1)), go(1));
    assert!(r.update_rule_set("missing", &rules).is_err());
}

#[test]
fn local_binary_rule_set() {
    let set = sbr_config::srs::PlainRuleSet::from_json(
        r#"{"version":2,"rules":[{"domain_suffix":"bin.test","ip_cidr":"203.0.113.0/24"}]}"#,
    )
    .unwrap();
    let bytes = set.write().unwrap();
    let r = router_with(
        &format!(
            r#"{{{OUTS},"route":{{
            "rule_set":[{{"type":"local","tag":"b","path":"sets/b.srs"}}],
            "rules":[{{"rule_set":"b","outbound":"c"}}]}}}}"#
        ),
        |p| {
            assert_eq!(p, "sets/b.srs");
            Ok(bytes.clone())
        },
    );
    assert_eq!(r.route(&meta("www.bin.test", 443)), go(2));
    assert_eq!(r.route(&meta("203.0.113.9", 443)), go(2));
    assert_eq!(r.route(&meta("x.test", 443)), go(0));
    assert_eq!(r.rules_info()[0].payload, "rule_set=b");
}

/// DNS rules compiled through `Matcher` (what sbr-dns does).
fn dns_matchers(json: &str) -> Vec<Matcher> {
    let o = sbr_config::Options::parse(json).unwrap();
    let sets = RuleSets::compile(&o.route.rule_sets, |_| Err(std::io::ErrorKind::NotFound.into())).unwrap();
    let dns = o.dns.unwrap();
    dns.rules
        .iter()
        .enumerate()
        .map(|(i, r)| Matcher::compile(&r.rule, &format!("dns.rules[{i}]"), &sets).unwrap())
        .collect()
}

fn dns_meta(name: &str, answers: &[&str]) -> Metadata {
    let mut m = meta(name, 0);
    m.destination_addresses = answers.iter().map(|a| a.parse().unwrap()).collect();
    m
}

#[test]
fn dns_query_type_ip_version_and_outbound() {
    let m = dns_matchers(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in"}}],{OUTS},"dns":{{"servers":[{{"type":"local","tag":"l"}}],"rules":[
            {{"query_type":["A","HTTPS"],"server":"l"}},
            {{"ip_version":6,"server":"l"}},
            {{"outbound":"any","server":"l"}},
            {{"outbound":"b","inbound":"in","server":"l"}}
        ]}}}}"#
    ));
    let q = |t: Option<u16>, o: Option<&'static str>| DnsQuery {
        query_type: t,
        outbound: o,
    };
    let meta = dns_meta("x.test", &[]);
    assert!(m[0].matches_dns(&meta, &q(Some(1), None)));
    assert!(m[0].matches_dns(&meta, &q(Some(65), None)));
    assert!(!m[0].matches_dns(&meta, &q(Some(28), None)));
    assert!(!m[0].matches_dns(&meta, &q(None, None)), "lookups carry no query type");
    assert!(
        m[1].matches_dns(&meta, &q(Some(28), None)),
        "ip_version from the query type"
    );
    assert!(!m[1].matches_dns(&meta, &q(Some(1), None)));
    assert!(
        !m[2].matches_dns(&meta, &q(Some(1), None)),
        "outbound needs an outbound"
    );
    assert!(m[2].matches_dns(&meta, &q(None, Some("a"))));
    assert!(m[3].matches_dns(&meta, &q(None, Some("b"))));
    assert!(!m[3].matches_dns(&meta, &q(None, Some("a"))));
    assert!(
        !m[0].matches(&meta),
        "route semantics: no DNS context, no query_type hit"
    );
}

#[test]
fn dns_address_limit_pre_and_post_match() {
    let m = dns_matchers(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in"}}],{OUTS},
            "route":{{"rule_set":[{{"type":"inline","tag":"cn","rules":[{{"ip_cidr":"1.0.0.0/8"}}]}},
                                 {{"type":"inline","tag":"names","rules":[{{"domain_suffix":"cn"}}]}}]}},
            "dns":{{"servers":[{{"type":"local","tag":"l"}}],"rules":[
            {{"ip_cidr":"10.0.0.0/8","server":"l"}},
            {{"rule_set":"cn","server":"l"}},
            {{"rule_set":"names","server":"l"}},
            {{"ip_accept_any":true,"server":"l"}},
            {{"rule_set":"cn","rule_set_ip_cidr_accept_empty":true,"server":"l"}},
            {{"domain":"x.test","ip_is_private":true,"server":"l"}}
        ]}}}}"#
    ));
    let q = DnsQuery {
        query_type: Some(1),
        outbound: None,
    };
    assert!(m[0].has_address_limit() && m[1].has_address_limit() && m[3].has_address_limit());
    assert!(!m[2].has_address_limit(), "a domain-only rule-set is no address limit");
    let none = dns_meta("a.test", &[]);
    assert!(
        m[0].pre_match_dns(&none, &q),
        "IP items are skipped before the response"
    );
    assert!(!m[0].matches_dns(&none, &q));
    assert!(m[0].matches_dns(&dns_meta("a.test", &["10.1.2.3"]), &q));
    assert!(!m[0].matches_dns(&dns_meta("a.test", &["11.1.2.3"]), &q));
    assert!(m[1].pre_match_dns(&none, &q));
    assert!(
        m[1].matches_dns(&dns_meta("a.test", &["1.2.3.4"]), &q),
        "rule-set CIDRs filter responses"
    );
    assert!(!m[1].matches_dns(&dns_meta("a.test", &["8.8.8.8"]), &q));
    assert!(!m[2].pre_match_dns(&none, &q));
    assert!(m[2].pre_match_dns(&dns_meta("x.cn", &[]), &q));
    assert!(!m[3].matches_dns(&none, &q));
    assert!(m[3].matches_dns(&dns_meta("a.test", &["8.8.8.8"]), &q));
    assert!(!m[1].matches_dns(&none, &q), "an empty response doesn't match ip_cidr");
    assert!(m[4].matches_dns(&none, &q), "unless rule_set_ip_cidr_accept_empty");
    // domain and IP items share one OR-group (sing-box): the domain alone satisfies it.
    assert!(m[5].matches_dns(&dns_meta("x.test", &["8.8.8.8"]), &q));
    assert!(m[5].matches_dns(&dns_meta("y.test", &["192.168.1.1"]), &q));
    assert!(!m[5].matches_dns(&dns_meta("y.test", &["8.8.8.8"]), &q));
}

#[test]
fn rule_set_updates_and_clash_mode_reach_dns_rules() {
    let o = sbr_config::Options::parse(&format!(
        r#"{{{OUTS},"dns":{{"servers":[{{"type":"local","tag":"l"}}],"rules":[
                {{"rule_set":"r","server":"l"}},
                {{"rule_set":"ip","server":"l"}},
                {{"clash_mode":"Direct","server":"l"}}]}},
            "route":{{"rule_set":[{{"type":"remote","tag":"r","url":"https://x/r.srs"}},
                                 {{"type":"remote","tag":"ip","url":"https://x/ip.srs"}}],
                      "rules":[{{"rule_set":"r","outbound":"b"}}]}}}}"#
    ))
    .unwrap();
    let tags: Vec<String> = o.outbounds.iter().map(|o| o.tag.clone()).collect();
    let sets = RuleSets::compile(&o.route.rule_sets, |_| unreachable!()).unwrap();
    let dns_rules: Vec<&Rule> = o.dns.as_ref().unwrap().rules.iter().map(|r| &r.rule).collect();
    sets.clash_mode().configure(
        None,
        ClashMode::modes_in(o.route.rules.iter().chain(dns_rules.iter().copied())),
    );
    let router = Router::with_sets(&o.route.rules, &sets, o.final_outbound(), |t| {
        tags.iter().position(|x| x == t)
    })
    .unwrap();
    let m: Vec<Matcher> = dns_rules
        .iter()
        .enumerate()
        .map(|(i, r)| Matcher::compile(r, &format!("dns.rules[{i}]"), &sets).unwrap())
        .collect();
    let q = DnsQuery::default();
    assert!(
        !m[0].matches_dns(&dns_meta("a.com", &[]), &q),
        "remote set not loaded yet"
    );
    assert!(!m[1].has_address_limit());
    // One update, through the route router, reaches the DNS rule too.
    let rules = sbr_config::parse_rule_set_source(r#"{"version":2,"rules":[{"domain":"a.com"}]}"#).unwrap();
    router.update_rule_set("r", &rules).unwrap();
    assert!(m[0].matches_dns(&dns_meta("a.com", &[]), &q));
    assert_eq!(router.route(&meta("a.com", 1)), go(1));
    // The address limit follows the set's new contents.
    let rules = sbr_config::parse_rule_set_source(r#"{"version":2,"rules":[{"ip_cidr":"10.0.0.0/8"}]}"#).unwrap();
    sets.update("ip", &rules).unwrap();
    assert!(m[1].has_address_limit());
    // The Clash mode is shared with DNS rules, and its list includes theirs.
    assert_eq!(router.clash_mode().list(), ["Rule", "Direct"].map(String::from));
    assert!(!m[2].matches_dns(&dns_meta("x.com", &[]), &q));
    router.clash_mode().set("direct");
    assert!(m[2].matches_dns(&dns_meta("x.com", &[]), &q));
}
