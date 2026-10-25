use std::time::Duration;

use sbr_config::*;

fn parse(dns: &str) -> Options {
    Options::parse(&format!(
        r#"{{"outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"direct","tag":"proxy"}}],
            "inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0}}],
            "dns":{dns}}}"#
    ))
    .unwrap()
}

fn err(dns: &str) -> String {
    Options::parse(&format!(
        r#"{{"outbounds":[{{"type":"direct","tag":"direct"}}],"dns":{dns}}}"#
    ))
    .unwrap_err()
    .to_string()
}

#[test]
fn typed_servers() {
    let o = parse(
        r#"{
        "servers":[
            {"type":"local","tag":"local","prefer_go":true},
            {"type":"hosts","tag":"hosts","path":"/etc/hosts","predefined":{"Router.Lan.":"10.0.0.1","x":["::1","1.2.3.4"]}},
            {"type":"udp","tag":"udp","server":"8.8.8.8"},
            {"type":"tcp","tag":"tcp","server":"1.1.1.1","server_port":5353,"detour":"proxy"},
            {"type":"tls","tag":"tls","server":"dns.google","domain_resolver":"local","tls":{"server_name":"dns.google"}},
            {"type":"https","tag":"doh","server":"1.1.1.1","path":"/q","method":"GET","headers":{"X-A":"b"},
             "domain_resolver":{"server":"udp","strategy":"ipv4_only","rewrite_ttl":60}},
            {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}
        ],
        "final":"doh","strategy":"prefer_ipv4","disable_expire":true,"independent_cache":true,
        "cache_capacity":4096,"reverse_mapping":true,"client_subnet":"1.2.3.4","timeout":"5s"
    }"#,
    );
    let d = o.dns.unwrap();
    assert_eq!(d.servers.len(), 7);
    let DnsServerKind::Hosts { path, predefined } = &d.servers[1].kind else {
        panic!()
    };
    assert_eq!(path, &["/etc/hosts"]);
    assert!(predefined.iter().any(|(n, a)| n == "router.lan" && a.len() == 1));
    assert!(matches!(&d.servers[2].kind, DnsServerKind::Udp(a) if a.server_port == 53));
    assert!(matches!(&d.servers[3].kind, DnsServerKind::Tcp(a) if a.server_port == 5353));
    assert_eq!(d.servers[3].dial.detour.as_deref(), Some("proxy"));
    assert!(matches!(&d.servers[4].kind, DnsServerKind::Tls { server, .. } if server.server_port == 853));
    let DnsServerKind::Https {
        server,
        path,
        get,
        headers,
        ..
    } = &d.servers[5].kind
    else {
        panic!()
    };
    assert_eq!((server.server_port, path.as_str(), *get), (443, "/q", true));
    assert_eq!(headers, &[("X-A".to_string(), "b".to_string())]);
    let r = d.servers[5].dial.domain_resolver.as_ref().unwrap();
    assert_eq!(r.server, "udp");
    assert_eq!(r.options.strategy, Some(DomainStrategy::Ipv4Only));
    assert_eq!(r.options.rewrite_ttl, Some(60));
    assert!(matches!(
        &d.servers[6].kind,
        DnsServerKind::FakeIp {
            inet4_range: Some(_),
            inet6_range: Some(_)
        }
    ));
    assert_eq!(d.final_server(), Some("doh"));
    assert_eq!(d.strategy, Some(DomainStrategy::PreferIpv4));
    assert!(d.disable_expire && d.reverse_mapping);
    assert_eq!(d.cache_capacity, 4096);
    assert_eq!(d.client_subnet, Some("1.2.3.4/32".parse().unwrap()));
    assert_eq!(d.timeout, Some(Duration::from_secs(5)));
    assert!(o.warnings.iter().any(|w| w.contains("prefer_go")));
}

#[test]
fn legacy_servers() {
    let o = parse(
        r#"{
        "servers":[
            {"tag":"google","address":"tls://dns.google","address_resolver":"local","address_strategy":"ipv4_only","strategy":"prefer_ipv6","client_subnet":"10.0.0.0/8"},
            {"tag":"cf","address":"https://1.1.1.1/dns-query","detour":"proxy"},
            {"tag":"plain","address":"8.8.8.8"},
            {"tag":"v6","address":"udp://[2001:4860:4860::8888]:5353"},
            {"tag":"local","address":"local"},
            {"tag":"block","address":"rcode://refused"},
            {"tag":"fake","address":"fakeip"}
        ],
        "fakeip":{"enabled":true,"inet4_range":"198.18.0.0/15"}
    }"#,
    );
    let d = o.dns.unwrap();
    let g = &d.servers[0];
    assert!(matches!(&g.kind, DnsServerKind::Tls { server, tls } if server.server == "dns.google" && tls.enabled));
    let r = g.dial.domain_resolver.as_ref().unwrap();
    assert_eq!(
        (r.server.as_str(), r.options.strategy),
        ("local", Some(DomainStrategy::Ipv4Only))
    );
    let l = g.legacy.as_ref().unwrap();
    assert_eq!(l.strategy, Some(DomainStrategy::PreferIpv6));
    assert!(
        l.default_outbound,
        "legacy servers without detour use the default outbound"
    );
    assert!(matches!(&d.servers[1].kind, DnsServerKind::Https { path, .. } if path == "/dns-query"));
    assert!(!d.servers[1].legacy.as_ref().unwrap().default_outbound);
    assert!(matches!(&d.servers[2].kind, DnsServerKind::Udp(a) if a.server == "8.8.8.8" && a.server_port == 53));
    assert!(
        matches!(&d.servers[3].kind, DnsServerKind::Udp(a) if a.server == "2001:4860:4860::8888" && a.server_port == 5353)
    );
    assert!(matches!(d.servers[4].kind, DnsServerKind::Local));
    assert!(matches!(d.servers[5].kind, DnsServerKind::Rcode(5)));
    assert!(matches!(
        d.servers[6].kind,
        DnsServerKind::FakeIp {
            inet4_range: Some(_),
            inet6_range: None
        }
    ));
    assert!(o.warnings.iter().any(|w| w.contains("legacy DNS server")));
}

#[test]
fn rules_parse() {
    let o = Options::parse(
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],
            "inbounds":[{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0}],
            "route":{"rule_set":[{"type":"inline","tag":"rs","rules":[{"ip_cidr":"10.0.0.0/8"}]}]},
            "dns":{
        "servers":[{"type":"local","tag":"local"},{"type":"udp","tag":"remote","server":"8.8.8.8"}],
        "rules":[
            {"query_type":["A","HTTPS",32768],"domain_suffix":".Test","server":"local","disable_cache":true,"rewrite_ttl":10,"client_subnet":"1.2.3.0/24"},
            {"outbound":"any","server":"local"},
            {"rule_set":"rs","ip_cidr":"10.0.0.0/8","ip_accept_any":true,"server":"remote"},
            {"type":"logical","mode":"or","rules":[{"query_type":"AAAA"},{"domain":"x"}],"action":"reject","method":"drop"},
            {"domain":"p","action":"predefined","rcode":"NXDOMAIN","answer":"p. IN A 1.2.3.4"},
            {"inbound":"in","action":"route-options","disable_cache":true,"timeout":"1s"}
        ]}}"#,
    )
    .unwrap();
    let d = o.dns.unwrap();
    let RuleKind::Default(m) = &d.rules[0].rule.kind else {
        panic!()
    };
    assert_eq!(m.query_type, [1, 65, 32768]);
    assert_eq!(m.domain_suffix, [".test"]);
    let DnsRuleAction::Route { server, options } = &d.rules[0].action else {
        panic!()
    };
    assert_eq!(server, "local");
    assert!(options.disable_cache);
    assert_eq!(options.rewrite_ttl, Some(10));
    assert_eq!(options.client_subnet, Some("1.2.3.0/24".parse().unwrap()));
    let RuleKind::Default(m) = &d.rules[1].rule.kind else {
        panic!()
    };
    assert_eq!(m.outbound, ["any"]);
    let RuleKind::Default(m) = &d.rules[2].rule.kind else {
        panic!()
    };
    assert!(m.ip_accept_any && m.rule_set == ["rs"]);
    let RuleKind::Logical { rules, .. } = &d.rules[3].rule.kind else {
        panic!()
    };
    assert!(matches!(&rules[0].kind, RuleKind::Default(m) if m.query_type == [28]));
    assert_eq!(
        d.rules[3].action,
        DnsRuleAction::Reject {
            method: RejectMethod::Drop,
            no_drop: false
        }
    );
    let DnsRuleAction::Predefined(p) = &d.rules[4].action else {
        panic!()
    };
    assert_eq!(p.rcode, 3);
    assert_eq!(p.answer.len(), 1);
    assert!(matches!(&d.rules[5].action, DnsRuleAction::RouteOptions(o) if o.timeout == Some(Duration::from_secs(1))));
}

#[test]
fn domain_resolver_on_outbounds_and_route() {
    let o = Options::parse(
        r#"{"outbounds":[{"type":"direct","tag":"d","domain_resolver":{"server":"local","strategy":"prefer_ipv6"}},
                         {"type":"socks","tag":"s","server":"proxy.example","server_port":1080,"domain_resolver":"local"}],
            "route":{"default_domain_resolver":"local","rules":[{"action":"resolve","server":"local"}]},
            "dns":{"servers":[{"type":"local","tag":"local"}]}}"#,
    )
    .unwrap();
    let OutboundKind::Direct(d) = &o.outbounds[0].kind else {
        panic!()
    };
    assert_eq!(
        d.domain_resolver.as_ref().unwrap().options.strategy,
        Some(DomainStrategy::PreferIpv6)
    );
    assert_eq!(o.route.default_domain_resolver.as_ref().unwrap().server, "local");
}

#[test]
fn path_errors() {
    let cases: &[(&str, &str)] = &[
        (
            r#"{"servers":[{"type":"quic","server":"1.1.1.1"}]}"#,
            "dns.servers[0].type",
        ),
        (
            r#"{"servers":[{"type":"h3","server":"1.1.1.1"}]}"#,
            "dns.servers[0].type",
        ),
        (r#"{"servers":[{"type":"bogus"}]}"#, "dns.servers[0].type"),
        (r#"{"servers":[{"type":"udp"}]}"#, "dns.servers[0].server"),
        (
            r#"{"servers":[{"type":"udp","server":"1.1.1.1","foo":1}]}"#,
            "dns.servers[0].foo",
        ),
        (
            r#"{"servers":[{"address":"quic://dns.adguard.com"}]}"#,
            "dns.servers[0].address",
        ),
        (r#"{"servers":[{"address":"fakeip"}]}"#, "dns.servers[0].address"),
        (
            r#"{"servers":[{"type":"tls","server":"1.1.1.1","tls":{"reality":{"enabled":true}}}]}"#,
            "dns.servers[0].tls.reality",
        ),
        (
            r#"{"servers":[{"type":"udp","server":"1.1.1.1","detour":"nope"}]}"#,
            "dns.servers[0].detour",
        ),
        (
            r#"{"servers":[{"type":"udp","tag":"a","server":"x.y","domain_resolver":"a"}]}"#,
            "dns.servers[0].domain_resolver",
        ),
        (
            r#"{"servers":[{"type":"udp","tag":"a","server":"1.1.1.1"},{"type":"local","tag":"a"}]}"#,
            "dns.servers[1].tag",
        ),
        (r#"{"servers":[{"type":"local","tag":"a"}],"final":"b"}"#, "dns.final"),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"server":"b"}]}"#,
            "dns.rules[0].server",
        ),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"domain":"x"}]}"#,
            "dns.rules[0].server",
        ),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"query_type":"NOPE","server":"a"}]}"#,
            "dns.rules[0].query_type",
        ),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"process_name":"x","server":"a"}]}"#,
            "dns.rules[0].process_name",
        ),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"action":"evaluate","server":"a"}]}"#,
            "dns.rules[0].action",
        ),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"match_response":true,"server":"a"}]}"#,
            "dns.rules[0].match_response",
        ),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"outbound":"nope","server":"a"}]}"#,
            "dns.rules[0].outbound",
        ),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"action":"predefined","answer":["x. IN LOC 1"]}]}"#,
            "dns.rules[0].answer[0]",
        ),
        (
            r#"{"servers":[{"type":"local","tag":"a"}],"rules":[{"type":"logical","mode":"and","rules":[{"query_type":"A","server":"a"}],"server":"a"}]}"#,
            "dns.rules[0].rules[0].server",
        ),
        (r#"{"optimistic":true,"disable_cache":true}"#, "dns.optimistic"),
        (r#"{"bogus":1}"#, "dns.bogus"),
    ];
    for (dns, path) in cases {
        let e = err(dns);
        assert!(e.starts_with(path), "{dns}\n  => {e}\n  expected path {path}");
    }
    // Outside `dns`: references into it.
    let e = Options::parse(r#"{"outbounds":[{"type":"direct","tag":"d","domain_resolver":"x"}]}"#)
        .unwrap_err()
        .to_string();
    assert!(e.starts_with("outbounds[0].domain_resolver"), "{e}");
    let e = Options::parse(r#"{"route":{"default_domain_resolver":"x"},"dns":{"servers":[{"type":"local"}]}}"#)
        .unwrap_err()
        .to_string();
    assert!(e.starts_with("route.default_domain_resolver"), "{e}");
    let e = Options::parse(r#"{"route":{"rules":[{"query_type":"A","outbound":"direct"}]}}"#)
        .unwrap_err()
        .to_string();
    assert!(
        e.starts_with("route.rules[0].query_type"),
        "DNS-only matchers stay out of route rules: {e}"
    );
}

#[test]
fn optimistic_forms() {
    let o = parse(r#"{"optimistic":true}"#);
    assert_eq!(o.dns.unwrap().optimistic, Some(Duration::from_secs(3 * 86400)));
    let o = parse(r#"{"optimistic":{"enabled":true,"timeout":"1h"}}"#);
    assert_eq!(o.dns.unwrap().optimistic, Some(Duration::from_secs(3600)));
    let o = parse(r#"{"optimistic":{"enabled":false,"timeout":"1h"}}"#);
    assert_eq!(o.dns.unwrap().optimistic, None);
}
