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
