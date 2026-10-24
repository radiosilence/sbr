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
    Metadata {
        inbound: "in".into(),
        inbound_type: "mixed",
        network: Network::Tcp,
        source: "192.168.1.10:50000".parse().unwrap(),
        destination: Destination::from_host_port(dest, port),
        user: None,
    }
}

const OUTS: &str = r#""outbounds":[{"type":"direct","tag":"a"},{"type":"direct","tag":"b"},{"type":"direct","tag":"c"}]"#;

#[test]
fn groups_or_within_and_across() {
    let r = router(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in"}}],{OUTS},"route":{{"rules":[
            {{"domain_suffix":"x.com","ip_cidr":"10.0.0.0/8","port":[443,8443],"outbound":"b"}}
        ]}}}}"#
    ));
    assert_eq!(r.route(&meta("www.x.com", 443)), Decision::Route(1));
    assert_eq!(
        r.route(&meta("10.2.3.4", 8443)),
        Decision::Route(1),
        "ip_cidr ORs with domain_suffix"
    );
    assert_eq!(
        r.route(&meta("www.x.com", 80)),
        Decision::Route(0),
        "port group must also hit"
    );
    assert_eq!(r.route(&meta("y.com", 443)), Decision::Route(0));
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
    assert_eq!(r.len(), 3, "sniff is not a routing decision");
    assert_eq!(
        r.route(&meta("ads.example", 80)),
        Decision::Reject { drop: true }
    );
    assert_eq!(r.route(&meta("127.0.0.1", 80)), Decision::Route(1));
    assert_eq!(r.route(&meta("1.1.1.1", 80)), Decision::Route(2));
    assert_eq!(
        r.route(&meta("example.com", 80)),
        Decision::Route(2),
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
    assert_eq!(r.route(&meta("example.com", 443)), Decision::Route(1));
    assert_eq!(r.route(&meta("example.com", 22)), Decision::Route(0));
    assert_eq!(r.route(&meta("ssh.host", 443)), Decision::Route(0));
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
    assert_eq!(r.route(&meta("mail.google.com", 443)), Decision::Route(1));
    assert_eq!(r.route(&meta("mail.google.com", 80)), Decision::Route(0));
    assert_eq!(r.route(&meta("8.8.8.8", 80)), Decision::Route(2));
    assert_eq!(r.route(&meta("a.com", 80)), Decision::Route(2));
    // source 192.168.1.10 is in `lan`, matched against the *source* address
    assert_eq!(r.route(&meta("9.9.9.9", 53)), Decision::Route(1));
}

#[test]
fn inbound_and_user() {
    let r = router(
        r#"{"inbounds":[{"type":"mixed","tag":"in"},{"type":"socks","tag":"other"}],
            "outbounds":[{"type":"direct","tag":"a"},{"type":"direct","tag":"b"}],
            "route":{"rules":[{"inbound":"other","outbound":"b"},{"auth_user":"bob","outbound":"b"}]}}"#,
    );
    let mut m = meta("x.com", 1);
    assert_eq!(r.route(&m), Decision::Route(0));
    m.user = Some("bob".into());
    assert_eq!(r.route(&m), Decision::Route(1));
    m.user = None;
    m.inbound = "other".into();
    assert_eq!(r.route(&m), Decision::Route(1));
    let _ = Host::Ip([1, 1, 1, 1].into());
}
