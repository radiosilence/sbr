//! Router behaviour against in-process servers (`hosts`, `fakeip`,
//! `rcode`) so no network is involved.

use std::net::IpAddr;
use std::sync::Arc;

use sbr_config::{DomainResolver, Options};
use sbr_core::dns::{Dns, ResolverSpec};
use sbr_core::router::RuleSets;
use sbr_core::{BoxFuture, Destination, Host, Metadata, Network, Outbound, Stream};

use super::*;

struct NoDial;

impl Outbound for NoDial {
    fn tag(&self) -> &str {
        "none"
    }
    fn kind(&self) -> &'static str {
        "test"
    }
    fn connect<'a>(&'a self, _: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async { Err(io::Error::other("no dialing in unit tests")) })
    }
}

fn router(dns: &str) -> DnsRouter {
    let o = Options::parse(&format!(
        r#"{{"outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"direct","tag":"proxy"}}],
            "inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0}}],
            "dns": {dns}}}"#
    ))
    .unwrap();
    let sets = RuleSets::compile(&o.route.rule_sets, |_| unreachable!()).unwrap();
    DnsRouter::new(o.dns.as_ref().unwrap(), &sets, &|_| Arc::new(NoDial), &|p| {
        std::fs::read(p)
    })
    .unwrap()
}

fn meta(inbound: &str) -> Metadata {
    Metadata::new(
        inbound.into(),
        "socks",
        Network::Udp,
        "127.0.0.1:5000".parse().unwrap(),
        Destination::new(Host::Ip("192.0.2.53".parse().unwrap()), 53),
    )
}

async fn ask(r: &DnsRouter, name: &str, qtype: u16) -> io::Result<Message> {
    let mut q = msg::query(name, qtype).unwrap();
    q.metadata.id = 0x4242;
    let raw = msg::encode(&q).unwrap();
    let resp = msg::decode(&r.exchange(&raw, &meta("in")).await?).unwrap();
    assert_eq!(resp.metadata.id, 0x4242, "response carries the query ID");
    Ok(resp)
}

fn ips(m: &Message) -> Vec<IpAddr> {
    msg::answer_addrs(m)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

const SERVERS: &str = r#"[
    {"type":"hosts","tag":"hosts","predefined":{"a.test":"1.1.1.1","b.test":["2.2.2.2","::2"],"ten.test":"10.0.0.10"}},
    {"type":"hosts","tag":"hosts2","predefined":{"a.test":"10.1.1.1","other.example":"3.3.3.3"}},
    {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"},
    {"tag":"refuse","address":"rcode://refused"}
]"#;

#[tokio::test]
async fn rules_actions_and_final() {
    let r = router(&format!(
        r#"{{"servers":{SERVERS},
            "rules":[
                {{"query_type":["A","AAAA"],"domain_suffix":"fake.test","server":"fake"}},
                {{"domain_suffix":".test","server":"hosts"}},
                {{"domain":"blocked.example","action":"reject"}},
                {{"domain":"drop.example","action":"reject","method":"drop"}},
                {{"domain_keyword":"pre","action":"predefined","answer":["*.pre.example. 60 IN A 9.9.9.9"],"rcode":"NOERROR"}},
                {{"inbound":"in","domain":"nx.example","action":"predefined","rcode":"NXDOMAIN"}}
            ],
            "final":"refuse"}}"#
    ));
    let m = ask(&r, "a.test", 1).await.unwrap();
    assert_eq!(ips(&m), [ip("1.1.1.1")]);
    let m = ask(&r, "b.test", 28).await.unwrap();
    assert_eq!(ips(&m), [ip("::2")], "AAAA answers only the v6 entry");

    let m = ask(&r, "x.fake.test", 1).await.unwrap();
    let fake = ips(&m)[0];
    assert_eq!(fake, ip("198.18.0.2"));
    assert_eq!(r.fakeip_lookup(fake), Some(Some("x.fake.test".into())));
    assert_eq!(r.fakeip_lookup(ip("198.18.9.9")), Some(None), "in range, unmapped");
    assert_eq!(r.fakeip_lookup(ip("1.1.1.1")), None, "not a fake address");
    let m = ask(&r, "x.fake.test", 16).await.unwrap();
    assert_eq!(
        msg::rcode(&m),
        3,
        "TXT skips the query_type rule and falls to hosts (NXDOMAIN)"
    );

    assert_eq!(
        msg::rcode(&ask(&r, "other.example", 1).await.unwrap()),
        5,
        "final server"
    );
    let m = ask(&r, "blocked.example", 1).await.unwrap();
    assert_eq!(msg::rcode(&m), 5, "reject answers REFUSED");
    assert!(ask(&r, "drop.example", 1).await.is_err(), "reject/drop gives no answer");
    let m = ask(&r, "www.pre.example", 1).await.unwrap();
    assert_eq!(ips(&m), [ip("9.9.9.9")]);
    assert_eq!(
        m.answers[0].name.to_ascii(),
        "www.pre.example.",
        "wildcard owner rewritten"
    );
    assert_eq!(m.answers[0].ttl, 60);
    assert_eq!(msg::rcode(&ask(&r, "nx.example", 1).await.unwrap()), 3);
}

#[tokio::test]
async fn address_limit_falls_through() {
    let r = router(&format!(
        r#"{{"servers":{SERVERS},
            "rules":[
                {{"inbound":"in","ip_cidr":"10.0.0.0/8","server":"hosts"}},
                {{"ip_accept_any":true,"server":"hosts2"}},
                {{"domain":"a.test","server":"hosts2"}}
            ],
            "final":"refuse"}}"#
    ));
    // hosts answers 10.0.0.10 for ten.test: inside 10/8, the first rule stands.
    assert_eq!(ips(&ask(&r, "ten.test", 1).await.unwrap()), [ip("10.0.0.10")]);
    // hosts answers 1.1.1.1 for a.test: rejected; hosts2 has 10.1.1.1 (ip_accept_any).
    assert_eq!(ips(&ask(&r, "a.test", 1).await.unwrap()), [ip("10.1.1.1")]);
    // hosts2 has other.example; nothing else matches.
    assert_eq!(ips(&ask(&r, "other.example", 1).await.unwrap()), [ip("3.3.3.3")]);
    // Nobody has it: both address rules reject, the final server answers.
    assert_eq!(msg::rcode(&ask(&r, "none.example", 1).await.unwrap()), 5);
    // Address-limited rules don't apply to non-address queries.
    assert_eq!(msg::rcode(&ask(&r, "ten.test", 16).await.unwrap()), 5);
}

#[tokio::test]
async fn lookups_strategy_and_resolvers() {
    let r = router(&format!(
        r#"{{"servers":{SERVERS},
            "rules":[{{"outbound":"proxy","server":"hosts2"}}, {{"outbound":"any","domain":"b.test","server":"hosts"}}],
            "final":"hosts","strategy":"ipv4_only"}}"#
    ));
    // Plain lookups walk the rules with no outbound: final server.
    assert_eq!(r.lookup("a.test", None).await.unwrap(), [ip("1.1.1.1")]);
    assert_eq!(
        r.lookup("b.test", None).await.unwrap(),
        [ip("2.2.2.2")],
        "dns.strategy ipv4_only"
    );
    assert_eq!(
        r.lookup("b.test", Some(DomainStrategy::PreferIpv6)).await.unwrap(),
        [ip("::2"), ip("2.2.2.2")],
        "the caller's strategy wins over the default"
    );
    // Bound to an outbound tag: the deprecated `outbound` rule item.
    let proxy = r
        .bind(&ResolverSpec {
            resolver: None,
            outbound: Some("proxy"),
        })
        .unwrap();
    assert_eq!(proxy.lookup("a.test", None).await.unwrap(), [ip("10.1.1.1")]);
    let direct = r
        .bind(&ResolverSpec {
            resolver: None,
            outbound: Some("direct"),
        })
        .unwrap();
    assert_eq!(
        direct.lookup("b.test", None).await.unwrap(),
        [ip("2.2.2.2")],
        "outbound any"
    );
    // A domain_resolver skips the rules.
    let res = DomainResolver {
        server: "hosts2".into(),
        ..Default::default()
    };
    let bound = r
        .bind(&ResolverSpec {
            resolver: Some(&res),
            outbound: Some("direct"),
        })
        .unwrap();
    assert_eq!(bound.lookup("a.test", None).await.unwrap(), [ip("10.1.1.1")]);
    assert!(bound.lookup("b.test", None).await.is_err(), "hosts2 has no b.test");

    // ipv4_only: AAAA queries get an empty NOERROR.
    let m = ask(&r, "b.test", 28).await.unwrap();
    assert_eq!(msg::rcode(&m), 0);
    assert!(m.answers.is_empty());
}

#[tokio::test]
async fn fakeip_is_not_used_for_lookups() {
    let r = router(&format!(
        r#"{{"servers":{SERVERS},
            "rules":[{{"domain_suffix":"test","server":"fake"}}],
            "final":"hosts"}}"#
    ));
    assert_eq!(
        r.lookup("a.test", None).await.unwrap(),
        [ip("1.1.1.1")],
        "fakeip skipped"
    );
    assert_eq!(ips(&ask(&r, "a.test", 1).await.unwrap()), [ip("198.18.0.2")]);
}

#[tokio::test]
async fn reverse_mapping() {
    let r = router(&format!(
        r#"{{"servers":{SERVERS},"final":"hosts","reverse_mapping":true}}"#
    ));
    assert_eq!(r.reverse_lookup(ip("1.1.1.1")), None);
    ask(&r, "a.test", 1).await.unwrap();
    assert_eq!(r.reverse_lookup(ip("1.1.1.1")).as_deref(), Some("a.test"));
}

#[tokio::test]
async fn malformed_and_ddr_queries() {
    let r = router(&format!(r#"{{"servers":{SERVERS},"final":"hosts"}}"#));
    assert!(r.exchange(b"\x00\x01", &meta("in")).await.is_err());
    let m = ask(&r, "_dns.resolver.arpa", 64).await.unwrap();
    assert_eq!(msg::rcode(&m), 0, "DDR gets an empty answer");
    assert!(m.answers.is_empty());
}

#[test]
fn build_errors_have_paths() {
    let o = Options::parse(r#"{"dns":{"servers":[{"type":"udp","tag":"u","server":"dns.example"}]}}"#).unwrap();
    let e = DnsRouter::new(
        o.dns.as_ref().unwrap(),
        &RuleSets::default(),
        &|_| Arc::new(NoDial),
        &|p| std::fs::read(p),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(e.starts_with("dns.servers[0].domain_resolver"), "{e}");

    let o = Options::parse(
        r#"{"dns":{"servers":[
            {"type":"udp","tag":"a","server":"a.example","domain_resolver":"b"},
            {"type":"udp","tag":"b","server":"b.example","domain_resolver":"a"}]}}"#,
    )
    .unwrap();
    let e = DnsRouter::new(
        o.dns.as_ref().unwrap(),
        &RuleSets::default(),
        &|_| Arc::new(NoDial),
        &|p| std::fs::read(p),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(e.contains("resolver loop"), "{e}");
}
