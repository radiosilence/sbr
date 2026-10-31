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
    assert!(matches!(o.dns.as_ref().unwrap().servers[0].kind, DnsServerKind::Local));
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
    let e = err(r#"{"outbounds":[{"type":"tor","tag":"v"}]}"#);
    assert!(e.contains("outbounds[0].type") && e.contains("tor"), "{e}");
}

#[test]
fn ssh_outbound() {
    let o = Options::parse(
        r#"{"outbounds":[{"type":"ssh","tag":"s","server":"a.com","private_key":["-----BEGIN","k"],
            "host_key":["ssh-ed25519 AAAA c"],"client_version":"SSH-2.0-OpenSSH_9.6"}]}"#,
    )
    .unwrap();
    let OutboundKind::Ssh(s) = &o.outbounds[0].kind else {
        panic!()
    };
    assert_eq!((s.server.server_port, s.user.as_str()), (22, "root"));
    assert_eq!(s.private_key.as_deref(), Some("-----BEGIN\nk"));
    assert!(!o.warnings.iter().any(|w| w.contains("host_key")));
    let o = Options::parse(r#"{"outbounds":[{"type":"ssh","server":"a.com","password":"p"}]}"#).unwrap();
    assert!(o.warnings.iter().any(|w| w.contains("no host_key")), "{:?}", o.warnings);
    let e = err(r#"{"outbounds":[{"type":"ssh","server":"a.com","client_version":"OpenSSH"}]}"#);
    assert!(e.starts_with("outbounds[0].client_version"), "{e}");
    let e = err(r#"{"outbounds":[{"type":"ssh","server":"a.com","host_key":["AAAA"]}]}"#);
    assert!(e.starts_with("outbounds[0].host_key[0]"), "{e}");
}

#[test]
fn v2ray_family_outbounds() {
    let o = Options::parse(
        r#"{"outbounds":[
        {"type":"trojan","tag":"t","server":"a.com","server_port":443,"password":"p","network":"tcp",
         "tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},
         "transport":{"type":"ws","path":"/ws?ed=2048","max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}},
        {"type":"vless","tag":"l","server":"a.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811",
         "flow":"xtls-rprx-vision","tls":{"enabled":true,"reality":{"enabled":true,"public_key":"k","short_id":"01"}}},
        {"type":"vmess","tag":"m","server":"a.com","server_port":443,"uuid":"x","security":"chacha20-poly1305",
         "global_padding":true,"authenticated_length":true,"packet_encoding":"xudp","network":["tcp","udp"],
         "transport":{"type":"grpc","service_name":"s"},"multiplex":{"enabled":false}},
        {"type":"http","tag":"h","server":"a.com","server_port":443,"tls":{"enabled":true,"server_name":"b.com"}}
    ]}"#,
    )
    .unwrap();
    let OutboundKind::Trojan(t) = &o.outbounds[0].kind else {
        panic!()
    };
    assert!(t.common.tcp() && !t.common.udp());
    assert!(matches!(
        &t.common.transport,
        Some(Transport::Ws {
            max_early_data: 2048,
            ..
        })
    ));
    let OutboundKind::Vless(l) = &o.outbounds[1].kind else {
        panic!()
    };
    assert_eq!(l.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(l.packet_encoding, PacketEncoding::Xudp, "VLESS defaults to xudp");
    let OutboundKind::Vmess(m) = &o.outbounds[2].kind else {
        panic!()
    };
    assert!(m.global_padding && m.authenticated_length && m.common.udp());
    let OutboundKind::Http(h) = &o.outbounds[3].kind else {
        panic!()
    };
    assert!(h.tls.as_ref().unwrap().enabled);
}

#[test]
fn v2ray_family_rejections() {
    let base = r#""server":"a.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811""#;
    let e = err(&format!(
        r#"{{"outbounds":[{{"type":"vless",{base},"flow":"xtls-rprx-vision","multiplex":{{"enabled":true}}}}]}}"#
    ));
    assert!(e.starts_with("outbounds[0].multiplex"), "{e}");
    let e = err(&format!(
        r#"{{"outbounds":[{{"type":"vless",{base},"multiplex":{{"enabled":true,"protocol":"mplex"}}}}]}}"#
    ));
    assert!(e.starts_with("outbounds[0].multiplex.protocol"), "{e}");
    let e = err(&format!(
        r#"{{"outbounds":[{{"type":"vless",{base},"multiplex":{{"enabled":true,"brutal":{{"enabled":true,"up_mbps":0,"down_mbps":10}}}}}}]}}"#
    ));
    assert!(e.starts_with("outbounds[0].multiplex.brutal.up_mbps"), "{e}");
    let o = Options::parse(&format!(
        r#"{{"outbounds":[{{"type":"shadowsocks","server":"a.com","server_port":1,"method":"none","multiplex":{{"enabled":true,"protocol":"smux","padding":true}}}}]}}"#
    ))
    .unwrap();
    let OutboundKind::Shadowsocks(ss) = &o.outbounds[0].kind else {
        panic!()
    };
    assert!(ss.multiplex.as_ref().is_some_and(|m| m.padding));
    let e = err(&format!(
        r#"{{"outbounds":[{{"type":"vless",{base},"flow":"xtls-rprx-vision"}}]}}"#
    ));
    assert!(e.starts_with("outbounds[0].flow"), "{e}");
    let e = err(&format!(r#"{{"outbounds":[{{"type":"vmess",{base},"alter_id":1}}]}}"#));
    assert!(e.starts_with("outbounds[0].alter_id"), "{e}");
    let e = err(&format!(
        r#"{{"outbounds":[{{"type":"vmess",{base},"transport":{{"type":"quic"}}}}]}}"#
    ));
    assert!(e.starts_with("outbounds[0].transport.type"), "{e}");
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
fn tun_without_dns_warns_of_the_system_resolver() {
    let tun =
        r#""inbounds":[{"type":"tun","address":["172.19.0.1/30"],"auto_route":true}],"outbounds":[{"type":"direct"}]"#;
    let o = Options::parse(&format!("{{{tun}}}")).unwrap();
    assert!(
        o.warnings
            .iter()
            .any(|w| w.starts_with("dns: missing with a tun inbound"))
    );
    let o = Options::parse(&format!(
        r#"{{{tun},"dns":{{"servers":[{{"type":"local","tag":"l"}}]}}}}"#
    ))
    .unwrap();
    assert!(!o.warnings.iter().any(|w| w.starts_with("dns: missing")));
    assert!(
        o.warnings
            .iter()
            .any(|w| w.starts_with("dns.servers[0] (l): asks the system resolver"))
    );
}

#[test]
fn tun_dns_in_cleartext_outside_the_tunnel_warns() {
    let o = Options::parse(
        r#"{"inbounds":[{"type":"tun","address":["172.19.0.1/30"],"auto_route":true}],
        "outbounds":[{"type":"direct","tag":"d"},{"type":"socks","tag":"p","server":"127.0.0.1","server_port":1080}],
        "dns":{"servers":[
            {"type":"udp","tag":"plain","server":"1.1.1.1"},
            {"type":"udp","tag":"via","server":"1.1.1.1","detour":"p"},
            {"type":"https","tag":"doh","server":"1.1.1.1"}]}}"#,
    )
    .unwrap();
    let w: Vec<_> = o.warnings.iter().filter(|w| w.starts_with("dns.servers")).collect();
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(
        w[0].starts_with("dns.servers[0] (plain): sends queries in cleartext"),
        "{w:?}"
    );
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
    assert_eq!(t.stack, Some(TunStack::Mixed));
    assert!(matches!(&o.route.rules[0].action, RuleAction::Sniff { sniffers, .. } if sniffers.len() == 2));
    assert_eq!(o.route.rules[1].action, RuleAction::HijackDns);
    assert!(
        matches!(&o.route.rules[5].action, RuleAction::Route { options, .. } if options.override_port == Some(8443))
    );
}

#[test]
fn fragment_split() {
    let http = |tls: &str| {
        format!(
            r#"{{"outbounds":[{{"type":"http","tag":"h","server":"a.com","server_port":443,"tls":{{"enabled":true,{tls}}}}}]}}"#
        )
    };
    let o = Options::parse(&http(r#""fragment_split":{"pieces":"6-3","delay":"10-20"}"#)).unwrap();
    let OutboundKind::Http(h) = &o.outbounds[0].kind else {
        panic!()
    };
    assert_eq!(
        h.tls.as_ref().unwrap().fragment_split,
        Some(FragmentSplit {
            segments: true,
            records: true,
            pieces: Some(Range::new(3, 6)),
            length: None,
            delay: Some(Range::new(10, 20)),
        })
    );
    let o = Options::parse(&http(r#""fragment_split":{"mode":"record","length":40}"#)).unwrap();
    let OutboundKind::Http(h) = &o.outbounds[0].kind else {
        panic!()
    };
    let s = h.tls.as_ref().unwrap().fragment_split.unwrap();
    assert!(!s.segments && s.records && s.length == Some(Range::new(40, 40)));

    for (tls, path) in [
        (r#""fragment":true,"fragment_split":{}"#, "tls.fragment_split"),
        (r#""fragment_split":{"pieces":3,"length":10}"#, "fragment_split.length"),
        (r#""fragment_split":{"pieces":1}"#, "fragment_split.pieces"),
        (
            r#""fragment_split":{"mode":"record","delay":5}"#,
            "fragment_split.delay",
        ),
        (r#""fragment_split":{"mode":"packet"}"#, "fragment_split.mode"),
    ] {
        let e = err(&http(tls));
        assert!(e.contains(path), "{tls}: {e}");
    }

    let route = |opts: &str| {
        format!(
            r#"{{"outbounds":[{{"type":"direct","tag":"d"}}],"route":{{"rules":[{{"action":"route-options",{opts}}}]}}}}"#
        )
    };
    let o = Options::parse(&route(r#""tls_fragment_split":{"pieces":3}"#)).unwrap();
    let RuleAction::RouteOptions(r) = &o.route.rules[0].action else {
        panic!()
    };
    assert_eq!(r.tls_fragment_split.unwrap().pieces, Some(Range::new(3, 3)));
    let e = err(&route(r#""tls_record_fragment":true,"tls_fragment_split":{}"#));
    assert!(e.contains("tls_fragment_split"), "{e}");
}

#[test]
fn quic_outbounds() {
    let o = Options::parse(
        r#"{"outbounds":[
        {"type":"hysteria2","tag":"hy2","server":"example.com","server_ports":["20000:20100","30000:"],
         "hop_interval":"10s","up_mbps":100,"down_mbps":200,"password":"p",
         "obfs":{"type":"salamander","password":"o"},"network":"tcp",
         "tls":{"enabled":true,"server_name":"example.com"},
         "idle_timeout":"20s","stream_receive_window":"16MB","bbr_profile":"aggressive"},
        {"type":"tuic","tag":"tuic","server":"1.2.3.4","server_port":443,
         "uuid":"2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365","password":"p","congestion_control":"bbr",
         "udp_relay_mode":"quic","zero_rtt_handshake":true,"heartbeat":"5s","tls":{"enabled":true,"alpn":["h3"]}}
    ]}"#,
    )
    .unwrap();
    let OutboundKind::Hysteria2(h) = &o.outbounds[0].kind else {
        panic!()
    };
    assert_eq!(h.server.server_port, 0, "server_port is optional with server_ports");
    assert_eq!(h.server_ports, [(20000, 20100), (30000, 65535)]);
    assert_eq!(h.obfs_salamander.as_deref(), Some("o"));
    assert_eq!(h.network, Some(Network::Tcp));
    assert_eq!(h.quic.idle_timeout, Some(std::time::Duration::from_secs(20)));
    assert_eq!(h.quic.stream_receive_window, Some(16 << 20));
    assert!(o.warnings.iter().any(|w| w.contains("bbr_profile")));
    let OutboundKind::Tuic(t) = &o.outbounds[1].kind else {
        panic!()
    };
    assert_eq!(t.congestion_control, TuicCongestion::Bbr);
    assert_eq!(t.udp_relay, TuicUdpRelay::Quic);
    assert_eq!(t.uuid[0], 0x2d);

    let hy2 = |extra: &str| {
        err(&format!(
            r#"{{"outbounds":[{{"type":"hysteria2","server":"a","server_port":1,"tls":{{"enabled":true}}{extra}}}]}}"#
        ))
    };
    let e = hy2(r#","realm":{}"#);
    assert!(e.starts_with("outbounds[0].realm"), "{e}");
    let e = hy2(r#","obfs":{"type":"gecko","password":"x"}"#);
    assert!(e.starts_with("outbounds[0].obfs.type"), "{e}");
    let e = hy2(r#","server_ports":"1:2","hop_interval":"1s""#);
    assert!(e.starts_with("outbounds[0].hop_interval"), "{e}");
    let e = hy2(r#","bogus":1"#);
    assert_eq!(e, "outbounds[0].bogus: unknown field, or not supported by sbr yet");
    let e = err(r#"{"outbounds":[{"type":"hysteria2","server":"a","server_port":1}]}"#);
    assert_eq!(e, "outbounds[0].tls: TLS is required");

    let tuic = |extra: &str| {
        err(&format!(
            r#"{{"outbounds":[{{"type":"tuic","server":"a","server_port":1,"tls":{{"enabled":true}}{extra}}}]}}"#
        ))
    };
    let uuid = r#","uuid":"2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365""#;
    let e = tuic(&format!(r#"{uuid},"udp_relay_mode":"quic","udp_over_stream":true"#));
    assert!(e.starts_with("outbounds[0].udp_relay_mode"), "{e}");
    let e = tuic(r#","uuid":"nope""#);
    assert!(e.starts_with("outbounds[0].uuid"), "{e}");
    let e = tuic(&format!(r#"{uuid},"congestion_control":"vegas""#));
    assert!(e.starts_with("outbounds[0].congestion_control"), "{e}");
}
