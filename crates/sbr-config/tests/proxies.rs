//! WireGuard endpoints, ShadowTLS, AnyTLS, UoT and SOCKS variants.

use sbr_config::*;

fn err(json: &str) -> String {
    Options::parse(json).unwrap_err().to_string()
}

const WG_KEY: &str = "UMw/nn/aarRTT0YpX2vhoKkkVyMMaRm//ZIp0NtcDVA=";

fn wg(extra: &str, peer: &str) -> String {
    format!(
        r#"{{"endpoints":[{{"type":"wireguard","tag":"wg","address":["10.0.0.2/32","fd00::2/128"],"private_key":"{WG_KEY}"{extra},
            "peers":[{{"address":"example.com","port":51820,"public_key":"{WG_KEY}","allowed_ips":["0.0.0.0/0","::/0"]{peer}}}]}}],
          "route":{{"rules":[{{"ip_cidr":"10.0.0.0/8","outbound":"wg"}}]}}}}"#
    )
}

#[test]
fn wireguard_endpoint() {
    let o = Options::parse(&wg(
        r#","mtu":1280,"workers":2,"udp_timeout":"1m""#,
        r#","reserved":[1,2,3],"persistent_keepalive_interval":25"#,
    ))
    .unwrap();
    assert_eq!(
        o.final_outbound(),
        "direct",
        "endpoints never become the default outbound"
    );
    assert_eq!(o.outbounds.len(), 2);
    let OutboundKind::WireGuard(w) = &o.outbounds[1].kind else {
        panic!("{:?}", o.outbounds[1].kind)
    };
    assert_eq!(o.outbounds[1].tag, "wg");
    assert_eq!((w.mtu, w.workers, w.address.len()), (1280, 2, 2));
    assert_eq!(w.peers[0].reserved, [1, 2, 3]);
    assert_eq!(w.peers[0].persistent_keepalive_interval, 25);
    assert_eq!(w.peers[0].allowed_ips.len(), 2);

    let d = Options::parse(&wg("", "")).unwrap();
    let OutboundKind::WireGuard(w) = &d.outbounds[1].kind else {
        panic!()
    };
    assert_eq!(w.mtu, WIREGUARD_DEFAULT_MTU);
}

#[test]
fn wireguard_errors_have_paths() {
    let e = err(&wg("", r#","reserved":[1,2]"#));
    assert!(e.starts_with("endpoints[0].peers[0].reserved"), "{e}");
    let e = err(&wg(r#","system":true"#, ""));
    assert!(e.starts_with("endpoints[0].system"), "{e}");
    let e = err(&wg(r#","bogus":1"#, ""));
    assert!(e.starts_with("endpoints[0].bogus"), "{e}");
    let e = err(&wg(r#","listen_port":1,"detour":"direct""#, ""));
    assert!(e.contains("conflict"), "{e}");
    let e = err(&wg("", "").replacen(WG_KEY, "AAAA", 1));
    assert!(e.starts_with("endpoints[0].private_key"), "{e}");
    let e = err(r#"{"outbounds":[{"type":"wireguard","tag":"w"}]}"#);
    assert!(e.contains("WireGuard endpoint"), "{e}");
    let e = err(r#"{"endpoints":[{"type":"tailscale","tag":"t"}]}"#);
    assert!(e.starts_with("endpoints[0].type"), "{e}");
    let e = err(&wg("", "").replace(r#""outbound":"wg""#, r#""outbound":"nope""#));
    assert!(e.contains("outbound not found"), "{e}");
}

#[test]
fn shadowtls_anytls_uot_socks() {
    let o = Options::parse(
        r#"{"outbounds":[
        {"type":"shadowsocks","tag":"ss","server":"x","server_port":1,"method":"2022-blake3-aes-128-gcm","password":"p","detour":"st","udp_over_tcp":true,"network":["tcp","udp"]},
        {"type":"shadowsocks","tag":"ss1","server":"x","server_port":1,"method":"aes-128-gcm","password":"p","udp_over_tcp":{"enabled":true,"version":1},"network":"udp"},
        {"type":"shadowtls","tag":"st","server":"x","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.com"}},
        {"type":"shadowtls","tag":"st3","server":"x","server_port":443,"version":3,"password":"p","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}}},
        {"type":"anytls","tag":"any","server":"x","server_port":443,"password":"p","idle_session_timeout":"60s","min_idle_session":2,"tls":{"enabled":true}},
        {"type":"socks","tag":"s4","server":"x","server_port":1,"version":"4a","network":"tcp"}
    ]}"#,
    )
    .unwrap();
    let OutboundKind::Shadowsocks(ss) = &o.outbounds[0].kind else {
        panic!()
    };
    assert_eq!((ss.network, ss.udp_over_tcp), (None, Some(UdpOverTcp { version: 2 })));
    let OutboundKind::Shadowsocks(ss) = &o.outbounds[1].kind else {
        panic!()
    };
    assert_eq!(
        (ss.network, ss.udp_over_tcp),
        (Some(Network::Udp), Some(UdpOverTcp { version: 1 }))
    );
    let OutboundKind::ShadowTls(st) = &o.outbounds[2].kind else {
        panic!()
    };
    assert_eq!(st.version, 1);
    assert_eq!(st.tls.max_version.as_deref(), Some("1.2"), "v1 is pinned to TLS 1.2");
    let OutboundKind::AnyTls(a) = &o.outbounds[4].kind else {
        panic!()
    };
    assert_eq!(a.min_idle_session, 2);
    assert_eq!(a.idle_session_timeout, Some(std::time::Duration::from_secs(60)));
    let OutboundKind::Socks(s) = &o.outbounds[5].kind else {
        panic!()
    };
    assert_eq!((s.version.as_str(), s.network), ("4a", Some(Network::Tcp)));

    let e = err(r#"{"outbounds":[{"type":"shadowtls","tag":"st","server":"x","server_port":443}]}"#);
    assert_eq!(e, "outbounds[0].tls: TLS required");
    let e = err(
        r#"{"outbounds":[{"type":"anytls","tag":"a","server":"x","server_port":443,"tcp_fast_open":true,"tls":{"enabled":true}}]}"#,
    );
    assert!(e.starts_with("outbounds[0].tcp_fast_open"), "{e}");
    let e = err(
        r#"{"outbounds":[{"type":"shadowsocks","tag":"s","server":"x","server_port":1,"method":"aes-128-gcm","udp_over_tcp":{"version":3}}]}"#,
    );
    assert!(e.starts_with("outbounds[0].udp_over_tcp.version"), "{e}");
    let e = err(
        r#"{"outbounds":[{"type":"shadowsocks","tag":"s","server":"x","server_port":1,"method":"aes-128-gcm","plugin":"obfs-local"}]}"#,
    );
    assert!(e.starts_with("outbounds[0].plugin"), "{e}");
    let e = err(r#"{"outbounds":[{"type":"socks","tag":"s","server":"x","server_port":1,"network":"icmp"}]}"#);
    assert!(e.starts_with("outbounds[0].network"), "{e}");
}
