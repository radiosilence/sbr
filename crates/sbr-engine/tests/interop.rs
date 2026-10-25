//! Interop: sbr outbounds against real servers (sing-box as the reference
//! server where it has one). sing-box tests skip when no binary is found;
//! point `SBR_SING_BOX` at one to run them.

mod common;

use common::*;

macro_rules! need_sing_box {
    () => {
        match sing_box() {
            Some(b) => b,
            None => {
                eprintln!("skipped: no sing-box binary (set SBR_SING_BOX)");
                return;
            }
        }
    };
}

const SS_KEY: &str = "Ixi/xBrzF3Nnrel2vh8Dsg==";

async fn ss_server(bin: &std::path::Path, method: &str, password: &str) -> (SingBox, u16) {
    let p = free_port();
    let cfg = format!(
        r#"{{"log":{{"level":"warn"}},
        "inbounds":[{{"type":"shadowsocks","listen":"127.0.0.1","listen_port":{p},"method":"{method}","password":"{password}"}}],
        "outbounds":[{{"type":"direct"}}]}}"#
    );
    (SingBox::start(bin, &cfg, Some(p)).await, p)
}

async fn sbr_via(outbound: &str) -> sbr_engine::Instance {
    start(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[{outbound}]}}"#
    ))
    .await
}

#[tokio::test]
async fn shadowsocks_2022_udp_and_tcp_vs_sing_box() {
    let bin = need_sing_box!();
    let method = "2022-blake3-aes-128-gcm";
    let (_sb, p) = ss_server(&bin, method, SS_KEY).await;
    let sbr = sbr_via(&format!(
        r#"{{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":{p},"method":"{method}","password":"{SS_KEY}"}}"#
    ))
    .await;
    let udp = SocksUdp::new(port(&sbr, "in")).await;
    udp.echo_check(udp_echo().await, &[1, 100, 1200, 1400, 8000]).await;
    let s = socks_connect(port(&sbr, "in"), echo().await).await;
    bulk_echo(s, 1 << 20).await;
}

#[tokio::test]
async fn shadowsocks_aead_udp_vs_sing_box() {
    let bin = need_sing_box!();
    let method = "chacha20-ietf-poly1305";
    let (_sb, p) = ss_server(&bin, method, "hunter2").await;
    let sbr = sbr_via(&format!(
        r#"{{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":{p},"method":"{method}","password":"hunter2"}}"#
    ))
    .await;
    let udp = SocksUdp::new(port(&sbr, "in")).await;
    udp.echo_check(udp_echo().await, &[1, 1400, 8000]).await;
}

#[tokio::test]
async fn shadowsocks_udp_over_tcp_vs_sing_box() {
    let bin = need_sing_box!();
    let method = "2022-blake3-aes-128-gcm";
    let (_sb, p) = ss_server(&bin, method, SS_KEY).await;
    for uot in [r#"true"#, r#"{"enabled":true,"version":1}"#] {
        let sbr = sbr_via(&format!(
            r#"{{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":{p},"method":"{method}","password":"{SS_KEY}","udp_over_tcp":{uot}}}"#
        ))
        .await;
        let udp = SocksUdp::new(port(&sbr, "in")).await;
        udp.echo_check(udp_echo().await, &[1, 100, 1400, 8000]).await;
        // A second destination over the same association (full-cone).
        udp.echo_check(udp_echo().await, &[64]).await;
    }
}

#[tokio::test]
async fn socks5_udp_associate_vs_sbr_inbound() {
    let target = udp_echo().await;
    let back = start(r#"{"inbounds":[{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0}]}"#).await;
    let front = sbr_via(&format!(
        r#"{{"type":"socks","tag":"s","server":"127.0.0.1","server_port":{}}}"#,
        port(&back, "in")
    ))
    .await;
    let udp = SocksUdp::new(port(&front, "in")).await;
    udp.echo_check(target, &[1, 100, 1400, 8000]).await;
    udp.echo_check(udp_echo().await, &[3]).await;
}

#[tokio::test]
async fn socks4a_connect_vs_sing_box() {
    let bin = need_sing_box!();
    let p = free_port();
    let _sb = SingBox::start(
        &bin,
        &format!(
            r#"{{"log":{{"level":"warn"}},"inbounds":[{{"type":"socks","listen":"127.0.0.1","listen_port":{p}}}],"outbounds":[{{"type":"direct"}}]}}"#
        ),
        Some(p),
    )
    .await;
    for v in ["4", "4a"] {
        let sbr = sbr_via(&format!(
            r#"{{"type":"socks","tag":"s","server":"127.0.0.1","server_port":{p},"version":"{v}"}}"#
        ))
        .await;
        let s = socks_connect(port(&sbr, "in"), echo().await).await;
        bulk_echo(s, 256 * 1024).await;
    }
}

// Two fixed key pairs: (server, client).
const WG_SERVER_PRIV: &str = "UMw/nn/aarRTT0YpX2vhoKkkVyMMaRm//ZIp0NtcDVA=";
const WG_SERVER_PUB: &str = "86aLVfau2HFqXMvhQCqNmZpmsBj+sA2NWZP18Q5d2is=";
const WG_CLIENT_PRIV: &str = "wB84HEwMuUsqfS3lzc0uVwGCRj1/AazY6Z6ixqVOEGo=";
const WG_CLIENT_PUB: &str = "fy+4MMVWHzNXfR+K+VPZ5qH2sA0M/HYanok123jxshI=";

/// sing-box as the "server" peer: flows to its tunnel address 10.66.0.1
/// are rewritten to 127.0.0.1 and leave through `direct`.
async fn wg_server(bin: &std::path::Path) -> (SingBox, u16) {
    let p = free_udp_port();
    let cfg = format!(
        r#"{{"log":{{"level":"warn"}},
        "endpoints":[{{"type":"wireguard","tag":"wg","address":["10.66.0.1/32"],"private_key":"{WG_SERVER_PRIV}","listen_port":{p},
            "peers":[{{"public_key":"{WG_CLIENT_PUB}","allowed_ips":["10.66.0.2/32"]}}]}}],
        "outbounds":[{{"type":"direct","tag":"direct"}}],
        "route":{{"final":"direct"}}}}"#
    );
    (SingBox::start(bin, &cfg, None).await, p)
}

fn wg_client(port: u16) -> String {
    format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "endpoints":[{{"type":"wireguard","tag":"wg","address":["10.66.0.2/32"],"private_key":"{WG_CLIENT_PRIV}",
            "peers":[{{"address":"127.0.0.1","port":{port},"public_key":"{WG_SERVER_PUB}","allowed_ips":["0.0.0.0/0"]}}]}}],
        "route":{{"final":"wg"}}}}"#
    )
}

#[tokio::test]
async fn wireguard_vs_sing_box() {
    let bin = need_sing_box!();
    let (_sb, p) = wg_server(&bin).await;
    let sbr = start(&wg_client(p)).await;
    let echo = echo().await;
    let via = std::net::SocketAddr::from(([10, 66, 0, 1], echo.port()));
    let s = socks_connect(port(&sbr, "in"), via).await;
    bulk_echo(s, 4 << 20).await;
    // Several flows at once.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let s = socks_connect(port(&sbr, "in"), via).await;
        set.spawn(bulk_echo(s, 1 << 20));
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
    let uecho = udp_echo().await;
    let udp = SocksUdp::new(port(&sbr, "in")).await;
    udp.echo_check(
        std::net::SocketAddr::from(([10, 66, 0, 1], uecho.port())),
        &[1, 100, 1300],
    )
    .await;

    // URL-less urltest: the endpoint reports its handshake RTT.
    let o = sbr_config::Options::parse(&wg_client(p)).unwrap();
    let ctx = sbr_engine::outbound::BuildContext {
        dns: std::sync::Arc::new(sbr_engine::sbr_core::dns::SystemDns),
        default_resolver: None,
        groups: Default::default(),
        base_dir: None,
    };
    let outs = sbr_engine::outbound::build_all(&o.outbounds, &ctx).unwrap();
    let wg = outs.iter().find(|o| o.tag() == "wg").unwrap();
    let probe = || async { tokio::time::timeout(std::time::Duration::from_secs(5), wg.probe_rtt().unwrap()).await };
    let rtt = probe().await.expect("handshake completes").unwrap();
    assert!(rtt < std::time::Duration::from_secs(1), "{rtt:?}");
    // A recent handshake is reused.
    assert_eq!(probe().await.unwrap().unwrap(), rtt);
}

/// On a multi-thread runtime sends go through the egress thread; a network
/// change swaps the socket under live flows, and the peer follows us.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wireguard_egress_thread_and_rebind_vs_sing_box() {
    let bin = need_sing_box!();
    let (_sb, p) = wg_server(&bin).await;
    let sbr = start(&wg_client(p)).await;
    let echo = echo().await;
    let via = std::net::SocketAddr::from(([10, 66, 0, 1], echo.port()));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let s = socks_connect(port(&sbr, "in"), via).await;
        set.spawn(bulk_echo(s, 4 << 20));
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
    let before = socks_connect(port(&sbr, "in"), via).await;
    sbr.engine.network_changed();
    bulk_echo(before, 2 << 20).await;
    let after = socks_connect(port(&sbr, "in"), via).await;
    bulk_echo(after, 2 << 20).await;
}

/// shadowsocks → detour shadowtls (v1/v2/v3) → sing-box shadowtls → ss.
#[tokio::test]
async fn shadowtls_with_shadowsocks_vs_sing_box() {
    let bin = need_sing_box!();
    let (cert, key) = self_signed();
    let camouflage = tls_sink(&cert, &key).await;
    let method = "2022-blake3-aes-128-gcm";
    for version in [3, 2, 1] {
        let p = free_port();
        let auth = match version {
            3 => r#""users":[{"name":"u","password":"shadow-pw"}],"#,
            2 => r#""password":"shadow-pw","#,
            _ => "",
        };
        let server = format!(
            r#"{{"log":{{"level":"warn"}},
            "inbounds":[
                {{"type":"shadowtls","listen":"127.0.0.1","listen_port":{p},"version":{version},{auth}
                  "handshake":{{"server":"127.0.0.1","server_port":{}}},"detour":"ss-in"}},
                {{"type":"shadowsocks","tag":"ss-in","listen":"127.0.0.1","method":"{method}","password":"{SS_KEY}"}}
            ],
            "outbounds":[{{"type":"direct"}}]}}"#,
            camouflage.port()
        );
        let _sb = SingBox::start(&bin, &server, Some(p)).await;
        let password = if version == 1 { "" } else { r#","password":"shadow-pw""# };
        // v2 hashes the camouflage server's whole flight; TLS 1.3 session
        // tickets sent after Finished race with that (in sing-box too).
        let max = if version == 2 { r#","max_version":"1.2""# } else { "" };
        let sbr = start(&format!(
            r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
            "outbounds":[
                {{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":{p},"method":"{method}","password":"{SS_KEY}","detour":"st"}},
                {{"type":"shadowtls","tag":"st","server":"127.0.0.1","server_port":{p},"version":{version}{password},
                  "tls":{{"enabled":true,"server_name":"localhost","insecure":true{max}}}}}
            ]}}"#
        ))
        .await;
        let s = socks_connect(port(&sbr, "in"), echo().await).await;
        bulk_echo(s, 1 << 20).await;
        let s = socks_connect(port(&sbr, "in"), echo().await).await;
        bulk_echo(s, 3000).await;
    }
}

#[tokio::test]
async fn anytls_vs_sing_box() {
    let bin = need_sing_box!();
    let (cert, key) = self_signed();
    let (cert_path, key_path) = (temp_file("cert.pem", &cert), temp_file("key.pem", &key));
    let p = free_port();
    let server = format!(
        r#"{{"log":{{"level":"warn"}},
        "inbounds":[{{"type":"anytls","listen":"127.0.0.1","listen_port":{p},"users":[{{"name":"u","password":"any-pw"}}],
            "tls":{{"enabled":true,"certificate_path":{:?},"key_path":{:?}}}}}],
        "outbounds":[{{"type":"direct"}}]}}"#,
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap()
    );
    let _sb = SingBox::start(&bin, &server, Some(p)).await;
    let cert_json = serde_json_string(&cert);
    let sbr = start(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[{{"type":"anytls","tag":"a","server":"127.0.0.1","server_port":{p},"password":"any-pw",
            "tls":{{"enabled":true,"server_name":"localhost","certificate":{cert_json}}}}}]}}"#
    ))
    .await;
    let target = echo().await;
    // Sequential streams reuse the idle session; concurrent ones share or add sessions.
    for _ in 0..3 {
        let s = socks_connect(port(&sbr, "in"), target).await;
        bulk_echo(s, 1 << 20).await;
    }
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let s = socks_connect(port(&sbr, "in"), target).await;
        set.spawn(bulk_echo(s, 512 * 1024));
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
    // UDP rides UoT v2 over a stream.
    let udp = SocksUdp::new(port(&sbr, "in")).await;
    udp.echo_check(udp_echo().await, &[1, 1400, 8000]).await;
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);
}

fn serde_json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
