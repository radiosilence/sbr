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
}
