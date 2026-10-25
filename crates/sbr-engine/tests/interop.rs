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
