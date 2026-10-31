//! sing-mux against sing-box: each protocol that allows `multiplex`, over
//! smux, yamux and h2mux, with and without padding. Every case pushes 1 MiB
//! through each of three concurrent streams and a set of datagrams through
//! a UDP echo. Skips without sing-box (`SBR_SING_BOX`).

mod common;

use common::*;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const SS_KEY: &str = "Ixi/xBrzF3Nnrel2vh8Dsg==";

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

/// `(sing-box inbound, sbr outbound)` without ports or multiplex.
fn protocols() -> Vec<(&'static str, String, String)> {
    vec![
        (
            "vless",
            format!(r#""type":"vless","users":[{{"uuid":"{UUID}"}}]"#),
            format!(r#""type":"vless","uuid":"{UUID}""#),
        ),
        (
            "vmess",
            format!(r#""type":"vmess","users":[{{"uuid":"{UUID}","alterId":0}}]"#),
            format!(r#""type":"vmess","uuid":"{UUID}","security":"aes-128-gcm""#),
        ),
        (
            "trojan",
            r#""type":"trojan","users":[{"password":"pw"}]"#.into(),
            r#""type":"trojan","password":"pw""#.into(),
        ),
        (
            "shadowsocks",
            format!(r#""type":"shadowsocks","method":"2022-blake3-aes-128-gcm","password":"{SS_KEY}""#),
            format!(r#""type":"shadowsocks","method":"2022-blake3-aes-128-gcm","password":"{SS_KEY}""#),
        ),
    ]
}

async fn check(name: &str, port_: u16, outbound: &str, mux: &str) {
    let sbr = start(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[{{{outbound},"tag":"o","server":"127.0.0.1","server_port":{port_},"multiplex":{mux}}}]}}"#
    ))
    .await;
    let target = echo().await;
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let s = socks_connect(port(&sbr, "in"), target).await;
        tasks.push(tokio::spawn(bulk_echo(s, 1 << 20)));
    }
    for t in tasks {
        t.await.unwrap_or_else(|e| panic!("{name} {mux}: {e}"));
    }
    let udp = SocksUdp::new(port(&sbr, "in")).await;
    udp.echo_check(udp_echo().await, &[1, 100, 1400, 8000]).await;
}

#[tokio::test]
async fn multiplex_vs_sing_box() {
    let bin = need_sing_box!();
    for (name, inbound, outbound) in protocols() {
        let p = free_port();
        let cfg = format!(
            r#"{{"log":{{"level":"warn"}},
            "inbounds":[{{{inbound},"listen":"127.0.0.1","listen_port":{p},"multiplex":{{"enabled":true}}}}],
            "outbounds":[{{"type":"direct"}}]}}"#
        );
        let _sb = SingBox::start(&bin, &cfg, Some(p)).await;
        for protocol in ["smux", "yamux", "h2mux"] {
            for padding in [false, true] {
                let mux =
                    format!(r#"{{"enabled":true,"protocol":"{protocol}","padding":{padding},"max_connections":2}}"#);
                check(name, p, &outbound, &mux).await;
            }
        }
    }
}

#[tokio::test]
async fn multiplex_brutal_exchange_vs_sing_box() {
    // sing-box refuses a brutal inbound where TCP Brutal (a Linux kernel
    // module) cannot exist.
    if !cfg!(target_os = "linux") {
        eprintln!("skipped: TCP Brutal servers need Linux");
        return;
    }
    let bin = need_sing_box!();
    let p = free_port();
    let cfg = format!(
        r#"{{"log":{{"level":"warn"}},
        "inbounds":[{{"type":"trojan","users":[{{"password":"pw"}}],"listen":"127.0.0.1","listen_port":{p},
            "multiplex":{{"enabled":true,"brutal":{{"enabled":true,"up_mbps":100,"down_mbps":100}}}}}}],
        "outbounds":[{{"type":"direct"}}]}}"#
    );
    let _sb = SingBox::start(&bin, &cfg, Some(p)).await;
    let mux = r#"{"enabled":true,"protocol":"h2mux","brutal":{"enabled":true,"up_mbps":50,"down_mbps":50}}"#;
    // TCP Brutal is a Linux kernel module: without it the server answers
    // the exchange with an error, which must reach the client intact.
    let sbr = start(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[{{"type":"trojan","password":"pw","tag":"o","server":"127.0.0.1","server_port":{p},"multiplex":{mux}}}]}}"#
    ))
    .await;
    let o = sbr.engine.outbound("o").unwrap();
    let dest = sbr_engine::sbr_core::Destination::from(echo().await);
    match o.connect(&dest).await {
        Ok(s) => drop(s),
        Err(e) => assert!(e.to_string().contains("brutal exchange: remote"), "{e}"),
    }
}

/// `network` applies to the streams inside the mux, not to the session,
/// which always runs over TCP.
#[tokio::test]
async fn multiplex_udp_only_network_vs_sing_box() {
    let bin = need_sing_box!();
    let p = free_port();
    let cfg = format!(
        r#"{{"log":{{"level":"warn"}},
        "inbounds":[{{"type":"trojan","users":[{{"password":"pw"}}],"listen":"127.0.0.1","listen_port":{p},"multiplex":{{"enabled":true}}}}],
        "outbounds":[{{"type":"direct"}}]}}"#
    );
    let _sb = SingBox::start(&bin, &cfg, Some(p)).await;
    let sbr = start(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[{{"type":"trojan","password":"pw","tag":"o","server":"127.0.0.1","server_port":{p},"network":"udp",
            "multiplex":{{"enabled":true,"protocol":"yamux"}}}}]}}"#
    ))
    .await;
    let udp = SocksUdp::new(port(&sbr, "in")).await;
    udp.echo_check(udp_echo().await, &[1, 1400]).await;
    let o = sbr.engine.outbound("o").unwrap();
    let dest = sbr_engine::sbr_core::Destination::from(echo().await);
    assert!(o.connect(&dest).await.is_err(), "tcp is disabled by network");
}
