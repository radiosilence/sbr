//! Made-up tunnel figures for `SBR_GUI_DEMO=1`, so the app's screens can be
//! run and looked at without an installed tunnel.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::proto::{Group, Member, Stats};
use crate::tunnel::{HISTORY, Sample};

fn noise(seed: u64) -> f64 {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 31;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    (x >> 11) as f64 / (1u64 << 53) as f64
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn stats(last: Option<&Stats>) -> Stats {
    stats_at(now(), last)
}

/// The two minutes before now, as the graphs would have drawn them.
pub fn history() -> Vec<Sample> {
    let end = now();
    let mut last = stats_at(end - HISTORY as u64, None);
    (end + 1 - HISTORY as u64..=end)
        .map(|t| {
            let s = stats_at(t, Some(&last));
            let sample = Sample {
                up: (s.uplink_bytes - last.uplink_bytes) as f64,
                down: (s.downlink_bytes - last.downlink_bytes) as f64,
                cpu: (s.cpu_time_micros - last.cpu_time_micros) as f64 / 1e6,
                memory: s.memory_footprint,
                connections: s.active_connections,
            };
            last = s;
            sample
        })
        .collect()
}

fn stats_at(t: u64, last: Option<&Stats>) -> Stats {
    let wave = ((t as f64) / 9.0).sin() * 0.5 + 0.5;
    let burst = if noise(t / 7) > 0.7 { 6.0 } else { 1.0 };
    let down = (400_000.0 + 2_400_000.0 * wave * burst * noise(t)) as u64;
    let up = (40_000.0 + 260_000.0 * noise(t + 99)) as u64;
    let prev = last.copied().unwrap_or_default();
    Stats {
        memory_footprint: 14_000_000 + (noise(t + 5) * 3_000_000.0) as u64,
        memory_available: 0,
        active_connections: 20 + (noise(t + 3) * 30.0) as u64,
        udp_sessions: 4,
        uplink_bytes: prev.uplink_bytes + up,
        downlink_bytes: prev.downlink_bytes + down,
        cpu_time_micros: prev.cpu_time_micros + (30_000.0 + 90_000.0 * wave) as u64,
    }
}

fn member(tag: &str, kind: &str, delay: Option<u32>) -> Member {
    Member {
        tag: tag.into(),
        kind: kind.into(),
        delay,
        degraded: None,
        reason: None,
        retry_in: None,
    }
}

pub fn groups() -> Vec<Group> {
    vec![
        Group {
            tag: "proxy".into(),
            kind: "selector".into(),
            selected: "auto".into(),
            now: "hk-02".into(),
            delay: Some(48),
            members: vec![
                member("auto", "urltest", Some(48)),
                member("hk-01", "vless", Some(62)),
                member("hk-02", "vless", Some(48)),
                member("jp-01", "hysteria2", Some(91)),
                member("sg-01", "trojan", Some(140)),
                Member {
                    degraded: Some(true),
                    reason: Some("no_response".into()),
                    retry_in: Some(24),
                    ..member("us-01", "shadowsocks", None)
                },
            ],
        },
        Group {
            tag: "streaming".into(),
            kind: "selector".into(),
            selected: "jp-01".into(),
            now: "jp-01".into(),
            delay: Some(91),
            members: vec![
                member("hk-01", "vless", Some(62)),
                member("jp-01", "hysteria2", Some(91)),
                member("direct", "direct", None),
            ],
        },
    ]
}

/// A latency test: fresh numbers for the group's members.
pub fn test(groups: &mut [Group], tag: &str) {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if let Some(g) = groups.iter_mut().find(|g| g.tag == tag) {
        for (i, m) in g.members.iter_mut().enumerate() {
            if m.delay.is_some() {
                m.delay = Some(30 + (noise(t + i as u64) * 150.0) as u32);
            }
        }
    }
}
