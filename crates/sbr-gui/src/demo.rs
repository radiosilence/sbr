//! Made-up tunnel figures for `SBR_GUI_DEMO=1`, so the app's screens can be
//! run and looked at without an installed tunnel.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::proto::{Group, Member, Stats};
use crate::tunnel::{KEPT, POLL, Sample};

fn noise(seed: u64) -> f64 {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 31;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    (x >> 11) as f64 / (1u64 << 53) as f64
}

/// Ticks of `POLL` since the epoch.
fn tick() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (since.as_millis() / POLL.as_millis()) as u64
}

/// Noise that moves smoothly from one second to the next.
fn smooth(seed: u64, tick: u64) -> f64 {
    let per = 1000 / POLL.as_millis() as u64;
    let (s, f) = (tick / per, (tick % per) as f64 / per as f64);
    let f = f * f * (3.0 - 2.0 * f);
    noise(seed ^ s) * (1.0 - f) + noise(seed ^ (s + 1)) * f
}

/// The demo's figures at `tick`, as a sample would report them.
fn sample_at(tick: u64) -> Sample {
    let secs = tick as f64 * POLL.as_secs_f64();
    let wave = (secs / 9.0).sin() * 0.5 + 0.5;
    let burst = 1.0 + 5.0 * (smooth(7, tick / 6) - 0.55).max(0.0) / 0.45;
    Sample {
        down: 400_000.0 + 2_400_000.0 * wave * burst * smooth(1, tick),
        up: 40_000.0 + 260_000.0 * smooth(99, tick),
        cpu: 0.03 + 0.09 * wave,
        memory: 14_000_000 + (smooth(5, tick / 8) * 3_000_000.0) as u64,
        connections: 20 + (smooth(3, tick / 4) * 30.0) as u64,
    }
}

/// The next stats report, counting on from `last`.
pub fn stats(last: Option<&Stats>) -> Stats {
    let s = sample_at(tick());
    let dt = POLL.as_secs_f64();
    let prev = last.copied().unwrap_or_default();
    Stats {
        memory_footprint: s.memory,
        memory_available: 0,
        active_connections: s.connections,
        udp_sessions: 4,
        uplink_bytes: prev.uplink_bytes + (s.up * dt) as u64,
        downlink_bytes: prev.downlink_bytes + (s.down * dt) as u64,
        cpu_time_micros: prev.cpu_time_micros + (s.cpu * dt * 1e6) as u64,
    }
}

/// The history before now, as the graphs would have drawn it.
pub fn history() -> Vec<Sample> {
    let end = tick();
    (end - KEPT as u64 + 1..=end).map(sample_at).collect()
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
