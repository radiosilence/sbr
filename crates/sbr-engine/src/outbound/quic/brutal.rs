//! Hysteria's "Brutal" congestion control, plus a controller that can be
//! switched to it after the connection exists.
//!
//! Brutal sends at a fixed rate (the configured upload bandwidth) and
//! never backs off on loss; instead it raises the rate by `1 / ack_rate`
//! so the *delivered* rate stays at the target. sing-quic paces explicitly
//! at `bps / ack_rate` with a window of `2 * bps * rtt / ack_rate`. quinn
//! has no pacing hook: its pacer runs at `1.25 * window / rtt`. So here
//! the window is exactly one bandwidth-delay product at the compensated
//! rate, which makes the window (not the pacer) hold the send rate at the
//! target; the pacer only smooths bursts.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quinn::congestion::{Bbr, BbrConfig, Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// sing-quic `pktInfoSlotCount`: seconds of ack/loss history.
const SLOTS: usize = 5;
const MIN_SAMPLES: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
/// Before the first RTT sample (sing-quic uses the same constant).
const UNKNOWN_RTT_WINDOW: u64 = 10240;

#[derive(Clone, Copy, Default)]
struct Slot {
    second: u64,
    acked: u64,
    lost: u64,
}

#[derive(Clone)]
pub(crate) struct Brutal {
    /// Bytes per second.
    bps: u64,
    mtu: u16,
    srtt: Option<Duration>,
    ack_rate: f64,
    slots: [Slot; SLOTS],
    epoch: Instant,
}

impl Brutal {
    pub(crate) fn new(bps: u64, mtu: u16, now: Instant) -> Self {
        Self {
            bps,
            mtu,
            srtt: None,
            ack_rate: 1.0,
            slots: [Slot::default(); SLOTS],
            epoch: now,
        }
    }

    fn slot(&mut self, now: Instant) -> &mut Slot {
        let second = now.saturating_duration_since(self.epoch).as_secs();
        let s = &mut self.slots[(second % SLOTS as u64) as usize];
        if s.second != second {
            *s = Slot {
                second,
                acked: 0,
                lost: 0,
            };
        }
        s
    }

    fn update_ack_rate(&mut self, now: Instant) {
        let second = now.saturating_duration_since(self.epoch).as_secs();
        let min = second.saturating_sub(SLOTS as u64);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|s| s.second >= min)
            .fold((0, 0), |(a, l), s| (a + s.acked, l + s.lost));
        self.ack_rate = if acked + lost < MIN_SAMPLES {
            1.0
        } else {
            (acked as f64 / (acked + lost) as f64).max(MIN_ACK_RATE)
        };
    }
}

impl Controller for Brutal {
    fn on_ack(&mut self, now: Instant, _sent: Instant, _bytes: u64, _app_limited: bool, rtt: &RttEstimator) {
        self.srtt = Some(rtt.get());
        self.slot(now).acked += 1;
    }

    fn on_end_acks(&mut self, now: Instant, _in_flight: u64, _app_limited: bool, _largest: Option<u64>) {
        self.update_ack_rate(now);
    }

    fn on_congestion_event(&mut self, now: Instant, _sent: Instant, _persistent: bool, lost_bytes: u64) {
        // quinn reports bytes, sing-quic counts packets.
        self.slot(now).lost += lost_bytes.div_ceil(u64::from(self.mtu)).max(1);
        self.update_ack_rate(now);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        let Some(rtt) = self.srtt else {
            return UNKNOWN_RTT_WINDOW;
        };
        let w = self.bps as f64 * rtt.as_secs_f64() / self.ack_rate;
        // A window below two packets would stall quinn outright on very
        // low-latency paths.
        (w as u64).max(2 * u64::from(self.mtu))
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        UNKNOWN_RTT_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Set after the hysteria2 handshake to switch a connection to Brutal at
/// this many bytes per second (0: stay on BBR).
#[derive(Default)]
pub(crate) struct BrutalSwitch(AtomicU64);

impl BrutalSwitch {
    pub(crate) fn set(&self, bps: u64) {
        self.0.store(bps, Ordering::Release);
    }
}

/// hysteria2 picks its congestion controller after authenticating, but
/// quinn fixes the controller when the connection is created. This one
/// starts as BBR and swaps itself for Brutal the first time it is called
/// after the switch is set. The check is one relaxed load per callback.
pub(crate) struct Switchable {
    inner: Box<dyn Controller>,
    switch: Arc<BrutalSwitch>,
    mtu: u16,
    switched: bool,
}

impl Switchable {
    fn check(&mut self, now: Instant) {
        if self.switched {
            return;
        }
        let bps = self.switch.0.load(Ordering::Relaxed);
        if bps != 0 {
            self.inner = Box::new(Brutal::new(bps, self.mtu, now));
            self.switched = true;
        }
    }
}

impl Controller for Switchable {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.check(now);
        self.inner.on_sent(now, bytes, last_packet_number)
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, app_limited: bool, rtt: &RttEstimator) {
        self.check(now);
        self.inner.on_ack(now, sent, bytes, app_limited, rtt)
    }

    fn on_end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool, largest: Option<u64>) {
        self.inner.on_end_acks(now, in_flight, app_limited, largest)
    }

    fn on_congestion_event(&mut self, now: Instant, sent: Instant, persistent: bool, lost_bytes: u64) {
        self.check(now);
        self.inner.on_congestion_event(now, sent, persistent, lost_bytes)
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.inner.on_mtu_update(new_mtu)
    }

    fn window(&self) -> u64 {
        self.inner.window()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            switch: self.switch.clone(),
            mtu: self.mtu,
            switched: self.switched,
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

pub(crate) struct SwitchableFactory(pub Arc<BrutalSwitch>);

impl ControllerFactory for SwitchableFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Switchable {
            inner: Box::new(Bbr::new(Arc::new(BbrConfig::default()), current_mtu)),
            switch: self.0.clone(),
            mtu: current_mtu,
            switched: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compensates_loss() {
        let t0 = Instant::now();
        let mut b = Brutal::new(1_000_000, 1200, t0);
        assert_eq!(b.window(), UNKNOWN_RTT_WINDOW);
        b.srtt = Some(Duration::from_millis(100));
        assert_eq!(b.window(), 100_000);
        // 30% loss is clamped to an 80% ack rate.
        for _ in 0..70 {
            b.slot(t0).acked += 1;
        }
        b.on_congestion_event(t0, t0, false, 30 * 1200);
        assert!((b.ack_rate - MIN_ACK_RATE).abs() < 1e-9);
        assert_eq!(b.window(), 125_000);
        // 10% loss: rate goes up by 1/0.9.
        b.slots = [Slot::default(); SLOTS];
        for _ in 0..90 {
            b.slot(t0).acked += 1;
        }
        b.on_congestion_event(t0, t0, false, 10 * 1200);
        assert_eq!(b.window(), 111_111);
    }
}
