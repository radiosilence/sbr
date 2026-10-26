//! Outbound health: notice paths that complete a handshake and then stop
//! carrying data, and keep `urltest` off them.
//!
//! The censors sbr is built against rarely refuse a connection any more.
//! Russia's TSPU freezes a flow after roughly 16–20 KB downstream (or about
//! 25 packets either way); Iran resets REALITY after its handshake; the GFW
//! has reset all of TCP/443 for an hour at a time. A TCP handshake or one
//! `HEAD` completes under all of them, so delay probes alone keep choosing a
//! dead path.
//!
//! Two inputs feed a per-leaf [`Record`]:
//!
//! - **Passive**, from the relay ([`watch`], [`finish`]). *Hard* signals are
//!   unambiguous about one connection: reset or closed before the remote sent
//!   a byte, a request with no answer at all for [`STALL`], a failed connect.
//!   A burst of them from [`BURST`] distinct destinations within [`WINDOW`]
//!   degrades the leaf; distinct destinations, so one dead website cannot.
//!   A clean close before any data is the weakest of these (servers and
//!   push endpoints do it on purpose, and a starved relay tears flows down
//!   the same way), so a burst made only with closes asks for a probe and
//!   degrades only if that fails. Closes are ignored outright while the
//!   leaf is moving [`PROOF_BYTES`] for other connections.
//!   *Soft* signals are what a freeze looks like but a long poll does too: the
//!   remote silent for [`STALL`] mid-TLS-record, or while the client waits.
//!   They never degrade on their own; they ask for a data probe.
//! - **Active**, a data probe (`HttpClient::data_probe`) that pulls
//!   [`PROOF_BYTES`] through the leaf on one connection. A probe that stops
//!   mid-transfer or is reset degrades the leaf at once: a freeze is
//!   deterministic per flow, so one conclusive probe is enough.
//!
//! A degraded leaf is out of `urltest` selection for a back-off that starts
//! at the residual-block length (120 s) and doubles on each repeat, then
//! comes back only after a probe started after the back-off. A connection
//! that moves [`PROOF_BYTES`] downstream proves the path is not frozen and
//! clears the failure history and the back-off.
//!
//! Cost: per connection, two relaxed timestamp stores per chunk and one timer
//! that is armed only while data is moving or a reply is outstanding. An idle
//! connection has no timer. The map lock is taken per signal, not per chunk.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::track::Conn;

/// Remote silence that makes a live connection suspect. Shorter than most
/// people wait for a page, longer than any server pauses inside a response.
pub const STALL: Duration = Duration::from_secs(8);
/// Downstream bytes on one flow that prove it is not frozen: well past the
/// 16–20 KB and 25-packet thresholds, with the tunnel's own handshake on top.
pub const PROOF_BYTES: u64 = 64 * 1024;
/// How long hard failures count towards a burst.
pub const WINDOW: Duration = Duration::from_secs(60);
/// Distinct destinations whose hard failures degrade a leaf.
pub const BURST: usize = 3;
/// First exclusion; TSPU's residual blocks last 120–600 s.
pub const BACKOFF_BASE: Duration = Duration::from_secs(120);
pub const BACKOFF_MAX: Duration = Duration::from_secs(1800);
/// Minimum spacing of probes a signal triggers for one leaf.
pub const PROBE_COOLDOWN: Duration = Duration::from_secs(30);
/// After a probe a soft signal triggered passes (a false alarm), soft signals
/// stop triggering probes for this long, so an app that long-polls does not
/// keep the radio up with probes.
pub const QUIET_AFTER_FALSE_ALARM: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Reset before the remote sent anything (or a data probe was reset).
    Reset,
    /// Closed by the remote before it sent anything.
    Closed,
    /// The client sent data and nothing at all came back for [`STALL`].
    NoResponse,
    /// The outbound could not connect.
    Connect,
    /// Soft: the client is waiting for a reply the remote has not sent.
    Waiting,
    /// Soft: the remote went silent in the middle of a TLS record.
    MidRecord,
    /// A data probe stopped receiving mid-transfer.
    Frozen,
}

impl Signal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reset => "reset",
            Self::Closed => "closed",
            Self::NoResponse => "no_response",
            Self::Connect => "connect",
            Self::Waiting => "waiting",
            Self::MidRecord => "mid_record",
            Self::Frozen => "frozen",
        }
    }

    fn hard(self) -> bool {
        !matches!(self, Self::Waiting | Self::MidRecord)
    }
}

/// What a data probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// [`PROOF_BYTES`] arrived.
    Pass,
    /// Data flowed, then stopped with more owed.
    Frozen,
    /// The connection was reset.
    Reset,
    /// Nothing to conclude: no target, the target closed early or served
    /// too little, the inner handshake failed.
    Inconclusive,
    /// The group's delay probe through the leaf failed.
    Unreachable,
}

#[derive(Debug, Clone, Copy)]
pub struct Degraded {
    pub reason: Signal,
    pub until: Instant,
}

#[derive(Debug, Clone)]
struct Event {
    at: Instant,
    signal: Signal,
    dest: String,
    conn: Option<u64>,
}

/// What a report asks the caller to do.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// The leaf just became degraded.
    pub degraded: bool,
    /// Run a data probe; the record now counts one as running.
    pub probe: bool,
    /// Like `probe`, for a burst of closes that degrades only if the leaf's
    /// delay probe or data probe then fails.
    pub confirm: bool,
    /// A close while the leaf carries data elsewhere; not counted.
    pub ignored: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    None,
    Degraded,
    Readmitted,
}

/// One leaf's health. Pure: callers pass the clock.
#[derive(Debug, Default)]
pub struct Record {
    events: Vec<Event>,
    degraded: Option<Degraded>,
    strikes: u32,
    probing: bool,
    /// The running probe was asked for by a soft signal.
    soft_probe: bool,
    last_triggered: Option<Instant>,
    false_alarm: Option<Instant>,
    /// The running probe decides a burst of closes.
    confirming: bool,
    last_carried: Option<Instant>,
}

impl Record {
    pub fn report(&mut self, now: Instant, signal: Signal, dest: &str, conn: Option<u64>) -> Outcome {
        let mut out = Outcome::default();
        // A degraded leaf gets no new connections; stragglers prove nothing.
        if self.degraded.is_some() {
            return out;
        }
        if signal == Signal::Closed && self.last_carried.is_some_and(|t| now.duration_since(t) < WINDOW) {
            out.ignored = true;
            return out;
        }
        if signal.hard() {
            self.events
                .retain(|e| now.duration_since(e.at) < WINDOW && (conn.is_none() || e.conn != conn));
            self.events.push(Event {
                at: now,
                signal,
                dest: dest.to_owned(),
                conn,
            });
            if self.distinct(|e| e.signal != Signal::Closed) >= BURST {
                self.degrade(now, signal);
                out.degraded = true;
                return out;
            }
            if self.distinct(|_| true) >= BURST {
                if self.claim_probe(now, false) {
                    self.confirming = true;
                    out.confirm = true;
                }
                return out;
            }
        }
        out.probe = self.claim_probe(now, !signal.hard());
        out
    }

    fn distinct(&self, f: impl Fn(&Event) -> bool) -> usize {
        let mut dests: Vec<&str> = self.events.iter().filter(|e| f(e)).map(|e| e.dest.as_str()).collect();
        dests.sort_unstable();
        dests.dedup();
        dests.len()
    }

    /// Destinations counting towards a burst, for logs.
    pub fn suspects(&self) -> Vec<&str> {
        let mut dests: Vec<&str> = self.events.iter().map(|e| e.dest.as_str()).collect();
        dests.sort_unstable();
        dests.dedup();
        dests
    }

    /// Another connection on the leaf is receiving data and has moved
    /// [`PROOF_BYTES`]: closes within [`WINDOW`] of this are not the path.
    pub fn carrying(&mut self, now: Instant) {
        self.last_carried = Some(now);
        self.events.retain(|e| e.signal != Signal::Closed);
    }

    fn claim_probe(&mut self, now: Instant, soft: bool) -> bool {
        let recent = |t: Option<Instant>, d: Duration| t.is_some_and(|t| now.duration_since(t) < d);
        if self.probing
            || recent(self.last_triggered, PROBE_COOLDOWN)
            || (soft && recent(self.false_alarm, QUIET_AFTER_FALSE_ALARM))
        {
            return false;
        }
        self.probing = true;
        self.soft_probe = soft;
        self.last_triggered = Some(now);
        true
    }

    /// Claim the probe slot for a scheduled probe. False if one is running.
    pub fn begin_probe(&mut self) -> bool {
        if self.probing {
            return false;
        }
        self.probing = true;
        self.soft_probe = false;
        true
    }

    /// A probe was abandoned before it finished.
    pub fn abort_probe(&mut self) {
        self.probing = false;
        self.confirming = false;
    }

    pub fn probe_done(&mut self, now: Instant, v: Verdict) -> Change {
        self.probing = false;
        let confirming = std::mem::take(&mut self.confirming);
        let expired = self.degraded.is_some_and(|d| now >= d.until);
        match v {
            Verdict::Pass => {
                if self.soft_probe {
                    self.false_alarm = Some(now);
                }
                self.events.clear();
                match self.degraded {
                    None => {
                        self.strikes = 0;
                        Change::None
                    }
                    Some(_) if expired => {
                        self.degraded = None;
                        Change::Readmitted
                    }
                    Some(_) => Change::None,
                }
            }
            Verdict::Frozen | Verdict::Reset if self.degraded.is_none() || expired => {
                let reason = if v == Verdict::Reset {
                    Signal::Reset
                } else {
                    Signal::Frozen
                };
                self.degrade(now, reason);
                Change::Degraded
            }
            Verdict::Unreachable if confirming && self.degraded.is_none() => {
                self.degrade(now, Signal::Closed);
                Change::Degraded
            }
            // Without a conclusive probe the handshake probe is the best
            // evidence there is; passive detection catches a relapse.
            Verdict::Inconclusive | Verdict::Unreachable if expired => {
                self.degraded = None;
                Change::Readmitted
            }
            _ => Change::None,
        }
    }

    /// A connection moved [`PROOF_BYTES`] downstream.
    pub fn success(&mut self, now: Instant) {
        // Connections opened before the demotion still finish; they don't
        // speak for new ones (port-443 policing kills later flows only).
        if self.degraded.is_none() {
            self.events.clear();
            self.strikes = 0;
            self.last_carried = Some(now);
        }
    }

    /// A stalled connection started receiving again: it wasn't frozen.
    pub fn retract(&mut self, conn: u64) {
        self.events.retain(|e| e.conn != Some(conn));
    }

    pub fn degraded(&self) -> Option<Degraded> {
        self.degraded
    }

    /// Degraded and past its back-off: probe it.
    pub fn due(&self, now: Instant) -> bool {
        self.degraded.is_some_and(|d| now >= d.until)
    }

    fn degrade(&mut self, now: Instant, reason: Signal) {
        let backoff = BACKOFF_BASE.saturating_mul(1 << self.strikes.min(8)).min(BACKOFF_MAX);
        self.degraded = Some(Degraded {
            reason,
            until: now + backoff,
        });
        self.strikes = self.strikes.saturating_add(1);
        self.events.clear();
    }
}

/// Every leaf's [`Record`], by tag.
#[derive(Default)]
pub struct Health(Mutex<HashMap<String, Record>>);

impl Health {
    pub fn with<R>(&self, tag: &str, f: impl FnOnce(&mut Record) -> R) -> R {
        let mut m = self.0.lock().unwrap();
        match m.get_mut(tag) {
            Some(r) => f(r),
            None => f(m.entry(tag.to_owned()).or_default()),
        }
    }

    pub fn degraded(&self, tag: &str) -> Option<Degraded> {
        self.0.lock().unwrap().get(tag).and_then(Record::degraded)
    }

    pub fn due(&self, tag: &str, now: Instant) -> bool {
        self.0.lock().unwrap().get(tag).is_some_and(|r| r.due(now))
    }

    /// A different network means a different censor: start over.
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

// ---------------------------------------------------------------------------
// Per-connection bookkeeping

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Milliseconds since [`epoch`], plus one so that 0 means "never".
fn now_ms() -> u64 {
    epoch().elapsed().as_millis() as u64 + 1
}

/// `Activity::remote_end` values; 0 is open.
const EOF: u8 = 1;
const RESET: u8 = 2;
const ERROR: u8 = 3;

/// Timing of one TCP relay, written by its task and read by [`watch`] and
/// the registry. Each field has one writer.
#[derive(Default)]
pub struct Activity {
    last_up: AtomicU64,
    last_down: AtomicU64,
    mid_record: AtomicBool,
    remote_end: AtomicU8,
    stalled: AtomicBool,
    armed: AtomicBool,
    notify: Notify,
}

impl Activity {
    #[inline]
    pub fn on_up(&self) {
        self.last_up.store(now_ms(), Ordering::Relaxed);
        self.arm();
    }

    #[inline]
    pub fn on_down(&self) {
        self.last_down.store(now_ms(), Ordering::Relaxed);
        if self.stalled.load(Ordering::Relaxed) {
            self.notify.notify_one();
        }
        self.arm();
    }

    #[inline]
    fn arm(&self) {
        if !self.armed.load(Ordering::Relaxed) {
            self.armed.store(true, Ordering::Relaxed);
            self.notify.notify_one();
        }
    }

    /// The remote sent data within `within`.
    pub fn receiving(&self, within: Duration) -> bool {
        let last = self.last_down.load(Ordering::Relaxed);
        last != 0 && now_ms().saturating_sub(last) < within.as_millis() as u64
    }

    /// [`watch`] has reported this connection and it has not recovered.
    pub fn stalled(&self) -> bool {
        self.stalled.load(Ordering::Relaxed)
    }
}

pub enum Watched {
    Stalled(Signal),
    Recovered,
}

/// Runs beside a relay and never returns. Sleeps only while the connection
/// is busy or owed a reply; a quiet keep-alive connection costs no wakeups.
pub async fn watch(conn: &Conn, mut on: impl FnMut(Watched)) -> Infallible {
    let a = &conn.activity;
    loop {
        if !a.armed.load(Ordering::Relaxed) {
            a.notify.notified().await;
            continue;
        }
        let (up, down) = (a.last_up.load(Ordering::Relaxed), a.last_down.load(Ordering::Relaxed));
        let last = up.max(down);
        let quiet = Duration::from_millis(now_ms().saturating_sub(last));
        if quiet < STALL {
            tokio::time::sleep(STALL - quiet).await;
            continue;
        }
        let signal = if conn.down.load(Ordering::Relaxed) == 0 && conn.up.load(Ordering::Relaxed) > 0 {
            Some(Signal::NoResponse)
        } else if up > down {
            Some(Signal::Waiting)
        } else if a.mid_record.load(Ordering::Relaxed) {
            Some(Signal::MidRecord)
        } else {
            None
        };
        let Some(signal) = signal else {
            // A finished exchange: sleep until the next one starts.
            a.armed.store(false, Ordering::Relaxed);
            continue;
        };
        a.stalled.store(true, Ordering::Relaxed);
        on(Watched::Stalled(signal));
        while a.last_down.load(Ordering::Relaxed) <= down {
            a.notify.notified().await;
        }
        a.stalled.store(false, Ordering::Relaxed);
        on(Watched::Recovered);
    }
}

/// How a connection ended, as far as health goes.
#[derive(Debug, PartialEq, Eq)]
pub enum Finish {
    Failed(Signal),
    Proven,
}

pub fn finish(conn: &Conn) -> Option<Finish> {
    let (up, down) = (conn.up.load(Ordering::Relaxed), conn.down.load(Ordering::Relaxed));
    if down >= PROOF_BYTES {
        return Some(Finish::Proven);
    }
    if down > 0 || up == 0 {
        return None;
    }
    match conn.activity.remote_end.load(Ordering::Relaxed) {
        EOF => Some(Finish::Failed(Signal::Closed)),
        RESET => Some(Finish::Failed(Signal::Reset)),
        _ => None,
    }
}

/// The outbound side of a relay: records how the remote ends and whether it
/// stopped inside a TLS record.
pub struct Observed<'a, S> {
    inner: S,
    activity: &'a Activity,
    framing: Framing,
}

impl<'a, S> Observed<'a, S> {
    pub fn new(inner: S, activity: &'a Activity) -> Self {
        Self {
            inner,
            activity,
            framing: Framing::default(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Observed<'_, S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        match &r {
            Poll::Ready(Ok(())) => {
                let this = &mut *self;
                let new = &buf.filled()[before..];
                if new.is_empty() {
                    if buf.remaining() > 0 {
                        this.activity.remote_end.store(EOF, Ordering::Relaxed);
                    }
                } else if this.framing.feed(new) {
                    this.activity
                        .mid_record
                        .store(this.framing.partial(), Ordering::Relaxed);
                }
            }
            Poll::Ready(Err(e)) => {
                let end = match e.kind() {
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => RESET,
                    _ => ERROR,
                };
                self.activity.remote_end.store(end, Ordering::Relaxed);
            }
            Poll::Pending => {}
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Observed<'_, S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Tracks TLS record boundaries in the downstream. A server writes whole
/// records, so a stream that goes quiet inside one was cut off in transit.
#[derive(Debug, Default)]
enum Framing {
    #[default]
    Unknown,
    NotTls,
    Tls {
        header: [u8; 5],
        have: u8,
        body: usize,
    },
}

impl Framing {
    /// Returns whether the stream is (still) TLS.
    fn feed(&mut self, mut b: &[u8]) -> bool {
        if let Self::Unknown = self {
            *self = match b.first() {
                Some(0x14..=0x17) => Self::Tls {
                    header: [0; 5],
                    have: 0,
                    body: 0,
                },
                _ => Self::NotTls,
            };
        }
        let Self::Tls { header, have, body } = self else {
            return false;
        };
        while !b.is_empty() {
            if *body > 0 {
                let k = (*body).min(b.len());
                *body -= k;
                b = &b[k..];
                continue;
            }
            let k = (5 - *have as usize).min(b.len());
            header[*have as usize..*have as usize + k].copy_from_slice(&b[..k]);
            *have += k as u8;
            b = &b[k..];
            if *have == 5 {
                if !(0x14..=0x18).contains(&header[0]) || header[1] != 3 {
                    *self = Self::NotTls;
                    return true;
                }
                *body = u16::from_be_bytes([header[3], header[4]]) as usize;
                *have = 0;
            }
        }
        true
    }

    fn partial(&self) -> bool {
        matches!(self, Self::Tls { have, body, .. } if *have > 0 || *body > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn burst_of_distinct_destinations_degrades() {
        let t = Instant::now();
        let mut r = Record::default();
        let o = r.report(t, Signal::Reset, "1", Some(1));
        assert_eq!(
            o,
            Outcome {
                probe: true,
                ..Default::default()
            }
        );
        r.probe_done(t, Verdict::Inconclusive);
        // The same destination failing again is one website, not the path.
        assert!(!r.report(t + S, Signal::Reset, "1", Some(2)).degraded);
        assert!(!r.report(t + S, Signal::Closed, "1", Some(3)).degraded);
        assert!(!r.report(t + 2 * S, Signal::NoResponse, "2", Some(4)).degraded);
        assert!(r.report(t + 3 * S, Signal::Connect, "3", None).degraded);
        let d = r.degraded().unwrap();
        assert_eq!(d.reason, Signal::Connect);
        assert_eq!(d.until, t + 3 * S + BACKOFF_BASE);
    }

    #[test]
    fn failures_outside_the_window_do_not_add_up() {
        let t = Instant::now();
        let mut r = Record::default();
        r.report(t, Signal::Reset, "1", None);
        r.report(t + 10 * S, Signal::Reset, "2", None);
        assert!(!r.report(t + WINDOW + S, Signal::Reset, "3", None).degraded);
        assert!(r.report(t + WINDOW + 2 * S, Signal::Reset, "4", None).degraded);
    }

    #[test]
    fn soft_signals_only_ask_for_probes() {
        let t = Instant::now();
        let mut r = Record::default();
        for i in 0..10u32 {
            let o = r.report(t + i * S, Signal::MidRecord, &i.to_string(), Some(i as u64));
            assert!(!o.degraded);
            assert_eq!(o.probe, i == 0, "one probe at a time");
        }
        assert_eq!(r.probe_done(t + 10 * S, Verdict::Pass), Change::None);
        // Within the cooldown nothing; after it, soft signals stay quiet
        // because the last one was a false alarm, hard ones still probe.
        assert!(!r.report(t + 20 * S, Signal::Waiting, "1", None).probe);
        assert!(!r.report(t + 50 * S, Signal::Waiting, "1", None).probe);
        assert!(r.report(t + 50 * S, Signal::Reset, "1", None).probe);
        r.probe_done(t + 51 * S, Verdict::Pass);
        assert!(
            r.report(t + 10 * S + QUIET_AFTER_FALSE_ALARM, Signal::Waiting, "1", None)
                .probe
        );

        // Scheduled probes neither delay nor silence signal-driven ones.
        let mut r = Record::default();
        assert!(r.begin_probe());
        r.probe_done(t, Verdict::Pass);
        assert!(r.report(t + S, Signal::MidRecord, "1", None).probe);
    }

    #[test]
    fn retracted_stalls_do_not_count() {
        let t = Instant::now();
        let mut r = Record::default();
        r.report(t, Signal::NoResponse, "1", Some(10));
        r.report(t, Signal::NoResponse, "2", Some(11));
        r.retract(10);
        assert!(!r.report(t, Signal::NoResponse, "3", Some(12)).degraded);
        // The same connection reporting again replaces its event.
        assert!(!r.report(t, Signal::Reset, "3", Some(12)).degraded);
        assert!(r.report(t, Signal::Reset, "4", Some(13)).degraded);
    }

    #[test]
    fn frozen_probe_degrades_and_backoff_doubles_to_a_cap() {
        let t = Instant::now();
        let mut r = Record::default();
        assert!(r.begin_probe());
        assert!(!r.begin_probe());
        assert_eq!(r.probe_done(t, Verdict::Frozen), Change::Degraded);
        assert_eq!(r.degraded().unwrap().reason, Signal::Frozen);
        let mut now = t;
        let mut expect = BACKOFF_BASE;
        for _ in 0..8 {
            let d = r.degraded().unwrap();
            assert_eq!(d.until - now, expect);
            // Not readmitted early, even by a passing probe.
            assert_eq!(r.probe_done(now + S, Verdict::Pass), Change::None);
            assert!(!r.due(d.until - S) && r.due(d.until));
            now = d.until;
            assert_eq!(r.probe_done(now, Verdict::Frozen), Change::Degraded);
            expect = (expect * 2).min(BACKOFF_MAX);
        }
        assert_eq!(r.degraded().unwrap().until - now, BACKOFF_MAX);
    }

    #[test]
    fn readmission_keeps_strikes_until_real_traffic_succeeds() {
        let t = Instant::now();
        let mut r = Record::default();
        r.probe_done(t, Verdict::Reset);
        assert_eq!(r.degraded().unwrap().reason, Signal::Reset);
        let until = r.degraded().unwrap().until;
        // Success on an old connection while degraded changes nothing.
        r.success(t);
        assert!(r.degraded().is_some());
        assert_eq!(r.probe_done(until, Verdict::Pass), Change::Readmitted);
        // Relapse: the second exclusion is twice as long.
        for d in 1..=3 {
            r.report(until + S, Signal::Reset, &d.to_string(), None);
        }
        assert_eq!(r.degraded().unwrap().until, until + S + 2 * BACKOFF_BASE);
        let until = r.degraded().unwrap().until;
        assert_eq!(r.probe_done(until, Verdict::Inconclusive), Change::Readmitted);
        r.success(t);
        r.probe_done(until + 10 * S, Verdict::Frozen);
        assert_eq!(
            r.degraded().unwrap().until,
            until + 10 * S + BACKOFF_BASE,
            "strikes reset"
        );
    }

    #[test]
    fn degraded_leaf_ignores_reports() {
        let t = Instant::now();
        let mut r = Record::default();
        r.probe_done(t, Verdict::Frozen);
        assert_eq!(r.report(t, Signal::Reset, "1", None), Outcome::default());
    }

    #[test]
    fn closes_alone_wait_for_a_probe() {
        let t = Instant::now();
        let mut r = Record::default();
        let first = r.report(t, Signal::Closed, "a", Some(1));
        assert!(first.probe);
        r.probe_done(t, Verdict::Inconclusive);
        assert_eq!(r.report(t + S, Signal::Closed, "b", Some(2)), Outcome::default());
        let o = r.report(t + PROBE_COOLDOWN, Signal::Closed, "c", Some(3));
        assert!(!o.degraded && o.confirm && !o.probe);
        assert!(r.degraded().is_none());
        assert_eq!(r.suspects(), ["a", "b", "c"]);
        // One reset among the closes is still not three non-close failures.
        assert!(!r.report(t + PROBE_COOLDOWN, Signal::Reset, "d", Some(4)).degraded);
        assert!(r.degraded().is_none());
    }

    #[test]
    fn close_burst_with_a_failing_probe_degrades() {
        let t = Instant::now();
        for v in [Verdict::Unreachable, Verdict::Reset, Verdict::Frozen] {
            let mut r = Record::default();
            assert!(r.report(t, Signal::Closed, "a", Some(1)).probe);
            r.probe_done(t, Verdict::Inconclusive);
            r.report(t + S, Signal::Closed, "b", Some(2));
            assert!(r.report(t + PROBE_COOLDOWN, Signal::Closed, "c", Some(3)).confirm);
            assert!(r.degraded().is_none());
            assert_eq!(r.probe_done(t + PROBE_COOLDOWN + S, v), Change::Degraded, "{v:?}");
            assert!(r.degraded().is_some());
        }
        // Unreachable degrades only when it answers a burst.
        let mut r = Record::default();
        assert!(r.begin_probe());
        assert_eq!(r.probe_done(t, Verdict::Unreachable), Change::None);
        assert!(r.degraded().is_none());
    }

    #[test]
    fn close_burst_with_a_passing_probe_clears() {
        let t = Instant::now();
        let mut r = Record::default();
        r.report(t, Signal::Closed, "a", Some(1));
        r.probe_done(t, Verdict::Inconclusive);
        r.report(t + S, Signal::Closed, "b", Some(2));
        assert!(r.report(t + PROBE_COOLDOWN, Signal::Closed, "c", Some(3)).confirm);
        assert_eq!(r.probe_done(t + PROBE_COOLDOWN, Verdict::Pass), Change::None);
        assert!(r.suspects().is_empty());
        // A later close starts from nothing.
        let later = t + 2 * PROBE_COOLDOWN;
        assert!(!r.report(later, Signal::Closed, "d", Some(4)).confirm);
        assert!(r.degraded().is_none());
    }

    #[test]
    fn closes_while_carrying_data_are_ignored() {
        let t = Instant::now();
        let mut r = Record::default();
        r.report(t, Signal::Closed, "a", Some(1));
        r.probe_done(t, Verdict::Inconclusive);
        r.carrying(t + S);
        assert!(r.suspects().is_empty(), "earlier closes are dropped too");
        for (i, d) in ["b", "c", "d", "e"].into_iter().enumerate() {
            let o = r.report(t + S * (i as u32 + 2), Signal::Closed, d, Some(i as u64 + 2));
            assert!(o.ignored && !o.confirm && !o.probe && !o.degraded);
        }
        assert!(r.degraded().is_none());
        // Other failures still count while it carries data.
        assert!(!r.report(t + 2 * S, Signal::Reset, "x", None).ignored);
        // A finished connection that moved PROOF_BYTES counts as carrying.
        let mut r = Record::default();
        r.success(t);
        assert!(r.report(t + S, Signal::Closed, "a", Some(1)).ignored);
        assert!(!r.report(t + WINDOW, Signal::Closed, "a", Some(1)).ignored);
    }

    #[test]
    fn tls_framing() {
        let mut f = Framing::default();
        // A 10-byte record split across reads, then a complete one.
        assert!(f.feed(&[0x17, 3, 3, 0, 10, 1, 2]));
        assert!(f.partial());
        assert!(f.feed(&[3, 4, 5, 6, 7, 8, 9, 10]));
        assert!(!f.partial());
        f.feed(&[0x17, 3]);
        assert!(f.partial(), "inside a header");
        f.feed(&[3, 0, 1, 0xff]);
        assert!(!f.partial());
        let mut f = Framing::default();
        assert!(!f.feed(b"HTTP/1.1 200 OK\r\n"));
        assert!(!f.partial());
        let mut f = Framing::default();
        assert!(f.feed(&[0x16, 9, 9, 0, 0]), "a bad version gives up");
        assert!(!f.partial());
        assert!(!f.feed(&[0x16]));
    }
}
