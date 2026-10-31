//! One TCP connection: RFC 9293 with window scaling and timestamps
//! (RFC 7323), SACK (RFC 2018) and SACK-based loss recovery (RFC 6675),
//! NewReno congestion control (RFC 5681, RFC 6582), RFC 6298 retransmission
//! timing and RFC 5961 RST/SYN hardening.
//!
//! Connections are opened either by answering a SYN (the TUN stack, where
//! the peer is an app on the same host and loss happens when an interface
//! queue overflows) or by sending one (the WireGuard outbound, where the
//! peer is across the internet). There is no LISTEN state, and simultaneous
//! open is refused.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::buf::{CHUNK, Pool};
use super::wire::{self, ACK, FIN, Opts, Out, PSH, RST, SYN, Seg};
use super::{Ctx, Shared};

const INITIAL_RTO: Duration = Duration::from_secs(1);
/// Linux's floor. On the TUN's local path RTTs are far below this, and the
/// floor keeps scheduling stalls in a busy extension from firing spurious
/// timeouts.
const MIN_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_secs(60);
/// SYN and SYN-ACK retransmissions: about a minute of backoff.
const SYN_RETRIES: u32 = 5;
/// RFC 6298 §5.7: the RTO once established when our SYN had to be
/// retransmitted and no RTT sample was taken. (The passive side keeps the
/// initial RTO after a lost SYN-ACK: on the TUN's local path the first data
/// ACK gives a sample almost at once.)
const SYN_LOSS_RTO: Duration = Duration::from_secs(3);
/// About five minutes of backed-off retransmissions.
const DATA_RETRIES: u32 = 12;
/// RFC 6928.
const INITIAL_WINDOW_SEGMENTS: u32 = 10;
/// Kept short: TIME-WAIT only exists to re-ACK a retransmitted FIN. On the
/// passive side a new SYN on the same 4-tuple replaces it anyway; on the
/// active side the port stays reserved until it ends.
const TIME_WAIT: Duration = Duration::from_secs(5);
/// How long a connection the engine has closed may keep draining its send
/// buffer or waiting for the app's FIN.
const ORPHAN_LINGER: Duration = Duration::from_secs(60);
/// The longest a deferred handshake waits for the engine's verdict, and how
/// long a silently dropped SYN keeps absorbing the app's retransmissions
/// (about as long as a kernel keeps retrying a connect).
const HOLD_LIMIT: Duration = Duration::from_secs(75);
/// Out-of-order segments held per connection; more are dropped and
/// retransmitted by the peer. The bytes held are already bounded by the
/// advertised window (and reserved against the pool by `sync_promise`); this
/// bounds the per-segment overhead of a peer sending tiny segments, while
/// leaving room for a 1 MiB window of out-of-order data at a 1460-byte MSS.
const MAX_OOO: usize = 1024;
const MAX_SACK_SCOREBOARD: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    FinWait1,
    FinWait2,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// The interface queue was full; nothing was sent and no state changed.
#[derive(Debug)]
pub struct Blocked;

fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn le(a: u32, b: u32) -> bool {
    !lt(b, a)
}

fn max_seq(a: u32, b: u32) -> u32 {
    if lt(a, b) { b } else { a }
}

fn min_seq(a: u32, b: u32) -> u32 {
    if lt(a, b) { a } else { b }
}

/// Smallest shift with `65535 << shift >= bytes` (RFC 7323 caps it at 14).
pub fn shift_for(bytes: usize) -> u8 {
    let mut s = 0;
    while s < 14 && (65535usize << s) < bytes {
        s += 1;
    }
    s
}

pub struct Tcb {
    /// The app's original destination: the source of everything we send.
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: State,
    pub shared: Arc<Shared>,

    iss: u32,
    snd_una: u32,
    /// Next sequence number to send. Behind `snd_max` only while resending
    /// after a retransmission timeout.
    snd_nxt: u32,
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    snd_shift: u8,
    /// The peer's SYN carried a window-scale option (a shift of 0 is valid).
    ws_ok: bool,
    /// Largest segment (payload plus options) the peer and link take.
    seg_max: u32,
    /// Sequence number of our FIN, once sent.
    fin_seq: Option<u32>,
    fin_acked: bool,
    /// Payload bytes in a full-sized segment (MSS less timestamp option).
    smss: u32,

    irs: u32,
    rcv_nxt: u32,
    /// Right edge of the window last advertised; never moves left.
    rcv_adv: u32,
    rcv_shift: u8,
    rx_cap: usize,
    tx_cap: usize,
    pool: Arc<Pool>,
    /// This connection's share of `Pool::promise`.
    promised: usize,
    ooo: VecDeque<(u32, Vec<u8>)>,
    last_ooo: Option<u32>,
    /// The peer's FIN, seen ahead of a gap.
    fin_at: Option<u32>,

    ts_ok: bool,
    ts_recent: u32,
    sack_ok: bool,

    cwnd: u32,
    ssthresh: u32,
    ca_acc: u32,
    dupacks: u32,
    /// `snd_max` when fast recovery began.
    recovery: Option<u32>,
    rexmit_next: u32,
    rexmit_end: u32,
    rexmit_force: bool,
    /// SACKed ranges above `snd_una`, sorted, disjoint.
    sb: Vec<(u32, u32)>,

    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    /// Karn's algorithm: the one segment being timed, unless retransmitted.
    rtt_seq: Option<(u32, Instant)>,
    retries: u32,
    /// When the retransmission timer now firing was armed: the last ACK
    /// that advanced `snd_una`, or the first send. A connection that keeps
    /// making progress, however slowly, never reaches the user timeout.
    stall_start: Option<Instant>,
    /// Abort once data has gone unacknowledged this long (RFC 5482's user
    /// timeout); `None` leaves it to `DATA_RETRIES`.
    pub user_timeout: Option<Duration>,

    rto_at: Option<Instant>,
    persist: bool,
    linger_at: Option<Instant>,
    /// Earliest timer-heap entry for this connection.
    pub scheduled: Option<Instant>,

    ack_due: bool,
    ack_now: bool,
    /// Our SYN (active open) or SYN-ACK is to be sent.
    syn_due: bool,
    /// The receive window offered in our SYN (active open), which applies
    /// from the peer's ISN once the SYN-ACK names it.
    syn_wnd: u32,
    rst_due: bool,
    orphan: bool,
    pub wake_rd: bool,
    pub wake_wr: bool,
    /// The SYN-ACK waits for the engine (`Stream::accept`).
    held: bool,
    /// Dropped by the engine without a reply: ignore the app's SYNs.
    blackhole: bool,
    /// Hand the connection to the engine now (set once).
    pub accept_now: bool,
    /// Why the connection died, for the stream.
    pub error: Option<io::ErrorKind>,
}

impl Tcb {
    /// `Tcb::connect` builds on this with a template SYN, relying on
    /// `input_syn_sent` to re-derive every field taken from `seg`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_syn(
        local: SocketAddr,
        remote: SocketAddr,
        seg: &Seg,
        iss: u32,
        mtu: usize,
        rx_cap: usize,
        tx_cap: usize,
        shared: Arc<Shared>,
        defer: Option<Instant>,
        pool: Arc<Pool>,
    ) -> Self {
        let v6 = local.is_ipv6();
        let ts_ok = seg.ts.is_some();
        let link_mss = mtu.saturating_sub(wire::ip_header_len(v6) + 20);
        let peer_mss = seg.mss.map_or(if v6 { 1220 } else { 536 }, |m| m as usize);
        let smss = (peer_mss.min(link_mss).saturating_sub(if ts_ok { 12 } else { 0 })).max(64) as u32;
        let rcv_shift = if seg.ws.is_some() { shift_for(rx_cap) } else { 0 };
        let irs = seg.seq;
        Self {
            local,
            remote,
            state: State::SynReceived,
            shared,
            iss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_max: iss.wrapping_add(1),
            snd_wnd: seg.wnd as u32,
            snd_wl1: seg.seq,
            snd_wl2: 0,
            snd_shift: seg.ws.unwrap_or(0),
            ws_ok: seg.ws.is_some(),
            seg_max: peer_mss.min(link_mss).max(64 + 12) as u32,
            fin_seq: None,
            fin_acked: false,
            smss,
            irs,
            rcv_nxt: irs.wrapping_add(1),
            rcv_adv: irs.wrapping_add(1),
            rcv_shift,
            rx_cap,
            tx_cap,
            pool,
            promised: 0,
            ooo: VecDeque::new(),
            last_ooo: None,
            fin_at: None,
            ts_ok,
            ts_recent: seg.ts.map_or(0, |t| t.0),
            sack_ok: seg.sack_perm,
            cwnd: INITIAL_WINDOW_SEGMENTS * smss,
            ssthresh: u32::MAX,
            ca_acc: 0,
            dupacks: 0,
            recovery: None,
            rexmit_next: 0,
            rexmit_end: 0,
            rexmit_force: false,
            sb: Vec::new(),
            srtt: None,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
            rtt_seq: None,
            retries: 0,
            stall_start: None,
            user_timeout: None,
            rto_at: None,
            persist: false,
            linger_at: defer.map(|now| now + HOLD_LIMIT),
            scheduled: None,
            ack_due: false,
            ack_now: false,
            syn_due: defer.is_none(),
            syn_wnd: 0,
            rst_due: false,
            orphan: false,
            wake_rd: false,
            wake_wr: false,
            held: defer.is_some(),
            blackhole: false,
            accept_now: defer.is_some(),
            error: None,
        }
    }

    /// Active open: a connection in SYN-SENT whose SYN goes out on the next
    /// `output`. Window scaling, SACK and timestamps are offered and used if
    /// the SYN-ACK carries them too.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        local: SocketAddr,
        remote: SocketAddr,
        iss: u32,
        mtu: usize,
        rx_cap: usize,
        tx_cap: usize,
        shared: Arc<Shared>,
        pool: Arc<Pool>,
    ) -> Self {
        // Parameters as if the peer had offered everything; the SYN-ACK
        // settles what is actually used.
        let offer = Seg {
            ws: Some(0),
            sack_perm: true,
            ts: Some((0, 0)),
            ..Seg::default()
        };
        let mut t = Self::from_syn(local, remote, &offer, iss, mtu, rx_cap, tx_cap, shared, None, pool);
        t.state = State::SynSent;
        t.irs = 0;
        t.rcv_nxt = 0;
        t.rcv_adv = 0;
        t.snd_wnd = 0;
        t
    }

    pub fn irs(&self) -> u32 {
        self.irs
    }

    /// The engine already has this connection (deferred handshakes are
    /// handed over on the SYN).
    fn accepted(&self) -> bool {
        self.shared.m.lock().unwrap().handed
    }

    pub fn deadline(&self) -> Option<Instant> {
        match (self.rto_at, self.linger_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The receive half has delivered the peer's FIN.
    fn rx_done(&self) -> bool {
        matches!(
            self.state,
            State::CloseWait | State::Closing | State::LastAck | State::TimeWait | State::Closed
        )
    }

    // --- input ---------------------------------------------------------

    pub fn input(&mut self, seg: &Seg, pkt: &[u8], cx: &mut Ctx<'_>) -> Result<(), Blocked> {
        let payload = &pkt[seg.payload.clone()];
        if self.state == State::SynSent {
            return self.input_syn_sent(seg, payload, cx);
        }
        if self.state == State::SynReceived {
            if seg.has(RST) {
                if seg.seq == self.rcv_nxt {
                    self.state = State::Closed;
                }
                return Ok(());
            }
            if seg.has(SYN) {
                // A retransmitted SYN: our SYN-ACK was lost (or is still
                // waiting for the engine).
                self.syn_due = !self.held;
                return Ok(());
            }
            if self.held {
                return Ok(());
            }
            if !seg.has(ACK) {
                return Ok(());
            }
            if seg.ack != self.iss.wrapping_add(1) {
                return send_rst_for(self.local, self.remote, seg, cx);
            }
            self.state = State::Established;
            self.accept_now |= !self.accepted();
            self.snd_una = seg.ack;
            self.snd_wnd = (seg.wnd as u32) << self.snd_shift;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
            if let Some((_, t)) = self.rtt_seq.take() {
                self.rtt_sample(cx.now - t);
            }
            self.retries = 0;
            self.rto_at = None;
            self.rto = self.computed_rto();
            self.shared.m.lock().unwrap().upd_thresh = (self.rx_cap / 2).min(self.smss as usize);
            self.on_data(seg, payload, cx);
            return self.flush_ack_now(cx);
        }
        if self.state == State::Closed {
            return Ok(());
        }

        let rwnd = self.rcv_adv.wrapping_sub(self.rcv_nxt);
        let rwnd = if lt(self.rcv_adv, self.rcv_nxt) { 0 } else { rwnd };
        if seg.has(RST) {
            // RFC 5961 §3: only an exact match resets; anything else in
            // the window draws a challenge ACK.
            if seg.seq == self.rcv_nxt {
                self.reset(io::ErrorKind::ConnectionReset);
            } else if le(self.rcv_nxt, seg.seq) && lt(seg.seq, self.rcv_nxt.wrapping_add(rwnd.max(1))) {
                self.ack_now = true;
            }
            return self.flush_ack_now(cx);
        }
        let end = seg.seq.wrapping_add(seg.seq_len());
        let acceptable = if seg.seq_len() == 0 {
            le(self.rcv_nxt, seg.seq) && le(seg.seq, self.rcv_nxt.wrapping_add(rwnd))
        } else {
            lt(self.rcv_nxt, end) && le(seg.seq, self.rcv_nxt.wrapping_add(rwnd))
        };
        if !acceptable {
            // Old duplicates and keepalive probes: re-ACK so the peer learns
            // where we are. A pure ACK behind `rcv_nxt` (the peer resending
            // after a timeout) still carries a valid acknowledgment. (Data
            // at a zero window is acceptable above, so its ACK field is
            // processed and the data trimmed.)
            self.ack_now = true;
            if seg.seq_len() == 0 && seg.has(ACK) && lt(seg.seq, self.rcv_nxt) {
                self.on_ack(seg, 0, false, cx);
            }
            return self.flush_ack_now(cx);
        }
        if seg.has(SYN) {
            // RFC 5961 §4.
            self.ack_now = true;
            return self.flush_ack_now(cx);
        }
        if !seg.has(ACK) {
            return Ok(());
        }
        if let Some((val, _)) = seg.ts
            && self.ts_ok
            && le(seg.seq, self.rcv_nxt)
            && !lt(val, self.ts_recent)
        {
            self.ts_recent = val;
        }
        self.on_ack(seg, payload.len(), true, cx);
        if self.state == State::Closed || self.rst_due {
            return Ok(());
        }
        self.on_data(seg, payload, cx);
        self.flush_ack_now(cx)
    }

    /// RFC 9293 §3.10.7.3.
    fn input_syn_sent(&mut self, seg: &Seg, payload: &[u8], cx: &mut Ctx<'_>) -> Result<(), Blocked> {
        let ack_ok = seg.ack == self.iss.wrapping_add(1);
        if seg.has(ACK) && !ack_ok {
            return send_rst_for(self.local, self.remote, seg, cx);
        }
        if seg.has(RST) {
            if seg.has(ACK) {
                self.reset(io::ErrorKind::ConnectionRefused);
            }
            return Ok(());
        }
        if !seg.has(SYN) {
            return Ok(());
        }
        if !seg.has(ACK) {
            // Simultaneous open. Our ports are random and never listen, so
            // only a confused peer gets here: refuse its SYN and give up.
            self.reset(io::ErrorKind::ConnectionRefused);
            return send_rst_for(self.local, self.remote, seg, cx);
        }
        let v6 = self.local.is_ipv6();
        let link_mss = cx.mtu.saturating_sub(wire::ip_header_len(v6) + 20);
        let peer_mss = seg.mss.map_or(if v6 { 1220 } else { 536 }, |m| m as usize);
        self.ts_ok = seg.ts.is_some();
        self.ts_recent = seg.ts.map_or(0, |t| t.0);
        self.sack_ok = seg.sack_perm;
        self.ws_ok = seg.ws.is_some();
        self.snd_shift = seg.ws.unwrap_or(0);
        if !self.ws_ok {
            self.rcv_shift = 0;
        }
        self.seg_max = peer_mss.min(link_mss).max(64 + 12) as u32;
        self.smss = (peer_mss.min(link_mss).saturating_sub(if self.ts_ok { 12 } else { 0 })).max(64) as u32;
        self.cwnd = INITIAL_WINDOW_SEGMENTS * self.smss;
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.rcv_adv = self.rcv_nxt.wrapping_add(self.syn_wnd);
        self.snd_una = seg.ack;
        // Windows in a SYN are never scaled.
        self.snd_wnd = seg.wnd as u32;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        match self.rtt_seq.take() {
            Some((_, t)) if self.retries == 0 => {
                self.rtt_sample(cx.now - t);
                self.rto = self.computed_rto();
            }
            _ => self.rto = SYN_LOSS_RTO,
        }
        self.retries = 0;
        self.rto_at = None;
        self.state = State::Established;
        self.wake_wr = true;
        {
            let mut g = self.shared.m.lock().unwrap();
            g.upd_thresh = (self.rx_cap / 2).min(self.smss as usize);
            g.connected = true;
        }
        self.sync_promise();
        self.ack_now = true;
        if !payload.is_empty() || seg.has(FIN) {
            // Data or a FIN on the SYN-ACK starts after the SYN.
            let rest = Seg {
                seq: seg.seq.wrapping_add(1),
                flags: seg.flags & !SYN,
                ..seg.clone()
            };
            self.on_data(&rest, payload, cx);
        }
        self.flush_ack_now(cx)
    }

    fn flush_ack_now(&mut self, cx: &mut Ctx<'_>) -> Result<(), Blocked> {
        if self.ack_now && self.state != State::Closed && !self.rst_due {
            self.send_ack(cx)?;
        }
        Ok(())
    }

    fn on_ack(&mut self, seg: &Seg, payload_len: usize, in_window: bool, cx: &mut Ctx<'_>) {
        let ack = seg.ack;
        if lt(self.snd_max, ack) {
            self.ack_now = true; // acks something we never sent
            return;
        }
        let wnd = (seg.wnd as u32) << self.snd_shift;
        let mut wnd_changed = false;
        if lt(self.snd_wl1, seg.seq) || (self.snd_wl1 == seg.seq && le(self.snd_wl2, ack)) {
            wnd_changed = wnd != self.snd_wnd;
            if self.snd_wnd == 0 && wnd > 0 {
                self.persist = false;
                self.rto_at = None;
            }
            self.snd_wnd = wnd;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = ack;
        }
        let sacked_before = self.sacked_total();
        if self.sack_ok {
            for &(l, r) in seg.sacks() {
                self.sb_add(l, r);
            }
        }
        let new_sack = self.sacked_total() > sacked_before;

        if lt(self.snd_una, ack) {
            let mut acked = ack.wrapping_sub(self.snd_una);
            if let Some(f) = self.fin_seq
                && lt(f, ack)
                && !self.fin_acked
            {
                self.fin_acked = true;
                acked -= 1;
            }
            {
                let mut g = self.shared.m.lock().unwrap();
                let n = (acked as usize).min(g.tx.len());
                g.tx.consume(n);
            }
            self.wake_wr = true;
            self.snd_una = ack;
            if lt(self.snd_nxt, ack) {
                self.snd_nxt = ack;
            }
            self.sb_prune();
            if let Some((s, t)) = self.rtt_seq
                && le(s, ack)
            {
                self.rtt_seq = None;
                self.rtt_sample(cx.now - t);
            }
            self.retries = 0;
            self.rto = self.computed_rto();
            match self.recovery {
                Some(point) if le(point, ack) => {
                    self.recovery = None;
                    self.cwnd = self.ssthresh.min(self.flight() + self.smss).max(2 * self.smss);
                }
                Some(_) => {
                    // Partial ACK (RFC 6582): the next hole is lost too.
                    self.rexmit_next = max_seq(self.rexmit_next, ack);
                    if !self.sack_ok {
                        self.rexmit_end = ack.wrapping_add(self.smss);
                        self.rexmit_force = true;
                    }
                }
                None => self.grow_cwnd(acked),
            }
            self.dupacks = 0;
            self.rto_at = if self.snd_una == self.snd_max {
                None
            } else {
                Some(cx.now + self.rto)
            };
            self.persist = false;
            if self.fin_acked {
                match self.state {
                    State::FinWait1 => {
                        self.state = State::FinWait2;
                        if self.orphan {
                            self.linger_at = Some(cx.now + ORPHAN_LINGER);
                        }
                    }
                    State::Closing => self.enter_time_wait(cx.now),
                    State::LastAck => self.state = State::Closed,
                    _ => {}
                }
            }
        } else if in_window
            && ack == self.snd_una
            && self.snd_una != self.snd_max
            && payload_len == 0
            && !seg.has(SYN | FIN)
            && (!wnd_changed || new_sack)
        {
            self.dupacks += 1;
        }

        if self.recovery.is_none()
            && self.snd_nxt == self.snd_max
            && self.snd_una != self.snd_max
            && (self.dupacks >= 3 || (self.sack_ok && self.sacked_total() > 2 * self.smss))
        {
            self.enter_recovery();
        }
        if self.recovery.is_some() && self.sack_ok {
            self.rexmit_end = max_seq(self.rexmit_end, self.high_sacked());
        }
    }

    /// Keep `Pool::promise` in step with the open window.
    fn sync_promise(&mut self) {
        let open = if self.state == State::SynSent {
            // The window our SYN offered, from wherever the peer starts.
            self.syn_wnd as usize
        } else if lt(self.rcv_adv, self.rcv_nxt) || self.rx_done() {
            0
        } else {
            self.rcv_adv.wrapping_sub(self.rcv_nxt) as usize
        };
        if open != self.promised {
            self.pool.promise(self.promised, open);
            self.promised = open;
        }
    }

    fn on_data(&mut self, seg: &Seg, payload: &[u8], cx: &mut Ctx<'_>) {
        self.on_data_inner(seg, payload, cx);
        self.sync_promise();
    }

    fn on_data_inner(&mut self, seg: &Seg, payload: &[u8], cx: &mut Ctx<'_>) {
        if !matches!(self.state, State::Established | State::FinWait1 | State::FinWait2) {
            return;
        }
        if !payload.is_empty() {
            if self.orphan {
                // Data for a connection the engine closed: like a kernel
                // socket closed with unread data, reset it.
                self.abort(io::ErrorKind::ConnectionAborted);
                return;
            }
            let mut seq = seg.seq;
            let mut data = payload;
            if lt(seq, self.rcv_nxt) {
                let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
                data = &data[skip.min(data.len())..];
                seq = self.rcv_nxt;
            }
            let edge = max_seq(self.rcv_adv, self.rcv_nxt);
            let room = if lt(seq, edge) {
                edge.wrapping_sub(seq) as usize
            } else {
                0
            };
            data = &data[..data.len().min(room)];
            if data.is_empty() {
                self.ack_now = true;
            } else if seq == self.rcv_nxt {
                let filled_gap = !self.ooo.is_empty();
                {
                    let mut g = self.shared.m.lock().unwrap();
                    g.rx.push(data);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
                    while let Some((s, d)) = self.ooo.front()
                        && le(*s, self.rcv_nxt)
                    {
                        let end = s.wrapping_add(d.len() as u32);
                        if lt(self.rcv_nxt, end) {
                            let skip = self.rcv_nxt.wrapping_sub(*s) as usize;
                            g.rx.push(&d[skip..]);
                            self.rcv_nxt = end;
                        }
                        self.ooo.pop_front();
                    }
                }
                self.wake_rd = true;
                self.ack_due = true;
                // RFC 5681 §4.2: ACK at once when a gap fills.
                if filled_gap {
                    self.ack_now = true;
                }
            } else {
                if !self.store_ooo(seq, data) {
                    cx.stats.ooo_dropped += 1;
                }
                self.ack_now = true;
            }
        }
        if seg.has(FIN) {
            let fseq = seg.seq.wrapping_add(payload.len() as u32);
            if lt(self.rcv_nxt, fseq) && le(fseq, max_seq(self.rcv_adv, self.rcv_nxt)) {
                self.fin_at = Some(fseq);
            }
        }
        if self.fin_at == Some(self.rcv_nxt) {
            self.fin_at = None;
            self.fin_received(cx.now);
        } else if seg.has(FIN) && seg.seq.wrapping_add(payload.len() as u32) == self.rcv_nxt {
            self.fin_received(cx.now);
        }
    }

    fn fin_received(&mut self, now: Instant) {
        if self.rx_done() {
            self.ack_now = true;
            return;
        }
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.shared.m.lock().unwrap().rx_fin = true;
        self.wake_rd = true;
        self.ack_now = true;
        self.state = match self.state {
            State::Established => State::CloseWait,
            State::FinWait1 if self.fin_acked => {
                self.enter_time_wait(now);
                State::TimeWait
            }
            State::FinWait1 => State::Closing,
            State::FinWait2 => {
                self.enter_time_wait(now);
                State::TimeWait
            }
            s => s,
        };
    }

    fn enter_time_wait(&mut self, now: Instant) {
        self.state = State::TimeWait;
        self.rto_at = None;
        self.linger_at = Some(now + TIME_WAIT);
    }

    /// False if the segment was dropped for want of room.
    fn store_ooo(&mut self, seq: u32, data: &[u8]) -> bool {
        // The common case past a hole: in order after everything held.
        if self
            .ooo
            .back()
            .is_some_and(|(es, ed)| le(es.wrapping_add(ed.len() as u32), seq))
        {
            if self.ooo.len() >= MAX_OOO {
                return false;
            }
            self.ooo.push_back((seq, data.to_vec()));
            self.last_ooo = Some(seq);
            return true;
        }
        let base = self.rcv_nxt;
        let key = |s: u32| s.wrapping_sub(base);
        let end = seq.wrapping_add(data.len() as u32);
        let mut pieces = Vec::new();
        let mut s = seq;
        for (es, ed) in &self.ooo {
            let ee = es.wrapping_add(ed.len() as u32);
            if le(ee, s) {
                continue;
            }
            if le(end, *es) {
                break;
            }
            if lt(s, *es) {
                let a = s.wrapping_sub(seq) as usize;
                let b = es.wrapping_sub(seq) as usize;
                pieces.push((s, data[a..b].to_vec()));
            }
            s = max_seq(s, ee);
        }
        if lt(s, end) {
            pieces.push((s, data[s.wrapping_sub(seq) as usize..].to_vec()));
        }
        if self.ooo.len() + pieces.len() > MAX_OOO {
            return false;
        }
        for p in pieces {
            let at = self.ooo.partition_point(|(es, _)| key(*es) < key(p.0));
            self.ooo.insert(at, p);
        }
        self.last_ooo = Some(seq);
        true
    }

    /// Contiguous runs of out-of-order data: the one holding the most
    /// recent arrival first (RFC 2018 §4), then the rest highest first.
    fn sack_blocks(&self) -> Vec<(u32, u32)> {
        let mut runs: Vec<(u32, u32)> = Vec::new();
        for (s, d) in &self.ooo {
            let e = s.wrapping_add(d.len() as u32);
            match runs.last_mut() {
                Some(last) if last.1 == *s => last.1 = e,
                _ => runs.push((*s, e)),
            }
        }
        runs.reverse();
        if let Some(i) = self
            .last_ooo
            .and_then(|x| runs.iter().position(|&(l, r)| le(l, x) && lt(x, r)))
        {
            runs[..=i].rotate_right(1);
        }
        runs
    }

    /// Option bytes on a non-SYN segment.
    fn opts_len(&self) -> u32 {
        let ts = if self.ts_ok { 12 } else { 0 };
        if !self.sack_ok || self.ooo.is_empty() {
            return ts;
        }
        let room = (wire::MAX_OPTS as u32 - ts - 4) / 8;
        let runs = self.sack_blocks().len() as u32;
        ts + 4 + 8 * runs.min(room)
    }

    /// Payload that fits in one segment with the current options.
    fn payload_cap(&self, mtu: usize) -> u32 {
        let link = mtu.saturating_sub(wire::ip_header_len(self.local.is_ipv6()) + 20) as u32;
        self.seg_max.min(link).saturating_sub(self.opts_len()).max(1)
    }

    // --- sender bookkeeping ----------------------------------------------

    fn sb_add(&mut self, l: u32, r: u32) {
        let l = max_seq(l, self.snd_una);
        if !lt(l, r) || lt(self.snd_max, r) {
            return;
        }
        let base = self.snd_una;
        let key = |s: u32| s.wrapping_sub(base);
        let (mut nl, mut nr) = (l, r);
        self.sb.retain(|&(a, b)| {
            if key(b) < key(nl) || key(a) > key(nr) {
                true
            } else {
                nl = min_seq(nl, a);
                nr = max_seq(nr, b);
                false
            }
        });
        if self.sb.len() >= MAX_SACK_SCOREBOARD {
            return;
        }
        let at = self.sb.partition_point(|&(a, _)| key(a) < key(nl));
        self.sb.insert(at, (nl, nr));
    }

    fn sb_prune(&mut self) {
        let una = self.snd_una;
        self.sb.retain_mut(|(a, b)| {
            if le(*b, una) {
                return false;
            }
            *a = max_seq(*a, una);
            true
        });
    }

    fn sacked_total(&self) -> u32 {
        self.sb.iter().map(|(a, b)| b.wrapping_sub(*a)).sum()
    }

    fn sacked_in(&self, from: u32, to: u32) -> u32 {
        self.sb
            .iter()
            .map(|&(a, b)| {
                let (a, b) = (max_seq(a, from), min_seq(b, to));
                if lt(a, b) { b.wrapping_sub(a) } else { 0 }
            })
            .sum()
    }

    fn high_sacked(&self) -> u32 {
        self.sb.last().map_or(self.snd_una, |r| r.1)
    }

    /// Bytes presumed in the network (RFC 6675 "pipe", simplified):
    /// outstanding minus SACKed minus lost-and-not-yet-resent.
    fn flight(&self) -> u32 {
        if self.recovery.is_some() {
            let out = self.snd_max.wrapping_sub(self.snd_una);
            let from = max_seq(self.rexmit_next, self.snd_una);
            let to = min_seq(self.rexmit_end, self.snd_max);
            let lost = if lt(from, to) {
                to.wrapping_sub(from) - self.sacked_in(from, to)
            } else {
                0
            };
            out.saturating_sub(self.sacked_total()).saturating_sub(lost)
        } else {
            self.snd_nxt.wrapping_sub(self.snd_una) - self.sacked_in(self.snd_una, self.snd_nxt)
        }
    }

    fn enter_recovery(&mut self) {
        let flight = self.flight();
        self.ssthresh = (flight / 2).max(2 * self.smss);
        self.cwnd = self.ssthresh;
        self.recovery = Some(self.snd_max);
        self.rexmit_next = self.snd_una;
        self.rexmit_end = if self.sack_ok {
            max_seq(self.high_sacked(), self.snd_una.wrapping_add(self.smss))
        } else {
            self.snd_una.wrapping_add(self.smss)
        };
        self.rexmit_force = true;
    }

    fn grow_cwnd(&mut self, acked: u32) {
        let cap = (4 * self.tx_cap as u32).max(64 * 1024);
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked);
        } else {
            self.ca_acc = self.ca_acc.saturating_add(acked);
            if self.ca_acc >= self.cwnd {
                self.ca_acc -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(self.smss);
            }
        }
        self.cwnd = self.cwnd.min(cap);
    }

    fn rtt_sample(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(s) => {
                let d = s.abs_diff(r);
                self.rttvar = (self.rttvar * 3 + d) / 4;
                self.srtt = Some((s * 7 + r) / 8);
            }
        }
    }

    fn computed_rto(&self) -> Duration {
        match self.srtt {
            None => INITIAL_RTO,
            Some(s) => (s + (self.rttvar * 4).max(Duration::from_millis(1))).clamp(MIN_RTO, MAX_RTO),
        }
    }

    // --- events from the engine side and timers ---------------------------

    /// The stream wrote, read, shut down, aborted or was dropped.
    pub fn on_app(&mut self, now: Instant) {
        let mut g = self.shared.m.lock().unwrap();
        g.queued = false;
        if let Some(rst) = g.abort.take() {
            drop(g);
            if rst {
                self.abort(io::ErrorKind::ConnectionAborted);
            } else if self.state == State::SynReceived {
                // Swallow the app's retransmitted SYNs, as a black hole
                // would, rather than routing each one again.
                self.held = true;
                self.blackhole = true;
                self.syn_due = false;
                self.rto_at = None;
                self.linger_at = Some(now + HOLD_LIMIT);
            } else {
                self.state = State::Closed;
            }
            return;
        }
        if g.accept && self.held && !self.blackhole {
            self.held = false;
            self.syn_due = true;
            self.linger_at = None;
        }
        if g.dropped && matches!(self.state, State::SynSent | State::SynReceived) && !self.blackhole {
            drop(g);
            self.abort(io::ErrorKind::ConnectionAborted);
            return;
        }
        if std::mem::take(&mut g.want_ack) {
            self.ack_due = true;
        }
        if g.dropped && !self.orphan {
            self.orphan = true;
            if !g.rx.is_empty() {
                drop(g);
                self.abort(io::ErrorKind::ConnectionAborted);
                return;
            }
            g.tx_fin = true;
            if self.state != State::TimeWait {
                self.linger_at = Some(now + ORPHAN_LINGER);
            }
        }
    }

    pub fn on_timer(&mut self, cx: &mut Ctx<'_>) {
        let now = cx.now;
        if let Some(t) = self.linger_at
            && t <= now
        {
            self.linger_at = None;
            if self.state == State::TimeWait || self.blackhole {
                self.state = State::Closed;
            } else {
                self.abort(io::ErrorKind::TimedOut);
            }
            return;
        }
        let Some(t) = self.rto_at else { return };
        if t > now {
            return;
        }
        self.rto_at = None;
        if matches!(self.state, State::SynSent | State::SynReceived) {
            self.retries += 1;
            if self.retries > SYN_RETRIES {
                if self.state == State::SynSent {
                    self.reset(io::ErrorKind::TimedOut);
                } else {
                    self.state = State::Closed;
                }
                return;
            }
            self.rto = (self.rto * 2).min(MAX_RTO);
            self.rtt_seq = None;
            self.syn_due = true;
            return;
        }
        if self.persist {
            // Zero-window probe: an old sequence number draws an ACK that
            // carries the current window.
            self.rto = (self.rto * 2).min(MAX_RTO);
            self.rto_at = Some(now + self.rto);
            let seq = self.snd_una.wrapping_sub(1);
            let _ = self.send_segment(seq, 0, ACK, cx);
            return;
        }
        if self.snd_una == self.snd_max {
            return;
        }
        self.retries += 1;
        if self.retries == 1 {
            // The data has been waiting since the RTO that just expired.
            self.stall_start = Some(now.checked_sub(self.rto).unwrap_or(now));
        }
        let gave_up = self
            .user_timeout
            .zip(self.stall_start)
            .is_some_and(|(limit, since)| now.duration_since(since) >= limit);
        if self.retries > DATA_RETRIES || gave_up {
            self.abort(io::ErrorKind::TimedOut);
            return;
        }
        cx.stats.timeouts += 1;
        // RFC 5681 §3.1 and RFC 6298 §5.5–5.7. The scoreboard is dropped:
        // the receiver may have discarded SACKed data (RFC 2018 §8).
        let flight = self.flight();
        self.ssthresh = (flight / 2).max(2 * self.smss);
        self.cwnd = self.smss;
        self.snd_nxt = self.snd_una;
        self.sb.clear();
        self.recovery = None;
        self.dupacks = 0;
        self.rtt_seq = None;
        self.rto = (self.rto * 2).min(MAX_RTO);
        if let (Some(limit), Some(since)) = (self.user_timeout, self.stall_start) {
            // Wake when the user timeout runs out, not a backed-off RTO later.
            let left = (since + limit).saturating_duration_since(now);
            self.rto = self.rto.min(left.max(MIN_RTO));
        }
    }

    fn reset(&mut self, e: io::ErrorKind) {
        self.state = State::Closed;
        self.error = Some(e);
    }

    pub fn abort(&mut self, e: io::ErrorKind) {
        if self.state == State::SynSent {
            // RFC 9293 §3.10.4: nothing to reset before the peer answered;
            // a late SYN-ACK finds no connection and is reset then.
            self.reset(e);
            return;
        }
        self.rst_due = true;
        self.error.get_or_insert(e);
    }

    // --- output -----------------------------------------------------------

    pub fn output(&mut self, cx: &mut Ctx<'_>) -> Result<(), Blocked> {
        if self.rst_due {
            let seq = self.snd_nxt;
            self.send_segment(seq, 0, RST | ACK, cx)?;
            self.rst_due = false;
            self.state = State::Closed;
            return Ok(());
        }
        match self.state {
            State::Closed => return Ok(()),
            State::SynSent | State::SynReceived => {
                if self.syn_due {
                    self.send_syn(cx)?;
                    self.syn_due = false;
                    if self.rto_at.is_none() {
                        self.rto_at = Some(cx.now + self.rto);
                    }
                }
                return Ok(());
            }
            _ => {}
        }
        let (tx_len, tx_fin) = {
            let g = self.shared.m.lock().unwrap();
            (g.tx.len() as u32, g.tx_fin)
        };
        if !self.fin_acked && self.state != State::TimeWait {
            loop {
                let cap = self.payload_cap(cx.mtu);
                if let Some((seq, len, fin)) = self.next_rexmit(tx_len, cap) {
                    self.send_data(seq, len, fin, cx)?;
                    cx.stats.fast_retransmits += 1;
                    self.rexmit_next = seq.wrapping_add(len + fin as u32);
                    self.rexmit_force = false;
                    self.rtt_seq = None;
                    continue;
                }
                if let Some((seq, len, fin)) = self.next_new(tx_len, tx_fin, cap) {
                    self.send_data(seq, len, fin, cx)?;
                    let end = seq.wrapping_add(len + fin as u32);
                    if lt(seq, self.snd_max) {
                        self.rtt_seq = None;
                    } else if self.rtt_seq.is_none() {
                        self.rtt_seq = Some((end, cx.now));
                    }
                    self.snd_nxt = end;
                    self.snd_max = max_seq(self.snd_max, end);
                    if fin {
                        self.fin_seq = Some(seq.wrapping_add(len));
                        self.state = match self.state {
                            State::Established => State::FinWait1,
                            State::CloseWait => State::LastAck,
                            s => s,
                        };
                    }
                    continue;
                }
                break;
            }
        }
        if self.ack_due || self.ack_now {
            self.send_ack(cx)?;
        }
        if self.snd_una != self.snd_max {
            if self.rto_at.is_none() || self.persist {
                self.persist = false;
                self.rto_at = Some(cx.now + self.rto);
            }
        } else if self.snd_wnd == 0
            && !self.fin_acked
            && (tx_len > 0 || (tx_fin && self.fin_seq.is_none()))
            && self.rto_at.is_none()
        {
            self.persist = true;
            self.rto_at = Some(cx.now + self.rto);
        }
        Ok(())
    }

    /// The next lost range to resend during fast recovery.
    fn next_rexmit(&self, tx_len: u32, cap: u32) -> Option<(u32, u32, bool)> {
        self.recovery?;
        let end = min_seq(self.rexmit_end, self.snd_max);
        let mut s = max_seq(self.rexmit_next, self.snd_una);
        let mut hole_end = end;
        for &(a, b) in &self.sb {
            if le(b, s) {
                continue;
            }
            if le(a, s) {
                s = b;
                continue;
            }
            hole_end = min_seq(a, end);
            break;
        }
        if !lt(s, hole_end) {
            return None;
        }
        let want = hole_end.wrapping_sub(s).min(cap);
        if !self.rexmit_force && self.flight() + want > self.cwnd {
            return None;
        }
        Some(self.piece(s, want, tx_len))
    }

    /// The next segment of new data (or of resent data after a timeout).
    fn next_new(&self, tx_len: u32, tx_fin: bool, cap: u32) -> Option<(u32, u32, bool)> {
        let data_end = self.snd_una.wrapping_add(tx_len);
        let fin_pending = tx_fin && self.fin_seq.is_none_or(|f| le(self.snd_nxt, f));
        let unsent = if lt(self.snd_nxt, data_end) {
            data_end.wrapping_sub(self.snd_nxt)
        } else {
            0
        };
        if unsent == 0 {
            return (fin_pending && self.snd_nxt == data_end).then_some((self.snd_nxt, 0, true));
        }
        let wnd_end = self.snd_una.wrapping_add(self.snd_wnd);
        let wnd_room = if lt(self.snd_nxt, wnd_end) {
            wnd_end.wrapping_sub(self.snd_nxt)
        } else {
            0
        };
        let flight = self.flight();
        let cwnd_room = self.cwnd.saturating_sub(flight);
        let full = unsent.min(cap);
        let len = full.min(wnd_room).min(cwnd_room);
        // Sender-side silly window avoidance (RFC 9293 §3.8.6.2.1): no
        // runts while ACKs are still due to open the window.
        if len == 0 || (len < full && flight > 0) {
            return None;
        }
        let fin = fin_pending && self.snd_nxt.wrapping_add(len) == data_end;
        Some((self.snd_nxt, len, fin))
    }

    /// Up to `want` sequence numbers from `seq`: payload length and
    /// whether the FIN is among them.
    fn piece(&self, seq: u32, want: u32, tx_len: u32) -> (u32, u32, bool) {
        let data_end = self.snd_una.wrapping_add(tx_len);
        let avail = if lt(seq, data_end) {
            data_end.wrapping_sub(seq)
        } else {
            0
        };
        let len = want.min(avail);
        (seq, len, len < want && self.fin_seq == Some(seq.wrapping_add(len)))
    }

    /// Our SYN (SYN-SENT) or SYN-ACK (SYN-RECEIVED). An active open offers
    /// every option; a passive one echoes those the app's SYN carried.
    fn send_syn(&mut self, cx: &mut Ctx<'_>) -> Result<(), Blocked> {
        let active = self.state == State::SynSent;
        let mut o = Opts::default();
        let v6 = self.local.is_ipv6();
        let link_mss = cx.mtu.saturating_sub(wire::ip_header_len(v6) + 20).min(65535);
        o.mss(link_mss as u16);
        if self.sack_ok {
            o.sack_perm();
        }
        if self.ts_ok {
            o.ts(cx.ts, self.ts_recent);
        }
        if self.ws_ok {
            o.ws(self.rcv_shift);
        }
        // Windows in a SYN are never scaled.
        let wnd = self.rx_cap.min(65535).min(cx.pool.headroom().max(CHUNK)) as u16;
        if active {
            self.syn_wnd = self.syn_wnd.max(wnd as u32);
        } else {
            self.rcv_adv = self.rcv_nxt.wrapping_add(wnd as u32);
        }
        self.sync_promise();
        let off = wire::payload_offset(v6, &o);
        cx.buf.clear();
        cx.buf.resize(off, 0);
        wire::finish(
            cx.buf,
            &Out {
                src: self.local,
                dst: self.remote,
                seq: self.iss,
                ack: self.rcv_nxt,
                flags: if active { SYN } else { SYN | ACK },
                wnd,
                opts: &o,
            },
        );
        (cx.link)(cx.buf)?;
        if self.rtt_seq.is_none() && self.retries == 0 {
            self.rtt_seq = Some((self.iss.wrapping_add(1), cx.now));
        }
        Ok(())
    }

    fn send_ack(&mut self, cx: &mut Ctx<'_>) -> Result<(), Blocked> {
        let seq = self.snd_nxt;
        self.send_segment(seq, 0, ACK, cx)
    }

    fn send_data(&mut self, seq: u32, len: u32, fin: bool, cx: &mut Ctx<'_>) -> Result<(), Blocked> {
        let mut flags = ACK;
        if fin {
            flags |= FIN;
        }
        self.send_segment(seq, len, flags, cx)
    }

    /// Build and send one segment carrying `len` bytes of the send buffer
    /// from `seq`, with the current ACK, window and options.
    fn send_segment(&mut self, seq: u32, len: u32, mut flags: u8, cx: &mut Ctx<'_>) -> Result<(), Blocked> {
        let v6 = self.local.is_ipv6();
        let mut o = Opts::default();
        if self.ts_ok {
            o.ts(cx.ts, self.ts_recent);
        }
        if self.sack_ok && !self.ooo.is_empty() && flags & RST == 0 {
            o.sack(self.sack_blocks().into_iter());
        }
        let off = wire::payload_offset(v6, &o);
        let room = cx.mtu.saturating_sub(off - crate::device::HEADROOM);
        debug_assert!(len as usize <= room, "segment larger than the MTU");
        let len = (len as usize).min(room);
        cx.buf.clear();
        cx.buf.resize(off + len, 0);
        let wnd = {
            let mut g = self.shared.m.lock().unwrap();
            if len > 0 {
                g.tx.copy_out(seq.wrapping_sub(self.snd_una) as usize, &mut cx.buf[off..]);
                if seq.wrapping_add(len as u32) == self.snd_una.wrapping_add(g.tx.len() as u32) {
                    flags |= PSH;
                }
            }
            let wnd = self.window(g.rx.len(), cx.pool.headroom());
            g.adv_free = wnd as usize;
            wnd
        };
        let wire_wnd = if flags & RST != 0 {
            0
        } else {
            // Rounded down: rounding up would creep the right edge forward on
            // every ACK, past what `window` allowed. (We still accept up to
            // `rcv_adv`, so the few bytes shaved off are not a retraction the
            // peer can trip over.)
            (wnd >> self.rcv_shift).min(65535) as u16
        };
        wire::finish(
            cx.buf,
            &Out {
                src: self.local,
                dst: self.remote,
                seq,
                ack: self.rcv_nxt,
                flags,
                wnd: wire_wnd,
                opts: &o,
            },
        );
        (cx.link)(cx.buf)?;
        cx.stats.segments_out += 1;
        if flags & RST != 0 {
            cx.stats.resets_out += 1;
        } else {
            let adv = self.rcv_nxt.wrapping_add((wire_wnd as u32) << self.rcv_shift);
            self.rcv_adv = max_seq(self.rcv_adv, adv);
            self.sync_promise();
        }
        self.ack_due = false;
        self.ack_now = false;
        Ok(())
    }

    /// The receive window to advertise: free buffer space, without
    /// retracting the right edge (RFC 9293 §3.8.6.2.2), without moving it
    /// by less than an MSS or half the buffer (receiver SWS avoidance), and
    /// opening it no further than `mem` bytes of stack-wide memory allow
    /// (but always to one chunk).
    fn window(&self, rx_len: usize, mem: usize) -> u32 {
        let cur = if lt(self.rcv_adv, self.rcv_nxt) {
            0
        } else {
            self.rcv_adv.wrapping_sub(self.rcv_nxt)
        };
        let free = self.rx_cap.saturating_sub(rx_len) as u32;
        let step = ((self.rx_cap / 2) as u32).min(self.smss);
        let wnd = if free >= cur.saturating_add(step) { free } else { cur };
        let floor = self.rx_cap.min(CHUNK).saturating_sub(rx_len) as u32;
        let wnd = wnd
            .min(cur.saturating_add(mem.min(u32::MAX as usize) as u32).max(floor))
            .max(cur);
        wnd.min(65535 << self.rcv_shift)
    }
}

impl Drop for Tcb {
    fn drop(&mut self) {
        self.pool.promise(self.promised, 0);
    }
}

/// RFC 9293 §3.10.7.1: the reset for a segment that has no connection.
pub fn send_rst_for(local: SocketAddr, remote: SocketAddr, seg: &Seg, cx: &mut Ctx<'_>) -> Result<(), Blocked> {
    if seg.has(RST) {
        return Ok(());
    }
    let (seq, ack, flags) = if seg.has(ACK) {
        (seg.ack, 0, RST)
    } else {
        (0, seg.seq.wrapping_add(seg.seq_len()), RST | ACK)
    };
    let o = Opts::default();
    let off = wire::payload_offset(local.is_ipv6(), &o);
    cx.buf.clear();
    cx.buf.resize(off, 0);
    wire::finish(
        cx.buf,
        &Out {
            src: local,
            dst: remote,
            seq,
            ack,
            flags,
            wnd: 0,
            opts: &o,
        },
    );
    (cx.link)(cx.buf)
}
