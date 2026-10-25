//! sbr's userspace TCP: terminates the TUN's TCP in-process, so no
//! connection depends on a kernel socket. Selected by `stack: gvisor`.
//!
//! One task (the TUN packet loop) owns every connection's state machine
//! (`tcb`). The engine talks to a connection through a `Stream`, which
//! shares only the two byte queues and a few flags with it under a
//! per-connection mutex held for copies, never across an await. Writes,
//! reads that open the window, shutdowns and drops queue the connection for
//! the packet loop and wake it; the loop answers with segments.
//!
//! Buffers are elastic (`buf`): a connection holds memory only for bytes in
//! flight or unread, up to the configured caps. Timers are deadlines in one
//! heap, so idle connections cost no wakeups.

pub(crate) mod buf;
pub(crate) mod tcb;
#[cfg(test)]
mod tests;
pub(crate) mod wire;

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tracing::{debug, trace};

use crate::packet::Parsed;
use buf::{ChunkBuf, Pool};
use tcb::{Blocked, State, Tcb};
use wire::{ACK, RST, SYN};

/// Limits for the userspace stack.
#[derive(Clone, Debug)]
pub struct TcpConfig {
    /// Receive buffer: the most the app can send ahead of the engine
    /// reading, and so the largest window advertised.
    pub rx_buffer: usize,
    /// Send buffer: the most the engine can write ahead of the app's ACKs.
    pub tx_buffer: usize,
    /// Connections the stack will hold, including ones still closing;
    /// further SYNs are reset. 0 is unlimited.
    pub max_connections: usize,
    /// Spare buffer memory kept for reuse across connections.
    pub pool_keep: usize,
    /// Connect before accepting: hand each connection to the engine on the
    /// app's SYN and answer only once the engine has a verdict, a SYN-ACK
    /// when the outbound connected (`Stream::accept`) or a reset when it
    /// failed or a rule rejected it. The app's connect() then takes as long
    /// as the outbound's and fails the way a refused connect does, so it
    /// can fall back at once instead of seeing an established connection
    /// die. A config that sniffs before routing still completes the
    /// handshake first, since sniffing needs the app's first bytes.
    pub defer_handshake: bool,
    /// Cap on what all connections' buffers hold together (0: none). At the
    /// cap, receive windows stop opening and writes wait, except that each
    /// connection may always buffer one 16 KiB chunk each way.
    pub memory_limit: usize,
}

const MOBILE: bool = cfg!(any(
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
));

impl Default for TcpConfig {
    /// iOS: 128 KiB each way covers a phone's bandwidth at the sub-
    /// millisecond RTT of the local path, and all buffers together stop at
    /// 8 MiB, inside the Network Extension's ~50 MB. Elsewhere 1 MiB each
    /// way, enough for multi-Gbit/s, and no overall cap.
    fn default() -> Self {
        if MOBILE {
            Self {
                rx_buffer: 128 << 10,
                tx_buffer: 128 << 10,
                max_connections: 0,
                pool_keep: 1 << 20,
                memory_limit: 8 << 20,
                defer_handshake: true,
            }
        } else {
            Self {
                rx_buffer: 1 << 20,
                tx_buffer: 1 << 20,
                max_connections: 0,
                pool_keep: 8 << 20,
                memory_limit: 0,
                defer_handshake: true,
            }
        }
    }
}

/// What a connection shares with its `Stream`.
pub(crate) struct Shared {
    key: (u32, u32),
    rx_cap: usize,
    tx_cap: usize,
    pub(crate) m: Mutex<Inner>,
}

pub(crate) struct Inner {
    pub rx: ChunkBuf,
    pub rx_fin: bool,
    pub tx: ChunkBuf,
    /// The engine shut down its write half (or dropped the stream).
    pub tx_fin: bool,
    pub err: Option<io::ErrorKind>,
    /// The connection is gone without error (closed both ways).
    pub gone: bool,
    rd: Option<Waker>,
    wr: Option<Waker>,
    /// Receive window in the last segment sent.
    pub adv_free: usize,
    /// Window growth worth announcing on its own.
    pub upd_thresh: usize,
    pub want_ack: bool,
    pub dropped: bool,
    /// Requested by the engine: `Some(true)` resets, `Some(false)` forgets
    /// the connection silently.
    pub abort: Option<bool>,
    /// Already on the packet loop's list.
    pub queued: bool,
    /// The engine has the stream.
    pub handed: bool,
    /// The engine asked for the handshake to complete.
    pub accept: bool,
}

impl Inner {
    fn new(pool: &Arc<Pool>) -> Self {
        Self {
            rx: ChunkBuf::new(pool.clone()),
            rx_fin: false,
            tx: ChunkBuf::new(pool.clone()),
            tx_fin: false,
            err: None,
            gone: false,
            rd: None,
            wr: None,
            adv_free: 0,
            upd_thresh: 0,
            want_ack: false,
            dropped: false,
            abort: None,
            queued: false,
            handed: false,
            accept: false,
        }
    }
}

/// State shared by the packet loop and every stream.
pub(crate) struct Env {
    pending: Mutex<Vec<(u32, u32)>>,
    pub notify: Notify,
    pool: Arc<Pool>,
}

impl Env {
    fn queue(&self, g: &mut Inner, key: (u32, u32)) {
        if !g.queued {
            g.queued = true;
            self.pending.lock().unwrap().push(key);
            self.notify.notify_one();
        }
    }
}

/// A connection from an app, terminated by sbr's userspace stack.
pub struct Stream {
    shared: Arc<Shared>,
    env: Arc<Env>,
}

impl Stream {
    /// Complete the handshake (with `defer_handshake`; otherwise it is
    /// already complete). Idempotent.
    pub fn accept(&self) {
        let mut g = self.shared.m.lock().unwrap();
        if !g.accept && g.err.is_none() {
            g.accept = true;
            self.env.queue(&mut g, self.shared.key);
        }
    }

    /// Reset the connection (the outbound refused it).
    pub fn abort(&self) {
        self.request_abort(true);
    }

    /// Forget the connection without telling the app (`reject` with drop).
    pub fn discard(&self) {
        self.request_abort(false);
    }

    fn request_abort(&self, rst: bool) {
        let mut g = self.shared.m.lock().unwrap();
        if g.err.is_none() && !g.gone {
            g.abort = Some(rst);
            g.err = Some(io::ErrorKind::ConnectionAborted);
            self.env.queue(&mut g, self.shared.key);
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut g = self.shared.m.lock().unwrap();
        if !g.rx.is_empty() {
            let want = buf.remaining().min(g.rx.len());
            let dst = buf.initialize_unfilled_to(want);
            let n = g.rx.read(dst);
            buf.advance(n);
            let free = self.shared.rx_cap.saturating_sub(g.rx.len());
            if !g.want_ack
                && g.adv_free < self.shared.rx_cap / 2
                && free >= g.adv_free + g.upd_thresh.max(1)
                && !g.rx_fin
            {
                g.want_ack = true;
                self.env.queue(&mut g, self.shared.key);
            }
            return Poll::Ready(Ok(()));
        }
        if g.rx_fin || g.gone {
            return Poll::Ready(Ok(()));
        }
        if let Some(e) = g.err {
            return Poll::Ready(Err(e.into()));
        }
        if !g.rd.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            g.rd = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut g = self.shared.m.lock().unwrap();
        if let Some(e) = g.err {
            return Poll::Ready(Err(e.into()));
        }
        if g.tx_fin || g.gone {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let own = self.shared.tx_cap.saturating_sub(g.tx.len());
        // The stack-wide cap, but never below one chunk per connection.
        let floor = buf::CHUNK.saturating_sub(g.tx.len());
        let shared = self.env.pool.headroom().max(g.tx.slack()).max(floor);
        let free = own.min(shared);
        if free == 0 {
            if !g.wr.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                g.wr = Some(cx.waker().clone());
            }
            if own > 0 {
                self.env.pool.wait(cx.waker());
            }
            return Poll::Pending;
        }
        let n = free.min(data.len());
        g.tx.push(&data[..n]);
        self.env.queue(&mut g, self.shared.key);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let g = self.shared.m.lock().unwrap();
        match g.err {
            Some(e) => Poll::Ready(Err(e.into())),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut g = self.shared.m.lock().unwrap();
        if g.err.is_none() && !g.gone && !g.tx_fin {
            g.tx_fin = true;
            self.env.queue(&mut g, self.shared.key);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let mut g = self.shared.m.lock().unwrap();
        g.dropped = true;
        if g.err.is_none() && !g.gone {
            self.env.queue(&mut g, self.shared.key);
        }
    }
}

/// What a connection's output needs from the packet loop.
pub(crate) struct Ctx<'a> {
    pub now: Instant,
    /// RFC 7323 TSval: milliseconds since the stack started.
    pub ts: u32,
    pub mtu: usize,
    pub pool: &'a Pool,
    /// Scratch for one packet, at `[HEADROOM..]`.
    pub buf: &'a mut Vec<u8>,
    pub link: &'a mut dyn FnMut(&mut [u8]) -> Result<(), Blocked>,
    pub stats: &'a mut Stats,
}

/// Counters since the stack started, for tests and debug logs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub accepted: u64,
    pub segments_out: u64,
    /// Segments resent during SACK/NewReno fast recovery.
    pub fast_retransmits: u64,
    /// Retransmission timeouts (each resends from the first unacked byte).
    pub timeouts: u64,
    pub resets_out: u64,
}

/// A packet sink for the stack: `buf` holds the packet at `[HEADROOM..]`.
/// `Err(Blocked)` means the interface queue is full and nothing was sent.
pub(crate) type Link<'a> = dyn FnMut(&mut [u8]) -> Result<(), Blocked> + 'a;

struct Slot {
    serial: u32,
    tcb: Option<Box<Tcb>>,
}

/// Every connection on one TUN.
pub(crate) struct Tcp {
    cfg: TcpConfig,
    mtu: usize,
    env: Arc<Env>,
    on_accept: Box<dyn FnMut(SocketAddr, SocketAddr, Stream) + Send>,
    table: FxHashMap<(SocketAddr, SocketAddr), u32>,
    slots: Vec<Slot>,
    free: Vec<u32>,
    live: usize,
    timers: BinaryHeap<Reverse<(Instant, u32, u32)>>,
    dirty: Vec<u32>,
    buf: Vec<u8>,
    epoch: Instant,
    isn: u64,
    /// The interface refused a write: retry output for `dirty` then.
    blocked_until: Option<Instant>,
    pub stats: Stats,
}

/// How long to back off when the interface queue is full.
const BLOCKED_RETRY: Duration = Duration::from_millis(1);

impl Tcp {
    pub fn new(
        cfg: TcpConfig,
        mtu: usize,
        on_accept: impl FnMut(SocketAddr, SocketAddr, Stream) + Send + 'static,
        now: Instant,
    ) -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Self {
            env: Arc::new(Env {
                pending: Mutex::new(Vec::new()),
                notify: Notify::new(),
                pool: Pool::new(cfg.pool_keep, cfg.memory_limit),
            }),
            cfg,
            mtu,
            on_accept: Box::new(on_accept),
            table: FxHashMap::default(),
            slots: Vec::new(),
            free: Vec::new(),
            live: 0,
            timers: BinaryHeap::new(),
            dirty: Vec::new(),
            buf: Vec::with_capacity(crate::device::HEADROOM + mtu),
            epoch: now,
            isn: seed | 1,
            blocked_until: None,
            stats: Stats::default(),
        }
    }

    pub fn env(&self) -> &Arc<Env> {
        &self.env
    }

    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.live
    }

    fn ctx<'a>(&'a mut self, now: Instant, link: &'a mut Link<'_>) -> (Ctx<'a>, &'a mut Vec<Slot>) {
        let ts = now.duration_since(self.epoch).as_millis() as u32;
        (
            Ctx {
                now,
                ts,
                mtu: self.mtu,
                pool: &self.env.pool,
                buf: &mut self.buf,
                link,
                stats: &mut self.stats,
            },
            &mut self.slots,
        )
    }

    /// RFC 6528: a clock plus a keyed hash of the 4-tuple.
    fn iss(&mut self, local: SocketAddr, remote: SocketAddr, now: Instant) -> u32 {
        use std::hash::{BuildHasher, Hash, Hasher};
        let mut h = rustc_hash::FxBuildHasher.build_hasher();
        self.isn.hash(&mut h);
        (local, remote).hash(&mut h);
        let clock = (now.duration_since(self.epoch).as_micros() / 4) as u32;
        (h.finish() as u32).wrapping_add(clock)
    }

    /// One TCP packet from the TUN.
    pub fn input(&mut self, pkt: &[u8], h: &Parsed, now: Instant, link: &mut Link<'_>) {
        let Some(seg) = wire::parse(pkt, h) else { return };
        let (remote, local) = (h.src, h.dst);
        let slot = match self.table.get(&(remote, local)) {
            Some(&i) => {
                let t = self.slots[i as usize].tcb.as_ref().unwrap();
                let fresh_syn = seg.has(SYN) && !seg.has(ACK) && !seg.has(RST);
                let replace = fresh_syn
                    && (matches!(t.state, State::TimeWait | State::Closed)
                        || (t.state == State::SynReceived && seg.seq != t.irs()));
                if replace {
                    self.remove(i);
                    None
                } else {
                    Some(i)
                }
            }
            None => None,
        };
        let i = match slot {
            Some(i) => i,
            None => {
                if !(seg.has(SYN) && !seg.has(ACK)) || seg.has(RST) {
                    trace!(%remote, %local, flags = seg.flags, "tcp: no connection, reset");
                    let (mut cx, _) = self.ctx(now, link);
                    let _ = tcb::send_rst_for(local, remote, &seg, &mut cx);
                    return;
                }
                if self.cfg.max_connections != 0 && self.live >= self.cfg.max_connections {
                    debug!(%remote, %local, "tcp: connection limit reached, reset");
                    let (mut cx, _) = self.ctx(now, link);
                    let _ = tcb::send_rst_for(local, remote, &seg, &mut cx);
                    return;
                }
                self.open(local, remote, &seg, now)
            }
        };
        let (mut cx, slots) = self.ctx(now, link);
        let t = slots[i as usize].tcb.as_mut().unwrap();
        let blocked = t.input(&seg, pkt, &mut cx).is_err();
        self.after(i, blocked, now);
    }

    fn open(&mut self, local: SocketAddr, remote: SocketAddr, seg: &wire::Seg, now: Instant) -> u32 {
        let i = match self.free.pop() {
            Some(i) => i,
            None => {
                self.slots.push(Slot { serial: 0, tcb: None });
                (self.slots.len() - 1) as u32
            }
        };
        let serial = self.slots[i as usize].serial;
        let shared = Arc::new(Shared {
            key: (i, serial),
            rx_cap: self.cfg.rx_buffer,
            tx_cap: self.cfg.tx_buffer,
            m: Mutex::new(Inner::new(&self.env.pool)),
        });
        let iss = self.iss(local, remote, now);
        let t = Tcb::from_syn(
            local,
            remote,
            seg,
            iss,
            self.mtu,
            self.cfg.rx_buffer,
            self.cfg.tx_buffer,
            shared,
            self.cfg.defer_handshake.then_some(now),
        );
        self.slots[i as usize].tcb = Some(Box::new(t));
        self.table.insert((remote, local), i);
        self.live += 1;
        i
    }

    fn after(&mut self, i: u32, blocked: bool, now: Instant) {
        if blocked && self.blocked_until.is_none() {
            self.blocked_until = Some(now + BLOCKED_RETRY);
        }
        self.dirty.push(i);
    }

    /// Streams that wrote, read, closed or dropped since the last call.
    pub fn drain_app(&mut self, now: Instant) {
        let pending = std::mem::take(&mut *self.env.pending.lock().unwrap());
        for (i, serial) in pending {
            let Some(s) = self.slots.get_mut(i as usize) else {
                continue;
            };
            if s.serial != serial {
                continue;
            }
            if let Some(t) = s.tcb.as_mut() {
                t.on_app(now);
                self.dirty.push(i);
            }
        }
    }

    pub fn run_timers(&mut self, now: Instant, link: &mut Link<'_>) {
        while let Some(&Reverse((at, i, serial))) = self.timers.peek()
            && at <= now
        {
            self.timers.pop();
            let s = &mut self.slots[i as usize];
            if s.serial != serial {
                continue;
            }
            let Some(t) = s.tcb.as_mut() else { continue };
            if t.scheduled != Some(at) {
                continue;
            }
            t.scheduled = None;
            let (mut cx, slots) = self.ctx(now, link);
            slots[i as usize].tcb.as_mut().unwrap().on_timer(&mut cx);
            self.dirty.push(i);
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        let t = self.timers.peek().map(|r| r.0.0);
        match (t, self.blocked_until) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Send what every touched connection owes, wake its stream, and
    /// reschedule or reap it.
    pub fn flush(&mut self, now: Instant, link: &mut Link<'_>) {
        if let Some(b) = self.blocked_until {
            if b > now {
                return;
            }
            self.blocked_until = None;
        }
        let mut dirty = std::mem::take(&mut self.dirty);
        dirty.sort_unstable();
        dirty.dedup();
        let mut k = 0;
        while k < dirty.len() {
            let i = dirty[k];
            k += 1;
            let (mut cx, slots) = self.ctx(now, link);
            let Some(t) = slots[i as usize].tcb.as_mut() else {
                continue;
            };
            if t.output(&mut cx).is_err() {
                // Keep this and the rest for the retry.
                self.blocked_until = Some(now + BLOCKED_RETRY);
                self.dirty.extend_from_slice(&dirty[k - 1..]);
                self.settle(i);
                for &j in &dirty[k..] {
                    self.settle(j);
                }
                return;
            }
            self.settle(i);
        }
        self.dirty = dirty;
        self.dirty.clear();
    }

    /// Wake the stream, hand over a new connection, schedule timers, reap.
    fn settle(&mut self, i: u32) {
        let s = &mut self.slots[i as usize];
        let Some(t) = s.tcb.as_mut() else { return };
        let (mut rd, mut wr) = (None, None);
        if t.wake_rd || t.wake_wr || t.state == State::Closed {
            let mut g = t.shared.m.lock().unwrap();
            if t.state == State::Closed {
                if let Some(e) = t.error {
                    g.err.get_or_insert(e);
                    g.rx.clear();
                } else {
                    g.gone = true;
                }
                g.tx.clear();
                t.wake_rd = true;
                t.wake_wr = true;
            }
            if std::mem::take(&mut t.wake_rd) {
                rd = g.rd.take();
            }
            if std::mem::take(&mut t.wake_wr) {
                wr = g.wr.take();
            }
        }
        if let Some(w) = rd {
            w.wake();
        }
        if let Some(w) = wr {
            w.wake();
        }
        if std::mem::take(&mut t.accept_now) && t.state != State::Closed {
            t.shared.m.lock().unwrap().handed = true;
            let stream = Stream {
                shared: t.shared.clone(),
                env: self.env.clone(),
            };
            let (src, dst) = (t.remote, t.local);
            self.stats.accepted += 1;
            (self.on_accept)(src, dst, stream);
        }
        let t = self.slots[i as usize].tcb.as_mut().unwrap();
        if t.state == State::Closed {
            self.remove(i);
            return;
        }
        if let Some(d) = t.deadline()
            && t.scheduled.is_none_or(|s| d < s)
        {
            t.scheduled = Some(d);
            self.timers.push(Reverse((d, i, self.slots[i as usize].serial)));
        }
    }

    fn remove(&mut self, i: u32) {
        let s = &mut self.slots[i as usize];
        let Some(t) = s.tcb.take() else { return };
        s.serial = s.serial.wrapping_add(1);
        self.table.remove(&(t.remote, t.local));
        self.free.push(i);
        self.live -= 1;
        let mut g = t.shared.m.lock().unwrap();
        if !g.gone && g.err.is_none() {
            g.err = Some(t.error.unwrap_or(io::ErrorKind::ConnectionReset));
        }
        // After a clean close the engine may still be reading.
        if g.err.is_some() {
            g.rx.clear();
        }
        g.tx.clear();
        let (rd, wr) = (g.rd.take(), g.wr.take());
        drop(g);
        if let Some(w) = rd {
            w.wake();
        }
        if let Some(w) = wr {
            w.wake();
        }
    }
}

impl Drop for Tcp {
    fn drop(&mut self) {
        for i in 0..self.slots.len() as u32 {
            if let Some(t) = self.slots[i as usize].tcb.as_mut() {
                t.error.get_or_insert(io::ErrorKind::BrokenPipe);
                self.remove(i);
            }
        }
    }
}
