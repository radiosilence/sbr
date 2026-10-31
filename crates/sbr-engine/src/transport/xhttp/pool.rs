//! XMUX (`splithttp/mux.go`): which HTTP connection carries the next
//! request. Each [`Slot`] is one HTTP client (one HTTP/2 connection, or for
//! HTTP/1.1 one pool of upload connections); slots retire after a number of
//! uses, requests or seconds, and are dropped once nothing runs on them.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use sbr_config::{Range, Xmux};

/// Xray `crypto.RandBetween`: uniform in `[from, to)`, or `from` when the
/// range is a single value.
pub fn rand_between(r: Range) -> i32 {
    let (from, to) = (r.from.min(r.to), r.from.max(r.to));
    if to - from <= 1 {
        return from;
    }
    fastrand::i32(from..to)
}

/// Go's `http.Transport.IdleConnTimeout` for XHTTP (`net.ConnIdleTimeout`).
/// Checked when a slot is picked, and by one timer per idle slot, which
/// drops it from the pool so its connection (and any keep-alive pings)
/// ends even if nothing connects through the outbound again.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

type Slots<C> = Mutex<Vec<Arc<Slot<C>>>>;

/// A slot's connection handle, which may die on its own.
pub trait PoolConn {
    fn is_closed(&self) -> bool;
}

pub struct Slot<C> {
    pub conn: C,
    running: AtomicI32,
    /// Picks left (`cMaxReuseTimes`); negative is unlimited. Guarded by the pool lock.
    left_usage: Mutex<i32>,
    pub left_requests: AtomicI32,
    unreusable_at: Option<Instant>,
    closed: AtomicBool,
    idle_since: Mutex<Option<Instant>>,
    pool: Weak<Slots<C>>,
    /// A task is waiting to retire this slot once it has idled long enough.
    reaping: AtomicBool,
}

impl<C: PoolConn> Slot<C> {
    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed) || self.conn.is_closed()
    }
    /// One request on this slot; `false` once `hMaxRequestTimes` is spent
    /// or `hMaxReusableSecs` has passed (packet-up then moves on).
    pub fn take_request(&self) -> bool {
        let left = self.left_requests.fetch_sub(1, Ordering::Relaxed) - 1;
        left > 0 && self.unreusable_at.is_none_or(|t| Instant::now() <= t)
    }
    fn unusable(&self, now: Instant) -> bool {
        self.is_closed()
            || *self.left_usage.lock().unwrap() == 0
            || self.left_requests.load(Ordering::Relaxed) <= 0
            || self.unreusable_at.is_some_and(|t| now > t)
            || self.idle_since.lock().unwrap().is_some_and(|t| now - t > IDLE_TIMEOUT)
    }
}

/// A connection that counts towards `maxConcurrency` while it lives.
pub struct Running<C: PoolConn + Send + Sync + 'static>(pub Arc<Slot<C>>);

impl<C: PoolConn + Send + Sync + 'static> Running<C> {
    pub fn new(slot: Arc<Slot<C>>) -> Self {
        slot.running.fetch_add(1, Ordering::Relaxed);
        *slot.idle_since.lock().unwrap() = None;
        Self(slot)
    }
}

impl<C: PoolConn + Send + Sync + 'static> Drop for Running<C> {
    fn drop(&mut self) {
        if self.0.running.fetch_sub(1, Ordering::Relaxed) == 1 {
            *self.0.idle_since.lock().unwrap() = Some(Instant::now());
            reap_when_idle(&self.0);
        }
    }
}

/// Retire `slot` once it has been idle for [`IDLE_TIMEOUT`]: one task per
/// idle slot, which ends as soon as the slot is used again.
fn reap_when_idle<C: PoolConn + Send + Sync + 'static>(slot: &Arc<Slot<C>>) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if slot.reaping.swap(true, Ordering::AcqRel) {
        return;
    }
    let weak = Arc::downgrade(slot);
    rt.spawn(async move {
        loop {
            let Some(since) = weak.upgrade().and_then(|s| *s.idle_since.lock().unwrap()) else {
                // Gone, or in use again: a later idle spell arms a new timer.
                if let Some(s) = weak.upgrade() {
                    s.reaping.store(false, Ordering::Release);
                    // Went idle again between the check and the reset.
                    if s.idle_since.lock().unwrap().is_some() && !s.reaping.swap(true, Ordering::AcqRel) {
                        continue;
                    }
                }
                return;
            };
            tokio::time::sleep_until((since + IDLE_TIMEOUT).into()).await;
            let Some(s) = weak.upgrade() else { return };
            if s.idle_since
                .lock()
                .unwrap()
                .is_some_and(|t| t.elapsed() >= IDLE_TIMEOUT)
            {
                s.mark_closed();
                if let Some(slots) = s.pool.upgrade() {
                    slots.lock().unwrap().retain(|x| !Arc::ptr_eq(x, &s));
                }
                return;
            }
        }
    });
}

pub struct Pool<C> {
    cfg: Xmux,
    concurrency: i32,
    connections: i32,
    slots: Arc<Slots<C>>,
}

impl<C: PoolConn> Pool<C> {
    pub fn new(cfg: &Xmux) -> Self {
        Self {
            concurrency: rand_between(cfg.max_concurrency),
            connections: rand_between(cfg.max_connections),
            cfg: cfg.clone(),
            slots: Arc::default(),
        }
    }

    fn slot(&self, conn: C) -> Arc<Slot<C>> {
        let reuse = rand_between(self.cfg.c_max_reuse_times);
        let requests = rand_between(self.cfg.h_max_request_times);
        let secs = rand_between(self.cfg.h_max_reusable_secs);
        Arc::new(Slot {
            conn,
            running: AtomicI32::new(0),
            left_usage: Mutex::new(if reuse > 0 { reuse - 1 } else { -1 }),
            left_requests: AtomicI32::new(if requests > 0 { requests } else { i32::MAX }),
            unreusable_at: (secs > 0).then(|| Instant::now() + Duration::from_secs(secs as u64)),
            closed: AtomicBool::new(false),
            idle_since: Mutex::new(Some(Instant::now())),
            pool: Arc::downgrade(&self.slots),
            reaping: AtomicBool::new(false),
        })
    }

    /// `XmuxManager.GetXmuxClient`. `make` builds a new slot's connection
    /// handle; it must not block (dialing happens on first use).
    pub fn get(&self, make: impl FnOnce() -> C) -> Arc<Slot<C>> {
        let now = Instant::now();
        let mut slots = self.slots.lock().unwrap();
        // Retired slots leave the pool; in-flight requests keep them alive
        // until they finish.
        slots.retain(|s| !s.unusable(now));
        if slots.is_empty() || (self.connections > 0 && slots.len() < self.connections as usize) {
            let s = self.slot(make());
            slots.push(s.clone());
            return s;
        }
        let candidates: Vec<&Arc<Slot<C>>> = if self.concurrency > 0 {
            slots
                .iter()
                .filter(|s| s.running.load(Ordering::Relaxed) < self.concurrency)
                .collect()
        } else {
            slots.iter().collect()
        };
        if candidates.is_empty() {
            let s = self.slot(make());
            slots.push(s.clone());
            return s;
        }
        let s = candidates[fastrand::usize(..candidates.len())].clone();
        let mut left = s.left_usage.lock().unwrap();
        if *left > 0 {
            *left -= 1;
        }
        drop(left);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl PoolConn for u32 {
        fn is_closed(&self) -> bool {
            false
        }
    }

    #[test]
    fn max_connections_then_reuse() {
        let p: Pool<u32> = Pool::new(&Xmux {
            max_connections: Range::new(2, 2),
            ..Xmux::default()
        });
        let mut n = 0;
        let a = p.get(|| {
            n += 1;
            n
        });
        let b = p.get(|| {
            n += 1;
            n
        });
        assert_ne!(a.conn, b.conn);
        for _ in 0..10 {
            let c = p.get(|| unreachable!());
            assert!(c.conn == 1 || c.conn == 2);
        }
    }

    #[test]
    fn concurrency_and_reuse_limits() {
        let p: Pool<u32> = Pool::new(&Xmux {
            max_concurrency: Range::new(1, 1),
            c_max_reuse_times: Range::new(2, 2),
            ..Xmux::default()
        });
        let a = p.get(|| 1);
        let _ra = Running::new(a.clone());
        // Slot 1 is busy: a new one.
        let b = p.get(|| 2);
        assert_eq!(b.conn, 2);
        drop(_ra);
        // Slot 1 was used once of twice; one more pick retires it.
        let c = p.get(|| 3);
        assert!(c.conn == 1 || c.conn == 2);
        let d = p.get(|| 4);
        let e = p.get(|| 5);
        assert!([c.conn, d.conn, e.conn].iter().all(|&x| x <= 5));
    }

    #[test]
    fn request_budget() {
        let p: Pool<u32> = Pool::new(&Xmux {
            h_max_request_times: Range::new(2, 2),
            ..Xmux::default()
        });
        let a = p.get(|| 1);
        assert!(a.take_request());
        assert!(!a.take_request());
        assert_eq!(p.get(|| 2).conn, 2);
    }
}
