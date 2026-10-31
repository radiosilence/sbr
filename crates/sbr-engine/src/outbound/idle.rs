//! Closing a shared connection once nothing has used it for a while, with
//! at most one timer per connection, armed only while it is idle.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::time::Instant;

pub struct Idle {
    users: AtomicUsize,
    since: Mutex<Instant>,
    armed: AtomicBool,
}

impl Default for Idle {
    fn default() -> Self {
        Self {
            users: AtomicUsize::new(0),
            since: Mutex::new(Instant::now()),
            armed: AtomicBool::new(false),
        }
    }
}

impl Idle {
    pub fn users(&self) -> usize {
        self.users.load(Ordering::Acquire)
    }

    pub fn acquire(&self) {
        self.users.fetch_add(1, Ordering::AcqRel);
    }

    /// True when this was the last user.
    pub fn release(&self) -> bool {
        let last = self.users.fetch_sub(1, Ordering::AcqRel) == 1;
        if last {
            *self.since.lock().unwrap() = Instant::now();
        }
        last
    }

    /// After the last user left: run `expire` once the connection has been
    /// idle for `timeout`, unless a user came back. The task holds only
    /// weak references, and a timer already running is reused.
    pub fn arm(self: &Arc<Self>, timeout: Duration, expire: impl FnOnce() + Send + 'static) {
        if self.armed.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            self.armed.store(false, Ordering::Release);
            return;
        };
        let me: Weak<Self> = Arc::downgrade(self);
        rt.spawn(async move {
            loop {
                let Some(since) = me.upgrade().map(|i| *i.since.lock().unwrap()) else {
                    return;
                };
                tokio::time::sleep_until(since + timeout).await;
                let Some(i) = me.upgrade() else { return };
                if i.users() > 0 {
                    i.armed.store(false, Ordering::Release);
                    // It went idle again after the check: keep this timer.
                    if i.users() > 0 || i.armed.swap(true, Ordering::AcqRel) {
                        return;
                    }
                    continue;
                }
                if *i.since.lock().unwrap() > since {
                    continue;
                }
                i.armed.store(false, Ordering::Release);
                expire();
                return;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[tokio::test(start_paused = true)]
    async fn one_timer_expires_once_after_the_last_use() {
        let idle = Arc::new(Idle::default());
        let fired = Arc::new(AtomicU32::new(0));
        for _ in 0..10 {
            idle.acquire();
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(idle.release());
            let f = fired.clone();
            idle.arm(Duration::from_secs(30), move || {
                f.fetch_add(1, Ordering::SeqCst);
            });
        }
        tokio::time::sleep(Duration::from_secs(29)).await;
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_returning_user_cancels_it() {
        let idle = Arc::new(Idle::default());
        let fired = Arc::new(AtomicU32::new(0));
        idle.acquire();
        idle.release();
        let f = fired.clone();
        idle.arm(Duration::from_secs(30), move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_secs(10)).await;
        idle.acquire();
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }
}
