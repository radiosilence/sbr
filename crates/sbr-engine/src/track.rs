//! Live connection registry for the Clash API and `interrupt_exist_connections`.
//!
//! Cost model: one small allocation and one sharded-map insert/remove per
//! connection; on the data path, a plain load+store of a per-connection
//! counter per chunk (each counter has exactly one writer, so no atomic RMW
//! and no shared cache line between connections). Totals are computed when
//! someone asks, by summing live connections plus those already closed.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::SystemTime;

use sbr_core::Metadata;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

const SHARDS: usize = 16;

/// One tracked connection (TCP stream or UDP session).
pub struct Conn {
    pub id: u64,
    pub meta: Metadata,
    /// Outbound tags from the leaf that carries the traffic to the outbound
    /// the rule picked (sing-box `chains` order).
    pub chain: Vec<Arc<str>>,
    /// Index of the route rule that decided, `None` for `route.final`.
    pub rule: Option<usize>,
    pub start: SystemTime,
    pub up: AtomicU64,
    pub down: AtomicU64,
    cancel: Mutex<Option<oneshot::Sender<()>>>,
}

impl Conn {
    /// Abort the connection's relay. Idempotent.
    pub fn close(&self) {
        if let Some(tx) = self.cancel.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }

    pub fn uuid(&self, t: &Tracker) -> String {
        t.uuid(self.id)
    }

    /// Single writer per counter: the relay task. A plain load+store avoids a
    /// locked RMW on every chunk.
    #[inline]
    fn add(counter: &AtomicU64, n: usize) {
        counter.store(counter.load(Ordering::Relaxed) + n as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_up(&self, n: usize) {
        Self::add(&self.up, n)
    }

    #[inline]
    pub fn add_down(&self, n: usize) {
        Self::add(&self.down, n)
    }
}

pub struct Tracker {
    shards: [Mutex<HashMap<u64, Arc<Conn>>>; SHARDS],
    next: AtomicU64,
    /// Random per process, so ids from different runs never collide in a dashboard.
    salt: u64,
    closed_up: AtomicU64,
    closed_down: AtomicU64,
}

impl Default for Tracker {
    fn default() -> Self {
        use std::hash::{BuildHasher, RandomState};
        Self {
            shards: Default::default(),
            next: AtomicU64::new(1),
            salt: RandomState::new().hash_one(std::process::id()),
            closed_up: AtomicU64::new(0),
            closed_down: AtomicU64::new(0),
        }
    }
}

/// Removes the connection from the registry when the relay ends, however it ends.
pub struct Registration<'a> {
    tracker: &'a Tracker,
    pub conn: Arc<Conn>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let t = self.tracker;
        t.shards[self.conn.id as usize % SHARDS]
            .lock()
            .unwrap()
            .remove(&self.conn.id);
        t.closed_up
            .fetch_add(self.conn.up.load(Ordering::Relaxed), Ordering::Relaxed);
        t.closed_down
            .fetch_add(self.conn.down.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

impl Tracker {
    /// Register a connection. The receiver resolves when someone closes it.
    pub fn register(&self, meta: Metadata, chain: Vec<Arc<str>>, rule: Option<usize>) -> (Registration<'_>, Cancelled) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        let conn = Arc::new(Conn {
            id,
            meta,
            chain,
            rule,
            start: SystemTime::now(),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            cancel: Mutex::new(Some(tx)),
        });
        self.shards[id as usize % SHARDS]
            .lock()
            .unwrap()
            .insert(id, conn.clone());
        (Registration { tracker: self, conn }, Cancelled(rx))
    }

    pub fn connections(&self) -> Vec<Arc<Conn>> {
        let mut v: Vec<Arc<Conn>> = self
            .shards
            .iter()
            .flat_map(|s| s.lock().unwrap().values().cloned().collect::<Vec<_>>())
            .collect();
        v.sort_by_key(|c| c.id);
        v
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// (upload, download) since start, including live connections.
    pub fn totals(&self) -> (u64, u64) {
        let (mut up, mut down) = (
            self.closed_up.load(Ordering::Relaxed),
            self.closed_down.load(Ordering::Relaxed),
        );
        for s in &self.shards {
            for c in s.lock().unwrap().values() {
                up += c.up.load(Ordering::Relaxed);
                down += c.down.load(Ordering::Relaxed);
            }
        }
        (up, down)
    }

    pub fn close_all(&self) {
        self.connections().iter().for_each(|c| c.close());
    }

    /// Close connections whose outbound chain passes through `tag`.
    pub fn close_through(&self, tag: &str) -> usize {
        let hit: Vec<_> = self
            .connections()
            .into_iter()
            .filter(|c| c.chain.iter().any(|t| &**t == tag))
            .collect();
        hit.iter().for_each(|c| c.close());
        hit.len()
    }

    /// Clash dashboards key connections by UUID. Ours embed the counter in
    /// the last 48 bits so they can be looked up without a second map.
    pub fn uuid(&self, id: u64) -> String {
        let s = self.salt;
        format!(
            "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
            (s >> 32) as u32,
            (s >> 16) as u16,
            (s >> 4) as u16 & 0xfff,
            s as u16 & 0xfff,
            id & 0xffff_ffff_ffff
        )
    }

    pub fn find(&self, uuid: &str) -> Option<Arc<Conn>> {
        let id = u64::from_str_radix(uuid.rsplit('-').next()?, 16).ok()?;
        let c = self.shards[id as usize % SHARDS].lock().unwrap().get(&id).cloned()?;
        (self.uuid(id) == uuid).then_some(c)
    }
}

/// Resolves when the connection is closed through the registry. Dropping
/// the registration (normal end) never resolves it.
pub struct Cancelled(oneshot::Receiver<()>);

impl Cancelled {
    pub async fn wait(self) {
        if self.0.await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Counts bytes through the client side: reads are upload, writes download.
pub struct Counted<'a, S> {
    pub inner: S,
    pub conn: &'a Conn,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<'_, S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.conn.add_up(n);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<'_, S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.conn.add_down(n);
        }
        r
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
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = r {
            self.conn.add_down(n);
        }
        r
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Metadata {
        Metadata::new(
            "in".into(),
            "mixed",
            sbr_core::Network::Tcp,
            "127.0.0.1:1".parse().unwrap(),
            sbr_core::Destination::from_host_port("a.com", 443),
        )
    }

    #[tokio::test]
    async fn register_close_totals() {
        let t = Tracker::default();
        let (reg, cancelled) = t.register(meta(), vec!["leaf".into(), "group".into()], Some(2));
        reg.conn.add_up(10);
        reg.conn.add_down(5);
        assert_eq!(t.totals(), (10, 5));
        let uuid = reg.conn.uuid(&t);
        assert!(Arc::ptr_eq(&t.find(&uuid).unwrap(), &reg.conn));
        assert!(t.find("00000000-0000-4000-8000-000000000001").is_none() || t.salt == 0);
        assert_eq!(t.close_through("group"), 1);
        cancelled.wait().await; // resolves
        drop(reg);
        assert!(t.is_empty());
        assert_eq!(t.totals(), (10, 5), "closed connections stay in the totals");

        let (reg, cancelled) = t.register(meta(), vec![], None);
        drop(reg);
        let r = tokio::time::timeout(std::time::Duration::from_millis(20), cancelled.wait()).await;
        assert!(r.is_err(), "a normal end is not a cancellation");
    }
}
