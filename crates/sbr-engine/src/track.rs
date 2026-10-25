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
    /// Relay timing for passive health checks (TCP only).
    pub activity: crate::health::Activity,
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
            activity: Default::default(),
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

    /// Close connections to `domain` (ASCII case-insensitive, trailing dot
    /// ignored), and to its subdomains when `subdomains` is set: a new route
    /// for a domain then applies to its open connections too. Matches the
    /// requested or sniffed domain, as the router does.
    pub fn close_domain(&self, domain: &str, subdomains: bool) -> usize {
        let want = domain.trim_end_matches('.');
        if want.is_empty() {
            return 0;
        }
        let hit: Vec<_> = self
            .connections()
            .into_iter()
            .filter(|c| {
                c.meta
                    .domain()
                    .is_some_and(|d| domain_matches(d.trim_end_matches('.'), want, subdomains))
            })
            .collect();
        hit.iter().for_each(|c| c.close());
        hit.len()
    }

    /// Close connections carried by `leaf` that are stalled or have received
    /// nothing: on a degraded path they are dead, and closing them makes the
    /// app retry now (on the next member) instead of after its own timeout.
    pub fn close_broken(&self, leaf: &str) -> usize {
        let hit: Vec<_> = self
            .connections()
            .into_iter()
            .filter(|c| {
                c.chain.first().is_some_and(|t| &**t == leaf)
                    && (c.activity.stalled() || c.down.load(Ordering::Relaxed) == 0)
            })
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

fn domain_matches(d: &str, want: &str, subdomains: bool) -> bool {
    if d.eq_ignore_ascii_case(want) {
        return true;
    }
    subdomains
        && d.len() > want.len()
        && d.as_bytes()[d.len() - want.len() - 1] == b'.'
        && d[d.len() - want.len()..].eq_ignore_ascii_case(want)
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
            self.conn.activity.on_up();
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<'_, S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r
            && n > 0
        {
            self.conn.add_down(n);
            self.conn.activity.on_down();
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
        if let Poll::Ready(Ok(n)) = r
            && n > 0
        {
            self.conn.add_down(n);
            self.conn.activity.on_down();
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
        meta_for("a.com")
    }

    fn meta_for(host: &str) -> Metadata {
        Metadata::new(
            "in".into(),
            "mixed",
            sbr_core::Network::Tcp,
            "127.0.0.1:1".parse().unwrap(),
            sbr_core::Destination::from_host_port(host, 443),
        )
    }

    #[test]
    fn close_domain_matches_exact_or_subdomains() {
        let t = Tracker::default();
        let regs: Vec<_> = [
            "bbc.co.uk",
            "www.BBC.co.uk",
            "notbbc.co.uk",
            "bbc.co.uk.evil.test",
            "1.2.3.4",
        ]
        .into_iter()
        .map(|h| t.register(meta_for(h), vec![], None))
        .collect();
        let mut sniffed = meta_for("10.0.0.1");
        sniffed.sniffed_domain = Some("cdn.bbc.co.uk".into());
        let _sniffed = t.register(sniffed, vec![], None);

        assert_eq!(t.close_domain("", true), 0);
        assert_eq!(
            t.close_domain("BBC.co.uk.", false),
            1,
            "exact, case and trailing dot ignored"
        );
        assert_eq!(
            t.close_domain("bbc.co.uk", true),
            3,
            "itself, a subdomain and a sniffed subdomain"
        );
        drop(regs);
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
