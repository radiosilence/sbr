//! UDP sockets under quinn.
//!
//! - The system path hands quinn a real socket through
//!   [`quinn::Runtime::wrap_udp_socket`], which keeps quinn-udp's GSO/GRO,
//!   ECN and pktinfo fast paths. On Darwin, which has no GSO, it is a
//!   connected socket instead (`Connected`).
//! - A `detour` gives us a [`PacketConn`]; [`PacketConnSocket`] adapts it.
//! - [`Salamander`] (hysteria2 obfs) and [`HopSocket`] (port hopping) wrap
//!   either of those.
//!
//! The wrappers that redirect traffic present one fixed peer address to
//! quinn, so a port hop or a detour never looks like a path migration.

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use blake2::Digest;
use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
#[cfg(not(target_vendor = "apple"))]
use quinn::{Runtime, TokioRuntime};
use sbr_core::dial::{self, DialOptions};
use sbr_core::{BoxPacketConn, Destination};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

/// quic-go's desired socket buffer size, also what sing-box asks for.
const SOCKET_BUFFER: usize = 8 << 20;

pub(crate) type Socket = Arc<dyn AsyncUdpSocket>;

/// A real UDP socket for `peer`'s address family with large buffers.
pub(crate) fn system(peer: SocketAddr, opts: &DialOptions) -> io::Result<Socket> {
    let sock = dial::bind_udp(peer.ip(), opts)?.into_std()?;
    let s2 = socket2::SockRef::from(&sock);
    // Best effort: the kernel caps these at its sysctl limits.
    let _ = s2.set_recv_buffer_size(SOCKET_BUFFER);
    let _ = s2.set_send_buffer_size(SOCKET_BUFFER);
    #[cfg(target_vendor = "apple")]
    {
        Connected::open(sock, peer)
    }
    #[cfg(not(target_vendor = "apple"))]
    TokioRuntime.wrap_udp_socket(sock)
}

/// A UDP socket connected to its one peer, for Darwin.
///
/// Darwin routes every unconnected `sendto` afresh, which costs more than
/// the rest of the send, and has no UDP GSO to amortise it. quinn-udp always
/// names a destination, which a connected socket refuses (`EISCONN`), so this
/// sends and receives with plain `send`/`recv` instead. ECN is not reported;
/// quinn then runs without it.
#[cfg(target_vendor = "apple")]
#[derive(Debug)]
struct Connected {
    sock: tokio::net::UdpSocket,
    peer: SocketAddr,
}

#[cfg(target_vendor = "apple")]
impl Connected {
    fn open(sock: std::net::UdpSocket, peer: SocketAddr) -> io::Result<Socket> {
        use std::os::fd::AsRawFd;
        let on: libc::c_int = 1;
        let (level, name) = match peer {
            SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_DONTFRAG),
            SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
        };
        // SAFETY: a valid socket and a c_int option value of the right size.
        let r = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                level,
                name,
                (&raw const on).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        sock.connect(peer)?;
        sock.set_nonblocking(true)?;
        Ok(Arc::new(Self {
            sock: tokio::net::UdpSocket::from_std(sock)?,
            peer,
        }))
    }
}

/// An ICMP error queued on a connected socket surfaces on its next call.
/// QUIC ignores ICMP, and quinn treats a receive error as fatal.
#[cfg(target_vendor = "apple")]
fn transient(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionRefused | ConnectionReset | HostUnreachable | NetworkUnreachable
    )
}

#[cfg(target_vendor = "apple")]
#[derive(Debug)]
struct SendReady(Arc<Connected>);

#[cfg(target_vendor = "apple")]
impl UdpPoller for SendReady {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.sock.poll_send_ready(cx)
    }
}

#[cfg(target_vendor = "apple")]
impl AsyncUdpSocket for Connected {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SendReady(self))
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        // max_transmit_segments is 1, so this is one datagram.
        match self.sock.try_send(t.contents) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            // As quinn-udp does: anything else loses the datagram, which QUIC
            // recovers.
            Err(_) => Ok(()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let r = if n == 0 {
                let mut rb = tokio::io::ReadBuf::new(&mut bufs[0]);
                match self.sock.poll_recv(cx, &mut rb) {
                    Poll::Ready(Ok(())) => Ok(rb.filled().len()),
                    Poll::Ready(Err(e)) => Err(e),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                self.sock.try_recv(&mut bufs[n])
            };
            match r {
                Ok(len) => {
                    meta[n] = RecvMeta {
                        addr: self.peer,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    n += 1;
                }
                Err(e) if transient(&e) => {}
                Err(e) if n > 0 && e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// The address quinn sees for a peer it cannot address directly (a
/// detour's peer may be a domain resolved on the far side).
pub(crate) const PLACEHOLDER_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1);

// ---------------------------------------------------------------------------

/// quinn over a detour's [`PacketConn`]. Everything goes to `peer`; replies
/// are reported as coming from [`PLACEHOLDER_PEER`].
///
/// quinn's socket API is synchronous (`try_send`) while `PacketConn` is
/// async, so a bounded queue and two pump tasks sit in between. This is the
/// detour path, not the fast path.
pub(crate) struct PacketConnSocket {
    out: mpsc::Sender<Bytes>,
    inbound: Mutex<mpsc::Receiver<Bytes>>,
    tasks: [JoinHandle<()>; 2],
}

const PUMP_QUEUE: usize = 256;

impl PacketConnSocket {
    pub(crate) fn new(conn: BoxPacketConn, peer: Destination) -> Arc<Self> {
        let conn: Arc<dyn sbr_core::PacketConn> = Arc::from(conn);
        let (out, mut out_rx) = mpsc::channel::<Bytes>(PUMP_QUEUE);
        let (in_tx, inbound) = mpsc::channel::<Bytes>(PUMP_QUEUE);
        let c = conn.clone();
        let send = tokio::spawn(async move {
            while let Some(p) = out_rx.recv().await {
                if let Err(e) = c.send_to(&p, &peer).await {
                    tracing::debug!(error = %e, "quic detour send");
                }
            }
        });
        let recv = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match conn.recv_from(&mut buf).await {
                    Ok((n, _)) => {
                        if in_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "quic detour recv");
                        return;
                    }
                }
            }
        });
        Arc::new(Self {
            out,
            inbound: Mutex::new(inbound),
            tasks: [send, recv],
        })
    }
}

impl Drop for PacketConnSocket {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl fmt::Debug for PacketConnSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PacketConnSocket")
    }
}

/// Ready when the outbound queue has room.
struct QueuePoller {
    out: mpsc::Sender<Bytes>,
    fut: Option<Pin<Box<dyn Future<Output = bool> + Send + Sync>>>,
}

impl fmt::Debug for QueuePoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QueuePoller")
    }
}

impl UdpPoller for QueuePoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let fut = this.fut.get_or_insert_with(|| {
            let out = this.out.clone();
            Box::pin(async move { out.reserve().await.is_ok() })
        });
        let ok = std::task::ready!(fut.as_mut().poll(cx));
        this.fut = None;
        if ok {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
    }
}

impl AsyncUdpSocket for PacketConnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(QueuePoller {
            out: self.out.clone(),
            fut: None,
        })
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        let seg = t.segment_size.unwrap_or(t.contents.len()).max(1);
        let n = t.contents.len().div_ceil(seg);
        // All or nothing, so a partial GSO batch is never half-sent.
        let permits = self.out.try_reserve_many(n).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => io::Error::from(io::ErrorKind::WouldBlock),
            mpsc::error::TrySendError::Closed(_) => io::Error::from(io::ErrorKind::BrokenPipe),
        })?;
        for (permit, chunk) in permits.zip(t.contents.chunks(seg)) {
            permit.send(Bytes::copy_from_slice(chunk));
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.inbound.lock().unwrap();
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let p = if n == 0 {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(p)) => p,
                    Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match rx.try_recv() {
                    Ok(p) => p,
                    Err(_) => break,
                }
            };
            let len = p.len().min(bufs[n].len());
            bufs[n][..len].copy_from_slice(&p[..len]);
            meta[n] = RecvMeta {
                addr: PLACEHOLDER_PEER,
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            n += 1;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }
}

// ---------------------------------------------------------------------------

const SALT: usize = 8;

/// hysteria2 "salamander": every datagram is `salt(8) || payload XOR
/// blake2b-256(password || salt)` (key repeated).
pub(crate) struct Salamander {
    inner: Socket,
    password: Box<[u8]>,
    scratch: Mutex<Vec<u8>>,
}

impl Salamander {
    pub(crate) fn new(inner: Socket, password: &str) -> Arc<Self> {
        Arc::new(Self {
            inner,
            password: password.as_bytes().into(),
            scratch: Mutex::new(Vec::new()),
        })
    }

    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut h = blake2::Blake2b::<blake2::digest::consts::U32>::new();
        h.update(&self.password);
        h.update(salt);
        h.finalize().into()
    }
}

fn xor(data: &mut [u8], key: &[u8; 32]) {
    for chunk in data.chunks_mut(32) {
        for (b, k) in chunk.iter_mut().zip(key) {
            *b ^= k;
        }
    }
}

impl fmt::Debug for Salamander {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salamander")
    }
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        let seg = t.segment_size.unwrap_or(t.contents.len()).max(1);
        let mut out = self.scratch.lock().unwrap();
        out.clear();
        // Each GSO segment gets its own salt; segments stay equal-sized
        // (+8 each), so the batch remains valid for GSO.
        for chunk in t.contents.chunks(seg) {
            let salt: [u8; SALT] = fastrand::u64(..).to_ne_bytes();
            let key = self.key(&salt);
            out.extend_from_slice(&salt);
            let start = out.len();
            out.extend_from_slice(chunk);
            xor(&mut out[start..], &key);
        }
        self.inner.try_send(&Transmit {
            destination: t.destination,
            ecn: t.ecn,
            contents: &out,
            segment_size: t.segment_size.map(|s| s + SALT),
            src_ip: t.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let n = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (buf, m) in bufs.iter_mut().zip(meta.iter_mut()).take(n) {
            // Decode each GRO segment and compact the payloads in place.
            let stride = m.stride.max(1);
            let mut w = 0;
            let mut r = 0;
            while r < m.len {
                let end = (r + stride).min(m.len);
                if end - r > SALT {
                    let key = self.key(&buf[r..r + SALT]);
                    let len = end - r - SALT;
                    buf.copy_within(r + SALT..end, w);
                    xor(&mut buf[w..w + len], &key);
                    w += len;
                }
                r = end;
            }
            m.len = w;
            m.stride = stride.saturating_sub(SALT).max(1);
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ---------------------------------------------------------------------------

/// Opens the base socket for one hop: returns it and the address to send to.
pub(crate) type HopDial =
    Arc<dyn Fn(u16) -> sbr_core::BoxFuture<'static, io::Result<(Socket, SocketAddr)>> + Send + Sync>;

struct Leg {
    sock: Socket,
    target: SocketAddr,
}

/// hysteria port hopping: a fresh socket to a random port from the range
/// every hop interval. The previous leg keeps receiving until the next
/// hop, so in-flight replies are not lost.
pub(crate) struct HopSocket {
    legs: Mutex<(Arc<Leg>, Option<Arc<Leg>>)>,
    generation: AtomicU64,
    peer: SocketAddr,
    hopper: Mutex<Option<JoinHandle<()>>>,
}

pub(crate) fn random_port(ranges: &[(u16, u16)]) -> u16 {
    let total: u64 = ranges.iter().map(|(a, b)| u64::from(b - a) + 1).sum();
    let mut i = fastrand::u64(..total);
    for (a, b) in ranges {
        let n = u64::from(b - a) + 1;
        if i < n {
            return a + i as u16;
        }
        i -= n;
    }
    ranges[0].0
}

impl HopSocket {
    /// Through a detour the peer may not have a local address at all, so
    /// quinn is shown [`PLACEHOLDER_PEER`]; otherwise the first leg's.
    pub(crate) async fn new(
        dial: HopDial,
        ranges: Vec<(u16, u16)>,
        interval: (Duration, Duration),
        detour: bool,
        keep_peer: Option<SocketAddr>,
    ) -> io::Result<Arc<Self>> {
        let (sock, target) = dial(random_port(&ranges)).await?;
        let peer = keep_peer.unwrap_or(if detour { PLACEHOLDER_PEER } else { target });
        let this = Arc::new(Self {
            legs: Mutex::new((Arc::new(Leg { sock, target }), None)),
            generation: AtomicU64::new(0),
            peer,
            hopper: Mutex::new(None),
        });
        // Only a weak reference: the hop task must not keep a dead
        // connection's socket alive. It ends with the socket.
        let weak = Arc::downgrade(&this);
        let task = tokio::spawn(async move {
            loop {
                let (min, max) = interval;
                let wait = if max > min {
                    min + Duration::from_nanos(fastrand::u64(..=(max - min).as_nanos() as u64))
                } else {
                    min
                };
                tokio::time::sleep(wait).await;
                let Some(this) = weak.upgrade() else { return };
                let port = random_port(&ranges);
                drop(this);
                let Ok((sock, target)) = dial(port).await else { continue };
                let Some(this) = weak.upgrade() else { return };
                let mut legs = this.legs.lock().unwrap();
                let current = std::mem::replace(&mut legs.0, Arc::new(Leg { sock, target }));
                legs.1 = Some(current);
                this.generation.fetch_add(1, Ordering::Release);
            }
        });
        *this.hopper.lock().unwrap() = Some(task);
        Ok(this)
    }

    /// The fixed address quinn knows the server by.
    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn current(&self) -> Arc<Leg> {
        self.legs.lock().unwrap().0.clone()
    }
}

impl Drop for HopSocket {
    fn drop(&mut self) {
        if let Some(t) = self.hopper.get_mut().unwrap().take() {
            t.abort();
        }
    }
}

impl fmt::Debug for HopSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HopSocket")
    }
}

/// Follows the current leg's writability across hops.
struct HopPoller {
    sock: Arc<HopSocket>,
    generation: u64,
    inner: Option<Pin<Box<dyn UdpPoller>>>,
}

impl fmt::Debug for HopPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HopPoller")
    }
}

impl UdpPoller for HopPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let generation = this.sock.generation.load(Ordering::Acquire);
        if this.inner.is_none() || generation != this.generation {
            this.generation = generation;
            this.inner = Some(this.sock.current().sock.clone().create_io_poller());
        }
        this.inner.as_mut().unwrap().as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for HopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HopPoller {
            sock: self,
            generation: u64::MAX,
            inner: None,
        })
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        let leg = self.current();
        leg.sock.try_send(&Transmit {
            destination: leg.target,
            ecn: t.ecn,
            contents: t.contents,
            segment_size: t.segment_size,
            src_ip: None,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (cur, prev) = self.legs.lock().unwrap().clone();
        // Poll both legs so both register the waker.
        let mut r = cur.sock.poll_recv(cx, bufs, meta);
        if matches!(r, Poll::Pending)
            && let Some(prev) = &prev
        {
            r = match prev.sock.poll_recv(cx, bufs, meta) {
                // The old leg dying is expected; the current one carries on.
                Poll::Ready(Err(_)) => Poll::Pending,
                other => other,
            };
        }
        if let Poll::Ready(Ok(n)) = r {
            for m in &mut meta[..n] {
                m.addr = self.peer;
                m.dst_ip = None;
            }
        }
        r
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.current().sock.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.current().sock.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.current().sock.max_receive_segments()
    }
}

// ---------------------------------------------------------------------------

/// Notes the first datagram received, so a migration knows the server
/// reached the new socket.
pub(crate) struct Witness {
    inner: Socket,
    heard: AtomicBool,
    notify: Notify,
}

impl Witness {
    pub(crate) fn new(inner: Socket) -> Arc<Self> {
        Arc::new(Self {
            inner,
            heard: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    pub(crate) async fn heard(&self) {
        if !self.heard.load(Ordering::Acquire) {
            self.notify.notified().await;
        }
    }
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Witness")
    }
}

impl AsyncUdpSocket for Witness {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        self.inner.try_send(t)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let r = self.inner.poll_recv(cx, bufs, meta);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0)
            && !self.heard.load(Ordering::Relaxed)
            && !self.heard.swap(true, Ordering::AcqRel)
        {
            // A stored permit: `heard` may start waiting after this.
            self.notify.notify_one();
        }
        r
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_cover_ranges() {
        let r = [(10, 11), (20, 20)];
        for _ in 0..200 {
            assert!([10, 11, 20].contains(&random_port(&r)));
        }
    }
}
