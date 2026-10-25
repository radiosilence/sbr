//! The TUN packet loop. TCP goes either to the kernel via NAT onto a
//! listener (the system stack; see the crate docs for the trick) or to
//! sbr's userspace TCP (`crate::tcp`). UDP is handed up as datagrams either
//! way, after fragment reassembly.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{debug, trace, warn};

use crate::device::{Device, HEADROOM, RecvBatch};
use crate::frag::Reassembler;
use crate::nat::Nat;
use crate::packet::{self, ACK, Ip, PROTO_TCP, PROTO_UDP, Parsed, SYN};
use crate::tcp::tcb::Blocked;
use crate::tcp::{self, Tcp, TcpConfig};

/// Who terminates the TUN's TCP connections.
#[derive(Clone, Debug, Default)]
pub enum TcpStack {
    /// The kernel, via NAT onto a listener on the interface address.
    #[default]
    System,
    /// sbr's userspace TCP.
    User(TcpConfig),
}

#[derive(Clone, Debug)]
pub struct StackConfig {
    /// The interface address and the next one (used as the NAT source).
    pub inet4: Option<(Ipv4Addr, Ipv4Addr)>,
    pub inet6: Option<(Ipv6Addr, Ipv6Addr)>,
    pub mtu: usize,
    pub tcp: TcpStack,
}

impl StackConfig {
    /// Derive from interface prefixes the way sing-box does: the NAT
    /// source is the address after the interface address.
    pub fn from_prefixes(prefixes: &[ipnet::IpNet], mtu: usize) -> Self {
        let mut c = Self {
            inet4: None,
            inet6: None,
            mtu,
            tcp: TcpStack::System,
        };
        for p in prefixes {
            match p {
                ipnet::IpNet::V4(v4) if c.inet4.is_none() => {
                    c.inet4 = Some((v4.addr(), Ipv4Addr::from(u32::from(v4.addr()).wrapping_add(1))));
                }
                ipnet::IpNet::V6(v6) if c.inet6.is_none() => {
                    c.inet6 = Some((v6.addr(), Ipv6Addr::from(u128::from(v6.addr()).wrapping_add(1))));
                }
                _ => {}
            }
        }
        c
    }
}

/// A TCP connection from an app. With the system stack, dropping it
/// releases the NAT entry (after a grace period for trailing segments).
pub struct Accepted {
    pub stream: TcpConn,
    /// The app's address.
    pub source: SocketAddr,
    /// Where the app was connecting to.
    pub destination: SocketAddr,
    _guard: Option<NatGuard>,
}

/// The app's end of an accepted connection.
pub enum TcpConn {
    Kernel(TcpStream),
    User(tcp::Stream),
}

impl TcpConn {
    /// The engine is ready for the connection: with the userspace stack's
    /// deferred handshake this sends the SYN-ACK. The kernel stack has
    /// already completed it.
    pub fn accept(&self) {
        if let Self::User(s) = self {
            s.accept();
        }
    }

    /// The outbound refused the connection: reset it, or with `silent`
    /// forget it without a word to the app. The kernel stack can only
    /// close.
    pub fn refuse(&self, silent: bool) {
        if let Self::User(s) = self {
            if silent { s.discard() } else { s.abort() }
        }
    }
}

impl AsyncRead for TcpConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(s) => Pin::new(s).poll_read(cx, buf),
            Self::User(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Kernel(s) => Pin::new(s).poll_write(cx, buf),
            Self::User(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(s) => Pin::new(s).poll_flush(cx),
            Self::User(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(s) => Pin::new(s).poll_shutdown(cx),
            Self::User(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

struct NatGuard {
    nat: Arc<Mutex<Nat>>,
    port: u16,
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        self.nat.lock().unwrap().close(self.port);
    }
}

/// A datagram from an app.
pub struct UdpIn {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: Bytes,
}

struct Family {
    addr: IpAddr,
    next: IpAddr,
    port: u16,
    nat: Arc<Mutex<Nat>>,
}

pub struct Stack {
    device: Arc<Device>,
    mtu: usize,
    /// IP identification for fragments sbr originates (IPv4 uses the low 16 bits).
    ids: Arc<AtomicU32>,
    tasks: JoinSet<()>,
}

impl Stack {
    /// Start the packet loop and listeners. The device's addresses must
    /// already be configured (true for adopted NE fds and `Device::create`).
    pub async fn start(
        device: Device,
        cfg: StackConfig,
        on_tcp: impl Fn(Accepted) + Send + Sync + 'static,
        on_udp: impl Fn(UdpIn) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let device = Arc::new(device);
        let on_tcp = Arc::new(on_tcp);
        let mut tasks = JoinSet::new();
        let mut fams: [Option<Arc<Family>>; 2] = [None, None];
        let pairs = [
            cfg.inet4.map(|(a, n)| (IpAddr::V4(a), IpAddr::V4(n))),
            cfg.inet6.map(|(a, n)| (IpAddr::V6(a), IpAddr::V6(n))),
        ];
        let user = matches!(cfg.tcp, TcpStack::User(_));
        for (slot, pair) in fams.iter_mut().zip(pairs) {
            let Some((addr, next)) = pair else { continue };
            if user {
                *slot = Some(Arc::new(Family {
                    addr,
                    next,
                    port: 0,
                    nat: Arc::new(Mutex::new(Nat::default())),
                }));
                continue;
            }
            let listener = listen(SocketAddr::new(addr, 0), device.name())?;
            let port = listener.local_addr()?.port();
            let fam = Arc::new(Family {
                addr,
                next,
                port,
                nat: Arc::new(Mutex::new(Nat::default())),
            });
            debug!(%addr, port, "system stack listening");
            tasks.spawn(accept_loop(listener, fam.clone(), on_tcp.clone()));
            *slot = Some(fam);
        }
        if fams.iter().all(Option::is_none) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "tun: no interface address"));
        }
        // Seeded so a restart does not reuse IDs the kernel may still be
        // reassembling.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let ids = Arc::new(AtomicU32::new(seed));
        match cfg.tcp {
            TcpStack::System => {
                tasks.spawn(packet_loop(device.clone(), fams, cfg.mtu, ids.clone(), on_udp));
            }
            TcpStack::User(tcfg) => {
                debug!(rx = tcfg.rx_buffer, tx = tcfg.tx_buffer, "userspace TCP stack");
                tasks.spawn(user_loop(device.clone(), fams, cfg.mtu, on_udp, on_tcp, tcfg));
            }
        }
        Ok(Self {
            device,
            mtu: cfg.mtu,
            ids,
            tasks,
        })
    }

    /// Deliver a datagram to an app: `from` is what the app will see as the
    /// sender. Drops (rather than blocks) when the interface is congested.
    /// Datagrams larger than the MTU are fragmented, as the sending host
    /// would; this applies to IPv6 too, since sbr is that source.
    /// Tell `client` its UDP flow to `remote` can't be carried (ICMP port
    /// unreachable), so it fails fast instead of timing out.
    pub fn write_udp_unreachable(&self, remote: SocketAddr, client: SocketAddr) -> io::Result<()> {
        if remote.is_ipv4() != client.is_ipv4() {
            return Ok(());
        }
        UDP_BUF.with(|b| {
            let mut b = b.borrow_mut();
            let pkt = &mut b.0;
            packet::build_udp_unreachable(pkt, remote, client);
            pkt.splice(0..0, [0u8; HEADROOM]);
            try_send(&self.device, pkt)
        })
    }

    pub fn write_udp(&self, from: SocketAddr, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        // The IP and UDP length fields are 16 bits; a larger payload (a big
        // DNS answer, a UDP-over-stream frame) would wrap them.
        let max = if to.is_ipv4() { 65535 - 28 } else { 65535 - 8 };
        if payload.len() > max {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        UDP_BUF.with(|b| {
            let mut b = b.borrow_mut();
            let (pkt, frag) = &mut *b;
            packet::build_udp(pkt, from, to, payload);
            let len = pkt.len();
            if len > self.mtu {
                let mut r = Ok(());
                let id = self.ids.fetch_add(1, Ordering::Relaxed);
                if packet::fragment(pkt, self.mtu, id, HEADROOM, frag, |f| {
                    if r.is_ok() {
                        r = try_send(&self.device, f);
                    }
                }) {
                    return r;
                }
            }
            // Shift right to make headroom; the buffer is reused per thread.
            pkt.splice(0..0, [0u8; HEADROOM]);
            try_send(&self.device, pkt)
        })
    }

    pub fn device(&self) -> &Device {
        &self.device
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

/// The NAT listener on the interface address. Its replies go to the NAT
/// source, which only exists inside the TUN. On Apple platforms a Network
/// Extension's own sockets are scoped to the physical interface and never
/// enter its tunnel, so without `IP_BOUND_IF` the kernel's SYN-ACKs left by
/// the cellular or Wi-Fi interface and no TCP connection completed.
fn listen(addr: SocketAddr, interface: &str) -> io::Result<TcpListener> {
    #[cfg(target_vendor = "apple")]
    {
        use std::os::fd::FromRawFd;
        let index = std::ffi::CString::new(interface)
            // SAFETY: a valid NUL-terminated string.
            .map(|n| unsafe { libc::if_nametoindex(n.as_ptr()) })
            .unwrap_or(0);
        if index == 0 {
            return Err(io::Error::other(format!("tun: no interface index for {interface:?}")));
        }
        let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        // SAFETY: plain socket creation; the fd is owned by `std` below.
        let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh socket that nothing else owns.
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        let (level, name) = if addr.is_ipv4() {
            (libc::IPPROTO_IP, libc::IP_BOUND_IF)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
        };
        let index = index as libc::c_int;
        let int_len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: setsockopt with a c_int option value.
        if unsafe { libc::setsockopt(fd, level, name, (&raw const index).cast(), int_len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (storage, len) = sockaddr(addr);
        // SAFETY: `storage` holds a sockaddr of `len` bytes for this family.
        if unsafe { libc::bind(fd, (&raw const storage).cast(), len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a bound stream socket.
        if unsafe { libc::listen(fd, 1024) } != 0 {
            return Err(io::Error::last_os_error());
        }
        std_listener.set_nonblocking(true)?;
        TcpListener::from_std(std_listener)
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let _ = interface;
        let l = std::net::TcpListener::bind(addr)?;
        l.set_nonblocking(true)?;
        TcpListener::from_std(l)
    }
}

#[cfg(target_vendor = "apple")]
fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: all-zero is a valid sockaddr_storage.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_len: size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits in sockaddr_storage.
            unsafe { std::ptr::write((&raw mut storage).cast(), sin) };
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_len: size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: sockaddr_in6 fits in sockaddr_storage.
            unsafe { std::ptr::write((&raw mut storage).cast(), sin6) };
            size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}

/// Send `buf[HEADROOM..]`, treating a full interface queue as a drop.
fn try_send(device: &Device, buf: &mut [u8]) -> io::Result<()> {
    match device.try_send(buf, buf.len() - HEADROOM) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
        r => r,
    }
}

thread_local! {
    /// A whole packet, and scratch space for its fragments.
    static UDP_BUF: std::cell::RefCell<(Vec<u8>, Vec<u8>)> = const { std::cell::RefCell::new((Vec::new(), Vec::new())) };
}

async fn accept_loop(listener: TcpListener, fam: Arc<Family>, on_tcp: Arc<dyn Fn(Accepted) + Send + Sync>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "tun accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        if peer.ip() != fam.next {
            warn!(%peer, expected = %fam.next, "tun: dropped a connection from an unexpected peer");
            continue;
        }
        let Some((source, destination)) = fam.nat.lock().unwrap().accept(peer.port()) else {
            warn!(%peer, "tun: dropped a connection with no NAT entry");
            continue;
        };
        debug!(%peer, "tun: accepted");
        let _ = stream.set_nodelay(true);
        on_tcp(Accepted {
            stream: TcpConn::Kernel(stream),
            source,
            destination,
            _guard: Some(NatGuard {
                nat: fam.nat.clone(),
                port: peer.port(),
            }),
        });
    }
}

/// Go's `netip.Addr.IsGlobalUnicast`: what sing-tun forwards.
fn global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified() || v4.is_loopback() || v4.is_multicast() || v4.is_broadcast() || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
const BATCH: (usize, usize) = (4, 32);
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
const BATCH: (usize, usize) = (8, 64);

async fn packet_loop(
    device: Arc<Device>,
    fams: [Option<Arc<Family>>; 2],
    mtu: usize,
    ids: Arc<AtomicU32>,
    on_udp: impl Fn(UdpIn) + Send + Sync + 'static,
) {
    let mut batch = RecvBatch::new(BATCH.0, BATCH.1, mtu.max(1500) + 64);
    let mut reasm = Reassembler::new(HEADROOM);
    let mut frag = Vec::new();
    loop {
        let n = match device.recv_batch(&mut batch).await {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "tun read failed; stopping");
                return;
            }
        };
        for i in 0..n {
            let len = batch.len(i);
            if len == 0 {
                continue;
            }
            let r = match process(&fams, &mut reasm, batch.buf(i), len, &on_udp, false) {
                Out::None | Out::Tcp(_) | Out::TcpOwned(..) => continue,
                Out::InPlace(len) => device.send(batch.buf(i), len).await,
                Out::Owned(mut pkt) if pkt.len() - HEADROOM > mtu => {
                    // A reassembled TCP segment. Fragment it again with our
                    // own ID: the rewritten flows all share one address pair,
                    // so the app's IDs could collide in the kernel.
                    let mut r = Ok(());
                    let id = ids.fetch_add(1, Ordering::Relaxed);
                    if !packet::fragment(&pkt[HEADROOM..], mtu, id, HEADROOM, &mut frag, |f| {
                        if r.is_ok() {
                            r = try_send(&device, f);
                        }
                    }) {
                        r = try_send(&device, &mut pkt);
                    }
                    r
                }
                Out::Owned(mut pkt) => {
                    let len = pkt.len() - HEADROOM;
                    device.send(&mut pkt, len).await
                }
            };
            if let Err(e) = r {
                debug!(error = %e, "tun write failed");
            }
        }
    }
}

#[derive(Debug)]
enum Out {
    None,
    /// Write back `len` bytes of the input buffer.
    InPlace(usize),
    /// Write back a reassembled packet at `[HEADROOM..]`.
    Owned(Vec<u8>),
    /// A TCP packet, in the input buffer, for the userspace stack.
    Tcp(Parsed),
    /// A reassembled TCP packet at `[HEADROOM..]` for the userspace stack.
    TcpOwned(Vec<u8>, Parsed),
}

/// Handle one packet in `buf[HEADROOM..HEADROOM + len]`: TCP is rewritten
/// for writing back into the TUN (or, with `user`, handed back for the
/// userspace stack), UDP is consumed, anything else dropped.
fn process(
    fams: &[Option<Arc<Family>>; 2],
    reasm: &mut Reassembler,
    buf: &mut [u8],
    len: usize,
    on_udp: &impl Fn(UdpIn),
    user: bool,
) -> Out {
    let pkt = &mut buf[HEADROOM..HEADROOM + len];
    match packet::classify(pkt) {
        Some(Ip::Whole(h)) => {
            let Some(fam) = fams[h.v6 as usize].as_ref() else {
                return Out::None;
            };
            match h.proto {
                PROTO_TCP if user => {
                    if global_unicast(h.dst.ip()) {
                        Out::Tcp(h)
                    } else {
                        Out::None
                    }
                }
                PROTO_TCP if nat_tcp(fam, pkt, &h) => Out::InPlace(len),
                PROTO_UDP if global_unicast(h.dst.ip()) => {
                    on_udp(UdpIn {
                        source: h.src,
                        destination: h.dst,
                        payload: Bytes::copy_from_slice(&pkt[h.l4 + 8..h.len]),
                    });
                    Out::None
                }
                _ => Out::None,
            }
        }
        Some(Ip::Fragment(f)) => {
            if fams[f.v6 as usize].is_none() || (!f.v6 && f.proto != PROTO_TCP && f.proto != PROTO_UDP) {
                return Out::None;
            }
            let Some(mut whole) = reasm.push(pkt, &f, Instant::now()) else {
                return Out::None;
            };
            let Some(h) = packet::parse(&whole[HEADROOM..]) else {
                return Out::None;
            };
            let Some(fam) = fams[h.v6 as usize].as_ref() else {
                return Out::None;
            };
            trace!(src = %h.src, dst = %h.dst, len = h.len, "reassembled");
            match h.proto {
                PROTO_TCP if user => {
                    if global_unicast(h.dst.ip()) {
                        Out::TcpOwned(whole, h)
                    } else {
                        Out::None
                    }
                }
                PROTO_TCP if nat_tcp(fam, &mut whole[HEADROOM..], &h) => Out::Owned(whole),
                PROTO_UDP if global_unicast(h.dst.ip()) => {
                    on_udp(UdpIn {
                        source: h.src,
                        destination: h.dst,
                        payload: Bytes::from(whole).slice(HEADROOM + h.l4 + 8..HEADROOM + h.len),
                    });
                    Out::None
                }
                _ => Out::None,
            }
        }
        None => Out::None,
    }
}

/// The packet loop with userspace TCP: also wakes for streams that have
/// something to send and for TCP timers.
async fn user_loop(
    device: Arc<Device>,
    fams: [Option<Arc<Family>>; 2],
    mtu: usize,
    on_udp: impl Fn(UdpIn) + Send + Sync + 'static,
    on_tcp: Arc<dyn Fn(Accepted) + Send + Sync>,
    cfg: TcpConfig,
) {
    let mut batch = RecvBatch::new(BATCH.0, BATCH.1, mtu.max(1500) + 64);
    let mut reasm = Reassembler::new(HEADROOM);
    let mut tcp = Tcp::new(
        cfg,
        mtu,
        move |source, destination, s| {
            on_tcp(Accepted {
                stream: TcpConn::User(s),
                source,
                destination,
                _guard: None,
            })
        },
        Instant::now(),
    );
    let env = tcp.env().clone();
    let mut link = |b: &mut [u8]| link_send(&device, b);
    loop {
        let deadline = tcp.next_deadline();
        let got = tokio::select! {
            r = device.recv_batch(&mut batch) => Some(r),
            _ = env.notify.notified() => None,
            _ = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None => std::future::pending().await,
                }
            } => None,
        };
        let now = Instant::now();
        if let Some(r) = got {
            let n = match r {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, "tun read failed; stopping");
                    return;
                }
            };
            for i in 0..n {
                let len = batch.len(i);
                if len == 0 {
                    continue;
                }
                match process(&fams, &mut reasm, batch.buf(i), len, &on_udp, true) {
                    Out::Tcp(h) => tcp.input(&batch.buf(i)[HEADROOM..HEADROOM + len], &h, now, &mut link),
                    Out::TcpOwned(pkt, h) => tcp.input(&pkt[HEADROOM..], &h, now, &mut link),
                    _ => {}
                }
            }
        }
        tcp.drain_app(now);
        tcp.run_timers(now, &mut link);
        tcp.flush(now, &mut link);
    }
}

/// Send `buf[HEADROOM..]` for the userspace stack. A full interface queue
/// is reported so the stack can retry without losing state; other errors
/// count as a lost packet.
fn link_send(device: &Device, buf: &mut [u8]) -> Result<(), Blocked> {
    match device.try_send(buf, buf.len() - HEADROOM) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS) => Err(Blocked),
        Err(e) => {
            debug!(error = %e, "tun write failed");
            Ok(())
        }
    }
}

/// Apply the NAT to a TCP packet in place. False if it has no entry.
fn nat_tcp(fam: &Family, pkt: &mut [u8], h: &Parsed) -> bool {
    let flags = packet::tcp_flags(pkt, h);
    let rewrite = if h.src.ip() == fam.addr && h.src.port() == fam.port {
        // Our listener replying: restore the original flow.
        fam.nat
            .lock()
            .unwrap()
            .inbound(h.dst.port())
            .map(|(src, dst)| (dst, src))
    } else if global_unicast(h.dst.ip()) {
        let syn_only = flags & SYN != 0 && flags & ACK == 0;
        let port = fam.nat.lock().unwrap().outbound(h.src, h.dst, syn_only);
        port.map(|p| (SocketAddr::new(fam.next, p), SocketAddr::new(fam.addr, fam.port)))
    } else {
        None
    };
    let Some((src, dst)) = rewrite else {
        trace!(src = %h.src, dst = %h.dst, flags, "tcp: no NAT entry, dropped");
        return false;
    };
    packet::rewrite(pkt, h, src, dst);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_udp, fold, fragment, parse, sum16, verify, wr16};

    fn fams() -> [Option<Arc<Family>>; 2] {
        [
            Some(Arc::new(Family {
                addr: "172.19.0.1".parse().unwrap(),
                next: "172.19.0.2".parse().unwrap(),
                port: 8000,
                nat: Arc::new(Mutex::new(Nat::default())),
            })),
            None,
        ]
    }

    /// Run fragments of `p` (at `mtu`) through `process`; returns the last result.
    fn feed(
        fams: &[Option<Arc<Family>>; 2],
        reasm: &mut Reassembler,
        p: &[u8],
        mtu: usize,
        on_udp: &impl Fn(UdpIn),
    ) -> Out {
        let mut frags = Vec::new();
        assert!(fragment(p, mtu, 42, HEADROOM, &mut Vec::new(), |f| frags.push(f.to_vec())));
        assert!(frags.len() > 1);
        let mut out = Out::None;
        for mut f in frags {
            let len = f.len() - HEADROOM;
            assert!(matches!(out, Out::None), "completed early");
            out = process(fams, reasm, &mut f, len, on_udp, false);
        }
        out
    }

    #[test]
    fn fragmented_udp_goes_up_whole() {
        let fams = fams();
        let mut reasm = Reassembler::new(HEADROOM);
        let (s, d) = ("172.19.0.1:4500".parse().unwrap(), "52.1.2.3:443".parse().unwrap());
        let payload: Vec<u8> = (0..1400u32).map(|i| (i % 253) as u8).collect();
        let mut p = Vec::new();
        build_udp(&mut p, s, d, &payload);
        let got = std::cell::RefCell::new(Vec::new());
        let on_udp = |u: UdpIn| got.borrow_mut().push((u.source, u.destination, u.payload));
        assert!(matches!(feed(&fams, &mut reasm, &p, 1280, &on_udp), Out::None));
        assert_eq!(got.borrow()[..], [(s, d, Bytes::from(payload))]);
        assert_eq!(reasm.pending(), 0);
    }

    #[test]
    fn fragmented_tcp_is_reassembled_and_translated() {
        let fams = fams();
        let mut reasm = Reassembler::new(HEADROOM);
        let (s, d): (SocketAddr, SocketAddr) = ("172.19.0.1:51000".parse().unwrap(), "52.1.2.3:443".parse().unwrap());
        // A SYN carrying 1400 bytes (TCP Fast Open style), built from a UDP packet.
        let mut p = Vec::new();
        build_udp(&mut p, s, d, &[7u8; 1412]);
        p[9] = PROTO_TCP;
        wr16(&mut p, 10, 0);
        let ck = !fold(sum16(&p[..20], 0));
        wr16(&mut p, 10, ck);
        p[20 + 4..20 + 20].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 5 << 4, SYN, 0xff, 0xff, 0, 0, 0, 0]);
        let mut pseudo = sum16(&p[12..20], 0) + PROTO_TCP as u32 + (p.len() - 20) as u32;
        pseudo = sum16(&p[20..], pseudo);
        wr16(&mut p, 36, !fold(pseudo));
        assert!(verify(&p));

        let Out::Owned(pkt) = feed(&fams, &mut reasm, &p, 576, &|_| panic!("not UDP")) else {
            panic!("expected the reassembled segment back")
        };
        let q = &pkt[HEADROOM..];
        assert!(verify(q), "checksums valid after reassembly and NAT");
        let h = parse(q).unwrap();
        assert_eq!(h.dst, "172.19.0.1:8000".parse().unwrap());
        assert_eq!(h.src.ip(), "172.19.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(&q[h.l4 + 20..], &p[40..]);
        let fam = fams[0].as_ref().unwrap();
        assert_eq!(fam.nat.lock().unwrap().accept(h.src.port()), Some((s, d)));
    }
}
