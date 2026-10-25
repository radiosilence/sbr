//! The userspace TCP stack through its real packet loop, without root: a
//! datagram socketpair stands in for the TUN fd (it is packet-oriented
//! like one), and smoltcp plays the apps on the other end.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sbr_tun::device::{Device, HEADROOM};
use sbr_tun::packet;
use sbr_tun::{Stack, StackConfig, TcpConfig, TcpStack, UdpIn};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp as stcp;
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncWriteExt, Interest};

/// Darwin's utun frames every packet with a 4-byte address family, and
/// `Device` expects it there.
const AF: usize = if cfg!(target_vendor = "apple") { HEADROOM } else { 0 };

fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: socketpair fills two fresh descriptors we then own.
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) },
        0
    );
    for fd in fds {
        // Deep buffers so bursts aren't dropped by the pair itself.
        let size: libc::c_int = 4 << 20;
        // SAFETY: setsockopt with an int on a valid fd.
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, (&raw const size).cast(), 4);
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, (&raw const size).cast(), 4);
        }
    }
    // SAFETY: both fds were just created and are owned by nobody else.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

struct Dev {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut Vec<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push(b);
        r
    }
}

impl phy::Device for Dev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;
    fn receive(&mut self, _: SInstant) -> Option<(RxTok, TxTok<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxTok(p), TxTok(&mut self.tx)))
    }
    fn transmit(&mut self, _: SInstant) -> Option<TxTok<'_>> {
        Some(TxTok(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}

const MTU: usize = 1500;

/// The apps: a smoltcp interface on the far end of the socketpair.
struct Apps {
    fd: AsyncFd<OwnedFd>,
    iface: Interface,
    sockets: SocketSet<'static>,
    dev: Dev,
    t0: Instant,
    port: u16,
}

impl Apps {
    fn new(fd: OwnedFd) -> Self {
        let mut dev = Dev {
            rx: VecDeque::new(),
            tx: Vec::new(),
        };
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, SInstant::from_micros(0));
        iface.update_ip_addrs(|a| a.push(IpCidr::new(IpAddress::v4(172, 19, 0, 1), 30)).unwrap());
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(172, 19, 0, 2))
            .unwrap();
        // SAFETY: plain fcntl on a valid fd.
        unsafe {
            let raw = fd.as_raw_fd();
            libc::fcntl(raw, libc::F_SETFL, libc::fcntl(raw, libc::F_GETFL) | libc::O_NONBLOCK);
        }
        Self {
            // SAFETY: the fd is owned by the AsyncFd and closed only after its
            // registration is gone.
            fd: unsafe { AsyncFd::register(fd) }.map_err(|e| -> std::io::Error { e.into() }).unwrap(),
            iface,
            sockets: SocketSet::new(Vec::new()),
            dev,
            t0: Instant::now(),
            port: 30000,
        }
    }

    fn connect(&mut self, to: SocketAddr, buf: usize) -> SocketHandle {
        let mut s = stcp::Socket::new(stcp::SocketBuffer::new(vec![0; buf]), stcp::SocketBuffer::new(vec![0; buf]));
        s.set_nagle_enabled(false);
        self.port += 1;
        s.connect(self.iface.context(), (IpAddress::from(to.ip()), to.port()), self.port)
            .unwrap();
        self.sockets.add(s)
    }

    fn sock(&mut self, h: SocketHandle) -> &mut stcp::Socket<'static> {
        self.sockets.get_mut::<stcp::Socket>(h)
    }

    fn send_raw(&self, pkt: &[u8]) {
        let mut b = vec![0u8; AF];
        if AF > 0 {
            b[..4].copy_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        }
        b.extend_from_slice(pkt);
        // SAFETY: writing a valid buffer to a valid fd.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), b.as_ptr().cast(), b.len()) };
        assert_eq!(n as usize, b.len(), "socketpair write");
    }

    /// Poll smoltcp, exchange packets, and wait briefly for more.
    async fn step(&mut self) -> Vec<Vec<u8>> {
        let now = SInstant::from_micros(self.t0.elapsed().as_micros() as i64);
        self.iface.poll(now, &mut self.dev, &mut self.sockets);
        for p in std::mem::take(&mut self.dev.tx) {
            self.send_raw(&p);
        }
        let mut other = Vec::new();
        let wait = self
            .iface
            .poll_delay(now, &self.sockets)
            .map_or(Duration::from_millis(5), |d| Duration::from_micros(d.total_micros()))
            .min(Duration::from_millis(5));
        if let Ok(Ok(())) = tokio::time::timeout(wait, async {
            let mut g = self.fd.ready(Interest::READABLE).await?;
            g.clear_ready();
            Ok::<_, std::io::Error>(())
        })
        .await
        {
            let mut b = vec![0u8; 65536];
            loop {
                // SAFETY: reading into a valid, sized buffer.
                let n = unsafe { libc::read(self.fd.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) };
                if n <= 0 {
                    break;
                }
                let p = b[AF..n as usize].to_vec();
                match packet::parse(&p) {
                    Some(h) if h.proto == packet::PROTO_TCP => self.dev.rx.push_back(p),
                    _ => other.push(p),
                }
            }
        }
        other
    }
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_add(seed).wrapping_mul(2654435761) >> 24) as u8)
        .collect()
}

async fn start(tcp: TcpConfig) -> (Arc<Stack>, Apps, Arc<Mutex<Vec<UdpIn>>>) {
    let (ours, theirs) = socketpair();
    let device = Device::adopt(ours.into_raw_fd()).unwrap();
    let cfg = StackConfig {
        inet4: Some((Ipv4Addr::new(172, 19, 0, 1), Ipv4Addr::new(172, 19, 0, 2))),
        inet6: None,
        mtu: MTU,
        tcp: TcpStack::User(tcp),
    };
    let udp = Arc::new(Mutex::new(Vec::new()));
    let u = udp.clone();
    let stack = Stack::start(
        device,
        cfg,
        |acc| {
            // The engine side: echo, then close.
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(acc.stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        },
        move |d| u.lock().unwrap().push(d),
    )
    .await
    .unwrap();
    (Arc::new(stack), Apps::new(theirs), udp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_many_connections_through_the_packet_loop() {
    let (_stack, mut apps, _) = start(TcpConfig {
        rx_buffer: 128 << 10,
        tx_buffer: 128 << 10,
        ..TcpConfig::default()
    })
    .await;
    let n = 24;
    let len = 512 << 10;
    let to: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let hs: Vec<_> = (0..n).map(|_| apps.connect(to, 64 << 10)).collect();
    let data: Vec<Vec<u8>> = (0..n).map(|i| pattern(len, i as u32)).collect();
    let mut sent = vec![0; n];
    let mut got: Vec<Vec<u8>> = vec![Vec::new(); n];
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(Instant::now() < deadline, "timed out: got {:?}", got.iter().map(Vec::len).collect::<Vec<_>>());
        apps.step().await;
        let mut done = true;
        for i in 0..n {
            let s = apps.sock(hs[i]);
            if s.can_send() && sent[i] < len {
                sent[i] += s.send_slice(&data[i][sent[i]..]).unwrap();
                if sent[i] == len {
                    s.close();
                }
            }
            while s.can_recv() {
                s.recv(|b| {
                    got[i].extend_from_slice(b);
                    (b.len(), ())
                })
                .unwrap();
            }
            done &= got[i].len() == len && !s.may_recv();
        }
        if done {
            break;
        }
    }
    for i in 0..n {
        assert!(got[i] == data[i], "connection {i} corrupted");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn udp_still_bypasses_tcp() {
    let (stack, mut apps, udp) = start(TcpConfig::default()).await;
    let (src, dst): (SocketAddr, SocketAddr) = ("172.19.0.1:5353".parse().unwrap(), "1.1.1.1:53".parse().unwrap());
    let mut p = Vec::new();
    packet::build_udp(&mut p, src, dst, b"query");
    apps.send_raw(&p);
    let deadline = Instant::now() + Duration::from_secs(5);
    while udp.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let u = udp.lock().unwrap().pop().unwrap();
    assert_eq!((u.source, u.destination, &u.payload[..]), (src, dst, &b"query"[..]));
    stack.write_udp(dst, src, b"answer").unwrap();
    let back = loop {
        assert!(Instant::now() < deadline);
        if let Some(p) = apps.step().await.pop() {
            break p;
        }
    };
    let h = packet::parse(&back).unwrap();
    assert_eq!((h.src, h.dst), (dst, src));
    assert_eq!(&back[h.l4 + 8..h.len], b"answer");
    assert!(packet::verify(&back));
}
