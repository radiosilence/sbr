//! TUN devices. Packets are always stored at `buf[HEADROOM..]` so the
//! Darwin 4-byte protocol-family prefix can be read and written in place.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use ipnet::IpNet;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Bytes reserved in front of every packet buffer.
pub const HEADROOM: usize = 4;

pub struct Device {
    fd: AsyncFd<OwnedFd>,
    /// utun prefixes each packet with a big-endian u32 address family.
    af_header: bool,
    name: String,
}

#[derive(Clone, Debug, Default)]
pub struct DeviceConfig {
    pub name: Option<String>,
    pub mtu: u32,
    pub address: Vec<IpNet>,
    /// Routes to send into the device.
    pub routes: Vec<IpNet>,
    /// Routes to keep on the previous default gateway.
    pub exclude: Vec<IpNet>,
}

impl Device {
    /// Adopt an fd for a tunnel the platform opened (Network Extension,
    /// VpnService). Takes ownership: the fd is closed when the device drops.
    /// Embedders that must keep their own copy pass a `dup()` (sbr-apple does).
    pub fn adopt(fd: RawFd) -> io::Result<Self> {
        // SAFETY: the caller transfers ownership of `fd` to us.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        set_nonblocking(owned.as_raw_fd())?;
        let name = platform::fd_name(owned.as_raw_fd()).unwrap_or_else(|| "tun".into());
        platform::tune(owned.as_raw_fd());
        Ok(Self {
            af_header: cfg!(target_vendor = "apple"),
            fd: register(owned)?,
            name,
        })
    }

    /// Create and configure an interface (CLI / desktop use; needs root).
    pub fn create(cfg: &DeviceConfig) -> io::Result<Self> {
        let (fd, name) = platform::create(cfg)?;
        set_nonblocking(fd.as_raw_fd())?;
        platform::tune(fd.as_raw_fd());
        Ok(Self {
            af_header: cfg!(target_vendor = "apple"),
            fd: register(fd)?,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Receive up to `batch.target()` packets in one wakeup. Each lands at
    /// `batch.packet(i)`. On Darwin this is a single `recvmsg_x`; elsewhere
    /// it drains the fd until `EAGAIN`. Fewer wakeups = less CPU and power.
    pub async fn recv_batch(&self, batch: &mut RecvBatch) -> io::Result<usize> {
        let off = if self.af_header { 0 } else { HEADROOM };
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = self.fd.as_raw_fd();
            #[cfg(target_vendor = "apple")]
            let r = platform::recv_batch_x(fd, batch);
            #[cfg(not(target_vendor = "apple"))]
            let r = recv_batch_read(fd, batch, off);
            match r {
                Ok(0) => {
                    guard.clear_ready();
                    continue;
                }
                Ok(n) => {
                    for i in 0..n {
                        batch.lens[i] = batch.lens[i].saturating_sub(if self.af_header { HEADROOM } else { 0 });
                    }
                    let _ = off;
                    batch.adapt(n);
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Receive one packet into `buf[HEADROOM..]`; returns its length.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let off = if self.af_header { 0 } else { HEADROOM };
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| {
                // SAFETY: reading into a valid, sized buffer.
                let n = unsafe { libc::read(fd.as_raw_fd(), buf[off..].as_mut_ptr().cast(), buf.len() - off) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) if self.af_header => return Ok(n.saturating_sub(HEADROOM)),
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Non-blocking send of `buf[HEADROOM..HEADROOM + len]`. `WouldBlock`
    /// means the interface queue is full: the packet is dropped, which TCP
    /// and UDP both tolerate.
    pub fn try_send(&self, buf: &mut [u8], len: usize) -> io::Result<()> {
        let start = self.frame(buf, len);
        // SAFETY: writing from a valid buffer range.
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                buf[start..].as_ptr().cast(),
                HEADROOM + len - start,
            )
        };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Send, waiting for writability instead of dropping.
    pub async fn send(&self, buf: &mut [u8], len: usize) -> io::Result<()> {
        let start = self.frame(buf, len);
        let frame = &buf[start..HEADROOM + len];
        self.fd
            .async_io(Interest::WRITABLE, |fd| {
                // SAFETY: as above.
                let n = unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
            })
            .await
    }

    fn frame(&self, buf: &mut [u8], _len: usize) -> usize {
        if !self.af_header {
            return HEADROOM;
        }
        let family: u32 = match buf[HEADROOM] >> 4 {
            6 => AF_INET6_DARWIN,
            _ => libc::AF_INET as u32,
        };
        buf[..HEADROOM].copy_from_slice(&family.to_be_bytes());
        0
    }
}

/// Reusable receive buffers for `Device::recv_batch`.
pub struct RecvBatch {
    bufs: Vec<Vec<u8>>,
    lens: Vec<usize>,
    target: usize,
    min: usize,
}

impl RecvBatch {
    /// `max` buffers of `HEADROOM + mtu` bytes; the batch size adapts
    /// between `min` and `max` with load (recvmsg_x walks every slot it is
    /// given, so oversizing it costs CPU when idle-ish).
    pub fn new(min: usize, max: usize, mtu: usize) -> Self {
        Self {
            bufs: (0..max).map(|_| vec![0u8; HEADROOM + mtu]).collect(),
            lens: vec![0; max],
            target: min,
            min,
        }
    }

    pub fn target(&self) -> usize {
        self.target
    }

    /// The i-th received packet's buffer (packet at `[HEADROOM..HEADROOM + len(i)]`).
    pub fn buf(&mut self, i: usize) -> &mut [u8] {
        &mut self.bufs[i]
    }

    pub fn len(&self, i: usize) -> usize {
        self.lens[i]
    }

    fn adapt(&mut self, got: usize) {
        if got >= self.target {
            self.target = (self.target * 2).min(self.bufs.len());
        } else if got * 2 < self.target {
            self.target = (self.target / 2).max(self.min);
        }
    }
}

#[cfg(not(target_vendor = "apple"))]
fn recv_batch_read(fd: RawFd, batch: &mut RecvBatch, off: usize) -> io::Result<usize> {
    let mut n = 0;
    while n < batch.target {
        let buf = &mut batch.bufs[n][off..];
        // SAFETY: reading into a valid, sized buffer.
        let r = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if n > 0 && e.kind() == io::ErrorKind::WouldBlock {
                break; // readiness stays set; the next call sees EAGAIN and clears it
            }
            return Err(e);
        }
        batch.lens[n] = r as usize;
        n += 1;
    }
    Ok(n)
}

/// `AF_INET6` on Darwin (not Linux's 10).
const AF_INET6_DARWIN: u32 = 30;

fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: `OwnedFd` closes only on drop, after the registration (owned by
    // the same AsyncFd) is gone; nothing else holds this descriptor.
    unsafe { AsyncFd::register(fd) }.map_err(|e| e.into())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain fcntl on a valid fd.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The interface and gateway currently carrying the default route, so
/// outbound sockets can be pinned to it once our routes take over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub interface: String,
    pub gateway: Option<std::net::IpAddr>,
}

pub fn default_route() -> Option<DefaultRoute> {
    platform::default_route()
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CStr;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use ipnet::IpNet;

    use super::{DefaultRoute, DeviceConfig};

    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const TUNGETIFF: libc::c_ulong = 0x800454d2;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    struct IfReqFlags {
        name: [u8; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    #[repr(C)]
    struct IfReqAddr {
        name: [u8; libc::IFNAMSIZ],
        addr: libc::sockaddr_in,
        _pad: [u8; 8],
    }

    #[repr(C)]
    struct IfReqInt {
        name: [u8; libc::IFNAMSIZ],
        value: libc::c_int,
        _pad: [u8; 20],
    }

    fn ifname(name: &str) -> io::Result<[u8; libc::IFNAMSIZ]> {
        let mut out = [0u8; libc::IFNAMSIZ];
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"));
        }
        out[..name.len()].copy_from_slice(name.as_bytes());
        Ok(out)
    }

    fn check(r: libc::c_int) -> io::Result<()> {
        if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    fn sock(family: libc::c_int) -> io::Result<OwnedFd> {
        // SAFETY: plain socket(2).
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh fd.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn sin(ip: Ipv4Addr) -> libc::sockaddr_in {
        // SAFETY: zeroed POD.
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        a.sin_family = libc::AF_INET as libc::sa_family_t;
        a.sin_addr.s_addr = u32::from(ip).to_be();
        a
    }

    pub fn tune(_fd: RawFd) {}

    pub fn fd_name(fd: RawFd) -> Option<String> {
        let mut req = IfReqFlags {
            name: [0; libc::IFNAMSIZ],
            flags: 0,
            _pad: [0; 22],
        };
        // SAFETY: ioctl with a correctly sized ifreq.
        if unsafe { libc::ioctl(fd, TUNGETIFF, &mut req) } < 0 {
            return None;
        }
        CStr::from_bytes_until_nul(&req.name)
            .ok()
            .map(|c| c.to_string_lossy().into_owned())
    }

    pub fn create(cfg: &DeviceConfig) -> io::Result<(OwnedFd, String)> {
        // SAFETY: open(2) of a static path.
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh fd.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut req = IfReqFlags {
            name: ifname(cfg.name.as_deref().unwrap_or(""))?,
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        // SAFETY: TUNSETIFF with a valid ifreq.
        check(unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut req) })?;
        let name = CStr::from_bytes_until_nul(&req.name)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .into_owned();
        configure(&name, cfg)?;
        Ok((fd, name))
    }

    fn configure(name: &str, cfg: &DeviceConfig) -> io::Result<()> {
        let s4 = sock(libc::AF_INET)?;
        let n = ifname(name)?;
        let mut mtu = IfReqInt {
            name: n,
            value: cfg.mtu as libc::c_int,
            _pad: [0; 20],
        };
        // SAFETY: SIOCSIFMTU with ifreq.
        check(unsafe { libc::ioctl(s4.as_raw_fd(), libc::SIOCSIFMTU, &mut mtu) })?;
        for net in &cfg.address {
            match net {
                IpNet::V4(v4) => {
                    let mut r = IfReqAddr {
                        name: n,
                        addr: sin(v4.addr()),
                        _pad: [0; 8],
                    };
                    // SAFETY: SIOCSIFADDR / SIOCSIFNETMASK with ifreq.
                    check(unsafe { libc::ioctl(s4.as_raw_fd(), libc::SIOCSIFADDR, &mut r) })?;
                    r.addr = sin(v4.netmask());
                    check(unsafe { libc::ioctl(s4.as_raw_fd(), libc::SIOCSIFNETMASK, &mut r) })?;
                }
                IpNet::V6(v6) => {
                    let s6 = sock(libc::AF_INET6)?;
                    let mut r = libc::in6_ifreq {
                        ifr6_addr: libc::in6_addr {
                            s6_addr: v6.addr().octets(),
                        },
                        ifr6_prefixlen: v6.prefix_len() as u32,
                        ifr6_ifindex: index(name)?,
                    };
                    // SAFETY: SIOCSIFADDR on an AF_INET6 socket takes in6_ifreq.
                    check(unsafe { libc::ioctl(s6.as_raw_fd(), libc::SIOCSIFADDR, &mut r) })?;
                }
            }
        }
        let mut f = IfReqFlags {
            name: n,
            flags: 0,
            _pad: [0; 22],
        };
        // SAFETY: get/set flags with ifreq.
        check(unsafe { libc::ioctl(s4.as_raw_fd(), libc::SIOCGIFFLAGS, &mut f) })?;
        f.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        check(unsafe { libc::ioctl(s4.as_raw_fd(), libc::SIOCSIFFLAGS, &mut f) })?;

        let gw = default_route().and_then(|d| d.gateway.map(|g| (d.interface, g)));
        for net in &cfg.exclude {
            match (&gw, net) {
                (Some((dev, IpAddr::V4(g))), IpNet::V4(_)) => add_route(&s4, net, Some(*g), dev)?,
                _ => tracing::warn!(%net, "route_exclude_address: no IPv4 default gateway to pin it to"),
            }
        }
        for net in &cfg.routes {
            add_route(&s4, net, None, name)?;
        }
        Ok(())
    }

    fn index(name: &str) -> io::Result<i32> {
        let c = std::ffi::CString::new(name).map_err(io::Error::other)?;
        // SAFETY: valid C string.
        match unsafe { libc::if_nametoindex(c.as_ptr()) } {
            0 => Err(io::Error::last_os_error()),
            i => Ok(i as i32),
        }
    }

    fn add_route(s4: &OwnedFd, net: &IpNet, gateway: Option<Ipv4Addr>, dev: &str) -> io::Result<()> {
        match net {
            IpNet::V4(v4) => {
                // SAFETY: zeroed POD, then fields set below.
                let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
                let put = |dst: &mut libc::sockaddr, ip: Ipv4Addr| {
                    let a = sin(ip);
                    // SAFETY: sockaddr_in fits in sockaddr.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            (&a as *const libc::sockaddr_in).cast::<u8>(),
                            (dst as *mut libc::sockaddr).cast::<u8>(),
                            std::mem::size_of::<libc::sockaddr_in>(),
                        )
                    };
                };
                put(&mut rt.rt_dst, v4.network());
                put(&mut rt.rt_genmask, v4.netmask());
                rt.rt_flags = libc::RTF_UP;
                if let Some(g) = gateway {
                    put(&mut rt.rt_gateway, g);
                    rt.rt_flags |= libc::RTF_GATEWAY;
                }
                let dev_c = std::ffi::CString::new(dev).map_err(io::Error::other)?;
                rt.rt_dev = dev_c.as_ptr().cast_mut();
                // SAFETY: SIOCADDRT with a filled rtentry; dev_c outlives the call.
                let r = unsafe { libc::ioctl(s4.as_raw_fd(), libc::SIOCADDRT, &rt) };
                match r {
                    0 => Ok(()),
                    _ if io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) => Ok(()),
                    _ => Err(io::Error::last_os_error()),
                }
            }
            IpNet::V6(v6) => {
                let s6 = sock(libc::AF_INET6)?;
                // SAFETY: zeroed POD.
                let mut rt: In6RtMsg = unsafe { std::mem::zeroed() };
                rt.rtmsg_dst = libc::in6_addr {
                    s6_addr: v6.network().octets(),
                };
                rt.rtmsg_dst_len = v6.prefix_len() as u16;
                rt.rtmsg_flags = libc::RTF_UP as u32;
                rt.rtmsg_metric = 1;
                rt.rtmsg_ifindex = index(dev)?;
                // SAFETY: SIOCADDRT on an AF_INET6 socket takes in6_rtmsg.
                let r = unsafe { libc::ioctl(s6.as_raw_fd(), libc::SIOCADDRT, &rt) };
                match r {
                    0 => Ok(()),
                    _ if io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) => Ok(()),
                    _ => Err(io::Error::last_os_error()),
                }
            }
        }
    }

    /// `struct in6_rtmsg` (linux/ipv6_route.h); libc keeps its fields private.
    #[repr(C)]
    struct In6RtMsg {
        rtmsg_dst: libc::in6_addr,
        rtmsg_src: libc::in6_addr,
        rtmsg_gateway: libc::in6_addr,
        rtmsg_type: u32,
        rtmsg_dst_len: u16,
        rtmsg_src_len: u16,
        rtmsg_metric: u32,
        rtmsg_info: libc::c_ulong,
        rtmsg_flags: u32,
        rtmsg_ifindex: libc::c_int,
    }

    pub fn default_route() -> Option<DefaultRoute> {
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        text.lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() > 7 && f[1] == "00000000" && f[7] == "00000000").then(|| {
                    let metric: u32 = f[6].parse().unwrap_or(u32::MAX);
                    let gw = u32::from_str_radix(f[2], 16)
                        .ok()
                        .map(|g| IpAddr::V4(Ipv4Addr::from(u32::from_be(g))));
                    (
                        metric,
                        DefaultRoute {
                            interface: f[0].to_owned(),
                            gateway: gw.filter(|g| !g.is_unspecified()),
                        },
                    )
                })
            })
            .min_by_key(|(m, _)| *m)
            .map(|(_, d)| d)
    }
}

#[cfg(target_vendor = "apple")]
mod platform {
    use std::io;
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::process::Command;

    use ipnet::IpNet;

    use super::{DefaultRoute, DeviceConfig};

    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    // <sys/kern_control.h>, <sys/sys_domain.h>: libc only exposes these on
    // macOS, but the kernel ABI is identical on iOS/tvOS.
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const PF_SYSTEM: libc::c_int = 32;
    const AF_SYS_CONTROL: u16 = 2;
    const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [libc::c_char; 96],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    const UTUN_OPT_MAX_PENDING_PACKETS: libc::c_int = 16;
    const SYS_RECVMSG_X: libc::c_int = 480;

    /// Raise the control socket's receive buffer, then let utun queue as
    /// many packets as that buffer holds (capped at 64) so bursts don't
    /// pause the interface. Values follow sing-tun's measurements.
    pub fn tune(fd: RawFd) {
        let mut size: libc::c_int = 8 << 20;
        while size >= 1 << 20 {
            // SAFETY: setsockopt with an int.
            let r = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&size as *const libc::c_int).cast(),
                    4,
                )
            };
            if r == 0 {
                break;
            }
            size /= 2;
        }
        let mut cur: libc::c_int = 0;
        let mut len: libc::socklen_t = 4;
        // SAFETY: getsockopt into an int.
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&mut cur as *mut libc::c_int).cast(),
                &mut len,
            )
        } == 0;
        let rcvbuf = if ok && cur > 0 { cur } else { 512 << 10 };
        let pending: libc::c_int = (rcvbuf / 8 * 7 / (65535 + 4)).clamp(1, 64);
        // SAFETY: as above. Failure (old kernels) just keeps the default.
        unsafe {
            libc::setsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_MAX_PENDING_PACKETS,
                (&pending as *const libc::c_int).cast(),
                4,
            );
        }
    }

    /// `struct msghdr_x` (<sys/socket.h>, private).
    #[repr(C)]
    struct MsgHdrX {
        msg: libc::msghdr,
        datalen: libc::size_t,
    }

    /// One `recvmsg_x` for up to `batch.target` packets.
    pub fn recv_batch_x(fd: RawFd, batch: &mut super::RecvBatch) -> io::Result<usize> {
        let n = batch.target;
        let mut iov: [libc::iovec; 64] = unsafe { std::mem::zeroed() };
        let mut hdrs: [MsgHdrX; 64] = unsafe { std::mem::zeroed() };
        for i in 0..n {
            iov[i] = libc::iovec {
                iov_base: batch.bufs[i].as_mut_ptr().cast(),
                iov_len: batch.bufs[i].len(),
            };
            // Older kernels validate the whole header, so it must be zeroed (it is).
            hdrs[i].msg.msg_iov = &mut iov[i];
            hdrs[i].msg.msg_iovlen = 1;
        }
        // SAFETY: recvmsg_x(fd, msghdr_x *, count, flags); arrays outlive the call.
        #[allow(deprecated)]
        let r = unsafe {
            libc::syscall(
                SYS_RECVMSG_X,
                fd,
                hdrs.as_mut_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        let got = r as usize;
        for i in 0..got {
            batch.lens[i] = if hdrs[i].msg.msg_flags & libc::MSG_TRUNC != 0 {
                0
            } else {
                hdrs[i].datalen
            };
        }
        Ok(got)
    }

    pub fn fd_name(fd: RawFd) -> Option<String> {
        let mut buf = [0u8; libc::IFNAMSIZ];
        let mut len = buf.len() as libc::socklen_t;
        // SAFETY: getsockopt into a sized buffer.
        let r = unsafe { libc::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, buf.as_mut_ptr().cast(), &mut len) };
        if r < 0 {
            return None;
        }
        std::ffi::CStr::from_bytes_until_nul(&buf)
            .ok()
            .map(|c| c.to_string_lossy().into_owned())
    }

    pub fn create(cfg: &DeviceConfig) -> io::Result<(OwnedFd, String)> {
        if !cfg!(target_os = "macos") {
            // iOS/tvOS: only a Network Extension may own a tunnel; adopt its fd.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "create a tunnel via NEPacketTunnelProvider and pass its fd",
            ));
        }
        // SAFETY: socket(2).
        let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh fd.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zeroed POD.
        let mut info: CtlInfo = unsafe { std::mem::zeroed() };
        for (d, s) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
            *d = *s as libc::c_char;
        }
        // SAFETY: CTLIOCGINFO with ctl_info.
        if unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let unit = match cfg
            .name
            .as_deref()
            .and_then(|n| n.strip_prefix("utun"))
            .and_then(|n| n.parse::<u32>().ok())
        {
            Some(n) => n + 1,
            None => 0, // kernel picks
        };
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: PF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };
        // SAFETY: connect with a sockaddr_ctl.
        let r = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&addr as *const SockaddrCtl).cast(),
                std::mem::size_of::<SockaddrCtl>() as u32,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        let name = fd_name(fd.as_raw_fd()).ok_or_else(|| io::Error::other("utun: no interface name"))?;
        configure(&name, cfg)?;
        Ok((fd, name))
    }

    fn run(cmd: &str, args: &[String]) -> io::Result<()> {
        let st = Command::new(cmd).args(args).status()?;
        if st.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("{cmd} {} failed: {st}", args.join(" "))))
        }
    }

    fn configure(name: &str, cfg: &DeviceConfig) -> io::Result<()> {
        for net in &cfg.address {
            match net {
                IpNet::V4(v4) => {
                    // Point-to-point: peer is the next address, as sing-box does.
                    let peer = std::net::Ipv4Addr::from(u32::from(v4.addr()).wrapping_add(1));
                    run(
                        "ifconfig",
                        &[
                            name.into(),
                            "inet".into(),
                            v4.addr().to_string(),
                            peer.to_string(),
                            "netmask".into(),
                            v4.netmask().to_string(),
                            "mtu".into(),
                            cfg.mtu.to_string(),
                            "up".into(),
                        ],
                    )?;
                }
                IpNet::V6(v6) => run(
                    "ifconfig",
                    &[
                        name.into(),
                        "inet6".into(),
                        v6.addr().to_string(),
                        "prefixlen".into(),
                        v6.prefix_len().to_string(),
                        "up".into(),
                    ],
                )?,
            }
        }
        let gw = default_route();
        for net in &cfg.exclude {
            if let Some(DefaultRoute { gateway: Some(g), .. }) = &gw {
                let fam = if net.addr().is_ipv4() { "-inet" } else { "-inet6" };
                run(
                    "route",
                    &["-n".into(), "add".into(), fam.into(), net.to_string(), g.to_string()],
                )?;
            }
        }
        for net in &cfg.routes {
            let fam = if net.addr().is_ipv4() { "-inet" } else { "-inet6" };
            run(
                "route",
                &[
                    "-n".into(),
                    "add".into(),
                    fam.into(),
                    net.to_string(),
                    "-interface".into(),
                    name.into(),
                ],
            )?;
        }
        Ok(())
    }

    pub fn default_route() -> Option<DefaultRoute> {
        let out = Command::new("route").args(["-n", "get", "default"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let field = |k: &str| {
            text.lines()
                .find_map(|l| l.trim().strip_prefix(k).map(|v| v.trim().to_owned()))
        };
        Some(DefaultRoute {
            interface: field("interface:")?,
            gateway: field("gateway:").and_then(|g| g.parse::<IpAddr>().ok()),
        })
    }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
mod platform {
    use std::io;
    use std::os::fd::{OwnedFd, RawFd};

    use super::{DefaultRoute, DeviceConfig};

    pub fn tune(_: RawFd) {}
    pub fn fd_name(_: RawFd) -> Option<String> {
        None
    }
    pub fn create(_: &DeviceConfig) -> io::Result<(OwnedFd, String)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "creating a TUN interface is not supported on this platform",
        ))
    }
    pub fn default_route() -> Option<DefaultRoute> {
        None
    }
}
