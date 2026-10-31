//! Stream and datagram handles inside the tunnel: TCP on sbr-tun's stack,
//! UDP on smoltcp sockets.

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;

use sbr_core::{BoxFuture, Destination, PacketConn};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::IpAddress;

use super::stack::Shared;

/// A TCP connection inside the tunnel, on the device task's stack.
pub async fn tcp_connect(shared: &Shared, ip: IpAddr, port: u16) -> io::Result<sbr_tun::tcp::Stream> {
    let local = shared.local_ip(ip)?;
    shared
        .tcp
        .connect(local, SocketAddr::new(ip, port))
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("wireguard: connect {ip}:{port}: {e}")))
}

/// A UDP socket inside the tunnel. IP destinations only; the outbound
/// resolves domains before they get here.
pub struct WgUdp {
    shared: Arc<Shared>,
    handle: SocketHandle,
    v6: bool,
}

impl WgUdp {
    pub fn bind(shared: Arc<Shared>, family: IpAddr) -> io::Result<Self> {
        let local = shared.local_ip(family)?;
        let handle = shared.stack.lock().unwrap().udp_bind(local)?;
        Ok(Self {
            shared,
            handle,
            v6: family.is_ipv6(),
        })
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    pub async fn send(&self, payload: &[u8], to: SocketAddr) -> io::Result<()> {
        poll_fn(|cx| {
            let mut st = self.shared.stack.lock().unwrap();
            let s = st.sockets.get_mut::<udp::Socket>(self.handle);
            if !s.is_open() {
                // Closed with the device it belonged to.
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            match s.send_slice(payload, (IpAddress::from(to.ip()), to.port())) {
                Ok(()) => {
                    drop(st);
                    self.shared.kick.notify_one();
                    Poll::Ready(Ok(()))
                }
                Err(udp::SendError::BufferFull) => {
                    s.register_send_waker(cx.waker());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(io::Error::other(format!("wireguard: udp send: {e}")))),
            }
        })
        .await
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| {
            let mut st = self.shared.stack.lock().unwrap();
            let s = st.sockets.get_mut::<udp::Socket>(self.handle);
            if !s.is_open() {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            match s.recv_slice(buf) {
                Ok((n, meta)) => {
                    let ip: IpAddr = meta.endpoint.addr.into();
                    Poll::Ready(Ok((n, SocketAddr::new(ip.to_canonical(), meta.endpoint.port))))
                }
                Err(udp::RecvError::Truncated) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "wireguard: datagram larger than the receive buffer",
                ))),
                Err(udp::RecvError::Exhausted) => {
                    s.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await
    }
}

impl Drop for WgUdp {
    fn drop(&mut self) {
        self.shared.stack.lock().unwrap().release_udp(self.handle);
    }
}

pub type Resolver = Arc<dyn Fn(&Destination) -> BoxFuture<'static, io::Result<IpAddr>> + Send + Sync>;

/// `PacketConn` over a tunnel UDP socket, resolving domains with the
/// engine's DNS (outside the tunnel, like sing-box's endpoint).
pub struct WgPacketConn {
    pub sock: WgUdp,
    pub resolve: Resolver,
}

impl PacketConn for WgPacketConn {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let ip = match dest.ip() {
                Some(ip) => ip,
                None => (self.resolve)(dest).await?,
            };
            if ip.is_ipv6() != self.sock.is_v6() {
                // One socket per family, like a plain UDP socket of the first family.
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("wireguard: {ip} is the other address family"),
                ));
            }
            self.sock.send(buf, SocketAddr::new(ip, dest.port)).await
        })
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(async move {
            let (n, from) = self.sock.recv(buf).await?;
            Ok((n, Destination::from(from)))
        })
    }
}
