//! Stream and datagram handles onto smoltcp sockets inside the tunnel.

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use sbr_core::{BoxFuture, Destination, PacketConn};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::IpAddress;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::stack::Shared;

pub struct WgTcp {
    shared: Arc<Shared>,
    handle: SocketHandle,
    port: u16,
    established: bool,
}

impl WgTcp {
    pub async fn connect(shared: Arc<Shared>, ip: IpAddr, port: u16) -> io::Result<Self> {
        let (handle, lport) = shared.stack.lock().unwrap().tcp_connect(ip, port)?;
        shared.kick.notify_one();
        let mut conn = Self {
            shared,
            handle,
            port: lport,
            established: false,
        };
        poll_fn(|cx| {
            let mut st = conn.shared.stack.lock().unwrap();
            let s = st.sockets.get_mut::<tcp::Socket>(conn.handle);
            match s.state() {
                tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
                tcp::State::Closed | tcp::State::TimeWait => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("wireguard: connection to {ip}:{port} refused"),
                ))),
                _ => {
                    // The send waker fires on every state change.
                    s.register_send_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await?;
        conn.established = true;
        Ok(conn)
    }
}

impl Drop for WgTcp {
    fn drop(&mut self) {
        let mut st = self.shared.stack.lock().unwrap();
        if self.established {
            st.release_tcp(self.handle, self.port);
        } else {
            st.abort_tcp(self.handle, self.port);
        }
        drop(st);
        self.shared.kick.notify_one();
    }
}

impl AsyncRead for WgTcp {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut st = self.shared.stack.lock().unwrap();
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        if s.can_recv() {
            let queued = s.recv_queue();
            let cap = s.recv_capacity();
            let n = s.recv_slice(buf.initialize_unfilled()).unwrap_or(0);
            buf.advance(n);
            drop(st);
            // Only a window that had shrunk needs an update sent promptly;
            // otherwise the next poll carries it.
            if queued * 2 >= cap {
                self.shared.kick.notify_one();
            }
            return Poll::Ready(Ok(()));
        }
        if !s.may_recv() {
            // FIN, or a reset/timeout (smoltcp doesn't tell them apart): EOF.
            return Poll::Ready(Ok(()));
        }
        s.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for WgTcp {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut st = self.shared.stack.lock().unwrap();
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        if !s.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if s.can_send() {
            let n = s.send_slice(buf).unwrap_or(0);
            drop(st);
            self.shared.kick.notify_one();
            return Poll::Ready(Ok(n));
        }
        s.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.shared.stack.lock().unwrap();
        st.sockets.get_mut::<tcp::Socket>(self.handle).close();
        drop(st);
        self.shared.kick.notify_one();
        Poll::Ready(Ok(()))
    }
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
        let handle = shared.stack.lock().unwrap().udp_bind(family)?;
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
