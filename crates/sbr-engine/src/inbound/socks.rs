use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use sbr_core::{BoxFuture, Destination, Metadata, Network};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use super::{Context, within};
use crate::dispatch::{InboundStream, OpenError};
use crate::socks5::*;
use crate::udp::{UdpPacket, UdpWriteBack};

/// The client after a CONNECT request: success is sent lazily (when the
/// engine first needs the client's bytes, or once the outbound is up), as
/// sing-box does, so sniffing can see the first payload.
struct SocksClient {
    s: TcpStream,
    replied: bool,
}

impl InboundStream for SocksClient {
    fn ready(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            if !self.replied {
                self.replied = true;
                write_reply(&mut self.s, REP_OK).await?;
            }
            Ok(())
        })
    }
    fn fail<'a>(&'a mut self, err: &'a OpenError) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            if self.replied {
                return Ok(());
            }
            self.replied = true;
            match err {
                OpenError::Rejected { drop: true } => Ok(()),
                OpenError::Rejected { drop: false } => write_reply(&mut self.s, REP_NOT_ALLOWED).await,
                OpenError::Io(e) => write_reply(&mut self.s, reply_code(e)).await,
            }
        })
    }
}

impl AsyncRead for SocksClient {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_read(cx, buf)
    }
}

impl AsyncWrite for SocksClient {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.s).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_shutdown(cx)
    }
}

pub async fn handle(ctx: &Context, mut s: TcpStream, deadline: Instant) -> io::Result<()> {
    let source = s.peer_addr()?;
    let Some((cmd, destination, user)) = within(deadline, handshake(ctx, &mut s)).await? else {
        return Ok(());
    };
    match cmd {
        CMD_CONNECT => {
            let mut meta = Metadata::new(ctx.tag.clone(), ctx.type_name(), Network::Tcp, source, destination);
            meta.user = user;
            ctx.engine.route_tcp(meta, SocksClient { s, replied: false }).await
        }
        CMD_UDP_ASSOCIATE => udp_associate(ctx, s, source).await,
        _ => {
            write_reply(&mut s, REP_CMD_UNSUPPORTED).await?;
            Ok(())
        }
    }
}

/// Greeting, authentication and request: the command, its address and the
/// authenticated user. `None` when no offered method is acceptable.
async fn handshake(ctx: &Context, s: &mut TcpStream) -> io::Result<Option<(u8, Destination, Option<Arc<str>>)>> {
    if s.read_u8().await? != VER {
        return Err(invalid("not SOCKS5"));
    }
    let n = s.read_u8().await? as usize;
    let mut methods = [0u8; 255];
    s.read_exact(&mut methods[..n]).await?;
    let methods = &methods[..n];

    let mut user: Option<Arc<str>> = None;
    if ctx.users.is_empty() {
        if !methods.contains(&NO_AUTH) {
            s.write_all(&[VER, NO_ACCEPTABLE]).await?;
            return Ok(None);
        }
        s.write_all(&[VER, NO_AUTH]).await?;
    } else {
        if !methods.contains(&USER_PASS) {
            s.write_all(&[VER, NO_ACCEPTABLE]).await?;
            return Ok(None);
        }
        s.write_all(&[VER, USER_PASS]).await?;
        let _ver = s.read_u8().await?;
        let ulen = s.read_u8().await? as usize;
        let mut u = vec![0; ulen];
        s.read_exact(&mut u).await?;
        let plen = s.read_u8().await? as usize;
        let mut p = vec![0; plen];
        s.read_exact(&mut p).await?;
        let (u, p) = (String::from_utf8_lossy(&u), String::from_utf8_lossy(&p));
        if !ctx.check_user(&u, &p) {
            s.write_all(&[1, 1]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("socks auth failed for {u:?}"),
            ));
        }
        s.write_all(&[1, 0]).await?;
        user = Some(u.as_ref().into());
    }

    let mut head = [0u8; 3];
    s.read_exact(&mut head).await?;
    let destination = read_addr(s).await?;
    Ok(Some((head[1], destination, user)))
}

/// RFC 1928 §7. The association lives as long as the TCP control connection.
async fn udp_associate(ctx: &Context, mut ctrl: TcpStream, client: SocketAddr) -> io::Result<()> {
    let local = ctrl.local_addr()?;
    let sock = Arc::new(UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?);
    let bound = sock.local_addr()?;
    let mut rep = vec![VER, REP_OK, 0];
    write_addr(&mut rep, &Destination::from(bound))?;
    ctrl.write_all(&rep).await?;

    let socks_back = Arc::new(SocksUdpBack {
        sock: sock.clone(),
        closed: AtomicBool::new(false),
    });
    let back: Arc<dyn UdpWriteBack> = socks_back.clone();
    let relay = async {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            // Only the client's host may use the association.
            if from.ip() != client.ip() && !client.ip().is_unspecified() {
                continue;
            }
            let pkt = &buf[..n];
            if n < 4 || pkt[2] != 0 {
                continue; // fragmented datagrams are optional and unsupported
            }
            let mut cur = std::io::Cursor::new(&pkt[3..]);
            let Ok(destination) = read_addr(&mut cur).await else {
                continue;
            };
            let off = 3 + cur.position() as usize;
            ctx.engine.handle_udp(
                &ctx.tag,
                ctx.type_name(),
                UdpPacket {
                    source: from,
                    destination,
                    payload: Bytes::copy_from_slice(&pkt[off..]),
                },
                back.clone(),
            );
        }
        #[allow(unreachable_code)]
        io::Result::Ok(())
    };
    let mut sink = [0u8; 64];
    let r = tokio::select! {
        r = relay => r,
        _ = async { while matches!(ctrl.read(&mut sink).await, Ok(n) if n > 0) {} } => Ok(()),
    };
    // The NAT sessions hold the socket through `back`: refusing their
    // replies ends them, and closes the socket, now rather than after their
    // idle timeout.
    socks_back.closed.store(true, Ordering::Relaxed);
    r
}

struct SocksUdpBack {
    sock: Arc<UdpSocket>,
    /// The association has ended.
    closed: AtomicBool,
}

impl UdpWriteBack for SocksUdpBack {
    fn write_back(&self, payload: &[u8], from: &Destination, to: SocketAddr) -> io::Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut out = Vec::with_capacity(payload.len() + 22);
        out.extend_from_slice(&[0, 0, 0]);
        write_addr(&mut out, from)?;
        out.extend_from_slice(payload);
        // Non-blocking: if the socket buffer is full the datagram is dropped.
        match self.sock.try_send_to(&out, to) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
}
