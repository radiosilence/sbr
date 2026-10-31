//! sing-box UDP-over-TCP (`sing/common/uot`), client side.
//!
//! The proxy protocol opens a TCP stream to a magic domain; the server
//! recognises it and relays datagrams framed as
//! `[address] length(u16be) payload`. Version 2 starts with a request
//! (`is_connect` + SOCKS address) that sbr sends together with the first
//! datagram, so the association costs no extra round trip.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sbr_core::{BoxFuture, Destination, Host, PacketConn, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::socks5;

pub const MAGIC_V2: &str = "sp.v2.udp-over-tcp.arpa";
pub const MAGIC_V1: &str = "sp.udp-over-tcp.arpa";

/// Where the proxy protocol must "connect" to start a UoT session.
pub fn request_destination(version: u8) -> Destination {
    let magic = if version == 1 { MAGIC_V1 } else { MAGIC_V2 };
    Destination::new(Host::Domain(magic.into()), 0)
}

/// UoT's own address encoding: family 0 = IPv4, 1 = IPv6, 2 = FQDN.
fn write_addr(buf: &mut Vec<u8>, d: &Destination) -> io::Result<()> {
    match &d.host {
        Host::Ip(IpAddr::V4(ip)) => {
            buf.push(0);
            buf.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            buf.push(1);
            buf.extend_from_slice(&ip.octets());
        }
        Host::Domain(name) => {
            let len = u8::try_from(name.len()).map_err(|_| socks5::invalid("domain too long"))?;
            buf.push(2);
            buf.push(len);
            buf.extend_from_slice(name.as_bytes());
        }
    }
    buf.extend_from_slice(&d.port.to_be_bytes());
    Ok(())
}

async fn read_addr<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<Destination> {
    let host = match r.read_u8().await? {
        0 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        1 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(b)).to_canonical())
        }
        2 => {
            let len = r.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            let s = String::from_utf8(b).map_err(|_| socks5::invalid("non-UTF-8 domain"))?;
            return Ok(Destination::from_host_port(&s, r.read_u16().await?));
        }
        _ => return Err(socks5::invalid("UoT: bad address family")),
    };
    Ok(Destination::new(host, r.read_u16().await?))
}

struct Writer {
    w: WriteHalf<Stream>,
    buf: Vec<u8>,
    /// v2 request, sent in front of the first datagram.
    request: Option<Vec<u8>>,
}

/// A full-cone UDP association carried over one stream (`is_connect = false`).
pub struct UotConn {
    reader: Mutex<BufReader<ReadHalf<Stream>>>,
    writer: Mutex<Writer>,
}

impl UotConn {
    /// `stream` must already be connected to [`request_destination`].
    pub fn new(stream: Stream, version: u8, first: &Destination) -> io::Result<Self> {
        let request = if version == 1 {
            None
        } else {
            let mut r = vec![0u8]; // is_connect = false: every datagram carries its address
            socks5::write_addr(&mut r, first)?;
            Some(r)
        };
        let (r, w) = tokio::io::split(stream);
        Ok(Self {
            // Only the small header reads use this buffer: a payload read at
            // least this long bypasses it.
            reader: Mutex::new(BufReader::with_capacity(2048, r)),
            writer: Mutex::new(Writer {
                w,
                buf: Vec::with_capacity(2048),
                request,
            }),
        })
    }
}

impl PacketConn for UotConn {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let len = u16::try_from(buf.len()).map_err(|_| socks5::invalid("UoT: datagram too large"))?;
            let mut w = self.writer.lock().await;
            let w = &mut *w;
            w.buf.clear();
            if let Some(req) = w.request.take() {
                w.buf.extend_from_slice(&req);
            }
            write_addr(&mut w.buf, dest)?;
            w.buf.extend_from_slice(&len.to_be_bytes());
            w.buf.extend_from_slice(buf);
            w.w.write_all(&w.buf).await?;
            w.w.flush().await
        })
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(async move {
            let mut r = self.reader.lock().await;
            loop {
                let from = read_addr(&mut *r).await?;
                let len = r.read_u16().await? as usize;
                if len > buf.len() {
                    // Too big for the caller: drop it and keep the session.
                    super::proto::discard(&mut *r, len).await?;
                    continue;
                }
                r.read_exact(&mut buf[..len]).await?;
                return Ok((len, from));
            }
        })
    }
}
