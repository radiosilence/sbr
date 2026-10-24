//! SOCKS5 wire format (RFC 1928 / RFC 1929), shared by the inbound and outbound.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sbr_core::{Destination, Host};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VER: u8 = 5;
pub const NO_AUTH: u8 = 0;
pub const USER_PASS: u8 = 2;
pub const NO_ACCEPTABLE: u8 = 0xff;
pub const CMD_CONNECT: u8 = 1;
pub const CMD_UDP_ASSOCIATE: u8 = 3;

pub const REP_OK: u8 = 0;
pub const REP_FAILURE: u8 = 1;
pub const REP_NOT_ALLOWED: u8 = 2;
pub const REP_NET_UNREACHABLE: u8 = 3;
pub const REP_HOST_UNREACHABLE: u8 = 4;
pub const REP_REFUSED: u8 = 5;
pub const REP_TTL: u8 = 6;
pub const REP_CMD_UNSUPPORTED: u8 = 7;

pub fn reply_code(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => REP_REFUSED,
        io::ErrorKind::TimedOut => REP_TTL,
        io::ErrorKind::HostUnreachable => REP_HOST_UNREACHABLE,
        io::ErrorKind::NetworkUnreachable => REP_NET_UNREACHABLE,
        io::ErrorKind::NotFound => REP_HOST_UNREACHABLE,
        io::ErrorKind::PermissionDenied => REP_NOT_ALLOWED,
        _ => REP_FAILURE,
    }
}

pub async fn read_addr<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Destination> {
    let atyp = r.read_u8().await?;
    let host = match atyp {
        1 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        4 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(b)).to_canonical())
        }
        3 => {
            let len = r.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            let s = String::from_utf8(b).map_err(|_| invalid("non-UTF-8 domain"))?;
            return Ok(Destination::from_host_port(&s, r.read_u16().await?));
        }
        _ => return Err(invalid("bad address type")),
    };
    Ok(Destination::new(host, r.read_u16().await?))
}

pub fn write_addr(buf: &mut Vec<u8>, d: &Destination) -> io::Result<()> {
    match &d.host {
        Host::Ip(IpAddr::V4(ip)) => {
            buf.push(1);
            buf.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        Host::Domain(name) => {
            let len = u8::try_from(name.len()).map_err(|_| invalid("domain too long"))?;
            buf.push(3);
            buf.push(len);
            buf.extend_from_slice(name.as_bytes());
        }
    }
    buf.extend_from_slice(&d.port.to_be_bytes());
    Ok(())
}

pub async fn write_reply<W: AsyncWrite + Unpin>(w: &mut W, rep: u8) -> io::Result<()> {
    // We never expose the outbound's bound address; 0.0.0.0:0 is what
    // sing-box and most proxies send, and clients ignore it for CONNECT.
    w.write_all(&[VER, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    w.flush().await
}

/// Client side: greeting, optional auth, CONNECT. Leaves `s` ready for payload.
pub async fn client_connect<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    dest: &Destination,
    auth: Option<(&str, &str)>,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(300);
    buf.extend_from_slice(&[VER, 1, if auth.is_some() { USER_PASS } else { NO_AUTH }]);
    s.write_all(&buf).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != VER {
        return Err(invalid("server is not SOCKS5"));
    }
    match (sel[1], auth) {
        (NO_AUTH, _) => {}
        (USER_PASS, Some((u, p))) => {
            buf.clear();
            buf.push(1);
            for f in [u, p] {
                buf.push(u8::try_from(f.len()).map_err(|_| invalid("credential too long"))?);
                buf.extend_from_slice(f.as_bytes());
            }
            s.write_all(&buf).await?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 authentication failed",
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 server rejected our auth methods",
            ));
        }
    }
    buf.clear();
    buf.extend_from_slice(&[VER, CMD_CONNECT, 0]);
    write_addr(&mut buf, dest)?;
    s.write_all(&buf).await?;
    let mut head = [0u8; 3];
    s.read_exact(&mut head).await?;
    if head[1] != REP_OK {
        return Err(io::Error::new(
            rep_kind(head[1]),
            format!("SOCKS5 server replied {}", head[1]),
        ));
    }
    read_addr(s).await?; // bound address, unused
    Ok(())
}

fn rep_kind(rep: u8) -> io::ErrorKind {
    match rep {
        REP_NOT_ALLOWED => io::ErrorKind::PermissionDenied,
        REP_NET_UNREACHABLE => io::ErrorKind::NetworkUnreachable,
        REP_HOST_UNREACHABLE => io::ErrorKind::HostUnreachable,
        REP_REFUSED => io::ErrorKind::ConnectionRefused,
        REP_TTL => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other,
    }
}

pub fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}
