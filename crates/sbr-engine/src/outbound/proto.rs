//! Pieces shared by trojan / vless / vmess: address encodings, the
//! "header rides with the first write" stream, and UDP over a stream.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use sbr_core::{BoxFuture, Destination, Host, PacketConn, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

/// SOCKS5-style address: ATYP (1 v4, 3 domain, 4 v6), address, port.
pub fn put_socks_addr(out: &mut Vec<u8>, d: &Destination) {
    match &d.host {
        Host::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(name) => {
            out.push(3);
            out.push(name.len().min(255) as u8);
            out.extend_from_slice(&name.as_bytes()[..name.len().min(255)]);
        }
    }
    out.extend_from_slice(&d.port.to_be_bytes());
}

/// VMess/VLESS-style address: port, then ATYP (1 v4, 2 domain, 3 v6), address.
pub fn put_vmess_addr(out: &mut Vec<u8>, d: &Destination) {
    out.extend_from_slice(&d.port.to_be_bytes());
    match &d.host {
        Host::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            Some(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            None => {
                out.push(3);
                out.extend_from_slice(&ip.octets());
            }
        },
        Host::Domain(name) => {
            out.push(2);
            out.push(name.len().min(255) as u8);
            out.extend_from_slice(&name.as_bytes()[..name.len().min(255)]);
        }
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

/// Read an address given its type byte, in either encoding's numbering.
async fn read_host<R: AsyncRead + Unpin>(r: &mut R, atyp: u8, v4: u8, domain: u8, v6: u8) -> io::Result<Host> {
    Ok(if atyp == v4 {
        let mut b = [0u8; 4];
        r.read_exact(&mut b).await?;
        Host::Ip(Ipv4Addr::from(b).into())
    } else if atyp == v6 {
        let mut b = [0u8; 16];
        r.read_exact(&mut b).await?;
        Host::Ip(Ipv6Addr::from(b).to_canonical())
    } else if atyp == domain {
        let n = r.read_u8().await? as usize;
        let mut b = vec![0u8; n];
        r.read_exact(&mut b).await?;
        Host::Domain(String::from_utf8_lossy(&b).to_ascii_lowercase().into())
    } else {
        return Err(bad("unknown address type"));
    })
}

pub async fn read_socks_addr<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Destination> {
    let atyp = r.read_u8().await?;
    let host = read_host(r, atyp, 1, 3, 4).await?;
    Ok(Destination::new(host, r.read_u16().await?))
}

/// Parse a VMess-style address from a byte slice; returns it and its length.
pub fn parse_vmess_addr(b: &[u8]) -> io::Result<(Destination, usize)> {
    let short = || bad("short address");
    let port = u16::from_be_bytes([*b.first().ok_or_else(short)?, *b.get(1).ok_or_else(short)?]);
    let (host, n) = match *b.get(2).ok_or_else(short)? {
        1 => {
            let o: [u8; 4] = b.get(3..7).ok_or_else(short)?.try_into().unwrap();
            (Host::Ip(Ipv4Addr::from(o).into()), 7)
        }
        3 => {
            let o: [u8; 16] = b.get(3..19).ok_or_else(short)?.try_into().unwrap();
            (Host::Ip(Ipv6Addr::from(o).to_canonical()), 19)
        }
        2 => {
            let l = *b.get(3).ok_or_else(short)? as usize;
            let name = b.get(4..4 + l).ok_or_else(short)?;
            (
                Host::Domain(String::from_utf8_lossy(name).to_ascii_lowercase().into()),
                4 + l,
            )
        }
        _ => return Err(bad("unknown address type")),
    };
    Ok((Destination::new(host, port), n))
}

/// What the server sends before the payload, stripped by the first read.
pub enum Response {
    None,
    /// VLESS: version byte, addons length, addons.
    Vless,
}

/// A stream whose request header is sent together with the first payload
/// (one segment, one TLS record, no extra round trip), or on the first
/// read if the client is silent (server-first protocols), as sing-box does.
pub struct HeaderStream<S> {
    inner: S,
    header: Option<Vec<u8>>,
    wbuf: Vec<u8>,
    wpos: usize,
    vless_response: bool,
    /// The reader sent the request (client silent so far): it flushes.
    read_flushes: bool,
    resp_hdr: [u8; 2],
    resp_got: usize,
    resp_skip: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HeaderStream<S> {
    pub fn new(inner: S, header: Vec<u8>, response: Response) -> Self {
        Self {
            inner,
            header: Some(header),
            wbuf: Vec::new(),
            wpos: 0,
            vless_response: matches!(response, Response::Vless),
            read_flushes: false,
            resp_hdr: [0; 2],
            resp_got: 0,
            resp_skip: 0,
        }
    }

    fn poll_flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        if !self.wbuf.is_empty() {
            self.wbuf = Vec::new();
            self.wpos = 0;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.vless_response {
            return Poll::Ready(Ok(()));
        }
        // Version and addons length, then skip the addons. Read exactly what
        // we need so no payload is consumed here.
        while self.resp_got < 2 {
            let mut rb = ReadBuf::new(&mut self.resp_hdr[self.resp_got..]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.resp_got += n;
            if self.resp_got == 2 {
                if self.resp_hdr[0] != 0 {
                    return Poll::Ready(Err(bad("vless: unknown response version")));
                }
                self.resp_skip = self.resp_hdr[1] as usize;
            }
        }
        while self.resp_skip > 0 {
            let mut scratch = [0u8; 255];
            let mut rb = ReadBuf::new(&mut scratch[..self.resp_skip]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.resp_skip -= n;
        }
        self.vless_response = false;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HeaderStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(h) = this.header.take() {
            this.wbuf = h;
            this.read_flushes = true;
        }
        if this.read_flushes && this.wpos < this.wbuf.len() {
            // Push the request out, but don't wait on writability here: the
            // write side may live in another task (split streams), and a
            // socket keeps one write wakeup, so only one side may wait on it.
            // Once the writer has written, flushing is its job.
            if let Poll::Ready(r) = this.poll_flush_wbuf(cx) {
                r?;
                if let Poll::Ready(Err(e)) = Pin::new(&mut this.inner).poll_flush(cx) {
                    return Poll::Ready(Err(e));
                }
            }
        }
        ready!(this.poll_response(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HeaderStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.read_flushes = false;
        if let Some(mut h) = this.header.take() {
            h.extend_from_slice(buf);
            this.wbuf = h;
            this.wpos = 0;
            if let Poll::Ready(Err(e)) = this.poll_flush_wbuf(cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        ready!(this.poll_flush_wbuf(cx))?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.header.is_some() || this.wpos < this.wbuf.len() {
            let first = bufs.iter().find(|b| !b.is_empty()).map_or(&[][..], |b| &b[..]);
            return Pin::new(this).poll_write(cx, first);
        }
        Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_wbuf(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(h) = this.header.take() {
            this.wbuf = h;
        }
        ready!(this.poll_flush_wbuf(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// How datagrams are framed on the stream.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Trojan: SOCKS address, length, CRLF, payload.
    Trojan,
    /// VLESS plain UDP: length, payload; one destination.
    Length,
    /// XUDP (Xray's mux framing for UDP), full-cone.
    Xudp,
    /// One write = one packet, one read = one packet (VMess chunks).
    Message,
}

struct Writer {
    w: WriteHalf<Stream>,
    buf: Vec<u8>,
    first: bool,
}

/// UDP over a proxy stream. The UDP NAT runs one reader and one writer per
/// session, so each lock is uncontended; they exist because `PacketConn`
/// takes `&self`.
pub struct StreamPacketConn {
    framing: Framing,
    /// The association's destination, for framings without addresses.
    dest: Destination,
    reader: Mutex<BufReader<ReadHalf<Stream>>>,
    writer: Mutex<Writer>,
}

impl StreamPacketConn {
    pub fn new(s: Stream, framing: Framing, dest: Destination) -> Arc<Self> {
        let (r, w) = tokio::io::split(s);
        Arc::new(Self {
            framing,
            dest,
            // Only the small header reads use this buffer: a payload read at
            // least this long bypasses it.
            reader: Mutex::new(BufReader::with_capacity(2048, r)),
            writer: Mutex::new(Writer {
                w,
                buf: Vec::with_capacity(2048),
                first: true,
            }),
        })
    }

    async fn send(&self, payload: &[u8], dest: &Destination) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"));
        }
        let mut w = self.writer.lock().await;
        let Writer { w: half, buf, first } = &mut *w;
        buf.clear();
        match self.framing {
            Framing::Trojan => {
                put_socks_addr(buf, dest);
                buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                buf.extend_from_slice(b"\r\n");
                buf.extend_from_slice(payload);
            }
            Framing::Length => {
                buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                buf.extend_from_slice(payload);
            }
            Framing::Xudp => {
                buf.extend_from_slice(&[0, 0, 0, 0, if *first { 1 } else { 2 }, 1, 2]);
                put_vmess_addr(buf, dest);
                let meta = (buf.len() - 2) as u16;
                buf[..2].copy_from_slice(&meta.to_be_bytes());
                buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                buf.extend_from_slice(payload);
            }
            Framing::Message => buf.extend_from_slice(payload),
        }
        *first = false;
        half.write_all(buf).await?;
        half.flush().await
    }

    async fn recv(&self, out: &mut [u8]) -> io::Result<(usize, Destination)> {
        let mut r = self.reader.lock().await;
        let r = &mut *r;
        match self.framing {
            Framing::Trojan => {
                let from = read_socks_addr(r).await?;
                let len = r.read_u16().await? as usize;
                let mut crlf = [0u8; 2];
                r.read_exact(&mut crlf).await?;
                Ok((read_payload(r, out, len).await?, from))
            }
            Framing::Length => {
                let len = r.read_u16().await? as usize;
                Ok((read_payload(r, out, len).await?, self.dest.clone()))
            }
            Framing::Xudp => loop {
                let meta_len = r.read_u16().await? as usize;
                if meta_len < 4 {
                    return Err(bad("xudp: invalid frame length"));
                }
                let mut meta = [0u8; 4 + 1 + 1 + 2 + 255];
                let meta = meta.get_mut(..meta_len).ok_or_else(|| bad("xudp: frame too long"))?;
                r.read_exact(meta).await?;
                let (status, option) = (meta[2], meta[3]);
                let from = match status {
                    1 => return Err(bad("xudp: unexpected frame new")),
                    2 if meta_len > 5 => parse_vmess_addr(&meta[5..])?.0,
                    2 | 4 => self.dest.clone(),
                    3 => return Err(io::ErrorKind::UnexpectedEof.into()),
                    _ => return Err(bad("xudp: unexpected frame")),
                };
                if option & 2 != 0 {
                    return Err(io::Error::new(io::ErrorKind::ConnectionReset, "xudp: remote closed"));
                }
                if option & 1 == 0 {
                    continue;
                }
                let len = r.read_u16().await? as usize;
                let n = read_payload(r, out, len).await?;
                if status == 4 {
                    continue; // keep-alive carrying data: not a packet for us
                }
                return Ok((n, from));
            },
            Framing::Message => {
                let n = r.read(out).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                Ok((n, self.dest.clone()))
            }
        }
    }
}

async fn read_payload<R: AsyncRead + Unpin>(r: &mut R, out: &mut [u8], len: usize) -> io::Result<usize> {
    if len > out.len() {
        // Too big for the caller: drop it, keep the framing.
        discard(r, len).await?;
        return Ok(0);
    }
    r.read_exact(&mut out[..len]).await?;
    Ok(len)
}

/// Read and drop `len` bytes without allocating them.
pub(crate) async fn discard<R: AsyncRead + Unpin>(r: &mut R, mut len: usize) -> io::Result<()> {
    let mut scratch = [0u8; 512];
    while len > 0 {
        let n = len.min(scratch.len());
        r.read_exact(&mut scratch[..n]).await?;
        len -= n;
    }
    Ok(())
}

/// `PacketConn` facade over a shared [`StreamPacketConn`].
pub struct PacketHandle(pub Arc<StreamPacketConn>);

impl PacketConn for PacketHandle {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.0.send(buf, dest))
    }
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(self.0.recv(buf))
    }
}
