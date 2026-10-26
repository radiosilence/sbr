//! hysteria2 client (sing-quic `hysteria2`).
//!
//! - Auth: HTTP/3 `POST https://hysteria/auth` with `Hysteria-Auth` and
//!   `Hysteria-CC-RX`; status 233 means OK. The HTTP/3 control stream must
//!   stay open for the connection's life, so the h3 driver and request
//!   sender live in the session.
//! - TCP: a bidirectional stream starting with
//!   `varint(0x401) varint(len) addr varint(len) padding`; the server answers
//!   `status(1) varint(len) msg varint(len) padding` before data.
//! - UDP: QUIC datagrams `session(4) packet(2) frag(1) total(1) varint(len)
//!   addr payload`, fragmented to the path's datagram size.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use sbr_config::{DomainStrategy, Hysteria2Outbound, Network};
use sbr_core::dns::Dns;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Outbound, PacketConn, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::Upstream;
use super::quic::brutal::{BrutalSwitch, SwitchableFactory};
use super::quic::{
    DEFAULT_IDLE, Dialer, Hop, Packet, PinnedUdp, Pool, Pooled, Sessions, Tuning, UDP_QUEUE, Usage, UseGuard,
    get_varint, io_err, parse_host_port, put_varint, recv_into, transport,
};

const TCP_REQUEST: u64 = 0x401;
const STATUS_AUTH_OK: u16 = 233;
/// sing-quic `protocol.MaxUDPSize`.
const MAX_UDP: usize = 4096;
const MAX_MESSAGE: u64 = 2048;
const MAX_PADDING: u64 = 4096;
/// hysteria `DefaultStreamReceiveWindow` / `DefaultConnReceiveWindow`.
const STREAM_WINDOW: u64 = 8 << 20;
/// Connections dialed together; see [`Pool`].
const STRIPES: usize = 2;
const CONN_WINDOW: u64 = STREAM_WINDOW * 5 / 2;
const KEEP_ALIVE: Duration = Duration::from_secs(10);
/// hysteria `MbpsToBps`: megabits to bytes.
const MBPS: u64 = 125_000;

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn padding(min: usize, max: usize) -> String {
    (0..fastrand::usize(min..max))
        .map(|_| PADDING_CHARS[fastrand::usize(..PADDING_CHARS.len())] as char)
        .collect()
}

pub struct Hysteria2 {
    tag: String,
    dialer: Dialer,
    pool: Pool<Session>,
    password: String,
    send_bps: u64,
    recv_bps: u64,
    network: Option<Network>,
    quic: sbr_config::QuicOptions,
    /// Resolves UDP destinations given as names ([`PinnedUdp`]).
    dns: Arc<dyn Dns>,
    strategy: Option<DomainStrategy>,
}

struct Session {
    conn: Connection,
    endpoint: Endpoint,
    usage: Arc<Usage>,
    udp_enabled: bool,
    udp: Arc<Sessions<u32>>,
    next_udp: AtomicU32,
    /// Keeps the HTTP/3 control stream open.
    _h3: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

impl Pooled for Session {
    fn conn(&self) -> &Connection {
        &self.conn
    }
    fn usage(&self) -> &Arc<Usage> {
        &self.usage
    }
}

impl Hysteria2 {
    pub fn new(tag: String, c: &Hysteria2Outbound, upstream: Upstream, dns: Arc<dyn Dns>) -> Result<Self, String> {
        let server = Destination::from_host_port(&c.server.server, c.server.server_port);
        let mut dialer = Dialer::new(upstream, server, &c.tls, &["h3"], false)?;
        if !c.server_ports.is_empty() {
            let min = c.hop_interval.unwrap_or(Duration::from_secs(30));
            dialer.hop = Some(Hop {
                ranges: c.server_ports.clone(),
                interval: (min, c.hop_interval_max.unwrap_or(min)),
            });
        }
        dialer.salamander = c.obfs_salamander.clone();
        dialer.scramble = !c.quic.disable_client_hello_scrambling;
        Ok(Self {
            tag,
            dialer,
            // Brutal paces each connection at the configured rate, so striping
            // would multiply it.
            pool: Pool::new(if c.up_mbps == 0 && c.down_mbps == 0 { STRIPES } else { 1 }),
            password: c.password.clone(),
            send_bps: u64::from(c.up_mbps) * MBPS,
            recv_bps: u64::from(c.down_mbps) * MBPS,
            network: c.network,
            quic: c.quic.clone(),
            dns,
            strategy: c.dial.domain_strategy,
        })
    }

    async fn dial(&self) -> io::Result<Arc<Session>> {
        let switch = Arc::new(BrutalSwitch::default());
        let t = transport(
            &self.quic,
            Tuning {
                stream_window: STREAM_WINDOW,
                conn_window: CONN_WINDOW,
                keep_alive: Some(KEEP_ALIVE),
                incoming_uni: 16,
            },
            Arc::new(SwitchableFactory(switch.clone())),
        );
        let (endpoint, connecting) = self.dialer.start(t).await?;
        let fut = async {
            let conn = connecting.await.map_err(io_err)?;
            self.authenticate(conn, endpoint, &switch).await
        };
        tokio::time::timeout(self.dialer.handshake_timeout, fut)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hysteria2: handshake timed out"))?
    }

    async fn authenticate(
        &self,
        conn: Connection,
        endpoint: Endpoint,
        switch: &BrutalSwitch,
    ) -> io::Result<Arc<Session>> {
        let fail = |e: &dyn std::fmt::Display| io::Error::other(format!("hysteria2 auth: {e}"));
        let (mut driver, mut send) = h3::client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|e| fail(&e))?;
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let req = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", &self.password)
            .header("Hysteria-CC-RX", self.recv_bps.to_string())
            .header("Hysteria-Padding", padding(256, 2048))
            .body(())
            .map_err(|e| fail(&e))?;
        let mut stream = send.send_request(req).await.map_err(|e| fail(&e))?;
        // A server rejecting us answers and closes at once, and its close can
        // reset our side of the stream before `finish` completes: the request
        // is already out, so the response (or how the server ended) decides.
        let _ = stream.finish().await;
        let resp = stream.recv_response().await.map_err(|e| {
            // Torn down cleanly before a 233 arrived: the server said no.
            let clean = e.is_h3_no_error()
                || matches!(&e, h3::error::StreamError::RemoteTerminate { code, .. } if *code == h3::error::Code::H3_NO_ERROR);
            if clean {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("hysteria2: authentication failed, server closed the connection ({e})"),
                )
            } else {
                fail(&e)
            }
        })?;
        drop(stream);
        if resp.status().as_u16() != STATUS_AUTH_OK {
            conn.close(0u32.into(), b"");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "hysteria2: authentication failed, status code: {}",
                    resp.status().as_u16()
                ),
            ));
        }
        let header = |k: &str| resp.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("");
        // Go's strconv.ParseBool.
        let udp_enabled = matches!(header("Hysteria-UDP"), "1" | "t" | "T" | "true" | "TRUE" | "True");
        let (rx, rx_auto) = match header("Hysteria-CC-RX") {
            "auto" => (0, true),
            v => (v.parse::<u64>().unwrap_or(0), false),
        };
        // The server's receive limit caps our send rate.
        let tx = if rx == 0 || rx > self.send_bps {
            self.send_bps
        } else {
            rx
        };
        if !rx_auto && tx > 0 {
            switch.set(tx);
        }
        let session = Arc::new(Session {
            conn: conn.clone(),
            endpoint,
            usage: Arc::default(),
            udp_enabled,
            udp: Arc::new(Sessions::new()),
            next_udp: AtomicU32::new(0),
            _h3: send,
        });
        if udp_enabled && self.network != Some(Network::Tcp) {
            tokio::spawn(recv_datagrams(conn.clone(), session.udp.clone()));
        }
        tokio::spawn(super::quic::watch(
            conn,
            session.usage.clone(),
            self.quic.idle_timeout.unwrap_or(DEFAULT_IDLE),
            None,
        ));
        Ok(session)
    }
}

async fn recv_datagrams(conn: Connection, sessions: Arc<Sessions<u32>>) {
    while let Ok(d) = conn.read_datagram().await {
        // sing-quic closes the connection on a malformed message; dropping
        // it is enough to stay safe.
        if d.len() < 9 {
            continue;
        }
        let sid = u32::from_be_bytes(d[0..4].try_into().unwrap());
        let pid = u16::from_be_bytes(d[4..6].try_into().unwrap());
        let (frag, total) = (d[6], d[7]);
        let Some((alen, vlen)) = get_varint(&d[8..]) else {
            continue;
        };
        let start = 8 + vlen;
        let Some(addr) = d.get(start..start + alen as usize) else {
            continue;
        };
        let Some(dest) = std::str::from_utf8(addr).ok().and_then(parse_host_port) else {
            continue;
        };
        let data = d.slice(start + alen as usize..);
        sessions.deliver(&sid, pid, frag, total, Some(dest), data);
    }
}

impl Outbound for Hysteria2 {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    /// The QUIC connection's smoothed RTT: a real round-trip measurement to
    /// the server that costs no extra traffic once the session exists.
    fn probe_rtt(&self) -> Option<BoxFuture<'_, io::Result<std::time::Duration>>> {
        Some(Box::pin(async move { Ok(self.dial().await?.conn.rtt()) }))
    }

    fn migrate(&self) -> Option<BoxFuture<'_, bool>> {
        if !self.dialer.migratable() {
            return None;
        }
        Some(Box::pin(async move {
            let mut ok = true;
            for s in self.pool.live() {
                ok &= self.dialer.migrate(&s.endpoint, &s.conn).await;
            }
            ok
        }))
    }

    fn network_changed(&self) {
        for s in self.pool.live() {
            s.conn.close(0u32.into(), b"");
        }
    }

    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if self.network == Some(Network::Udp) {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2: TCP disabled"));
            }
            let (s, guard) = self.pool.get(|| self.dial()).await?;
            let (mut send, recv) = s.conn.open_bi().await.map_err(io_err)?;
            let addr = dest.to_string();
            let pad = padding(64, 512);
            let mut req = Vec::with_capacity(16 + addr.len() + pad.len());
            put_varint(&mut req, TCP_REQUEST);
            put_varint(&mut req, addr.len() as u64);
            req.extend_from_slice(addr.as_bytes());
            put_varint(&mut req, pad.len() as u64);
            req.extend_from_slice(pad.as_bytes());
            // Buffered by quinn: costs no round trip. The response is read
            // lazily, so client data can follow immediately.
            send.write_all(&req).await.map_err(io_err)?;
            Ok(Box::new(Hy2Stream {
                send,
                recv,
                head: Some(Vec::new()),
                leftover: Bytes::new(),
                _guard: guard,
            }) as Stream)
        })
    }

    fn connect_udp<'a>(&'a self, _dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            if self.network == Some(Network::Tcp) {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2: UDP disabled"));
            }
            let (s, guard) = self.pool.get(|| self.dial()).await?;
            if !s.udp_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "hysteria2: UDP disabled by server",
                ));
            }
            let id = s.next_udp.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::channel(UDP_QUEUE);
            s.udp.map.lock().unwrap().insert(
                id,
                super::quic::SessionEntry {
                    tx,
                    defrag: Default::default(),
                },
            );
            let udp = Hy2Udp {
                session: s,
                id,
                rx: Mutex::new(rx),
                packet_id: AtomicU16::new(0),
                _guard: guard,
            };
            Ok(Box::new(PinnedUdp::new(udp, self.dns.clone(), self.strategy)) as BoxPacketConn)
        })
    }
}

/// A proxied TCP connection: one bidirectional stream.
struct Hy2Stream {
    send: SendStream,
    recv: RecvStream,
    /// Response header bytes until it has been parsed.
    head: Option<Vec<u8>>,
    leftover: Bytes,
    _guard: UseGuard,
}

/// `Ok(None)`: need more bytes. `Ok(Some(n))`: header is `n` bytes.
fn parse_response(b: &[u8]) -> io::Result<Option<usize>> {
    let Some(&status) = b.first() else { return Ok(None) };
    let Some((mlen, v1)) = get_varint(&b[1..]) else {
        return Ok(None);
    };
    if mlen > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteria2: invalid message length",
        ));
    }
    let at = 1 + v1 + mlen as usize;
    let Some(msg) = b.get(1 + v1..at) else { return Ok(None) };
    let Some((plen, v2)) = get_varint(&b[at..]) else {
        return Ok(None);
    };
    if plen > MAX_PADDING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteria2: invalid padding length",
        ));
    }
    let end = at + v2 + plen as usize;
    if b.len() < end {
        return Ok(None);
    }
    if status != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("hysteria2: remote error: {}", String::from_utf8_lossy(msg)),
        ));
    }
    Ok(Some(end))
}

impl AsyncRead for Hy2Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while let Some(head) = &mut this.head {
            let mut tmp = [0u8; 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.recv).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            head.extend_from_slice(rb.filled());
            if let Some(n) = parse_response(head)? {
                this.leftover = Bytes::copy_from_slice(&head[n..]);
                this.head = None;
            }
        }
        if !this.leftover.is_empty() {
            let n = this.leftover.len().min(buf.remaining());
            buf.put_slice(&this.leftover.split_to(n));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hy2Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

struct Hy2Udp {
    session: Arc<Session>,
    id: u32,
    rx: Mutex<mpsc::Receiver<Packet>>,
    packet_id: AtomicU16,
    _guard: UseGuard,
}

impl Drop for Hy2Udp {
    fn drop(&mut self) {
        self.session.udp.map.lock().unwrap().remove(&self.id);
    }
}

impl Hy2Udp {
    fn send(&self, payload: &[u8], dest: &Destination) -> io::Result<()> {
        if payload.len() > MAX_UDP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2: UDP packet too large",
            ));
        }
        let addr = dest.to_string();
        let mut head = Vec::with_capacity(16 + addr.len());
        head.extend_from_slice(&self.id.to_be_bytes());
        let pid = self.packet_id.fetch_add(1, Ordering::Relaxed);
        head.extend_from_slice(&pid.to_be_bytes());
        head.extend_from_slice(&[0, 1]);
        put_varint(&mut head, addr.len() as u64);
        head.extend_from_slice(addr.as_bytes());
        let max = self
            .session
            .conn
            .max_datagram_size()
            .ok_or_else(|| io_err("hysteria2: datagrams not supported by the server"))?;
        let room = max.saturating_sub(head.len());
        if payload.len() <= room {
            let mut d = BytesMut::with_capacity(head.len() + payload.len());
            d.extend_from_slice(&head);
            d.extend_from_slice(payload);
            return self.session.conn.send_datagram(d.freeze()).map_err(io_err);
        }
        // Every fragment repeats the full header (hysteria requires it).
        if room == 0 {
            return Err(io_err("hysteria2: path MTU too small"));
        }
        let total = payload.len().div_ceil(room);
        if total > usize::from(u8::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2: UDP packet too large",
            ));
        }
        for (i, chunk) in payload.chunks(room).enumerate() {
            let mut d = BytesMut::with_capacity(head.len() + chunk.len());
            d.extend_from_slice(&head);
            d[6] = i as u8;
            d[7] = total as u8;
            d.extend_from_slice(chunk);
            self.session.conn.send_datagram(d.freeze()).map_err(io_err)?;
        }
        Ok(())
    }
}

impl PacketConn for Hy2Udp {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.send(buf, dest) })
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(recv_into(&self.rx, buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_parsing() {
        let mut ok = vec![0];
        put_varint(&mut ok, 0);
        put_varint(&mut ok, 300);
        ok.extend(std::iter::repeat_n(b'x', 300));
        for cut in 0..ok.len() {
            assert!(parse_response(&ok[..cut]).unwrap().is_none());
        }
        ok.extend_from_slice(b"data");
        assert_eq!(parse_response(&ok).unwrap(), Some(ok.len() - 4));
        let mut err = vec![1];
        put_varint(&mut err, 4);
        err.extend_from_slice(b"nope");
        put_varint(&mut err, 0);
        let e = parse_response(&err).unwrap_err();
        assert!(e.to_string().contains("nope"));
    }
}
