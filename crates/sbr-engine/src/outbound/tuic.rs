//! TUIC v5 client (sing-quic `tuic`).
//!
//! - Auth: a unidirectional stream `5 0 uuid(16) token(32)`, the token being
//!   the TLS exporter output for label = uuid, context = password. The
//!   server holds other streams until it arrives, so it costs no RTT.
//! - TCP: a bidirectional stream starting with `5 1 addr`; no response.
//! - UDP `native`: datagrams `5 2 assoc(2) packet(2) total(1) index(1)
//!   size(2) addr payload` (later fragments carry no address); `quic`: the
//!   same message on its own unidirectional stream; `udp_over_stream`:
//!   UDP-over-TCP v2 inside a TCP stream. `5 3 assoc` dissociates.
//! - Heartbeat: datagram `5 4`, only while the connection has users.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use sbr_config::{Network, TuicCongestion, TuicOutbound, TuicUdpRelay};
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Host, Outbound, PacketConn, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::Upstream;
use super::quic::{
    DEFAULT_IDLE, Dialer, Packet, Pool, Pooled, SessionEntry, Sessions, Tuning, UDP_QUEUE, Usage, UseGuard, io_err,
    recv_into, transport, watch,
};

const VERSION: u8 = 5;
const CMD_AUTH: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_PACKET: u8 = 2;
const CMD_DISSOCIATE: u8 = 3;
const CMD_HEARTBEAT: u8 = 4;
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(10);
/// quic-go's maximum receive windows (it auto-tunes up to these).
const STREAM_WINDOW: u64 = 6 << 20;
const CONN_WINDOW: u64 = 15 << 20;
const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

pub struct Tuic {
    tag: String,
    dialer: Dialer,
    pool: Pool<Session>,
    uuid: [u8; 16],
    password: String,
    cc: TuicCongestion,
    relay: TuicUdpRelay,
    zero_rtt: bool,
    heartbeat: Duration,
    network: Option<Network>,
    quic: sbr_config::QuicOptions,
}

struct Session {
    conn: Connection,
    _endpoint: Endpoint,
    usage: Arc<Usage>,
    udp: Arc<Sessions<u16>>,
    next_udp: AtomicU16,
}

impl Pooled for Session {
    fn conn(&self) -> &Connection {
        &self.conn
    }
    fn usage(&self) -> &Arc<Usage> {
        &self.usage
    }
}

/// TUIC address: `0 len fqdn` / `1 v4` / `2 v6`, then the port; `0xff`
/// alone for none.
fn put_addr(out: &mut Vec<u8>, d: Option<&Destination>) {
    let Some(d) = d else {
        out.push(0xff);
        return;
    };
    match &d.host {
        Host::Domain(name) => {
            out.push(0);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(2);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&d.port.to_be_bytes());
}

/// Returns the address (if any) and bytes consumed.
fn get_addr(b: &[u8]) -> Option<(Option<Destination>, usize)> {
    let (host, n) = match *b.first()? {
        0xff => return Some((None, 1)),
        0 => {
            let len = usize::from(*b.get(1)?);
            let name = std::str::from_utf8(b.get(2..2 + len)?).ok()?;
            (Destination::from_host_port(name, 0).host, 2 + len)
        }
        1 => (Host::Ip(<[u8; 4]>::try_from(b.get(1..5)?).ok()?.into()), 5),
        2 => (Host::Ip(<[u8; 16]>::try_from(b.get(1..17)?).ok()?.into()), 17),
        _ => return None,
    };
    let port = u16::from_be_bytes(b.get(n..n + 2)?.try_into().ok()?);
    Some((Some(Destination::new(host, port)), n + 2))
}

impl Tuic {
    pub fn new(tag: String, c: &TuicOutbound, upstream: Upstream) -> Result<Self, String> {
        let server = Destination::from_host_port(&c.server.server, c.server.server_port);
        // sing-box sets no default ALPN for TUIC.
        let dialer = Dialer::new(upstream, server, &c.tls, &[], c.zero_rtt_handshake)?;
        Ok(Self {
            tag,
            dialer,
            pool: Pool::new(),
            uuid: c.uuid,
            password: c.password.clone(),
            cc: c.congestion_control,
            relay: c.udp_relay,
            zero_rtt: c.zero_rtt_handshake,
            heartbeat: c.heartbeat.unwrap_or(DEFAULT_HEARTBEAT),
            network: c.network,
            quic: c.quic.clone(),
        })
    }

    async fn dial(&self) -> io::Result<Arc<Session>> {
        let cc: Arc<dyn ControllerFactory + Send + Sync> = match self.cc {
            TuicCongestion::Cubic => Arc::new(CubicConfig::default()),
            TuicCongestion::NewReno => Arc::new(NewRenoConfig::default()),
            TuicCongestion::Bbr => Arc::new(BbrConfig::default()),
        };
        let t = transport(
            &self.quic,
            Tuning {
                stream_window: STREAM_WINDOW,
                conn_window: CONN_WINDOW,
                keep_alive: None,
                incoming_uni: if self.relay == TuicUdpRelay::Quic { 1024 } else { 16 },
            },
            cc,
        );
        let (endpoint, connecting) = self.dialer.start(t).await?;
        let early = if self.zero_rtt {
            connecting.into_0rtt()
        } else {
            Err(connecting)
        };
        let conn = match early {
            Ok((conn, accepted)) => {
                // Streams go out as 0-RTT data now; the exporter needs the
                // finished handshake, so authenticate once it completes.
                let (c, uuid, pw) = (conn.clone(), self.uuid, self.password.clone());
                tokio::spawn(async move {
                    accepted.await;
                    if let Err(e) = authenticate(&c, &uuid, &pw).await {
                        tracing::debug!(error = %e, "tuic: auth");
                        c.close(0u32.into(), b"");
                    }
                });
                conn
            }
            Err(connecting) => {
                let conn = tokio::time::timeout(self.dialer.handshake_timeout, connecting)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tuic: handshake timed out"))?
                    .map_err(io_err)?;
                authenticate(&conn, &self.uuid, &self.password).await?;
                conn
            }
        };
        let session = Arc::new(Session {
            conn: conn.clone(),
            _endpoint: endpoint,
            usage: Arc::default(),
            udp: Arc::new(Sessions::new()),
            next_udp: AtomicU16::new(0),
        });
        if self.network != Some(Network::Tcp) {
            tokio::spawn(recv_datagrams(conn.clone(), session.udp.clone()));
            if self.relay == TuicUdpRelay::Quic {
                tokio::spawn(recv_uni(conn.clone(), session.udp.clone()));
            }
        }
        let beat_conn = conn.clone();
        let beat: Box<dyn Fn() + Send + Sync> = Box::new(move || {
            let _ = beat_conn.send_datagram(Bytes::from_static(&[VERSION, CMD_HEARTBEAT]));
        });
        tokio::spawn(watch(
            conn,
            session.usage.clone(),
            self.quic.idle_timeout.unwrap_or(DEFAULT_IDLE),
            Some((self.heartbeat, beat)),
        ));
        Ok(session)
    }

    async fn open(&self, dest: &Destination) -> io::Result<(QuicStream, Arc<Session>)> {
        let (s, guard) = self.pool.get(|| self.dial()).await?;
        let (mut send, recv) = s.conn.open_bi().await.map_err(io_err)?;
        let mut req = vec![VERSION, CMD_CONNECT];
        put_addr(&mut req, Some(dest));
        send.write_all(&req).await.map_err(io_err)?;
        Ok((
            QuicStream {
                send,
                recv,
                _guard: guard,
            },
            s,
        ))
    }
}

async fn authenticate(conn: &Connection, uuid: &[u8; 16], password: &str) -> io::Result<()> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|_| io_err("tuic: export keying material"))?;
    let mut s = conn.open_uni().await.map_err(io_err)?;
    let mut msg = Vec::with_capacity(50);
    msg.extend_from_slice(&[VERSION, CMD_AUTH]);
    msg.extend_from_slice(uuid);
    msg.extend_from_slice(&token);
    s.write_all(&msg).await.map_err(io_err)?;
    s.finish().map_err(io_err)?;
    Ok(())
}

/// Parses `assoc packet total index size addr payload` (after `5 2`).
fn parse_packet(d: &Bytes) -> Option<(u16, u16, u8, u8, Option<Destination>, Bytes)> {
    let assoc = u16::from_be_bytes(d.get(0..2)?.try_into().ok()?);
    let pid = u16::from_be_bytes(d.get(2..4)?.try_into().ok()?);
    let (total, index) = (*d.get(4)?, *d.get(5)?);
    let size = usize::from(u16::from_be_bytes(d.get(6..8)?.try_into().ok()?));
    let (dest, n) = get_addr(d.get(8..)?)?;
    let data = d.slice(8 + n..);
    if data.len() != size {
        return None;
    }
    Some((assoc, pid, total, index, dest, data))
}

fn deliver(sessions: &Sessions<u16>, msg: &Bytes) {
    if msg.len() < 2 || msg[0] != VERSION || msg[1] != CMD_PACKET {
        return;
    }
    if let Some((assoc, pid, total, index, dest, data)) = parse_packet(&msg.slice(2..)) {
        sessions.deliver(&assoc, pid, index, total, dest, data);
    }
}

async fn recv_datagrams(conn: Connection, sessions: Arc<Sessions<u16>>) {
    while let Ok(d) = conn.read_datagram().await {
        deliver(&sessions, &d);
    }
}

async fn recv_uni(conn: Connection, sessions: Arc<Sessions<u16>>) {
    while let Ok(mut s) = conn.accept_uni().await {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Ok(msg) = s.read_to_end(u16::MAX as usize + 512).await {
                deliver(&sessions, &Bytes::from(msg));
            }
        });
    }
}

impl Outbound for Tuic {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "tuic"
    }

    /// The QUIC connection's smoothed RTT: a real round-trip measurement to
    /// the server that costs no extra traffic once the session exists.
    fn probe_rtt(&self) -> Option<BoxFuture<'_, io::Result<std::time::Duration>>> {
        Some(Box::pin(async move { Ok(self.dial().await?.conn.rtt()) }))
    }

    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if self.network == Some(Network::Udp) {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "tuic: TCP disabled"));
            }
            Ok(Box::new(self.open(dest).await?.0) as Stream)
        })
    }

    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            if self.network == Some(Network::Tcp) {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "tuic: UDP disabled"));
            }
            if self.relay == TuicUdpRelay::OverStream {
                let (mut s, _) = self.open(&Destination::from_host_port(UOT_MAGIC, 0)).await?;
                // UoT v2 request: not "connect" mode, so any destination works.
                let mut req = vec![0u8];
                put_socks_addr(&mut req, dest);
                s.send.write_all(&req).await.map_err(io_err)?;
                return Ok(Box::new(Uot {
                    send: tokio::sync::Mutex::new(s.send),
                    recv: tokio::sync::Mutex::new(s.recv),
                    _guard: s._guard,
                }) as BoxPacketConn);
            }
            let (s, guard) = self.pool.get(|| self.dial()).await?;
            let id = s.next_udp.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::channel(UDP_QUEUE);
            s.udp.map.lock().unwrap().insert(
                id,
                SessionEntry {
                    tx,
                    defrag: Default::default(),
                },
            );
            Ok(Box::new(TuicUdp {
                session: s,
                id,
                rx: Mutex::new(rx),
                packet_id: AtomicU16::new(0),
                over_streams: self.relay == TuicUdpRelay::Quic,
                _guard: guard,
            }) as BoxPacketConn)
        })
    }
}

/// A proxied TCP connection over one bidirectional QUIC stream.
struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    _guard: UseGuard,
}

impl AsyncRead for QuicStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
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

struct TuicUdp {
    session: Arc<Session>,
    id: u16,
    rx: Mutex<mpsc::Receiver<Packet>>,
    packet_id: AtomicU16,
    over_streams: bool,
    _guard: UseGuard,
}

impl Drop for TuicUdp {
    fn drop(&mut self) {
        self.session.udp.map.lock().unwrap().remove(&self.id);
        let conn = self.session.conn.clone();
        let msg = [VERSION, CMD_DISSOCIATE, (self.id >> 8) as u8, self.id as u8];
        tokio::spawn(async move {
            if let Ok(mut s) = conn.open_uni().await {
                let _ = s.write_all(&msg).await;
                let _ = s.finish();
            }
        });
    }
}

impl TuicUdp {
    fn message(&self, pid: u16, total: u8, index: u8, dest: Option<&Destination>, data: &[u8]) -> Bytes {
        let mut head = Vec::with_capacity(32);
        head.extend_from_slice(&[VERSION, CMD_PACKET]);
        head.extend_from_slice(&self.id.to_be_bytes());
        head.extend_from_slice(&pid.to_be_bytes());
        head.extend_from_slice(&[total, index]);
        head.extend_from_slice(&(data.len() as u16).to_be_bytes());
        put_addr(&mut head, dest);
        let mut b = BytesMut::with_capacity(head.len() + data.len());
        b.put_slice(&head);
        b.put_slice(data);
        b.freeze()
    }

    async fn send(&self, payload: &[u8], dest: &Destination) -> io::Result<()> {
        if payload.len() > usize::from(u16::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tuic: UDP packet too large",
            ));
        }
        let pid = self.packet_id.fetch_add(1, Ordering::Relaxed);
        let conn = &self.session.conn;
        if self.over_streams {
            let msg = self.message(pid, 1, 0, Some(dest), payload);
            let mut s = conn.open_uni().await.map_err(io_err)?;
            s.write_all(&msg).await.map_err(io_err)?;
            return s.finish().map_err(io_err);
        }
        let max = conn
            .max_datagram_size()
            .ok_or_else(|| io_err("tuic: datagrams not supported by the server"))?;
        let mut first = Vec::new();
        put_addr(&mut first, Some(dest));
        let head = 10 + first.len();
        if payload.len() + head <= max {
            return conn
                .send_datagram(self.message(pid, 1, 0, Some(dest), payload))
                .map_err(io_err);
        }
        // Size fragments by the first (largest) header; later ones carry
        // no address.
        let room = max.saturating_sub(head);
        if room == 0 {
            return Err(io_err("tuic: path MTU too small"));
        }
        let total = payload.len().div_ceil(room);
        if total > usize::from(u8::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tuic: UDP packet too large",
            ));
        }
        for (i, chunk) in payload.chunks(room).enumerate() {
            let d = if i == 0 { Some(dest) } else { None };
            conn.send_datagram(self.message(pid, total as u8, i as u8, d, chunk))
                .map_err(io_err)?;
        }
        Ok(())
    }
}

impl PacketConn for TuicUdp {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.send(buf, dest))
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(recv_into(&self.rx, buf))
    }
}

/// SOCKS5-style address (`1` v4, `3` fqdn, `4` v6) + port: the UoT request.
fn put_socks_addr(out: &mut Vec<u8>, d: &Destination) {
    match &d.host {
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(name) => {
            out.push(3);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&d.port.to_be_bytes());
}

/// UoT v2 packet address (`0` v4, `1` v6, `2` fqdn) + port.
fn put_uot_addr(out: &mut Vec<u8>, d: &Destination) {
    match &d.host {
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(0);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(name) => {
            out.push(2);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&d.port.to_be_bytes());
}

/// `udp_over_stream`: sing UoT v2 (non-connect) over a TUIC stream:
/// `addr port len(2) payload` per packet in both directions.
struct Uot {
    send: tokio::sync::Mutex<SendStream>,
    recv: tokio::sync::Mutex<RecvStream>,
    _guard: UseGuard,
}

async fn read_exact(r: &mut RecvStream, buf: &mut [u8]) -> io::Result<()> {
    r.read_exact(buf).await.map_err(io_err)
}

impl PacketConn for Uot {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let len = u16::try_from(buf.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UoT: packet too large"))?;
            let mut msg = Vec::with_capacity(buf.len() + 24);
            put_uot_addr(&mut msg, dest);
            msg.extend_from_slice(&len.to_be_bytes());
            msg.extend_from_slice(buf);
            // A stream mutex: packets must not interleave on the wire.
            self.send.lock().await.write_all(&msg).await.map_err(io_err)
        })
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(async move {
            let mut r = self.recv.lock().await;
            let mut ty = [0u8; 1];
            read_exact(&mut r, &mut ty).await?;
            let host = match ty[0] {
                0 => {
                    let mut a = [0u8; 4];
                    read_exact(&mut r, &mut a).await?;
                    Host::Ip(a.into())
                }
                1 => {
                    let mut a = [0u8; 16];
                    read_exact(&mut r, &mut a).await?;
                    Host::Ip(a.into())
                }
                2 => {
                    let mut l = [0u8; 1];
                    read_exact(&mut r, &mut l).await?;
                    let mut name = vec![0u8; usize::from(l[0])];
                    read_exact(&mut r, &mut name).await?;
                    Destination::from_host_port(&String::from_utf8_lossy(&name), 0).host
                }
                t => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("UoT: address type {t}"),
                    ));
                }
            };
            let mut pl = [0u8; 4];
            read_exact(&mut r, &mut pl).await?;
            let port = u16::from_be_bytes([pl[0], pl[1]]);
            let len = usize::from(u16::from_be_bytes([pl[2], pl[3]]));
            if len > buf.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "UoT: short buffer"));
            }
            read_exact(&mut r, &mut buf[..len]).await?;
            Ok((len, Destination::new(host, port)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_roundtrip() {
        for d in [
            Destination::from_host_port("1.2.3.4", 80),
            Destination::from_host_port("::1", 53),
            Destination::from_host_port("example.com", 443),
        ] {
            let mut b = Vec::new();
            put_addr(&mut b, Some(&d));
            assert_eq!(get_addr(&b), Some((Some(d), b.len())));
        }
        assert_eq!(get_addr(&[0xff]), Some((None, 1)));
        assert_eq!(get_addr(&[1, 2, 3]), None);
    }
}
