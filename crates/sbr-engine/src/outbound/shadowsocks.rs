use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};

use bytes::BytesMut;
use sbr_config::{Network, ShadowsocksOutbound, UdpOverTcp};
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Host, PacketConn, Stream};
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::{CipherCategory, CipherKind};
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::udprelay::crypto_io::{decrypt_server_payload, encrypt_client_payload};
use shadowsocks::relay::udprelay::options::UdpSocketControlData;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Upstream;
use sbr_core::Outbound;

pub struct Shadowsocks {
    tag: String,
    server: Destination,
    config: ServerConfig,
    context: SharedContext,
    upstream: Upstream,
    network: Option<Network>,
    uot: Option<UdpOverTcp>,
}

impl Shadowsocks {
    pub fn new(tag: String, c: &ShadowsocksOutbound, upstream: Upstream) -> Result<Self, String> {
        const STREAM: &[&str] = &[
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "rc4-md5",
            "chacha20-ietf",
            "xchacha20",
        ];
        if STREAM.contains(&c.method.as_str()) {
            return Err(format!(
                "stream cipher {:?} is broken crypto and not supported by sbr",
                c.method
            ));
        }
        let method: CipherKind = c
            .method
            .parse()
            .map_err(|_| format!("unsupported method {:?}", c.method))?;
        let addr = match c.server.server.parse() {
            Ok(ip) => ServerAddr::SocketAddr(std::net::SocketAddr::new(ip, c.server.server_port)),
            Err(_) => ServerAddr::DomainName(c.server.server.clone(), c.server.server_port),
        };
        let config = ServerConfig::new(addr, c.password.clone(), method).map_err(|e| e.to_string())?;
        Ok(Self {
            tag,
            server: Destination::from_host_port(&c.server.server, c.server.server_port),
            config,
            context: Context::new_shared(ServerType::Local),
            upstream,
            network: c.network,
            uot: c.udp_over_tcp,
        })
    }

    async fn open(&self, dest: &Destination) -> io::Result<Stream> {
        let s = self.upstream.connect(&self.server).await?;
        // The request header goes out with the first payload write, so
        // this costs no extra round trip (same as sing-box).
        let inner = ProxyClientStream::from_stream(self.context.clone(), s, &self.config, to_address(dest));
        Ok(Box::new(FirstWriteCap { inner, first: true }) as Stream)
    }
}

fn to_address(d: &Destination) -> Address {
    match &d.host {
        Host::Ip(ip) => Address::SocketAddress(std::net::SocketAddr::new(*ip, d.port)),
        Host::Domain(name) => Address::DomainNameAddress(name.to_string(), d.port),
    }
}

fn from_address(a: Address) -> Destination {
    match a {
        Address::SocketAddress(sa) => Destination::from(sa),
        Address::DomainNameAddress(d, port) => Destination::from_host_port(&d, port),
    }
}

impl Outbound for Shadowsocks {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "shadowsocks"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if self.network == Some(Network::Udp) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "shadowsocks: TCP disabled by `network`",
                ));
            }
            self.open(dest).await
        })
    }

    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            if self.network == Some(Network::Tcp) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "shadowsocks: UDP disabled by `network`",
                ));
            }
            if let Some(uot) = self.uot {
                // Internal TCP: allowed even when `network` is "udp", as in sing-box.
                let s = self.open(&super::uot::request_destination(uot.version)).await?;
                return Ok(Box::new(super::uot::UotConn::new(s, uot.version, dest)?) as BoxPacketConn);
            }
            let conn = self.upstream.connect_udp(&self.server).await?;
            Ok(Box::new(SsPacket::new(self, conn)) as BoxPacketConn)
        })
    }
}

/// Shadowsocks UDP: one encrypted datagram per packet. For AEAD-2022 the
/// association has a random client session id and a monotonically
/// increasing packet id; replies are checked against our session id and a
/// replay window keyed by the server's session id (SIP022).
struct SsPacket {
    conn: BoxPacketConn,
    server: Destination,
    context: SharedContext,
    method: CipherKind,
    key: Box<[u8]>,
    identity_keys: std::sync::Arc<Vec<bytes::Bytes>>,
    session_id: u64,
    packet_id: AtomicU64,
    send_buf: Mutex<Option<BytesMut>>,
    replay: Mutex<ReplayWindow>,
}

impl SsPacket {
    fn new(ss: &Shadowsocks, conn: BoxPacketConn) -> Self {
        let mut id = [0u8; 8];
        getrandom(&mut id);
        Self {
            conn,
            server: ss.server.clone(),
            context: ss.context.clone(),
            method: ss.config.method(),
            key: ss.config.key().into(),
            identity_keys: ss.config.clone_identity_keys(),
            session_id: u64::from_be_bytes(id),
            packet_id: AtomicU64::new(0),
            send_buf: Mutex::new(Some(BytesMut::with_capacity(2048))),
            replay: Mutex::new(ReplayWindow::default()),
        }
    }
}

fn getrandom(buf: &mut [u8]) {
    use aws_lc_rs::rand::SecureRandom;
    aws_lc_rs::rand::SystemRandom::new().fill(buf).expect("system RNG");
}

impl PacketConn for SsPacket {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut control = UdpSocketControlData::default();
            control.client_session_id = self.session_id;
            control.packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
            // Reuse one buffer per association; a concurrent sender just allocates.
            let mut out = self.send_buf.lock().unwrap().take().unwrap_or_default();
            out.clear();
            encrypt_client_payload(
                &self.context,
                self.method,
                &self.key,
                &to_address(dest),
                &control,
                &self.identity_keys,
                buf,
                &mut out,
            );
            let r = self.conn.send_to(&out, &self.server).await;
            *self.send_buf.lock().unwrap() = Some(out);
            r
        })
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(async move {
            loop {
                let (n, _) = self.conn.recv_from(buf).await?;
                let (len, addr, control) =
                    match decrypt_server_payload(&self.context, self.method, &self.key, &mut buf[..n]) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::debug!(error = %e, "shadowsocks: dropping undecryptable datagram");
                            continue;
                        }
                    };
                if self.method.category() == CipherCategory::Aead2022 {
                    let Some(c) = control else { continue };
                    if c.client_session_id != self.session_id
                        || !self.replay.lock().unwrap().accept(c.server_session_id, c.packet_id)
                    {
                        continue;
                    }
                }
                return Ok((len, from_address(addr)));
            }
        })
    }
}

/// Sliding anti-replay window over packet ids (WireGuard-style), reset when
/// the server starts a new session.
#[derive(Default)]
struct ReplayWindow {
    session: Option<u64>,
    last: u64,
    bits: u128,
}

impl ReplayWindow {
    fn accept(&mut self, session: u64, id: u64) -> bool {
        if self.session != Some(session) {
            self.session = Some(session);
            self.last = id;
            self.bits = 1;
            return true;
        }
        if id > self.last {
            let shift = id - self.last;
            self.bits = if shift >= 128 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.last = id;
            true
        } else {
            let back = self.last - id;
            if back >= 128 || self.bits & (1 << back) != 0 {
                return false;
            }
            self.bits |= 1 << back;
            true
        }
    }
}

/// `ProxyClientStream` emits the address header together with the first
/// payload as one AEAD chunk, and assumes that chunk fits. If the first write
/// is larger than a chunk it reports the whole buffer as written while only
/// part of it went out (a `debug_assert!` upstream; silent loss in release).
/// Capping the first write keeps header + payload inside one chunk; later
/// writes are chunked correctly by the crate.
struct FirstWriteCap<S> {
    inner: S,
    first: bool,
}

/// Comfortably below the smallest chunk limit (AEAD v1: 0x3FFF) after the
/// largest header (salt + 255-byte domain + 2022 padding).
const FIRST_WRITE_MAX: usize = 8 * 1024;

impl<S: AsyncRead + Unpin> AsyncRead for FirstWriteCap<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstWriteCap<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.first {
            let n = buf.len().min(FIRST_WRITE_MAX);
            let r = Pin::new(&mut this.inner).poll_write(cx, &buf[..n]);
            if matches!(r, Poll::Ready(Ok(_))) {
                this.first = false;
            }
            return r;
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
