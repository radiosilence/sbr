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
        Ok(Box::new(WriteFix::new(inner)) as Stream)
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

/// Works around two ways the `shadowsocks` 1.25 writer loses bytes.
///
/// - `ProxyClientStream` emits the address header together with the first
///   payload as one AEAD chunk and assumes that chunk fits. A larger first
///   write is reported as written in full while only part of it went out (a
///   `debug_assert!` upstream). Capping the first write keeps header and
///   payload inside one chunk; later writes are chunked by the crate.
/// - When a write returns `Pending`, the crate keeps the chunk it already
///   sealed and, once the retry completes, reports the *retry's* `buf.len()`
///   as written. `tokio::io::copy` reads more while a write is pending and
///   retries with a longer buffer, so the difference was dropped and the
///   peer waited forever. Retrying with exactly the length that went
///   pending keeps the count equal to what was sealed.
struct WriteFix<S> {
    inner: S,
    first: bool,
    /// Length of the write that returned `Pending`.
    pending: Option<usize>,
}

impl<S> WriteFix<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            first: true,
            pending: None,
        }
    }
}

/// Comfortably below the smallest chunk limit (AEAD v1: 0x3FFF) after the
/// largest header (salt + 255-byte domain + 2022 padding).
const FIRST_WRITE_MAX: usize = 8 * 1024;

impl<S: AsyncRead + Unpin> AsyncRead for WriteFix<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteFix<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let n = match this.pending {
            Some(n) if n > buf.len() => {
                // The sealed chunk holds bytes the caller no longer offers.
                return Poll::Ready(Err(io::Error::other(
                    "shadowsocks: write retried with fewer bytes than it offered",
                )));
            }
            Some(n) => n,
            None if this.first => buf.len().min(FIRST_WRITE_MAX),
            None => buf.len(),
        };
        let r = Pin::new(&mut this.inner).poll_write(cx, &buf[..n]);
        match &r {
            Poll::Pending => this.pending = Some(n),
            Poll::Ready(r) => {
                this.pending = None;
                if r.is_ok() {
                    this.first = false;
                }
            }
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks::relay::tcprelay::proxy_stream::ProxyServerStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// xorshift64*: deterministic sizes without a dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self, below: usize) -> usize {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % below as u64) as usize
        }
    }

    /// `tokio::io::copy` into a congested shadowsocks stream: writes go
    /// `Pending` constantly and are retried with more bytes. Every byte must
    /// arrive, in order.
    async fn copy_through_congestion(method: &str, key: &str) {
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = ServerConfig::new(addr, key, method.parse().unwrap()).unwrap();
        let data: Vec<u8> = (0..2_000_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let (client_io, server_io) = tokio::io::duplex(256);
        let (mut feed, mut source) = tokio::io::duplex(4096);
        let client = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local),
            client_io,
            &config,
            Address::DomainNameAddress("example.com".into(), 443),
        );
        let mut client = WriteFix::new(client);
        let feeder = {
            let data = data.clone();
            tokio::spawn(async move {
                let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
                let mut rest = &data[..];
                while !rest.is_empty() {
                    let n = (rng.next(3000) + 1).min(rest.len());
                    feed.write_all(&rest[..n]).await.unwrap();
                    rest = &rest[n..];
                    if rng.next(8) == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            })
        };
        let writer = tokio::spawn(async move {
            tokio::io::copy(&mut source, &mut client).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut server = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server),
            server_io,
            config.method(),
            config.key(),
        );
        let target = server.handshake().await.unwrap();
        assert_eq!(target.to_string(), "example.com:443");
        let mut got = Vec::with_capacity(data.len());
        let mut rng = Rng(42);
        let mut chunk = vec![0u8; 5000];
        loop {
            let n = server.read(&mut chunk[..rng.next(5000) + 1]).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
            if rng.next(4) == 0 {
                tokio::task::yield_now().await;
            }
        }
        feeder.await.unwrap();
        writer.await.unwrap();
        assert_eq!(got.len(), data.len(), "{method}: bytes lost");
        assert!(got == data, "{method}: bytes reordered or corrupted");
    }

    #[tokio::test]
    async fn congested_writes_lose_nothing_2022() {
        copy_through_congestion("2022-blake3-aes-128-gcm", "Ixi/xBrzF3Nnrel2vh8Dsg==").await;
    }

    #[tokio::test]
    async fn congested_writes_lose_nothing_aead() {
        copy_through_congestion("chacha20-ietf-poly1305", "password").await;
    }
}
