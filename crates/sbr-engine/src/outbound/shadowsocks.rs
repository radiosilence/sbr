use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use sbr_config::ShadowsocksOutbound;
use sbr_core::{BoxFuture, Destination, Host, Stream};
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Outbound, Upstream};

pub struct Shadowsocks {
    tag: String,
    server: Destination,
    config: ServerConfig,
    context: SharedContext,
    upstream: Upstream,
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
        if c.network == Some(sbr_config::Network::Udp) {
            return Err("UDP-only shadowsocks is not supported by sbr yet".into());
        }
        let addr = match c.server.server.parse() {
            Ok(ip) => ServerAddr::SocketAddr(std::net::SocketAddr::new(ip, c.server.server_port)),
            Err(_) => ServerAddr::DomainName(c.server.server.clone(), c.server.server_port),
        };
        let config =
            ServerConfig::new(addr, c.password.clone(), method).map_err(|e| e.to_string())?;
        Ok(Self {
            tag,
            server: Destination::from_host_port(&c.server.server, c.server.server_port),
            config,
            context: Context::new_shared(ServerType::Local),
            upstream,
        })
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
            let s = self.upstream.connect(&self.server).await?;
            let addr = match &dest.host {
                Host::Ip(ip) => Address::SocketAddress(std::net::SocketAddr::new(*ip, dest.port)),
                Host::Domain(d) => Address::DomainNameAddress(d.to_string(), dest.port),
            };
            // The request header goes out with the first payload write, so
            // this costs no extra round trip (same as sing-box).
            let inner = ProxyClientStream::from_stream(self.context.clone(), s, &self.config, addr);
            Ok(Box::new(FirstWriteCap { inner, first: true }) as Stream)
        })
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
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstWriteCap<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
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
