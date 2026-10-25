//! The TCP pipeline: walk the rules (sniffing / resolving when told to),
//! connect, answer the inbound, relay.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use sbr_core::router::{Action, RouteOptions};
use sbr_core::sniff::{self, Sniffed};
use sbr_core::{AsyncStream, BoxFuture, Metadata, Protocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, info, warn};

use crate::{Engine, health};

/// sing-box `C.ReadPayloadTimeout`.
pub const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
const SNIFF_MAX: usize = 8 * 1024;

/// Why a connection could not be opened.
#[derive(Debug)]
pub enum OpenError {
    Rejected { drop: bool },
    Io(io::Error),
}

/// A client connection handed to the engine by an inbound.
pub trait InboundStream: AsyncStream {
    /// The engine is about to read from the client or relay: inbounds that
    /// owe the client a handshake reply (SOCKS5, HTTP CONNECT) send success.
    /// Must be idempotent.
    fn ready(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    /// The outbound failed before `ready` ran: tell the client why.
    fn fail<'a>(&'a mut self, err: &'a OpenError) -> BoxFuture<'a, io::Result<()>> {
        let _ = err;
        Box::pin(async { Ok(()) })
    }
}

impl InboundStream for tokio::net::TcpStream {}

/// Wraps the client so bytes read while sniffing are replayed to the relay.
struct Replay<S> {
    inner: S,
    head: Vec<u8>,
    pos: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pos < this.head.len() {
            let n = (this.head.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.head[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.head.len() {
                this.head = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl Engine {
    /// Run a client TCP connection to completion.
    pub async fn handle_tcp<S: InboundStream>(&self, mut meta: Metadata, mut client: S) -> io::Result<()> {
        let Some(_slot) = self.admit() else {
            debug!(inbound = %meta.inbound, dest = %meta.destination, limit = self.max_connections, "connection limit reached");
            return client.fail(&OpenError::Rejected { drop: false }).await;
        };
        // DNS: a FakeIP destination becomes its domain (and, with
        // reverse_mapping, a recently resolved IP gains one) before routing.
        if let Err(e) = self.restore_domain(&mut meta) {
            let err = OpenError::Io(e);
            client.fail(&err).await?;
            let OpenError::Io(e) = err else { unreachable!() };
            return Err(e);
        }
        let mut client = Replay {
            inner: client,
            head: Vec::new(),
            pos: 0,
        };
        let mut opts = RouteOptions::default();
        let mut sniffed = false;
        let mut i = 0;
        // The deciding rule, for the connection registry (`None`: final).
        let mut matched = None;
        let action = loop {
            let Some((idx, action)) = self.router.next(&meta, i) else {
                break Action::Route {
                    outbound: self.router.final_outbound(),
                    options: opts,
                };
            };
            i = idx + 1;
            match action {
                Action::Sniff { sniffers, timeout } => {
                    if !sniffed {
                        sniffed = true;
                        client.inner.ready().await?;
                        sniff_stream(&mut client, &mut meta, sniffers, timeout.unwrap_or(SNIFF_TIMEOUT)).await?;
                    }
                }
                Action::RouteOptions(o) => opts.merge(o),
                Action::Resolve { server, strategy } => self.resolve(&mut meta, server.as_deref(), *strategy).await,
                Action::Route { outbound, options } => {
                    opts.merge(options);
                    matched = Some(idx);
                    break Action::Route {
                        outbound: *outbound,
                        options: opts,
                    };
                }
                final_action => {
                    matched = Some(idx);
                    break final_action.clone();
                }
            }
        };

        match action {
            Action::Route { outbound, options } => {
                let out = &self.outbounds[outbound];
                let dest = options.apply(&meta.destination);
                debug!(inbound = %meta.inbound, dest = %meta.destination, domain = meta.sniffed_domain.as_deref().unwrap_or(""), outbound = out.tag(), "route");
                match out.connect(&dest).await {
                    Ok(remote) => {
                        client.inner.ready().await?;
                        // Registered once connected, like sing-box; closing it
                        // through the registry aborts the relay.
                        let (reg, cancelled) = self.tracker.register(meta.clone(), self.chain(outbound), matched);
                        let conn = &reg.conn;
                        let leaf = conn.chain.first().cloned().unwrap_or_else(|| out.tag().into());
                        let client = crate::track::Counted { inner: client, conn };
                        let remote = health::Observed::new(remote, &conn.activity);
                        let watch = health::watch(conn, |w| match w {
                            health::Watched::Stalled(s) => self.groups.report(&leaf, s, &dest, Some(conn.id)),
                            health::Watched::Recovered => self.groups.retract(&leaf, conn.id),
                        });
                        let r = tokio::select! {
                            biased;
                            r = self.relay(&meta, client, remote) => r,
                            _ = cancelled.wait() => Ok(()),
                            never = watch => match never {},
                        };
                        self.groups.finished(&leaf, conn, &dest);
                        r
                    }
                    Err(e) => {
                        warn!(inbound = %meta.inbound, dest = %dest, outbound = out.tag(), error = %e, "connect failed");
                        if out.kind() != "block"
                            && let Some(leaf) = self.chain(outbound).first()
                        {
                            self.groups.report(leaf, health::Signal::Connect, &dest, None);
                        }
                        let err = OpenError::Io(e);
                        client.inner.fail(&err).await?;
                        let OpenError::Io(e) = err else { unreachable!() };
                        Err(e)
                    }
                }
            }
            Action::Reject { drop, .. } => {
                info!(inbound = %meta.inbound, dest = %meta.destination, domain = meta.sniffed_domain.as_deref().unwrap_or(""), "rejected");
                client.inner.fail(&OpenError::Rejected { drop }).await?;
                if drop {
                    // Black-hole: hold the connection open without answering.
                    let mut sink = [0u8; 4096];
                    while client.read(&mut sink).await? > 0 {}
                }
                Ok(())
            }
            Action::HijackDns => {
                client.inner.ready().await?;
                self.serve_dns_tcp(&meta, client).await
            }
            _ => unreachable!("non-final action"),
        }
    }

    pub(crate) async fn resolve(
        &self,
        meta: &mut Metadata,
        server: Option<&str>,
        strategy: Option<sbr_config::DomainStrategy>,
    ) {
        let Some(domain) = meta.destination.domain().map(str::to_owned) else {
            return;
        };
        // `server` names a DNS server; otherwise DNS rules see the connection.
        let bound = server.and_then(|s| {
            let r = sbr_config::DomainResolver {
                server: s.to_owned(),
                ..Default::default()
            };
            self.dns.bind(&sbr_core::dns::ResolverSpec {
                resolver: Some(&r),
                outbound: None,
            })
        });
        let result = match bound {
            Some(d) => d.lookup(&domain, strategy).await,
            None => self.dns.lookup_for(&domain, strategy, meta).await,
        };
        match result {
            Ok(ips) => meta.destination_addresses = ips,
            Err(e) => tracing::warn!(%domain, error = %e, "resolve failed"),
        }
    }

    /// DNS over TCP (RFC 7766): length-prefixed messages until EOF.
    async fn serve_dns_tcp<S: AsyncRead + AsyncWrite + Unpin>(&self, meta: &Metadata, mut s: S) -> io::Result<()> {
        loop {
            let len = match s.read_u16().await {
                Ok(n) => n as usize,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            let mut q = vec![0u8; len];
            s.read_exact(&mut q).await?;
            let resp = self.dns.exchange(&q, meta).await?;
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            s.write_all(&out).await?;
        }
    }
}

async fn sniff_stream<S: AsyncRead + Unpin>(
    client: &mut Replay<S>,
    meta: &mut Metadata,
    sniffers: &[Protocol],
    timeout: Duration,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = std::mem::take(&mut client.head);
    loop {
        match sniff::stream(&buf, sniffers) {
            Sniffed::Found { protocol, domain } => {
                meta.protocol = Some(protocol);
                if let Some(d) = domain {
                    meta.sniffed_domain = Some(d.into());
                }
                break;
            }
            Sniffed::Unknown if !buf.is_empty() => break,
            _ if buf.len() >= SNIFF_MAX => break,
            _ => {}
        }
        let start = buf.len();
        buf.resize(start + 2048, 0);
        let n = match tokio::time::timeout_at(deadline, client.inner.read(&mut buf[start..])).await {
            Ok(r) => r?,
            Err(_) => 0, // timed out: route with what we have
        };
        buf.truncate(start + n);
        if n == 0 {
            break;
        }
    }
    client.head = buf;
    client.pos = 0;
    Ok(())
}
