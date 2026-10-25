//! The `tun` inbound: a TUN device plus sbr's system or userspace TCP
//! stack, feeding the engine's TCP pipeline and UDP NAT.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll};

use ipnet::IpNet;
use sbr_config::{TunInbound, TunStack};
use sbr_core::{Destination, Host, Metadata, Network};
use sbr_tun::device::{Device, DeviceConfig};
use sbr_tun::{Accepted, Stack, StackConfig, TcpStack};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info, warn};

use crate::dispatch::{InboundStream, OpenError};
use crate::udp::{UdpPacket, UdpWriteBack};
use crate::{Engine, Settings, TunTcp};

/// sing-box's default TUN MTU.
const DEFAULT_MTU: u32 = 9000;

struct TunClient(Accepted);

impl InboundStream for TunClient {
    /// With the userspace stack the app gets a reset, as from a refused
    /// connect; the kernel stack can only close.
    fn fail<'a>(&'a mut self, err: &'a OpenError) -> sbr_core::BoxFuture<'a, io::Result<()>> {
        self.0.stream.refuse(matches!(err, OpenError::Rejected { drop: true }));
        Box::pin(async { Ok(()) })
    }
}

impl AsyncRead for TunClient {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunClient {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0.stream).poll_shutdown(cx)
    }
}

struct TunBack {
    stack: OnceLock<Weak<Stack>>,
}

impl UdpWriteBack for TunBack {
    fn write_back(&self, payload: &[u8], from: &Destination, to: SocketAddr) -> io::Result<()> {
        let Some(stack) = self.stack.get().and_then(Weak::upgrade) else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        let from = match from.host {
            // IPv4-mapped replies to an IPv4 client must go out as IPv4.
            Host::Ip(ip) => SocketAddr::new(ip.to_canonical(), from.port),
            // A domain can't be an IP source; the engine only reports one
            // when the client itself sent to a domain, which TUN apps can't.
            Host::Domain(_) => return Ok(()),
        };
        if from.is_ipv4() != to.is_ipv4() {
            return Ok(());
        }
        stack.write_udp(from, to, payload)
    }

    fn unreachable(&self, from: &Destination, to: SocketAddr) {
        let (Some(stack), Host::Ip(ip)) = (self.stack.get().and_then(Weak::upgrade), &from.host) else {
            return;
        };
        let _ = stack.write_udp_unreachable(SocketAddr::new(ip.to_canonical(), from.port), to);
    }
}

/// Default routes split in halves so they win over the existing default
/// without replacing it (and are cleaned up with the interface).
fn auto_routes(t: &TunInbound) -> Vec<IpNet> {
    if !t.route_address.is_empty() {
        return t.route_address.clone();
    }
    let mut r = Vec::new();
    if t.address.iter().any(|a| a.addr().is_ipv4()) {
        r.extend(["0.0.0.0/1", "128.0.0.0/1"].map(|s| s.parse::<IpNet>().unwrap()));
    }
    if t.address.iter().any(|a| a.addr().is_ipv6()) {
        r.extend(["::/1", "8000::/1"].map(|s| s.parse::<IpNet>().unwrap()));
    }
    r
}

pub async fn start(engine: Arc<Engine>, tag: &str, t: &TunInbound, settings: &Settings) -> io::Result<Arc<Stack>> {
    let mtu = t.mtu.unwrap_or(DEFAULT_MTU);
    let tcp = match settings.tun_stack {
        Some(TunTcp::Userspace) => true,
        Some(TunTcp::Kernel) => false,
        None => t.stack == Some(TunStack::Gvisor),
    };
    if t.strict_route {
        warn!(inbound = tag, "strict_route is not enforced by sbr yet");
    }
    let device = match settings.tun_fd {
        Some(fd) => {
            // The platform (Network Extension) configured addresses and routes.
            Device::adopt(fd)?
        }
        None => {
            let routes = if t.auto_route { auto_routes(t) } else { Vec::new() };
            if t.auto_route {
                // Pin our own sockets to the current default interface before
                // the tunnel's routes take over.
                match sbr_tun::device::default_route() {
                    Some(d) => {
                        info!(interface = %d.interface, "auto_route: outbound sockets bound to the default interface");
                        sbr_core::dial::set_default_interface(Some(d.interface));
                    }
                    None => warn!("auto_route: no default route found; outbound traffic may loop into the tunnel"),
                }
            }
            Device::create(&DeviceConfig {
                name: t.interface_name.clone(),
                mtu,
                address: t.address.clone(),
                routes,
                exclude: t.route_exclude_address.clone(),
            })?
        }
    };
    info!(
        inbound = tag,
        interface = device.name(),
        mtu,
        tcp = if tcp { "userspace" } else { "system" },
        "tun up"
    );

    let tag: Arc<str> = tag.into();
    let back = Arc::new(TunBack { stack: OnceLock::new() });
    let on_tcp = {
        let (engine, tag) = (engine.clone(), tag.clone());
        move |acc: Accepted| {
            let meta = Metadata::new(
                tag.clone(),
                "tun",
                Network::Tcp,
                acc.source,
                Destination::from(acc.destination),
            );
            let engine = engine.clone();
            tokio::spawn(async move {
                let dest = meta.destination.clone();
                if let Err(e) = engine.handle_tcp(meta, TunClient(acc)).await {
                    debug!(%dest, error = %e, "tun tcp");
                }
            });
        }
    };
    let on_udp = {
        let (engine, tag, back) = (engine.clone(), tag.clone(), back.clone() as Arc<dyn UdpWriteBack>);
        move |u: sbr_tun::UdpIn| {
            engine.handle_udp(
                &tag,
                "tun",
                UdpPacket {
                    source: u.source,
                    destination: Destination::from(u.destination),
                    payload: u.payload,
                },
                back.clone(),
            );
        }
    };
    let mut cfg = StackConfig::from_prefixes(&t.address, mtu as usize);
    if tcp {
        cfg.tcp = TcpStack::User(settings.tun_tcp.clone());
    }
    let stack = Arc::new(Stack::start(device, cfg, on_tcp, on_udp).await?);
    let _ = back.stack.set(Arc::downgrade(&stack));
    Ok(stack)
}
