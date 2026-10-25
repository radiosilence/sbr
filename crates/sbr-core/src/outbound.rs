//! The contracts every protocol implements.

use std::io;
use std::sync::Arc;

use crate::{BoxFuture, Destination, Stream};

/// A UDP association. One per NAT session; `send_to` may address any
/// destination (full-cone), replies carry their source.
pub trait PacketConn: Send + Sync {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>>;
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>>;
}

pub type BoxPacketConn = Box<dyn PacketConn>;

pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    /// sing-box type name, e.g. `"vless"`.
    fn kind(&self) -> &'static str;
    /// Open a TCP stream to `dest`.
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>>;
    /// Open a UDP association. `dest` is the first destination, which some
    /// protocols need up front (and which `udp_connect` pins).
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        let _ = dest;
        let kind = self.kind();
        Box::pin(async move {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{kind}: UDP not supported by sbr yet"),
            ))
        })
    }
    /// Groups expose their selection API.
    fn as_group(&self) -> Option<&dyn Group> {
        None
    }
    /// Round-trip time to the protocol's server, measured without contacting
    /// anything else (e.g. a QUIC connection's RTT estimate). `urltest` uses
    /// it when no `url` is configured. `None`: not supported.
    fn probe_rtt(&self) -> Option<BoxFuture<'_, io::Result<std::time::Duration>>> {
        None
    }
}

/// `selector` / `urltest`.
pub trait Group: Send + Sync {
    fn members(&self) -> Vec<Arc<dyn Outbound>>;
    fn selected(&self) -> Arc<dyn Outbound>;
    /// Only meaningful for `selector`; returns false otherwise.
    fn select(&self, tag: &str) -> bool;
}
