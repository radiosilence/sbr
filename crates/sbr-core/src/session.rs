use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::Destination;
pub use sbr_config::{Network, Protocol};

/// Everything the router knows about a connection.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub inbound: Arc<str>,
    pub inbound_type: &'static str,
    pub network: Network,
    pub source: SocketAddr,
    pub destination: Destination,
    pub user: Option<Arc<str>>,
    /// Domain recovered by sniffing (TLS SNI, HTTP Host, QUIC SNI).
    pub sniffed_domain: Option<Arc<str>>,
    pub protocol: Option<Protocol>,
    /// Filled by the `resolve` action; `ip_cidr` matches these when the
    /// destination is a domain.
    pub destination_addresses: Vec<IpAddr>,
}

impl Metadata {
    pub fn new(
        inbound: Arc<str>,
        inbound_type: &'static str,
        network: Network,
        source: SocketAddr,
        destination: Destination,
    ) -> Self {
        Self {
            inbound,
            inbound_type,
            network,
            source,
            destination,
            user: None,
            sniffed_domain: None,
            protocol: None,
            destination_addresses: Vec::new(),
        }
    }

    /// The domain rules match against: the requested FQDN, else a sniffed one.
    pub fn domain(&self) -> Option<&str> {
        self.destination.domain().or(self.sniffed_domain.as_deref())
    }

    /// Addresses `ip_cidr`/`ip_is_private` match against.
    pub fn destination_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.destination
            .ip()
            .into_iter()
            .chain(self.destination_addresses.iter().copied())
    }
}
