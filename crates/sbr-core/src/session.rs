use std::net::SocketAddr;
use std::sync::Arc;

use crate::Destination;
pub use sbr_config::Network;

/// Everything the router knows about a connection.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub inbound: Arc<str>,
    pub inbound_type: &'static str,
    pub network: Network,
    pub source: SocketAddr,
    pub destination: Destination,
    pub user: Option<Arc<str>>,
}
