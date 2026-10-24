//! The data plane: session metadata, routing and the relay loop. No protocol
//! code lives here.

mod addr;
pub mod dial;
pub mod relay;
pub mod router;
mod session;

pub use addr::{Destination, Host, is_private};
pub use session::{Metadata, Network};

use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub type Stream = Box<dyn AsyncStream>;
