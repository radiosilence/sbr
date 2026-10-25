//! TUN for sbr: devices, packet rewriting, the "system stack" and a
//! userspace TCP stack (`tcp`, selected by `stack: gvisor`).
//!
//! The system stack lets the OS kernel run TCP. A SYN from an app to
//! `D:dp` arriving on the TUN is rewritten to come from `next:nat_port` and go
//! to `addr:listen_port`, then written back into the TUN. The kernel delivers
//! it to our listener on the TUN address, and the accepted socket's peer port
//! identifies the original flow. Replies are rewritten in reverse. Only
//! headers are touched, so bulk TCP costs two syscalls and a checksum fix
//! per packet, with no userspace TCP state machine. UDP is handed to the
//! engine's NAT as datagrams. IP fragments are reassembled first (`frag`).

pub mod device;
pub mod frag;
pub mod nat;
pub mod packet;
pub mod stack;
pub mod tcp;

pub use device::Device;
pub use stack::{Accepted, Stack, StackConfig, TcpConn, TcpStack, UdpIn};
pub use tcp::TcpConfig;
