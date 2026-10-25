//! DNS over UDP: one socket (or proxied UDP association) per server shared
//! by all queries, answers matched by ID. A truncated answer is retried
//! over TCP to the same server through the same dialer.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use sbr_core::{BoxFuture, Destination, PacketConn};
use tokio::task::AbortHandle;

use super::stream::{Pending, StreamTransport, encode_with_id};
use super::{Remote, Transport};
use crate::msg;

/// One retransmission if the first datagram (or its answer) got lost.
const RETRANSMIT: Duration = Duration::from_secs(2);

pub(crate) struct Udp {
    remote: Remote,
    conn: tokio::sync::Mutex<Option<Arc<UdpConn>>>,
    tcp: StreamTransport,
}

struct UdpConn {
    pc: Arc<dyn PacketConn>,
    dest: Destination,
    pending: Arc<Pending>,
    reader: AbortHandle,
}

impl Drop for UdpConn {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Udp {
    pub fn new(remote: Remote) -> Self {
        Self {
            tcp: StreamTransport::new(remote.clone(), None),
            remote,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    async fn conn(&self) -> io::Result<Arc<UdpConn>> {
        let mut slot = self.conn.lock().await;
        if let Some(c) = slot.as_ref()
            && !c.pending.is_dead()
        {
            return Ok(c.clone());
        }
        let (pc, dest) = self.remote.connect_udp().await?;
        let pc: Arc<dyn PacketConn> = Arc::from(pc);
        let pending = Arc::new(Pending::default());
        let reader = {
            let (pc, pending) = (pc.clone(), pending.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, _)) = pc.recv_from(&mut buf).await {
                    if let Ok(m) = msg::decode(&buf[..n]) {
                        pending.deliver(m);
                    }
                }
                pending.close();
            })
            .abort_handle()
        };
        let c = Arc::new(UdpConn {
            pc,
            dest,
            pending,
            reader,
        });
        *slot = Some(c.clone());
        Ok(c)
    }
}

impl Transport for Udp {
    fn exchange<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, io::Result<Message>> {
        Box::pin(async move {
            let c = self.conn().await?;
            let (id, mut rx, _unregister) = c.pending.register()?;
            let raw = encode_with_id(query, id)?;
            c.pc.send_to(&raw, &c.dest).await?;
            let resp = match tokio::time::timeout(RETRANSMIT, &mut rx).await {
                Ok(r) => r,
                Err(_) => {
                    c.pc.send_to(&raw, &c.dest).await?;
                    rx.await
                }
            }
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "dns socket closed"))?;
            if resp.metadata.truncation {
                return self.tcp.exchange(query).await;
            }
            Ok(resp)
        })
    }
}
