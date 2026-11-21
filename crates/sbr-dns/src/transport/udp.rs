//! DNS over UDP: one socket (or proxied UDP association) per server shared
//! by all queries, answers matched by ID and question. A truncated answer is retried
//! over TCP to the same server through the same dialer.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use sbr_core::{BoxFuture, Destination, Host, PacketConn};
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

impl UdpConn {
    /// A failed send retires the socket: a proxied association whose
    /// connection died can keep failing sends while its reads never end, so
    /// the next query dials a new one rather than reusing it.
    async fn send(&self, raw: &[u8]) -> io::Result<()> {
        let r = self.pc.send_to(raw, &self.dest).await;
        if r.is_err() {
            self.pending.close();
        }
        r
    }
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
            let (pc, pending, server) = (pc.clone(), pending.clone(), dest.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, from)) = pc.recv_from(&mut buf).await {
                    // The socket is unconnected: drop datagrams that are not
                    // from the server, so an off-path injector must also spoof
                    // its address. A proxy may report the source by name, so
                    // only addresses are compared.
                    if let (Host::Ip(a), Host::Ip(b)) = (&from.host, &server.host)
                        && (a.to_canonical() != b.to_canonical() || from.port != server.port)
                    {
                        continue;
                    }
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
            let (id, mut rx, _unregister) = c.pending.register(query)?;
            let raw = encode_with_id(query, id)?;
            c.send(&raw).await?;
            let resp = match tokio::time::timeout(RETRANSMIT, &mut rx).await {
                Ok(r) => r,
                Err(_) => {
                    c.send(&raw).await?;
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};
    use sbr_core::{BoxPacketConn, Outbound, Stream};

    use super::*;

    /// The first association acts like one through a QUIC connection that
    /// died: sends fail and reads never end. Later ones answer every query.
    struct Proxy {
        dials: AtomicUsize,
    }

    struct Dead;

    impl PacketConn for Dead {
        fn send_to<'a>(&'a self, _: &'a [u8], _: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async { Err(io::Error::other("connection lost")) })
        }
        fn recv_from<'a>(&'a self, _: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
            Box::pin(std::future::pending())
        }
    }

    struct Echo {
        server: Destination,
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    impl PacketConn for Echo {
        fn send_to<'a>(&'a self, buf: &'a [u8], _: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async move {
                let mut m = msg::decode(buf)?;
                m.metadata.message_type = hickory_proto::op::MessageType::Response;
                let _ = self.tx.send(m.to_vec().map_err(io::Error::other)?);
                Ok(())
            })
        }
        fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
            Box::pin(async move {
                let d = self.rx.lock().await.recv().await.ok_or(io::ErrorKind::BrokenPipe)?;
                buf[..d.len()].copy_from_slice(&d);
                Ok((d.len(), self.server.clone()))
            })
        }
    }

    impl Outbound for Proxy {
        fn tag(&self) -> &str {
            "proxy"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        fn connect<'a>(&'a self, _: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
            Box::pin(async { Err(io::Error::other("no tcp")) })
        }
        fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
            Box::pin(async move {
                if self.dials.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Ok(Box::new(Dead) as BoxPacketConn);
                }
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                Ok(Box::new(Echo {
                    server: dest.clone(),
                    tx,
                    rx: tokio::sync::Mutex::new(rx),
                }) as BoxPacketConn)
            })
        }
    }

    #[tokio::test]
    async fn a_failed_send_dials_a_new_association() {
        let proxy = Arc::new(Proxy {
            dials: AtomicUsize::new(0),
        });
        let udp = Udp::new(Remote {
            host: Host::Ip("127.0.0.1".parse().unwrap()),
            port: 53,
            dialer: proxy.clone(),
            resolver: None,
        });
        let mut query = Message::query();
        query.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
        let first = udp.exchange(&query).await.unwrap_err();
        assert_eq!(first.to_string(), "connection lost");
        let answer = tokio::time::timeout(Duration::from_secs(1), udp.exchange(&query))
            .await
            .expect("the dead association was reused")
            .unwrap();
        assert_eq!(answer.queries, query.queries);
        assert_eq!(proxy.dials.load(Ordering::SeqCst), 2);
    }
}
