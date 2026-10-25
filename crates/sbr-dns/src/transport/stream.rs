//! DNS over TCP and over TLS (RFC 7766 / RFC 7858): one connection per
//! server, queries pipelined on it and matched to answers by ID.
//!
//! The connection lives until the server closes it or it fails; the next
//! query then dials a new one. Nothing is timed on our side while idle.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hickory_proto::op::Message;
use sbr_core::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use super::tls::Tls;
use super::{Remote, Transport};
use crate::msg;

pub(crate) struct StreamTransport {
    remote: Remote,
    tls: Option<Tls>,
    conn: tokio::sync::Mutex<Option<Arc<Conn>>>,
}

/// Outstanding queries per upstream connection.
const MAX_PENDING: usize = 4096;

/// State shared by a connection's task and its users.
#[derive(Default)]
pub(crate) struct Pending {
    map: Mutex<HashMap<u16, oneshot::Sender<Message>>>,
    dead: AtomicBool,
}

impl Pending {
    /// Register a waiter under a fresh ID. Fails when too many queries are
    /// outstanding on this connection; the ID search below would otherwise
    /// spin forever once all 65536 IDs are taken.
    pub fn register(self: &Arc<Self>) -> io::Result<(u16, oneshot::Receiver<Message>, Unregister)> {
        let mut map = self.map.lock().unwrap();
        if map.len() >= MAX_PENDING {
            return Err(io::Error::other("too many DNS queries in flight"));
        }
        let (tx, rx) = oneshot::channel();
        let mut id = crate::random_u16();
        while map.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        map.insert(id, tx);
        Ok((id, rx, Unregister(self.clone(), id)))
    }

    pub fn deliver(&self, m: Message) {
        if let Some(tx) = self.map.lock().unwrap().remove(&m.metadata.id) {
            let _ = tx.send(m);
        }
    }

    /// The connection is gone: fail every waiter.
    pub fn close(&self) {
        self.dead.store(true, Ordering::Release);
        self.map.lock().unwrap().clear();
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }
}

/// Drops a waiter whose caller gave up (timeout, cancellation).
pub(crate) struct Unregister(Arc<Pending>, u16);

impl Drop for Unregister {
    fn drop(&mut self) {
        self.0.map.lock().unwrap().remove(&self.1);
    }
}

pub(crate) struct Conn {
    tx: mpsc::Sender<Vec<u8>>,
    pending: Arc<Pending>,
}

/// Encode `query` under `id` without cloning the message.
pub(crate) fn encode_with_id(query: &Message, id: u16) -> io::Result<Vec<u8>> {
    let mut raw = msg::encode(query)?;
    raw[..2].copy_from_slice(&id.to_be_bytes());
    Ok(raw)
}

impl StreamTransport {
    pub fn new(remote: Remote, tls: Option<Tls>) -> Self {
        Self {
            remote,
            tls,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// The live connection, or a new one. The bool says it was reused.
    async fn conn(&self) -> io::Result<(Arc<Conn>, bool)> {
        let mut slot = self.conn.lock().await;
        if let Some(c) = slot.as_ref()
            && !c.pending.is_dead()
        {
            return Ok((c.clone(), true));
        }
        let mut stream = self.remote.connect().await?;
        if let Some(tls) = &self.tls {
            stream = tls.connect(stream).await?.0;
        }
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
        let pending = Arc::new(Pending::default());
        let conn = Arc::new(Conn {
            tx,
            pending: pending.clone(),
        });
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            let reader = async {
                loop {
                    let len = r.read_u16().await? as usize;
                    let mut buf = vec![0u8; len];
                    r.read_exact(&mut buf).await?;
                    match msg::decode(&buf) {
                        Ok(m) => pending.deliver(m),
                        Err(e) => return Err::<(), io::Error>(e),
                    }
                }
            };
            // Ends when every `Conn` handle is dropped.
            let writer = async {
                while let Some(frame) = rx.recv().await {
                    w.write_all(&frame).await?;
                    w.flush().await?;
                }
                Ok::<(), io::Error>(())
            };
            tokio::select! {
                _ = reader => {}
                _ = writer => {}
            }
            pending.close();
        });
        *slot = Some(conn.clone());
        Ok((conn, false))
    }

    async fn once(&self, query: &Message) -> (io::Result<Message>, bool) {
        let (conn, reused) = match self.conn().await {
            Ok(c) => c,
            Err(e) => return (Err(e), false),
        };
        let (id, rx, _unregister) = match conn.pending.register() {
            Ok(r) => r,
            Err(e) => return (Err(e), false),
        };
        let raw = match encode_with_id(query, id) {
            Ok(r) => r,
            Err(e) => return (Err(e), false),
        };
        let mut frame = Vec::with_capacity(raw.len() + 2);
        frame.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        frame.extend_from_slice(&raw);
        if conn.tx.send(frame).await.is_err() {
            return (
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "dns connection closed")),
                reused,
            );
        }
        match rx.await {
            Ok(m) => (Ok(m), reused),
            Err(_) => (
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "dns connection closed")),
                reused,
            ),
        }
    }
}

impl Transport for StreamTransport {
    fn exchange<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, io::Result<Message>> {
        Box::pin(async move {
            // A reused connection may have been closed by the server just as
            // we wrote to it: retry once on a fresh one.
            match self.once(query).await {
                (Err(_), true) => self.once(query).await.0,
                (r, _) => r,
            }
        })
    }
}
