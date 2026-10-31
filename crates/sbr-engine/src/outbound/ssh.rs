//! SSH client (sing-box `ssh` outbound): one SSH connection per outbound,
//! one `direct-tcpip` channel per stream.
//!
//! russh's flow control is its per-channel message queue, not the SSH window:
//! it adjusts the window as packets arrive, then blocks the whole connection
//! when a channel's queue is full. `CHANNEL_QUEUE` therefore bounds memory
//! per channel, `max_channels` bounds it per connection, and one stalled
//! reader stalls every channel on the connection.

use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::future::Shared;
use russh::client::{self, Handle};
use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::{Disconnect, Limits, Preferred, SshId, cipher, compression, kex, mac};
use sbr_config::SshOutbound;
use sbr_core::{BoxFuture, Destination, Host, Outbound, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{BuildContext, Upstream};

/// What sbr announces unless `client_version` says otherwise.
const DEFAULT_CLIENT_VERSION: &str = "SSH-2.0-OpenSSH_9.9";
/// TCP connect, key exchange and authentication together.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);
/// A channel open that gets no answer means the connection is dead (often a
/// NAT mapping that expired while idle).
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);
/// A connection with no channels for this long is closed, so a stale one is
/// never reused after a long idle period and idle costs no wakeups.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Messages (up to `MAX_PACKET` each) queued per channel before russh stops
/// reading the connection.
const CHANNEL_QUEUE: usize = 4;
const MAX_PACKET: u32 = 32768;

/// Concurrent channels per outbound, sized so that full queues stay within
/// the iOS extension's memory budget (`CHANNEL_QUEUE * MAX_PACKET` each).
fn max_channels() -> usize {
    if cfg!(any(target_os = "ios", target_os = "tvos")) {
        32
    } else {
        256
    }
}

/// OpenSSH 9.9's client proposal, limited to what russh implements, so the
/// key exchange matches the banner as closely as russh allows.
const KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_GEX_SHA256,
    kex::DH_G16_SHA512,
    kex::DH_G18_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];
const CIPHERS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_128_CTR,
    cipher::AES_192_CTR,
    cipher::AES_256_CTR,
    cipher::AES_128_GCM,
    cipher::AES_256_GCM,
];
const MACS: &[mac::Name] = &[
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA1_ETM,
    mac::HMAC_SHA256,
    mac::HMAC_SHA512,
    mac::HMAC_SHA1,
];
const COMPRESSION: &[compression::Name] = &[compression::NONE, compression::ZLIB_LEGACY];
const HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];

type DialResult = Result<Arc<Conn>, Arc<io::Error>>;

enum State {
    Down,
    Dialing(Shared<BoxFuture<'static, DialResult>>),
    Up(Arc<Conn>),
}

struct Conn {
    handle: Handle<Client>,
    channels: AtomicUsize,
    /// Bumped whenever the channel count leaves zero, so an idle timer can
    /// tell whether the connection was used since it was armed.
    epoch: AtomicU64,
}

/// Ask the server to close; the session task then ends and drops the socket.
fn close(conn: &Arc<Conn>) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let conn = conn.clone();
    rt.spawn(async move {
        let _ = conn.handle.disconnect(Disconnect::ByApplication, "", "").await;
    });
}

struct Inner {
    upstream: Upstream,
    server: Destination,
    config: Arc<client::Config>,
    user: String,
    key: Option<Arc<PrivateKey>>,
    password: Option<String>,
    pins: Arc<[PublicKey]>,
    state: Mutex<State>,
    slots: Arc<Semaphore>,
}

pub struct Ssh {
    tag: String,
    inner: Arc<Inner>,
}

impl Ssh {
    pub fn new(tag: String, c: &SshOutbound, upstream: Upstream, ctx: &BuildContext) -> Result<Self, String> {
        let pem = match (&c.private_key, &c.private_key_path) {
            (Some(k), _) => Some(k.clone()),
            (None, Some(p)) => {
                let path = match &ctx.base_dir {
                    Some(base) => base.join(p),
                    None => p.into(),
                };
                Some(std::fs::read_to_string(&path).map_err(|e| format!("private_key_path {}: {e}", path.display()))?)
            }
            (None, None) => None,
        };
        let key = pem
            .map(|pem| russh::keys::decode_secret_key(&pem, c.private_key_passphrase.as_deref()))
            .transpose()
            .map_err(|e| format!("private_key: {e}"))?
            .map(Arc::new);
        if key.is_none() && c.password.is_none() {
            return Err("one of password, private_key or private_key_path is required".into());
        }
        let pins = c
            .host_key
            .iter()
            .map(|line| {
                let b64 = line.split_whitespace().nth(1).unwrap_or_default();
                russh::keys::parse_public_key_base64(b64).map_err(|e| format!("host_key {line:?}: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let host_keys = host_key_algorithms(&c.host_key_algorithms, &pins)?;
        let config = client::Config {
            client_id: SshId::Standard(Cow::Owned(
                c.client_version
                    .clone()
                    .unwrap_or_else(|| DEFAULT_CLIENT_VERSION.into()),
            )),
            // OpenSSH rekeys on volume only; a time limit would also wake every idle connection.
            limits: Limits::new(1 << 30, 1 << 30, Duration::MAX),
            maximum_packet_size: MAX_PACKET,
            channel_buffer_size: CHANNEL_QUEUE,
            preferred: Preferred {
                kex: Cow::Borrowed(KEX),
                key: Cow::Owned(host_keys),
                cipher: Cow::Borrowed(CIPHERS),
                mac: Cow::Borrowed(MACS),
                compression: Cow::Borrowed(COMPRESSION),
                ..Preferred::DEFAULT
            },
            inactivity_timeout: None,
            keepalive_interval: None,
            nodelay: true,
            ..Default::default()
        };
        Ok(Self {
            tag,
            inner: Arc::new(Inner {
                upstream,
                server: Destination::from_host_port(&c.server.server, c.server.server_port),
                config: Arc::new(config),
                user: c.user.clone(),
                key,
                password: c.password.clone(),
                pins: pins.into(),
                state: Mutex::new(State::Down),
                slots: Arc::new(Semaphore::new(max_channels())),
            }),
        })
    }
}

/// `host_key_algorithms` when given; otherwise the pinned keys' algorithms
/// (so a server with several host keys presents the pinned one), or the
/// OpenSSH order when nothing is pinned.
fn host_key_algorithms(names: &[String], pins: &[PublicKey]) -> Result<Vec<Algorithm>, String> {
    if !names.is_empty() {
        return names
            .iter()
            .map(|n| {
                n.parse::<Algorithm>()
                    .map_err(|e| format!("host_key_algorithms {n:?}: {e}"))
            })
            .collect();
    }
    if pins.is_empty() {
        return Ok(HOST_KEYS.to_vec());
    }
    Ok(HOST_KEYS
        .iter()
        .filter(|a| {
            pins.iter().any(|p| match (p.algorithm(), a) {
                (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
                (pa, a) => &pa == *a,
            })
        })
        .cloned()
        .collect())
}

impl Inner {
    /// The live connection, dialing one if there is none. Concurrent callers
    /// share one dial and its outcome.
    async fn conn(self: &Arc<Self>) -> io::Result<Arc<Conn>> {
        let dial = {
            let mut st = self.state.lock().unwrap();
            match &*st {
                State::Up(c) if !c.handle.is_closed() => return Ok(c.clone()),
                State::Dialing(f) => f.clone(),
                _ => {
                    let me = Arc::downgrade(self);
                    let f = async move {
                        let me = me
                            .upgrade()
                            .ok_or_else(|| Arc::new(io::Error::other("ssh: outbound closed")))?;
                        let r = tokio::time::timeout(DIAL_TIMEOUT, me.dial()).await.unwrap_or_else(|_| {
                            Err(io::Error::new(io::ErrorKind::TimedOut, "ssh: handshake timed out"))
                        });
                        let mut st = me.state.lock().unwrap();
                        match r {
                            Ok(c) => {
                                let c = Arc::new(c);
                                *st = State::Up(c.clone());
                                Ok(c)
                            }
                            Err(e) => {
                                *st = State::Down;
                                Err(Arc::new(e))
                            }
                        }
                    }
                    .boxed()
                    .shared();
                    *st = State::Dialing(f.clone());
                    f
                }
            }
        };
        dial.await.map_err(|e| io::Error::new(e.kind(), e.to_string()))
    }

    async fn dial(&self) -> io::Result<Conn> {
        let stream = self.upstream.connect(&self.server).await?;
        let handler = Client {
            pins: self.pins.clone(),
        };
        let mut handle = client::connect_stream(self.config.clone(), stream, handler)
            .await
            .map_err(ssh_err)?;
        // Key first: a signature gives an impostor nothing, a password gives it the password.
        let mut ok = false;
        if let Some(key) = &self.key {
            let hash = handle.best_supported_rsa_hash().await.map_err(ssh_err)?.flatten();
            let key = PrivateKeyWithHashAlg::new(key.clone(), hash);
            ok = handle
                .authenticate_publickey(&self.user, key)
                .await
                .map_err(ssh_err)?
                .success();
        }
        if !ok && let Some(pw) = &self.password {
            ok = handle
                .authenticate_password(&self.user, pw)
                .await
                .map_err(ssh_err)?
                .success();
        }
        if !ok {
            let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ssh: authentication failed",
            ));
        }
        Ok(Conn {
            handle,
            channels: AtomicUsize::new(0),
            epoch: AtomicU64::new(0),
        })
    }

    /// Drop `conn` if it is still the current one.
    fn discard(&self, conn: &Arc<Conn>) {
        let mut st = self.state.lock().unwrap();
        if matches!(&*st, State::Up(c) if Arc::ptr_eq(c, conn)) {
            *st = State::Down;
        }
        drop(st);
        close(conn);
    }

    async fn open(self: &Arc<Self>, dest: &Destination) -> io::Result<Stream> {
        let permit = tokio::time::timeout(OPEN_TIMEOUT, self.slots.clone().acquire_owned())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ssh: too many open channels"))?
            .expect("semaphore never closed");
        let host = match &dest.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(d) => d.to_string(),
        };
        // A connection that stopped answering is replaced once.
        for attempt in 0..2 {
            let conn = self.conn().await?;
            conn.channels.fetch_add(1, Ordering::AcqRel);
            conn.epoch.fetch_add(1, Ordering::AcqRel);
            let mut guard = ChannelGuard {
                conn: conn.clone(),
                inner: Arc::downgrade(self),
                _permit: None,
            };
            let opened = tokio::time::timeout(
                OPEN_TIMEOUT,
                conn.handle
                    .channel_open_direct_tcpip(host.as_str(), dest.port as u32, "127.0.0.1", 0),
            )
            .await;
            match opened {
                Ok(Ok(ch)) => {
                    guard._permit = Some(permit);
                    return Ok(Box::new(SshStream {
                        s: ch.into_stream(),
                        _guard: guard,
                    }));
                }
                // The server refused this destination; the connection is fine.
                Ok(Err(russh::Error::ChannelOpenFailure(reason))) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("ssh: channel open refused: {reason:?}"),
                    ));
                }
                Ok(Err(e)) if attempt == 1 => return Err(ssh_err(e)),
                Err(_) if attempt == 1 => {
                    self.discard(&conn);
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "ssh: channel open timed out"));
                }
                Ok(Err(_)) | Err(_) => self.discard(&conn),
            }
        }
        unreachable!("the second attempt returns")
    }

    fn network_changed(&self) {
        let old = std::mem::replace(&mut *self.state.lock().unwrap(), State::Down);
        if let State::Up(c) = old {
            close(&c);
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let State::Up(c) = std::mem::replace(self.state.get_mut().unwrap(), State::Down) {
            close(&c);
        }
    }
}

/// Counts a channel against its connection; the last one out arms the idle close.
struct ChannelGuard {
    conn: Arc<Conn>,
    inner: Weak<Inner>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        if self.conn.channels.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let epoch = self.conn.epoch.load(Ordering::Acquire);
        let conn = Arc::downgrade(&self.conn);
        let inner = self.inner.clone();
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        rt.spawn(async move {
            tokio::time::sleep(IDLE_TIMEOUT).await;
            let Some(conn) = conn.upgrade() else { return };
            if conn.channels.load(Ordering::Acquire) == 0 && conn.epoch.load(Ordering::Acquire) == epoch {
                match inner.upgrade() {
                    Some(inner) => inner.discard(&conn),
                    None => close(&conn),
                }
            }
        });
    }
}

struct SshStream {
    s: russh::ChannelStream<client::Msg>,
    _guard: ChannelGuard,
}

impl AsyncRead for SshStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.s).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_shutdown(cx)
    }
}

struct Client {
    pins: Arc<[PublicKey]>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        Ok(self.pins.is_empty() || self.pins.iter().any(|p| p.key_data() == key.key_data()))
    }
}

fn ssh_err(e: russh::Error) -> io::Error {
    match e {
        russh::Error::IO(e) => e,
        russh::Error::UnknownKey => io::Error::new(io::ErrorKind::PermissionDenied, "ssh: server host key not pinned"),
        e => io::Error::other(format!("ssh: {e}")),
    }
}

impl Outbound for Ssh {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "ssh"
    }

    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(self.inner.open(dest))
    }

    fn network_changed(&self) {
        self.inner.network_changed();
    }
}
