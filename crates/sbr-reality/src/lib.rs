//! A TLS 1.3 client whose ClientHello is a browser's, for REALITY and for
//! ordinary TLS.
//!
//! rustls cannot emit a browser ClientHello, and its own is recognisable on
//! the wire, so this crate carries a small TLS 1.3 client (aws-lc-rs for every
//! primitive): `hello` builds the fingerprinted ClientHello, `handshake` runs
//! the handshake (HelloRetryRequest, certificate compression and ALPS
//! included), and [`TlsStream`] is the record layer.
//!
//! - [`connect_tls`]: ordinary TLS; the server certificate goes through a
//!   rustls [`ServerCertVerifier`], so WebPKI, custom roots and pins work as
//!   with rustls.
//! - [`connect`]: REALITY (XTLS/Xray, as in sing-box
//!   `common/tls/reality_client.go`), a TLS 1.3 handshake that authenticates
//!   to the server with an X25519 public key and a short_id hidden in the
//!   ClientHello session_id. Unauthenticated clients are proxied to a real
//!   "dest" site; authenticated ones get a throwaway certificate signed with a
//!   key derived from the shared secret.
//!
//! TLS 1.2 is offered in the ClientHello, as browsers do, but not
//! implemented: a server that picks it gets an alert-free close and the
//! caller an `Unsupported` error. Sessions are never resumed.
//!
//! ```no_run
//! # async fn f() -> std::io::Result<()> {
//! let tcp = tokio::net::TcpStream::connect("203.0.113.1:443").await?;
//! let cfg = sbr_reality::RealityConfig::new(
//!     "www.example.com",
//!     "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
//!     "0123456789abcdef",
//! )?;
//! let tls = sbr_reality::connect(tcp, &cfg).await?;
//! # let _ = tls; Ok(()) }
//! ```

mod fallback;
mod handshake;
mod hello;
mod keys;
mod reality;
mod record;
mod stream;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_tests;

use std::io;
use std::sync::Arc;

use base64::Engine;
pub use rustls::client::danger::ServerCertVerifier;
pub use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};

pub use hello::Fingerprint;
pub use keys::CipherSuite;
pub use stream::TlsStream;

/// Writes a ClientHello's session id; see [`connect_tls_with_session_id`].
pub type SessionIdFn = dyn Fn(&mut [u8]) + Sync;

/// The REALITY connection type (an alias kept for existing callers).
pub type RealityStream<S> = TlsStream<S>;

/// Options for ordinary TLS with a browser ClientHello.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// Certificate verification name.
    pub server_name: ServerName<'static>,
    /// Send SNI (sing-box `disable_sni` turns it off). IP addresses never go in SNI.
    pub sni: bool,
    pub fingerprint: Fingerprint,
    /// `tls.alpn`; empty keeps the fingerprint's own list (h2, http/1.1).
    pub alpn: Vec<String>,
    /// Offer X25519MLKEM768 where the browser does.
    pub post_quantum: bool,
    pub verifier: Arc<dyn ServerCertVerifier>,
}

impl TlsConfig {
    fn hello_name(&self) -> Option<String> {
        match &self.server_name {
            ServerName::DnsName(d) if self.sni => Some(d.as_ref().to_owned()),
            _ => None,
        }
    }
}

/// TLS 1.3 handshake over `stream` with the configured browser fingerprint.
pub async fn connect_tls<S>(stream: S, cfg: &TlsConfig) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    connect_tls_with_session_id(stream, cfg, None).await
}

/// As [`connect_tls`], with the first ClientHello's 32-byte session id
/// chosen by `session_id`: it gets the whole handshake message with the
/// session id (at byte 39) zeroed and writes the id in place. ShadowTLS v3
/// authenticates with it.
pub async fn connect_tls_with_session_id<S>(
    stream: S,
    cfg: &TlsConfig,
    session_id: Option<&SessionIdFn>,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = cfg.hello_name();
    let params = hello::HelloParams {
        fingerprint: cfg.fingerprint,
        server_name: name.as_deref(),
        alpn: &cfg.alpn,
        post_quantum: cfg.post_quantum,
    };
    let auth = handshake::Auth::Verify {
        verifier: cfg.verifier.as_ref(),
        name: &cfg.server_name,
        session_id,
    };
    handshake::handshake(stream, &params, auth).await
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub use handshake::fuzz_handshake_messages;

/// Client options, mirroring sing-box's outbound `tls` with `utls` and `reality`.
#[derive(Clone, Debug)]
pub struct RealityConfig {
    /// SNI; must be one of the server's `server_names`. An IP literal sends no SNI.
    pub server_name: String,
    /// Server X25519 public key (`reality.public_key`, decoded).
    pub public_key: [u8; 32],
    /// `reality.short_id`, decoded and zero-padded to 8 bytes.
    pub short_id: [u8; 8],
    /// `utls.fingerprint`.
    pub fingerprint: Fingerprint,
    /// `tls.alpn`; empty keeps the fingerprint's own list (h2, http/1.1).
    pub alpn: Vec<String>,
    /// Offer X25519MLKEM768 where the browser does (Chrome). Default true:
    /// current Chrome sends it, and Xray and sing-box (metacubex/utls) servers
    /// accept it. Turn it off for old REALITY servers that only handle X25519
    /// (sing-box's own client strips it).
    pub post_quantum: bool,
}

impl RealityConfig {
    /// Parses the sing-box string forms. The fingerprint is Chrome; set the
    /// public fields to change the rest.
    pub fn new(server_name: impl Into<String>, public_key: &str, short_id: &str) -> io::Result<Self> {
        Ok(Self {
            server_name: server_name.into(),
            public_key: parse_public_key(public_key)?,
            short_id: parse_short_id(short_id)?,
            fingerprint: Fingerprint::Chrome,
            alpn: Vec::new(),
            post_quantum: true,
        })
    }
}

/// `reality.public_key`: unpadded base64url of 32 bytes (Go `base64.RawURLEncoding`).
pub fn parse_public_key(s: &str) -> io::Result<[u8; 32]> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid REALITY public_key: {m}"));
    let v = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| bad(&e.to_string()))?;
    v.try_into().map_err(|_| bad("not 32 bytes"))
}

/// `reality.short_id`: up to 16 hex digits, even length; shorter ids are zero-padded.
pub fn parse_short_id(s: &str) -> io::Result<[u8; 8]> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("invalid REALITY short_id: {s:?}"));
    if !s.len().is_multiple_of(2) || s.len() > 16 {
        return Err(bad());
    }
    let mut out = [0u8; 8];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(pair).map_err(|_| bad())?;
        out[i] = u8::from_str_radix(hex, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Runs the REALITY handshake over `stream` (any transport, e.g. a detour chain).
///
/// Fails with `PermissionDenied` when the server answers with a real
/// certificate: it did not accept our credentials and proxied its cover site.
/// Before failing, the client requests the site's front page like the
/// imitated browser and reads the response for up to three seconds; only the
/// server name and fixed browser headers are sent.
pub async fn connect<S>(stream: S, cfg: &RealityConfig) -> io::Result<RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    reality_handshake(stream, cfg, false).await
}

pub(crate) async fn reality_handshake<S>(stream: S, cfg: &RealityConfig, skip_verify: bool) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let params = hello::HelloParams {
        fingerprint: cfg.fingerprint,
        server_name: Some(&cfg.server_name),
        alpn: &cfg.alpn,
        post_quantum: cfg.post_quantum,
    };
    handshake::handshake(stream, &params, handshake::Auth::Reality { cfg, skip_verify }).await
}
