//! The established connection: TLS 1.3 application data records over `S`.

use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf as TokioReadBuf};

use crate::keys::{CipherSuite, RecordKey, TAG_LEN};
use crate::record::{
    CT_ALERT, CT_APPLICATION_DATA, CT_HANDSHAKE, HEADER_LEN, HandshakeBuf, MAX_WRITE_RECORD, ReadBuf, alert_error,
    invalid, seal_record,
};

const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_KEY_UPDATE: u8 = 24;

/// Write at most this much ciphertext per underlying write: two full records
/// halve the syscalls for large writes without holding much memory.
const MAX_WRITE_BATCH: usize = 2 * MAX_WRITE_RECORD;

/// Rotate AES-GCM write keys well before the RFC 8446 §5.5 limit (2^24.5 records).
const REKEY_AFTER_RECORDS: u64 = 1 << 23;

/// A TLS 1.3 client connection over `S` (REALITY or browser-fingerprinted TLS).
///
/// Reads decrypt in place in one fixed buffer; writes encrypt into one reused
/// buffer. Writes return as soon as data is encrypted; `poll_flush` pushes it
/// out. KeyUpdate and NewSessionTicket are handled internally.
pub struct TlsStream<S> {
    io: S,
    rb: ReadBuf,
    read_key: RecordKey,
    write_key: RecordKey,
    /// Decrypted application data not yet returned, inside `rb`.
    plaintext: Range<usize>,
    /// Post-handshake handshake messages split across records (rare).
    hs: HandshakeBuf,
    wbuf: Vec<u8>,
    wpos: usize,
    /// KeyUpdate to send before the next application data: Some(request_update).
    key_update: Option<bool>,
    read_closed: bool,
    write_closed: bool,
    alpn: Option<Vec<u8>>,
    group: u16,
    /// Largest plaintext per record (the server's record_size_limit, if any).
    max_fragment: usize,
}

impl<S> TlsStream<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        io: S,
        rb: ReadBuf,
        read_key: RecordKey,
        write_key: RecordKey,
        wbuf: Vec<u8>,
        alpn: Option<Vec<u8>>,
        group: u16,
        max_fragment: usize,
    ) -> Self {
        Self {
            io,
            rb,
            read_key,
            write_key,
            plaintext: 0..0,
            hs: HandshakeBuf::default(),
            wbuf,
            wpos: 0,
            key_update: None,
            read_closed: false,
            write_closed: false,
            alpn,
            group,
            max_fragment,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// The protocol the server picked from our ALPN list, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The key exchange group of the handshake (IANA id: 0x001d X25519,
    /// 0x11ec X25519MLKEM768, 0x0017 secp256r1).
    pub fn key_exchange_group(&self) -> u16 {
        self.group
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.write_key.suite
    }

    /// Leaves TLS for the raw stream (XTLS Vision "direct" mode): returns the
    /// decrypted bytes not yet read, then the ciphertext bytes read past the
    /// last processed record, which belong to whatever follows on the raw
    /// stream. Records are processed one at a time, so nothing past the
    /// current one has been decrypted. Don't read from this stream afterwards.
    pub fn take_buffered(&mut self) -> Vec<u8> {
        let mut out = self.rb.slice(self.plaintext.clone()).to_vec();
        self.plaintext = 0..0;
        out.extend_from_slice(&self.rb.take_unread());
        out
    }

    /// Queues a KeyUpdate (update_requested) sent before the next write or flush:
    /// both directions move to fresh traffic keys.
    pub fn refresh_traffic_keys(&mut self) {
        self.key_update = Some(true);
    }

    fn queue_key_update(&mut self) {
        if let Some(request) = self.key_update.take() {
            seal_record(
                &mut self.write_key,
                &mut self.wbuf,
                CT_HANDSHAKE,
                &[HS_KEY_UPDATE, 0, 0, 1, request as u8],
            );
            self.write_key = self.write_key.updated();
        }
    }

    /// Handles one record; may expose plaintext.
    fn process_record(&mut self) -> io::Result<bool> {
        let Some(rec) = self.rb.next()? else { return Ok(false) };
        if rec.typ != CT_APPLICATION_DATA {
            return Err(match rec.typ {
                CT_ALERT => alert_error(self.rb.body(&rec)),
                _ => invalid("unprotected TLS record after handshake"),
            });
        }
        let (ty, range) = self.rb.open(&mut self.read_key, &rec)?;
        match ty {
            CT_APPLICATION_DATA => {
                if !self.hs.is_empty() {
                    return Err(invalid("application data inside a fragmented handshake message"));
                }
                self.plaintext = range;
            }
            CT_HANDSHAKE => {
                self.hs.push(self.rb.slice(range));
                while let Some(msg) = self.hs.next_message()? {
                    match msg[0] {
                        HS_NEW_SESSION_TICKET => {} // sessions are not resumed
                        HS_KEY_UPDATE => {
                            let request = match &msg[4..] {
                                [0] => false,
                                [1] => true,
                                _ => return Err(invalid("malformed KeyUpdate")),
                            };
                            if !self.hs.is_empty() {
                                return Err(invalid("KeyUpdate not at a record boundary"));
                            }
                            self.read_key = self.read_key.updated();
                            if request && self.key_update.is_none() {
                                self.key_update = Some(false);
                            }
                        }
                        _ => return Err(invalid("unexpected post-handshake message")),
                    }
                }
            }
            CT_ALERT => match self.rb.slice(range.clone()) {
                [_, 0] => self.read_closed = true, // close_notify
                b => return Err(alert_error(b)),
            },
            _ => return Err(invalid("unexpected TLS record type")),
        }
        Ok(true)
    }

    fn rekey_if_needed(&mut self) {
        if self.write_key.seq >= REKEY_AFTER_RECORDS && self.write_key.suite.needs_rekey() && self.key_update.is_none()
        {
            self.key_update = Some(false);
        }
    }
}

impl<S: AsyncWrite + Unpin> TlsStream<S> {
    fn poll_write_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut TokioReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.plaintext.is_empty() {
                let n = this.plaintext.len().min(buf.remaining());
                let start = this.plaintext.start;
                buf.put_slice(this.rb.slice(start..start + n));
                this.plaintext.start += n;
                return Poll::Ready(Ok(()));
            }
            if this.read_closed {
                return Poll::Ready(Ok(()));
            }
            if this.process_record()? {
                continue;
            }
            let n = ready!(this.rb.poll_fill(&mut this.io, cx))?;
            if n == 0 {
                if this.rb.has_partial() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TLS record",
                    )));
                }
                // EOF without close_notify reads as EOF, like Go's crypto/tls.
                this.read_closed = true;
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_write_out(cx))?;
        if this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.queue_key_update();
        let mut n = 0;
        while n < buf.len() {
            let chunk = (buf.len() - n).min(this.max_fragment);
            if n > 0 && this.wbuf.len() + HEADER_LEN + chunk + 1 + TAG_LEN > MAX_WRITE_BATCH {
                break;
            }
            seal_record(
                &mut this.write_key,
                &mut this.wbuf,
                CT_APPLICATION_DATA,
                &buf[n..n + chunk],
            );
            n += chunk;
            this.rekey_if_needed();
            this.queue_key_update();
        }
        // Best effort: the data is accepted; anything left goes out on the next
        // write or flush.
        if let Poll::Ready(Err(e)) = this.poll_write_out(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            this.queue_key_update();
        }
        ready!(this.poll_write_out(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            ready!(this.poll_write_out(cx))?;
            this.queue_key_update();
            seal_record(&mut this.write_key, &mut this.wbuf, CT_ALERT, &[1, 0]);
            this.write_closed = true;
        }
        ready!(this.poll_write_out(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
