//! TLS 1.3 record layer buffers. One fixed read buffer per connection, records
//! are decrypted in place, and the write buffer is reused across records, so
//! the steady state does not allocate.

use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::AsyncRead;

use crate::keys::{RecordKey, TAG_LEN};

pub(crate) const HEADER_LEN: usize = 5;
pub(crate) const MAX_PLAINTEXT: usize = 1 << 14;
/// RFC 8446 §5.2: ciphertext may exceed the plaintext limit by at most 256.
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
/// Two full records: a read normally pulls in more than one record, and the
/// partial tail only has to be moved when it would not fit.
const READ_BUF_LEN: usize = 2 * (HEADER_LEN + MAX_CIPHERTEXT);
/// The largest record this client writes.
pub(crate) const MAX_WRITE_RECORD: usize = HEADER_LEN + MAX_PLAINTEXT + 1 + TAG_LEN;

pub(crate) const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const CT_ALERT: u8 = 21;
pub(crate) const CT_HANDSHAKE: u8 = 22;
pub(crate) const CT_APPLICATION_DATA: u8 = 23;

pub(crate) fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub(crate) fn alert_error(body: &[u8]) -> io::Error {
    match body {
        [_, desc] => io::Error::new(io::ErrorKind::ConnectionAborted, format!("received TLS alert {desc}")),
        _ => invalid("malformed TLS alert"),
    }
}

/// A complete record sitting in the read buffer.
pub(crate) struct RawRecord {
    pub(crate) typ: u8,
    header: [u8; 5],
    body: Range<usize>,
}

pub(crate) struct ReadBuf {
    buf: Box<[u8]>,
    head: usize,
    tail: usize,
}

impl ReadBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: vec![0; READ_BUF_LEN].into_boxed_slice(),
            head: 0,
            tail: 0,
        }
    }

    /// Takes the next complete record, if buffered. Its bytes stay valid until
    /// the next `poll_fill`.
    pub(crate) fn next(&mut self) -> io::Result<Option<RawRecord>> {
        let avail = &self.buf[self.head..self.tail];
        if avail.len() < HEADER_LEN {
            return Ok(None);
        }
        let len = u16::from_be_bytes([avail[3], avail[4]]) as usize;
        if len > MAX_CIPHERTEXT {
            return Err(invalid("TLS record overflow"));
        }
        if avail.len() < HEADER_LEN + len {
            return Ok(None);
        }
        let header: [u8; 5] = avail[..HEADER_LEN].try_into().unwrap();
        let start = self.head + HEADER_LEN;
        self.head = start + len;
        Ok(Some(RawRecord {
            typ: header[0],
            header,
            body: start..start + len,
        }))
    }

    pub(crate) fn body(&self, r: &RawRecord) -> &[u8] {
        &self.buf[r.body.clone()]
    }

    pub(crate) fn slice(&self, r: Range<usize>) -> &[u8] {
        &self.buf[r]
    }

    /// Decrypts a protected record in place. Returns the inner content type
    /// and the content range (padding and type byte stripped).
    pub(crate) fn open(&mut self, key: &mut RecordKey, r: &RawRecord) -> io::Result<(u8, Range<usize>)> {
        if r.body.len() < TAG_LEN + 1 {
            return Err(invalid("TLS record too short"));
        }
        let n = key
            .open(r.header, &mut self.buf[r.body.clone()])
            .map_err(|_| invalid("TLS record authentication failed (bad_record_mac)"))?;
        let pt = &self.buf[r.body.start..r.body.start + n];
        let Some(type_at) = pt.iter().rposition(|&b| b != 0) else {
            return Err(invalid("TLS record without content type"));
        };
        if type_at > MAX_PLAINTEXT {
            return Err(invalid("TLS plaintext record overflow"));
        }
        Ok((pt[type_at], r.body.start..r.body.start + type_at))
    }

    /// Bytes read from the wire but not yet taken as records.
    pub(crate) fn take_unread(&mut self) -> Vec<u8> {
        let v = self.buf[self.head..self.tail].to_vec();
        self.head = self.tail;
        v
    }

    pub(crate) fn has_partial(&self) -> bool {
        self.head != self.tail
    }

    /// Reads more ciphertext. Invalidates every range handed out before.
    pub(crate) fn poll_fill<S: AsyncRead + Unpin>(
        &mut self,
        io: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        } else {
            let pending = &self.buf[self.head..self.tail];
            let need = if pending.len() >= HEADER_LEN {
                HEADER_LEN + u16::from_be_bytes([pending[3], pending[4]]) as usize
            } else {
                HEADER_LEN + MAX_CIPHERTEXT
            };
            if self.buf.len() - self.head < need {
                self.buf.copy_within(self.head..self.tail, 0);
                self.tail -= self.head;
                self.head = 0;
            }
        }
        let mut rb = tokio::io::ReadBuf::new(&mut self.buf[self.tail..]);
        ready!(Pin::new(io).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        self.tail += n;
        Poll::Ready(Ok(n))
    }
}

/// Appends one protected record carrying `payload` as `content_type`.
pub(crate) fn seal_record(key: &mut RecordKey, out: &mut Vec<u8>, content_type: u8, payload: &[u8]) {
    debug_assert!(payload.len() <= MAX_PLAINTEXT);
    let len = payload.len() + 1 + TAG_LEN;
    let header = [CT_APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8];
    let start = out.len();
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    out.push(content_type);
    let tag = key.seal(header, &mut out[start + HEADER_LEN..]);
    out.extend_from_slice(&tag);
}

/// Reassembles handshake messages from record fragments.
#[derive(Default)]
pub(crate) struct HandshakeBuf {
    data: Vec<u8>,
}

/// Generous: real certificate chains stay well below this.
const MAX_HANDSHAKE_MSG: usize = 1 << 17;

impl HandshakeBuf {
    pub(crate) fn push(&mut self, b: &[u8]) {
        self.data.extend_from_slice(b);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Pops one complete message (header included).
    pub(crate) fn next_message(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.data.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([0, self.data[1], self.data[2], self.data[3]]) as usize;
        if len > MAX_HANDSHAKE_MSG {
            return Err(invalid("TLS handshake message too large"));
        }
        if self.data.len() < 4 + len {
            return Ok(None);
        }
        let rest = self.data.split_off(4 + len);
        Ok(Some(std::mem::replace(&mut self.data, rest)))
    }
}
