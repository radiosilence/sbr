//! XTLS Vision (`xtls-rprx-vision`), client side, following sing-vmess
//! `vless/vision.go` byte for byte where the wire is concerned.
//!
//! The first packets in each direction are padded so the TLS-in-TLS record
//! sizes don't fingerprint the inner handshake. Once the inner connection
//! is TLS 1.3 and starts sending application data, both sides switch to
//! "direct": the outer TLS is dropped and inner records go raw over TCP,
//! saving a layer of encryption.
//!
//! Differences from sing-vmess that don't touch the wire:
//! - no 5 ms sleep between the last padded record and the first raw write;
//! - reads are not forced into 8 KiB chunks after padding ends;
//! - rustls is fed one TLS record at a time ([`crate::tls::TlsIo::limit_to_records`])
//!   until we know whether the server will go direct, instead of reaching
//!   into the TLS library's buffers. Afterwards reads are unrestricted.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tls::{TlsConn, rand_u32};

const CMD_CONTINUE: u8 = 0;
const CMD_END: u8 = 1;
const CMD_DIRECT: u8 = 2;
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const APP_DATA: [u8; 3] = [0x17, 0x03, 0x03];
/// sing-vmess `xrayChunkSize`: read size while unpadding.
const CHUNK: usize = 8192;

pub struct VisionStream {
    tls: TlsConn,
    uuid: [u8; 16],
    /// VLESS request, sent ahead of the first padded block.
    header: Option<Vec<u8>>,
    resp_hdr: [u8; 2],
    resp_got: usize,
    resp_skip: usize,
    resp_done: bool,

    // Write side.
    tls_out: Vec<u8>,
    /// The reader sent the request (client silent so far): it flushes.
    read_flushes: bool,
    tls_pos: usize,
    raw_out: Vec<u8>,
    raw_pos: usize,
    is_padding: bool,
    write_uuid: bool,
    direct_write: bool,
    /// The outer TLS was flushed after the switch to direct writes.
    tls_drained: bool,

    // TLS sniffing of the inner connection.
    filter_left: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: u16,
    enable_xtls: bool,

    // Read side.
    within_padding: bool,
    remaining_content: i32,
    remaining_padding: i32,
    command: u8,
    pad_hdr: [u8; 5],
    pad_hdr_len: usize,
    direct_read: bool,
    rbuf: Vec<u8>,
    content: Vec<u8>,
    content_pos: usize,
}

impl VisionStream {
    pub fn new(mut tls: TlsConn, header: Vec<u8>, uuid: [u8; 16]) -> Self {
        tls.limit_reads();
        Self {
            tls,
            uuid,
            header: Some(header),
            resp_hdr: [0; 2],
            resp_got: 0,
            resp_skip: 0,
            resp_done: false,
            tls_out: Vec::new(),
            read_flushes: false,
            tls_pos: 0,
            raw_out: Vec::new(),
            raw_pos: 0,
            is_padding: true,
            write_uuid: true,
            direct_write: false,
            tls_drained: false,
            filter_left: 8,
            is_tls: false,
            is_tls12_or_above: false,
            remaining_server_hello: -1,
            cipher: 0,
            enable_xtls: false,
            within_padding: true,
            remaining_content: -1,
            remaining_padding: -1,
            command: 0,
            pad_hdr: [0; 5],
            pad_hdr_len: 0,
            direct_read: false,
            rbuf: vec![0; CHUNK],
            content: Vec::new(),
            content_pos: 0,
        }
    }

    fn raw(&mut self) -> &mut sbr_core::Stream {
        self.tls.raw()
    }

    /// sing-vmess `filterTLS`: watch the inner handshake for TLS 1.3.
    fn filter(&mut self, b: &[u8]) {
        if self.filter_left <= 0 {
            return;
        }
        self.filter_left -= 1;
        if b.len() > 6 {
            if b[0] == 22 && b[1] == 3 && b[2] == 3 {
                self.is_tls = true;
                if b[5] == 2 {
                    self.is_tls12_or_above = true;
                    self.remaining_server_hello = ((b[3] as i32) << 8 | b[4] as i32) + 5;
                    if b.len() >= 79 && self.remaining_server_hello >= 79 {
                        let sid = b[43] as usize;
                        if b.len() >= 43 + sid + 3 {
                            self.cipher = u16::from_be_bytes([b[43 + sid + 1], b[43 + sid + 2]]);
                        }
                    }
                }
            } else if b[0] == 22 && b[1] == 3 && b[5] == 1 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= end as i32;
            if b[..end].windows(6).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
                // TLS_AES_128_GCM .. TLS_AES_128_CCM_SHA256; not CCM_8.
                self.enable_xtls = (0x1301..=0x1304).contains(&self.cipher);
                self.filter_left = 0;
            } else if self.remaining_server_hello == 0 {
                self.filter_left = 0;
            }
        }
    }

    fn pad(&mut self, out: &mut Vec<u8>, content: &[u8], command: u8) {
        let len = content.len();
        let padding = if len < 900 && self.is_tls {
            (rand_u32() % 500) as usize + 900 - len
        } else {
            (rand_u32() % 256) as usize
        };
        if self.write_uuid {
            out.extend_from_slice(&self.uuid);
            self.write_uuid = false;
        }
        out.push(command);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding, 0);
    }

    /// Queue `p` (padded as needed); sing-vmess `VisionConn.Write`.
    fn queue_padded(&mut self, p: &[u8]) {
        self.filter(p);
        let mut tls_out = self.header.take().unwrap_or_default();
        let mut rest: &[u8] = &[];
        for piece in reshape(p) {
            if self.is_tls && piece.len() > 6 && piece[..3] == APP_DATA {
                let command = if self.enable_xtls {
                    self.direct_write = true;
                    CMD_DIRECT
                } else {
                    CMD_END
                };
                self.is_padding = false;
                self.pad(&mut tls_out, piece, command);
                rest = tail_after(p, piece);
                break;
            } else if !self.is_tls12_or_above && self.filter_left <= 1 {
                self.is_padding = false;
                self.pad(&mut tls_out, piece, CMD_END);
                rest = tail_after(p, piece);
                break;
            }
            self.pad(&mut tls_out, piece, CMD_CONTINUE);
        }
        if self.direct_write {
            self.raw_out.extend_from_slice(rest);
        } else {
            tls_out.extend_from_slice(rest);
        }
        self.tls_out = tls_out;
        self.tls_pos = 0;
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tls_pos < self.tls_out.len() {
            let n = ready!(Pin::new(&mut self.tls).poll_write(cx, &self.tls_out[self.tls_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.tls_pos += n;
        }
        if !self.tls_out.is_empty() {
            self.tls_out = Vec::new();
            self.tls_pos = 0;
        }
        if self.direct_write && !self.tls_drained {
            // Everything sent through TLS must be on the wire before raw bytes.
            ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
            self.tls_drained = true;
        }
        if self.raw_pos < self.raw_out.len() {
            while self.raw_pos < self.raw_out.len() {
                let (out, pos) = (&self.raw_out, self.raw_pos);
                let n = ready!(Pin::new(self.tls.raw()).poll_write(cx, &out[pos..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.raw_pos += n;
            }
            self.raw_out = Vec::new();
            self.raw_pos = 0;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.resp_got < 2 {
            let mut rb = ReadBuf::new(&mut self.resp_hdr[self.resp_got..]);
            ready!(Pin::new(&mut self.tls).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.resp_got += n;
            if self.resp_got == 2 {
                if self.resp_hdr[0] != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vless: unknown response version",
                    )));
                }
                self.resp_skip = self.resp_hdr[1] as usize;
            }
        }
        while self.resp_skip > 0 {
            let mut scratch = [0u8; 255];
            let mut rb = ReadBuf::new(&mut scratch[..self.resp_skip]);
            ready!(Pin::new(&mut self.tls).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.resp_skip -= n;
        }
        self.resp_done = true;
        Poll::Ready(Ok(()))
    }

    /// sing-vmess `unPadding`: strip padding from `n` bytes in `rbuf`,
    /// appending content to `self.content`; returns the content ranges for
    /// TLS filtering.
    fn unpad(&mut self, n: usize) -> Vec<(usize, usize)> {
        let mut pieces = Vec::new();
        let buf = std::mem::take(&mut self.rbuf);
        let b = &buf[..n];
        let mut i = 0;
        if self.remaining_content == -1 && self.remaining_padding == -1 {
            if b.len() >= 21 && b[..16] == self.uuid {
                i = 16;
                self.remaining_content = 0;
                self.remaining_padding = 0;
                self.command = 0;
            } else {
                pieces.push(self.push_content(b));
                self.rbuf = buf;
                return pieces;
            }
        }
        while i < b.len() {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.command == CMD_END {
                    pieces.push(self.push_content(&b[i..]));
                    break;
                }
                let take = (5 - self.pad_hdr_len).min(b.len() - i);
                self.pad_hdr[self.pad_hdr_len..self.pad_hdr_len + take].copy_from_slice(&b[i..i + take]);
                self.pad_hdr_len += take;
                i += take;
                if self.pad_hdr_len < 5 {
                    break;
                }
                self.pad_hdr_len = 0;
                let h = self.pad_hdr;
                self.command = h[0];
                self.remaining_content = u16::from_be_bytes([h[1], h[2]]) as i32;
                self.remaining_padding = u16::from_be_bytes([h[3], h[4]]) as i32;
            } else if self.remaining_content > 0 {
                let end = (self.remaining_content as usize).min(b.len() - i);
                pieces.push(self.push_content(&b[i..i + end]));
                self.remaining_content -= end as i32;
                i += end;
            } else {
                let end = (self.remaining_padding as usize).min(b.len() - i);
                self.remaining_padding -= end as i32;
                i += end;
            }
        }
        self.rbuf = buf;
        pieces
    }

    fn push_content(&mut self, b: &[u8]) -> (usize, usize) {
        if self.content_pos == self.content.len() {
            self.content.clear();
            self.content_pos = 0;
        }
        let start = self.content.len();
        self.content.extend_from_slice(b);
        (start, self.content.len())
    }

    /// Switch reads to the raw socket: whatever rustls already decrypted, and
    /// whatever was read but not yet given to rustls, comes first.
    fn go_direct_read(&mut self) -> io::Result<()> {
        self.direct_read = true;
        let rest = self.tls.take_buffered()?;
        self.push_content(&rest);
        Ok(())
    }
}

/// The part of `whole` after `piece` (a sub-slice of it).
fn tail_after<'a>(whole: &'a [u8], piece: &[u8]) -> &'a [u8] {
    let end = piece.as_ptr() as usize - whole.as_ptr() as usize + piece.len();
    &whole[end.min(whole.len())..]
}

/// sing-vmess `reshapeBuffer`: keep padded blocks under 8 KiB, preferring
/// to cut at an inner TLS record boundary.
fn reshape(b: &[u8]) -> Vec<&[u8]> {
    const LIMIT: usize = 8192 - 21;
    if b.len() < LIMIT {
        return vec![b];
    }
    let mut out = Vec::new();
    let mut b = b;
    while b.len() >= LIMIT {
        let idx = b.windows(3).rposition(|w| w == APP_DATA);
        let idx = match idx {
            Some(i) if (32..=LIMIT).contains(&i) => i,
            _ => 8192 / 2,
        };
        out.push(&b[..idx]);
        b = &b[idx..];
    }
    out.push(b);
    out
}

impl AsyncRead for VisionStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.header.is_some() {
            // Silent client (server-first protocol): send the request with an
            // empty padded block, as sing-box's `Write(nil)` does.
            this.queue_padded(&[]);
            this.read_flushes = true;
        }
        if this.read_flushes && (this.tls_pos < this.tls_out.len() || this.raw_pos < this.raw_out.len()) {
            // Push the request out, but don't wait on writability here: the
            // write side may live in another task (split streams), and a
            // socket keeps one write wakeup, so only one side may wait on it.
            // Once the writer has written, flushing is its job.
            if let Poll::Ready(r) = this.poll_flush_out(cx) {
                r?;
                if let Poll::Ready(Err(e)) = Pin::new(&mut this.tls).poll_flush(cx) {
                    return Poll::Ready(Err(e));
                }
            }
        }
        if !this.resp_done {
            ready!(this.poll_response(cx))?;
        }
        loop {
            if this.content_pos < this.content.len() {
                let n = (this.content.len() - this.content_pos).min(out.remaining());
                out.put_slice(&this.content[this.content_pos..this.content_pos + n]);
                this.content_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.direct_read {
                return Pin::new(this.raw()).poll_read(cx, out);
            }
            let unpadding = this.within_padding || this.filter_left > 0;
            if !unpadding {
                return Pin::new(&mut this.tls).poll_read(cx, out);
            }
            let mut rb = ReadBuf::new(&mut this.rbuf[..CHUNK]);
            ready!(Pin::new(&mut this.tls).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            let pieces = this.unpad(n);
            if this.remaining_content == 0 && this.remaining_padding == 0 {
                match this.command {
                    CMD_END => {
                        this.within_padding = false;
                        this.remaining_content = -1;
                        this.remaining_padding = -1;
                    }
                    CMD_DIRECT => {
                        this.within_padding = false;
                        this.go_direct_read()?;
                    }
                    CMD_CONTINUE => this.within_padding = true,
                    c => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("vision: unknown command {c}"),
                        )));
                    }
                }
            } else {
                this.within_padding = this.remaining_content > 0 || this.remaining_padding > 0;
            }
            if this.filter_left > 0 {
                let content = std::mem::take(&mut this.content);
                for (s, e) in pieces {
                    this.filter(&content[s..e]);
                }
                this.content = content;
            }
            if !this.direct_read && !this.within_padding && this.filter_left <= 0 {
                // No Direct command can follow: stop feeding rustls record by record.
                this.tls.unlimit_reads();
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.read_flushes = false;
        ready!(this.poll_flush_out(cx))?;
        if this.direct_write {
            return Pin::new(this.raw()).poll_write(cx, buf);
        }
        if !this.is_padding {
            return Pin::new(&mut this.tls).poll_write(cx, buf);
        }
        this.queue_padded(buf);
        if let Poll::Ready(Err(e)) = this.poll_flush_out(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_out(cx))?;
        if this.direct_write {
            Pin::new(this.raw()).poll_flush(cx)
        } else {
            Pin::new(&mut this.tls).poll_flush(cx)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_out(cx))?;
        if this.direct_write {
            Pin::new(this.raw()).poll_shutdown(cx)
        } else {
            Pin::new(&mut this.tls).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reshape_cuts_at_record_boundaries() {
        let small = vec![1u8; 100];
        assert_eq!(reshape(&small).len(), 1);
        let mut big = vec![0u8; 10000];
        big[6000..6003].copy_from_slice(&APP_DATA);
        let parts = reshape(&big);
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), vec![6000, 4000]);
        let plain = vec![0u8; 20000];
        let parts = reshape(&plain);
        assert_eq!(parts.iter().map(|p| p.len()).sum::<usize>(), 20000);
        assert!(parts.iter().all(|p| p.len() < 8192));
    }
}
