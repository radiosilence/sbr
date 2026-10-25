//! The transport under rustls: the dialed stream plus two optional tricks.
//!
//! - ClientHello fragmentation (`fragment` / `record_fragment`), the
//!   anti-censorship feature of sing-box `common/tlsfragment`: the first TLS
//!   record is split inside the SNI host name, across TCP segments, TLS
//!   records, or both.
//! - Noticing a connection cut before the server sent a byte (a reset or
//!   close in answer to the ClientHello), which is what SNI filtering looks
//!   like from the client, so the automatic mode can turn fragmentation on.
//! - Record-at-a-time reads, which XTLS Vision needs: when the server
//!   switches a VLESS connection to "direct" mode, everything after the TLS
//!   record carrying that command is raw inner traffic. Feeding rustls one
//!   record per read guarantees rustls never buffers (and tries to decrypt)
//!   bytes past that point; the leftovers stay here for [`TlsIo::take_raw`].

use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use sbr_core::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// sing-box `C.TLSFragmentFallbackDelay`.
pub const FRAGMENT_FALLBACK_DELAY: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug)]
pub struct FragmentOptions {
    pub split_packet: bool,
    pub split_record: bool,
    pub fallback_delay: Duration,
}

pub struct TlsIo {
    inner: Stream,
    /// Raw socket under `inner`, when it was dialed directly: lets the
    /// fragmenter wait for ACKs instead of sleeping blindly.
    fd: Option<i32>,
    frag: Option<Fragmenter>,
    reader: RecordReader,
    /// Set if the connection is reset or closed before the first byte from
    /// the server arrives; dropped once one does.
    cut_early: Option<Arc<AtomicBool>>,
}

impl TlsIo {
    pub fn new(inner: Stream, fd: Option<i32>, frag: Option<FragmentOptions>) -> Self {
        Self {
            inner,
            fd,
            frag: frag.map(|opts| Fragmenter { opts, plan: None }),
            reader: RecordReader::default(),
            cut_early: None,
        }
    }

    /// Report a cut before the server's first byte through `flag`.
    pub fn watch_cut(mut self, flag: Arc<AtomicBool>) -> Self {
        self.cut_early = Some(flag);
        self
    }

    /// Hand rustls whole TLS records only (see the module docs).
    pub fn limit_to_records(&mut self) {
        self.reader.limit = true;
    }

    /// Stop limiting reads; buffered bytes are still delivered first.
    pub fn unlimit(&mut self) {
        self.reader.limit = false;
    }

    /// Bytes read from the wire but not yet handed to rustls. Reads go
    /// straight to the wire afterwards.
    pub fn take_raw(&mut self) -> Vec<u8> {
        let r = &mut self.reader;
        let out = r.buf[r.pos..r.end].to_vec();
        *r = RecordReader {
            bypass: true,
            ..RecordReader::default()
        };
        out
    }

    /// The dialed stream, bypassing TLS (Vision direct mode).
    pub fn raw(&mut self) -> &mut Stream {
        &mut self.inner
    }
}

impl AsyncRead for TlsIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(flag) = &this.cut_early else {
            return this.reader.poll_read(&mut this.inner, cx, out);
        };
        let before = out.filled().len();
        let r = ready!(this.reader.poll_read(&mut this.inner, cx, out));
        match &r {
            Ok(()) if out.filled().len() > before => this.cut_early = None,
            Ok(()) if out.remaining() > 0 => flag.store(true, Ordering::Relaxed),
            Err(e) if is_cut(e) => flag.store(true, Ordering::Relaxed),
            _ => {}
        }
        Poll::Ready(r)
    }
}

fn is_cut(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

impl AsyncWrite for TlsIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = match &mut this.frag {
            Some(f) => match ready!(f.poll_write(&mut this.inner, this.fd, cx, buf)) {
                Some(r) => {
                    this.frag = None;
                    r
                }
                None => {
                    this.frag = None;
                    ready!(Pin::new(&mut this.inner).poll_write(cx, buf))
                }
            },
            None => ready!(Pin::new(&mut this.inner).poll_write(cx, buf)),
        };
        if let (Err(e), Some(flag)) = (&r, &this.cut_early)
            && is_cut(e)
        {
            flag.store(true, Ordering::Relaxed);
        }
        Poll::Ready(r)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.frag.is_some() || self.cut_early.is_some() {
            let first = bufs.iter().find(|b| !b.is_empty()).map_or(&[][..], |b| &b[..]);
            return self.poll_write(cx, first);
        }
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Read-ahead under rustls. rustls pulls ciphertext 4 KiB at a time; one
/// large socket read per TLS record instead of four is a measurable win for
/// bulk transfers. In `limit` mode it also stops at record boundaries.
#[derive(Default)]
struct RecordReader {
    buf: Box<[u8]>,
    pos: usize,
    end: usize,
    /// Bytes left in the record being handed out; 0 = at a record header.
    left: usize,
    limit: bool,
    /// A record was just completed: report `WouldBlock` once.
    gate: bool,
    /// Vision went direct: no buffering at all.
    bypass: bool,
}

/// One maximal TLS record (16 KiB + 256 + header) fits.
const READ_AHEAD: usize = 20 * 1024;

impl RecordReader {
    fn poll_read(&mut self, inner: &mut Stream, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.bypass {
            return Pin::new(inner).poll_read(cx, out);
        }
        if self.gate && self.limit {
            // One record per wakeup: tokio-rustls keeps calling `read_tls`
            // within one poll, so a record boundary has to look like
            // `WouldBlock` to stop it there. Wake ourselves to continue.
            self.gate = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        loop {
            let avail = self.end - self.pos;
            if avail > 0 && (!self.limit || self.left > 0 || avail >= 5) {
                let mut n = avail.min(out.remaining());
                if self.limit {
                    if self.left == 0 {
                        let h = &self.buf[self.pos..];
                        self.left = 5 + u16::from_be_bytes([h[3], h[4]]) as usize;
                    }
                    n = n.min(self.left);
                    self.left -= n;
                    self.gate = self.left == 0;
                } else {
                    self.left = self.left.saturating_sub(n);
                }
                out.put_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                if self.pos == self.end {
                    self.pos = 0;
                    self.end = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if avail == 0 && !self.limit && out.remaining() >= READ_AHEAD {
                return Pin::new(inner).poll_read(cx, out);
            }
            // Need more bytes from the wire.
            if self.buf.is_empty() {
                self.buf = vec![0u8; READ_AHEAD].into_boxed_slice();
            }
            if self.pos > 0 {
                self.buf.copy_within(self.pos..self.end, 0);
                self.end -= self.pos;
                self.pos = 0;
            }
            let mut rb = ReadBuf::new(&mut self.buf[self.end..]);
            ready!(Pin::new(&mut *inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                // EOF: hand out whatever is left (rustls reports a truncated
                // record if it was mid-record).
                if self.end > self.pos {
                    self.limit = false;
                    continue;
                }
                return Poll::Ready(Ok(()));
            }
            self.end += n;
        }
    }
}

struct Fragmenter {
    opts: FragmentOptions,
    plan: Option<Plan>,
}

struct Plan {
    /// Wire bytes to send, piece by piece.
    data: Vec<u8>,
    /// End offsets of each piece in `data`.
    ends: Vec<usize>,
    piece: usize,
    written: usize,
    /// Length of the caller's buffer, reported once everything is out.
    consumed: usize,
    wait: Option<Wait>,
}

struct Wait {
    sleep: Pin<Box<Sleep>>,
    started: tokio::time::Instant,
    /// Polling for the ACK of what we sent; false = plain fallback sleep.
    polling_ack: bool,
}

impl Fragmenter {
    /// `Ready(None)`: not a ClientHello, write it normally.
    fn poll_write(
        &mut self,
        inner: &mut Stream,
        fd: Option<i32>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Option<io::Result<usize>>> {
        if self.plan.is_none() {
            match plan(buf, self.opts) {
                Some(p) => self.plan = Some(p),
                None => return Poll::Ready(None),
            }
        }
        let p = self.plan.as_mut().unwrap();
        loop {
            if let Some(w) = &mut p.wait {
                ready!(w.sleep.as_mut().poll(cx));
                if w.polling_ack {
                    let elapsed = w.started.elapsed();
                    match fd.map(unacked) {
                        Some(Some(0)) | None | Some(None) => {
                            // Acked very quickly: we're probably talking to a
                            // local transparent proxy, which wouldn't split our
                            // segments anyway. Fall back to a fixed delay
                            // (sing-box `writeAndWaitAck`).
                            if elapsed <= Duration::from_millis(20) {
                                w.polling_ack = false;
                                w.sleep
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + self.opts.fallback_delay);
                                continue;
                            }
                        }
                        Some(Some(_)) if elapsed < self.opts.fallback_delay.max(Duration::from_secs(1)) => {
                            w.sleep
                                .as_mut()
                                .reset(tokio::time::Instant::now() + Duration::from_millis(10));
                            continue;
                        }
                        Some(Some(_)) => {}
                    }
                }
                p.wait = None;
            }
            if p.piece == p.ends.len() {
                return Poll::Ready(Some(Ok(p.consumed)));
            }
            let start = if p.piece == 0 { 0 } else { p.ends[p.piece - 1] };
            let end = p.ends[p.piece];
            while start + p.written < end {
                match ready!(Pin::new(&mut *inner).poll_write(cx, &p.data[start + p.written..end])) {
                    Ok(0) => return Poll::Ready(Some(Err(io::ErrorKind::WriteZero.into()))),
                    Ok(n) => p.written += n,
                    Err(e) => return Poll::Ready(Some(Err(e))),
                }
            }
            p.piece += 1;
            p.written = 0;
            if p.piece < p.ends.len() {
                let polling_ack = fd.is_some() && cfg!(target_os = "linux");
                let first = if polling_ack {
                    Duration::from_millis(1)
                } else {
                    self.opts.fallback_delay
                };
                p.wait = Some(Wait {
                    sleep: Box::pin(tokio::time::sleep(first)),
                    started: tokio::time::Instant::now(),
                    polling_ack,
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn unacked(fd: i32) -> Option<u32> {
    // SAFETY: `tcp_info` is plain old data; getsockopt fills at most `len` bytes.
    unsafe {
        let mut info: libc::tcp_info = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let r = libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut len,
        );
        (r == 0).then_some(info.tcpi_unacked)
    }
}

#[cfg(not(target_os = "linux"))]
fn unacked(_fd: i32) -> Option<u32> {
    None
}

/// Where the SNI host name sits in a ClientHello record (sing-box
/// `tlsfragment.IndexTLSServerName`): (offset of the name, the name).
pub(crate) fn index_server_name(b: &[u8]) -> Option<(usize, &[u8])> {
    if b.len() < 5 || b[0] != 22 {
        return None;
    }
    let rec_len = u16::from_be_bytes([b[3], b[4]]) as usize;
    if b.len() < 5 + rec_len {
        return None;
    }
    let hs = &b[5..];
    if hs.len() < 6 + 32 + 1 || hs[0] != 1 {
        return None;
    }
    let hs_len = (hs[1] as usize) << 16 | (hs[2] as usize) << 8 | hs[3] as usize;
    if hs.len() - 4 != hs_len {
        return None;
    }
    let ver = u16::from_be_bytes([hs[4], hs[5]]);
    if ver & 0xfffc != 0x0300 && ver != 0x0304 {
        return None;
    }
    let sid = hs[38] as usize;
    let mut i = 6 + 32 + 1 + sid;
    let cs_len = u16::from_be_bytes([*hs.get(i)?, *hs.get(i + 1)?]) as usize;
    let comp_len = *hs.get(i + 2 + cs_len)? as usize;
    i += 2 + cs_len + 1 + comp_len;
    let ext_total = u16::from_be_bytes([*hs.get(i)?, *hs.get(i + 1)?]) as usize;
    let mut e = i + 2;
    let ext_end = e + ext_total;
    if hs.len() < ext_end {
        return None;
    }
    while e + 4 <= ext_end {
        let ty = u16::from_be_bytes([hs[e], hs[e + 1]]);
        let len = u16::from_be_bytes([hs[e + 2], hs[e + 3]]) as usize;
        let body = hs.get(e + 4..e + 4 + len)?;
        if ty == 0 {
            // server_name_list length (2), name type (1), name length (2).
            if body.len() < 5 || body[2] != 0 {
                return None;
            }
            let n = u16::from_be_bytes([body[3], body[4]]) as usize;
            let name = body.get(5..5 + n)?;
            return Some((5 + e + 4 + 5, name));
        }
        e += 4 + len;
    }
    None
}

/// Where to cut the host name: at a random point strictly inside each label
/// but the last, so no record and no segment carries a whole label of the
/// registered name (`www.example.com` → `w|ww.exa|mple.com`). A filter that
/// matches the name as a substring of one record or one packet then finds
/// nothing. sing-box cuts the first label only. Labels of one character
/// cannot be cut inside; with no other label, the cut goes before the name.
fn cuts(idx: usize, name: &[u8]) -> Vec<usize> {
    let labels: Vec<&[u8]> = name.split(|c| *c == b'.').collect();
    let mut out = Vec::new();
    let mut at = idx;
    for l in &labels[..labels.len().saturating_sub(1).max(1)] {
        if l.len() >= 2 {
            out.push(at + 1 + rand_u32() as usize % (l.len() - 1));
        }
        at += l.len() + 1;
    }
    if out.is_empty() {
        out.push(idx);
    }
    out
}

/// Records are cut at every point from [`cuts`]; TCP segments at the first
/// only, since each segment boundary costs a wait for the ACK.
fn plan(b: &[u8], opts: FragmentOptions) -> Option<Plan> {
    let (idx, name) = index_server_name(b)?;
    let mut cuts = cuts(idx, name);
    if !opts.split_record {
        cuts.truncate(1);
    }
    let mut data = Vec::with_capacity(b.len() + 5 * (cuts.len() + 1));
    let mut ends = Vec::new();
    let mut prev = 5;
    for (i, &c) in cuts.iter().chain(std::iter::once(&b.len())).enumerate() {
        let piece = &b[prev..c];
        prev = c;
        if opts.split_record {
            data.extend_from_slice(&b[..3]);
            data.extend_from_slice(&(piece.len() as u16).to_be_bytes());
            data.extend_from_slice(piece);
        } else {
            if i == 0 {
                data.extend_from_slice(&b[..5]);
            }
            data.extend_from_slice(piece);
        }
        if opts.split_packet && i == 0 {
            ends.push(data.len());
        }
    }
    ends.push(data.len());
    Some(Plan {
        data,
        ends,
        piece: 0,
        written: 0,
        consumed: b.len(),
        wait: None,
    })
}

pub(crate) fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    aws_lc_rs::rand::fill(&mut b).expect("system RNG");
    u32::from_ne_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: &str) -> Vec<u8> {
        // Minimal ClientHello: version, random, empty session id, one suite,
        // null compression, SNI extension only.
        let mut ext = Vec::new();
        let n = sni.len() as u16;
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(n + 5).to_be_bytes());
        ext.extend_from_slice(&(n + 3).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&n.to_be_bytes());
        ext.extend_from_slice(sni.as_bytes());
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![22, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_sni() {
        let ch = client_hello("www.example.com");
        let (i, name) = index_server_name(&ch).unwrap();
        assert_eq!(name, b"www.example.com");
        assert_eq!(&ch[i..i + name.len()], b"www.example.com");
        assert!(index_server_name(&ch[..ch.len() - 1]).is_none());
    }

    #[test]
    fn record_split_reassembles() {
        let ch = client_hello("www.example.com");
        let opts = FragmentOptions {
            split_packet: false,
            split_record: true,
            fallback_delay: Duration::ZERO,
        };
        for _ in 0..50 {
            let p = plan(&ch, opts).unwrap();
            assert_eq!(p.ends, vec![p.data.len()]);
            // Three records whose bodies concatenate to the original
            // handshake; none holds a whole label but the last.
            let mut body = Vec::new();
            let mut d = &p.data[..];
            let mut records = 0;
            while !d.is_empty() {
                assert_eq!(&d[..3], &ch[..3]);
                let n = u16::from_be_bytes([d[3], d[4]]) as usize;
                let rec = &d[5..5 + n];
                for label in [&b"www"[..], b"example"] {
                    assert!(!rec.windows(label.len()).any(|w| w == label));
                }
                body.extend_from_slice(rec);
                d = &d[5 + n..];
                records += 1;
            }
            assert_eq!(records, 3);
            assert_eq!(body, &ch[5..]);
        }

        // One-character labels cannot be cut: the cut goes before the name.
        let ch1 = client_hello("a.b");
        let (i, _) = index_server_name(&ch1).unwrap();
        assert_eq!(cuts(i, b"a.b"), vec![i]);
        assert_eq!(cuts(i, b"localhost").len(), 1);

        let p = plan(
            &ch,
            FragmentOptions {
                split_packet: true,
                split_record: false,
                fallback_delay: Duration::ZERO,
            },
        )
        .unwrap();
        assert_eq!(p.data, ch);
        assert_eq!(p.ends.len(), 2);

        // Both: three records, still one segment boundary, after the first.
        let p = plan(
            &ch,
            FragmentOptions {
                split_packet: true,
                split_record: true,
                fallback_delay: Duration::ZERO,
            },
        )
        .unwrap();
        assert_eq!(p.data.len(), ch.len() + 10);
        assert_eq!(p.ends.len(), 2);
        let first = u16::from_be_bytes([p.data[3], p.data[4]]) as usize;
        assert_eq!(p.ends[0], 5 + first);
    }
}
