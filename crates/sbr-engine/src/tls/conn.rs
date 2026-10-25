//! A client TLS connection: rustls, or REALITY (`sbr-reality`). Both run over
//! [`TlsIo`], which also gives XTLS Vision its way out to the raw stream.

use std::io::{self, Read as _};
use std::pin::Pin;
use std::task::{Context, Poll};

use sbr_core::Stream;
use sbr_reality::RealityStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{TlsIo, TlsStream};

pub enum TlsConn {
    Rustls(Box<TlsStream>),
    Reality(Box<RealityStream<TlsIo>>),
}

impl TlsConn {
    fn io(&mut self) -> &mut TlsIo {
        match self {
            Self::Rustls(t) => t.get_mut().0,
            Self::Reality(r) => r.get_mut(),
        }
    }

    /// The dialed stream under TLS (Vision direct mode).
    pub fn raw(&mut self) -> &mut Stream {
        self.io().raw()
    }

    /// Make sure the TLS layer never consumes bytes past the record it is
    /// working on (Vision may switch to raw after any record).
    pub fn limit_reads(&mut self) {
        // REALITY's record layer already decrypts one record at a time.
        if let Self::Rustls(t) = self {
            t.get_mut().0.limit_to_records();
        }
    }

    pub fn unlimit_reads(&mut self) {
        if let Self::Rustls(t) = self {
            t.get_mut().0.unlimit();
        }
    }

    /// Leave TLS: decrypted-but-unread bytes, then raw bytes already read
    /// off the wire. Read from [`TlsConn::raw`] afterwards.
    pub fn take_buffered(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Rustls(t) => {
                let mut tmp = [0u8; 4096];
                loop {
                    match t.get_mut().1.reader().read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => out.extend_from_slice(&tmp[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
            Self::Reality(r) => out = r.take_buffered(),
        }
        out.extend_from_slice(&self.io().take_raw());
        Ok(out)
    }
}

impl AsyncRead for TlsConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(t) => Pin::new(&mut **t).poll_read(cx, buf),
            Self::Reality(r) => Pin::new(&mut **r).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Rustls(t) => Pin::new(&mut **t).poll_write(cx, buf),
            Self::Reality(r) => Pin::new(&mut **r).poll_write(cx, buf),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Rustls(t) => Pin::new(&mut **t).poll_write_vectored(cx, bufs),
            Self::Reality(r) => Pin::new(&mut **r).poll_write_vectored(cx, bufs),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Rustls(t) => t.is_write_vectored(),
            Self::Reality(r) => r.is_write_vectored(),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(t) => Pin::new(&mut **t).poll_flush(cx),
            Self::Reality(r) => Pin::new(&mut **r).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(t) => Pin::new(&mut **t).poll_shutdown(cx),
            Self::Reality(r) => Pin::new(&mut **r).poll_shutdown(cx),
        }
    }
}
