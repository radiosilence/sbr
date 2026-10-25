//! REALITY client handshake against a server that sends arbitrary bytes (the
//! plaintext record layer, ServerHello parsing and alert handling), and the
//! parsers for the handshake messages that arrive encrypted.
#![no_main]

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Reads the fuzz input in small, varying chunks; discards writes.
struct Server<'a> {
    data: &'a [u8],
    chunk: usize,
}

impl AsyncRead for Server<'_> {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let n = self.data.len().min(buf.remaining()).min(self.chunk);
        buf.put_slice(&self.data[..n]);
        self.data = &self.data[n..];
        self.chunk = self.chunk % 4096 + 7;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Server<'_> {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let cfg = sbr_reality::RealityConfig::new(
        "www.example.com",
        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
        "0123456789abcdef",
    )
    .unwrap();
    let chunk = data.first().map_or(1, |&b| b as usize + 1);
    let _ = rt.block_on(sbr_reality::connect(Server { data, chunk }, &cfg));
    sbr_reality::fuzz_handshake_messages(data);
});
