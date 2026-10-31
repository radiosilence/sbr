//! An `h3_quinn` connection that refuses oversized HTTP/3 frames before h3
//! buffers them.
//!
//! h3 reads every frame other than DATA whole before decoding it, and its
//! `max_field_section_size` is checked only after that, so a server sending
//! a HEADERS (or unknown) frame with a huge length makes the client buffer
//! all of it. The wrapper parses frame headers as bytes pass and fails the
//! stream on any non-DATA frame longer than [`MAX_FRAME`].

use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};

/// Longest non-DATA frame accepted: the response header cap.
const MAX_FRAME: u64 = crate::transport::MAX_RESPONSE_HEADERS as u64;
const FRAME_DATA: u64 = 0;
/// WebTransport's bidirectional stream marker: no length follows, and h3
/// treats the rest of the stream as its payload. sbr never enables it.
const FRAME_WEBTRANSPORT_BI: u64 = 0x41;
const STREAM_CONTROL: u64 = 0;

pub(crate) struct Connection(h3_quinn::Connection);

impl Connection {
    pub(crate) fn new(conn: quinn::Connection) -> Self {
        Self(h3_quinn::Connection::new(conn))
    }
}

pub(crate) struct OpenStreams(h3_quinn::OpenStreams);

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub(crate) struct BidiStream<B: Buf> {
    send: h3_quinn::SendStream<B>,
    recv: RecvStream,
}

impl<B: Buf> BidiStream<B> {
    fn new(s: h3_quinn::BidiStream<B>) -> Self {
        let (send, recv) = quic::BidiStream::split(s);
        Self {
            send,
            recv: RecvStream::new(recv, Frames::request()),
        }
    }
}

pub(crate) struct RecvStream {
    inner: h3_quinn::RecvStream,
    frames: Frames,
}

impl RecvStream {
    fn new(inner: h3_quinn::RecvStream, frames: Frames) -> Self {
        Self { inner, frames }
    }
}

impl<B: Buf> quic::Connection<B> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<RecvStream, ConnectionErrorIncoming>> {
        quic::Connection::<B>::poll_accept_recv(&mut self.0, cx).map_ok(|r| RecvStream::new(r, Frames::uni()))
    }

    fn poll_accept_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<BidiStream<B>, ConnectionErrorIncoming>> {
        quic::Connection::<B>::poll_accept_bidi(&mut self.0, cx).map_ok(BidiStream::new)
    }

    fn opener(&self) -> OpenStreams {
        OpenStreams(quic::Connection::<B>::opener(&self.0))
    }
}

impl<B: Buf> quic::OpenStreams<B> for Connection {
    type BidiStream = BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<BidiStream<B>, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.0, cx).map_ok(BidiStream::new)
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.0, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.0, code, reason)
    }
}

impl<B: Buf> quic::OpenStreams<B> for OpenStreams {
    type BidiStream = BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<BidiStream<B>, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.0, cx).map_ok(BidiStream::new)
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.0, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.0, code, reason)
    }
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = h3_quinn::SendStream<B>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let data = std::task::ready!(self.inner.poll_data(cx))?;
        if let Some(d) = &data
            && let Err(e) = self.frames.feed(d)
        {
            return Poll::Ready(Err(StreamErrorIncoming::Unknown(e.into())));
        }
        Poll::Ready(Ok(data))
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

/// A QUIC variable-length integer read a byte at a time.
#[derive(Default)]
struct VarInt {
    value: u64,
    have: u8,
    need: u8,
}

impl VarInt {
    fn push(&mut self, b: u8) -> Option<u64> {
        if self.have == 0 {
            self.need = 1 << (b >> 6);
            self.value = u64::from(b & 0x3f);
        } else {
            self.value = (self.value << 8) | u64::from(b);
        }
        self.have += 1;
        (self.have == self.need).then(|| std::mem::take(self).value)
    }
}

enum State {
    StreamType(VarInt),
    FrameType(VarInt),
    Length(u64, VarInt),
    Payload(u64),
    /// Not a framed stream (QPACK, or a type h3 rejects or ignores).
    Unframed,
}

/// Frame headers on one receive stream.
struct Frames(State);

impl Frames {
    fn request() -> Self {
        Self(State::FrameType(VarInt::default()))
    }

    fn uni() -> Self {
        Self(State::StreamType(VarInt::default()))
    }

    fn feed(&mut self, mut data: &[u8]) -> Result<(), &'static str> {
        while let Some((&b, rest)) = data.split_first() {
            match &mut self.0 {
                State::Unframed => return Ok(()),
                State::Payload(left) => {
                    let n = (*left).min(data.len() as u64);
                    *left -= n;
                    data = &data[n as usize..];
                    if *left == 0 {
                        self.0 = State::FrameType(VarInt::default());
                    }
                    continue;
                }
                State::StreamType(v) => {
                    if let Some(t) = v.push(b) {
                        self.0 = if t == STREAM_CONTROL {
                            State::FrameType(VarInt::default())
                        } else {
                            State::Unframed
                        };
                    }
                }
                State::FrameType(v) => {
                    if let Some(t) = v.push(b) {
                        if t == FRAME_WEBTRANSPORT_BI {
                            return Err("unexpected WebTransport stream");
                        }
                        self.0 = State::Length(t, VarInt::default());
                    }
                }
                State::Length(t, v) => {
                    if let Some(len) = v.push(b) {
                        if *t != FRAME_DATA && len > MAX_FRAME {
                            return Err("HTTP/3 frame over the size limit");
                        }
                        self.0 = if len == 0 {
                            State::FrameType(VarInt::default())
                        } else {
                            State::Payload(len)
                        };
                    }
                }
            }
            data = rest;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::quic::put_varint;

    fn frame(ty: u64, len: u64) -> Vec<u8> {
        let mut b = Vec::new();
        put_varint(&mut b, ty);
        put_varint(&mut b, len);
        b
    }

    #[test]
    fn refuses_long_headers_split_anywhere() {
        let mut wire = frame(1, 100);
        wire.extend_from_slice(&[0; 100]);
        wire.extend(frame(0, 1 << 30)); // DATA may be long
        wire.extend_from_slice(&[0; 3]);
        let mut f = Frames::request();
        for b in wire.chunks(1) {
            f.feed(b).unwrap();
        }
        let mut f = Frames::request();
        let bad = frame(1, MAX_FRAME + 1);
        assert!(bad.chunks(1).try_for_each(|b| f.feed(b)).is_err());
        let mut f = Frames::request();
        assert!(f.feed(&frame(0x21, 1 << 40)).is_err(), "reserved types too");
        let mut ok = frame(0x21, 100);
        ok.extend_from_slice(&[0; 100]);
        assert!(Frames::request().feed(&ok).is_ok());
        let mut wt = Vec::new();
        put_varint(&mut wt, FRAME_WEBTRANSPORT_BI);
        assert!(Frames::request().feed(&wt).is_err());
    }

    #[test]
    fn long_data_passes_without_buffering() {
        let mut f = Frames::request();
        f.feed(&frame(0, 1 << 40)).unwrap();
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..4 {
            f.feed(&chunk).unwrap();
        }
        assert!(matches!(f.0, State::Payload(n) if n == (1 << 40) - (4 << 20)));
    }

    #[test]
    fn control_stream_framed_others_not() {
        let mut ctrl = vec![0x00];
        ctrl.extend(frame(4, MAX_FRAME + 1));
        assert!(Frames::uni().feed(&ctrl).is_err());
        let mut qpack = vec![0x02];
        qpack.extend(frame(4, MAX_FRAME + 1));
        assert!(Frames::uni().feed(&qpack).is_ok());
    }
}
