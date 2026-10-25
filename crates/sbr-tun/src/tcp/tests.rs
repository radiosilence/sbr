//! The userspace stack against smoltcp, an independent TCP implementation,
//! on a simulated link with a virtual clock. Loss, reordering, duplication
//! and small windows are injected deterministically (seeded), and timeouts
//! cost no wall-clock time.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp as stcp;
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::*;
use crate::device::HEADROOM;
use crate::packet;

const SERVER4: &str = "93.184.216.34";
const CLIENT6: &str = "fdfe:dcba:9876::1";
const SERVER6: &str = "2001:db8::34";

#[derive(Clone, Copy, Default)]
struct Impair {
    loss: f64,
    reorder: f64,
    dup: f64,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Packets in flight one way, each with its delivery time.
#[derive(Default)]
struct Wire {
    q: Vec<(Duration, Vec<u8>)>,
    sent: usize,
    dropped: usize,
}

impl Wire {
    fn push(&mut self, at: Duration, p: Vec<u8>, imp: Impair, rng: &mut Rng) {
        self.sent += 1;
        if rng.next() < imp.loss {
            self.dropped += 1;
            return;
        }
        let base = Duration::from_micros(50);
        let extra = if rng.next() < imp.reorder {
            Duration::from_micros(400)
        } else {
            Duration::ZERO
        };
        if rng.next() < imp.dup {
            self.q.push((at + base + Duration::from_micros(700), p.clone()));
        }
        self.q.push((at + base + extra, p));
    }

    fn due(&mut self, now: Duration) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut i = 0;
        // Stable: equal delivery times keep send order.
        self.q.sort_by_key(|(t, _)| *t);
        while i < self.q.len() {
            if self.q[i].0 <= now {
                out.push(self.q.remove(i).1);
            } else {
                i += 1;
            }
        }
        out
    }

    fn next(&self) -> Option<Duration> {
        self.q.iter().map(|(t, _)| *t).min()
    }
}

/// The app's side of the link, as smoltcp sees it.
struct Dev {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut Vec<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push(b);
        r
    }
}

impl phy::Device for Dev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _: SInstant) -> Option<(RxTok, TxTok<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxTok(p), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _: SInstant) -> Option<TxTok<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

type Accepts = Arc<Mutex<Vec<(SocketAddr, SocketAddr, Stream)>>>;

struct Sim {
    t0: Instant,
    now: Duration,
    tcp: Tcp,
    accepted: Accepts,
    iface: Interface,
    sockets: SocketSet<'static>,
    dev: Dev,
    up: Wire,
    down: Wire,
    imp_up: Impair,
    imp_down: Impair,
    rng: Rng,
    next_port: u16,
}

impl Sim {
    fn new(cfg: TcpConfig, mtu: usize) -> Self {
        let t0 = Instant::now();
        let accepted: Accepts = Arc::default();
        let acc = accepted.clone();
        let tcp = Tcp::new(cfg, mtu, move |s, d, st| acc.lock().unwrap().push((s, d, st)), t0);
        let mut dev = Dev {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu,
        };
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, SInstant::from_micros(0));
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(IpAddress::v4(172, 19, 0, 1), 30)).unwrap();
            a.push(IpCidr::new(CLIENT6.parse::<std::net::Ipv6Addr>().unwrap().into(), 126))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(172, 19, 0, 2))
            .unwrap();
        iface
            .routes_mut()
            .add_default_ipv6_route("fdfe:dcba:9876::2".parse::<std::net::Ipv6Addr>().unwrap())
            .unwrap();
        Self {
            t0,
            now: Duration::ZERO,
            tcp,
            accepted,
            iface,
            sockets: SocketSet::new(Vec::new()),
            dev,
            up: Wire::default(),
            down: Wire::default(),
            imp_up: Impair::default(),
            imp_down: Impair::default(),
            rng: Rng(0x9e37_79b9_7f4a_7c15),
            next_port: 40000,
        }
    }

    fn impair(&mut self, both: Impair) {
        self.imp_up = both;
        self.imp_down = both;
    }

    /// A smoltcp client socket connecting to `server:port`.
    fn connect(&mut self, v6: bool, port: u16, rx: usize, tx: usize, ts: bool) -> SocketHandle {
        let mut s = stcp::Socket::new(
            stcp::SocketBuffer::new(vec![0; rx]),
            stcp::SocketBuffer::new(vec![0; tx]),
        );
        if ts {
            s.set_tsval_generator(Some(|| 0x1234_5678));
        }
        s.set_nagle_enabled(false);
        let remote: IpAddr = if v6 { SERVER6 } else { SERVER4 }.parse().unwrap();
        self.next_port += 1;
        s.connect(self.iface.context(), (IpAddress::from(remote), port), self.next_port)
            .unwrap();
        self.sockets.add(s)
    }

    fn sock(&mut self, h: SocketHandle) -> &mut stcp::Socket<'static> {
        self.sockets.get_mut::<stcp::Socket>(h)
    }

    fn take_accepted(&mut self) -> Vec<(SocketAddr, SocketAddr, Stream)> {
        std::mem::take(&mut *self.accepted.lock().unwrap())
    }

    /// One round: both stacks process what has arrived and send. Returns
    /// whether anything was delivered.
    fn round(&mut self) -> bool {
        let snow = SInstant::from_micros(self.now.as_micros() as i64);
        self.iface.poll(snow, &mut self.dev, &mut self.sockets);
        for p in self.dev.tx.drain(..) {
            self.up.push(self.now, p, self.imp_up, &mut self.rng);
        }
        let now = self.t0 + self.now;
        let arrivals = self.up.due(self.now);
        let delivered = !arrivals.is_empty();
        let Self {
            tcp,
            down,
            imp_down,
            rng,
            now: vnow,
            ..
        } = self;
        let mut link = |b: &mut [u8]| {
            let p = b[HEADROOM..].to_vec();
            assert!(packet::verify(&p), "bad checksum from the stack");
            down.push(*vnow, p, *imp_down, rng);
            Ok(())
        };
        for p in arrivals {
            let h = packet::parse(&p).expect("smoltcp sent a TCP packet");
            tcp.input(&p, &h, now, &mut link);
        }
        tcp.drain_app(now);
        tcp.run_timers(now, &mut link);
        tcp.flush(now, &mut link);
        let back = self.down.due(self.now);
        let delivered = delivered || !back.is_empty();
        self.dev.rx.extend(back);
        delivered
    }

    /// Advance the clock to the next event, at most `max`.
    fn tick(&mut self, max: Duration) {
        let snow = SInstant::from_micros(self.now.as_micros() as i64);
        let mut next = self.now + max;
        for t in [self.up.next(), self.down.next()].into_iter().flatten() {
            next = next.min(t);
        }
        if let Some(d) = self.tcp.next_deadline() {
            next = next.min(d.saturating_duration_since(self.t0));
        }
        if let Some(d) = self.iface.poll_delay(snow, &self.sockets) {
            next = next.min(self.now + Duration::from_micros(d.total_micros()));
        }
        self.now = next.max(self.now + Duration::from_micros(1));
    }

    /// Run until `done` or `limit` of virtual time passes.
    fn run(&mut self, limit: Duration, mut done: impl FnMut(&mut Self) -> bool) {
        let end = self.now + limit;
        while self.now < end {
            self.round();
            if done(self) {
                return;
            }
            self.tick(Duration::from_millis(1));
        }
        panic!("not done after {limit:?} of virtual time");
    }
}

fn poll_read(s: &mut Stream, buf: &mut [u8]) -> Option<io::Result<usize>> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut rb = ReadBuf::new(buf);
    match Pin::new(s).poll_read(&mut cx, &mut rb) {
        Poll::Ready(Ok(())) => Some(Ok(rb.filled().len())),
        Poll::Ready(Err(e)) => Some(Err(e)),
        Poll::Pending => None,
    }
}

fn poll_write(s: &mut Stream, buf: &[u8]) -> Option<io::Result<usize>> {
    let mut cx = Context::from_waker(Waker::noop());
    match Pin::new(s).poll_write(&mut cx, buf) {
        Poll::Ready(r) => Some(r),
        Poll::Pending => None,
    }
}

fn shutdown(s: &mut Stream) {
    let mut cx = Context::from_waker(Waker::noop());
    let _ = Pin::new(s).poll_shutdown(&mut cx);
}

/// The engine side: echo everything back, close after the app closes.
struct Echo {
    s: Stream,
    pend: Vec<u8>,
    eof: bool,
    closed: bool,
    err: Option<io::ErrorKind>,
    total: usize,
}

impl Echo {
    fn new(s: Stream) -> Self {
        s.accept();
        Self {
            s,
            pend: Vec::new(),
            eof: false,
            closed: false,
            err: None,
            total: 0,
        }
    }

    fn step(&mut self) {
        if self.err.is_some() || self.closed {
            return;
        }
        let mut b = [0u8; 9000];
        loop {
            while !self.pend.is_empty() {
                match poll_write(&mut self.s, &self.pend) {
                    Some(Ok(n)) => {
                        self.pend.drain(..n);
                    }
                    Some(Err(e)) => {
                        self.err = Some(e.kind());
                        return;
                    }
                    None => return,
                }
            }
            if self.eof {
                shutdown(&mut self.s);
                self.closed = true;
                return;
            }
            match poll_read(&mut self.s, &mut b) {
                Some(Ok(0)) => self.eof = true,
                Some(Ok(n)) => {
                    self.total += n;
                    self.pend.extend_from_slice(&b[..n]);
                }
                Some(Err(e)) => {
                    self.err = Some(e.kind());
                    return;
                }
                None => return,
            }
        }
    }
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_add(seed).wrapping_mul(2654435761) >> 24) as u8)
        .collect()
}

/// A client that sends `data`, closes, and collects the echo.
struct Client {
    h: SocketHandle,
    data: Vec<u8>,
    sent: usize,
    got: Vec<u8>,
}

impl Client {
    fn step(&mut self, sim: &mut Sim) {
        let s = sim.sock(self.h);
        if s.can_send() && self.sent < self.data.len() {
            self.sent += s.send_slice(&self.data[self.sent..]).unwrap();
            if self.sent == self.data.len() {
                s.close();
            }
        }
        while s.can_recv() {
            s.recv(|b| {
                self.got.extend_from_slice(b);
                (b.len(), ())
            })
            .unwrap();
        }
    }

    fn done(&self, sim: &mut Sim) -> bool {
        self.got.len() == self.data.len() && !sim.sock(self.h).may_recv()
    }
}

/// Echo `n` connections of `len` bytes each through the stack.
fn echo(sim: &mut Sim, n: usize, len: usize, v6: bool, ts: bool, client_buf: usize, limit: Duration) {
    let mut clients: Vec<Client> = (0..n)
        .map(|i| Client {
            h: sim.connect(v6, 443, client_buf, client_buf, ts),
            data: pattern(len, i as u32),
            sent: 0,
            got: Vec::new(),
        })
        .collect();
    let mut servers: Vec<Echo> = Vec::new();
    sim.run(limit, |sim| {
        for (_, _, s) in sim.take_accepted() {
            servers.push(Echo::new(s));
        }
        for e in &mut servers {
            e.step();
        }
        for c in &mut clients {
            c.step(sim);
        }
        clients.iter().all(|c| c.done(sim))
    });
    for (i, c) in clients.iter().enumerate() {
        assert!(c.got == c.data, "connection {i}: echo corrupted");
    }
    assert!(servers.iter().all(|e| e.err.is_none()), "an engine stream saw an error");
    // Let the closes finish: every connection must be reaped.
    sim.run(Duration::from_secs(30), |sim| {
        for e in &mut servers {
            e.step();
        }
        sim.tcp.live() == 0
    });
}

fn cfg(rx: usize, tx: usize) -> TcpConfig {
    TcpConfig {
        rx_buffer: rx,
        tx_buffer: tx,
        max_connections: 0,
        pool_keep: 1 << 20,
        memory_limit: 0,
        defer_handshake: false,
    }
}

#[test]
fn clean_echo_v4_and_v6() {
    for v6 in [false, true] {
        let mut sim = Sim::new(cfg(256 << 10, 256 << 10), 1500);
        // 2 MiB each way over a 100 µs RTT: no stalls, so well under 100 ms.
        echo(&mut sim, 1, 2 << 20, v6, true, 128 << 10, Duration::from_millis(100));
        assert_eq!(sim.down.dropped + sim.up.dropped, 0);
        let st = sim.tcp.stats;
        assert_eq!((st.fast_retransmits, st.timeouts), (0, 0), "{st:?}");
    }
}

#[test]
fn clean_echo_jumbo_mtu_without_timestamps() {
    let mut sim = Sim::new(cfg(1 << 20, 1 << 20), 9000);
    echo(
        &mut sim,
        1,
        4 << 20,
        false,
        false,
        512 << 10,
        Duration::from_millis(100),
    );
}

#[test]
fn loss_reordering_and_duplication() {
    for (seed, ts) in [(1u64, true), (2, false), (3, true)] {
        let mut sim = Sim::new(cfg(256 << 10, 256 << 10), 1500);
        sim.rng = Rng(0x2545_f491_4f6c_dd1d ^ seed);
        sim.impair(Impair {
            loss: 0.02,
            reorder: 0.05,
            dup: 0.01,
        });
        echo(&mut sim, 2, 1 << 20, seed == 2, ts, 128 << 10, Duration::from_secs(300));
        assert!(
            sim.down.dropped > 0 && sim.up.dropped > 0,
            "the test must actually lose packets"
        );
        // Most of our losses must be repaired by fast retransmit, not by
        // waiting out a timeout.
        let st = sim.tcp.stats;
        eprintln!(
            "seed {seed}: {st:?}, {} of {} dropped toward the app",
            sim.down.dropped, sim.down.sent
        );
        assert!(st.fast_retransmits > 0, "{st:?}");
        assert!(st.timeouts * 4 < sim.down.dropped as u64, "{st:?}");
    }
}

#[test]
fn heavy_loss_still_completes() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    sim.impair(Impair {
        loss: 0.15,
        reorder: 0.1,
        dup: 0.0,
    });
    echo(&mut sim, 1, 128 << 10, false, true, 32 << 10, Duration::from_secs(1200));
}

#[test]
fn small_windows_both_ways() {
    // Our receive window is 4 KiB and the app's is 2 KiB: both senders
    // spend most of the transfer window-limited, through zero windows.
    let mut sim = Sim::new(cfg(4 << 10, 4 << 10), 1500);
    echo(&mut sim, 1, 256 << 10, false, true, 2 << 10, Duration::from_secs(120));
}

#[test]
fn many_concurrent_connections() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    sim.impair(Impair {
        loss: 0.005,
        reorder: 0.01,
        dup: 0.0,
    });
    echo(&mut sim, 300, 16 << 10, false, true, 16 << 10, Duration::from_secs(300));
}

#[test]
fn zero_window_until_the_app_reads() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    let h = sim.connect(false, 80, 8 << 10, 8 << 10, true);
    let mut srv = None;
    sim.run(Duration::from_secs(5), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some() && sim.sock(h).may_send()
    });
    let mut srv = srv.unwrap();
    let data = pattern(200 << 10, 7);
    let mut sent = 0;
    // The app reads nothing for a minute of virtual time.
    let until = sim.now + Duration::from_secs(60);
    sim.run(Duration::from_secs(61), |sim| {
        while sent < data.len() {
            match poll_write(&mut srv, &data[sent..]) {
                Some(Ok(n)) => sent += n,
                _ => break,
            }
        }
        sim.now >= until
    });
    assert!(!sim.sock(h).can_send() || sim.sock(h).recv_queue() == 8 << 10);
    assert!(sent > 8 << 10, "the send buffer should absorb writes");
    let deadline = sim.tcp.next_deadline().expect("persist timer armed");
    assert!(deadline.saturating_duration_since(sim.t0) <= sim.now + MAX_PROBE_GAP);
    let mut got = Vec::new();
    sim.run(Duration::from_secs(120), |sim| {
        while sent < data.len() {
            match poll_write(&mut srv, &data[sent..]) {
                Some(Ok(n)) => sent += n,
                _ => break,
            }
        }
        let s = sim.sock(h);
        while s.can_recv() {
            s.recv(|b| {
                got.extend_from_slice(b);
                (b.len(), ())
            })
            .unwrap();
        }
        got.len() == data.len()
    });
    assert!(got == data);
}

/// Probes back off but never stop while data is waiting.
const MAX_PROBE_GAP: Duration = Duration::from_secs(61);

#[test]
fn half_close_from_the_app() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    let h = sim.connect(false, 80, 64 << 10, 64 << 10, true);
    let req = b"GET / HTTP/1.0\r\n\r\n";
    let mut srv: Option<Stream> = None;
    let mut got_req = Vec::new();
    let mut req_sent = false;
    sim.run(Duration::from_secs(5), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        let s = sim.sock(h);
        if s.can_send() && !req_sent {
            s.send_slice(req).unwrap();
            s.close(); // FIN after the request
            req_sent = true;
        }
        let Some(srv) = srv.as_mut() else { return false };
        let mut b = [0u8; 100];
        match poll_read(srv, &mut b) {
            Some(Ok(0)) => true,
            Some(Ok(n)) => {
                got_req.extend_from_slice(&b[..n]);
                false
            }
            _ => false,
        }
    });
    assert_eq!(got_req, req);
    // The app's write half is closed; ours still works.
    let mut srv = srv.unwrap();
    let body = pattern(300 << 10, 3);
    let mut sent = 0;
    let mut got = Vec::new();
    sim.run(Duration::from_secs(10), |sim| {
        while sent < body.len() {
            match poll_write(&mut srv, &body[sent..]) {
                Some(Ok(n)) => sent += n,
                _ => break,
            }
        }
        if sent == body.len() {
            shutdown(&mut srv);
        }
        let s = sim.sock(h);
        while s.can_recv() {
            s.recv(|b| {
                got.extend_from_slice(b);
                (b.len(), ())
            })
            .unwrap();
        }
        !s.may_recv() && got.len() == body.len()
    });
    assert!(got == body);
    drop(srv);
    sim.run(Duration::from_secs(10), |sim| sim.tcp.live() == 0);
}

#[test]
fn half_close_from_the_engine() {
    // The engine finishes first (an upstream that closed after its
    // response) while the app keeps sending.
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    let h = sim.connect(false, 80, 64 << 10, 64 << 10, false);
    let mut srv = None;
    sim.run(Duration::from_secs(5), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some()
    });
    let mut srv = srv.unwrap();
    assert_eq!(poll_write(&mut srv, b"bye").unwrap().unwrap(), 3);
    shutdown(&mut srv);
    let upload = pattern(100 << 10, 9);
    let (mut sent, mut got, mut got_resp) = (0, Vec::new(), Vec::new());
    sim.run(Duration::from_secs(10), |sim| {
        let s = sim.sock(h);
        while s.can_recv() {
            s.recv(|b| {
                got_resp.extend_from_slice(b);
                (b.len(), ())
            })
            .unwrap();
        }
        if s.can_send() && sent < upload.len() {
            sent += s.send_slice(&upload[sent..]).unwrap();
            if sent == upload.len() {
                s.close();
            }
        }
        let mut b = [0u8; 4096];
        loop {
            match poll_read(&mut srv, &mut b) {
                Some(Ok(0)) => return got.len() == upload.len(),
                Some(Ok(n)) => got.extend_from_slice(&b[..n]),
                _ => return false,
            }
        }
    });
    assert_eq!(got_resp, b"bye");
    assert!(got == upload);
    assert!(
        matches!(poll_write(&mut srv, b"x"), Some(Err(_))),
        "writes after shutdown fail"
    );
    drop(srv);
    sim.run(Duration::from_secs(10), |sim| {
        sim.tcp.live() == 0 && sim.sock(h).state() == stcp::State::Closed
            || sim.sock(h).state() == stcp::State::TimeWait
    });
}

#[test]
fn reset_from_the_app() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    let h = sim.connect(false, 80, 64 << 10, 64 << 10, true);
    let mut srv = None;
    sim.run(Duration::from_secs(5), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some()
    });
    let mut srv = srv.unwrap();
    sim.sock(h).abort();
    let mut err = None;
    sim.run(Duration::from_secs(5), |_| {
        let mut b = [0u8; 16];
        if let Some(Err(e)) = poll_read(&mut srv, &mut b) {
            err = Some(e.kind());
        }
        err.is_some()
    });
    assert_eq!(err, Some(io::ErrorKind::ConnectionReset));
    assert!(poll_write(&mut srv, b"late").unwrap().is_err());
    assert_eq!(sim.tcp.live(), 0);
}

#[test]
fn abort_from_the_engine_resets_the_app() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    let h = sim.connect(true, 80, 64 << 10, 64 << 10, true);
    let mut srv = None;
    sim.run(Duration::from_secs(5), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some() && sim.sock(h).state() == stcp::State::Established
    });
    srv.as_ref().unwrap().abort();
    sim.run(Duration::from_secs(5), |sim| sim.sock(h).state() == stcp::State::Closed);
    assert_eq!(sim.tcp.live(), 0);
}

#[test]
fn engine_drop_with_unread_data_resets() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    let h = sim.connect(false, 80, 64 << 10, 64 << 10, true);
    let mut srv = None;
    sim.run(Duration::from_secs(5), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        let s = sim.sock(h);
        if s.can_send() && s.send_queue() == 0 {
            s.send_slice(b"unread").unwrap();
        }
        srv.is_some()
    });
    sim.run(Duration::from_secs(1), |sim| sim.sock(h).send_queue() == 0);
    drop(srv);
    sim.run(Duration::from_secs(5), |sim| sim.sock(h).state() == stcp::State::Closed);
    assert_eq!(sim.tcp.live(), 0);
}

#[test]
fn engine_drop_drains_the_send_buffer_first() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    let h = sim.connect(false, 80, 16 << 10, 16 << 10, true);
    let mut srv = None;
    sim.run(Duration::from_secs(5), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some()
    });
    let mut srv = srv.unwrap();
    let data = pattern(64 << 10, 5);
    assert_eq!(poll_write(&mut srv, &data).unwrap().unwrap(), data.len());
    drop(srv);
    let mut got = Vec::new();
    sim.run(Duration::from_secs(10), |sim| {
        let s = sim.sock(h);
        while s.can_recv() {
            s.recv(|b| {
                got.extend_from_slice(b);
                (b.len(), ())
            })
            .unwrap();
        }
        !s.may_recv()
    });
    assert!(got == data, "the engine's last bytes reach the app before the FIN");
}

#[test]
fn lost_syn_ack_is_retransmitted() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    sim.imp_down.loss = 1.0;
    let h = sim.connect(false, 80, 4096, 4096, true);
    sim.run(Duration::from_millis(500), |sim| sim.down.dropped > 0);
    sim.imp_down.loss = 0.0;
    sim.run(Duration::from_secs(10), |sim| sim.tcp.stats.accepted == 1);
    assert_eq!(sim.sock(h).state(), stcp::State::Established);
}

#[test]
fn stray_segment_gets_a_reset() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    // A segment for a connection that does not exist, as after the stack
    // restarted under a live app connection.
    let mut o = wire::Opts::default();
    o.ts(1, 1);
    let src: SocketAddr = "172.19.0.1:50000".parse().unwrap();
    let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let off = wire::payload_offset(false, &o);
    let mut buf = vec![0u8; off + 10];
    wire::finish(
        &mut buf,
        &wire::Out {
            src,
            dst,
            seq: 1000,
            ack: 5000,
            flags: wire::ACK | wire::PSH,
            wnd: 100,
            opts: &o,
        },
    );
    let p = &buf[HEADROOM..];
    let h = packet::parse(p).unwrap();
    let mut out = Vec::new();
    sim.tcp.input(p, &h, sim.t0, &mut |b: &mut [u8]| {
        out.push(b[HEADROOM..].to_vec());
        Ok(())
    });
    assert_eq!(out.len(), 1);
    let h = packet::parse(&out[0]).unwrap();
    let s = wire::parse(&out[0], &h).unwrap();
    assert_eq!((h.src, h.dst), (dst, src));
    assert_eq!((s.flags, s.seq), (wire::RST, 5000));
    assert_eq!(sim.tcp.live(), 0);
}

#[test]
fn idle_connections_cost_no_timers_or_buffers() {
    let mut sim = Sim::new(cfg(256 << 10, 256 << 10), 1500);
    let hs: Vec<_> = (0..20)
        .map(|_| sim.connect(false, 80, 64 << 10, 64 << 10, true))
        .collect();
    let mut srvs = Vec::new();
    sim.run(Duration::from_secs(5), |sim| {
        srvs.extend(sim.take_accepted().into_iter().map(|(_, _, s)| Echo::new(s)));
        srvs.len() == hs.len()
    });
    // A burst each way, then silence.
    for &h in &hs {
        sim.sock(h).send_slice(&pattern(50 << 10, 1)).unwrap();
    }
    sim.run(Duration::from_secs(10), |sim| {
        for e in &mut srvs {
            e.step();
        }
        hs.iter().all(|&h| {
            let s = sim.sock(h);
            while s.can_recv() {
                s.recv(|b| (b.len(), ())).unwrap();
            }
            s.send_queue() == 0
        }) && srvs.iter().all(|e| e.total == 50 << 10 && e.pend.is_empty())
    });
    sim.run(Duration::from_secs(5), |sim| sim.tcp.next_deadline().is_none());
    for e in &srvs {
        let g = e.s.shared.m.lock().unwrap();
        assert_eq!(g.rx.held() + g.tx.held(), 0, "idle connection holds buffer memory");
    }
    assert_eq!(sim.tcp.live(), 20);
}

#[test]
fn connection_limit_resets_new_syns() {
    let mut c = cfg(64 << 10, 64 << 10);
    c.max_connections = 2;
    let mut sim = Sim::new(c, 1500);
    let hs: Vec<_> = (0..3).map(|_| sim.connect(false, 80, 4096, 4096, true)).collect();
    sim.run(Duration::from_secs(5), |sim| {
        sim.sock(hs[2]).state() == stcp::State::Closed && sim.tcp.stats.accepted == 2
    });
    assert!(hs[..2].iter().all(|&h| sim.sock(h).state() == stcp::State::Established));
}

#[test]
fn stack_shutdown_fails_streams() {
    let mut sim = Sim::new(cfg(64 << 10, 64 << 10), 1500);
    sim.connect(false, 80, 4096, 4096, true);
    let mut srv = None;
    sim.run(Duration::from_secs(5), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some()
    });
    let mut srv = srv.unwrap();
    let Sim { tcp, .. } = sim;
    drop(tcp);
    let mut b = [0u8; 4];
    assert!(poll_read(&mut srv, &mut b).unwrap().is_err());
    assert!(poll_write(&mut srv, b"x").unwrap().is_err());
}

#[test]
fn memory_limit_bounds_all_buffers_together() {
    let n = 8;
    let limit = 128 << 10;
    let mut c = cfg(256 << 10, 256 << 10);
    c.memory_limit = limit;
    let mut sim = Sim::new(c, 1500);
    let hs: Vec<_> = (0..n)
        .map(|_| sim.connect(false, 80, 256 << 10, 256 << 10, true))
        .collect();
    let mut srvs = Vec::new();
    sim.run(Duration::from_secs(5), |sim| {
        srvs.extend(sim.take_accepted().into_iter().map(|(_, _, s)| s));
        srvs.len() == n
    });
    // Apps upload and the engine writes, but nobody reads for ten seconds.
    let data = pattern(256 << 10, 4);
    let mut up = vec![0; n];
    let mut down = vec![0; n];
    // The cap, plus what each connection may always hold: a chunk each way
    // (the floor) and a partly filled chunk each way.
    let bound = limit + 4 * n * buf::CHUNK;
    let mut peak = 0;
    let until = sim.now + Duration::from_secs(10);
    sim.run(Duration::from_secs(11), |sim| {
        for i in 0..n {
            let s = sim.sock(hs[i]);
            if s.can_send() && up[i] < data.len() {
                up[i] += s.send_slice(&data[up[i]..]).unwrap();
            }
            while down[i] < data.len() {
                match poll_write(&mut srvs[i], &data[down[i]..]) {
                    Some(Ok(k)) => down[i] += k,
                    _ => break,
                }
            }
        }
        peak = peak.max(sim.tcp.env().pool.used());
        sim.now >= until
    });
    assert!(peak <= bound, "buffers peaked at {peak}, over {bound}");
    assert!(peak >= limit / 2, "the test should approach the limit");
    // Now both sides drain and everything gets through.
    let mut got_up = vec![0usize; n];
    let mut got_down = vec![0usize; n];
    sim.run(Duration::from_secs(60), |sim| {
        let mut b = [0u8; 16384];
        for i in 0..n {
            while let Some(Ok(k)) = poll_read(&mut srvs[i], &mut b) {
                if k == 0 {
                    break;
                }
                got_up[i] += k;
            }
            while down[i] < data.len() {
                match poll_write(&mut srvs[i], &data[down[i]..]) {
                    Some(Ok(k)) => down[i] += k,
                    _ => break,
                }
            }
            let s = sim.sock(hs[i]);
            if s.can_send() && up[i] < data.len() {
                up[i] += s.send_slice(&data[up[i]..]).unwrap();
            }
            while s.can_recv() {
                s.recv(|b| {
                    got_down[i] += b.len();
                    (b.len(), ())
                })
                .unwrap();
            }
        }
        peak = peak.max(sim.tcp.env().pool.used());
        got_up.iter().chain(&got_down).all(|&g| g == data.len())
    });
    assert!(peak <= bound, "buffers peaked at {peak}, over {bound}");
}

fn deferred() -> TcpConfig {
    let mut c = cfg(64 << 10, 64 << 10);
    c.defer_handshake = true;
    c
}

/// With a deferred handshake the engine gets the connection on the SYN,
/// and the app's connect completes only once the engine accepts.
#[test]
fn deferred_handshake_waits_for_the_engine() {
    let mut sim = Sim::new(deferred(), 1500);
    let h = sim.connect(false, 443, 64 << 10, 64 << 10, true);
    let mut srv = None;
    sim.run(Duration::from_secs(1), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some()
    });
    // The outbound takes three seconds to connect; the app's SYN
    // retransmissions in the meantime draw nothing and create nothing.
    let until = sim.now + Duration::from_secs(3);
    sim.run(Duration::from_secs(4), |sim| sim.now >= until);
    assert_eq!(sim.sock(h).state(), stcp::State::SynSent);
    assert_eq!(sim.tcp.stats.accepted, 1);
    assert_eq!(sim.tcp.live(), 1);
    let mut e = Echo::new(srv.unwrap());
    sim.run(Duration::from_secs(5), |sim| {
        sim.sock(h).state() == stcp::State::Established
    });
    let data = pattern(100 << 10, 2);
    let mut c = Client {
        h,
        data: data.clone(),
        sent: 0,
        got: Vec::new(),
    };
    sim.run(Duration::from_secs(10), |sim| {
        e.step();
        c.step(sim);
        c.done(sim)
    });
    assert!(c.got == data);
}

#[test]
fn deferred_handshake_refused_resets_the_connect() {
    let mut sim = Sim::new(deferred(), 1500);
    let h = sim.connect(false, 443, 4096, 4096, true);
    let mut srv = None;
    sim.run(Duration::from_secs(1), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some()
    });
    srv.as_ref().unwrap().abort();
    sim.run(Duration::from_secs(1), |sim| sim.sock(h).state() == stcp::State::Closed);
    assert_eq!(sim.tcp.live(), 0);
    assert_eq!(sim.tcp.stats.resets_out, 1);
}

#[test]
fn deferred_handshake_dropped_engine_resets_the_connect() {
    let mut sim = Sim::new(deferred(), 1500);
    let h = sim.connect(false, 443, 4096, 4096, true);
    sim.run(Duration::from_secs(1), |sim| {
        // The engine task dies without a verdict.
        !sim.take_accepted().is_empty()
    });
    sim.run(Duration::from_secs(1), |sim| sim.sock(h).state() == stcp::State::Closed);
    assert_eq!(sim.tcp.live(), 0);
}

#[test]
fn deferred_handshake_silent_drop_is_a_black_hole() {
    let mut sim = Sim::new(deferred(), 1500);
    let h = sim.connect(false, 443, 4096, 4096, true);
    let mut srv = None;
    sim.run(Duration::from_secs(1), |sim| {
        if let Some((_, _, s)) = sim.take_accepted().pop() {
            srv = Some(s);
        }
        srv.is_some()
    });
    srv.unwrap().discard();
    let until = sim.now + Duration::from_secs(20);
    sim.run(Duration::from_secs(21), |sim| sim.now >= until);
    assert_eq!(sim.sock(h).state(), stcp::State::SynSent, "no answer at all");
    assert_eq!(sim.tcp.stats.accepted, 1, "retransmitted SYNs are not routed again");
    assert_eq!(sim.tcp.stats.segments_out, 0);
    // The placeholder goes away on its own.
    sim.sock(h).abort();
    sim.run(Duration::from_secs(120), |sim| sim.tcp.live() == 0);
}

#[test]
fn deferred_handshake_echo_under_loss() {
    let mut sim = Sim::new(deferred(), 1500);
    sim.impair(Impair {
        loss: 0.02,
        reorder: 0.02,
        dup: 0.0,
    });
    echo(&mut sim, 20, 64 << 10, false, true, 64 << 10, Duration::from_secs(300));
}
