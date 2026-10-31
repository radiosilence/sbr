//! What connections leave behind once closed, and what they cost while
//! open: tasks, file descriptors and heap bytes. A leaked relay or reader
//! task, or a socket nobody closes, passes every functional test; on iOS it
//! is memory and descriptors the extension never gets back.
//!
//! Its own binary with a single test, so the counting allocator sees
//! nothing else: the harness would run further tests on other threads, and
//! their allocations would land in these numbers.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: forwards to the system allocator, counting bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        grew(new);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd").map_or(0, |d| d.count())
}

fn tasks() -> usize {
    tokio::runtime::Handle::current().metrics().num_alive_tasks()
}

/// The iOS relay buffer, so the per-connection cost is the extension's.
const RELAY_BUFFER: usize = 16 * 1024;
const CONNECTIONS: usize = 200;
/// Heap per idle connection, after it carried data, for everything in this
/// process: both instances (2 × 16 KiB of relay buffers each), SOCKS state,
/// connection records, and the echo server's and test client's own buffers.
/// Not the extension's figure, which is the client instance alone, but it
/// moves with it.
const BYTES_PER_CONNECTION: usize = 128 * 1024;
/// Heap still held after a second identical round, beyond the first's.
/// Growth that stays (map capacity, timer wheel levels) happens in round
/// one; a per-connection leak shows again in round two.
const ROUND_SLACK: usize = 256 * 1024;
/// Connections that carry a megabyte each before the idle measurement.
const BULKED: usize = 20;
/// What a connection that carried bulk traffic may hold beyond an idle one:
/// buffers that grow to a burst and stay are what this catches.
const AFTER_BULK: usize = 16 * 1024;

async fn start(json: &str) -> Instance {
    let o = Options::parse(json).unwrap();
    let settings = Settings {
        relay_buffer: RELAY_BUFFER,
        ..Settings::default()
    };
    Instance::start(&o, settings).await.unwrap()
}

/// Poll until `f` holds or the deadline passes: aborted tasks are dropped
/// on their next poll, and sockets close as their tasks drop.
async fn settles(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "{what} did not settle");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn round_trip(mut s: tokio::net::TcpStream) -> tokio::net::TcpStream {
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    s
}

/// Echo `data` through `s` and keep it open.
async fn bulk(s: &mut tokio::net::TcpStream, data: &[u8], got: &mut [u8]) {
    let (mut r, mut w) = s.split();
    let (a, b) = tokio::join!(w.write_all(data), r.read_exact(got));
    a.unwrap();
    b.unwrap();
    assert!(got == data);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_connections_leave_nothing_and_open_ones_stay_small() {
    let echo = common::echo().await;
    let server = start(
        r#"{"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}],
        "outbounds":[{"type":"direct","tag":"direct"}]}"#,
    )
    .await;
    let server_port = common::port(&server, "in");
    let client = start(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[{{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":{server_port}}}]}}"#
    ))
    .await;
    let proxy = common::port(&client, "in");
    let idle = || client.engine.active_connections() == 0 && server.engine.active_connections() == 0;

    // The bulk pattern and its echo, allocated once so they are not counted.
    let (data, got) = (&vec![0x5au8; 1 << 20], &mut vec![0u8; 1 << 20]);
    // Open, carry data, idle, close; returns heap per idle connection, per
    // connection at peak, and held per connection after bulk traffic.
    let mut round = async || {
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);
        let mut open = Vec::with_capacity(CONNECTIONS);
        for _ in 0..CONNECTIONS {
            open.push(round_trip(common::socks_connect(proxy, echo).await).await);
        }
        let per = LIVE.load(Ordering::Relaxed).saturating_sub(before) / CONNECTIONS;
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before) / CONNECTIONS;
        // Buffers grow under bulk traffic and may stay: what the connections
        // that carried a megabyte hold afterwards, beyond the idle ones.
        let bulk_before = LIVE.load(Ordering::Relaxed);
        for s in &mut open[..BULKED] {
            bulk(s, data, got).await;
        }
        let after_bulk = LIVE.load(Ordering::Relaxed).saturating_sub(bulk_before) / BULKED;
        drop(open);
        settles("connections", idle).await;
        (per, peak, after_bulk)
    };

    let (per, peak, after_bulk) = round().await;
    eprintln!("round 1: {per} heap bytes per idle connection, {peak} at peak, {after_bulk} more after bulk");
    assert!(per < BYTES_PER_CONNECTION, "{per} bytes per idle connection");
    assert!(
        after_bulk < AFTER_BULK,
        "{after_bulk} more bytes per connection after bulk traffic"
    );
    let (tasks0, fds0, bytes0) = (tasks(), open_fds(), LIVE.load(Ordering::Relaxed));

    let (per, peak, after_bulk) = round().await;
    eprintln!("round 2: {per} heap bytes per idle connection, {peak} at peak, {after_bulk} more after bulk");
    settles("tasks, file descriptors and heap", || {
        tasks() <= tasks0 && open_fds() <= fds0 && LIVE.load(Ordering::Relaxed) <= bytes0 + ROUND_SLACK
    })
    .await;
}
