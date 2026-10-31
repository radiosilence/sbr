//! What connections leave behind once closed, and what they cost while
//! open: tasks, file descriptors and heap bytes. A leaked relay or reader
//! task, or a socket nobody closes, passes every functional test; on iOS it
//! is memory and descriptors the extension never gets back.
//!
//! Its own binary, so the counting allocator sees only this test.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator, counting bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Ordering::Relaxed);
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_add(new, Ordering::Relaxed);
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
/// Heap per idle proxied connection after it carried data: two instances'
/// relays (2 × 16 KiB each), the SOCKS outbound and inbound state and the
/// connection records, with headroom.
const BYTES_PER_CONNECTION: usize = 96 * 1024;

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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not return to baseline"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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

    let round_trip = |mut s: tokio::net::TcpStream| async move {
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        s
    };
    // Warm up lazily started pieces (DNS, pools) before the baseline.
    drop(round_trip(common::socks_connect(proxy, echo).await).await);
    let idle = || client.engine.active_connections() == 0 && server.engine.active_connections() == 0;
    settles("warm-up connection", idle).await;
    let (tasks0, fds0, bytes0) = (tasks(), open_fds(), LIVE.load(Ordering::Relaxed));

    let mut open = Vec::with_capacity(CONNECTIONS);
    for _ in 0..CONNECTIONS {
        open.push(round_trip(common::socks_connect(proxy, echo).await).await);
    }
    let per = LIVE.load(Ordering::Relaxed).saturating_sub(bytes0) / CONNECTIONS;
    eprintln!("{per} heap bytes per idle proxied connection");
    assert!(per < BYTES_PER_CONNECTION, "{per} bytes per idle connection");

    // A bulk transfer on some, then close everything.
    for s in open.drain(..20) {
        common::bulk_echo(s, 1 << 20).await;
    }
    drop(open);
    settles("connections", idle).await;
    settles("tasks", || tasks() <= tasks0).await;
    settles("file descriptors", || open_fds() <= fds0).await;
    let after = LIVE.load(Ordering::Relaxed).saturating_sub(bytes0);
    assert!(after < 1 << 20, "{after} heap bytes still held after closing");
}
