//! Wakeups and context switches of the embedded engine, per runtime flavour.
//!
//! `cargo run --release -p sbr-apple --example power -- [idle-secs] [bulk-MiB]`
//!
//! Drives sbr through the C ABI exactly as the Network Extension does, then
//! reads per-thread counters from /proc for sbr's own threads only (the test
//! client and sink run on other threads), so flavours compare like for like.
//! Linux only: Darwin has no /proc.

use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ptr;
use std::time::{Duration, Instant};

use sbr_apple::*;

#[derive(Default, Clone, Copy, Debug)]
struct Counters {
    threads: u64,
    voluntary: u64,
    involuntary: u64,
    cpu_ticks: u64,
}

impl std::ops::Sub for Counters {
    type Output = Self;
    fn sub(self, o: Self) -> Self {
        Self {
            threads: self.threads,
            voluntary: self.voluntary - o.voluntary,
            involuntary: self.involuntary - o.involuntary,
            cpu_ticks: self.cpu_ticks - o.cpu_ticks,
        }
    }
}

/// Sum over threads whose name starts with "sbr".
fn sample() -> Counters {
    let mut c = Counters::default();
    for t in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let p = t.path();
        let comm = std::fs::read_to_string(p.join("comm")).unwrap_or_default();
        if !comm.starts_with("sbr") {
            continue;
        }
        c.threads += 1;
        let status = std::fs::read_to_string(p.join("status")).unwrap_or_default();
        for l in status.lines() {
            let v = |l: &str| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0)
            };
            if l.starts_with("voluntary_ctxt_switches") {
                c.voluntary += v(l);
            } else if l.starts_with("nonvoluntary_ctxt_switches") {
                c.involuntary += v(l);
            }
        }
        // stat: fields after the ")" of comm; utime and stime are 14 and 15.
        let stat = std::fs::read_to_string(p.join("stat")).unwrap_or_default();
        let rest = &stat[stat.rfind(')').map_or(0, |i| i + 2)..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        c.cpu_ticks += f.get(11).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
            + f.get(12).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    }
    c
}

fn start(threads: i32, port: u16) -> *mut SbrInstance {
    let cfg = CString::new(format!(
        r#"{{"log":{{"level":"warn"}},"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":{port}}}],
            "outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
    ))
    .unwrap();
    let opts = SbrStartOptions {
        threads,
        relay_buffer: 16 * 1024, // the iOS default, whatever host this runs on
        ..sbr_start_options_default()
    };
    let mut err = ptr::null_mut();
    let i = unsafe { sbr_start_ex(cfg.as_ptr(), &opts, &mut err) };
    assert!(!i.is_null(), "start failed");
    i
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn sink() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::Builder::new()
        .name("sink".into())
        .spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut b = vec![0u8; 256 * 1024];
                while matches!(s.read(&mut b), Ok(1..)) {}
            }
        })
        .unwrap();
    a
}

fn socks(proxy: u16, to: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut b = [0u8; 10];
    s.read_exact(&mut b[..2]).unwrap();
    let SocketAddr::V4(v4) = to else { unreachable!() };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).unwrap();
    s.read_exact(&mut b).unwrap();
    assert_eq!(b[1], 0);
    s
}

fn main() {
    let args: Vec<u64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let idle_secs = args.first().copied().unwrap_or(10);
    let bulk_mib = args.get(1).copied().unwrap_or(1024);
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let sink = sink();

    println!(
        "flavour        | idle {idle_secs}s: thr  wakeups  invol  cpu-ms | bulk {bulk_mib} MiB: MiB/s   vol-cs  invol-cs  cpu-ms  cs/MiB"
    );
    for (name, threads) in [("current-thread", 1), ("2 workers", 2), ("4 workers", 4)] {
        let port = free_port();
        let i = start(threads, port);

        // Idle: listener bound, nothing connected.
        std::thread::sleep(Duration::from_millis(500));
        let a = sample();
        std::thread::sleep(Duration::from_secs(idle_secs));
        let idle = sample() - a;

        // Bulk: one upload through socks -> direct -> sink.
        let mut s = socks(port, sink);
        let chunk = vec![0x5au8; 64 * 1024];
        let a = sample();
        let t0 = Instant::now();
        for _ in 0..bulk_mib * 16 {
            s.write_all(&chunk).unwrap();
        }
        drop(s);
        // Let the relay drain and close.
        let mut st = SbrRuntimeStats::default();
        while {
            unsafe { sbr_runtime_stats(i, &mut st) };
            st.active_connections > 0
        } {
            std::thread::sleep(Duration::from_millis(1));
        }
        let secs = t0.elapsed().as_secs_f64();
        let bulk = sample() - a;
        unsafe { sbr_stop(i) };

        println!(
            "{name:<14} | {:>13} {:>8} {:>6} {:>7.0} | {:>15.0} {:>8} {:>9} {:>7.0} {:>7.1}",
            idle.threads,
            idle.voluntary,
            idle.involuntary,
            idle.cpu_ticks as f64 * 1000.0 / ticks_per_sec,
            bulk_mib as f64 / secs,
            bulk.voluntary,
            bulk.involuntary,
            bulk.cpu_ticks as f64 * 1000.0 / ticks_per_sec,
            (bulk.voluntary + bulk.involuntary) as f64 / bulk_mib as f64,
        );
    }
}
