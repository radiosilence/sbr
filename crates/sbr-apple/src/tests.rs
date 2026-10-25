use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use super::*;

const CFG: &str = r#"{"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}],
    "outbounds":[{"type":"selector","tag":"proxy","outbounds":["a","b"]},{"type":"direct","tag":"a"},{"type":"direct","tag":"b"}]}"#;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
    unsafe { sbr_string_free(p) };
    s
}

fn start(cfg: &str, o: SbrStartOptions) -> *mut SbrInstance {
    let mut err = ptr::null_mut();
    let i = unsafe { sbr_start_ex(c(cfg).as_ptr(), &o, &mut err) };
    assert!(err.is_null(), "{}", unsafe { take(err) });
    assert!(!i.is_null());
    i
}

fn listen_addr(i: *mut SbrInstance) -> SocketAddr {
    unsafe { &*i }.lock().running.as_ref().unwrap().listening[0].1
}

/// SOCKS5 no-auth CONNECT; returns the stream and the reply code.
fn socks(proxy: SocketAddr, to: SocketAddr) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).unwrap();
    let SocketAddr::V4(v4) = to else { unreachable!() };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    (s, rep[1])
}

fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut b = [0u8; 4096];
                while let Ok(n @ 1..) = s.read(&mut b) {
                    if s.write_all(&b[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    a
}

#[test]
fn lifecycle_over_the_c_abi() {
    unsafe {
        assert!(sbr_check(c(CFG).as_ptr()).is_null());
        let e = take(sbr_check(c(r#"{"outbounds":[{"type":"warp-drive"}]}"#).as_ptr()));
        assert!(e.contains("outbounds[0].type"), "{e}");
        assert!(take(sbr_check(ptr::null())).contains("NULL"));
        assert!(!CStr::from_ptr(sbr_version()).to_bytes().is_empty());

        let mut err = ptr::null_mut();
        let i = sbr_start(c(CFG).as_ptr(), ptr::null(), &mut err);
        assert!(!i.is_null() && err.is_null());
        assert_eq!(sbr_select(i, c("proxy").as_ptr(), c("b").as_ptr()), 1);
        assert_eq!(sbr_select(i, c("proxy").as_ptr(), c("zzz").as_ptr()), 0);
        assert_eq!(sbr_select(i, ptr::null(), c("b").as_ptr()), 0);
        assert_eq!(
            take(sbr_groups(i)),
            r#"[{"tag":"proxy","type":"selector","selected":"b","now":"b","delay":null,"members":[{"tag":"a","type":"direct","delay":null},{"tag":"b","type":"direct","delay":null}]}]"#
        );
        let mut active = 99;
        sbr_stats(i, ptr::null_mut(), ptr::null_mut(), &mut active);
        assert_eq!(active, 0);
        sbr_network_changed(i);
        sbr_stop(i);

        // NULL instances are no-ops, not crashes.
        sbr_stop(ptr::null_mut());
        sbr_network_changed(ptr::null_mut());
        assert!(sbr_groups(ptr::null_mut()).is_null());
        let mut st = SbrRuntimeStats::default();
        sbr_runtime_stats(ptr::null_mut(), &mut st);
        assert_eq!(st.active_connections, 0);
        #[cfg(target_os = "linux")]
        assert!(st.memory_footprint > 1 << 20);
        assert_eq!(sbr_find_tun_fd(), -1);
    }
}

#[test]
fn start_errors_are_reported() {
    let mut err = ptr::null_mut();
    let i = unsafe { sbr_start_ex(c("{nope").as_ptr(), ptr::null(), &mut err) };
    assert!(i.is_null());
    assert!(!unsafe { take(err) }.is_empty());
    // Listener conflicts surface from the runtime thread.
    let busy = TcpListener::bind("127.0.0.1:0").unwrap();
    let cfg = CFG.replace(
        r#""listen_port":0"#,
        &format!(r#""listen_port":{}"#, busy.local_addr().unwrap().port()),
    );
    let i = unsafe { sbr_start_ex(c(&cfg).as_ptr(), ptr::null(), &mut err) };
    assert!(i.is_null());
    assert!(unsafe { take(err) }.contains("listen"));
}

#[test]
fn both_runtime_flavours_relay_and_count_live() {
    let echo = echo_server();
    for threads in [1, 2] {
        let i = start(
            CFG,
            SbrStartOptions {
                threads,
                ..sbr_start_options_default()
            },
        );
        let (mut s, rep) = socks(listen_addr(i), echo);
        assert_eq!(rep, 0);
        s.write_all(&[7u8; 1000]).unwrap();
        let mut back = [0u8; 1000];
        s.read_exact(&mut back).unwrap();
        // Live: counted while the connection is still open. The count lands
        // just after the write syscall, so the client can see bytes first.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut st = SbrRuntimeStats::default();
        while {
            unsafe { sbr_runtime_stats(i, &mut st) };
            st.downlink_bytes < 1000 && Instant::now() < deadline
        } {
            std::thread::yield_now();
        }
        assert_eq!(
            (st.uplink_bytes, st.downlink_bytes, st.active_connections),
            (1000, 1000, 1)
        );
        drop(s);
        unsafe { sbr_stop(i) };
    }
}

#[test]
fn connection_limit() {
    let echo = echo_server();
    let i = start(
        CFG,
        SbrStartOptions {
            max_connections: 1,
            ..sbr_start_options_default()
        },
    );
    let proxy = listen_addr(i);
    let (held, rep) = socks(proxy, echo);
    assert_eq!(rep, 0);
    let (_, rep) = socks(proxy, echo);
    assert_ne!(rep, 0, "second connection must be refused");
    drop(held);
    // The slot frees once the relay notices the close.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (_s, rep) = socks(proxy, echo);
        if rep == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "slot never released");
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe { sbr_stop(i) };
}

#[test]
fn reload_keeps_running_on_bad_config_and_swaps_on_good() {
    // A pipe stands in for the utun fd: reload must hand each run its own dup.
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let i = start(
        CFG,
        SbrStartOptions {
            tun_fd: fds[0],
            ..sbr_start_options_default()
        },
    );
    assert_eq!(unsafe { &*i }.lock().launch.tun_fd, Some(fds[0]));
    unsafe {
        let e = take(sbr_reload(i, c(r#"{"outbounds":[{"type":"warp-drive"}]}"#).as_ptr()));
        assert!(e.contains("outbounds[0].type"), "{e}");
        assert!(
            take(sbr_groups(i)).contains(r#""tag":"proxy""#),
            "old config still running"
        );

        let next = CFG.replace(r#""tag":"proxy""#, r#""tag":"main""#);
        assert!(sbr_reload(i, c(&next).as_ptr()).is_null());
        assert!(take(sbr_groups(i)).contains(r#""tag":"main""#));
        // The host's fd is untouched.
        assert!(libc::fcntl(fds[0], libc::F_GETFD) >= 0);
        sbr_stop(i);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

static LOGS: StdMutex<Vec<(i32, String)>> = StdMutex::new(Vec::new());

unsafe extern "C" fn collect(level: i32, msg: *const c_char, ctx: *mut c_void) {
    assert_eq!(ctx as usize, 0x5b);
    let m = unsafe { CStr::from_ptr(msg) }.to_string_lossy().into_owned();
    LOGS.lock().unwrap().push((level, m));
}

#[test]
fn log_callback_receives_engine_logs() {
    unsafe { sbr_set_log_callback(Some(collect), 0x5b as *mut c_void) };
    let i = start(CFG, sbr_start_options_default());
    unsafe { sbr_stop(i) };
    unsafe { sbr_set_log_callback(None, ptr::null_mut()) };
    let logs = LOGS.lock().unwrap();
    assert!(
        logs.iter()
            .any(|(l, m)| *l == log::INFO && m.starts_with("listening") && m.contains("inbound=in")),
        "{logs:?}"
    );
}

#[test]
fn panics_do_not_escape() {
    assert_eq!(guard(7, || panic!("boom")), 7);
}
