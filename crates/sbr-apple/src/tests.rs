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

/// A refusal by closing: an inbound over its connection cap closes before
/// the SOCKS greeting.
const CLOSED: u8 = 0xff;

/// SOCKS5 no-auth CONNECT; returns the stream and the reply code, or
/// `CLOSED` when the proxy closed the connection instead of replying.
fn socks(proxy: SocketAddr, to: SocketAddr) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0u8; 2];
    if s.write_all(&[5, 1, 0]).is_err() || s.read_exact(&mut b).is_err() {
        return (s, CLOSED);
    }
    let SocketAddr::V4(v4) = to else { unreachable!() };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    let mut rep = [0u8; 10];
    if s.write_all(&req).is_err() || s.read_exact(&mut rep).is_err() {
        return (s, CLOSED);
    }
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
            r#"[{"tag":"proxy","type":"selector","selected":"b","now":"b","delay":null,"members":[{"tag":"a","type":"direct","delay":null,"degraded":false,"reason":null,"retry_in":null},{"tag":"b","type":"direct","delay":null,"degraded":false,"reason":null,"retry_in":null}]}]"#
        );
        let mut active = 99;
        sbr_stats(i, ptr::null_mut(), ptr::null_mut(), &mut active);
        assert_eq!(active, 0);
        sbr_network_changed(i);
        sbr_network_migrate(i);
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
fn connections_snapshot_and_close() {
    let echo = echo_server();
    let i = start(CFG, sbr_start_options_default());
    let proxy = listen_addr(i);
    let mut streams: Vec<TcpStream> = (0..3)
        .map(|_| {
            let (mut s, rep) = socks(proxy, echo);
            assert_eq!(rep, 0);
            s.write_all(b"ping").unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).unwrap();
            s
        })
        .collect();
    let snapshot =
        |limit| -> serde_json::Value { serde_json::from_str(&unsafe { take(sbr_connections(i, limit)) }).unwrap() };
    // Counts land just after the write syscall, so the client can be ahead.
    let deadline = Instant::now() + Duration::from_secs(5);
    let v = loop {
        let v = snapshot(2);
        let counted = v["connections"].as_array().unwrap().iter().all(|c| c["download"] == 4);
        if v["total"] == 3 && counted || Instant::now() > deadline {
            break v;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let conns = v["connections"].as_array().unwrap();
    assert_eq!(v["total"], 3, "{v}");
    assert_eq!(conns.len(), 2, "limit caps the list");
    let first = &conns[0];
    let id = first["id"].as_str().unwrap().to_owned();
    assert!(id.as_str() > conns[1]["id"].as_str().unwrap(), "newest first: {v}");
    assert_eq!(first["network"], "tcp");
    assert_eq!(first["inbound"], "mixed/in");
    assert_eq!(first["destination"], echo.to_string());
    assert_eq!(first["domain"], serde_json::Value::Null);
    assert_eq!(first["ip"], "127.0.0.1");
    assert_eq!(first["protocol"], serde_json::Value::Null);
    assert_eq!(first["chain"], serde_json::json!(["a", "proxy"]));
    assert_eq!(first["rule"], "final");
    assert_eq!((&first["upload"], &first["download"]), (&4.into(), &4.into()));
    let start = first["start"].as_u64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(start <= now && now - start < 60_000, "{start} vs {now}");
    assert_eq!(v["upload_total"], 12);
    assert_eq!(snapshot(0)["connections"].as_array().unwrap().len(), 3);

    // Addressed by IP: no domain to match.
    assert_eq!(unsafe { sbr_close_domain(i, c("127.0.0.1").as_ptr(), 1) }, 0);
    assert_eq!(unsafe { sbr_close_domain(i, ptr::null(), 1) }, 0);
    let id = c(&id);
    assert_eq!(unsafe { sbr_close_connection(i, id.as_ptr()) }, 1);
    // The newest stream was the one closed: its client sees EOF.
    let mut b = [0u8; 1];
    assert_eq!(streams.pop().unwrap().read(&mut b).unwrap(), 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while snapshot(0)["total"] != 2 {
        assert!(Instant::now() < deadline, "closed connection still listed");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(unsafe { sbr_close_connection(i, id.as_ptr()) }, 0);
    assert_eq!(unsafe { sbr_close_connection(i, c("not-an-id").as_ptr()) }, 0);
    unsafe { sbr_stop(i) };
    assert!(unsafe { sbr_connections(ptr::null_mut(), 0) }.is_null());
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

/// Serves `body` to every request and records each request head.
fn profile_server(body: &'static str) -> (SocketAddr, std::sync::mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
                head.push(b[0]);
            }
            let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (a, rx)
}

fn fetch_blocking(i: *mut SbrInstance, url: &str) -> Result<String, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let url = Url::parse(url).unwrap();
    assert!(unsafe { &*i }.fetch(url, move |r| tx.send(r).unwrap()));
    rx.recv_timeout(Duration::from_secs(10)).expect("fetch finished")
}

#[test]
fn profile_fetch_goes_through_routing_without_identifying_headers() {
    let (addr, heads) = profile_server("{}");
    let i = start(CFG, sbr_start_options_default());
    assert_eq!(fetch_blocking(i, &format!("http://{addr}/p?token=x")).unwrap(), "{}");
    let head = heads.recv().unwrap();
    assert!(head.starts_with("GET /p?token=x HTTP/1.1\r\n"), "{head}");
    let names: Vec<String> = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    assert_eq!(names, ["host", "connection"], "{head}");
    unsafe { sbr_stop(i) };

    // The route rules decide: a destination they reject is not fetched.
    let cfg = CFG.replace(
        r#""outbounds":[{"type":"selector""#,
        r#""route":{"rules":[{"ip_cidr":["127.0.0.0/8"],"action":"reject"}]},"outbounds":[{"type":"selector""#,
    );
    let i = start(&cfg, sbr_start_options_default());
    let e = fetch_blocking(i, &format!("http://{addr}/p")).unwrap_err();
    assert!(e.contains("rejected"), "{e}");
    unsafe { sbr_stop(i) };
}

/// What the fetch callback got: the profile, or the error.
type Outcome = (Option<String>, Option<String>);
type Sent = std::sync::mpsc::Sender<Outcome>;

unsafe extern "C" fn fetched(ctx: *mut c_void, profile: *const c_char, error: *const c_char) {
    let tx = unsafe { Box::from_raw(ctx.cast::<Sent>()) };
    let s = |p: *const c_char| (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned());
    tx.send((s(profile), s(error))).unwrap();
}

fn fetch_abi(i: *mut SbrInstance, url: &str) -> (i32, std::sync::mpsc::Receiver<Outcome>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let ctx = Box::into_raw(Box::new(tx)).cast::<c_void>();
    let started = unsafe { sbr_fetch_profile(i, c(url).as_ptr(), Some(fetched), ctx) };
    if started == 0 {
        drop(unsafe { Box::from_raw(ctx.cast::<Sent>()) });
    }
    (started, rx)
}

#[test]
fn profile_fetch_abi_calls_back_exactly_once() {
    let i = start(CFG, sbr_start_options_default());
    let (addr, _) = profile_server("{}");
    assert_eq!(fetch_abi(i, &format!("http://{addr}/")).0, 0, "https only");
    assert_eq!(fetch_abi(i, "not a url").0, 0);

    // A peer that hangs up mid-handshake: an error, through the callback.
    let closing = TcpListener::bind("127.0.0.1:0").unwrap();
    let closing_addr = closing.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in closing.incoming() {
            drop(s);
        }
    });
    let (started, rx) = fetch_abi(i, &format!("https://{closing_addr}/"));
    assert_eq!(started, 1);
    let (p, e) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(p.is_none() && e.is_some_and(|e| e.contains("profile download failed")));

    // A server that never answers: stopping the instance cancels the fetch.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let (started, rx) = fetch_abi(i, &format!("https://{}/", silent.local_addr().unwrap()));
    assert_eq!(started, 1);
    let _held = silent.accept().unwrap();
    unsafe { sbr_stop(i) };
    let (p, e) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(p.is_none() && e.is_some_and(|e| e.contains("cancelled")));
    assert!(rx.recv().is_err(), "called back once");
}

#[test]
fn apply_profile_validates_before_swapping() {
    let i = start(CFG, sbr_start_options_default());
    let apply = |text: &str| {
        let mut err = ptr::null_mut();
        let r = unsafe { sbr_apply_profile(i, c(text).as_ptr(), &mut err) };
        let e = (!err.is_null()).then(|| unsafe { take(err) });
        (r, e)
    };
    let groups = || unsafe { take(sbr_groups(i)) };

    assert_eq!(apply(CFG), (0, None), "same text: no restart");

    let (r, e) = apply(r#"{"outbounds":[{"type":"warp-drive"}]}"#);
    assert_eq!(r, -1);
    assert!(e.unwrap().contains("outbounds[0].type"));
    let (r, _) = apply("<html>captive portal</html>");
    assert_eq!(r, -1);
    assert!(groups().contains(r#""tag":"proxy""#), "old config still running");

    // A different tun asks the host for new interface settings first.
    let tun = CFG.replace(
        r#""inbounds":["#,
        r#""inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"]},"#,
    );
    assert_eq!(apply(&tun), (2, None));
    assert!(groups().contains(r#""tag":"proxy""#), "not applied yet");

    let next = CFG.replace(r#""tag":"proxy""#, r#""tag":"main""#);
    assert_eq!(apply(&next), (1, None));
    assert!(groups().contains(r#""tag":"main""#));
    assert_eq!(unsafe { &*i }.lock().config, next);
    assert_eq!(apply(&next), (0, None));
    unsafe { sbr_stop(i) };
}

#[test]
fn host_traffic_is_routed_as_the_tun_inbound() {
    let o = Options::parse(
        r#"{"inbounds":[{"type":"mixed","tag":"m"},{"type":"tun","tag":"t","address":["172.19.0.1/30"]}],
            "outbounds":[{"type":"direct","tag":"d"}]}"#,
    )
    .unwrap();
    assert_eq!(profile::host_inbound(&o), ("t".into(), "tun"));
    let o = Options::parse(CFG).unwrap();
    assert_eq!(profile::host_inbound(&o), ("in".into(), "mixed"));
}

/// Answers every connection with `response` once its request head is in.
fn raw_server(response: String) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
                head.push(b[0]);
            }
            let _ = s.write_all(response.as_bytes());
        }
    });
    a
}

#[test]
fn profile_fetch_errors_never_reveal_the_url() {
    let i = start(CFG, sbr_start_options_default());
    let not_found = raw_server("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into());
    let redirect = raw_server(
        "HTTP/1.1 302 Found\r\nLocation: http://hop-secret.invalid/next?key=s3cret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .into(),
    );
    let closing = TcpListener::bind("127.0.0.1:0").unwrap();
    let closing_port = closing.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in closing.incoming() {
            drop(s);
        }
    });
    let cases = [
        (
            format!("http://{not_found}/tok-path?key=s3cret"),
            "unexpected status: 404",
        ),
        (
            "http://host-secret.invalid/tok-path?key=s3cret".to_owned(),
            "profile download failed",
        ),
        (
            format!("http://{redirect}/tok-path?key=s3cret"),
            "profile download failed",
        ),
        (
            format!("https://localhost:{closing_port}/tok-path?key=s3cret"),
            "profile download failed",
        ),
    ];
    for (url, expect) in cases {
        let e = fetch_blocking(i, &url).unwrap_err();
        assert!(e.contains(expect), "{url}: {e}");
        let port = Url::parse(&url).unwrap().port.to_string();
        for secret in [
            "secret",
            "s3cret",
            "tok-path",
            ".invalid",
            "localhost",
            "127.0.0.1",
            "next",
            port.as_str(),
        ] {
            assert!(!e.contains(secret), "{url}: {e:?} reveals {secret:?}");
        }
    }
    unsafe { sbr_stop(i) };
}
