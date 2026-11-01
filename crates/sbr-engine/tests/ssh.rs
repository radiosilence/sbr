//! SSH outbound against OpenSSH `sshd`, run unprivileged on a free port and
//! logging in as the current user. Skips when `sshd` or `ssh-keygen` is
//! missing (`SBR_SSHD` overrides the `sshd` path).

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{bulk_echo, echo, free_port, port, socks_connect, start};
use tokio::net::{TcpListener, TcpStream};

fn sshd_bin() -> Option<PathBuf> {
    let p = std::env::var_os("SBR_SSHD")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/usr/sbin/sshd".into());
    let keygen = Command::new("ssh-keygen")
        .arg("-?")
        .stderr(Stdio::null())
        .status()
        .is_ok();
    (p.is_file() && keygen).then_some(p)
}

macro_rules! need_sshd {
    () => {
        match sshd_bin() {
            Some(b) => b,
            None => {
                eprintln!("skipped: no sshd/ssh-keygen (set SBR_SSHD)");
                return;
            }
        }
    };
}

fn keygen(dir: &Path, name: &str, ty: &str) -> (PathBuf, String) {
    let path = dir.join(name);
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", ty, "-N", "", "-C", "", "-f"])
        .arg(&path)
        .status()
        .unwrap()
        .success();
    assert!(ok, "ssh-keygen -t {ty}");
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    (path, public.trim().to_owned())
}

struct Sshd {
    child: Child,
    port: u16,
    host_pub: String,
    user_key: PathBuf,
    _dir: tempdir::Dir,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

mod tempdir {
    pub struct Dir(pub std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

async fn sshd(bin: &Path) -> Sshd {
    let dir = std::env::temp_dir().join(format!("sbr-sshd-{}-{}", std::process::id(), fastrand::u64(..)));
    std::fs::create_dir_all(&dir).unwrap();
    let (host_key, host_pub) = keygen(&dir, "host_ed25519", "ed25519");
    let (user_key, user_pub) = keygen(&dir, "user_ed25519", "ed25519");
    let auth = dir.join("authorized_keys");
    std::fs::write(&auth, format!("{user_pub}\n")).unwrap();
    let port = free_port();
    let cfg = dir.join("sshd_config");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\n\
             AllowTcpForwarding yes\nPidFile {}\nLogLevel ERROR\n",
            host_key.display(),
            auth.display(),
            dir.join("sshd.pid").display(),
        ),
    )
    .unwrap();
    let child = Command::new(bin)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn sshd");
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Sshd {
        child,
        port,
        host_pub,
        user_key,
        _dir: tempdir::Dir(dir),
    }
}

fn user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".into())
}

async fn sbr_via(outbound: &str) -> sbr_engine::Instance {
    start(&format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[{outbound}]}}"#
    ))
    .await
}

fn ssh_outbound(d: &Sshd, key: &Path, pin: &str) -> String {
    format!(
        r#"{{"type":"ssh","tag":"ssh","server":"127.0.0.1","server_port":{},"user":"{}","private_key_path":"{}","host_key":["{pin}"]}}"#,
        d.port,
        user(),
        key.display()
    )
}

#[tokio::test]
async fn ssh_ed25519_pinned_bulk() {
    let bin = need_sshd!();
    let d = sshd(&bin).await;
    let sbr = sbr_via(&ssh_outbound(&d, &d.user_key, &d.host_pub)).await;
    let target = echo().await;
    // Several streams share the one connection.
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let s = socks_connect(port(&sbr, "in"), target).await;
        tasks.push(tokio::spawn(bulk_echo(s, 1 << 20)));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test]
async fn ssh_rsa_keys_are_refused() {
    let _ = need_sshd!();
    let dir = std::env::temp_dir().join(format!("sbr-rsa-{}-{}", std::process::id(), fastrand::u64(..)));
    std::fs::create_dir_all(&dir).unwrap();
    let _dir = tempdir::Dir(dir.clone());
    let (ed_key, ed_pub) = keygen(&dir, "ed25519", "ed25519");
    let (rsa_key, rsa_pub) = keygen(&dir, "rsa", "rsa");
    let outbound = |key: &Path, extra: &str| {
        format!(
            r#"{{"type":"ssh","tag":"ssh","server":"127.0.0.1","server_port":22,"user":"u","private_key_path":"{}"{extra}}}"#,
            key.display()
        )
    };
    for ob in [
        outbound(&rsa_key, &format!(r#","host_key":["{ed_pub}"]"#)),
        outbound(&ed_key, &format!(r#","host_key":["{rsa_pub}"]"#)),
        outbound(&ed_key, r#","host_key_algorithms":["rsa-sha2-256"]"#),
    ] {
        let json = format!(r#"{{"outbounds":[{ob}]}}"#);
        let o = sbr_engine::sbr_config::Options::parse(&json).unwrap();
        let err = match sbr_engine::Instance::start(&o, sbr_engine::Settings::default()).await {
            Ok(_) => panic!("accepted: {ob}"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("RSA keys are not supported"), "{err}");
    }
}

#[tokio::test]
async fn ssh_wrong_pin_is_refused() {
    let bin = need_sshd!();
    let d = sshd(&bin).await;
    let other = sshd(&bin).await;
    let sbr = sbr_via(&ssh_outbound(&d, &d.user_key, &other.host_pub)).await;
    let target = echo().await;
    let r = tokio::time::timeout(Duration::from_secs(10), async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port(&sbr, "in")))
            .await
            .unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut b = [0u8; 2];
        s.read_exact(&mut b).await.unwrap();
        let std::net::SocketAddr::V4(a) = target else {
            unreachable!()
        };
        let mut req = vec![5, 1, 0, 1];
        req.extend_from_slice(&a.ip().octets());
        req.extend_from_slice(&a.port().to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        let n = s.read(&mut rep).await.unwrap_or(0);
        n >= 2 && rep[1] == 0
    })
    .await
    .unwrap();
    assert!(!r, "connect must fail when the host key is not the pinned one");
}

/// A TCP relay to `upstream` that can stop forwarding every flow open so
/// far while still relaying new ones: a NAT mapping that expired.
async fn freezer(upstream: u16) -> (u16, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    let frozen_below = Arc::new(AtomicU64::new(0));
    let f = frozen_below.clone();
    tokio::spawn(async move {
        let mut n = 0u64;
        while let Ok((c, _)) = l.accept().await {
            n += 1;
            let (id, f) = (n, f.clone());
            tokio::spawn(async move {
                let u = TcpStream::connect(("127.0.0.1", upstream)).await.unwrap();
                let (cr, cw) = c.into_split();
                let (ur, uw) = u.into_split();
                let pump = |mut r: tokio::net::tcp::OwnedReadHalf, mut w: tokio::net::tcp::OwnedWriteHalf| {
                    let f = f.clone();
                    async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut b = vec![0u8; 16 * 1024];
                        loop {
                            let Ok(k) = r.read(&mut b).await else { return };
                            if k == 0 {
                                return;
                            }
                            if f.load(Ordering::SeqCst) >= id {
                                // Swallow everything from now on, keep the socket open.
                                std::future::pending::<()>().await;
                            }
                            if w.write_all(&b[..k]).await.is_err() {
                                return;
                            }
                        }
                    }
                };
                let a = tokio::spawn(pump(cr, uw));
                let b = tokio::spawn(pump(ur, cw));
                let _ = (a.await, b.await);
            });
        }
    });
    (p, frozen_below)
}

#[tokio::test]
async fn ssh_dead_connection_is_replaced() {
    let bin = need_sshd!();
    let d = sshd(&bin).await;
    let (relay, freeze) = freezer(d.port).await;
    let ob = ssh_outbound(&d, &d.user_key, &d.host_pub).replace(&format!(":{},", d.port), &format!(":{relay},"));
    let sbr = sbr_via(&ob).await;
    let target = echo().await;
    bulk_echo(socks_connect(port(&sbr, "in"), target).await, 64 * 1024).await;
    // The first connection's path goes silent; the next connect times out
    // its channel open and redials on a fresh one.
    freeze.store(1, Ordering::SeqCst);
    let t = std::time::Instant::now();
    bulk_echo(socks_connect(port(&sbr, "in"), target).await, 64 * 1024).await;
    assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
}

/// Live SSH connections to `d`: sshd forks one child per connection.
fn sessions(d: &Sshd) -> usize {
    let out = Command::new("pgrep")
        .args(["-P", &d.child.id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().count()
}

async fn wait_sessions(d: &Sshd, n: usize) -> bool {
    for _ in 0..100 {
        if sessions(d) == n {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn ssh_connection_ends_with_the_instance() {
    let bin = need_sshd!();
    let d = sshd(&bin).await;
    let target = echo().await;
    // Idle when the instance goes.
    let sbr = sbr_via(&ssh_outbound(&d, &d.user_key, &d.host_pub)).await;
    bulk_echo(socks_connect(port(&sbr, "in"), target).await, 64 * 1024).await;
    assert!(wait_sessions(&d, 1).await, "one connection while in use");
    drop(sbr);
    assert!(
        wait_sessions(&d, 0).await,
        "idle connection left open: {}",
        sessions(&d)
    );
    // A stream still open when the instance goes.
    let sbr = sbr_via(&ssh_outbound(&d, &d.user_key, &d.host_pub)).await;
    let s = socks_connect(port(&sbr, "in"), target).await;
    assert!(wait_sessions(&d, 1).await);
    drop(sbr);
    drop(s);
    assert!(
        wait_sessions(&d, 0).await,
        "busy connection left open: {}",
        sessions(&d)
    );
}
