//! ECH against an OpenSSL (4.0 or later) `s_server`, which, unlike Go's
//! crypto/tls in sing-box, sends `retry_configs` when it rejects an offer.
//! Covers a static config, one from DNS, a stale (rotated) config recovered
//! through `retry_configs`, and the single retry per connection.
//!
//! Needs an `openssl` with ECH: `$SBR_OPENSSL_ECH`, else Homebrew's
//! `openssl@4`, else `openssl` on `PATH`. Without one the tests print a
//! note and pass.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::rr::rdata::HTTPS;
use hickory_proto::rr::rdata::svcb::{EchConfigList, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::{Name, RData, Record};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::client::EchStatus;
use sbr_dns::msg;
use sbr_engine::outbound::Upstream;
use sbr_engine::sbr_config::{DomainStrategy, Ech, TlsOutbound};
use sbr_engine::sbr_core::dial::DialOptions;
use sbr_engine::sbr_core::dns::Dns;
use sbr_engine::sbr_core::{BoxFuture, Destination, Metadata};
use sbr_engine::tls::{TlsClient, TlsConn};
use sbr_engine::transport::ServerDialer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn openssl() -> Option<PathBuf> {
    let candidates = std::env::var_os("SBR_OPENSSL_ECH")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("/opt/homebrew/opt/openssl@4/bin/openssl"),
            PathBuf::from("openssl"),
        ]);
    for bin in candidates {
        let Ok(out) = Command::new(&bin).args(["s_server", "-help"]).output() else {
            continue;
        };
        if String::from_utf8_lossy(&out.stderr).contains("-ech_key")
            || String::from_utf8_lossy(&out.stdout).contains("-ech_key")
        {
            return Some(bin);
        }
    }
    eprintln!("note: no openssl with ECH found; skipping ECH tests");
    None
}

struct Fixture {
    bin: PathBuf,
    dir: PathBuf,
    ca_pem: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    fn new(bin: PathBuf, name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sbr-ech-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["example.com".to_owned(), "inner.test".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        std::fs::write(dir.join("cert.pem"), leaf.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), leaf_key.serialize_pem()).unwrap();
        Self {
            bin,
            dir,
            ca_pem: ca.pem(),
        }
    }

    /// A fresh ECH key pair for public name `example.com`; returns the key
    /// file and its ECHConfigList.
    fn ech_key(&self, name: &str) -> (PathBuf, Vec<u8>) {
        use base64::Engine as _;
        let path = self.dir.join(format!("{name}.pem"));
        let st = Command::new(&self.bin)
            .args(["ech", "-public_name", "example.com", "-out"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(st.success());
        let text = std::fs::read_to_string(&path).unwrap();
        let b64: String = text
            .split("-----BEGIN ECHCONFIG-----")
            .nth(1)
            .and_then(|r| r.split("-----END ECHCONFIG-----").next())
            .unwrap()
            .split_whitespace()
            .collect();
        (path, base64::engine::general_purpose::STANDARD.decode(b64).unwrap())
    }

    /// `s_server -www` with `args` for its ECH keys.
    async fn server(&self, args: &[&std::ffi::OsStr]) -> Counted {
        for _ in 0..3 {
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let child = Command::new(&self.bin)
                .args(["s_server", "-www", "-tls1_3", "-quiet", "-accept"])
                .arg(format!("127.0.0.1:{port}"))
                .arg("-cert")
                .arg(self.dir.join("cert.pem"))
                .arg("-key")
                .arg(self.dir.join("key.pem"))
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut s = Server(child);
            for _ in 0..200 {
                if s.0.try_wait().ok().flatten().is_some() {
                    break;
                }
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    return s.counted(port).await;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let _ = s.0.kill();
        }
        panic!("s_server failed to start");
    }

    fn tls(&self, ech: Ech) -> TlsOutbound {
        TlsOutbound {
            enabled: true,
            server_name: Some("inner.test".into()),
            certificate: Some(self.ca_pem.clone()),
            ech: Some(Ech { enabled: true, ..ech }),
            ..Default::default()
        }
    }
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The server behind a forwarder that counts the connections made to it.
struct Counted {
    _server: Server,
    port: u16,
    addr: SocketAddr,
    conns: Arc<AtomicUsize>,
}

impl Server {
    async fn counted(self, port: u16) -> Counted {
        let (addr, conns) = forward(vec![port]).await;
        Counted {
            _server: self,
            port,
            addr,
            conns,
        }
    }
}

/// A forwarder handing connections to `ports` in turn, counting them.
async fn forward(ports: Vec<u16>) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c = conns.clone();
    tokio::spawn(async move {
        while let Ok((mut a, _)) = l.accept().await {
            let port = ports[c.fetch_add(1, Ordering::Relaxed) % ports.len()];
            tokio::spawn(async move {
                if let Ok(mut b) = TcpStream::connect(("127.0.0.1", port)).await {
                    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                }
            });
        }
    });
    (addr, conns)
}

fn pem(list: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "-----BEGIN ECH CONFIGS-----\n{}\n-----END ECH CONFIGS-----\n",
        base64::engine::general_purpose::STANDARD.encode(list)
    )
}

/// Answers HTTPS queries for `ech.test` with `list`.
struct HttpsRecord {
    list: Vec<u8>,
    queries: AtomicUsize,
}

impl Dns for HttpsRecord {
    fn lookup<'a>(&'a self, _: &'a str, _: Option<DomainStrategy>) -> BoxFuture<'a, io::Result<Vec<std::net::IpAddr>>> {
        Box::pin(async { Err(io::Error::other("no lookups expected")) })
    }
    fn exchange<'a>(&'a self, query: &'a [u8], _: &'a Metadata) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        Box::pin(async move {
            self.queries.fetch_add(1, Ordering::Relaxed);
            let q = msg::decode(query)?;
            if msg::domain_of(&q.queries[0]) != "ech.test" {
                return msg::encode(&msg::status(&q, 3));
            }
            let mut m = msg::status(&q, 0);
            let ech = (
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(self.list.clone())),
            );
            m.answers.push(Record::from_rdata(
                q.queries[0].name().clone(),
                300,
                RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), vec![ech]))),
            ));
            msg::encode(&m)
        })
    }
}

fn dialer(t: &TlsOutbound, addr: SocketAddr, dns: Arc<dyn Dns>) -> ServerDialer {
    let tls = TlsClient::new(t, "127.0.0.1", None::<&Path>, &dns).unwrap();
    ServerDialer::new(
        Upstream::System(DialOptions::default(), dns),
        Destination::from(addr),
        Some(tls),
    )
}

/// One handshake and an HTTP request; the ECH status it ended with.
async fn fetch(d: &ServerDialer) -> io::Result<EchStatus> {
    let mut conn = tokio::time::timeout(Duration::from_secs(10), d.tls())
        .await
        .map_err(|_| io::Error::other("handshake timed out"))??;
    let status = match &conn {
        TlsConn::Rustls(t) => t.get_ref().1.ech_status(),
        TlsConn::Browser(_) => panic!("ECH needs the rustls client"),
    };
    conn.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
    let mut body = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), conn.read_to_end(&mut body)).await;
    let body = String::from_utf8_lossy(&body);
    assert!(body.starts_with("HTTP/1.0 200 ok"), "{body}");
    Ok(status)
}

fn no_dns() -> Arc<dyn Dns> {
    Arc::new(HttpsRecord {
        list: Vec::new(),
        queries: AtomicUsize::new(0),
    })
}

#[tokio::test]
async fn static_config_and_rotated_key() {
    let Some(bin) = openssl() else { return };
    let f = Fixture::new(bin, "static");
    let (key, current) = f.ech_key("current");
    let (_, stale) = f.ech_key("stale");
    let s = f.server(&["-ech_key".as_ref(), key.as_os_str()]).await;

    let d = dialer(
        &f.tls(Ech {
            config: Some(pem(&current)),
            ..Default::default()
        }),
        s.addr,
        no_dns(),
    );
    assert_eq!(fetch(&d).await.unwrap(), EchStatus::Accepted);
    assert_eq!(s.conns.load(Ordering::Relaxed), 1);

    // The server rejects the stale config and sends the current one; the
    // client retries once on a fresh connection and keeps the new list.
    let d = dialer(
        &f.tls(Ech {
            config: Some(pem(&stale)),
            ..Default::default()
        }),
        s.addr,
        no_dns(),
    );
    assert_eq!(fetch(&d).await.unwrap(), EchStatus::Accepted);
    assert_eq!(s.conns.load(Ordering::Relaxed), 3);
    assert_eq!(fetch(&d).await.unwrap(), EchStatus::Accepted);
    assert_eq!(s.conns.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn config_from_dns() {
    let Some(bin) = openssl() else { return };
    let f = Fixture::new(bin, "dns");
    let (key, current) = f.ech_key("current");
    let (_, stale) = f.ech_key("stale");
    let s = f.server(&["-ech_key".as_ref(), key.as_os_str()]).await;
    let opts = f.tls(Ech {
        query_server_name: Some("ech.test".into()),
        ..Default::default()
    });

    let dns = Arc::new(HttpsRecord {
        list: current,
        queries: AtomicUsize::new(0),
    });
    let d = dialer(&opts, s.addr, dns.clone());
    assert_eq!(fetch(&d).await.unwrap(), EchStatus::Accepted);
    assert_eq!(fetch(&d).await.unwrap(), EchStatus::Accepted);
    assert_eq!(dns.queries.load(Ordering::Relaxed), 1, "cached for the record's TTL");

    let dns = Arc::new(HttpsRecord {
        list: stale,
        queries: AtomicUsize::new(0),
    });
    let before = s.conns.load(Ordering::Relaxed);
    let d = dialer(&opts, s.addr, dns.clone());
    assert_eq!(fetch(&d).await.unwrap(), EchStatus::Accepted);
    assert_eq!(
        s.conns.load(Ordering::Relaxed) - before,
        2,
        "retried with retry_configs"
    );
}

#[tokio::test]
async fn one_retry_per_connection() {
    let Some(bin) = openssl() else { return };
    let f = Fixture::new(bin, "once");
    let (key, _) = f.ech_key("current");
    let (_, stale) = f.ech_key("stale");
    let opts = f.tls(Ech {
        config: Some(pem(&stale)),
        ..Default::default()
    });

    // Two servers in turn, each with its own key: the retry meets the
    // other server, which rejects it as well, and the error surfaces.
    let (other_key, _) = f.ech_key("other");
    let s1 = f.server(&["-ech_key".as_ref(), key.as_os_str()]).await;
    let s2 = f.server(&["-ech_key".as_ref(), other_key.as_os_str()]).await;
    let (addr, conns) = forward(vec![s1.port, s2.port]).await;
    let d = dialer(&opts, addr, no_dns());
    let err = fetch(&d).await.unwrap_err();
    assert!(err.to_string().contains("ECH"), "{err}");
    assert_eq!(conns.load(Ordering::Relaxed), 2);

    // No retry_configs at all: no retry.
    let noretry = f.dir.join("noretry");
    std::fs::create_dir_all(&noretry).unwrap();
    std::fs::copy(&key, noretry.join("current.pem")).unwrap();
    let s = f.server(&["-ech_noretry_dir".as_ref(), noretry.as_os_str()]).await;
    let d = dialer(&opts, s.addr, no_dns());
    assert!(fetch(&d).await.is_err());
    assert_eq!(s.conns.load(Ordering::Relaxed), 1);
}
