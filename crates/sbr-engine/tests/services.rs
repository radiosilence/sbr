//! End-to-end tests for remote rule-sets, the Clash API, urltest and the
//! cache file. Everything runs against local servers.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sbr_engine::sbr_config::Options;
use sbr_engine::sbr_core::router::Action;
use sbr_engine::sbr_core::{Destination, Metadata, Network};
use sbr_engine::{Instance, Settings};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sbr-svc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn start(json: &str, settings: Settings) -> Instance {
    Instance::start(&Options::parse(json).unwrap(), settings).await.unwrap()
}

fn port(i: &Instance, tag: &str) -> u16 {
    i.listening.iter().find(|(t, _)| t == tag).unwrap().1.port()
}

async fn echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn socks_connect(proxy: u16, host: &str, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "socks connect failed");
    s
}

fn route(i: &Instance, host: &str) -> String {
    let m = Metadata::new(
        "in".into(),
        "mixed",
        Network::Tcp,
        "127.0.0.1:1".parse().unwrap(),
        Destination::from_host_port(host, 443),
    );
    match i.engine.router().route(&m) {
        Action::Route { outbound, .. } => i.engine.outbounds()[outbound].tag().to_owned(),
        a => format!("{a:?}"),
    }
}

/// Minimal HTTP/1.1 client: (status, headers, body).
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head.to_owned(), body.to_owned())
}

async fn api_json(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (st, _, b) = http(addr, method, path, &[("Authorization", "Bearer s3cret")], body).await;
    (st, serde_json::from_str(&b).unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// Remote rule-sets over HTTPS

struct RuleSetServer {
    addr: SocketAddr,
    body: Arc<Mutex<(Vec<u8>, String)>>,
    hits: Arc<AtomicUsize>,
    not_modified: Arc<AtomicUsize>,
    roots: Arc<rustls::RootCertStore>,
    task: tokio::task::JoinHandle<()>,
}

async fn rule_set_server(content: Vec<u8>) -> RuleSetServer {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let body = Arc::new(Mutex::new((content, "\"v1\"".to_string())));
    let hits = Arc::new(AtomicUsize::new(0));
    let not_modified = Arc::new(AtomicUsize::new(0));
    let (b, h, nm) = (body.clone(), hits.clone(), not_modified.clone());
    let task = tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let (acceptor, b, h, nm) = (acceptor.clone(), b.clone(), h.clone(), nm.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(s).await else { return };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..n]);
                }
                h.fetch_add(1, Ordering::SeqCst);
                let head = String::from_utf8_lossy(&head).to_lowercase();
                let (content, etag) = b.lock().unwrap().clone();
                let resp = if head.contains(&format!("if-none-match: {}", etag.to_lowercase())) {
                    nm.fetch_add(1, Ordering::SeqCst);
                    b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_vec()
                } else {
                    let mut r = format!(
                        "HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        content.len()
                    )
                    .into_bytes();
                    r.extend_from_slice(&content);
                    r
                };
                let _ = s.write_all(&resp).await;
                let _ = s.shutdown().await;
            });
        }
    });
    RuleSetServer {
        addr,
        body,
        hits,
        not_modified,
        roots: Arc::new(roots),
        task,
    }
}

fn srs(json: &str) -> Vec<u8> {
    sbr_engine::sbr_config::srs::PlainRuleSet::from_json(json)
        .unwrap()
        .write()
        .unwrap()
}

fn remote_config(port: u16, interval: &str) -> String {
    format!(
        r#"{{"log":{{"level":"error"}},
        "outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"block","tag":"blocked"}}],
        "route":{{
            "rule_set":[{{"type":"remote","tag":"ads","url":"https://localhost:{port}/ads.srs",
                          "download_detour":"direct","update_interval":"{interval}"}}],
            "rules":[{{"rule_set":"ads","outbound":"blocked"}}],
            "final":"direct"}}}}"#
    )
}

#[tokio::test]
async fn remote_rule_set_download_hot_reload_and_offline_cache() {
    let dir = temp_dir("remote");
    let server = rule_set_server(srs(r#"{"version":2,"rules":[{"domain_suffix":"ads.test"}]}"#)).await;
    let settings = || Settings {
        base_dir: Some(dir.clone()),
        http_roots: Some(server.roots.clone()),
        ..Settings::default()
    };
    let i = start(&remote_config(server.addr.port(), "300ms"), settings()).await;
    assert_eq!(route(&i, "x.ads.test"), "blocked", "downloaded at start");
    assert_eq!(route(&i, "tracker.test"), "direct");

    // Unchanged content: the refresh is a conditional GET answered with 304.
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(server.not_modified.load(Ordering::SeqCst) >= 1, "If-None-Match sent");

    // New content is swapped in without restarting.
    *server.body.lock().unwrap() = (
        srs(r#"{"version":2,"rules":[{"domain_suffix":"tracker.test"}]}"#),
        "\"v2\"".into(),
    );
    let mut ok = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if route(&i, "a.tracker.test") == "blocked" {
            ok = true;
            break;
        }
    }
    assert!(ok, "hot reload");
    assert_eq!(route(&i, "x.ads.test"), "direct");
    i.shutdown();

    // Offline: the server is gone, the cached copy is used.
    server.task.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let hits = server.hits.load(Ordering::SeqCst);
    let i = start(&remote_config(server.addr.port(), "1h"), settings()).await;
    assert_eq!(route(&i, "a.tracker.test"), "blocked", "cached copy");
    assert_eq!(server.hits.load(Ordering::SeqCst), hits);
    i.shutdown();

    // No cache and no server: startup fails, like sing-box.
    let empty = temp_dir("remote-empty");
    let e = Instance::start(
        &Options::parse(&remote_config(server.addr.port(), "1h")).unwrap(),
        Settings {
            base_dir: Some(empty),
            http_roots: Some(server.roots.clone()),
            ..Settings::default()
        },
    )
    .await
    .err()
    .expect("initial download must fail");
    assert!(e.to_string().contains("initial rule-set ads"), "{e}");
}

#[tokio::test]
async fn remote_rule_set_refuses_untrusted_certificate() {
    let dir = temp_dir("untrusted");
    let server = rule_set_server(srs(r#"{"version":2,"rules":[{"domain":"a.test"}]}"#)).await;
    // Default roots (webpki): the self-signed certificate must be rejected.
    let r = Instance::start(
        &Options::parse(&remote_config(server.addr.port(), "1h")).unwrap(),
        Settings {
            base_dir: Some(dir),
            ..Settings::default()
        },
    )
    .await;
    assert!(r.is_err());
}

// ---------------------------------------------------------------------------
// Clash API

fn api_config(echo_port: u16, extra_outbounds: &str, ui: &str) -> String {
    format!(
        r#"{{"log":{{"level":"info"}},
        "inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[
            {{"type":"selector","tag":"proxy","outbounds":["direct","direct2"],"interrupt_exist_connections":true}},
            {{"type":"direct","tag":"direct"}},{{"type":"direct","tag":"direct2"}},
            {{"type":"block","tag":"blocked"}}{extra_outbounds}],
        "route":{{"rules":[
            {{"clash_mode":"Global","outbound":"blocked"}},
            {{"port":{echo_port},"outbound":"proxy"}}
        ],"final":"direct"}},
        "experimental":{{"clash_api":{{"external_controller":"127.0.0.1:0","secret":"s3cret",
            "access_control_allow_origin":["http://dash.local"],
            "access_control_allow_private_network":true{ui}}}}}}}"#
    )
}

#[tokio::test]
async fn clash_api_without_secret_refuses_cross_origin() {
    let i = start(
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],
            "experimental":{"clash_api":{"external_controller":"127.0.0.1:0"}}}"#,
        Settings::default(),
    )
    .await;
    let api = i.clash_api.unwrap();
    let (st, _, _) = http(api, "GET", "/version", &[], "").await;
    assert_eq!(st, 200);
    let own = format!("http://{api}");
    let (st, _, _) = http(api, "GET", "/version", &[("Origin", &own)], "").await;
    assert_eq!(st, 200);
    let (st, _, _) = http(api, "GET", "/connections", &[("Origin", "https://evil.example")], "").await;
    assert_eq!(st, 403);
}

#[tokio::test]
async fn clash_api_endpoints() {
    let target = echo().await;
    let i = start(&api_config(target.port(), "", ""), Settings::default()).await;
    let api = i.clash_api.unwrap();

    // Auth.
    let (st, _, _) = http(api, "GET", "/version", &[], "").await;
    assert_eq!(st, 401);
    let (st, _, _) = http(api, "GET", "/version", &[("Authorization", "Bearer nope")], "").await;
    assert_eq!(st, 401);
    let (st, v) = api_json(api, "GET", "/version", "").await;
    assert_eq!(st, 200);
    assert_eq!(v["meta"], true);
    assert!(v["version"].as_str().unwrap().starts_with("sing-box"));
    let (st, v) = api_json(api, "GET", "/", "").await;
    assert_eq!((st, v), (200, json!({"hello": "clash"})));

    // CORS preflight, including Private Network Access.
    let (st, head, _) = http(
        api,
        "OPTIONS",
        "/proxies",
        &[
            ("Origin", "http://dash.local"),
            ("Access-Control-Request-Method", "PUT"),
            ("Access-Control-Request-Private-Network", "true"),
        ],
        "",
    )
    .await;
    assert_eq!(st, 204);
    let head = head.to_lowercase();
    assert!(
        head.contains("access-control-allow-origin: http://dash.local"),
        "{head}"
    );
    assert!(head.contains("access-control-allow-private-network: true"), "{head}");
    let (_, head, _) = http(
        api,
        "OPTIONS",
        "/proxies",
        &[
            ("Origin", "http://evil.local"),
            ("Access-Control-Request-Method", "PUT"),
        ],
        "",
    )
    .await;
    assert!(!head.to_lowercase().contains("access-control-allow-origin"));

    // Proxies and selection.
    let (_, v) = api_json(api, "GET", "/proxies", "").await;
    assert_eq!(v["proxies"]["proxy"]["type"], "Selector");
    assert_eq!(v["proxies"]["proxy"]["now"], "direct");
    assert_eq!(v["proxies"]["proxy"]["all"], json!(["direct", "direct2"]));
    assert_eq!(v["proxies"]["blocked"]["type"], "Reject");
    assert_eq!(v["proxies"]["GLOBAL"]["now"], "direct");
    let (st, _) = api_json(api, "PUT", "/proxies/proxy", r#"{"name":"nope"}"#).await;
    assert_eq!(st, 400);
    let (st, _) = api_json(api, "PUT", "/proxies/direct", r#"{"name":"direct"}"#).await;
    assert_eq!(st, 400, "not a selector");
    let (st, _) = api_json(api, "GET", "/proxies/missing", "").await;
    assert_eq!(st, 404);

    // A live connection shows up with its chain and rule, counts bytes,
    // and is closed by a selector switch (interrupt_exist_connections).
    let p = port(&i, "in");
    let mut c = socks_connect(p, "127.0.0.1", target.port()).await;
    c.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    c.read_exact(&mut buf).await.unwrap();
    let (_, v) = api_json(api, "GET", "/connections", "").await;
    let conns = v["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1);
    let conn = &conns[0];
    assert_eq!(conn["chains"], json!(["direct", "proxy"]));
    assert_eq!(conn["rule"], format!("port={} => route(proxy)", target.port()));
    assert_eq!(conn["metadata"]["type"], "mixed/in");
    assert_eq!(conn["metadata"]["destinationPort"], target.port().to_string());
    assert_eq!(conn["upload"], 5);
    assert_eq!(conn["download"], 5);
    assert!(v["uploadTotal"].as_u64().unwrap() >= 5);

    let (st, _) = api_json(api, "PUT", "/proxies/proxy", r#"{"name":"direct2"}"#).await;
    assert_eq!(st, 204);
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0, "interrupted by the selector switch");
    let (_, v) = api_json(api, "GET", "/proxies/proxy", "").await;
    assert_eq!(v["now"], "direct2");

    // DELETE /connections/{id} aborts a relay.
    let mut c = socks_connect(p, "127.0.0.1", target.port()).await;
    c.write_all(b"x").await.unwrap();
    c.read_exact(&mut buf[..1]).await.unwrap();
    let (_, v) = api_json(api, "GET", "/connections", "").await;
    let id = v["connections"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(v["connections"][0]["chains"], json!(["direct2", "proxy"]));
    let (st, _) = api_json(api, "DELETE", &format!("/connections/{id}"), "").await;
    assert_eq!(st, 204);
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (_, v) = api_json(api, "GET", "/connections", "").await;
    assert_eq!(v["connections"], json!([]));

    // Mode switch drives the clash_mode matcher.
    let (_, v) = api_json(api, "GET", "/configs", "").await;
    assert_eq!(v["mode"], "Rule");
    assert_eq!(v["mode-list"], json!(["Rule", "Global"]));
    let (st, _) = api_json(api, "PATCH", "/configs", r#"{"mode":"global"}"#).await;
    assert_eq!(st, 204);
    let (_, v) = api_json(api, "GET", "/configs", "").await;
    assert_eq!(v["mode"], "Global");
    assert_eq!(route(&i, "anything.test"), "blocked");
    api_json(api, "PATCH", "/configs", r#"{"mode":"Rule"}"#).await;
    assert_eq!(route(&i, "anything.test"), "direct");

    // Rules and groups.
    let (_, v) = api_json(api, "GET", "/rules", "").await;
    assert_eq!(
        v["rules"][0],
        json!({"type":"default","payload":"clash_mode=Global","proxy":"route(blocked)"})
    );
    let (_, v) = api_json(api, "GET", "/group", "").await;
    assert_eq!(v["proxies"].as_array().unwrap().len(), 1);
    let (st, _) = api_json(api, "GET", "/group/direct", "").await;
    assert_eq!(st, 404);
    let (st, _) = api_json(api, "GET", "/proxies/proxy/delay", "").await;
    assert_eq!(st, 400, "timeout is required");

    // DNS query (system resolver).
    let (st, v) = api_json(api, "GET", "/dns/query?name=localhost&type=A", "").await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["Question"][0]["Name"], "localhost.");

    // WebSockets: token auth in the query string, traffic and connections feeds.
    let url = format!("ws://{api}/traffic?token=s3cret");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let v: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert!(v["up"].is_u64() && v["down"].is_u64(), "{v}");
    ws.close(None).await.unwrap();
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{api}/traffic?token=bad"))
            .await
            .is_err()
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{api}/connections?token=s3cret&interval=100"))
        .await
        .unwrap();
    let msg = ws.next().await.unwrap().unwrap();
    let v: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert!(v["connections"].is_array());
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{api}/memory?token=s3cret"))
        .await
        .unwrap();
    let first: Value = serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
    assert_eq!(first["inuse"], 0, "first sample is zero, like sing-box");
    let second: Value = serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
    assert!(second["inuse"].as_u64().unwrap() > 0);
    ws.send(tokio_tungstenite::tungstenite::Message::Close(None))
        .await
        .unwrap();

    // DELETE /connections closes everything.
    let mut c = socks_connect(p, "127.0.0.1", target.port()).await;
    let (st, _) = api_json(api, "DELETE", "/connections", "").await;
    assert_eq!(st, 204);
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
    i.shutdown();
}

#[tokio::test]
async fn clash_api_serves_local_ui_only() {
    let target = echo().await;
    let dir = temp_dir("ui");
    std::fs::create_dir_all(dir.join("ui/assets")).unwrap();
    std::fs::write(dir.join("ui/index.html"), "<h1>dash</h1>").unwrap();
    std::fs::write(dir.join("ui/assets/app.js"), "go()").unwrap();
    let i = start(
        &api_config(target.port(), "", r#","external_ui":"ui""#),
        Settings {
            base_dir: Some(dir.clone()),
            ..Settings::default()
        },
    )
    .await;
    let api = i.clash_api.unwrap();
    // The UI is outside the secret, like sing-box.
    let (st, head, body) = http(api, "GET", "/ui/", &[], "").await;
    assert_eq!((st, body.as_str()), (200, "<h1>dash</h1>"));
    assert!(head.to_lowercase().contains("content-type: text/html"));
    let (st, head, _) = http(api, "GET", "/ui/assets/app.js", &[], "").await;
    assert_eq!(st, 200);
    assert!(head.to_lowercase().contains("text/javascript"));
    let (st, _, _) = http(api, "GET", "/ui/../secret", &[], "").await;
    assert_ne!(st, 200);
    let (st, head, _) = http(api, "GET", "/", &[("Authorization", "Bearer s3cret")], "").await;
    assert_eq!(st, 307);
    assert!(head.to_lowercase().contains("location: /ui/"));
    // No download URL configured: upgrading has nothing to fetch, and no
    // third party was contacted.
    let (st, _) = api_json(api, "POST", "/upgrade/ui", "").await;
    assert_eq!(st, 500);
    assert_eq!(
        std::fs::read_to_string(dir.join("ui/index.html")).unwrap(),
        "<h1>dash</h1>"
    );
    i.shutdown();
}

// ---------------------------------------------------------------------------
// urltest

/// An HTTP CONNECT proxy that waits `delay` before answering.
async fn slow_proxy(delay: Duration, hits: Arc<AtomicUsize>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let hits = hits.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                hits.fetch_add(1, Ordering::SeqCst);
                let line = String::from_utf8_lossy(&head);
                let target = line.split(' ').nth(1).unwrap().to_owned();
                tokio::time::sleep(delay).await;
                let Ok(mut up) = TcpStream::connect(target).await else {
                    return;
                };
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    port
}

/// Answers every request with 204, like generate_204.
async fn no_content_server(hits: Arc<AtomicUsize>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let hits = hits.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 256];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut b).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&b[..n]);
                }
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = s
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    port
}

#[tokio::test]
async fn urltest_picks_fastest_and_sleeps_when_idle() {
    let probe_hits = Arc::new(AtomicUsize::new(0));
    let web = no_content_server(probe_hits.clone()).await;
    let (h1, h2, h3) = Default::default();
    let slow = slow_proxy(Duration::from_millis(300), h1).await;
    let fast = slow_proxy(Duration::from_millis(10), h2).await;
    let mid = slow_proxy(Duration::from_millis(150), h3).await;
    let target = echo().await;
    let cfg = format!(
        r#"{{"log":{{"level":"error"}},
        "inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[
            {{"type":"urltest","tag":"auto","outbounds":["slow","inner"],"url":"http://127.0.0.1:{web}/generate_204",
              "interval":"300ms","idle_timeout":"900ms","tolerance":20}},
            {{"type":"urltest","tag":"inner","outbounds":["mid","fast"],"url":"http://127.0.0.1:{web}/generate_204",
              "interval":"300ms","idle_timeout":"900ms"}},
            {{"type":"http","tag":"slow","server":"127.0.0.1","server_port":{slow}}},
            {{"type":"http","tag":"fast","server":"127.0.0.1","server_port":{fast}}},
            {{"type":"http","tag":"mid","server":"127.0.0.1","server_port":{mid}}}],
        "experimental":{{"clash_api":{{"external_controller":"127.0.0.1:0"}}}}}}"#
    );
    let i = start(&cfg, Settings::default()).await;
    let api = i.clash_api.unwrap();
    let g = i.engine.groups().urltest("auto").unwrap().clone();
    // The initial check runs in the background at start.
    let mut picked = String::new();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (_, v) = api_json(api, "GET", "/proxies/auto", "").await;
        picked = v["now"].as_str().unwrap_or("").to_owned();
        // Members are probed one at a time and the first to answer is
        // adopted, so the inner group settles on the fastest afterwards.
        let (_, inner) = api_json(api, "GET", "/proxies/inner", "").await;
        if picked == "inner" && inner["now"] == "fast" && i.engine.groups().history("fast").is_some() {
            break;
        }
    }
    assert_eq!(picked, "inner", "nested group with the fastest leaf wins");
    let (_, v) = api_json(api, "GET", "/proxies/inner", "").await;
    assert_eq!(v["now"], "fast");
    assert!(v["history"][0]["delay"].as_u64().unwrap() < 150, "{v}");
    let (_, v) = api_json(api, "GET", "/proxies/auto", "").await;
    assert_eq!(
        v["history"][0]["delay"], v["history"][0]["delay"],
        "group history is its leaf's"
    );

    // Traffic goes through the fastest leaf.
    let p = port(&i, "in");
    let mut c = socks_connect(p, "127.0.0.1", target.port()).await;
    c.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    c.read_exact(&mut b).await.unwrap();
    let (_, v) = api_json(api, "GET", "/connections", "").await;
    assert_eq!(v["connections"][0]["chains"], json!(["fast", "inner", "auto"]));
    drop(c);

    // Using the group starts the probe loop; once idle it stops (no wakeups).
    assert!(g.probing(), "touched by the connection");
    tokio::time::sleep(Duration::from_millis(800)).await;
    let during = probe_hits.load(Ordering::SeqCst);
    let mut stopped = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !g.probing() {
            stopped = true;
            break;
        }
    }
    assert!(stopped, "probing pauses after idle_timeout");
    // A probe already in flight when the loop stopped may still land.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = probe_hits.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(probe_hits.load(Ordering::SeqCst), after, "no probes while idle");
    assert!(during > 0);

    // On-demand group test through the API, with the configured URL.
    let url = format!("http://127.0.0.1:{web}/generate_204");
    let (st, v) = api_json(api, "GET", &format!("/group/auto/delay?timeout=5000&url={url}"), "").await;
    assert_eq!(st, 200);
    assert!(
        v["fast"].as_u64().is_some() && v["slow"].as_u64().unwrap() >= 300,
        "{v}"
    );
    assert!(v["inner"].is_u64());

    // A dashboard-supplied URL the config doesn't name is never fetched.
    let before = probe_hits.load(Ordering::SeqCst);
    let (st, v) = api_json(
        api,
        "GET",
        "/proxies/fast/delay?timeout=5000&url=http://127.0.0.1:1/elsewhere",
        "",
    )
    .await;
    assert_eq!(st, 200, "measured by handshake instead: {v}");
    assert!(v["delay"].as_u64().unwrap() >= 1);
    assert_eq!(probe_hits.load(Ordering::SeqCst), before);
    i.shutdown();
}

#[tokio::test]
async fn urltest_without_url_measures_server_handshake() {
    let target = echo().await;
    let (h1, h2) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let up = slow_proxy(Duration::ZERO, h1.clone()).await;
    let down = {
        // A port nothing listens on.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let _ = h2;
    let cfg = format!(
        r#"{{"log":{{"level":"error"}},
        "inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[
            {{"type":"urltest","tag":"auto","outbounds":["down","up"]}},
            {{"type":"http","tag":"down","server":"127.0.0.1","server_port":{down}}},
            {{"type":"http","tag":"up","server":"127.0.0.1","server_port":{up}}}]}}"#
    );
    let i = start(&cfg, Settings::default()).await;
    let g = i.engine.groups().urltest("auto").unwrap().clone();
    let r = g.url_test(true).await;
    assert!(r.contains_key("up") && !r.contains_key("down"), "{r:?}");
    assert_eq!(sbr_engine::outbound::group::real_tag(g.as_ref()), "up");
    // The handshake probe never sent a request through the proxy.
    assert_eq!(h1.load(Ordering::SeqCst), 0);
    let p = port(&i, "in");
    let mut c = socks_connect(p, "127.0.0.1", target.port()).await;
    c.write_all(b"ok").await.unwrap();
    let mut b = [0u8; 2];
    c.read_exact(&mut b).await.unwrap();
    assert_eq!(h1.load(Ordering::SeqCst), 1);
    i.shutdown();
}

// ---------------------------------------------------------------------------
// Cache file

#[tokio::test]
async fn cache_file_persists_selection_and_mode() {
    let dir = temp_dir("cache");
    let cfg = r#"{"log":{"level":"error"},
        "outbounds":[{"type":"selector","tag":"proxy","outbounds":["a","b"],"default":"a"},
                     {"type":"direct","tag":"a"},{"type":"direct","tag":"b"}],
        "route":{"rules":[{"clash_mode":"Direct","outbound":"b"}]},
        "experimental":{"cache_file":{"enabled":true,"path":"state/cache.db","cache_id":"phone"},
                        "clash_api":{"external_controller":"127.0.0.1:0"}}}"#;
    let settings = || Settings {
        base_dir: Some(dir.clone()),
        ..Settings::default()
    };
    {
        let i = start(cfg, settings()).await;
        let api = i.clash_api.unwrap();
        let (st, _) = api_json(api, "PUT", "/proxies/proxy", r#"{"name":"b"}"#).await;
        assert_eq!(st, 204);
        api_json(api, "PATCH", "/configs", r#"{"mode":"Direct"}"#).await;
        assert!(dir.join("state/cache.db").exists());
        i.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let i = start(cfg, settings()).await;
    let g = i.engine.outbound("proxy").unwrap().clone();
    assert_eq!(g.as_group().unwrap().selected().tag(), "b", "selection restored");
    assert_eq!(i.engine.router().clash_mode().current(), "Direct", "mode restored");
    i.shutdown();
}

/// A zip with stored (uncompressed) entries.
fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for (name, data) in files {
        let offset = out.len() as u32;
        let sizes = [(data.len() as u32).to_le_bytes(), (data.len() as u32).to_le_bytes()].concat();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&sizes);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&sizes);
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let at = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&at.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

#[tokio::test]
async fn external_ui_downloads_only_from_the_configured_url() {
    let zip = stored_zip(&[("dash-main/index.html", b"<p>v1</p>"), ("dash-main/a.js", b"1")]);
    let hits = Arc::new(AtomicUsize::new(0));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web = l.local_addr().unwrap();
    {
        let hits = hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let (zip, hits) = (zip.clone(), hits.clone());
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut b = [0u8; 512];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        let n = s.read(&mut b).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        head.extend_from_slice(&b[..n]);
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    // GitHub-style redirect first.
                    let resp = if head.starts_with(b"GET /latest ") {
                        b"HTTP/1.1 302 Found\r\nLocation: /dash.zip\r\nContent-Length: 0\r\n\r\n".to_vec()
                    } else {
                        let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", zip.len()).into_bytes();
                        r.extend_from_slice(&zip);
                        r
                    };
                    let _ = s.write_all(&resp).await;
                });
            }
        });
    }
    let target = echo().await;
    let dir = temp_dir("ui-download");
    let ui = format!(
        r#","external_ui":"dash","external_ui_download_url":"http://{web}/latest","external_ui_download_detour":"direct""#
    );
    let i = start(
        &api_config(target.port(), "", &ui),
        Settings {
            base_dir: Some(dir.clone()),
            ..Settings::default()
        },
    )
    .await;
    let api = i.clash_api.unwrap();
    let mut body = String::new();
    for _ in 0..50 {
        let (st, _, b) = http(api, "GET", "/ui/", &[], "").await;
        if st == 200 {
            body = b;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(body, "<p>v1</p>", "downloaded, single top directory trimmed");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "redirect followed");
    let (st, v) = api_json(api, "POST", "/upgrade/ui", "").await;
    assert_eq!((st, v), (200, json!({"status": "ok"})));
    assert_eq!(std::fs::read_to_string(dir.join("dash/a.js")).unwrap(), "1");
    i.shutdown();
}
