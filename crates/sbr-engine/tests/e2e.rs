//! End-to-end: real sockets, real handshakes, real bytes.

use std::net::SocketAddr;

use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Echo server; returns its address.
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

async fn start(json: &str) -> Instance {
    let o = Options::parse(json).unwrap();
    Instance::start(&o, Settings::default()).await.unwrap()
}

fn port(i: &Instance, tag: &str) -> u16 {
    i.listening.iter().find(|(t, _)| t == tag).unwrap().1.port()
}

async fn socks_connect(
    proxy: u16,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await?;
    let method = if auth.is_some() { 2 } else { 0 };
    s.write_all(&[5, 1, method]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    assert_eq!(r, [5, method]);
    if let Some((u, p)) = auth {
        let mut b = vec![1, u.len() as u8];
        b.extend_from_slice(u.as_bytes());
        b.push(p.len() as u8);
        b.extend_from_slice(p.as_bytes());
        s.write_all(&b).await?;
        s.read_exact(&mut r).await?;
        if r[1] != 0 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await?;
    if rep[1] != 0 {
        return Err(std::io::Error::other(format!("socks reply {}", rep[1])));
    }
    Ok(s)
}

async fn roundtrip(s: &mut TcpStream, payload: &[u8]) {
    s.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);
}

#[tokio::test]
async fn mixed_socks5_and_http_connect() {
    let target = echo().await;
    let i =
        start(r#"{"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}]}"#)
            .await;
    let p = port(&i, "in");

    let mut s = socks_connect(p, "localhost", target.port(), None)
        .await
        .unwrap();
    roundtrip(&mut s, b"hello over socks").await;

    let mut h = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    h.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\nearly").as_bytes())
        .await
        .unwrap();
    let mut head = [0u8; 39];
    h.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 Connection established\r\n\r\n");
    let mut early = [0u8; 5];
    h.read_exact(&mut early).await.unwrap();
    assert_eq!(
        &early, b"early",
        "bytes pipelined after the CONNECT head must not be lost"
    );
    roundtrip(&mut h, b"hello over http").await;
}

#[tokio::test]
async fn http_forward_proxy_rewrites_request() {
    // A fake origin that returns the request line it saw.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let body = req.lines().next().unwrap().to_owned()
            + if req.contains("Proxy-Connection") {
                " LEAK"
            } else {
                ""
            };
        s.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    });
    let i =
        start(r#"{"inbounds":[{"type":"http","tag":"in","listen":"127.0.0.1","listen_port":0}]}"#)
            .await;
    let mut c = TcpStream::connect(("127.0.0.1", port(&i, "in")))
        .await
        .unwrap();
    c.write_all(format!("GET http://{origin}/a?b=1 HTTP/1.1\r\nHost: {origin}\r\nProxy-Connection: keep-alive\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    c.read_to_string(&mut resp).await.unwrap();
    assert!(resp.ends_with("GET /a?b=1 HTTP/1.1"), "{resp}");
}

#[tokio::test]
async fn auth_required() {
    let target = echo().await;
    let i = start(r#"{"inbounds":[{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0,"users":[{"username":"u","password":"p"}]}]}"#).await;
    let p = port(&i, "in");
    assert!(
        socks_connect(p, "127.0.0.1", target.port(), Some(("u", "nope")))
            .await
            .is_err()
    );
    let mut s = socks_connect(p, "127.0.0.1", target.port(), Some(("u", "p")))
        .await
        .unwrap();
    roundtrip(&mut s, b"authed").await;
}

#[tokio::test]
async fn routing_reject_and_selector() {
    let target = echo().await;
    let i = start(
        r#"{
        "inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}],
        "outbounds":[
            {"type":"selector","tag":"sel","outbounds":["blk","direct"],"default":"blk"},
            {"type":"direct","tag":"direct"},
            {"type":"block","tag":"blk"}
        ],
        "route":{"rules":[{"domain_suffix":"blocked.test","action":"reject"},{"ip_is_private":true,"outbound":"sel"}],"final":"direct"}
    }"#,
    )
    .await;
    let p = port(&i, "in");
    let e = socks_connect(p, "x.blocked.test", 80, None)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("socks reply 2"), "{e}");
    // selector defaults to block…
    assert!(
        socks_connect(p, "127.0.0.1", target.port(), None)
            .await
            .is_err()
    );
    // …and switching it takes effect for new connections.
    let sel = i.engine.outbound("sel").unwrap().as_selector().unwrap();
    assert!(sel.select("direct"));
    let mut s = socks_connect(p, "127.0.0.1", target.port(), None)
        .await
        .unwrap();
    roundtrip(&mut s, b"selected").await;
}

#[tokio::test]
async fn chained_detour_through_socks_and_http() {
    let target = echo().await;
    let upstream = start(r#"{"inbounds":[{"type":"mixed","tag":"up","listen":"127.0.0.1","listen_port":0,"users":[{"username":"a","password":"b"}]}]}"#).await;
    let up = port(&upstream, "up");
    let front = start(&format!(
        r#"{{
        "inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[
            {{"type":"socks","tag":"s","server":"127.0.0.1","server_port":{up},"username":"a","password":"b","detour":"h"}},
            {{"type":"http","tag":"h","server":"127.0.0.1","server_port":{up},"username":"a","password":"b"}}
        ]
    }}"#
    ))
    .await;
    // front -> (http CONNECT to upstream) -> (socks5 to upstream, inside that tunnel) -> echo
    let mut s = socks_connect(port(&front, "in"), "127.0.0.1", target.port(), None)
        .await
        .unwrap();
    roundtrip(&mut s, b"two hops").await;
}

#[tokio::test]
async fn shadowsocks_2022() {
    use shadowsocks::config::{ServerConfig, ServerType};
    use shadowsocks::context::Context;
    use shadowsocks::crypto::CipherKind;
    use shadowsocks::relay::tcprelay::proxy_listener::ProxyListener;

    let target = echo().await;
    let key = "Ixi/xBrzF3Nnrel2vh8Dsg=="; // 16 bytes, base64
    let method = "2022-blake3-aes-128-gcm";
    let cfg = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        key,
        method.parse::<CipherKind>().unwrap(),
    )
    .unwrap();
    let listener = ProxyListener::bind(Context::new_shared(ServerType::Server), &cfg)
        .await
        .unwrap();
    let ss_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let addr = s.handshake().await.unwrap();
                let mut remote = TcpStream::connect(addr.to_string()).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut s, &mut remote).await;
            });
        }
    });

    let i = start(&format!(
        r#"{{
        "inbounds":[{{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}}],
        "outbounds":[{{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":{ss_port},"method":"{method}","password":"{key}"}}]
    }}"#
    ))
    .await;
    let mut s = socks_connect(port(&i, "in"), "127.0.0.1", target.port(), None)
        .await
        .unwrap();
    let big: Vec<u8> = (0..1_000_000u32).map(|x| (x % 251) as u8).collect();
    let (mut r, mut w) = s.split();
    let send = async {
        w.write_all(&big).await.unwrap();
    };
    let recv = async {
        let mut got = vec![0u8; big.len()];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::join!(send, recv);
    assert!(
        got == big,
        "1 MB through shadowsocks-2022 must survive intact"
    );
}
