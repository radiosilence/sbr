//! `experimental.clash_api` (sing-box `experimental/clashapi`): the HTTP +
//! WebSocket API that yacd, metacubexd, zashboard and the iOS app talk to.
//!
//! Deliberate differences from sing-box:
//! - `external_ui` is never downloaded unless `external_ui_download_url` is
//!   set (sing-box defaults to a GitHub URL).
//! - Delay tests use a URL only if the config names it as some `urltest`
//!   group's `url`; dashboards default to `gstatic.com`, and sbr does not
//!   contact third parties on its own. Otherwise the member's server
//!   handshake is measured (see `outbound/group.rs`).

pub mod log;
pub mod ui;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use sbr_config::{ClashApiOptions, Options, OutboundKind};
use sbr_core::Outbound;
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::fetch::Url;
use crate::outbound::group::{real_tag, test_outbounds};
use crate::track::Conn;
use crate::{Engine, Settings};

type Api = Arc<ApiState>;

pub struct ApiState {
    engine: Arc<Engine>,
    secret: Option<String>,
    ui: Option<PathBuf>,
    ui_download: Option<(String, Option<String>)>,
    /// Empty: any origin.
    origins: Vec<String>,
    private_network: bool,
    log_level: &'static str,
    /// URLs the config names (urltest `url`s); the only ones delay tests may fetch.
    allowed_urls: HashSet<String>,
}

pub type Serve = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Bind the controller. Returns its address and the serving future, or
/// `None` when `external_controller` is unset (the clash mode still works).
pub async fn start(
    engine: Arc<Engine>,
    opts: &ClashApiOptions,
    settings: &Settings,
    options: &Options,
) -> Result<Option<(SocketAddr, Serve)>, String> {
    let Some(addr) = &opts.external_controller else {
        return Ok(None);
    };
    let (host, port) = sbr_config::split_host_port(addr).ok_or("invalid external_controller")?;
    let host = if host.is_empty() { "0.0.0.0" } else { host };
    let listener = tokio::net::TcpListener::bind((host, port))
        .await
        .map_err(|e| format!("external controller listen error: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    info!("restful api listening at {local}");
    let allowed_urls = options
        .outbounds
        .iter()
        .filter_map(|o| match &o.kind {
            OutboundKind::UrlTest(u) => u.url.clone(),
            _ => None,
        })
        .collect();
    let api = Arc::new(ApiState {
        engine,
        secret: opts.secret.clone(),
        ui: opts.external_ui.as_deref().map(|p| crate::resolve_path(settings, p)),
        ui_download: opts
            .external_ui_download_url
            .clone()
            .map(|u| (u, opts.external_ui_download_detour.clone())),
        origins: opts
            .access_control_allow_origin
            .iter()
            .filter(|o| *o != "*")
            .cloned()
            .collect(),
        private_network: opts.access_control_allow_private_network,
        log_level: match options.log.level.as_deref() {
            Some("trace" | "debug") => "debug",
            Some("warn" | "warning") => "warn",
            Some("error" | "fatal" | "panic") => "error",
            _ => "info",
        },
        allowed_urls,
    });
    let app = router(api.clone());
    let serve: Serve = Box::pin(async move {
        if api.ui.is_some()
            && api.ui_download.is_some()
            && let Err(e) = check_and_download_ui(&api).await
        {
            warn!("download external ui error: {e}");
        }
        if let Err(e) = axum::serve(listener, app).await {
            warn!("external controller serve error: {e}");
        }
    });
    Ok(Some((local, serve)))
}

pub fn router(api: Api) -> Router {
    let mut r = Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route("/configs", get(get_configs).patch(patch_configs).put(no_content))
        .route("/proxies", get(get_proxies))
        .route("/proxies/{name}", get(get_proxy).put(put_proxy))
        .route("/proxies/{name}/delay", get(proxy_delay))
        .route("/group", get(get_groups))
        .route("/group/{name}", get(get_group))
        .route("/group/{name}/delay", get(group_delay))
        .route("/rules", get(get_rules))
        .route("/connections", get(connections).delete(close_all))
        .route("/connections/{id}", delete(close_one))
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
        .route("/logs", get(logs))
        .route("/providers/proxies", get(|| async { Json(json!({"providers": {}})) }))
        .route("/providers/rules", get(|| async { Json(json!({"providers": []})) }))
        .route("/dns/query", get(dns_query))
        .route("/cache/fakeip/flush", post(flush_fakeip))
        .route("/cache/dns/flush", post(no_content))
        .route("/upgrade/ui", post(upgrade_ui));
    if api.ui.is_some() {
        r = r
            .route(
                "/ui",
                get(|| async { (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, "/ui/")]) }),
            )
            .route("/ui/", get(serve_ui))
            .route("/ui/{*path}", get(serve_ui));
    }
    r.layer(middleware::from_fn_with_state(api.clone(), auth))
        .layer(middleware::from_fn_with_state(api.clone(), cors))
        .with_state(api)
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "message": msg }))).into_response()
}

async fn no_content() -> StatusCode {
    StatusCode::NO_CONTENT
}

// ---------------------------------------------------------------------------
// Middleware

/// rs/cors as sing-box configures it.
async fn cors(State(api): State<Api>, req: Request, next: Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).cloned();
    let allow = origin.and_then(|o| {
        if api.origins.is_empty() {
            Some(HeaderValue::from_static("*"))
        } else {
            api.origins.iter().any(|a| a.as_bytes() == o.as_bytes()).then_some(o)
        }
    });
    if req.method() == Method::OPTIONS && req.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) {
        let mut r = StatusCode::NO_CONTENT.into_response();
        if let Some(a) = allow {
            let h = r.headers_mut();
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, a);
            h.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE"),
            );
            h.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("Content-Type, Authorization"),
            );
            h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("300"));
            if api.private_network
                && req
                    .headers()
                    .get("access-control-request-private-network")
                    .is_some_and(|v| v == "true")
            {
                h.insert("access-control-allow-private-network", HeaderValue::from_static("true"));
            }
            h.insert(header::VARY, HeaderValue::from_static("Origin"));
        }
        return r;
    }
    let mut r = next.run(req).await;
    if let Some(a) = allow {
        r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, a);
        r.headers_mut().insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    r
}

fn eq_ct(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Bearer secret; browsers can't set headers on WebSockets, so those may
/// pass `?token=`.
async fn auth(State(api): State<Api>, req: Request, next: Next) -> Response {
    let Some(secret) = &api.secret else {
        if !unauthenticated_ok(&api, &req) {
            return error(StatusCode::FORBIDDEN, "Forbidden");
        }
        return next.run(req).await;
    };
    if req.uri().path() == "/ui" || req.uri().path().starts_with("/ui/") {
        return next.run(req).await;
    }
    let is_ws = req
        .headers()
        .get(header::UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if is_ws && let Some(token) = query_param(req.uri(), "token") {
        if eq_ct(&token, secret) {
            return next.run(req).await;
        }
        return error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .is_some_and(|(scheme, token)| scheme == "Bearer" && eq_ct(token, secret));
    if ok {
        next.run(req).await
    } else {
        error(StatusCode::UNAUTHORIZED, "Unauthorized")
    }
}

/// Without a secret, the API is open to anything that can reach it, including
/// a web page in the device's browser. Refuse the two ways a page gets in:
/// a cross-origin request (only listed origins, or the API's own `/ui`, may
/// call it) and DNS rebinding (a Host that is a domain other than localhost).
/// sing-box allows any origin here; sbr does not.
fn unauthenticated_ok(api: &ApiState, req: &Request) -> bool {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let name = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    if name.parse::<std::net::IpAddr>().is_err() && !name.eq_ignore_ascii_case("localhost") {
        return false;
    }
    match req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        None => true,
        Some(o) => {
            api.origins.iter().any(|a| a == o)
                || o.split_once("://")
                    .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(host))
        }
    }
}

fn query_param(uri: &Uri, key: &str) -> Option<String> {
    Query::<HashMap<String, String>>::try_from_uri(uri)
        .ok()?
        .0
        .remove(key)
        .filter(|v| !v.is_empty())
}

/// Split a request into an optional WebSocket upgrade.
async fn ws_upgrade(req: Request) -> Option<WebSocketUpgrade> {
    let (mut parts, _) = req.into_parts();
    if !parts
        .headers
        .get(header::UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
    {
        return None;
    }
    WebSocketUpgrade::from_request_parts(&mut parts, &()).await.ok()
}

// ---------------------------------------------------------------------------
// Basics

async fn hello(State(api): State<Api>, headers: HeaderMap) -> Response {
    let json_ct = headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v == "application/json");
    if api.ui.is_some() && !json_ct {
        return (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, "/ui/")]).into_response();
    }
    Json(json!({"hello": "clash"})).into_response()
}

async fn version() -> Json<Value> {
    // Dashboards look for "sing-box" and `meta` to enable features.
    Json(json!({
        "version": concat!("sing-box (sbr ", env!("CARGO_PKG_VERSION"), ")"),
        "premium": true,
        "meta": true,
    }))
}

async fn get_configs(State(api): State<Api>) -> Json<Value> {
    let mode = api.engine.router.clash_mode();
    Json(json!({
        "port": 0, "socks-port": 0, "redir-port": 0, "tproxy-port": 0, "mixed-port": 0,
        "allow-lan": false,
        "bind-address": "*",
        "mode": mode.current(),
        "mode-list": mode.list(),
        "log-level": api.log_level,
        "ipv6": false,
        "tun": null,
    }))
}

async fn patch_configs(State(api): State<Api>, body: Bytes) -> Response {
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "Body invalid");
    };
    if let Some(mode) = v.get("mode").and_then(Value::as_str).filter(|m| !m.is_empty())
        && let Some(new) = api.engine.router.clash_mode().set(mode)
    {
        if let Some(c) = &api.engine.cache {
            c.store_mode(&new);
        }
        info!("updated mode: {new}");
    }
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Proxies and groups

/// sing-box `C.ProxyDisplayName`.
fn display_type(kind: &str) -> &'static str {
    match kind {
        "direct" => "Direct",
        "block" => "Reject",
        "dns" => "DNS",
        "socks" => "SOCKS",
        "http" => "HTTP",
        "shadowsocks" => "Shadowsocks",
        "vmess" => "VMess",
        "vless" => "VLESS",
        "trojan" => "Trojan",
        "naive" => "Naive",
        "wireguard" => "WireGuard",
        "hysteria" => "Hysteria",
        "hysteria2" => "Hysteria2",
        "tuic" => "TUIC",
        "tor" => "Tor",
        "ssh" => "SSH",
        "shadowtls" => "ShadowTLS",
        "anytls" => "AnyTLS",
        "snell" => "Snell",
        "selector" => "Selector",
        "urltest" => "URLTest",
        _ => "Unknown",
    }
}

/// Go's RFC 3339 JSON time, in UTC.
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86400, secs % 86400);
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        d.subsec_millis()
    )
}

fn proxy_info(api: &ApiState, o: &Arc<dyn Outbound>) -> Value {
    let leaf = real_tag(o.as_ref());
    let history = match api.engine.groups.history(&leaf) {
        Some(h) => json!([{ "time": rfc3339(h.time), "delay": h.delay }]),
        None => json!([]),
    };
    // `alive` as in mihomo; the rest are sbr's: why the path was dropped
    // and when it is next tried (see `crate::health`).
    let degraded = api.engine.groups.degraded(&leaf);
    let mut v = json!({
        "type": display_type(o.kind()),
        "name": o.tag(),
        "udp": true,
        "history": history,
        "alive": degraded.is_none(),
        "degraded": degraded.is_some(),
        "reason": degraded.map(|d| d.reason.as_str()),
        "retry_in": degraded.map(|d| d.until.saturating_duration_since(std::time::Instant::now()).as_secs()),
    });
    if let Some(g) = o.as_group() {
        v["now"] = json!(g.selected().tag());
        v["all"] = json!(g.members().iter().map(|m| m.tag().to_owned()).collect::<Vec<_>>());
    }
    v
}

async fn get_proxies(State(api): State<Api>) -> Json<Value> {
    let e = &api.engine;
    let default = e.outbounds[e.router.final_outbound()].tag().to_owned();
    let mut all: Vec<String> = e
        .outbounds
        .iter()
        .filter(|o| !matches!(o.kind(), "direct" | "block" | "dns"))
        .map(|o| o.tag().to_owned())
        .collect();
    all.sort_by_key(|t| *t != default);
    let mut map = serde_json::Map::new();
    // Clash dashboards expect a GLOBAL pseudo-group.
    map.insert(
        "GLOBAL".into(),
        json!({"type": "Fallback", "name": "GLOBAL", "udp": true, "history": [], "all": all, "now": default}),
    );
    for o in &e.outbounds {
        map.insert(o.tag().to_owned(), proxy_info(&api, o));
    }
    Json(json!({ "proxies": map }))
}

fn find(api: &ApiState, name: &str) -> Option<Arc<dyn Outbound>> {
    api.engine.outbound(name).cloned()
}

fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "Resource not found")
}

async fn get_proxy(State(api): State<Api>, Path(name): Path<String>) -> Response {
    match find(&api, &name) {
        Some(o) => Json(proxy_info(&api, &o)).into_response(),
        None => not_found(),
    }
}

async fn put_proxy(State(api): State<Api>, Path(name): Path<String>, body: Bytes) -> Response {
    let o = match find(&api, &name) {
        Some(o) => o,
        None => return not_found(),
    };
    let Some(member) = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_owned))
    else {
        return error(StatusCode::BAD_REQUEST, "Body invalid");
    };
    let Some(g) = o.as_group().filter(|_| o.kind() == "selector") else {
        return error(StatusCode::BAD_REQUEST, "Must be a Selector");
    };
    if !g.select(&member) {
        return error(StatusCode::BAD_REQUEST, "Selector update error: not found");
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(serde::Deserialize)]
struct DelayQuery {
    url: Option<String>,
    timeout: Option<String>,
}

impl DelayQuery {
    fn timeout(&self) -> Option<Duration> {
        self.timeout.as_deref()?.parse::<u64>().ok().map(Duration::from_millis)
    }

    /// Only URLs the config itself names; see the module docs.
    fn url(&self, api: &ApiState) -> Option<Url> {
        let u = self.url.as_deref().filter(|u| api.allowed_urls.contains(*u))?;
        Url::parse(u)
    }
}

async fn proxy_delay(State(api): State<Api>, Path(name): Path<String>, Query(q): Query<DelayQuery>) -> Response {
    let o = match find(&api, &name) {
        Some(o) => o,
        None => return not_found(),
    };
    let Some(timeout) = q.timeout() else {
        return error(StatusCode::BAD_REQUEST, "Body invalid");
    };
    let url = q.url(&api);
    let env = &api.engine.groups;
    let r = tokio::time::timeout(timeout, env.probe(&o, url.as_ref())).await;
    env.recheck_containing(&real_tag(o.as_ref()));
    match r {
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "Timeout"),
        Ok(Err(_)) => error(StatusCode::SERVICE_UNAVAILABLE, "An error occurred in the delay test"),
        Ok(Ok(d)) => Json(json!({ "delay": d })).into_response(),
    }
}

async fn get_groups(State(api): State<Api>) -> Json<Value> {
    let groups: Vec<Value> = api
        .engine
        .outbounds
        .iter()
        .filter(|o| o.as_group().is_some())
        .map(|o| proxy_info(&api, o))
        .collect();
    Json(json!({ "proxies": groups }))
}

async fn get_group(State(api): State<Api>, Path(name): Path<String>) -> Response {
    match find(&api, &name) {
        Some(o) if o.as_group().is_some() => Json(proxy_info(&api, &o)).into_response(),
        _ => error(StatusCode::NOT_FOUND, "Resource not found"),
    }
}

async fn group_delay(State(api): State<Api>, Path(name): Path<String>, Query(q): Query<DelayQuery>) -> Response {
    let o = match find(&api, &name) {
        Some(o) if o.as_group().is_some() => o,
        _ => return error(StatusCode::NOT_FOUND, "Resource not found"),
    };
    let Some(timeout) = q.timeout() else {
        return error(StatusCode::BAD_REQUEST, "Body invalid");
    };
    let env = api.engine.groups.clone();
    let url = q.url(&api);
    let run = async {
        match env.urltest(o.tag()) {
            Some(u) => u.url_test(true).await,
            None => {
                let members = o.as_group().map(|g| g.members()).unwrap_or_default();
                let r = test_outbounds(&env, &members, url.as_ref(), Duration::ZERO, true, &|| {}).await;
                for m in &members {
                    env.recheck_containing(&real_tag(m.as_ref()));
                }
                r
            }
        }
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(r) => Json(json!(r)).into_response(),
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "context deadline exceeded"),
    }
}

async fn get_rules(State(api): State<Api>) -> Json<Value> {
    let rules: Vec<Value> = api
        .engine
        .router
        .rules_info()
        .iter()
        .map(|r| json!({"type": r.kind, "payload": r.payload, "proxy": r.action}))
        .collect();
    Json(json!({ "rules": rules }))
}

// ---------------------------------------------------------------------------
// Connections, traffic, memory, logs

fn conn_json(api: &ApiState, c: &Conn) -> Value {
    let m = &c.meta;
    let inbound = format!("{}/{}", m.inbound_type, m.inbound);
    let host = m.domain().unwrap_or("");
    let dst_ip = m.destination_ips().next().map(|ip| ip.to_string()).unwrap_or_default();
    let rule = api.engine.rule_label(c.rule);
    json!({
        "id": c.uuid(&api.engine.tracker),
        "metadata": {
            "network": match m.network { sbr_core::Network::Tcp => "tcp", sbr_core::Network::Udp => "udp", sbr_core::Network::Icmp => "icmp" },
            "type": inbound,
            "sourceIP": m.source.ip().to_string(),
            "destinationIP": dst_ip,
            "sourcePort": m.source.port().to_string(),
            "destinationPort": m.destination.port.to_string(),
            "host": host,
            "dnsMode": "normal",
            "processPath": "",
        },
        "upload": c.up.load(std::sync::atomic::Ordering::Relaxed),
        "download": c.down.load(std::sync::atomic::Ordering::Relaxed),
        "start": rfc3339(c.start),
        "chains": c.chain.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
        "rule": rule,
        "rulePayload": "",
    })
}

fn snapshot(api: &ApiState) -> Value {
    let t = &api.engine.tracker;
    let (up, down) = t.totals();
    let conns: Vec<Value> = t.connections().iter().map(|c| conn_json(api, c)).collect();
    json!({
        "downloadTotal": down,
        "uploadTotal": up,
        "connections": conns,
        "memory": log::process_memory(),
    })
}

async fn connections(State(api): State<Api>, req: Request) -> Response {
    let interval = query_param(req.uri(), "interval");
    let Some(ws) = ws_upgrade(req).await else {
        return Json(snapshot(&api)).into_response();
    };
    let interval = match interval.map(|i| i.parse::<u64>()) {
        None => Duration::from_secs(1),
        Some(Ok(ms)) => Duration::from_millis(ms.max(100)),
        Some(Err(_)) => return error(StatusCode::BAD_REQUEST, "Body invalid"),
    };
    ws.on_upgrade(move |mut socket| async move {
        loop {
            let text = snapshot(&api).to_string();
            if socket.send(Message::Text(text.into())).await.is_err() {
                return;
            }
            if !wait_or_closed(&mut socket, interval).await {
                return;
            }
        }
    })
}

/// Sleep `d`, returning false if the peer closed the socket meanwhile.
async fn wait_or_closed(socket: &mut WebSocket, d: Duration) -> bool {
    let sleep = tokio::time::sleep(d);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return true,
            m = socket.recv() => match m {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return false,
                Some(Ok(_)) => {}
            },
        }
    }
}

async fn close_all(State(api): State<Api>) -> StatusCode {
    api.engine.tracker.close_all();
    StatusCode::NO_CONTENT
}

async fn close_one(State(api): State<Api>, Path(id): Path<String>) -> StatusCode {
    if let Some(c) = api.engine.tracker.find(&id) {
        c.close();
    }
    StatusCode::NO_CONTENT
}

/// A once-a-second feed, as a WebSocket or a chunked JSON-lines response.
fn ticker<F>(ws: Option<WebSocketUpgrade>, mut next: F) -> Response
where
    F: FnMut() -> String + Send + 'static,
{
    match ws {
        Some(ws) => ws.on_upgrade(move |mut socket| async move {
            loop {
                if !wait_or_closed(&mut socket, Duration::from_secs(1)).await {
                    return;
                }
                if socket.send(Message::Text(next().into())).await.is_err() {
                    return;
                }
            }
        }),
        None => {
            let stream = futures_util::stream::unfold(next, |mut next| async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let mut line = next();
                line.push('\n');
                Some((Ok::<_, std::io::Error>(Bytes::from(line)), next))
            });
            ([(header::CONTENT_TYPE, "application/json")], Body::from_stream(stream)).into_response()
        }
    }
}

async fn traffic(State(api): State<Api>, req: Request) -> Response {
    let ws = ws_upgrade(req).await;
    let mut last = api.engine.tracker.totals();
    ticker(ws, move || {
        let now = api.engine.tracker.totals();
        let v = json!({"up": now.0.saturating_sub(last.0), "down": now.1.saturating_sub(last.1)});
        last = now;
        v.to_string()
    })
}

async fn memory(req: Request) -> Response {
    let ws = ws_upgrade(req).await;
    let mut first = true;
    ticker(ws, move || {
        // Like sing-box: the first sample is 0 so charts start from zero.
        let inuse = if std::mem::take(&mut first) {
            0
        } else {
            log::process_memory()
        };
        json!({"inuse": inuse, "oslimit": 0}).to_string()
    })
}

async fn logs(req: Request) -> Response {
    let Some(level) = log::parse_level(&query_param(req.uri(), "level").unwrap_or_default()) else {
        return error(StatusCode::BAD_REQUEST, "Body invalid");
    };
    let ws = ws_upgrade(req).await;
    let rx = log::subscribe();
    let line = move |e: log::LogEntry| -> Option<String> {
        (e.level <= level).then(|| json!({"type": log::level_name(e.level), "payload": e.message}).to_string())
    };
    let stream = tokio_stream_from(rx).filter_map(move |e| std::future::ready(line(e)));
    match ws {
        Some(ws) => ws.on_upgrade(move |mut socket| async move {
            tokio::pin!(stream);
            loop {
                tokio::select! {
                    l = stream.next() => match l {
                        Some(l) => if socket.send(Message::Text(l.into())).await.is_err() { return },
                        None => return,
                    },
                    m = socket.recv() => if matches!(m, None | Some(Err(_)) | Some(Ok(Message::Close(_)))) { return },
                }
            }
        }),
        None => {
            let body = stream.map(|mut l| {
                l.push('\n');
                Ok::<_, std::io::Error>(Bytes::from(l))
            });
            ([(header::CONTENT_TYPE, "application/json")], Body::from_stream(body)).into_response()
        }
    }
}

/// A broadcast receiver as a stream; lagging subscribers skip ahead.
fn tokio_stream_from<T: Clone + Send + 'static>(
    rx: tokio::sync::broadcast::Receiver<T>,
) -> impl futures_util::Stream<Item = T> + Send {
    futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(v) => return Some((v, rx)),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    })
}

// ---------------------------------------------------------------------------
// DNS, cache, UI

#[derive(serde::Deserialize)]
struct DnsQuery {
    name: String,
    #[serde(rename = "type")]
    qtype: Option<String>,
}

async fn dns_query(State(api): State<Api>, Query(q): Query<DnsQuery>) -> Response {
    use sbr_config::DomainStrategy;
    let (code, strategy) = match q.qtype.as_deref().unwrap_or("A") {
        "A" => (1, DomainStrategy::Ipv4Only),
        "AAAA" => (28, DomainStrategy::Ipv6Only),
        _ => return error(StatusCode::BAD_REQUEST, "invalid query type"),
    };
    let fqdn = format!("{}.", q.name.trim_end_matches('.'));
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        api.engine.dns.lookup(q.name.trim_end_matches('.'), Some(strategy)),
    )
    .await;
    let ips = match r {
        Ok(Ok(ips)) => ips,
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "timeout"),
    };
    let mut v = json!({
        "Status": 0,
        "Question": [{"Name": fqdn, "Qtype": code, "Qclass": 1}],
        "Server": "internal",
        "TC": false, "RD": true, "RA": true, "AD": false, "CD": false,
    });
    if !ips.is_empty() {
        v["Answer"] = json!(
            ips.iter()
                .map(|ip| json!({"name": fqdn, "type": code, "TTL": 0, "data": ip.to_string()}))
                .collect::<Vec<_>>()
        );
    }
    Json(v).into_response()
}

async fn flush_fakeip(State(api): State<Api>) -> Response {
    if let Some(c) = &api.engine.cache
        && let Err(e) = c.table("fakeip").clear()
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn serve_ui(State(api): State<Api>, path: Option<Path<String>>) -> Response {
    let Some(root) = &api.ui else {
        return error(StatusCode::NOT_FOUND, "Resource not found");
    };
    let rel = path.map(|p| p.0).unwrap_or_default();
    let Some(file) = ui::resolve(root, &rel) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = file.clone();
    match tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)))
    {
        Ok(b) => ([(header::CONTENT_TYPE, ui::content_type(&file))], b).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "404 page not found\n").into_response(),
    }
}

async fn download_ui(api: &ApiState) -> Result<usize, String> {
    let (url, detour) = api.ui_download.as_ref().ok_or("external_ui_download_url is not set")?;
    let root = api.ui.as_ref().ok_or("external UI not enabled")?;
    let e = &api.engine;
    let via = match detour {
        Some(t) => e
            .outbound(t)
            .cloned()
            .ok_or_else(|| format!("detour outbound not found: {t}"))?,
        None => e.outbounds[e.router.final_outbound()].clone(),
    };
    info!("downloading external ui using outbound/{}[{}]", via.kind(), via.tag());
    let u = Url::parse(url).ok_or("invalid external_ui_download_url")?;
    let resp = e
        .http
        .get(via.as_ref(), &u, &[], 128 << 20)
        .await
        .map_err(|e| e.to_string())?;
    // Extract next to the target, then swap, so a bad archive leaves the old UI.
    let tmp = root.with_extension("download");
    let _ = std::fs::remove_dir_all(&tmp);
    let n = ui::extract_zip(&resp.body, &tmp).map_err(|e| {
        let _ = std::fs::remove_dir_all(&tmp);
        e.to_string()
    })?;
    let _ = std::fs::remove_dir_all(root);
    std::fs::rename(&tmp, root).map_err(|e| e.to_string())?;
    Ok(n)
}

async fn check_and_download_ui(api: &ApiState) -> Result<(), String> {
    let root = api.ui.as_ref().ok_or("no ui")?;
    let empty = std::fs::read_dir(root).map(|mut d| d.next().is_none()).unwrap_or(true);
    if empty {
        let n = download_ui(api).await?;
        info!("downloaded external ui ({n} files)");
    }
    Ok(())
}

async fn upgrade_ui(State(api): State<Api>) -> Response {
    if api.ui.is_none() {
        return error(StatusCode::NOT_FOUND, "external UI not enabled");
    }
    info!("upgrading external UI");
    match download_ui(&api).await {
        Ok(_) => Json(json!({"status": "ok"})).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc3339() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_761_397_200_123);
        assert_eq!(super::rfc3339(t), "2025-10-25T13:00:00.123Z");
        assert_eq!(super::rfc3339(std::time::UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
    }
}
