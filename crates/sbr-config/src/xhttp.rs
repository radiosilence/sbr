//! The `xhttp` v2ray transport, an sbr extension: sing-box has no XHTTP, so
//! the object mirrors Xray-core's `xhttpSettings` (field names included) and
//! applies the defaults and checks of Xray's `SplitHTTPConfig.Build`
//! (`infra/conf/transport_method.go`).

use serde::Deserialize;
use serde::de::{self, Deserializer};

use crate::obj::{Diag, Obj};
use crate::tls::{TlsOutbound, Transport, headers, parse_tls, parse_transport};
use crate::{Error, Result, ServerAddr, parse_server};

/// Xray `Int32Range`: `7` or `"7"` or `"1-9"`, reordered so `from <= to`.
/// `0-0` means "unset" wherever Xray has a default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Range {
    pub from: i32,
    pub to: i32,
}

impl Range {
    pub const fn new(from: i32, to: i32) -> Self {
        Self { from, to }
    }
    pub fn is_unset(&self) -> bool {
        self.to == 0
    }
    /// The range, or `default` when unset (Xray's `GetNormalized*`).
    pub fn or(self, default: Range) -> Range {
        if self.is_unset() { default } else { self }
    }
}

fn parse_range(s: &str) -> Option<(i64, i64)> {
    if s.is_empty() {
        return Some((0, 0));
    }
    if let Ok(v) = s.parse::<i64>() {
        return Some((v, v));
    }
    // A leading '-' belongs to the first number ("-5-10").
    let split = if let Some(rest) = s.strip_prefix('-') {
        rest.find('-').map(|i| i + 1)
    } else {
        s.find('-')
    };
    let i = split?;
    Some((s[..i].trim().parse().ok()?, s[i + 1..].trim().parse().ok()?))
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let err = || de::Error::custom("invalid integer range, expected a string like \"1-2\" or an integer");
        let (a, b) = match serde_json::Value::deserialize(d)? {
            serde_json::Value::Number(n) => {
                let v = n.as_i64().ok_or_else(err)?;
                (v, v)
            }
            serde_json::Value::String(s) => parse_range(&s).ok_or_else(err)?,
            _ => return Err(err()),
        };
        let (a, b) = (
            i32::try_from(a).map_err(|_| err())?,
            i32::try_from(b).map_err(|_| err())?,
        );
        Ok(Range::new(a.min(b), a.max(b)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpMode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

/// Where a piece of request metadata goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Path,
    Query,
    Header,
    Cookie,
    /// A URL with the value in its query, in a header (Xray's default for
    /// padding: `Referer: https://host/path?x_padding=XXX`).
    QueryInHeader,
    Body,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingMethod {
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Xmux {
    pub max_concurrency: Range,
    pub max_connections: Range,
    pub c_max_reuse_times: Range,
    pub h_max_request_times: Range,
    pub h_max_reusable_secs: Range,
    /// Seconds; negative disables keep-alive pings.
    pub h_keep_alive_period: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xhttp {
    pub host: Option<String>,
    pub path: String,
    pub mode: XhttpMode,
    pub headers: Vec<(String, String)>,
    pub x_padding_bytes: Range,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: Placement,
    pub x_padding_method: PaddingMethod,
    pub uplink_http_method: String,
    pub session_id_placement: Placement,
    pub session_id_key: String,
    /// The alphabet for generated session IDs; empty means a UUIDv4.
    pub session_id_table: String,
    pub session_id_length: Range,
    pub seq_placement: Placement,
    pub seq_key: String,
    pub uplink_data_placement: Placement,
    pub uplink_data_key: String,
    pub uplink_chunk_size: Range,
    pub no_grpc_header: bool,
    pub sc_max_each_post_bytes: Range,
    pub sc_min_posts_interval_ms: Range,
    pub xmux: Xmux,
    /// A separate server (and its own XHTTP options) for the download.
    pub download: Option<Box<XhttpDownload>>,
    /// Server-side options, accepted because Xray configs share one object
    /// between both ends. They have no client-side effect in Xray either.
    pub no_sse_header: bool,
    pub sc_max_buffered_posts: i64,
    pub sc_stream_up_server_secs: Range,
    pub server_max_header_bytes: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpDownload {
    pub server: ServerAddr,
    pub tls: Option<TlsOutbound>,
    pub xhttp: Xhttp,
}

/// Xray `PredefinedTable`.
pub fn predefined_table(name: &str) -> Option<&'static str> {
    Some(match name {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        _ => return None,
    })
}

fn placement(o: &mut Obj, key: &str, allowed: &[Placement], default: Placement) -> Result<Placement> {
    let path = o.sub(key);
    let p = match o.string(key)?.as_deref() {
        None => return Ok(default),
        Some("path") => Placement::Path,
        Some("query") => Placement::Query,
        Some("header") => Placement::Header,
        Some("cookie") => Placement::Cookie,
        Some("queryInHeader") => Placement::QueryInHeader,
        Some("body") => Placement::Body,
        Some("auto") => Placement::Auto,
        Some(other) => return Err(Error::at(&path, format!("unsupported placement: {other}"))),
    };
    if !allowed.contains(&p) {
        return Err(Error::at(&path, format!("unsupported placement: {p:?}")));
    }
    Ok(p)
}

/// Fields of the object after `type`. `o` is consumed up to `finish`.
pub(crate) fn parse_xhttp(o: &mut Obj, diag: &mut Diag) -> Result<Xhttp> {
    let host = o.string("host")?;
    let path = o.string("path")?.unwrap_or_default();
    let mode_path = o.sub("mode");
    let mode = match o.string("mode")?.as_deref() {
        None | Some("auto") => XhttpMode::Auto,
        Some("packet-up") => XhttpMode::PacketUp,
        Some("stream-up") => XhttpMode::StreamUp,
        Some("stream-one") => XhttpMode::StreamOne,
        Some(m) => return Err(Error::at(&mode_path, format!("unsupported mode: {m}"))),
    };
    // Xray: everything but host, path and mode may come from `extra` instead
    // (share links carry it that way); `extra` then replaces the object.
    if let Some(extra) = o.raw("extra") {
        let mut e = Obj::new(extra, o.sub("extra"))?;
        for k in ["host", "path", "mode", "extra"] {
            e.raw(k);
        }
        let x = parse_fields(&mut e, host, path, mode, diag)?;
        e.finish()?;
        // Xray ignores the outer object's other fields when `extra` is set;
        // the caller's `finish` rejects them instead.
        return Ok(x);
    }
    parse_fields(o, host, path, mode, diag)
}

fn parse_fields(o: &mut Obj, host: Option<String>, path: String, mode: XhttpMode, diag: &mut Diag) -> Result<Xhttp> {
    use Placement::*;
    let headers_path = o.sub("headers");
    let headers = headers(o, "headers")?;
    if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        return Err(Error::at(
            &headers_path,
            "\"headers\" can't contain \"host\"; use \"host\"",
        ));
    }

    let pad_path = o.sub("xPaddingBytes");
    let x_padding_bytes: Range = o.get("xPaddingBytes")?;
    if x_padding_bytes != Range::default() && (x_padding_bytes.from <= 0 || x_padding_bytes.to <= 0) {
        return Err(Error::at(&pad_path, "xPaddingBytes cannot be disabled"));
    }
    let x_padding_obfs_mode = o.bool("xPaddingObfsMode")?;
    let x_padding_key = o.string("xPaddingKey")?.unwrap_or_else(|| "x_padding".into());
    let x_padding_header = o.string("xPaddingHeader")?.unwrap_or_else(|| "X-Padding".into());
    let x_padding_placement = placement(
        o,
        "xPaddingPlacement",
        &[Cookie, Header, Query, QueryInHeader],
        QueryInHeader,
    )?;
    let method_path = o.sub("xPaddingMethod");
    let x_padding_method = match o.string("xPaddingMethod")?.as_deref() {
        None | Some("repeat-x") => PaddingMethod::RepeatX,
        Some("tokenish") => PaddingMethod::Tokenish,
        Some(m) => return Err(Error::at(&method_path, format!("unsupported padding method: {m}"))),
    };

    let data_path = o.sub("uplinkDataPlacement");
    let uplink_data_placement = placement(o, "uplinkDataPlacement", &[Auto, Body, Cookie, Header], Auto)?;
    if matches!(uplink_data_placement, Cookie | Header) && mode != XhttpMode::PacketUp {
        return Err(Error::at(&data_path, "cookie and header placement need mode packet-up"));
    }
    let method_path = o.sub("uplinkHTTPMethod");
    let uplink_http_method = o
        .string("uplinkHTTPMethod")?
        .unwrap_or_else(|| "POST".into())
        .to_ascii_uppercase();
    if uplink_http_method == "GET" && mode != XhttpMode::PacketUp {
        return Err(Error::at(
            &method_path,
            "uplinkHTTPMethod can be GET only in packet-up mode",
        ));
    }
    if http_token(&uplink_http_method).is_none() {
        return Err(Error::at(&method_path, "invalid HTTP method"));
    }

    let session_id_placement = placement(o, "sessionIDPlacement", &[Path, Cookie, Header, Query], Path)?;
    let session_id_key = o.string("sessionIDKey")?.unwrap_or_else(|| match session_id_placement {
        Header => "X-Session".into(),
        Cookie | Query => "x_session".into(),
        _ => String::new(),
    });
    let table_path = o.sub("sessionIDTable");
    let mut session_id_table = o.string("sessionIDTable")?.unwrap_or_default();
    let session_id_length: Range = o.get("sessionIDLength")?;
    if !session_id_table.is_empty() {
        if let Some(t) = predefined_table(&session_id_table) {
            session_id_table = t.into();
        }
        if !session_id_table.is_ascii() {
            return Err(Error::at(
                &table_path,
                "sessionIDTable must contain only ASCII characters",
            ));
        }
        if session_id_length.from <= 0 {
            return Err(Error::at(
                &o.sub("sessionIDLength"),
                "sessionIDLength.from must be greater than 0",
            ));
        }
        // At least 2^31 possible IDs.
        let base = session_id_table.len() as u128;
        let room = (session_id_length.from..=session_id_length.to)
            .fold(0u128, |acc, k| acc.saturating_add(base.saturating_pow(k as u32)));
        if room < 1 << 31 {
            return Err(Error::at(&table_path, "sessionIDTable or sessionIDLength is too small"));
        }
    }

    let seq_placement = placement(o, "seqPlacement", &[Path, Cookie, Header, Query], Path)?;
    let seq_key = o.string("seqKey")?.unwrap_or_else(|| match seq_placement {
        Header => "X-Seq".into(),
        Cookie | Query => "x_seq".into(),
        _ => String::new(),
    });
    let uplink_data_key = o
        .string("uplinkDataKey")?
        .unwrap_or_else(|| match uplink_data_placement {
            Cookie => "x_data".into(),
            Auto | Header => "X-Data".into(),
            _ => String::new(),
        });
    let uplink_chunk_size = o.get("uplinkChunkSize")?;
    let no_grpc_header = o.bool("noGRPCHeader")?;
    let no_sse_header = o.bool("noSSEHeader")?;
    let each_path = o.sub("scMaxEachPostBytes");
    let sc_max_each_post_bytes: Range = o.get("scMaxEachPostBytes")?;
    if !sc_max_each_post_bytes.is_unset() && sc_max_each_post_bytes.from <= 0 {
        return Err(Error::at(&each_path, "scMaxEachPostBytes should be bigger than 0"));
    }
    let sc_min_posts_interval_ms = o.get("scMinPostsIntervalMs")?;
    let sc_max_buffered_posts = o.get("scMaxBufferedPosts")?;
    let sc_stream_up_server_secs = o.get("scStreamUpServerSecs")?;
    let mh_path = o.sub("serverMaxHeaderBytes");
    let server_max_header_bytes: i32 = o.get("serverMaxHeaderBytes")?;
    if server_max_header_bytes < 0 {
        return Err(Error::at(&mh_path, "invalid negative value of maxHeaderBytes"));
    }

    let xmux = match o.raw("xmux") {
        None => Xmux::default(),
        Some(v) => {
            let mut x = Obj::new(v, o.sub("xmux"))?;
            let m = Xmux {
                max_concurrency: x.get("maxConcurrency")?,
                max_connections: x.get("maxConnections")?,
                c_max_reuse_times: x.get("cMaxReuseTimes")?,
                h_max_request_times: x.get("hMaxRequestTimes")?,
                h_max_reusable_secs: x.get("hMaxReusableSecs")?,
                h_keep_alive_period: x.get("hKeepAlivePeriod")?,
            };
            if m.max_connections.to > 0 && m.max_concurrency.to > 0 {
                return Err(Error::at(
                    &x.sub("maxConnections"),
                    "maxConnections cannot be specified together with maxConcurrency",
                ));
            }
            x.finish()?;
            m
        }
    };
    let xmux = if xmux == Xmux::default() {
        Xmux {
            max_connections: Range::new(3, 3),
            h_max_request_times: Range::new(600, 900),
            h_max_reusable_secs: Range::new(1800, 3000),
            ..Xmux::default()
        }
    } else {
        xmux
    };

    let download_path = o.sub("downloadSettings");
    let download = match o.raw("downloadSettings") {
        None => None,
        Some(_) if mode == XhttpMode::StreamOne => {
            return Err(Error::at(
                &download_path,
                "can not use downloadSettings in stream-one mode",
            ));
        }
        Some(v) => {
            let mut d = Obj::new(v, download_path.clone())?;
            let server = parse_server(&mut d)?;
            let tls = parse_tls(&mut d, "tls", diag)?;
            let tpath = d.sub("transport");
            let xhttp = match parse_transport(&mut d, "transport", diag)? {
                Some(Transport::Xhttp(x)) => *x,
                _ => return Err(Error::at(&tpath, "must be an xhttp transport")),
            };
            if xhttp.download.is_some() {
                return Err(Error::at(&tpath, "downloadSettings cannot nest"));
            }
            d.finish()?;
            Some(Box::new(XhttpDownload { server, tls, xhttp }))
        }
    };

    Ok(Xhttp {
        host,
        path,
        mode,
        headers,
        x_padding_bytes,
        x_padding_obfs_mode,
        x_padding_key,
        x_padding_header,
        x_padding_placement,
        x_padding_method,
        uplink_http_method,
        session_id_placement,
        session_id_key,
        session_id_table,
        session_id_length,
        seq_placement,
        seq_key,
        uplink_data_placement,
        uplink_data_key,
        uplink_chunk_size,
        no_grpc_header,
        sc_max_each_post_bytes,
        sc_min_posts_interval_ms,
        xmux,
        download,
        no_sse_header,
        sc_max_buffered_posts,
        sc_stream_up_server_secs,
        server_max_header_bytes,
    })
}

fn http_token(s: &str) -> Option<&str> {
    (!s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)))
    .then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let r = |v: serde_json::Value| serde_json::from_value::<Range>(v).ok();
        assert_eq!(r(serde_json::json!(5)), Some(Range::new(5, 5)));
        assert_eq!(r(serde_json::json!("100-1000")), Some(Range::new(100, 1000)));
        assert_eq!(r(serde_json::json!("9-3")), Some(Range::new(3, 9)));
        assert_eq!(r(serde_json::json!("-5-10")), Some(Range::new(-5, 10)));
        assert_eq!(r(serde_json::json!("")), Some(Range::new(0, 0)));
        assert_eq!(r(serde_json::json!("x")), None);
    }
}
