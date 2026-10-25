//! Shared outbound `tls` and v2ray `transport` objects.
#![allow(dead_code)] // consumed by the protocol outbounds as they land

use std::time::Duration;

use serde_json::Value;

use crate::obj::{Diag, Obj};
use crate::{Error, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsOutbound {
    pub enabled: bool,
    pub disable_sni: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    /// PEM, inline (joined lines) or from `certificate_path`.
    pub certificate: Option<String>,
    pub certificate_path: Option<String>,
    /// Pinned leaf certificate SHA-256 hashes (base64 in config).
    pub certificate_sha256: Vec<String>,
    pub certificate_public_key_sha256: Vec<String>,
    pub client_certificate: Option<String>,
    pub client_certificate_path: Option<String>,
    pub client_key: Option<String>,
    pub client_key_path: Option<String>,
    pub fragment: bool,
    pub fragment_fallback_delay: Option<Duration>,
    pub record_fragment: bool,
    pub handshake_timeout: Option<Duration>,
    pub utls: Option<Utls>,
    pub reality: Option<Reality>,
    pub ech: Option<Ech>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Utls {
    pub enabled: bool,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reality {
    pub enabled: bool,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ech {
    pub enabled: bool,
    pub config: Option<String>,
    pub config_path: Option<String>,
    pub query_server_name: Option<String>,
}

fn joined(o: &mut Obj, key: &str) -> Result<Option<String>> {
    let lines: Vec<String> = o.list(key)?;
    Ok(if lines.is_empty() { None } else { Some(lines.join("\n")) })
}

/// Parse the `tls` object at `key` if present.
pub(crate) fn parse_tls(parent: &mut Obj, key: &str, diag: &mut Diag) -> Result<Option<TlsOutbound>> {
    let Some(v) = parent.raw(key) else { return Ok(None) };
    let mut o = Obj::new(v, parent.sub(key))?;
    let mut t = TlsOutbound {
        enabled: o.bool("enabled")?,
        disable_sni: o.bool("disable_sni")?,
        server_name: o.string("server_name")?,
        insecure: o.bool("insecure")?,
        alpn: o.list("alpn")?,
        min_version: o.string("min_version")?,
        max_version: o.string("max_version")?,
        certificate: joined(&mut o, "certificate")?,
        certificate_path: o.string("certificate_path")?,
        certificate_sha256: o.list("certificate_sha256")?,
        certificate_public_key_sha256: o.list("certificate_public_key_sha256")?,
        client_certificate: joined(&mut o, "client_certificate")?,
        client_certificate_path: o.string("client_certificate_path")?,
        client_key: joined(&mut o, "client_key")?,
        client_key_path: o.string("client_key_path")?,
        fragment: o.bool("fragment")?,
        fragment_fallback_delay: o.duration("fragment_fallback_delay")?,
        record_fragment: o.bool("record_fragment")?,
        handshake_timeout: o.duration("handshake_timeout")?,
        utls: None,
        reality: None,
        ech: None,
    };
    for v in [&t.min_version, &t.max_version].into_iter().flatten() {
        if !["1.0", "1.1", "1.2", "1.3"].contains(&v.as_str()) {
            return Err(Error::at(&o.sub("min_version"), format!("unknown TLS version {v:?}")));
        }
    }
    if let Some(v) = o.raw("utls") {
        let mut u = Obj::new(v, o.sub("utls"))?;
        t.utls = Some(Utls {
            enabled: u.bool("enabled")?,
            fingerprint: u.string("fingerprint")?,
        });
        u.finish()?;
    }
    if let Some(v) = o.raw("reality") {
        let mut r = Obj::new(v, o.sub("reality"))?;
        t.reality = Some(Reality {
            enabled: r.bool("enabled")?,
            public_key: r.string("public_key")?.unwrap_or_default(),
            short_id: r.string("short_id")?.unwrap_or_default(),
        });
        r.finish()?;
    }
    if let Some(v) = o.raw("ech") {
        let mut e = Obj::new(v, o.sub("ech"))?;
        t.ech = Some(Ech {
            enabled: e.bool("enabled")?,
            config: joined(&mut e, "config")?,
            config_path: e.string("config_path")?,
            query_server_name: e.string("query_server_name")?,
        });
        e.tolerate(
            diag,
            &["pq_signature_schemes_enabled", "dynamic_record_sizing_disabled"],
        );
        e.finish()?;
    }
    o.tolerate(
        diag,
        &["engine", "cipher_suites", "curve_preferences", "kernel_tx", "kernel_rx"],
    );
    for k in ["spoof", "spoof_method"] {
        if o.has(k) {
            return Err(Error::at(&o.sub(k), "not supported by sbr yet"));
        }
    }
    o.finish()?;
    Ok(Some(t))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Http {
        host: Vec<String>,
        path: Option<String>,
        method: Option<String>,
        headers: Vec<(String, String)>,
        idle_timeout: Option<Duration>,
        ping_timeout: Option<Duration>,
    },
    Ws {
        path: Option<String>,
        headers: Vec<(String, String)>,
        max_early_data: u32,
        early_data_header_name: Option<String>,
    },
    Quic,
    Grpc {
        service_name: Option<String>,
        idle_timeout: Option<Duration>,
        ping_timeout: Option<Duration>,
        permit_without_stream: bool,
    },
    HttpUpgrade {
        host: Option<String>,
        path: Option<String>,
        headers: Vec<(String, String)>,
    },
}

/// `badoption.HTTPHeader`: values are a string or a list of strings.
pub(crate) fn headers(o: &mut Obj, key: &str) -> Result<Vec<(String, String)>> {
    Ok(o.get::<serde_json::Map<String, Value>>(key)?
        .into_iter()
        .flat_map(|(k, v)| match v {
            Value::Array(vs) => vs.into_iter().map(|v| (k.clone(), json_str(v))).collect::<Vec<_>>(),
            v => vec![(k, json_str(v))],
        })
        .collect())
}

fn json_str(v: Value) -> String {
    match v {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

pub(crate) fn parse_transport(parent: &mut Obj, key: &str) -> Result<Option<Transport>> {
    let Some(v) = parent.raw(key) else { return Ok(None) };
    let mut o = Obj::new(v, parent.sub(key))?;
    let ty: String = o.req("type")?;
    let t = match ty.as_str() {
        "http" => Transport::Http {
            host: o.list("host")?,
            path: o.string("path")?,
            method: o.string("method")?,
            headers: headers(&mut o, "headers")?,
            idle_timeout: o.duration("idle_timeout")?,
            ping_timeout: o.duration("ping_timeout")?,
        },
        "ws" => Transport::Ws {
            path: o.string("path")?,
            headers: headers(&mut o, "headers")?,
            max_early_data: o.get("max_early_data")?,
            early_data_header_name: o.string("early_data_header_name")?,
        },
        "quic" => Transport::Quic,
        "grpc" => Transport::Grpc {
            service_name: o.string("service_name")?,
            idle_timeout: o.duration("idle_timeout")?,
            ping_timeout: o.duration("ping_timeout")?,
            permit_without_stream: o.bool("permit_without_stream")?,
        },
        "httpupgrade" => Transport::HttpUpgrade {
            host: o.string("host")?,
            path: o.string("path")?,
            headers: headers(&mut o, "headers")?,
        },
        t => return Err(Error::at(&o.sub("type"), format!("unknown transport {t:?}"))),
    };
    o.finish()?;
    Ok(Some(t))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Multiplex {
    pub enabled: bool,
    pub protocol: Option<String>,
    pub max_connections: u32,
    pub min_streams: u32,
    pub max_streams: u32,
    pub padding: bool,
    pub brutal: Option<(u32, u32)>,
}

pub(crate) fn parse_multiplex(parent: &mut Obj, key: &str) -> Result<Option<Multiplex>> {
    let Some(v) = parent.raw(key) else { return Ok(None) };
    let mut o = Obj::new(v, parent.sub(key))?;
    let mut m = Multiplex {
        enabled: o.bool("enabled")?,
        protocol: o.string("protocol")?,
        max_connections: o.get("max_connections")?,
        min_streams: o.get("min_streams")?,
        max_streams: o.get("max_streams")?,
        padding: o.bool("padding")?,
        brutal: None,
    };
    if let Some(v) = o.raw("brutal") {
        let mut b = Obj::new(v, o.sub("brutal"))?;
        if b.bool("enabled")? {
            m.brutal = Some((b.get("up_mbps")?, b.get("down_mbps")?));
        } else {
            b.raw("up_mbps");
            b.raw("down_mbps");
        }
        b.finish()?;
    }
    o.finish()?;
    Ok(Some(m))
}
