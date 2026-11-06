//! The messages the app sends the packet tunnel over
//! `NETunnelProviderSession.sendProviderMessage`, encoded as SbrKit's
//! `SbrRequest` and `SbrResponse` are by Swift's `Codable`: a request is an
//! object keyed by its case, and a case without values carries `{}`.

use serde::{Deserialize, Serialize};

use crate::profile::{ProfileSnapshot, RemoteProfile};
use crate::rules::PersonalRule;

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum Request {
    Groups {},
    Select {
        group: String,
        member: String,
    },
    UrlTest {
        group: String,
    },
    Stats {},
    Connections {},
    CloseConnection {
        id: String,
    },
    Logs {},
    /// Run this config (nothing restarts when it is already running), or
    /// re-read the saved one when none. With a config, `remote` and
    /// `log_level` replace the tunnel's; `rules` replaces the personal rules.
    #[serde(rename_all = "camelCase")]
    Reload {
        #[serde(skip_serializing_if = "Option::is_none")]
        config: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote: Option<RemoteProfile>,
        #[serde(skip_serializing_if = "Option::is_none")]
        log_level: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rules: Option<Vec<PersonalRule>>,
    },
    /// The remote profile the tunnel last downloaded itself, if any.
    Profile {},
    /// Delete the extension's files before the app removes its configuration.
    Erase {},
}

#[derive(Deserialize, Debug, Default)]
pub struct Response {
    pub groups: Option<Vec<Group>>,
    pub stats: Option<Stats>,
    pub logs: Option<Vec<String>>,
    pub connections: Option<Connections>,
    pub profile: Option<ProfileSnapshot>,
    pub error: Option<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Group {
    pub tag: String,
    /// `selector` (picked by hand) or `urltest` (picks the fastest itself).
    #[serde(rename = "type")]
    pub kind: String,
    pub selected: String,
    /// The leaf outbound traffic resolves to through nested groups.
    pub now: String,
    pub delay: Option<u32>,
    pub members: Vec<Member>,
}

impl Group {
    pub fn selectable(&self) -> bool {
        self.kind == "selector"
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Member {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// Last measured latency in milliseconds; none when untested.
    pub delay: Option<u32>,
    /// Dropped by failover, with why and seconds until it is retried.
    pub degraded: Option<bool>,
    pub reason: Option<String>,
    pub retry_in: Option<u32>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    /// Bytes jetsam charges the extension.
    pub memory_footprint: u64,
    /// Bytes left before jetsam on iOS; 0 on macOS.
    pub memory_available: u64,
    pub active_connections: u64,
    pub udp_sessions: u64,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    #[serde(default)]
    pub cpu_time_micros: u64,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Connections {
    pub total: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub connections: Vec<Connection>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Connection {
    pub id: String,
    pub network: String,
    pub inbound: String,
    pub source: String,
    pub destination: String,
    pub domain: Option<String>,
    pub ip: Option<String>,
    #[serde(rename = "protocol")]
    pub sniffed: Option<String>,
    pub chain: Vec<String>,
    pub rule: String,
    pub upload: u64,
    pub download: u64,
    /// Unix milliseconds.
    pub start: i64,
}

impl Connection {
    pub fn host(&self) -> &str {
        self.domain
            .as_deref()
            .or(self.ip.as_deref())
            .unwrap_or(&self.destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_encode_as_swift_codable_does() {
        let s = |r: Request| serde_json::to_string(&r).unwrap();
        assert_eq!(s(Request::Groups {}), r#"{"groups":{}}"#);
        assert_eq!(
            s(Request::Select {
                group: "proxy".into(),
                member: "hk".into()
            }),
            r#"{"select":{"group":"proxy","member":"hk"}}"#
        );
        assert_eq!(
            s(Request::UrlTest { group: "auto".into() }),
            r#"{"urlTest":{"group":"auto"}}"#
        );
        assert_eq!(
            s(Request::Reload {
                config: Some("{}".into()),
                remote: None,
                log_level: Some("debug".into()),
                rules: Some(Vec::new()),
            }),
            r#"{"reload":{"config":"{}","logLevel":"debug","rules":[]}}"#
        );
        assert_eq!(s(Request::Erase {}), r#"{"erase":{}}"#);
    }

    #[test]
    fn stats_decode_from_swift_keys() {
        let r: Response = serde_json::from_str(
            r#"{"stats":{"memoryFootprint":1,"memoryAvailable":2,"activeConnections":3,
                "udpSessions":4,"uplinkBytes":5,"downlinkBytes":6,"cpuTimeMicros":7}}"#,
        )
        .unwrap();
        assert_eq!(r.stats.unwrap().downlink_bytes, 6);
    }
}
