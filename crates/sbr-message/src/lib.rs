//! The messages the app sends the packet tunnel over
//! `NETunnelProviderSession.sendProviderMessage`, and the values the two
//! share through `providerConfiguration` and the Keychain.
//!
//! Everything is encoded as SbrKit's Swift `Codable` types are by
//! `JSONEncoder` with default strategies, so a Swift app and a Rust tunnel
//! (or the reverse) understand each other: a request is an object keyed by
//! its case, a case without values carries `{}`, absent optionals are left
//! out, URLs are strings and dates are seconds since 2001-01-01 UTC
//! (`Date.timeIntervalSinceReferenceDate`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// App → tunnel requests (`SbrRequest`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Request {
    Groups {},
    Select {
        group: String,
        member: String,
    },
    /// Start a latency test of a group; poll `Groups` for the results.
    UrlTest {
        group: String,
    },
    Stats {},
    /// The newest open connections (at most 200).
    Connections {},
    /// Close one connection; answers with the connections left.
    CloseConnection {
        id: String,
    },
    /// The extension's recent log lines (memory only).
    Logs {},
    /// Run this config (a no-op when it is already running), or re-read the
    /// saved one when none. With a config, `remote` and `log_level` replace
    /// the tunnel's: no `remote` stops background refresh. `rules` replaces
    /// the personal rules; connections to domains whose route changed close.
    #[serde(rename_all = "camelCase")]
    Reload {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remote: Option<RemoteProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        log_level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rules: Option<Vec<PersonalRule>>,
    },
    /// The remote profile the tunnel last downloaded itself, if any.
    Profile {},
    /// Delete the extension's files (cache, rule-sets, logs, downloaded
    /// profile) before the app stops the tunnel and removes its configuration.
    Erase {},
}

/// `SbrResponse`.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Response {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Group>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<Stats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections: Option<Connections>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Group {
    pub tag: String,
    /// `selector` (picked by hand) or `urltest` (picks the fastest itself).
    #[serde(rename = "type")]
    pub kind: String,
    pub selected: String,
    /// The leaf outbound traffic resolves to through nested groups.
    pub now: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<u32>,
    pub members: Vec<Member>,
}

impl Group {
    pub fn selectable(&self) -> bool {
        self.kind == "selector"
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Member {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// Last measured latency in milliseconds; none when untested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<u32>,
    /// Dropped by failover, with why and seconds until it is retried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_in: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Connections {
    /// Every open connection; `connections` lists at most 200 of them.
    pub total: u64,
    /// Bytes since start, including closed connections.
    pub upload_total: u64,
    pub download_total: u64,
    pub connections: Vec<Connection>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Connection {
    pub id: String,
    pub network: String,
    pub inbound: String,
    pub source: String,
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(rename = "protocol", default, skip_serializing_if = "Option::is_none")]
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

/// A point in time as Swift's `Date` encodes it: seconds since
/// 2001-01-01 00:00:00 UTC.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct Date(pub f64);

impl Date {
    /// 2001-01-01 00:00:00 UTC in Unix seconds.
    const REFERENCE: f64 = 978_307_200.0;

    pub fn now() -> Self {
        Self::from(SystemTime::now())
    }

    pub fn to_system_time(self) -> SystemTime {
        let unix = self.0 + Self::REFERENCE;
        if unix >= 0.0 {
            UNIX_EPOCH + Duration::from_secs_f64(unix)
        } else {
            UNIX_EPOCH - Duration::from_secs_f64(-unix)
        }
    }
}

impl From<SystemTime> for Date {
    fn from(t: SystemTime) -> Self {
        let unix = match t.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs_f64(),
            Err(e) => -e.duration().as_secs_f64(),
        };
        Date(unix - Self::REFERENCE)
    }
}

/// A remote profile the tunnel keeps fresh by itself (`SbrRemoteProfile`).
/// The URL usually carries credentials: never log it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteProfile {
    pub url: String,
    /// sing-box's `auto_update_interval`: 60 by default.
    pub refresh_minutes: i64,
    /// When the config handed to the tunnel was downloaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Date>,
}

/// A remote profile as the tunnel downloaded and validated it
/// (`SbrProfileSnapshot`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProfileSnapshot {
    pub url: String,
    pub text: String,
    pub updated: Date,
}

impl ProfileSnapshot {
    /// The Keychain item the tunnel keeps it in, next to the stored profile.
    pub const ACCOUNT: &'static str = "tunnel.snapshot";
}

/// A route the user keeps on top of whatever profile runs: these domains go
/// through `outbound` (`SbrPersonalRule`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct PersonalRule {
    /// A UUID, as Swift writes it (upper case).
    pub id: String,
    /// What a rule made from a template is called; none for a single domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub domains: Vec<String>,
    /// Match the domains and their subdomains (`domain_suffix`), or the
    /// domains exactly (`domain`).
    pub subdomains: bool,
    /// An outbound or group tag in the profile.
    pub outbound: String,
    pub enabled: bool,
}

/// `providerConfiguration["stored"]` (`SbrStoredProfile`): which Keychain
/// item holds the tunnel's profile. Nothing secret, so the VPN preferences
/// (which the system keeps on disk) carry no server or credential.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredProfile {
    pub access_group: String,
    pub id: String,
    /// For a remote profile: its refresh interval and when the stored config
    /// was downloaded.
    pub refresh_minutes: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Date>,
}

impl StoredProfile {
    /// The Keychain account of its `ProfileSecret`.
    pub fn account(&self) -> String {
        format!("profile.{}", self.id)
    }
}

/// What makes a profile usable (`SbrProfileSecret`): the config and the link
/// it came from, which is itself a bearer credential.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProfileSecret {
    /// None while a remote profile waits to be downloaded again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Keys the tunnel reads from `NETunnelProviderProtocol.providerConfiguration`
/// (`SbrProviderKey`).
pub mod provider_key {
    /// JSON-encoded `StoredProfile`: the config, and the remote URL it is
    /// refreshed from, are read from the Keychain.
    pub const STORED: &str = "stored";
    /// Inline sing-box JSON, for a provider that cannot reach the app's
    /// Keychain, such as a macOS system extension, which runs as root.
    pub const CONFIG: &str = "config";
    /// The tun inbound's `stack`, overriding the profile's.
    pub const TUN_STACK: &str = "tunStack";
    /// App Group identifier whose container holds `config.json`.
    pub const APP_GROUP: &str = "appGroup";
    /// JSON-encoded `RemoteProfile`: the URL `config` came from.
    pub const REMOTE: &str = "remote";
    /// Replaces the config's `log.level`.
    pub const LOG_LEVEL: &str = "logLevel";
    /// JSON-encoded `[PersonalRule]`.
    pub const PERSONAL_RULES: &str = "personalRules";
}

/// Keys of the options passed to `startVPNTunnel(options:)` (`SbrStartOption`).
pub mod start_option {
    /// Delete the extension's files and stop without connecting.
    pub const ERASE: &str = "sbrErase";
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
            s(Request::CloseConnection { id: "a".into() }),
            r#"{"closeConnection":{"id":"a"}}"#
        );
        assert_eq!(
            s(Request::Reload {
                config: None,
                remote: None,
                log_level: Some("debug".into()),
                rules: None
            }),
            r#"{"reload":{"logLevel":"debug"}}"#
        );
    }

    #[test]
    fn requests_decode_from_swift() {
        let r: Request = serde_json::from_str(
            r#"{"reload":{"config":"{}","remote":{"url":"https:\/\/x.example\/p","refreshMinutes":60,
                "updated":784000000.5},"rules":[{"id":"6B1A5C9E-0000-4000-8000-000000000001",
                "domains":["example.com"],"subdomains":true,"outbound":"proxy","enabled":true}]}}"#,
        )
        .unwrap();
        let Request::Reload {
            config,
            remote,
            log_level,
            rules,
        } = r
        else {
            panic!("not a reload")
        };
        assert_eq!(config.as_deref(), Some("{}"));
        let remote = remote.unwrap();
        assert_eq!(remote.url, "https://x.example/p");
        assert_eq!(remote.updated, Some(Date(784000000.5)));
        assert_eq!(log_level, None);
        assert_eq!(rules.unwrap()[0].outbound, "proxy");
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"erase":{}}"#).unwrap(),
            Request::Erase {}
        );
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

    #[test]
    fn empty_response_is_an_empty_object() {
        assert_eq!(serde_json::to_string(&Response::default()).unwrap(), "{}");
    }

    #[test]
    fn dates_count_from_2001() {
        let t = UNIX_EPOCH + Duration::from_secs(978_307_200 + 10);
        assert_eq!(Date::from(t), Date(10.0));
        assert_eq!(Date(10.0).to_system_time(), t);
    }
}
