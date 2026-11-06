//! What the app keeps about profiles, in the shapes the Swift app wrote to
//! the Keychain (apple/App/App/Profiles.swift, SbrKit's SbrKeychain.swift and
//! SbrMessage.swift), so an existing install keeps its profiles and the Swift
//! tunnel extension reads what this app writes. Field names, optional fields
//! left out when empty, and `Date` and `UUID` encodings all follow Swift's
//! synthesised `Codable` with a default `JSONEncoder`.
//!
//! URLs are kept as the text they were given in: Foundation's `URL` encodes
//! as its `absoluteString`, and normalising them here would make a link the
//! user adds again look like a different profile.

use serde::{Deserialize, Serialize};

use crate::swift::{Date, Uuid};

/// The Keychain account holding the [`Index`].
pub const INDEX_ACCOUNT: &str = "index";

/// sing-box's default remote-profile refresh interval.
pub const DEFAULT_REFRESH_MINUTES: i64 = 60;

/// One profile in the index. Its config and URL live in its own
/// [`ProfileSecret`] item.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    /// A bearer link, filled from the profile's secret on load. Never
    /// written into the index; read only from a pre-Keychain index.
    #[serde(rename = "remoteURL", default, skip_serializing)]
    pub remote_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Date>,
    pub auto_update_minutes: i64,
}

impl Profile {
    pub fn new(name: String, remote_url: Option<String>) -> Self {
        let updated = remote_url.is_some().then(Date::now);
        Profile {
            id: Uuid::new(),
            name,
            remote_url,
            updated,
            auto_update_minutes: DEFAULT_REFRESH_MINUTES,
        }
    }

    /// A remote profile not downloaded within its refresh interval.
    pub fn is_stale(&self) -> bool {
        if self.remote_url.is_none() {
            return false;
        }
        match self.updated {
            None => true,
            Some(u) => u.age() > self.auto_update_minutes as f64 * 60.0,
        }
    }

    /// The host only: profile URLs usually carry a secret in the path.
    pub fn host(&self) -> Option<String> {
        self.remote_url.as_deref().and_then(host)
    }
}

/// The profile list and which one the tunnel runs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Index {
    pub profiles: Vec<Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<Uuid>,
}

/// What makes a profile usable, and so what a seized device must not give
/// up: the config and the link it came from. `SbrProfileSecret`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ProfileSecret {
    /// None while a remote profile waits to be downloaded again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl ProfileSecret {
    pub fn account(id: &Uuid) -> String {
        format!("profile.{id}")
    }
}

/// `providerConfiguration["stored"]`: which Keychain item holds the
/// tunnel's profile, so the VPN preferences carry no credentials.
/// `SbrStoredProfile`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredProfile {
    pub access_group: String,
    /// The profile's `uuidString`.
    pub id: String,
    pub refresh_minutes: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Date>,
}

/// A remote profile the tunnel refreshes by itself. `SbrRemoteProfile`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteProfile {
    pub url: String,
    pub refresh_minutes: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Date>,
}

/// The tunnel's own download of the active remote profile.
/// `SbrProfileSnapshot`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProfileSnapshot {
    pub url: String,
    pub text: String,
    pub updated: Date,
}

impl ProfileSnapshot {
    /// The Keychain item the tunnel keeps it in.
    pub const ACCOUNT: &str = "tunnel.snapshot";
}

/// What a sing-box or sbr import link asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileLink {
    /// An https URL to a JSON profile.
    pub url: String,
    pub name: Option<String>,
}

impl ProfileLink {
    /// `sing-box://import-remote-profile?url=<encoded>#<name>`, the same
    /// under `sbr://`, or a bare https URL. Surrounding whitespace is
    /// ignored.
    pub fn parse(link: &str) -> Option<Self> {
        let link = link.trim();
        let parsed = url::Url::parse(link).ok()?;
        let name = parsed.fragment().map(decode);
        match parsed.scheme() {
            "sing-box" | "sbr" => {
                if parsed.host_str() != Some("import-remote-profile") {
                    return None;
                }
                // Percent-decoded as URLComponents does, leaving `+` alone.
                let raw = parsed.query()?.split('&').find_map(|item| {
                    let (k, v) = item.split_once('=').unwrap_or((item, ""));
                    (decode(k) == "url").then(|| decode(v))
                })?;
                let inner = url::Url::parse(&raw).ok()?;
                (inner.scheme() == "https").then_some(ProfileLink { url: raw, name })
            }
            "https" => Some(ProfileLink {
                url: link.to_owned(),
                name,
            }),
            _ => None,
        }
    }
}

/// The name a remote profile gets when its link gives none.
pub fn default_name(url: &str) -> String {
    let parsed = url::Url::parse(url).ok();
    if let Some(fragment) = parsed.as_ref().and_then(|u| u.fragment()).filter(|f| !f.is_empty()) {
        return decode(fragment);
    }
    parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .map_or_else(|| "profile".to_owned(), str::to_owned)
}

/// The name a profile file gets: its file name without the extension.
pub fn file_name(path: &std::path::Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "profile".to_owned())
}

fn host(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(str::to_owned)
}

fn decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An index as the Swift app writes it: `JSONEncoder` escapes slashes,
    /// writes dates as seconds since 2001 and UUIDs in uppercase.
    const SWIFT_INDEX: &str = r#"{"profiles":[{"id":"6B1F0B4C-2E0A-4C55-9D3B-8F1E2A3B4C5D","name":"home","updated":784000000.5,"autoUpdateMinutes":60},{"id":"0D3E4F5A-6B7C-4D8E-9F0A-1B2C3D4E5F60","name":"file","autoUpdateMinutes":60}],"active":"6B1F0B4C-2E0A-4C55-9D3B-8F1E2A3B4C5D"}"#;

    #[test]
    fn index_round_trips_with_swift() {
        let index: Index = serde_json::from_str(SWIFT_INDEX).unwrap();
        assert_eq!(index.profiles.len(), 2);
        assert_eq!(index.profiles[0].updated, Some(Date(784_000_000.5)));
        assert_eq!(index.profiles[1].updated, None);
        assert_eq!(index.active, Some(index.profiles[0].id));
        assert_eq!(serde_json::to_string(&index).unwrap(), SWIFT_INDEX);
    }

    #[test]
    fn index_never_carries_the_link() {
        // A pre-Keychain index held the URL; it is read, never written.
        let legacy = r#"{"profiles":[{"id":"6B1F0B4C-2E0A-4C55-9D3B-8F1E2A3B4C5D","name":"a","remoteURL":"https:\/\/x.example\/p","autoUpdateMinutes":30}]}"#;
        let index: Index = serde_json::from_str(legacy).unwrap();
        assert_eq!(index.profiles[0].remote_url.as_deref(), Some("https://x.example/p"));
        assert_eq!(index.active, None);
        let out = serde_json::to_string(&index).unwrap();
        assert!(!out.contains("remoteURL") && !out.contains("active"), "{out}");
    }

    #[test]
    fn secret_matches_swift() {
        let swift = r#"{"config":"{\"outbounds\":[]}","url":"https:\/\/x.example\/p?t=1"}"#;
        let s: ProfileSecret = serde_json::from_str(swift).unwrap();
        assert_eq!(s.url.as_deref(), Some("https://x.example/p?t=1"));
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"config":"{\"outbounds\":[]}","url":"https://x.example/p?t=1"}"#
        );
        let local = ProfileSecret {
            config: Some("{}".into()),
            url: None,
        };
        assert_eq!(serde_json::to_string(&local).unwrap(), r#"{"config":"{}"}"#);
        let id: Uuid = serde_json::from_str(r#""6b1f0b4c-2e0a-4c55-9d3b-8f1e2a3b4c5d""#).unwrap();
        assert_eq!(
            ProfileSecret::account(&id),
            "profile.6B1F0B4C-2E0A-4C55-9D3B-8F1E2A3B4C5D"
        );
    }

    #[test]
    fn provider_values_match_swift() {
        let stored = StoredProfile {
            access_group: "TEAM.cc.blit.sbr".into(),
            id: "6B1F0B4C-2E0A-4C55-9D3B-8F1E2A3B4C5D".into(),
            refresh_minutes: 60,
            updated: Some(Date(784_000_000.0)),
        };
        assert_eq!(
            serde_json::to_string(&stored).unwrap(),
            r#"{"accessGroup":"TEAM.cc.blit.sbr","id":"6B1F0B4C-2E0A-4C55-9D3B-8F1E2A3B4C5D","refreshMinutes":60,"updated":784000000}"#
        );
        let remote: RemoteProfile =
            serde_json::from_str(r#"{"url":"https:\/\/x.example\/p","refreshMinutes":60}"#).unwrap();
        assert_eq!(remote.updated, None);
        let snapshot: ProfileSnapshot =
            serde_json::from_str(r#"{"url":"https:\/\/x.example\/p","text":"{}","updated":5.25}"#).unwrap();
        assert_eq!(snapshot.updated, Date(5.25));
    }

    #[test]
    fn staleness() {
        let mut p = Profile::new("a".into(), Some("https://x.example/p".into()));
        assert!(!p.is_stale());
        p.updated = Some(Date(Date::now().0 - 61.0 * 60.0));
        assert!(p.is_stale());
        p.updated = None;
        assert!(p.is_stale());
        assert!(!Profile::new("b".into(), None).is_stale());
    }

    #[test]
    fn import_links() {
        let l = ProfileLink::parse(
            "sing-box://import-remote-profile?url=https%3A%2F%2Fx.example%2Fsub%3Ftoken%3Da%2Bb#My%20VPN",
        )
        .unwrap();
        assert_eq!(l.url, "https://x.example/sub?token=a+b");
        assert_eq!(l.name.as_deref(), Some("My VPN"));

        let l = ProfileLink::parse("  sbr://import-remote-profile?url=https://x.example/p  ").unwrap();
        assert_eq!(l.url, "https://x.example/p");
        assert_eq!(l.name, None);

        let l = ProfileLink::parse("https://x.example/p.json#work").unwrap();
        assert_eq!(l.url, "https://x.example/p.json#work");
        assert_eq!(l.name.as_deref(), Some("work"));

        // Kept as given: Foundation would not add the trailing slash.
        assert_eq!(
            ProfileLink::parse("https://x.example").unwrap().url,
            "https://x.example"
        );
    }

    #[test]
    fn rejected_links() {
        for link in [
            "http://x.example/p",
            "sing-box://import-remote-profile?url=http%3A%2F%2Fx.example",
            "sing-box://something-else?url=https%3A%2F%2Fx.example",
            "sing-box://import-remote-profile",
            "ftp://x.example/p",
            "not a link",
            "",
        ] {
            assert_eq!(ProfileLink::parse(link), None, "{link}");
        }
    }

    #[test]
    fn default_names() {
        assert_eq!(default_name("https://x.example/p#home"), "home");
        assert_eq!(default_name("https://x.example/p#"), "x.example");
        assert_eq!(default_name("https://x.example/p"), "x.example");
        assert_eq!(default_name("nonsense"), "profile");
        assert_eq!(file_name(std::path::Path::new("/a/b/work.json")), "work");
    }
}
