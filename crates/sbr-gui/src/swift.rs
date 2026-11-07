//! Values encoded the way Swift's `JSONEncoder` encodes them by default, so
//! items the Swift app wrote decode here and the reverse: a `Date` is a
//! number of seconds since 2001-01-01 UTC, and a `UUID` an uppercase string.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Foundation's `Date`, shared with the tunnel.
pub use sbr_message::Date;

/// Foundation's `UUID`, written as `uuidString` writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid(pub uuid::Uuid);

impl Uuid {
    pub fn new() -> Self {
        Uuid(uuid::Uuid::new_v4())
    }
}

impl Default for Uuid {
    fn default() -> Self {
        Uuid::new()
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0.hyphenated().encode_upper(&mut uuid::Uuid::encode_buffer())
        )
    }
}

impl Serialize for Uuid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        uuid::Uuid::parse_str(&s).map(Uuid).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn dates_count_from_2001() {
        let d: Date = (UNIX_EPOCH + Duration::from_secs(978_307_200 + 60)).into();
        assert_eq!(d, Date(60.0));
        assert_eq!(serde_json::to_string(&Date(784_000_000.0)).unwrap(), "784000000");
        assert_eq!(serde_json::to_string(&Date(784_000_000.25)).unwrap(), "784000000.25");
        assert_eq!(serde_json::from_str::<Date>("784000000").unwrap(), Date(784_000_000.0));
        assert_eq!(
            SystemTime::from(Date(0.0)),
            UNIX_EPOCH + Duration::from_secs(978_307_200)
        );
    }

    #[test]
    fn uuids_are_uppercase() {
        let id: Uuid = serde_json::from_str(r#""e621e1f8-c36c-495a-93fc-0c247a3e6e5f""#).unwrap();
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            r#""E621E1F8-C36C-495A-93FC-0C247A3E6E5F""#
        );
    }
}
