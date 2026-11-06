//! Values encoded the way Swift's `JSONEncoder` encodes them by default, so
//! items the Swift app wrote decode here and the reverse: a `Date` is a
//! number of seconds since 2001-01-01 UTC, and a `UUID` an uppercase string.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Seconds from the Unix epoch to Foundation's reference date.
const REFERENCE: f64 = 978_307_200.0;

/// Foundation's `Date`: seconds since 2001-01-01 00:00 UTC.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Default)]
pub struct Date(pub f64);

impl Date {
    pub fn now() -> Self {
        SystemTime::now().into()
    }

    /// Seconds from `self` until now; negative for a date in the future.
    pub fn age(self) -> f64 {
        Date::now().0 - self.0
    }
}

impl From<SystemTime> for Date {
    fn from(t: SystemTime) -> Self {
        let unix = match t.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs_f64(),
            Err(e) => -e.duration().as_secs_f64(),
        };
        Date(unix - REFERENCE)
    }
}

impl From<Date> for SystemTime {
    fn from(d: Date) -> Self {
        let unix = d.0 + REFERENCE;
        if unix >= 0.0 {
            UNIX_EPOCH + Duration::from_secs_f64(unix)
        } else {
            UNIX_EPOCH - Duration::from_secs_f64(-unix)
        }
    }
}

impl Serialize for Date {
    /// `JSONEncoder` writes a whole number of seconds without a fraction.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0.fract() == 0.0 && self.0.abs() < 9.0e15 {
            s.serialize_i64(self.0 as i64)
        } else {
            s.serialize_f64(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Date {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        f64::deserialize(d).map(Date)
    }
}

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
