//! `experimental.cache_file`: selector choices, the Clash mode, remote
//! rule-set contents, and generic tables for other subsystems (FakeIP, RDRC).
//!
//! Stored with `redb` rather than a rewritten JSON file because FakeIP and
//! RDRC entries are many small, frequent writes: redb updates one key per
//! transaction with crash safety, where a JSON file would be rewritten whole
//! each time. Selections and the mode commit durably; the high-churn tables
//! can use [`Table::put_lazy`], which skips the fsync (battery) and is made
//! durable by the next durable commit.
//!
//! Not file-compatible with sing-box's bbolt `cache.db`; give it a different
//! `path` if both cores share a directory.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition, TableError};
use tracing::warn;

/// A few hundred KB of page cache is plenty for this workload; redb's
/// default (1 GiB ceiling) would not fit an iOS network extension.
const CACHE_BYTES: usize = 512 * 1024;

pub struct CacheFile {
    db: Database,
    /// `cache_id` namespaces every table, like sing-box's per-ID buckets.
    prefix: String,
    pub store_fakeip: bool,
    pub store_dns: bool,
    /// `Some` when `store_rdrc` is on: how long a rejected response is remembered.
    pub rdrc_timeout: Option<Duration>,
}

/// A downloaded remote rule-set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedRuleSet {
    pub content: Vec<u8>,
    pub last_updated: SystemTime,
    pub etag: Option<String>,
    /// The URL it came from; a changed URL refetches.
    pub url: String,
}

impl SavedRuleSet {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let secs = self
            .last_updated
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let etag = self.etag.as_deref().unwrap_or("");
        let mut v = Vec::with_capacity(self.content.len() + self.url.len() + etag.len() + 16);
        v.extend_from_slice(&secs.to_be_bytes());
        for s in [etag.as_bytes(), self.url.as_bytes()] {
            v.extend_from_slice(&(s.len() as u32).to_be_bytes());
            v.extend_from_slice(s);
        }
        v.extend_from_slice(&self.content);
        v
    }

    pub(crate) fn decode(b: &[u8]) -> Option<Self> {
        let secs = u64::from_be_bytes(b.get(..8)?.try_into().ok()?);
        let mut rest = &b[8..];
        let mut field = || -> Option<String> {
            let n = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let s = String::from_utf8(rest.get(4..4 + n)?.to_vec()).ok()?;
            rest = &rest[4 + n..];
            Some(s)
        };
        let etag = field()?;
        let url = field()?;
        Some(Self {
            content: rest.to_vec(),
            last_updated: UNIX_EPOCH + Duration::from_secs(secs),
            etag: (!etag.is_empty()).then_some(etag),
            url,
        })
    }
}

/// A named key/value table inside the cache file.
pub struct Table<'a> {
    cache: &'a CacheFile,
    name: String,
}

impl Table<'_> {
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let def: TableDefinition<&str, &[u8]> = TableDefinition::new(&self.name);
        let tx = self.cache.db.begin_read().ok()?;
        let table = match tx.open_table(def) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return None,
            Err(e) => {
                warn!(table = %self.name, error = %e, "cache read");
                return None;
            }
        };
        table.get(key).ok()?.map(|v| v.value().to_vec())
    }

    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), String> {
        self.write(Durability::Immediate, |t| t.insert(key, value).map(drop))
    }

    /// Like `put`, without forcing it to disk now (FakeIP/RDRC churn).
    pub fn put_lazy(&self, key: &str, value: &[u8]) -> Result<(), String> {
        self.write(Durability::None, |t| t.insert(key, value).map(drop))
    }

    pub fn delete(&self, key: &str) -> Result<(), String> {
        self.write(Durability::Immediate, |t| t.remove(key).map(drop))
    }

    /// Every entry, for loading a whole table at start.
    pub fn entries(&self) -> Vec<(String, Vec<u8>)> {
        let def: TableDefinition<&str, &[u8]> = TableDefinition::new(&self.name);
        let Ok(tx) = self.cache.db.begin_read() else {
            return Vec::new();
        };
        let Ok(table) = tx.open_table(def) else {
            return Vec::new();
        };
        let Ok(iter) = table.iter() else {
            return Vec::new();
        };
        iter.filter_map(Result::ok)
            .map(|(k, v)| (k.value().to_owned(), v.value().to_vec()))
            .collect()
    }

    /// Drop every entry (e.g. a FakeIP reset).
    pub fn clear(&self) -> Result<(), String> {
        let def: TableDefinition<&str, &[u8]> = TableDefinition::new(&self.name);
        let tx = self.cache.db.begin_write().map_err(|e| e.to_string())?;
        tx.delete_table(def).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    fn write(
        &self,
        durability: Durability,
        f: impl FnOnce(&mut redb::Table<&str, &[u8]>) -> Result<(), redb::StorageError>,
    ) -> Result<(), String> {
        let def: TableDefinition<&str, &[u8]> = TableDefinition::new(&self.name);
        let mut tx = self.cache.db.begin_write().map_err(|e| e.to_string())?;
        tx.set_durability(durability).map_err(|e| e.to_string())?;
        {
            let mut t = tx.open_table(def).map_err(|e| e.to_string())?;
            f(&mut t).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }
}

const SELECTED: &str = "selected";
const MODE: &str = "clash_mode";
const RULE_SET: &str = "rule_set";

impl CacheFile {
    pub fn open(path: &Path, options: &sbr_config::CacheFileOptions) -> Result<Arc<Self>, String> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let db = Database::builder()
            .set_cache_size(CACHE_BYTES)
            .create(path)
            .map_err(|e| format!("open cache file {}: {e}", path.display()))?;
        Ok(Arc::new(Self {
            db,
            prefix: options
                .cache_id
                .as_deref()
                .map(|id| format!("{id}/"))
                .unwrap_or_default(),
            store_fakeip: options.store_fakeip,
            store_dns: options.store_dns,
            rdrc_timeout: options
                .store_rdrc
                .then(|| options.rdrc_timeout.unwrap_or(Duration::from_secs(7 * 24 * 3600))),
        }))
    }

    /// A table namespaced by `cache_id`, for other subsystems' state.
    ///
    /// TODO(dns): persist FakeIP when `store_fakeip` is set. Needs, in
    /// `sbr_dns::FakeIp`, an allocation observer (write `addr -> domain` with
    /// `table("fakeip").put_lazy`) and a restore entry point (bulk-insert
    /// `entries()` and the next offsets at start), plus engine access to the
    /// DNS router's FakeIP stores. `/cache/fakeip/flush` already clears the table.
    pub fn table(&self, name: &str) -> Table<'_> {
        Table {
            cache: self,
            name: format!("{}{name}", self.prefix),
        }
    }

    pub fn load_selected(&self, group: &str) -> Option<String> {
        String::from_utf8(self.table(SELECTED).get(group)?).ok()
    }

    pub fn store_selected(&self, group: &str, member: &str) {
        if let Err(e) = self.table(SELECTED).put(group, member.as_bytes()) {
            warn!(group, error = %e, "save selected outbound");
        }
    }

    pub fn load_mode(&self) -> Option<String> {
        String::from_utf8(self.table(MODE).get("mode")?).ok()
    }

    pub fn store_mode(&self, mode: &str) {
        if let Err(e) = self.table(MODE).put("mode", mode.as_bytes()) {
            warn!(error = %e, "save clash mode");
        }
    }

    pub fn load_rule_set(&self, tag: &str) -> Option<SavedRuleSet> {
        SavedRuleSet::decode(&self.table(RULE_SET).get(tag)?)
    }

    pub fn store_rule_set(&self, tag: &str, set: &SavedRuleSet) -> Result<(), String> {
        self.table(RULE_SET).put(tag, &set.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("sbr-cache-test-{}", std::process::id()));
        let path = dir.join("cache.db");
        let opts = sbr_config::CacheFileOptions {
            cache_id: Some("a".into()),
            ..Default::default()
        };
        let saved = SavedRuleSet {
            content: b"SRS\x02...".to_vec(),
            last_updated: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            etag: Some("\"x\"".into()),
            url: "https://example.org/a.srs".into(),
        };
        {
            let c = CacheFile::open(&path, &opts).unwrap();
            assert_eq!(c.load_selected("proxy"), None);
            c.store_selected("proxy", "b");
            c.store_mode("Global");
            c.store_rule_set("geo", &saved).unwrap();
            c.table("fakeip").put_lazy("198.18.0.1", b"a.com").unwrap();
            c.table("fakeip").put("198.18.0.2", b"b.com").unwrap();
        }
        let c = CacheFile::open(&path, &opts).unwrap();
        assert_eq!(c.load_selected("proxy").as_deref(), Some("b"));
        assert_eq!(c.load_mode().as_deref(), Some("Global"));
        assert_eq!(c.load_rule_set("geo"), Some(saved));
        assert_eq!(c.table("fakeip").entries().len(), 2);
        c.table("fakeip").clear().unwrap();
        assert!(c.table("fakeip").entries().is_empty());
        drop(c);
        // Another cache_id sees nothing.
        let other = sbr_config::CacheFileOptions {
            cache_id: Some("b".into()),
            ..Default::default()
        };
        let c = CacheFile::open(&path, &other).unwrap();
        assert_eq!(c.load_selected("proxy"), None);
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
