//! Remote rule-sets (sing-box `route/rule/rule_set_remote.go`).
//!
//! At engine construction each set is restored from its cached copy (the
//! cache file when enabled, else a file under `Settings::base_dir`), or from
//! `initial_path`. `Instance::start` downloads the ones still empty and fails
//! if it can't, like sing-box. Afterwards one task sleeps until the earliest
//! `update_interval` deadline (no periodic wakeups), refreshes what is due
//! with `If-None-Match`, and swaps the new contents into the router.
//! Failures keep the previous contents.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use sbr_config::{RemoteRuleSet, RuleSet, RuleSetSource};
use tracing::{debug, info, warn};

use crate::cache::{CacheFile, SavedRuleSet};
use crate::fetch::{HttpClient, Url};
use crate::{Engine, Settings};

const MAX_SIZE: usize = 64 << 20;

pub(crate) enum Store {
    Cache(Arc<CacheFile>),
    /// One file per rule-set.
    Dir(PathBuf),
}

impl Store {
    fn file(dir: &std::path::Path, tag: &str) -> PathBuf {
        let safe: String = tag
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        dir.join(format!("{safe}.cache"))
    }

    fn load(&self, tag: &str) -> Option<SavedRuleSet> {
        match self {
            Store::Cache(c) => c.load_rule_set(tag),
            Store::Dir(d) => SavedRuleSet::decode(&std::fs::read(Self::file(d, tag)).ok()?),
        }
    }

    fn save(&self, tag: &str, s: &SavedRuleSet) -> Result<(), String> {
        match self {
            Store::Cache(c) => c.store_rule_set(tag, s),
            Store::Dir(d) => {
                std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
                let path = Self::file(d, tag);
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, s.encode()).map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
            }
        }
    }
}

pub(crate) struct Remote {
    pub tag: String,
    pub cfg: RemoteRuleSet,
    state: Mutex<State>,
}

#[derive(Default, Clone)]
struct State {
    /// `None` until a download (or a cached download) is loaded.
    last_updated: Option<SystemTime>,
    etag: Option<String>,
    loaded: bool,
}

pub(crate) struct RemoteSets {
    pub sets: Vec<Remote>,
    store: Store,
    http: HttpClient,
}

impl RemoteSets {
    pub fn new(rule_sets: &[RuleSet], settings: &Settings, cache: Option<Arc<CacheFile>>, http: HttpClient) -> Self {
        let sets = rule_sets
            .iter()
            .filter_map(|rs| match &rs.source {
                RuleSetSource::Remote(r) => Some(Remote {
                    tag: rs.tag.clone(),
                    cfg: r.clone(),
                    state: Mutex::default(),
                }),
                _ => None,
            })
            .collect();
        let store = match cache {
            Some(c) => Store::Cache(c),
            None => Store::Dir(crate::resolve_path(settings, "rule-set-cache")),
        };
        Self { sets, store, http }
    }

    /// Restore cached or shipped copies into the router. Never touches the network.
    pub fn restore(&self, engine: &Engine, settings: &Settings) {
        for r in &self.sets {
            if let Some(saved) = self.store.load(&r.tag) {
                if saved.url != r.cfg.url {
                    info!(rule_set = %r.tag, "cached rule-set was downloaded from another URL, will refetch");
                } else {
                    match engine.apply_rule_set(&r.tag, &r.cfg, &saved.content) {
                        Ok(()) => {
                            let mut st = r.state.lock().unwrap();
                            st.last_updated = Some(saved.last_updated);
                            st.etag = saved.etag;
                            st.loaded = true;
                            continue;
                        }
                        Err(e) => warn!(rule_set = %r.tag, error = %e, "restore cached rule-set, will refetch"),
                    }
                }
            }
            if let Some(p) = &r.cfg.initial_path {
                let path = crate::resolve_path(settings, p);
                match std::fs::read(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|b| engine.apply_rule_set(&r.tag, &r.cfg, &b))
                {
                    Ok(()) => r.state.lock().unwrap().loaded = true,
                    Err(e) => warn!(rule_set = %r.tag, path = %path.display(), error = %e, "load initial rule-set"),
                }
            }
        }
    }

    /// Download every set that has nothing loaded yet.
    pub async fn initial(&self, engine: &Engine) -> Result<(), String> {
        for r in &self.sets {
            if !r.state.lock().unwrap().loaded {
                self.fetch(engine, r)
                    .await
                    .map_err(|e| format!("initial rule-set {}: {e}", r.tag))?;
            }
        }
        Ok(())
    }

    /// Fetch one set now and swap it in.
    pub async fn fetch(&self, engine: &Engine, r: &Remote) -> Result<(), String> {
        let url = Url::parse(&r.cfg.url).ok_or("invalid url")?;
        let via = match &r.cfg.download_detour {
            Some(t) => engine
                .outbound(t)
                .ok_or_else(|| format!("outbound not found: {t}"))?
                .clone(),
            None => engine.outbounds[engine.router.final_outbound()].clone(),
        };
        let st = r.state.lock().unwrap().clone();
        let etag = st.etag.filter(|_| st.loaded);
        let headers: Vec<(&str, &str)> = etag.iter().map(|e| ("if-none-match", e.as_str())).collect();
        debug!(rule_set = %r.tag, url = %r.cfg.url, via = via.tag(), "updating rule-set");
        let resp = self
            .http
            .get(via.as_ref(), &url, &headers, MAX_SIZE)
            .await
            .map_err(|e| e.to_string())?;
        let now = SystemTime::now();
        if resp.status == hyper::StatusCode::NOT_MODIFIED {
            r.state.lock().unwrap().last_updated = Some(now);
            if let Some(mut saved) = self.store.load(&r.tag) {
                saved.last_updated = now;
                let _ = self.store.save(&r.tag, &saved);
            }
            info!(rule_set = %r.tag, "update rule-set: not modified");
            return Ok(());
        }
        engine.apply_rule_set(&r.tag, &r.cfg, &resp.body)?;
        let etag = resp
            .headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        {
            let mut s = r.state.lock().unwrap();
            s.last_updated = Some(now);
            s.loaded = true;
            if etag.is_some() {
                s.etag.clone_from(&etag);
            }
        }
        let saved = SavedRuleSet {
            content: resp.body.to_vec(),
            last_updated: now,
            etag,
            url: r.cfg.url.clone(),
        };
        if let Err(e) = self.store.save(&r.tag, &saved) {
            warn!(rule_set = %r.tag, error = %e, "save rule-set cache");
        }
        info!(rule_set = %r.tag, "updated rule-set");
        Ok(())
    }

    fn next_due(&self, r: &Remote) -> SystemTime {
        match r.state.lock().unwrap().last_updated {
            Some(t) => t + r.cfg.update_interval,
            None => SystemTime::now(),
        }
    }

    /// The update loop. One timer, set to the earliest deadline.
    pub async fn run(self: Arc<Self>, engine: Arc<Engine>) {
        if self.sets.is_empty() {
            return;
        }
        loop {
            let next = self.sets.iter().map(|r| self.next_due(r)).min().expect("non-empty");
            let wait = next.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO);
            tokio::time::sleep(wait).await;
            let now = SystemTime::now();
            for r in &self.sets {
                if self.next_due(r) <= now
                    && let Err(e) = self.fetch(&engine, r).await
                {
                    warn!(rule_set = %r.tag, error = %e, "fetch rule-set");
                    // Try again at the next interval, like sing-box.
                    r.state.lock().unwrap().last_updated = Some(now);
                }
            }
        }
    }
}

impl Engine {
    /// Parse rule-set bytes and swap them into the router.
    pub(crate) fn apply_rule_set(&self, tag: &str, cfg: &RemoteRuleSet, data: &[u8]) -> Result<(), String> {
        let rules = sbr_config::parse_rule_set(data, cfg.format).map_err(|e| e.to_string())?;
        self.router.update_rule_set(tag, &rules).map_err(|e| e.to_string())
    }

    /// Refresh a remote rule-set now (e.g. on user request).
    pub async fn update_rule_set(&self, tag: &str) -> io::Result<()> {
        let sets = self
            .remote_sets
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no remote rule-sets"))?;
        let r = sets
            .sets
            .iter()
            .find(|r| r.tag == tag)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("rule-set not found: {tag}")))?;
        sets.fetch(self, r).await.map_err(io::Error::other)
    }
}
