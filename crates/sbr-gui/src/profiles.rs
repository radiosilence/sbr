//! The profile store: ProfileStore in apple/App/App/Profiles.swift.
//!
//! Profiles live in the Keychain, in the access group the app shares with
//! its tunnel: an [`Index`] of names and refresh times under `index`, and per
//! profile a [`ProfileSecret`] holding its whole config and remote URL. The
//! tunnel reads the active profile's item itself ([`StoredProfile`]), so the
//! VPN preferences carry no credentials. Every config is checked with the
//! tunnel's own parser before it is stored.
//!
//! Remote profiles refresh when they are stale and the app asks
//! ([`Profiles::refresh_stale`]), with no timers of its own; the running
//! tunnel refreshes the active one itself.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use koan_kit::app::*;

use crate::keychain::{self, Keychain};
use crate::profile::{
    INDEX_ACCOUNT, Index, Profile, ProfileLink, ProfileSecret, ProfileSnapshot, RemoteProfile, StoredProfile,
    default_name, file_name, secret_account,
};
use crate::swift::{Date, Uuid};

/// Where items go: the Keychain, or memory for the demo.
enum Vault {
    Keychain(Keychain),
    Memory(RefCell<HashMap<String, Vec<u8>>>),
}

impl Vault {
    fn value<T: serde::de::DeserializeOwned>(&self, account: &str) -> Result<Option<T>, String> {
        match self {
            Vault::Keychain(k) => k.value(account),
            Vault::Memory(m) => Ok(m.borrow().get(account).and_then(|d| serde_json::from_slice(d).ok())),
        }
    }

    fn set_value(&self, value: &impl serde::Serialize, account: &str) -> Result<(), String> {
        match self {
            Vault::Keychain(k) => k.set_value(value, account),
            Vault::Memory(m) => {
                let data = serde_json::to_vec(value).map_err(|e| e.to_string())?;
                m.borrow_mut().insert(account.to_owned(), data);
                Ok(())
            }
        }
    }

    fn remove(&self, account: &str) -> Result<(), String> {
        match self {
            Vault::Keychain(k) => k.remove(account),
            Vault::Memory(m) => {
                m.borrow_mut().remove(account);
                Ok(())
            }
        }
    }

    fn remove_all(&self) -> Result<(), String> {
        match self {
            Vault::Keychain(k) => k.remove_all(),
            Vault::Memory(m) => {
                m.borrow_mut().clear();
                Ok(())
            }
        }
    }
}

pub struct Profiles {
    pub profiles: Vec<Profile>,
    pub active_id: Option<Uuid>,
    /// Remote profiles being downloaded again.
    pub refreshing: BTreeSet<Uuid>,
    /// A link being downloaded to add.
    pub adding: bool,
    /// The active profile's config, for the tunnel.
    pub active_text: Option<String>,
    /// What the tunnel's parser warns about in the active profile.
    pub active_warnings: Vec<String>,
    /// The last thing that went wrong, for the page to show.
    pub problem: Option<String>,
    /// The tunnel's Keychain access group; none in a build without one.
    group: Option<String>,
    vault: Vault,
}

impl Profiles {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let demo = std::env::var_os("SBR_GUI_DEMO").is_some();
        let group = if demo { None } else { keychain::app_group() };
        let vault = if demo {
            Vault::Memory(RefCell::default())
        } else {
            Vault::Keychain(Keychain::new(group.clone()))
        };
        let mut store = Profiles {
            profiles: Vec::new(),
            active_id: None,
            refreshing: BTreeSet::new(),
            adding: false,
            active_text: None,
            active_warnings: Vec::new(),
            problem: None,
            group,
            vault,
        };
        if demo {
            store.fill_demo();
        } else {
            store.load();
            store.restore(cx);
        }
        store
    }

    /// Made-up profiles for `SBR_GUI_DEMO`, held in memory.
    fn fill_demo(&mut self) {
        let config = r#"{"outbounds":[{"type":"selector","tag":"proxy","outbounds":["direct"]},{"type":"direct","tag":"direct"}]}"#;
        for (name, url, age) in [
            ("home", Some("https://profiles.example/sub/3f9a"), 600.0),
            ("travel", Some("https://vpn.example.net/p/77c1"), 86_400.0 * 3.0),
            ("lab", None, 0.0),
        ] {
            let mut p = Profile::new(name.into(), url.map(str::to_owned));
            p.updated = url.map(|_| Date(Date::now().0 - age));
            let _ = self.write(p, config);
        }
    }

    pub fn active(&self) -> Option<&Profile> {
        self.profiles.iter().find(|p| Some(p.id) == self.active_id)
    }

    /// The active profile's source, for the tunnel to refresh it from.
    pub fn active_remote(&self) -> Option<RemoteProfile> {
        let p = self.active()?;
        Some(RemoteProfile {
            url: p.remote_url.clone()?,
            refresh_minutes: p.auto_update_minutes,
            updated: p.updated,
        })
    }

    /// The Keychain item holding the active profile, which the tunnel reads.
    pub fn active_stored(&self) -> Option<StoredProfile> {
        let p = self.active()?;
        Some(StoredProfile {
            access_group: self.group.clone()?,
            id: p.id.to_string(),
            refresh_minutes: p.auto_update_minutes,
            updated: p.updated,
        })
    }

    fn load(&mut self) {
        let index = match self.vault.value::<Index>(INDEX_ACCOUNT) {
            Ok(Some(index)) => index,
            Ok(None) => return,
            Err(e) => {
                self.problem = Some(e);
                return;
            }
        };
        self.profiles = index
            .profiles
            .into_iter()
            .map(|mut p| {
                p.remote_url = self.secret(&p.id).ok().flatten().and_then(|s| s.url);
                p
            })
            .collect();
        self.active_id = index.active;
        let text = self.active().and_then(|p| self.text_of(p).ok());
        self.set_active_text(text);
    }

    /// Download again any remote profile whose config is missing.
    fn restore(&mut self, cx: &mut Context<Self>) {
        let missing: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| p.remote_url.is_some() && self.text_of(p).is_err())
            .cloned()
            .collect();
        for p in missing {
            self.download(p, false, cx);
        }
    }

    pub fn text_of(&self, profile: &Profile) -> Result<String, String> {
        self.secret(&profile.id)?
            .and_then(|s| s.config)
            .ok_or_else(|| "this profile has not been downloaded".into())
    }

    fn secret(&self, id: &Uuid) -> Result<Option<ProfileSecret>, String> {
        self.vault.value(&secret_account(id))
    }

    fn set_active_text(&mut self, text: Option<String>) {
        if text != self.active_text {
            self.active_warnings = text.as_deref().map(sbr_apple::app::warnings).unwrap_or_default();
            self.active_text = text;
        }
    }

    /// A pasted or typed link (`sing-box://`, `sbr://` or https), or a
    /// pasted JSON profile.
    pub fn add_input(&mut self, input: &str, cx: &mut Context<Self>) {
        let input = input.trim();
        if input.starts_with('{') {
            let r = self.add_text(input.to_owned(), "pasted".into());
            self.report(r.map(drop), cx);
            return;
        }
        let Some(link) = ProfileLink::parse(input) else {
            self.report(
                Err("that isn't a profile link. it should start with https://, sing-box:// or sbr://".into()),
                cx,
            );
            return;
        };
        let name = link.name.clone().unwrap_or_else(|| default_name(&link.url));
        // Adding a link already present updates that profile in place.
        let profile = match self
            .profiles
            .iter()
            .find(|p| p.remote_url.as_deref() == Some(&link.url))
        {
            Some(existing) => Profile {
                name: link.name.unwrap_or_else(|| existing.name.clone()),
                ..existing.clone()
            },
            None => Profile::new(name, Some(link.url)),
        };
        self.adding = true;
        self.download(profile, true, cx);
    }

    /// A profile file the user picked.
    pub fn add_file(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        let r = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|text| self.add_text(text, file_name(&path)));
        self.report(r.map(drop), cx);
    }

    pub fn add_text(&mut self, text: String, name: String) -> Result<Profile, String> {
        let profile = Profile::new(name, None);
        self.write(profile.clone(), &text)?;
        Ok(profile)
    }

    pub fn rename(&mut self, id: Uuid, name: &str, cx: &mut Context<Self>) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        let Some(p) = self.profiles.iter_mut().find(|p| p.id == id) else {
            return;
        };
        p.name = name.to_owned();
        let r = self.save_index();
        self.report(r, cx);
    }

    /// Make the profile the one the tunnel runs.
    pub fn activate(&mut self, id: Uuid, cx: &mut Context<Self>) {
        let r = self.activate_now(id);
        self.report(r, cx);
    }

    fn activate_now(&mut self, id: Uuid) -> Result<(), String> {
        let p = self.profiles.iter().find(|p| p.id == id).ok_or("no such profile")?;
        let text = self.text_of(p)?;
        self.active_id = Some(id);
        self.set_active_text(Some(text));
        self.save_index()
    }

    /// Delete a profile. True when it was the active one: the caller stops
    /// the tunnel and clears what the extension kept of it.
    pub fn remove(&mut self, id: Uuid, cx: &mut Context<Self>) -> bool {
        let _ = self.vault.remove(&secret_account(&id));
        self.profiles.retain(|p| p.id != id);
        let was_active = self.active_id == Some(id);
        if was_active {
            // The tunnel's own download of it.
            let _ = self.vault.remove(ProfileSnapshot::ACCOUNT);
            self.active_id = None;
            self.set_active_text(None);
        }
        let r = self.save_index();
        self.report(r, cx);
        was_active
    }

    /// Download one remote profile again.
    pub fn refresh(&mut self, id: Uuid, cx: &mut Context<Self>) {
        let Some(p) = self.profiles.iter().find(|p| p.id == id).cloned() else {
            return;
        };
        if p.remote_url.is_some() {
            self.download(p, true, cx);
        }
    }

    /// Refresh every stale remote profile but `except` (the active one while
    /// the tunnel refreshes it itself).
    pub fn refresh_stale(&mut self, except: Option<Uuid>, cx: &mut Context<Self>) {
        let stale: Vec<Uuid> = self
            .profiles
            .iter()
            .filter(|p| p.is_stale() && Some(p.id) != except && !self.refreshing.contains(&p.id))
            .map(|p| p.id)
            .collect();
        for id in stale {
            self.refresh(id, cx);
        }
    }

    /// Fetch `profile`'s URL off the main thread, then validate and store
    /// it. `report` shows a failure on the page.
    fn download(&mut self, profile: Profile, report: bool, cx: &mut Context<Self>) {
        let Some(url) = profile.remote_url.clone() else {
            return;
        };
        // The demo's profiles have nowhere to come from.
        if matches!(self.vault, Vault::Memory(_)) {
            return;
        }
        self.refreshing.insert(profile.id);
        cx.notify();
        cx.spawn(async move |this, cx| {
            let fetched = cx
                .background_spawn(async move { sbr_apple::app::fetch_profile(&url) })
                .await;
            let _ = this.update(cx, |store, cx| {
                store.refreshing.remove(&profile.id);
                store.adding = false;
                let r = fetched.and_then(|text| {
                    let mut p = profile;
                    p.updated = Some(Date::now());
                    store.write(p, &text)
                });
                if report {
                    store.report(r, cx);
                } else {
                    cx.notify();
                }
            });
        })
        .detach();
    }

    /// Store the tunnel's own download of the active profile when it is
    /// newer than the app's. Checked again before it is written.
    pub fn adopt(&mut self, snapshot: ProfileSnapshot, cx: &mut Context<Self>) {
        let Some(mut p) = self.active().cloned() else {
            return;
        };
        let newer = p.updated.is_none_or(|u| snapshot.updated > u);
        if p.remote_url.as_deref() != Some(&snapshot.url) || !newer {
            return;
        }
        p.updated = Some(snapshot.updated);
        if self.write(p, &snapshot.text).is_ok() {
            cx.notify();
        }
    }

    /// Delete every profile and everything else in the shared Keychain
    /// group, the tunnel's downloaded copy included.
    pub fn erase_all(&mut self, cx: &mut Context<Self>) -> Result<(), String> {
        self.vault.remove_all()?;
        self.profiles.clear();
        self.active_id = None;
        self.set_active_text(None);
        self.refreshing.clear();
        cx.notify();
        Ok(())
    }

    pub fn dismiss_problem(&mut self, cx: &mut Context<Self>) {
        self.problem = None;
        cx.notify();
    }

    fn report(&mut self, r: Result<(), String>, cx: &mut Context<Self>) {
        self.problem = r.err();
        cx.notify();
    }

    /// Check `text` with the tunnel's parser, then store it and the index.
    /// The first profile becomes the active one.
    fn write(&mut self, profile: Profile, text: &str) -> Result<(), String> {
        sbr_apple::app::check(text).map_err(|e| format!("this profile can't be used: {e}"))?;
        let secret = ProfileSecret {
            config: Some(text.to_owned()),
            url: profile.remote_url.clone(),
        };
        self.vault.set_value(&secret, &secret_account(&profile.id))?;
        let id = profile.id;
        match self.profiles.iter_mut().find(|p| p.id == id) {
            Some(p) => *p = profile,
            None => self.profiles.push(profile),
        }
        if self.active_id.is_none() {
            return self.activate_now(id);
        }
        if self.active_id == Some(id) {
            self.set_active_text(Some(text.to_owned()));
        }
        self.save_index()
    }

    fn save_index(&self) -> Result<(), String> {
        let index = Index {
            profiles: self.profiles.clone(),
            active: self.active_id,
        };
        self.vault.set_value(&index, INDEX_ACCOUNT)
    }
}
