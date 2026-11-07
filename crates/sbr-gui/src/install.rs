//! The VPN configuration the app installs for the tunnel: TunnelModel's
//! install, forgetActive and erase (apple/App/App/TunnelModel.swift), the
//! on-demand rules of AutoConnect.swift, and the settings that shape them.
//!
//! Settings live in the user defaults under the Swift app's keys, so an
//! existing install keeps them. The configuration carries what the Swift
//! tunnel extension reads from `providerConfiguration` (SbrKit's
//! `SbrProviderKey`): which Keychain item holds the profile, the personal
//! rules, the TCP stack and the log level.

#[cfg(target_os = "macos")]
mod sysext;

use std::rc::Rc;
use std::time::{Duration, Instant};

use koan_kit::app::*;
use objc2_foundation::{NSArray, NSData, NSString, NSUserDefaults};

use crate::ne::{Configuration, Manager, ProviderValue, Status};
use crate::profile::{RemoteProfile, StoredProfile};
use crate::profiles::Profiles;
use crate::proto::Request;
use crate::rules::{self, PersonalRule};
use crate::swift::Uuid;
use crate::tunnel::Tunnel;

/// The user's choices about the tunnel, as the Swift app stored them.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    /// "Block traffic outside the tunnel"; none follows the profile's
    /// `strict_route`.
    pub strict: Option<bool>,
    /// Under `strict`, let local-network traffic bypass the tunnel.
    pub allow_local_network: bool,
    /// Connect on demand everywhere but `trusted_networks`.
    pub auto_connect: bool,
    /// Wi-Fi names, matched exactly.
    pub trusted_networks: Vec<String>,
    /// sbr's userspace TCP stack rather than the kernel's.
    pub userspace_tcp: bool,
    /// Debug-level engine logs.
    pub verbose: bool,
    pub rules: Vec<PersonalRule>,
}

const STRICT: &str = "strict";
const ALLOW_LOCAL_NETWORK: &str = "allowLocalNetwork";
const AUTO_CONNECT: &str = "autoConnect";
const TRUSTED_NETWORKS: &str = "trustedNetworks";
const USERSPACE_TCP: &str = "tcpStackUserspace";
const VERBOSE: &str = "verbose";
const PERSONAL_RULES: &str = "personalRules";

impl Default for Settings {
    fn default() -> Self {
        Settings {
            strict: None,
            allow_local_network: false,
            auto_connect: false,
            trusted_networks: Vec::new(),
            userspace_tcp: true,
            verbose: false,
            rules: Vec::new(),
        }
    }
}

impl Settings {
    fn load() -> Self {
        let d = NSUserDefaults::standardUserDefaults();
        let key = |k: &str| NSString::from_str(k);
        let has = |k: &str| d.objectForKey(&key(k)).is_some();
        Settings {
            strict: has(STRICT).then(|| d.boolForKey(&key(STRICT))),
            allow_local_network: d.boolForKey(&key(ALLOW_LOCAL_NETWORK)),
            auto_connect: d.boolForKey(&key(AUTO_CONNECT)),
            trusted_networks: d
                .stringArrayForKey(&key(TRUSTED_NETWORKS))
                .map(|a| a.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default(),
            userspace_tcp: !has(USERSPACE_TCP) || d.boolForKey(&key(USERSPACE_TCP)),
            verbose: d.boolForKey(&key(VERBOSE)),
            rules: rules::decode(d.dataForKey(&key(PERSONAL_RULES)).map(|d| d.to_vec()).as_deref()),
        }
    }

    fn save(&self) {
        let d = NSUserDefaults::standardUserDefaults();
        let key = |k: &str| NSString::from_str(k);
        match self.strict {
            Some(s) => d.setBool_forKey(s, &key(STRICT)),
            None => d.removeObjectForKey(&key(STRICT)),
        }
        d.setBool_forKey(self.allow_local_network, &key(ALLOW_LOCAL_NETWORK));
        d.setBool_forKey(self.auto_connect, &key(AUTO_CONNECT));
        d.setBool_forKey(self.userspace_tcp, &key(USERSPACE_TCP));
        d.setBool_forKey(self.verbose, &key(VERBOSE));
        let networks: Vec<_> = self.trusted_networks.iter().map(|s| NSString::from_str(s)).collect();
        let networks = NSArray::from_retained_slice(&networks);
        let rules = NSData::with_bytes(&rules::encode(&self.rules));
        unsafe {
            d.setObject_forKey(Some(&networks), &key(TRUSTED_NETWORKS));
            d.setObject_forKey(Some(&rules), &key(PERSONAL_RULES));
        }
    }

    fn erase() {
        let d = NSUserDefaults::standardUserDefaults();
        for k in [
            STRICT,
            ALLOW_LOCAL_NETWORK,
            AUTO_CONNECT,
            TRUSTED_NETWORKS,
            USERSPACE_TCP,
            VERBOSE,
            PERSONAL_RULES,
        ] {
            d.removeObjectForKey(&NSString::from_str(k));
        }
    }
}

/// The active profile as the VPN configuration names it.
#[derive(Clone, Debug, PartialEq, Default)]
struct Active {
    config: Option<String>,
    remote: Option<RemoteProfile>,
    stored: Option<StoredProfile>,
}

/// What the configuration lost, for whoever keeps something from it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VpnEvent {
    /// The active profile was deleted, or everything erased: its logs go.
    ForgotActive,
}

impl EventEmitter<VpnEvent> for Vpn {}

/// Whether this build's tunnel is a system extension, which runs as root
/// outside the user's Keychain and must be activated before each install.
fn system_extension() -> bool {
    #[cfg(target_os = "macos")]
    return sysext::enabled();
    #[cfg(not(target_os = "macos"))]
    false
}

pub struct Vpn {
    pub settings: Settings,
    pub error: Option<String>,
    /// The system extension waits for the user to allow it in System
    /// Settings. Always false outside the Developer ID build.
    pub needs_approval: bool,
    /// The profile's `strict_route`, which `strict` follows until set.
    profile_strict: bool,
    active: Active,
    /// The last install failed part-way, so the saved configuration may
    /// name an older profile; the next connect saves it again.
    install_failed: bool,
    tunnel: Entity<Tunnel>,
    profiles: Entity<Profiles>,
    demo: bool,
    _observe: Subscription,
}

impl Vpn {
    pub fn new(tunnel: Entity<Tunnel>, profiles: Entity<Profiles>, cx: &mut Context<Self>) -> Self {
        let demo = std::env::var_os("SBR_GUI_DEMO").is_some();
        let _observe = cx.observe(&profiles, |vpn, _, cx| vpn.apply(cx));
        let this = cx.weak_entity();
        tunnel.update(cx, |t, _| {
            // Called while the tunnel is being updated, which `set_on` reads.
            t.on_set_on = Some(Rc::new(move |on, cx: &mut App| {
                let this = this.clone();
                cx.defer(move |cx| {
                    let _ = this.update(cx, |vpn, cx| vpn.set_on(on, cx));
                });
            }))
        });
        let mut vpn = Vpn {
            settings: if demo { Settings::default() } else { Settings::load() },
            error: None,
            profile_strict: false,
            active: Active::default(),
            install_failed: false,
            tunnel,
            profiles,
            demo,
            needs_approval: false,
            _observe,
        };
        #[cfg(target_os = "macos")]
        if system_extension() {
            let mut changes = sysext::watch();
            cx.spawn(async move |this, cx| {
                use futures::StreamExt as _;
                while let Some(error) = changes.next().await {
                    let alive = this.update(cx, |vpn, cx| vpn.approval_changed(error, cx));
                    if alive.is_err() {
                        return;
                    }
                }
            })
            .detach();
        }
        vpn.apply(cx);
        vpn
    }

    /// The user allowed the extension, or it is waiting for them to; with
    /// the error a request then failed with. The approval message goes once
    /// it no longer applies.
    #[cfg(target_os = "macos")]
    fn approval_changed(&mut self, error: Option<String>, cx: &mut Context<Self>) {
        self.needs_approval = sysext::awaiting_approval();
        if let Some(e) = error {
            self.error = Some(e);
        } else if !self.needs_approval && self.error.as_deref() == Some(sysext::APPROVAL_NEEDED) {
            self.error = None;
        }
        cx.notify();
    }

    /// Opens System Settings where the user allows the system extension.
    pub fn open_approval_settings(&self) {
        #[cfg(target_os = "macos")]
        sysext::open_settings();
    }

    pub fn strict(&self) -> bool {
        self.settings.strict.unwrap_or(self.profile_strict)
    }

    /// Change the settings, keep them, and save the configuration so the
    /// next connect uses them. `on_demand` arms or disarms on-demand rules.
    pub fn update_settings(&mut self, on_demand: Option<bool>, cx: &mut Context<Self>, f: impl FnOnce(&mut Settings)) {
        if self.store(cx, f) && (self.tunnel.read(cx).manager().is_some() || on_demand.is_some()) {
            self.install(on_demand, cx).detach();
        }
    }

    /// Change and keep the settings; whether they changed.
    fn store(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&mut Settings)) -> bool {
        let before = self.settings.clone();
        f(&mut self.settings);
        if self.settings == before {
            return false;
        }
        if !self.demo {
            self.settings.save();
        }
        cx.notify();
        true
    }

    pub fn remove_rule(&mut self, id: String, cx: &mut Context<Self>) {
        self.update_settings(None, cx, |s| s.rules.retain(|r| r.id != id));
        self.reload_running(cx);
    }

    /// Outbounds a personal rule can name in the active profile.
    /// The active profile's selector groups and their members, which a
    /// personal rule can route through.
    pub fn route_groups(&self) -> Vec<(String, Vec<String>)> {
        let demo = self.demo.then_some(crate::demo::CONFIG);
        self.active
            .config
            .as_deref()
            .or(demo)
            .map(rules::selector_groups)
            .unwrap_or_default()
    }

    /// Route `domain` and its subdomains through `outbound`, replacing any
    /// rule for the same domain. Checked against the active profile first.
    pub fn add_rule(&mut self, domain: &str, outbound: String, cx: &mut Context<Self>) {
        let Some(domain) = rules::normalize(domain) else {
            return self.fail("not a domain".into(), cx);
        };
        let mut next: Vec<PersonalRule> = self
            .settings
            .rules
            .iter()
            .filter(|r| r.domains != [domain.clone()])
            .cloned()
            .collect();
        next.insert(0, PersonalRule::new(domain, outbound));
        if let Some(config) = &self.active.config
            && let Err(problem) = sbr_apple::app::check(&rules::apply(&next, config).0)
        {
            return self.fail(problem, cx);
        }
        self.update_settings(None, cx, |s| s.rules = next);
        self.reload_running(cx);
    }

    /// Debug-level engine logs, applied to a running tunnel at once.
    pub fn set_verbose(&mut self, on: bool, cx: &mut Context<Self>) {
        self.update_settings(None, cx, |s| s.verbose = on);
        self.reload_running(cx);
    }

    /// The TCP stack, applied by reconnecting a running tunnel.
    pub fn set_userspace_tcp(&mut self, on: bool, cx: &mut Context<Self>) {
        if !self.store(cx, |s| s.userspace_tcp = on) || self.tunnel.read(cx).manager().is_none() {
            return;
        }
        let install = self.install(None, cx);
        let tunnel = self.tunnel.clone();
        cx.spawn(async move |_, cx| {
            let _ = install.await;
            let m = tunnel.read_with(cx, |t, _| t.manager().filter(|_| t.status.is_on()));
            if let Some(m) = m {
                m.stop();
                cx.background_executor().timer(Duration::from_millis(1500)).await;
                let _ = m.start();
            }
        })
        .detach();
    }

    /// The active profile changed: point the configuration at it, so a
    /// restart uses it, and hand a running tunnel the new profile.
    fn apply(&mut self, cx: &mut Context<Self>) {
        let p = self.profiles.read(cx);
        let next = Active {
            config: p.active_text.clone(),
            remote: p.active_remote(),
            stored: p.active_stored(),
        };
        if next == self.active {
            return;
        }
        self.profile_strict = next.config.as_deref().is_some_and(sbr_apple::app::strict_route);
        self.active = next;
        cx.notify();
        if self.active.config.is_none() || self.tunnel.read(cx).manager().is_none() {
            return;
        }
        let install = self.install(None, cx);
        cx.spawn(async move |this, cx| {
            if let Err(e) = install.await {
                let _ = this.update(cx, |vpn, cx| vpn.fail(e, cx));
            }
            let _ = this.update(cx, |vpn, cx| vpn.reload_running(cx));
        })
        .detach();
    }

    /// Hand a running tunnel the profile, log level and rules.
    fn reload_running(&mut self, cx: &mut Context<Self>) {
        let tunnel = self.tunnel.read(cx);
        let (Some(m), Status::On) = (tunnel.manager(), tunnel.status) else {
            return;
        };
        if self.active.config.is_none() {
            return;
        }
        let request = Request::Reload {
            config: self.active.config.clone(),
            remote: self.active.remote.clone(),
            log_level: self.log_level(),
            rules: Some(self.settings.rules.clone()),
        };
        let tunnel = self.tunnel.clone();
        cx.spawn(async move |this, cx| {
            let r = m.send(&request).await;
            match r {
                Ok(r) => tunnel.update(cx, |t, cx| {
                    if let Some(groups) = r.groups {
                        t.groups = groups;
                    }
                    cx.notify();
                }),
                Err(e) => {
                    let _ = this.update(cx, |vpn, cx| vpn.fail(e, cx));
                }
            }
        })
        .detach();
    }

    fn log_level(&self) -> Option<String> {
        self.settings.verbose.then(|| "debug".to_owned())
    }

    fn fail(&mut self, e: String, cx: &mut Context<Self>) {
        self.error = Some(e);
        cx.notify();
    }

    pub fn dismiss_error(&mut self, cx: &mut Context<Self>) {
        self.error = None;
        cx.notify();
    }

    /// What the tunnel reads from `providerConfiguration`.
    fn provider(&self) -> Result<Vec<(&'static str, ProviderValue)>, String> {
        let mut pc = Vec::new();
        if system_extension() {
            // A system extension runs as root, outside the user's Keychain:
            // the config travels inline.
            pc.push((
                "config",
                ProviderValue::String(self.active.config.clone().unwrap_or_default()),
            ));
            if let Some(remote) = &self.active.remote {
                pc.push(("remote", ProviderValue::Data(json(remote)?)));
            }
        } else {
            let stored = self
                .active
                .stored
                .as_ref()
                .ok_or("the profile is not in the Keychain")?;
            pc.push(("stored", ProviderValue::Data(json(stored)?)));
        }
        if let Some(level) = self.log_level() {
            pc.push(("logLevel", ProviderValue::String(level)));
        }
        pc.push((
            "personalRules",
            ProviderValue::Data(rules::encode(&self.settings.rules)),
        ));
        let stack = if self.settings.userspace_tcp {
            "gvisor"
        } else {
            "system"
        };
        pc.push(("tunStack", ProviderValue::String(stack.into())));
        Ok(pc)
    }

    /// Save the VPN configuration. `on_demand` arms or disarms on-demand
    /// rules; none keeps what a manual connect or disconnect last left, and
    /// arms it while the tunnel is on.
    fn install(&mut self, on_demand: Option<bool>, cx: &mut Context<Self>) -> Task<Result<(), String>> {
        if self.demo {
            return Task::ready(Ok(()));
        }
        if self.active.config.is_none() {
            return Task::ready(Err("no profile selected".into()));
        }
        let Some(bundle_id) = crate::ne::tunnel_bundle_id() else {
            return Task::ready(Err("this build names no tunnel extension".into()));
        };
        let provider = match self.provider() {
            Ok(p) => p,
            Err(e) => return Task::ready(Err(e)),
        };
        let tunnel = self.tunnel.read(cx);
        let existing = tunnel.manager();
        let is_on = tunnel.status.is_on();
        let strict = self.strict();
        let s = self.settings.clone();
        self.install_failed = true;
        let tunnel = self.tunnel.clone();
        cx.spawn(async move |this, cx| {
            #[cfg(target_os = "macos")]
            if system_extension() {
                let activated = sysext::activate(&bundle_id).await;
                let _ = this.update(cx, |vpn, cx| {
                    vpn.needs_approval = sysext::awaiting_approval();
                    cx.notify();
                });
                activated?;
            }
            let fresh = existing.is_none();
            let m = existing.unwrap_or_else(|| Rc::new(Manager::create()));
            if !fresh {
                // Another process (Settings, a control) may have changed it.
                let _ = m.reload().await;
            }
            // Under `strict`, on demand also restarts a tunnel the system
            // killed rather than leaving traffic outside it.
            let rules = if s.auto_connect {
                Some(s.trusted_networks.clone())
            } else if strict {
                Some(Vec::new())
            } else {
                None
            };
            // A first install arms auto-connect, which the user asked for;
            // strict alone arms on demand only once the tunnel is on.
            let armed = m.on_demand_enabled() || is_on || (s.auto_connect && fresh);
            m.configure(&Configuration {
                bundle_id,
                provider,
                leak_protection: strict,
                allow_local_network: s.allow_local_network,
                on_demand: rules,
                on_demand_enabled: on_demand.unwrap_or(armed),
            });
            m.save().await?;
            // A freshly saved configuration must be loaded before it starts.
            m.reload().await?;
            if fresh {
                tunnel.update(cx, |t, cx| t.adopt(m, cx));
            }
            this.update(cx, |vpn, _| vpn.install_failed = false)
                .map_err(|e| e.to_string())
        })
    }

    /// Connect or disconnect by hand. Connecting installs the configuration
    /// first when there is none or the last install failed. Disconnecting
    /// disarms on demand, so it stays off until the next connect.
    fn set_on(&mut self, on: bool, cx: &mut Context<Self>) {
        let needs_install = self.tunnel.read(cx).manager().is_none() || (on && self.install_failed);
        let install = needs_install.then(|| self.install(None, cx));
        let tunnel = self.tunnel.clone();
        cx.spawn(async move |this, cx| {
            let r: Result<(), String> = async {
                if let Some(install) = install {
                    install.await?;
                }
                let m = tunnel
                    .read_with(cx, |t, _| t.manager())
                    .ok_or("choose a profile first")?;
                if on {
                    let auto = m.has_on_demand_rules();
                    if !m.is_enabled() || m.on_demand_enabled() != auto {
                        m.set_enabled(true);
                        m.set_on_demand_enabled(auto);
                        m.save().await?;
                        m.reload().await?;
                    }
                    m.start()
                } else {
                    if m.on_demand_enabled() {
                        m.set_on_demand_enabled(false);
                        m.save().await?;
                    }
                    m.stop();
                    Ok(())
                }
            }
            .await;
            if let Err(e) = r {
                let _ = this.update(cx, |vpn, cx| vpn.fail(e, cx));
            }
        })
        .detach();
    }

    /// Bring the profiles up to date: take the running tunnel's own download
    /// of the active profile when it is newer, and download stale ones (the
    /// active one only while the tunnel is down, since the tunnel refreshes
    /// it itself).
    pub fn refresh_profiles(&mut self, cx: &mut Context<Self>) {
        let tunnel = self.tunnel.read(cx);
        let running = tunnel.status == Status::On;
        let manager = tunnel.manager().filter(|_| running);
        let profiles = self.profiles.clone();
        let except = running.then(|| profiles.read(cx).active_id).flatten();
        profiles.update(cx, |p, cx| p.refresh_stale(except, cx));
        let Some(m) = manager else {
            return;
        };
        cx.spawn(async move |_, cx| {
            if let Ok(Some(snapshot)) = m.send(&Request::Profile {}).await.map(|r| r.profile) {
                profiles.update(cx, |p, cx| p.adopt(snapshot, cx));
            }
        })
        .detach();
    }

    /// Delete a profile: when it was the active one, stop the tunnel and
    /// delete what the extension kept of it. The configuration stays, so
    /// the next profile needs no new system prompt.
    pub fn delete_profile(&mut self, id: Uuid, cx: &mut Context<Self>) {
        let was_active = self.profiles.update(cx, |p, cx| p.remove(id, cx));
        if !was_active {
            return;
        }
        crate::logs::remove_cache();
        cx.emit(VpnEvent::ForgotActive);
        if self.demo {
            return;
        }
        self.active = Active::default();
        let manager = self.tunnel.read(cx).manager();
        let tunnel = self.tunnel.clone();
        cx.spawn(async move |this, cx| {
            if let Some(m) = &manager {
                // Armed on demand would keep starting a tunnel whose profile
                // is gone.
                disarm(m).await;
                m.clear_profile();
                let _ = m.save().await;
                let _ = m.reload().await;
                if m.status().is_on() {
                    m.stop();
                }
                wait(m, cx, |s| matches!(s, Status::Off | Status::Invalid)).await;
            }
            let e = erase_tunnel_files(manager.as_deref(), cx).await;
            tunnel.update(cx, |t, cx| {
                t.groups.clear();
                cx.notify();
            });
            if let Err(e) = e {
                let _ = this.update(cx, |vpn, cx| vpn.fail(e, cx));
            }
        })
        .detach();
    }

    /// Remove the VPN configuration, every profile and everything the app
    /// remembers about them: settings, personal rules and trusted networks.
    /// A tunnel first deletes its own files.
    pub fn erase(&mut self, cx: &mut Context<Self>) {
        self.active = Active::default();
        self.settings = Settings::default();
        self.profile_strict = false;
        self.install_failed = false;
        if !self.demo {
            Settings::erase();
        }
        let r = self.profiles.update(cx, |p, cx| p.erase_all(cx));
        self.error = r.err();
        crate::logs::remove_cache();
        cx.emit(VpnEvent::ForgotActive);
        cx.notify();
        if self.demo {
            return;
        }
        let manager = self.tunnel.read(cx).manager();
        let tunnel = self.tunnel.clone();
        cx.spawn(async move |this, cx| {
            let mut errors = Vec::new();
            if let Err(e) = erase_tunnel_files(manager.as_deref(), cx).await {
                errors.push(e);
            }
            for m in Manager::load_all().await.unwrap_or_default() {
                m.stop();
                if let Err(e) = m.remove().await {
                    errors.push(e);
                }
            }
            tunnel.update(cx, |t, cx| t.forget(cx));
            // Launch at login, which the menu bar sets.
            #[cfg(target_os = "macos")]
            if let Err(e) = unregister_login_item() {
                errors.push(e);
            }
            if let Some(e) = errors.pop() {
                let _ = this.update(cx, |vpn, cx| vpn.fail(e, cx));
            }
        })
        .detach();
    }
}

/// Takes sbr out of the login items when it is in them, or waits there for
/// the user's approval.
#[cfg(target_os = "macos")]
fn unregister_login_item() -> Result<(), String> {
    use objc2_service_management::{SMAppService, SMAppServiceStatus};
    let service = unsafe { SMAppService::mainAppService() };
    let status = unsafe { service.status() };
    if status != SMAppServiceStatus::Enabled && status != SMAppServiceStatus::RequiresApproval {
        return Ok(());
    }
    unsafe { service.unregisterAndReturnError() }.map_err(|e| e.localizedDescription().to_string())
}

fn json(value: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

async fn disarm(m: &Manager) {
    if m.on_demand_enabled() {
        m.set_on_demand_enabled(false);
        let _ = m.save().await;
        let _ = m.reload().await;
    }
}

/// Poll the tunnel's status until `done`, for up to ten seconds; false on
/// timeout.
async fn wait(m: &Manager, cx: &AsyncApp, done: impl Fn(Status) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done(m.status()) {
        if Instant::now() > deadline {
            return false;
        }
        cx.background_executor().timer(Duration::from_millis(50)).await;
    }
    true
}

/// Have the extension delete its files (cache, rule-sets, logs). They live
/// in its own container, so a stopped tunnel is started with the erase
/// option, which deletes them and stops. On demand is disarmed first, or it
/// would start the tunnel again right after.
async fn erase_tunnel_files(m: Option<&Manager>, cx: &AsyncApp) -> Result<(), String> {
    let Some(m) = m else {
        return Ok(());
    };
    if m.status() == Status::On {
        return m.send(&Request::Erase {}).await.map(drop);
    }
    let failed = || "the tunnel's own files (cache, rule-sets, logs) could not be erased; try again".to_owned();
    if m.status() != Status::Off {
        return Err(failed());
    }
    disarm(m).await;
    m.start_erasing().map_err(|_| failed())?;
    // Starting is asynchronous: wait for it to begin (a cold extension
    // launch takes a while), then to end.
    let began = wait(m, cx, |s| s != Status::Off).await;
    let ended = wait(m, cx, |s| matches!(s, Status::Off | Status::Invalid)).await;
    if began && ended { Ok(()) } else { Err(failed()) }
}
