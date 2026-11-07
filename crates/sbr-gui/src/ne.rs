//! The installed VPN configuration and its packet tunnel, through
//! NetworkExtension: finding sbr's configuration, starting and stopping the
//! tunnel, following its status, and asking the running tunnel things.
//!
//! Completion handlers run on NetworkExtension's queues; each hands its
//! result to the awaiting task over a channel, so the objects themselves
//! stay on the main thread.

use block2::RcBlock;
use futures::channel::{mpsc, oneshot};
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_foundation::{
    NSArray, NSBundle, NSData, NSError, NSNotification, NSNotificationCenter, NSOperationQueue, NSString,
};
use objc2_network_extension::{
    NETunnelProviderManager, NETunnelProviderProtocol, NETunnelProviderSession, NEVPNStatus,
    NEVPNStatusDidChangeNotification,
};

use crate::proto::{Request, Response};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// No configuration installed yet.
    Invalid,
    Off,
    Connecting,
    On,
    Reasserting,
    Disconnecting,
}

impl Status {
    fn of(s: NEVPNStatus) -> Self {
        match s {
            NEVPNStatus::Disconnected => Status::Off,
            NEVPNStatus::Connecting => Status::Connecting,
            NEVPNStatus::Connected => Status::On,
            NEVPNStatus::Reasserting => Status::Reasserting,
            NEVPNStatus::Disconnecting => Status::Disconnecting,
            _ => Status::Invalid,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Status::Invalid => "not installed",
            Status::Off => "off",
            Status::Connecting => "connecting",
            Status::On => "on",
            Status::Reasserting => "reconnecting",
            Status::Disconnecting => "disconnecting",
        }
    }

    /// Up, or on its way up.
    pub fn is_on(self) -> bool {
        matches!(self, Status::On | Status::Connecting | Status::Reasserting)
    }
}

/// The tunnel extension's bundle identifier, from the app's Info.plist
/// (`SbrTunnelBundleIdentifier`), or `SBR_TUNNEL_BUNDLE_ID` for an
/// unbundled development run.
pub fn tunnel_bundle_id() -> Option<String> {
    if let Ok(id) = std::env::var("SBR_TUNNEL_BUNDLE_ID") {
        return Some(id);
    }
    let key = NSString::from_str("SbrTunnelBundleIdentifier");
    let value = NSBundle::mainBundle().objectForInfoDictionaryKey(&key)?;
    let value = value.downcast::<NSString>().ok()?;
    Some(value.to_string()).filter(|s| !s.is_empty())
}

/// sbr's VPN configuration.
pub struct Manager(Retained<NETunnelProviderManager>);

impl Manager {
    /// The saved configuration whose provider is `bundle_id`, if the app has
    /// installed one.
    pub async fn load(bundle_id: &str) -> Result<Option<Manager>, String> {
        let (tx, rx) = oneshot::channel();
        let tx = std::cell::Cell::new(Some(tx));
        let bundle_id = bundle_id.to_owned();
        // Matching happens in the handler, on NetworkExtension's queue; only
        // the matched manager, retained, crosses back.
        let block = RcBlock::new(move |all: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            let result = if let Some(error) = unsafe { error.as_ref() } {
                Err(error.localizedDescription().to_string())
            } else {
                let found = unsafe { all.as_ref() }.and_then(|all| {
                    all.iter().find(|m| {
                        unsafe { m.protocolConfiguration() }
                            .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok())
                            .and_then(|p| unsafe { p.providerBundleIdentifier() })
                            .is_some_and(|id| id.to_string() == bundle_id)
                    })
                });
                Ok(found.map(SendManager))
            };
            if let Some(tx) = tx.take() {
                let _ = tx.send(result);
            }
        });
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&block) };
        match rx.await {
            Ok(r) => r.map(|m| m.map(|m| Manager(m.0))),
            Err(_) => Err("NetworkExtension did not answer".into()),
        }
    }

    pub fn status(&self) -> Status {
        Status::of(unsafe { self.0.connection().status() })
    }

    pub fn start(&self) -> Result<(), String> {
        unsafe { self.0.connection().startVPNTunnelAndReturnError() }.map_err(|e| e.localizedDescription().to_string())
    }

    pub fn stop(&self) {
        unsafe { self.0.connection().stopVPNTunnel() }
    }

    /// Status changes, as they happen, until the receiver is dropped.
    pub fn statuses(&self) -> (mpsc::UnboundedReceiver<Status>, Observer) {
        let (tx, rx) = mpsc::unbounded();
        let connection = unsafe { self.0.connection() };
        let watched = connection.clone();
        let block = RcBlock::new(move |_: std::ptr::NonNull<NSNotification>| {
            let _ = tx.unbounded_send(Status::of(unsafe { watched.status() }));
        });
        let center = NSNotificationCenter::defaultCenter();
        let token = unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NEVPNStatusDidChangeNotification),
                Some(&connection),
                Some(&NSOperationQueue::mainQueue()),
                &block,
            )
        };
        (rx, Observer(token))
    }

    /// Ask the running tunnel something; fails when it is not running or
    /// does not answer.
    pub async fn send(&self, request: &Request) -> Result<Response, String> {
        let connection = unsafe { self.0.connection() };
        let session = connection
            .downcast::<NETunnelProviderSession>()
            .map_err(|_| "not a packet tunnel".to_string())?;
        let body = serde_json::to_vec(request).map_err(|e| e.to_string())?;
        let data = NSData::with_bytes(&body);
        let (tx, rx) = oneshot::channel::<Option<Vec<u8>>>();
        let tx = std::cell::Cell::new(Some(tx));
        let block = RcBlock::new(move |reply: *mut NSData| {
            let bytes = unsafe { reply.as_ref() }.map(|d| d.to_vec());
            if let Some(tx) = tx.take() {
                let _ = tx.send(bytes);
            }
        });
        let mut error = None;
        let sent =
            unsafe { session.sendProviderMessage_returnError_responseHandler(&data, Some(&mut error), Some(&block)) };
        if !sent {
            return Err(error
                .map(|e| e.localizedDescription().to_string())
                .unwrap_or_else(|| "the tunnel is not running".into()));
        }
        let reply = rx
            .await
            .ok()
            .flatten()
            .ok_or_else(|| "the tunnel did not answer".to_string())?;
        let response: Response = serde_json::from_slice(&reply).map_err(|e| e.to_string())?;
        match response.error {
            Some(e) => Err(e),
            None => Ok(response),
        }
    }
}

/// A manager handed from NetworkExtension's queue to the main thread. It is
/// only touched again on the main thread.
struct SendManager(Retained<NETunnelProviderManager>);
unsafe impl Send for SendManager {}

/// Removes its status observer when dropped.
pub struct Observer(Retained<objc2::runtime::ProtocolObject<dyn objc2::runtime::NSObjectProtocol>>);

impl Drop for Observer {
    fn drop(&mut self) {
        let token: &AnyObject = self.0.as_ref();
        unsafe { NSNotificationCenter::defaultCenter().removeObserver(token) };
    }
}

/// A `providerConfiguration` value: the provider reads strings and data.
pub enum ProviderValue {
    String(String),
    Data(Vec<u8>),
}

/// What [`Manager::configure`] writes into the VPN configuration.
pub struct Configuration {
    pub bundle_id: String,
    /// Replaces the whole `providerConfiguration`.
    pub provider: Vec<(&'static str, ProviderValue)>,
    /// `includeAllNetworks` and `enforceRoutes`: SbrKit's
    /// `Sbr.applyLeakProtection`.
    pub leak_protection: bool,
    /// Under leak protection, `excludeLocalNetworks`.
    pub allow_local_network: bool,
    /// On-demand rules: off on these Wi-Fi networks, on everywhere else.
    /// None for no rules.
    pub on_demand: Option<Vec<String>>,
    pub on_demand_enabled: bool,
}

/// Waits for a NetworkExtension completion handler that reports only an
/// error.
async fn completed(call: impl FnOnce(&block2::DynBlock<dyn Fn(*mut NSError)>)) -> Result<(), String> {
    let (tx, rx) = oneshot::channel::<Result<(), String>>();
    let tx = std::cell::Cell::new(Some(tx));
    let block = RcBlock::new(move |error: *mut NSError| {
        let r = match unsafe { error.as_ref() } {
            Some(e) => Err(e.localizedDescription().to_string()),
            None => Ok(()),
        };
        if let Some(tx) = tx.take() {
            let _ = tx.send(r);
        }
    });
    call(&block);
    rx.await
        .unwrap_or_else(|_| Err("NetworkExtension did not answer".into()))
}

/// The keys of the profile in `providerConfiguration`: SbrKit's
/// `SbrProviderKey.config`, `.remote` and `.stored`.
pub const PROFILE_KEYS: [&str; 3] = ["config", "remote", "stored"];

impl Manager {
    /// A configuration not yet saved.
    pub fn create() -> Manager {
        Manager(unsafe { NETunnelProviderManager::new() })
    }

    /// Every VPN configuration this app has saved, whatever its provider.
    pub async fn load_all() -> Result<Vec<Manager>, String> {
        let (tx, rx) = oneshot::channel();
        let tx = std::cell::Cell::new(Some(tx));
        let block = RcBlock::new(move |all: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            let result = match unsafe { error.as_ref() } {
                Some(error) => Err(error.localizedDescription().to_string()),
                None => Ok(unsafe { all.as_ref() }
                    .map(|all| all.iter().map(SendManager).collect::<Vec<_>>())
                    .unwrap_or_default()),
            };
            if let Some(tx) = tx.take() {
                let _ = tx.send(result);
            }
        });
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&block) };
        match rx.await {
            Ok(r) => r.map(|all| all.into_iter().map(|m| Manager(m.0)).collect()),
            Err(_) => Err("NetworkExtension did not answer".into()),
        }
    }

    pub async fn save(&self) -> Result<(), String> {
        completed(|b| unsafe { self.0.saveToPreferencesWithCompletionHandler(Some(b)) }).await
    }

    /// Re-read the saved configuration: needed after a save before the
    /// tunnel can start, and to pick up changes made by another process.
    pub async fn reload(&self) -> Result<(), String> {
        completed(|b| unsafe { self.0.loadFromPreferencesWithCompletionHandler(b) }).await
    }

    pub async fn remove(&self) -> Result<(), String> {
        completed(|b| unsafe { self.0.removeFromPreferencesWithCompletionHandler(Some(b)) }).await
    }

    pub fn on_demand_enabled(&self) -> bool {
        unsafe { self.0.isOnDemandEnabled() }
    }

    pub fn set_on_demand_enabled(&self, on: bool) {
        unsafe { self.0.setOnDemandEnabled(on) }
    }

    pub fn has_on_demand_rules(&self) -> bool {
        unsafe { self.0.onDemandRules() }.is_some_and(|r| r.count() > 0)
    }

    pub fn is_enabled(&self) -> bool {
        unsafe { self.0.isEnabled() }
    }

    pub fn set_enabled(&self, on: bool) {
        unsafe { self.0.setEnabled(on) }
    }

    /// Write `c` into the configuration, keeping its protocol object when it
    /// has one. Saved by [`Manager::save`].
    pub fn configure(&self, c: &Configuration) {
        use objc2_foundation::NSMutableDictionary;
        use objc2_network_extension::{
            NEOnDemandRule, NEOnDemandRuleConnect, NEOnDemandRuleDisconnect, NEOnDemandRuleInterfaceType,
        };

        let proto = unsafe { self.0.protocolConfiguration() }
            .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok())
            .unwrap_or_else(|| unsafe { NETunnelProviderProtocol::new() });
        let pc = NSMutableDictionary::<NSString, AnyObject>::new();
        for (key, value) in &c.provider {
            let key = NSString::from_str(key);
            match value {
                ProviderValue::String(s) => pc.insert(&*key, NSString::from_str(s).as_ref()),
                ProviderValue::Data(d) => pc.insert(&*key, NSData::with_bytes(d).as_ref()),
            }
        }
        unsafe {
            proto.setProviderBundleIdentifier(Some(&NSString::from_str(&c.bundle_id)));
            proto.setServerAddress(Some(&NSString::from_str("sbr")));
            proto.setProviderConfiguration(Some(&pc));
            #[cfg(not(target_os = "tvos"))]
            {
                proto.setIncludeAllNetworks(c.leak_protection);
                proto.setExcludeLocalNetworks(c.leak_protection && c.allow_local_network);
            }
            proto.setEnforceRoutes(c.leak_protection);
            self.0.setProtocolConfiguration(Some(&proto));
            self.0.setLocalizedDescription(Some(&NSString::from_str("sbr")));
            self.0.setEnabled(true);
        }
        let rules = c.on_demand.as_ref().map(|trusted| {
            let mut rules: Vec<Retained<NEOnDemandRule>> = Vec::new();
            // Evaluated in order; the first match wins.
            if !trusted.is_empty() {
                let off = unsafe { NEOnDemandRuleDisconnect::new() };
                let ssids: Vec<Retained<NSString>> = trusted.iter().map(|s| NSString::from_str(s)).collect();
                unsafe {
                    off.setInterfaceTypeMatch(NEOnDemandRuleInterfaceType::WiFi);
                    off.setSSIDMatch(Some(&NSArray::from_retained_slice(&ssids)));
                }
                rules.push(Retained::into_super(off));
            }
            let on = unsafe { NEOnDemandRuleConnect::new() };
            unsafe { on.setInterfaceTypeMatch(NEOnDemandRuleInterfaceType::Any) };
            rules.push(Retained::into_super(on));
            NSArray::from_retained_slice(&rules)
        });
        unsafe {
            self.0.setOnDemandRules(rules.as_deref());
            self.0.setOnDemandEnabled(rules.is_some() && c.on_demand_enabled);
        }
    }

    /// Take the profile out of the configuration, so nothing that starts
    /// the tunnel (Settings, a control, an intent) connects with it. Saved
    /// by [`Manager::save`].
    pub fn clear_profile(&self) {
        use objc2_foundation::NSMutableDictionary;

        let Some(proto) =
            unsafe { self.0.protocolConfiguration() }.and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok())
        else {
            return;
        };
        let pc = NSMutableDictionary::<NSString, AnyObject>::new();
        if let Some(old) = unsafe { proto.providerConfiguration() } {
            let (keys, values) = old.to_vecs();
            for (k, v) in keys.iter().zip(values.iter()) {
                if !PROFILE_KEYS.contains(&k.to_string().as_str()) {
                    pc.insert(&**k, &**v);
                }
            }
        }
        unsafe {
            proto.setProviderConfiguration(Some(&pc));
            self.0.setProtocolConfiguration(Some(&proto));
        }
    }

    /// Start the tunnel with `SbrStartOption.erase`: it deletes its files
    /// (cache, rule-sets, logs) and stops without connecting.
    pub fn start_erasing(&self) -> Result<(), String> {
        use objc2_foundation::{NSDictionary, NSNumber, NSObject};

        let key = NSString::from_str("sbrErase");
        let yes = NSNumber::new_bool(true);
        let options = NSDictionary::<NSString, NSObject>::from_slices(&[&*key], &[yes.as_ref()]);
        unsafe {
            self.0
                .connection()
                .startVPNTunnelWithOptions_andReturnError(Some(&options))
        }
        .map_err(|e| e.localizedDescription().to_string())
    }
}
