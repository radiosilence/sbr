//! What the tunnel needs from its `NEPacketTunnelProvider`: the provider
//! configuration the app saved, and applying network settings.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::rc::Weak;
use objc2_foundation::{NSData, NSError, NSString};
use objc2_network_extension::{
    NEPacketTunnelProvider, NEProviderStopReason, NETunnelNetworkSettings, NETunnelProviderProtocol,
};
use sbr_message::{PersonalRule, RemoteProfile, StoredProfile, provider_key};

/// A weak reference to the provider object, usable from the tunnel's own
/// threads. NetworkExtension's provider methods are thread-safe; Swift's
/// async provider calls them from arbitrary executor threads too.
pub struct Provider(Weak<NEPacketTunnelProvider>);

// SAFETY: see above; the weak reference itself is thread-safe.
unsafe impl Send for Provider {}
unsafe impl Sync for Provider {}

/// `providerConfiguration` and the protocol switches the tunnel reads.
#[derive(Default)]
pub struct ProviderConfig {
    pub stored: Option<StoredProfile>,
    pub config: Option<String>,
    pub app_group: Option<String>,
    pub remote: Option<RemoteProfile>,
    pub log_level: Option<String>,
    pub rules: Vec<PersonalRule>,
    pub tun_stack: Option<String>,
    pub include_all_networks: bool,
}

impl Provider {
    pub fn new(p: &NEPacketTunnelProvider) -> Self {
        Provider(Weak::from(p))
    }

    /// Read afresh each time: the app can save a new configuration while
    /// the tunnel runs.
    pub fn config(&self) -> ProviderConfig {
        let Some(p) = self.0.load() else {
            return ProviderConfig::default();
        };
        // SAFETY: plain property reads.
        let Ok(proto) = unsafe { p.protocolConfiguration() }.downcast::<NETunnelProviderProtocol>() else {
            return ProviderConfig::default();
        };
        #[cfg(not(target_os = "tvos"))]
        let include_all_networks = unsafe { proto.includeAllNetworks() };
        #[cfg(target_os = "tvos")]
        let include_all_networks = false;
        let Some(dict) = (unsafe { proto.providerConfiguration() }) else {
            return ProviderConfig {
                include_all_networks,
                ..ProviderConfig::default()
            };
        };
        let get = |key: &str| dict.objectForKey(&NSString::from_str(key));
        let string = |key: &str| {
            get(key)
                .and_then(|o| o.downcast::<NSString>().ok())
                .map(|s| s.to_string())
        };
        let data = |key: &str| get(key).and_then(|o| o.downcast::<NSData>().ok()).map(|d| d.to_vec());
        fn json<T: serde::de::DeserializeOwned>(data: Option<Vec<u8>>) -> Option<T> {
            data.and_then(|d| serde_json::from_slice(&d).ok())
        }
        ProviderConfig {
            stored: json(data(provider_key::STORED)),
            config: string(provider_key::CONFIG),
            app_group: string(provider_key::APP_GROUP),
            remote: json(data(provider_key::REMOTE)),
            log_level: string(provider_key::LOG_LEVEL),
            rules: json(data(provider_key::PERSONAL_RULES)).unwrap_or_default(),
            tun_stack: string(provider_key::TUN_STACK),
            include_all_networks,
        }
    }

    /// Apply the network settings `config`'s tun inbound asks for, and wait
    /// until NetworkExtension has (the utun exists afterwards).
    pub fn set_network_settings(&self, config: &str) -> Result<(), String> {
        let settings = crate::settings::network_settings(config)?;
        let p = self.0.load().ok_or("the provider has gone")?;
        let (tx, rx) = mpsc::channel::<Option<String>>();
        let done = RcBlock::new(move |error: *mut NSError| {
            // SAFETY: NULL or a valid error for the duration of the call.
            let _ = tx.send(unsafe { error.as_ref() }.map(|e| e.localizedDescription().to_string()));
        });
        let settings: &NETunnelNetworkSettings = &settings;
        // SAFETY: the settings object and block are valid; NetworkExtension
        // copies the block.
        unsafe { p.setTunnelNetworkSettings_completionHandler(Some(settings), Some(&done)) };
        drop(p);
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(None) => Ok(()),
            Ok(Some(e)) => Err(e),
            Err(_) => Err("NetworkExtension did not apply the network settings".into()),
        }
    }
}

/// `NEProviderStopReason`.
#[derive(Clone, Copy)]
pub struct StopReason(pub isize);

impl StopReason {
    /// Stops the user, sleep, an update or a configuration change cause,
    /// rather than the system giving up on the tunnel.
    pub fn is_expected(self) -> bool {
        [
            NEProviderStopReason::UserInitiated,
            NEProviderStopReason::ProviderDisabled,
            NEProviderStopReason::ConfigurationDisabled,
            NEProviderStopReason::ConfigurationRemoved,
            NEProviderStopReason::Sleep,
            NEProviderStopReason::AppUpdate,
            NEProviderStopReason::UserLogout,
            NEProviderStopReason::UserSwitch,
        ]
        .iter()
        .any(|r| r.0 == self.0)
    }

    pub fn describe(self) -> &'static str {
        match NEProviderStopReason(self.0) {
            NEProviderStopReason::ProviderFailed => "provider failed",
            NEProviderStopReason::NoNetworkAvailable => "no network",
            NEProviderStopReason::UnrecoverableNetworkChange => "unrecoverable network change",
            NEProviderStopReason::AuthenticationCanceled => "authentication cancelled",
            NEProviderStopReason::ConfigurationFailed => "configuration failed",
            NEProviderStopReason::IdleTimeout => "idle timeout",
            NEProviderStopReason::Superceded => "another vpn took over",
            NEProviderStopReason::ConnectionFailed => "connection failed",
            NEProviderStopReason::InternalError => "internal error",
            _ => "other",
        }
    }
}
