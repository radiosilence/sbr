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
                        let proto = unsafe { m.protocolConfiguration() };
                        proto
                            .downcast::<NETunnelProviderProtocol>()
                            .ok()
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
