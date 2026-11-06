//! The Developer ID build ships the tunnel as a system extension, which is
//! activated (and approved by the user in System Settings) before the VPN
//! configuration can use it: SystemExtensionActivator.swift. Activating an
//! extension already active is cheap, so it runs before every install.
//!
//! The build says so at run time with `SbrSystemExtension` in its
//! Info.plist, since one library serves both macOS apps.
//!
//! The delegate runs on the main queue, as the app's code does, so the
//! state is the main thread's own.

use std::cell::RefCell;

use futures::channel::{mpsc, oneshot};
use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{MainThreadMarker, MainThreadOnly, Message as _, define_class, msg_send};
use objc2_foundation::{NSBundle, NSError, NSNumber, NSString, NSURL};
use objc2_system_extensions::{
    OSSystemExtensionErrorCode, OSSystemExtensionErrorDomain, OSSystemExtensionManager, OSSystemExtensionProperties,
    OSSystemExtensionReplacementAction, OSSystemExtensionRequest, OSSystemExtensionRequestDelegate,
    OSSystemExtensionRequestResult,
};

pub const APPROVAL_NEEDED: &str = "allow sbr's network extension in System Settings, then connect again";
const REBOOT_NEEDED: &str = "restart your Mac to finish installing sbr's network extension";
/// macOS found no notarisation ticket for the extension, offline or online.
/// A fresh copy from the disk image carries one.
const NOT_VERIFIED: &str = "macOS could not verify sbr's network extension. move sbr to the bin, install it again from the disk image, then connect";

/// Whether this build runs its tunnel as a system extension: Info.plist's
/// `SbrSystemExtension`, or `SBR_SYSTEM_EXTENSION` for an unbundled run.
pub fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        if let Some(v) = std::env::var_os("SBR_SYSTEM_EXTENSION") {
            return v == "1";
        }
        let key = NSString::from_str("SbrSystemExtension");
        NSBundle::mainBundle()
            .objectForInfoDictionaryKey(&key)
            .and_then(|v| v.downcast::<NSNumber>().ok())
            .is_some_and(|v| v.boolValue())
    })
}

/// Opens System Settings where the user allows the extension.
pub fn open_settings() {
    let url = NSString::from_str("x-apple.systempreferences:com.apple.LoginItems-Settings.extension");
    if let Some(url) = NSURL::URLWithString(&url) {
        objc2_app_kit::NSWorkspace::sharedWorkspace().openURL(&url);
    }
}

#[derive(Default)]
struct State {
    /// The request waiting for the user's approval. It stays submitted and
    /// finishes by itself once they allow it, so no other is submitted.
    pending: Option<Retained<Activator>>,
    /// The request under way, kept alive: a request holds its delegate
    /// weakly.
    current: Option<(Retained<Activator>, Retained<OSSystemExtensionRequest>)>,
    /// Who waits on the request under way.
    waiting: Vec<oneshot::Sender<Result<(), String>>>,
    /// Told whenever `awaiting_approval` changes, with the error if the
    /// request then failed: nobody waits on a request once it asked.
    watchers: Vec<mpsc::UnboundedSender<Option<String>>>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::default();
}

pub fn awaiting_approval() -> bool {
    STATE.with(|s| s.borrow().pending.is_some())
}

/// Changes to `awaiting_approval`, each with the error a request that had
/// waited for approval then failed with.
pub fn watch() -> mpsc::UnboundedReceiver<Option<String>> {
    let (tx, rx) = mpsc::unbounded();
    STATE.with(|s| s.borrow_mut().watchers.push(tx));
    rx
}

fn tell_watchers(state: &mut State, error: Option<String>) {
    state.watchers.retain(|w| w.unbounded_send(error.clone()).is_ok());
}

/// Activates the extension `identifier`, replacing an older version. Fails
/// with `APPROVAL_NEEDED` while the user has yet to allow it.
pub async fn activate(identifier: &str) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("system extensions are activated from the main thread")?;
    let (tx, rx) = oneshot::channel();
    let submit = STATE.with(|s| {
        let mut s = s.borrow_mut();
        if s.pending.is_some() {
            return Err(APPROVAL_NEEDED.to_owned());
        }
        s.waiting.push(tx);
        Ok(s.current.is_none())
    })?;
    if submit {
        let activator: Retained<Activator> = unsafe { msg_send![Activator::alloc(mtm), init] };
        let request = unsafe {
            OSSystemExtensionRequest::activationRequestForExtension_queue(
                &NSString::from_str(identifier),
                dispatch2::DispatchQueue::main(),
            )
        };
        unsafe {
            request.setDelegate(Some(ProtocolObject::from_ref(&*activator)));
        }
        STATE.with(|s| s.borrow_mut().current = Some((activator, request.clone())));
        unsafe { OSSystemExtensionManager::sharedManager().submitRequest(&request) };
    }
    rx.await
        .unwrap_or_else(|_| Err("the system extension request was dropped".into()))
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and the class keeps
    // no state of its own.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "SbrSystemExtensionActivator"]
    struct Activator;

    unsafe impl NSObjectProtocol for Activator {}

    unsafe impl OSSystemExtensionRequestDelegate for Activator {
        #[unsafe(method(request:actionForReplacingExtension:withExtension:))]
        fn replacing(
            &self,
            _: &OSSystemExtensionRequest,
            _: &OSSystemExtensionProperties,
            _: &OSSystemExtensionProperties,
        ) -> OSSystemExtensionReplacementAction {
            OSSystemExtensionReplacementAction::Replace
        }

        #[unsafe(method(requestNeedsUserApproval:))]
        fn needs_approval(&self, _: &OSSystemExtensionRequest) {
            STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.pending = Some(self.retain());
                for waiter in s.waiting.drain(..) {
                    let _ = waiter.send(Err(APPROVAL_NEEDED.to_owned()));
                }
                tell_watchers(&mut s, None);
            });
        }

        #[unsafe(method(request:didFinishWithResult:))]
        fn finished(&self, _: &OSSystemExtensionRequest, result: OSSystemExtensionRequestResult) {
            let r = if result == OSSystemExtensionRequestResult::WillCompleteAfterReboot {
                Err(REBOOT_NEEDED.to_owned())
            } else {
                Ok(())
            };
            self.finish(r);
        }

        #[unsafe(method(request:didFailWithError:))]
        fn failed(&self, _: &OSSystemExtensionRequest, error: &NSError) {
            let unverified = error.code() == OSSystemExtensionErrorCode::CodeSignatureInvalid.0
                && &*error.domain() == unsafe { OSSystemExtensionErrorDomain };
            self.finish(Err(if unverified {
                NOT_VERIFIED.to_owned()
            } else {
                error.localizedDescription().to_string()
            }));
        }
    }
);

impl Activator {
    fn finish(&self, result: Result<(), String>) {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            if s.current.as_ref().is_some_and(|(a, _)| std::ptr::eq(&**a, self)) {
                s.current = None;
            }
            if s.pending.as_ref().is_some_and(|a| std::ptr::eq(&**a, self)) {
                s.pending = None;
                tell_watchers(&mut s, result.clone().err());
            }
            for waiter in s.waiting.drain(..) {
                let _ = waiter.send(result.clone());
            }
        });
    }
}
