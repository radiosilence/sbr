//! sbr's packet tunnel provider, defined in Rust: `SbrTunnelProvider`, an
//! `NEPacketTunnelProvider` subclass, linked as a static library into the
//! iOS / tvOS / macOS app extension and the macOS system extension, and
//! named as their principal / provider class.
//!
//! A class defined with `define_class!` exists only once registered with
//! the Objective-C runtime, and NetworkExtension looks its principal class
//! up by name before any of our code runs. So the library registers it from
//! an image initializer (`__mod_init_func`) as the extension loads. A linker
//! keeps an archive member only when something references it: the
//! extension links with `-u _sbr_tunnel_provider_register`, which pulls in
//! the member holding the initializer.
//!
//! Each NetworkExtension callback copies its completion handler and does
//! its work on a thread of its own, so NetworkExtension's queue is never
//! held up and a slow start or reload cannot block a message.

#[cfg(target_vendor = "apple")]
mod logs;
#[cfg(target_vendor = "apple")]
mod provider;
pub mod rules;
#[cfg(target_vendor = "apple")]
mod settings;
#[cfg(target_vendor = "apple")]
mod store;
#[cfg(target_vendor = "apple")]
mod tunnel;
#[cfg(target_vendor = "apple")]
mod watch;

#[cfg(target_vendor = "apple")]
pub use class::{SbrTunnelProvider, sbr_tunnel_provider_register};

#[cfg(target_vendor = "apple")]
mod class {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, OnceLock};

    use block2::{DynBlock, RcBlock};
    use objc2::rc::{Allocated, Retained};
    use objc2::runtime::AnyObject;
    use objc2::{ClassType, DefinedClass, define_class, msg_send};
    use objc2_foundation::{NSData, NSDictionary, NSError, NSLocalizedDescriptionKey, NSObject, NSString};
    use objc2_network_extension::{NEPacketTunnelProvider, NEProvider, NEProviderStopReason, NETunnelProvider};
    use sbr_message::start_option;

    use crate::provider::{Provider, StopReason};
    use crate::tunnel::Tunnel;

    #[derive(Default)]
    pub struct Ivars {
        tunnel: OnceLock<Arc<Tunnel>>,
    }

    define_class!(
        // SAFETY: NEPacketTunnelProvider is designed to be subclassed; the
        // class does not implement Drop.
        #[unsafe(super(NEPacketTunnelProvider, NETunnelProvider, NEProvider, NSObject))]
        #[name = "SbrTunnelProvider"]
        #[ivars = Ivars]
        pub struct SbrTunnelProvider;

        impl SbrTunnelProvider {
            #[unsafe(method_id(init))]
            fn init(this: Allocated<Self>) -> Option<Retained<Self>> {
                let this = this.set_ivars(Ivars::default());
                // SAFETY: NEPacketTunnelProvider's designated initializer.
                unsafe { msg_send![super(this), init] }
            }

            #[unsafe(method(startTunnelWithOptions:completionHandler:))]
            fn start_tunnel(
                &self,
                options: Option<&NSDictionary<NSString, NSObject>>,
                completion: &DynBlock<dyn Fn(*mut NSError)>,
            ) {
                let erase = options.is_some_and(|o| o.objectForKey(&NSString::from_str(start_option::ERASE)).is_some());
                let done = Done(completion.copy());
                let tunnel = self.tunnel();
                spawn("sbr-start", move || {
                    let done = done;
                    let result = catch(|| tunnel.start(erase));
                    let error = result.err().map(|e| error(&e));
                    done.0.call((error.as_ref().map_or(std::ptr::null_mut(), |e| Retained::as_ptr(e).cast_mut()),));
                });
            }

            #[unsafe(method(stopTunnelWithReason:completionHandler:))]
            fn stop_tunnel(&self, reason: NEProviderStopReason, completion: &DynBlock<dyn Fn()>) {
                let done = Done(completion.copy());
                let tunnel = self.tunnel();
                spawn("sbr-stop", move || {
                    let done = done;
                    let _ = catch(|| {
                        tunnel.stop(StopReason(reason.0));
                        Ok(())
                    });
                    done.0.call(());
                });
            }

            #[unsafe(method(handleAppMessage:completionHandler:))]
            fn handle_app_message(&self, data: &NSData, completion: Option<&DynBlock<dyn Fn(*mut NSData)>>) {
                let message = data.to_vec();
                let done = completion.map(|c| Done(c.copy()));
                let tunnel = self.tunnel();
                spawn("sbr-message", move || {
                    let done = done;
                    let reply = catch(|| Ok(tunnel.handle_message(&message)))
                        .unwrap_or_else(|e| format!(r#"{{"error":{}}}"#, serde_json::Value::from(e)).into_bytes());
                    if let Some(done) = done {
                        let reply = NSData::with_bytes(&reply);
                        done.0.call((Retained::as_ptr(&reply).cast_mut(),));
                    }
                });
            }

            #[unsafe(method(sleepWithCompletionHandler:))]
            fn sleep(&self, completion: &DynBlock<dyn Fn()>) {
                self.tunnel().sleep();
                completion.call(());
            }

            #[unsafe(method(wake))]
            fn wake(&self) {
                let tunnel = self.tunnel();
                spawn("sbr-wake", move || {
                    let _ = catch(|| {
                        tunnel.wake();
                        Ok(())
                    });
                });
            }
        }
    );

    impl SbrTunnelProvider {
        fn tunnel(&self) -> Arc<Tunnel> {
            self.ivars()
                .tunnel
                .get_or_init(|| Arc::new(Tunnel::new(Provider::new(self))))
                .clone()
        }
    }

    /// A completion handler NetworkExtension passed in, copied to the heap.
    /// NetworkExtension's handlers may be called from any thread.
    struct Done<F: ?Sized>(RcBlock<F>);

    // SAFETY: see above.
    unsafe impl<F: ?Sized> Send for Done<F> {}

    fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
        // Should the thread not start, run inline: NetworkExtension waits
        // for every completion handler.
        let f = std::sync::Mutex::new(Some(f));
        let f = Arc::new(f);
        let theirs = f.clone();
        let started = std::thread::Builder::new().name(name.into()).spawn(move || {
            if let Some(f) = theirs.lock().ok().and_then(|mut f| f.take()) {
                f();
            }
        });
        if started.is_err()
            && let Some(f) = f.lock().ok().and_then(|mut f| f.take())
        {
            f();
        }
    }

    /// Run `f`, turning a panic into an error so every completion handler
    /// is still called.
    fn catch<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err("internal error (panic)".into()))
    }

    /// An `NSError` whose `localizedDescription` is `message`.
    fn error(message: &str) -> Retained<NSError> {
        let text = NSString::from_str(message);
        let info = NSDictionary::<NSString, AnyObject>::from_slices(
            // SAFETY: a Foundation constant.
            &[unsafe { NSLocalizedDescriptionKey }],
            &[text.as_ref()],
        );
        // SAFETY: a plain NSError constructor.
        unsafe { NSError::errorWithDomain_code_userInfo(&NSString::from_str("sbr"), 1, Some(&info)) }
    }

    /// Registers `SbrTunnelProvider` with the Objective-C runtime. Runs as
    /// an image initializer; exported so the extension can link it in with
    /// `-u _sbr_tunnel_provider_register`.
    #[unsafe(no_mangle)]
    pub extern "C" fn sbr_tunnel_provider_register() {
        let _ = SbrTunnelProvider::class();
    }

    #[used]
    #[unsafe(link_section = "__DATA,__mod_init_func")]
    static REGISTER: extern "C" fn() = sbr_tunnel_provider_register;
}
