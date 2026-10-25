//! One engine run: a Tokio runtime on its own thread plus the `Instance`.
//!
//! The runtime is owned by a dedicated driver thread rather than the caller,
//! because Swift calls in from arbitrary (often main) threads and a
//! current-thread runtime needs one thread that sits in `block_on` to drive
//! I/O and timers. With the multi-thread flavour that thread just parks.

use std::sync::Arc;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use sbr_engine::sbr_config::Options;
use sbr_engine::{Engine, Instance, Settings};
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    /// Everything on one thread: fewest wakeups and context switches.
    CurrentThread,
    /// Work-stealing pool of N workers.
    MultiThread(usize),
}

impl Flavor {
    /// iOS/tvOS default to one thread; see the README for the measurements.
    pub fn platform_default() -> Self {
        if cfg!(any(target_os = "ios", target_os = "tvos", target_os = "visionos")) {
            Flavor::CurrentThread
        } else {
            Flavor::MultiThread(std::thread::available_parallelism().map_or(4, |n| n.get().min(8)))
        }
    }

    pub fn from_threads(n: i32) -> Self {
        match n {
            ..=0 => Self::platform_default(),
            1 => Flavor::CurrentThread,
            n => Flavor::MultiThread(n as usize),
        }
    }
}

/// Upper bound on `spawn_blocking` threads (getaddrinfo, file reads). Tokio's
/// default of 512 would be ~1 GB of stack reservations in a 50 MB extension.
const MAX_BLOCKING_THREADS: usize = 8;

pub struct Running {
    pub engine: Arc<Engine>,
    /// For work the ABI starts but doesn't wait on (latency tests).
    pub handle: tokio::runtime::Handle,
    #[cfg(test)]
    pub listening: Vec<(String, std::net::SocketAddr)>,
    /// Handing the instance back to the driver stops it.
    stop: Option<(oneshot::Sender<Instance>, Instance)>,
    thread: Option<JoinHandle<()>>,
}

impl Running {
    pub fn start(options: Options, settings: Settings, flavor: Flavor) -> Result<Self, String> {
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(Instance, tokio::runtime::Handle), String>>(1);
        let (stop_tx, stop_rx) = oneshot::channel::<Instance>();
        let thread = std::thread::Builder::new()
            .name("sbr".into())
            .spawn(move || {
                let mut b = match flavor {
                    Flavor::CurrentThread => tokio::runtime::Builder::new_current_thread(),
                    Flavor::MultiThread(n) => {
                        let mut b = tokio::runtime::Builder::new_multi_thread();
                        b.worker_threads(n).thread_name("sbr-worker");
                        b
                    }
                };
                let rt = match b.max_blocking_threads(MAX_BLOCKING_THREADS).enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("runtime: {e}")));
                        return;
                    }
                };
                let started = rt.block_on(Instance::start(&options, settings));
                let ok = started.is_ok();
                let _ = ready_tx.send(started.map(|i| (i, rt.handle().clone())).map_err(|e| e.to_string()));
                if ok {
                    // Parks with no timer armed: an idle engine costs no wakeups.
                    if let Ok(instance) = rt.block_on(stop_rx) {
                        let _g = rt.enter();
                        instance.shutdown();
                    }
                }
                rt.shutdown_timeout(Duration::from_secs(2));
            })
            .map_err(|e| format!("spawn runtime thread: {e}"))?;
        match ready_rx.recv() {
            Ok(Ok((instance, handle))) => Ok(Self {
                engine: instance.engine.clone(),
                handle,
                #[cfg(test)]
                listening: instance.listening.clone(),
                stop: Some((stop_tx, instance)),
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err("runtime thread exited during start".into())
            }
        }
    }
}

impl Drop for Running {
    /// Stop accepting, then tear the runtime down (which drops every task,
    /// closing their sockets and the TUN fd). Blocks until done; must not be
    /// called from an sbr thread (e.g. inside the log callback).
    fn drop(&mut self) {
        if let Some((tx, instance)) = self.stop.take() {
            let _ = tx.send(instance);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
