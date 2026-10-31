//! Crash breadcrumbs. A Network Extension that dies takes its in-memory log
//! with it, and the system only reports "plugin failed". Panics and fatal
//! signals are appended to a file the host reads on the next start.

use std::cell::RefCell;
use std::ffi::c_int;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Once, OnceLock};

static FD: AtomicI32 = AtomicI32::new(-1);
static HOOKS: Once = Once::new();
const SIGNALS: [c_int; 5] = [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE, libc::SIGABRT];
/// The handlers installed before ours (the host's crash reporter, say),
/// put back before the signal is raised again.
static PREVIOUS: [OnceLock<libc::sigaction>; SIGNALS.len()] = [const { OnceLock::new() }; SIGNALS.len()];

/// Append breadcrumbs to `path` from now on. Panics are recorded whether or
/// not something later catches them; fatal signals are recorded and then
/// re-raised with the default action, so the process still dies as before.
pub fn install(path: &str) -> io::Result<()> {
    let fd = OpenOptions::new().create(true).append(true).open(path)?.into_raw_fd();
    let old = FD.load(Ordering::Acquire);
    if old >= 0 {
        // A writer may hold the old number: move the new file onto it rather
        // than closing it, or the number could be reused by a socket first.
        // SAFETY: both fds are ours; dup2 replaces `old` atomically.
        let r = unsafe { libc::dup2(fd, old) };
        // SAFETY: `fd` is ours and, after dup2, unused.
        unsafe { libc::close(fd) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
    } else {
        FD.store(fd, Ordering::Release);
    }
    HOOKS.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current();
            let line = format!("panic on {}: {info}\n", thread.name().unwrap_or("unnamed thread"));
            write_all(line.as_bytes());
            previous(info);
        }));
        for (i, sig) in SIGNALS.into_iter().enumerate() {
            // SA_ONSTACK: a stack overflow can only be reported from an
            // alternate signal stack ([`alt_stack`]).
            // SAFETY: the handler only calls async-signal-safe functions.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = on_signal as *const () as libc::sighandler_t;
                action.sa_flags = libc::SA_ONSTACK;
                libc::sigemptyset(&mut action.sa_mask);
                let mut previous: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, &action, &mut previous) == 0 {
                    let _ = PREVIOUS[i].set(previous);
                }
            }
        }
    });
    Ok(())
}

fn write_all(bytes: &[u8]) {
    let fd = FD.load(Ordering::Acquire);
    if fd >= 0 {
        // SAFETY: writing from a valid buffer to our own fd.
        unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    }
}

extern "C" fn on_signal(sig: c_int) {
    let msg: &[u8] = match sig {
        libc::SIGSEGV => b"fatal signal SIGSEGV (bad memory access or stack overflow)\n",
        libc::SIGBUS => b"fatal signal SIGBUS\n",
        libc::SIGILL => b"fatal signal SIGILL\n",
        libc::SIGFPE => b"fatal signal SIGFPE\n",
        libc::SIGABRT => b"fatal signal SIGABRT (abort)\n",
        _ => b"fatal signal\n",
    };
    write_all(msg);
    // SAFETY: sigaction and raise are async-signal-safe. The signal is
    // blocked while this handler runs, so the handler that was there before
    // ours (or the default action, which kills the process) takes it once
    // this one returns.
    unsafe {
        match SIGNALS.iter().position(|&s| s == sig).and_then(|i| PREVIOUS[i].get()) {
            Some(previous) => libc::sigaction(sig, previous, std::ptr::null_mut()),
            None => {
                libc::signal(sig, libc::SIG_DFL);
                0
            }
        };
        libc::raise(sig);
    }
}

/// Signal stack size for [`alt_stack`]: the handler only formats nothing and
/// calls write(2).
const ALT_STACK: usize = 64 * 1024;

thread_local! {
    static ALT: RefCell<Option<AltStack>> = const { RefCell::new(None) };
}

struct AltStack(Box<[u8]>);

impl Drop for AltStack {
    fn drop(&mut self) {
        // SAFETY: disabling this thread's alternate stack before its memory
        // is freed.
        unsafe {
            let mut ss: libc::stack_t = std::mem::zeroed();
            ss.ss_flags = libc::SS_DISABLE;
            libc::sigaltstack(&ss, std::ptr::null_mut());
        }
    }
}

/// Give the calling thread an alternate signal stack, freed when it exits.
/// Rust sets these up only when it owns `main`, which a library linked into
/// the host does not; without one a stack overflow cannot run the handler,
/// and the process dies with no breadcrumb. Call it on every thread sbr
/// starts.
pub fn alt_stack() {
    ALT.with(|a| {
        let mut a = a.borrow_mut();
        if a.is_some() {
            return;
        }
        let mut mem = vec![0u8; ALT_STACK].into_boxed_slice();
        // SAFETY: `mem` outlives the registration: `AltStack::drop` disables
        // it first.
        let ok = unsafe {
            let ss = libc::stack_t {
                ss_sp: mem.as_mut_ptr().cast(),
                ss_size: mem.len(),
                ss_flags: 0,
            };
            libc::sigaltstack(&ss, std::ptr::null_mut()) == 0
        };
        if ok {
            *a = Some(AltStack(mem));
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn threads_get_an_alt_stack() {
        std::thread::spawn(|| {
            super::alt_stack();
            // SAFETY: querying this thread's alternate stack.
            let ss = unsafe {
                let mut ss: libc::stack_t = std::mem::zeroed();
                assert_eq!(libc::sigaltstack(std::ptr::null(), &mut ss), 0);
                ss
            };
            assert_eq!(ss.ss_flags & libc::SS_DISABLE, 0);
            assert_eq!(ss.ss_size, super::ALT_STACK);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn panics_leave_a_breadcrumb() {
        let path = std::env::temp_dir().join(format!("sbr-crash-{}.log", std::process::id()));
        super::install(path.to_str().unwrap()).unwrap();
        let _ = std::thread::Builder::new()
            .name("breadcrumb-test".into())
            .spawn(|| panic!("breadcrumb boom"))
            .unwrap()
            .join();
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(text.contains("panic on breadcrumb-test"), "{text}");
        assert!(text.contains("breadcrumb boom"), "{text}");
    }
}
