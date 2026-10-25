//! Crash breadcrumbs. A Network Extension that dies takes its in-memory log
//! with it, and the system only reports "plugin failed". Panics and fatal
//! signals are appended to a file the host reads on the next start.

use std::ffi::c_int;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::IntoRawFd;
use std::sync::Once;
use std::sync::atomic::{AtomicI32, Ordering};

static FD: AtomicI32 = AtomicI32::new(-1);
static HOOKS: Once = Once::new();

/// Append breadcrumbs to `path` from now on. Panics are recorded whether or
/// not something later catches them; fatal signals are recorded and then
/// re-raised with the default action, so the process still dies as before.
pub fn install(path: &str) -> io::Result<()> {
    let fd = OpenOptions::new().create(true).append(true).open(path)?.into_raw_fd();
    let old = FD.swap(fd, Ordering::AcqRel);
    if old >= 0 {
        // SAFETY: `old` was ours, from a previous install.
        unsafe { libc::close(old) };
    }
    HOOKS.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current();
            let line = format!("panic on {}: {info}\n", thread.name().unwrap_or("unnamed thread"));
            write_all(line.as_bytes());
            previous(info);
        }));
        for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE, libc::SIGABRT] {
            // SAFETY: installing a handler that only calls async-signal-safe
            // functions (write, signal, raise).
            unsafe { libc::signal(sig, on_signal as libc::sighandler_t) };
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
    // SAFETY: restoring the default action and re-raising are
    // async-signal-safe; the process then dies as it would have.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

#[cfg(test)]
mod tests {
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
