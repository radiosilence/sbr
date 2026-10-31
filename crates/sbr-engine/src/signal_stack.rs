//! Alternate signal stacks for the threads sbr starts.

use std::cell::RefCell;

/// Signal stack size: the handler formats nothing and only
/// calls write(2).
const ALT_STACK: usize = 64 * 1024;

thread_local! {
    static ALT: RefCell<Option<AltStack>> = const { RefCell::new(None) };
}

/// Owns the memory registered with `sigaltstack`.
struct AltStack(#[allow(dead_code)] Box<[u8]>);

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
/// a host app does not; without one a stack overflow cannot run a fault
/// handler (sbr-apple's crash breadcrumbs), and the process dies without a
/// trace. Call it on every thread sbr starts.
pub fn install() {
    ALT.with(|a| {
        let mut a = a.borrow_mut();
        if a.is_some() {
            return;
        }
        // SAFETY: querying this thread's alternate stack.
        let existing = unsafe {
            let mut ss: libc::stack_t = std::mem::zeroed();
            libc::sigaltstack(std::ptr::null(), &mut ss) == 0 && ss.ss_flags & libc::SS_DISABLE == 0
        };
        if existing {
            // Rust's own, when it owns `main`, or the host's.
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
            super::install();
            // SAFETY: querying this thread's alternate stack.
            let ss = unsafe {
                let mut ss: libc::stack_t = std::mem::zeroed();
                assert_eq!(libc::sigaltstack(std::ptr::null(), &mut ss), 0);
                ss
            };
            assert_eq!(ss.ss_flags & libc::SS_DISABLE, 0);
        })
        .join()
        .unwrap();
    }
}
