//! Alternate signal stacks for the threads sbr starts.

use std::cell::RefCell;

/// Signal stack size: the handler formats nothing and only
/// calls write(2).
const ALT_STACK: usize = 64 * 1024;

thread_local! {
    static ALT: RefCell<Option<AltStack>> = const { RefCell::new(None) };
}

/// Owns the memory registered with `sigaltstack`.
struct AltStack(Option<Box<[u8]>>);

impl Drop for AltStack {
    fn drop(&mut self) {
        if !disable() {
            // Still registered: freeing it would leave signals a stack in
            // freed memory. Leak it instead.
            std::mem::forget(self.0.take());
        }
    }
}

/// Turn off this thread's alternate stack. Darwin refuses `SS_DISABLE`
/// with a zeroed stack, so the current one is passed back with the flag.
/// False if it may still be registered.
fn disable() -> bool {
    // SAFETY: querying and then disabling this thread's alternate stack.
    unsafe {
        let mut ss: libc::stack_t = std::mem::zeroed();
        if libc::sigaltstack(std::ptr::null(), &mut ss) != 0 {
            return false;
        }
        ss.ss_flags = libc::SS_DISABLE;
        libc::sigaltstack(&ss, std::ptr::null_mut()) == 0
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
            *a = Some(AltStack(Some(mem)));
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn threads_get_an_alt_stack() {
        std::thread::spawn(|| {
            // The test harness has a Rust `main`, so std gave this thread a
            // stack already; remove it to exercise what a host thread gets.
            assert!(super::disable());
            let flags = |()| {
                // SAFETY: querying this thread's alternate stack.
                unsafe {
                    let mut ss: libc::stack_t = std::mem::zeroed();
                    assert_eq!(libc::sigaltstack(std::ptr::null(), &mut ss), 0);
                    ss
                }
            };
            assert_ne!(flags(()).ss_flags & libc::SS_DISABLE, 0, "disabled");
            super::install();
            let ss = flags(());
            assert_eq!(ss.ss_flags & libc::SS_DISABLE, 0);
            assert_eq!(ss.ss_size, super::ALT_STACK);
            super::ALT.with(|a| a.borrow_mut().take());
            assert_ne!(flags(()).ss_flags & libc::SS_DISABLE, 0, "disabled before it is freed");
        })
        .join()
        .unwrap();
    }
}
