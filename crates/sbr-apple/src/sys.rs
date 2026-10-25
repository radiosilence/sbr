//! OS probes: the Network Extension's utun fd, and memory as jetsam sees it.

/// Find the utun control socket that `NEPacketTunnelProvider` opened for this
/// process, the way WireGuard-apple and sing-box do: NetworkExtension does
/// not hand the fd out, but it lives in our fd table, and only a utun kernel
/// control socket answers `UTUN_OPT_IFNAME` with a `utunN` name.
#[cfg(target_vendor = "apple")]
pub fn find_utun_fd() -> Option<i32> {
    // <sys/sys_domain.h> and <net/if_utun.h>; libc only exports them for macOS.
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    for fd in 0..1024 {
        let mut name = [0u8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `name`; probing
        // an fd that isn't a socket just fails with ENOTSOCK/EBADF.
        let r = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if r == 0 && name.starts_with(b"utun") {
            return Some(fd);
        }
    }
    None
}

#[cfg(not(target_vendor = "apple"))]
pub fn find_utun_fd() -> Option<i32> {
    None
}

/// Bytes charged to this process: `phys_footprint` on Apple (the number
/// jetsam compares against the extension's limit, which includes compressed
/// and IOKit memory, unlike RSS), resident set size elsewhere.
#[cfg(target_vendor = "apple")]
pub fn memory_footprint() -> u64 {
    // <mach/task_info.h> `task_vm_info` up to `phys_footprint` (rev1). The
    // header packs it to 4 bytes.
    #[repr(C, packed(4))]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
    }
    const TASK_VM_INFO: libc::task_flavor_t = 22;
    // What the `mach_task_self()` macro in <mach/mach_init.h> reads; libc's
    // binding of it is deprecated.
    unsafe extern "C" {
        static mach_task_self_: libc::mach_port_t;
    }
    let mut info = TaskVmInfo::default();
    let mut count = (size_of::<TaskVmInfo>() / size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;
    // SAFETY: `count` is the size of `info` in natural_t units; the kernel
    // fills at most that many.
    let kr = unsafe { libc::task_info(mach_task_self_, TASK_VM_INFO, (&raw mut info).cast(), &mut count) };
    if kr == libc::KERN_SUCCESS {
        info.phys_footprint
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
pub fn memory_footprint() -> u64 {
    // statm: size resident shared ... (pages)
    let Ok(s) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let pages: u64 = s.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    // SAFETY: sysconf has no preconditions.
    pages * unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
pub fn memory_footprint() -> u64 {
    0
}

/// Bytes the process may still allocate before jetsam kills it
/// (`os_proc_available_memory`, iOS/tvOS 13+). 0 when there's no such limit
/// or it can't be known (macOS, Linux).
#[cfg(all(
    any(target_os = "ios", target_os = "tvos", target_os = "visionos"),
    not(target_abi = "macabi")
))]
pub fn memory_available() -> u64 {
    unsafe extern "C" {
        // <os/proc.h>
        fn os_proc_available_memory() -> usize;
    }
    // SAFETY: no arguments, no preconditions.
    unsafe { os_proc_available_memory() as u64 }
}

#[cfg(not(all(
    any(target_os = "ios", target_os = "tvos", target_os = "visionos"),
    not(target_abi = "macabi")
)))]
pub fn memory_available() -> u64 {
    0
}

/// Duplicate the host's TUN fd for one engine run. The engine owns (and
/// closes) what it is given, while the Network Extension keeps the original,
/// so `sbr_reload` can start again from the same tunnel. sing-box's libbox
/// does the same.
#[cfg(unix)]
pub fn dup_fd(fd: i32) -> Result<i32, String> {
    // SAFETY: dup has no memory-safety preconditions.
    let d = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if d < 0 {
        Err(format!("dup tun fd {fd}: {}", std::io::Error::last_os_error()))
    } else {
        Ok(d)
    }
}

#[cfg(not(unix))]
pub fn dup_fd(fd: i32) -> Result<i32, String> {
    Ok(fd)
}

/// User plus system CPU time this process has used, in microseconds.
pub fn cpu_time_us() -> u64 {
    // SAFETY: getrusage fills a zeroed rusage for this process.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return 0;
    }
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    us(ru.ru_utime) + us(ru.ru_stime)
}

#[cfg(test)]
mod tests {
    #[test]
    fn probes() {
        #[cfg(target_os = "linux")]
        assert!(super::memory_footprint() > 0);
        // No NE here: nothing in our fd table is a utun.
        assert_eq!(super::find_utun_fd(), None);
    }
}
