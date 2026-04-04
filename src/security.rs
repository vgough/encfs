//! Process-level memory protections against extraction attacks.
//!
//! Applies platform-appropriate hardening at process startup:
//! - Disables core dumps (RLIMIT_CORE)
//! - Marks the process as non-dumpable (prevents ptrace, /proc/pid/mem reads)
//! - Locks all memory pages to prevent swapping key material to disk

use log::warn;

/// Apply all available memory protections for the current platform.
///
/// This should be called early in main(), before any sensitive data is loaded.
/// Failures are logged as warnings but do not abort — some protections require
/// elevated privileges (e.g. mlockall may need CAP_IPC_LOCK on Linux).
pub fn harden_process() {
    disable_core_dumps();
    set_nondumpable();
    lock_memory();
}

/// Set RLIMIT_CORE to 0 to prevent core dumps.
/// Available on Linux, FreeBSD, and macOS.
fn disable_core_dumps() {
    unsafe {
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rl) != 0 {
            warn!("Failed to disable core dumps (setrlimit RLIMIT_CORE)");
        }
    }
}

/// Mark the process as non-dumpable.
///
/// On Linux: prctl(PR_SET_DUMPABLE, 0) — prevents ptrace attach and
/// /proc/pid/mem reads by non-root processes.
///
/// On FreeBSD: procctl(P_PID, 0, PROC_TRACE_CTL, &PROC_TRACE_CTL_DISABLE) —
/// prevents tracing by non-root processes.
///
/// On macOS: ptrace(PT_DENY_ATTACH, 0, ...) — prevents debugger attachment.
fn set_nondumpable() {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            warn!("Failed to set PR_SET_DUMPABLE");
        }
    }

    #[cfg(target_os = "freebsd")]
    unsafe {
        // PROC_TRACE_CTL = 7, PROC_TRACE_CTL_DISABLE = 1
        const PROC_TRACE_CTL: libc::c_int = 7;
        const PROC_TRACE_CTL_DISABLE: libc::c_int = 1;
        let val = PROC_TRACE_CTL_DISABLE;
        let ret = libc::procctl(
            libc::P_PID,
            0,
            PROC_TRACE_CTL,
            &val as *const libc::c_int as *mut libc::c_void,
        );
        if ret != 0 {
            warn!("Failed to disable process tracing (procctl PROC_TRACE_CTL)");
        }
    }

    #[cfg(target_os = "macos")]
    unsafe {
        // PT_DENY_ATTACH = 31
        const PT_DENY_ATTACH: libc::c_int = 31;
        if libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) != 0 {
            warn!("Failed to set PT_DENY_ATTACH");
        }
    }
}

/// Lock all current and future memory pages to prevent swapping.
///
/// This prevents sensitive key material from being written to swap space.
/// Requires CAP_IPC_LOCK on Linux or appropriate privileges on other platforms.
/// Available on Linux, FreeBSD, and macOS.
fn lock_memory() {
    unsafe {
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            warn!(
                "Failed to lock memory (mlockall). \
                 Key material may be swapped to disk. \
                 Consider running with CAP_IPC_LOCK or raising RLIMIT_MEMLOCK."
            );
        }
    }
}
