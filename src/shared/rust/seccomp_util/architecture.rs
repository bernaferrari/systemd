// SPDX-License-Identifier: LGPL-2.1-or-later

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::Errno;

use super::model::{
    SCMP_ARCH_AARCH64, SCMP_ARCH_ARM, SCMP_ARCH_LOONGARCH64, SCMP_ARCH_MIPS, SCMP_ARCH_MIPS64,
    SCMP_ARCH_MIPS64N32, SCMP_ARCH_MIPSEL, SCMP_ARCH_MIPSEL64, SCMP_ARCH_MIPSEL64N32,
    SCMP_ARCH_NATIVE, SCMP_ARCH_PARISC, SCMP_ARCH_PARISC64, SCMP_ARCH_PPC, SCMP_ARCH_PPC64,
    SCMP_ARCH_PPC64LE, SCMP_ARCH_RISCV64, SCMP_ARCH_S390, SCMP_ARCH_S390X, SCMP_ARCH_X32,
    SCMP_ARCH_X86, SCMP_ARCH_X86_64, SECCOMP_LOCAL_ARCH_BLOCKED, SECCOMP_LOCAL_ARCH_END,
};

// ── Architecture String Conversion ───────────────────────────────────────

/// Convert a seccomp architecture constant to its human-readable name.
///
/// Returns `None` for unknown architecture codes.
///
/// Corresponds to `seccomp_arch_to_string()` in the C source.
pub fn seccomp_arch_to_string(arch: u32) -> Option<&'static str> {
    match arch {
        SCMP_ARCH_NATIVE => Some("native"),
        SCMP_ARCH_X86 => Some("x86"),
        SCMP_ARCH_X86_64 => Some("x86-64"),
        SCMP_ARCH_X32 => Some("x32"),
        SCMP_ARCH_ARM => Some("arm"),
        SCMP_ARCH_AARCH64 => Some("arm64"),
        SCMP_ARCH_LOONGARCH64 => Some("loongarch64"),
        SCMP_ARCH_MIPS => Some("mips"),
        SCMP_ARCH_MIPS64 => Some("mips64"),
        SCMP_ARCH_MIPS64N32 => Some("mips64-n32"),
        SCMP_ARCH_MIPSEL => Some("mips-le"),
        SCMP_ARCH_MIPSEL64 => Some("mips64-le"),
        SCMP_ARCH_MIPSEL64N32 => Some("mips64-le-n32"),
        SCMP_ARCH_PARISC => Some("parisc"),
        SCMP_ARCH_PARISC64 => Some("parisc64"),
        SCMP_ARCH_PPC => Some("ppc"),
        SCMP_ARCH_PPC64 => Some("ppc64"),
        SCMP_ARCH_PPC64LE => Some("ppc64-le"),
        SCMP_ARCH_RISCV64 => Some("riscv64"),
        SCMP_ARCH_S390 => Some("s390"),
        SCMP_ARCH_S390X => Some("s390x"),
        _ => None,
    }
}

/// Convert a human-readable architecture name to its seccomp constant.
///
/// Returns `Err(Errno::EINVAL)` for unknown names.
///
/// Corresponds to `seccomp_arch_from_string()` in the C source.
pub fn seccomp_arch_from_string(name: &str) -> std::result::Result<u32, Errno> {
    match name {
        "native" => Ok(SCMP_ARCH_NATIVE),
        "x86" => Ok(SCMP_ARCH_X86),
        "x86-64" => Ok(SCMP_ARCH_X86_64),
        "x32" => Ok(SCMP_ARCH_X32),
        "arm" => Ok(SCMP_ARCH_ARM),
        "arm64" => Ok(SCMP_ARCH_AARCH64),
        "loongarch64" => Ok(SCMP_ARCH_LOONGARCH64),
        "mips" => Ok(SCMP_ARCH_MIPS),
        "mips64" => Ok(SCMP_ARCH_MIPS64),
        "mips64-n32" => Ok(SCMP_ARCH_MIPS64N32),
        "mips-le" => Ok(SCMP_ARCH_MIPSEL),
        "mips64-le" => Ok(SCMP_ARCH_MIPSEL64),
        "mips64-le-n32" => Ok(SCMP_ARCH_MIPSEL64N32),
        "parisc" => Ok(SCMP_ARCH_PARISC),
        "parisc64" => Ok(SCMP_ARCH_PARISC64),
        "ppc" => Ok(SCMP_ARCH_PPC),
        "ppc64" => Ok(SCMP_ARCH_PPC64),
        "ppc64-le" => Ok(SCMP_ARCH_PPC64LE),
        "riscv64" => Ok(SCMP_ARCH_RISCV64),
        "s390" => Ok(SCMP_ARCH_S390),
        "s390x" => Ok(SCMP_ARCH_S390X),
        _ => Err(Errno::EINVAL),
    }
}

// ── Seccomp Library (OS Boundary) ────────────────────────────────────────

/// Cached availability flag — mirrors the `static int cached_enabled` in C.
static SECCOMP_AVAILABLE: AtomicBool = AtomicBool::new(false);
static SECCOMP_CHECKED: AtomicBool = AtomicBool::new(false);

/// Check whether seccomp filtering is available on this system.
///
/// The result is cached after the first call.  This corresponds to
/// `is_seccomp_available()` in the C source.
pub fn is_seccomp_available() -> bool {
    if SECCOMP_CHECKED.load(Ordering::Acquire) {
        return SECCOMP_AVAILABLE.load(Ordering::Relaxed);
    }

    const PR_GET_SECCOMP: i32 = 21;
    const PR_SET_SECCOMP: i32 = 22;
    const SECCOMP_MODE_FILTER: i32 = 2;

    // SAFETY: PR_GET_SECCOMP takes only integer values here and dereferences no
    // caller-provided pointer.
    let basic = unsafe { crate::ffi::prctl(PR_GET_SECCOMP, 0, 0, 0, 0) } >= 0;

    // The filter check is: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL)
    // which should fail with EFAULT if seccomp is available.
    // SAFETY: the null filter pointer is intentional: EFAULT is the feature
    // probe result, and the remaining arguments are integer values.
    let filter = unsafe { crate::ffi::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0, 0, 0) } < 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EFAULT);

    let available = basic && filter;
    SECCOMP_AVAILABLE.store(available, Ordering::Relaxed);
    SECCOMP_CHECKED.store(true, Ordering::Release);
    available
}

/// Reset the cached availability check (useful for testing).
#[cfg(test)]
pub fn reset_seccomp_available_cache() {
    SECCOMP_CHECKED.store(false, Ordering::Relaxed);
    SECCOMP_AVAILABLE.store(false, Ordering::Relaxed);
}

// ── Local Architecture Array ─────────────────────────────────────────────

/// Returns the initial list of local architectures for the current target.
///
/// The native architecture is always listed last so that deny-listed
/// seccomp() calls still succeed for our own use.
fn initial_local_archs() -> Vec<u32> {
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    {
        vec![
            SCMP_ARCH_X86,
            SCMP_ARCH_X32,
            SCMP_ARCH_X86_64,
            SECCOMP_LOCAL_ARCH_END,
        ]
    }
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "32"))]
    {
        vec![
            SCMP_ARCH_X86,
            SCMP_ARCH_X86_64,
            SCMP_ARCH_X32,
            SECCOMP_LOCAL_ARCH_END,
        ]
    }
    #[cfg(target_arch = "x86")]
    {
        vec![SCMP_ARCH_X86, SECCOMP_LOCAL_ARCH_END]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec![SCMP_ARCH_ARM, SCMP_ARCH_AARCH64, SECCOMP_LOCAL_ARCH_END]
    }
    #[cfg(target_arch = "arm")]
    {
        vec![SCMP_ARCH_ARM, SECCOMP_LOCAL_ARCH_END]
    }
    #[cfg(target_arch = "riscv64")]
    {
        vec![SCMP_ARCH_RISCV64, SECCOMP_LOCAL_ARCH_END]
    }
    #[cfg(target_arch = "s390x")]
    {
        vec![SCMP_ARCH_S390, SCMP_ARCH_S390X, SECCOMP_LOCAL_ARCH_END]
    }
    #[cfg(all(target_arch = "powerpc64", target_endian = "big"))]
    {
        vec![
            SCMP_ARCH_PPC,
            SCMP_ARCH_PPC64LE,
            SCMP_ARCH_PPC64,
            SECCOMP_LOCAL_ARCH_END,
        ]
    }
    #[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
    {
        vec![
            SCMP_ARCH_PPC,
            SCMP_ARCH_PPC64,
            SCMP_ARCH_PPC64LE,
            SECCOMP_LOCAL_ARCH_END,
        ]
    }
    #[cfg(target_arch = "powerpc")]
    {
        vec![SCMP_ARCH_PPC, SECCOMP_LOCAL_ARCH_END]
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "x86_64", target_pointer_width = "32"),
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
        target_arch = "s390x",
        all(target_arch = "powerpc64", target_endian = "big"),
        all(target_arch = "powerpc64", target_endian = "little"),
        target_arch = "powerpc",
    )))]
    {
        // Default: just native (empty, since we don't know the arch)
        vec![SECCOMP_LOCAL_ARCH_END]
    }
}

static LOCAL_ARCHS: OnceLock<Mutex<Vec<u32>>> = OnceLock::new();

/// Get (or initialise) the mutable local-architecture array.
///
/// Corresponds to the global `seccomp_local_archs[]` in the C source.
pub fn seccomp_local_archs() -> &'static Mutex<Vec<u32>> {
    LOCAL_ARCHS.get_or_init(|| Mutex::new(initial_local_archs()))
}

/// Iterate over the non-blocked local architectures.
///
/// Corresponds to the `SECCOMP_FOREACH_LOCAL_ARCH` macro in the C source.
pub fn foreach_local_arch() -> Vec<u32> {
    let archs = seccomp_local_archs()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    archs
        .iter()
        .copied()
        .filter(|&a| a != SECCOMP_LOCAL_ARCH_END && a != SECCOMP_LOCAL_ARCH_BLOCKED)
        .collect()
}

// ── Architecture Support Queries ─────────────────────────────────────────

/// Returns `true` if the given architecture uses `socket()` directly
/// (rather than the multiplexed `socketcall()`).
///
/// Corresponds to the `supported` switch in
/// `seccomp_restrict_address_families()`.
pub fn arch_supports_socket_filter(arch: u32) -> bool {
    matches!(
        arch,
        SCMP_ARCH_X86_64
            | SCMP_ARCH_X32
            | SCMP_ARCH_ARM
            | SCMP_ARCH_AARCH64
            | SCMP_ARCH_LOONGARCH64
            | SCMP_ARCH_MIPSEL64N32
            | SCMP_ARCH_MIPS64N32
            | SCMP_ARCH_MIPSEL64
            | SCMP_ARCH_MIPS64
            | SCMP_ARCH_RISCV64
    )
}

/// Returns `true` if the given architecture is known to have `_sysctl`.
///
/// Architectures without `_sysctl` are skipped in `seccomp_protect_sysctl()`.
pub fn arch_has_sysctl(arch: u32) -> bool {
    !matches!(
        arch,
        SCMP_ARCH_AARCH64 | SCMP_ARCH_LOONGARCH64 | SCMP_ARCH_X32 | SCMP_ARCH_RISCV64
    )
}

/// Returns `true` if the given architecture uses the s390 parameter
/// ordering for `clone()` (first two parameters are swapped).
pub fn arch_is_s390(arch: u32) -> bool {
    matches!(arch, SCMP_ARCH_S390 | SCMP_ARCH_S390X)
}

// ── Sync Syscall Classification ──────────────────────────────────────────

/// Returns `true` if the given syscall name needs an fd-range check
/// when suppressing sync operations (i.e. it takes a file descriptor
/// as its first argument).
///
/// Corresponds to the `STR_IN_SET` check in `seccomp_suppress_sync()`.
pub fn sync_syscall_needs_fd_check(name: &str) -> bool {
    matches!(
        name,
        "fdatasync" | "fsync" | "sync_file_range" | "sync_file_range2" | "syncfs"
    )
}
