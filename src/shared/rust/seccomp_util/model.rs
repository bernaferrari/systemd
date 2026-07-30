// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;

use crate::Errno;

// ── Architecture Constants ────────────────────────────────────────────────

pub const SCMP_ARCH_NATIVE: u32 = 0;
pub const SCMP_ARCH_X86: u32 = 0x40000003;
pub const SCMP_ARCH_X86_64: u32 = 0xC000003E;
pub const SCMP_ARCH_X32: u32 = 0x4000003E;
pub const SCMP_ARCH_ARM: u32 = 0x40000028;
pub const SCMP_ARCH_AARCH64: u32 = 0xC00000B7;
pub const SCMP_ARCH_LOONGARCH64: u32 = 0xC0000102;
pub const SCMP_ARCH_MIPS: u32 = 0x00000008;
pub const SCMP_ARCH_MIPS64: u32 = 0x80000008;
pub const SCMP_ARCH_MIPS64N32: u32 = 0xA0000008;
pub const SCMP_ARCH_MIPSEL: u32 = 0x40000008;
pub const SCMP_ARCH_MIPSEL64: u32 = 0x80000008 | 0x40000000;
pub const SCMP_ARCH_MIPSEL64N32: u32 = 0xA0000008 | 0x40000000;
pub const SCMP_ARCH_PARISC: u32 = 0x0000000F;
pub const SCMP_ARCH_PARISC64: u32 = 0x8000000F;
pub const SCMP_ARCH_PPC: u32 = 0x00000014;
pub const SCMP_ARCH_PPC64: u32 = 0x80000015;
pub const SCMP_ARCH_PPC64LE: u32 = 0xC0000015;
pub const SCMP_ARCH_RISCV64: u32 = 0xC00000F3;
pub const SCMP_ARCH_S390: u32 = 0x00000016;
pub const SCMP_ARCH_S390X: u32 = 0x80000016;

// ── Local Architecture Markers ───────────────────────────────────────────

/// Sentinel marking the end of the `seccomp_local_archs` array.
pub const SECCOMP_LOCAL_ARCH_END: u32 = u32::MAX;

/// Marker value: `0` is safe because `SCMP_ARCH_NATIVE` (also `0`) would
/// never appear in `seccomp_local_archs`, so we can reuse it as a
/// "blocked" sentinel.
pub const SECCOMP_LOCAL_ARCH_BLOCKED: u32 = 0;

// ── Seccomp Action Constants ─────────────────────────────────────────────

pub const SCMP_ACT_KILL_PROCESS: u32 = 0x80000000;
pub const SCMP_ACT_KILL_THREAD: u32 = 0x00000000;
pub const SCMP_ACT_TRAP: u32 = 0x00030000;
pub const SCMP_ACT_ERRNO_BASE: u32 = 0x00050000;
pub const SCMP_ACT_TRACE: u32 = 0x7ff00000;
pub const SCMP_ACT_LOG: u32 = 0x7ffc0000;
pub const SCMP_ACT_ALLOW: u32 = 0x7fff0000;

/// Special value used where syscall filters otherwise expect errno numbers;
/// replaced with `SCMP_ACT_KILL_PROCESS` at load time.
pub const SECCOMP_ERROR_NUMBER_KILL: i32 = i32::MAX - 1;

/// Build a `SCMP_ACT_ERRNO(x)` value for a specific errno number.
#[inline]
pub const fn scmp_act_errno(errno: u32) -> u32 {
    SCMP_ACT_ERRNO_BASE | (errno & 0x0000ffff)
}

// ── Filter Attribute Constants ────────────────────────────────────────────

pub const SCMP_FLTATR_ACT_DEFAULT: u32 = 1;
pub const SCMP_FLTATR_ACT_BADARCH: u32 = 2;
pub const SCMP_FLTATR_CTL_NNP: u32 = 3;
pub const SCMP_FLTATR_CTL_TSYNC: u32 = 4;
pub const SCMP_FLTATR_CTL_LOG: u32 = 6;
pub const SCMP_FLTATR_CTL_OPTIMIZE: u32 = 8;

// ── Comparison Operators ──────────────────────────────────────────────────

pub const SCMP_CMP_NE: u32 = 1;
pub const SCMP_CMP_LT: u32 = 2;
pub const SCMP_CMP_LE: u32 = 3;
pub const SCMP_CMP_EQ: u32 = 4;
pub const SCMP_CMP_GE: u32 = 5;
pub const SCMP_CMP_GT: u32 = 6;
pub const SCMP_CMP_MASKED_EQ: u32 = 7;

// ── Error Type ────────────────────────────────────────────────────────────

/// Errors produced by seccomp utility functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeccompError {
    /// Invalid argument.
    InvalidArgument(String),
    /// libseccomp is not available (not installed or dlopen failed).
    NotAvailable,
    /// Memory allocation failure.
    OutOfMemory,
    /// A libseccomp call returned an error.
    LibSeccomp(i32),
    /// I/O or OS error.
    Os(i32),
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Self::NotAvailable => write!(f, "libseccomp not available"),
            Self::OutOfMemory => write!(f, "Out of memory"),
            Self::LibSeccomp(code) => write!(f, "libseccomp error: {}", code),
            Self::Os(code) => write!(f, "OS error: {}", code),
        }
    }
}

impl std::error::Error for SeccompError {}

impl SeccompError {
    /// Construct from a negative errno-style return code.
    pub fn from_neg_errno(code: i32) -> Self {
        match code {
            code if code == -libc::EINVAL => Self::InvalidArgument(format!("errno {}", code)),
            code if code == -libc::ENOMEM => Self::OutOfMemory,
            code if code == -libc::EOPNOTSUPP => Self::NotAvailable,
            _ => Self::LibSeccomp(code),
        }
    }

    /// Construct from an `Errno` value.
    pub fn from_errno(e: Errno) -> Self {
        Self::LibSeccomp(e.to_neg_errno())
    }
}

/// Result type for seccomp operations.
pub type Result<T> = std::result::Result<T, SeccompError>;

/// Named groups of system calls used for seccomp filter configuration.
///
/// The enum variants are ordered so that `Default` is first and `Known`
/// is last, matching the C header convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallFilterSet {
    Default,
    Aio,
    BasicIo,
    Chown,
    Clock,
    CpuEmulation,
    Debug,
    FileSystem,
    IoEvent,
    Ipc,
    Keyring,
    Memlock,
    Module,
    Mount,
    NetworkIo,
    Obsolete,
    Pkey,
    Privileged,
    Process,
    RawIo,
    Reboot,
    Resources,
    Sandbox,
    Setuid,
    Signal,
    Swap,
    Sync,
    SystemService,
    Timer,
    Known,
}

// ── Seccomp Parse Flags ──────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SeccompParseFlags: u32 {
        /// Invert the filter logic (deny-list ↔ allow-list).
        const INVERT     = 1 << 0;
        /// This is an allow-list (whitelist).
        const ALLOW_LIST = 1 << 1;
        /// Log issues at warning level instead of debug.
        const LOG        = 1 << 2;
        /// Silently ignore unknown syscalls instead of failing.
        const PERMISSIVE = 1 << 3;
    }
}

impl SeccompParseFlags {
    /// Check whether a raw `u32` flags word contains a specific flag.
    #[inline]
    pub fn is_set(flags: u32, flag: Self) -> bool {
        (flags & flag.bits()) != 0
    }
}

/// Result of parsing a syscall filter entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSyscallEntry {
    /// Syscall name or `@`-prefixed set name.
    pub name: String,
    /// Associated errno number, or `-1` for default action.
    pub errno: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallFilterOperation {
    Insert(i32),
    Remove,
}
