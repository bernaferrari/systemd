// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/seccomp-util.c (seccomp_errno_or_action_*, seccomp_arch_*)
//
// This basic-crate module backs the small rs_seccomp_* C comparison ABI. It
// deliberately does not pretend to implement the libseccomp filter runtime;
// that larger boundary remains owned by src/shared/seccomp-util.c.

use std::ffi::{CStr, c_char, c_int};
use std::ptr;

use crate::ffi::Errno;

pub const SECCOMP_ERROR_NUMBER_KILL: i32 = i32::MAX - 1;
const ERRNO_MAX: i32 = 4095;

// SCMP_ARCH_* is a stable public libseccomp ABI. Keep these values synchronized
// with <seccomp.h>; unlike Linux AUDIT_ARCH_*, the MIPS N32 tokens include
// libseccomp's __AUDIT_ARCH_64BIT flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SeccompArch {
    Native = 0x0000_0000,
    X86 = 0x4000_0003,
    X86_64 = 0xc000_003e,
    X32 = 0x4000_003e,
    Arm = 0x4000_0028,
    Aarch64 = 0xc000_00b7,
    // These tokens appeared after libseccomp's minimum supported version.
    // Meson probes the selected seccomp.h and passes the cfg explicitly; do
    // not infer them from Rust's target architecture.
    #[cfg(systemd_seccomp_arch_loongarch64)]
    Loongarch64 = 0xc000_0102,
    Mips = 0x0000_0008,
    Mips64 = 0x8000_0008,
    Mips64N32 = 0xa000_0008,
    Mipsel = 0x4000_0008,
    Mipsel64 = 0xc000_0008,
    Mipsel64N32 = 0xe000_0008,
    Parisc = 0x0000_000f,
    Parisc64 = 0x8000_000f,
    Ppc = 0x0000_0014,
    Ppc64 = 0x8000_0015,
    Ppc64Le = 0xc000_0015,
    #[cfg(systemd_seccomp_arch_riscv64)]
    Riscv64 = 0xc000_00f3,
    S390 = 0x0000_0016,
    S390X = 0x8000_0016,
}

static ARCHITECTURES: &[(SeccompArch, &CStr)] = &[
    (SeccompArch::Native, c"native"),
    (SeccompArch::X86, c"x86"),
    (SeccompArch::X86_64, c"x86-64"),
    (SeccompArch::X32, c"x32"),
    (SeccompArch::Arm, c"arm"),
    (SeccompArch::Aarch64, c"arm64"),
    #[cfg(systemd_seccomp_arch_loongarch64)]
    (SeccompArch::Loongarch64, c"loongarch64"),
    (SeccompArch::Mips, c"mips"),
    (SeccompArch::Mips64, c"mips64"),
    (SeccompArch::Mips64N32, c"mips64-n32"),
    (SeccompArch::Mipsel, c"mips-le"),
    (SeccompArch::Mipsel64, c"mips64-le"),
    (SeccompArch::Mipsel64N32, c"mips64-le-n32"),
    (SeccompArch::Parisc, c"parisc"),
    (SeccompArch::Parisc64, c"parisc64"),
    (SeccompArch::Ppc, c"ppc"),
    (SeccompArch::Ppc64, c"ppc64"),
    (SeccompArch::Ppc64Le, c"ppc64-le"),
    #[cfg(systemd_seccomp_arch_riscv64)]
    (SeccompArch::Riscv64, c"riscv64"),
    (SeccompArch::S390, c"s390"),
    (SeccompArch::S390X, c"s390x"),
];

impl SeccompArch {
    pub fn from_u32(value: u32) -> Option<Self> {
        ARCHITECTURES
            .iter()
            .find_map(|&(arch, _)| (arch as u32 == value).then_some(arch))
    }

    pub fn name(&self) -> &'static str {
        seccomp_arch_to_string(*self as u32).unwrap_or("unknown")
    }
}

pub fn seccomp_errno_or_action_is_valid(n: i32) -> bool {
    n == SECCOMP_ERROR_NUMBER_KILL || crate::errno_util::errno_is_valid(n)
}

fn numeric_digit(byte: u8, radix: u32) -> Option<i64> {
    let digit = match byte {
        b'0'..=b'9' => u32::from(byte - b'0'),
        b'a'..=b'f' => u32::from(byte - b'a') + 10,
        b'A'..=b'F' => u32::from(byte - b'A') + 10,
        _ => return None,
    };
    (digit < radix).then_some(i64::from(digit))
}

/// Parse the integer syntax accepted by C `safe_atoi()`.
///
/// In addition to `strtol(..., base=0)` syntax this accepts systemd's `0b` and
/// `0o` prefixes. Leading C whitespace is accepted, trailing bytes are not.
fn parse_safe_i32(input: &[u8]) -> Result<i32, i32> {
    let mut input = input;
    while matches!(input.first(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        input = &input[1..];
    }

    // mangle_base() runs before strtol(), so the systemd-only prefixes are
    // recognized only when they occur before the optional sign.
    let (mut radix, mut digits) = if let Some(rest) = input
        .strip_prefix(b"0b")
        .or_else(|| input.strip_prefix(b"0B"))
    {
        (2, rest)
    } else if let Some(rest) = input
        .strip_prefix(b"0o")
        .or_else(|| input.strip_prefix(b"0O"))
    {
        (8, rest)
    } else {
        (0, input)
    };

    // strtol() performs its own locale-independent C whitespace skip after
    // mangle_base() has selected/removed a prefix. This ordering intentionally
    // makes "0b 10" valid while "\v0b10" remains invalid.
    while matches!(
        digits.first(),
        Some(b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
    ) {
        digits = &digits[1..];
    }

    let negative = match digits.first() {
        Some(b'-') => {
            digits = &digits[1..];
            true
        }
        Some(b'+') => {
            digits = &digits[1..];
            false
        }
        _ => false,
    };

    if radix == 0 {
        if let Some(rest) = digits
            .strip_prefix(b"0x")
            .or_else(|| digits.strip_prefix(b"0X"))
        {
            radix = 16;
            digits = rest;
        } else if digits.first() == Some(&b'0') {
            radix = 8;
        } else {
            radix = 10;
        }
    }
    if digits.is_empty() {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let limit = if negative {
        i64::from(i32::MAX) + 1
    } else {
        i64::from(i32::MAX)
    };
    let mut value = 0_i64;
    for &byte in digits {
        let Some(digit) = numeric_digit(byte, radix) else {
            return Err(Errno::EINVAL.to_neg_errno());
        };
        let Some(next) = value
            .checked_mul(i64::from(radix))
            .and_then(|value| value.checked_add(digit))
        else {
            return Err(Errno::ERANGE.to_neg_errno());
        };
        if next > limit {
            return Err(Errno::ERANGE.to_neg_errno());
        }
        value = next;
    }

    if negative {
        if value == i64::from(i32::MAX) + 1 {
            Ok(i32::MIN)
        } else {
            Ok(-(value as i32))
        }
    } else {
        Ok(value as i32)
    }
}

fn seccomp_parse_errno_or_action_bytes(p: &[u8]) -> Result<i32, i32> {
    if p == b"kill" {
        return Ok(SECCOMP_ERROR_NUMBER_KILL);
    }
    if let Ok(name) = std::str::from_utf8(p) {
        if let Ok(errno) = crate::errno_util::errno_from_name(name) {
            return Ok(errno);
        }
    }

    let errno = parse_safe_i32(p)?;
    if errno == 0 || crate::errno_util::errno_is_valid(errno) {
        Ok(errno)
    } else {
        Err(Errno::ERANGE.to_neg_errno())
    }
}

pub fn seccomp_parse_errno_or_action(p: &str) -> Result<i32, i32> {
    seccomp_parse_errno_or_action_bytes(p.as_bytes())
}

fn seccomp_errno_or_action_to_cstr(num: i32) -> Option<&'static CStr> {
    if num == SECCOMP_ERROR_NUMBER_KILL {
        return Some(c"kill");
    }
    crate::errno_util::errno_name_no_fallback_cstr(num).ok()
}

pub fn seccomp_errno_or_action_to_string(num: i32) -> Result<&'static str, i32> {
    seccomp_errno_or_action_to_cstr(num)
        .and_then(|name| name.to_str().ok())
        .ok_or_else(|| Errno::EINVAL.to_neg_errno())
}

fn seccomp_arch_to_cstr(arch: u32) -> Option<&'static CStr> {
    ARCHITECTURES
        .iter()
        .find_map(|&(candidate, name)| (candidate as u32 == arch).then_some(name))
}

pub fn seccomp_arch_to_string(arch: u32) -> Option<&'static str> {
    seccomp_arch_to_cstr(arch).and_then(|name| name.to_str().ok())
}

fn seccomp_arch_from_bytes(name: &[u8]) -> Result<u32, i32> {
    ARCHITECTURES
        .iter()
        .find_map(|&(arch, candidate)| (candidate.to_bytes() == name).then_some(arch as u32))
        .ok_or_else(|| Errno::EINVAL.to_neg_errno())
}

pub fn seccomp_arch_from_string(name: &str) -> Result<u32, i32> {
    seccomp_arch_from_bytes(name.as_bytes())
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_seccomp_errno_or_action_is_valid(n: c_int) -> bool {
    seccomp_errno_or_action_is_valid(n)
}

/// Parse a NUL-terminated errno/action string for C.
///
/// # Safety
/// `p` must be null or point to a readable NUL-terminated C string for the
/// duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_seccomp_parse_errno_or_action(p: *const c_char) -> c_int {
    if p.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the caller contract guarantees a readable NUL-terminated string.
    let p = unsafe { CStr::from_ptr(p) };
    seccomp_parse_errno_or_action_bytes(p.to_bytes()).unwrap_or_else(|error| error)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_seccomp_errno_or_action_to_string(num: c_int) -> *const c_char {
    seccomp_errno_or_action_to_cstr(num).map_or(ptr::null(), CStr::as_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_seccomp_arch_to_string(arch: u32) -> *const c_char {
    seccomp_arch_to_cstr(arch).map_or(ptr::null(), CStr::as_ptr)
}

/// Convert a NUL-terminated architecture name and write its token for C.
///
/// # Safety
/// `name` must be null or point to a readable NUL-terminated C string. `ret`
/// must be null or point to writable, properly aligned storage for one `u32`.
/// The two regions must not violate Rust's aliasing rules for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_seccomp_arch_from_string(name: *const c_char, ret: *mut u32) -> c_int {
    if name.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the caller contract guarantees a readable NUL-terminated string.
    let name = unsafe { CStr::from_ptr(name) };
    let Ok(arch) = seccomp_arch_from_bytes(name.to_bytes()) else {
        return Errno::EINVAL.to_neg_errno();
    };
    // SAFETY: the caller contract guarantees writable aligned storage.
    unsafe { ret.write(arch) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_or_action_validation_matches_c_range() {
        assert!(seccomp_errno_or_action_is_valid(SECCOMP_ERROR_NUMBER_KILL));
        assert!(seccomp_errno_or_action_is_valid(1));
        assert!(seccomp_errno_or_action_is_valid(ERRNO_MAX));
        assert!(!seccomp_errno_or_action_is_valid(0));
        assert!(!seccomp_errno_or_action_is_valid(-1));
        assert!(!seccomp_errno_or_action_is_valid(ERRNO_MAX + 1));
    }

    #[test]
    fn errno_or_action_parser_matches_parse_errno_syntax() {
        assert_eq!(
            seccomp_parse_errno_or_action("kill"),
            Ok(SECCOMP_ERROR_NUMBER_KILL)
        );
        assert_eq!(seccomp_parse_errno_or_action("EPERM"), Ok(libc::EPERM));
        assert_eq!(seccomp_parse_errno_or_action("0"), Ok(0));
        assert_eq!(seccomp_parse_errno_or_action("  02"), Ok(2));
        assert_eq!(seccomp_parse_errno_or_action("0x2"), Ok(2));
        assert_eq!(seccomp_parse_errno_or_action("0b10"), Ok(2));
        assert_eq!(seccomp_parse_errno_or_action("0b 10"), Ok(2));
        assert_eq!(seccomp_parse_errno_or_action("0o2"), Ok(2));
        assert_eq!(
            seccomp_parse_errno_or_action("\u{b}0b10"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            seccomp_parse_errno_or_action("-1"),
            Err(Errno::ERANGE.to_neg_errno())
        );
        assert_eq!(
            seccomp_parse_errno_or_action("4096"),
            Err(Errno::ERANGE.to_neg_errno())
        );
        assert_eq!(
            seccomp_parse_errno_or_action("2 "),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }

    #[test]
    fn errno_names_are_static_c_strings() {
        assert_eq!(
            seccomp_errno_or_action_to_cstr(SECCOMP_ERROR_NUMBER_KILL),
            Some(c"kill")
        );
        assert_eq!(seccomp_errno_or_action_to_cstr(libc::EPERM), Some(c"EPERM"));
        assert_eq!(seccomp_errno_or_action_to_cstr(0), None);
    }

    #[test]
    fn architecture_constants_match_libseccomp_abi() {
        #[cfg(systemd_seccomp_arch_loongarch64)]
        assert_eq!(SeccompArch::Loongarch64 as u32, 0xc000_0102);
        #[cfg(systemd_seccomp_arch_riscv64)]
        assert_eq!(SeccompArch::Riscv64 as u32, 0xc000_00f3);
        assert_eq!(SeccompArch::Mips64N32 as u32, 0xa000_0008);
        assert_eq!(SeccompArch::Mipsel as u32, 0x4000_0008);
        assert_eq!(SeccompArch::Mipsel64 as u32, 0xc000_0008);
        assert_eq!(SeccompArch::Mipsel64N32 as u32, 0xe000_0008);
        assert_eq!(SeccompArch::Ppc as u32, 0x0000_0014);
    }

    #[test]
    fn architectures_round_trip() {
        for &(arch, name) in ARCHITECTURES {
            assert_eq!(seccomp_arch_to_cstr(arch as u32), Some(name));
            assert_eq!(seccomp_arch_from_bytes(name.to_bytes()), Ok(arch as u32));
        }
        assert_eq!(seccomp_arch_to_cstr(0xdead_beef), None);
        assert_eq!(
            seccomp_arch_from_bytes(b"X86"),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }
}
