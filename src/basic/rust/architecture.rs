// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/architecture.c, src/basic/architecture.h
//
// Architecture string table lookup: to_string, from_string.

use crate::ffi::Errno;
use crate::ffi_string_table::{self, Entry as FfiEntry};
use libc::c_char;

// ── Architecture enum ─────────────────────────────────────────────────────

/// Architecture types matching the C enum in architecture.h.
/// Order and discriminant values must match the C definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Architecture {
    Alpha = 0,
    Arc = 1,
    ArcBe = 2,
    Arm = 3,
    Arm64 = 4,
    Arm64Be = 5,
    ArmBe = 6,
    Cris = 7,
    Ia64 = 8,
    Loongarch64 = 9,
    M68k = 10,
    Mips = 11,
    Mips64 = 12,
    Mips64Le = 13,
    MipsLe = 14,
    Nios2 = 15,
    Parisc = 16,
    Parisc64 = 17,
    Ppc = 18,
    Ppc64 = 19,
    Ppc64Le = 20,
    PpcLe = 21,
    Riscv32 = 22,
    Riscv64 = 23,
    S390 = 24,
    S390x = 25,
    Sh = 26,
    Sh64 = 27,
    Sparc = 28,
    Sparc64 = 29,
    Tilegx = 30,
    X86 = 31,
    X86_64 = 32,
}

impl Architecture {
    /// Total number of valid architecture variants.
    pub const COUNT: usize = ARCHITECTURE_TABLE.len();

    /// Convert from a raw i32 value (as used in the C enum).
    pub fn from_raw(val: i32) -> Option<Self> {
        match val {
            value if value == Self::Alpha as i32 => Some(Self::Alpha),
            value if value == Self::Arc as i32 => Some(Self::Arc),
            value if value == Self::ArcBe as i32 => Some(Self::ArcBe),
            value if value == Self::Arm as i32 => Some(Self::Arm),
            value if value == Self::Arm64 as i32 => Some(Self::Arm64),
            value if value == Self::Arm64Be as i32 => Some(Self::Arm64Be),
            value if value == Self::ArmBe as i32 => Some(Self::ArmBe),
            value if value == Self::Cris as i32 => Some(Self::Cris),
            value if value == Self::Ia64 as i32 => Some(Self::Ia64),
            value if value == Self::Loongarch64 as i32 => Some(Self::Loongarch64),
            value if value == Self::M68k as i32 => Some(Self::M68k),
            value if value == Self::Mips as i32 => Some(Self::Mips),
            value if value == Self::Mips64 as i32 => Some(Self::Mips64),
            value if value == Self::Mips64Le as i32 => Some(Self::Mips64Le),
            value if value == Self::MipsLe as i32 => Some(Self::MipsLe),
            value if value == Self::Nios2 as i32 => Some(Self::Nios2),
            value if value == Self::Parisc as i32 => Some(Self::Parisc),
            value if value == Self::Parisc64 as i32 => Some(Self::Parisc64),
            value if value == Self::Ppc as i32 => Some(Self::Ppc),
            value if value == Self::Ppc64 as i32 => Some(Self::Ppc64),
            value if value == Self::Ppc64Le as i32 => Some(Self::Ppc64Le),
            value if value == Self::PpcLe as i32 => Some(Self::PpcLe),
            value if value == Self::Riscv32 as i32 => Some(Self::Riscv32),
            value if value == Self::Riscv64 as i32 => Some(Self::Riscv64),
            value if value == Self::S390 as i32 => Some(Self::S390),
            value if value == Self::S390x as i32 => Some(Self::S390x),
            value if value == Self::Sh as i32 => Some(Self::Sh),
            value if value == Self::Sh64 as i32 => Some(Self::Sh64),
            value if value == Self::Sparc as i32 => Some(Self::Sparc),
            value if value == Self::Sparc64 as i32 => Some(Self::Sparc64),
            value if value == Self::Tilegx as i32 => Some(Self::Tilegx),
            value if value == Self::X86 as i32 => Some(Self::X86),
            value if value == Self::X86_64 as i32 => Some(Self::X86_64),
            _ => None,
        }
    }

    /// Convert to raw i32 value.
    pub fn to_raw(self) -> i32 {
        self as i32
    }
}

// ── Architecture name table ───────────────────────────────────────────────

/// The sole architecture value/name authority. Each key is derived from the
/// public enum variant, so changing an enum ordinal cannot silently rebind a
/// Rust or C ABI name. The NUL-terminated literals also back borrowed C ABI
/// return values directly.
const ARCHITECTURE_TABLE: &[FfiEntry] = &[
    (Architecture::Alpha as i32, b"alpha\0"),
    (Architecture::Arc as i32, b"arc\0"),
    (Architecture::ArcBe as i32, b"arc-be\0"),
    (Architecture::Arm as i32, b"arm\0"),
    (Architecture::Arm64 as i32, b"arm64\0"),
    (Architecture::Arm64Be as i32, b"arm64-be\0"),
    (Architecture::ArmBe as i32, b"arm-be\0"),
    (Architecture::Cris as i32, b"cris\0"),
    (Architecture::Ia64 as i32, b"ia64\0"),
    (Architecture::Loongarch64 as i32, b"loongarch64\0"),
    (Architecture::M68k as i32, b"m68k\0"),
    (Architecture::Mips as i32, b"mips\0"),
    (Architecture::Mips64 as i32, b"mips64\0"),
    (Architecture::Mips64Le as i32, b"mips64-le\0"),
    (Architecture::MipsLe as i32, b"mips-le\0"),
    (Architecture::Nios2 as i32, b"nios2\0"),
    (Architecture::Parisc as i32, b"parisc\0"),
    (Architecture::Parisc64 as i32, b"parisc64\0"),
    (Architecture::Ppc as i32, b"ppc\0"),
    (Architecture::Ppc64 as i32, b"ppc64\0"),
    (Architecture::Ppc64Le as i32, b"ppc64-le\0"),
    (Architecture::PpcLe as i32, b"ppc-le\0"),
    (Architecture::Riscv32 as i32, b"riscv32\0"),
    (Architecture::Riscv64 as i32, b"riscv64\0"),
    (Architecture::S390 as i32, b"s390\0"),
    (Architecture::S390x as i32, b"s390x\0"),
    (Architecture::Sh as i32, b"sh\0"),
    (Architecture::Sh64 as i32, b"sh64\0"),
    (Architecture::Sparc as i32, b"sparc\0"),
    (Architecture::Sparc64 as i32, b"sparc64\0"),
    (Architecture::Tilegx as i32, b"tilegx\0"),
    (Architecture::X86 as i32, b"x86\0"),
    (Architecture::X86_64 as i32, b"x86-64\0"),
];

// ── architecture_to_string ────────────────────────────────────────────────

/// Convert an Architecture to its string representation.
/// Returns None for invalid values.
/// Matches C DEFINE_STRING_TABLE_LOOKUP behavior.
pub fn architecture_to_string(arch: Architecture) -> &'static str {
    ffi_string_table::to_str(ARCHITECTURE_TABLE, arch as i32)
        .expect("valid Architecture variant must have a table entry")
}

/// Convert a raw i32 architecture value to its string representation.
/// Returns None for invalid values.
pub fn architecture_to_string_from_raw(val: i32) -> Option<&'static str> {
    Architecture::from_raw(val).map(|a| architecture_to_string(a))
}

// ── architecture_from_string ──────────────────────────────────────────────

/// Convert a string to an Architecture enum value.
/// Case-sensitive, returns Err(-EINVAL) on failure.
/// Matches C DEFINE_STRING_TABLE_LOOKUP behavior.
pub fn architecture_from_string(s: &str) -> Result<Architecture, i32> {
    ffi_string_table::from_str(ARCHITECTURE_TABLE, s)
        .and_then(Architecture::from_raw)
        .ok_or(Errno::EINVAL.to_neg_errno())
}

/// C ABI facade for `architecture_to_string()`.
///
/// The returned pointer refers to immutable static storage and must not be
/// freed. Invalid enum values produce NULL, matching the C string-table
/// helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_architecture_to_string(architecture: i32) -> *const c_char {
    ffi_string_table::to_ptr(ARCHITECTURE_TABLE, architecture)
}

/// C ABI facade for `architecture_from_string()`.
///
/// # Safety
///
/// A non-NULL `name` must point to a valid NUL-terminated C string for the
/// duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_architecture_from_string(name: *const c_char) -> i32 {
    if name.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: required by this C ABI entry point's contract and checked for
    // NULL above; the shared adapter borrows it only.
    unsafe { ffi_string_table::from_ptr(ARCHITECTURE_TABLE, name, Errno::EINVAL.to_neg_errno()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_to_string_all() {
        assert_eq!(architecture_to_string(Architecture::Alpha), "alpha");
        assert_eq!(architecture_to_string(Architecture::X86_64), "x86-64");
        assert_eq!(architecture_to_string(Architecture::Arm64), "arm64");
        assert_eq!(architecture_to_string(Architecture::Riscv64), "riscv64");
        assert_eq!(architecture_to_string(Architecture::S390x), "s390x");
        assert_eq!(
            architecture_to_string(Architecture::Loongarch64),
            "loongarch64"
        );
    }

    #[test]
    fn test_architecture_to_string_from_raw_valid() {
        assert_eq!(architecture_to_string_from_raw(0), Some("alpha"));
        assert_eq!(architecture_to_string_from_raw(32), Some("x86-64"));
        assert_eq!(architecture_to_string_from_raw(4), Some("arm64"));
        assert_eq!(architecture_to_string_from_raw(31), Some("x86"));
    }

    #[test]
    fn test_architecture_to_string_from_raw_invalid() {
        assert_eq!(architecture_to_string_from_raw(-1), None);
        assert_eq!(architecture_to_string_from_raw(33), None);
        assert_eq!(architecture_to_string_from_raw(100), None);
        assert_eq!(architecture_to_string_from_raw(i32::MIN), None);
        assert_eq!(architecture_to_string_from_raw(i32::MAX), None);
    }

    #[test]
    fn test_architecture_from_string_valid() {
        assert_eq!(architecture_from_string("alpha"), Ok(Architecture::Alpha));
        assert_eq!(architecture_from_string("x86-64"), Ok(Architecture::X86_64));
        assert_eq!(architecture_from_string("arm64"), Ok(Architecture::Arm64));
        assert_eq!(
            architecture_from_string("riscv64"),
            Ok(Architecture::Riscv64)
        );
        assert_eq!(architecture_from_string("s390x"), Ok(Architecture::S390x));
        assert_eq!(
            architecture_from_string("loongarch64"),
            Ok(Architecture::Loongarch64)
        );
    }

    #[test]
    fn test_architecture_from_string_invalid() {
        assert!(architecture_from_string("x86_64").is_err());
        assert!(architecture_from_string("").is_err());
        assert!(architecture_from_string("unknown").is_err());
        assert!(architecture_from_string("ARM64").is_err());
        assert!(architecture_from_string("X86-64").is_err());
    }

    #[test]
    fn test_architecture_from_string_error_value() {
        assert_eq!(
            architecture_from_string("invalid"),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }

    #[test]
    fn test_architecture_roundtrip() {
        for i in 0..Architecture::COUNT {
            let arch = Architecture::from_raw(i as i32).unwrap();
            let name = architecture_to_string(arch);
            let result = architecture_from_string(name).unwrap();
            assert_eq!(result, arch, "roundtrip failed for {} (idx={})", name, i);
        }
    }

    #[test]
    fn test_architecture_from_raw_all_valid() {
        for i in 0..Architecture::COUNT {
            assert!(Architecture::from_raw(i as i32).is_some());
        }
    }

    #[test]
    fn test_architecture_from_raw_to_raw_roundtrip() {
        for i in 0..Architecture::COUNT {
            let arch = Architecture::from_raw(i as i32).unwrap();
            assert_eq!(arch.to_raw(), i as i32);
        }
    }

    #[test]
    fn test_architecture_enum_equality() {
        assert_eq!(Architecture::X86_64, Architecture::X86_64);
        assert_ne!(Architecture::X86, Architecture::X86_64);
        assert_ne!(Architecture::Arm, Architecture::Arm64);
    }

    #[test]
    fn test_architecture_to_string_edge_cases() {
        assert_eq!(architecture_to_string(Architecture::Mips64Le), "mips64-le");
        assert_eq!(architecture_to_string(Architecture::MipsLe), "mips-le");
        assert_eq!(architecture_to_string(Architecture::Ppc64Le), "ppc64-le");
        assert_eq!(architecture_to_string(Architecture::PpcLe), "ppc-le");
        assert_eq!(architecture_to_string(Architecture::ArcBe), "arc-be");
        assert_eq!(architecture_to_string(Architecture::Arm64Be), "arm64-be");
    }
}
