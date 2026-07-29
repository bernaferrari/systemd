// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.compress; authority=src/basic/compress.c,src/basic/compress.h
//
// Compression enum tables and compression_supported() C ABI facades.

use crate::ffi::Errno;
use crate::ffi_string_table::{self, Entry as FfiEntry};
use std::ffi::c_char;

// ── Enum ──────────────────────────────────────────────────────────────────

/// Mirrors the native C `Compression` enum exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Compression {
    None = 0,
    Xz = 1,
    Lz4 = 2,
    Zstd = 3,
    Gzip = 4,
    Bzip2 = 5,
}

pub const COMPRESSION_MAX: usize = 6;

impl Compression {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Xz),
            2 => Some(Self::Lz4),
            3 => Some(Self::Zstd),
            4 => Some(Self::Gzip),
            5 => Some(Self::Bzip2),
            _ => None,
        }
    }

    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

const fn supported_bit(enabled: bool, compression: Compression) -> u32 {
    if enabled {
        1_u32 << compression as u32
    } else {
        0
    }
}

// Meson supplies these cfgs from the same HAVE_* feature probes that compile
// compress.c. Standalone Cargo intentionally falls back to NONE-only, which
// is safe and does not introduce a test-only C symbol dependency.
const CONFIGURED_COMPRESSION_SUPPORTED_MASK: u32 = (1_u32 << Compression::None as u32)
    | supported_bit(cfg!(systemd_have_xz), Compression::Xz)
    | supported_bit(cfg!(systemd_have_lz4), Compression::Lz4)
    | supported_bit(cfg!(systemd_have_zstd), Compression::Zstd)
    | supported_bit(cfg!(systemd_have_zlib), Compression::Gzip)
    | supported_bit(cfg!(systemd_have_bzip2), Compression::Bzip2);

// ── String tables ─────────────────────────────────────────────────────────

/// Rust-owned NUL-backed copies of C's `compression_table`. Their pointers
/// are borrowed process-lifetime storage, like C's static table entries.
static COMPRESSION_TABLE: &[FfiEntry] = &[
    (Compression::None as i32, b"uncompressed\0"),
    (Compression::Xz as i32, b"xz\0"),
    (Compression::Lz4 as i32, b"lz4\0"),
    (Compression::Zstd as i32, b"zstd\0"),
    (Compression::Gzip as i32, b"gzip\0"),
    (Compression::Bzip2 as i32, b"bzip2\0"),
];

/// Rust-owned NUL-backed copies of C's `compression_uppercase_table`.
static COMPRESSION_UPPERCASE_TABLE: &[FfiEntry] = &[
    (Compression::None as i32, b"NONE\0"),
    (Compression::Xz as i32, b"XZ\0"),
    (Compression::Lz4 as i32, b"LZ4\0"),
    (Compression::Zstd as i32, b"ZSTD\0"),
    (Compression::Gzip as i32, b"GZIP\0"),
    (Compression::Bzip2 as i32, b"BZIP2\0"),
];

// ── Pure Rust API ─────────────────────────────────────────────────────────

/// Mirrors C's `compression_to_string()`.
pub fn compression_to_string(compression: Compression) -> Option<&'static str> {
    ffi_string_table::to_str(COMPRESSION_TABLE, compression as i32)
}

/// Mirrors C's `compression_from_string()`.
pub fn compression_from_string(value: &str) -> Result<Compression, Errno> {
    ffi_string_table::from_str(COMPRESSION_TABLE, value)
        .and_then(Compression::from_i32)
        .ok_or(Errno::EINVAL)
}

/// Mirrors C's `compression_uppercase_to_string()`.
pub fn compression_to_string_uppercase(compression: Compression) -> Option<&'static str> {
    ffi_string_table::to_str(COMPRESSION_UPPERCASE_TABLE, compression as i32)
}

/// Mirrors C's `compression_uppercase_from_string()`.
pub fn compression_from_string_uppercase(value: &str) -> Result<Compression, Errno> {
    ffi_string_table::from_str(COMPRESSION_UPPERCASE_TABLE, value)
        .and_then(Compression::from_i32)
        .ok_or(Errno::EINVAL)
}

/// Compatibility spelling for consumers of the former Rust API.
///
/// C no longer has a separate lowercase table. Its current ordinary table is
/// lowercase except for the historical `"uncompressed"` spelling.
pub fn compression_to_string_lowercase(compression: Compression) -> Option<&'static str> {
    compression_to_string(compression)
}

/// Compatibility spelling for consumers of the former Rust API.
pub fn compression_from_string_lowercase(value: &str) -> Result<Compression, Errno> {
    compression_from_string(value)
}

/// Check a valid compression value against a C-style feature mask.
pub fn compression_supported_with_mask(compression: Compression, mask: u32) -> bool {
    mask & (1u32 << compression as u32) != 0
}

/// Mirrors C's `compression_supported()` using the configured C feature mask.
pub fn compression_supported(compression: Compression) -> bool {
    compression_supported_with_mask(compression, CONFIGURED_COMPRESSION_SUPPORTED_MASK)
}

// ── C ABI facades ─────────────────────────────────────────────────────────

/// C ABI facade for `compression_to_string()`.
///
/// The result is borrowed immutable static storage and remains valid for the
/// process lifetime. Unknown discriminants return NULL.
#[unsafe(no_mangle)]
pub extern "C" fn rs_compression_to_string(compression: i32) -> *const c_char {
    ffi_string_table::to_ptr(COMPRESSION_TABLE, compression)
}

/// C ABI facade for `compression_from_string()`.
///
/// # Safety
///
/// `value` may be NULL, which returns `-EINVAL`. A non-NULL pointer must be a
/// live NUL-terminated C string for this call; its bytes are borrowed only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_compression_from_string(value: *const c_char) -> i32 {
    // SAFETY: this forwards the documented C-string borrowing contract.
    unsafe { ffi_string_table::from_ptr(COMPRESSION_TABLE, value, Errno::EINVAL.to_neg_errno()) }
}

/// C ABI facade for `compression_uppercase_to_string()`.
///
/// Its result is borrowed immutable static storage, or NULL for an unknown
/// discriminant.
#[unsafe(no_mangle)]
pub extern "C" fn rs_compression_uppercase_to_string(compression: i32) -> *const c_char {
    ffi_string_table::to_ptr(COMPRESSION_UPPERCASE_TABLE, compression)
}

/// C ABI facade for `compression_uppercase_from_string()`.
///
/// # Safety
///
/// `value` may be NULL, which returns `-EINVAL`. A non-NULL pointer must be a
/// live NUL-terminated C string for this call; its bytes are borrowed only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_compression_uppercase_from_string(value: *const c_char) -> i32 {
    // SAFETY: this forwards the documented C-string borrowing contract.
    unsafe {
        ffi_string_table::from_ptr(
            COMPRESSION_UPPERCASE_TABLE,
            value,
            Errno::EINVAL.to_neg_errno(),
        )
    }
}

/// C ABI facade for `compression_supported()`.
///
/// C asserts on invalid enum values. This checked facade instead returns false
/// for them, avoiding an invalid shift while preserving C's result over its
/// documented valid enum domain.
#[unsafe(no_mangle)]
pub extern "C" fn rs_compression_supported(compression: i32) -> bool {
    Compression::from_i32(compression).is_some_and(compression_supported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_enum_c_domain_is_complete() {
        assert_eq!(COMPRESSION_MAX, 6);
        assert_eq!(Compression::from_i32(0), Some(Compression::None));
        assert_eq!(Compression::from_i32(1), Some(Compression::Xz));
        assert_eq!(Compression::from_i32(2), Some(Compression::Lz4));
        assert_eq!(Compression::from_i32(3), Some(Compression::Zstd));
        assert_eq!(Compression::from_i32(4), Some(Compression::Gzip));
        assert_eq!(Compression::from_i32(5), Some(Compression::Bzip2));
        assert_eq!(Compression::from_i32(-1), None);
        assert_eq!(Compression::from_i32(COMPRESSION_MAX as i32), None);
    }

    #[test]
    fn compression_tables_match_c_spellings() {
        assert_eq!(
            compression_to_string(Compression::None),
            Some("uncompressed")
        );
        assert_eq!(compression_to_string(Compression::Gzip), Some("gzip"));
        assert_eq!(compression_to_string(Compression::Bzip2), Some("bzip2"));
        assert_eq!(
            compression_to_string_uppercase(Compression::None),
            Some("NONE")
        );
        assert_eq!(
            compression_to_string_uppercase(Compression::Gzip),
            Some("GZIP")
        );
        assert_eq!(
            compression_to_string_uppercase(Compression::Bzip2),
            Some("BZIP2")
        );
        assert_eq!(
            compression_from_string("uncompressed"),
            Ok(Compression::None)
        );
        assert_eq!(
            compression_from_string_uppercase("NONE"),
            Ok(Compression::None)
        );
        assert_eq!(compression_from_string("NONE"), Err(Errno::EINVAL));
        assert_eq!(
            compression_from_string_uppercase("uncompressed"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn compression_supported_honours_all_current_bits() {
        let mask = (1u32 << Compression::None as u32)
            | (1u32 << Compression::Gzip as u32)
            | (1u32 << Compression::Bzip2 as u32);

        assert!(compression_supported_with_mask(Compression::None, mask));
        assert!(!compression_supported_with_mask(Compression::Xz, mask));
        assert!(!compression_supported_with_mask(Compression::Lz4, mask));
        assert!(!compression_supported_with_mask(Compression::Zstd, mask));
        assert!(compression_supported_with_mask(Compression::Gzip, mask));
        assert!(compression_supported_with_mask(Compression::Bzip2, mask));
    }
}
