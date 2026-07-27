// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/compress.c (string table subset)
//
// Compression enum, string table lookups, and compression_supported().

use crate::ffi::Errno;

// ── Enums ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Compression {
    None = 0,
    Xz = 1,
    Lz4 = 2,
    Zstd = 3,
}

pub const COMPRESSION_MAX: usize = 4;

impl Compression {
    pub fn from_i32(val: i32) -> Option<Self> {
        match val {
            0 => Some(Compression::None),
            1 => Some(Compression::Xz),
            2 => Some(Compression::Lz4),
            3 => Some(Compression::Zstd),
            _ => None,
        }
    }

    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

// ── String tables ────────────────────────────────────────────────────────

static COMPRESSION_NAMES: &[&str] = &["NONE", "XZ", "LZ4", "ZSTD"];
static COMPRESSION_NAMES_LOWERCASE: &[&str] = &["none", "xz", "lz4", "zstd"];

// ── compression_to_string ───────────────────────────────────────────────

pub fn compression_to_string(c: Compression) -> Option<&'static str> {
    COMPRESSION_NAMES.get(c as usize).copied()
}

// ── compression_from_string ─────────────────────────────────────────────

pub fn compression_from_string(s: &str) -> Result<Compression, Errno> {
    for (i, name) in COMPRESSION_NAMES.iter().enumerate() {
        if *name == s {
            return Ok(Compression::from_i32(i as i32).unwrap());
        }
    }
    Err(Errno::EINVAL)
}

// ── compression_to_string_lowercase ─────────────────────────────────────

pub fn compression_to_string_lowercase(c: Compression) -> Option<&'static str> {
    COMPRESSION_NAMES_LOWERCASE.get(c as usize).copied()
}

// ── compression_from_string_lowercase ───────────────────────────────────

pub fn compression_from_string_lowercase(s: &str) -> Result<Compression, Errno> {
    for (i, name) in COMPRESSION_NAMES_LOWERCASE.iter().enumerate() {
        if *name == s {
            return Ok(Compression::from_i32(i as i32).unwrap());
        }
    }
    Err(Errno::EINVAL)
}

// ── compression_supported ───────────────────────────────────────────────

/// Default supported mask: only COMPRESSION_NONE is always available.
/// The other algorithms depend on build-time features. Callers may
/// provide a different mask if the build configuration is known.
pub const DEFAULT_COMPRESSION_SUPPORTED_MASK: u32 = 1u32 << (Compression::None as u32);

/// Check whether a compression algorithm is supported given a bitmask.
/// Each bit `i` indicates that `Compression::from_i32(i)` is available.
pub fn compression_supported_with_mask(c: Compression, mask: u32) -> bool {
    (mask & (1u32 << c as u32)) != 0
}

/// Check whether a compression algorithm is supported using the default mask.
pub fn compression_supported(c: Compression) -> bool {
    compression_supported_with_mask(c, DEFAULT_COMPRESSION_SUPPORTED_MASK)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Compression enum ───────────────────────────────────────────────

    #[test]
    fn test_compression_from_i32_valid() {
        assert_eq!(Compression::from_i32(0), Some(Compression::None));
        assert_eq!(Compression::from_i32(1), Some(Compression::Xz));
        assert_eq!(Compression::from_i32(2), Some(Compression::Lz4));
        assert_eq!(Compression::from_i32(3), Some(Compression::Zstd));
    }

    #[test]
    fn test_compression_from_i32_invalid() {
        assert_eq!(Compression::from_i32(-1), None);
        assert_eq!(Compression::from_i32(4), None);
        assert_eq!(Compression::from_i32(100), None);
    }

    #[test]
    fn test_compression_to_i32_roundtrip() {
        for val in 0..4 {
            let c = Compression::from_i32(val).unwrap();
            assert_eq!(c.to_i32(), val);
        }
    }

    // ── compression_to_string ──────────────────────────────────────────

    #[test]
    fn test_compression_to_string_all() {
        assert_eq!(compression_to_string(Compression::None), Some("NONE"));
        assert_eq!(compression_to_string(Compression::Xz), Some("XZ"));
        assert_eq!(compression_to_string(Compression::Lz4), Some("LZ4"));
        assert_eq!(compression_to_string(Compression::Zstd), Some("ZSTD"));
    }

    #[test]
    fn test_compression_from_string_valid() {
        assert_eq!(compression_from_string("NONE"), Ok(Compression::None));
        assert_eq!(compression_from_string("XZ"), Ok(Compression::Xz));
        assert_eq!(compression_from_string("LZ4"), Ok(Compression::Lz4));
        assert_eq!(compression_from_string("ZSTD"), Ok(Compression::Zstd));
    }

    #[test]
    fn test_compression_from_string_invalid() {
        assert_eq!(compression_from_string("xz"), Err(Errno::EINVAL));
        assert_eq!(compression_from_string(""), Err(Errno::EINVAL));
        assert_eq!(compression_from_string("unknown"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_compression_string_roundtrip() {
        for val in 0..4 {
            let c = Compression::from_i32(val).unwrap();
            let s = compression_to_string(c).unwrap();
            assert_eq!(compression_from_string(s), Ok(c));
        }
    }

    // ── lowercase variants ─────────────────────────────────────────────

    #[test]
    fn test_compression_to_string_lowercase_all() {
        assert_eq!(
            compression_to_string_lowercase(Compression::None),
            Some("none")
        );
        assert_eq!(compression_to_string_lowercase(Compression::Xz), Some("xz"));
        assert_eq!(
            compression_to_string_lowercase(Compression::Lz4),
            Some("lz4")
        );
        assert_eq!(
            compression_to_string_lowercase(Compression::Zstd),
            Some("zstd")
        );
    }

    #[test]
    fn test_compression_from_string_lowercase_valid() {
        assert_eq!(
            compression_from_string_lowercase("none"),
            Ok(Compression::None)
        );
        assert_eq!(compression_from_string_lowercase("xz"), Ok(Compression::Xz));
        assert_eq!(
            compression_from_string_lowercase("lz4"),
            Ok(Compression::Lz4)
        );
        assert_eq!(
            compression_from_string_lowercase("zstd"),
            Ok(Compression::Zstd)
        );
    }

    #[test]
    fn test_compression_from_string_lowercase_uppercase_fails() {
        assert_eq!(
            compression_from_string_lowercase("ZSTD"),
            Err(Errno::EINVAL)
        );
        assert_eq!(compression_from_string_lowercase("XZ"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_compression_lowercase_roundtrip() {
        for val in 0..4 {
            let c = Compression::from_i32(val).unwrap();
            let s = compression_to_string_lowercase(c).unwrap();
            assert_eq!(compression_from_string_lowercase(s), Ok(c));
        }
    }

    // ── compression_supported ──────────────────────────────────────────

    #[test]
    fn test_compression_supported_default_only_none() {
        assert!(compression_supported(Compression::None));
        assert!(!compression_supported(Compression::Xz));
        assert!(!compression_supported(Compression::Lz4));
        assert!(!compression_supported(Compression::Zstd));
    }

    #[test]
    fn test_compression_supported_with_custom_mask() {
        let all_mask: u32 = 0b1111;
        assert!(compression_supported_with_mask(Compression::None, all_mask));
        assert!(compression_supported_with_mask(Compression::Xz, all_mask));
        assert!(compression_supported_with_mask(Compression::Lz4, all_mask));
        assert!(compression_supported_with_mask(Compression::Zstd, all_mask));
    }

    #[test]
    fn test_compression_supported_with_partial_mask() {
        let mask: u32 = (1 << 0) | (1 << 3); // None + Zstd
        assert!(compression_supported_with_mask(Compression::None, mask));
        assert!(!compression_supported_with_mask(Compression::Xz, mask));
        assert!(!compression_supported_with_mask(Compression::Lz4, mask));
        assert!(compression_supported_with_mask(Compression::Zstd, mask));
    }

    #[test]
    fn test_compression_max_constant() {
        assert_eq!(COMPRESSION_MAX, 4);
    }
}
