// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/addon.c
//
// Addon binary stub. This is intended to carry data, not to be executed.
// The C implementation simply returns EFI_UNSUPPORTED from efi_main.

// ── Constants ─────────────────────────────────────────────────────────────

/// EFI status code indicating the operation is not supported.
pub const EFI_UNSUPPORTED: usize = 0x8000_0003;

/// Magic prefix for recognizing systemd-boot addon binaries.
pub const ADDON_MAGIC_PREFIX: &str = "#### LoaderInfo: systemd-addon";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during addon operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddonError {
    /// The addon binary is not intended for execution.
    NotSupported,
    /// The magic string is missing or invalid.
    InvalidMagic,
    /// The addon data is empty.
    EmptyData,
}

impl std::fmt::Display for AddonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddonError::NotSupported => write!(f, "addon binary is not executable"),
            AddonError::InvalidMagic => write!(f, "addon magic string is invalid"),
            AddonError::EmptyData => write!(f, "addon data is empty"),
        }
    }
}

impl std::error::Error for AddonError {}

// ── Core functions ────────────────────────────────────────────────────────

/// Simulates the EFI main entry point for an addon binary.
///
/// Addon binaries are data carriers and should never be executed.
/// Returns `Err(AddonError::NotSupported)` always, matching the C behavior
/// where `efi_main` returns `EFI_UNSUPPORTED`.
pub fn efi_main() -> Result<(), AddonError> {
    Err(AddonError::NotSupported)
}

/// Validates that a byte slice contains a valid addon magic string.
///
/// The C source uses a `.sdmagic` section containing:
/// `"#### LoaderInfo: systemd-addon <version> ####"`
/// This function checks that the data starts with the expected prefix.
pub fn validate_addon_magic(data: &[u8]) -> Result<(), AddonError> {
    if data.is_empty() {
        return Err(AddonError::EmptyData);
    }

    let prefix_bytes = ADDON_MAGIC_PREFIX.as_bytes();
    if data.len() < prefix_bytes.len() {
        return Err(AddonError::InvalidMagic);
    }

    if &data[..prefix_bytes.len()] == prefix_bytes {
        Ok(())
    } else {
        Err(AddonError::InvalidMagic)
    }
}

/// Checks if a given binary blob looks like a valid systemd addon.
///
/// Validates both that the data is non-empty and contains the expected
/// magic identifier in its header section.
pub fn is_valid_addon(data: &[u8]) -> bool {
    validate_addon_magic(data).is_ok()
}

/// Extracts the version string from an addon magic line.
///
/// The magic format is: `"#### LoaderInfo: systemd-addon <version> ####"`
/// Returns the version substring between "systemd-addon " and " ####".
pub fn extract_addon_version(data: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(data).ok()?;
    let prefix = "systemd-addon ";
    let suffix = " ####";

    let start = s.find(prefix)?;
    let after_prefix = &s[start + prefix.len()..];
    let end = after_prefix.find(suffix)?;
    Some(&after_prefix[..end])
}

/// Returns the complete magic string for a given version.
pub fn make_addon_magic(version: &str) -> String {
    format!("#### LoaderInfo: systemd-addon {version} ####")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_efi_main_returns_unsupported() {
        assert_eq!(efi_main(), Err(AddonError::NotSupported));
    }

    #[test]
    fn test_efi_main_always_fails() {
        // efi_main should never succeed - addon is not executable
        for _ in 0..10 {
            assert!(efi_main().is_err());
        }
    }

    #[test]
    fn test_validate_addon_magic_valid() {
        let magic = b"#### LoaderInfo: systemd-addon 256 ####";
        assert!(validate_addon_magic(magic).is_ok());
    }

    #[test]
    fn test_validate_addon_magic_empty() {
        assert_eq!(validate_addon_magic(&[]), Err(AddonError::EmptyData));
    }

    #[test]
    fn test_validate_addon_magic_too_short() {
        assert_eq!(validate_addon_magic(b"####"), Err(AddonError::InvalidMagic));
    }

    #[test]
    fn test_validate_addon_magic_wrong_prefix() {
        let data = b"#### LoaderInfo: something-else 1.0 ####";
        assert_eq!(validate_addon_magic(data), Err(AddonError::InvalidMagic));
    }

    #[test]
    fn test_is_valid_addon() {
        let valid = b"#### LoaderInfo: systemd-addon 257 ####";
        assert!(is_valid_addon(valid));
        assert!(!is_valid_addon(&[]));
        assert!(!is_valid_addon(b"random data"));
    }

    #[test]
    fn test_extract_addon_version() {
        let magic = b"#### LoaderInfo: systemd-addon 256.7 ####";
        assert_eq!(extract_addon_version(magic), Some("256.7"));
    }

    #[test]
    fn test_extract_addon_version_no_version() {
        let data = b"no version info here";
        assert_eq!(extract_addon_version(data), None);
    }

    #[test]
    fn test_make_addon_magic() {
        let magic = make_addon_magic("255");
        assert!(magic.starts_with("#### LoaderInfo: systemd-addon 255 ####"));
        assert!(validate_addon_magic(magic.as_bytes()).is_ok());
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            AddonError::NotSupported.to_string(),
            "addon binary is not executable"
        );
        assert_eq!(
            AddonError::InvalidMagic.to_string(),
            "addon magic string is invalid"
        );
        assert_eq!(AddonError::EmptyData.to_string(), "addon data is empty");
    }
}
