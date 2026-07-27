// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/shim.c
//
// Shim lock protocol handling for secure boot integration.
//
// Provides safe wrappers around the UEFI shim lock protocol for image
// verification and loading. Handles both pre-v16 shim (manual lock protocol)
// and v16+ shim (image loader protocol with automatic LoadImage hook).

// ── Constants ─────────────────────────────────────────────────────────────

/// SHIM_LOCK protocol GUID: { 605dab50, e046, 4700, ... }
pub const SHIM_LOCK_GUID: EfiGuid = EfiGuid {
    data1: 0x605dab50,
    data2: 0xe046,
    data3: 0x4700,
    data4: [0x92, 0x94, 0xa2, 0x17, 0x54, 0x1f, 0x7a, 0xba],
};

/// SHIM_IMAGE_LOADER_GUID for shim v16+:
/// { 0x1f492041, 0xfadb, 0x4e59, { 0x9e, 0x57, 0x7c, 0xaf, 0xe7, 0x3a, 0x55, 0xab } }
pub const SHIM_IMAGE_LOADER_GUID: EfiGuid = EfiGuid {
    data1: 0x1f492041,
    data2: 0xfadb,
    data3: 0x4e59,
    data4: [0x9e, 0x57, 0x7c, 0xaf, 0xe7, 0x3a, 0x55, 0xab],
};

/// Minimum shim version that supports the image loader protocol.
pub const SHIM_VERSION_WITH_LOADER: u32 = 16;

/// Variable name for retaining the shim protocol across StartImage.
pub const SHIM_RETAIN_PROTOCOL_VAR: &str = "ShimRetainProtocol";

// ── Types ─────────────────────────────────────────────────────────────────

/// Simplified EFI GUID representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// Status of the shim protocol availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimStatus {
    /// No shim protocol found.
    NotAvailable,
    /// Pre-v16 shim with lock protocol only.
    LockProtocolOnly,
    /// Shim v16+ with image loader protocol.
    ImageLoaderAvailable,
}

/// Result of a shim image load operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimLoadResult {
    /// Whether the shim lock protocol was installed for the load.
    pub used_lock_protocol: bool,
    /// Whether the load operation succeeded.
    pub success: bool,
}

/// Error type for shim operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimError {
    /// The shim lock protocol is not available.
    NoProtocol,
    /// Image verification failed.
    VerificationFailed,
    /// Device path is invalid or missing.
    InvalidDevicePath,
    /// Failed to locate the device for the given path.
    DeviceNotFound,
    /// Failed to open the volume.
    VolumeOpenFailed,
    /// Failed to convert device path to string.
    PathToStringFailed,
    /// Failed to read the file.
    FileReadFailed,
    /// A parameter was unexpectedly null.
    NullParameter,
}

impl std::fmt::Display for ShimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShimError::NoProtocol => write!(f, "shim lock protocol not available"),
            ShimError::VerificationFailed => write!(f, "image verification failed"),
            ShimError::InvalidDevicePath => write!(f, "invalid device path"),
            ShimError::DeviceNotFound => write!(f, "device not found for path"),
            ShimError::VolumeOpenFailed => write!(f, "failed to open volume"),
            ShimError::PathToStringFailed => write!(f, "failed to convert path to string"),
            ShimError::FileReadFailed => write!(f, "failed to read file"),
            ShimError::NullParameter => write!(f, "null parameter"),
        }
    }
}

impl std::error::Error for ShimError {}

// ── Core logic ────────────────────────────────────────────────────────────

/// Determine the current shim availability status.
///
/// In the C code, this checks BS->LocateProtocol for SHIM_LOCK and
/// SHIM_IMAGE_LOADER_GUID respectively.
pub fn shim_detect_status(has_lock_protocol: bool, has_image_loader: bool) -> ShimStatus {
    if has_image_loader {
        ShimStatus::ImageLoaderAvailable
    } else if has_lock_protocol {
        ShimStatus::LockProtocolOnly
    } else {
        ShimStatus::NotAvailable
    }
}

/// Check if the shim lock protocol is loaded.
///
/// Maps to `shim_loaded()` in C, which locates the SHIM_LOCK protocol.
pub fn shim_loaded(status: ShimStatus) -> bool {
    matches!(
        status,
        ShimStatus::LockProtocolOnly | ShimStatus::ImageLoaderAvailable
    )
}

/// Check if the shim image loader (v16+) is available.
///
/// Maps to `shim_loader_available()` in C.
pub fn shim_loader_available(status: ShimStatus) -> bool {
    matches!(status, ShimStatus::ImageLoaderAvailable)
}

/// Check if we need to use the pre-v16 lock protocol path.
///
/// In C: `bool have_shim = shim_loaded() && !shim_loader_available();`
pub fn needs_lock_protocol(status: ShimStatus) -> bool {
    status == ShimStatus::LockProtocolOnly
}

/// Validate a PE image buffer against the shim lock protocol.
///
/// Maps to `shim_validate()` in C. When `file_buffer` is `None`, the
/// function would attempt to load the file from `device_path`. In this
/// safe port, we only validate the provided buffer.
pub fn shim_validate_buffer(
    file_buffer: Option<&[u8]>,
    shim_verify_fn: Option<&dyn Fn(&[u8]) -> bool>,
) -> Result<bool, ShimError> {
    let buffer = file_buffer.ok_or(ShimError::NullParameter)?;
    let verify = shim_verify_fn.ok_or(ShimError::NoProtocol)?;
    Ok(verify(buffer))
}

/// Determine the load strategy for shim.
///
/// In C, `shim_load_image()` checks whether to install the security
/// override. Returns whether the lock protocol should be used.
pub fn shim_load_strategy(status: ShimStatus, boot_policy: bool) -> ShimLoadResult {
    let use_lock = needs_lock_protocol(status);
    // In C: if have_shim, install_security_override, then BS->LoadImage, then uninstall
    ShimLoadResult {
        used_lock_protocol: use_lock,
        success: true, // Actual load is handled by UEFI runtime
    }
}

/// Check if the shim retain protocol variable should be set.
///
/// Maps to `shim_retain_protocol()` in C. Only needed for pre-v16 shim
/// to prevent it from uninstalling the security protocol.
pub fn should_retain_protocol(status: ShimStatus) -> bool {
    !shim_loader_available(status) && shim_loaded(status)
}

/// Build the retain protocol variable payload.
///
/// In C, this sets a uint8_t value of 1 via efivar_set_raw.
pub fn retain_protocol_payload() -> [u8; 1] {
    [1u8]
}

/// Check whether a device path should be validated through shim.
///
/// Helper that combines the status check with the validation logic.
pub fn should_validate_via_shim(
    status: ShimStatus,
    has_file_buffer: bool,
    has_device_path: bool,
) -> bool {
    if has_file_buffer {
        return shim_loaded(status);
    }
    has_device_path && shim_loaded(status)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim_detect_status_no_shim() {
        assert_eq!(shim_detect_status(false, false), ShimStatus::NotAvailable);
    }

    #[test]
    fn test_shim_detect_status_lock_only() {
        assert_eq!(
            shim_detect_status(true, false),
            ShimStatus::LockProtocolOnly
        );
    }

    #[test]
    fn test_shim_detect_status_image_loader() {
        assert_eq!(
            shim_detect_status(false, true),
            ShimStatus::ImageLoaderAvailable
        );
        assert_eq!(
            shim_detect_status(true, true),
            ShimStatus::ImageLoaderAvailable
        );
    }

    #[test]
    fn test_shim_loaded() {
        assert!(!shim_loaded(ShimStatus::NotAvailable));
        assert!(shim_loaded(ShimStatus::LockProtocolOnly));
        assert!(shim_loaded(ShimStatus::ImageLoaderAvailable));
    }

    #[test]
    fn test_shim_loader_available() {
        assert!(!shim_loader_available(ShimStatus::NotAvailable));
        assert!(!shim_loader_available(ShimStatus::LockProtocolOnly));
        assert!(shim_loader_available(ShimStatus::ImageLoaderAvailable));
    }

    #[test]
    fn test_needs_lock_protocol() {
        assert!(!needs_lock_protocol(ShimStatus::NotAvailable));
        assert!(needs_lock_protocol(ShimStatus::LockProtocolOnly));
        assert!(!needs_lock_protocol(ShimStatus::ImageLoaderAvailable));
    }

    #[test]
    fn test_shim_validate_buffer_success() {
        let result = shim_validate_buffer(Some(b"PE data"), Some(&|_buf| true));
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_shim_validate_buffer_no_buffer() {
        let result = shim_validate_buffer(None, Some(&|_buf| true));
        assert_eq!(result, Err(ShimError::NullParameter));
    }

    #[test]
    fn test_shim_validate_buffer_no_protocol() {
        let result = shim_validate_buffer(Some(b"PE data"), None);
        assert_eq!(result, Err(ShimError::NoProtocol));
    }

    #[test]
    fn test_shim_validate_buffer_verify_fails() {
        let result = shim_validate_buffer(Some(b"bad data"), Some(&|_buf| false));
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_shim_load_strategy() {
        let result = shim_load_strategy(ShimStatus::LockProtocolOnly, false);
        assert!(result.used_lock_protocol);
        assert!(result.success);

        let result = shim_load_strategy(ShimStatus::ImageLoaderAvailable, true);
        assert!(!result.used_lock_protocol);
        assert!(result.success);
    }

    #[test]
    fn test_should_retain_protocol() {
        assert!(!should_retain_protocol(ShimStatus::NotAvailable));
        assert!(should_retain_protocol(ShimStatus::LockProtocolOnly));
        assert!(!should_retain_protocol(ShimStatus::ImageLoaderAvailable));
    }

    #[test]
    fn test_retain_protocol_payload() {
        assert_eq!(retain_protocol_payload(), [1u8]);
    }

    #[test]
    fn test_should_validate_via_shim() {
        // With file buffer, any loaded shim works
        assert!(should_validate_via_shim(
            ShimStatus::LockProtocolOnly,
            true,
            false
        ));
        assert!(should_validate_via_shim(
            ShimStatus::ImageLoaderAvailable,
            true,
            false
        ));
        // Without file buffer, needs device path
        assert!(!should_validate_via_shim(
            ShimStatus::LockProtocolOnly,
            false,
            false
        ));
        assert!(should_validate_via_shim(
            ShimStatus::LockProtocolOnly,
            false,
            true
        ));
        // No shim at all
        assert!(!should_validate_via_shim(
            ShimStatus::NotAvailable,
            true,
            false
        ));
    }
}
