// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/drivers.c
//
// EFI driver loading for systemd-boot.
//
// Loads additional EFI drivers from the \\EFI\\systemd\\drivers directory
// on the ESP. After loading drivers, reconnects all handles so that
// newly loaded drivers can take effect.

// ── Constants ─────────────────────────────────────────────────────────────

/// Path to the drivers directory on the ESP.
pub const DRIVERS_DIR_PATH: &str = "\\EFI\\systemd\\drivers";

/// EFI driver file extension (platform-specific).
pub const DRIVER_EXTENSION: &str = ".efi";

/// Batch allocation size for directory entries.
pub const ENTRY_BATCH_SIZE: usize = 16;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    NotFound,
    InvalidParameter,
    Unsupported,
    LoadFailed,
    StartFailed,
    NotADriver,
    DirectoryOpenFailed,
    DirectoryReadFailed,
    OutOfResources,
    ProtocolNotFound,
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriverError::NotFound => write!(f, "not found"),
            DriverError::InvalidParameter => write!(f, "invalid parameter"),
            DriverError::Unsupported => write!(f, "unsupported"),
            DriverError::LoadFailed => write!(f, "failed to load image"),
            DriverError::StartFailed => write!(f, "failed to start image"),
            DriverError::NotADriver => write!(f, "image is not a driver"),
            DriverError::DirectoryOpenFailed => write!(f, "failed to open drivers directory"),
            DriverError::DirectoryReadFailed => write!(f, "failed to read directory"),
            DriverError::OutOfResources => write!(f, "out of resources"),
            DriverError::ProtocolNotFound => write!(f, "protocol not found"),
        }
    }
}

impl std::error::Error for DriverError {}

// ── Data structures ───────────────────────────────────────────────────────

/// Result of loading a single driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverLoadResult {
    /// Driver loaded and started successfully.
    Success,
    /// Driver was skipped (not an .efi file, dot-file, etc.).
    Skipped,
    /// Driver loaded but returned EFI_ABORTED (initializing driver).
    Aborted,
}

/// Result of loading all drivers from the drivers directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriversResult {
    pub total_scanned: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl Default for DriversResult {
    fn default() -> Self {
        Self::new()
    }
}

impl DriversResult {
    pub fn new() -> Self {
        Self {
            total_scanned: 0,
            succeeded: 0,
            failed: 0,
            skipped: 0,
        }
    }

    pub fn any_succeeded(&self) -> bool {
        self.succeeded > 0
    }
}

// ── Driver file filtering ────────────────────────────────────────────────

/// Check if a filename looks like a valid EFI driver.
pub fn is_valid_driver_filename(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.starts_with('.') {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower.ends_with(DRIVER_EXTENSION)
}

/// Build the full driver path from a filename.
pub fn make_driver_path(filename: &str) -> String {
    format!("{DRIVERS_DIR_PATH}\\{filename}")
}

/// Build the full driver path from a filename with a custom directory.
pub fn make_driver_path_in(dir: &str, filename: &str) -> String {
    format!("{dir}\\{filename}")
}

// ── Driver loading simulation ────────────────────────────────────────────

/// Classify a directory entry for driver loading.
pub fn classify_driver_entry(name: &str, is_directory: bool) -> DriverLoadResult {
    if is_directory {
        return DriverLoadResult::Skipped;
    }
    if name.starts_with('.') {
        return DriverLoadResult::Skipped;
    }
    if !is_valid_driver_filename(name) {
        return DriverLoadResult::Skipped;
    }
    DriverLoadResult::Success
}

/// Process a list of directory entries and categorize them.
pub fn scan_driver_entries(entries: &[(String, bool)]) -> DriversResult {
    let mut result = DriversResult::new();

    for (name, is_dir) in entries {
        result.total_scanned += 1;
        match classify_driver_entry(name, *is_dir) {
            DriverLoadResult::Success => result.succeeded += 1,
            DriverLoadResult::Skipped => result.skipped += 1,
            DriverLoadResult::Aborted => result.succeeded += 1,
        }
    }

    result
}

/// Check if we should attempt reconnection after loading drivers.
pub fn should_reconnect(result: &DriversResult) -> bool {
    result.any_succeeded()
}

// ── Image type classification ─────────────────────────────────────────────

/// EFI image types for driver validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfiImageCodeType {
    BootServicesCode,
    RuntimeServicesCode,
    Other,
}

/// Check if an image code type is valid for a driver.
pub fn is_valid_driver_type(code_type: EfiImageCodeType) -> bool {
    matches!(
        code_type,
        EfiImageCodeType::BootServicesCode | EfiImageCodeType::RuntimeServicesCode
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_driver_filename() {
        assert!(is_valid_driver_filename("driver.efi"));
        assert!(is_valid_driver_filename("MyDriver.EFI"));
        assert!(!is_valid_driver_filename(".hidden.efi"));
        assert!(!is_valid_driver_filename("readme.txt"));
        assert!(!is_valid_driver_filename(""));
        assert!(!is_valid_driver_filename("driver.bin"));
    }

    #[test]
    fn test_make_driver_path() {
        let path = make_driver_path("video.efi");
        assert_eq!(path, "\\EFI\\systemd\\drivers\\video.efi");
    }

    #[test]
    fn test_make_driver_path_in() {
        let path = make_driver_path_in("\\custom\\dir", "test.efi");
        assert_eq!(path, "\\custom\\dir\\test.efi");
    }

    #[test]
    fn test_classify_driver_entry_valid() {
        assert_eq!(
            classify_driver_entry("driver.efi", false),
            DriverLoadResult::Success
        );
    }

    #[test]
    fn test_classify_driver_entry_directory() {
        assert_eq!(
            classify_driver_entry("subdir", true),
            DriverLoadResult::Skipped
        );
    }

    #[test]
    fn test_classify_driver_entry_dotfile() {
        assert_eq!(
            classify_driver_entry(".hidden.efi", false),
            DriverLoadResult::Skipped
        );
    }

    #[test]
    fn test_classify_driver_entry_non_efi() {
        assert_eq!(
            classify_driver_entry("readme.txt", false),
            DriverLoadResult::Skipped
        );
    }

    #[test]
    fn test_scan_driver_entries_mixed() {
        let entries = vec![
            ("driver1.efi".to_string(), false),
            ("driver2.efi".to_string(), false),
            (".hidden".to_string(), false),
            ("subdir".to_string(), true),
            ("readme.txt".to_string(), false),
        ];
        let result = scan_driver_entries(&entries);
        assert_eq!(result.total_scanned, 5);
        assert_eq!(result.succeeded, 2);
        assert_eq!(result.skipped, 3);
        assert!(result.any_succeeded());
    }

    #[test]
    fn test_scan_driver_entries_empty() {
        let result = scan_driver_entries(&[]);
        assert_eq!(result.total_scanned, 0);
        assert!(!result.any_succeeded());
    }

    #[test]
    fn test_should_reconnect() {
        let with_drivers = DriversResult {
            total_scanned: 2,
            succeeded: 1,
            failed: 0,
            skipped: 1,
        };
        assert!(should_reconnect(&with_drivers));

        let no_drivers = DriversResult {
            total_scanned: 1,
            succeeded: 0,
            failed: 0,
            skipped: 1,
        };
        assert!(!should_reconnect(&no_drivers));
    }

    #[test]
    fn test_is_valid_driver_type() {
        assert!(is_valid_driver_type(EfiImageCodeType::BootServicesCode));
        assert!(is_valid_driver_type(EfiImageCodeType::RuntimeServicesCode));
        assert!(!is_valid_driver_type(EfiImageCodeType::Other));
    }

    #[test]
    fn test_drivers_result_default() {
        let result = DriversResult::default();
        assert_eq!(result.total_scanned, 0);
        assert_eq!(result.succeeded, 0);
    }

    #[test]
    fn test_error_display() {
        assert!(!DriverError::LoadFailed.to_string().is_empty());
        assert!(!DriverError::NotADriver.to_string().is_empty());
    }
}
