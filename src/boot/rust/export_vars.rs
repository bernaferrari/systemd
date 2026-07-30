// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/export-vars.c
//
// EFI variable export logic for the boot loader.
//
// Manages the creation of `Loader*` EFI variables that communicate
// boot-device information to the OS.  The pure logic (which variables to
// set, under what conditions) is faithfully ported; the EFI runtime
// calls are abstracted behind a `VarWriter` trait.

// ── Constants ─────────────────────────────────────────────────────────────

/// EFI variable name: device partition UUID.
pub const LOADER_DEVICE_PART_UUID: &str = "LoaderDevicePartUUID";

/// EFI variable name: device URL.
pub const LOADER_DEVICE_URL: &str = "LoaderDeviceURL";

/// EFI variable name: image identifier.
pub const LOADER_IMAGE_IDENTIFIER: &str = "LoaderImageIdentifier";

/// EFI variable name: firmware info string.
pub const LOADER_FIRMWARE_INFO: &str = "LoaderFirmwareInfo";

/// EFI variable name: firmware type string.
pub const LOADER_FIRMWARE_TYPE: &str = "LoaderFirmwareType";

/// EFI variable name: TPM2 active PCR banks.
pub const LOADER_TPM2_ACTIVE_PCR_BANKS: &str = "LoaderTpm2ActivePcrBanks";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from the export-variables logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportError {
    /// The loaded-image handle is null / missing.
    NullImage,
    /// An EFI variable operation failed.
    VarError,
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::NullImage => write!(f, "Null loaded-image handle"),
            ExportError::VarError => write!(f, "EFI variable operation failed"),
        }
    }
}

impl std::error::Error for ExportError {}

// ── Data model ────────────────────────────────────────────────────────────

/// Information extracted from the loaded-image protocol.
///
/// In the C source this comes from `EFI_LOADED_IMAGE_PROTOCOL`.  Here we
/// model only the fields relevant to `export_common_variables`.
#[derive(Debug, Clone)]
pub struct LoadedImageInfo {
    /// Optional device handle (null if unavailable).
    pub device_handle: Option<()>,
    /// Device-partition UUID string (may be empty).
    pub device_part_uuid: String,
    /// Device URL string (may be empty).
    pub device_url: String,
    /// File path of the loaded image (may be empty).
    pub file_path: Option<String>,
    /// Firmware vendor string.
    pub firmware_vendor: String,
    /// Firmware revision (packed BCD-like u32).
    pub firmware_revision: u32,
    /// UEFI specification revision.
    pub uefi_revision: u32,
    /// TPM2 active PCR banks bitmask.
    pub tpm2_active_pcr_banks: u32,
}

// ── Variable store abstraction ────────────────────────────────────────────

/// Abstraction over a store that can read and write EFI variables.
///
/// In production this wraps `RT->GetVariable` / `RT->SetVariable`;
/// in tests it is backed by a `HashMap`.
pub trait VarStore {
    /// Check if a variable exists (get raw with no output buffers).
    fn var_exists(&self, vendor: &str, name: &str) -> bool;

    /// Set a string EFI variable (flags default to 0).
    fn set_str(&mut self, vendor: &str, name: &str, value: &str) -> Result<(), ExportError>;
}

// ── Formatting helpers ───────────────────────────────────────────────────

/// Format firmware info as `"Vendor Major.Minor"`.
///
/// Mirrors `xasprintf("%ls %u.%02u", ...)` in the C source.
pub fn format_firmware_info(vendor: &str, revision: u32) -> String {
    format!("{} {}.{}", vendor, revision >> 16, revision & 0xFFFF)
}

/// Format firmware type as `"UEFI Major.Minor"`.
///
/// Mirrors `xasprintf("UEFI %u.%02u", ...)` in the C source.
pub fn format_firmware_type(uefi_revision: u32) -> String {
    format!("UEFI {}.{}", uefi_revision >> 16, uefi_revision & 0xFFFF)
}

/// Format TPM2 PCR banks as `"0x%08x"`.
///
/// Mirrors `xasprintf("0x%08x", ...)` in the C source.
pub fn format_pcr_banks(banks: u32) -> String {
    format!("0x{:08x}", banks)
}

// ── Core export logic ────────────────────────────────────────────────────

/// Export all common Loader* EFI variables.
///
/// Mirrors `export_common_variables` in the C source.  Each variable is
/// only set if it does not already exist (idempotent).
pub fn export_common_variables(
    info: &LoadedImageInfo,
    store: &mut dyn VarStore,
    vendor: &str,
) -> Result<(), ExportError> {
    // Export device partition UUID
    if info.device_handle.is_some()
        && !store.var_exists(vendor, LOADER_DEVICE_PART_UUID)
        && !info.device_part_uuid.is_empty()
    {
        store.set_str(vendor, LOADER_DEVICE_PART_UUID, &info.device_part_uuid)?;
    }

    // Export device URL
    if info.device_handle.is_some()
        && !store.var_exists(vendor, LOADER_DEVICE_URL)
        && !info.device_url.is_empty()
    {
        store.set_str(vendor, LOADER_DEVICE_URL, &info.device_url)?;
    }

    // Export image identifier
    match info.file_path.as_deref() {
        Some(fp) if !store.var_exists(vendor, LOADER_IMAGE_IDENTIFIER) && !fp.is_empty() => {
            store.set_str(vendor, LOADER_IMAGE_IDENTIFIER, fp)?;
        }
        _ => {}
    }

    // Export firmware info
    if !store.var_exists(vendor, LOADER_FIRMWARE_INFO) {
        let s = format_firmware_info(&info.firmware_vendor, info.firmware_revision);
        store.set_str(vendor, LOADER_FIRMWARE_INFO, &s)?;
    }

    // Export firmware type
    if !store.var_exists(vendor, LOADER_FIRMWARE_TYPE) {
        let s = format_firmware_type(info.uefi_revision);
        store.set_str(vendor, LOADER_FIRMWARE_TYPE, &s)?;
    }

    // Export TPM2 PCR banks
    if !store.var_exists(vendor, LOADER_TPM2_ACTIVE_PCR_BANKS) {
        let s = format_pcr_banks(info.tpm2_active_pcr_banks);
        store.set_str(vendor, LOADER_TPM2_ACTIVE_PCR_BANKS, &s)?;
    }

    Ok(())
}

// ── In-memory test store ──────────────────────────────────────────────────

/// A simple in-memory variable store for testing.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    vars: std::collections::HashMap<(String, String), String>,
}

impl MemoryStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the value of a variable.
    pub fn get(&self, vendor: &str, name: &str) -> Option<&str> {
        self.vars
            .get(&(vendor.to_string(), name.to_string()))
            .map(|s| s.as_str())
    }
}

impl VarStore for MemoryStore {
    fn var_exists(&self, vendor: &str, name: &str) -> bool {
        self.vars
            .contains_key(&(vendor.to_string(), name.to_string()))
    }

    fn set_str(&mut self, vendor: &str, name: &str, value: &str) -> Result<(), ExportError> {
        self.vars
            .insert((vendor.to_string(), name.to_string()), value.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info() -> LoadedImageInfo {
        LoadedImageInfo {
            device_handle: Some(()),
            device_part_uuid: "1234-5678".to_string(),
            device_url: "http://example.com/boot".to_string(),
            file_path: Some("\\EFI\\BOOT\\BOOTX64.EFI".to_string()),
            firmware_vendor: "TestVendor".to_string(),
            firmware_revision: 0x0002_0003,
            uefi_revision: 0x0002_0080,
            tpm2_active_pcr_banks: 0x0000_000F,
        }
    }

    #[test]
    fn test_format_firmware_info() {
        assert_eq!(format_firmware_info("Vendor", 0x0001_0002), "Vendor 1.2");
        assert_eq!(format_firmware_info("ACME", 0x0002_0080), "ACME 2.128");
    }

    #[test]
    fn test_format_firmware_type() {
        assert_eq!(format_firmware_type(0x0002_0050), "UEFI 2.80");
    }

    #[test]
    fn test_format_pcr_banks() {
        assert_eq!(format_pcr_banks(0xFF), "0x000000ff");
        assert_eq!(format_pcr_banks(0x0000_000F), "0x0000000f");
    }

    #[test]
    fn test_export_common_variables() {
        let info = make_info();
        let mut store = MemoryStore::new();
        export_common_variables(&info, &mut store, "LOADER").unwrap();

        assert_eq!(
            store.get("LOADER", LOADER_DEVICE_PART_UUID),
            Some("1234-5678")
        );
        assert_eq!(
            store.get("LOADER", LOADER_DEVICE_URL),
            Some("http://example.com/boot")
        );
        assert_eq!(
            store.get("LOADER", LOADER_IMAGE_IDENTIFIER),
            Some("\\EFI\\BOOT\\BOOTX64.EFI")
        );
        assert_eq!(
            store.get("LOADER", LOADER_FIRMWARE_INFO),
            Some("TestVendor 2.3")
        );
        assert_eq!(
            store.get("LOADER", LOADER_FIRMWARE_TYPE),
            Some("UEFI 2.128")
        );
        assert_eq!(
            store.get("LOADER", LOADER_TPM2_ACTIVE_PCR_BANKS),
            Some("0x0000000f")
        );
    }

    #[test]
    fn test_export_idempotent() {
        let info = make_info();
        let mut store = MemoryStore::new();
        // Pre-set one variable
        store
            .set_str("LOADER", LOADER_DEVICE_PART_UUID, "old-value")
            .unwrap();
        export_common_variables(&info, &mut store, "LOADER").unwrap();
        // Should NOT have overwritten
        assert_eq!(
            store.get("LOADER", LOADER_DEVICE_PART_UUID),
            Some("old-value")
        );
    }

    #[test]
    fn test_export_no_device_handle() {
        let mut info = make_info();
        info.device_handle = None;
        let mut store = MemoryStore::new();
        export_common_variables(&info, &mut store, "LOADER").unwrap();
        // Device vars should NOT be set
        assert_eq!(store.get("LOADER", LOADER_DEVICE_PART_UUID), None);
        assert_eq!(store.get("LOADER", LOADER_DEVICE_URL), None);
        // Non-device vars should still be set
        assert!(store.get("LOADER", LOADER_FIRMWARE_INFO).is_some());
    }

    #[test]
    fn test_export_no_file_path() {
        let mut info = make_info();
        info.file_path = None;
        let mut store = MemoryStore::new();
        export_common_variables(&info, &mut store, "LOADER").unwrap();
        assert_eq!(store.get("LOADER", LOADER_IMAGE_IDENTIFIER), None);
    }

    #[test]
    fn test_export_empty_uuid() {
        let mut info = make_info();
        info.device_part_uuid.clear();
        let mut store = MemoryStore::new();
        export_common_variables(&info, &mut store, "LOADER").unwrap();
        assert_eq!(store.get("LOADER", LOADER_DEVICE_PART_UUID), None);
    }

    #[test]
    fn test_memory_store_var_exists() {
        let mut store = MemoryStore::new();
        assert!(!store.var_exists("v", "n"));
        store.set_str("v", "n", "val").unwrap();
        assert!(store.var_exists("v", "n"));
    }
}
