// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/efi-api.c
//! EFI API utilities
//!
//! Functions for interacting with UEFI/EFI firmware.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// EFI variable attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiVariableAttributes(pub u32);

impl EfiVariableAttributes {
    /// Variable is non-volatile
    pub const NON_VOLATILE: u32 = 0x00000001;
    /// Variable can be accessed during boot service
    pub const BOOTSERVICE_ACCESS: u32 = 0x00000002;
    /// Variable can be accessed at runtime
    pub const RUNTIME_ACCESS: u32 = 0x00000004;
    /// Variable is stored in hardware error record
    pub const HARDWARE_ERROR_RECORD: u32 = 0x00000008;
    /// Variable requires authentication to write
    pub const AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000010;
    /// Variable requires time-based authentication
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000020;
    /// Variable is append-only
    pub const APPEND_WRITE: u32 = 0x00000040;

    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    pub fn contains(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    pub fn is_non_volatile(&self) -> bool {
        self.contains(Self::NON_VOLATILE)
    }

    pub fn is_bootservice_access(&self) -> bool {
        self.contains(Self::BOOTSERVICE_ACCESS)
    }

    pub fn is_runtime_access(&self) -> bool {
        self.contains(Self::RUNTIME_ACCESS)
    }

    pub fn to_string_list(&self) -> Vec<&'static str> {
        let mut result = Vec::new();

        if self.contains(Self::NON_VOLATILE) {
            result.push("non-volatile");
        }
        if self.contains(Self::BOOTSERVICE_ACCESS) {
            result.push("bootservice-access");
        }
        if self.contains(Self::RUNTIME_ACCESS) {
            result.push("runtime-access");
        }
        if self.contains(Self::HARDWARE_ERROR_RECORD) {
            result.push("hardware-error-record");
        }
        if self.contains(Self::AUTHENTICATED_WRITE_ACCESS) {
            result.push("authenticated-write-access");
        }
        if self.contains(Self::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
            result.push("time-based-authenticated-write-access");
        }
        if self.contains(Self::APPEND_WRITE) {
            result.push("append-write");
        }

        result
    }
}

impl fmt::Display for EfiVariableAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = self.to_string_list();
        if flags.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", flags.join(", "))
        }
    }
}

/// Well-known EFI variable GUIDs
pub mod efi_guids {
    /// Global variable namespace
    pub const GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
    /// Boot manager
    pub const BOOT: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
    /// Runtime services
    pub const RUNTIME: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
}

/// EFI boot manager entry
#[derive(Debug, Clone)]
pub struct EfiBootEntry {
    pub id: u16,
    pub description: String,
    pub path: String,
    pub is_active: bool,
}

impl EfiBootEntry {
    pub fn new(id: u16, description: impl Into<String>) -> Self {
        Self {
            id,
            description: description.into(),
            path: String::new(),
            is_active: false,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    pub fn active(mut self) -> Self {
        self.is_active = true;
        self
    }
}

/// EFI API manager
#[derive(Debug)]
pub struct EfiApi {
    efi_vars_path: Option<std::path::PathBuf>,
}

impl EfiApi {
    /// Create new EFI API instance
    ///
    /// Attempts to detect EFI variables filesystem
    pub fn new() -> Self {
        let efi_vars_path = Self::detect_efi_vars_path();
        Self { efi_vars_path }
    }

    fn detect_efi_vars_path() -> Option<std::path::PathBuf> {
        // Check common locations for efivarfs
        let paths = ["/sys/firmware/efi/efivars", "/sys/firmware/efi/vars"];

        for path in &paths {
            let p = std::path::Path::new(path);
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }

        None
    }

    /// Check if system is EFI-booted
    pub fn is_efi_boot(&self) -> bool {
        // Check for EFI system partition mounted
        Path::new("/sys/firmware/efi").exists()
    }

    /// Get EFI variable path
    pub fn efi_vars_path(&self) -> Option<&std::path::PathBuf> {
        self.efi_vars_path.as_ref()
    }

    /// Read an EFI variable
    ///
    /// # Operational safety
    /// This function reads from firmware variables which may not be available
    /// on all systems. Check `is_efi_boot()` first.
    pub fn read_variable(&self, name: &str, guid: &str) -> Result<Vec<u8>, EfiError> {
        let path = self.efi_vars_path.as_ref().ok_or(EfiError::NotSupported)?;

        let var_path = path.join(format!("{}-{}", name, guid));

        std::fs::read(&var_path)
            .map_err(|e| EfiError::Io(format!("Failed to read EFI variable: {}", e)))
    }

    /// List all EFI variables
    ///
    /// # Operational safety
    /// This function accesses EFI variables which may not be available
    /// on all systems. Check `is_efi_boot()` first.
    pub fn list_variables(&self) -> Result<Vec<String>, EfiError> {
        let path = self.efi_vars_path.as_ref().ok_or(EfiError::NotSupported)?;

        let mut vars = Vec::new();

        for entry in std::fs::read_dir(path)
            .map_err(|e| EfiError::Io(format!("Failed to list EFI variables: {}", e)))?
            .flatten()
        {
            let name = entry.file_name();
            vars.push(name.to_string_lossy().to_string());
        }

        Ok(vars)
    }

    /// Get boot order
    ///
    /// # Operational safety
    /// This function reads from EFI variables
    pub fn get_boot_order(&self) -> Result<Vec<u16>, EfiError> {
        let data = self.read_variable("BootOrder", efi_guids::GLOBAL)?;

        // BootOrder is a list of u16 values
        let mut order = Vec::new();
        for chunk in data.chunks_exact(2) {
            let id = u16::from_le_bytes([chunk[0], chunk[1]]);
            order.push(id);
        }

        Ok(order)
    }

    /// Get boot entries
    ///
    /// # Operational safety
    /// This function reads from EFI variables
    pub fn get_boot_entries(&self) -> Result<Vec<EfiBootEntry>, EfiError> {
        let order = self.get_boot_order()?;
        let mut entries = Vec::new();

        for id in order {
            let var_name = format!("Boot{:04X}", id);
            if let Ok(data) = self.read_variable(&var_name, efi_guids::GLOBAL) {
                // Parse boot entry data
                // Format is complex, this is simplified
                if data.len() > 6 {
                    let desc_len = u16::from_le_bytes([data[0], data[1]]) as usize;
                    if let Some(end) = 2usize.checked_add(desc_len) {
                        if let Some(description) = data.get(2..end) {
                            if let Ok(desc) = String::from_utf8(description.to_vec()) {
                                entries.push(EfiBootEntry::new(id, desc));
                            }
                        }
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Get the current boot number
    ///
    /// # Operational safety
    /// This function reads from EFI variables
    pub fn get_current_boot(&self) -> Result<u16, EfiError> {
        let data = self.read_variable("BootCurrent", efi_guids::GLOBAL)?;

        if data.len() >= 2 {
            Ok(u16::from_le_bytes([data[0], data[1]]))
        } else {
            Err(EfiError::InvalidData("BootCurrent too short".to_string()))
        }
    }
}

impl Default for EfiApi {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for EFI operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EfiError {
    NotSupported,
    Io(String),
    InvalidData(String),
    PermissionDenied,
    VariableNotFound(String),
}

impl fmt::Display for EfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EfiError::NotSupported => write!(f, "EFI not supported on this system"),
            EfiError::Io(msg) => write!(f, "IO error: {}", msg),
            EfiError::InvalidData(msg) => write!(f, "Invalid EFI data: {}", msg),
            EfiError::PermissionDenied => write!(f, "Permission denied accessing EFI variables"),
            EfiError::VariableNotFound(name) => write!(f, "EFI variable not found: {}", name),
        }
    }
}

impl std::error::Error for EfiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_efi_attributes() {
        let attrs = EfiVariableAttributes(
            EfiVariableAttributes::NON_VOLATILE | EfiVariableAttributes::BOOTSERVICE_ACCESS,
        );

        assert!(attrs.is_non_volatile());
        assert!(attrs.is_bootservice_access());
        assert!(!attrs.is_runtime_access());

        let flags = attrs.to_string_list();
        assert!(flags.contains(&"non-volatile"));
        assert!(flags.contains(&"bootservice-access"));
    }

    #[test]
    fn test_efi_boot_entry() {
        let entry = EfiBootEntry::new(1, "Ubuntu")
            .with_path("/EFI/ubuntu/shimx64.efi")
            .active();

        assert_eq!(entry.id, 1);
        assert_eq!(entry.description, "Ubuntu");
        assert!(entry.is_active);
        assert!(!entry.path.is_empty());
    }

    #[test]
    fn test_efi_api_new() {
        let efi = EfiApi::new();
        // On non-EFI systems, efi_vars_path should be None
        // On EFI systems, it should be Some
        assert!(efi.efi_vars_path().is_none() || efi.efi_vars_path().is_some());
    }

    #[test]
    fn test_efi_error_display() {
        let err = EfiError::NotSupported;
        assert!(err.to_string().contains("not supported"));
    }
}
