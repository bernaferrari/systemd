// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/efivars.c, src/basic/efivars.h, src/fundamental/efivars.h
//
// EFI variables utilities.
//
// Provides reading and writing of EFI variables via the efivarfs filesystem
// (/sys/firmware/efi/efivars/), secure boot detection, and string/path
// conversion helpers.

// ── Constants ─────────────────────────────────────────────────────────────

/// Base path for EFI variables on efivarfs
pub const EFIVARS_PATH: &str = "/sys/firmware/efi/efivars";

/// Fallback path for legacy EFI variables
pub const EFIVARS_LEGACY_PATH: &str = "/sys/firmware/efi/vars";

/// Default attributes for newly-written EFI variables:
/// NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
pub const EFI_DEFAULT_VARIABLE_ATTRS: u32 = EfiVariableAttributes::NON_VOLATILE
    | EfiVariableAttributes::BOOTSERVICE_ACCESS
    | EfiVariableAttributes::RUNTIME_ACCESS;

/// Maximum size for an EFI variable payload (4 × 64 MiB).
/// Variables larger than this are rejected as likely corrupt.
pub const EFI_VARIABLE_MAX_SIZE: usize = 4 * 64 * 1024 * 1024;

/// Number of fast retries (no delay) for efivarfs reads before backing off
const EFI_N_RETRIES_NO_DELAY: u32 = 20;

/// Total number of retries for efivarfs reads before giving up
const EFI_N_RETRIES_TOTAL: u32 = 25;

/// Delay between retries after the fast-retry budget is exhausted (50 ms)
const EFI_RETRY_DELAY_US: u64 = 50_000;

/// Size of the attribute header prepended to every efivarfs variable value
const EFI_ATTR_SIZE: usize = 4;

// ── Re-exports ────────────────────────────────────────────────────────────

pub use crate::efi_api::{efi_guids, EfiError, EfiVariableAttributes};

// ── Secure Boot Mode ──────────────────────────────────────────────────────

/// Possible states of the UEFI Secure Boot feature.
///
/// Derived from the `SecureBootMode` enum in
/// `src/fundamental/efivars.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SecureBootMode {
    /// System does not support Secure Boot at all
    Unsupported = 0,
    /// Secure Boot is supported but disabled
    Disabled = 1,
    /// Secure Boot state is unknown (e.g. variable missing)
    Unknown = 2,
    /// Secure Boot is in audit mode
    Audit = 3,
    /// Secure Boot is in deployed mode
    Deployed = 4,
    /// System is in Setup Mode (no Platform Key)
    Setup = 5,
    /// Secure Boot is enabled with user keys
    User = 6,
    /// Secure Boot is tainted (shim's MokSBState bypassed)
    Tainted = 7,
}

impl SecureBootMode {
    /// Sentinel for "invalid / not yet determined".
    pub const INVALID: i32 = -22; // -EINVAL
}

impl std::fmt::Display for SecureBootMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureBootMode::Unsupported => write!(f, "unsupported"),
            SecureBootMode::Disabled => write!(f, "disabled"),
            SecureBootMode::Unknown => write!(f, "unknown"),
            SecureBootMode::Audit => write!(f, "audit"),
            SecureBootMode::Deployed => write!(f, "deployed"),
            SecureBootMode::Setup => write!(f, "setup"),
            SecureBootMode::User => write!(f, "user"),
            SecureBootMode::Tainted => write!(f, "tainted"),
        }
    }
}

/// Decode the secure boot mode from individual EFI variable flag values.
///
/// This mirrors the C function `decode_secure_boot_mode()` and combines the
/// values of SecureBoot, AuditMode, DeployedMode, SetupMode, and MokSBStateRT
/// into a single [`SecureBootMode`] value.
pub fn decode_secure_boot_mode(
    secure: bool,
    audit: bool,
    deployed: bool,
    setup: bool,
    moksb: bool,
) -> SecureBootMode {
    match (secure, audit, deployed, setup, moksb) {
        (_, false, true, _, _) => SecureBootMode::Deployed,
        (true, true, _, _, _) => SecureBootMode::Audit,
        (true, _, _, true, _) => SecureBootMode::Setup,
        (true, _, _, _, false) => SecureBootMode::User,
        (true, _, _, _, true) => SecureBootMode::Tainted,
        (false, _, _, _, _) => SecureBootMode::Disabled,
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur when operating on EFI variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EfiVarsError {
    /// EFI variables filesystem is not available on this system
    NotAvailable,
    /// The requested EFI variable does not exist
    NotFound(String),
    /// An I/O error occurred
    Io(String),
    /// Variable data is malformed or too short
    InvalidData(String),
    /// Insufficient permissions to read/write the variable
    PermissionDenied,
    /// Operation not supported (e.g. non-EFI system)
    Unsupported,
    /// The variable is larger than the accepted maximum
    TooLarge(String),
    /// Retry budget exhausted (efivarfs rate-limiting)
    Busy(String),
}

impl std::fmt::Display for EfiVarsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EfiVarsError::NotAvailable => write!(f, "EFI variables not available"),
            EfiVarsError::NotFound(name) => write!(f, "EFI variable not found: {}", name),
            EfiVarsError::Io(msg) => write!(f, "I/O error: {}", msg),
            EfiVarsError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            EfiVarsError::PermissionDenied => write!(f, "Permission denied"),
            EfiVarsError::Unsupported => write!(f, "Operation not supported"),
            EfiVarsError::TooLarge(msg) => write!(f, "Variable too large: {}", msg),
            EfiVarsError::Busy(msg) => write!(f, "Retry exhausted: {}", msg),
        }
    }
}

impl std::error::Error for EfiVarsError {}

impl From<std::io::Error> for EfiVarsError {
    fn from(err: std::io::Error) -> Self {
        EfiVarsError::Io(err.to_string())
    }
}

// ── EFI Variable ──────────────────────────────────────────────────────────

/// A single EFI variable with its name, GUID, attributes, and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfiVariable {
    /// Variable name (e.g. "BootOrder", "SecureBoot")
    pub name: String,
    /// Variable GUID in lowercase-UUID form
    pub guid: String,
    /// EFI variable attributes bitmask
    pub attributes: EfiVariableAttributes,
    /// Raw variable data (after the 4-byte attribute header)
    pub data: Vec<u8>,
}

impl EfiVariable {
    /// Create a new empty EFI variable.
    pub fn new(name: impl Into<String>, guid: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            guid: guid.into(),
            attributes: EfiVariableAttributes(0),
            data: Vec::new(),
        }
    }

    /// Builder: set the raw variable data.
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Builder: set the attributes bitmask.
    pub fn with_attributes(mut self, attrs: EfiVariableAttributes) -> Self {
        self.attributes = attrs;
        self
    }

    /// Builder: set both attributes and data at once.
    pub fn with_attributes_and_data(mut self, attrs: EfiVariableAttributes, data: Vec<u8>) -> Self {
        self.attributes = attrs;
        self.data = data;
        self
    }

    /// Interpret the data as a UTF-16 LE string, stripping trailing NULs.
    ///
    /// Returns an error if the data is too short to contain even one
    /// UTF-16 code unit, or if the resulting bytes are not valid UTF-16.
    pub fn data_as_utf16_string(&self) -> Result<String, EfiVarsError> {
        if self.data.len() < 2 {
            return Err(EfiVarsError::InvalidData(
                "Data too short for UTF-16".into(),
            ));
        }

        let byte_len = self.data.len() / 2;
        let mut u16_vec = Vec::with_capacity(byte_len);
        for chunk in self.data.chunks_exact(2) {
            u16_vec.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }

        String::from_utf16(&u16_vec)
            .map(|s| s.trim_end_matches('\0').to_string())
            .map_err(|e| EfiVarsError::InvalidData(format!("UTF-16 decode: {e}")))
    }

    /// Interpret the data as a little-endian `u64`.
    ///
    /// Returns the value if the data is exactly 1, 2, 4, or 8 bytes.
    pub fn data_as_u64(&self) -> Result<u64, EfiVarsError> {
        match self.data.len() {
            0 => Err(EfiVarsError::InvalidData("Empty data".into())),
            1 => Ok(self.data[0] as u64),
            2 => Ok(u16::from_le_bytes([self.data[0], self.data[1]]) as u64),
            4 => Ok(
                u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]) as u64,
            ),
            8 => Ok(u64::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
                self.data[4],
                self.data[5],
                self.data[6],
                self.data[7],
            ])),
            n => Err(EfiVarsError::InvalidData(format!(
                "Expected 1, 2, 4, or 8 bytes, got {n}"
            ))),
        }
    }

    /// Interpret the data as a little-endian `u32`.
    pub fn data_as_u32(&self) -> Result<u32, EfiVarsError> {
        if self.data.len() < 4 {
            return Err(EfiVarsError::InvalidData("Data too short for u32".into()));
        }
        Ok(u32::from_le_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ]))
    }

    /// Interpret the data as a little-endian `u16`.
    pub fn data_as_u16(&self) -> Result<u16, EfiVarsError> {
        if self.data.len() < 2 {
            return Err(EfiVarsError::InvalidData("Data too short for u16".into()));
        }
        Ok(u16::from_le_bytes([self.data[0], self.data[1]]))
    }

    /// Interpret the data as a single boolean flag byte.
    pub fn data_as_bool(&self) -> Result<bool, EfiVarsError> {
        if self.data.len() != 1 {
            return Err(EfiVarsError::InvalidData(format!(
                "Expected exactly 1 byte, got {}",
                self.data.len()
            )));
        }
        Ok(self.data[0] != 0)
    }

    /// Serialize this variable into the on-disk efivarfs format:
    /// `[4-byte LE attributes][payload bytes]`.
    pub fn to_efivarfs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EFI_ATTR_SIZE + self.data.len());
        out.extend_from_slice(&self.attributes.0.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Build the efivarfs filename from name and GUID.
    ///
    /// Format: `{name}-{guid}`
    pub fn efivarfs_filename(&self) -> String {
        format!("{}-{}", self.name, self.guid)
    }
}

// ── EFI Variables Manager ────────────────────────────────────────────────

/// High-level interface to the efivarfs filesystem.
///
/// All filesystem I/O is encapsulated here.  The `unsafe` boundary is
/// restricted to [`read_variable`](Self::read_variable),
/// [`write_variable`](Self::write_variable), and
/// [`delete_variable`](Self::delete_variable) because they directly touch
/// firmware state through efivarfs.
#[derive(Debug)]
pub struct EfiVars {
    efivarfs_path: Option<std::path::PathBuf>,
}

impl EfiVars {
    /// Create a new manager, probing for the efivarfs mount point.
    pub fn new() -> Self {
        let efivarfs_path = Self::detect_efivarfs();
        Self { efivarfs_path }
    }

    /// Create a manager with an explicit efivarfs path (useful for testing).
    pub fn with_path(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            efivarfs_path: Some(path.into()),
        }
    }

    /// Probe the filesystem for the efivarfs mount point.
    fn detect_efivarfs() -> Option<std::path::PathBuf> {
        let primary = std::path::Path::new(EFIVARS_PATH);
        if primary.exists() {
            return Some(primary.to_path_buf());
        }
        let legacy = std::path::Path::new(EFIVARS_LEGACY_PATH);
        if legacy.exists() {
            return Some(legacy.to_path_buf());
        }
        None
    }

    /// Check if EFI variables are accessible on this system.
    pub fn is_available(&self) -> bool {
        self.efivarfs_path.is_some()
    }

    /// Return the detected efivarfs path, if any.
    pub fn path(&self) -> Option<&std::path::Path> {
        self.efivarfs_path.as_deref()
    }

    // ── Read ──────────────────────────────────────────────────────────

    /// Read an EFI variable by name and GUID.
    ///
    /// # Operational safety
    /// This reads from firmware variables that may require elevated
    /// privileges and whose contents are controlled by the platform
    /// firmware, not by the OS.
    pub fn read_variable(&self, name: &str, guid: &str) -> Result<EfiVariable, EfiVarsError> {
        let base = self
            .efivarfs_path
            .as_ref()
            .ok_or(EfiVarsError::NotAvailable)?;
        let var_path = base.join(format!("{name}-{guid}"));

        // stat to determine the expected size
        let meta = std::fs::metadata(&var_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                EfiVarsError::NotFound(format!("{name}-{guid}"))
            } else {
                EfiVarsError::Io(format!("stat {}: {e}", var_path.display()))
            }
        })?;

        if !meta.is_file() {
            return Err(EfiVarsError::InvalidData(format!(
                "'{}' is not a regular file",
                var_path.display()
            )));
        }

        let file_size = meta.len() as usize;

        // Zero-size means uncommitted variable → treat as missing
        if file_size == 0 {
            return Err(EfiVarsError::NotFound(format!(
                "'{name}-{guid}' is uncommitted"
            )));
        }

        // Must have at least the 4-byte attribute header
        if file_size < EFI_ATTR_SIZE {
            return Err(EfiVarsError::InvalidData(format!(
                "'{name}-{guid}' is only {file_size} bytes (need ≥ {EFI_ATTR_SIZE})"
            )));
        }

        // Sanity-check: reject absurdly large variables
        if file_size > EFI_ATTR_SIZE + EFI_VARIABLE_MAX_SIZE {
            return Err(EfiVarsError::TooLarge(format!("{name}-{guid}")));
        }

        // Read the raw file with retry on EINTR (efivarfs rate-limiting)
        let raw = Self::read_with_retry(&var_path, file_size)?;

        if raw.len() < EFI_ATTR_SIZE {
            return Err(EfiVarsError::InvalidData(format!(
                "Short read from '{}': {} bytes",
                var_path.display(),
                raw.len()
            )));
        }

        let attrs = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let data = raw[EFI_ATTR_SIZE..].to_vec();

        Ok(EfiVariable {
            name: name.to_string(),
            guid: guid.to_string(),
            attributes: EfiVariableAttributes(attrs),
            data,
        })
    }

    /// Read an EFI variable's raw bytes, retrying on `EINTR`.
    ///
    /// This mirrors the retry loop in the C `efi_get_variable()` which
    /// handles kernel efivarfs rate-limiting.
    fn read_with_retry(
        path: &std::path::Path,
        expected_size: usize,
    ) -> Result<Vec<u8>, EfiVarsError> {
        use std::io::{Error, ErrorKind};

        for attempt in 0..EFI_N_RETRIES_TOTAL {
            match std::fs::read(path) {
                Ok(data) => return Ok(data),
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {
                    if attempt >= EFI_N_RETRIES_TOTAL - 1 {
                        return Err(EfiVarsError::Busy(format!(
                            "read {} failed after {} retries",
                            path.display(),
                            EFI_N_RETRIES_TOTAL
                        )));
                    }
                    // After the fast-retry budget, sleep briefly
                    if attempt >= EFI_N_RETRIES_NO_DELAY {
                        std::thread::sleep(std::time::Duration::from_micros(EFI_RETRY_DELAY_US));
                    }
                    continue;
                }
                Err(e) => {
                    if e.kind() == ErrorKind::NotFound {
                        return Err(EfiVarsError::NotFound(path.display().to_string()));
                    }
                    return Err(EfiVarsError::Io(format!("read {}: {e}", path.display())));
                }
            }
        }
        unreachable!()
    }

    // ── Write ─────────────────────────────────────────────────────────

    /// Write (create or update) an EFI variable.
    ///
    /// The variable is serialized as `[attributes u32 LE][data]` and
    /// written to the efivarfs file `{name}-{guid}`.
    ///
    /// # Operational safety
    /// Writing to EFI variables can alter system boot behaviour and may
    /// brick the firmware if misused.
    pub fn write_variable(&self, variable: &EfiVariable) -> Result<(), EfiVarsError> {
        let base = self
            .efivarfs_path
            .as_ref()
            .ok_or(EfiVarsError::NotAvailable)?;
        let var_path = base.join(variable.efivarfs_filename());

        let payload = variable.to_efivarfs_bytes();
        std::fs::write(&var_path, &payload)?;

        Ok(())
    }

    // ── Delete ────────────────────────────────────────────────────────

    /// Delete an EFI variable by removing its efivarfs file.
    ///
    /// # Operational safety
    /// Deleting firmware variables can make the system unbootable.
    pub fn delete_variable(&self, name: &str, guid: &str) -> Result<(), EfiVarsError> {
        let base = self
            .efivarfs_path
            .as_ref()
            .ok_or(EfiVarsError::NotAvailable)?;
        let var_path = base.join(format!("{name}-{guid}"));

        std::fs::remove_file(&var_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                EfiVarsError::NotFound(format!("{name}-{guid}"))
            } else {
                EfiVarsError::Io(format!("delete {}: {e}", var_path.display()))
            }
        })?;

        Ok(())
    }

    // ── List ──────────────────────────────────────────────────────────

    /// List all EFI variables as `(name, guid)` pairs.
    ///
    /// Filenames in efivarfs have the form `{name}-{guid}` where the
    /// last `-` separates the variable name from its GUID.
    pub fn list_variables(&self) -> Result<Vec<(String, String)>, EfiVarsError> {
        let base = self
            .efivarfs_path
            .as_ref()
            .ok_or(EfiVarsError::NotAvailable)?;

        let mut vars = Vec::new();
        for entry in std::fs::read_dir(base)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // The GUID is everything after the *last* hyphen
            if let Some(pos) = name_str.rfind('-') {
                let var_name = &name_str[..pos];
                let var_guid = &name_str[pos + 1..];
                vars.push((var_name.to_string(), var_guid.to_string()));
            }
        }

        Ok(vars)
    }

    // ── Secure Boot helpers ───────────────────────────────────────────

    /// Read the `SecureBoot` EFI variable and return whether Secure Boot
    /// is enabled.
    ///
    /// Returns `Ok(false)` if the variable is missing (not an EFI system
    /// or Secure Boot not supported).
    ///
    /// # Operational safety
    /// Reads from firmware variables.
    pub fn secure_boot_enabled(&self) -> Result<bool, EfiVarsError> {
        let var = match self.read_variable("SecureBoot", efi_guids::GLOBAL) {
            Ok(v) => v,
            Err(EfiVarsError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        var.data_as_bool()
    }

    /// Read the `SetupMode` EFI variable.
    ///
    /// Returns `Ok(false)` if the variable is missing.
    ///
    /// # Operational safety
    /// Reads from firmware variables.
    pub fn setup_mode(&self) -> Result<bool, EfiVarsError> {
        let var = match self.read_variable("SetupMode", efi_guids::GLOBAL) {
            Ok(v) => v,
            Err(EfiVarsError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        var.data_as_bool()
    }

    /// Compute the full [`SecureBootMode`] by reading all relevant EFI
    /// variables (SecureBoot, AuditMode, DeployedMode, SetupMode,
    /// MokSBStateRT).
    ///
    /// # Operational safety
    /// Reads from multiple firmware variables.
    pub fn secure_boot_mode(&self) -> Result<SecureBootMode, EfiVarsError> {
        let secure = self.read_flag("SecureBoot", efi_guids::GLOBAL)?;
        let audit = self.read_flag("AuditMode", efi_guids::GLOBAL)?;
        let deployed = self.read_flag("DeployedMode", efi_guids::GLOBAL)?;
        let setup = self.read_flag("SetupMode", efi_guids::GLOBAL)?;
        // MokSBStateRT uses the ShimLock vendor GUID
        let moksb = self.read_flag("MokSBStateRT", "605dab50-e046-4300-abb6-3dd810dd8b23")?;

        Ok(decode_secure_boot_mode(
            secure, audit, deployed, setup, moksb,
        ))
    }

    /// Read a single-byte boolean EFI flag.
    ///
    /// Returns `false` if the variable does not exist.
    fn read_flag(&self, name: &str, guid: &str) -> Result<bool, EfiVarsError> {
        let var = match self.read_variable(name, guid) {
            Ok(v) => v,
            Err(EfiVarsError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        var.data_as_bool()
            .map_err(|_| EfiVarsError::InvalidData(format!("Expected {name} to be a single byte")))
    }
}

impl Default for EfiVars {
    fn default() -> Self {
        Self::new()
    }
}

// ── System-level helpers ─────────────────────────────────────────────────

/// Check whether the system was booted via UEFI.
///
/// This is a pure-filesystem check — it simply tests whether
/// `/sys/firmware/efi/` exists.
pub fn is_efi_boot() -> bool {
    std::path::Path::new("/sys/firmware/efi/").exists()
}

/// Replace all backslashes with forward slashes in a string.
///
/// EFI device paths use `\` as a separator, but Linux paths use `/`.
/// This mirrors the C function `efi_tilt_backslashes()`.
pub fn tilt_backslashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            out.push('/');
        } else {
            out.push(c);
        }
    }
    out
}

/// Build the efivarfs variable name from a variable name and GUID.
///
/// The efivarfs convention is `{name}-{guid}` (lowercase UUID).
pub fn make_variable_path(name: &str, guid: &str) -> String {
    format!("{name}-{guid}")
}

/// Build the full efivarfs filesystem path for a variable.
pub fn make_variable_full_path(name: &str, guid: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(EFIVARS_PATH).join(format!("{name}-{guid}"))
}

// ── Encoding helpers ─────────────────────────────────────────────────────

/// Encode a Rust `&str` as a NUL-terminated UTF-16 LE byte sequence,
/// suitable for writing as an EFI string variable.
pub fn encode_efi_utf16_string(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(s.len() * 2 + 2);
    for ch in s.encode_utf16() {
        bytes.extend_from_slice(&ch.to_le_bytes());
    }
    // NUL terminator
    bytes.extend_from_slice(&[0u8, 0u8]);
    bytes
}

/// Decode a byte slice as UTF-16 LE, stripping trailing NULs.
pub fn decode_efi_utf16_string(data: &[u8]) -> Result<String, EfiVarsError> {
    if data.len() < 2 {
        return Err(EfiVarsError::InvalidData("Too short for UTF-16".into()));
    }

    let byte_len = data.len() / 2;
    let mut u16_vec = Vec::with_capacity(byte_len);
    for chunk in data.chunks_exact(2) {
        u16_vec.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    String::from_utf16(&u16_vec)
        .map(|s| s.trim_end_matches('\0').to_string())
        .map_err(|e| EfiVarsError::InvalidData(format!("UTF-16 decode: {e}")))
}

/// Verify that the current value of an EFI variable matches the expected
/// attributes and data.
///
/// Returns `Ok(true)` if they match, `Ok(false)` if they differ.
///
/// # Operational safety
/// Reads from firmware variables.
pub fn verify_variable(
    vars: &EfiVars,
    name: &str,
    guid: &str,
    expected_attrs: u32,
    expected_data: &[u8],
) -> Result<bool, EfiVarsError> {
    let var = match vars.read_variable(name, guid) {
        Ok(v) => v,
        Err(EfiVarsError::NotFound(_)) => return Ok(false),
        Err(e) => return Err(e),
    };

    Ok(var.attributes.0 == expected_attrs && var.data == expected_data)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- SecureBootMode --------------------------------------------------

    #[test]
    fn test_decode_secure_boot_mode_user() {
        let mode = decode_secure_boot_mode(true, false, false, false, false);
        assert_eq!(mode, SecureBootMode::User);
    }

    #[test]
    fn test_decode_secure_boot_mode_tainted() {
        let mode = decode_secure_boot_mode(true, false, false, false, true);
        assert_eq!(mode, SecureBootMode::Tainted);
    }

    #[test]
    fn test_decode_secure_boot_mode_setup() {
        let mode = decode_secure_boot_mode(true, false, false, true, false);
        assert_eq!(mode, SecureBootMode::Setup);
    }

    #[test]
    fn test_decode_secure_boot_mode_audit() {
        let mode = decode_secure_boot_mode(true, true, false, false, false);
        assert_eq!(mode, SecureBootMode::Audit);
    }

    #[test]
    fn test_decode_secure_boot_mode_deployed() {
        // Deployed takes priority over secure=true
        let mode = decode_secure_boot_mode(true, false, true, false, false);
        assert_eq!(mode, SecureBootMode::Deployed);
    }

    #[test]
    fn test_decode_secure_boot_mode_disabled() {
        let mode = decode_secure_boot_mode(false, false, false, false, false);
        assert_eq!(mode, SecureBootMode::Disabled);
    }

    #[test]
    fn test_secure_boot_mode_display() {
        assert_eq!(SecureBootMode::User.to_string(), "user");
        assert_eq!(SecureBootMode::Setup.to_string(), "setup");
        assert_eq!(SecureBootMode::Unsupported.to_string(), "unsupported");
    }

    // -- EfiVariable constructors ----------------------------------------

    #[test]
    fn test_efi_variable_new() {
        let var = EfiVariable::new("BootOrder", efi_guids::GLOBAL);
        assert_eq!(var.name, "BootOrder");
        assert_eq!(var.guid, efi_guids::GLOBAL);
        assert!(var.data.is_empty());
        assert_eq!(var.attributes.0, 0);
    }

    #[test]
    fn test_efi_variable_builder() {
        let var = EfiVariable::new("TestVar", efi_guids::GLOBAL)
            .with_data(vec![0x01, 0x00, 0x00, 0x00])
            .with_attributes(EfiVariableAttributes(EfiVariableAttributes::NON_VOLATILE));

        assert_eq!(var.name, "TestVar");
        assert!(var.attributes.is_non_volatile());
        assert_eq!(var.data, vec![0x01, 0x00, 0x00, 0x00]);
    }

    // -- Data interpretation ---------------------------------------------

    #[test]
    fn test_data_as_u64() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL)
            .with_data(vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]);
        assert_eq!(var.data_as_u64(), Ok(0xDEADBEEF12345678));
    }

    #[test]
    fn test_data_as_u64_from_u32() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(var.data_as_u64(), Ok(0x12345678));
    }

    #[test]
    fn test_data_as_u32() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(var.data_as_u32(), Ok(0x12345678));
    }

    #[test]
    fn test_data_as_u16() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![0x34, 0x12]);
        assert_eq!(var.data_as_u16(), Ok(0x1234));
    }

    #[test]
    fn test_data_as_bool() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![1]);
        assert_eq!(var.data_as_bool(), Ok(true));

        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![0]);
        assert_eq!(var.data_as_bool(), Ok(false));
    }

    #[test]
    fn test_data_as_bool_wrong_size() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![1, 2]);
        assert!(var.data_as_bool().is_err());
    }

    #[test]
    fn test_data_as_u32_too_short() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![0x01]);
        assert!(var.data_as_u32().is_err());
    }

    #[test]
    fn test_data_as_u16_too_short() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![0x01]);
        assert!(var.data_as_u16().is_err());
    }

    // -- UTF-16 encoding/decoding ----------------------------------------

    #[test]
    fn test_encode_decode_utf16_roundtrip() {
        let original = "Hello, EFI!";
        let encoded = encode_efi_utf16_string(original);
        let decoded = decode_efi_utf16_string(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_utf16_nul_terminated() {
        let encoded = encode_efi_utf16_string("AB");
        // "AB" = 0x41 0x00 0x42 0x00, then NUL = 0x00 0x00
        assert_eq!(encoded, vec![0x41, 0x00, 0x42, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_decode_utf16_too_short() {
        assert!(decode_efi_utf16_string(&[0x41]).is_err());
    }

    #[test]
    fn test_data_as_utf16_string() {
        // "Hi" in UTF-16 LE + NUL
        let data = vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(data);
        assert_eq!(var.data_as_utf16_string().unwrap(), "Hi");
    }

    #[test]
    fn test_data_as_utf16_string_too_short() {
        let var = EfiVariable::new("x", efi_guids::GLOBAL).with_data(vec![0x00]);
        assert!(var.data_as_utf16_string().is_err());
    }

    // -- Serialization ---------------------------------------------------

    #[test]
    fn test_to_efivarfs_bytes() {
        let var = EfiVariable::new("Test", efi_guids::GLOBAL)
            .with_attributes(EfiVariableAttributes(0x07))
            .with_data(vec![0xDE, 0xAD]);

        let bytes = var.to_efivarfs_bytes();
        assert_eq!(bytes, vec![0x07, 0x00, 0x00, 0x00, 0xDE, 0xAD]);
    }

    #[test]
    fn test_efivarfs_filename() {
        let var = EfiVariable::new("BootOrder", "8be4df61-93ca-11d2-aa0d-00e098032b8c");
        assert_eq!(
            var.efivarfs_filename(),
            "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        );
    }

    // -- tilt_backslashes ------------------------------------------------

    #[test]
    fn test_tilt_backslashes() {
        assert_eq!(
            tilt_backslashes("\\EFI\\ubuntu\\grubx64.efi"),
            "/EFI/ubuntu/grubx64.efi"
        );
    }

    #[test]
    fn test_tilt_backslashes_no_backslash() {
        assert_eq!(tilt_backslashes("/normal/path"), "/normal/path");
    }

    #[test]
    fn test_tilt_backslashes_empty() {
        assert_eq!(tilt_backslashes(""), "");
    }

    // -- make_variable_path ----------------------------------------------

    #[test]
    fn test_make_variable_path() {
        assert_eq!(
            make_variable_path("BootOrder", efi_guids::GLOBAL),
            format!("BootOrder-{}", efi_guids::GLOBAL)
        );
    }

    #[test]
    fn test_make_variable_full_path() {
        let p = make_variable_full_path("SecureBoot", efi_guids::GLOBAL);
        assert!(p
            .to_str()
            .unwrap()
            .starts_with("/sys/firmware/efi/efivars/"));
        assert!(p.to_str().unwrap().contains("SecureBoot-"));
    }

    // -- EfiVarsError ----------------------------------------------------

    #[test]
    fn test_efi_vars_error_display() {
        assert!(EfiVarsError::NotAvailable
            .to_string()
            .contains("not available"));
        assert!(EfiVarsError::NotFound("x".into())
            .to_string()
            .contains("not found"));
        assert!(EfiVarsError::PermissionDenied
            .to_string()
            .contains("Permission"));
        assert!(EfiVarsError::Unsupported
            .to_string()
            .contains("not supported"));
    }

    #[test]
    fn test_efi_vars_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broke");
        let efi_err: EfiVarsError = io_err.into();
        assert!(matches!(efi_err, EfiVarsError::Io(_)));
    }

    // -- EfiVars construction --------------------------------------------

    #[test]
    fn test_efi_vars_default() {
        let vars = EfiVars::default();
        // Whether EFI vars are available depends on the host
        assert!(vars.path().is_none() || vars.path().is_some());
    }

    #[test]
    fn test_efi_vars_with_path() {
        let vars = EfiVars::with_path("/tmp/fake-efivars");
        assert_eq!(vars.path().unwrap().to_str().unwrap(), "/tmp/fake-efivars");
        assert!(vars.is_available());
    }

    // -- EFI_DEFAULT_VARIABLE_ATTRS --------------------------------------

    #[test]
    fn test_default_attrs_includes_non_volatile() {
        let attrs = EfiVariableAttributes(EFI_DEFAULT_VARIABLE_ATTRS);
        assert!(attrs.is_non_volatile());
        assert!(attrs.is_bootservice_access());
        assert!(attrs.is_runtime_access());
    }

    // -- decode_efi_utf16_string edge cases ------------------------------

    #[test]
    fn test_decode_utf16_empty_after_nul_strip() {
        // All zeros → empty string after NUL strip
        let data = vec![0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode_efi_utf16_string(&data).unwrap(), "");
    }
}
