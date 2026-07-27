// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/efi-loader.c, src/shared/efi-loader.h
//
// EFI loader configuration — reading/writing EFI variables for boot loader
// configuration, SecureBoot state detection, EFI loader feature flags,
// boot entry counting, and UKI measurement status.
//
// Port of the C efi-loader.c module to idiomatic safe Rust.
// All public functions return `Result<T, EfiLoaderError>`.

use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

// ── Constants ─────────────────────────────────────────────────────────────

/// Vendor GUID for systemd-boot loader variables.
const EFI_VENDOR_LOADER_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// Vendor GUID for systemd-stub variables.
const EFI_VENDOR_STUB_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// Microseconds in one hour (sanity ceiling for boot timing).
const USEC_PER_HOUR: u64 = 3_600_000_000;

/// Microseconds in one second.
const USEC_PER_SEC: u64 = 1_000_000;

/// Maximum representable microsecond value.
const USEC_INFINITY: u64 = u64::MAX;

/// PCR index used by sd-stub for kernel image measurement.
const TPM2_PCR_KERNEL_BOOT: u32 = 11;

/// Valid characters for EFI loader entry names.
const ENTRY_NAME_VALID_CHARS: &[u8] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-_.@";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by EFI loader operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EfiLoaderError {
    /// System was not booted via UEFI.
    NotEfiBoot,
    /// An EFI variable was not found.
    NotFound(String),
    /// The EFI variable data is malformed or has the wrong size.
    InvalidData(String),
    /// An I/O error occurred reading from sysfs/efivarfs.
    Io(String),
    /// Value out of acceptable range.
    OutOfRange(String),
    /// Operation not supported on this system.
    Unsupported,
    /// The boot loader entry name contains invalid characters.
    InvalidEntryName(String),
}

impl fmt::Display for EfiLoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EfiLoaderError::NotEfiBoot => write!(f, "Not an EFI boot"),
            EfiLoaderError::NotFound(var) => write!(f, "EFI variable not found: {var}"),
            EfiLoaderError::InvalidData(msg) => write!(f, "Invalid EFI variable data: {msg}"),
            EfiLoaderError::Io(msg) => write!(f, "I/O error: {msg}"),
            EfiLoaderError::OutOfRange(msg) => write!(f, "Value out of range: {msg}"),
            EfiLoaderError::Unsupported => write!(f, "Operation not supported"),
            EfiLoaderError::InvalidEntryName(name) => {
                write!(f, "Invalid loader entry name: {name}")
            }
        }
    }
}

impl std::error::Error for EfiLoaderError {}

impl From<std::io::Error> for EfiLoaderError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => EfiLoaderError::NotFound(err.to_string()),
            std::io::ErrorKind::PermissionDenied => EfiLoaderError::Io(err.to_string()),
            _ => EfiLoaderError::Io(err.to_string()),
        }
    }
}

// ── Result alias ──────────────────────────────────────────────────────────

/// Specialized `Result` type for EFI loader operations.
pub type EfiLoaderResult<T> = Result<T, EfiLoaderError>;

// ── Cached measurement state ──────────────────────────────────────────────

/// Cached result for `efi_measured_uki()`. Negative means uncached.
static EFI_MEASURED_UKI_CACHED: AtomicI32 = AtomicI32::new(-1);

/// Cached result for `efi_measured_os()`. Negative means uncached.
static EFI_MEASURED_OS_CACHED: AtomicI32 = AtomicI32::new(-1);

// ── Boot timing ───────────────────────────────────────────────────────────

/// Result of reading the boot firmware and loader timestamps from EFI
/// variables set by systemd-boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootTimings {
    /// Microseconds spent in firmware before the boot loader started.
    pub firmware_usec: u64,
    /// Microseconds at which the boot loader handed off to the kernel.
    pub loader_usec: u64,
}

/// Read firmware and loader timestamps from EFI variables.
///
/// Returns the microseconds at which the loader was initialised
/// (`LoaderTimeInitUSec`) and at which it executed the kernel
/// (`LoaderTimeExecUSec`).
///
/// # Errors
///
/// Returns [`EfiLoaderError::NotEfiBoot`] on non-EFI systems.
/// Returns [`EfiLoaderError::InvalidData`] if the timing values are
/// nonsensical (e.g. loader time before init time, or delta > 1 hour).
pub fn efi_loader_get_boot_usec() -> EfiLoaderResult<BootTimings> {
    if !is_efi_boot() {
        return Err(EfiLoaderError::NotEfiBoot);
    }

    let init_str = read_efi_variable_string("LoaderTimeInitUSec", EFI_VENDOR_LOADER_GUID)?;
    let exec_str = read_efi_variable_string("LoaderTimeExecUSec", EFI_VENDOR_LOADER_GUID)?;

    let x: u64 = init_str
        .trim()
        .parse()
        .map_err(|_| EfiLoaderError::InvalidData("LoaderTimeInitUSec".into()))?;
    let y: u64 = exec_str
        .trim()
        .parse()
        .map_err(|_| EfiLoaderError::InvalidData("LoaderTimeExecUSec".into()))?;

    if y == 0 || y < x || y - x > USEC_PER_HOUR {
        return Err(EfiLoaderError::InvalidData(format!(
            "Bad LoaderTimeInitUSec={x}, LoaderTimeExecUSec={y}"
        )));
    }

    Ok(BootTimings {
        firmware_usec: x,
        loader_usec: y,
    })
}

// ── Device partition UUID ─────────────────────────────────────────────────

/// A 128-bit UUID (sd-id128 compatible).
pub type Id128 = [u8; 16];

/// Read the `LoaderDevicePartUUID` EFI variable as a 128-bit UUID.
///
/// # Errors
///
/// Returns [`EfiLoaderError::NotEfiBoot`] on non-EFI systems.
pub fn efi_loader_get_device_part_uuid() -> EfiLoaderResult<Id128> {
    get_device_part_uuid("LoaderDevicePartUUID")
}

/// Read the `StubDevicePartUUID` EFI variable as a 128-bit UUID.
///
/// # Errors
///
/// Returns [`EfiLoaderError::NotEfiBoot`] on non-EFI systems.
pub fn efi_stub_get_device_part_uuid() -> EfiLoaderResult<Id128> {
    get_device_part_uuid("StubDevicePartUUID")
}

fn get_device_part_uuid(variable: &str) -> EfiLoaderResult<Id128> {
    if !is_efi_boot() {
        return Err(EfiLoaderError::NotEfiBoot);
    }

    let s = read_efi_variable_string(variable, EFI_VENDOR_LOADER_GUID)?;
    parse_id128(&s)
}

/// Read an arbitrary EFI variable as a 128-bit UUID string.
///
/// # Errors
///
/// Returns [`EfiLoaderError::NotEfiBoot`] on non-EFI systems.
pub fn efi_get_variable_id128(variable: &str) -> EfiLoaderResult<Id128> {
    if !is_efi_boot() {
        return Err(EfiLoaderError::NotEfiBoot);
    }

    let s = read_efi_variable_string(variable, EFI_VENDOR_LOADER_GUID)?;
    parse_id128(&s)
}

// ── Boot entries ──────────────────────────────────────────────────────────

/// Read the list of boot loader entry names from the `LoaderEntries` EFI
/// variable.
///
/// The variable contains a series of NUL-terminated UTF-16LE strings.
/// Only entries whose names pass [`efi_loader_entry_name_valid`] are
/// returned.
///
/// # Errors
///
/// Returns [`EfiLoaderError::NotEfiBoot`] on non-EFI systems.
pub fn efi_loader_get_entries() -> EfiLoaderResult<Vec<String>> {
    if !is_efi_boot() {
        return Err(EfiLoaderError::NotEfiBoot);
    }

    let data = read_efi_variable_raw("LoaderEntries", EFI_VENDOR_LOADER_GUID)?;

    // Skip the 4-byte attribute header.
    let content = if data.len() > 4 {
        &data[4..]
    } else {
        &data[..]
    };

    let mut entries = Vec::new();
    let mut current_code_units: Vec<u16> = Vec::new();

    // Process UTF-16LE code units; each string is NUL-terminated.
    for chunk in content.chunks_exact(2) {
        let code_unit = u16::from_le_bytes([chunk[0], chunk[1]]);

        if code_unit == 0 {
            if !current_code_units.is_empty() {
                if let Ok(s) = String::from_utf16(&current_code_units) {
                    if efi_loader_entry_name_valid(&s) {
                        entries.push(s);
                    }
                }
                current_code_units.clear();
            }
        } else {
            current_code_units.push(code_unit);
        }
    }

    // Handle trailing string without NUL terminator.
    if !current_code_units.is_empty() {
        if let Ok(s) = String::from_utf16(&current_code_units) {
            if efi_loader_entry_name_valid(&s) {
                entries.push(s);
            }
        }
    }

    Ok(entries)
}

// ── Loader features ───────────────────────────────────────────────────────

/// Feature flags reported by the systemd-boot loader via the
/// `LoaderFeatures` EFI variable.
///
/// When the `LoaderFeatures` variable is absent but the loader identifies
/// as `systemd-boot`, a hardcoded legacy feature set is returned
/// (config timeout, entry default, entry one-shot).
///
/// Returns `0` on non-EFI systems or when no features are supported.
pub fn efi_loader_get_features() -> EfiLoaderResult<u64> {
    if !is_efi_boot() {
        return Ok(0);
    }

    // Try reading LoaderFeatures variable (u64).
    match read_efi_variable_u64("LoaderFeatures", EFI_VENDOR_LOADER_GUID) {
        Ok(features) => return Ok(features),
        // Variable doesn't exist yet — fall through to legacy detection.
        Err(EfiLoaderError::NotFound(_)) => {}
        Err(e) => return Err(e),
    }

    // Legacy path: check if this is systemd-boot at all via LoaderInfo.
    match read_efi_variable_string("LoaderInfo", EFI_VENDOR_LOADER_GUID) {
        Ok(info) => {
            if first_word(&info, "systemd-boot") {
                // Hardcoded feature set for older systemd-boot versions.
                return Ok(EfiLoaderFeature::ConfigTimeout as u64
                    | EfiLoaderFeature::EntryDefault as u64
                    | EfiLoaderFeature::EntryOneshot as u64);
            }
        }
        Err(EfiLoaderError::NotFound(_)) => {
            // Variable not set — not systemd-boot at all.
        }
        Err(e) => return Err(e),
    }

    Ok(0)
}

/// Feature flags reported by systemd-stub via the `StubFeatures` EFI
/// variable.
///
/// When the variable is absent but the stub identifies as
/// `systemd-stub`, a hardcoded legacy feature set is returned
/// (report boot partition).
///
/// Returns `0` on non-EFI systems or when no features are supported.
pub fn efi_stub_get_features() -> EfiLoaderResult<u64> {
    if !is_efi_boot() {
        return Ok(0);
    }

    match read_efi_variable_u64("StubFeatures", EFI_VENDOR_STUB_GUID) {
        Ok(features) => return Ok(features),
        Err(EfiLoaderError::NotFound(_)) => {}
        Err(e) => return Err(e),
    }

    match read_efi_variable_string("StubInfo", EFI_VENDOR_STUB_GUID) {
        Ok(info) => {
            if first_word(&info, "systemd-stub") {
                return Ok(EfiStubFeature::ReportBootPartition as u64);
            }
        }
        Err(EfiLoaderError::NotFound(_)) => {}
        Err(e) => return Err(e),
    }

    Ok(0)
}

// ── Loader feature flag enum ──────────────────────────────────────────────

/// Feature flags for the systemd-boot loader.
///
/// Each variant corresponds to a bit in the `LoaderFeatures` u64 bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum EfiLoaderFeature {
    ConfigTimeout = 1 << 0,
    ConfigTimeoutOneShot = 1 << 1,
    EntryDefault = 1 << 2,
    EntryOneshot = 1 << 3,
    BootCounting = 1 << 4,
    Xbootldr = 1 << 5,
    RandomSeed = 1 << 6,
    LoadDriver = 1 << 7,
    SortKey = 1 << 8,
    SavedEntry = 1 << 9,
    Devicetree = 1 << 10,
    SecurebootEnroll = 1 << 11,
    RetainShim = 1 << 12,
    MenuDisable = 1 << 13,
    MultiProfileUki = 1 << 14,
    ReportUrl = 1 << 15,
    Type1Uki = 1 << 16,
    Type1UkiUrl = 1 << 17,
    Tpm2ActivePcrBanks = 1 << 18,
    EntryPreferred = 1 << 19,
}

/// Feature flags for the systemd-stub.
///
/// Each variant corresponds to a bit in the `StubFeatures` u64 bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum EfiStubFeature {
    ReportBootPartition = 1 << 0,
    PickUpCredentials = 1 << 1,
    PickUpSysexts = 1 << 2,
    ThreePcrs = 1 << 3,
    RandomSeed = 1 << 4,
    CmdlineAddons = 1 << 5,
    CmdlineSmbios = 1 << 6,
    DevicetreeAddons = 1 << 7,
    PickUpConfexts = 1 << 8,
    MultiProfileUki = 1 << 9,
    ReportStubPartition = 1 << 10,
    ReportUrl = 1 << 11,
}

// ── UKI measurement status ────────────────────────────────────────────────

/// Result of checking whether the kernel was measured into a TPM PCR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasuredUkiStatus {
    /// Kernel was measured into the expected PCR by sd-stub.
    Measured,
    /// No measurement was performed (no TPM2, no stub, etc.).
    NotMeasured,
    /// Stub measured into a different PCR than expected.
    WrongPcr,
    /// EFI is not available on this system.
    NotEfi,
    /// An error occurred reading the EFI variable.
    Error,
}

/// Check if the system booted with a measured UKI (kernel image measured
/// into a TPM2 PCR by systemd-stub).
///
/// Returns [`MeasuredUkiStatus::Measured`] if sd-stub measured the kernel
/// into PCR 11 (the expected index).
/// Returns [`MeasuredUkiStatus::WrongPcr`] if a different PCR was used.
/// Returns [`MeasuredUkiStatus::NotMeasured`] if no measurement is detected.
///
/// The `$SYSTEMD_FORCE_MEASURE` environment variable can override the
/// detection for debugging purposes.
pub fn efi_measured_uki() -> MeasuredUkiStatus {
    // Check cached result.
    let cached = EFI_MEASURED_UKI_CACHED.load(Ordering::Acquire);
    if cached >= 0 {
        return i32_to_measured_status(cached);
    }

    // Allow env override for debugging.
    match secure_getenv_bool("SYSTEMD_FORCE_MEASURE") {
        Ok(true) => {
            EFI_MEASURED_UKI_CACHED.store(1, Ordering::Release);
            return MeasuredUkiStatus::Measured;
        }
        Ok(false) => {
            EFI_MEASURED_UKI_CACHED.store(0, Ordering::Release);
            return MeasuredUkiStatus::NotMeasured;
        }
        Err(_) => {} // Not set or unparseable — continue.
    }

    if !is_efi_boot() {
        EFI_MEASURED_UKI_CACHED.store(-1, Ordering::Release);
        return MeasuredUkiStatus::NotEfi;
    }

    if !efi_has_tpm2() {
        EFI_MEASURED_UKI_CACHED.store(0, Ordering::Release);
        return MeasuredUkiStatus::NotMeasured;
    }

    let pcr_string = match read_efi_variable_string("StubPcrKernelImage", EFI_VENDOR_STUB_GUID) {
        Ok(s) => s,
        Err(_) => {
            EFI_MEASURED_UKI_CACHED.store(0, Ordering::Release);
            return MeasuredUkiStatus::NotMeasured;
        }
    };

    let pcr_nr: u32 = match pcr_string.trim().parse() {
        Ok(v) => v,
        Err(_) => {
            EFI_MEASURED_UKI_CACHED.store(2, Ordering::Release);
            return MeasuredUkiStatus::Error;
        }
    };

    let status = if pcr_nr == TPM2_PCR_KERNEL_BOOT {
        MeasuredUkiStatus::Measured
    } else {
        MeasuredUkiStatus::WrongPcr
    };

    let cache_val = match status {
        MeasuredUkiStatus::Measured => 1,
        MeasuredUkiStatus::NotMeasured => 0,
        MeasuredUkiStatus::WrongPcr => 3,
        MeasuredUkiStatus::NotEfi => -1,
        MeasuredUkiStatus::Error => 2,
    };
    EFI_MEASURED_UKI_CACHED.store(cache_val, Ordering::Release);
    status
}

/// Check if the OS should enable its TPM2 measurement machinery.
///
/// Reads `systemd.tpm2_measured_os=` from `/proc/cmdline`. If not set,
/// falls back to [`efi_measured_uki()`].
pub fn efi_measured_os() -> MeasuredUkiStatus {
    let cached = EFI_MEASURED_OS_CACHED.load(Ordering::Acquire);
    if cached >= 0 {
        return i32_to_measured_status(cached);
    }

    // Check kernel command line for explicit override.
    if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
        for arg in cmdline.split_whitespace() {
            if let Some(val) = arg.strip_prefix("systemd.tpm2_measured_os=") {
                match parse_boolean(val) {
                    Some(true) => {
                        EFI_MEASURED_OS_CACHED.store(1, Ordering::Release);
                        return MeasuredUkiStatus::Measured;
                    }
                    Some(false) => {
                        EFI_MEASURED_OS_CACHED.store(0, Ordering::Release);
                        return MeasuredUkiStatus::NotMeasured;
                    }
                    None => {} // Unparseable — continue.
                }
            }
        }
    }

    // Default: if we booted with a measured UKI, assume measured OS.
    let status = efi_measured_uki();
    let cache_val = match status {
        MeasuredUkiStatus::Measured => 1,
        MeasuredUkiStatus::NotMeasured => 0,
        MeasuredUkiStatus::WrongPcr => 3,
        MeasuredUkiStatus::NotEfi => -1,
        MeasuredUkiStatus::Error => 2,
    };
    EFI_MEASURED_OS_CACHED.store(cache_val, Ordering::Release);
    status
}

// ── Config timeout ────────────────────────────────────────────────────────

/// Read the one-shot configuration timeout from the
/// `LoaderConfigTimeoutOneShot` EFI variable.
///
/// The value is read in seconds and converted to microseconds.
///
/// # Errors
///
/// Returns [`EfiLoaderError::NotEfiBoot`] on non-EFI systems.
/// Returns [`EfiLoaderError::OutOfRange`] if the value would overflow
/// when converted to microseconds.
pub fn efi_loader_get_config_timeout_one_shot() -> EfiLoaderResult<u64> {
    if !is_efi_boot() {
        return Err(EfiLoaderError::NotEfiBoot);
    }

    let v = read_efi_variable_string("LoaderConfigTimeoutOneShot", EFI_VENDOR_LOADER_GUID)?;

    let sec: u64 = v
        .trim()
        .parse()
        .map_err(|_| EfiLoaderError::InvalidData("LoaderConfigTimeoutOneShot".into()))?;

    if sec > USEC_INFINITY / USEC_PER_SEC {
        return Err(EfiLoaderError::OutOfRange(format!(
            "Timeout {sec}s would overflow in microseconds"
        )));
    }

    Ok(sec * USEC_PER_SEC)
}

// ── Entry name validation ─────────────────────────────────────────────────

/// Check whether a boot loader entry name is valid.
///
/// Valid entry names are non-empty, fit in a filename, and contain only
/// alphanumeric characters plus `+`, `-`, `_`, `.`, and `@`.
pub fn efi_loader_entry_name_valid(s: &str) -> bool {
    if !filename_is_valid(s) {
        return false;
    }
    s.bytes().all(|b| ENTRY_NAME_VALID_CHARS.contains(&b))
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check whether the system was booted via UEFI.
fn is_efi_boot() -> bool {
    Path::new("/sys/firmware/efi").exists()
}

/// Check whether the system has a TPM2 chip.
fn efi_has_tpm2() -> bool {
    Path::new("/sys/class/tpm/tpm0").exists() || Path::new("/sys/class/tpm/tpm1").exists()
}

/// Read an EFI variable as a raw byte vector (including the 4-byte
/// attribute header).
///
/// # Safety
/// This reads from firmware state via efivarfs.
fn read_efi_variable_raw(variable: &str, guid: &str) -> EfiLoaderResult<Vec<u8>> {
    let path = format!("/sys/firmware/efi/efivars/{variable}-{guid}");
    let data = fs::read(&path)?;
    Ok(data)
}

/// Read an EFI variable and interpret it as a UTF-8 string
/// (after stripping the 4-byte attribute header).
fn read_efi_variable_string(variable: &str, guid: &str) -> EfiLoaderResult<String> {
    let data = read_efi_variable_raw(variable, guid)?;

    if data.len() < 4 {
        return Err(EfiLoaderError::InvalidData(format!(
            "Variable {variable} is too short"
        )));
    }

    let content = &data[4..];
    String::from_utf8(content.to_vec())
        .map(|s| s.trim_end_matches('\0').to_string())
        .map_err(|_| EfiLoaderError::InvalidData(format!("Variable {variable} is not valid UTF-8")))
}

/// Read an EFI variable and interpret the payload as a little-endian u64.
fn read_efi_variable_u64(variable: &str, guid: &str) -> EfiLoaderResult<u64> {
    let data = read_efi_variable_raw(variable, guid)?;

    if data.len() < 4 + 8 {
        return Err(EfiLoaderError::InvalidData(format!(
            "Variable {variable} is too short for u64 (got {} bytes)",
            data.len()
        )));
    }

    let bytes: [u8; 8] = data[4..12]
        .try_into()
        .map_err(|_| EfiLoaderError::InvalidData(format!("Variable {variable} slice error")))?;
    Ok(u64::from_le_bytes(bytes))
}

/// Check if the first whitespace-delimited word of `s` equals `word`.
fn first_word(s: &str, word: &str) -> bool {
    s.split_whitespace().next() == Some(word)
}

/// Parse a boolean from common string representations.
fn parse_boolean(s: &str) -> Option<bool> {
    match s.trim().to_lowercase().as_str() {
        "1" | "yes" | "true" | "on" | "y" => Some(true),
        "0" | "no" | "false" | "off" | "n" => Some(false),
        _ => None,
    }
}

/// Read a boolean environment variable (using `secure_getenv` semantics).
fn secure_getenv_bool(name: &str) -> Result<bool, ()> {
    let val = std::env::var(name).map_err(|_| ())?;
    parse_boolean(&val).ok_or(())
}

/// Check if a string is a valid filename (non-empty, ≤255 bytes, no `/`
/// or NUL).
fn filename_is_valid(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    !s.bytes().any(|b| b == b'/')
}

/// Parse a 128-bit UUID from a hyphenated or raw hex string.
fn parse_id128(s: &str) -> EfiLoaderResult<Id128> {
    let hex: String = s.trim().chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(EfiLoaderError::InvalidData(format!(
            "Expected 32 hex digits for UUID, got {}",
            hex.len()
        )));
    }

    let mut result = [0u8; 16];
    for i in 0..16 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        result[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| EfiLoaderError::InvalidData(format!("Invalid hex in UUID: {byte_str}")))?;
    }
    Ok(result)
}

/// Convert a cached i32 to a [`MeasuredUkiStatus`].
fn i32_to_measured_status(val: i32) -> MeasuredUkiStatus {
    match val {
        1 => MeasuredUkiStatus::Measured,
        0 => MeasuredUkiStatus::NotMeasured,
        3 => MeasuredUkiStatus::WrongPcr,
        _ => MeasuredUkiStatus::Error,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Entry name validation --------------------------------------------

    #[test]
    fn test_entry_name_valid_simple() {
        assert!(efi_loader_entry_name_valid("linux"));
        assert!(efi_loader_entry_name_valid("linux-6.1.0"));
        assert!(efi_loader_entry_name_valid("auto-windows"));
        assert!(efi_loader_entry_name_valid("pop_os.conf"));
        assert!(efi_loader_entry_name_valid("entry@test"));
    }

    #[test]
    fn test_entry_name_valid_empty() {
        assert!(!efi_loader_entry_name_valid(""));
    }

    #[test]
    fn test_entry_name_invalid_chars() {
        assert!(!efi_loader_entry_name_valid("entry/name"));
        assert!(!efi_loader_entry_name_valid("entry name"));
        assert!(!efi_loader_entry_name_valid("entry!"));
        assert!(!efi_loader_entry_name_valid("entry#hash"));
    }

    #[test]
    fn test_entry_name_too_long() {
        assert!(!efi_loader_entry_name_valid(&"a".repeat(256)));
        assert!(efi_loader_entry_name_valid(&"a".repeat(255)));
    }

    // -- filename_is_valid ------------------------------------------------

    #[test]
    fn test_filename_is_valid() {
        assert!(filename_is_valid("foo"));
        assert!(filename_is_valid("foo-bar_baz.qux"));
        assert!(filename_is_valid("a"));
        assert!(!filename_is_valid(""));
        assert!(!filename_is_valid("foo/bar"));
    }

    // -- Boolean parsing --------------------------------------------------

    #[test]
    fn test_parse_boolean() {
        assert_eq!(parse_boolean("1"), Some(true));
        assert_eq!(parse_boolean("yes"), Some(true));
        assert_eq!(parse_boolean("true"), Some(true));
        assert_eq!(parse_boolean("on"), Some(true));
        assert_eq!(parse_boolean("y"), Some(true));
        assert_eq!(parse_boolean("0"), Some(false));
        assert_eq!(parse_boolean("no"), Some(false));
        assert_eq!(parse_boolean("false"), Some(false));
        assert_eq!(parse_boolean("off"), Some(false));
        assert_eq!(parse_boolean("n"), Some(false));
        assert_eq!(parse_boolean("maybe"), None);
        assert_eq!(parse_boolean(""), None);
    }

    #[test]
    fn test_parse_boolean_case_insensitive() {
        assert_eq!(parse_boolean("YES"), Some(true));
        assert_eq!(parse_boolean("True"), Some(true));
        assert_eq!(parse_boolean("FALSE"), Some(false));
        assert_eq!(parse_boolean(" No "), Some(false));
    }

    // -- first_word -------------------------------------------------------

    #[test]
    fn test_first_word() {
        assert!(first_word("systemd-boot 254", "systemd-boot"));
        assert!(first_word("systemd-stub v255", "systemd-stub"));
        assert!(!first_word("systemd-boot 254", "grub"));
        assert!(!first_word("", "systemd-boot"));
        assert!(!first_word("no-match", "systemd-boot"));
    }

    // -- UUID parsing -----------------------------------------------------

    #[test]
    fn test_parse_id128_hyphenated() {
        let id = parse_id128("5a1c6a86-df9d-4096-b1d5-a65e0862f19a").unwrap();
        assert_eq!(id[0], 0x5a);
        assert_eq!(id[1], 0x1c);
        assert_eq!(id[15], 0x9a);
    }

    #[test]
    fn test_parse_id128_raw_hex() {
        let with_dashes = parse_id128("5a1c6a86-df9d-4096-b1d5-a65e0862f19a").unwrap();
        let without_dashes = parse_id128("5a1c6a86df9d4096b1d5a65e0862f19a").unwrap();
        assert_eq!(with_dashes, without_dashes);
    }

    #[test]
    fn test_parse_id128_invalid() {
        assert!(parse_id128("invalid").is_err());
        assert!(parse_id128("5a1c6a86-df9d-4096").is_err());
        assert!(parse_id128("").is_err());
    }

    // -- Feature flag enums -----------------------------------------------

    #[test]
    fn test_loader_feature_flags() {
        assert_eq!(EfiLoaderFeature::ConfigTimeout as u64, 1);
        assert_eq!(EfiLoaderFeature::EntryDefault as u64, 1 << 2);
        assert_eq!(EfiLoaderFeature::EntryOneshot as u64, 1 << 3);
        assert_eq!(EfiLoaderFeature::BootCounting as u64, 1 << 4);
        assert_eq!(EfiLoaderFeature::Xbootldr as u64, 1 << 5);
        assert_eq!(EfiLoaderFeature::Tpm2ActivePcrBanks as u64, 1 << 18);
        assert_eq!(EfiLoaderFeature::EntryPreferred as u64, 1 << 19);
    }

    #[test]
    fn test_stub_feature_flags() {
        assert_eq!(EfiStubFeature::ReportBootPartition as u64, 1);
        assert_eq!(EfiStubFeature::PickUpCredentials as u64, 1 << 1);
        assert_eq!(EfiStubFeature::ThreePcrs as u64, 1 << 3);
        assert_eq!(EfiStubFeature::ReportUrl as u64, 1 << 11);
    }

    #[test]
    fn test_feature_flag_combination() {
        let features = EfiLoaderFeature::ConfigTimeout as u64
            | EfiLoaderFeature::EntryDefault as u64
            | EfiLoaderFeature::EntryOneshot as u64;
        assert!(features & EfiLoaderFeature::ConfigTimeout as u64 != 0);
        assert!(features & EfiLoaderFeature::EntryDefault as u64 != 0);
        assert!(features & EfiLoaderFeature::BootCounting as u64 == 0);
    }

    // -- Error type -------------------------------------------------------

    #[test]
    fn test_error_display() {
        let err = EfiLoaderError::NotEfiBoot;
        assert!(err.to_string().contains("EFI"));

        let err = EfiLoaderError::NotFound("LoaderInfo-xxx".into());
        assert!(err.to_string().contains("LoaderInfo-xxx"));

        let err = EfiLoaderError::InvalidEntryName("bad/name".into());
        assert!(err.to_string().contains("bad/name"));

        let err = EfiLoaderError::OutOfRange("overflow".into());
        assert!(err.to_string().contains("overflow"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let efi_err: EfiLoaderError = io_err.into();
        assert!(matches!(efi_err, EfiLoaderError::NotFound(_)));

        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broke");
        let efi_err: EfiLoaderError = io_err.into();
        assert!(matches!(efi_err, EfiLoaderError::Io(_)));
    }

    // -- Boot timings -----------------------------------------------------

    #[test]
    fn test_boot_timings_derived() {
        let t = BootTimings {
            firmware_usec: 1_000_000,
            loader_usec: 3_000_000,
        };
        assert_eq!(t.firmware_usec, 1_000_000);
        assert_eq!(t.loader_usec, 3_000_000);
        assert!(t.loader_usec > t.firmware_usec);
    }

    // -- Measured UKI status conversion -----------------------------------

    #[test]
    fn test_i32_to_measured_status() {
        assert_eq!(i32_to_measured_status(1), MeasuredUkiStatus::Measured);
        assert_eq!(i32_to_measured_status(0), MeasuredUkiStatus::NotMeasured);
        assert_eq!(i32_to_measured_status(3), MeasuredUkiStatus::WrongPcr);
        assert_eq!(i32_to_measured_status(-1), MeasuredUkiStatus::Error);
        assert_eq!(i32_to_measured_status(99), MeasuredUkiStatus::Error);
    }
}
