// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/blkid-util.c, src/shared/blkid-util.h
//
// Block device identification via libblkid — dynamic loading, partition
// table type/UUID helpers, filesystem superblock probing, and partition
// type string lookup.  All libblkid symbols are resolved through dlopen
// so the module gracefully degrades when libblkid is absent.

use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by blkid dynamic-loading and probe operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlkidError {
    /// libblkid is not available on this system.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// The requested value was not present (ENXIO equivalent).
    NotFound,
    /// A string value could not be parsed as the expected type.
    ParseError(String),
}

impl fmt::Display for BlkidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "libblkid support is not available"),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libblkid: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libblkid symbol not found: {}", sym)
            }
            Self::NotFound => write!(f, "Requested blkid value not found"),
            Self::ParseError(msg) => write!(f, "Failed to parse blkid value: {}", msg),
        }
    }
}

impl std::error::Error for BlkidError {}

impl From<BlkidError> for i32 {
    fn from(e: BlkidError) -> i32 {
        match e {
            BlkidError::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            BlkidError::DlopenFailed(_) => Errno::ENOENT.to_neg_errno(),
            BlkidError::SymbolNotFound(_) => Errno::ENOENT.to_neg_errno(),
            BlkidError::NotFound => Errno::ENXIO.to_neg_errno(),
            BlkidError::ParseError(_) => Errno::EINVAL.to_neg_errno(),
        }
    }
}

// ── Library name constant ───────────────────────────────────────────────────

/// Shared library name for libblkid.
const LIBBLKID_NAME: &str = "libblkid.so.1";

// ── Required symbol names ───────────────────────────────────────────────────

/// All libblkid symbols that must be resolved at dlopen time.
const REQUIRED_SYMBOLS: &[&str] = &[
    "blkid_do_fullprobe",
    "blkid_do_probe",
    "blkid_do_safeprobe",
    "blkid_do_wipe",
    "blkid_encode_string",
    "blkid_free_probe",
    "blkid_new_probe",
    "blkid_new_probe_from_filename",
    "blkid_partition_get_flags",
    "blkid_partition_get_name",
    "blkid_partition_get_partno",
    "blkid_partition_get_size",
    "blkid_partition_get_start",
    "blkid_partition_get_type",
    "blkid_partition_get_type_string",
    "blkid_partition_get_uuid",
    "blkid_partlist_devno_to_partition",
    "blkid_partlist_get_partition",
    "blkid_partlist_numof_partitions",
    "blkid_probe_enable_partitions",
    "blkid_probe_enable_superblocks",
    "blkid_probe_filter_superblocks_type",
    "blkid_probe_filter_superblocks_usage",
    "blkid_probe_get_fd",
    "blkid_probe_get_partitions",
    "blkid_probe_get_size",
    "blkid_probe_get_value",
    "blkid_probe_is_wholedisk",
    "blkid_probe_lookup_value",
    "blkid_probe_numof_values",
    "blkid_probe_set_device",
    "blkid_probe_set_hint",
    "blkid_probe_set_partitions_flags",
    "blkid_probe_set_sectorsize",
    "blkid_probe_set_superblocks_flags",
    "blkid_safe_string",
];

// ── Dlopen state ────────────────────────────────────────────────────────────

/// Global flag: has `dlopen_libblkid()` been called and completed successfully?
static BLKID_LOADED: AtomicBool = AtomicBool::new(false);

/// Attempt to dynamically load libblkid and resolve all required symbols.
///
/// Idempotent: after the first successful call returns `Ok(())` immediately.
/// On failure the error is not cached — callers may retry (e.g. after
/// installing the library).
pub fn dlopen_libblkid() -> Result<(), BlkidError> {
    if BLKID_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let handle = unsafe { dlopen_wrapper(LIBBLKID_NAME) }?;

    // Verify every required symbol is present.
    let missing: Vec<String> = REQUIRED_SYMBOLS
        .iter()
        .filter_map(|sym| {
            let c_sym = CString::new(*sym).unwrap_or_default();
            let ptr = unsafe { dlsym_wrapper(handle, &c_sym) };
            if ptr.is_null() {
                Some((*sym).to_string())
            } else {
                None
            }
        })
        .collect();

    if !missing.is_empty() {
        return Err(BlkidError::SymbolNotFound(missing.join(", ")));
    }

    // Keep the handle open for the process lifetime.
    let _ = handle;

    BLKID_LOADED.store(true, Ordering::Release);
    Ok(())
}

/// Returns `true` if libblkid was successfully loaded.
pub fn have_blkid() -> bool {
    BLKID_LOADED.load(Ordering::Acquire)
}

// ── Platform dlopen / dlsym wrappers ────────────────────────────────────────

/// Open a shared library, returning the handle on success.
///
/// Wraps `dlopen()` with `RTLD_LAZY | RTLD_LOCAL`.
unsafe fn dlopen_wrapper(lib_name: &str) -> Result<*mut c_void, BlkidError> {
    let c_name = CString::new(lib_name)
        .map_err(|e| BlkidError::DlopenFailed(format!("Invalid library name: {}", e)))?;
    // SAFETY: c_name is NUL-terminated and remains live for the call.
    let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let detail = unsafe {
            let err_ptr = libc::dlerror();
            if err_ptr.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(err_ptr).to_string_lossy().into_owned()
            }
        };
        Err(BlkidError::DlopenFailed(detail))
    } else {
        Ok(handle)
    }
}

/// Look up a symbol in an already-opened library handle.
///
/// Returns a raw pointer that is non-null on success, null if not found.
unsafe fn dlsym_wrapper(handle: *mut c_void, name: &CStr) -> *const c_void {
    // SAFETY: the caller supplies a live dlopen handle and name is NUL-terminated.
    unsafe { libc::dlsym(handle, name.as_ptr()) }
}

// ── Safeprobe return codes ──────────────────────────────────────────────────

/// Return codes from `blkid_do_safeprobe()`, matching the C header enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum BlkidSafeprobeResult {
    /// Probing succeeded, result is unambiguous.
    Found = 0,
    /// No filesystem / partition table detected.
    NotFound = 1,
    /// Multiple ambiguous results found.
    Ambiguous = -2,
    /// An error occurred during probing.
    Error = -1,
}

impl BlkidSafeprobeResult {
    /// Construct from a raw return code, defaulting to `Error` for unknown values.
    pub fn from_raw(raw: i32) -> Self {
        match raw {
            0 => Self::Found,
            1 => Self::NotFound,
            -2 => Self::Ambiguous,
            -1 | _ => Self::Error,
        }
    }
}

// ── UUID type ───────────────────────────────────────────────────────────────

/// A 128-bit ID matching `sd_id128_t` layout (16 bytes, big-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdId128(pub [u8; 16]);

impl SdId128 {
    /// All-zero (null) ID.
    pub const NULL: SdId128 = SdId128([0u8; 16]);

    /// Create from a byte array.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        SdId128(bytes)
    }

    /// Parse a UUID string into an `SdId128`.
    ///
    /// Accepts the standard 36-char form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    /// or a 32-char lowercase hex string without separators.
    pub fn from_string(s: &str) -> Result<Self, BlkidError> {
        let s = s.trim();
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return Err(BlkidError::ParseError(format!(
                "UUID string must be 32 hex chars (or 36 with dashes), got {}",
                hex.len()
            )));
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| {
                BlkidError::ParseError(format!("Invalid hex in UUID at position {}: {}", i * 2, e))
            })?;
        }
        Ok(SdId128(bytes))
    }

    /// Format as a UUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
    pub fn to_uuid_string(&self) -> String {
        let b = &self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15],
        )
    }

    /// Format as a 32-char lowercase hex string without separators.
    pub fn to_hex_string(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ── Safe string extraction ─────────────────────────────────────────────────

/// Extract a C string from a pointer, returning `None` for null or empty.
///
/// This is the Rust equivalent of the C `isempty()` check used in
/// `blkid_partition_get_uuid_id128()` and friends.
fn c_str_to_option(ptr: *const libc::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    if s.is_empty() { None } else { Some(s) }
}

// ── Partition UUID / type helpers ───────────────────────────────────────────

/// Get the partition UUID as an `SdId128`.
///
/// Equivalent to the C function `blkid_partition_get_uuid_id128()`.
/// Returns `Err(BlkidError::NotFound)` if the partition has no UUID.
pub fn blkid_partition_get_uuid_id128(uuid_str: Option<&str>) -> Result<SdId128, BlkidError> {
    match uuid_str {
        None | Some("") => Err(BlkidError::NotFound),
        Some(s) => SdId128::from_string(s),
    }
}

/// Get the partition type UUID as an `SdId128`.
///
/// Equivalent to the C function `blkid_partition_get_type_id128()`.
/// Returns `Err(BlkidError::NotFound)` if the partition has no type string.
pub fn blkid_partition_get_type_id128(type_str: Option<&str>) -> Result<SdId128, BlkidError> {
    match type_str {
        None | Some("") => Err(BlkidError::NotFound),
        Some(s) => SdId128::from_string(s),
    }
}

// ── Probe value helpers ─────────────────────────────────────────────────────

/// Look up a probe field and parse it as an `SdId128`.
///
/// Equivalent to the C function `blkid_probe_lookup_value_id128()`.
/// Returns `Err(BlkidError::NotFound)` if the field is absent.
pub fn blkid_probe_lookup_value_id128(field_value: Option<&str>) -> Result<SdId128, BlkidError> {
    match field_value {
        None | Some("") => Err(BlkidError::NotFound),
        Some(s) => SdId128::from_string(s),
    }
}

/// Look up a probe field and parse it as a `u64`.
///
/// Equivalent to the C function `blkid_probe_lookup_value_u64()`.
/// Returns `Err(BlkidError::NotFound)` if the field is absent.
pub fn blkid_probe_lookup_value_u64(field_value: Option<&str>) -> Result<u64, BlkidError> {
    match field_value {
        None | Some("") => Err(BlkidError::NotFound),
        Some(s) => s
            .trim()
            .parse::<u64>()
            .map_err(|e| BlkidError::ParseError(format!("Cannot parse '{}' as u64: {}", s, e))),
    }
}

// ── Partition table type ───────────────────────────────────────────────────

/// Well-known partition table type strings returned by libblkid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTableType {
    /// GUID Partition Table.
    Gpt,
    /// Master Boot Record (DOS partition table).
    Dos,
    /// Apple Partition Map.
    Mac,
    /// BSD disklabel.
    Bsd,
    /// SGI (IRIX) disk label.
    Sgi,
    /// Sun disklabel.
    Sun,
    /// AIX volume label.
    Aix,
    /// Unknown or unrecognized partition table type.
    Unknown,
}

impl PartitionTableType {
    /// Map a libblkid `PTTYPE` probe value string to a known type.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "gpt" => Self::Gpt,
            "dos" | "mbr" => Self::Dos,
            "mac" => Self::Mac,
            "bsd" => Self::Bsd,
            "sgi" => Self::Sgi,
            "sun" => Self::Sun,
            "aix" => Self::Aix,
            _ => Self::Unknown,
        }
    }
}

/// Get the partition table type from a probe field value.
///
/// Wraps `blkid_probe_lookup_value_id128` logic for the `PTTYPE` field.
pub fn blkid_partition_table_type(
    pttype_value: Option<&str>,
) -> Result<PartitionTableType, BlkidError> {
    match pttype_value {
        None | Some("") => Err(BlkidError::NotFound),
        Some(s) => Ok(PartitionTableType::from_str_lossy(s)),
    }
}

/// Get the partition table UUID from a probe field value.
///
/// Wraps `blkid_probe_lookup_value_id128` logic for the `PTUUID` field.
pub fn blkid_partition_table_uuid(ptxuid_value: Option<&str>) -> Result<SdId128, BlkidError> {
    blkid_probe_lookup_value_id128(ptxuid_value)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SdId128 tests ────────────────────────────────────────────────────

    #[test]
    fn test_sd_id128_null() {
        assert_eq!(SdId128::NULL.0, [0u8; 16]);
    }

    #[test]
    fn test_sd_id128_from_string_uuid_format() {
        let uuid = SdId128::from_string("c5a364bd-412a-4bdf-a66d-098e840a4e1c").unwrap();
        assert_eq!(uuid.0[0], 0xc5);
        assert_eq!(uuid.0[1], 0xa3);
        assert_eq!(uuid.0[15], 0x1c);
    }

    #[test]
    fn test_sd_id128_from_string_hex_format() {
        let with_dashes = SdId128::from_string("c5a364bd-412a-4bdf-a66d-098e840a4e1c").unwrap();
        let without = SdId128::from_string("c5a364bd412a4bdfa66d098e840a4e1c").unwrap();
        assert_eq!(with_dashes, without);
    }

    #[test]
    fn test_sd_id128_from_string_invalid() {
        assert!(SdId128::from_string("").is_err());
        assert!(SdId128::from_string("too-short").is_err());
        assert!(SdId128::from_string("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn test_sd_id128_to_uuid_string() {
        let uuid = SdId128::from_bytes([
            0xc5, 0xa3, 0x64, 0xbd, 0x41, 0x2a, 0x4b, 0xdf, 0xa6, 0x6d, 0x09, 0x8e, 0x84, 0x0a,
            0x4e, 0x1c,
        ]);
        assert_eq!(
            uuid.to_uuid_string(),
            "c5a364bd-412a-4bdf-a66d-098e840a4e1c"
        );
    }

    #[test]
    fn test_sd_id128_to_hex_string() {
        let uuid = SdId128::NULL;
        assert_eq!(uuid.to_hex_string(), "00000000000000000000000000000000");
    }

    // ── Partition UUID / type helpers ────────────────────────────────────

    #[test]
    fn test_blkid_partition_get_uuid_id128_valid() {
        let result = blkid_partition_get_uuid_id128(Some("c5a364bd-412a-4bdf-a66d-098e840a4e1c"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0[0], 0xc5);
    }

    #[test]
    fn test_blkid_partition_get_uuid_id128_none() {
        assert_eq!(
            blkid_partition_get_uuid_id128(None).unwrap_err(),
            BlkidError::NotFound
        );
    }

    #[test]
    fn test_blkid_partition_get_uuid_id128_empty() {
        assert_eq!(
            blkid_partition_get_uuid_id128(Some("")).unwrap_err(),
            BlkidError::NotFound
        );
    }

    #[test]
    fn test_blkid_partition_get_type_id128_valid() {
        let result = blkid_partition_get_type_id128(Some("0fc63daf-8483-4772-8e79-3d69d8477de4"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0[0], 0x0f);
    }

    #[test]
    fn test_blkid_partition_get_type_id128_none() {
        assert_eq!(
            blkid_partition_get_type_id128(None).unwrap_err(),
            BlkidError::NotFound
        );
    }

    // ── Probe value helpers ──────────────────────────────────────────────

    #[test]
    fn test_blkid_probe_lookup_value_id128_valid() {
        let result = blkid_probe_lookup_value_id128(Some("c5a364bd-412a-4bdf-a66d-098e840a4e1c"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_blkid_probe_lookup_value_id128_not_found() {
        assert_eq!(
            blkid_probe_lookup_value_id128(None).unwrap_err(),
            BlkidError::NotFound
        );
    }

    #[test]
    fn test_blkid_probe_lookup_value_u64_valid() {
        let result = blkid_probe_lookup_value_u64(Some("12345678"));
        assert_eq!(result.unwrap(), 12345678u64);
    }

    #[test]
    fn test_blkid_probe_lookup_value_u64_not_found() {
        assert_eq!(
            blkid_probe_lookup_value_u64(None).unwrap_err(),
            BlkidError::NotFound
        );
    }

    #[test]
    fn test_blkid_probe_lookup_value_u64_invalid() {
        let result = blkid_probe_lookup_value_u64(Some("not-a-number"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlkidError::ParseError(_)));
    }

    // ── Partition table type ─────────────────────────────────────────────

    #[test]
    fn test_partition_table_type_from_str() {
        assert_eq!(
            PartitionTableType::from_str_lossy("gpt"),
            PartitionTableType::Gpt
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("dos"),
            PartitionTableType::Dos
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("mbr"),
            PartitionTableType::Dos
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("mac"),
            PartitionTableType::Mac
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("bsd"),
            PartitionTableType::Bsd
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("sgi"),
            PartitionTableType::Sgi
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("sun"),
            PartitionTableType::Sun
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("aix"),
            PartitionTableType::Aix
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("unknown"),
            PartitionTableType::Unknown
        );
        assert_eq!(
            PartitionTableType::from_str_lossy("GPT"),
            PartitionTableType::Gpt
        );
    }

    #[test]
    fn test_blkid_partition_table_type_valid() {
        assert_eq!(
            blkid_partition_table_type(Some("gpt")).unwrap(),
            PartitionTableType::Gpt
        );
        assert_eq!(
            blkid_partition_table_type(Some("dos")).unwrap(),
            PartitionTableType::Dos
        );
    }

    #[test]
    fn test_blkid_partition_table_type_not_found() {
        assert_eq!(
            blkid_partition_table_type(None).unwrap_err(),
            BlkidError::NotFound
        );
    }

    #[test]
    fn test_blkid_partition_table_uuid_valid() {
        let result = blkid_partition_table_uuid(Some("12345678-1234-1234-1234-123456789abc"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0[0], 0x12);
    }

    #[test]
    fn test_blkid_partition_table_uuid_not_found() {
        assert_eq!(
            blkid_partition_table_uuid(None).unwrap_err(),
            BlkidError::NotFound
        );
    }

    // ── Safeprobe result ─────────────────────────────────────────────────

    #[test]
    fn test_safeprobe_result_from_raw() {
        assert_eq!(
            BlkidSafeprobeResult::from_raw(0),
            BlkidSafeprobeResult::Found
        );
        assert_eq!(
            BlkidSafeprobeResult::from_raw(1),
            BlkidSafeprobeResult::NotFound
        );
        assert_eq!(
            BlkidSafeprobeResult::from_raw(-2),
            BlkidSafeprobeResult::Ambiguous
        );
        assert_eq!(
            BlkidSafeprobeResult::from_raw(-1),
            BlkidSafeprobeResult::Error
        );
        // Unknown codes default to Error
        assert_eq!(
            BlkidSafeprobeResult::from_raw(42),
            BlkidSafeprobeResult::Error
        );
    }

    // ── Error type conversion ────────────────────────────────────────────

    #[test]
    fn test_blkid_error_into_c_int() {
        let code: i32 = BlkidError::Unsupported.into();
        assert_eq!(code, Errno::EOPNOTSUPP.to_neg_errno());

        let code: i32 = BlkidError::NotFound.into();
        assert_eq!(code, Errno::ENXIO.to_neg_errno());
    }

    #[test]
    fn test_blkid_error_display() {
        assert!(!BlkidError::Unsupported.to_string().is_empty());
        assert!(
            !BlkidError::DlopenFailed("test".into())
                .to_string()
                .is_empty()
        );
        assert!(
            !BlkidError::SymbolNotFound("sym".into())
                .to_string()
                .is_empty()
        );
        assert!(!BlkidError::NotFound.to_string().is_empty());
        assert!(!BlkidError::ParseError("err".into()).to_string().is_empty());
    }

    // ── c_str_to_option helper ───────────────────────────────────────────

    #[test]
    fn test_c_str_to_option_null() {
        assert_eq!(c_str_to_option(std::ptr::null()), None);
    }

    #[test]
    fn test_c_str_to_option_valid() {
        let s = CString::new("hello").unwrap();
        assert_eq!(c_str_to_option(s.as_ptr()), Some("hello".to_string()));
    }

    #[test]
    fn test_c_str_to_option_empty() {
        let s = CString::new("").unwrap();
        assert_eq!(c_str_to_option(s.as_ptr()), None);
    }
}
