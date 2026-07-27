// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/fdisk-util.c, src/shared/fdisk-util.h
//
// libfdisk partition table utilities — dlopen of libfdisk for partition
// table manipulation.  Provides context creation, partition UUID/type
// extraction, and GPT attribute flags parsing/serialization.
//
// All libfdisk symbols are resolved through dlopen so the module
// gracefully degrades when libfdisk is absent.

use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by fdisk dynamic-loading and partition operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdiskError {
    /// libfdisk is not available on this system.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// The requested value was not present (ENXIO equivalent).
    NotFound,
    /// A string value could not be parsed as the expected type.
    ParseError(String),
    /// An invalid argument was provided.
    InvalidArgument(String),
}

impl fmt::Display for FdiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "libfdisk support is not available"),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libfdisk: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libfdisk symbol not found: {}", sym)
            }
            Self::NotFound => write!(f, "Requested fdisk value not found"),
            Self::ParseError(msg) => write!(f, "Failed to parse fdisk value: {}", msg),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl std::error::Error for FdiskError {}

// ── GPT partition attribute flags ───────────────────────────────────────────

/// Bit 0: partition is required for the platform to function.
pub const SD_GPT_FLAG_REQUIRED_PARTITION: u64 = 1u64 << 0;

/// Bit 1: do not issue block I/O protocol requests for this partition.
pub const SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL: u64 = 1u64 << 1;

/// Bit 2: legacy BIOS bootable flag (MBR-compatible).
pub const SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE: u64 = 1u64 << 2;

/// Well-known GPT attribute flag names mapped to their bit positions.
///
/// These correspond to the named flags from `sd-gpt.h` and are used by
/// `parse_gpt_attrs_string()` and `flags_to_gpt_attrs_string()`.
struct NamedGptFlag {
    name: &'static str,
    value: u64,
}

/// Named GPT flags table, in the same order as the C source checks them.
static NAMED_GPT_FLAGS: &[NamedGptFlag] = &[
    NamedGptFlag {
        name: "RequiredPartition",
        value: SD_GPT_FLAG_REQUIRED_PARTITION,
    },
    NamedGptFlag {
        name: "NoBlockIOProtocol",
        value: SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL,
    },
    NamedGptFlag {
        name: "LegacyBIOSBootable",
        value: SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE,
    },
];

// ── Library name constant ───────────────────────────────────────────────────

/// Shared library name for libfdisk.
const LIBFDISK_NAME: &str = "libfdisk.so.1";

/// All libfdisk symbols that must be resolved at dlopen time.
const REQUIRED_SYMBOLS: &[&str] = &[
    "fdisk_new_context",
    "fdisk_unref_context",
    "fdisk_save_user_sector_size",
    "fdisk_assign_device",
    "fdisk_partition_get_uuid",
    "fdisk_partition_get_type",
    "fdisk_parttype_get_string",
    "fdisk_partition_get_attrs",
    "fdisk_partition_set_attrs",
];

// ── Dlopen state ────────────────────────────────────────────────────────────

/// Global flag: has `dlopen_libfdisk()` been called and completed successfully?
static FDISK_LOADED: AtomicBool = AtomicBool::new(false);

/// Attempt to dynamically load libfdisk and resolve all required symbols.
///
/// Idempotent: after the first successful call returns `Ok(())` immediately.
/// On failure the error is not cached — callers may retry.
pub fn dlopen_libfdisk() -> Result<(), FdiskError> {
    if FDISK_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let handle = unsafe { dlopen_wrapper(LIBFDISK_NAME) }?;

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
        return Err(FdiskError::SymbolNotFound(missing.join(", ")));
    }

    // Keep the handle open for the process lifetime.
    let _ = handle;

    FDISK_LOADED.store(true, Ordering::Release);
    Ok(())
}

/// Returns `true` if libfdisk was successfully loaded.
pub fn have_fdisk() -> bool {
    FDISK_LOADED.load(Ordering::Acquire)
}

// ── Platform dlopen / dlsym wrappers ────────────────────────────────────────

/// Open a shared library, returning the handle on success.
///
/// Wraps `dlopen()` with `RTLD_LAZY | RTLD_LOCAL`.
unsafe fn dlopen_wrapper(lib_name: &str) -> Result<*mut c_void, FdiskError> {
    #[cfg(target_os = "linux")]
    {
        let c_name = CString::new(lib_name)
            .map_err(|e| FdiskError::DlopenFailed(format!("Invalid library name: {}", e)))?;
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
            Err(FdiskError::DlopenFailed(detail))
        } else {
            Ok(handle)
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = lib_name;
        Err(FdiskError::Unsupported)
    }
}

/// Look up a symbol in an already-opened library handle.
///
/// Returns a raw pointer that is non-null on success, null if not found.
#[cfg(target_os = "linux")]
unsafe fn dlsym_wrapper(handle: *mut c_void, name: &CStr) -> *const c_void {
    // SAFETY: the caller supplies a live dlopen handle and name is NUL-terminated.
    unsafe { libc::dlsym(handle, name.as_ptr()) }
}

#[cfg(not(target_os = "linux"))]
unsafe fn dlsym_wrapper(_handle: *mut c_void, _name: &CStr) -> *const c_void {
    std::ptr::null()
}

// ── Sector size sentinel ────────────────────────────────────────────────────

/// Sentinel value indicating the sector size should be probed automatically.
pub const FDISK_SECTOR_SIZE_AUTO: u32 = u32::MAX;

// ── Partition UUID helpers ──────────────────────────────────────────────────

/// Parse a partition UUID string into a 16-byte array.
///
/// Accepts the standard 36-char form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// or a 32-char lowercase hex string without separators.
///
/// Equivalent to `sd_id128_from_string()` used in the C source for UUID parsing.
pub fn parse_partition_uuid(s: &str) -> Result<[u8; 16], FdiskError> {
    let s = s.trim();
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(FdiskError::ParseError(format!(
            "UUID string must be 32 hex chars (or 36 with dashes), got {}",
            hex.len()
        )));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| {
            FdiskError::ParseError(format!("Invalid hex in UUID at position {}: {}", i * 2, e))
        })?;
    }
    Ok(bytes)
}

/// Get the partition UUID from a UUID string.
///
/// This is the pure-Rust equivalent of `fdisk_partition_get_uuid_as_id128()`.
/// Returns `Err(FdiskError::NotFound)` if the UUID string is `None` or empty.
pub fn fdisk_partition_get_uuid(uuid_str: Option<&str>) -> Result<[u8; 16], FdiskError> {
    match uuid_str {
        None | Some("") => Err(FdiskError::NotFound),
        Some(s) => parse_partition_uuid(s),
    }
}

/// Get the partition type UUID from a type string.
///
/// This is the pure-Rust equivalent of `fdisk_partition_get_type_as_id128()`.
/// Returns `Err(FdiskError::NotFound)` if the type string is `None` or empty.
pub fn fdisk_partition_get_type(type_str: Option<&str>) -> Result<[u8; 16], FdiskError> {
    match type_str {
        None | Some("") => Err(FdiskError::NotFound),
        Some(s) => parse_partition_uuid(s),
    }
}

// ── GPT attribute flags parsing ─────────────────────────────────────────────

/// Parse a comma-separated GPT attribute flags string into a `u64` bitmask.
///
/// This is the Rust equivalent of `fdisk_partition_get_attrs_as_uint64()`.
///
/// Recognised named flags:
/// - `RequiredPartition` → bit 0
/// - `NoBlockIOProtocol` → bit 1
/// - `LegacyBIOSBootable` → bit 2
///
/// Numeric flags may be specified as bare numbers or with a `GUID:` prefix,
/// e.g. `"3"` or `"GUID:3"` sets bit 3.  Flags above bit 63 are silently
/// ignored.
///
/// Returns `Ok(0)` for `None` or empty input.
pub fn parse_gpt_attrs_string(attrs: Option<&str>) -> u64 {
    let Some(raw) = attrs else {
        return 0;
    };
    if raw.is_empty() {
        return 0;
    }

    let mut flags: u64 = 0;

    for word in raw.split(',') {
        let word = word.trim();
        if word.is_empty() {
            continue;
        }

        let mut matched = false;
        for named in NAMED_GPT_FLAGS {
            if word == named.name {
                flags |= named.value;
                matched = true;
                break;
            }
        }

        if matched {
            continue;
        }

        // Try numeric: strip optional "GUID:" prefix.
        let num_str = word.strip_prefix("GUID:").unwrap_or(word);

        if let Ok(u) = num_str.parse::<u32>() {
            if (u as usize) < 64 {
                flags |= 1u64 << u;
            }
            // Flags above bit 63 are silently ignored, matching the C behaviour.
        }
        // Unknown non-numeric flags are silently ignored, matching the C behaviour.
    }

    flags
}

/// Serialize a `u64` bitmask into a comma-separated GPT attribute flags string.
///
/// This is the Rust equivalent of `fdisk_partition_set_attrs_as_uint64()`.
///
/// Only numeric bit positions are emitted; named flags are not recognised on
/// output (matching the C implementation which iterates over all bits).
pub fn flags_to_gpt_attrs_string(flags: u64) -> String {
    if flags == 0 {
        return String::new();
    }

    let mut parts = Vec::new();
    for i in 0..64u32 {
        if (flags & (1u64 << i)) != 0 {
            parts.push(i.to_string());
        }
    }
    parts.join(",")
}

// ── Safe C-string extraction ────────────────────────────────────────────────

/// Extract a C string from a pointer, returning `None` for null or empty.
///
/// This is the Rust equivalent of checking `isempty()` on the result of
/// `fdisk_partition_get_uuid()` and friends.
///
/// # Safety
/// A non-null `ptr` must remain readable through a terminating NUL for this
/// call.
pub unsafe fn c_str_to_option(ptr: *const libc::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── GPT flag constants ───────────────────────────────────────────────

    #[test]
    fn test_gpt_flag_constants() {
        assert_eq!(SD_GPT_FLAG_REQUIRED_PARTITION, 1u64 << 0);
        assert_eq!(SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL, 1u64 << 1);
        assert_eq!(SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE, 1u64 << 2);
        assert!(
            SD_GPT_FLAG_REQUIRED_PARTITION != SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE,
            "flags must have distinct bit positions"
        );
    }

    // ── Sector size sentinel ─────────────────────────────────────────────

    #[test]
    fn test_sector_size_auto_sentinel() {
        assert_eq!(FDISK_SECTOR_SIZE_AUTO, u32::MAX);
        assert_ne!(FDISK_SECTOR_SIZE_AUTO, 0);
        assert_ne!(FDISK_SECTOR_SIZE_AUTO, 512);
    }

    // ── UUID parsing ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_partition_uuid_with_dashes() {
        let result = parse_partition_uuid("c5a364bd-412a-4bdf-a66d-098e840a4e1c").unwrap();
        assert_eq!(result[0], 0xc5);
        assert_eq!(result[1], 0xa3);
        assert_eq!(result[15], 0x1c);
    }

    #[test]
    fn test_parse_partition_uuid_without_dashes() {
        let with = parse_partition_uuid("c5a364bd-412a-4bdf-a66d-098e840a4e1c").unwrap();
        let without = parse_partition_uuid("c5a364bd412a4bdfa66d098e840a4e1c").unwrap();
        assert_eq!(with, without);
    }

    #[test]
    fn test_parse_partition_uuid_invalid() {
        assert!(parse_partition_uuid("").is_err());
        assert!(parse_partition_uuid("too-short").is_err());
        assert!(parse_partition_uuid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn test_fdisk_partition_get_uuid_valid() {
        let result =
            fdisk_partition_get_uuid(Some("c5a364bd-412a-4bdf-a66d-098e840a4e1c")).unwrap();
        assert_eq!(result[0], 0xc5);
        assert_eq!(result[15], 0x1c);
    }

    #[test]
    fn test_fdisk_partition_get_uuid_none() {
        assert_eq!(
            fdisk_partition_get_uuid(None).unwrap_err(),
            FdiskError::NotFound
        );
    }

    #[test]
    fn test_fdisk_partition_get_uuid_empty() {
        assert_eq!(
            fdisk_partition_get_uuid(Some("")).unwrap_err(),
            FdiskError::NotFound
        );
    }

    #[test]
    fn test_fdisk_partition_get_type_valid() {
        let result =
            fdisk_partition_get_type(Some("0fc63daf-8483-4772-8e79-3d69d8477de4")).unwrap();
        assert_eq!(result[0], 0x0f);
        assert_eq!(result[1], 0xc6);
    }

    #[test]
    fn test_fdisk_partition_get_type_none() {
        assert_eq!(
            fdisk_partition_get_type(None).unwrap_err(),
            FdiskError::NotFound
        );
    }

    // ── Attribute flags parsing ──────────────────────────────────────────

    #[test]
    fn test_parse_gpt_attrs_string_none() {
        assert_eq!(parse_gpt_attrs_string(None), 0);
    }

    #[test]
    fn test_parse_gpt_attrs_string_empty() {
        assert_eq!(parse_gpt_attrs_string(Some("")), 0);
    }

    #[test]
    fn test_parse_gpt_attrs_string_required_partition() {
        assert_eq!(
            parse_gpt_attrs_string(Some("RequiredPartition")),
            SD_GPT_FLAG_REQUIRED_PARTITION
        );
    }

    #[test]
    fn test_parse_gpt_attrs_string_named_flags() {
        let result = parse_gpt_attrs_string(Some(
            "RequiredPartition,NoBlockIOProtocol,LegacyBIOSBootable",
        ));
        assert_eq!(
            result,
            SD_GPT_FLAG_REQUIRED_PARTITION
                | SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL
                | SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE
        );
    }

    #[test]
    fn test_parse_gpt_attrs_string_numeric() {
        assert_eq!(parse_gpt_attrs_string(Some("3")), 1u64 << 3);
    }

    #[test]
    fn test_parse_gpt_attrs_string_guid_prefix() {
        assert_eq!(parse_gpt_attrs_string(Some("GUID:5")), 1u64 << 5);
    }

    #[test]
    fn test_parse_gpt_attrs_string_mixed() {
        let result = parse_gpt_attrs_string(Some("RequiredPartition,3,GUID:5"));
        assert_eq!(
            result,
            SD_GPT_FLAG_REQUIRED_PARTITION | (1u64 << 3) | (1u64 << 5)
        );
    }

    #[test]
    fn test_parse_gpt_attrs_string_unknown_ignored() {
        // Unknown non-numeric flags are silently ignored.
        assert_eq!(parse_gpt_attrs_string(Some("UnknownFlag")), 0);
    }

    #[test]
    fn test_parse_gpt_attrs_string_bit_above_63_ignored() {
        // Bit 64 and above are silently ignored (GPT flags are 64-bit).
        assert_eq!(parse_gpt_attrs_string(Some("64")), 0);
        assert_eq!(parse_gpt_attrs_string(Some("100")), 0);
    }

    // ── Attribute flags serialization ────────────────────────────────────

    #[test]
    fn test_flags_to_gpt_attrs_string_zero() {
        assert_eq!(flags_to_gpt_attrs_string(0), "");
    }

    #[test]
    fn test_flags_to_gpt_attrs_string_single_bit() {
        assert_eq!(flags_to_gpt_attrs_string(1u64 << 3), "3");
    }

    #[test]
    fn test_flags_to_gpt_attrs_string_multiple_bits() {
        let result =
            flags_to_gpt_attrs_string(SD_GPT_FLAG_REQUIRED_PARTITION | (1u64 << 3) | (1u64 << 5));
        // Bits 0, 3, 5 → "0,3,5"
        assert_eq!(result, "0,3,5");
    }

    #[test]
    fn test_flags_roundtrip() {
        let original = SD_GPT_FLAG_REQUIRED_PARTITION
            | SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL
            | SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE
            | (1u64 << 10)
            | (1u64 << 42);
        let serialized = flags_to_gpt_attrs_string(original);
        let reparsed = parse_gpt_attrs_string(Some(&serialized));
        assert_eq!(reparsed, original);
    }

    // ── c_str_to_option ──────────────────────────────────────────────────

    #[test]
    fn test_c_str_to_option_null() {
        // SAFETY: null is explicitly accepted.
        assert_eq!(unsafe { c_str_to_option(std::ptr::null()) }, None);
    }

    #[test]
    fn test_c_str_to_option_valid() {
        let s = CString::new("hello").unwrap();
        // SAFETY: `s` is a live NUL-terminated CString.
        assert_eq!(
            unsafe { c_str_to_option(s.as_ptr()) },
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_c_str_to_option_empty() {
        let s = CString::new("").unwrap();
        // SAFETY: `s` is a live NUL-terminated CString.
        assert_eq!(unsafe { c_str_to_option(s.as_ptr()) }, None);
    }

    // ── Dlopen state ─────────────────────────────────────────────────────

    #[test]
    fn test_have_fdisk_initial_false() {
        // On platforms without libfdisk or before loading, this is false.
        // We don't call dlopen_libfdisk() in tests to avoid side effects.
        if !cfg!(target_os = "linux") {
            assert!(!have_fdisk());
        }
    }

    // ── Error display ────────────────────────────────────────────────────

    #[test]
    fn test_fdisk_error_display() {
        assert!(!FdiskError::Unsupported.to_string().is_empty());
        assert!(!FdiskError::DlopenFailed("test".into())
            .to_string()
            .is_empty());
        assert!(!FdiskError::SymbolNotFound("sym".into())
            .to_string()
            .is_empty());
        assert!(!FdiskError::NotFound.to_string().is_empty());
        assert!(!FdiskError::ParseError("err".into()).to_string().is_empty());
        assert!(!FdiskError::InvalidArgument("bad".into())
            .to_string()
            .is_empty());
    }
}
