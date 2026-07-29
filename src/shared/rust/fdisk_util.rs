// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/fdisk-util.c, src/shared/fdisk-util.h
// PORT-GAP: Stateful `libfdisk` context/partition operations still execute
// through the C implementation. This module owns only the safe value parsing,
// attribute serialization, and availability boundary until those opaque C
// types have a complete audited Rust ownership model.
//
// libfdisk partition-table value utilities and availability boundary. Provides
// UUID/type extraction and GPT attribute flags parsing/serialization without
// exposing raw libfdisk pointers to safe Rust.

use std::ffi::CStr;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use systemd_libsystemd_rs::sd_id128_strings::sd_id128_from_string;

// SAFETY: Exact fdisk-util.h declaration. `dlopen_fdisk()` mutates C's
// process-global loader and symbol state, so the call below is serialized by
// `FDISK_LOAD_LOCK`; C retains all loaded-library and resolved-symbol state.
unsafe extern "C" {
    #[link_name = "dlopen_fdisk"]
    fn c_dlopen_fdisk(log_level: libc::c_int) -> libc::c_int;
}

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

// ── Dlopen state ────────────────────────────────────────────────────────────

/// Global flag: has `dlopen_libfdisk()` been called and completed successfully?
static FDISK_LOADED: AtomicBool = AtomicBool::new(false);

/// Serialize Rust calls into C's mutable process-global loader state.
///
/// C remains the single source of truth for its handle and all resolved
/// symbols. The Rust flag below is only a fast-path observation for callers of
/// this Rust facade.
static FDISK_LOAD_LOCK: Mutex<()> = Mutex::new(());

/// Attempt to dynamically load libfdisk through C's authoritative loader.
///
/// This convenience form uses C's normal debug-level diagnostics. Call
/// [`dlopen_libfdisk_full`] when the enclosing operation needs a different
/// diagnostic priority.
pub fn dlopen_libfdisk() -> Result<(), FdiskError> {
    dlopen_libfdisk_full(libc::LOG_DEBUG)
}

/// Attempt to dynamically load libfdisk through C's authoritative loader.
///
/// This retains C's exact `HAVE_LIBFDISK`, `dlopen_safe()`, logging, complete
/// symbol-list, and process-lifetime ownership policy. Idempotent successes
/// return `Ok(())`; failures are not cached, so callers may retry.
pub fn dlopen_libfdisk_full(log_level: libc::c_int) -> Result<(), FdiskError> {
    if FDISK_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let _lock = FDISK_LOAD_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if FDISK_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    // SAFETY: the declaration is exact, the lock serializes Rust callers that
    // could otherwise mutate C's `fdisk_dl`/`sym_fdisk_*` globals together,
    // and C retains every pointer it publishes beyond this call.
    let result = unsafe { c_dlopen_fdisk(log_level) };
    if result < 0 {
        return Err(match result {
            x if x == -libc::EOPNOTSUPP => FdiskError::Unsupported,
            x if x == -libc::ELIBBAD => FdiskError::SymbolNotFound(
                "C loader rejected the required libfdisk ABI".to_string(),
            ),
            x => {
                let errno = x.checked_neg().unwrap_or(libc::EIO);
                FdiskError::DlopenFailed(format!(
                    "C dlopen_fdisk() failed with errno {}: {}",
                    errno,
                    std::io::Error::from_raw_os_error(errno),
                ))
            }
        });
    }

    FDISK_LOADED.store(true, Ordering::Release);
    Ok(())
}

/// Returns `true` if libfdisk was successfully loaded.
pub fn have_fdisk() -> bool {
    FDISK_LOADED.load(Ordering::Acquire)
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
    // Share the port's strict id128 parser so misplaced dashes and whitespace
    // stay invalid exactly as they are for C's `sd_id128_from_string()`.
    sd_id128_from_string(s)
        .map(|id| id.0)
        .map_err(|_| FdiskError::ParseError("not a valid sd_id128 string".to_string()))
}

/// Get the partition UUID from a UUID string.
///
/// This is the pure-Rust equivalent of `fdisk_partition_get_uuid_as_id128()`.
/// Returns `Err(FdiskError::NotFound)` for a missing UUID and rejects an empty
/// string as C's `sd_id128_from_string()` does.
pub fn fdisk_partition_get_uuid(uuid_str: Option<&str>) -> Result<[u8; 16], FdiskError> {
    match uuid_str {
        None => Err(FdiskError::NotFound),
        Some(s) => parse_partition_uuid(s),
    }
}

/// Get the partition type UUID from a type string.
///
/// This is the pure-Rust equivalent of `fdisk_partition_get_type_as_id128()`.
/// Returns `Err(FdiskError::NotFound)` for a missing type and rejects an empty
/// string as C's `sd_id128_from_string()` does.
pub fn fdisk_partition_get_type(type_str: Option<&str>) -> Result<[u8; 16], FdiskError> {
    match type_str {
        None => Err(FdiskError::NotFound),
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
    // SAFETY: the caller guarantees that this non-null pointer remains
    // readable through its terminating NUL for the duration of this copy.
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    if s.is_empty() { None } else { Some(s) }
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
        assert!(parse_partition_uuid("c5a364bd4-12a-4bdf-a66d-098e840a4e1c").is_err());
        assert!(parse_partition_uuid(" c5a364bd-412a-4bdf-a66d-098e840a4e1c").is_err());
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
    fn test_fdisk_partition_get_uuid_empty_is_invalid() {
        assert!(matches!(
            fdisk_partition_get_uuid(Some("")),
            Err(FdiskError::ParseError(_))
        ));
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
        assert!(
            !FdiskError::DlopenFailed("test".into())
                .to_string()
                .is_empty()
        );
        assert!(
            !FdiskError::SymbolNotFound("sym".into())
                .to_string()
                .is_empty()
        );
        assert!(!FdiskError::NotFound.to_string().is_empty());
        assert!(!FdiskError::ParseError("err".into()).to_string().is_empty());
        assert!(
            !FdiskError::InvalidArgument("bad".into())
                .to_string()
                .is_empty()
        );
    }
}
