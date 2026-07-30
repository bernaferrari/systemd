// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/coredump-util.c, src/shared/coredump-util.h
//
// Coredump utilities — coredump filter parsing, /proc/self/coredump_filter
// manipulation, ELF auxiliary vector parsing, and core dump disabling.

use crate::ffi::*;
use std::fmt;
use std::io;

// ── Constants ─────────────────────────────────────────────────────────────

/// Default coredump filter mask: private-anonymous, shared-anonymous,
/// elf-headers, private-huge.
pub const COREDUMP_FILTER_MASK_DEFAULT: u64 = (1 << CoredumpFilter::PrivateAnonymous as u8)
    | (1 << CoredumpFilter::SharedAnonymous as u8)
    | (1 << CoredumpFilter::ElfHeaders as u8)
    | (1 << CoredumpFilter::PrivateHuge as u8);

/// All coredump filter bits.  The kernel rejects `u64::MAX` (ERANGE), so we
/// cap at `u32::MAX` to leave room for future flags.
pub const COREDUMP_FILTER_MASK_ALL: u64 = u32::MAX as u64;

/// Path written by [`set_coredump_filter`].
const COREDUMP_FILTER_PATH: &str = "/proc/self/coredump_filter";

/// Path written by [`disable_coredumps`].
const CORE_PATTERN_PATH: &str = "/proc/sys/kernel/core_pattern";

// ── ELF auxiliary vector constants ───────────────────────────────────────

const AT_NULL: u64 = 0;
const AT_SECURE: u64 = 23;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

// ── Enums ────────────────────────────────────────────────────────────────

/// Coredump filter flags corresponding to the kernel's `RLIMIT_CORE` filter
/// bits (see `Documentation/filesystems/proc.rst`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CoredumpFilter {
    PrivateAnonymous = 0,
    SharedAnonymous = 1,
    PrivateFileBacked = 2,
    SharedFileBacked = 3,
    ElfHeaders = 4,
    PrivateHuge = 5,
    SharedHuge = 6,
    PrivateDax = 7,
    SharedDax = 8,
}

impl CoredumpFilter {
    /// All variants in declaration order.
    pub const ALL: [CoredumpFilter; 9] = [
        Self::PrivateAnonymous,
        Self::SharedAnonymous,
        Self::PrivateFileBacked,
        Self::SharedFileBacked,
        Self::ElfHeaders,
        Self::PrivateHuge,
        Self::SharedHuge,
        Self::PrivateDax,
        Self::SharedDax,
    ];

    /// Total number of filter variants.
    pub const COUNT: usize = Self::ALL.len();

    /// Bit position in the filter mask.
    pub const fn bit(self) -> u8 {
        self as u8
    }
}

// ── String table (from_name / to_name) ───────────────────────────────────

/// Human-readable name for each [`CoredumpFilter`] variant.
impl CoredumpFilter {
    /// Resolve a hyphenated name to a [`CoredumpFilter`] variant.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "private-anonymous" => Some(Self::PrivateAnonymous),
            "shared-anonymous" => Some(Self::SharedAnonymous),
            "private-file-backed" => Some(Self::PrivateFileBacked),
            "shared-file-backed" => Some(Self::SharedFileBacked),
            "elf-headers" => Some(Self::ElfHeaders),
            "private-huge" => Some(Self::PrivateHuge),
            "shared-huge" => Some(Self::SharedHuge),
            "private-dax" => Some(Self::PrivateDax),
            "shared-dax" => Some(Self::SharedDax),
            _ => None,
        }
    }

    /// Canonical hyphenated name for this filter.
    pub const fn to_name(self) -> &'static str {
        match self {
            Self::PrivateAnonymous => "private-anonymous",
            Self::SharedAnonymous => "shared-anonymous",
            Self::PrivateFileBacked => "private-file-backed",
            Self::SharedFileBacked => "shared-file-backed",
            Self::ElfHeaders => "elf-headers",
            Self::PrivateHuge => "private-huge",
            Self::SharedHuge => "shared-huge",
            Self::PrivateDax => "private-dax",
            Self::SharedDax => "shared-dax",
        }
    }
}

impl fmt::Display for CoredumpFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

// ── SuidDumpMode ─────────────────────────────────────────────────────────

/// Mode argument for `PR_SET_DUMPABLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SuidDumpMode {
    Disable = 0,
    User = 1,
    Safe = 2,
}

impl SuidDumpMode {
    /// Convert a raw integer to [`SuidDumpMode`], returning `None` for
    /// out-of-range values.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Disable),
            1 => Some(Self::User),
            2 => Some(Self::Safe),
            _ => None,
        }
    }
}

impl fmt::Display for SuidDumpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Disable => "disable",
            Self::User => "user",
            Self::Safe => "safe",
        })
    }
}

// ── Error types ──────────────────────────────────────────────────────────

/// Error returned by [`coredump_filter_mask_from_string`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseCoredumpFilterError {
    /// An unrecognised token was encountered.
    UnknownToken(String),
    /// A hex/decimal literal could not be parsed.
    InvalidNumber(String),
}

impl fmt::Display for ParseCoredumpFilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownToken(t) => write!(f, "unknown coredump filter: {t}"),
            Self::InvalidNumber(t) => write!(f, "invalid number '{t}'"),
        }
    }
}

impl std::error::Error for ParseCoredumpFilterError {}

/// Error returned by [`parse_auxv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAuxvError {
    /// The data size is not a multiple of 2 × element size.
    IncompleteStructure(usize),
    /// `AT_NULL` terminator was not found.
    MissingTerminator,
    /// Unknown ELF class byte.
    UnknownElfClass(u8),
}

impl fmt::Display for ParseAuxvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteStructure(n) => {
                write!(f, "incomplete auxv structure ({n} bytes)")
            }
            Self::MissingTerminator => {
                f.write_str("AT_NULL terminator not found, cannot parse auxv structure")
            }
            Self::UnknownElfClass(c) => write!(f, "unknown ELF class {c}"),
        }
    }
}

impl std::error::Error for ParseAuxvError {}

// ── Auxv parsed result ───────────────────────────────────────────────────

/// Parsed fields from the ELF auxiliary vector.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuxvInfo {
    /// `AT_SECURE`: whether the process is in secure-execution mode.
    pub at_secure: bool,
    /// `AT_UID`: real user ID.
    pub uid: u32,
    /// `AT_EUID`: effective user ID.
    pub euid: u32,
    /// `AT_GID`: real group ID.
    pub gid: u32,
    /// `AT_EGID`: effective group ID.
    pub egid: u32,
}

// ── set_dumpable ─────────────────────────────────────────────────────────

/// Set the dumpable flag for the current process via `prctl(PR_SET_DUMPABLE)`.
///
/// # Errors
///
/// Returns an [`io::Error`] if the syscall fails. On non-Linux platforms this
/// always returns [`io::ErrorKind::Unsupported`].
pub fn set_dumpable(mode: SuidDumpMode) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, mode) is a well-defined kernel
        // interface; we cast mode to c_long as the kernel expects.
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, mode as libc::c_long, 0, 0, 0) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "PR_SET_DUMPABLE is only available on Linux",
        ))
    }
}

// ── coredump_filter_mask_from_string ─────────────────────────────────────

/// Parse a whitespace-separated list of coredump filter tokens into a mask.
///
/// Accepted tokens:
/// - Named filters: `private-anonymous`, `shared-anonymous`, …
/// - `"default"` — expands to [`COREDUMP_FILTER_MASK_DEFAULT`].
/// - `"all"` — expands to [`COREDUMP_FILTER_MASK_ALL`] (short-circuits).
/// - Hex literal: `0x33` or bare hex digits.
/// - Decimal literal: e.g. `51`.
///
/// # Errors
///
/// Returns [`ParseCoredumpFilterError`] on the first unrecognised token.
pub fn coredump_filter_mask_from_string(s: &str) -> Result<u64, ParseCoredumpFilterError> {
    let mut mask: u64 = 0;

    for word in s.split_whitespace() {
        if word == "default" {
            mask |= COREDUMP_FILTER_MASK_DEFAULT;
            continue;
        }
        if word == "all" {
            mask = COREDUMP_FILTER_MASK_ALL;
            continue;
        }
        if let Some(filter) = CoredumpFilter::from_name(word) {
            mask |= 1u64 << filter.bit();
            continue;
        }
        // Try hex first (with optional 0x prefix), then decimal.
        if let Some(hex_str) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
            match u64::from_str_radix(hex_str, 16) {
                Ok(val) => {
                    mask |= val;
                    continue;
                }
                Err(_) => {
                    return Err(ParseCoredumpFilterError::InvalidNumber(word.to_owned()));
                }
            }
        }
        if let Ok(val) = u64::from_str_radix(word, 16) {
            mask |= val;
            continue;
        }
        if let Ok(val) = word.parse::<u64>() {
            mask |= val;
            continue;
        }
        return Err(ParseCoredumpFilterError::UnknownToken(word.to_owned()));
    }

    Ok(mask)
}

// ── parse_auxv (internal) ───────────────────────────────────────────────

/// Parse an ELF auxiliary vector of 32-bit entries.
fn parse_auxv_32(data: &[u8], info: &mut AuxvInfo) -> Result<(), ParseAuxvError> {
    parse_auxv_impl::<u32>(data, info)
}

/// Parse an ELF auxiliary vector of 64-bit entries.
fn parse_auxv_64(data: &[u8], info: &mut AuxvInfo) -> Result<(), ParseAuxvError> {
    parse_auxv_impl::<u64>(data, info)
}

/// Generic auxv parser for a given word size.
fn parse_auxv_impl<T: AuxvWord>(data: &[u8], info: &mut AuxvInfo) -> Result<(), ParseAuxvError> {
    let elem_size = std::mem::size_of::<T>();

    if !data.len().is_multiple_of(2 * elem_size) {
        return Err(ParseAuxvError::IncompleteStructure(data.len()));
    }

    let words = data.len() / elem_size;

    for i in (0..words).step_by(2) {
        let key = T::read_unaligned(data, i * elem_size);
        let val = T::read_unaligned(data, (i + 1) * elem_size);

        match key.as_u64() {
            AT_NULL => {
                if val.as_u64() != 0 {
                    return Err(ParseAuxvError::MissingTerminator);
                }
                return Ok(());
            }
            AT_SECURE => info.at_secure = val.as_u64() != 0,
            AT_UID => info.uid = val.as_u64() as u32,
            AT_EUID => info.euid = val.as_u64() as u32,
            AT_GID => info.gid = val.as_u64() as u32,
            AT_EGID => info.egid = val.as_u64() as u32,
            _ => {} // skip unknown entries
        }
    }

    Err(ParseAuxvError::MissingTerminator)
}

/// Trait for reading unaligned words from a byte slice.
trait AuxvWord: Copy + Sized {
    fn read_unaligned(data: &[u8], offset: usize) -> Self;
    fn as_u64(self) -> u64;
}

impl AuxvWord for u32 {
    fn read_unaligned(data: &[u8], offset: usize) -> Self {
        u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
    }
    fn as_u64(self) -> u64 {
        self as u64
    }
}

impl AuxvWord for u64 {
    fn read_unaligned(data: &[u8], offset: usize) -> Self {
        u64::from_ne_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
    }
    fn as_u64(self) -> u64 {
        self
    }
}

// ── parse_auxv (public) ─────────────────────────────────────────────────

/// Parse an ELF auxiliary vector and extract security/identity fields.
///
/// `elf_class` must be [`ELFCLASS32`] (1) or [`ELFCLASS64`] (2).
///
/// # Errors
///
/// Returns [`ParseAuxvError`] for malformed input.
pub fn parse_auxv(elf_class: u8, data: &[u8]) -> Result<AuxvInfo, ParseAuxvError> {
    let mut info = AuxvInfo::default();

    match elf_class {
        ELFCLASS64 => parse_auxv_64(data, &mut info),
        ELFCLASS32 => parse_auxv_32(data, &mut info),
        c => return Err(ParseAuxvError::UnknownElfClass(c)),
    }?;

    Ok(info)
}

// ── set_coredump_filter ──────────────────────────────────────────────────

/// Write a new value to `/proc/self/coredump_filter`.
///
/// The value is written as a hexadecimal string (e.g. `"0x33"`).
///
/// # Errors
///
/// Returns [`io::Error`] if the file cannot be opened or written.
pub fn set_coredump_filter(value: u64) -> io::Result<()> {
    let content = format!("0x{:x}", value);
    std::fs::write(COREDUMP_FILTER_PATH, content)
}

// ── disable_coredumps ────────────────────────────────────────────────────

/// Disable core dumps by writing `|/bin/false` to `/proc/sys/kernel/core_pattern`.
///
/// This is a no-op inside containers (detection is best-effort on non-Linux
/// platforms and always skips).
pub fn disable_coredumps() {
    // Best-effort container detection.  On non-Linux we conservatively assume
    // we might be in a container and skip.
    #[cfg(target_os = "linux")]
    if detect_container() {
        return;
    }

    #[cfg(not(target_os = "linux"))]
    return;

    if let Err(e) = std::fs::write(CORE_PATTERN_PATH, "|/bin/false") {
        // C records this at debug level. This crate has no logging facade, so
        // keep the failure non-propagating without introducing a user-visible
        // stderr side effect.
        let _ = e;
    }
}

/// Returns `true` if the current process appears to be running inside a
/// container.
#[cfg(target_os = "linux")]
fn detect_container() -> bool {
    // systemd's detect_container() checks many heuristics.  We use a
    // simplified version: if /.dockerenv exists, we're likely in Docker.
    std::path::Path::new("/.dockerenv").exists()
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CoredumpFilter round-trip ─────────────────────────────────────

    #[test]
    fn test_coredump_filter_from_name_all_variants() {
        for v in CoredumpFilter::ALL {
            assert_eq!(CoredumpFilter::from_name(v.to_name()), Some(v));
        }
    }

    #[test]
    fn test_coredump_filter_from_name_unknown() {
        assert_eq!(CoredumpFilter::from_name("bogus"), None);
        assert_eq!(CoredumpFilter::from_name(""), None);
    }

    #[test]
    fn test_coredump_filter_display() {
        assert_eq!(
            CoredumpFilter::PrivateAnonymous.to_string(),
            "private-anonymous"
        );
        assert_eq!(CoredumpFilter::SharedDax.to_string(), "shared-dax");
    }

    #[test]
    fn test_coredump_filter_count() {
        assert_eq!(CoredumpFilter::COUNT, 9);
        assert_eq!(CoredumpFilter::ALL.len(), 9);
    }

    // ── Default / All masks ───────────────────────────────────────────

    #[test]
    fn test_default_mask_bits() {
        let d = COREDUMP_FILTER_MASK_DEFAULT;
        assert_ne!(d & (1 << CoredumpFilter::PrivateAnonymous as u8), 0);
        assert_ne!(d & (1 << CoredumpFilter::SharedAnonymous as u8), 0);
        assert_ne!(d & (1 << CoredumpFilter::ElfHeaders as u8), 0);
        assert_ne!(d & (1 << CoredumpFilter::PrivateHuge as u8), 0);
        // Should NOT include shared-file-backed.
        assert_eq!(d & (1 << CoredumpFilter::SharedFileBacked as u8), 0);
    }

    #[test]
    fn test_all_mask_is_u32_max() {
        assert_eq!(COREDUMP_FILTER_MASK_ALL, u32::MAX as u64);
    }

    // ── coredump_filter_mask_from_string ──────────────────────────────

    #[test]
    fn test_mask_from_string_default() {
        assert_eq!(
            coredump_filter_mask_from_string("default").unwrap(),
            COREDUMP_FILTER_MASK_DEFAULT,
        );
    }

    #[test]
    fn test_mask_from_string_all() {
        assert_eq!(
            coredump_filter_mask_from_string("all").unwrap(),
            COREDUMP_FILTER_MASK_ALL,
        );
    }

    #[test]
    fn test_mask_from_string_single_name() {
        let m = coredump_filter_mask_from_string("private-anonymous").unwrap();
        assert_eq!(m, 1u64);
    }

    #[test]
    fn test_mask_from_string_multiple_names() {
        let m = coredump_filter_mask_from_string("private-anonymous shared-anonymous elf-headers")
            .unwrap();
        assert_eq!(
            m,
            (1 << CoredumpFilter::PrivateAnonymous as u8)
                | (1 << CoredumpFilter::SharedAnonymous as u8)
                | (1 << CoredumpFilter::ElfHeaders as u8),
        );
    }

    #[test]
    fn test_mask_from_string_hex_0x_prefix() {
        let m = coredump_filter_mask_from_string("0x33").unwrap();
        assert_eq!(m, 0x33);
    }

    #[test]
    fn test_mask_from_string_hex_uppercase() {
        let m = coredump_filter_mask_from_string("0xAB").unwrap();
        assert_eq!(m, 0xAB);
    }

    #[test]
    fn test_mask_from_string_mixed() {
        // Named + hex
        let m = coredump_filter_mask_from_string("default 0x10").unwrap();
        assert_eq!(m, COREDUMP_FILTER_MASK_DEFAULT | 0x10);
    }

    #[test]
    fn test_mask_from_string_unknown_token() {
        let err = coredump_filter_mask_from_string("private-anonymous bogus").unwrap_err();
        assert_eq!(err, ParseCoredumpFilterError::UnknownToken("bogus".into()));
    }

    #[test]
    fn test_mask_from_string_empty() {
        assert_eq!(coredump_filter_mask_from_string("").unwrap(), 0);
        assert_eq!(coredump_filter_mask_from_string("   ").unwrap(), 0);
    }

    // ── SuidDumpMode ──────────────────────────────────────────────────

    #[test]
    fn test_suid_dump_mode_from_i32() {
        assert_eq!(SuidDumpMode::from_i32(0), Some(SuidDumpMode::Disable));
        assert_eq!(SuidDumpMode::from_i32(1), Some(SuidDumpMode::User));
        assert_eq!(SuidDumpMode::from_i32(2), Some(SuidDumpMode::Safe));
        assert_eq!(SuidDumpMode::from_i32(3), None);
        assert_eq!(SuidDumpMode::from_i32(-1), None);
    }

    #[test]
    fn test_suid_dump_mode_display() {
        assert_eq!(SuidDumpMode::Disable.to_string(), "disable");
        assert_eq!(SuidDumpMode::User.to_string(), "user");
        assert_eq!(SuidDumpMode::Safe.to_string(), "safe");
    }

    // ── parse_auxv ────────────────────────────────────────────────────

    /// Helper: build a 64-bit auxv byte vector from (key, val) pairs
    /// followed by an implicit AT_NULL terminator.
    fn make_auxv64(pairs: &[(u64, u64)]) -> Vec<u8> {
        let mut data = Vec::new();
        for &(k, v) in pairs {
            data.extend_from_slice(&k.to_ne_bytes());
            data.extend_from_slice(&v.to_ne_bytes());
        }
        // AT_NULL terminator
        data.extend_from_slice(&0u64.to_ne_bytes());
        data.extend_from_slice(&0u64.to_ne_bytes());
        data
    }

    #[test]
    fn test_parse_auxv64_empty() {
        let data = make_auxv64(&[]);
        let info = parse_auxv(ELFCLASS64, &data).unwrap();
        assert_eq!(info, AuxvInfo::default());
    }

    #[test]
    fn test_parse_auxv64_uids_gids() {
        let data = make_auxv64(&[
            (AT_UID, 1000),
            (AT_EUID, 1001),
            (AT_GID, 100),
            (AT_EGID, 101),
        ]);
        let info = parse_auxv(ELFCLASS64, &data).unwrap();
        assert_eq!(info.uid, 1000);
        assert_eq!(info.euid, 1001);
        assert_eq!(info.gid, 100);
        assert_eq!(info.egid, 101);
        assert!(!info.at_secure);
    }

    #[test]
    fn test_parse_auxv64_at_secure() {
        let data = make_auxv64(&[(AT_SECURE, 1)]);
        let info = parse_auxv(ELFCLASS64, &data).unwrap();
        assert!(info.at_secure);
    }

    #[test]
    fn test_parse_auxv32() {
        let mut data = Vec::new();
        data.extend_from_slice(&(AT_UID as u32).to_ne_bytes());
        data.extend_from_slice(&(42u32).to_ne_bytes());
        data.extend_from_slice(&(AT_EUID as u32).to_ne_bytes());
        data.extend_from_slice(&(43u32).to_ne_bytes());
        // AT_NULL
        data.extend_from_slice(&0u32.to_ne_bytes());
        data.extend_from_slice(&0u32.to_ne_bytes());

        let info = parse_auxv(ELFCLASS32, &data).unwrap();
        assert_eq!(info.uid, 42);
        assert_eq!(info.euid, 43);
    }

    #[test]
    fn test_parse_auxv_incomplete() {
        // 5 bytes — not a multiple of 2*8.
        let err = parse_auxv(ELFCLASS64, &[0u8; 5]).unwrap_err();
        assert!(matches!(err, ParseAuxvError::IncompleteStructure(5)));
    }

    #[test]
    fn test_parse_auxv_missing_terminator() {
        // Two words but no AT_NULL.
        let data = {
            let mut d = Vec::new();
            d.extend_from_slice(&(AT_UID as u64).to_ne_bytes());
            d.extend_from_slice(&1000u64.to_ne_bytes());
            d
        };
        let err = parse_auxv(ELFCLASS64, &data).unwrap_err();
        assert!(matches!(err, ParseAuxvError::MissingTerminator));
    }

    #[test]
    fn test_parse_auxv_null_with_nonzero_val() {
        let mut data = Vec::new();
        data.extend_from_slice(&(AT_NULL as u64).to_ne_bytes());
        data.extend_from_slice(&1u64.to_ne_bytes()); // non-zero val → error
        let err = parse_auxv(ELFCLASS64, &data).unwrap_err();
        assert!(matches!(err, ParseAuxvError::MissingTerminator));
    }

    #[test]
    fn test_parse_auxv_unknown_elf_class() {
        let err = parse_auxv(99, &[]).unwrap_err();
        assert!(matches!(err, ParseAuxvError::UnknownElfClass(99)));
    }

    // ── Error display ─────────────────────────────────────────────────

    #[test]
    fn test_parse_error_display() {
        let e = ParseCoredumpFilterError::UnknownToken("foo".into());
        assert_eq!(format!("{e}"), "unknown coredump filter: foo");

        let e = ParseAuxvError::MissingTerminator;
        assert!(format!("{e}").contains("AT_NULL"));
    }
}
