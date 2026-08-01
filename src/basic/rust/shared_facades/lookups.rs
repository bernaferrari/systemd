// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/condition.c,src/shared/condition.h,src/shared/resolve-util.c,
//           src/shared/resolve-util.h,src/shared/netif-util.c,src/shared/netif-util.h,
//           src/basic/compress.c,src/basic/compress.h,src/basic/socket-util.c,
//           src/basic/socket-util.h,src/shared/output-mode.c,src/shared/output-mode.h

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::{Errno, malloc};
use std::ffi::{CStr, c_char, c_void};
use std::ptr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    Invalid,
    OutOfRange,
}

impl LookupError {
    pub const fn errno(self) -> Errno {
        match self {
            Self::Invalid => Errno::EINVAL,
            Self::OutOfRange => Errno::ERANGE,
        }
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionType {
    Architecture = 0,
    Firmware = 1,
    Virtualization = 2,
    Host = 3,
    Fraction = 4,
    KernelCommandLine = 5,
    Version = 6,
    Credential = 7,
    Security = 8,
    Capability = 9,
    AcPower = 10,
    Memory = 11,
    Cpus = 12,
    Environment = 13,
    CpuFeature = 14,
    OsRelease = 15,
    MachineTag = 16,
    MemoryPressure = 17,
    CpuPressure = 18,
    IoPressure = 19,
    NeedsUpdate = 20,
    FirstBoot = 21,
    PathExists = 22,
    PathExistsGlob = 23,
    PathIsDirectory = 24,
    PathIsSymbolicLink = 25,
    PathIsMountPoint = 26,
    PathIsReadWrite = 27,
    PathIsEncrypted = 28,
    PathIsSocket = 29,
    DirectoryNotEmpty = 30,
    FileNotEmpty = 31,
    FileIsExecutable = 32,
    User = 33,
    Group = 34,
    ControlGroupController = 35,
    KernelModuleLoaded = 36,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None = 0,
    Xz = 1,
    Lz4 = 2,
    Zstd = 3,
    Gzip = 4,
    Bzip2 = 5,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Short = 0,
    ShortFull = 1,
    ShortIso = 2,
    ShortIsoPrecise = 3,
    ShortPrecise = 4,
    ShortMonotonic = 5,
    ShortDelta = 6,
    ShortUnix = 7,
    Verbose = 8,
    Export = 9,
    Json = 10,
    JsonPretty = 11,
    JsonSse = 12,
    JsonSeq = 13,
    Cat = 14,
    WithUnit = 15,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveSupport {
    No = 0,
    Resolve = 1,
    Yes = 2,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecMode {
    No = 0,
    AllowDowngrade = 1,
    Yes = 2,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOverTlsMode {
    No = 0,
    Opportunistic = 1,
    Yes = 2,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCacheMode {
    No = 0,
    Yes = 1,
    NoNegative = 2,
}

pub const SD_JSON_FORMAT_NEWLINE: u32 = 1 << 1;
pub const SD_JSON_FORMAT_PRETTY: u32 = 1 << 2;
pub const SD_JSON_FORMAT_SSE: u32 = 1 << 7;
pub const SD_JSON_FORMAT_SEQ: u32 = 1 << 8;

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
pub const INADDR_DNS_STUB: u32 = 0x7f000035;
pub const INADDR_DNS_PROXY_STUB: u32 = 0x7f000036;

pub const IF_OPER_UNKNOWN: u8 = 0;
pub const IF_OPER_UP: u8 = 6;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_LOWER_UP: u32 = 0x10000;
pub const IFF_DORMANT: u32 = 0x20000;

/// This is the only data authority for both the ergonomic API and the C ABI.
/// Every entry is a static, exactly-one-NUL C string.
const CONDITION_TYPE_TABLE: [&[u8]; 37] = [
    b"ConditionArchitecture\0",
    b"ConditionFirmware\0",
    b"ConditionVirtualization\0",
    b"ConditionHost\0",
    b"ConditionFraction\0",
    b"ConditionKernelCommandLine\0",
    b"ConditionVersion\0",
    b"ConditionCredential\0",
    b"ConditionSecurity\0",
    b"ConditionCapability\0",
    b"ConditionACPower\0",
    b"ConditionMemory\0",
    b"ConditionCPUs\0",
    b"ConditionEnvironment\0",
    b"ConditionCPUFeature\0",
    b"ConditionOSRelease\0",
    b"ConditionMachineTag\0",
    b"ConditionMemoryPressure\0",
    b"ConditionCPUPressure\0",
    b"ConditionIOPressure\0",
    b"ConditionNeedsUpdate\0",
    b"ConditionFirstBoot\0",
    b"ConditionPathExists\0",
    b"ConditionPathExistsGlob\0",
    b"ConditionPathIsDirectory\0",
    b"ConditionPathIsSymbolicLink\0",
    b"ConditionPathIsMountPoint\0",
    b"ConditionPathIsReadWrite\0",
    b"ConditionPathIsEncrypted\0",
    b"ConditionPathIsSocket\0",
    b"ConditionDirectoryNotEmpty\0",
    b"ConditionFileNotEmpty\0",
    b"ConditionFileIsExecutable\0",
    b"ConditionUser\0",
    b"ConditionGroup\0",
    b"ConditionControlGroupController\0",
    b"ConditionKernelModuleLoaded\0",
];

const ASSERT_TYPE_TABLE: [&[u8]; 37] = [
    b"AssertArchitecture\0",
    b"AssertFirmware\0",
    b"AssertVirtualization\0",
    b"AssertHost\0",
    b"AssertFraction\0",
    b"AssertKernelCommandLine\0",
    b"AssertVersion\0",
    b"AssertCredential\0",
    b"AssertSecurity\0",
    b"AssertCapability\0",
    b"AssertACPower\0",
    b"AssertMemory\0",
    b"AssertCPUs\0",
    b"AssertEnvironment\0",
    b"AssertCPUFeature\0",
    b"AssertOSRelease\0",
    b"AssertMachineTag\0",
    b"AssertMemoryPressure\0",
    b"AssertCPUPressure\0",
    b"AssertIOPressure\0",
    b"AssertNeedsUpdate\0",
    b"AssertFirstBoot\0",
    b"AssertPathExists\0",
    b"AssertPathExistsGlob\0",
    b"AssertPathIsDirectory\0",
    b"AssertPathIsSymbolicLink\0",
    b"AssertPathIsMountPoint\0",
    b"AssertPathIsReadWrite\0",
    b"AssertPathIsEncrypted\0",
    b"AssertPathIsSocket\0",
    b"AssertDirectoryNotEmpty\0",
    b"AssertFileNotEmpty\0",
    b"AssertFileIsExecutable\0",
    b"AssertUser\0",
    b"AssertGroup\0",
    b"AssertControlGroupController\0",
    b"AssertKernelModuleLoaded\0",
];

/* Keep this in the exact order and spelling of compression_table in
 * src/basic/compress.c. In particular, "uncompressed" is a compatibility
 * spelling, whereas "NONE" belongs to compression_uppercase_table. */
const COMPRESSION_TABLE: [&[u8]; 6] = [
    b"uncompressed\0",
    b"xz\0",
    b"lz4\0",
    b"zstd\0",
    b"gzip\0",
    b"bzip2\0",
];

const SOCKET_ADDRESS_TYPE_TABLE: [Option<&[u8]>; 7] = [
    None,
    Some(b"Stream\0"),
    Some(b"Datagram\0"),
    Some(b"Raw\0"),
    Some(b"ReliableDatagram\0"),
    Some(b"SequentialPacket\0"),
    Some(b"DatagramCongestionControl\0"),
];

const NETLINK_FAMILY_TABLE: [Option<&[u8]>; 21] = [
    Some(b"route\0"),
    Some(b"firewall\0"),
    None,
    None,
    Some(b"inet-diag\0"),
    Some(b"nflog\0"),
    Some(b"xfrm\0"),
    Some(b"selinux\0"),
    Some(b"iscsi\0"),
    Some(b"audit\0"),
    Some(b"fib-lookup\0"),
    Some(b"connector\0"),
    Some(b"netfilter\0"),
    Some(b"ip6-fw\0"),
    Some(b"dnrtmsg\0"),
    Some(b"kobject-uevent\0"),
    Some(b"generic\0"),
    None,
    Some(b"scsitransport\0"),
    Some(b"ecryptfs\0"),
    Some(b"rdma\0"),
];

const RESOLVE_SUPPORT_TABLE: [&[u8]; 3] = [b"no\0", b"resolve\0", b"yes\0"];
const DNSSEC_MODE_TABLE: [&[u8]; 3] = [b"no\0", b"allow-downgrade\0", b"yes\0"];
const DNS_OVER_TLS_MODE_TABLE: [&[u8]; 3] = [b"no\0", b"opportunistic\0", b"yes\0"];
const DNS_CACHE_MODE_TABLE: [&[u8]; 3] = [b"no\0", b"yes\0", b"no-negative\0"];

fn static_text(entry: &[u8]) -> &str {
    // All table literals above are audited ASCII, NUL-terminated C strings.
    std::str::from_utf8(&entry[..entry.len() - 1])
        .expect("shared string-table entries must be valid UTF-8")
}

fn parse_enum_name(table: &[&[u8]], name: &str) -> Result<i32, LookupError> {
    table
        .iter()
        .position(|entry| static_text(entry) == name)
        .map(|i| i as i32)
        .ok_or(LookupError::Invalid)
}

fn parse_enum_name_with_boolean(
    table: &[&[u8]],
    yes_value: i32,
    name: &str,
) -> Result<i32, LookupError> {
    if ["0", "no", "n", "false", "f", "off"]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
    {
        Ok(0)
    } else if ["1", "yes", "y", "true", "t", "on"]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
    {
        Ok(yes_value)
    } else {
        parse_enum_name(table, name)
    }
}

fn table_string(table: &[&'static [u8]], value: i32) -> Option<&'static str> {
    if value < 0 {
        return None;
    }
    table.get(value as usize).copied().map(static_text)
}

/// Safe counterpart of the `safe_atou(..., base=0)` fallback used by the C
/// string-table macros. It accepts leading C whitespace and the C/Python
/// `0x`, `0o`, and `0b` spellings, but never trailing bytes.
fn parse_fallback_u32(input: &str) -> Result<u32, LookupError> {
    let mut bytes = input.as_bytes();
    while bytes
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
    {
        bytes = &bytes[1..];
    }

    let negative = bytes.first() == Some(&b'-');
    let had_sign = matches!(bytes.first(), Some(&b'+') | Some(&b'-'));
    if had_sign {
        bytes = &bytes[1..];
    }
    if bytes.is_empty() {
        return Err(LookupError::Invalid);
    }

    let (base, digits) = if bytes.len() >= 2 && bytes[0] == b'0' {
        match bytes[1] {
            b'x' | b'X' => (16, &bytes[2..]),
            b'o' | b'O' if !had_sign => (8, &bytes[2..]),
            b'b' | b'B' if !had_sign => (2, &bytes[2..]),
            _ if bytes.len() > 1 => (8, bytes),
            _ => (10, bytes),
        }
    } else {
        (10, bytes)
    };
    if digits.is_empty() || !digits.is_ascii() {
        return Err(LookupError::Invalid);
    }

    let digits = std::str::from_utf8(digits).map_err(|_| LookupError::Invalid)?;
    let value = u32::from_str_radix(digits, base).map_err(|_| LookupError::Invalid)?;
    if negative && value != 0 {
        return Err(LookupError::Invalid);
    }
    Ok(value)
}

pub fn condition_type_to_string(value: ConditionType) -> &'static str {
    static_text(CONDITION_TYPE_TABLE[value as usize])
}

pub fn condition_type_from_string(name: &str) -> Result<ConditionType, LookupError> {
    let value = if name == "ConditionKernelVersion" {
        ConditionType::Version as i32
    } else {
        parse_enum_name(&CONDITION_TYPE_TABLE, name)?
    };
    condition_type_from_i32(value)
}

pub fn condition_type_from_i32(value: i32) -> Result<ConditionType, LookupError> {
    match value {
        0 => Ok(ConditionType::Architecture),
        1 => Ok(ConditionType::Firmware),
        2 => Ok(ConditionType::Virtualization),
        3 => Ok(ConditionType::Host),
        4 => Ok(ConditionType::Fraction),
        5 => Ok(ConditionType::KernelCommandLine),
        6 => Ok(ConditionType::Version),
        7 => Ok(ConditionType::Credential),
        8 => Ok(ConditionType::Security),
        9 => Ok(ConditionType::Capability),
        10 => Ok(ConditionType::AcPower),
        11 => Ok(ConditionType::Memory),
        12 => Ok(ConditionType::Cpus),
        13 => Ok(ConditionType::Environment),
        14 => Ok(ConditionType::CpuFeature),
        15 => Ok(ConditionType::OsRelease),
        16 => Ok(ConditionType::MachineTag),
        17 => Ok(ConditionType::MemoryPressure),
        18 => Ok(ConditionType::CpuPressure),
        19 => Ok(ConditionType::IoPressure),
        20 => Ok(ConditionType::NeedsUpdate),
        21 => Ok(ConditionType::FirstBoot),
        22 => Ok(ConditionType::PathExists),
        23 => Ok(ConditionType::PathExistsGlob),
        24 => Ok(ConditionType::PathIsDirectory),
        25 => Ok(ConditionType::PathIsSymbolicLink),
        26 => Ok(ConditionType::PathIsMountPoint),
        27 => Ok(ConditionType::PathIsReadWrite),
        28 => Ok(ConditionType::PathIsEncrypted),
        29 => Ok(ConditionType::PathIsSocket),
        30 => Ok(ConditionType::DirectoryNotEmpty),
        31 => Ok(ConditionType::FileNotEmpty),
        32 => Ok(ConditionType::FileIsExecutable),
        33 => Ok(ConditionType::User),
        34 => Ok(ConditionType::Group),
        35 => Ok(ConditionType::ControlGroupController),
        36 => Ok(ConditionType::KernelModuleLoaded),
        _ => Err(LookupError::Invalid),
    }
}

pub fn assert_type_to_string(value: ConditionType) -> &'static str {
    static_text(ASSERT_TYPE_TABLE[value as usize])
}

pub fn assert_type_from_string(name: &str) -> Result<ConditionType, LookupError> {
    let value = if name == "AssertKernelVersion" {
        ConditionType::Version as i32
    } else {
        parse_enum_name(&ASSERT_TYPE_TABLE, name)?
    };
    condition_type_from_i32(value)
}

pub fn compression_to_string(value: Compression) -> &'static str {
    static_text(COMPRESSION_TABLE[value as usize])
}

pub fn compression_from_string(name: &str) -> Result<Compression, LookupError> {
    match parse_enum_name(&COMPRESSION_TABLE, name)? {
        0 => Ok(Compression::None),
        1 => Ok(Compression::Xz),
        2 => Ok(Compression::Lz4),
        3 => Ok(Compression::Zstd),
        4 => Ok(Compression::Gzip),
        5 => Ok(Compression::Bzip2),
        _ => Err(LookupError::Invalid),
    }
}

pub fn socket_address_type_to_string(value: i32) -> Option<&'static str> {
    if value < 0 {
        return None;
    }
    SOCKET_ADDRESS_TYPE_TABLE
        .get(value as usize)
        .copied()
        .flatten()
        .map(static_text)
}

pub fn socket_address_type_from_string(name: &str) -> Result<i32, LookupError> {
    SOCKET_ADDRESS_TYPE_TABLE
        .iter()
        .enumerate()
        .find_map(|(i, entry)| {
            entry
                .is_some_and(|candidate| static_text(candidate) == name)
                .then_some(i as i32)
        })
        .ok_or(LookupError::Invalid)
}

pub fn netlink_family_to_string(value: i32) -> Result<String, LookupError> {
    if value < 0 || value > i32::MAX {
        return Err(LookupError::OutOfRange);
    }

    if let Some(name) = NETLINK_FAMILY_TABLE.get(value as usize).copied().flatten() {
        Ok(static_text(name).to_string())
    } else {
        Ok(value.to_string())
    }
}

pub fn netlink_family_from_string(name: &str) -> Result<i32, LookupError> {
    if let Some((index, _)) = NETLINK_FAMILY_TABLE
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.is_some_and(|candidate| static_text(candidate) == name))
    {
        return Ok(index as i32);
    }

    parse_fallback_u32(name)
        .and_then(|value| i32::try_from(value).map_err(|_| LookupError::Invalid))
}

pub fn ip_tos_to_string(value: i32) -> Result<Option<String>, LookupError> {
    if !(0..=0xff).contains(&value) {
        return Ok(None);
    }

    let text = match value {
        0x02 => "low-cost".to_string(),
        0x04 => "reliability".to_string(),
        0x08 => "throughput".to_string(),
        0x10 => "low-delay".to_string(),
        _ => value.to_string(),
    };

    Ok(Some(text))
}

pub fn ip_tos_from_string(name: &str) -> Result<i32, LookupError> {
    match name {
        "low-cost" => Ok(0x02),
        "reliability" => Ok(0x04),
        "throughput" => Ok(0x08),
        "low-delay" => Ok(0x10),
        _ => {
            let value = parse_fallback_u32(name)?;
            if value > 0xff {
                return Err(LookupError::Invalid);
            }
            Ok(value as i32)
        }
    }
}

pub const fn output_mode_to_json_format_flags(mode: i32) -> u32 {
    if mode == OutputMode::JsonSse as i32 {
        SD_JSON_FORMAT_SSE
    } else if mode == OutputMode::JsonSeq as i32 {
        SD_JSON_FORMAT_SEQ
    } else if mode == OutputMode::JsonPretty as i32 {
        SD_JSON_FORMAT_PRETTY
    } else {
        SD_JSON_FORMAT_NEWLINE
    }
}

pub fn resolve_support_to_string(value: i32) -> Option<&'static str> {
    table_string(&RESOLVE_SUPPORT_TABLE, value)
}

pub fn resolve_support_from_string(name: &str) -> Result<i32, LookupError> {
    parse_enum_name_with_boolean(&RESOLVE_SUPPORT_TABLE, ResolveSupport::Yes as i32, name)
}

pub fn dnssec_mode_to_string(value: i32) -> Option<&'static str> {
    table_string(&DNSSEC_MODE_TABLE, value)
}

pub fn dnssec_mode_from_string(name: &str) -> Result<i32, LookupError> {
    parse_enum_name_with_boolean(&DNSSEC_MODE_TABLE, DnssecMode::Yes as i32, name)
}

pub fn dns_over_tls_mode_to_string(value: i32) -> Option<&'static str> {
    table_string(&DNS_OVER_TLS_MODE_TABLE, value)
}

pub fn dns_over_tls_mode_from_string(name: &str) -> Result<i32, LookupError> {
    parse_enum_name_with_boolean(&DNS_OVER_TLS_MODE_TABLE, DnsOverTlsMode::Yes as i32, name)
}

pub fn dns_cache_mode_to_string(value: i32) -> Option<&'static str> {
    table_string(&DNS_CACHE_MODE_TABLE, value)
}

pub fn dns_cache_mode_from_string(name: &str) -> Result<i32, LookupError> {
    parse_enum_name_with_boolean(&DNS_CACHE_MODE_TABLE, DnsCacheMode::Yes as i32, name)
}

pub fn dns_server_address_valid(family: i32, address: &[u8]) -> bool {
    match family {
        AF_INET => {
            if address.len() < 4 || address[..4] == [0, 0, 0, 0] {
                return false;
            }

            let value = u32::from_be_bytes([address[0], address[1], address[2], address[3]]);
            value != INADDR_DNS_STUB && value != INADDR_DNS_PROXY_STUB
        }
        AF_INET6 => address.len() >= 16 && address[..16].iter().any(|byte| *byte != 0),
        _ => false,
    }
}

pub const fn netif_has_carrier(operstate: u8, flags: u32) -> bool {
    if operstate == IF_OPER_UP {
        return true;
    }
    if operstate != IF_OPER_UNKNOWN {
        return false;
    }
    (flags & (IFF_LOWER_UP | IFF_RUNNING)) == (IFF_LOWER_UP | IFF_RUNNING)
        && (flags & IFF_DORMANT) == 0
}

// ── Narrow C ABI facade ───────────────────────────────────────────────────
//
// Keep all pointer handling here. The lookup and policy functions above take
// Rust values only, and the tables above are the one data authority for both
// APIs. Returned lookup pointers borrow immutable program-lifetime storage;
// callers must not free them. The two *_to_string_alloc functions instead
// transfer a libc allocation to the caller, exactly like their C counterparts.

#[inline]
/// # Safety
/// `input` must be null or point to a live NUL-terminated C string. The
/// caller retains ownership and must not mutate it for the returned borrow.
unsafe fn input_bytes<'a>(input: *const c_char) -> Option<&'a [u8]> {
    if input.is_null() {
        return None;
    }

    // SAFETY: the C ABI contract requires a live NUL-terminated input string.
    Some(unsafe_ffi!(CStr::from_ptr(input)).to_bytes())
}

#[inline]
fn table_ptr(table: &[&'static [u8]], value: i32) -> *const c_char {
    if value < 0 {
        return ptr::null();
    }
    table
        .get(value as usize)
        .map_or(ptr::null(), |entry| entry.as_ptr().cast())
}

#[inline]
fn optional_table_ptr(table: &[Option<&'static [u8]>], value: i32) -> *const c_char {
    if value < 0 {
        return ptr::null();
    }
    table
        .get(value as usize)
        .and_then(|entry| *entry)
        .map_or(ptr::null(), |entry| entry.as_ptr().cast())
}

#[inline]
/// # Safety
/// `input` must satisfy [`input_bytes`]'s C-string contract.
unsafe fn table_from_input(table: &[&'static [u8]], input: *const c_char) -> i32 {
    // SAFETY: propagated from the C ABI facade caller.
    let Some(input) = (unsafe_ffi!(input_bytes(input))) else {
        return Errno::EINVAL.to_neg_errno();
    };

    table
        .iter()
        .position(|entry| &entry[..entry.len() - 1] == input)
        .map_or_else(|| Errno::EINVAL.to_neg_errno(), |index| index as i32)
}

#[inline]
/// # Safety
/// `input` must satisfy [`input_bytes`]'s C-string contract.
unsafe fn optional_table_from_input(table: &[Option<&'static [u8]>], input: *const c_char) -> i32 {
    // SAFETY: propagated from the C ABI facade caller.
    let Some(input) = (unsafe_ffi!(input_bytes(input))) else {
        return Errno::EINVAL.to_neg_errno();
    };

    table
        .iter()
        .enumerate()
        .find_map(|(index, entry)| {
            entry
                .is_some_and(|candidate| &candidate[..candidate.len() - 1] == input)
                .then_some(index as i32)
        })
        .unwrap_or_else(|| Errno::EINVAL.to_neg_errno())
}

/// Allocate a C-owned NUL-terminated copy and publish it only on success.
///
/// # Safety
/// `ret` must be non-null and writable for one `char *`. The caller owns the
/// returned `libc::malloc` allocation and must release it with `free(3)`.
unsafe fn copy_to_c_allocation(text: &str, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    let Some(size) = text.len().checked_add(1) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let allocation = malloc(size).cast::<u8>();
    if allocation.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: `allocation` has `text.len() + 1` writable bytes and source is
    // a valid, non-overlapping Rust byte slice. `ret` is writable by contract.
    unsafe {
        ptr::copy_nonoverlapping(text.as_ptr(), allocation, text.len());
        *allocation.add(text.len()) = 0;
        *ret = allocation.cast();
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_condition_type_to_string(value: i32) -> *const c_char {
    table_ptr(&CONDITION_TYPE_TABLE, value)
}

/// # Safety
/// `input` must be null or point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_condition_type_from_string(input: *const c_char) -> i32 {
    // SAFETY: propagated from this FFI function's contract.
    let Some(input) = (unsafe_ffi!(input_bytes(input))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    if input == b"ConditionKernelVersion" {
        return ConditionType::Version as i32;
    }
    CONDITION_TYPE_TABLE
        .iter()
        .position(|entry| &entry[..entry.len() - 1] == input)
        .map_or_else(|| Errno::EINVAL.to_neg_errno(), |index| index as i32)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_assert_type_to_string(value: i32) -> *const c_char {
    table_ptr(&ASSERT_TYPE_TABLE, value)
}

/// # Safety
/// `input` must be null or point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_assert_type_from_string(input: *const c_char) -> i32 {
    // SAFETY: propagated from this FFI function's contract.
    let Some(input) = (unsafe_ffi!(input_bytes(input))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    if input == b"AssertKernelVersion" {
        return ConditionType::Version as i32;
    }
    ASSERT_TYPE_TABLE
        .iter()
        .position(|entry| &entry[..entry.len() - 1] == input)
        .map_or_else(|| Errno::EINVAL.to_neg_errno(), |index| index as i32)
}

/// # Safety
/// `address` must be null or readable for 4 bytes with `AF_INET`, or 16 bytes
/// with `AF_INET6`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_server_address_valid(family: i32, address: *const c_void) -> bool {
    if address.is_null() {
        return false;
    }
    let length = match family {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => return false,
    };
    // SAFETY: length is selected by the documented ABI family contract.
    let address = unsafe_ffi!(std::slice::from_raw_parts(address.cast::<u8>(), length));
    dns_server_address_valid(family, address)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_netif_has_carrier(operstate: u8, flags: u32) -> bool {
    netif_has_carrier(operstate, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_compression_to_string(value: i32) -> *const c_char {
    table_ptr(&COMPRESSION_TABLE, value)
}

/// # Safety
/// `input` must be null or point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_compression_from_string(input: *const c_char) -> i32 {
    // SAFETY: propagated from this FFI function's contract.
    unsafe_ffi!(table_from_input(&COMPRESSION_TABLE, input))
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_socket_address_type_to_string(value: i32) -> *const c_char {
    optional_table_ptr(&SOCKET_ADDRESS_TYPE_TABLE, value)
}

/// # Safety
/// `input` must be null or point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_socket_address_type_from_string(input: *const c_char) -> i32 {
    // SAFETY: propagated from this FFI function's contract.
    unsafe_ffi!(optional_table_from_input(&SOCKET_ADDRESS_TYPE_TABLE, input))
}

/// # Safety
/// `ret` must be non-null and writable for one pointer. On success it receives
/// a `libc::malloc` allocation owned by the caller; it is unchanged on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_netlink_family_to_string_alloc(
    value: i32,
    ret: *mut *mut c_char,
) -> i32 {
    let Ok(text) = netlink_family_to_string(value) else {
        return Errno::ERANGE.to_neg_errno();
    };
    // SAFETY: propagated from this FFI function's contract.
    unsafe_ffi!(copy_to_c_allocation(&text, ret))
}

/// # Safety
/// `input` must be null or point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_netlink_family_from_string(input: *const c_char) -> i32 {
    // SAFETY: propagated from this FFI function's contract.
    let Some(input) = (unsafe_ffi!(input_bytes(input))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    let Ok(input) = std::str::from_utf8(input) else {
        return Errno::EINVAL.to_neg_errno();
    };
    netlink_family_from_string(input).unwrap_or_else(|error| error.errno().to_neg_errno())
}

/// # Safety
/// `ret` must be non-null and writable for one pointer. On success it receives
/// a `libc::malloc` allocation owned by the caller; it is unchanged on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ip_tos_to_string_alloc(value: i32, ret: *mut *mut c_char) -> i32 {
    let Ok(Some(text)) = ip_tos_to_string(value) else {
        return Errno::ERANGE.to_neg_errno();
    };
    // SAFETY: propagated from this FFI function's contract.
    unsafe_ffi!(copy_to_c_allocation(&text, ret))
}

/// # Safety
/// `input` must be null or point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ip_tos_from_string(input: *const c_char) -> i32 {
    // SAFETY: propagated from this FFI function's contract.
    let Some(input) = (unsafe_ffi!(input_bytes(input))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    let Ok(input) = std::str::from_utf8(input) else {
        return Errno::EINVAL.to_neg_errno();
    };
    ip_tos_from_string(input).unwrap_or_else(|error| error.errno().to_neg_errno())
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_output_mode_to_json_format_flags(mode: i32) -> i64 {
    i64::from(output_mode_to_json_format_flags(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_type_roundtrip_matches_c() {
        assert_eq!(
            condition_type_to_string(ConditionType::Architecture),
            "ConditionArchitecture"
        );
        assert_eq!(
            condition_type_to_string(ConditionType::KernelModuleLoaded),
            "ConditionKernelModuleLoaded"
        );
        assert_eq!(
            condition_type_from_string("ConditionPathExists"),
            Ok(ConditionType::PathExists)
        );
        assert_eq!(
            condition_type_from_string("ConditionKernelVersion"),
            Ok(ConditionType::Version)
        );
    }

    #[test]
    fn assert_type_roundtrip_matches_c() {
        assert_eq!(
            assert_type_to_string(ConditionType::Architecture),
            "AssertArchitecture"
        );
        assert_eq!(
            assert_type_to_string(ConditionType::KernelModuleLoaded),
            "AssertKernelModuleLoaded"
        );
        assert_eq!(
            assert_type_from_string("AssertPathExists"),
            Ok(ConditionType::PathExists)
        );
        assert_eq!(
            assert_type_from_string("AssertKernelVersion"),
            Ok(ConditionType::Version)
        );
    }

    #[test]
    fn compression_lookup_matches_c() {
        assert_eq!(compression_to_string(Compression::None), "uncompressed");
        assert_eq!(compression_from_string("zstd"), Ok(Compression::Zstd));
        assert_eq!(compression_from_string("gzip"), Ok(Compression::Gzip));
        assert_eq!(compression_from_string("NONE"), Err(LookupError::Invalid));
    }

    #[test]
    fn socket_address_type_lookup_matches_c() {
        assert_eq!(socket_address_type_to_string(1), Some("Stream"));
        assert_eq!(socket_address_type_to_string(5), Some("SequentialPacket"));
        assert_eq!(socket_address_type_to_string(0), None);
        assert_eq!(socket_address_type_from_string("Datagram"), Ok(2));
    }

    #[test]
    fn netlink_family_lookup_matches_c_fallback() {
        assert_eq!(netlink_family_to_string(0), Ok("route".to_string()));
        assert_eq!(netlink_family_to_string(9), Ok("audit".to_string()));
        assert_eq!(netlink_family_to_string(99), Ok("99".to_string()));
        assert_eq!(netlink_family_from_string("42"), Ok(42));
    }

    #[test]
    fn numeric_fallback_matches_c_safe_atou_base_zero_rules() {
        assert_eq!(parse_fallback_u32("010"), Ok(8));
        assert_eq!(parse_fallback_u32("0x10"), Ok(16));
        assert_eq!(parse_fallback_u32("0o10"), Ok(8));
        assert_eq!(parse_fallback_u32("0b10"), Ok(2));
        assert_eq!(parse_fallback_u32(" +0x10"), Ok(16));
        assert_eq!(parse_fallback_u32("-0"), Ok(0));
        assert_eq!(parse_fallback_u32("+0b1"), Err(LookupError::Invalid));
        assert_eq!(parse_fallback_u32("1 "), Err(LookupError::Invalid));
        assert_eq!(parse_fallback_u32("-1"), Err(LookupError::Invalid));
    }

    #[test]
    fn ip_tos_lookup_matches_c_fallback() {
        assert_eq!(ip_tos_to_string(0x10), Ok(Some("low-delay".to_string())));
        assert_eq!(ip_tos_to_string(0x20), Ok(Some("32".to_string())));
        assert_eq!(ip_tos_to_string(0x100), Ok(None));
        assert_eq!(ip_tos_from_string("throughput"), Ok(0x08));
        assert_eq!(ip_tos_from_string("256"), Err(LookupError::Invalid));
    }

    #[test]
    fn output_mode_flags_match_c() {
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::JsonSse as i32),
            SD_JSON_FORMAT_SSE
        );
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::JsonSeq as i32),
            SD_JSON_FORMAT_SEQ
        );
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::JsonPretty as i32),
            SD_JSON_FORMAT_PRETTY
        );
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::Short as i32),
            SD_JSON_FORMAT_NEWLINE
        );
    }

    #[test]
    fn boolean_aware_resolve_tables_match_c() {
        assert_eq!(resolve_support_from_string("false"), Ok(0));
        assert_eq!(
            resolve_support_from_string("true"),
            Ok(ResolveSupport::Yes as i32)
        );
        assert_eq!(
            resolve_support_from_string("resolve"),
            Ok(ResolveSupport::Resolve as i32)
        );
        assert_eq!(
            dnssec_mode_from_string("allow-downgrade"),
            Ok(DnssecMode::AllowDowngrade as i32)
        );
        assert_eq!(
            dns_over_tls_mode_from_string("yes"),
            Ok(DnsOverTlsMode::Yes as i32)
        );
        assert_eq!(
            dns_cache_mode_from_string("no-negative"),
            Ok(DnsCacheMode::NoNegative as i32)
        );
    }

    #[test]
    fn dns_server_address_validation_matches_c() {
        assert!(dns_server_address_valid(AF_INET, &[8, 8, 8, 8]));
        assert!(!dns_server_address_valid(AF_INET, &[0, 0, 0, 0]));
        assert!(!dns_server_address_valid(AF_INET, &[127, 0, 0, 53]));
        assert!(!dns_server_address_valid(AF_INET, &[127, 0, 0, 54]));
        assert!(dns_server_address_valid(
            AF_INET6,
            &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        ));
        assert!(!dns_server_address_valid(AF_INET6, &[0; 16]));
    }

    #[test]
    fn netif_carrier_logic_matches_c() {
        assert!(netif_has_carrier(IF_OPER_UP, 0));
        assert!(netif_has_carrier(
            IF_OPER_UNKNOWN,
            IFF_LOWER_UP | IFF_RUNNING
        ));
        assert!(!netif_has_carrier(IF_OPER_UNKNOWN, IFF_LOWER_UP));
        assert!(!netif_has_carrier(
            IF_OPER_UNKNOWN,
            IFF_LOWER_UP | IFF_RUNNING | IFF_DORMANT
        ));
        assert!(!netif_has_carrier(1, IFF_LOWER_UP | IFF_RUNNING));
    }
}
