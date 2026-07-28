// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-print-properties.c, src/shared/bus-print-properties.h
//
// D-Bus property formatting for terminal output.
//
// Converts typed D-Bus property values into human-readable strings with
// type-aware formatting (timestamps, timespans, octal modes, capability
// sets, namespace flags, etc.) and supports filtering by expected value
// and display flags.

use std::{ffi::CStr, fmt::Write as FmtWrite};

use systemd_basic_rs::{
    capability_list::capability_to_string,
    capability_util::CAP_LIMIT,
    mountpoint_util::{MountPropagationFlag, mount_propagation_flag_to_string},
};

use crate::nsflags::{NAMESPACE_FLAGS_ALL, NamespaceFlags, namespace_flags_to_string};

// ── Flags ──────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling bus property display.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BusPrintPropertyFlags: u32 {
        /// Print only the value, not the property name (e.g. systemctl --value).
        const ONLY_VALUE   = 1 << 0;
        /// Show properties even when empty (e.g. systemctl --all).
        const SHOW_EMPTY   = 1 << 1;
    }
}

impl Default for BusPrintPropertyFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Sentinel constants ─────────────────────────────────────────────────────

/// Represents infinity for microsecond-based values.
pub const USEC_INFINITY: u64 = u64::MAX;

/// Invalid / unset UID sentinel.
pub const UID_INVALID: u32 = u32::MAX;

/// Invalid / unset GID sentinel.
pub const GID_INVALID: u32 = u32::MAX;

/// Cgroup weight meaning "idle" priority.
pub const CGROUP_WEIGHT_IDLE: u64 = 1;

/// Cgroup weight meaning "not configured" (unset).
pub const CGROUP_WEIGHT_INVALID: u64 = 0;

/// Cgroup memory limit meaning "max" / no explicit limit.
pub const CGROUP_LIMIT_MAX: u64 = u64::MAX;

// ── Property value representation ──────────────────────────────────────────

/// Represents a D-Bus property value for formatting purposes.
#[derive(Debug, Clone, PartialEq)]
pub enum BusPropertyValue {
    /// D-Bus string (`'s'`).
    String(String),
    /// D-Bus boolean (`'b'`).
    Boolean(bool),
    /// D-Bus uint64 (`'t'`).
    Uint64(u64),
    /// D-Bus int64 (`'x'`).
    Int64(i64),
    /// D-Bus uint32 (`'u'`).
    Uint32(u32),
    /// D-Bus int32 (`'i'`).
    Int32(i32),
    /// D-Bus double (`'d'`).
    Double(f64),
    /// D-Bus array of strings (`'as'`).
    StringArray(Vec<String>),
    /// D-Bus array of bytes (`'ay'`).
    ByteArray(Vec<u8>),
    /// D-Bus array of uint32 (`'au'`).
    Uint32Array(Vec<u32>),
}

// ── Timestamp detection ────────────────────────────────────────────────────

/// Property names that are timestamps despite not ending in "Timestamp".
static TIMESTAMP_EXCEPTIONS: &[&str] = &[
    "NextElapseUSecRealtime",
    "LastTriggerUSec",
    "TimeUSec",
    "RTCTimeUSec",
];

/// Check if a property name indicates a timestamp value.
///
/// Trust the naming convention: anything ending in "Timestamp" is a timestamp,
/// plus a handful of well-known exceptions.
pub fn bus_property_is_timestamp(name: &str) -> bool {
    name.ends_with("Timestamp") || TIMESTAMP_EXCEPTIONS.contains(&name)
}

// ── Core formatting helpers ────────────────────────────────────────────────

/// Format a single property line: `"Name=value\n"` or just `"value\n"`.
///
/// Returns `None` if the property should be suppressed (expected_value mismatch
/// or empty value when `SHOW_EMPTY` is not set).
fn format_property_line(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: &str,
) -> Option<String> {
    // Filter by expected value
    if let Some(expected) = expected_value {
        if expected != value {
            return None;
        }
    }

    // Hide empty values unless SHOW_EMPTY is set
    if !flags.contains(BusPrintPropertyFlags::SHOW_EMPTY) && value.is_empty() {
        return None;
    }

    let mut out = String::new();
    if flags.contains(BusPrintPropertyFlags::ONLY_VALUE) {
        out.push_str(value);
    } else {
        write!(out, "{}={}", name, value).unwrap();
    }
    Some(out)
}

/// Format a property line using a pre-formatted value.
///
/// This is the public equivalent of the C `bus_print_property_value`.
pub fn bus_print_property_value(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: &str,
) -> Option<String> {
    format_property_line(name, expected_value, flags, value)
}

// ── uint64 formatting ──────────────────────────────────────────────────────

/// Property names that render as idle when their value equals `CGROUP_WEIGHT_IDLE`.
static CPU_WEIGHT_IDLE_NAMES: &[&str] = &["CPUWeight", "StartupCPUWeight"];

/// Property names where `CGROUP_WEIGHT_INVALID` means "[not set]".
static WEIGHT_INVALID_NAMES: &[&str] = &[
    "CPUWeight",
    "StartupCPUWeight",
    "IOWeight",
    "StartupIOWeight",
];

/// Property names where `UINT64_MAX` means "[not set]" for current values.
static CURRENT_UINT64_MAX_NAMES: &[&str] = &["MemoryCurrent", "MemoryAvailable", "TasksCurrent"];

/// Property names where `CGROUP_LIMIT_MAX` means "[not set]" for memory
/// current/peak readings.
static MEMORY_CURRENT_PEAK_SUFFIXES: &[&str] = &["Current", "Peak"];

/// Property names where `UINT64_MAX` means "[not set]" for IO counters.
static IO_SUFFIXES: &[&str] = &["Bytes", "Operations"];

/// Property names where `CGROUP_LIMIT_MAX` means "infinity" for memory limits.
static MEMORY_LIMIT_SUFFIXES: &[&str] = &[
    "MemoryLow",
    "MemoryMin",
    "MemoryHigh",
    "MemoryMax",
    "MemorySwapMax",
    "MemoryZSwapMax",
    "MemoryLimit",
];

/// Property names where `UINT64_MAX` means "[no data]".
static NO_DATA_NAMES: &[&str] = &[
    "IPIngressBytes",
    "IPIngressPackets",
    "IPEgressBytes",
    "IPEgressPackets",
];

/// Capability-related property names.
static CAPABILITY_NAMES: &[&str] = &["CapabilityBoundingSet", "AmbientCapabilities"];

/// Format a uint64 property value according to systemd naming conventions.
///
/// This handles the extensive special-casing in the C `bus_print_property`
/// for `SD_BUS_TYPE_UINT64`: timestamps, timespans, octal modes, capability
/// sets, namespace flags, cgroup weights, memory limits, etc.
///
/// Returns `Some(formatted_string)` if the property should be printed,
/// or `None` if it was suppressed by the expected_value filter.
pub fn format_uint64_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: u64,
) -> Option<String> {
    // FORMAT_TIMESTAMP() returns NULL for unset timestamps. In C that means
    // any non-NULL expected value cannot match, even an empty string.
    if bus_property_is_timestamp(name)
        && (value == 0 || value == USEC_INFINITY)
        && expected_value.is_some()
    {
        return None;
    }

    let formatted = if name == "RTCTimeUSec" {
        format_timestamp_utc(value)
    } else if bus_property_is_timestamp(name) {
        format_timestamp(value)
    } else if name == "ManagedOOMMemoryPressureDurationUSec" && value == USEC_INFINITY {
        "[not set]".into()
    } else if name.contains("USec") {
        format_timespan(value)
    } else if name == "CoredumpFilter" {
        format!("0x{:x}", value)
    } else if name == "RestrictNamespaces" {
        format_namespace_flags(value)
    } else if name == "MountFlags" {
        // The C helper rejects conflicting propagation bits with -EINVAL. The
        // string-only public API has no error channel, so do not invent a
        // value: suppress this malformed property.
        return format_mount_flags(value)
            .and_then(|formatted| format_property_line(name, expected_value, flags, &formatted));
    } else if CAPABILITY_NAMES.contains(&name) {
        format_capability_set(value)
    } else if CPU_WEIGHT_IDLE_NAMES.contains(&name) && value == CGROUP_WEIGHT_IDLE {
        "idle".into()
    } else if WEIGHT_INVALID_NAMES.contains(&name) && value == CGROUP_WEIGHT_INVALID {
        "[not set]".into()
    } else if CURRENT_UINT64_MAX_NAMES.contains(&name) && value == u64::MAX {
        "[not set]".into()
    } else if name.starts_with("Memory")
        && MEMORY_CURRENT_PEAK_SUFFIXES
            .iter()
            .any(|s| name.ends_with(s))
        && value == CGROUP_LIMIT_MAX
    {
        "[not set]".into()
    } else if name.starts_with("IO")
        && IO_SUFFIXES.iter().any(|s| name.ends_with(s))
        && value == u64::MAX
    {
        "[not set]".into()
    } else if name.ends_with("NSec") && value == u64::MAX {
        "[not set]".into()
    } else if MEMORY_LIMIT_SUFFIXES.iter().any(|s| name.ends_with(s)) && value == CGROUP_LIMIT_MAX {
        "infinity".into()
    } else if name.ends_with("TasksMax") && value == u64::MAX {
        "infinity".into()
    } else if name.starts_with("Limit") && value == u64::MAX {
        "infinity".into()
    } else if name.starts_with("DefaultLimit") && value == u64::MAX {
        "infinity".into()
    } else if NO_DATA_NAMES.contains(&name) && value == u64::MAX {
        "[no data]".into()
    } else {
        value.to_string()
    };

    format_property_line(name, expected_value, flags, &formatted)
}

// ── String property formatting ─────────────────────────────────────────────

/// Format a string property value.
///
/// Strings containing newlines are rendered as `[unprintable]`.
pub fn format_string_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: &str,
) -> Option<String> {
    // Skip empty values unless SHOW_EMPTY
    if !flags.contains(BusPrintPropertyFlags::SHOW_EMPTY) && value.is_empty() {
        return None;
    }

    let display = if value.contains('\n') {
        "[unprintable]"
    } else {
        value
    };

    format_property_line(name, expected_value, flags, display)
}

// ── Boolean property formatting ────────────────────────────────────────────

/// Format a boolean property value as "yes" or "no".
///
/// When `expected_value` is provided, it is parsed as a boolean and the
/// property is only printed if the values match.
pub fn format_boolean_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: bool,
) -> Option<String> {
    // Boolean expected-value comparison: parse the expected string as bool
    if let Some(expected) = expected_value {
        let expected_bool = parse_boolean(expected);
        if expected_bool != Some(value) {
            return None;
        }
    }

    let display = yes_no(value);
    format_property_line(name, None, flags, &display)
}

// ── int64 formatting ───────────────────────────────────────────────────────

/// Format an int64 property value.
pub fn format_int64_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: i64,
) -> Option<String> {
    format_property_line(name, expected_value, flags, &value.to_string())
}

// ── uint32 formatting ──────────────────────────────────────────────────────

/// Format a uint32 property value with special handling for UMask/Mode (octal)
/// and UID/GID (invalid sentinel).
pub fn format_uint32_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: u32,
) -> Option<String> {
    let formatted = if name.contains("UMask") || name.contains("Mode") {
        format!("{:04o}", value)
    } else if name == "UID" {
        if value == UID_INVALID {
            "[not set]".into()
        } else {
            value.to_string()
        }
    } else if name == "GID" {
        if value == GID_INVALID {
            "[not set]".into()
        } else {
            value.to_string()
        }
    } else {
        value.to_string()
    };

    format_property_line(name, expected_value, flags, &formatted)
}

// ── int32 formatting ───────────────────────────────────────────────────────

/// Format an int32 property value.
pub fn format_int32_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: i32,
) -> Option<String> {
    format_property_line(name, expected_value, flags, &value.to_string())
}

// ── Double formatting ──────────────────────────────────────────────────────

/// Format a double property value (using `%g`-style formatting).
pub fn format_double_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    value: f64,
) -> Option<String> {
    // Rust's {} formatting for f64 is close to C's %g
    let display = format!("{}", value);
    format_property_line(name, expected_value, flags, &display)
}

// ── Array formatting ───────────────────────────────────────────────────────

/// Format a string array property.
///
/// Values are shell-quoted and space-separated on a single line.
pub fn format_string_array_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    values: &[String],
) -> Option<String> {
    // Filter by expected value (match against joined output)
    if !flags.contains(BusPrintPropertyFlags::SHOW_EMPTY) && values.is_empty() {
        return None;
    }

    let quoted: Vec<String> = values.iter().map(|s| shell_maybe_quote(s)).collect();
    let joined = quoted.join(" ");

    if let Some(expected) = expected_value {
        if expected != joined {
            return None;
        }
    }

    let mut out = String::new();
    if !flags.contains(BusPrintPropertyFlags::ONLY_VALUE) {
        write!(out, "{}=", name).unwrap();
    }
    out.push_str(&joined);
    Some(out)
}

/// Format a byte array property as hex.
pub fn format_byte_array_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    bytes: &[u8],
) -> Option<String> {
    if !flags.contains(BusPrintPropertyFlags::SHOW_EMPTY) && bytes.is_empty() {
        return None;
    }

    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();

    if let Some(expected) = expected_value {
        if expected != hex {
            return None;
        }
    }

    let mut out = String::new();
    if !flags.contains(BusPrintPropertyFlags::ONLY_VALUE) {
        write!(out, "{}=", name).unwrap();
    }
    out.push_str(&hex);
    Some(out)
}

/// Format a uint32 array property as 8-digit hex values.
pub fn format_uint32_array_property(
    name: &str,
    expected_value: Option<&str>,
    flags: BusPrintPropertyFlags,
    values: &[u32],
) -> Option<String> {
    if !flags.contains(BusPrintPropertyFlags::SHOW_EMPTY) && values.is_empty() {
        return None;
    }

    let hex: String = values.iter().map(|v| format!("{:08x}", v)).collect();

    if let Some(expected) = expected_value {
        if expected != hex {
            return None;
        }
    }

    let mut out = String::new();
    if !flags.contains(BusPrintPropertyFlags::ONLY_VALUE) {
        write!(out, "{}=", name).unwrap();
    }
    out.push_str(&hex);
    Some(out)
}

// ── Unified dispatch ───────────────────────────────────────────────────────

/// Result of formatting a property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatPropertyResult {
    /// Property was formatted and should be displayed.
    Printed(String),
    /// Property was recognized but suppressed (filter mismatch, empty, etc.).
    Suppressed,
    /// Property type was not recognized by this formatter.
    Unhandled,
}

/// Format a single D-Bus property value using type-aware formatting.
///
/// This is the Rust equivalent of `bus_print_property` — dispatches to the
/// correct formatter based on the value variant.
pub fn format_bus_property(
    name: &str,
    expected_value: Option<&str>,
    value: &BusPropertyValue,
    flags: BusPrintPropertyFlags,
) -> FormatPropertyResult {
    match value {
        BusPropertyValue::String(s) => {
            match format_string_property(name, expected_value, flags, s) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::Boolean(b) => {
            match format_boolean_property(name, expected_value, flags, *b) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::Uint64(u) => {
            match format_uint64_property(name, expected_value, flags, *u) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::Int64(i) => {
            match format_int64_property(name, expected_value, flags, *i) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::Uint32(u) => {
            match format_uint32_property(name, expected_value, flags, *u) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::Int32(i) => {
            match format_int32_property(name, expected_value, flags, *i) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::Double(d) => {
            match format_double_property(name, expected_value, flags, *d) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::StringArray(arr) => {
            match format_string_array_property(name, expected_value, flags, arr) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::ByteArray(arr) => {
            match format_byte_array_property(name, expected_value, flags, arr) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
        BusPropertyValue::Uint32Array(arr) => {
            match format_uint32_array_property(name, expected_value, flags, arr) {
                Some(line) => FormatPropertyResult::Printed(line),
                None => FormatPropertyResult::Suppressed,
            }
        }
    }
}

// ── Formatting primitives ──────────────────────────────────────────────────

/// Format a microsecond timestamp as C `FORMAT_TIMESTAMP()` does.
///
/// This is deliberately a small platform boundary: `localtime_r(3)` is needed
/// to preserve systemd's configured local timezone and daylight-saving rules.
/// Its raw result is immediately copied into Rust-owned data.
pub fn format_timestamp(usec: u64) -> String {
    format_timestamp_style(usec, false)
}

/// Format a microsecond timestamp in UTC, as `FORMAT_TIMESTAMP_STYLE(...,
/// TIMESTAMP_UTC)` does for the RTC clock property.
pub fn format_timestamp_utc(usec: u64) -> String {
    format_timestamp_style(usec, true)
}

fn format_timestamp_style(usec: u64, utc: bool) -> String {
    const USEC_PER_SEC: u64 = 1_000_000;
    const USEC_TIMESTAMP_FORMATTABLE_MAX_64BIT: u64 = 253_402_214_399_000_000;
    const USEC_TIMESTAMP_FORMATTABLE_MAX_32BIT: u64 =
        i32::MAX as u64 * USEC_PER_SEC - 24 * 60 * 60 * USEC_PER_SEC;
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    // timestamp_is_set(), used by format_timestamp_style(), rejects both the
    // zero/unset sentinel and USEC_INFINITY. bus_print_property_value() then
    // renders that NULL value as an empty string.
    if usec == 0 || usec == USEC_INFINITY {
        return String::new();
    }

    let format_table_max = if cfg!(target_pointer_width = "64") {
        USEC_TIMESTAMP_FORMATTABLE_MAX_64BIT
    } else {
        USEC_TIMESTAMP_FORMATTABLE_MAX_32BIT
    };
    if usec > format_table_max {
        return "--- XXXX-XX-XX XX:XX:XX".into();
    }

    let mut seconds = (usec / USEC_PER_SEC) as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::zeroed();
    // SAFETY: `seconds` and `tm` are valid, writable pointers for localtime_r
    // or gmtime_r; each function is reentrant and a successful return
    // initializes `tm`.
    let tm = unsafe {
        let result = if utc {
            libc::gmtime_r(&mut seconds, tm.as_mut_ptr())
        } else {
            libc::localtime_r(&mut seconds, tm.as_mut_ptr())
        };
        if result.is_null() {
            return String::new();
        }
        tm.assume_init()
    };

    let weekday = WEEKDAYS.get(tm.tm_wday as usize).copied().unwrap_or("---");
    let mut formatted = format!(
        "{weekday} {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
    );

    // FORMAT_TIMESTAMP_MAX is 38 bytes. C appends the local timezone only
    // when it fits; the fixed portion above is 23 bytes, so a zone of at most
    // 13 bytes is retained.
    if utc {
        formatted.push_str(" UTC");
    } else if !tm.tm_zone.is_null() {
        // SAFETY: tm_zone is a NUL-terminated string owned by libc's timezone
        // state and remains valid for this formatting operation.
        if let Ok(zone) = unsafe { CStr::from_ptr(tm.tm_zone) }.to_str() {
            if !zone.is_empty() && zone.len() <= 13 {
                formatted.push(' ');
                formatted.push_str(zone);
            }
        }
    }

    formatted
}

/// Format a microsecond timespan as C `FORMAT_TIMESPAN(usec, 0)` does.
pub fn format_timespan(usec: u64) -> String {
    const USEC_PER_MSEC: u64 = 1_000;
    const USEC_PER_SEC: u64 = 1_000_000;
    const USEC_PER_MINUTE: u64 = 60 * USEC_PER_SEC;
    const USEC_PER_HOUR: u64 = 60 * USEC_PER_MINUTE;
    const USEC_PER_DAY: u64 = 24 * USEC_PER_HOUR;
    const USEC_PER_WEEK: u64 = 7 * USEC_PER_DAY;
    // Keep these values in sync with time-util.h, not average Gregorian
    // durations: format_timespan() intentionally uses fixed parse_sec units.
    const USEC_PER_MONTH: u64 = 2_629_800 * USEC_PER_SEC;
    const USEC_PER_YEAR: u64 = 31_557_600 * USEC_PER_SEC;
    const TABLE: [(&str, u64); 9] = [
        ("y", USEC_PER_YEAR),
        ("month", USEC_PER_MONTH),
        ("w", USEC_PER_WEEK),
        ("d", USEC_PER_DAY),
        ("h", USEC_PER_HOUR),
        ("min", USEC_PER_MINUTE),
        ("s", USEC_PER_SEC),
        ("ms", USEC_PER_MSEC),
        ("us", 1),
    ];

    if usec == USEC_INFINITY {
        return "infinity".into();
    }
    if usec == 0 {
        return "0".into();
    }

    let mut remaining = usec;
    let mut parts = Vec::new();

    for (suffix, unit) in TABLE {
        if remaining == 0 {
            break;
        }
        if remaining < unit {
            continue;
        }

        let whole = remaining / unit;
        let fraction = remaining % unit;

        // The C helper uses decimal notation only below one minute. With the
        // zero accuracy passed by bus-print-properties.c this preserves all
        // sub-unit digits.
        if remaining < USEC_PER_MINUTE && fraction > 0 {
            let mut digits = 0usize;
            let mut scale = unit;
            while scale > 1 {
                scale /= 10;
                digits += 1;
            }
            parts.push(format!("{whole}.{fraction:0digits$}{suffix}"));
            break;
        }

        parts.push(format!("{whole}{suffix}"));
        remaining = fraction;
    }

    parts.join(" ")
}

/// Convert a boolean to "yes" / "no" (systemd convention).
pub fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Parse a string as a boolean in systemd convention.
///
/// Recognizes "1", "yes", "true", "on" as true and "0", "no", "false", "off"
/// as false.
pub fn parse_boolean(s: &str) -> Option<bool> {
    match s {
        "1" | "yes" | "true" | "on" | "True" | "TRUE" | "Yes" | "YES" | "ON" => Some(true),
        "0" | "no" | "false" | "off" | "False" | "FALSE" | "No" | "NO" | "OFF" => Some(false),
        _ => None,
    }
}

/// Shell-quote a string if it contains special characters.
///
/// Wraps in single quotes and escapes embedded single quotes per shell convention.
pub fn shell_maybe_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    let needs_quoting = s
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.' && c != '/');
    if !needs_quoting {
        return s.into();
    }
    // Use single-quote quoting: replace ' with '\''
    let escaped = s.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

/// Format namespace restriction flags.
///
/// - 0 → "yes" (all namespaces restricted)
/// - ALL bits set → "no" (no restriction)
/// - Partial → list specific namespaces
pub fn format_namespace_flags(flags: u64) -> String {
    let all = NAMESPACE_FLAGS_ALL.bits();
    if flags & all == 0 {
        "yes".into()
    } else if (flags & all) == all {
        "no".into()
    } else {
        namespace_flags_to_string(NamespaceFlags::from_bits_retain(flags))
    }
}

/// Format mount propagation flags, returning `None` for C's `-EINVAL` case.
pub fn format_mount_flags(flags: u64) -> Option<String> {
    MountPropagationFlag::from_raw_flags(flags)
        .map(mount_propagation_flag_to_string)
        .map(str::to_owned)
}

/// Format a capability set as a human-readable string.
pub fn format_capability_set(caps: u64) -> String {
    // This is the safe equivalent of capability_set_to_string(). The kernel
    // advertises the current upper bound in procfs; use the source-tree's
    // compiled CAP_LAST_CAP (40) when procfs is unavailable, rather than
    // inventing names for bits the running kernel cannot support.
    const COMPILED_CAP_LAST: u32 = 40;
    let last = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(COMPILED_CAP_LAST)
        .min(CAP_LIMIT as u32);

    (0..=last)
        .filter(|cap| (caps & (1_u64 << cap)) != 0)
        .filter_map(|cap| capability_to_string(cap as i32))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_default_empty() {
        let flags = BusPrintPropertyFlags::default();
        assert!(!flags.contains(BusPrintPropertyFlags::ONLY_VALUE));
        assert!(!flags.contains(BusPrintPropertyFlags::SHOW_EMPTY));
    }

    #[test]
    fn test_flags_combined() {
        let flags = BusPrintPropertyFlags::ONLY_VALUE | BusPrintPropertyFlags::SHOW_EMPTY;
        assert!(flags.contains(BusPrintPropertyFlags::ONLY_VALUE));
        assert!(flags.contains(BusPrintPropertyFlags::SHOW_EMPTY));
    }

    #[test]
    fn test_bus_property_is_timestamp_suffix() {
        assert!(bus_property_is_timestamp("ExecMainStartTimestamp"));
        assert!(bus_property_is_timestamp("InactiveEnterTimestamp"));
        assert!(bus_property_is_timestamp("SomeTimestamp"));
    }

    #[test]
    fn test_bus_property_is_timestamp_exceptions() {
        assert!(bus_property_is_timestamp("NextElapseUSecRealtime"));
        assert!(bus_property_is_timestamp("LastTriggerUSec"));
        assert!(bus_property_is_timestamp("TimeUSec"));
        assert!(bus_property_is_timestamp("RTCTimeUSec"));
    }

    #[test]
    fn test_bus_property_is_timestamp_negative() {
        assert!(!bus_property_is_timestamp("Description"));
        assert!(!bus_property_is_timestamp("LoadState"));
        assert!(!bus_property_is_timestamp("MemoryCurrent"));
        assert!(!bus_property_is_timestamp("TimestampSuffix")); // has "Timestamp" substring — wait, it ends with "Timestamp" no, ends with "Suffix"
    }

    #[test]
    fn test_bus_print_property_value_basic() {
        let result = bus_print_property_value(
            "Description",
            None,
            BusPrintPropertyFlags::empty(),
            "hello world",
        );
        assert_eq!(result, Some("Description=hello world".into()));
    }

    #[test]
    fn test_bus_print_property_value_only_value() {
        let result = bus_print_property_value(
            "Description",
            None,
            BusPrintPropertyFlags::ONLY_VALUE,
            "hello world",
        );
        assert_eq!(result, Some("hello world".into()));
    }

    #[test]
    fn test_bus_print_property_value_expected_match() {
        let result = bus_print_property_value(
            "LoadState",
            Some("loaded"),
            BusPrintPropertyFlags::empty(),
            "loaded",
        );
        assert_eq!(result, Some("LoadState=loaded".into()));
    }

    #[test]
    fn test_bus_print_property_value_expected_mismatch() {
        let result = bus_print_property_value(
            "LoadState",
            Some("active"),
            BusPrintPropertyFlags::empty(),
            "loaded",
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_bus_print_property_value_empty_suppressed() {
        let result =
            bus_print_property_value("Description", None, BusPrintPropertyFlags::empty(), "");
        assert_eq!(result, None);
    }

    #[test]
    fn test_bus_print_property_value_empty_shown() {
        let result =
            bus_print_property_value("Description", None, BusPrintPropertyFlags::SHOW_EMPTY, "");
        assert_eq!(result, Some("Description=".into()));
    }

    #[test]
    fn test_format_string_property_newline() {
        let result = format_string_property(
            "Description",
            None,
            BusPrintPropertyFlags::empty(),
            "hello\nworld",
        );
        assert_eq!(result, Some("Description=[unprintable]".into()));
    }

    #[test]
    fn test_format_boolean_property_yes_no() {
        let result =
            format_boolean_property("ReadOnly", None, BusPrintPropertyFlags::empty(), true);
        assert_eq!(result, Some("ReadOnly=yes".into()));

        let result =
            format_boolean_property("ReadOnly", None, BusPrintPropertyFlags::empty(), false);
        assert_eq!(result, Some("ReadOnly=no".into()));
    }

    #[test]
    fn test_format_boolean_property_expected_filter() {
        // Matching expected
        let result = format_boolean_property(
            "ReadOnly",
            Some("yes"),
            BusPrintPropertyFlags::empty(),
            true,
        );
        assert_eq!(result, Some("ReadOnly=yes".into()));

        // Mismatched expected
        let result =
            format_boolean_property("ReadOnly", Some("no"), BusPrintPropertyFlags::empty(), true);
        assert_eq!(result, None);
    }

    #[test]
    fn test_format_uint64_property_timestamp() {
        let result = format_uint64_property(
            "ExecMainStartTimestamp",
            None,
            BusPrintPropertyFlags::empty(),
            1_700_000_000_000_000,
        );
        assert!(
            result
                .as_deref()
                .is_some_and(|line| line.starts_with("ExecMainStartTimestamp="))
        );
    }

    #[test]
    fn test_format_uint64_property_timespan() {
        let result = format_uint64_property(
            "TimeoutStartUSec",
            None,
            BusPrintPropertyFlags::empty(),
            90_000_000,
        );
        assert_eq!(result, Some("TimeoutStartUSec=1min 30s".into()));
    }

    #[test]
    fn test_format_uint64_property_coredump_filter() {
        let result =
            format_uint64_property("CoredumpFilter", None, BusPrintPropertyFlags::empty(), 0x33);
        assert_eq!(result, Some("CoredumpFilter=0x33".into()));
    }

    #[test]
    fn test_format_uint64_property_plain() {
        let result = format_uint64_property("Nice", None, BusPrintPropertyFlags::empty(), 42);
        assert_eq!(result, Some("Nice=42".into()));
    }

    #[test]
    fn test_format_uint64_property_memory_limit_infinity() {
        let result = format_uint64_property(
            "MemoryMax",
            None,
            BusPrintPropertyFlags::empty(),
            CGROUP_LIMIT_MAX,
        );
        assert_eq!(result, Some("MemoryMax=infinity".into()));
    }

    #[test]
    fn test_format_uint64_property_memory_current_not_set() {
        let result = format_uint64_property(
            "MemoryCurrent",
            None,
            BusPrintPropertyFlags::empty(),
            u64::MAX,
        );
        assert_eq!(result, Some("MemoryCurrent=[not set]".into()));
    }

    #[test]
    fn test_format_uint64_property_io_weight_not_set() {
        let result = format_uint64_property(
            "IOWeight",
            None,
            BusPrintPropertyFlags::empty(),
            CGROUP_WEIGHT_INVALID,
        );
        assert_eq!(result, Some("IOWeight=[not set]".into()));
    }

    #[test]
    fn test_format_uint64_property_cpu_weight_idle() {
        let result = format_uint64_property(
            "CPUWeight",
            None,
            BusPrintPropertyFlags::empty(),
            CGROUP_WEIGHT_IDLE,
        );
        assert_eq!(result, Some("CPUWeight=idle".into()));
    }

    #[test]
    fn test_format_uint64_property_tasks_max_infinity() {
        let result =
            format_uint64_property("TasksMax", None, BusPrintPropertyFlags::empty(), u64::MAX);
        assert_eq!(result, Some("TasksMax=infinity".into()));
    }

    #[test]
    fn test_format_uint64_property_limit_infinity() {
        let result = format_uint64_property(
            "LimitNOFILE",
            None,
            BusPrintPropertyFlags::empty(),
            u64::MAX,
        );
        assert_eq!(result, Some("LimitNOFILE=infinity".into()));
    }

    #[test]
    fn test_format_uint64_property_oom_pressure_not_set() {
        let result = format_uint64_property(
            "ManagedOOMMemoryPressureDurationUSec",
            None,
            BusPrintPropertyFlags::empty(),
            USEC_INFINITY,
        );
        assert_eq!(
            result,
            Some("ManagedOOMMemoryPressureDurationUSec=[not set]".into())
        );
    }

    #[test]
    fn test_format_uint64_property_nsec_not_set() {
        let result = format_uint64_property(
            "WatchdogNSec",
            None,
            BusPrintPropertyFlags::empty(),
            u64::MAX,
        );
        assert_eq!(result, Some("WatchdogNSec=[not set]".into()));
    }

    #[test]
    fn test_format_uint64_property_no_data() {
        let result = format_uint64_property(
            "IPIngressBytes",
            None,
            BusPrintPropertyFlags::empty(),
            u64::MAX,
        );
        assert_eq!(result, Some("IPIngressBytes=[no data]".into()));
    }

    #[test]
    fn test_format_uint32_property_octal_mode() {
        let result = format_uint32_property("UMask", None, BusPrintPropertyFlags::empty(), 0o022);
        assert_eq!(result, Some("UMask=0022".into()));
    }

    #[test]
    fn test_format_uint32_property_file_mode() {
        let result =
            format_uint32_property("DirectoryMode", None, BusPrintPropertyFlags::empty(), 0o755);
        assert_eq!(result, Some("DirectoryMode=0755".into()));
    }

    #[test]
    fn test_format_uint32_property_uid_invalid() {
        let result =
            format_uint32_property("UID", None, BusPrintPropertyFlags::empty(), UID_INVALID);
        assert_eq!(result, Some("UID=[not set]".into()));
    }

    #[test]
    fn test_format_uint32_property_uid_valid() {
        let result = format_uint32_property("UID", None, BusPrintPropertyFlags::empty(), 1000);
        assert_eq!(result, Some("UID=1000".into()));
    }

    #[test]
    fn test_format_uint32_property_gid_invalid() {
        let result =
            format_uint32_property("GID", None, BusPrintPropertyFlags::empty(), GID_INVALID);
        assert_eq!(result, Some("GID=[not set]".into()));
    }

    #[test]
    fn test_format_uint32_property_plain() {
        let result = format_uint32_property("PID", None, BusPrintPropertyFlags::empty(), 1234);
        assert_eq!(result, Some("PID=1234".into()));
    }

    #[test]
    fn test_format_int64_property() {
        let result = format_int64_property("Nice", None, BusPrintPropertyFlags::empty(), -5);
        assert_eq!(result, Some("Nice=-5".into()));
    }

    #[test]
    fn test_format_int32_property() {
        let result = format_int32_property("Signal", None, BusPrintPropertyFlags::empty(), 9);
        assert_eq!(result, Some("Signal=9".into()));
    }

    #[test]
    fn test_format_double_property() {
        let result = format_double_property(
            "CPUUsagePerCent",
            None,
            BusPrintPropertyFlags::empty(),
            3.14,
        );
        assert_eq!(result, Some("CPUUsagePerCent=3.14".into()));
    }

    #[test]
    fn test_format_string_array_property() {
        let values = vec!["foo".into(), "bar baz".into()];
        let result =
            format_string_array_property("Wants", None, BusPrintPropertyFlags::empty(), &values);
        assert_eq!(result, Some("Wants=foo 'bar baz'".into()));
    }

    #[test]
    fn test_format_string_array_property_empty() {
        let result =
            format_string_array_property("Wants", None, BusPrintPropertyFlags::empty(), &[]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_format_string_array_property_empty_show_empty() {
        let result =
            format_string_array_property("Wants", None, BusPrintPropertyFlags::SHOW_EMPTY, &[]);
        assert_eq!(result, Some("Wants=".into()));
    }

    #[test]
    fn test_format_byte_array_property() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let result =
            format_byte_array_property("CalloutMask", None, BusPrintPropertyFlags::empty(), &bytes);
        assert_eq!(result, Some("CalloutMask=deadbeef".into()));
    }

    #[test]
    fn test_format_uint32_array_property() {
        let values = vec![0x12345678, 0xabcdef00];
        let result = format_uint32_array_property(
            "BindPaths",
            None,
            BusPrintPropertyFlags::empty(),
            &values,
        );
        assert_eq!(result, Some("BindPaths=12345678abcdef00".into()));
    }

    #[test]
    fn test_format_bus_property_dispatch_string() {
        let val = BusPropertyValue::String("active".into());
        let result = format_bus_property("ActiveState", None, &val, BusPrintPropertyFlags::empty());
        assert_eq!(
            result,
            FormatPropertyResult::Printed("ActiveState=active".into())
        );
    }

    #[test]
    fn test_format_bus_property_dispatch_boolean() {
        let val = BusPropertyValue::Boolean(true);
        let result = format_bus_property("ReadOnly", None, &val, BusPrintPropertyFlags::empty());
        assert_eq!(result, FormatPropertyResult::Printed("ReadOnly=yes".into()));
    }

    #[test]
    fn test_format_bus_property_dispatch_uint64() {
        let val = BusPropertyValue::Uint64(42);
        let result = format_bus_property("Nice", None, &val, BusPrintPropertyFlags::empty());
        assert_eq!(result, FormatPropertyResult::Printed("Nice=42".into()));
    }

    #[test]
    fn test_format_bus_property_dispatch_suppressed() {
        let val = BusPropertyValue::String("active".into());
        let result = format_bus_property(
            "ActiveState",
            Some("inactive"),
            &val,
            BusPrintPropertyFlags::empty(),
        );
        assert_eq!(result, FormatPropertyResult::Suppressed);
    }

    #[test]
    fn test_parse_boolean_variants() {
        assert_eq!(parse_boolean("1"), Some(true));
        assert_eq!(parse_boolean("yes"), Some(true));
        assert_eq!(parse_boolean("true"), Some(true));
        assert_eq!(parse_boolean("on"), Some(true));
        assert_eq!(parse_boolean("Yes"), Some(true));
        assert_eq!(parse_boolean("0"), Some(false));
        assert_eq!(parse_boolean("no"), Some(false));
        assert_eq!(parse_boolean("false"), Some(false));
        assert_eq!(parse_boolean("off"), Some(false));
        assert_eq!(parse_boolean("maybe"), None);
        assert_eq!(parse_boolean(""), None);
    }

    #[test]
    fn test_yes_no() {
        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");
    }

    #[test]
    fn test_shell_maybe_quote_simple() {
        assert_eq!(shell_maybe_quote("hello"), "hello");
        assert_eq!(shell_maybe_quote("hello-world"), "hello-world");
        assert_eq!(shell_maybe_quote("hello.world"), "hello.world");
        assert_eq!(shell_maybe_quote("/usr/bin/foo"), "/usr/bin/foo");
    }

    #[test]
    fn test_shell_maybe_quote_needs_quoting() {
        assert_eq!(shell_maybe_quote("hello world"), "'hello world'");
        assert_eq!(shell_maybe_quote(""), "''");
        assert_eq!(shell_maybe_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_format_timestamp_infinity() {
        // C timestamp_is_set() treats USEC_INFINITY as an unset timestamp.
        assert_eq!(format_timestamp(USEC_INFINITY), "");
    }

    #[test]
    fn test_format_timestamp_unset() {
        assert_eq!(format_timestamp(0), "");
    }

    #[test]
    fn test_unset_timestamp_never_matches_an_expected_string() {
        assert_eq!(
            format_uint64_property(
                "ExecMainStartTimestamp",
                Some(""),
                BusPrintPropertyFlags::SHOW_EMPTY,
                0,
            ),
            None
        );
    }

    #[test]
    fn test_format_timestamp_out_of_range() {
        assert_eq!(
            format_timestamp(253_402_214_399_000_001),
            "--- XXXX-XX-XX XX:XX:XX"
        );
    }

    #[test]
    fn test_format_timespan_infinity() {
        assert_eq!(format_timespan(USEC_INFINITY), "infinity");
    }

    #[test]
    fn test_format_timespan_c_vectors() {
        assert_eq!(format_timespan(0), "0");
        assert_eq!(format_timespan(1), "1us");
        assert_eq!(format_timespan(1_234), "1.234ms");
        assert_eq!(format_timespan(1_234_567), "1.234567s");
        assert_eq!(format_timespan(90_000_000), "1min 30s");
    }

    #[test]
    fn test_format_namespace_flags() {
        assert_eq!(format_namespace_flags(0), "yes");
        assert_eq!(format_namespace_flags(NAMESPACE_FLAGS_ALL.bits()), "no");
        assert_eq!(format_namespace_flags(NamespaceFlags::MNT.bits()), "mnt");
    }

    #[test]
    fn test_format_mount_flags() {
        assert_eq!(format_mount_flags(0), Some("".into()));
        assert_eq!(format_mount_flags(1 << 20), Some("shared".into()));
        assert_eq!(format_mount_flags(1 << 19), Some("slave".into()));
        assert_eq!(format_mount_flags(1 << 18), Some("private".into()));
        assert_eq!(format_mount_flags((1 << 20) | (1 << 19)), None);
    }

    #[test]
    fn test_format_capability_set_empty() {
        assert_eq!(format_capability_set(0), "");
    }

    #[test]
    fn test_format_capability_set_nonzero() {
        let result = format_capability_set(0xFF);
        assert_eq!(
            result,
            "cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid"
        );
    }

    #[test]
    fn test_bus_print_property_value_expected_match_none_value() {
        // expected_value is None → always passes filter
        let result = bus_print_property_value("Key", None, BusPrintPropertyFlags::empty(), "any");
        assert_eq!(result, Some("Key=any".into()));
    }

    #[test]
    fn test_format_uint64_property_memory_peak_not_set() {
        let result = format_uint64_property(
            "MemoryPeak",
            None,
            BusPrintPropertyFlags::empty(),
            CGROUP_LIMIT_MAX,
        );
        assert_eq!(result, Some("MemoryPeak=[not set]".into()));
    }

    #[test]
    fn test_format_uint64_property_io_bytes_not_set() {
        let result = format_uint64_property(
            "IOReadBytes",
            None,
            BusPrintPropertyFlags::empty(),
            u64::MAX,
        );
        assert_eq!(result, Some("IOReadBytes=[not set]".into()));
    }

    #[test]
    fn test_format_uint64_property_default_limit_infinity() {
        let result = format_uint64_property(
            "DefaultLimitNOFILE",
            None,
            BusPrintPropertyFlags::empty(),
            u64::MAX,
        );
        assert_eq!(result, Some("DefaultLimitNOFILE=infinity".into()));
    }

    #[test]
    fn test_format_uint64_property_startup_cpu_weight_idle() {
        let result = format_uint64_property(
            "StartupCPUWeight",
            None,
            BusPrintPropertyFlags::empty(),
            CGROUP_WEIGHT_IDLE,
        );
        assert_eq!(result, Some("StartupCPUWeight=idle".into()));
    }
}
