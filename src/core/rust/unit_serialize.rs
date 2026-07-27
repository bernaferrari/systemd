// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit-serialize.c
//
// Unit serialization and deserialization helpers.
//
// Provides marker bitmask serialization, unit dependency mask printing,
// key-value line parsing for serialization streams, and the skip-to-
// end-marker logic used when deserializing unknown unit data.

// ── Unit marker enum ──────────────────────────────────────────────────────

/// Unit marker types, used as bitmask flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitMarker {
    NeedsReload = 0,
    NeedsRestart = 1,
}

static UNIT_MARKER_TABLE: &[&str] = &["needs-reload", "needs-restart"];

const MARKER_COUNT: u32 = 2;

// ── Marker serialization ─────────────────────────────────────────────────

/// Serialize a marker bitmask into a space-separated string.
///
/// Port of `serialize_markers()` from unit-serialize.c.
pub fn serialize_markers(markers: u32) -> Result<String, i32> {
    if markers == 0 {
        return Ok(String::new());
    }

    let mut parts: Vec<&str> = Vec::new();
    for bit in 0..MARKER_COUNT {
        if markers & (1u32 << bit) != 0 {
            let name = UNIT_MARKER_TABLE.get(bit as usize).ok_or(-22)?;
            parts.push(name);
        }
    }

    Ok(parts.join(" "))
}

/// Deserialize a marker bitmask from a space-separated string.
///
/// Port of `deserialize_markers()` from unit-serialize.c.
pub fn deserialize_markers(value: &str) -> Result<u32, i32> {
    let mut markers: u32 = 0;

    if value.is_empty() {
        return Ok(0);
    }

    for word in value.split_whitespace() {
        let idx = UNIT_MARKER_TABLE
            .iter()
            .position(|entry| *entry == word)
            .ok_or(-22)?;
        markers |= 1u32 << idx;
    }

    Ok(markers)
}

/// Convert a unit marker to its string representation.
pub fn unit_marker_to_string(m: UnitMarker) -> Result<&'static str, i32> {
    UNIT_MARKER_TABLE.get(m as usize).copied().ok_or(-22)
}

/// Parse a unit marker from its string representation.
pub fn unit_marker_from_string(s: &str) -> Result<UnitMarker, i32> {
    match s {
        "needs-reload" => Ok(UnitMarker::NeedsReload),
        "needs-restart" => Ok(UnitMarker::NeedsRestart),
        _ => Err(-22),
    }
}

// ── Dependency mask ───────────────────────────────────────────────────────

/// Unit dependency origin masks.
///
/// Port of `UnitDependencyMask` from unit.h and the
/// `print_unit_dependency_mask()` table in unit-serialize.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitDependencyMask(u32);

impl UnitDependencyMask {
    pub const FILE: Self = Self(1 << 0);
    pub const IMPLICIT: Self = Self(1 << 1);
    pub const DEFAULT: Self = Self(1 << 2);
    pub const UDEV: Self = Self(1 << 3);
    pub const PATH: Self = Self(1 << 4);
    pub const MOUNT_FILE: Self = Self(1 << 5);
    pub const MOUNTINFO: Self = Self(1 << 6);
    pub const PROC_SWAP: Self = Self(1 << 7);
    pub const SLICE_PROPERTY: Self = Self(1 << 8);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }
}

impl std::ops::BitOr for UnitDependencyMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

static DEPENDENCY_MASK_TABLE: &[(UnitDependencyMask, &str)] = &[
    (UnitDependencyMask::FILE, "file"),
    (UnitDependencyMask::IMPLICIT, "implicit"),
    (UnitDependencyMask::DEFAULT, "default"),
    (UnitDependencyMask::UDEV, "udev"),
    (UnitDependencyMask::PATH, "path"),
    (UnitDependencyMask::MOUNT_FILE, "mount-file"),
    (UnitDependencyMask::MOUNTINFO, "mountinfo"),
    (UnitDependencyMask::PROC_SWAP, "proc-swap"),
    (UnitDependencyMask::SLICE_PROPERTY, "slice-property"),
];

/// Print a unit dependency mask as a formatted string with kind prefix.
///
/// Port of `print_unit_dependency_mask()` from unit-serialize.c.
/// Produces space-separated tokens like "origin-file destination-implicit".
pub fn format_dependency_mask(kind: &str, mask: UnitDependencyMask) -> Result<String, i32> {
    let mut parts: Vec<String> = Vec::new();
    let mut remaining = mask.bits();

    for &(flag, name) in DEPENDENCY_MASK_TABLE {
        if remaining == 0 {
            break;
        }
        if mask.contains(flag) {
            parts.push(format!("{}-{}", kind, name));
            remaining &= !flag.bits();
        }
    }

    // All bits should have been accounted for
    if remaining != 0 {
        return Err(-22);
    }

    Ok(parts.join(" "))
}

// ── Key-value line parsing ────────────────────────────────────────────────

/// A parsed serialization line split into key and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

impl KeyValue {
    /// Parse a serialization line into key and value.
    ///
    /// Lines use `key=value` format. If no `=` is present, the entire
    /// line is the key and the value is empty.
    pub fn parse(line: &str) -> Self {
        if let Some(eq_pos) = line.find('=') {
            KeyValue {
                key: line[..eq_pos].to_string(),
                value: line[eq_pos + 1..].to_string(),
            }
        } else {
            KeyValue {
                key: line.to_string(),
                value: String::new(),
            }
        }
    }
}

// ── Deserialize state skip ────────────────────────────────────────────────

/// Skip serialized data for a unit until the end marker (empty line).
///
/// Port of `unit_deserialize_state_skip()` from unit-serialize.c.
/// Returns Ok(count) with the number of lines skipped (including the
/// end marker line), or Err if input is malformed.
pub fn deserialize_skip_lines(lines: &[&str]) -> Result<usize, i32> {
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(i + 1);
        }
    }
    // No end marker found
    Err(-22)
}

// ── Serialize key-value helper ────────────────────────────────────────────

/// Format a key-value pair for serialization output.
pub fn serialize_kv(key: &str, value: &str) -> String {
    format!("{}={}", key, value)
}

/// Format a boolean for serialization.
pub fn serialize_bool(key: &str, val: bool) -> String {
    serialize_kv(key, if val { "yes" } else { "no" })
}

// ── Known serialization keys ──────────────────────────────────────────────

/// Recognized serialization key types for unit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeKey {
    Job,
    StateChangeTimestamp,
    InactiveExitTimestamp,
    ActiveEnterTimestamp,
    ActiveExitTimestamp,
    InactiveEnterTimestamp,
    ConditionTimestamp,
    AssertTimestamp,
    StartRatelimit,
    AutoStartStopRatelimit,
    ConditionResult,
    AssertResult,
    Transient,
    InAudit,
    DebugInvocation,
    ExportedInvocationId,
    ExportedLogLevelMax,
    ExportedLogExtraFields,
    ExportedLogRateLimitInterval,
    ExportedLogRateLimitBurst,
    RefUid,
    RefGid,
    Ref,
    InvocationId,
    FreezerState,
    Markers,
    Unknown,
}

static SERIALIZE_KEY_TABLE: &[(&str, SerializeKey)] = &[
    ("job", SerializeKey::Job),
    ("state-change-timestamp", SerializeKey::StateChangeTimestamp),
    (
        "inactive-exit-timestamp",
        SerializeKey::InactiveExitTimestamp,
    ),
    ("active-enter-timestamp", SerializeKey::ActiveEnterTimestamp),
    ("active-exit-timestamp", SerializeKey::ActiveExitTimestamp),
    (
        "inactive-enter-timestamp",
        SerializeKey::InactiveEnterTimestamp,
    ),
    ("condition-timestamp", SerializeKey::ConditionTimestamp),
    ("assert-timestamp", SerializeKey::AssertTimestamp),
    ("start-ratelimit", SerializeKey::StartRatelimit),
    (
        "auto-start-stop-ratelimit",
        SerializeKey::AutoStartStopRatelimit,
    ),
    ("condition-result", SerializeKey::ConditionResult),
    ("assert-result", SerializeKey::AssertResult),
    ("transient", SerializeKey::Transient),
    ("in-audit", SerializeKey::InAudit),
    ("debug-invocation", SerializeKey::DebugInvocation),
    ("exported-invocation-id", SerializeKey::ExportedInvocationId),
    ("exported-log-level-max", SerializeKey::ExportedLogLevelMax),
    (
        "exported-log-extra-fields",
        SerializeKey::ExportedLogExtraFields,
    ),
    (
        "exported-log-rate-limit-interval",
        SerializeKey::ExportedLogRateLimitInterval,
    ),
    (
        "exported-log-rate-limit-burst",
        SerializeKey::ExportedLogRateLimitBurst,
    ),
    ("ref-uid", SerializeKey::RefUid),
    ("ref-gid", SerializeKey::RefGid),
    ("ref", SerializeKey::Ref),
    ("invocation-id", SerializeKey::InvocationId),
    ("freezer-state", SerializeKey::FreezerState),
    ("markers", SerializeKey::Markers),
];

/// Look up a serialization key name.
pub fn classify_serialize_key(key: &str) -> SerializeKey {
    SERIALIZE_KEY_TABLE
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, sk)| *sk)
        .unwrap_or(SerializeKey::Unknown)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_markers_empty() {
        assert_eq!(serialize_markers(0).unwrap(), "");
    }

    #[test]
    fn test_serialize_markers_single() {
        assert_eq!(serialize_markers(1).unwrap(), "needs-reload");
        assert_eq!(serialize_markers(2).unwrap(), "needs-restart");
    }

    #[test]
    fn test_serialize_markers_both() {
        assert_eq!(serialize_markers(3).unwrap(), "needs-reload needs-restart");
    }

    #[test]
    fn test_deserialize_markers_roundtrip() {
        for markers in 0u32..4 {
            let serialized = serialize_markers(markers).unwrap();
            let deserialized = deserialize_markers(&serialized).unwrap();
            assert_eq!(deserialized, markers);
        }
    }

    #[test]
    fn test_deserialize_markers_invalid() {
        assert!(deserialize_markers("bogus").is_err());
    }

    #[test]
    fn test_deserialize_markers_empty() {
        assert_eq!(deserialize_markers("").unwrap(), 0);
    }

    #[test]
    fn test_unit_marker_to_string() {
        assert_eq!(
            unit_marker_to_string(UnitMarker::NeedsReload).unwrap(),
            "needs-reload"
        );
        assert_eq!(
            unit_marker_to_string(UnitMarker::NeedsRestart).unwrap(),
            "needs-restart"
        );
    }

    #[test]
    fn test_unit_marker_from_string() {
        assert_eq!(
            unit_marker_from_string("needs-reload").unwrap(),
            UnitMarker::NeedsReload
        );
        assert_eq!(
            unit_marker_from_string("needs-restart").unwrap(),
            UnitMarker::NeedsRestart
        );
        assert!(unit_marker_from_string("bogus").is_err());
    }

    #[test]
    fn test_format_dependency_mask_single() {
        let result = format_dependency_mask("origin", UnitDependencyMask::FILE).unwrap();
        assert_eq!(result, "origin-file");
    }

    #[test]
    fn test_format_dependency_mask_multiple() {
        let result = format_dependency_mask(
            "origin",
            UnitDependencyMask::FILE | UnitDependencyMask::IMPLICIT,
        )
        .unwrap();
        assert_eq!(result, "origin-file origin-implicit");
    }

    #[test]
    fn test_format_dependency_mask_all() {
        let all = UnitDependencyMask::FILE
            | UnitDependencyMask::IMPLICIT
            | UnitDependencyMask::DEFAULT
            | UnitDependencyMask::UDEV
            | UnitDependencyMask::PATH
            | UnitDependencyMask::MOUNT_FILE
            | UnitDependencyMask::MOUNTINFO
            | UnitDependencyMask::PROC_SWAP
            | UnitDependencyMask::SLICE_PROPERTY;
        let result = format_dependency_mask("dest", all).unwrap();
        assert!(result.contains("dest-file"));
        assert!(result.contains("dest-slice-property"));
    }

    #[test]
    fn test_format_dependency_mask_unknown_bit() {
        // Bit not in the table should cause an error
        let result =
            format_dependency_mask("origin", UnitDependencyMask::from_bits_retain(1 << 30));
        assert!(result.is_err());
    }

    #[test]
    fn test_key_value_parse_with_equals() {
        let kv = KeyValue::parse("state-change-timestamp=12345");
        assert_eq!(kv.key, "state-change-timestamp");
        assert_eq!(kv.value, "12345");
    }

    #[test]
    fn test_key_value_parse_no_equals() {
        let kv = KeyValue::parse("end-marker");
        assert_eq!(kv.key, "end-marker");
        assert_eq!(kv.value, "");
    }

    #[test]
    fn test_key_value_parse_empty_value() {
        let kv = KeyValue::parse("key=");
        assert_eq!(kv.key, "key");
        assert_eq!(kv.value, "");
    }

    #[test]
    fn test_deserialize_skip_lines_with_end() {
        let lines = &["key1=val1", "key2=val2", "", "next-section"];
        let count = deserialize_skip_lines(lines).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_deserialize_skip_lines_immediate_end() {
        let lines = &["", "next-section"];
        let count = deserialize_skip_lines(lines).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_deserialize_skip_lines_no_end() {
        let lines = &["key1=val1", "key2=val2"];
        assert!(deserialize_skip_lines(lines).is_err());
    }

    #[test]
    fn test_serialize_kv() {
        assert_eq!(serialize_kv("key", "value"), "key=value");
        assert_eq!(serialize_kv("a", "b"), "a=b");
    }

    #[test]
    fn test_serialize_bool() {
        assert_eq!(serialize_bool("transient", true), "transient=yes");
        assert_eq!(serialize_bool("transient", false), "transient=no");
    }

    #[test]
    fn test_classify_serialize_key_known() {
        assert_eq!(classify_serialize_key("job"), SerializeKey::Job);
        assert_eq!(classify_serialize_key("markers"), SerializeKey::Markers);
        assert_eq!(classify_serialize_key("transient"), SerializeKey::Transient);
        assert_eq!(
            classify_serialize_key("invocation-id"),
            SerializeKey::InvocationId
        );
    }

    #[test]
    fn test_classify_serialize_key_unknown() {
        assert_eq!(classify_serialize_key("unknown-key"), SerializeKey::Unknown);
    }
}
