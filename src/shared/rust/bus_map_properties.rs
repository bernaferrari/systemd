// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-map-properties.c, src/shared/bus-map-properties.h
//
// D-Bus property mapping — maps D-Bus property dictionaries to structured data.
//
// Provides generic D-Bus property-to-struct-field mapping via a property map
// table. Supports basic D-Bus types (string, boolean, int32/64, uint32/64,
// double, string arrays) and custom setters for id128, sorted string vectors,
// and job IDs.

use std::collections::BTreeMap;
use std::fmt;

// ── Error types ────────────────────────────────────────────────────────────

/// Errors that can occur during D-Bus property mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusMapError {
    /// The D-Bus type signature is not supported for automatic mapping.
    UnsupportedType(char),
    /// A required property member was not found.
    MemberNotFound(String),
    /// The property data is invalid or could not be parsed.
    InvalidData(String),
    /// A null/empty string was encountered where a value was expected.
    NullString,
    /// The property map table entry has no matching setter.
    NoSetter(String),
}

impl fmt::Display for BusMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedType(c) => write!(f, "unsupported D-Bus type: '{c}'"),
            Self::MemberNotFound(m) => write!(f, "property member not found: {m}"),
            Self::InvalidData(s) => write!(f, "invalid property data: {s}"),
            Self::NullString => write!(f, "null/empty string where value expected"),
            Self::NoSetter(m) => write!(f, "no setter for property: {m}"),
        }
    }
}

impl std::error::Error for BusMapError {}

// ── Flags ──────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling how D-Bus property values are mapped.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BusMapFlags: u32 {
        /// Duplicate strings (allocate new memory) rather than referencing.
        ///
        /// In C this controls whether `free_and_strdup` is used versus a
        /// direct pointer assignment. In Rust, `String` is always owned, so
        /// this flag is a no-op but retained for API compatibility.
        const STRDUP = 1 << 0;
        /// Store boolean values as `bool` instead of `i32`.
        const BOOLEAN_AS_BOOL = 1 << 1;
    }
}

// ── D-Bus type signature constants ─────────────────────────────────────────

/// D-Bus type signature characters used in property mapping.
pub mod dbus_type {
    /// D-Bus `STRING`.
    pub const STRING: char = 's';
    /// D-Bus `OBJECT_PATH`.
    pub const OBJECT_PATH: char = 'o';
    /// D-Bus `BOOLEAN`.
    pub const BOOLEAN: char = 'b';
    /// D-Bus `INT32`.
    pub const INT32: char = 'i';
    /// D-Bus `UINT32`.
    pub const UINT32: char = 'u';
    /// D-Bus `INT64`.
    pub const INT64: char = 'x';
    /// D-Bus `UINT64`.
    pub const UINT64: char = 't';
    /// D-Bus `DOUBLE`.
    pub const DOUBLE: char = 'd';
    /// D-Bus `ARRAY`.
    pub const ARRAY: char = 'a';
    /// D-Bus `VARIANT`.
    pub const VARIANT: char = 'v';
    /// D-Bus `DICT_ENTRY`.
    pub const DICT_ENTRY: char = 'e';
    /// D-Bus `BYTE`.
    pub const BYTE: char = 'y';
}

// ── Property value ─────────────────────────────────────────────────────────

/// Represents a D-Bus property value extracted from a message.
///
/// Covers the basic D-Bus types used in property mappings. Custom types
/// (id128, job IDs) are handled by dedicated setter functions that accept
/// [`PropertyValue`] and return [`MappedValue`].
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyValue {
    /// D-Bus `STRING` or `OBJECT_PATH`.
    String(String),
    /// D-Bus `BOOLEAN` (stored as `i32` matching the wire format).
    Boolean(i32),
    /// D-Bus `INT32` or `UINT32` (C `map_basic` stores both into `uint32_t`).
    Uint32(u32),
    /// D-Bus `INT64` or `UINT64` (C `map_basic` stores both into `uint64_t`).
    Int64(i64),
    /// D-Bus `DOUBLE`.
    Double(f64),
    /// D-Bus array of strings (`as`).
    StringArray(Vec<String>),
    /// A raw byte array (`ay`), used for id128 and similar fixed-size types.
    ByteArray(Vec<u8>),
}

impl PropertyValue {
    /// Returns the D-Bus type signature character for this value.
    pub fn type_char(&self) -> char {
        match self {
            Self::String(_) => dbus_type::STRING,
            Self::Boolean(_) => dbus_type::BOOLEAN,
            Self::Uint32(_) => dbus_type::UINT32,
            Self::Int64(_) => dbus_type::INT64,
            Self::Double(_) => dbus_type::DOUBLE,
            Self::StringArray(_) => dbus_type::ARRAY,
            Self::ByteArray(_) => dbus_type::ARRAY,
        }
    }

    /// Try to extract as a string, converting empty strings to `None`.
    ///
    /// This mirrors the C `empty_to_null()` pattern where empty strings
    /// are treated as absent values.
    pub fn as_optional_string(&self) -> Option<&str> {
        match self {
            Self::String(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }

    /// Try to extract as a boolean (any non-zero `i32` is `true`).
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(b) => Some(*b != 0),
            _ => None,
        }
    }

    /// Try to extract as `u32`.
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Uint32(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to extract as `i64`.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int64(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to extract as `f64`.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Double(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to extract as a string array reference.
    pub fn as_string_array(&self) -> Option<&[String]> {
        match self {
            Self::StringArray(v) => Some(v),
            _ => None,
        }
    }

    /// Try to extract as a byte array reference.
    pub fn as_byte_array(&self) -> Option<&[u8]> {
        match self {
            Self::ByteArray(v) => Some(v),
            _ => None,
        }
    }
}

// ── Mapped value ───────────────────────────────────────────────────────────

/// The result of mapping a D-Bus property value — the extracted typed value.
///
/// This is the output of both [`map_basic`] and custom setter functions.
#[derive(Debug, Clone, PartialEq)]
pub enum MappedValue {
    /// A mapped string property.
    String(String),
    /// A mapped boolean property.
    Bool(bool),
    /// A mapped 32-bit unsigned integer property.
    Uint32(u32),
    /// A mapped 64-bit signed integer property.
    Int64(i64),
    /// A mapped double-precision float property.
    Double(f64),
    /// A mapped string array property.
    StringArray(Vec<String>),
    /// A mapped 128-bit identifier.
    Id128([u8; 16]),
    /// A mapped job ID extracted from a `(uo)` tuple.
    JobId(u32),
}

// ── Property map entry ─────────────────────────────────────────────────────

/// A single entry in a property mapping table.
///
/// Each entry associates a D-Bus property member name with an optional custom
/// setter function. When no setter is provided, [`map_basic`] handles the
/// property based on its D-Bus type signature.
///
/// This is the Rust equivalent of C's `struct bus_properties_map`, without
/// the `offset` field (offset-based struct patching is inherently unsafe
/// and unnecessary in idiomatic Rust).
#[derive(Debug, Clone, Copy)]
pub struct PropertyMapEntry {
    /// The D-Bus property member name (e.g., `"Description"`).
    pub member: &'static str,
    /// Optional custom setter function. When `None`, basic type mapping is used.
    pub set: Option<fn(&str, &PropertyValue) -> Result<MappedValue, BusMapError>>,
}

// ── Basic type mapping ─────────────────────────────────────────────────────

/// Map a basic D-Bus property value based on its type.
///
/// Handles `STRING`, `OBJECT_PATH`, `BOOLEAN`, `INT32`, `UINT32`,
/// `INT64`, `UINT64`, `DOUBLE`, and string arrays.
///
/// Returns [`BusMapError::UnsupportedType`] for byte arrays and any other
/// type that requires a custom setter.
///
/// This corresponds to the C function `map_basic()`.
pub fn map_basic(value: &PropertyValue, flags: BusMapFlags) -> Result<MappedValue, BusMapError> {
    match value {
        // STRING / OBJECT_PATH: empty strings become empty String (mirrors empty_to_null).
        // In Rust, String is always owned, so BUS_MAP_STRDUP is a no-op.
        PropertyValue::String(s) => Ok(MappedValue::String(s.clone())),

        // BOOLEAN: always stored as bool (C stores as int or bool based on flag).
        PropertyValue::Boolean(b) => Ok(MappedValue::Bool(*b != 0)),

        // INT32 / UINT32
        PropertyValue::Uint32(v) => Ok(MappedValue::Uint32(*v)),

        // INT64 / UINT64
        PropertyValue::Int64(v) => Ok(MappedValue::Int64(*v)),

        // DOUBLE
        PropertyValue::Double(v) => Ok(MappedValue::Double(*v)),

        // String array (as) — read via sd_bus_message_read_strv_extend in C
        PropertyValue::StringArray(arr) => Ok(MappedValue::StringArray(arr.clone())),

        // Byte arrays require custom handling (e.g., id128)
        PropertyValue::ByteArray(_) => Err(BusMapError::UnsupportedType(dbus_type::ARRAY)),
    }
}

// ── Custom setters ─────────────────────────────────────────────────────────

/// Map a 128-bit ID from a byte array property value.
///
/// The input must be a `ByteArray` of exactly 16 bytes, corresponding to
/// the D-Bus `ay` representation of `sd_id128_t`.
///
/// This corresponds to the C function `bus_map_id128()`.
pub fn bus_map_id128(_member: &str, value: &PropertyValue) -> Result<MappedValue, BusMapError> {
    match value {
        PropertyValue::ByteArray(bytes) if bytes.len() == 16 => {
            let mut id = [0u8; 16];
            id.copy_from_slice(bytes);
            Ok(MappedValue::Id128(id))
        }
        PropertyValue::ByteArray(bytes) => Err(BusMapError::InvalidData(format!(
            "id128 requires exactly 16 bytes, got {}",
            bytes.len()
        ))),
        _ => Err(BusMapError::InvalidData(
            "id128 property is not a byte array".into(),
        )),
    }
}

/// Map a string array property value, sorting the result.
///
/// Reads a D-Bus string array (`as`) and returns the strings sorted
/// in lexicographic order. This mirrors the C `bus_map_strv_sort()`
/// which calls `sd_bus_message_read_strv_extend` followed by `strv_sort`.
pub fn bus_map_strv_sort(_member: &str, value: &PropertyValue) -> Result<MappedValue, BusMapError> {
    match value {
        PropertyValue::StringArray(arr) => {
            let mut sorted = arr.clone();
            sorted.sort();
            Ok(MappedValue::StringArray(sorted))
        }
        _ => Err(BusMapError::InvalidData(
            "strv property is not a string array".into(),
        )),
    }
}

/// Map a job ID from a structured property value.
///
/// In C, this reads a `(uo)` D-Bus struct containing a uint32 job ID
/// and an object path (which is discarded). In the pure Rust model, the
/// caller should pre-extract the uint32 component.
///
/// This corresponds to the C function `bus_map_job_id()`.
pub fn bus_map_job_id(_member: &str, value: &PropertyValue) -> Result<MappedValue, BusMapError> {
    match value {
        PropertyValue::Uint32(id) => Ok(MappedValue::JobId(*id)),
        _ => Err(BusMapError::InvalidData(
            "job ID property is not a uint32".into(),
        )),
    }
}

// ── Map all properties ─────────────────────────────────────────────────────

/// Result of mapping all properties from a D-Bus property dictionary.
///
/// Contains all successfully mapped properties keyed by member name,
/// and a list of members that were in the message but not in the map table.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MapAllResult {
    /// Properties that were successfully mapped.
    pub mapped: BTreeMap<String, MappedValue>,
    /// Property names that appeared in the message but had no map entry.
    pub skipped: Vec<String>,
}

/// Map all properties from a D-Bus property dictionary using a property map table.
///
/// For each property in `properties`:
/// - If the member name exists in `map` and has a custom setter, the setter is called.
/// - If the member name exists in `map` with no custom setter, [`map_basic`] is used.
/// - If the member name is not in `map`, the property is added to [`skipped`](MapAllResult::skipped).
///
/// This corresponds to the C function `bus_message_map_all_properties()`.
pub fn bus_message_map_all_properties(
    properties: &BTreeMap<String, PropertyValue>,
    map: &[PropertyMapEntry],
    flags: BusMapFlags,
) -> Result<MapAllResult, BusMapError> {
    let mut result = MapAllResult::default();

    for (member, value) in properties {
        let entry = map.iter().find(|e| e.member == member);

        if let Some(entry) = entry {
            let mapped = if let Some(setter) = entry.set {
                setter(member, value)?
            } else {
                map_basic(value, flags)?
            };
            result.mapped.insert(member.clone(), mapped);
        } else {
            result.skipped.push(member.clone());
        }
    }

    Ok(result)
}

/// Extract and map all properties from a D-Bus property dictionary.
///
/// This is the high-level entry point corresponding to the C function
/// `bus_map_all_properties()`. In C, this calls
/// `org.freedesktop.DBus.Properties.GetAll` and then processes the reply.
/// In the pure Rust model, the caller provides the pre-extracted property
/// dictionary and the mapping is done by [`bus_message_map_all_properties`].
pub fn bus_map_all_properties(
    properties: BTreeMap<String, PropertyValue>,
    map: &[PropertyMapEntry],
    flags: BusMapFlags,
) -> Result<MapAllResult, BusMapError> {
    bus_message_map_all_properties(&properties, map, flags)
}

// ── Typed accessors ────────────────────────────────────────────────────────

/// Look up a mapped string value by member name.
pub fn get_mapped_string<'a>(result: &'a MapAllResult, member: &str) -> Option<&'a str> {
    result.mapped.get(member).and_then(|v| match v {
        MappedValue::String(s) => Some(s.as_str()),
        _ => None,
    })
}

/// Look up a mapped boolean value by member name.
pub fn get_mapped_bool(result: &MapAllResult, member: &str) -> Option<bool> {
    result.mapped.get(member).and_then(|v| match v {
        MappedValue::Bool(b) => Some(*b),
        _ => None,
    })
}

/// Look up a mapped `u32` value by member name.
///
/// Also matches [`MappedValue::JobId`] since job IDs are semantically uint32.
pub fn get_mapped_u32(result: &MapAllResult, member: &str) -> Option<u32> {
    result.mapped.get(member).and_then(|v| match v {
        MappedValue::Uint32(n) => Some(*n),
        MappedValue::JobId(n) => Some(*n),
        _ => None,
    })
}

/// Look up a mapped `i64` value by member name.
pub fn get_mapped_i64(result: &MapAllResult, member: &str) -> Option<i64> {
    result.mapped.get(member).and_then(|v| match v {
        MappedValue::Int64(n) => Some(*n),
        _ => None,
    })
}

/// Look up a mapped `f64` value by member name.
pub fn get_mapped_f64(result: &MapAllResult, member: &str) -> Option<f64> {
    result.mapped.get(member).and_then(|v| match v {
        MappedValue::Double(d) => Some(*d),
        _ => None,
    })
}

/// Look up a mapped string array by member name.
pub fn get_mapped_string_array<'a>(result: &'a MapAllResult, member: &str) -> Option<&'a [String]> {
    result.mapped.get(member).and_then(|v| match v {
        MappedValue::StringArray(arr) => Some(arr.as_slice()),
        _ => None,
    })
}

/// Look up a mapped id128 by member name.
pub fn get_mapped_id128(result: &MapAllResult, member: &str) -> Option<[u8; 16]> {
    result.mapped.get(member).and_then(|v| match v {
        MappedValue::Id128(id) => Some(*id),
        _ => None,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PropertyValue ───────────────────────────────────────────────────────

    #[test]
    fn test_property_value_type_char() {
        assert_eq!(PropertyValue::String("x".into()).type_char(), 's');
        assert_eq!(PropertyValue::Boolean(1).type_char(), 'b');
        assert_eq!(PropertyValue::Uint32(42).type_char(), 'u');
        assert_eq!(PropertyValue::Int64(-1).type_char(), 'x');
        assert_eq!(PropertyValue::Double(3.14).type_char(), 'd');
        assert_eq!(PropertyValue::StringArray(vec![]).type_char(), 'a');
        assert_eq!(PropertyValue::ByteArray(vec![]).type_char(), 'a');
    }

    #[test]
    fn test_property_value_as_optional_string() {
        assert_eq!(
            PropertyValue::String("hello".into()).as_optional_string(),
            Some("hello")
        );
        assert_eq!(PropertyValue::String("".into()).as_optional_string(), None);
        assert_eq!(PropertyValue::Boolean(1).as_optional_string(), None);
    }

    #[test]
    fn test_property_value_as_bool() {
        assert_eq!(PropertyValue::Boolean(1).as_bool(), Some(true));
        assert_eq!(PropertyValue::Boolean(0).as_bool(), Some(false));
        assert_eq!(PropertyValue::Boolean(-1).as_bool(), Some(true));
        assert_eq!(PropertyValue::String("x".into()).as_bool(), None);
    }

    #[test]
    fn test_property_value_numeric_accessors() {
        assert_eq!(PropertyValue::Uint32(42).as_u32(), Some(42));
        assert!(PropertyValue::String("x".into()).as_u32().is_none());

        assert_eq!(PropertyValue::Int64(-100).as_i64(), Some(-100));
        assert!(PropertyValue::Boolean(0).as_i64().is_none());

        assert_eq!(PropertyValue::Double(3.14).as_f64(), Some(3.14));
        assert!(PropertyValue::Uint32(0).as_f64().is_none());
    }

    #[test]
    fn test_property_value_array_accessors() {
        let arr = vec!["a".into(), "b".into()];
        assert_eq!(
            PropertyValue::StringArray(arr.clone()).as_string_array(),
            Some(arr.as_slice())
        );
        assert!(PropertyValue::Boolean(0).as_string_array().is_none());

        let bytes = vec![0u8; 16];
        assert_eq!(
            PropertyValue::ByteArray(bytes.clone()).as_byte_array(),
            Some(bytes.as_slice())
        );
        assert!(PropertyValue::String("x".into()).as_byte_array().is_none());
    }

    // ── map_basic ───────────────────────────────────────────────────────────

    #[test]
    fn test_map_basic_string() {
        let val = PropertyValue::String("test".into());
        let result = map_basic(&val, BusMapFlags::empty()).unwrap();
        assert_eq!(result, MappedValue::String("test".into()));
    }

    #[test]
    fn test_map_basic_empty_string() {
        let val = PropertyValue::String("".into());
        let result = map_basic(&val, BusMapFlags::empty()).unwrap();
        assert_eq!(result, MappedValue::String("".into()));
    }

    #[test]
    fn test_map_basic_string_with_strdup_flag() {
        let val = PropertyValue::String("test".into());
        // STRDUP is a no-op in Rust (String is always owned), but should not error
        let result = map_basic(&val, BusMapFlags::STRDUP).unwrap();
        assert_eq!(result, MappedValue::String("test".into()));
    }

    #[test]
    fn test_map_basic_boolean_true() {
        let val = PropertyValue::Boolean(1);
        let result = map_basic(&val, BusMapFlags::empty()).unwrap();
        assert_eq!(result, MappedValue::Bool(true));
    }

    #[test]
    fn test_map_basic_boolean_false() {
        let val = PropertyValue::Boolean(0);
        let result = map_basic(&val, BusMapFlags::empty()).unwrap();
        assert_eq!(result, MappedValue::Bool(false));
    }

    #[test]
    fn test_map_basic_boolean_negative() {
        // Any non-zero i32 is true (C boolean semantics)
        let val = PropertyValue::Boolean(-1);
        let result = map_basic(&val, BusMapFlags::BOOLEAN_AS_BOOL).unwrap();
        assert_eq!(result, MappedValue::Bool(true));
    }

    #[test]
    fn test_map_basic_uint32() {
        let val = PropertyValue::Uint32(12345);
        let result = map_basic(&val, BusMapFlags::empty()).unwrap();
        assert_eq!(result, MappedValue::Uint32(12345));
    }

    #[test]
    fn test_map_basic_int64() {
        let val = PropertyValue::Int64(-999);
        let result = map_basic(&val, BusMapFlags::empty()).unwrap();
        assert_eq!(result, MappedValue::Int64(-999));
    }

    #[test]
    fn test_map_basic_double() {
        let val = PropertyValue::Double(2.718);
        let result = map_basic(&val, BusMapFlags::empty()).unwrap();
        assert_eq!(result, MappedValue::Double(2.718));
    }

    #[test]
    fn test_map_basic_string_array() {
        let val = PropertyValue::StringArray(vec!["b".into(), "a".into()]);
        let result = map_basic(&val, BusMapFlags::empty()).unwrap();
        // map_basic preserves order; sorting is done by bus_map_strv_sort
        assert_eq!(
            result,
            MappedValue::StringArray(vec!["b".into(), "a".into()])
        );
    }

    #[test]
    fn test_map_basic_byte_array_unsupported() {
        let val = PropertyValue::ByteArray(vec![0; 16]);
        let err = map_basic(&val, BusMapFlags::empty()).unwrap_err();
        assert_eq!(err, BusMapError::UnsupportedType('a'));
    }

    // ── bus_map_id128 ───────────────────────────────────────────────────────

    #[test]
    fn test_bus_map_id128_valid() {
        let bytes: Vec<u8> = (0..16).collect();
        let val = PropertyValue::ByteArray(bytes.clone());
        let result = bus_map_id128("InvocationID", &val).unwrap();
        let expected: [u8; 16] = bytes.try_into().unwrap();
        assert_eq!(result, MappedValue::Id128(expected));
    }

    #[test]
    fn test_bus_map_id128_null() {
        let val = PropertyValue::ByteArray(vec![0u8; 16]);
        let result = bus_map_id128("BootID", &val).unwrap();
        assert_eq!(result, MappedValue::Id128([0u8; 16]));
    }

    #[test]
    fn test_bus_map_id128_wrong_length() {
        let val = PropertyValue::ByteArray(vec![0; 8]);
        let err = bus_map_id128("Id", &val).unwrap_err();
        assert!(matches!(err, BusMapError::InvalidData(msg) if msg.contains("16 bytes")));
    }

    #[test]
    fn test_bus_map_id128_not_byte_array() {
        let val = PropertyValue::String("not-bytes".into());
        let err = bus_map_id128("Id", &val).unwrap_err();
        assert!(matches!(err, BusMapError::InvalidData(_)));
    }

    // ── bus_map_strv_sort ───────────────────────────────────────────────────

    #[test]
    fn test_bus_map_strv_sort_sorts() {
        let val = PropertyValue::StringArray(vec![
            "z.target".into(),
            "a.target".into(),
            "m.target".into(),
        ]);
        let result = bus_map_strv_sort("Wants", &val).unwrap();
        assert_eq!(
            result,
            MappedValue::StringArray(vec![
                "a.target".into(),
                "m.target".into(),
                "z.target".into(),
            ])
        );
    }

    #[test]
    fn test_bus_map_strv_sort_empty() {
        let val = PropertyValue::StringArray(vec![]);
        let result = bus_map_strv_sort("Wants", &val).unwrap();
        assert_eq!(result, MappedValue::StringArray(vec![]));
    }

    #[test]
    fn test_bus_map_strv_sort_already_sorted() {
        let val = PropertyValue::StringArray(vec!["a".into(), "b".into(), "c".into()]);
        let result = bus_map_strv_sort("After", &val).unwrap();
        assert_eq!(
            result,
            MappedValue::StringArray(vec!["a".into(), "b".into(), "c".into()])
        );
    }

    #[test]
    fn test_bus_map_strv_sort_wrong_type() {
        let val = PropertyValue::Boolean(1);
        let err = bus_map_strv_sort("Wants", &val).unwrap_err();
        assert!(matches!(err, BusMapError::InvalidData(_)));
    }

    // ── bus_map_job_id ──────────────────────────────────────────────────────

    #[test]
    fn test_bus_map_job_id_valid() {
        let val = PropertyValue::Uint32(42);
        let result = bus_map_job_id("JobId", &val).unwrap();
        assert_eq!(result, MappedValue::JobId(42));
    }

    #[test]
    fn test_bus_map_job_id_zero() {
        let val = PropertyValue::Uint32(0);
        let result = bus_map_job_id("JobId", &val).unwrap();
        assert_eq!(result, MappedValue::JobId(0));
    }

    #[test]
    fn test_bus_map_job_id_wrong_type() {
        let val = PropertyValue::String("not-a-job".into());
        let err = bus_map_job_id("JobId", &val).unwrap_err();
        assert!(matches!(err, BusMapError::InvalidData(_)));
    }

    // ── bus_message_map_all_properties ──────────────────────────────────────

    #[test]
    fn test_map_all_properties_basic_types() {
        let mut props = BTreeMap::new();
        props.insert(
            "Description".into(),
            PropertyValue::String("test service".into()),
        );
        props.insert("MainPID".into(), PropertyValue::Uint32(1234));
        props.insert("MemoryCurrent".into(), PropertyValue::Int64(1048576));
        props.insert("CPUUsageNSec".into(), PropertyValue::Double(0.5));

        let map = [
            PropertyMapEntry {
                member: "Description",
                set: None,
            },
            PropertyMapEntry {
                member: "MainPID",
                set: None,
            },
            PropertyMapEntry {
                member: "MemoryCurrent",
                set: None,
            },
            PropertyMapEntry {
                member: "CPUUsageNSec",
                set: None,
            },
        ];

        let result = bus_message_map_all_properties(&props, &map, BusMapFlags::empty()).unwrap();

        assert_eq!(
            get_mapped_string(&result, "Description"),
            Some("test service")
        );
        assert_eq!(get_mapped_u32(&result, "MainPID"), Some(1234));
        assert_eq!(get_mapped_i64(&result, "MemoryCurrent"), Some(1048576));
        assert_eq!(get_mapped_f64(&result, "CPUUsageNSec"), Some(0.5));
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn test_map_all_properties_with_custom_id128_setter() {
        let mut props = BTreeMap::new();
        props.insert(
            "InvocationID".into(),
            PropertyValue::ByteArray((0..16u8).collect()),
        );

        let map = [PropertyMapEntry {
            member: "InvocationID",
            set: Some(bus_map_id128),
        }];

        let result = bus_message_map_all_properties(&props, &map, BusMapFlags::empty()).unwrap();

        let id = get_mapped_id128(&result, "InvocationID").unwrap();
        assert_eq!(
            id,
            <[u8; 16]>::try_from((0u8..16u8).collect::<Vec<u8>>()).unwrap()
        );
    }

    #[test]
    fn test_map_all_properties_with_strv_sort_setter() {
        let mut props = BTreeMap::new();
        props.insert(
            "Wants".into(),
            PropertyValue::StringArray(vec!["z.target".into(), "a.target".into()]),
        );

        let map = [PropertyMapEntry {
            member: "Wants",
            set: Some(bus_map_strv_sort),
        }];

        let result = bus_message_map_all_properties(&props, &map, BusMapFlags::empty()).unwrap();

        let arr = get_mapped_string_array(&result, "Wants").unwrap();
        assert_eq!(arr, &["a.target", "z.target"]);
    }

    #[test]
    fn test_map_all_properties_with_job_id_setter() {
        let mut props = BTreeMap::new();
        props.insert("CurrentJob".into(), PropertyValue::Uint32(99));

        let map = [PropertyMapEntry {
            member: "CurrentJob",
            set: Some(bus_map_job_id),
        }];

        let result = bus_message_map_all_properties(&props, &map, BusMapFlags::empty()).unwrap();

        // get_mapped_u32 also matches JobId
        assert_eq!(get_mapped_u32(&result, "CurrentJob"), Some(99));
    }

    #[test]
    fn test_map_all_properties_skips_unmapped() {
        let mut props = BTreeMap::new();
        props.insert("Name".into(), PropertyValue::String("x".into()));
        props.insert("Unknown1".into(), PropertyValue::String("y".into()));
        props.insert("Unknown2".into(), PropertyValue::Boolean(1));

        let map = [PropertyMapEntry {
            member: "Name",
            set: None,
        }];

        let result = bus_message_map_all_properties(&props, &map, BusMapFlags::empty()).unwrap();

        assert_eq!(result.mapped.len(), 1);
        assert!(result.mapped.contains_key("Name"));
        assert_eq!(result.skipped.len(), 2);
        assert!(result.skipped.contains(&"Unknown1".to_string()));
        assert!(result.skipped.contains(&"Unknown2".to_string()));
    }

    #[test]
    fn test_map_all_properties_empty_input() {
        let props = BTreeMap::new();
        let map = [PropertyMapEntry {
            member: "Name",
            set: None,
        }];

        let result = bus_message_map_all_properties(&props, &map, BusMapFlags::empty()).unwrap();

        assert!(result.mapped.is_empty());
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn test_map_all_properties_empty_map() {
        let mut props = BTreeMap::new();
        props.insert("Name".into(), PropertyValue::String("x".into()));

        let map: &[PropertyMapEntry] = &[];

        let result = bus_message_map_all_properties(&props, map, BusMapFlags::empty()).unwrap();

        assert!(result.mapped.is_empty());
        assert_eq!(result.skipped, vec!["Name"]);
    }

    #[test]
    fn test_map_all_properties_map_entry_not_in_input() {
        let props = BTreeMap::new();
        let map = [
            PropertyMapEntry {
                member: "Name",
                set: None,
            },
            PropertyMapEntry {
                member: "PID",
                set: None,
            },
        ];

        let result = bus_message_map_all_properties(&props, &map, BusMapFlags::empty()).unwrap();

        assert!(result.mapped.is_empty());
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn test_map_all_properties_mixed_setters_and_basic() {
        let mut props = BTreeMap::new();
        props.insert("Name".into(), PropertyValue::String("test".into()));
        props.insert("MainPID".into(), PropertyValue::Uint32(100));
        props.insert(
            "InvocationID".into(),
            PropertyValue::ByteArray(vec![0xAA; 16]),
        );
        props.insert("Extra".into(), PropertyValue::Boolean(1));

        let map = [
            PropertyMapEntry {
                member: "Name",
                set: None, // basic
            },
            PropertyMapEntry {
                member: "MainPID",
                set: None, // basic
            },
            PropertyMapEntry {
                member: "InvocationID",
                set: Some(bus_map_id128), // custom
            },
        ];

        let result = bus_message_map_all_properties(&props, &map, BusMapFlags::empty()).unwrap();

        assert_eq!(result.mapped.len(), 3);
        assert_eq!(get_mapped_string(&result, "Name"), Some("test"));
        assert_eq!(get_mapped_u32(&result, "MainPID"), Some(100));
        assert_eq!(get_mapped_id128(&result, "InvocationID"), Some([0xAA; 16]));
        assert_eq!(result.skipped, vec!["Extra"]);
    }

    // ── bus_map_all_properties (high-level) ─────────────────────────────────

    #[test]
    fn test_bus_map_all_properties_high_level() {
        let mut props = BTreeMap::new();
        props.insert("Name".into(), PropertyValue::String("hi".into()));

        let map = [PropertyMapEntry {
            member: "Name",
            set: None,
        }];

        let result = bus_map_all_properties(props, &map, BusMapFlags::empty()).unwrap();
        assert_eq!(get_mapped_string(&result, "Name"), Some("hi"));
    }

    // ── Flags ───────────────────────────────────────────────────────────────

    #[test]
    fn test_bus_map_flags_bits() {
        assert_eq!(BusMapFlags::STRDUP.bits(), 1);
        assert_eq!(BusMapFlags::BOOLEAN_AS_BOOL.bits(), 2);
    }

    #[test]
    fn test_bus_map_flags_combinations() {
        let empty = BusMapFlags::empty();
        assert!(empty.is_empty());

        let both = BusMapFlags::STRDUP | BusMapFlags::BOOLEAN_AS_BOOL;
        assert!(both.contains(BusMapFlags::STRDUP));
        assert!(both.contains(BusMapFlags::BOOLEAN_AS_BOOL));
        assert_eq!(both.bits(), 3);

        let all = BusMapFlags::all();
        assert!(all.contains(BusMapFlags::STRDUP));
        assert!(all.contains(BusMapFlags::BOOLEAN_AS_BOOL));
    }

    // ── Error display ───────────────────────────────────────────────────────

    #[test]
    fn test_bus_map_error_display() {
        assert_eq!(
            BusMapError::UnsupportedType('z').to_string(),
            "unsupported D-Bus type: 'z'"
        );
        assert_eq!(
            BusMapError::MemberNotFound("Foo".into()).to_string(),
            "property member not found: Foo"
        );
        assert_eq!(
            BusMapError::InvalidData("bad".into()).to_string(),
            "invalid property data: bad"
        );
        assert_eq!(
            BusMapError::NullString.to_string(),
            "null/empty string where value expected"
        );
        assert_eq!(
            BusMapError::NoSetter("Bar".into()).to_string(),
            "no setter for property: Bar"
        );
    }

    #[test]
    fn test_bus_map_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(BusMapError::UnsupportedType('q'));
        assert!(err.to_string().contains("'q'"));
    }

    // ── Getters on empty result ─────────────────────────────────────────────

    #[test]
    fn test_getters_on_empty_result() {
        let result = MapAllResult::default();
        assert!(get_mapped_string(&result, "Name").is_none());
        assert!(get_mapped_bool(&result, "Running").is_none());
        assert!(get_mapped_u32(&result, "Pid").is_none());
        assert!(get_mapped_i64(&result, "Size").is_none());
        assert!(get_mapped_f64(&result, "CPU").is_none());
        assert!(get_mapped_string_array(&result, "Deps").is_none());
        assert!(get_mapped_id128(&result, "Id").is_none());
    }

    // ── D-Bus type constants ────────────────────────────────────────────────

    #[test]
    fn test_dbus_type_constants() {
        assert_eq!(dbus_type::STRING, 's');
        assert_eq!(dbus_type::OBJECT_PATH, 'o');
        assert_eq!(dbus_type::BOOLEAN, 'b');
        assert_eq!(dbus_type::INT32, 'i');
        assert_eq!(dbus_type::UINT32, 'u');
        assert_eq!(dbus_type::INT64, 'x');
        assert_eq!(dbus_type::UINT64, 't');
        assert_eq!(dbus_type::DOUBLE, 'd');
        assert_eq!(dbus_type::ARRAY, 'a');
        assert_eq!(dbus_type::VARIANT, 'v');
        assert_eq!(dbus_type::DICT_ENTRY, 'e');
        assert_eq!(dbus_type::BYTE, 'y');
    }

    // ── MappedValue equality ────────────────────────────────────────────────

    #[test]
    fn test_mapped_value_equality() {
        assert_eq!(
            MappedValue::String("a".into()),
            MappedValue::String("a".into())
        );
        assert_ne!(
            MappedValue::String("a".into()),
            MappedValue::String("b".into())
        );
        assert_eq!(MappedValue::Bool(true), MappedValue::Bool(true));
        assert_ne!(MappedValue::Bool(true), MappedValue::Bool(false));
        assert_eq!(MappedValue::Uint32(42), MappedValue::Uint32(42));
        assert_eq!(MappedValue::Int64(-1), MappedValue::Int64(-1));
        assert_eq!(MappedValue::Double(1.0), MappedValue::Double(1.0));
        assert_eq!(MappedValue::Id128([1; 16]), MappedValue::Id128([1; 16]));
        assert_ne!(MappedValue::Id128([0; 16]), MappedValue::Id128([1; 16]));
        assert_eq!(MappedValue::JobId(7), MappedValue::JobId(7));
        assert_ne!(MappedValue::JobId(7), MappedValue::Uint32(7));
    }

    // ── MapAllResult default ────────────────────────────────────────────────

    #[test]
    fn test_map_all_result_default() {
        let result = MapAllResult::default();
        assert!(result.mapped.is_empty());
        assert!(result.skipped.is_empty());
    }

    // ── PropertyMapEntry construction ───────────────────────────────────────

    #[test]
    fn test_property_map_entry_with_and_without_setter() {
        let with_setter = PropertyMapEntry {
            member: "Id",
            set: Some(bus_map_id128),
        };
        assert!(with_setter.set.is_some());

        let without_setter = PropertyMapEntry {
            member: "Name",
            set: None,
        };
        assert!(without_setter.set.is_none());
    }
}
