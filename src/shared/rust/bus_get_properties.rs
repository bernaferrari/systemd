// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-get-properties.c, src/shared/bus-get-properties.h
//
// D-Bus property getter conversion logic.
//
// Pure Rust helpers for converting between native types and D-Bus wire
// representations. The actual sd_bus_message_append calls remain in C;
// this module provides the type conversions that feed into them.

// ── D-Bus type signature constants ──────────────────────────────────────────

/// D-Bus type signature for boolean (`'b'`).
pub const DBUS_TYPE_BOOLEAN: char = 'b';
/// D-Bus type signature for uint64 (`'t'`).
pub const DBUS_TYPE_UINT64: char = 't';
/// D-Bus type signature for int64 (`'x'`).
pub const DBUS_TYPE_INT64: char = 'x';
/// D-Bus type signature for byte array (`"ay"`).
pub const DBUS_TYPE_BYTE_ARRAY: &str = "ay";

// ── Global property values ─────────────────────────────────────────────────

/// Sentinel value for a global false boolean property.
pub const BUS_PROPERTY_BOOL_FALSE: i32 = 0;
/// Sentinel value for a global true boolean property.
pub const BUS_PROPERTY_BOOL_TRUE: i32 = 1;
/// Sentinel value for a global zero uint64 property.
pub const BUS_PROPERTY_UINT64_ZERO: u64 = 0;
/// Sentinel value for a global max uint64 property.
pub const BUS_PROPERTY_UINT64_MAX: u64 = u64::MAX;

/// Value representing `RLIM_INFINITY` mapped to the D-Bus wire format.
///
/// On the bus, resource limit infinity is encoded as `UINT64_MAX` so that
/// all architectures agree on the representation regardless of `rlim_t` size.
pub const RLIM_INFINITY_DBUS: u64 = u64::MAX;

// ── sd-id128 helpers ───────────────────────────────────────────────────────

/// A 128-bit identifier (sd_id128_t equivalent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id128(pub [u8; 16]);

impl Id128 {
    /// The null / zero id128.
    pub const NULL: Self = Self([0u8; 16]);

    /// Create from a byte slice (must be exactly 16 bytes).
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 16 {
            return None;
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Returns `true` if every byte is zero.
    pub fn is_null(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Returns the raw 16-byte representation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for Id128 {
    fn default() -> Self {
        Self::NULL
    }
}

// ── Bool ↔ D-Bus conversions ──────────────────────────────────────────────

/// Convert a Rust `bool` to the D-Bus wire integer (0 or 1).
#[inline]
pub fn bool_to_dbus_int(val: bool) -> i32 {
    i32::from(val)
}

/// Convert a D-Bus wire integer to a Rust `bool`.
///
/// Any non-zero value is treated as `true`, matching C boolean semantics.
#[inline]
pub fn dbus_int_to_bool(val: i32) -> bool {
    val != 0
}

// ── Tristate conversion ───────────────────────────────────────────────────

/// Convert a tristate integer to a boolean.
///
/// Positive values map to `true`; zero and negative values map to `false`.
/// This matches the C convention where `int > 0` means enabled.
#[inline]
pub fn tristate_to_bool(val: i32) -> bool {
    val > 0
}

// ── Size / long / ulong conversions ───────────────────────────────────────

/// Convert a `usize` (C `size_t`) to a D-Bus `uint64`.
///
/// On 64-bit systems `size_t == u64` so this is a no-op cast.
/// On 32-bit systems it zero-extends to 64 bits.
#[inline]
pub fn size_to_dbus_u64(val: usize) -> u64 {
    val as u64
}

/// Convert a C `long` to a D-Bus `int64`.
///
/// On 64-bit Linux `long == i64`; on 32-bit it sign-extends.
#[inline]
pub fn long_to_dbus_i64(val: i64) -> i64 {
    val
}

/// Convert a C `unsigned long` to a D-Bus `uint64`.
///
/// On 64-bit Linux `unsigned long == u64`; on 32-bit it zero-extends.
#[inline]
pub fn ulong_to_dbus_u64(val: u64) -> u64 {
    val
}

// ── Rlimit conversions ───────────────────────────────────────────────────

/// Convert an `rlim_t` value to the D-Bus wire representation.
///
/// `RLIM_INFINITY` is mapped to `UINT64_MAX` so all architectures agree.
/// Any other value is zero-extended to 64 bits.
#[inline]
pub fn rlimit_to_dbus_u64(rlim: u64, is_infinity: bool) -> u64 {
    if is_infinity {
        RLIM_INFINITY_DBUS
    } else {
        rlim
    }
}

/// Determine whether a D-Bus property name refers to the *soft* rlimit.
///
/// In systemd convention, soft-limit properties end with `"Soft"`
/// (e.g. `"LimitNOFILESoft"`). Returns `true` when the suffix is present.
pub fn rlimit_property_is_soft(property: &str) -> bool {
    property.ends_with("Soft") || property.ends_with("soft")
}

// ── String-set helpers ────────────────────────────────────────────────────

/// Sort a mutable slice of string references, matching the D-Bus convention
/// that `bus_message_append_string_set` sends them in order.
pub fn sort_string_set(set: &mut [&str]) {
    set.sort();
}

/// Sort a mutable vector of owned strings in place.
pub fn sort_string_vec(set: &mut Vec<String>) {
    set.sort();
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── bool_to_dbus_int / dbus_int_to_bool ────────────────────────────────

    #[test]
    fn test_bool_to_dbus_int_true() {
        assert_eq!(bool_to_dbus_int(true), 1);
    }

    #[test]
    fn test_bool_to_dbus_int_false() {
        assert_eq!(bool_to_dbus_int(false), 0);
    }

    #[test]
    fn test_dbus_int_to_bool_nonzero() {
        assert!(dbus_int_to_bool(1));
        assert!(dbus_int_to_bool(42));
        assert!(dbus_int_to_bool(-1));
    }

    #[test]
    fn test_dbus_int_to_bool_zero() {
        assert!(!dbus_int_to_bool(0));
    }

    #[test]
    fn test_bool_roundtrip() {
        for val in [true, false] {
            assert_eq!(dbus_int_to_bool(bool_to_dbus_int(val)), val);
        }
    }

    // ── tristate_to_bool ───────────────────────────────────────────────────

    #[test]
    fn test_tristate_positive() {
        assert!(tristate_to_bool(1));
        assert!(tristate_to_bool(100));
    }

    #[test]
    fn test_tristate_non_positive() {
        assert!(!tristate_to_bool(0));
        assert!(!tristate_to_bool(-1));
        assert!(!tristate_to_bool(-100));
    }

    // ── Id128 ──────────────────────────────────────────────────────────────

    #[test]
    fn test_id128_null_is_null() {
        assert!(Id128::NULL.is_null());
        assert!(Id128::default().is_null());
    }

    #[test]
    fn test_id128_non_null() {
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        assert!(!Id128(bytes).is_null());
    }

    #[test]
    fn test_id128_from_slice_valid() {
        let bytes = [0xFFu8; 16];
        let id = Id128::from_slice(&bytes).unwrap();
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_id128_from_slice_wrong_length() {
        assert!(Id128::from_slice(&[0; 15]).is_none());
        assert!(Id128::from_slice(&[0; 17]).is_none());
        assert!(Id128::from_slice(&[]).is_none());
    }

    // ── size / long / ulong ────────────────────────────────────────────────

    #[test]
    fn test_size_to_dbus_u64() {
        assert_eq!(size_to_dbus_u64(0), 0);
        assert_eq!(size_to_dbus_u64(usize::MAX), usize::MAX as u64);
    }

    #[test]
    fn test_long_to_dbus_i64_identity() {
        assert_eq!(long_to_dbus_i64(i64::MIN), i64::MIN);
        assert_eq!(long_to_dbus_i64(0), 0);
        assert_eq!(long_to_dbus_i64(i64::MAX), i64::MAX);
    }

    #[test]
    fn test_ulong_to_dbus_u64_identity() {
        assert_eq!(ulong_to_dbus_u64(0), 0);
        assert_eq!(ulong_to_dbus_u64(u64::MAX), u64::MAX);
    }

    // ── rlimit ─────────────────────────────────────────────────────────────

    #[test]
    fn test_rlimit_infinity_maps_to_max() {
        assert_eq!(rlimit_to_dbus_u64(0, true), u64::MAX);
        assert_eq!(rlimit_to_dbus_u64(12345, true), u64::MAX);
    }

    #[test]
    fn test_rlimit_finite_passthrough() {
        assert_eq!(rlimit_to_dbus_u64(0, false), 0);
        assert_eq!(rlimit_to_dbus_u64(65536, false), 65536);
        assert_eq!(rlimit_to_dbus_u64(u64::MAX - 1, false), u64::MAX - 1);
    }

    #[test]
    fn test_rlimit_property_is_soft() {
        assert!(rlimit_property_is_soft("LimitNOFILESoft"));
        assert!(rlimit_property_is_soft("DefaultLimitNOFILESoft"));
        assert!(rlimit_property_is_soft("LimitNICEsoft")); // case-sensitive
        assert!(!rlimit_property_is_soft("LimitNOFILE"));
        assert!(!rlimit_property_is_soft("SoftLimitNOFILE"));
        assert!(!rlimit_property_is_soft(""));
    }

    // ── string set sorting ─────────────────────────────────────────────────

    #[test]
    fn test_sort_string_set() {
        let mut set = vec!["banana", "apple", "cherry"];
        sort_string_set(&mut set);
        assert_eq!(set, vec!["apple", "banana", "cherry"]);
    }

    #[test]
    fn test_sort_string_vec() {
        let mut set = vec![String::from("z"), String::from("a"), String::from("m")];
        sort_string_vec(&mut set);
        assert_eq!(set, vec!["a", "m", "z"]);
    }

    // ── constants ──────────────────────────────────────────────────────────

    #[test]
    fn test_global_constants() {
        assert_eq!(BUS_PROPERTY_BOOL_FALSE, 0);
        assert_eq!(BUS_PROPERTY_BOOL_TRUE, 1);
        assert_eq!(BUS_PROPERTY_UINT64_ZERO, 0);
        assert_eq!(BUS_PROPERTY_UINT64_MAX, u64::MAX);
    }

    #[test]
    fn test_dbus_type_signatures() {
        assert_eq!(DBUS_TYPE_BOOLEAN, 'b');
        assert_eq!(DBUS_TYPE_UINT64, 't');
        assert_eq!(DBUS_TYPE_INT64, 'x');
        assert_eq!(DBUS_TYPE_BYTE_ARRAY, "ay");
    }
}
