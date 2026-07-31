// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.af-list; authority=src/basic/af-list.c,src/basic/af-list.h,src/basic/generate-af-list.sh,src/basic/af-to-name.awk,src/basic/meson.build,src/include/meson.build,src/include/override/sys/socket.h,tools/generate-gperfs.py
//
// Address family name/value lookups.
// Faithfully re-implements af_to_name, af_to_name_short, af_from_name,
// af_to_ipv4_ipv6, and af_from_ipv4_ipv6 from af-list.c.
//
// `af_names` and the gperf parser are generated from the selected target's
// <sys/socket.h>. The static Linux table below is deliberately kept separate
// from that build-time authority: the C-vs-Rust fixture exhausts the target
// table when it is available, but a target-generated-table parity claim must
// not be inferred from this source-only port.

// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter validates the pointer and lifetime contract.
        unsafe { $expression }
    }};
}
use crate::ffi_string_table::{self, Entry as FfiEntry};
use libc::c_char;

// ── Address family enum ──────────────────────────────────────────────────

/// Linux address family values, matching the AF_* defines from <sys/socket.h>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AddressFamily {
    Unspec = 0,
    Unix = 1,
    Inet = 2,
    Ax25 = 3,
    Ipx = 4,
    Appletalk = 5,
    Netrom = 6,
    Bridge = 7,
    Atmpvc = 8,
    X25 = 9,
    Inet6 = 10,
    Rose = 11,
    Decnet = 12,
    Netbeui = 13,
    Security = 14,
    Key = 15,
    Netlink = 16,
    Packet = 17,
    Ash = 18,
    Econet = 19,
    Atmsvc = 20,
    Rds = 21,
    Sna = 22,
    Irda = 23,
    Pppox = 24,
    Wanpipe = 25,
    Llc = 26,
    Ib = 27,
    Mpls = 28,
    Can = 29,
    Tipc = 30,
    Bluetooth = 31,
    Iucv = 32,
    Rxrpc = 33,
    Isdn = 34,
    Phonet = 35,
    Ieee802154 = 36,
    Caif = 37,
    Alg = 38,
    Nfc = 39,
    Vsock = 40,
    Kcm = 41,
    Qipcrtr = 42,
    Smc = 43,
    Xdp = 44,
    Mctp = 45,
}

/// Error returned for unknown address family names.
pub const AF_INVALID: i32 = -22; // -EINVAL

// ── Single-source address-family table ────────────────────────────────────
//
// Names, safe Rust conversion, and C ABI pointers all derive from this one
// variant/name list. Values are taken from the enum variants themselves.
macro_rules! address_family_table {
    ($( $variant:ident => $name:literal ),+ $(,)?) => {
        static AF_TABLE: &[FfiEntry] = &[
            $((AddressFamily::$variant as i32, concat!($name, "\0").as_bytes()),)+
        ];

        impl AddressFamily {
            fn from_raw(value: i32) -> Option<Self> {
                match value {
                    $(value if value == Self::$variant as i32 => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

address_family_table!(
    Unix => "AF_UNIX", Inet => "AF_INET", Ax25 => "AF_AX25", Ipx => "AF_IPX",
    Appletalk => "AF_APPLETALK", Netrom => "AF_NETROM", Bridge => "AF_BRIDGE",
    Atmpvc => "AF_ATMPVC", X25 => "AF_X25", Inet6 => "AF_INET6", Rose => "AF_ROSE",
    Decnet => "AF_DECnet", Netbeui => "AF_NETBEUI", Security => "AF_SECURITY", Key => "AF_KEY",
    Netlink => "AF_NETLINK", Packet => "AF_PACKET", Ash => "AF_ASH", Econet => "AF_ECONET",
    Atmsvc => "AF_ATMSVC", Rds => "AF_RDS", Sna => "AF_SNA", Irda => "AF_IRDA",
    Pppox => "AF_PPPOX", Wanpipe => "AF_WANPIPE", Llc => "AF_LLC", Ib => "AF_IB",
    Mpls => "AF_MPLS", Can => "AF_CAN", Tipc => "AF_TIPC", Bluetooth => "AF_BLUETOOTH",
    Iucv => "AF_IUCV", Rxrpc => "AF_RXRPC", Isdn => "AF_ISDN", Phonet => "AF_PHONET",
    Ieee802154 => "AF_IEEE802154", Caif => "AF_CAIF", Alg => "AF_ALG", Nfc => "AF_NFC",
    Vsock => "AF_VSOCK", Kcm => "AF_KCM", Qipcrtr => "AF_QIPCRTR", Smc => "AF_SMC",
    Xdp => "AF_XDP", Mctp => "AF_MCTP",
);

// `af-to-name.awk` intentionally removes these aliases so output has one
// canonical spelling per numeric family. `af-from-name.gperf`, however, is
// generated from the unfiltered macro list and accepts all three. Keep that
// asymmetry explicit instead of adding duplicate output entries.
static AF_FROM_NAME_ALIASES: &[FfiEntry] = &[
    (AddressFamily::Unix as i32, b"AF_LOCAL\0"),
    (AddressFamily::Unix as i32, b"AF_FILE\0"),
    (AddressFamily::Netlink as i32, b"AF_ROUTE\0"),
];

/// Look up an address-family spelling with gperf's ASCII case folding.
///
/// The C generator passes `--ignore-case`; `eq_ignore_ascii_case` has the
/// same byte-oriented behavior for the ASCII macro names and never attempts
/// a Unicode conversion of FFI input.
fn af_from_name_bytes(name: &[u8]) -> Option<AddressFamily> {
    AF_TABLE
        .iter()
        .chain(AF_FROM_NAME_ALIASES)
        .find_map(|&(value, bytes)| {
            bytes[..bytes.len() - 1]
                .eq_ignore_ascii_case(name)
                .then_some(value)
        })
        .and_then(AddressFamily::from_raw)
}

// ── af_to_name ───────────────────────────────────────────────────────────

/// Convert an address family ID to its name string.
/// Mirrors `af_to_name()` from af-list.c: returns `None` for id <= 0 or unknown values.
pub fn af_to_name(id: i32) -> Option<&'static str> {
    ffi_string_table::to_str(AF_TABLE, id)
}

// ── af_to_name_short ────────────────────────────────────────────────────

/// Return the short AF name (without "AF_" prefix).
/// Mirrors `af_to_name_short()` from af-list.c:
/// - AF_UNSPEC (0) → "*"
/// - Known family → name without "AF_" prefix
/// - Unknown → "unknown"
pub fn af_to_name_short(id: i32) -> &'static str {
    if id == 0 {
        return "*";
    }
    match af_to_name(id) {
        Some(name) => &name[3..], // Strip "AF_" prefix
        None => "unknown",
    }
}

// ── af_from_name ────────────────────────────────────────────────────────

/// Parse an AF_* name string into its address family value.
/// Mirrors `af_from_name()` from af-list.c.
pub fn af_from_name(name: &str) -> Result<AddressFamily, i32> {
    af_from_name_bytes(name.as_bytes()).ok_or(AF_INVALID)
}

// ── af_to_ipv4_ipv6 ─────────────────────────────────────────────────────

/// Map AF_INET to "ipv4" and AF_INET6 to "ipv6".
/// Mirrors `af_to_ipv4_ipv6()` from af-list.c.
pub fn af_to_ipv4_ipv6(id: i32) -> Option<&'static str> {
    match id {
        2 => Some("ipv4"),  // AF_INET
        10 => Some("ipv6"), // AF_INET6
        _ => None,
    }
}

// ── af_from_ipv4_ipv6 ──────────────────────────────────────────────────

/// Map "ipv4"/"ipv6" to AF_INET/AF_INET6.
/// Mirrors `af_from_ipv4_ipv6()` from af-list.c.
/// Returns `Ok(AddressFamily)` for known names, `Ok(AddressFamily::Unspec)` otherwise.
pub fn af_from_ipv4_ipv6(af: Option<&str>) -> Result<AddressFamily, i32> {
    match af {
        Some("ipv4") => Ok(AddressFamily::Inet),
        Some("ipv6") => Ok(AddressFamily::Inet6),
        _ => Ok(AddressFamily::Unspec),
    }
}

/// Return C's exclusive address-family table bound.
///
/// `af_names` reserves index zero for the unnamed `AF_UNSPEC`; the highest
/// current named family is `AF_MCTP`, therefore `ELEMENTSOF(af_names)` is its
/// numeric value plus one.
pub fn af_max() -> i32 {
    AddressFamily::Mctp as i32 + 1
}

/// C ABI facade for `af_to_name()`. Returned pointers are borrowed statics.
#[unsafe(no_mangle)]
pub extern "C" fn rs_af_to_name(id: i32) -> *const c_char {
    ffi_string_table::to_ptr(AF_TABLE, id)
}

/// C ABI facade for `af_to_name_short()`. Returned pointers are borrowed
/// statics, including pointers into the static `AF_*` strings.
#[unsafe(no_mangle)]
pub extern "C" fn rs_af_to_name_short(id: i32) -> *const c_char {
    if id == AddressFamily::Unspec as i32 {
        return c"*".as_ptr();
    }

    let name = rs_af_to_name(id);
    if name.is_null() {
        c"unknown".as_ptr()
    } else {
        name.wrapping_add(3)
    }
}

/// C ABI facade for `af_from_name()`.
///
/// # Safety
///
/// A non-NULL `name` must point to a valid NUL-terminated C string for the
/// duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_af_from_name(name: *const c_char) -> i32 {
    if name.is_null() {
        return AF_INVALID;
    }

    // SAFETY: required by this C ABI entry point's contract and checked for
    // NULL above. This borrows opaque C bytes only for the lookup.
    let name = unsafe_ffi!(std::ffi::CStr::from_ptr(name)).to_bytes();
    af_from_name_bytes(name).map_or(AF_INVALID, |family| family as i32)
}

/// C ABI facade for `af_to_ipv4_ipv6()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_af_to_ipv4_ipv6(id: i32) -> *const c_char {
    match id {
        2 => c"ipv4".as_ptr(),
        10 => c"ipv6".as_ptr(),
        _ => std::ptr::null(),
    }
}

/// C ABI facade for `af_max()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_af_max() -> i32 {
    af_max()
}

/// C ABI facade for `af_from_ipv4_ipv6()`.
///
/// # Safety
///
/// A non-NULL `family` must point to a valid NUL-terminated C string for the
/// duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_af_from_ipv4_ipv6(family: *const c_char) -> i32 {
    if family.is_null() {
        return AddressFamily::Unspec as i32;
    }

    // SAFETY: required by this C ABI entry point's contract and checked for
    // NULL above.
    match unsafe_ffi!(std::ffi::CStr::from_ptr(family)).to_bytes() {
        b"ipv4" => AddressFamily::Inet as i32,
        b"ipv6" => AddressFamily::Inet6 as i32,
        _ => AddressFamily::Unspec as i32,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_af_to_name_valid() {
        assert_eq!(af_to_name(1), Some("AF_UNIX"));
        assert_eq!(af_to_name(2), Some("AF_INET"));
        assert_eq!(af_to_name(10), Some("AF_INET6"));
        assert_eq!(af_to_name(45), Some("AF_MCTP"));
        assert_eq!(af_to_name(31), Some("AF_BLUETOOTH"));
    }

    #[test]
    fn test_af_to_name_invalid() {
        assert_eq!(af_to_name(0), None);
        assert_eq!(af_to_name(-1), None);
        assert_eq!(af_to_name(46), None);
        assert_eq!(af_to_name(100), None);
    }

    #[test]
    fn test_af_to_name_short_valid() {
        assert_eq!(af_to_name_short(1), "UNIX");
        assert_eq!(af_to_name_short(2), "INET");
        assert_eq!(af_to_name_short(10), "INET6");
    }

    #[test]
    fn test_af_to_name_short_unspec() {
        assert_eq!(af_to_name_short(0), "*");
    }

    #[test]
    fn test_af_to_name_short_unknown() {
        assert_eq!(af_to_name_short(99), "unknown");
    }

    #[test]
    fn test_af_from_name_valid() {
        assert_eq!(af_from_name("AF_UNIX"), Ok(AddressFamily::Unix));
        assert_eq!(af_from_name("AF_INET"), Ok(AddressFamily::Inet));
        assert_eq!(af_from_name("AF_INET6"), Ok(AddressFamily::Inet6));
        assert_eq!(af_from_name("AF_BLUETOOTH"), Ok(AddressFamily::Bluetooth));
        assert_eq!(af_from_name("AF_MCTP"), Ok(AddressFamily::Mctp));
    }

    #[test]
    fn test_af_from_name_invalid() {
        assert_eq!(af_from_name("AF_NONEXISTENT"), Err(AF_INVALID));
        assert_eq!(af_from_name(""), Err(AF_INVALID));
    }

    #[test]
    fn test_af_to_ipv4_ipv6_valid() {
        assert_eq!(af_to_ipv4_ipv6(2), Some("ipv4"));
        assert_eq!(af_to_ipv4_ipv6(10), Some("ipv6"));
    }

    #[test]
    fn test_af_to_ipv4_ipv6_invalid() {
        assert_eq!(af_to_ipv4_ipv6(0), None);
        assert_eq!(af_to_ipv4_ipv6(1), None);
        assert_eq!(af_to_ipv4_ipv6(31), None);
    }

    #[test]
    fn test_af_from_ipv4_ipv6_valid() {
        assert_eq!(af_from_ipv4_ipv6(Some("ipv4")), Ok(AddressFamily::Inet));
        assert_eq!(af_from_ipv4_ipv6(Some("ipv6")), Ok(AddressFamily::Inet6));
    }

    #[test]
    fn test_af_from_ipv4_ipv6_null() {
        assert_eq!(af_from_ipv4_ipv6(None), Ok(AddressFamily::Unspec));
    }

    #[test]
    fn test_af_from_ipv4_ipv6_other() {
        assert_eq!(af_from_ipv4_ipv6(Some("foobar")), Ok(AddressFamily::Unspec));
        assert_eq!(af_from_ipv4_ipv6(Some("")), Ok(AddressFamily::Unspec));
    }

    #[test]
    fn test_af_max_matches_the_current_table_bound() {
        assert_eq!(af_max(), AddressFamily::Mctp as i32 + 1);
        assert_eq!(af_to_name(af_max()), None);
    }

    #[test]
    fn test_af_roundtrip() {
        for &(value, _) in AF_TABLE {
            let af = AddressFamily::from_raw(value).unwrap();
            let name = af_to_name(value).unwrap();
            assert_eq!(af_from_name(name), Ok(af));
        }
    }

    #[test]
    fn test_all_entries_have_names() {
        for &(value, bytes) in AF_TABLE {
            let name = ffi_string_table::entry_str(bytes);
            assert!(name.starts_with("AF_"));
            assert_eq!(af_to_name(value), Some(name));
        }
    }
}
