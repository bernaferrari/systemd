// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/netif-util.c, src/shared/netif-util.h
//
// Network interface utility functions.
//
// Provides carrier detection, interface name validation, Ethernet address
// inspection/normalization, and system-call wrappers for interface index
// lookup.  Pure-logic helpers are fully safe; only `if_nametoindex` and
// `if_indextoname` use `unsafe` to call into libc.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface operational state: interface is up (RFC 2863 / operstates.txt).
// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::*;
pub const IF_OPER_UP: u8 = 6;
/// Interface operational state: state is unknown / not reported.
pub const IF_OPER_UNKNOWN: u8 = 0;

/// Interface flag: L1 carrier is present.
pub const IFF_LOWER_UP: u32 = 0x1;
/// Interface flag: resources are allocated and the interface is running.
pub const IFF_RUNNING: u32 = 0x40;
/// Interface flag: interface is in dormant state (waiting for external event).
pub const IFF_DORMANT: u32 = 0x10000;

/// Maximum interface name length including NUL terminator (Linux `IFNAMSIZ`).
pub const IFNAMSIZ: usize = 16;
/// Maximum usable interface name length (IFNAMSIZ minus the NUL byte).
pub const IFNAMSIZ_MINUS1: usize = IFNAMSIZ - 1;

/// Ethernet (MAC) address length in bytes.
pub const ETH_ALEN: usize = 6;
/// InfiniBand hardware address length in bytes.
pub const INFINIBAND_ALEN: usize = 20;

/// ARPHRD type for Ethernet.
pub const ARPHRD_ETHER: u16 = 1;
/// ARPHRD type for InfiniBand.
pub const ARPHRD_INFINIBAND: u16 = 32;

/// Expected hardware address length for Ethernet.
pub const ETHER_ADDR_LEN: usize = ETH_ALEN;
/// Expected hardware address length for InfiniBand.
pub const INFINIBAND_ADDR_LEN: usize = INFINIBAND_ALEN;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced by network interface utility functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetifError {
    /// Interface name is empty.
    EmptyName,
    /// Interface name exceeds `IFNAMSIZ_MINUS1` characters.
    NameTooLong,
    /// Interface name contains invalid characters.
    InvalidName,
    /// No interface found with the given name or index.
    NotFound,
    /// Hardware address validation failed.
    InvalidHwAddr(&'static str),
    /// Hardware address length does not match the expected length for the ARPHRD type.
    HwAddrLengthMismatch { actual: usize, expected: usize },
    /// Interface type is not supported for the requested operation.
    UnsupportedType(u16),
    /// A libc / system-call error occurred.
    Syscall(i32),
}

impl std::fmt::Display for NetifError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetifError::EmptyName => write!(f, "interface name is empty"),
            NetifError::NameTooLong => {
                write!(f, "interface name too long (max {IFNAMSIZ_MINUS1} chars)")
            }
            NetifError::InvalidName => write!(f, "interface name contains invalid characters"),
            NetifError::NotFound => write!(f, "network interface not found"),
            NetifError::InvalidHwAddr(reason) => write!(f, "invalid hardware address: {reason}"),
            NetifError::HwAddrLengthMismatch { actual, expected } => {
                write!(
                    f,
                    "hardware address length {actual} does not match expected {expected}"
                )
            }
            NetifError::UnsupportedType(t) => write!(f, "unsupported interface type {t}"),
            NetifError::Syscall(code) => write!(f, "system call failed (errno {code})"),
        }
    }
}

impl std::error::Error for NetifError {}

// ── Bit-flag helpers ──────────────────────────────────────────────────────

/// Returns `true` when *all* bits set in `mask` are also set in `flags`.
#[inline]
pub const fn flags_set(flags: u32, mask: u32) -> bool {
    (flags & mask) == mask
}

/// Returns `true` when *any* bit set in `mask` is also set in `flags`.
#[inline]
pub const fn flags_has_any(flags: u32, mask: u32) -> bool {
    (flags & mask) != 0
}

// ── Carrier detection ─────────────────────────────────────────────────────

/// Determine whether a network interface has carrier.
///
/// Follows the kernel's `Documentation/networking/operstates.txt`:
/// * `IF_OPER_UP` → carrier present.
/// * Any other known state → no carrier.
/// * `IF_OPER_UNKNOWN` → fall back to `IFF_LOWER_UP | IFF_RUNNING` without `IFF_DORMANT`.
pub fn netif_has_carrier(operstate: u8, flags: u32) -> bool {
    if operstate == IF_OPER_UP {
        return true;
    }
    if operstate != IF_OPER_UNKNOWN {
        return false;
    }
    flags_set(flags, IFF_LOWER_UP | IFF_RUNNING) && !flags_set(flags, IFF_DORMANT)
}

// ── Interface name validation ─────────────────────────────────────────────

/// Returns `true` if `name` is a valid network interface name.
///
/// Rules (mirroring `netif_is_valid_name` in the C codebase):
/// * Non-empty.
/// * Shorter than `IFNAMSIZ` (≤ 15 characters).
/// * Contains only ASCII alphanumeric characters, hyphens, and underscores.
/// * Does not start with a hyphen or dot (to avoid confusion with options).
pub fn netif_name_is_valid(name: &str) -> bool {
    if name.is_empty() || name.len() >= IFNAMSIZ {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Validates an interface name and returns `Ok(())` on success.
pub fn validate_ifname(name: &str) -> Result<(), NetifError> {
    if name.is_empty() {
        return Err(NetifError::EmptyName);
    }
    if name.len() >= IFNAMSIZ {
        return Err(NetifError::NameTooLong);
    }
    if !netif_name_is_valid(name) {
        return Err(NetifError::InvalidName);
    }
    Ok(())
}

// ── Ethernet address utilities ────────────────────────────────────────────

/// Check whether an Ethernet address is all zeros (null / zero address).
pub fn ether_addr_is_null(addr: &[u8; ETH_ALEN]) -> bool {
    addr.iter().all(|&b| b == 0)
}

/// Check whether an Ethernet address is the broadcast address (`ff:ff:ff:ff:ff:ff`).
pub fn ether_addr_is_broadcast(addr: &[u8; ETH_ALEN]) -> bool {
    addr.iter().all(|&b| b == 0xff)
}

/// Check whether an Ethernet address is a multicast address (I/G bit set).
///
/// The multicast bit is the least-significant bit of the first octet.
pub fn ether_addr_is_multicast(addr: &[u8; ETH_ALEN]) -> bool {
    (addr[0] & 0x01) != 0
}

/// Check whether an Ethernet address is locally administered (U/L bit set).
///
/// The local bit is the second-least-significant bit of the first octet.
pub fn ether_addr_is_local(addr: &[u8; ETH_ALEN]) -> bool {
    (addr[0] & 0x02) != 0
}

/// Validate and normalise an Ethernet MAC address in place.
///
/// * Rejects null and broadcast addresses with `InvalidHwAddr`.
/// * Clears the multicast (I/G) bit.
/// * For non-static (randomly generated) addresses, sets the locally-administered (U/L) bit.
pub fn ether_addr_normalize(addr: &mut [u8; ETH_ALEN], is_static: bool) -> Result<(), NetifError> {
    if ether_addr_is_null(addr) {
        return Err(NetifError::InvalidHwAddr("null MAC address"));
    }
    if ether_addr_is_broadcast(addr) {
        return Err(NetifError::InvalidHwAddr("broadcast MAC address"));
    }

    // Clear the multicast bit.
    addr[0] &= 0xfe;

    // For randomly-generated addresses, ensure the locally-administered bit is set.
    if !is_static && !ether_addr_is_local(addr) {
        addr[0] |= 0x02;
    }

    Ok(())
}

/// Expected hardware address length for a given ARPHRD interface type.
///
/// Returns `None` for unknown interface types.
pub fn arphrd_to_hw_addr_len(iftype: u16) -> Option<usize> {
    match iftype {
        ARPHRD_ETHER => Some(ETHER_ADDR_LEN),
        ARPHRD_INFINIBAND => Some(INFINIBAND_ADDR_LEN),
        _ => None,
    }
}

/// Verify and normalise a hardware address for a given interface type.
///
/// Mirrors `net_verify_hardware_address()` for the Ethernet case.
/// * Checks that the address length matches the expected length for `iftype`.
/// * For Ethernet, validates and normalises the address.
/// * Returns the (possibly modified) address on success.
pub fn verify_hardware_address(
    iftype: u16,
    addr: &mut [u8],
    is_static: bool,
) -> Result<(), NetifError> {
    if addr.is_empty() {
        return Ok(());
    }

    let expected = arphrd_to_hw_addr_len(iftype).ok_or(NetifError::UnsupportedType(iftype))?;

    if addr.len() != expected {
        return Err(NetifError::HwAddrLengthMismatch {
            actual: addr.len(),
            expected,
        });
    }

    match iftype {
        ARPHRD_ETHER => {
            let mut eth = [0u8; ETH_ALEN];
            eth.copy_from_slice(addr);
            ether_addr_normalize(&mut eth, is_static)?;
            addr.copy_from_slice(&eth);
            Ok(())
        }
        _ => Err(NetifError::UnsupportedType(iftype)),
    }
}

// ── Interface name shortening ─────────────────────────────────────────────

/// Shorten an interface name to fit within `IFNAMSIZ_MINUS1` characters.
///
/// When `use_hash` is `false`, the name is simply truncated.
/// When `use_hash` is `true` (the modern behaviour), the last 4 characters
/// before the NUL are replaced with a URL-safe base64 encoding of a
/// 24-bit SipHash of the original name, providing better uniqueness.
///
/// Returns `Ok(true)` if the name was modified, `Ok(false)` if it already fit.
pub fn netif_shorten_ifname(ifname: &mut String, use_hash: bool) -> Result<bool, NetifError> {
    if ifname.is_empty() {
        return Err(NetifError::EmptyName);
    }
    if ifname.len() < IFNAMSIZ {
        return Ok(false);
    }

    if use_hash {
        // Use a deterministic hash to generate a suffix for better uniqueness.
        // The C code uses SipHash-2-4 with a fixed key; here we use a simple
        // FNV-1a hash as a self-contained pure-Rust substitute.
        let hash = fnv1a_hash(ifname.as_bytes());
        // Encode the lower 24 bits as 4 URL-safe base64 characters.
        let suffix = [
            urlsafe_base64char((hash >> 18) & 0x3f),
            urlsafe_base64char((hash >> 12) & 0x3f),
            urlsafe_base64char((hash >> 6) & 0x3f),
            urlsafe_base64char(hash & 0x3f),
        ];
        let base_len = IFNAMSIZ_MINUS1 - 4;
        ifname.truncate(base_len);
        ifname.push_str(&suffix.iter().map(|&b| b as char).collect::<String>());
    } else {
        // Legacy behaviour: just truncate.
        ifname.truncate(IFNAMSIZ_MINUS1);
    }

    Ok(true)
}

/// FNV-1a 64-bit hash.
fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Encode a 6-bit value as a URL-safe base64 character.
fn urlsafe_base64char(v: u64) -> u8 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    ALPHABET[(v & 0x3f) as usize]
}

// ── System-call wrappers ──────────────────────────────────────────────────

/// Map a network interface name to its index via `if_nametoindex(3)`.
///
/// Returns the interface index on success, or `NetifError` on failure.
pub fn if_nametoindex(name: &str) -> Result<u32, NetifError> {
    validate_ifname(name)?;

    let c_name = std::ffi::CString::new(name).map_err(|_| NetifError::InvalidName)?;

    // SAFETY: `c_name` is a valid NUL-terminated C string.  `if_nametoindex`
    // is a standard POSIX function that does not retain the pointer.
    let index = unsafe_ffi!(libc::if_nametoindex(c_name.as_ptr()));

    if index == 0 {
        Err(NetifError::NotFound)
    } else {
        Ok(index)
    }
}

/// Map a network interface index to its name via `if_indextoname(3)`.
///
/// Returns the interface name on success, or `NetifError` on failure.
pub fn if_indextoname(index: u32) -> Result<String, NetifError> {
    let mut buf = [0u8; IFNAMSIZ];

    // SAFETY: `buf` is a valid mutable buffer of `IFNAMSIZ` bytes.
    // `if_indextoname` is a standard POSIX function.
    let ptr = unsafe_ffi!(libc::if_indextoname(index, buf.as_mut_ptr().cast()));

    if ptr.is_null() {
        Err(NetifError::NotFound)
    } else {
        let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
        String::from_utf8(buf[..nul_pos].to_vec()).map_err(|_| NetifError::InvalidName)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── flags helpers ──────────────────────────────────────────────────

    #[test]
    fn test_flags_set_both() {
        assert!(flags_set(
            IFF_LOWER_UP | IFF_RUNNING,
            IFF_LOWER_UP | IFF_RUNNING
        ));
    }

    #[test]
    fn test_flags_set_partial() {
        assert!(!flags_set(IFF_LOWER_UP, IFF_LOWER_UP | IFF_RUNNING));
    }

    #[test]
    fn test_flags_set_none() {
        assert!(!flags_set(0, IFF_LOWER_UP));
    }

    #[test]
    fn test_flags_has_any() {
        assert!(flags_has_any(IFF_LOWER_UP, IFF_LOWER_UP | IFF_RUNNING));
        assert!(!flags_has_any(0, IFF_LOWER_UP));
    }

    // ── carrier detection ─────────────────────────────────────────────

    #[test]
    fn test_carrier_operstate_up() {
        assert!(netif_has_carrier(IF_OPER_UP, 0));
    }

    #[test]
    fn test_carrier_operstate_down() {
        // IF_OPER_DOWN = 2
        assert!(!netif_has_carrier(2, 0));
    }

    #[test]
    fn test_carrier_unknown_with_lower_up_running() {
        let flags = IFF_LOWER_UP | IFF_RUNNING;
        assert!(netif_has_carrier(IF_OPER_UNKNOWN, flags));
    }

    #[test]
    fn test_carrier_unknown_dormant() {
        let flags = IFF_LOWER_UP | IFF_RUNNING | IFF_DORMANT;
        assert!(!netif_has_carrier(IF_OPER_UNKNOWN, flags));
    }

    #[test]
    fn test_carrier_unknown_no_flags() {
        assert!(!netif_has_carrier(IF_OPER_UNKNOWN, 0));
    }

    // ── name validation ───────────────────────────────────────────────

    #[test]
    fn test_valid_ifname() {
        assert!(netif_name_is_valid("eth0"));
        assert!(netif_name_is_valid("enp3s0"));
        assert!(netif_name_is_valid("br-0"));
        assert!(netif_name_is_valid("wl_test"));
        assert!(netif_name_is_valid("_underscore"));
        assert!(netif_name_is_valid("a"));
    }

    #[test]
    fn test_invalid_ifname() {
        assert!(!netif_name_is_valid(""));
        assert!(!netif_name_is_valid("-leading"));
        assert!(!netif_name_is_valid("has spaces"));
        assert!(!netif_name_is_valid("has.dots"));
        assert!(!netif_name_is_valid("has/slash"));
    }

    #[test]
    fn test_ifname_too_long() {
        let long = "a".repeat(IFNAMSIZ);
        assert!(!netif_name_is_valid(&long));
        // Exactly IFNAMSIZ-1 is ok
        let ok = "a".repeat(IFNAMSIZ_MINUS1);
        assert!(netif_name_is_valid(&ok));
    }

    #[test]
    fn test_validate_ifname_ok() {
        assert!(validate_ifname("eth0").is_ok());
    }

    #[test]
    fn test_validate_ifname_errors() {
        assert_eq!(validate_ifname(""), Err(NetifError::EmptyName));
        let long = "a".repeat(IFNAMSIZ);
        assert_eq!(validate_ifname(&long), Err(NetifError::NameTooLong));
        assert_eq!(validate_ifname(".bad"), Err(NetifError::InvalidName));
    }

    // ── Ethernet address helpers ──────────────────────────────────────

    #[test]
    fn test_ether_addr_null() {
        assert!(ether_addr_is_null(&[0; 6]));
        assert!(!ether_addr_is_null(&[0, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn test_ether_addr_broadcast() {
        assert!(ether_addr_is_broadcast(&[0xff; 6]));
        assert!(!ether_addr_is_broadcast(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xfe
        ]));
    }

    #[test]
    fn test_ether_addr_multicast() {
        // I/G bit set in first byte
        assert!(ether_addr_is_multicast(&[0x01, 0, 0, 0, 0, 0]));
        assert!(ether_addr_is_multicast(&[0x33, 0x33, 0, 0, 0, 0]));
        assert!(!ether_addr_is_multicast(&[0x02, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_ether_addr_local() {
        // U/L bit set
        assert!(ether_addr_is_local(&[0x02, 0, 0, 0, 0, 0]));
        assert!(ether_addr_is_local(&[0x0a, 0, 0, 0, 0, 0]));
        assert!(!ether_addr_is_local(&[0x00, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_ether_addr_normalize_rejects_null() {
        let mut addr = [0u8; 6];
        assert_eq!(
            ether_addr_normalize(&mut addr, true),
            Err(NetifError::InvalidHwAddr("null MAC address"))
        );
    }

    #[test]
    fn test_ether_addr_normalize_rejects_broadcast() {
        let mut addr = [0xffu8; 6];
        assert_eq!(
            ether_addr_normalize(&mut addr, true),
            Err(NetifError::InvalidHwAddr("broadcast MAC address"))
        );
    }

    #[test]
    fn test_ether_addr_normalize_clears_multicast() {
        let mut addr = [0x33, 0x22, 0x11, 0x44, 0x55, 0x66];
        ether_addr_normalize(&mut addr, true).unwrap();
        // First byte should have I/G bit cleared: 0x33 & 0xfe = 0x32
        assert_eq!(addr[0], 0x32);
        assert!(!ether_addr_is_multicast(&addr));
    }

    #[test]
    fn test_ether_addr_normalize_static_no_local_bit() {
        // Static address: local bit should NOT be forced on.
        let mut addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        ether_addr_normalize(&mut addr, true).unwrap();
        assert_eq!(addr[0], 0x00);
    }

    #[test]
    fn test_ether_addr_normalize_nonstatic_sets_local() {
        // Non-static: if local bit is not set, it should be added.
        let mut addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        ether_addr_normalize(&mut addr, false).unwrap();
        assert_eq!(addr[0], 0x02);
        assert!(ether_addr_is_local(&addr));
    }

    // ── arphrd helpers ────────────────────────────────────────────────

    #[test]
    fn test_arphrd_to_hw_addr_len() {
        assert_eq!(arphrd_to_hw_addr_len(ARPHRD_ETHER), Some(ETHER_ADDR_LEN));
        assert_eq!(
            arphrd_to_hw_addr_len(ARPHRD_INFINIBAND),
            Some(INFINIBAND_ADDR_LEN)
        );
        assert_eq!(arphrd_to_hw_addr_len(999), None);
    }

    // ── verify_hardware_address ───────────────────────────────────────

    #[test]
    fn test_verify_hw_addr_empty_ok() {
        let mut empty: [u8; 0] = [];
        assert!(verify_hardware_address(ARPHRD_ETHER, &mut empty, true).is_ok());
    }

    #[test]
    fn test_verify_hw_addr_ether_ok() {
        let mut addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert!(verify_hardware_address(ARPHRD_ETHER, &mut addr, true).is_ok());
        // After normalisation, local bit should be set for non-static
        let mut addr2 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        verify_hardware_address(ARPHRD_ETHER, &mut addr2, false).unwrap();
        assert_eq!(addr2[0], 0x02);
    }

    #[test]
    fn test_verify_hw_addr_length_mismatch() {
        let mut short = [0u8; 4];
        assert_eq!(
            verify_hardware_address(ARPHRD_ETHER, &mut short, true),
            Err(NetifError::HwAddrLengthMismatch {
                actual: 4,
                expected: ETHER_ADDR_LEN,
            })
        );
    }

    #[test]
    fn test_verify_hw_addr_unsupported_type() {
        let mut addr = [0u8; 8];
        assert_eq!(
            verify_hardware_address(999, &mut addr, true),
            Err(NetifError::UnsupportedType(999))
        );
    }

    // ── name shortening ───────────────────────────────────────────────

    #[test]
    fn test_shorten_ifname_already_short() {
        let mut name = String::from("eth0");
        assert!(!netif_shorten_ifname(&mut name, true).unwrap());
        assert_eq!(name, "eth0");
    }

    #[test]
    fn test_shorten_ifname_truncate() {
        let mut name = "a".repeat(20);
        assert!(netif_shorten_ifname(&mut name, false).unwrap());
        assert_eq!(name.len(), IFNAMSIZ_MINUS1);
    }

    #[test]
    fn test_shorten_ifname_hash() {
        let mut name = "verylonginterfacename".to_string();
        assert!(netif_shorten_ifname(&mut name, true).unwrap());
        assert_eq!(name.len(), IFNAMSIZ_MINUS1);
        // The last 4 chars should be URL-safe base64 characters.
        let suffix = &name[IFNAMSIZ_MINUS1 - 4..];
        for ch in suffix.chars() {
            assert!(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
        }
    }

    #[test]
    fn test_shorten_ifname_empty() {
        let mut name = String::new();
        assert_eq!(
            netif_shorten_ifname(&mut name, true),
            Err(NetifError::EmptyName)
        );
    }

    #[test]
    fn test_shorten_ifname_deterministic() {
        let mut a = "thisisaverylonginterfacename".to_string();
        let mut b = "thisisaverylonginterfacename".to_string();
        netif_shorten_ifname(&mut a, true).unwrap();
        netif_shorten_ifname(&mut b, true).unwrap();
        assert_eq!(a, b);
    }

    // ── FNV-1a hash ───────────────────────────────────────────────────

    #[test]
    fn test_fnv1a_empty() {
        // FNV-1a offset basis
        assert_eq!(fnv1a_hash(b""), 0xcbf29ce484222325);
    }

    #[test]
    fn test_fnv1a_deterministic() {
        assert_eq!(fnv1a_hash(b"hello"), fnv1a_hash(b"hello"));
        assert_ne!(fnv1a_hash(b"hello"), fnv1a_hash(b"world"));
    }

    // ── urlsafe_base64char ────────────────────────────────────────────

    #[test]
    fn test_urlsafe_base64char_range() {
        for i in 0..64u64 {
            let ch = urlsafe_base64char(i);
            assert!(ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-');
        }
    }

    // ── NetifError Display ────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = NetifError::EmptyName;
        assert!(!e.to_string().is_empty());

        let e = NetifError::NameTooLong;
        assert!(e.to_string().contains("15"));

        let e = NetifError::HwAddrLengthMismatch {
            actual: 4,
            expected: 6,
        };
        assert!(e.to_string().contains("4") && e.to_string().contains("6"));
    }
}
