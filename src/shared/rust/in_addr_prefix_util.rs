// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/in-addr-prefix-util.c, src/shared/in-addr-prefix-util.h
//
// IPv4/IPv6 address prefix utilities.
//
// Provides types and functions for parsing, formatting, comparing,
// masking, and intersecting IP address prefixes in CIDR notation.
// Supports both IPv4 (e.g. 192.168.1.0/24) and IPv6 (e.g. 2001:db8::/32)
// address prefixes, as well as well-known named prefixes (any, localhost,
// link-local, multicast).

use crate::ffi::*;
use std::cmp::Ordering;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ── Error type ───────────────────────────────────────────────────────────

/// Error type for address prefix operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InAddrPrefixError {
    /// Address family not supported (not AF_INET or AF_INET6).
    EAFNOSUPPORT,
    /// Invalid argument.
    EINVAL,
    /// Numerical result out of range.
    ERANGE,
    /// Value too large for target type.
    ERANGEOverflow,
    /// No prefix length specified when required.
    ENOANO,
    /// String parsing failure.
    ParseError(String),
}

impl fmt::Display for InAddrPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EAFNOSUPPORT => write!(f, "Address family not supported"),
            Self::EINVAL => write!(f, "Invalid argument"),
            Self::ERANGE => write!(f, "Numerical result out of range"),
            Self::ERANGEOverflow => write!(f, "Value too large for target type"),
            Self::ENOANO => write!(f, "No prefix length specified when required"),
            Self::ParseError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for InAddrPrefixError {}

// ── InAddrPrefix ─────────────────────────────────────────────────────────

/// An IP address prefix (network address + prefix length).
///
/// Represents a CIDR prefix for either IPv4 or IPv6. The address is stored
/// as the network (masked) portion, and `prefixlen` is the number of
/// significant leading bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InAddrPrefix {
    pub address: IpAddr,
    pub prefixlen: u8,
}

// ── Well-known prefix constants ─────────────────────────────────────────

impl InAddrPrefix {
    /// `0.0.0.0/0` — matches all IPv4 addresses.
    pub const IPV4_ANY: Self = Self {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        prefixlen: 0,
    };

    /// `::/0` — matches all IPv6 addresses.
    pub const IPV6_ANY: Self = Self {
        address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        prefixlen: 0,
    };

    /// `127.0.0.0/8` — IPv4 loopback network.
    pub const IPV4_LOCALHOST: Self = Self {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        prefixlen: 8,
    };

    /// `::1/128` — IPv6 loopback address.
    pub const IPV6_LOCALHOST: Self = Self {
        address: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        prefixlen: 128,
    };

    /// `169.254.0.0/16` — IPv4 link-local addresses.
    pub const IPV4_LINKLOCAL: Self = Self {
        address: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        prefixlen: 16,
    };

    /// `fe80::/64` — IPv6 link-local addresses.
    pub const IPV6_LINKLOCAL: Self = Self {
        address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
        prefixlen: 64,
    };

    /// `224.0.0.0/4` — IPv4 multicast addresses.
    pub const IPV4_MULTICAST: Self = Self {
        address: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        prefixlen: 4,
    };

    /// `ff00::/8` — IPv6 multicast addresses.
    pub const IPV6_MULTICAST: Self = Self {
        address: IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
        prefixlen: 8,
    };
}

// ── Display / FromStr ───────────────────────────────────────────────────

impl fmt::Display for InAddrPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefixlen)
    }
}

impl FromStr for InAddrPrefix {
    type Err = InAddrPrefixError;

    /// Parse a CIDR prefix string like "192.168.1.0/24" or "::1/128".
    /// Auto-detects IPv4 vs IPv6. If no prefix length is given, defaults to
    /// the full address width (32 for IPv4, 128 for IPv6).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        in_addr_prefix_from_string_auto(s, InAddrPrefixLenMode::Full)
    }
}

// ── Prefix length mode ──────────────────────────────────────────────────

/// Controls behavior when no prefix length is specified in a prefix string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InAddrPrefixLenMode {
    /// Default to full address width (32 for IPv4, 128 for IPv6).
    Full,
    /// Return an error if no prefix length is specified.
    Refuse,
}

// ── Address family helpers ──────────────────────────────────────────────

/// Returns the full prefix length for the given address (32 for IPv4, 128 for IPv6).
fn family_address_bits(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Returns the byte size of the address family (4 for IPv4, 16 for IPv6).
fn family_address_size(addr: IpAddr) -> usize {
    match addr {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

// ── Masking ─────────────────────────────────────────────────────────────

/// Apply a network mask to an IPv4 address, keeping only the top `prefixlen` bits.
fn ipv4_mask(addr: &mut Ipv4Addr, prefixlen: u8) -> Result<(), InAddrPrefixError> {
    if prefixlen > 32 {
        return Err(InAddrPrefixError::ERANGE);
    }
    let bits = u32::from(*addr);
    let mask = if prefixlen == 0 {
        0
    } else {
        u32::MAX << (32 - prefixlen)
    };
    *addr = Ipv4Addr::from(bits & mask);
    Ok(())
}

/// Apply a network mask to an IPv6 address, keeping only the top `prefixlen` bits.
fn ipv6_mask(addr: &mut Ipv6Addr, prefixlen: u8) -> Result<(), InAddrPrefixError> {
    if prefixlen > 128 {
        return Err(InAddrPrefixError::ERANGE);
    }
    let mut segments = addr.segments();
    let mut remaining = prefixlen;
    for seg in segments.iter_mut() {
        if remaining >= 16 {
            *seg &= 0xFFFF;
            remaining -= 16;
        } else if remaining > 0 {
            *seg &= 0xFFFF << (16 - remaining);
            remaining = 0;
        } else {
            *seg = 0;
        }
    }
    *addr = Ipv6Addr::from(segments);
    Ok(())
}

/// Apply a network mask to an IP address, keeping only the top `prefixlen` bits.
pub fn in_addr_mask(addr: &mut IpAddr, prefixlen: u8) -> Result<(), InAddrPrefixError> {
    match addr {
        IpAddr::V4(ref mut a) => ipv4_mask(a, prefixlen),
        IpAddr::V6(ref mut a) => ipv6_mask(a, prefixlen),
    }
}

// ── Parsing ─────────────────────────────────────────────────────────────

/// Parse a prefix length string for the given address family.
fn parse_prefixlen(s: &str, max_bits: u8) -> Result<u8, InAddrPrefixError> {
    let val: u8 = s.parse().map_err(|_| InAddrPrefixError::EINVAL)?;
    if val > max_bits {
        return Err(InAddrPrefixError::ERANGE);
    }
    Ok(val)
}

/// Parse a CIDR prefix string with a known address family.
///
/// Parses strings like `"192.168.1.0/24"` (IPv4) or `"2001:db8::/32"` (IPv6).
/// If no `/prefixlen` is given, defaults to the full address width.
pub fn in_addr_prefix_from_string(
    s: &str,
    family: &IpAddr,
) -> Result<InAddrPrefix, InAddrPrefixError> {
    let max_bits = family_address_bits(*family);

    let (addr_str, prefixlen) = if let Some(slash) = s.find('/') {
        let addr_part = &s[..slash];
        let len_part = &s[slash + 1..];
        let k = parse_prefixlen(len_part, max_bits)?;
        (addr_part, k)
    } else {
        (s, max_bits)
    };

    let addr = match family {
        IpAddr::V4(_) => {
            let a: Ipv4Addr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
                InAddrPrefixError::ParseError(e.to_string())
            })?;
            IpAddr::V4(a)
        }
        IpAddr::V6(_) => {
            let a: Ipv6Addr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
                InAddrPrefixError::ParseError(e.to_string())
            })?;
            IpAddr::V6(a)
        }
    };

    Ok(InAddrPrefix {
        address: addr,
        prefixlen,
    })
}

/// Parse a CIDR prefix string, auto-detecting the address family.
///
/// Parses strings like `"192.168.1.0/24"` or `"2001:db8::/32"`.
/// Tries IPv4 first, then IPv6. The `mode` controls behavior when
/// no prefix length is specified.
pub fn in_addr_prefix_from_string_auto(
    s: &str,
    mode: InAddrPrefixLenMode,
) -> Result<InAddrPrefix, InAddrPrefixError> {
    let (addr_str, explicit_prefix) = if let Some(slash) = s.find('/') {
        (&s[..slash], Some(&s[slash + 1..]))
    } else {
        (s, None)
    };

    // Try IPv4 first, then IPv6.
    let addr = if let Ok(a) = addr_str.parse::<Ipv4Addr>() {
        IpAddr::V4(a)
    } else if let Ok(a) = addr_str.parse::<Ipv6Addr>() {
        IpAddr::V6(a)
    } else {
        return Err(InAddrPrefixError::ParseError(format!(
            "Invalid IP address: {}",
            addr_str
        )));
    };

    let max_bits = family_address_bits(addr);
    let prefixlen = if let Some(len_str) = explicit_prefix {
        parse_prefixlen(len_str, max_bits)?
    } else {
        match mode {
            InAddrPrefixLenMode::Full => max_bits,
            InAddrPrefixLenMode::Refuse => return Err(InAddrPrefixError::ENOANO),
        }
    };

    Ok(InAddrPrefix {
        address: addr,
        prefixlen,
    })
}

// ── Formatting ──────────────────────────────────────────────────────────

/// Convert a prefix to a CIDR notation string (e.g. "192.168.1.0/24").
pub fn in_addr_prefix_to_string(prefix: &InAddrPrefix) -> String {
    format!("{}/{}", prefix.address, prefix.prefixlen)
}

// ── Comparison ──────────────────────────────────────────────────────────

impl Ord for InAddrPrefix {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare by family first (IPv4 < IPv6), then prefixlen, then address.
        let family_cmp = match (&self.address, &other.address) {
            (IpAddr::V4(_), IpAddr::V4(_)) => Ordering::Equal,
            (IpAddr::V6(_), IpAddr::V6(_)) => Ordering::Equal,
            (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
            (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
        };
        if family_cmp != Ordering::Equal {
            return family_cmp;
        }

        match self.prefixlen.cmp(&other.prefixlen) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Compare address bytes within the prefix length.
        match (&self.address, &other.address) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let m = u32::from(*a) ^ u32::from(*b);
                let mask = if self.prefixlen == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefixlen)
                };
                (m & mask).cmp(&0)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let octets_a = a.octets();
                let octets_b = b.octets();
                let mut remaining = self.prefixlen as usize;
                for i in 0..16 {
                    let x = octets_a[i] ^ octets_b[i];
                    if remaining >= 8 {
                        if x != 0 {
                            return x.cmp(&0);
                        }
                        remaining -= 8;
                    } else if remaining > 0 {
                        let mask = 0xFFu8 << (8 - remaining);
                        let masked = x & mask;
                        if masked != 0 {
                            return masked.cmp(&0);
                        }
                        break;
                    } else {
                        break;
                    }
                }
                Ordering::Equal
            }
            _ => unreachable!(),
        }
    }
}

impl PartialOrd for InAddrPrefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ── Intersection ────────────────────────────────────────────────────────

/// Check whether two IPv4 prefixes have any addresses in common.
fn ipv4_prefix_intersect(a: Ipv4Addr, a_prefixlen: u8, b: Ipv4Addr, b_prefixlen: u8) -> bool {
    let m = a_prefixlen.min(b_prefixlen).min(32);
    if m == 0 {
        return true;
    }
    let x = u32::from(a) ^ u32::from(b);
    let n = u32::MAX << (32 - m);
    (x & n) == 0
}

/// Check whether two IPv6 prefixes have any addresses in common.
fn ipv6_prefix_intersect(a: Ipv6Addr, a_prefixlen: u8, b: Ipv6Addr, b_prefixlen: u8) -> bool {
    let m = a_prefixlen.min(b_prefixlen).min(128);
    if m == 0 {
        return true;
    }
    let octets_a = a.octets();
    let octets_b = b.octets();
    let mut remaining = m as usize;
    for i in 0..16 {
        let x = octets_a[i] ^ octets_b[i];
        let mask = if remaining < 8 {
            0xFFu8 << (8 - remaining)
        } else {
            0xFF
        };
        if (x & mask) != 0 {
            return false;
        }
        if remaining <= 8 {
            break;
        }
        remaining -= 8;
    }
    true
}

/// Check whether two IP address prefixes have any addresses in common.
///
/// Two prefixes intersect if there exists at least one address that belongs
/// to both networks.
pub fn in_addr_prefix_intersect(
    a: &InAddrPrefix,
    b: &InAddrPrefix,
) -> Result<bool, InAddrPrefixError> {
    match (&a.address, &b.address) {
        (IpAddr::V4(aa), IpAddr::V4(bb)) => {
            Ok(ipv4_prefix_intersect(*aa, a.prefixlen, *bb, b.prefixlen))
        }
        (IpAddr::V6(aa), IpAddr::V6(bb)) => {
            Ok(ipv6_prefix_intersect(*aa, a.prefixlen, *bb, b.prefixlen))
        }
        _ => Err(InAddrPrefixError::EAFNOSUPPORT),
    }
}

// ── Prefix covers ───────────────────────────────────────────────────────

/// Check whether `prefix` covers `address`, i.e. the address falls within the prefix network.
pub fn in_addr_prefix_covers(
    prefix: &InAddrPrefix,
    address: &IpAddr,
) -> Result<bool, InAddrPrefixError> {
    if std::mem::discriminant(&prefix.address) != std::mem::discriminant(address) {
        return Err(InAddrPrefixError::EAFNOSUPPORT);
    }

    match (&prefix.address, address) {
        (IpAddr::V4(pa), IpAddr::V4(aa)) => {
            let m = prefix.prefixlen.min(32);
            if m == 0 {
                return Ok(true);
            }
            let x = u32::from(*pa) ^ u32::from(*aa);
            let mask = u32::MAX << (32 - m);
            Ok((x & mask) == 0)
        }
        (IpAddr::V6(pa), IpAddr::V6(aa)) => {
            let m = prefix.prefixlen.min(128);
            if m == 0 {
                return Ok(true);
            }
            let octets_p = pa.octets();
            let octets_a = aa.octets();
            let mut remaining = m as usize;
            for i in 0..16 {
                let x = octets_p[i] ^ octets_a[i];
                let mask = if remaining < 8 {
                    0xFFu8 << (8 - remaining)
                } else {
                    0xFF
                };
                if (x & mask) != 0 {
                    return Ok(false);
                }
                if remaining <= 8 {
                    break;
                }
                remaining -= 8;
            }
            Ok(true)
        }
        _ => unreachable!(),
    }
}

// ── Prefix set operations ───────────────────────────────────────────────

/// Check whether a set of prefixes contains both `0.0.0.0/0` and `::/0`.
pub fn in_addr_prefixes_is_any(prefixes: &[InAddrPrefix]) -> bool {
    prefixes.contains(&InAddrPrefix::IPV4_ANY) && prefixes.contains(&InAddrPrefix::IPV6_ANY)
}

/// Add a prefix to a deduplicated set, applying the network mask.
/// Returns `true` if the prefix was newly inserted, `false` if it already existed.
pub fn in_addr_prefix_add(
    prefixes: &mut Vec<InAddrPrefix>,
    prefix: InAddrPrefix,
) -> Result<bool, InAddrPrefixError> {
    let mut masked = prefix;
    in_addr_mask(&mut masked.address, masked.prefixlen)?;

    if prefixes.contains(&masked) {
        return Ok(false);
    }

    prefixes.push(masked);
    Ok(true)
}

/// Merge all prefixes from `src` into `dest`.
pub fn in_addr_prefixes_merge(
    dest: &mut Vec<InAddrPrefix>,
    src: &[InAddrPrefix],
) -> Result<(), InAddrPrefixError> {
    for &p in src {
        in_addr_prefix_add(dest, p)?;
    }
    Ok(())
}

/// Reduce a set of prefixes by removing entries that are fully covered by
/// a less-specific (shorter prefix) entry already in the set.
///
/// For example, if both `10.0.0.0/8` and `10.1.0.0/16` are in the set,
/// `10.1.0.0/16` is redundant and will be removed.
pub fn in_addr_prefixes_reduce(prefixes: &mut Vec<InAddrPrefix>) {
    // Collect prefix lengths that exist for each family.
    let mut ipv4_has_any = false;
    let mut ipv6_has_any = false;
    let mut ipv4_prefixlens = [false; 33]; // 0..=32
    let mut ipv6_prefixlens = [false; 129]; // 0..=128

    for p in prefixes.iter() {
        match p.address {
            IpAddr::V4(_) => {
                if p.prefixlen == 0 {
                    ipv4_has_any = true;
                } else if (p.prefixlen as usize) <= 32 {
                    ipv4_prefixlens[p.prefixlen as usize] = true;
                }
            }
            IpAddr::V6(_) => {
                if p.prefixlen == 0 {
                    ipv6_has_any = true;
                } else if (p.prefixlen as usize) <= 128 {
                    ipv6_prefixlens[p.prefixlen as usize] = true;
                }
            }
        }
    }

    // Sort prefix lengths ascending for efficient checking.
    let mut ipv4_lens: Vec<u8> = (1..=32u8)
        .filter(|&i| ipv4_prefixlens[i as usize])
        .collect();
    let mut ipv6_lens: Vec<u8> = (1..=128u8)
        .filter(|&i| ipv6_prefixlens[i as usize])
        .collect();

    // Remove covered prefixes in-place (iterate in reverse to allow removal).
    let mut i = prefixes.len();
    while i > 0 {
        i -= 1;
        let p = &prefixes[i];
        if p.prefixlen == 0 {
            continue;
        }

        let (covered_by_any, lens) = match p.address {
            IpAddr::V4(_) => (ipv4_has_any, &ipv4_lens),
            IpAddr::V6(_) => (ipv6_has_any, &ipv6_lens),
        };

        let mut covered = covered_by_any;
        if !covered {
            for &len in lens {
                if len >= p.prefixlen {
                    break;
                }
                // Check if there's a prefix with this shorter length that covers p.
                let mut test_prefix = *p;
                test_prefix.prefixlen = len;
                if let Ok(()) = in_addr_mask(&mut test_prefix.address, len) {
                    if prefixes.contains(&test_prefix) {
                        covered = true;
                        break;
                    }
                }
            }
        }

        if covered {
            prefixes.swap_remove(i);
        }
    }
}

/// Parse a named prefix shortcut or a CIDR string.
///
/// Recognized shortcuts: `"any"`, `"localhost"`, `"link-local"`, `"multicast"`.
/// Returns the expanded prefixes for the specified family, or `None` if
/// the input is not a recognized shortcut.
pub fn in_addr_prefix_from_name(name: &str) -> Option<(Vec<InAddrPrefix>, Vec<InAddrPrefix>)> {
    match name {
        "any" => Some((vec![InAddrPrefix::IPV4_ANY], vec![InAddrPrefix::IPV6_ANY])),
        "localhost" => Some((
            vec![InAddrPrefix::IPV4_LOCALHOST],
            vec![InAddrPrefix::IPV6_LOCALHOST],
        )),
        "link-local" => Some((
            vec![InAddrPrefix::IPV4_LINKLOCAL],
            vec![InAddrPrefix::IPV6_LINKLOCAL],
        )),
        "multicast" => Some((
            vec![InAddrPrefix::IPV4_MULTICAST],
            vec![InAddrPrefix::IPV6_MULTICAST],
        )),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_any_constant() {
        let p = InAddrPrefix::IPV4_ANY;
        assert_eq!(p.address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(p.prefixlen, 0);
    }

    #[test]
    fn test_ipv6_any_constant() {
        let p = InAddrPrefix::IPV6_ANY;
        assert_eq!(p.address, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(p.prefixlen, 0);
    }

    #[test]
    fn test_localhost_constants() {
        assert_eq!(InAddrPrefix::IPV4_LOCALHOST.prefixlen, 8);
        assert_eq!(
            InAddrPrefix::IPV4_LOCALHOST.address,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0))
        );
        assert_eq!(InAddrPrefix::IPV6_LOCALHOST.prefixlen, 128);
        assert_eq!(
            InAddrPrefix::IPV6_LOCALHOST.address,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_linklocal_constants() {
        assert_eq!(InAddrPrefix::IPV4_LINKLOCAL.prefixlen, 16);
        assert_eq!(
            InAddrPrefix::IPV4_LINKLOCAL.address,
            IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0))
        );
        assert_eq!(InAddrPrefix::IPV6_LINKLOCAL.prefixlen, 64);
        assert_eq!(
            InAddrPrefix::IPV6_LINKLOCAL.address,
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn test_multicast_constants() {
        assert_eq!(InAddrPrefix::IPV4_MULTICAST.prefixlen, 4);
        assert_eq!(InAddrPrefix::IPV6_MULTICAST.prefixlen, 8);
    }

    #[test]
    fn test_parse_ipv4_prefix_with_len() {
        let p: InAddrPrefix = "192.168.1.0/24".parse().unwrap();
        assert_eq!(p.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(p.prefixlen, 24);
    }

    #[test]
    fn test_parse_ipv4_prefix_without_len() {
        let p = in_addr_prefix_from_string_auto("10.0.0.1", InAddrPrefixLenMode::Full).unwrap();
        assert_eq!(p.address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(p.prefixlen, 32); // defaults to full width
    }

    #[test]
    fn test_parse_ipv6_prefix_with_len() {
        let p: InAddrPrefix = "2001:db8::/32".parse().unwrap();
        assert_eq!(
            p.address,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
        assert_eq!(p.prefixlen, 32);
    }

    #[test]
    fn test_parse_ipv6_prefix_without_len() {
        let p = in_addr_prefix_from_string_auto("::1", InAddrPrefixLenMode::Full).unwrap();
        assert_eq!(p.address, IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(p.prefixlen, 128);
    }

    #[test]
    fn test_parse_prefix_refuse_mode() {
        let result = in_addr_prefix_from_string_auto("10.0.0.1", InAddrPrefixLenMode::Refuse);
        assert_eq!(result.unwrap_err(), InAddrPrefixError::ENOANO);
    }

    #[test]
    fn test_parse_invalid_prefix_len_too_large() {
        let result: Result<InAddrPrefix, _> = "10.0.0.0/33".parse();
        assert_eq!(result.unwrap_err(), InAddrPrefixError::ERANGE);
    }

    #[test]
    fn test_parse_invalid_address() {
        let result: Result<InAddrPrefix, _> = "not-an-address/24".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_to_string_ipv4() {
        let p = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefixlen: 24,
        };
        assert_eq!(in_addr_prefix_to_string(&p), "192.168.1.0/24");
    }

    #[test]
    fn test_to_string_ipv6() {
        let p = InAddrPrefix {
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefixlen: 32,
        };
        assert_eq!(in_addr_prefix_to_string(&p), "2001:db8::/32");
    }

    #[test]
    fn test_ipv4_mask() {
        let mut addr = Ipv4Addr::new(192, 168, 1, 100);
        ipv4_mask(&mut addr, 24).unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_ipv4_mask_zero() {
        let mut addr = Ipv4Addr::new(192, 168, 1, 100);
        ipv4_mask(&mut addr, 0).unwrap();
        assert_eq!(addr, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_ipv4_mask_full() {
        let mut addr = Ipv4Addr::new(192, 168, 1, 100);
        ipv4_mask(&mut addr, 32).unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_ipv6_mask() {
        let mut addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
        ipv6_mask(&mut addr, 32).unwrap();
        assert_eq!(addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    }

    #[test]
    fn test_ipv6_mask_partial_octet() {
        // /65 should clear the low 63 bits.
        let mut addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
        ipv6_mask(&mut addr, 65).unwrap();
        // First 8 octets = 64 bits + 1 bit of 9th octet.
        // 9th octet should be 0x80 (top bit only).
        assert_eq!(addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0x8000, 0, 0, 0));
    }

    #[test]
    fn test_ipv4_prefix_intersect_yes() {
        let a = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefixlen: 8,
        };
        let b = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
            prefixlen: 16,
        };
        assert!(in_addr_prefix_intersect(&a, &b).unwrap());
    }

    #[test]
    fn test_ipv4_prefix_intersect_no() {
        let a = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefixlen: 8,
        };
        let b = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefixlen: 16,
        };
        assert!(!in_addr_prefix_intersect(&a, &b).unwrap());
    }

    #[test]
    fn test_ipv6_prefix_intersect_yes() {
        let a = InAddrPrefix {
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefixlen: 32,
        };
        let b = InAddrPrefix {
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0)),
            prefixlen: 48,
        };
        assert!(in_addr_prefix_intersect(&a, &b).unwrap());
    }

    #[test]
    fn test_prefix_intersect_zero_length() {
        // /0 intersects with everything
        let a = InAddrPrefix::IPV4_ANY;
        let b = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefixlen: 24,
        };
        assert!(in_addr_prefix_intersect(&a, &b).unwrap());
    }

    #[test]
    fn test_prefix_intersect_mixed_family() {
        let a = InAddrPrefix::IPV4_ANY;
        let b = InAddrPrefix::IPV6_ANY;
        assert!(in_addr_prefix_intersect(&a, &b).is_err());
    }

    #[test]
    fn test_prefix_covers_ipv4() {
        let prefix = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefixlen: 8,
        };
        assert!(in_addr_prefix_covers(&prefix, &IpAddr::V4(Ipv4Addr::new(10, 5, 6, 7))).unwrap());
        assert!(
            !in_addr_prefix_covers(&prefix, &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).unwrap()
        );
    }

    #[test]
    fn test_prefix_covers_ipv6() {
        let prefix = InAddrPrefix {
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefixlen: 32,
        };
        assert!(
            in_addr_prefix_covers(
                &prefix,
                &IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0))
            )
            .unwrap()
        );
        assert!(
            !in_addr_prefix_covers(
                &prefix,
                &IpAddr::V6(Ipv6Addr::new(0x2002, 0xdb8, 0, 0, 0, 0, 0, 0))
            )
            .unwrap()
        );
    }

    #[test]
    fn test_is_any() {
        let prefixes = vec![InAddrPrefix::IPV4_ANY, InAddrPrefix::IPV6_ANY];
        assert!(in_addr_prefixes_is_any(&prefixes));
    }

    #[test]
    fn test_is_any_missing_v6() {
        let prefixes = vec![InAddrPrefix::IPV4_ANY];
        assert!(!in_addr_prefixes_is_any(&prefixes));
    }

    #[test]
    fn test_is_any_empty() {
        let prefixes: Vec<InAddrPrefix> = vec![];
        assert!(!in_addr_prefixes_is_any(&prefixes));
    }

    #[test]
    fn test_prefix_add_masks_address() {
        let mut prefixes = Vec::new();
        let result = in_addr_prefix_add(
            &mut prefixes,
            InAddrPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                prefixlen: 8,
            },
        )
        .unwrap();
        assert!(result); // newly inserted
        assert_eq!(prefixes[0].address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[test]
    fn test_prefix_add_duplicate() {
        let mut prefixes = Vec::new();
        in_addr_prefix_add(
            &mut prefixes,
            InAddrPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefixlen: 8,
            },
        )
        .unwrap();
        let result = in_addr_prefix_add(
            &mut prefixes,
            InAddrPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, 5, 5, 5)),
                prefixlen: 8,
            },
        )
        .unwrap();
        assert!(!result); // already exists (after masking)
        assert_eq!(prefixes.len(), 1);
    }

    #[test]
    fn test_prefixes_merge() {
        let mut dest = Vec::new();
        let src = vec![
            InAddrPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefixlen: 8,
            },
            InAddrPrefix {
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
                prefixlen: 64,
            },
        ];
        in_addr_prefixes_merge(&mut dest, &src).unwrap();
        assert_eq!(dest.len(), 2);
    }

    #[test]
    fn test_prefixes_reduce_removes_covered() {
        let mut prefixes = vec![
            InAddrPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefixlen: 8,
            },
            InAddrPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
                prefixlen: 16,
            },
        ];
        in_addr_prefixes_reduce(&mut prefixes);
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].prefixlen, 8);
    }

    #[test]
    fn test_prefixes_reduce_keeps_independent() {
        let mut prefixes = vec![
            InAddrPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefixlen: 8,
            },
            InAddrPrefix {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                prefixlen: 16,
            },
        ];
        in_addr_prefixes_reduce(&mut prefixes);
        assert_eq!(prefixes.len(), 2);
    }

    #[test]
    fn test_from_name_any() {
        let (v4, v6) = in_addr_prefix_from_name("any").unwrap();
        assert_eq!(v4[0], InAddrPrefix::IPV4_ANY);
        assert_eq!(v6[0], InAddrPrefix::IPV6_ANY);
    }

    #[test]
    fn test_from_name_localhost() {
        let (v4, v6) = in_addr_prefix_from_name("localhost").unwrap();
        assert_eq!(v4[0], InAddrPrefix::IPV4_LOCALHOST);
        assert_eq!(v6[0], InAddrPrefix::IPV6_LOCALHOST);
    }

    #[test]
    fn test_from_name_link_local() {
        let (v4, v6) = in_addr_prefix_from_name("link-local").unwrap();
        assert_eq!(v4[0], InAddrPrefix::IPV4_LINKLOCAL);
        assert_eq!(v6[0], InAddrPrefix::IPV6_LINKLOCAL);
    }

    #[test]
    fn test_from_name_multicast() {
        let (v4, v6) = in_addr_prefix_from_name("multicast").unwrap();
        assert_eq!(v4[0], InAddrPrefix::IPV4_MULTICAST);
        assert_eq!(v6[0], InAddrPrefix::IPV6_MULTICAST);
    }

    #[test]
    fn test_from_name_unknown() {
        assert!(in_addr_prefix_from_name("bogus").is_none());
    }

    #[test]
    fn test_ord_same_family() {
        let a = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefixlen: 8,
        };
        let b = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefixlen: 16,
        };
        assert_eq!(a.cmp(&b), Ordering::Less); // prefixlen 8 < 16
    }

    #[test]
    fn test_ord_ipv4_before_ipv6() {
        let a = InAddrPrefix::IPV4_ANY;
        let b = InAddrPrefix::IPV6_ANY;
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn test_display_trait() {
        let p = InAddrPrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefixlen: 24,
        };
        assert_eq!(format!("{}", p), "10.0.0.0/24");
    }
}
