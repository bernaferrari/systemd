// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.arphrd-util; authority=src/basic/arphrd-util.c,src/basic/arphrd-util.h,src/basic/arphrd-to-name.awk,src/basic/generate-arphrd-list.sh,src/basic/meson.build,src/include/uapi/linux/if_arp.h,tools/generate-gperfs.py
//
// ARP hardware type name/value lookups and hardware address length mapping.

use std::ffi::{CStr, c_char, c_int};

use crate::ffi::Errno;
use crate::ffi_string_table;

// ── Arphrd enum ───────────────────────────────────────────────────────────

/// ARP hardware type constants from linux/if_arp.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arphrd {
    Netrom = 0,
    Ether = 1,
    Eether = 2,
    Ax25 = 3,
    Pronet = 4,
    Chaos = 5,
    Ieee802 = 6,
    Arcnet = 7,
    Appletlk = 8,
    Dlci = 15,
    Atm = 19,
    Metricom = 23,
    Ieee1394 = 24,
    Eui64 = 27,
    Infiniband = 32,
    Slip = 256,
    Cslip = 257,
    Slip6 = 258,
    Cslip6 = 259,
    Rsrvd = 260,
    Adapt = 264,
    Rose = 270,
    X25 = 271,
    Hwx25 = 272,
    Can = 280,
    Mctp = 290,
    Ppp = 512,
    Cisco = 513,
    Lapb = 516,
    Ddcmp = 517,
    Rawhdlc = 518,
    Rawip = 519,
    Tunnel = 768,
    Tunnel6 = 769,
    Frad = 770,
    Skip = 771,
    Loopback = 772,
    Localtlk = 773,
    Fddi = 774,
    Bif = 775,
    Sit = 776,
    Ipddp = 777,
    Ipgre = 778,
    Pimreg = 779,
    Hippi = 780,
    Ash = 781,
    Econet = 782,
    Irda = 783,
    Fcpp = 784,
    Fcal = 785,
    Fcpl = 786,
    Fcfabric = 787,
    Ieee802Tr = 800,
    Ieee80211 = 801,
    Ieee80211Prism = 802,
    Ieee80211Radiotap = 803,
    Ieee802154 = 804,
    Ieee802154Monitor = 805,
    Phonet = 820,
    PhonetPipe = 821,
    Caif = 822,
    Ip6gre = 823,
    Netlink = 824,
    Sixlowpan = 825,
    Vsockmon = 826,
    None = 65534,
    Void = 65535,
}

// ── Value-to-name lookup table (sorted by value) ──────────────────────────
//
// Mirrors the list generated from linux/if_arp.h. The to-name AWK authority
// deliberately omits HDLC because it aliases CISCO; from-name accepts that
// alias explicitly below.

struct ArphrdValueEntry {
    value: i32,
    name: &'static [u8],
}

static ARPHRD_TO_NAME_TABLE: &[ArphrdValueEntry] = &[
    ArphrdValueEntry {
        value: 0,
        name: b"NETROM\0",
    },
    ArphrdValueEntry {
        value: 1,
        name: b"ETHER\0",
    },
    ArphrdValueEntry {
        value: 2,
        name: b"EETHER\0",
    },
    ArphrdValueEntry {
        value: 3,
        name: b"AX25\0",
    },
    ArphrdValueEntry {
        value: 4,
        name: b"PRONET\0",
    },
    ArphrdValueEntry {
        value: 5,
        name: b"CHAOS\0",
    },
    ArphrdValueEntry {
        value: 6,
        name: b"IEEE802\0",
    },
    ArphrdValueEntry {
        value: 7,
        name: b"ARCNET\0",
    },
    ArphrdValueEntry {
        value: 8,
        name: b"APPLETLK\0",
    },
    ArphrdValueEntry {
        value: 15,
        name: b"DLCI\0",
    },
    ArphrdValueEntry {
        value: 19,
        name: b"ATM\0",
    },
    ArphrdValueEntry {
        value: 23,
        name: b"METRICOM\0",
    },
    ArphrdValueEntry {
        value: 24,
        name: b"IEEE1394\0",
    },
    ArphrdValueEntry {
        value: 27,
        name: b"EUI64\0",
    },
    ArphrdValueEntry {
        value: 32,
        name: b"INFINIBAND\0",
    },
    ArphrdValueEntry {
        value: 256,
        name: b"SLIP\0",
    },
    ArphrdValueEntry {
        value: 257,
        name: b"CSLIP\0",
    },
    ArphrdValueEntry {
        value: 258,
        name: b"SLIP6\0",
    },
    ArphrdValueEntry {
        value: 259,
        name: b"CSLIP6\0",
    },
    ArphrdValueEntry {
        value: 260,
        name: b"RSRVD\0",
    },
    ArphrdValueEntry {
        value: 264,
        name: b"ADAPT\0",
    },
    ArphrdValueEntry {
        value: 270,
        name: b"ROSE\0",
    },
    ArphrdValueEntry {
        value: 271,
        name: b"X25\0",
    },
    ArphrdValueEntry {
        value: 272,
        name: b"HWX25\0",
    },
    ArphrdValueEntry {
        value: 280,
        name: b"CAN\0",
    },
    ArphrdValueEntry {
        value: 290,
        name: b"MCTP\0",
    },
    ArphrdValueEntry {
        value: 512,
        name: b"PPP\0",
    },
    ArphrdValueEntry {
        value: 513,
        name: b"CISCO\0",
    },
    ArphrdValueEntry {
        value: 516,
        name: b"LAPB\0",
    },
    ArphrdValueEntry {
        value: 517,
        name: b"DDCMP\0",
    },
    ArphrdValueEntry {
        value: 518,
        name: b"RAWHDLC\0",
    },
    ArphrdValueEntry {
        value: 519,
        name: b"RAWIP\0",
    },
    ArphrdValueEntry {
        value: 768,
        name: b"TUNNEL\0",
    },
    ArphrdValueEntry {
        value: 769,
        name: b"TUNNEL6\0",
    },
    ArphrdValueEntry {
        value: 770,
        name: b"FRAD\0",
    },
    ArphrdValueEntry {
        value: 771,
        name: b"SKIP\0",
    },
    ArphrdValueEntry {
        value: 772,
        name: b"LOOPBACK\0",
    },
    ArphrdValueEntry {
        value: 773,
        name: b"LOCALTLK\0",
    },
    ArphrdValueEntry {
        value: 774,
        name: b"FDDI\0",
    },
    ArphrdValueEntry {
        value: 775,
        name: b"BIF\0",
    },
    ArphrdValueEntry {
        value: 776,
        name: b"SIT\0",
    },
    ArphrdValueEntry {
        value: 777,
        name: b"IPDDP\0",
    },
    ArphrdValueEntry {
        value: 778,
        name: b"IPGRE\0",
    },
    ArphrdValueEntry {
        value: 779,
        name: b"PIMREG\0",
    },
    ArphrdValueEntry {
        value: 780,
        name: b"HIPPI\0",
    },
    ArphrdValueEntry {
        value: 781,
        name: b"ASH\0",
    },
    ArphrdValueEntry {
        value: 782,
        name: b"ECONET\0",
    },
    ArphrdValueEntry {
        value: 783,
        name: b"IRDA\0",
    },
    ArphrdValueEntry {
        value: 784,
        name: b"FCPP\0",
    },
    ArphrdValueEntry {
        value: 785,
        name: b"FCAL\0",
    },
    ArphrdValueEntry {
        value: 786,
        name: b"FCPL\0",
    },
    ArphrdValueEntry {
        value: 787,
        name: b"FCFABRIC\0",
    },
    ArphrdValueEntry {
        value: 800,
        name: b"IEEE802_TR\0",
    },
    ArphrdValueEntry {
        value: 801,
        name: b"IEEE80211\0",
    },
    ArphrdValueEntry {
        value: 802,
        name: b"IEEE80211_PRISM\0",
    },
    ArphrdValueEntry {
        value: 803,
        name: b"IEEE80211_RADIOTAP\0",
    },
    ArphrdValueEntry {
        value: 804,
        name: b"IEEE802154\0",
    },
    ArphrdValueEntry {
        value: 805,
        name: b"IEEE802154_MONITOR\0",
    },
    ArphrdValueEntry {
        value: 820,
        name: b"PHONET\0",
    },
    ArphrdValueEntry {
        value: 821,
        name: b"PHONET_PIPE\0",
    },
    ArphrdValueEntry {
        value: 822,
        name: b"CAIF\0",
    },
    ArphrdValueEntry {
        value: 823,
        name: b"IP6GRE\0",
    },
    ArphrdValueEntry {
        value: 824,
        name: b"NETLINK\0",
    },
    ArphrdValueEntry {
        value: 825,
        name: b"6LOWPAN\0",
    },
    ArphrdValueEntry {
        value: 826,
        name: b"VSOCKMON\0",
    },
    ArphrdValueEntry {
        value: 65534,
        name: b"NONE\0",
    },
    ArphrdValueEntry {
        value: 65535,
        name: b"VOID\0",
    },
];

// ── arphrd_from_name ──────────────────────────────────────────────────────

fn arphrd_from_name_bytes(name: &[u8]) -> Result<i32, i32> {
    if name.eq_ignore_ascii_case(b"HDLC") {
        return Ok(Arphrd::Cisco as i32);
    }

    ARPHRD_TO_NAME_TABLE
        .iter()
        .find_map(|entry| {
            ffi_string_table::entry_cstr(entry.name)
                .to_bytes()
                .eq_ignore_ascii_case(name)
                .then_some(entry.value)
        })
        .ok_or_else(|| Errno::EINVAL.to_neg_errno())
}

/// Convert an ARPHRD name string to its integer value.
///
/// The generated C gperf table is ASCII case-insensitive and accepts the
/// `HDLC` alias for `CISCO`; names do not include an `ARPHRD_` prefix.
pub fn arphrd_from_name(name: &str) -> Result<i32, i32> {
    arphrd_from_name_bytes(name.as_bytes())
}

// ── arphrd_to_name ───────────────────────────────────────────────────────

/// Return the ARPHRD name string for the given hardware type value.
/// Returns None if the value is not recognized.
pub fn arphrd_to_name(id: i32) -> Option<&'static str> {
    arphrd_entry(id).map(|entry| ffi_string_table::entry_str(entry.name))
}

fn arphrd_entry(id: i32) -> Option<&'static ArphrdValueEntry> {
    let mut lo: usize = 0;
    let mut hi = ARPHRD_TO_NAME_TABLE.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let mid_val = ARPHRD_TO_NAME_TABLE[mid].value;
        if mid_val < id {
            lo = mid + 1;
        } else if mid_val > id {
            hi = mid;
        } else {
            return Some(&ARPHRD_TO_NAME_TABLE[mid]);
        }
    }
    None
}

// ── arphrd_to_hw_addr_len ────────────────────────────────────────────────

/// Return the hardware address length for the given ARP hardware type.
/// Matches C arphrd_to_hw_addr_len(): ETH_ALEN=6, INFINIBAND_ALEN=20,
/// sizeof(in_addr)=4, sizeof(in6_addr)=16.
pub fn arphrd_to_hw_addr_len(arphrd: u16) -> usize {
    match arphrd {
        1 => 6,               // ARPHRD_ETHER
        32 => 20,             // ARPHRD_INFINIBAND
        768 | 776 | 778 => 4, // TUNNEL, SIT, IPGRE
        769 | 823 => 16,      // TUNNEL6, IP6GRE
        _ => 0,
    }
}

/// C ABI facade for `arphrd_from_name()`.
///
/// The C authority asserts on NULL. The Rust facade returns `-EINVAL` for that
/// invalid call domain so the shadow ABI fails closed instead of aborting.
///
/// # Safety
///
/// A non-NULL `name` must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_arphrd_from_name(name: *const c_char) -> c_int {
    if name.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: required by this facade's contract and checked for NULL above.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    match arphrd_from_name_bytes(name) {
        Ok(value) | Err(value) => value,
    }
}

/// C ABI facade for `arphrd_to_name()`.
///
/// Returned pointers borrow immutable process-lifetime storage and must not be
/// freed. Unknown values return NULL.
#[unsafe(no_mangle)]
pub extern "C" fn rs_arphrd_to_name(id: c_int) -> *const c_char {
    arphrd_entry(id).map_or(std::ptr::null(), |entry| {
        ffi_string_table::entry_cstr(entry.name).as_ptr()
    })
}

/// C ABI facade for `arphrd_to_hw_addr_len()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_arphrd_to_hw_addr_len(arphrd: u16) -> usize {
    arphrd_to_hw_addr_len(arphrd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arphrd_from_name_ether() {
        assert_eq!(arphrd_from_name("ETHER"), Ok(1));
    }

    #[test]
    fn test_arphrd_from_name_loopback() {
        assert_eq!(arphrd_from_name("LOOPBACK"), Ok(772));
    }

    #[test]
    fn test_arphrd_from_name_netrom() {
        assert_eq!(arphrd_from_name("NETROM"), Ok(0));
    }

    #[test]
    fn test_arphrd_from_name_none_and_void() {
        assert_eq!(arphrd_from_name("NONE"), Ok(65534));
        assert_eq!(arphrd_from_name("VOID"), Ok(65535));
    }

    #[test]
    fn test_arphrd_from_name_matches_generated_gperf_semantics() {
        assert_eq!(arphrd_from_name("ether"), Ok(1));
        assert_eq!(arphrd_from_name("Ether"), Ok(1));
        assert_eq!(arphrd_from_name("HDLC"), Ok(513));
        assert!(arphrd_from_name("ARPHRD_ETHER").is_err());
    }

    #[test]
    fn test_arphrd_from_name_various() {
        assert_eq!(arphrd_from_name("AX25"), Ok(3));
        assert_eq!(arphrd_from_name("PPP"), Ok(512));
        assert_eq!(arphrd_from_name("CAN"), Ok(280));
        assert_eq!(arphrd_from_name("ATM"), Ok(19));
        assert_eq!(arphrd_from_name("INFINIBAND"), Ok(32));
        assert_eq!(arphrd_from_name("IEEE80211"), Ok(801));
        assert_eq!(arphrd_from_name("MCTP"), Ok(290));
        assert_eq!(arphrd_from_name("6LOWPAN"), Ok(825));
        assert_eq!(arphrd_from_name("IPDDP"), Ok(777));
        assert_eq!(arphrd_from_name("PIMREG"), Ok(779));
    }

    #[test]
    fn test_arphrd_from_name_invalid() {
        assert_eq!(
            arphrd_from_name("INVALID_TYPE"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(arphrd_from_name(""), Err(Errno::EINVAL.to_neg_errno()));
    }

    #[test]
    fn test_arphrd_from_name_partial_match() {
        assert!(arphrd_from_name("ETHE").is_err());
        assert!(arphrd_from_name("ETHERX").is_err());
    }

    #[test]
    fn test_arphrd_to_name_ether() {
        assert_eq!(arphrd_to_name(1), Some("ETHER"));
    }

    #[test]
    fn test_arphrd_to_name_netrom() {
        assert_eq!(arphrd_to_name(0), Some("NETROM"));
    }

    #[test]
    fn test_arphrd_to_name_none_and_void() {
        assert_eq!(arphrd_to_name(65534), Some("NONE"));
        assert_eq!(arphrd_to_name(65535), Some("VOID"));
    }

    #[test]
    fn test_arphrd_to_name_infiniband() {
        assert_eq!(arphrd_to_name(32), Some("INFINIBAND"));
    }

    #[test]
    fn test_arphrd_to_name_not_found() {
        assert!(arphrd_to_name(999).is_none());
        assert!(arphrd_to_name(42).is_none());
        assert!(arphrd_to_name(100).is_none());
        assert!(arphrd_to_name(-1).is_none());
    }

    #[test]
    fn test_arphrd_to_hw_addr_len_ether() {
        assert_eq!(arphrd_to_hw_addr_len(1), 6);
    }

    #[test]
    fn test_arphrd_to_hw_addr_len_infiniband() {
        assert_eq!(arphrd_to_hw_addr_len(32), 20);
    }

    #[test]
    fn test_arphrd_to_hw_addr_len_tunnel() {
        assert_eq!(arphrd_to_hw_addr_len(768), 4);
        assert_eq!(arphrd_to_hw_addr_len(776), 4);
        assert_eq!(arphrd_to_hw_addr_len(778), 4);
    }

    #[test]
    fn test_arphrd_to_hw_addr_len_tunnel6() {
        assert_eq!(arphrd_to_hw_addr_len(769), 16);
        assert_eq!(arphrd_to_hw_addr_len(823), 16);
    }

    #[test]
    fn test_arphrd_to_hw_addr_len_unknown() {
        assert_eq!(arphrd_to_hw_addr_len(0), 0);
        assert_eq!(arphrd_to_hw_addr_len(3), 0);
        assert_eq!(arphrd_to_hw_addr_len(999), 0);
        assert_eq!(arphrd_to_hw_addr_len(u16::MAX), 0);
    }

    #[test]
    fn test_arphrd_roundtrip() {
        let cases: &[(i32, &str)] = &[
            (1, "ETHER"),
            (3, "AX25"),
            (512, "PPP"),
            (280, "CAN"),
            (19, "ATM"),
            (772, "LOOPBACK"),
            (0, "NETROM"),
            (32, "INFINIBAND"),
        ];
        for &(val, name) in cases {
            assert_eq!(arphrd_from_name(name), Ok(val));
            assert_eq!(arphrd_to_name(val), Some(name));
        }
    }
}
