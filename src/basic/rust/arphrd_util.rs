// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/arphrd-util.c, src/basic/arphrd-util.h
//
// ARP hardware type name/value lookups and hardware address length mapping.

use crate::ffi::Errno;

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
    Ipddp = 277,
    Pimreg = 279,
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
    Ipgre = 778,
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

// ── Name-to-value lookup table (sorted by name) ───────────────────────────

struct ArphrdEntry {
    name: &'static str,
    value: i32,
}

static ARPHRD_FROM_NAME_TABLE: &[ArphrdEntry] = &[
    ArphrdEntry {
        name: "6LOWPAN",
        value: 825,
    },
    ArphrdEntry {
        name: "ADAPT",
        value: 264,
    },
    ArphrdEntry {
        name: "APPLETLK",
        value: 8,
    },
    ArphrdEntry {
        name: "ARCNET",
        value: 7,
    },
    ArphrdEntry {
        name: "ARPHRD_NONE",
        value: 65534,
    },
    ArphrdEntry {
        name: "ARPHRD_VOID",
        value: 65535,
    },
    ArphrdEntry {
        name: "ASH",
        value: 781,
    },
    ArphrdEntry {
        name: "ATM",
        value: 19,
    },
    ArphrdEntry {
        name: "AX25",
        value: 3,
    },
    ArphrdEntry {
        name: "BIF",
        value: 775,
    },
    ArphrdEntry {
        name: "CAN",
        value: 280,
    },
    ArphrdEntry {
        name: "CAIF",
        value: 822,
    },
    ArphrdEntry {
        name: "CHAOS",
        value: 5,
    },
    ArphrdEntry {
        name: "CISCO",
        value: 513,
    },
    ArphrdEntry {
        name: "CSLIP",
        value: 257,
    },
    ArphrdEntry {
        name: "CSLIP6",
        value: 259,
    },
    ArphrdEntry {
        name: "DDCMP",
        value: 517,
    },
    ArphrdEntry {
        name: "DLCI",
        value: 15,
    },
    ArphrdEntry {
        name: "ECONET",
        value: 782,
    },
    ArphrdEntry {
        name: "EETHER",
        value: 2,
    },
    ArphrdEntry {
        name: "ETHER",
        value: 1,
    },
    ArphrdEntry {
        name: "EUI64",
        value: 27,
    },
    ArphrdEntry {
        name: "FDDI",
        value: 774,
    },
    ArphrdEntry {
        name: "FCAL",
        value: 785,
    },
    ArphrdEntry {
        name: "FCFABRIC",
        value: 787,
    },
    ArphrdEntry {
        name: "FCPL",
        value: 786,
    },
    ArphrdEntry {
        name: "FCPP",
        value: 784,
    },
    ArphrdEntry {
        name: "FRAD",
        value: 770,
    },
    ArphrdEntry {
        name: "HIPPI",
        value: 780,
    },
    ArphrdEntry {
        name: "HWX25",
        value: 272,
    },
    ArphrdEntry {
        name: "IEEE1394",
        value: 24,
    },
    ArphrdEntry {
        name: "IEEE802",
        value: 6,
    },
    ArphrdEntry {
        name: "IEEE80211",
        value: 801,
    },
    ArphrdEntry {
        name: "IEEE80211_PRISM",
        value: 802,
    },
    ArphrdEntry {
        name: "IEEE80211_RADIOTAP",
        value: 803,
    },
    ArphrdEntry {
        name: "IEEE802154",
        value: 804,
    },
    ArphrdEntry {
        name: "IEEE802154_MONITOR",
        value: 805,
    },
    ArphrdEntry {
        name: "IEEE802_TR",
        value: 800,
    },
    ArphrdEntry {
        name: "INFINIBAND",
        value: 32,
    },
    ArphrdEntry {
        name: "IP6GRE",
        value: 823,
    },
    ArphrdEntry {
        name: "IPDDP",
        value: 277,
    },
    ArphrdEntry {
        name: "IPGRE",
        value: 778,
    },
    ArphrdEntry {
        name: "IRDA",
        value: 783,
    },
    ArphrdEntry {
        name: "LAPB",
        value: 516,
    },
    ArphrdEntry {
        name: "LOCALTLK",
        value: 773,
    },
    ArphrdEntry {
        name: "LOOPBACK",
        value: 772,
    },
    ArphrdEntry {
        name: "METRICOM",
        value: 23,
    },
    ArphrdEntry {
        name: "MCTP",
        value: 290,
    },
    ArphrdEntry {
        name: "NETLINK",
        value: 824,
    },
    ArphrdEntry {
        name: "NETROM",
        value: 0,
    },
    ArphrdEntry {
        name: "NONE",
        value: 65534,
    },
    ArphrdEntry {
        name: "PIMREG",
        value: 279,
    },
    ArphrdEntry {
        name: "PHONET",
        value: 820,
    },
    ArphrdEntry {
        name: "PHONET_PIPE",
        value: 821,
    },
    ArphrdEntry {
        name: "PPP",
        value: 512,
    },
    ArphrdEntry {
        name: "PRONET",
        value: 4,
    },
    ArphrdEntry {
        name: "RAWHDLC",
        value: 518,
    },
    ArphrdEntry {
        name: "RAWIP",
        value: 519,
    },
    ArphrdEntry {
        name: "ROSE",
        value: 270,
    },
    ArphrdEntry {
        name: "RSRVD",
        value: 260,
    },
    ArphrdEntry {
        name: "SKIP",
        value: 771,
    },
    ArphrdEntry {
        name: "SLIP",
        value: 256,
    },
    ArphrdEntry {
        name: "SLIP6",
        value: 258,
    },
    ArphrdEntry {
        name: "SIT",
        value: 776,
    },
    ArphrdEntry {
        name: "TUNNEL",
        value: 768,
    },
    ArphrdEntry {
        name: "TUNNEL6",
        value: 769,
    },
    ArphrdEntry {
        name: "VOID",
        value: 65535,
    },
    ArphrdEntry {
        name: "VSOCKMON",
        value: 826,
    },
    ArphrdEntry {
        name: "X25",
        value: 271,
    },
];

// ── Value-to-name lookup table (sorted by value) ──────────────────────────

struct ArphrdValueEntry {
    value: i32,
    name: &'static str,
}

static ARPHRD_TO_NAME_TABLE: &[ArphrdValueEntry] = &[
    ArphrdValueEntry {
        value: 0,
        name: "NETROM",
    },
    ArphrdValueEntry {
        value: 1,
        name: "ETHER",
    },
    ArphrdValueEntry {
        value: 2,
        name: "EETHER",
    },
    ArphrdValueEntry {
        value: 3,
        name: "AX25",
    },
    ArphrdValueEntry {
        value: 4,
        name: "PRONET",
    },
    ArphrdValueEntry {
        value: 5,
        name: "CHAOS",
    },
    ArphrdValueEntry {
        value: 6,
        name: "IEEE802",
    },
    ArphrdValueEntry {
        value: 7,
        name: "ARCNET",
    },
    ArphrdValueEntry {
        value: 8,
        name: "APPLETLK",
    },
    ArphrdValueEntry {
        value: 15,
        name: "DLCI",
    },
    ArphrdValueEntry {
        value: 19,
        name: "ATM",
    },
    ArphrdValueEntry {
        value: 23,
        name: "METRICOM",
    },
    ArphrdValueEntry {
        value: 24,
        name: "IEEE1394",
    },
    ArphrdValueEntry {
        value: 27,
        name: "EUI64",
    },
    ArphrdValueEntry {
        value: 32,
        name: "INFINIBAND",
    },
    ArphrdValueEntry {
        value: 256,
        name: "SLIP",
    },
    ArphrdValueEntry {
        value: 257,
        name: "CSLIP",
    },
    ArphrdValueEntry {
        value: 258,
        name: "SLIP6",
    },
    ArphrdValueEntry {
        value: 259,
        name: "CSLIP6",
    },
    ArphrdValueEntry {
        value: 260,
        name: "RSRVD",
    },
    ArphrdValueEntry {
        value: 264,
        name: "ADAPT",
    },
    ArphrdValueEntry {
        value: 270,
        name: "ROSE",
    },
    ArphrdValueEntry {
        value: 271,
        name: "X25",
    },
    ArphrdValueEntry {
        value: 272,
        name: "HWX25",
    },
    ArphrdValueEntry {
        value: 277,
        name: "IPDDP",
    },
    ArphrdValueEntry {
        value: 279,
        name: "PIMREG",
    },
    ArphrdValueEntry {
        value: 280,
        name: "CAN",
    },
    ArphrdValueEntry {
        value: 290,
        name: "MCTP",
    },
    ArphrdValueEntry {
        value: 512,
        name: "PPP",
    },
    ArphrdValueEntry {
        value: 513,
        name: "CISCO",
    },
    ArphrdValueEntry {
        value: 516,
        name: "LAPB",
    },
    ArphrdValueEntry {
        value: 517,
        name: "DDCMP",
    },
    ArphrdValueEntry {
        value: 518,
        name: "RAWHDLC",
    },
    ArphrdValueEntry {
        value: 519,
        name: "RAWIP",
    },
    ArphrdValueEntry {
        value: 768,
        name: "TUNNEL",
    },
    ArphrdValueEntry {
        value: 769,
        name: "TUNNEL6",
    },
    ArphrdValueEntry {
        value: 770,
        name: "FRAD",
    },
    ArphrdValueEntry {
        value: 771,
        name: "SKIP",
    },
    ArphrdValueEntry {
        value: 772,
        name: "LOOPBACK",
    },
    ArphrdValueEntry {
        value: 773,
        name: "LOCALTLK",
    },
    ArphrdValueEntry {
        value: 774,
        name: "FDDI",
    },
    ArphrdValueEntry {
        value: 775,
        name: "BIF",
    },
    ArphrdValueEntry {
        value: 776,
        name: "SIT",
    },
    ArphrdValueEntry {
        value: 778,
        name: "IPGRE",
    },
    ArphrdValueEntry {
        value: 780,
        name: "HIPPI",
    },
    ArphrdValueEntry {
        value: 781,
        name: "ASH",
    },
    ArphrdValueEntry {
        value: 782,
        name: "ECONET",
    },
    ArphrdValueEntry {
        value: 783,
        name: "IRDA",
    },
    ArphrdValueEntry {
        value: 784,
        name: "FCPP",
    },
    ArphrdValueEntry {
        value: 785,
        name: "FCAL",
    },
    ArphrdValueEntry {
        value: 786,
        name: "FCPL",
    },
    ArphrdValueEntry {
        value: 787,
        name: "FCFABRIC",
    },
    ArphrdValueEntry {
        value: 800,
        name: "IEEE802_TR",
    },
    ArphrdValueEntry {
        value: 801,
        name: "IEEE80211",
    },
    ArphrdValueEntry {
        value: 802,
        name: "IEEE80211_PRISM",
    },
    ArphrdValueEntry {
        value: 803,
        name: "IEEE80211_RADIOTAP",
    },
    ArphrdValueEntry {
        value: 804,
        name: "IEEE802154",
    },
    ArphrdValueEntry {
        value: 805,
        name: "IEEE802154_MONITOR",
    },
    ArphrdValueEntry {
        value: 820,
        name: "PHONET",
    },
    ArphrdValueEntry {
        value: 821,
        name: "PHONET_PIPE",
    },
    ArphrdValueEntry {
        value: 822,
        name: "CAIF",
    },
    ArphrdValueEntry {
        value: 823,
        name: "IP6GRE",
    },
    ArphrdValueEntry {
        value: 824,
        name: "NETLINK",
    },
    ArphrdValueEntry {
        value: 825,
        name: "6LOWPAN",
    },
    ArphrdValueEntry {
        value: 826,
        name: "VSOCKMON",
    },
    ArphrdValueEntry {
        value: 65534,
        name: "NONE",
    },
    ArphrdValueEntry {
        value: 65535,
        name: "VOID",
    },
];

// ── arphrd_from_name ──────────────────────────────────────────────────────

/// Convert an ARPHRD name string to its integer value.
/// Accepts both short names ("ETHER") and "ARPHRD_ETHER" form.
/// Case-sensitive. Returns Err(-EINVAL) on unknown names.
pub fn arphrd_from_name(name: &str) -> Result<i32, i32> {
    let lookup = name.strip_prefix("ARPHRD_").unwrap_or(name);
    for entry in ARPHRD_FROM_NAME_TABLE {
        if entry.name == lookup {
            return Ok(entry.value);
        }
    }
    Err(Errno::EINVAL.to_neg_errno())
}

// ── arphrd_to_name ───────────────────────────────────────────────────────

/// Return the ARPHRD name string for the given hardware type value.
/// Returns None if the value is not recognized.
pub fn arphrd_to_name(id: i32) -> Option<&'static str> {
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
            return Some(ARPHRD_TO_NAME_TABLE[mid].name);
        }
    }
    None
}

// ── arphrd_to_hw_addr_len ────────────────────────────────────────────────

/// Return the hardware address length for the given ARP hardware type.
/// Matches C arphrd_to_hw_addr_len(): ETH_ALEN=6, INFINIBAND_ALEN=20,
/// sizeof(in_addr)=4, sizeof(in6_addr)=16.
pub fn arphrd_to_hw_addr_len(arphrd: u32) -> usize {
    match arphrd as i32 {
        1 => 6,               // ARPHRD_ETHER
        32 => 20,             // ARPHRD_INFINIBAND
        768 | 776 | 778 => 4, // TUNNEL, SIT, IPGRE
        769 | 823 => 16,      // TUNNEL6, IP6GRE
        _ => 0,
    }
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
    fn test_arphrd_from_name_arphrd_prefix() {
        assert_eq!(arphrd_from_name("ARPHRD_ETHER"), Ok(1));
        assert_eq!(arphrd_from_name("ARPHRD_NONE"), Ok(65534));
        assert_eq!(arphrd_from_name("ARPHRD_VOID"), Ok(65535));
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
    }

    #[test]
    fn test_arphrd_from_name_invalid() {
        assert_eq!(
            arphrd_from_name("INVALID_TYPE"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(arphrd_from_name(""), Err(Errno::EINVAL.to_neg_errno()));
        assert!(arphrd_from_name("ether").is_err());
        assert!(arphrd_from_name("Ether").is_err());
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
        assert_eq!(arphrd_to_hw_addr_len(u32::MAX), 0);
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
