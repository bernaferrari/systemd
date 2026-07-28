// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-types-genl.c
//

pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyType {
    Unspec,
    Flag,
    U8,
    U16,
    U32,
    U64,
    String,
    Binary,
    InAddr,
    EtherAddr,
    SockAddr,
    Nested(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyEntry {
    pub attribute: u16,
    pub kind: PolicyType,
    pub size: usize,
}

pub const GENL_CTRL_POLICIES: &[PolicyEntry] = &[
    PolicyEntry {
        attribute: 1,
        kind: PolicyType::U16,
        size: 0,
    },
    PolicyEntry {
        attribute: 2,
        kind: PolicyType::String,
        size: 0,
    },
    PolicyEntry {
        attribute: 3,
        kind: PolicyType::U32,
        size: 0,
    },
    PolicyEntry {
        attribute: 4,
        kind: PolicyType::U32,
        size: 0,
    },
    PolicyEntry {
        attribute: 5,
        kind: PolicyType::U32,
        size: 0,
    },
    PolicyEntry {
        attribute: 6,
        kind: PolicyType::Nested("genl_ctrl_ops"),
        size: 0,
    },
    PolicyEntry {
        attribute: 7,
        kind: PolicyType::Nested("genl_ctrl_mcast_group"),
        size: 0,
    },
    PolicyEntry {
        attribute: 8,
        kind: PolicyType::U32,
        size: 0,
    },
];

pub const GENL_BATADV_POLICIES: &[PolicyEntry] = &[
    PolicyEntry {
        attribute: 1,
        kind: PolicyType::String,
        size: 0,
    },
    PolicyEntry {
        attribute: 4,
        kind: PolicyType::String,
        size: 15,
    },
    PolicyEntry {
        attribute: 5,
        kind: PolicyType::EtherAddr,
        size: 6,
    },
    PolicyEntry {
        attribute: 10,
        kind: PolicyType::U8,
        size: 0,
    },
    PolicyEntry {
        attribute: 12,
        kind: PolicyType::U64,
        size: 0,
    },
];

pub const GENL_FOU_POLICIES: &[PolicyEntry] = &[
    PolicyEntry {
        attribute: 1,
        kind: PolicyType::U16,
        size: 0,
    },
    PolicyEntry {
        attribute: 2,
        kind: PolicyType::U8,
        size: 0,
    },
    PolicyEntry {
        attribute: 6,
        kind: PolicyType::InAddr,
        size: 4,
    },
    PolicyEntry {
        attribute: 8,
        kind: PolicyType::InAddr,
        size: 16,
    },
];

pub const GENL_L2TP_POLICIES: &[PolicyEntry] = &[
    PolicyEntry {
        attribute: 1,
        kind: PolicyType::U16,
        size: 0,
    },
    PolicyEntry {
        attribute: 8,
        kind: PolicyType::String,
        size: 0,
    },
    PolicyEntry {
        attribute: 10,
        kind: PolicyType::U32,
        size: 0,
    },
    PolicyEntry {
        attribute: 20,
        kind: PolicyType::InAddr,
        size: 4,
    },
];

pub const GENL_MACSEC_POLICIES: &[PolicyEntry] = &[
    PolicyEntry {
        attribute: 1,
        kind: PolicyType::U32,
        size: 0,
    },
    PolicyEntry {
        attribute: 2,
        kind: PolicyType::Nested("genl_macsec_rxsc"),
        size: 0,
    },
    PolicyEntry {
        attribute: 3,
        kind: PolicyType::Nested("genl_macsec_sa"),
        size: 0,
    },
];

pub const GENL_NL80211_POLICIES: &[PolicyEntry] = &[
    PolicyEntry {
        attribute: 1,
        kind: PolicyType::U32,
        size: 0,
    },
    PolicyEntry {
        attribute: 2,
        kind: PolicyType::String,
        size: 0,
    },
    PolicyEntry {
        attribute: 6,
        kind: PolicyType::EtherAddr,
        size: 6,
    },
    PolicyEntry {
        attribute: 7,
        kind: PolicyType::Binary,
        size: 32,
    },
];

pub const GENL_WIREGUARD_POLICIES: &[PolicyEntry] = &[
    PolicyEntry {
        attribute: 1,
        kind: PolicyType::U32,
        size: 0,
    },
    PolicyEntry {
        attribute: 2,
        kind: PolicyType::String,
        size: 15,
    },
    PolicyEntry {
        attribute: 4,
        kind: PolicyType::Binary,
        size: 32,
    },
    PolicyEntry {
        attribute: 7,
        kind: PolicyType::Nested("genl_wireguard_peer"),
        size: 0,
    },
];

pub fn policy_set_by_name(name: &str) -> Option<&'static [PolicyEntry]> {
    match name {
        "nlctrl" => Some(GENL_CTRL_POLICIES),
        "batadv" => Some(GENL_BATADV_POLICIES),
        "fou" => Some(GENL_FOU_POLICIES),
        "l2tp" => Some(GENL_L2TP_POLICIES),
        "macsec" => Some(GENL_MACSEC_POLICIES),
        "nl80211" => Some(GENL_NL80211_POLICIES),
        "wireguard" => Some(GENL_WIREGUARD_POLICIES),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_policy_lookup_works() {
        assert_eq!(
            policy_set_by_name("nlctrl").unwrap()[0].kind,
            PolicyType::U16
        );
    }

    #[test]
    fn unknown_family_returns_none() {
        assert!(policy_set_by_name("unknown").is_none());
    }

    #[test]
    fn wireguard_policy_contains_nested_peers() {
        assert!(
            GENL_WIREGUARD_POLICIES
                .iter()
                .any(|p| p.kind == PolicyType::Nested("genl_wireguard_peer"))
        );
    }

    #[test]
    fn batadv_contains_fixed_size_ether_addr() {
        assert!(
            GENL_BATADV_POLICIES
                .iter()
                .any(|p| p.kind == PolicyType::EtherAddr && p.size == 6)
        );
    }
}
