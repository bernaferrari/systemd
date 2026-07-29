// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bond-util.c, bridge-util.c, ethtool-util.c

use super::*;

static BOND_MODE_TABLE: &[(i32, &[u8])] = &[
    (0, b"balance-rr\0"),
    (1, b"active-backup\0"),
    (2, b"balance-xor\0"),
    (3, b"broadcast\0"),
    (4, b"802.3ad\0"),
    (5, b"balance-tlb\0"),
    (6, b"balance-alb\0"),
];
string_table!(
    rs_bond_mode_to_string,
    rs_bond_mode_from_string,
    BOND_MODE_TABLE
);

static BOND_XMIT_HASH_POLICY_TABLE: &[(i32, &[u8])] = &[
    (0, b"layer2\0"),
    (1, b"layer3+4\0"),
    (2, b"layer2+3\0"),
    (3, b"encap2+3\0"),
    (4, b"encap3+4\0"),
];
string_table!(
    rs_bond_xmit_hash_policy_to_string,
    rs_bond_xmit_hash_policy_from_string,
    BOND_XMIT_HASH_POLICY_TABLE
);

static BOND_LACP_RATE_TABLE: &[(i32, &[u8])] = &[(0, b"slow\0"), (1, b"fast\0")];
string_table!(
    rs_bond_lacp_rate_to_string,
    rs_bond_lacp_rate_from_string,
    BOND_LACP_RATE_TABLE
);

static BOND_AD_SELECT_TABLE: &[(i32, &[u8])] =
    &[(0, b"stable\0"), (1, b"bandwidth\0"), (2, b"count\0")];
string_table!(
    rs_bond_ad_select_to_string,
    rs_bond_ad_select_from_string,
    BOND_AD_SELECT_TABLE
);

static BOND_FAIL_OVER_MAC_TABLE: &[(i32, &[u8])] =
    &[(0, b"none\0"), (1, b"active\0"), (2, b"follow\0")];
string_table!(
    rs_bond_fail_over_mac_to_string,
    rs_bond_fail_over_mac_from_string,
    BOND_FAIL_OVER_MAC_TABLE
);

static BOND_ARP_VALIDATE_TABLE: &[(i32, &[u8])] = &[
    (0, b"none\0"),
    (1, b"active\0"),
    (2, b"backup\0"),
    (3, b"all\0"),
];
string_table!(
    rs_bond_arp_validate_to_string,
    rs_bond_arp_validate_from_string,
    BOND_ARP_VALIDATE_TABLE
);

static BOND_ARP_ALL_TARGETS_TABLE: &[(i32, &[u8])] = &[(0, b"any\0"), (1, b"all\0")];
string_table!(
    rs_bond_arp_all_targets_to_string,
    rs_bond_arp_all_targets_from_string,
    BOND_ARP_ALL_TARGETS_TABLE
);

static BOND_PRIMARY_RESELECT_TABLE: &[(i32, &[u8])] =
    &[(0, b"always\0"), (1, b"better\0"), (2, b"failure\0")];
string_table!(
    rs_bond_primary_reselect_to_string,
    rs_bond_primary_reselect_from_string,
    BOND_PRIMARY_RESELECT_TABLE
);

static BRIDGE_STATE_TABLE: &[(i32, &[u8])] = &[
    (0, b"disabled\0"),
    (1, b"listening\0"),
    (2, b"learning\0"),
    (3, b"forwarding\0"),
];
string_table!(
    rs_bridge_state_to_string,
    rs_bridge_state_from_string,
    BRIDGE_STATE_TABLE
);

static DUPLEX_TABLE: &[(i32, &[u8])] = &[(0, b"half\0"), (1, b"full\0")];
string_table!(rs_duplex_to_string, rs_duplex_from_string, DUPLEX_TABLE);

static PORT_TABLE: &[(i32, &[u8])] = &[
    (0, b"tp\0"),
    (1, b"aui\0"),
    (2, b"mii\0"),
    (3, b"fibre\0"),
    (4, b"bnc\0"),
];
string_table!(rs_port_to_string, rs_port_from_string, PORT_TABLE);

static MDI_TABLE: &[(i32, &[u8])] = &[
    (0, b"unknown\0"),
    (1, b"mdi\0"),
    (2, b"mdi-x\0"),
    (3, b"auto\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_mdi_to_string(v: i32) -> *const c_char {
    table_core::to_cstr(MDI_TABLE, v).map_or(std::ptr::null(), |name| name.as_ptr())
}
