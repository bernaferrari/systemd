// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/macvlan-util.c, ipvlan-util.c, geneve-util.c

use super::*;

static MACVLAN_MODE_TABLE: &[(i32, &[u8])] = &[
    (1, b"private\0"),
    (2, b"vepa\0"),
    (4, b"bridge\0"),
    (8, b"passthru\0"),
    (16, b"source\0"),
];
string_table!(
    rs_macvlan_mode_to_string,
    rs_macvlan_mode_from_string,
    MACVLAN_MODE_TABLE
);

static IPVLAN_MODE_TABLE: &[(i32, &[u8])] = &[(0, b"L2\0"), (1, b"L3\0"), (2, b"L3S\0")];
string_table!(
    rs_ipvlan_mode_to_string,
    rs_ipvlan_mode_from_string,
    IPVLAN_MODE_TABLE
);

static IPVLAN_FLAGS_TABLE: &[(i32, &[u8])] = &[(0, b"bridge\0"), (1, b"private\0"), (2, b"vepa\0")];
string_table!(
    rs_ipvlan_flags_to_string,
    rs_ipvlan_flags_from_string,
    IPVLAN_FLAGS_TABLE
);

static GENEVE_DF_TABLE: &[(i32, &[u8])] = &[(0, b"unset\0"), (1, b"set\0"), (2, b"inherit\0")];
string_table!(
    rs_geneve_df_to_string,
    rs_geneve_df_from_string,
    GENEVE_DF_TABLE
);
