// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-types-rtnl.c

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    Binary,
    EtherAddr,
    Flag,
    InAddr,
    Nested,
    NestedUnionByFamily,
    NestedUnionByString,
    S32,
    String,
    U8,
    U16,
    U32,
    U64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub kind: PolicyKind,
    pub size: usize,
    pub target: Option<&'static str>,
}

impl Policy {
    const fn scalar(kind: PolicyKind) -> Self {
        Self {
            kind,
            size: 0,
            target: None,
        }
    }

    const fn sized(kind: PolicyKind, size: usize) -> Self {
        Self {
            kind,
            size,
            target: None,
        }
    }

    const fn nested(kind: PolicyKind, size: usize, target: &'static str) -> Self {
        Self {
            kind,
            size,
            target: Some(target),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyEntry {
    pub index: u16,
    pub name: &'static str,
    pub policy: Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyTable {
    pub name: &'static str,
    pub entries: &'static [PolicyEntry],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnionEntry {
    pub discriminator: &'static str,
    pub table_name: &'static str,
}

pub const IFNAMSIZ: usize = 16;
pub const IFALIASZ: usize = 256;
pub const ALTIFNAMSIZ: usize = 128;
pub const ETH_ALEN: usize = 6;

const LINK_INFO_DATA_BAREUDP: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_BAREUDP_PORT",
        policy: Policy::scalar(PolicyKind::U16),
    },
    PolicyEntry {
        index: 2,
        name: "IFLA_BAREUDP_ETHERTYPE",
        policy: Policy::scalar(PolicyKind::U16),
    },
    PolicyEntry {
        index: 3,
        name: "IFLA_BAREUDP_SRCPORT_MIN",
        policy: Policy::scalar(PolicyKind::U16),
    },
    PolicyEntry {
        index: 4,
        name: "IFLA_BAREUDP_MULTIPROTO_MODE",
        policy: Policy::scalar(PolicyKind::Flag),
    },
];

const LINK_INFO_DATA_BOND: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_BOND_MODE",
        policy: Policy::scalar(PolicyKind::U8),
    },
    PolicyEntry {
        index: 3,
        name: "IFLA_BOND_MIIMON",
        policy: Policy::scalar(PolicyKind::U32),
    },
    PolicyEntry {
        index: 8,
        name: "IFLA_BOND_ARP_IP_TARGET",
        policy: Policy::nested(PolicyKind::Nested, 0, "rtnl_bond_arp_ip_target"),
    },
    PolicyEntry {
        index: 23,
        name: "IFLA_BOND_AD_INFO",
        policy: Policy::nested(PolicyKind::Nested, 0, "rtnl_bond_ad_info"),
    },
];

const LINK_INFO_DATA_BRIDGE: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_BR_FORWARD_DELAY",
        policy: Policy::scalar(PolicyKind::U32),
    },
    PolicyEntry {
        index: 6,
        name: "IFLA_BR_PRIORITY",
        policy: Policy::scalar(PolicyKind::U16),
    },
    PolicyEntry {
        index: 20,
        name: "IFLA_BR_FDB_FLUSH",
        policy: Policy::scalar(PolicyKind::Flag),
    },
    PolicyEntry {
        index: 39,
        name: "IFLA_BR_VLAN_DEFAULT_PVID",
        policy: Policy::scalar(PolicyKind::U16),
    },
];

const LINK_INFO_DATA_CAN: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_CAN_BITTIMING",
        policy: Policy::sized(PolicyKind::Binary, 0),
    },
    PolicyEntry {
        index: 4,
        name: "IFLA_CAN_STATE",
        policy: Policy::scalar(PolicyKind::U32),
    },
    PolicyEntry {
        index: 10,
        name: "IFLA_CAN_TERMINATION",
        policy: Policy::scalar(PolicyKind::U16),
    },
    PolicyEntry {
        index: 15,
        name: "IFLA_CAN_BITRATE_MAX",
        policy: Policy::scalar(PolicyKind::U32),
    },
];

const LINK_INFO_DATA_GRE: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_GRE_LINK",
        policy: Policy::scalar(PolicyKind::U32),
    },
    PolicyEntry {
        index: 6,
        name: "IFLA_GRE_LOCAL",
        policy: Policy::scalar(PolicyKind::InAddr),
    },
    PolicyEntry {
        index: 7,
        name: "IFLA_GRE_REMOTE",
        policy: Policy::scalar(PolicyKind::InAddr),
    },
    PolicyEntry {
        index: 23,
        name: "IFLA_GRE_ERSPAN_HWID",
        policy: Policy::scalar(PolicyKind::U16),
    },
];

const LINK_INFO_DATA_VLAN: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_VLAN_ID",
        policy: Policy::scalar(PolicyKind::U16),
    },
    PolicyEntry {
        index: 2,
        name: "IFLA_VLAN_FLAGS",
        policy: Policy::sized(PolicyKind::Binary, 0),
    },
    PolicyEntry {
        index: 3,
        name: "IFLA_VLAN_EGRESS_QOS",
        policy: Policy::nested(PolicyKind::Nested, 0, "rtnl_vlan_qos_map"),
    },
    PolicyEntry {
        index: 5,
        name: "IFLA_VLAN_PROTOCOL",
        policy: Policy::scalar(PolicyKind::U16),
    },
];

const LINK_INFO_DATA_VXLAN: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_VXLAN_ID",
        policy: Policy::scalar(PolicyKind::U32),
    },
    PolicyEntry {
        index: 2,
        name: "IFLA_VXLAN_GROUP",
        policy: Policy::sized(PolicyKind::InAddr, 4),
    },
    PolicyEntry {
        index: 15,
        name: "IFLA_VXLAN_PORT",
        policy: Policy::scalar(PolicyKind::U16),
    },
    PolicyEntry {
        index: 29,
        name: "IFLA_VXLAN_VNIFILTER",
        policy: Policy::scalar(PolicyKind::U8),
    },
];

const LINK_INFO: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_INFO_KIND",
        policy: Policy::scalar(PolicyKind::String),
    },
    PolicyEntry {
        index: 2,
        name: "IFLA_INFO_DATA",
        policy: Policy::nested(PolicyKind::NestedUnionByString, 0, "rtnl_link_info_data"),
    },
    PolicyEntry {
        index: 4,
        name: "IFLA_INFO_SLAVE_KIND",
        policy: Policy::scalar(PolicyKind::String),
    },
    PolicyEntry {
        index: 5,
        name: "IFLA_INFO_SLAVE_DATA",
        policy: Policy::nested(
            PolicyKind::NestedUnionByString,
            0,
            "rtnl_link_info_slave_data",
        ),
    },
];

const LINK: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_ADDRESS",
        policy: Policy::scalar(PolicyKind::EtherAddr),
    },
    PolicyEntry {
        index: 3,
        name: "IFLA_IFNAME",
        policy: Policy::sized(PolicyKind::String, IFNAMSIZ - 1),
    },
    PolicyEntry {
        index: 4,
        name: "IFLA_MTU",
        policy: Policy::scalar(PolicyKind::U32),
    },
    PolicyEntry {
        index: 18,
        name: "IFLA_LINKINFO",
        policy: Policy::nested(PolicyKind::Nested, 0, "rtnl_link_info"),
    },
    PolicyEntry {
        index: 20,
        name: "IFLA_IFALIAS",
        policy: Policy::sized(PolicyKind::String, IFALIASZ - 1),
    },
    PolicyEntry {
        index: 26,
        name: "IFLA_AF_SPEC",
        policy: Policy::nested(PolicyKind::NestedUnionByFamily, 0, "rtnl_af_spec"),
    },
    PolicyEntry {
        index: 43,
        name: "IFLA_PROP_LIST",
        policy: Policy::nested(PolicyKind::Nested, 0, "rtnl_prop_list"),
    },
    PolicyEntry {
        index: 44,
        name: "IFLA_ALT_IFNAME",
        policy: Policy::sized(PolicyKind::String, ALTIFNAMSIZ - 1),
    },
    PolicyEntry {
        index: 45,
        name: "IFLA_PERM_ADDRESS",
        policy: Policy::scalar(PolicyKind::EtherAddr),
    },
    PolicyEntry {
        index: 46,
        name: "IFLA_PROTO_DOWN_REASON",
        policy: Policy::nested(PolicyKind::Nested, 0, "rtnl_proto_down_reason"),
    },
];

const ADDRESS: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFA_ADDRESS",
        policy: Policy::scalar(PolicyKind::InAddr),
    },
    PolicyEntry {
        index: 2,
        name: "IFA_LOCAL",
        policy: Policy::scalar(PolicyKind::InAddr),
    },
    PolicyEntry {
        index: 3,
        name: "IFA_LABEL",
        policy: Policy::sized(PolicyKind::String, IFNAMSIZ - 1),
    },
    PolicyEntry {
        index: 6,
        name: "IFA_CACHEINFO",
        policy: Policy::sized(PolicyKind::Binary, 0),
    },
    PolicyEntry {
        index: 8,
        name: "IFA_FLAGS",
        policy: Policy::scalar(PolicyKind::U32),
    },
];

const ROUTE: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "RTA_DST",
        policy: Policy::scalar(PolicyKind::InAddr),
    },
    PolicyEntry {
        index: 5,
        name: "RTA_GATEWAY",
        policy: Policy::scalar(PolicyKind::InAddr),
    },
    PolicyEntry {
        index: 8,
        name: "RTA_METRICS",
        policy: Policy::nested(PolicyKind::Nested, 0, "rtnl_route_metrics"),
    },
    PolicyEntry {
        index: 21,
        name: "RTA_NH_ID",
        policy: Policy::scalar(PolicyKind::U32),
    },
];

const NEIGH: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NDA_DST",
        policy: Policy::scalar(PolicyKind::InAddr),
    },
    PolicyEntry {
        index: 2,
        name: "NDA_LLADDR",
        policy: Policy::scalar(PolicyKind::EtherAddr),
    },
    PolicyEntry {
        index: 5,
        name: "NDA_VLAN",
        policy: Policy::scalar(PolicyKind::U16),
    },
    PolicyEntry {
        index: 8,
        name: "NDA_IFINDEX",
        policy: Policy::scalar(PolicyKind::U32),
    },
];

const PROP_LIST: &[PolicyEntry] = &[PolicyEntry {
    index: 1,
    name: "IFLA_ALT_IFNAME",
    policy: Policy::sized(PolicyKind::String, ALTIFNAMSIZ - 1),
}];

const PROTO_DOWN_REASON: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "IFLA_PROTO_DOWN_REASON_MASK",
        policy: Policy::scalar(PolicyKind::U32),
    },
    PolicyEntry {
        index: 2,
        name: "IFLA_PROTO_DOWN_REASON_VALUE",
        policy: Policy::scalar(PolicyKind::U32),
    },
];

const RTNL_TOPLEVEL: &[PolicyEntry] = &[
    PolicyEntry {
        index: 16,
        name: "RTM_NEWLINK",
        policy: Policy::nested(PolicyKind::Nested, 16, "rtnl_link"),
    },
    PolicyEntry {
        index: 19,
        name: "RTM_SETLINK",
        policy: Policy::nested(PolicyKind::Nested, 16, "rtnl_link"),
    },
    PolicyEntry {
        index: 20,
        name: "RTM_NEWADDR",
        policy: Policy::nested(PolicyKind::Nested, 8, "rtnl_address"),
    },
    PolicyEntry {
        index: 24,
        name: "RTM_NEWROUTE",
        policy: Policy::nested(PolicyKind::Nested, 12, "rtnl_route"),
    },
    PolicyEntry {
        index: 28,
        name: "RTM_NEWNEIGH",
        policy: Policy::nested(PolicyKind::Nested, 12, "rtnl_neigh"),
    },
];

pub const LINK_INFO_DATA_UNION: &[UnionEntry] = &[
    UnionEntry {
        discriminator: "bareudp",
        table_name: "rtnl_link_info_data_bareudp",
    },
    UnionEntry {
        discriminator: "bond",
        table_name: "rtnl_link_info_data_bond",
    },
    UnionEntry {
        discriminator: "bridge",
        table_name: "rtnl_link_info_data_bridge",
    },
    UnionEntry {
        discriminator: "can",
        table_name: "rtnl_link_info_data_can",
    },
    UnionEntry {
        discriminator: "gre",
        table_name: "rtnl_link_info_data_gre",
    },
    UnionEntry {
        discriminator: "vlan",
        table_name: "rtnl_link_info_data_vlan",
    },
    UnionEntry {
        discriminator: "vxlan",
        table_name: "rtnl_link_info_data_vxlan",
    },
];

pub const TABLES: &[PolicyTable] = &[
    PolicyTable {
        name: "rtnl_link_info_data_bareudp",
        entries: LINK_INFO_DATA_BAREUDP,
    },
    PolicyTable {
        name: "rtnl_link_info_data_bond",
        entries: LINK_INFO_DATA_BOND,
    },
    PolicyTable {
        name: "rtnl_link_info_data_bridge",
        entries: LINK_INFO_DATA_BRIDGE,
    },
    PolicyTable {
        name: "rtnl_link_info_data_can",
        entries: LINK_INFO_DATA_CAN,
    },
    PolicyTable {
        name: "rtnl_link_info_data_gre",
        entries: LINK_INFO_DATA_GRE,
    },
    PolicyTable {
        name: "rtnl_link_info_data_vlan",
        entries: LINK_INFO_DATA_VLAN,
    },
    PolicyTable {
        name: "rtnl_link_info_data_vxlan",
        entries: LINK_INFO_DATA_VXLAN,
    },
    PolicyTable {
        name: "rtnl_link_info",
        entries: LINK_INFO,
    },
    PolicyTable {
        name: "rtnl_link",
        entries: LINK,
    },
    PolicyTable {
        name: "rtnl_address",
        entries: ADDRESS,
    },
    PolicyTable {
        name: "rtnl_route",
        entries: ROUTE,
    },
    PolicyTable {
        name: "rtnl_neigh",
        entries: NEIGH,
    },
    PolicyTable {
        name: "rtnl_prop_list",
        entries: PROP_LIST,
    },
    PolicyTable {
        name: "rtnl_proto_down_reason",
        entries: PROTO_DOWN_REASON,
    },
    PolicyTable {
        name: "rtnl",
        entries: RTNL_TOPLEVEL,
    },
];

pub fn table(name: &str) -> Option<&'static PolicyTable> {
    TABLES.iter().find(|table| table.name == name)
}

pub fn union_table(kind: &str) -> Option<&'static str> {
    LINK_INFO_DATA_UNION
        .iter()
        .find(|entry| entry.discriminator == kind)
        .map(|entry| entry.table_name)
}

pub fn lookup_entry(table_name: &str, index: u16) -> Result<&'static PolicyEntry, String> {
    table(table_name)
        .and_then(|table| table.entries.iter().find(|entry| entry.index == index))
        .ok_or_else(|| format!("unknown attribute {index} in {table_name}"))
}

pub fn lookup_message_policy(nlmsg_type: u16) -> Result<&'static PolicyEntry, String> {
    lookup_entry("rtnl", nlmsg_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_newlink_message() {
        let entry = lookup_message_policy(16).unwrap();
        assert_eq!(entry.name, "RTM_NEWLINK");
    }

    #[test]
    fn resolves_link_info_kind() {
        let entry = lookup_entry("rtnl_link_info", 1).unwrap();
        assert_eq!(entry.policy.kind, PolicyKind::String);
    }

    #[test]
    fn resolves_af_spec_union() {
        let entry = lookup_entry("rtnl_link", 26).unwrap();
        assert_eq!(entry.policy.kind, PolicyKind::NestedUnionByFamily);
    }

    #[test]
    fn resolves_vlan_protocol() {
        let entry = lookup_entry("rtnl_link_info_data_vlan", 5).unwrap();
        assert_eq!(entry.policy.kind, PolicyKind::U16);
    }

    #[test]
    fn resolves_vxlan_id() {
        let entry = lookup_entry("rtnl_link_info_data_vxlan", 1).unwrap();
        assert_eq!(entry.policy.kind, PolicyKind::U32);
    }

    #[test]
    fn resolves_union_discriminator() {
        assert_eq!(union_table("bridge"), Some("rtnl_link_info_data_bridge"));
    }

    #[test]
    fn rejects_unknown_union_discriminator() {
        assert_eq!(union_table("ppp"), None);
    }

    #[test]
    fn alt_ifname_is_sized() {
        let entry = lookup_entry("rtnl_prop_list", 1).unwrap();
        assert_eq!(entry.policy.size, ALTIFNAMSIZ - 1);
    }

    #[test]
    fn rejects_unknown_message() {
        assert!(lookup_message_policy(999).is_err());
    }
}
