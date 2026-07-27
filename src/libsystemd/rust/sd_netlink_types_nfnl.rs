// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-types-nfnl.c

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    Binary,
    Nested,
    NestedUnionByString,
    String,
    U32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub kind: PolicyKind,
    pub size: usize,
    pub target: Option<&'static str>,
}

impl Policy {
    const fn u32() -> Self {
        Self {
            kind: PolicyKind::U32,
            size: 0,
            target: None,
        }
    }

    const fn binary(size: usize) -> Self {
        Self {
            kind: PolicyKind::Binary,
            size,
            target: None,
        }
    }

    const fn string(size: usize) -> Self {
        Self {
            kind: PolicyKind::String,
            size,
            target: None,
        }
    }

    const fn nested(size: usize, target: &'static str) -> Self {
        Self {
            kind: PolicyKind::Nested,
            size,
            target: Some(target),
        }
    }

    const fn nested_union(target: &'static str) -> Self {
        Self {
            kind: PolicyKind::NestedUnionByString,
            size: 0,
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
pub struct ExprUnionEntry {
    pub expr_name: &'static str,
    pub table_name: &'static str,
}

pub const NFGENMSG_SIZE: usize = 4;
pub const NFT_TABLE_MAXNAMELEN: usize = 256;
pub const IFNAMSIZ: usize = 16;

const NFT_TABLE: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_TABLE_NAME",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_TABLE_FLAGS",
        policy: Policy::u32(),
    },
];

const NFT_CHAIN_HOOK: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_HOOK_HOOKNUM",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_HOOK_PRIORITY",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_HOOK_DEV",
        policy: Policy::string(IFNAMSIZ - 1),
    },
];

const NFT_CHAIN: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_CHAIN_TABLE",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_CHAIN_NAME",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_CHAIN_HOOK",
        policy: Policy::nested(0, "nfnl_nft_chain_hook"),
    },
    PolicyEntry {
        index: 4,
        name: "NFTA_CHAIN_TYPE",
        policy: Policy::string(16),
    },
    PolicyEntry {
        index: 5,
        name: "NFTA_CHAIN_FLAGS",
        policy: Policy::u32(),
    },
];

const NFT_DATA: &[PolicyEntry] = &[PolicyEntry {
    index: 1,
    name: "NFTA_DATA_VALUE",
    policy: Policy::binary(0),
}];

const NFT_EXPR_META: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_META_DREG",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_META_KEY",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_META_SREG",
        policy: Policy::u32(),
    },
];

const NFT_EXPR_PAYLOAD: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_PAYLOAD_DREG",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_PAYLOAD_BASE",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_PAYLOAD_OFFSET",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 4,
        name: "NFTA_PAYLOAD_LEN",
        policy: Policy::u32(),
    },
];

const NFT_EXPR_NAT: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_NAT_TYPE",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_NAT_FAMILY",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_NAT_REG_ADDR_MIN",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 4,
        name: "NFTA_NAT_REG_ADDR_MAX",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 5,
        name: "NFTA_NAT_REG_PROTO_MIN",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 6,
        name: "NFTA_NAT_REG_PROTO_MAX",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 7,
        name: "NFTA_NAT_FLAGS",
        policy: Policy::u32(),
    },
];

const NFT_EXPR_BITWISE: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_BITWISE_SREG",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_BITWISE_DREG",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_BITWISE_LEN",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 4,
        name: "NFTA_BITWISE_MASK",
        policy: Policy::nested(0, "nfnl_nft_data"),
    },
    PolicyEntry {
        index: 5,
        name: "NFTA_BITWISE_XOR",
        policy: Policy::nested(0, "nfnl_nft_data"),
    },
];

const NFT_EXPR_CMP: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_CMP_SREG",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_CMP_OP",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_CMP_DATA",
        policy: Policy::nested(0, "nfnl_nft_data"),
    },
];

const NFT_EXPR_FIB: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_FIB_DREG",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_FIB_RESULT",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_FIB_FLAGS",
        policy: Policy::u32(),
    },
];

const NFT_EXPR_LOOKUP: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_LOOKUP_SET",
        policy: Policy::string(0),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_LOOKUP_SREG",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_LOOKUP_DREG",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 4,
        name: "NFTA_LOOKUP_FLAGS",
        policy: Policy::u32(),
    },
];

const NFT_EXPR_MASQ: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_MASQ_FLAGS",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_MASQ_REG_PROTO_MIN",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_MASQ_REG_PROTO_MAX",
        policy: Policy::u32(),
    },
];

const NFT_RULE_EXPR: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_EXPR_NAME",
        policy: Policy::string(16),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_EXPR_DATA",
        policy: Policy::nested_union("nfnl_expr_data"),
    },
];

const NFT_RULE: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_RULE_TABLE",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_RULE_CHAIN",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_RULE_EXPRESSIONS",
        policy: Policy::nested(0, "nfnl_nft_rule_expr"),
    },
];

const NFT_SET: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_SET_TABLE",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_SET_NAME",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_SET_FLAGS",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 4,
        name: "NFTA_SET_KEY_TYPE",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 5,
        name: "NFTA_SET_KEY_LEN",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 6,
        name: "NFTA_SET_DATA_TYPE",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 7,
        name: "NFTA_SET_DATA_LEN",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 8,
        name: "NFTA_SET_POLICY",
        policy: Policy::u32(),
    },
    PolicyEntry {
        index: 9,
        name: "NFTA_SET_ID",
        policy: Policy::u32(),
    },
];

const NFT_SETELEM: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_SET_ELEM_KEY",
        policy: Policy::nested(0, "nfnl_nft_data"),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_SET_ELEM_DATA",
        policy: Policy::nested(0, "nfnl_nft_data"),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_SET_ELEM_FLAGS",
        policy: Policy::u32(),
    },
];

const NFT_SETELEM_LIST: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFTA_SET_ELEM_LIST_TABLE",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 2,
        name: "NFTA_SET_ELEM_LIST_SET",
        policy: Policy::string(NFT_TABLE_MAXNAMELEN - 1),
    },
    PolicyEntry {
        index: 3,
        name: "NFTA_SET_ELEM_LIST_ELEMENTS",
        policy: Policy::nested(0, "nfnl_nft_setelem"),
    },
];

const MSG_BATCH: &[PolicyEntry] = &[PolicyEntry {
    index: 1,
    name: "NFNL_BATCH_GENID",
    policy: Policy::u32(),
}];

const SUBSYS_NONE: &[PolicyEntry] = &[
    PolicyEntry {
        index: 1,
        name: "NFNL_MSG_BATCH_BEGIN",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_msg_batch"),
    },
    PolicyEntry {
        index: 2,
        name: "NFNL_MSG_BATCH_END",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_msg_batch"),
    },
];

const SUBSYS_NFT: &[PolicyEntry] = &[
    PolicyEntry {
        index: 2,
        name: "NFT_MSG_DELTABLE",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_nft_table"),
    },
    PolicyEntry {
        index: 3,
        name: "NFT_MSG_NEWTABLE",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_nft_table"),
    },
    PolicyEntry {
        index: 4,
        name: "NFT_MSG_NEWCHAIN",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_nft_chain"),
    },
    PolicyEntry {
        index: 5,
        name: "NFT_MSG_NEWRULE",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_nft_rule"),
    },
    PolicyEntry {
        index: 6,
        name: "NFT_MSG_NEWSET",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_nft_set"),
    },
    PolicyEntry {
        index: 7,
        name: "NFT_MSG_NEWSETELEM",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_nft_setelem_list"),
    },
    PolicyEntry {
        index: 8,
        name: "NFT_MSG_DELSETELEM",
        policy: Policy::nested(NFGENMSG_SIZE, "nfnl_nft_setelem_list"),
    },
];

pub const EXPR_UNION: &[ExprUnionEntry] = &[
    ExprUnionEntry {
        expr_name: "bitwise",
        table_name: "nfnl_nft_expr_bitwise",
    },
    ExprUnionEntry {
        expr_name: "cmp",
        table_name: "nfnl_nft_expr_cmp",
    },
    ExprUnionEntry {
        expr_name: "fib",
        table_name: "nfnl_nft_expr_fib",
    },
    ExprUnionEntry {
        expr_name: "lookup",
        table_name: "nfnl_nft_expr_lookup",
    },
    ExprUnionEntry {
        expr_name: "masq",
        table_name: "nfnl_nft_expr_masq",
    },
    ExprUnionEntry {
        expr_name: "meta",
        table_name: "nfnl_nft_expr_meta",
    },
    ExprUnionEntry {
        expr_name: "nat",
        table_name: "nfnl_nft_expr_nat",
    },
    ExprUnionEntry {
        expr_name: "payload",
        table_name: "nfnl_nft_expr_payload",
    },
];

pub const TABLES: &[PolicyTable] = &[
    PolicyTable {
        name: "nfnl_nft_table",
        entries: NFT_TABLE,
    },
    PolicyTable {
        name: "nfnl_nft_chain_hook",
        entries: NFT_CHAIN_HOOK,
    },
    PolicyTable {
        name: "nfnl_nft_chain",
        entries: NFT_CHAIN,
    },
    PolicyTable {
        name: "nfnl_nft_data",
        entries: NFT_DATA,
    },
    PolicyTable {
        name: "nfnl_nft_expr_meta",
        entries: NFT_EXPR_META,
    },
    PolicyTable {
        name: "nfnl_nft_expr_payload",
        entries: NFT_EXPR_PAYLOAD,
    },
    PolicyTable {
        name: "nfnl_nft_expr_nat",
        entries: NFT_EXPR_NAT,
    },
    PolicyTable {
        name: "nfnl_nft_expr_bitwise",
        entries: NFT_EXPR_BITWISE,
    },
    PolicyTable {
        name: "nfnl_nft_expr_cmp",
        entries: NFT_EXPR_CMP,
    },
    PolicyTable {
        name: "nfnl_nft_expr_fib",
        entries: NFT_EXPR_FIB,
    },
    PolicyTable {
        name: "nfnl_nft_expr_lookup",
        entries: NFT_EXPR_LOOKUP,
    },
    PolicyTable {
        name: "nfnl_nft_expr_masq",
        entries: NFT_EXPR_MASQ,
    },
    PolicyTable {
        name: "nfnl_nft_rule_expr",
        entries: NFT_RULE_EXPR,
    },
    PolicyTable {
        name: "nfnl_nft_rule",
        entries: NFT_RULE,
    },
    PolicyTable {
        name: "nfnl_nft_set",
        entries: NFT_SET,
    },
    PolicyTable {
        name: "nfnl_nft_setelem",
        entries: NFT_SETELEM,
    },
    PolicyTable {
        name: "nfnl_nft_setelem_list",
        entries: NFT_SETELEM_LIST,
    },
    PolicyTable {
        name: "nfnl_msg_batch",
        entries: MSG_BATCH,
    },
    PolicyTable {
        name: "nfnl_subsys_none",
        entries: SUBSYS_NONE,
    },
    PolicyTable {
        name: "nfnl_subsys_nft",
        entries: SUBSYS_NFT,
    },
];

pub fn nfnl_subsys_id(nlmsg_type: u16) -> u16 {
    (nlmsg_type >> 8) & 0x0f
}

pub fn nfnl_msg_type(nlmsg_type: u16) -> u16 {
    nlmsg_type & 0x00ff
}

pub fn table(name: &str) -> Option<&'static PolicyTable> {
    TABLES.iter().find(|table| table.name == name)
}

pub fn expression_table(name: &str) -> Option<&'static str> {
    EXPR_UNION
        .iter()
        .find(|entry| entry.expr_name == name)
        .map(|entry| entry.table_name)
}

pub fn lookup_entry(table_name: &str, index: u16) -> Result<&'static PolicyEntry, String> {
    table(table_name)
        .and_then(|table| table.entries.iter().find(|entry| entry.index == index))
        .ok_or_else(|| format!("unknown attribute {index} in {table_name}"))
}

pub fn lookup_policy(nlmsg_type: u16) -> Result<&'static PolicyEntry, String> {
    let subsystem_table = match nfnl_subsys_id(nlmsg_type) {
        0 => "nfnl_subsys_none",
        1 => "nfnl_subsys_nft",
        other => return Err(format!("unsupported NFNL subsystem {other}")),
    };

    lookup_entry(subsystem_table, nfnl_msg_type(nlmsg_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_subsystem() {
        assert_eq!(nfnl_subsys_id(0x0105), 1);
    }

    #[test]
    fn splits_message_type() {
        assert_eq!(nfnl_msg_type(0x0105), 5);
    }

    #[test]
    fn resolves_batch_begin() {
        let entry = lookup_policy(0x0001).unwrap();
        assert_eq!(entry.name, "NFNL_MSG_BATCH_BEGIN");
    }

    #[test]
    fn resolves_newrule() {
        let entry = lookup_policy(0x0105).unwrap();
        assert_eq!(entry.policy.target, Some("nfnl_nft_rule"));
    }

    #[test]
    fn resolves_nested_lookup_data() {
        let entry = lookup_entry("nfnl_nft_expr_bitwise", 4).unwrap();
        assert_eq!(entry.policy.target, Some("nfnl_nft_data"));
    }

    #[test]
    fn expression_union_contains_payload() {
        assert_eq!(expression_table("payload"), Some("nfnl_nft_expr_payload"));
    }

    #[test]
    fn unknown_expression_is_none() {
        assert_eq!(expression_table("missing"), None);
    }

    #[test]
    fn lookup_set_is_unsized_string() {
        let entry = lookup_entry("nfnl_nft_expr_lookup", 1).unwrap();
        assert_eq!(entry.policy.kind, PolicyKind::String);
        assert_eq!(entry.policy.size, 0);
    }

    #[test]
    fn unsupported_subsystem_fails() {
        assert!(lookup_policy(0x0f01).is_err());
    }
}
