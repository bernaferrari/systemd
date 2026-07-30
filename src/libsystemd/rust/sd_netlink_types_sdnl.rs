// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-types-sdnl.c

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    Binary,
    Nested,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub kind: PolicyKind,
    pub size: usize,
    pub target: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyEntry {
    pub index: u16,
    pub name: &'static str,
    pub policy: Policy,
}

pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const NLM_F_REQUEST: u16 = 0x0001;
// Linux UAPI struct unix_diag_req: two u8 fields, one u16 field, and five
// u32 fields.
pub const UNIX_DIAG_REQ_SIZE: usize = 24;
// Linux UAPI struct unix_diag_msg: four u8 fields plus three u32 fields.
pub const UNIX_DIAG_MSG_SIZE: usize = 16;
pub const UNIX_DIAG_VFS_SIZE: usize = 8;
pub const UNIX_DIAG_RQLEN_SIZE: usize = 8;

pub const UNIX_DIAG_NAME: u16 = 0;
pub const UNIX_DIAG_VFS: u16 = 1;
pub const UNIX_DIAG_RQLEN: u16 = 4;

pub const SDNL_REQ: &[PolicyEntry] = &[PolicyEntry {
    index: SOCK_DIAG_BY_FAMILY,
    name: "SOCK_DIAG_BY_FAMILY",
    policy: Policy {
        kind: PolicyKind::Nested,
        size: UNIX_DIAG_REQ_SIZE,
        target: Some("unix_diag_req"),
    },
}];

pub const SDNL_MSG: &[PolicyEntry] = &[PolicyEntry {
    index: SOCK_DIAG_BY_FAMILY,
    name: "SOCK_DIAG_BY_FAMILY",
    policy: Policy {
        kind: PolicyKind::Nested,
        size: UNIX_DIAG_MSG_SIZE,
        target: Some("unix_diag_msg"),
    },
}];

pub const UNIX_DIAG_MSG: &[PolicyEntry] = &[
    PolicyEntry {
        index: UNIX_DIAG_NAME,
        name: "UNIX_DIAG_NAME",
        // C classifies this as STRING, but its wire data is specifically not
        // NUL-terminated. This table is metadata only; it performs no string
        // validation or decoding.
        policy: Policy {
            kind: PolicyKind::String,
            size: 0,
            target: None,
        },
    },
    PolicyEntry {
        index: UNIX_DIAG_VFS,
        name: "UNIX_DIAG_VFS",
        policy: Policy {
            kind: PolicyKind::Binary,
            size: UNIX_DIAG_VFS_SIZE,
            target: None,
        },
    },
    PolicyEntry {
        index: UNIX_DIAG_RQLEN,
        name: "UNIX_DIAG_RQLEN",
        policy: Policy {
            kind: PolicyKind::Binary,
            size: UNIX_DIAG_RQLEN_SIZE,
            target: None,
        },
    },
];

pub fn get_policy(nlmsg_type: u16, flags: u16) -> Result<&'static PolicyEntry, String> {
    let table = if flags & NLM_F_REQUEST != 0 {
        SDNL_REQ
    } else {
        SDNL_MSG
    };
    table
        .iter()
        .find(|entry| entry.index == nlmsg_type)
        .ok_or_else(|| format!("unknown sock_diag message {nlmsg_type}"))
}

pub fn unix_diag_message_policy(index: u16) -> Result<&'static PolicyEntry, String> {
    UNIX_DIAG_MSG
        .iter()
        .find(|entry| entry.index == index)
        .ok_or_else(|| format!("unknown unix diag attribute {index}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_policy_uses_unix_diag_req() {
        let entry = get_policy(SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST).unwrap();
        assert_eq!(entry.policy.target, Some("unix_diag_req"));
    }

    #[test]
    fn reply_policy_uses_unix_diag_msg() {
        let entry = get_policy(SOCK_DIAG_BY_FAMILY, 0).unwrap();
        assert_eq!(entry.policy.target, Some("unix_diag_msg"));
    }

    #[test]
    fn request_policy_size_matches_struct() {
        let entry = get_policy(SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST).unwrap();
        assert_eq!(UNIX_DIAG_REQ_SIZE, 24);
        assert_eq!(entry.policy.size, 24);
    }

    #[test]
    fn reply_policy_uses_linux_unix_diag_msg_size() {
        let entry = get_policy(SOCK_DIAG_BY_FAMILY, 0).unwrap();
        assert_eq!(UNIX_DIAG_MSG_SIZE, 16);
        assert_eq!(entry.policy.size, 16);
    }

    #[test]
    fn unix_diag_rqlen_is_binary() {
        let entry = unix_diag_message_policy(UNIX_DIAG_RQLEN).unwrap();
        assert_eq!(entry.name, "UNIX_DIAG_RQLEN");
        assert_eq!(entry.policy.kind, PolicyKind::Binary);
    }

    #[test]
    fn unix_diag_rqlen_size_matches() {
        let entry = unix_diag_message_policy(UNIX_DIAG_RQLEN).unwrap();
        assert_eq!(entry.policy.size, UNIX_DIAG_RQLEN_SIZE);
    }

    #[test]
    fn unix_diag_name_is_a_string() {
        let entry = unix_diag_message_policy(UNIX_DIAG_NAME).unwrap();
        assert_eq!(entry.name, "UNIX_DIAG_NAME");
        assert_eq!(entry.policy.kind, PolicyKind::String);
        assert_eq!(entry.policy.size, 0);
    }

    #[test]
    fn unix_diag_vfs_is_eight_byte_binary_data() {
        let entry = unix_diag_message_policy(UNIX_DIAG_VFS).unwrap();
        assert_eq!(entry.name, "UNIX_DIAG_VFS");
        assert_eq!(entry.policy.kind, PolicyKind::Binary);
        assert_eq!(entry.policy.size, UNIX_DIAG_VFS_SIZE);
    }

    #[test]
    fn unmodeled_unix_diag_attributes_are_rejected() {
        assert!(unix_diag_message_policy(2).is_err()); // UNIX_DIAG_PEER
        assert!(unix_diag_message_policy(3).is_err()); // UNIX_DIAG_ICONS
    }

    #[test]
    fn unknown_message_fails() {
        assert!(get_policy(999, 0).is_err());
    }

    #[test]
    fn unknown_unix_diag_attribute_fails() {
        assert!(unix_diag_message_policy(999).is_err());
    }
}
