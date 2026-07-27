// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-types-sdnl.c

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    Binary,
    Nested,
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
pub const UNIX_DIAG_REQ_SIZE: usize = 8;
pub const UNIX_DIAG_MSG_SIZE: usize = 24;
pub const UNIX_DIAG_RQLEN_SIZE: usize = 8;

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

pub const UNIX_DIAG_MSG: &[PolicyEntry] = &[PolicyEntry {
    index: 1,
    name: "UNIX_DIAG_RQLEN",
    policy: Policy {
        kind: PolicyKind::Binary,
        size: UNIX_DIAG_RQLEN_SIZE,
        target: None,
    },
}];

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
        assert_eq!(entry.policy.size, UNIX_DIAG_REQ_SIZE);
    }

    #[test]
    fn reply_policy_size_matches_struct() {
        let entry = get_policy(SOCK_DIAG_BY_FAMILY, 0).unwrap();
        assert_eq!(entry.policy.size, UNIX_DIAG_MSG_SIZE);
    }

    #[test]
    fn unix_diag_rqlen_is_binary() {
        let entry = unix_diag_message_policy(1).unwrap();
        assert_eq!(entry.policy.kind, PolicyKind::Binary);
    }

    #[test]
    fn unix_diag_rqlen_size_matches() {
        let entry = unix_diag_message_policy(1).unwrap();
        assert_eq!(entry.policy.size, UNIX_DIAG_RQLEN_SIZE);
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
