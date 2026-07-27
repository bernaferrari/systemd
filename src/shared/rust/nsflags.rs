// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/nsflags.c

use std::fmt;

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct NamespaceFlags: u64 {
        const CGROUP = 1 << 25;
        const IPC = 1 << 27;
        const NET = 1 << 30;
        const MNT = 1 << 17;
        const PID = 1 << 29;
        const USER = 1 << 28;
        const UTS = 1 << 26;
        const TIME = 1 << 7;

        const ALL = Self::CGROUP.bits()
            | Self::IPC.bits()
            | Self::NET.bits()
            | Self::MNT.bits()
            | Self::PID.bits()
            | Self::USER.bits()
            | Self::UTS.bits()
            | Self::TIME.bits();
    }
}

pub const NAMESPACE_FLAGS_ALL: NamespaceFlags = NamespaceFlags::ALL;
pub const NAMESPACE_FLAGS_INITIAL: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceType {
    Cgroup,
    Ipc,
    Net,
    Mount,
    Pid,
    User,
    Uts,
    Time,
}

impl NamespaceType {
    pub const fn proc_name(self) -> &'static str {
        match self {
            Self::Cgroup => "cgroup",
            Self::Ipc => "ipc",
            Self::Net => "net",
            Self::Mount => "mnt",
            Self::Pid => "pid",
            Self::User => "user",
            Self::Uts => "uts",
            Self::Time => "time",
        }
    }

    pub const fn flag(self) -> NamespaceFlags {
        match self {
            Self::Cgroup => NamespaceFlags::CGROUP,
            Self::Ipc => NamespaceFlags::IPC,
            Self::Net => NamespaceFlags::NET,
            Self::Mount => NamespaceFlags::MNT,
            Self::Pid => NamespaceFlags::PID,
            Self::User => NamespaceFlags::USER,
            Self::Uts => NamespaceFlags::UTS,
            Self::Time => NamespaceFlags::TIME,
        }
    }

    pub fn from_proc_name(name: &str) -> Option<Self> {
        match name {
            "cgroup" => Some(Self::Cgroup),
            "ipc" => Some(Self::Ipc),
            "net" => Some(Self::Net),
            "mnt" => Some(Self::Mount),
            "pid" => Some(Self::Pid),
            "user" => Some(Self::User),
            "uts" => Some(Self::Uts),
            "time" => Some(Self::Time),
            _ => None,
        }
    }
}

pub const NAMESPACE_TYPES: [NamespaceType; 8] = [
    NamespaceType::Cgroup,
    NamespaceType::Ipc,
    NamespaceType::Net,
    NamespaceType::Mount,
    NamespaceType::Pid,
    NamespaceType::User,
    NamespaceType::Uts,
    NamespaceType::Time,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceFlagsParseError {
    InvalidName(String),
}

impl fmt::Display for NamespaceFlagsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(f, "invalid namespace name: {name}"),
        }
    }
}

impl std::error::Error for NamespaceFlagsParseError {}

pub fn namespace_flags_from_string(
    input: &str,
) -> Result<NamespaceFlags, NamespaceFlagsParseError> {
    let mut flags = NamespaceFlags::empty();

    for word in input.split_whitespace() {
        let namespace = NamespaceType::from_proc_name(word)
            .ok_or_else(|| NamespaceFlagsParseError::InvalidName(word.to_owned()))?;
        flags |= namespace.flag();
    }

    Ok(flags)
}

pub fn namespace_flags_to_string(flags: NamespaceFlags) -> String {
    namespace_flags_to_strv(flags).join(" ")
}

pub fn namespace_flags_to_strv(flags: NamespaceFlags) -> Vec<&'static str> {
    NAMESPACE_TYPES
        .into_iter()
        .filter(|namespace| flags.contains(namespace.flag()))
        .map(NamespaceType::proc_name)
        .collect()
}

pub fn namespace_single_flag_to_string(flag: NamespaceFlags) -> Option<&'static str> {
    NAMESPACE_TYPES
        .into_iter()
        .find(|namespace| namespace.flag() == flag)
        .map(NamespaceType::proc_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_string_returns_empty_flags() {
        assert_eq!(namespace_flags_from_string(""), Ok(NamespaceFlags::empty()));
    }

    #[test]
    fn parse_whitespace_only_returns_empty_flags() {
        assert_eq!(
            namespace_flags_from_string(" \t\n"),
            Ok(NamespaceFlags::empty())
        );
    }

    #[test]
    fn parse_single_flag() {
        assert_eq!(namespace_flags_from_string("mnt"), Ok(NamespaceFlags::MNT));
    }

    #[test]
    fn parse_multiple_flags() {
        assert_eq!(
            namespace_flags_from_string("mnt net pid"),
            Ok(NamespaceFlags::MNT | NamespaceFlags::NET | NamespaceFlags::PID)
        );
    }

    #[test]
    fn parse_duplicate_flags_is_idempotent() {
        assert_eq!(
            namespace_flags_from_string("mnt mnt net"),
            Ok(NamespaceFlags::MNT | NamespaceFlags::NET)
        );
    }

    #[test]
    fn parse_invalid_name_returns_error() {
        assert_eq!(
            namespace_flags_from_string("bogus"),
            Err(NamespaceFlagsParseError::InvalidName("bogus".to_owned()))
        );
    }

    #[test]
    fn parse_stops_on_invalid_name() {
        assert_eq!(
            namespace_flags_from_string("mnt bogus net"),
            Err(NamespaceFlagsParseError::InvalidName("bogus".to_owned()))
        );
    }

    #[test]
    fn to_strv_preserves_c_iteration_order() {
        assert_eq!(
            namespace_flags_to_strv(
                NamespaceFlags::TIME | NamespaceFlags::CGROUP | NamespaceFlags::PID
            ),
            vec!["cgroup", "pid", "time"]
        );
    }

    #[test]
    fn to_strv_empty_is_empty_vector() {
        assert!(namespace_flags_to_strv(NamespaceFlags::empty()).is_empty());
    }

    #[test]
    fn to_string_joins_with_spaces() {
        assert_eq!(
            namespace_flags_to_string(NamespaceFlags::MNT | NamespaceFlags::NET),
            "net mnt"
        );
    }

    #[test]
    fn to_string_empty_is_empty_string() {
        assert_eq!(namespace_flags_to_string(NamespaceFlags::empty()), "");
    }

    #[test]
    fn single_flag_to_string_returns_known_name() {
        assert_eq!(
            namespace_single_flag_to_string(NamespaceFlags::USER),
            Some("user")
        );
    }

    #[test]
    fn single_flag_to_string_rejects_empty_flags() {
        assert_eq!(
            namespace_single_flag_to_string(NamespaceFlags::empty()),
            None
        );
    }

    #[test]
    fn single_flag_to_string_rejects_multiple_flags() {
        assert_eq!(
            namespace_single_flag_to_string(NamespaceFlags::MNT | NamespaceFlags::NET),
            None
        );
    }

    #[test]
    fn namespace_type_roundtrip_matches_flag_mapping() {
        for namespace in NAMESPACE_TYPES {
            assert_eq!(
                NamespaceType::from_proc_name(namespace.proc_name()),
                Some(namespace)
            );
            assert_eq!(
                namespace_single_flag_to_string(namespace.flag()),
                Some(namespace.proc_name())
            );
        }
    }

    #[test]
    fn all_flags_constant_matches_union_of_all_namespace_types() {
        let combined = NAMESPACE_TYPES
            .into_iter()
            .fold(NamespaceFlags::empty(), |flags, namespace| {
                flags | namespace.flag()
            });

        assert_eq!(combined, NAMESPACE_FLAGS_ALL);
    }

    #[test]
    fn initial_constant_is_max_value() {
        assert_eq!(NAMESPACE_FLAGS_INITIAL, u64::MAX);
    }

    #[test]
    fn all_flags_roundtrip_through_string() {
        let as_string = namespace_flags_to_string(NAMESPACE_FLAGS_ALL);

        assert_eq!(
            namespace_flags_from_string(&as_string),
            Ok(NAMESPACE_FLAGS_ALL)
        );
    }

    #[test]
    fn every_namespace_name_is_unique() {
        for (index, namespace) in NAMESPACE_TYPES.into_iter().enumerate() {
            for other in NAMESPACE_TYPES.into_iter().skip(index + 1) {
                assert_ne!(namespace.proc_name(), other.proc_name());
            }
        }
    }
}
