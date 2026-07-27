// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/namespace.c, src/core/namespace.h
//
use crate::ffi::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseNamespaceTableError;

impl ParseNamespaceTableError {
    pub const fn errno(self) -> i32 {
        Errno::EINVAL.to_neg_errno()
    }
}

macro_rules! namespace_enum {
    ($name:ident, $(($variant:ident, $index:expr, $text:expr)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            pub const fn to_index(self) -> i32 {
                match self {
                    $(Self::$variant => $index),+
                }
            }

            pub const fn from_index(value: i32) -> Option<Self> {
                match value {
                    $($index => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn from_str(value: &str) -> Result<Self, ParseNamespaceTableError> {
                match value {
                    $($text => Ok(Self::$variant),)+
                    _ => Err(ParseNamespaceTableError),
                }
            }
        }
    };
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value {
        "1" | "y" | "Y" | "yes" | "YES" | "true" | "TRUE" | "t" | "T" | "on" | "ON" => Some(true),
        "0" | "n" | "N" | "no" | "NO" | "false" | "FALSE" | "f" | "F" | "off" | "OFF" => {
            Some(false)
        }
        _ => None,
    }
}

fn parse_with_boolean<T, F>(
    value: &str,
    yes_value: T,
    parser: F,
) -> Result<T, ParseNamespaceTableError>
where
    F: FnOnce(&str) -> Result<T, ParseNamespaceTableError>,
{
    match parse_boolean(value) {
        Some(true) => Ok(yes_value),
        Some(false) => parser("no"),
        None => parser(value),
    }
}

namespace_enum!(
    ProtectHome,
    (No, 0, "no"),
    (Yes, 1, "yes"),
    (ReadOnly, 2, "read-only"),
    (Tmpfs, 3, "tmpfs"),
);

namespace_enum!(
    ProtectHostname,
    (No, 0, "no"),
    (Yes, 1, "yes"),
    (Private, 2, "private"),
);

namespace_enum!(
    ProtectSystem,
    (No, 0, "no"),
    (Yes, 1, "yes"),
    (Full, 2, "full"),
    (Strict, 3, "strict"),
);

namespace_enum!(
    ProtectControlGroups,
    (No, 0, "no"),
    (Yes, 1, "yes"),
    (Private, 2, "private"),
    (Strict, 3, "strict"),
);

namespace_enum!(
    ProtectProc,
    (Default, 0, "default"),
    (NoAccess, 1, "noaccess"),
    (Invisible, 2, "invisible"),
    (Ptraceable, 3, "ptraceable"),
);

namespace_enum!(ProcSubset, (All, 0, "all"), (Pid, 1, "pid"),);

namespace_enum!(PrivateBpf, (No, 0, "no"), (Yes, 1, "yes"),);

namespace_enum!(
    PrivateTmp,
    (No, 0, "no"),
    (Connected, 1, "connected"),
    (Disconnected, 2, "disconnected"),
);

namespace_enum!(
    PrivateUsers,
    (No, 0, "no"),
    (SelfUser, 1, "self"),
    (Identity, 2, "identity"),
    (Full, 3, "full"),
    (Managed, 4, "managed"),
);

namespace_enum!(PrivatePids, (No, 0, "no"), (Yes, 1, "yes"),);

pub const fn protect_home_to_string(value: ProtectHome) -> &'static str {
    value.as_str()
}

pub fn protect_home_from_string(value: &str) -> Result<ProtectHome, ParseNamespaceTableError> {
    parse_with_boolean(value, ProtectHome::Yes, ProtectHome::from_str)
}

pub const fn protect_hostname_to_string(value: ProtectHostname) -> &'static str {
    value.as_str()
}

pub fn protect_hostname_from_string(
    value: &str,
) -> Result<ProtectHostname, ParseNamespaceTableError> {
    parse_with_boolean(value, ProtectHostname::Yes, ProtectHostname::from_str)
}

pub const fn protect_system_to_string(value: ProtectSystem) -> &'static str {
    value.as_str()
}

pub fn protect_system_from_string(value: &str) -> Result<ProtectSystem, ParseNamespaceTableError> {
    parse_with_boolean(value, ProtectSystem::Yes, ProtectSystem::from_str)
}

pub const fn protect_control_groups_to_string(value: ProtectControlGroups) -> &'static str {
    value.as_str()
}

pub fn protect_control_groups_from_string(
    value: &str,
) -> Result<ProtectControlGroups, ParseNamespaceTableError> {
    parse_with_boolean(
        value,
        ProtectControlGroups::Yes,
        ProtectControlGroups::from_str,
    )
}

pub const fn protect_proc_to_string(value: ProtectProc) -> &'static str {
    value.as_str()
}

pub fn protect_proc_from_string(value: &str) -> Result<ProtectProc, ParseNamespaceTableError> {
    ProtectProc::from_str(value)
}

pub const fn proc_subset_to_string(value: ProcSubset) -> &'static str {
    value.as_str()
}

pub fn proc_subset_from_string(value: &str) -> Result<ProcSubset, ParseNamespaceTableError> {
    ProcSubset::from_str(value)
}

pub const fn private_bpf_to_string(value: PrivateBpf) -> &'static str {
    value.as_str()
}

pub fn private_bpf_from_string(value: &str) -> Result<PrivateBpf, ParseNamespaceTableError> {
    parse_with_boolean(value, PrivateBpf::Yes, PrivateBpf::from_str)
}

pub const fn private_tmp_to_string(value: PrivateTmp) -> &'static str {
    value.as_str()
}

pub fn private_tmp_from_string(value: &str) -> Result<PrivateTmp, ParseNamespaceTableError> {
    parse_with_boolean(value, PrivateTmp::Connected, PrivateTmp::from_str)
}

pub const fn private_users_to_string(value: PrivateUsers) -> &'static str {
    value.as_str()
}

pub fn private_users_from_string(value: &str) -> Result<PrivateUsers, ParseNamespaceTableError> {
    parse_with_boolean(value, PrivateUsers::SelfUser, PrivateUsers::from_str)
}

pub const fn private_pids_to_string(value: PrivatePids) -> &'static str {
    value.as_str()
}

pub fn private_pids_from_string(value: &str) -> Result<PrivatePids, ParseNamespaceTableError> {
    parse_with_boolean(value, PrivatePids::Yes, PrivatePids::from_str)
}

pub fn bpf_delegate_to_string<F>(mask: u64, parser: F) -> String
where
    F: Fn(u32) -> Option<&'static str>,
{
    if mask == u64::MAX {
        return "any".to_string();
    }

    let mut parts = Vec::new();
    for bit in 0..64u32 {
        if (mask & (1u64 << bit)) == 0 {
            continue;
        }

        match parser(bit) {
            Some(name) => parts.push(name.to_string()),
            None => parts.push(bit.to_string()),
        }
    }

    parts.join(",")
}

pub fn bpf_delegate_from_string<F>(value: &str, parser: F) -> Result<u64, ParseNamespaceTableError>
where
    F: Fn(&str) -> Option<u32>,
{
    if value == "any" {
        return Ok(u64::MAX);
    }

    let mut mask = 0u64;
    for word in value.split(',').filter(|word| !word.is_empty()) {
        let bit = parser(word)
            .or_else(|| word.parse::<u32>().ok())
            .ok_or(ParseNamespaceTableError)?;
        if bit >= 64 {
            return Err(ParseNamespaceTableError);
        }
        mask |= 1u64 << bit;
    }

    Ok(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_home_accepts_boolean_and_named_forms() {
        assert_eq!(protect_home_from_string("yes"), Ok(ProtectHome::Yes));
        assert_eq!(protect_home_from_string("1"), Ok(ProtectHome::Yes));
        assert_eq!(
            protect_home_from_string("read-only"),
            Ok(ProtectHome::ReadOnly)
        );
    }

    #[test]
    fn protect_hostname_round_trips() {
        assert_eq!(
            protect_hostname_to_string(ProtectHostname::Private),
            "private"
        );
        assert_eq!(protect_hostname_from_string("on"), Ok(ProtectHostname::Yes));
    }

    #[test]
    fn protect_system_round_trips() {
        assert_eq!(ProtectSystem::Strict.to_index(), 3);
        assert_eq!(protect_system_from_string("full"), Ok(ProtectSystem::Full));
    }

    #[test]
    fn protect_control_groups_round_trips() {
        assert_eq!(
            protect_control_groups_from_string("false"),
            Ok(ProtectControlGroups::No)
        );
        assert_eq!(
            protect_control_groups_to_string(ProtectControlGroups::Strict),
            "strict"
        );
    }

    #[test]
    fn protect_proc_and_proc_subset_use_plain_string_tables() {
        assert_eq!(
            protect_proc_from_string("ptraceable"),
            Ok(ProtectProc::Ptraceable)
        );
        assert_eq!(proc_subset_from_string("pid"), Ok(ProcSubset::Pid));
    }

    #[test]
    fn private_modes_honor_boolean_shortcuts() {
        assert_eq!(private_bpf_from_string("true"), Ok(PrivateBpf::Yes));
        assert_eq!(private_tmp_from_string("yes"), Ok(PrivateTmp::Connected));
        assert_eq!(private_users_from_string("1"), Ok(PrivateUsers::SelfUser));
        assert_eq!(private_pids_from_string("0"), Ok(PrivatePids::No));
    }

    #[test]
    fn invalid_value_maps_to_einval_shape() {
        let err = protect_proc_from_string("bogus").unwrap_err();
        assert_eq!(err.errno(), Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn bpf_delegate_to_string_handles_any_and_unknown_bits() {
        assert_eq!(bpf_delegate_to_string(u64::MAX, |_| None), "any");
        assert_eq!(
            bpf_delegate_to_string((1 << 1) | (1 << 3), |bit| match bit {
                1 => Some("bind"),
                _ => None,
            }),
            "bind,3"
        );
    }

    #[test]
    fn bpf_delegate_from_string_accepts_named_and_numeric_bits() {
        let mask = bpf_delegate_from_string("bind,4", |word| match word {
            "bind" => Some(1),
            _ => None,
        })
        .unwrap();
        assert_eq!(mask, (1 << 1) | (1 << 4));
    }

    #[test]
    fn bpf_delegate_from_string_rejects_invalid_tokens() {
        assert!(bpf_delegate_from_string("bogus", |_| None).is_err());
        assert!(bpf_delegate_from_string("64", |_| None).is_err());
    }
}
