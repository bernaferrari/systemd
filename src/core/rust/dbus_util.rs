// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-util.c, src/core/dbus-util.h
//

use std::collections::BTreeMap;

use crate::ffi::Errno;
use systemd_shared_rs::bus_polkit::{
    self, AsyncPolkitQueryAction, AsyncPolkitReturn, PolkitError, PolkitFlags, UID_INVALID,
};

pub const SOURCE_PATHS: &[&str] = &["src/core/dbus-util.c", "src/core/dbus-util.h"];
pub const USEC_INFINITY: u64 = u64::MAX;
pub const POLKIT_ACTION_MANAGE_UNITS: &str = "org.freedesktop.systemd1.manage-units";
pub const POLKIT_ACTION_RELOAD_DAEMON: &str = "org.freedesktop.systemd1.reload-daemon";
pub const POLKIT_ACTION_SET_ENVIRONMENT: &str = "org.freedesktop.systemd1.set-environment";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitWriteFlags(u32);

impl UnitWriteFlags {
    pub const NONE: Self = Self(0);
    pub const NOOP: Self = Self(1 << 0);
    pub const ESCAPE_SPECIFIERS: Self = Self(1 << 1);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransientChange<T> {
    pub value: T,
    pub written_setting: Option<String>,
}

pub fn bus_property_get_triggered_unit(triggered_unit: Option<&str>) -> Option<String> {
    triggered_unit.map(str::to_string)
}

pub fn valid_user_group_name_or_id_relaxed(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    value.bytes().all(|b| b.is_ascii_digit())
        || value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub fn bus_set_transient_string(
    name: &str,
    value: &str,
    flags: UnitWriteFlags,
) -> Result<TransientChange<Option<String>>, Errno> {
    if name.is_empty() {
        return Err(Errno::EINVAL);
    }

    let stored = (!value.is_empty()).then(|| value.to_string());
    Ok(TransientChange {
        value: stored,
        written_setting: (!flags.contains(UnitWriteFlags::NOOP)).then(|| format!("{name}={value}")),
    })
}

pub fn bus_set_transient_bool(
    name: &str,
    value: bool,
    flags: UnitWriteFlags,
) -> Result<TransientChange<bool>, Errno> {
    if name.is_empty() {
        return Err(Errno::EINVAL);
    }

    Ok(TransientChange {
        value,
        written_setting: (!flags.contains(UnitWriteFlags::NOOP))
            .then(|| format!("{name}={}", yes_no(value))),
    })
}

pub fn bus_set_transient_tristate(
    name: &str,
    value: bool,
    flags: UnitWriteFlags,
) -> Result<TransientChange<i32>, Errno> {
    if name.is_empty() {
        return Err(Errno::EINVAL);
    }

    Ok(TransientChange {
        value: i32::from(value),
        written_setting: (!flags.contains(UnitWriteFlags::NOOP))
            .then(|| format!("{name}={}", yes_no(value))),
    })
}

pub fn bus_set_transient_usec_internal(
    name: &str,
    value: u64,
    fix_0: bool,
    flags: UnitWriteFlags,
) -> Result<TransientChange<u64>, Errno> {
    if !name.ends_with("USec") {
        return Err(Errno::EINVAL);
    }

    let stored = if fix_0 && value == 0 {
        USEC_INFINITY
    } else {
        value
    };
    let key = name.strip_suffix("USec").ok_or(Errno::EINVAL)?;
    Ok(TransientChange {
        value: stored,
        written_setting: (!flags.contains(UnitWriteFlags::NOOP))
            .then(|| format!("{key}Sec={value}")),
    })
}

pub fn bus_set_transient_usec(
    name: &str,
    value: u64,
    flags: UnitWriteFlags,
) -> Result<TransientChange<u64>, Errno> {
    bus_set_transient_usec_internal(name, value, false, flags)
}

pub fn bus_set_transient_usec_fix_0(
    name: &str,
    value: u64,
    flags: UnitWriteFlags,
) -> Result<TransientChange<u64>, Errno> {
    bus_set_transient_usec_internal(name, value, true, flags)
}

pub fn bus_verify_manage_units_async_impl(
    id: Option<&str>,
    verb: Option<&str>,
    polkit_message: Option<&str>,
) -> Vec<(String, String)> {
    let mut details = Vec::new();
    if let Some(id) = id {
        details.push(("unit".into(), id.into()));
    }
    if let Some(verb) = verb {
        details.push(("verb".into(), verb.into()));
    }
    if let Some(message) = polkit_message {
        details.push(("polkit.message".into(), message.into()));
        details.push(("polkit.gettext_domain".into(), "systemd".into()));
    }
    details
}

pub fn bus_verify_manage_units_authorization(
    id: Option<&str>,
    verb: Option<&str>,
    polkit_message: Option<&str>,
    sender_uid: u32,
    sender_privileged: bool,
    existing_actions: &[AsyncPolkitQueryAction],
    allow_interactive: bool,
) -> Result<AsyncPolkitReturn, PolkitError> {
    let mut flags = PolkitFlags::empty();
    if allow_interactive {
        flags |= PolkitFlags::ALLOW_INTERACTIVE;
    }

    let details = bus_verify_manage_units_async_impl(id, verb, polkit_message);
    bus_polkit::bus_verify_polkit_async_full(
        POLKIT_ACTION_MANAGE_UNITS,
        UID_INVALID,
        flags,
        sender_uid,
        sender_privileged,
        existing_actions,
        &details,
    )
}

pub fn bus_verify_polkit_action_authorization(
    action: &str,
    sender_uid: u32,
    sender_privileged: bool,
    existing_actions: &[AsyncPolkitQueryAction],
    allow_interactive: bool,
) -> Result<AsyncPolkitReturn, PolkitError> {
    let mut flags = PolkitFlags::empty();
    if allow_interactive {
        flags |= PolkitFlags::ALLOW_INTERACTIVE;
    }

    bus_polkit::bus_verify_polkit_async_full(
        action,
        UID_INVALID,
        flags,
        sender_uid,
        sender_privileged,
        existing_actions,
        &[],
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountOptions {
    pub by_partition: BTreeMap<String, String>,
}

pub fn bus_read_mount_options(
    entries: &[(String, String)],
    in_out_format_str: Option<&str>,
    separator: Option<&str>,
) -> Result<(MountOptions, Option<String>), Errno> {
    if in_out_format_str.is_some() != separator.is_some() {
        return Err(Errno::EINVAL);
    }

    let mut options = MountOptions::default();
    let mut format_parts = in_out_format_str
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .into_iter()
        .collect::<Vec<_>>();

    for (partition, mount_options) in entries {
        if mount_options.chars().any(char::is_whitespace) || partition.is_empty() {
            return Err(Errno::EINVAL);
        }

        options
            .by_partition
            .insert(partition.clone(), mount_options.clone());

        if !mount_options.is_empty() {
            if let Some(_) = separator {
                format_parts.push(format!("{partition}:{}", shell_escape_colon(mount_options)));
            }
        }
    }

    let format_str = separator
        .map(|sep| format_parts.join(sep))
        .filter(|s| !s.is_empty());
    Ok((options, format_str))
}

pub fn bus_property_get_activation_details(
    details: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    details
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn shell_escape_colon(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, ':' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemd_shared_rs::bus_polkit::AsyncActionStatus;

    #[test]
    fn triggered_unit_property_is_optional() {
        assert_eq!(
            bus_property_get_triggered_unit(Some("dbus.service")),
            Some("dbus.service".into())
        );
        assert_eq!(bus_property_get_triggered_unit(None), None);
    }

    #[test]
    fn relaxed_user_group_validation_matches_intent() {
        assert!(valid_user_group_name_or_id_relaxed("root"));
        assert!(valid_user_group_name_or_id_relaxed("1000"));
        assert!(!valid_user_group_name_or_id_relaxed("bad name"));
    }

    #[test]
    fn transient_string_elides_empty_values() {
        let change = bus_set_transient_string("User", "", UnitWriteFlags::NONE).unwrap();
        assert_eq!(change.value, None);
        assert_eq!(change.written_setting.as_deref(), Some("User="));
    }

    #[test]
    fn transient_bool_formats_yes_no() {
        let change = bus_set_transient_bool("PrivateTmp", true, UnitWriteFlags::NONE).unwrap();
        assert_eq!(change.written_setting.as_deref(), Some("PrivateTmp=yes"));
    }

    #[test]
    fn transient_usec_fix_zero_uses_infinity() {
        let change = bus_set_transient_usec_fix_0("TimeoutUSec", 0, UnitWriteFlags::NONE).unwrap();
        assert_eq!(change.value, USEC_INFINITY);
        assert_eq!(change.written_setting.as_deref(), Some("TimeoutSec=0"));
    }

    #[test]
    fn polkit_details_follow_c_key_order() {
        let details = bus_verify_manage_units_async_impl(
            Some("a.service"),
            Some("start"),
            Some("Start a.service"),
        );
        assert_eq!(details[0], ("unit".into(), "a.service".into()));
        assert_eq!(details[1], ("verb".into(), "start".into()));
        assert_eq!(details[2].0, "polkit.message");
    }

    #[test]
    fn manage_units_authorization_allows_privileged_sender() {
        let result = bus_verify_manage_units_authorization(
            Some("a.service"),
            Some("start"),
            Some("Start a.service"),
            1000,
            true,
            &[],
            false,
        )
        .unwrap();

        assert_eq!(result, AsyncPolkitReturn::Authorized);
    }

    #[test]
    fn manage_units_authorization_requires_polkit_for_unprivileged_sender() {
        let result = bus_verify_manage_units_authorization(
            Some("a.service"),
            Some("start"),
            Some("Start a.service"),
            1000,
            false,
            &[],
            false,
        )
        .unwrap();

        assert_eq!(result, AsyncPolkitReturn::QueryDispatched);
    }

    #[test]
    fn manage_units_authorization_denies_cached_polkit_denial() {
        let details = bus_verify_manage_units_async_impl(
            Some("a.service"),
            Some("start"),
            Some("Start a.service"),
        );
        let existing = vec![AsyncPolkitQueryAction {
            action: POLKIT_ACTION_MANAGE_UNITS.to_string(),
            details: details.clone(),
            status: AsyncActionStatus::Denied,
        }];

        let result = bus_verify_manage_units_authorization(
            Some("a.service"),
            Some("start"),
            Some("Start a.service"),
            1000,
            false,
            &existing,
            false,
        )
        .unwrap();

        assert_eq!(result, AsyncPolkitReturn::Denied);
    }

    #[test]
    fn manage_units_authorization_allows_cached_polkit_grant() {
        let details = bus_verify_manage_units_async_impl(
            Some("a.service"),
            Some("start"),
            Some("Start a.service"),
        );
        let existing = vec![AsyncPolkitQueryAction {
            action: POLKIT_ACTION_MANAGE_UNITS.to_string(),
            details: details.clone(),
            status: AsyncActionStatus::Authorized,
        }];

        let result = bus_verify_manage_units_authorization(
            Some("a.service"),
            Some("start"),
            Some("Start a.service"),
            1000,
            false,
            &existing,
            false,
        )
        .unwrap();

        assert_eq!(result, AsyncPolkitReturn::Authorized);
    }

    #[test]
    fn action_authorization_requires_polkit_for_unprivileged_sender() {
        let result = bus_verify_polkit_action_authorization(
            POLKIT_ACTION_RELOAD_DAEMON,
            1000,
            false,
            &[],
            false,
        )
        .unwrap();

        assert_eq!(result, AsyncPolkitReturn::QueryDispatched);
    }

    #[test]
    fn action_authorization_allows_cached_polkit_grant() {
        let existing = vec![AsyncPolkitQueryAction {
            action: POLKIT_ACTION_SET_ENVIRONMENT.to_string(),
            details: vec![],
            status: AsyncActionStatus::Authorized,
        }];

        let result = bus_verify_polkit_action_authorization(
            POLKIT_ACTION_SET_ENVIRONMENT,
            1000,
            false,
            &existing,
            false,
        )
        .unwrap();

        assert_eq!(result, AsyncPolkitReturn::Authorized);
    }

    #[test]
    fn mount_options_builds_accumulator_string() {
        let (options, format_str) = bus_read_mount_options(
            &[("root".into(), "rw:nodev".into())],
            Some("existing"),
            Some(","),
        )
        .unwrap();

        assert_eq!(options.by_partition.get("root").unwrap(), "rw:nodev");
        assert_eq!(format_str.as_deref(), Some("existing,root:rw\\:nodev"));
    }

    #[test]
    fn mount_options_rejects_whitespace() {
        let result = bus_read_mount_options(&[("root".into(), "rw noexec".into())], None, None);
        assert_eq!(result, Err(Errno::EINVAL));
    }

    #[test]
    fn activation_details_preserve_sorted_pairs() {
        let map = BTreeMap::from([
            ("job".to_string(), "42".to_string()),
            ("trigger".to_string(), "timer".to_string()),
        ]);
        let pairs = bus_property_get_activation_details(&map);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "job");
    }
}
