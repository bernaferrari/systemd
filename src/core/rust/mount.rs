// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/mount.c
//

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Activating,
    Active,
    Reloading,
    Deactivating,
    Failed,
    Maintenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountState {
    Dead,
    Mounting,
    MountingDone,
    Mounted,
    Remounting,
    RemountingSigterm,
    RemountingSigkill,
    Unmounting,
    UnmountingSigterm,
    UnmountingSigkill,
    Failed,
    Cleaning,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountParameters {
    pub what: Option<String>,
    pub options: Option<String>,
    pub fstype: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountConfig {
    pub from_fragment: bool,
    pub from_proc_self_mountinfo: bool,
    pub where_path: String,
    pub parameters_fragment: Option<MountParameters>,
    pub parameters_proc_self_mountinfo: Option<MountParameters>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountOptionError {
    InvalidBoolean(String),
}

pub fn active_state(state: MountState) -> UnitActiveState {
    match state {
        MountState::Dead => UnitActiveState::Inactive,
        MountState::Mounting | MountState::MountingDone => UnitActiveState::Activating,
        MountState::Mounted => UnitActiveState::Active,
        MountState::Remounting | MountState::RemountingSigterm | MountState::RemountingSigkill => {
            UnitActiveState::Reloading
        }
        MountState::Unmounting | MountState::UnmountingSigterm | MountState::UnmountingSigkill => {
            UnitActiveState::Deactivating
        }
        MountState::Failed => UnitActiveState::Failed,
        MountState::Cleaning => UnitActiveState::Maintenance,
    }
}

pub fn get_mount_parameters_fragment(config: &MountConfig) -> Option<&MountParameters> {
    config
        .from_fragment
        .then_some(config.parameters_fragment.as_ref())
        .flatten()
}

pub fn get_mount_parameters(config: &MountConfig) -> Option<&MountParameters> {
    if config.from_proc_self_mountinfo {
        config.parameters_proc_self_mountinfo.as_ref()
    } else {
        get_mount_parameters_fragment(config)
    }
}

pub fn mount_is_network(parameters: &MountParameters) -> bool {
    has_option(parameters.options.as_deref(), "_netdev")
        || parameters.fstype.as_deref().is_some_and(is_network_fstype)
}

pub fn mount_is_nofail(config: &MountConfig) -> bool {
    if !config.from_fragment {
        return false;
    }

    yes_no_option(
        get_mount_parameters_fragment(config).and_then(|p| p.options.as_deref()),
        "nofail",
        "fail",
    )
    .unwrap_or(false)
}

pub fn mount_is_loop(parameters: &MountParameters) -> bool {
    has_option(parameters.options.as_deref(), "loop")
}

pub fn mount_is_bind(parameters: &MountParameters) -> bool {
    has_option(parameters.options.as_deref(), "bind")
        || has_option(parameters.options.as_deref(), "rbind")
        || parameters.fstype.as_deref() == Some("bind")
}

pub fn mount_is_bound_to_device(config: &MountConfig) -> Result<Option<bool>, MountOptionError> {
    let Some(parameters) = get_mount_parameters(config) else {
        return Ok(None);
    };

    let Some(value) = option_value(parameters.options.as_deref(), "x-systemd.device-bound") else {
        return Ok(None);
    };

    match value {
        None => Ok(Some(true)),
        Some(raw) => parse_boolean(raw).map(Some),
    }
}

pub fn mount_propagate_stop(config: &MountConfig) -> bool {
    match mount_is_bound_to_device(config) {
        Ok(Some(_)) => false,
        Ok(None) | Err(_) => config.from_fragment,
    }
}

pub fn mount_source_requires_mounts_for(parameters: &MountParameters) -> bool {
    parameters.what.as_deref().is_some_and(is_absolute_path)
        && (mount_is_bind(parameters) || mount_is_loop(parameters) || !mount_is_network(parameters))
}

fn option_iter(options: Option<&str>) -> impl Iterator<Item = &str> {
    options
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn has_option(options: Option<&str>, key: &str) -> bool {
    option_iter(options)
        .any(|option| option.split_once('=').map_or(option, |(head, _)| head) == key)
}

fn option_value<'a>(options: Option<&'a str>, key: &str) -> Option<Option<&'a str>> {
    let mut result = None;
    for option in option_iter(options) {
        if let Some((head, value)) = option.split_once('=') {
            if head == key {
                result = Some(Some(value));
            }
        } else if option == key {
            result = Some(None);
        }
    }
    result
}

fn yes_no_option(options: Option<&str>, yes_key: &str, no_key: &str) -> Option<bool> {
    let mut result = None;
    for option in option_iter(options) {
        match option {
            value if value == yes_key => result = Some(true),
            value if value == no_key => result = Some(false),
            _ => {}
        }
    }
    result
}

fn parse_boolean(value: &str) -> Result<bool, MountOptionError> {
    match value {
        "1" | "yes" | "y" | "true" | "t" | "on" => Ok(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Ok(false),
        other => Err(MountOptionError::InvalidBoolean(other.to_string())),
    }
}

fn is_network_fstype(fstype: &str) -> bool {
    matches!(
        fstype,
        "9p" | "ceph" | "cifs" | "glusterfs" | "nfs" | "nfs4" | "smb3" | "sshfs"
    )
}

fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_mount_states() {
        assert_eq!(
            active_state(MountState::Mounting),
            UnitActiveState::Activating
        );
        assert_eq!(
            active_state(MountState::Cleaning),
            UnitActiveState::Maintenance
        );
    }

    #[test]
    fn detects_network_mounts_by_option_or_fstype() {
        let by_option = MountParameters {
            options: Some("rw,_netdev".into()),
            ..Default::default()
        };
        let by_type = MountParameters {
            fstype: Some("nfs".into()),
            ..Default::default()
        };

        assert!(mount_is_network(&by_option));
        assert!(mount_is_network(&by_type));
    }

    #[test]
    fn nofail_is_only_considered_for_fragment_mounts() {
        let config = MountConfig {
            from_fragment: true,
            parameters_fragment: Some(MountParameters {
                options: Some("nofail".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let runtime_only = MountConfig {
            from_fragment: false,
            parameters_fragment: config.parameters_fragment.clone(),
            ..Default::default()
        };

        assert!(mount_is_nofail(&config));
        assert!(!mount_is_nofail(&runtime_only));
    }

    #[test]
    fn explicit_device_bound_disables_stop_propagation() {
        let config = MountConfig {
            from_fragment: true,
            parameters_fragment: Some(MountParameters {
                options: Some("x-systemd.device-bound=no".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(mount_is_bound_to_device(&config).unwrap(), Some(false));
        assert!(!mount_propagate_stop(&config));
    }

    #[test]
    fn unspecified_device_bound_propagates_for_fragment_mounts() {
        let config = MountConfig {
            from_fragment: true,
            parameters_fragment: Some(MountParameters::default()),
            ..Default::default()
        };

        assert_eq!(mount_is_bound_to_device(&config).unwrap(), None);
        assert!(mount_propagate_stop(&config));
    }

    #[test]
    fn bind_and_loop_sources_need_support_mounts() {
        let bind = MountParameters {
            what: Some("/srv/source".into()),
            options: Some("bind".into()),
            ..Default::default()
        };
        let loop_mount = MountParameters {
            what: Some("/var/lib/disk.img".into()),
            options: Some("loop".into()),
            ..Default::default()
        };

        assert!(mount_source_requires_mounts_for(&bind));
        assert!(mount_source_requires_mounts_for(&loop_mount));
    }
}
