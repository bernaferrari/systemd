// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/path.c
//

use std::path::PathBuf;
use std::time::Duration;

const IN_DELETE_SELF: u32 = 0x0000_0400;
const IN_MOVE_SELF: u32 = 0x0000_0800;
const IN_ATTRIB: u32 = 0x0000_0004;
const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_MODIFY: u32 = 0x0000_0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Active,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Dead,
    Waiting,
    Running,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathType {
    Exists,
    ExistsGlob,
    Changed,
    Modified,
    DirectoryNotEmpty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSpec {
    pub path: PathBuf,
    pub path_type: PathType,
    pub previous_exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathObservation {
    pub exists: bool,
    pub glob_trigger: Option<PathBuf>,
    pub directory_is_empty: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TriggerLimit {
    pub interval: Duration,
    pub burst: u32,
}

pub fn active_state(state: PathState) -> UnitActiveState {
    match state {
        PathState::Dead => UnitActiveState::Inactive,
        PathState::Waiting | PathState::Running => UnitActiveState::Active,
        PathState::Failed => UnitActiveState::Failed,
    }
}

pub fn watch_mask(path_type: PathType) -> u32 {
    match path_type {
        PathType::Exists | PathType::ExistsGlob => IN_DELETE_SELF | IN_MOVE_SELF | IN_ATTRIB,
        PathType::Changed => {
            IN_DELETE_SELF
                | IN_MOVE_SELF
                | IN_ATTRIB
                | IN_CLOSE_WRITE
                | IN_CREATE
                | IN_DELETE
                | IN_MOVED_FROM
                | IN_MOVED_TO
        }
        PathType::Modified => {
            IN_DELETE_SELF
                | IN_MOVE_SELF
                | IN_ATTRIB
                | IN_CLOSE_WRITE
                | IN_CREATE
                | IN_DELETE
                | IN_MOVED_FROM
                | IN_MOVED_TO
                | IN_MODIFY
        }
        PathType::DirectoryNotEmpty => {
            IN_DELETE_SELF | IN_MOVE_SELF | IN_ATTRIB | IN_CREATE | IN_MOVED_TO
        }
    }
}

pub fn evaluate_spec(
    spec: &mut PathSpec,
    initial: bool,
    from_trigger_notify: bool,
    observation: &PathObservation,
) -> Option<PathBuf> {
    match spec.path_type {
        PathType::Exists => observation.exists.then(|| spec.path.clone()),
        PathType::ExistsGlob => observation.glob_trigger.clone(),
        PathType::DirectoryNotEmpty => {
            matches!(observation.directory_is_empty, Some(false)).then(|| spec.path.clone())
        }
        PathType::Changed | PathType::Modified => {
            let changed =
                !initial && !from_trigger_notify && observation.exists != spec.previous_exists;
            spec.previous_exists = observation.exists;
            changed.then(|| spec.path.clone())
        }
    }
}

pub fn should_mkdir(path_type: PathType) -> bool {
    !matches!(path_type, PathType::Exists | PathType::ExistsGlob)
}

pub fn default_trigger_limit(interval: Option<Duration>, burst: Option<u32>) -> TriggerLimit {
    TriggerLimit {
        interval: interval.unwrap_or(Duration::from_secs(2)),
        burst: burst.unwrap_or(200),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_path_states() {
        assert_eq!(active_state(PathState::Dead), UnitActiveState::Inactive);
        assert_eq!(active_state(PathState::Running), UnitActiveState::Active);
    }

    #[test]
    fn exposes_modified_watch_mask_superset() {
        let changed = watch_mask(PathType::Changed);
        let modified = watch_mask(PathType::Modified);
        assert_ne!(changed & IN_MODIFY, IN_MODIFY);
        assert_eq!(modified & IN_MODIFY, IN_MODIFY);
    }

    #[test]
    fn detects_glob_trigger_paths() {
        let mut spec = PathSpec {
            path: "/tmp/example".into(),
            path_type: PathType::ExistsGlob,
            previous_exists: false,
        };
        let trigger = evaluate_spec(
            &mut spec,
            false,
            false,
            &PathObservation {
                glob_trigger: Some("/tmp/example.txt".into()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(trigger, PathBuf::from("/tmp/example.txt"));
    }

    #[test]
    fn changed_paths_trigger_only_after_initial_transition() {
        let mut spec = PathSpec {
            path: "/tmp/example".into(),
            path_type: PathType::Changed,
            previous_exists: false,
        };

        assert!(
            evaluate_spec(
                &mut spec,
                true,
                false,
                &PathObservation {
                    exists: true,
                    ..Default::default()
                }
            )
            .is_none()
        );
        assert!(
            evaluate_spec(
                &mut spec,
                false,
                false,
                &PathObservation {
                    exists: false,
                    ..Default::default()
                }
            )
            .is_some()
        );
    }

    #[test]
    fn mkdir_is_skipped_for_plain_existence_checks() {
        assert!(!should_mkdir(PathType::Exists));
        assert!(!should_mkdir(PathType::ExistsGlob));
        assert!(should_mkdir(PathType::DirectoryNotEmpty));
    }

    #[test]
    fn applies_default_trigger_limit_values() {
        let limit = default_trigger_limit(None, None);
        assert_eq!(limit.interval, Duration::from_secs(2));
        assert_eq!(limit.burst, 200);
    }
}
