// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/swap.c
//

use crate::ffi::Errno;
use crate::swap_tables::{SwapExecCommand, SwapResult};

pub type Result<T> = std::result::Result<T, SwapError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    InvalidWhat,
    WrongUnitName,
    InContainer,
    Busy,
    UnsupportedCleanMask,
    ConcurrentActivation,
}

impl SwapError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::InvalidWhat | Self::WrongUnitName => Errno::ENOEXEC.to_neg_errno(),
            Self::InContainer => Errno::EPERM.to_neg_errno(),
            Self::Busy => Errno::EBUSY.to_neg_errno(),
            Self::UnsupportedCleanMask => Errno::EUNATCH.to_neg_errno(),
            Self::ConcurrentActivation => Errno::EAGAIN.to_neg_errno(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapState {
    Dead,
    Activating,
    ActivatingDone,
    Active,
    Deactivating,
    DeactivatingSigterm,
    DeactivatingSigkill,
    Failed,
    Cleaning,
}

impl SwapState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dead => "dead",
            Self::Activating => "activating",
            Self::ActivatingDone => "activating-done",
            Self::Active => "active",
            Self::Deactivating => "deactivating",
            Self::DeactivatingSigterm => "deactivating-sigterm",
            Self::DeactivatingSigkill => "deactivating-sigkill",
            Self::Failed => "failed",
            Self::Cleaning => "cleaning",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Activating,
    Active,
    Deactivating,
    Failed,
    Maintenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanMask {
    ExecRuntime,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SwapParameters {
    pub what: Option<String>,
    pub options: Option<String>,
    pub priority: i32,
    pub priority_set: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Swap {
    pub unit_name: String,
    pub state: SwapState,
    pub result: SwapResult,
    pub clean_result: SwapResult,
    pub what: Option<String>,
    pub devnode: Option<String>,
    pub from_proc_swaps: bool,
    pub from_fragment: bool,
    pub timeout_usec: u64,
    pub parameters_proc_swaps: SwapParameters,
    pub parameters_fragment: SwapParameters,
    pub control_command_id: Option<SwapExecCommand>,
    pub control_pid_watched: bool,
    pub timer_armed: bool,
}

impl Swap {
    pub fn new(unit_name: impl Into<String>, timeout_usec: u64) -> Self {
        Self {
            unit_name: unit_name.into(),
            state: SwapState::Dead,
            result: SwapResult::Success,
            clean_result: SwapResult::Success,
            what: None,
            devnode: None,
            from_proc_swaps: false,
            from_fragment: false,
            timeout_usec,
            parameters_proc_swaps: SwapParameters::default(),
            parameters_fragment: SwapParameters::default(),
            control_command_id: None,
            control_pid_watched: false,
            timer_armed: false,
        }
    }
}

pub fn swap_state_with_process(state: SwapState) -> bool {
    matches!(
        state,
        SwapState::Activating
            | SwapState::ActivatingDone
            | SwapState::Deactivating
            | SwapState::DeactivatingSigterm
            | SwapState::DeactivatingSigkill
            | SwapState::Cleaning
    )
}

pub fn swap_active_state(swap: &Swap) -> UnitActiveState {
    match swap.state {
        SwapState::Dead => UnitActiveState::Inactive,
        SwapState::Activating => UnitActiveState::Activating,
        SwapState::ActivatingDone | SwapState::Active => UnitActiveState::Active,
        SwapState::Deactivating
        | SwapState::DeactivatingSigterm
        | SwapState::DeactivatingSigkill => UnitActiveState::Deactivating,
        SwapState::Failed => UnitActiveState::Failed,
        SwapState::Cleaning => UnitActiveState::Maintenance,
    }
}

pub fn swap_sub_state_to_string(swap: &Swap) -> &'static str {
    swap.state.as_str()
}

pub fn swap_may_gc(swap: &Swap) -> bool {
    !swap.from_proc_swaps
}

pub fn swap_is_extrinsic(user_manager: bool) -> bool {
    user_manager
}

pub fn swap_unset_proc_swaps(swap: &mut Swap) {
    if !swap.from_proc_swaps {
        return;
    }

    swap.parameters_proc_swaps.what = None;
    swap.from_proc_swaps = false;
}

pub fn swap_set_devnode(swap: &mut Swap, devnode: Option<String>) {
    swap.devnode = devnode;
}

pub fn swap_init(unit_name: impl Into<String>, timeout_usec: u64) -> Swap {
    Swap::new(unit_name, timeout_usec)
}

pub fn swap_add_default_dependencies(
    default_dependencies: bool,
    system_manager: bool,
    in_container: bool,
) -> Vec<&'static str> {
    if !default_dependencies || !system_manager || in_container {
        return Vec::new();
    }

    vec!["swap.target", "umount.target(conflicts)"]
}

fn unit_name_from_path(path: &str) -> Result<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err(SwapError::InvalidWhat);
    }

    let mut name = trimmed.trim_start_matches('/').replace('/', "-");
    name = name.replace(' ', "\\x20");
    Ok(format!("{name}.swap"))
}

pub fn swap_verify(swap: &Swap) -> Result<()> {
    let what = swap.what.as_deref().ok_or(SwapError::InvalidWhat)?;
    let expected = unit_name_from_path(what)?;
    if expected != swap.unit_name {
        return Err(SwapError::WrongUnitName);
    }

    Ok(())
}

pub fn swap_set_state(swap: &mut Swap, state: SwapState) {
    swap.state = state;

    if !swap_state_with_process(state) {
        swap.timer_armed = false;
        swap.control_pid_watched = false;
        swap.control_command_id = None;
    }
}

pub fn swap_coldplug(swap: &mut Swap, deserialized_state: SwapState) {
    let new_state = if deserialized_state != swap.state {
        deserialized_state
    } else if swap.from_proc_swaps {
        SwapState::Active
    } else {
        swap.state
    };

    swap_set_state(swap, new_state);
}

pub fn swap_enter_dead(swap: &mut Swap, result: SwapResult) {
    if swap.result == SwapResult::Success || result == SwapResult::StartLimitHit {
        swap.result = result;
    }

    let target = if swap.result == SwapResult::Success {
        SwapState::Dead
    } else {
        SwapState::Failed
    };

    swap_set_state(swap, target);
}

pub fn swap_enter_active(swap: &mut Swap, result: SwapResult) {
    if swap.result == SwapResult::Success {
        swap.result = result;
    }
    swap_set_state(swap, SwapState::Active);
}

pub fn swap_enter_dead_or_active(swap: &mut Swap, result: SwapResult) {
    if swap.from_proc_swaps {
        swap_enter_active(swap, result);
    } else {
        swap_enter_dead(swap, result);
    }
}

pub fn swap_start(
    swap: &mut Swap,
    in_container: bool,
    competing_running_job: bool,
) -> Result<bool> {
    if in_container {
        return Err(SwapError::InContainer);
    }
    if competing_running_job {
        return Err(SwapError::ConcurrentActivation);
    }

    swap.result = SwapResult::Success;
    swap.control_command_id = Some(SwapExecCommand::Activate);
    swap.control_pid_watched = true;
    swap.timer_armed = true;
    swap_set_state(swap, SwapState::Activating);
    Ok(true)
}

pub fn swap_stop(swap: &mut Swap, in_container: bool) -> Result<bool> {
    match swap.state {
        SwapState::Deactivating
        | SwapState::DeactivatingSigterm
        | SwapState::DeactivatingSigkill => Ok(false),
        SwapState::Activating | SwapState::ActivatingDone => {
            swap_set_state(swap, SwapState::DeactivatingSigterm);
            Ok(false)
        }
        SwapState::Active => {
            if in_container {
                return Err(SwapError::InContainer);
            }
            swap.control_command_id = Some(SwapExecCommand::Deactivate);
            swap.control_pid_watched = true;
            swap.timer_armed = true;
            swap_set_state(swap, SwapState::Deactivating);
            Ok(true)
        }
        SwapState::Cleaning => {
            swap_set_state(swap, SwapState::DeactivatingSigkill);
            Ok(false)
        }
        _ => Err(SwapError::Busy),
    }
}

pub fn swap_can_clean(swap: &Swap) -> bool {
    matches!(swap.state, SwapState::Dead | SwapState::Failed)
}

pub fn swap_clean(swap: &Swap, mask: CleanMask) -> Result<()> {
    if !swap_can_clean(swap) {
        return Err(SwapError::Busy);
    }
    if mask != CleanMask::ExecRuntime {
        return Err(SwapError::UnsupportedCleanMask);
    }
    Ok(())
}

pub fn swap_is_network_ns_bound(namespace_path: Option<&str>) -> bool {
    namespace_path.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_states_match_c_helper() {
        assert!(swap_state_with_process(SwapState::Activating));
        assert!(swap_state_with_process(SwapState::Cleaning));
        assert!(!swap_state_with_process(SwapState::Active));
    }

    #[test]
    fn active_state_translation_matches_table() {
        let mut swap = Swap::new("dev-sda.swap", 10);
        swap.state = SwapState::Dead;
        assert_eq!(swap_active_state(&swap), UnitActiveState::Inactive);
        swap.state = SwapState::Active;
        assert_eq!(swap_active_state(&swap), UnitActiveState::Active);
        swap.state = SwapState::Cleaning;
        assert_eq!(swap_active_state(&swap), UnitActiveState::Maintenance);
    }

    #[test]
    fn may_gc_depends_on_proc_swaps_origin() {
        let mut swap = Swap::new("dev-sda.swap", 10);
        assert!(swap_may_gc(&swap));
        swap.from_proc_swaps = true;
        assert!(!swap_may_gc(&swap));
    }

    #[test]
    fn unset_proc_swaps_clears_flag_and_path() {
        let mut swap = Swap::new("dev-sda.swap", 10);
        swap.from_proc_swaps = true;
        swap.parameters_proc_swaps.what = Some("/dev/sda2".into());
        swap_unset_proc_swaps(&mut swap);
        assert!(!swap.from_proc_swaps);
        assert_eq!(swap.parameters_proc_swaps.what, None);
    }

    #[test]
    fn verify_checks_unit_name_matches_what() {
        let mut swap = Swap::new("dev-sda2.swap", 10);
        swap.what = Some("/dev/sda2".into());
        assert!(swap_verify(&swap).is_ok());

        swap.unit_name = "other.swap".into();
        assert_eq!(swap_verify(&swap), Err(SwapError::WrongUnitName));
    }

    #[test]
    fn start_respects_container_and_competing_jobs() {
        let mut swap = Swap::new("dev-sda2.swap", 10);
        assert_eq!(
            swap_start(&mut swap, true, false),
            Err(SwapError::InContainer)
        );
        assert_eq!(
            swap_start(&mut swap, false, true),
            Err(SwapError::ConcurrentActivation)
        );
        assert_eq!(swap_start(&mut swap, false, false), Ok(true));
        assert_eq!(swap.state, SwapState::Activating);
    }

    #[test]
    fn stop_follows_state_machine_rules() {
        let mut swap = Swap::new("dev-sda2.swap", 10);
        swap.state = SwapState::Active;
        assert_eq!(swap_stop(&mut swap, false), Ok(true));
        assert_eq!(swap.state, SwapState::Deactivating);

        let mut activating = Swap::new("dev-sda2.swap", 10);
        activating.state = SwapState::Activating;
        assert_eq!(swap_stop(&mut activating, false), Ok(false));
        assert_eq!(activating.state, SwapState::DeactivatingSigterm);
    }

    #[test]
    fn dead_or_active_prefers_active_for_proc_swaps_units() {
        let mut swap = Swap::new("dev-sda2.swap", 10);
        swap.from_proc_swaps = true;
        swap_enter_dead_or_active(&mut swap, SwapResult::Success);
        assert_eq!(swap.state, SwapState::Active);

        swap.from_proc_swaps = false;
        swap_enter_dead_or_active(&mut swap, SwapResult::Timeout);
        assert_eq!(swap.state, SwapState::Failed);
    }

    #[test]
    fn clean_requires_dead_or_failed_and_exec_runtime_mask() {
        let mut swap = Swap::new("dev-sda2.swap", 10);
        swap.state = SwapState::Dead;
        assert!(swap_clean(&swap, CleanMask::ExecRuntime).is_ok());
        assert_eq!(
            swap_clean(&swap, CleanMask::Other),
            Err(SwapError::UnsupportedCleanMask)
        );

        swap.state = SwapState::Active;
        assert_eq!(
            swap_clean(&swap, CleanMask::ExecRuntime),
            Err(SwapError::Busy)
        );
    }

    #[test]
    fn network_namespace_binding_is_presence_based() {
        assert!(swap_is_network_ns_bound(Some("/run/netns/demo")));
        assert!(!swap_is_network_ns_bound(None));
    }
}
