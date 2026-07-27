// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/selinux-setup.c
//

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/selinux-setup.c";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessResult {
    Exists,
    Missing,
    Error(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetConResult<'a> {
    Error,
    Empty,
    Context(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadPolicyResult {
    Loaded { enforce: i32 },
    NotLoaded { enforce: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitLabelResult<'a> {
    Error(i32),
    Label(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetConResult {
    Success,
    Error(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelinuxSetupInput<'a> {
    pub library_available: bool,
    pub in_initrd: bool,
    pub policy_access: AccessResult,
    pub current_context: GetConResult<'a>,
    pub load_policy: LoadPolicyResult,
    pub init_label: InitLabelResult<'a>,
    pub set_con: SetConResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelinuxSetupOutcome {
    pub loaded_policy: bool,
    pub initialized_before_setup: bool,
    pub retested_after_load: bool,
    pub attempted_transition: bool,
    pub reopened_log_after_load: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxSetupError {
    PolicyLoadFailedEnforcing,
}

impl SelinuxSetupError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::PolicyLoadFailedEnforcing => Errno::EIO.to_neg_errno(),
        }
    }
}

pub fn mac_selinux_setup(
    input: SelinuxSetupInput<'_>,
) -> Result<SelinuxSetupOutcome, SelinuxSetupError> {
    if !input.library_available {
        return Ok(SelinuxSetupOutcome {
            loaded_policy: false,
            initialized_before_setup: false,
            retested_after_load: false,
            attempted_transition: false,
            reopened_log_after_load: false,
        });
    }

    if input.in_initrd {
        match input.policy_access {
            AccessResult::Missing => {
                return Ok(SelinuxSetupOutcome {
                    loaded_policy: false,
                    initialized_before_setup: false,
                    retested_after_load: false,
                    attempted_transition: false,
                    reopened_log_after_load: false,
                });
            }
            AccessResult::Exists | AccessResult::Error(_) => {}
        }
    }

    let initialized_before_setup =
        matches!(input.current_context, GetConResult::Context(con) if con != "kernel");

    match input.load_policy {
        LoadPolicyResult::Loaded { .. } => {
            let attempted_transition = matches!(input.init_label, InitLabelResult::Label(_));
            Ok(SelinuxSetupOutcome {
                loaded_policy: true,
                initialized_before_setup,
                retested_after_load: true,
                attempted_transition,
                reopened_log_after_load: attempted_transition,
            })
        }
        LoadPolicyResult::NotLoaded { enforce } => {
            if enforce > 0 && !initialized_before_setup {
                return Err(SelinuxSetupError::PolicyLoadFailedEnforcing);
            }

            Ok(SelinuxSetupOutcome {
                loaded_policy: false,
                initialized_before_setup,
                retested_after_load: false,
                attempted_transition: false,
                reopened_log_after_load: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> SelinuxSetupInput<'static> {
        SelinuxSetupInput {
            library_available: true,
            in_initrd: false,
            policy_access: AccessResult::Exists,
            current_context: GetConResult::Context("kernel"),
            load_policy: LoadPolicyResult::Loaded { enforce: 1 },
            init_label: InitLabelResult::Label("system_u:system_r:init_t:s0"),
            set_con: SetConResult::Success,
        }
    }

    #[test]
    fn skips_when_library_is_unavailable() {
        let mut input = base_input();
        input.library_available = false;

        let outcome = mac_selinux_setup(input).unwrap();
        assert!(!outcome.loaded_policy);
        assert!(!outcome.retested_after_load);
    }

    #[test]
    fn skips_in_initrd_when_policy_path_is_missing() {
        let mut input = base_input();
        input.in_initrd = true;
        input.policy_access = AccessResult::Missing;

        let outcome = mac_selinux_setup(input).unwrap();
        assert!(!outcome.loaded_policy);
        assert!(!outcome.attempted_transition);
    }

    #[test]
    fn access_errors_in_initrd_do_not_force_skip() {
        let mut input = base_input();
        input.in_initrd = true;
        input.policy_access = AccessResult::Error(Errno::EACCES.to_neg_errno());

        let outcome = mac_selinux_setup(input).unwrap();
        assert!(outcome.loaded_policy);
    }

    #[test]
    fn kernel_context_is_not_treated_as_initialized() {
        let outcome = mac_selinux_setup(base_input()).unwrap();
        assert!(!outcome.initialized_before_setup);
    }

    #[test]
    fn non_kernel_context_is_treated_as_initialized() {
        let mut input = base_input();
        input.current_context = GetConResult::Context("system_u:system_r:init_t:s0");

        let outcome = mac_selinux_setup(input).unwrap();
        assert!(outcome.initialized_before_setup);
    }

    #[test]
    fn empty_context_is_not_treated_as_initialized() {
        let mut input = base_input();
        input.current_context = GetConResult::Empty;

        let outcome = mac_selinux_setup(input).unwrap();
        assert!(!outcome.initialized_before_setup);
    }

    #[test]
    fn successful_load_marks_policy_loaded_and_retested() {
        let outcome = mac_selinux_setup(base_input()).unwrap();
        assert!(outcome.loaded_policy);
        assert!(outcome.retested_after_load);
        assert!(outcome.attempted_transition);
        assert!(outcome.reopened_log_after_load);
    }

    #[test]
    fn label_lookup_failure_skips_transition_attempt() {
        let mut input = base_input();
        input.init_label = InitLabelResult::Error(Errno::ENOENT.to_neg_errno());

        let outcome = mac_selinux_setup(input).unwrap();
        assert!(outcome.loaded_policy);
        assert!(!outcome.attempted_transition);
        assert!(!outcome.reopened_log_after_load);
    }

    #[test]
    fn enforcing_load_failure_without_previous_initialization_is_fatal() {
        let mut input = base_input();
        input.load_policy = LoadPolicyResult::NotLoaded { enforce: 1 };

        assert_eq!(
            mac_selinux_setup(input),
            Err(SelinuxSetupError::PolicyLoadFailedEnforcing)
        );
    }

    #[test]
    fn enforcing_load_failure_with_previous_initialization_is_not_fatal() {
        let mut input = base_input();
        input.current_context = GetConResult::Context("user_u:user_r:user_t:s0");
        input.load_policy = LoadPolicyResult::NotLoaded { enforce: 1 };

        let outcome = mac_selinux_setup(input).unwrap();
        assert!(!outcome.loaded_policy);
        assert!(outcome.initialized_before_setup);
        assert!(outcome.reopened_log_after_load);
    }

    #[test]
    fn permissive_load_failure_is_ignored() {
        let mut input = base_input();
        input.load_policy = LoadPolicyResult::NotLoaded { enforce: 0 };

        let outcome = mac_selinux_setup(input).unwrap();
        assert!(!outcome.loaded_policy);
        assert!(!outcome.retested_after_load);
    }

    #[test]
    fn setup_error_maps_to_eio() {
        assert_eq!(
            SelinuxSetupError::PolicyLoadFailedEnforcing.errno(),
            Errno::EIO.to_neg_errno()
        );
    }
}
