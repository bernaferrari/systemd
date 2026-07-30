// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/smack-setup.c
//

pub const SOURCE_PATH: &str = "src/core/smack-setup.c";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    Ok,
    KernelUnsupported,
    SourceMissing,
    IgnoredFailure(i32),
    FatalFailure(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLabelWrites {
    pub proc_attr_current: bool,
    pub ambient: bool,
    pub default_netlabel: bool,
    pub localhost_netlabel: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmackSetupInput {
    pub access_rules: StepResult,
    pub have_run_label: bool,
    pub cipso_rules: StepResult,
    pub netlabel_rules: StepResult,
    pub onlycap_list: StepResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmackSetupOutcome {
    pub loaded_policy: bool,
    pub wrote_run_label: RunLabelWrites,
    pub completed_cipso_stage: bool,
    pub completed_netlabel_stage: bool,
    pub completed_onlycap_stage: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmackSetupError {
    OnlycapWriteFailed(i32),
}

impl SmackSetupError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::OnlycapWriteFailed(code) => code,
        }
    }
}

pub fn mac_smack_setup(input: SmackSetupInput) -> Result<SmackSetupOutcome, SmackSetupError> {
    let mut outcome = SmackSetupOutcome {
        loaded_policy: false,
        wrote_run_label: RunLabelWrites {
            proc_attr_current: false,
            ambient: false,
            default_netlabel: false,
            localhost_netlabel: false,
        },
        completed_cipso_stage: false,
        completed_netlabel_stage: false,
        completed_onlycap_stage: false,
    };

    match input.access_rules {
        StepResult::KernelUnsupported
        | StepResult::SourceMissing
        | StepResult::IgnoredFailure(_) => return Ok(outcome),
        StepResult::FatalFailure(code) => return Err(SmackSetupError::OnlycapWriteFailed(code)),
        StepResult::Ok => {}
    }

    if input.have_run_label {
        outcome.wrote_run_label = RunLabelWrites {
            proc_attr_current: true,
            ambient: true,
            default_netlabel: true,
            localhost_netlabel: true,
        };
    }

    match input.cipso_rules {
        StepResult::KernelUnsupported => return Ok(outcome),
        StepResult::SourceMissing | StepResult::IgnoredFailure(_) | StepResult::Ok => {
            outcome.completed_cipso_stage = true;
        }
        StepResult::FatalFailure(code) => return Err(SmackSetupError::OnlycapWriteFailed(code)),
    }

    match input.netlabel_rules {
        StepResult::KernelUnsupported => return Ok(outcome),
        StepResult::SourceMissing | StepResult::IgnoredFailure(_) | StepResult::Ok => {
            outcome.completed_netlabel_stage = true;
        }
        StepResult::FatalFailure(code) => return Err(SmackSetupError::OnlycapWriteFailed(code)),
    }

    match input.onlycap_list {
        StepResult::KernelUnsupported | StepResult::SourceMissing | StepResult::Ok => {
            outcome.completed_onlycap_stage = true;
        }
        StepResult::IgnoredFailure(code) | StepResult::FatalFailure(code) => {
            return Err(SmackSetupError::OnlycapWriteFailed(code));
        }
    }

    outcome.loaded_policy = true;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::Errno;

    fn ok_input() -> SmackSetupInput {
        SmackSetupInput {
            access_rules: StepResult::Ok,
            have_run_label: true,
            cipso_rules: StepResult::Ok,
            netlabel_rules: StepResult::Ok,
            onlycap_list: StepResult::Ok,
        }
    }

    #[test]
    fn access_kernel_unsupported_short_circuits() {
        let mut input = ok_input();
        input.access_rules = StepResult::KernelUnsupported;

        let outcome = mac_smack_setup(input).unwrap();
        assert!(!outcome.loaded_policy);
        assert!(!outcome.completed_cipso_stage);
    }

    #[test]
    fn missing_access_directory_short_circuits() {
        let mut input = ok_input();
        input.access_rules = StepResult::SourceMissing;

        let outcome = mac_smack_setup(input).unwrap();
        assert!(!outcome.loaded_policy);
        assert!(!outcome.wrote_run_label.proc_attr_current);
    }

    #[test]
    fn ignored_access_failure_is_non_fatal() {
        let mut input = ok_input();
        input.access_rules = StepResult::IgnoredFailure(Errno::EIO.to_neg_errno());

        let outcome = mac_smack_setup(input).unwrap();
        assert!(!outcome.loaded_policy);
    }

    #[test]
    fn successful_run_marks_every_stage() {
        let outcome = mac_smack_setup(ok_input()).unwrap();
        assert!(outcome.loaded_policy);
        assert!(outcome.wrote_run_label.proc_attr_current);
        assert!(outcome.wrote_run_label.ambient);
        assert!(outcome.completed_cipso_stage);
        assert!(outcome.completed_netlabel_stage);
        assert!(outcome.completed_onlycap_stage);
    }

    #[test]
    fn run_label_writes_are_skipped_when_feature_is_absent() {
        let mut input = ok_input();
        input.have_run_label = false;

        let outcome = mac_smack_setup(input).unwrap();
        assert!(outcome.loaded_policy);
        assert!(!outcome.wrote_run_label.proc_attr_current);
        assert!(!outcome.wrote_run_label.localhost_netlabel);
    }

    #[test]
    fn cipso_kernel_unsupported_returns_before_loaded_policy_is_set() {
        let mut input = ok_input();
        input.cipso_rules = StepResult::KernelUnsupported;

        let outcome = mac_smack_setup(input).unwrap();
        assert!(!outcome.loaded_policy);
        assert!(!outcome.completed_netlabel_stage);
    }

    #[test]
    fn missing_cipso_directory_is_ignored() {
        let mut input = ok_input();
        input.cipso_rules = StepResult::SourceMissing;

        let outcome = mac_smack_setup(input).unwrap();
        assert!(outcome.loaded_policy);
        assert!(outcome.completed_cipso_stage);
    }

    #[test]
    fn missing_netlabel_directory_is_ignored() {
        let mut input = ok_input();
        input.netlabel_rules = StepResult::SourceMissing;

        let outcome = mac_smack_setup(input).unwrap();
        assert!(outcome.loaded_policy);
        assert!(outcome.completed_netlabel_stage);
    }

    #[test]
    fn onlycap_kernel_unsupported_is_non_fatal() {
        let mut input = ok_input();
        input.onlycap_list = StepResult::KernelUnsupported;

        let outcome = mac_smack_setup(input).unwrap();
        assert!(outcome.loaded_policy);
        assert!(outcome.completed_onlycap_stage);
    }

    #[test]
    fn onlycap_missing_file_is_non_fatal() {
        let mut input = ok_input();
        input.onlycap_list = StepResult::SourceMissing;

        let outcome = mac_smack_setup(input).unwrap();
        assert!(outcome.loaded_policy);
    }

    #[test]
    fn onlycap_failure_is_fatal() {
        let mut input = ok_input();
        input.onlycap_list = StepResult::IgnoredFailure(Errno::EIO.to_neg_errno());

        assert_eq!(
            mac_smack_setup(input),
            Err(SmackSetupError::OnlycapWriteFailed(
                Errno::EIO.to_neg_errno()
            ))
        );
    }
}
