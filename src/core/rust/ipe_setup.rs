// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/ipe-setup.c
//

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const IPE_SECFS_DIR: &str = "/sys/kernel/security/ipe";
pub const IPE_SECFS_NEW_POLICY: &str = "/sys/kernel/security/ipe/new_policy";
pub const IPE_SECFS_POLICIES: &str = "/sys/kernel/security/ipe/policies";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpeSetupError {
    InvalidPolicyPath(PathBuf),
    InvalidPolicyName(String),
    DuplicatePolicyName(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFile {
    pub source_path: PathBuf,
    pub file_name: String,
    pub policy_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyOutputTarget {
    Update(PathBuf),
    Install(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLoadPlan {
    pub policy: PolicyFile,
    pub output_target: PolicyOutputTarget,
    pub activate_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationDisposition {
    Activated,
    SkippedAlreadyCurrent,
}

impl PolicyFile {
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, IpeSetupError> {
        let source_path = path.into();
        let file_name = source_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| IpeSetupError::InvalidPolicyPath(source_path.clone()))?;

        let policy_name = file_name
            .strip_suffix(".p7b")
            .ok_or_else(|| IpeSetupError::InvalidPolicyPath(source_path.clone()))?
            .to_string();

        if !filename_is_valid(&policy_name) {
            return Err(IpeSetupError::InvalidPolicyName(policy_name));
        }

        Ok(Self {
            source_path,
            file_name,
            policy_name,
        })
    }
}

pub fn collect_policy_load_plans<I, P>(
    securityfs_present: bool,
    policy_paths: I,
    installed_policies: &BTreeSet<String>,
) -> Result<Vec<PolicyLoadPlan>, IpeSetupError>
where
    I: IntoIterator<Item = P>,
    P: Into<PathBuf>,
{
    if !securityfs_present {
        return Ok(Vec::new());
    }

    let mut seen = BTreeSet::new();
    let mut plans = Vec::new();

    for path in policy_paths {
        let policy = PolicyFile::from_path(path)?;
        if !seen.insert(policy.policy_name.clone()) {
            return Err(IpeSetupError::DuplicatePolicyName(policy.policy_name));
        }

        let already_installed = installed_policies.contains(&policy.policy_name);
        plans.push(build_policy_load_plan(policy, already_installed));
    }

    Ok(plans)
}

pub fn build_policy_load_plan(policy: PolicyFile, already_installed: bool) -> PolicyLoadPlan {
    let output_target = if already_installed {
        PolicyOutputTarget::Update(
            Path::new(IPE_SECFS_POLICIES)
                .join(&policy.policy_name)
                .join("update"),
        )
    } else {
        PolicyOutputTarget::Install(PathBuf::from(IPE_SECFS_NEW_POLICY))
    };

    let activate_path = Path::new(IPE_SECFS_POLICIES)
        .join(&policy.policy_name)
        .join("active");

    PolicyLoadPlan {
        policy,
        output_target,
        activate_path,
    }
}

pub fn finalize_activation(write_result: Result<(), i32>) -> Result<ActivationDisposition, i32> {
    match write_result {
        Ok(()) => Ok(ActivationDisposition::Activated),
        Err(code) if code == -libc::ESTALE => Ok(ActivationDisposition::SkippedAlreadyCurrent),
        Err(code) => Err(code),
    }
}

fn filename_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.as_bytes().contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_work_when_kernel_support_is_absent() {
        let plans = collect_policy_load_plans(false, ["/etc/ipe/a.p7b"], &BTreeSet::new()).unwrap();
        assert!(plans.is_empty());
    }

    #[test]
    fn builds_install_plan_for_new_policy() {
        let policy = PolicyFile::from_path("/etc/ipe/example.p7b").unwrap();
        let plan = build_policy_load_plan(policy, false);

        assert_eq!(plan.policy.policy_name, "example");
        assert_eq!(
            plan.output_target,
            PolicyOutputTarget::Install(PathBuf::from(IPE_SECFS_NEW_POLICY))
        );
        assert_eq!(
            plan.activate_path,
            Path::new(IPE_SECFS_POLICIES).join("example").join("active")
        );
    }

    #[test]
    fn builds_update_plan_for_installed_policy() {
        let policy = PolicyFile::from_path("/etc/ipe/example.p7b").unwrap();
        let plan = build_policy_load_plan(policy, true);

        assert_eq!(
            plan.output_target,
            PolicyOutputTarget::Update(
                Path::new(IPE_SECFS_POLICIES).join("example").join("update")
            )
        );
    }

    #[test]
    fn rejects_invalid_extension() {
        let error = PolicyFile::from_path("/etc/ipe/example.pem").unwrap_err();
        assert!(matches!(error, IpeSetupError::InvalidPolicyPath(_)));
    }

    #[test]
    fn interprets_estale_as_already_current() {
        let result = finalize_activation(Err(-libc::ESTALE)).unwrap();
        assert_eq!(result, ActivationDisposition::SkippedAlreadyCurrent);
    }

    #[test]
    fn detects_duplicate_policy_names() {
        let installed = BTreeSet::new();
        let error = collect_policy_load_plans(
            true,
            ["/etc/ipe/first/example.p7b", "/run/ipe/example.p7b"],
            &installed,
        )
        .unwrap_err();

        assert_eq!(error, IpeSetupError::DuplicatePolicyName("example".into()));
    }
}
