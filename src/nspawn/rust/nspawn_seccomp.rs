// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-seccomp.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn-seccomp.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &["add_syscall_filters", "setup_seccomp"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompArch {
    Native,
    Secondary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompProfile {
    pub arch: SeccompArch,
    pub allowed: Vec<String>,
    pub denied: Vec<String>,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_seccomp",
        source_path: SOURCE_PATH,
        source_lines: 253,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn add_syscall_filters(
    arch: SeccompArch,
    cap_list_retain: u64,
    syscall_allow_list: &[&str],
    syscall_deny_list: &[&str],
) -> Result<SeccompProfile, Errno> {
    let mut allowed = vec![
        "@basic-io".to_string(),
        "@default".to_string(),
        "@file-system".to_string(),
        "@network-io".to_string(),
        "@process".to_string(),
    ];

    if cap_list_retain != 0 {
        allowed.push("capability-gated-syscalls".to_string());
    }

    allowed.extend(syscall_allow_list.iter().map(|s| (*s).to_string()));

    Ok(SeccompProfile {
        arch,
        allowed,
        denied: syscall_deny_list.iter().map(|s| (*s).to_string()).collect(),
    })
}

pub fn setup_seccomp(
    seccomp_available: bool,
    cap_list_retain: u64,
    syscall_allow_list: &[&str],
    syscall_deny_list: &[&str],
) -> Result<Vec<SeccompProfile>, Errno> {
    if !seccomp_available {
        return Ok(Vec::new());
    }

    Ok(vec![
        add_syscall_filters(
            SeccompArch::Native,
            cap_list_retain,
            syscall_allow_list,
            syscall_deny_list,
        )?,
        add_syscall_filters(
            SeccompArch::Secondary,
            cap_list_retain,
            syscall_allow_list,
            syscall_deny_list,
        )?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_seccomp_produces_no_profiles() {
        assert!(setup_seccomp(false, 0, &[], &[]).unwrap().is_empty());
    }

    #[test]
    fn configured_profiles_preserve_explicit_rules() {
        let profiles = setup_seccomp(true, 1, &["ioctl"], &["mount"]).unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles[0].allowed.iter().any(|s| s == "ioctl"));
        assert!(profiles[0].denied.iter().any(|s| s == "mount"));
    }
}
