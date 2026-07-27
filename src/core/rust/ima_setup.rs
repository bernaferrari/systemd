// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/ima-setup.c, src/core/ima-setup.h

use crate::ffi::Errno;

pub const IMA_SECFS_DIR: &str = "/sys/kernel/security/ima";
pub const IMA_SECFS_POLICY: &str = "/sys/kernel/security/ima/policy";
pub const IMA_POLICY_PATH: &str = "/etc/ima/ima-policy";

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImaSetupState {
    DisabledAtBuild,
    KernelUnsupported,
    PolicyAlreadyLoaded,
    PolicyMissing,
    LoadedByReference,
    LoadedByCopy { written_lines: usize },
}

pub trait ImaPolicyBackend {
    fn secfs_dir_exists(&self) -> bool;
    fn policy_is_writable(&self) -> bool;
    fn custom_policy_exists(&self) -> bool;
    fn open_policy_for_write(&mut self) -> Result<()>;
    fn write_policy_reference(&mut self, path: &str) -> Result<bool>;
    fn read_policy_lines(&self) -> Result<Vec<String>>;
    fn reopen_policy_for_write(&mut self) -> Result<()>;
    fn write_policy_line(&mut self, line: &str) -> Result<()>;
}

pub fn ima_setup(
    enabled_at_build: bool,
    backend: &mut impl ImaPolicyBackend,
) -> Result<ImaSetupState> {
    if !enabled_at_build {
        return Ok(ImaSetupState::DisabledAtBuild);
    }

    if !backend.secfs_dir_exists() {
        return Ok(ImaSetupState::KernelUnsupported);
    }

    if !backend.policy_is_writable() {
        return Ok(ImaSetupState::PolicyAlreadyLoaded);
    }

    if !backend.custom_policy_exists() {
        return Ok(ImaSetupState::PolicyMissing);
    }

    backend.open_policy_for_write()?;
    if backend.write_policy_reference(IMA_POLICY_PATH)? {
        return Ok(ImaSetupState::LoadedByReference);
    }

    let lines = backend.read_policy_lines()?;
    backend.reopen_policy_for_write()?;

    let mut written_lines = 0;
    for line in lines {
        if !line.is_empty() {
            backend.write_policy_line(&line)?;
        }
        written_lines += 1;
    }

    Ok(ImaSetupState::LoadedByCopy { written_lines })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        secfs_dir_exists: bool,
        policy_is_writable: bool,
        custom_policy_exists: bool,
        reference_result: Option<Result<bool>>,
        read_result: Option<Result<Vec<String>>>,
        written_lines: Vec<String>,
        opened: usize,
        reopened: usize,
    }

    impl ImaPolicyBackend for FakeBackend {
        fn secfs_dir_exists(&self) -> bool {
            self.secfs_dir_exists
        }

        fn policy_is_writable(&self) -> bool {
            self.policy_is_writable
        }

        fn custom_policy_exists(&self) -> bool {
            self.custom_policy_exists
        }

        fn open_policy_for_write(&mut self) -> Result<()> {
            self.opened += 1;
            Ok(())
        }

        fn write_policy_reference(&mut self, _path: &str) -> Result<bool> {
            self.reference_result.take().unwrap_or(Ok(true))
        }

        fn read_policy_lines(&self) -> Result<Vec<String>> {
            self.read_result.clone().unwrap_or_else(|| Ok(Vec::new()))
        }

        fn reopen_policy_for_write(&mut self) -> Result<()> {
            self.reopened += 1;
            Ok(())
        }

        fn write_policy_line(&mut self, line: &str) -> Result<()> {
            self.written_lines.push(line.to_string());
            Ok(())
        }
    }

    #[test]
    fn direct_policy_reference_short_circuits_copy() {
        let mut backend = FakeBackend {
            secfs_dir_exists: true,
            policy_is_writable: true,
            custom_policy_exists: true,
            reference_result: Some(Ok(true)),
            ..FakeBackend::default()
        };

        let state = ima_setup(true, &mut backend).unwrap();
        assert_eq!(state, ImaSetupState::LoadedByReference);
        assert_eq!(backend.opened, 1);
        assert_eq!(backend.reopened, 0);
    }

    #[test]
    fn falls_back_to_line_by_line_copy() {
        let mut backend = FakeBackend {
            secfs_dir_exists: true,
            policy_is_writable: true,
            custom_policy_exists: true,
            reference_result: Some(Ok(false)),
            read_result: Some(Ok(vec!["measure func=BPRM_CHECK".into(), "".into()])),
            ..FakeBackend::default()
        };

        let state = ima_setup(true, &mut backend).unwrap();
        assert_eq!(state, ImaSetupState::LoadedByCopy { written_lines: 2 });
        assert_eq!(backend.reopened, 1);
        assert_eq!(backend.written_lines, vec!["measure func=BPRM_CHECK"]);
    }
}
