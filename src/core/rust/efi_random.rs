// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/efi-random.c, src/core/efi-random.h

use crate::ffi::Errno;

pub const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub const LOADER_SYSTEM_TOKEN_MODE: u32 = 0o600;

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockDownWarning {
    Open(Errno),
    ClearImmutable(Errno),
    SetMode(Errno),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockDownReport {
    pub opened: bool,
    pub warnings: Vec<LockDownWarning>,
}

pub trait EfiVariableStore {
    fn open_loader_system_token(&mut self) -> Result<i32>;
    fn clear_immutable(&mut self, fd: i32, mask: u32) -> Result<()>;
    fn set_mode(&mut self, fd: i32, mode: u32) -> Result<()>;
    fn close(&mut self, fd: i32);
}

pub fn lock_down_efi_variables(store: &mut impl EfiVariableStore) -> Result<LockDownReport> {
    let fd = match store.open_loader_system_token() {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => {
            return Ok(LockDownReport {
                opened: false,
                warnings: Vec::new(),
            });
        }
        Err(error) => {
            return Ok(LockDownReport {
                opened: false,
                warnings: vec![LockDownWarning::Open(error)],
            });
        }
    };

    let mut warnings = Vec::new();

    if let Err(error) = store.clear_immutable(fd, FS_IMMUTABLE_FL) {
        warnings.push(LockDownWarning::ClearImmutable(error));
    }

    if let Err(error) = store.set_mode(fd, LOADER_SYSTEM_TOKEN_MODE) {
        warnings.push(LockDownWarning::SetMode(error));
    }

    store.close(fd);

    Ok(LockDownReport {
        opened: true,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeStore {
        open_result: Option<Result<i32>>,
        clear_result: Option<Result<()>>,
        mode_result: Option<Result<()>>,
        closed: Vec<i32>,
    }

    impl EfiVariableStore for FakeStore {
        fn open_loader_system_token(&mut self) -> Result<i32> {
            self.open_result.take().unwrap_or(Ok(7))
        }

        fn clear_immutable(&mut self, _fd: i32, _mask: u32) -> Result<()> {
            self.clear_result.take().unwrap_or(Ok(()))
        }

        fn set_mode(&mut self, _fd: i32, _mode: u32) -> Result<()> {
            self.mode_result.take().unwrap_or(Ok(()))
        }

        fn close(&mut self, fd: i32) {
            self.closed.push(fd);
        }
    }

    #[test]
    fn missing_variable_is_silently_ignored() {
        let mut store = FakeStore {
            open_result: Some(Err(Errno::ENOENT)),
            ..FakeStore::default()
        };

        let report = lock_down_efi_variables(&mut store).unwrap();
        assert!(!report.opened);
        assert!(report.warnings.is_empty());
        assert!(store.closed.is_empty());
    }

    #[test]
    fn other_open_failures_are_warning_only() {
        let mut store = FakeStore {
            open_result: Some(Err(Errno::EACCES)),
            ..FakeStore::default()
        };

        let report = lock_down_efi_variables(&mut store).unwrap();
        assert!(!report.opened);
        assert_eq!(report.warnings, vec![LockDownWarning::Open(Errno::EACCES)]);
        assert!(store.closed.is_empty());
    }

    #[test]
    fn chmod_and_chattr_failures_are_recorded() {
        let mut store = FakeStore {
            clear_result: Some(Err(Errno::EPERM)),
            mode_result: Some(Err(Errno::EACCES)),
            ..FakeStore::default()
        };

        let report = lock_down_efi_variables(&mut store).unwrap();
        assert!(report.opened);
        assert_eq!(store.closed, vec![7]);
        assert_eq!(
            report.warnings,
            vec![
                LockDownWarning::ClearImmutable(Errno::EPERM),
                LockDownWarning::SetMode(Errno::EACCES),
            ]
        );
    }
}
