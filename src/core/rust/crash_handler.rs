// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/crash-handler.c, src/core/crash-handler.h

use crate::crash_action::CrashAction;
use crate::ffi::Errno;

pub const EXIT_EXCEPTION: i32 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashDisposition {
    Exit { status: i32 },
    Reboot { delay_seconds: u64 },
    Poweroff,
    Freeze,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashHandlerInstall {
    pub installed_signals: Vec<i32>,
    pub ignored_error: Option<Errno>,
}

pub type Result<T> = std::result::Result<T, Errno>;

pub fn freeze_or_exit_or_reboot(
    in_container: bool,
    action: CrashAction,
) -> Result<CrashDisposition> {
    let disposition = if in_container {
        CrashDisposition::Exit {
            status: EXIT_EXCEPTION,
        }
    } else {
        match action {
            CrashAction::Poweroff => CrashDisposition::Poweroff,
            CrashAction::Reboot => CrashDisposition::Reboot { delay_seconds: 10 },
            CrashAction::Freeze => CrashDisposition::Freeze,
        }
    };

    Ok(disposition)
}

pub fn install_crash_handler<F>(signals: &[i32], installer: F) -> Result<CrashHandlerInstall>
where
    F: FnOnce(&[i32]) -> Result<()>,
{
    if signals.is_empty() {
        return Err(Errno::EINVAL);
    }

    let ignored_error = installer(signals).err();
    Ok(CrashHandlerInstall {
        installed_signals: signals.to_vec(),
        ignored_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_crash_prefers_exit() {
        let action = freeze_or_exit_or_reboot(true, CrashAction::Reboot).unwrap();
        assert_eq!(
            action,
            CrashDisposition::Exit {
                status: EXIT_EXCEPTION
            }
        );
    }

    #[test]
    fn reboot_action_keeps_delay() {
        let action = freeze_or_exit_or_reboot(false, CrashAction::Reboot).unwrap();
        assert_eq!(action, CrashDisposition::Reboot { delay_seconds: 10 });
    }

    #[test]
    fn crash_handler_install_records_ignored_error() {
        let install = install_crash_handler(&[6, 11], |_| Err(Errno::ENOMEM)).unwrap();
        assert_eq!(install.installed_signals, vec![6, 11]);
        assert_eq!(install.ignored_error, Some(Errno::ENOMEM));
    }

    #[test]
    fn empty_signal_set_is_rejected() {
        let error = install_crash_handler::<_>(&[], |_| Ok(())).unwrap_err();
        assert_eq!(error, Errno::EINVAL);
    }
}
