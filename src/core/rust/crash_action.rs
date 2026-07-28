// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/crash-handler.c, src/core/crash-handler.h
//
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashAction {
    Freeze,
    Reboot,
    Poweroff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseCrashActionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Notice,
    Emerg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalCrashBehavior {
    ExitException,
    Frozen,
}

pub trait CrashActionEnvironment {
    fn detect_container(&self) -> Result<bool, i32>;
    fn poweroff(&mut self) -> Result<(), i32>;
    fn reboot(&mut self) -> Result<(), i32>;
    fn sleep(&mut self, seconds: u64);
    fn sync(&mut self);
    fn freeze(&mut self);
    fn log(&mut self, level: LogLevel, message: String);
}

impl CrashAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Freeze => "freeze",
            Self::Reboot => "reboot",
            Self::Poweroff => "poweroff",
        }
    }

    pub fn from_str(value: &str) -> Result<Self, ParseCrashActionError> {
        match value {
            "freeze" => Ok(Self::Freeze),
            "reboot" => Ok(Self::Reboot),
            "poweroff" => Ok(Self::Poweroff),
            _ => Err(ParseCrashActionError),
        }
    }
}

pub fn crash_action_to_string(action: CrashAction) -> &'static str {
    action.as_str()
}

pub fn crash_action_from_string(value: &str) -> Result<CrashAction, ParseCrashActionError> {
    CrashAction::from_str(value)
}

pub fn freeze_or_exit_or_reboot(
    env: &mut impl CrashActionEnvironment,
    action: CrashAction,
) -> FinalCrashBehavior {
    if env.detect_container().unwrap_or(false) {
        env.log(LogLevel::Emerg, "Exiting PID 1...".into());
        return FinalCrashBehavior::ExitException;
    }

    match action {
        CrashAction::Poweroff => {
            env.log(LogLevel::Notice, "Shutting down...".into());
            if let Err(errno) = env.poweroff() {
                env.log(
                    LogLevel::Emerg,
                    format!("Failed to power off: errno {}", -errno),
                );
            }
        }
        CrashAction::Reboot => {
            env.log(LogLevel::Notice, "Rebooting in 10s...".into());
            env.sleep(10);
            env.log(LogLevel::Notice, "Rebooting now...".into());
            if let Err(errno) = env.reboot() {
                env.log(
                    LogLevel::Emerg,
                    format!("Failed to reboot: errno {}", -errno),
                );
            }
        }
        CrashAction::Freeze => {}
    }

    env.log(LogLevel::Emerg, "Freezing execution.".into());
    env.sync();
    env.freeze();
    FinalCrashBehavior::Frozen
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEnv {
        container: bool,
        poweroff_result: Result<(), i32>,
        reboot_result: Result<(), i32>,
        slept: Vec<u64>,
        synced: usize,
        froze: usize,
        logs: Vec<(LogLevel, String)>,
    }

    impl Default for MockEnv {
        fn default() -> Self {
            Self {
                container: false,
                poweroff_result: Ok(()),
                reboot_result: Ok(()),
                slept: Vec::new(),
                synced: 0,
                froze: 0,
                logs: Vec::new(),
            }
        }
    }

    impl CrashActionEnvironment for MockEnv {
        fn detect_container(&self) -> Result<bool, i32> {
            Ok(self.container)
        }

        fn poweroff(&mut self) -> Result<(), i32> {
            self.poweroff_result
        }

        fn reboot(&mut self) -> Result<(), i32> {
            self.reboot_result
        }

        fn sleep(&mut self, seconds: u64) {
            self.slept.push(seconds);
        }

        fn sync(&mut self) {
            self.synced += 1;
        }

        fn freeze(&mut self) {
            self.froze += 1;
        }

        fn log(&mut self, level: LogLevel, message: String) {
            self.logs.push((level, message));
        }
    }

    #[test]
    fn freeze_round_trips() {
        assert_eq!(CrashAction::from_str("freeze"), Ok(CrashAction::Freeze));
    }

    #[test]
    fn reboot_round_trips() {
        assert_eq!(CrashAction::from_str("reboot"), Ok(CrashAction::Reboot));
    }

    #[test]
    fn poweroff_round_trips() {
        assert_eq!(CrashAction::from_str("poweroff"), Ok(CrashAction::Poweroff));
    }

    #[test]
    fn invalid_action_is_rejected() {
        assert_eq!(CrashAction::from_str("halt"), Err(ParseCrashActionError));
    }

    #[test]
    fn container_prefers_exit() {
        let mut env = MockEnv {
            container: true,
            ..MockEnv::default()
        };
        assert_eq!(
            freeze_or_exit_or_reboot(&mut env, CrashAction::Freeze),
            FinalCrashBehavior::ExitException
        );
        assert_eq!(env.froze, 0);
    }

    #[test]
    fn freeze_action_syncs_and_freezes() {
        let mut env = MockEnv::default();
        assert_eq!(
            freeze_or_exit_or_reboot(&mut env, CrashAction::Freeze),
            FinalCrashBehavior::Frozen
        );
        assert_eq!(env.synced, 1);
        assert_eq!(env.froze, 1);
    }

    #[test]
    fn reboot_action_waits_before_rebooting() {
        let mut env = MockEnv::default();
        assert_eq!(
            freeze_or_exit_or_reboot(&mut env, CrashAction::Reboot),
            FinalCrashBehavior::Frozen
        );
        assert_eq!(env.slept, vec![10]);
        assert_eq!(env.froze, 1);
    }

    #[test]
    fn reboot_failures_are_logged_before_freezing() {
        let mut env = MockEnv {
            reboot_result: Err(-libc::EIO),
            ..MockEnv::default()
        };
        let _ = freeze_or_exit_or_reboot(&mut env, CrashAction::Reboot);
        assert!(
            env.logs
                .iter()
                .any(|(_, msg)| msg.contains("Failed to reboot"))
        );
    }

    #[test]
    fn poweroff_failures_are_logged_before_freezing() {
        let mut env = MockEnv {
            poweroff_result: Err(-libc::EIO),
            ..MockEnv::default()
        };
        let _ = freeze_or_exit_or_reboot(&mut env, CrashAction::Poweroff);
        assert!(
            env.logs
                .iter()
                .any(|(_, msg)| msg.contains("Failed to power off"))
        );
    }
}
