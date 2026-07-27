// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homed.c
//
// Minimal safe model of the systemd-homed daemon entrypoint.

use crate::homed_conf::ManagerConfig;

pub const SERVICE_NAME: &str = "systemd-homed.service";
pub const SERVICE_DESCRIPTION: &str = "A service to create, remove, change or inspect home areas.";
pub const DEFAULT_UMASK: u32 = 0o022;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomedServiceSpec {
    pub service_name: &'static str,
    pub description: &'static str,
    pub umask: u32,
}

impl Default for HomedServiceSpec {
    fn default() -> Self {
        Self {
            service_name: SERVICE_NAME,
            description: SERVICE_DESCRIPTION,
            umask: DEFAULT_UMASK,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomedManager {
    pub startup_calls: usize,
    pub loop_calls: usize,
    pub started: bool,
    pub fail_startup: Option<i32>,
    pub fail_loop: Option<i32>,
}

impl HomedManager {
    pub fn new() -> Self {
        Self {
            startup_calls: 0,
            loop_calls: 0,
            started: false,
            fail_startup: None,
            fail_loop: None,
        }
    }

    pub fn startup(&mut self) -> Result<(), HomedError> {
        self.startup_calls += 1;
        if let Some(code) = self.fail_startup {
            return Err(HomedError::Startup(code));
        }

        self.started = true;
        Ok(())
    }

    pub fn event_loop(&mut self) -> Result<(), HomedError> {
        self.loop_calls += 1;
        if let Some(code) = self.fail_loop {
            return Err(HomedError::EventLoop(code));
        }

        Ok(())
    }
}

impl Default for HomedManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomedError {
    ArgumentParsing(i32),
    ManagerCreate(i32),
    Startup(i32),
    EventLoop(i32),
}

impl std::fmt::Display for HomedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArgumentParsing(code) => write!(f, "argument parsing failed: {code}"),
            Self::ManagerCreate(code) => write!(f, "could not create manager: {code}"),
            Self::Startup(code) => write!(f, "failed to start up daemon: {code}"),
            Self::EventLoop(code) => write!(f, "event loop failed: {code}"),
        }
    }
}

impl std::error::Error for HomedError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub config: ManagerConfig,
    pub spec: HomedServiceSpec,
    pub notified_ready: bool,
    pub notified_stopping: bool,
}

pub fn parse_service_arguments(parse_result: i32) -> Result<(), HomedError> {
    if parse_result > 0 {
        Ok(())
    } else {
        Err(HomedError::ArgumentParsing(parse_result))
    }
}

pub fn run_with_manager(
    config: ManagerConfig,
    parse_result: i32,
    manager: &mut HomedManager,
) -> Result<RunOutcome, HomedError> {
    parse_service_arguments(parse_result)?;
    manager.startup()?;
    manager.event_loop()?;

    Ok(RunOutcome {
        config,
        spec: HomedServiceSpec::default(),
        notified_ready: true,
        notified_stopping: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_spec_matches_c_constants() {
        let spec = HomedServiceSpec::default();
        assert_eq!(spec.service_name, SERVICE_NAME);
        assert_eq!(spec.description, SERVICE_DESCRIPTION);
        assert_eq!(spec.umask, 0o022);
    }

    #[test]
    fn parse_accepts_positive_result() {
        assert!(parse_service_arguments(1).is_ok());
    }

    #[test]
    fn parse_rejects_zero_result() {
        assert_eq!(
            parse_service_arguments(0),
            Err(HomedError::ArgumentParsing(0))
        );
    }

    #[test]
    fn parse_rejects_negative_result() {
        assert_eq!(
            parse_service_arguments(-22),
            Err(HomedError::ArgumentParsing(-22))
        );
    }

    #[test]
    fn manager_startup_sets_started_flag() {
        let mut manager = HomedManager::new();
        manager.startup().unwrap();
        assert!(manager.started);
        assert_eq!(manager.startup_calls, 1);
    }

    #[test]
    fn manager_startup_propagates_error() {
        let mut manager = HomedManager::new();
        manager.fail_startup = Some(-5);
        assert_eq!(manager.startup(), Err(HomedError::Startup(-5)));
    }

    #[test]
    fn manager_event_loop_tracks_calls() {
        let mut manager = HomedManager::new();
        manager.event_loop().unwrap();
        assert_eq!(manager.loop_calls, 1);
    }

    #[test]
    fn run_with_manager_returns_notifications() {
        let mut manager = HomedManager::new();
        let outcome = run_with_manager(ManagerConfig::default(), 1, &mut manager).unwrap();
        assert!(outcome.notified_ready);
        assert!(outcome.notified_stopping);
        assert!(manager.started);
    }

    #[test]
    fn run_with_manager_stops_on_startup_failure() {
        let mut manager = HomedManager::new();
        manager.fail_startup = Some(-12);
        assert_eq!(
            run_with_manager(ManagerConfig::default(), 1, &mut manager),
            Err(HomedError::Startup(-12))
        );
        assert_eq!(manager.loop_calls, 0);
    }

    #[test]
    fn run_with_manager_propagates_event_loop_failure() {
        let mut manager = HomedManager::new();
        manager.fail_loop = Some(-32);
        assert_eq!(
            run_with_manager(ManagerConfig::default(), 1, &mut manager),
            Err(HomedError::EventLoop(-32))
        );
    }
}
