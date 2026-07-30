// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevd.c
//
// systemd-udevd — device event manager daemon.
//
// Defines daemon configuration, startup sequence modelling, and
// library-preload tracking for the udevd daemon.

// ── Constants ─────────────────────────────────────────────────────────────

pub const UDEV_RUN_DIR: &str = "/run/udev";
pub const UDEV_RUN_DIR_MODE: u32 = 0o755;
pub const DEFAULT_UMASK: u32 = 0o022;

// ── Shared libraries ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedLib {
    Libacl,
    Libblkid,
    Libkmod,
    Libmount,
    LibTpm2,
}

impl SharedLib {
    pub fn all() -> &'static [SharedLib] {
        &[
            SharedLib::Libacl,
            SharedLib::Libblkid,
            SharedLib::Libkmod,
            SharedLib::Libmount,
            SharedLib::LibTpm2,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            SharedLib::Libacl => "libacl",
            SharedLib::Libblkid => "libblkid",
            SharedLib::Libkmod => "libkmod",
            SharedLib::Libmount => "libmount",
            SharedLib::LibTpm2 => "libtpm2",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LibLoadResults {
    pub loaded: Vec<SharedLib>,
    pub failed: Vec<SharedLib>,
}

impl LibLoadResults {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, lib: SharedLib, success: bool) {
        if success {
            self.loaded.push(lib);
        } else {
            self.failed.push(lib);
        }
    }

    pub fn all_succeeded(&self) -> bool {
        self.failed.is_empty()
    }
}

// ── Daemon configuration ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DaemonConfig {
    pub daemonize: bool,
}

// ── Startup sequence ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupPhase {
    InitLogging,
    CreateManager,
    LoadConfig,
    CheckRoot,
    SetUmask,
    MacInit,
    BumpRlimit,
    CreateRunDir,
    PreloadLibs,
    Daemonize,
    RunMain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupStatus {
    Ok,
    Err(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupStep {
    pub phase: StartupPhase,
    pub status: StartupStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StartupSequence {
    pub steps: Vec<StartupStep>,
}

impl StartupSequence {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_ok(&mut self, phase: StartupPhase) {
        self.steps.push(StartupStep {
            phase,
            status: StartupStatus::Ok,
        });
    }

    pub fn push_err(&mut self, phase: StartupPhase, code: i32) {
        self.steps.push(StartupStep {
            phase,
            status: StartupStatus::Err(code),
        });
    }

    pub fn is_complete(&self) -> bool {
        self.steps.last().is_some_and(|s| {
            matches!(s.phase, StartupPhase::RunMain) || matches!(s.status, StartupStatus::Err(_))
        })
    }

    pub fn has_error(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s.status, StartupStatus::Err(_)))
    }

    pub fn first_error(&self) -> Option<&StartupStep> {
        self.steps
            .iter()
            .find(|s| matches!(s.status, StartupStatus::Err(_)))
    }
}

// ── Daemonize logic ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioRedirect {
    /// Max log level is debug, keep normal stdio.
    KeepNormal,
    /// Redirect stdin/stdout/stderr to /dev/null.
    RedirectToNull,
}

/// Determine stdio handling based on log level.
/// Mirrors the check in C `run_udevd()`.
pub fn stdio_redirect_for_log_level(is_debug: bool) -> StdioRedirect {
    if is_debug {
        StdioRedirect::KeepNormal
    } else {
        StdioRedirect::RedirectToNull
    }
}

// ── Run directory creation ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDirResult {
    Created,
    AlreadyExists,
    Error(i32),
}

/// Classify the result of creating /run/udev.
pub fn classify_run_dir_create(result: i32) -> RunDirResult {
    if result >= 0 {
        RunDirResult::Created
    } else if result == -17 {
        RunDirResult::AlreadyExists
    } else {
        RunDirResult::Error(result)
    }
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdevdError {
    ManagerCreateFailed,
    ManagerLoadFailed(i32),
    NotRoot,
    MacInitFailed(i32),
    RunDirCreateFailed(i32),
    ForkFailed(i32),
    StdioRedirectFailed(i32),
}

impl std::fmt::Display for UdevdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdevdError::ManagerCreateFailed => write!(f, "Failed to create manager"),
            UdevdError::ManagerLoadFailed(code) => {
                write!(f, "Manager load failed with code {code}")
            }
            UdevdError::NotRoot => write!(f, "Must be run as root"),
            UdevdError::MacInitFailed(code) => {
                write!(f, "MAC initialization failed: {code}")
            }
            UdevdError::RunDirCreateFailed(code) => {
                write!(f, "Failed to create /run/udev: {code}")
            }
            UdevdError::ForkFailed(code) => {
                write!(f, "Failed to fork daemon: {code}")
            }
            UdevdError::StdioRedirectFailed(code) => {
                write!(f, "Failed to redirect stdio: {code}")
            }
        }
    }
}

impl std::error::Error for UdevdError {}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_lib_names() {
        assert_eq!(SharedLib::Libacl.name(), "libacl");
        assert_eq!(SharedLib::Libblkid.name(), "libblkid");
        assert_eq!(SharedLib::Libkmod.name(), "libkmod");
        assert_eq!(SharedLib::Libmount.name(), "libmount");
        assert_eq!(SharedLib::LibTpm2.name(), "libtpm2");
    }

    #[test]
    fn test_lib_load_results() {
        let mut results = LibLoadResults::new();
        results.record(SharedLib::Libacl, true);
        results.record(SharedLib::Libblkid, true);
        results.record(SharedLib::LibTpm2, false);
        assert!(!results.all_succeeded());
        assert_eq!(results.loaded.len(), 2);
        assert_eq!(results.failed.len(), 1);
    }

    #[test]
    fn test_lib_load_results_all_ok() {
        let mut results = LibLoadResults::new();
        for lib in SharedLib::all() {
            results.record(*lib, true);
        }
        assert!(results.all_succeeded());
    }

    #[test]
    fn test_daemon_config_default() {
        let config = DaemonConfig::default();
        assert!(!config.daemonize);
    }

    #[test]
    fn test_startup_sequence_ok() {
        let mut seq = StartupSequence::new();
        seq.push_ok(StartupPhase::InitLogging);
        seq.push_ok(StartupPhase::CreateManager);
        seq.push_ok(StartupPhase::RunMain);
        assert!(!seq.has_error());
        assert!(seq.first_error().is_none());
    }

    #[test]
    fn test_startup_sequence_error() {
        let mut seq = StartupSequence::new();
        seq.push_ok(StartupPhase::InitLogging);
        seq.push_err(StartupPhase::CreateManager, -12);
        assert!(seq.has_error());
        let err = seq.first_error().unwrap();
        assert_eq!(err.phase, StartupPhase::CreateManager);
    }

    #[test]
    fn test_stdio_redirect_debug() {
        assert_eq!(
            stdio_redirect_for_log_level(true),
            StdioRedirect::KeepNormal
        );
        assert_eq!(
            stdio_redirect_for_log_level(false),
            StdioRedirect::RedirectToNull
        );
    }

    #[test]
    fn test_classify_run_dir() {
        assert_eq!(classify_run_dir_create(0), RunDirResult::Created);
        assert_eq!(classify_run_dir_create(-17), RunDirResult::AlreadyExists);
        assert_eq!(classify_run_dir_create(-13), RunDirResult::Error(-13));
    }

    #[test]
    fn test_error_display() {
        let err = UdevdError::NotRoot;
        assert!(err.to_string().contains("root"));
        let err = UdevdError::ForkFailed(11);
        assert!(err.to_string().contains("11"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(UDEV_RUN_DIR, "/run/udev");
        assert_eq!(UDEV_RUN_DIR_MODE, 0o755);
        assert_eq!(DEFAULT_UMASK, 0o022);
    }
}
