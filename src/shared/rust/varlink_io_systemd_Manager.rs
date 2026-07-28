// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Manager.c
//
// Varlink interface definition for io.systemd.Manager.
//
// Manager control APIs for describing, reloading, and managing
// the system manager (PID 1), including power operations and
// runtime configuration introspection.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Manager";

pub const METHOD_DESCRIBE: &str = "Describe";
pub const METHOD_REEXECUTE: &str = "Reexecute";
pub const METHOD_RELOAD: &str = "Reload";
pub const METHOD_ENQUEUE_MARKED_JOBS: &str = "EnqueueMarkedJobs";
pub const METHOD_POWER_OFF: &str = "PowerOff";
pub const METHOD_REBOOT: &str = "Reboot";
pub const METHOD_HALT: &str = "Halt";
pub const METHOD_KEXEC: &str = "KExec";
pub const METHOD_SOFT_REBOOT: &str = "SoftReboot";

pub const METHODS: &[&str] = &[
    METHOD_DESCRIBE,
    METHOD_REEXECUTE,
    METHOD_RELOAD,
    METHOD_ENQUEUE_MARKED_JOBS,
    METHOD_POWER_OFF,
    METHOD_REBOOT,
    METHOD_HALT,
    METHOD_KEXEC,
    METHOD_SOFT_REBOOT,
];

// ── Enums ──────────────────────────────────────────────────────────────────

/// System state as reported by the manager
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemState {
    Initializing,
    Starting,
    Running,
    Degraded,
    Maintenance,
    Stopping,
    Offline,
}

impl SystemState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SystemState::Initializing => "initializing",
            SystemState::Starting => "starting",
            SystemState::Running => "running",
            SystemState::Degraded => "degraded",
            SystemState::Maintenance => "maintenance",
            SystemState::Stopping => "stopping",
            SystemState::Offline => "offline",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "initializing" => Some(SystemState::Initializing),
            "starting" => Some(SystemState::Starting),
            "running" => Some(SystemState::Running),
            "degraded" => Some(SystemState::Degraded),
            "maintenance" => Some(SystemState::Maintenance),
            "stopping" => Some(SystemState::Stopping),
            "offline" => Some(SystemState::Offline),
            _ => None,
        }
    }

    /// Returns true if the system is in an operational state
    pub fn is_operational(&self) -> bool {
        matches!(self, SystemState::Running | SystemState::Degraded)
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// Log level configuration for a specific target
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLevelStruct {
    /// Console target log level
    pub console: String,
    /// Kernel message buffer log level
    pub kmsg: String,
    /// Syslog target log level
    pub syslog: String,
    /// Journal target log level
    pub journal: String,
}

impl LogLevelStruct {
    /// Create a new log level configuration with all targets set to the same level
    pub fn uniform(level: &str) -> Self {
        Self {
            console: level.into(),
            kmsg: level.into(),
            syslog: level.into(),
            journal: level.into(),
        }
    }

    /// Check if all targets use the same log level
    pub fn is_uniform(&self) -> bool {
        self.console == self.kmsg && self.kmsg == self.syslog && self.syslog == self.journal
    }
}

/// Static manager context (configuration constants)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerContext {
    pub show_status: bool,
    pub log_level: LogLevelStruct,
    pub log_target: String,
    pub environment: Vec<String>,
    pub default_standard_output: String,
    pub default_standard_error: String,
    pub service_watchdogs: bool,
    pub default_timer_accuracy_usec: i64,
    pub default_timeout_start_usec: i64,
    pub default_timeout_stop_usec: i64,
    pub default_timeout_abort_usec: i64,
    pub default_device_timeout_usec: i64,
    pub default_restart_usec: i64,
    pub default_io_accounting: bool,
    pub default_ip_accounting: bool,
    pub default_memory_accounting: bool,
    pub default_tasks_accounting: bool,
    pub default_tasks_max: i64,
    pub default_memory_pressure_threshold_usec: i64,
    pub default_memory_pressure_watch: String,
    pub timer_slack_nsec: i64,
    pub default_oom_policy: String,
    pub default_oom_score_adjust: i64,
    pub default_restrict_suid_sgid: bool,
    pub ctrl_alt_del_burst_action: String,
}

/// Runtime manager information (changeable)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerRuntime {
    /// Version string of running systemd instance
    pub version: String,
    /// Architecture string
    pub architecture: String,
    /// Build features string
    pub features: String,
    /// Taint strings
    pub taints: Vec<String>,
    /// Unit search paths
    pub unit_path: Vec<String>,
    /// Virtualization technology
    pub virtualization: String,
    /// Confidential virtualization technology
    pub confidential_virtualization: String,
    /// Number of loaded unit names
    pub n_names: i64,
    /// Number of failed units
    pub n_failed_units: i64,
    /// Number of currently queued jobs
    pub n_jobs: i64,
    /// Total installed jobs
    pub n_installed_jobs: i64,
    /// Total failed jobs
    pub n_failed_jobs: i64,
    /// Boot progress (0.0 to 1.0) - stored as fixed-point
    pub progress_permille: i64,
    /// Current system state
    pub system_state: String,
    /// Manager exit code
    pub exit_code: i64,
    /// Soft-reboot count
    pub soft_reboots_count: i64,
}

impl ManagerRuntime {
    /// Parse the system state string
    pub fn parse_system_state(&self) -> Option<SystemState> {
        SystemState::from_str(&self.system_state)
    }

    /// Get boot progress as a float (0.0 to 1.0)
    pub fn progress_float(&self) -> f64 {
        self.progress_permille as f64 / 1000.0
    }
}

/// Output from the Describe method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribeOutput {
    pub context: ManagerContext,
    pub runtime: ManagerRuntime,
}

/// Output from the EnqueueMarkedJobs method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueMarkedJobsOutput {
    pub unit_id: Option<String>,
    pub job_id: Option<i64>,
    pub error: Option<String>,
    pub error_message: Option<String>,
}

impl EnqueueMarkedJobsOutput {
    /// Whether the job was enqueued successfully
    pub fn is_success(&self) -> bool {
        self.error.is_none()
    }
}

/// Input for the SoftReboot method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftRebootInput {
    /// New root directory for the soft reboot
    pub root: Option<String>,
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerError {
    /// Rate limit reached for method calls
    RateLimitReached,
}

impl ManagerError {
    pub fn error_id(&self) -> &'static str {
        match self {
            ManagerError::RateLimitReached => "io.systemd.Manager.RateLimitReached",
        }
    }
}

pub const ERROR_IDS: &[&str] = &["io.systemd.Manager.RateLimitReached"];

// ── Helper functions ───────────────────────────────────────────────────────

/// Check if a method is a power/shutdown operation
pub fn is_power_method(method: &str) -> bool {
    matches!(
        method,
        METHOD_POWER_OFF | METHOD_REBOOT | METHOD_HALT | METHOD_KEXEC | METHOD_SOFT_REBOOT
    )
}

/// Check if a method is a read-only operation
pub fn is_read_only_method(method: &str) -> bool {
    method == METHOD_DESCRIBE
}

/// Validate a log level string
pub fn is_valid_log_level(level: &str) -> bool {
    matches!(
        level,
        "emerg" | "alert" | "crit" | "err" | "warning" | "notice" | "info" | "debug"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Manager");
        assert_eq!(METHODS.len(), 9);
    }

    #[test]
    fn test_system_state_roundtrip() {
        for s in &[
            "initializing",
            "starting",
            "running",
            "degraded",
            "maintenance",
            "stopping",
            "offline",
        ] {
            assert_eq!(SystemState::from_str(s).unwrap().as_str(), *s);
        }
        assert_eq!(SystemState::from_str("unknown"), None);
    }

    #[test]
    fn test_system_state_is_operational() {
        assert!(SystemState::Running.is_operational());
        assert!(SystemState::Degraded.is_operational());
        assert!(!SystemState::Maintenance.is_operational());
        assert!(!SystemState::Offline.is_operational());
    }

    #[test]
    fn test_log_level_uniform() {
        let ll = LogLevelStruct::uniform("info");
        assert!(ll.is_uniform());
        assert_eq!(ll.console, "info");
    }

    #[test]
    fn test_log_level_not_uniform() {
        let ll = LogLevelStruct {
            console: "info".into(),
            kmsg: "err".into(),
            syslog: "info".into(),
            journal: "info".into(),
        };
        assert!(!ll.is_uniform());
    }

    #[test]
    fn test_manager_runtime_system_state() {
        let rt = ManagerRuntime {
            version: "256".into(),
            architecture: "x86_64".into(),
            features: "feat".into(),
            taints: vec![],
            unit_path: vec![],
            virtualization: "none".into(),
            confidential_virtualization: "none".into(),
            n_names: 100,
            n_failed_units: 0,
            n_jobs: 0,
            n_installed_jobs: 50,
            n_failed_jobs: 0,
            progress_permille: 1000,
            system_state: "running".into(),
            exit_code: 0,
            soft_reboots_count: 0,
        };
        assert_eq!(rt.parse_system_state(), Some(SystemState::Running));
        assert_eq!(rt.progress_float(), 1.0);
    }

    #[test]
    fn test_enqueue_marked_jobs_output() {
        let success = EnqueueMarkedJobsOutput {
            unit_id: Some("test.service".into()),
            job_id: Some(42),
            error: None,
            error_message: None,
        };
        assert!(success.is_success());

        let failure = EnqueueMarkedJobsOutput {
            unit_id: None,
            job_id: None,
            error: Some("failed".into()),
            error_message: Some("reason".into()),
        };
        assert!(!failure.is_success());
    }

    #[test]
    fn test_is_power_method() {
        assert!(is_power_method(METHOD_POWER_OFF));
        assert!(is_power_method(METHOD_REBOOT));
        assert!(is_power_method(METHOD_HALT));
        assert!(is_power_method(METHOD_KEXEC));
        assert!(is_power_method(METHOD_SOFT_REBOOT));
        assert!(!is_power_method(METHOD_DESCRIBE));
        assert!(!is_power_method(METHOD_RELOAD));
    }

    #[test]
    fn test_is_read_only_method() {
        assert!(is_read_only_method(METHOD_DESCRIBE));
        assert!(!is_read_only_method(METHOD_REEXECUTE));
    }

    #[test]
    fn test_is_valid_log_level() {
        assert!(is_valid_log_level("emerg"));
        assert!(is_valid_log_level("debug"));
        assert!(is_valid_log_level("info"));
        assert!(!is_valid_log_level("trace"));
        assert!(!is_valid_log_level(""));
    }

    #[test]
    fn test_error_ids() {
        assert_eq!(ERROR_IDS.len(), 1);
        assert!(
            ManagerError::RateLimitReached
                .error_id()
                .contains("RateLimitReached")
        );
    }

    #[test]
    fn test_soft_reboot_input() {
        let input = SoftRebootInput {
            root: Some("/newroot".into()),
        };
        assert_eq!(input.root.as_deref(), Some("/newroot"));

        let default = SoftRebootInput { root: None };
        assert!(default.root.is_none());
    }
}
