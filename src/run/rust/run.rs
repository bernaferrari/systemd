// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/run/run.c
//
// Runs the specified command in a transient scope or service.
//
// Provides configuration types, job mode parsing, stdio mode handling, and
// shell mode logic faithfully mirroring the C implementation's data types
// and command-line argument processing.

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Enums ─────────────────────────────────────────────────────────────────

/// How stdio should be connected for the transient unit.
/// Corresponds to the `arg_stdio` bitfield in run.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    /// Default: stdin → /dev/null, stdout+stderr → journal.
    None,
    /// Interactive: allocate a pty.
    Pty,
    /// Direct: pass stdin/stdout/stderr directly.
    Direct,
    /// Auto: choose pty on TTY, direct otherwise.
    Auto,
}

/// D-Bus transport mode.
/// Corresponds to `BusTransport` in run.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusTransport {
    Local,
    Remote,
    Machine,
    Capsule,
}

/// Runtime scope for the unit.
/// Corresponds to `RuntimeScope` in run.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

/// Job scheduling mode.
/// Corresponds to `JobMode` / `arg_job_mode` in run.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobMode {
    Fail,
    Replace,
    Irreversibly,
    Isolate,
    IgnoreDependencies,
    IgnoreRequirements,
    Flush,
    Triggering,
    RestartDependencies,
}

impl JobMode {
    /// Parse from the string representation.
    pub fn from_string(s: &str) -> Result<Self> {
        match s {
            "fail" => Ok(JobMode::Fail),
            "replace" => Ok(JobMode::Replace),
            "irreversibly" => Ok(JobMode::Irreversibly),
            "isolate" => Ok(JobMode::Isolate),
            "ignore-dependencies" => Ok(JobMode::IgnoreDependencies),
            "ignore-requirements" => Ok(JobMode::IgnoreRequirements),
            "flush" => Ok(JobMode::Flush),
            "triggering" => Ok(JobMode::Triggering),
            "restart-dependencies" => Ok(JobMode::RestartDependencies),
            _ => Err(Errno(-22)), // -EINVAL
        }
    }

    /// Convert to string.
    pub fn to_string_name(self) -> &'static str {
        match self {
            JobMode::Fail => "fail",
            JobMode::Replace => "replace",
            JobMode::Irreversibly => "irreversibly",
            JobMode::Isolate => "isolate",
            JobMode::IgnoreDependencies => "ignore-dependencies",
            JobMode::IgnoreRequirements => "ignore-requirements",
            JobMode::Flush => "flush",
            JobMode::Triggering => "triggering",
            JobMode::RestartDependencies => "restart-dependencies",
        }
    }
}

// ── Run configuration ─────────────────────────────────────────────────────

/// Configuration for the systemd-run / run0 tool, mirroring the static args.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub scope: bool,
    pub remain_after_exit: bool,
    pub no_block: bool,
    pub wait: bool,
    pub send_sighup: bool,
    pub stdio: StdioMode,
    pub pty_late: bool,
    pub shell: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub aggressive_gc: bool,
    pub ask_password: bool,
    pub expand_environment: bool,
    pub job_mode: JobMode,
    pub runtime_scope: RuntimeScope,
    pub transport: BusTransport,
    pub service_type: Option<String>,
    pub exec_user: Option<String>,
    pub exec_group: Option<String>,
    pub nice: i32,
    pub nice_set: bool,
    pub description: Option<String>,
    pub slice: Option<String>,
    pub slice_inherit: bool,
    pub unit: Option<String>,
    pub working_directory: Option<String>,
    pub root_directory: Option<String>,
    pub environment: Vec<String>,
    pub property: Vec<String>,
    pub timer_property: Vec<String>,
    pub path_property: Vec<String>,
    pub socket_property: Vec<String>,
    pub cmdline: Vec<String>,
    pub background: Option<String>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            scope: false,
            remain_after_exit: false,
            no_block: false,
            wait: false,
            send_sighup: false,
            stdio: StdioMode::None,
            pty_late: false,
            shell: false,
            quiet: false,
            verbose: false,
            aggressive_gc: false,
            ask_password: true,
            expand_environment: true,
            job_mode: JobMode::Fail,
            runtime_scope: RuntimeScope::System,
            transport: BusTransport::Local,
            service_type: None,
            exec_user: None,
            exec_group: None,
            nice: 0,
            nice_set: false,
            description: None,
            slice: None,
            slice_inherit: false,
            unit: None,
            working_directory: None,
            root_directory: None,
            environment: Vec::new(),
            property: Vec::new(),
            timer_property: Vec::new(),
            path_property: Vec::new(),
            socket_property: Vec::new(),
            cmdline: Vec::new(),
            background: None,
        }
    }
}

impl RunConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether any trigger unit type is active (path, socket, or timer).
    /// Corresponds to `with_trigger = !!arg_path_property || !!arg_socket_property || arg_with_timer`.
    pub fn has_trigger(&self) -> bool {
        !self.path_property.is_empty()
            || !self.socket_property.is_empty()
            || !self.timer_property.is_empty()
    }

    /// Whether we are becoming root. Corresponds to `become_root()`.
    pub fn is_become_root(&self) -> bool {
        if self.runtime_scope != RuntimeScope::System {
            return false;
        }
        match &self.exec_user {
            None => true,
            Some(u) => u == "root" || u == "0",
        }
    }

    /// Apply shell mode defaults, mirroring the logic in `parse_argv()`.
    pub fn apply_shell_defaults(&mut self) {
        if self.stdio == StdioMode::None {
            self.stdio = StdioMode::Auto;
        }
        if self.service_type.is_none() {
            self.service_type = Some("exec".to_string());
        }
        if !self.scope {
            self.wait = true;
        }
        self.aggressive_gc = true;
    }

    /// Resolve auto stdio mode based on TTY availability.
    /// Corresponds to `if (arg_stdio == ARG_STDIO_AUTO)` logic.
    pub fn resolve_auto_stdio(&mut self, is_tty: bool) {
        if self.stdio == StdioMode::Auto {
            self.stdio = if is_tty {
                StdioMode::Pty
            } else {
                StdioMode::Direct
            };
        }
    }

    /// Validate the configuration consistency.
    /// Returns the first validation error encountered.
    pub fn validate(&self) -> Result<()> {
        // Only single trigger type allowed
        let trigger_count = (!self.path_property.is_empty()) as usize
            + (!self.socket_property.is_empty()) as usize
            + (!self.timer_property.is_empty()) as usize;
        if trigger_count > 1 {
            return Err(Errno(-22));
        }

        // --wait incompatible with --no-block
        if self.wait && self.no_block {
            return Err(Errno(-22));
        }

        // --wait incompatible with --scope
        if self.wait && self.scope {
            return Err(Errno(-22));
        }

        // --scope incompatible with --remain-after-exit or --service-type
        if self.scope && self.remain_after_exit {
            return Err(Errno(-22));
        }

        // --pty/--pipe not compatible with trigger or scope mode
        if self.stdio != StdioMode::None && (self.has_trigger() || self.scope) {
            return Err(Errno(-22));
        }

        Ok(())
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Make a login shell argv0 from a shell path.
/// Corresponds to `make_login_shell_cmdline()` in run.c.
pub fn make_login_shell_argv0(shell: &str) -> String {
    format!("-{}", shell)
}

/// Parse a nice value from string, clamped to [-20, 19].
/// Corresponds to `parse_nice()` logic.
pub fn parse_nice(s: &str) -> Result<i32> {
    let val: i32 = s.parse().map_err(|_| Errno(-22))?;
    if val < -20 || val > 19 {
        return Err(Errno(-22));
    }
    Ok(val)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_mode_roundtrip() {
        for mode in [
            JobMode::Fail,
            JobMode::Replace,
            JobMode::Irreversibly,
            JobMode::Isolate,
            JobMode::IgnoreDependencies,
            JobMode::IgnoreRequirements,
            JobMode::Flush,
            JobMode::Triggering,
            JobMode::RestartDependencies,
        ] {
            assert_eq!(JobMode::from_string(mode.to_string_name()).unwrap(), mode);
        }
    }

    #[test]
    fn job_mode_unknown() {
        assert!(JobMode::from_string("unknown").is_err());
    }

    #[test]
    fn default_config() {
        let cfg = RunConfig::new();
        assert!(!cfg.scope);
        assert!(!cfg.remain_after_exit);
        assert!(cfg.ask_password);
        assert!(cfg.expand_environment);
        assert_eq!(cfg.job_mode, JobMode::Fail);
        assert_eq!(cfg.runtime_scope, RuntimeScope::System);
        assert_eq!(cfg.transport, BusTransport::Local);
        assert!(!cfg.has_trigger());
    }

    #[test]
    fn has_trigger_with_timer() {
        let mut cfg = RunConfig::new();
        cfg.timer_property.push("OnActiveSec=5".into());
        assert!(cfg.has_trigger());
    }

    #[test]
    fn has_trigger_with_socket() {
        let mut cfg = RunConfig::new();
        cfg.socket_property.push("ListenStream=8080".into());
        assert!(cfg.has_trigger());
    }

    #[test]
    fn has_trigger_with_path() {
        let mut cfg = RunConfig::new();
        cfg.path_property.push("PathModified=/tmp/x".into());
        assert!(cfg.has_trigger());
    }

    #[test]
    fn is_become_root_system_no_user() {
        let cfg = RunConfig::new();
        assert!(cfg.is_become_root());
    }

    #[test]
    fn is_become_root_explicit_root() {
        let cfg = RunConfig {
            exec_user: Some("root".into()),
            ..Default::default()
        };
        assert!(cfg.is_become_root());
    }

    #[test]
    fn is_not_become_root_other_user() {
        let cfg = RunConfig {
            exec_user: Some("nobody".into()),
            ..Default::default()
        };
        assert!(!cfg.is_become_root());
    }

    #[test]
    fn is_not_become_root_user_scope() {
        let cfg = RunConfig {
            runtime_scope: RuntimeScope::User,
            ..Default::default()
        };
        assert!(!cfg.is_become_root());
    }

    #[test]
    fn apply_shell_defaults() {
        let mut cfg = RunConfig::new();
        cfg.shell = true;
        cfg.apply_shell_defaults();
        assert_eq!(cfg.stdio, StdioMode::Auto);
        assert_eq!(cfg.service_type.as_deref(), Some("exec"));
        assert!(cfg.wait);
        assert!(cfg.aggressive_gc);
    }

    #[test]
    fn resolve_auto_stdio_tty() {
        let mut cfg = RunConfig {
            stdio: StdioMode::Auto,
            ..Default::default()
        };
        cfg.resolve_auto_stdio(true);
        assert_eq!(cfg.stdio, StdioMode::Pty);
    }

    #[test]
    fn resolve_auto_stdio_not_tty() {
        let mut cfg = RunConfig {
            stdio: StdioMode::Auto,
            ..Default::default()
        };
        cfg.resolve_auto_stdio(false);
        assert_eq!(cfg.stdio, StdioMode::Direct);
    }

    #[test]
    fn validate_ok() {
        let cfg = RunConfig::new();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_wait_with_no_block() {
        let cfg = RunConfig {
            wait: true,
            no_block: true,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_scope_with_remain() {
        let cfg = RunConfig {
            scope: true,
            remain_after_exit: true,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn make_login_shell_argv0_format() {
        assert_eq!(make_login_shell_argv0("/bin/bash"), "-/bin/bash");
        assert_eq!(make_login_shell_argv0("/bin/zsh"), "-/bin/zsh");
    }

    #[test]
    fn parse_nice_valid() {
        assert_eq!(parse_nice("0").unwrap(), 0);
        assert_eq!(parse_nice("-5").unwrap(), -5);
        assert_eq!(parse_nice("19").unwrap(), 19);
        assert_eq!(parse_nice("-20").unwrap(), -20);
    }

    #[test]
    fn parse_nice_out_of_range() {
        assert!(parse_nice("-21").is_err());
        assert!(parse_nice("20").is_err());
    }

    #[test]
    fn parse_nice_invalid() {
        assert!(parse_nice("abc").is_err());
    }
}
