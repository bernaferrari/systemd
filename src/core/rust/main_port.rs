// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/main.c
//
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const SOURCE_PATH: &str = "src/core/main.c";
pub const MANAGER_OK: i32 = 0;
pub const MANAGER_EXIT: i32 = 1;
pub const MANAGER_RELOAD: i32 = 2;
pub const MANAGER_REEXECUTE: i32 = 3;
pub const MANAGER_REBOOT: i32 = 4;
pub const MANAGER_SOFT_REBOOT: i32 = 5;
pub const MANAGER_POWEROFF: i32 = 6;
pub const MANAGER_HALT: i32 = 7;
pub const MANAGER_KEXEC: i32 = 8;
pub const MANAGER_SWITCH_ROOT: i32 = 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainError {
    InvalidArgument(&'static str),
    ParseError(String),
    MissingData(&'static str),
}

impl fmt::Display for MainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
            Self::MissingData(msg) => write!(f, "missing data: {msg}"),
        }
    }
}

impl std::error::Error for MainError {}

pub type Result<T> = std::result::Result<T, MainError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RlimitSnapshot {
    pub soft: u64,
    pub hard: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPaths {
    pub files: Vec<String>,
    pub dirs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReexecutePlan {
    pub fds: Vec<i32>,
    pub switch_root_init: bool,
    pub switch_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalBroadcast {
    pub signal: i32,
    pub wait_for_exit: bool,
    pub send_sighup: bool,
    pub timeout_usec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainPort {
    pub default_unit: Option<String>,
    pub environment: BTreeMap<String, String>,
    pub manager_environment: BTreeMap<String, String>,
    pub argv: Vec<String>,
    pub saved_env: BTreeMap<String, String>,
    pub timeout_abort_usec: u64,
    pub oom_score_adjust: i32,
    pub crash_reboot: bool,
    pub rlimit_nofile: Option<RlimitSnapshot>,
    pub rlimit_memlock: Option<RlimitSnapshot>,
    pub unix_max_dgram_qlen_bumped: bool,
    pub security_initialized: bool,
    pub runtime_initialized: bool,
    pub random_seed_taken: bool,
    pub first_boot: bool,
    pub objective: i32,
    pub queued_jobs: Vec<String>,
    pub stopped_units: Vec<String>,
    pub wait_timeout_usec: Option<u64>,
    pub signal_broadcasts: Vec<SignalBroadcast>,
    pub sync_performed: usize,
    pub reboot_operations: Vec<String>,
    pub soft_reboot_plan: Option<ReexecutePlan>,
    pub vt_reduced: bool,
    pub action_log: Vec<String>,
}

impl Default for MainPort {
    fn default() -> Self {
        Self {
            default_unit: Some("default.target".into()),
            environment: BTreeMap::new(),
            manager_environment: BTreeMap::new(),
            argv: Vec::new(),
            saved_env: BTreeMap::new(),
            timeout_abort_usec: 0,
            oom_score_adjust: 0,
            crash_reboot: false,
            rlimit_nofile: None,
            rlimit_memlock: None,
            unix_max_dgram_qlen_bumped: false,
            security_initialized: false,
            runtime_initialized: false,
            random_seed_taken: false,
            first_boot: false,
            objective: MANAGER_OK,
            queued_jobs: Vec::new(),
            stopped_units: Vec::new(),
            wait_timeout_usec: None,
            signal_broadcasts: Vec::new(),
            sync_performed: 0,
            reboot_operations: Vec::new(),
            soft_reboot_plan: None,
            vt_reduced: false,
            action_log: Vec::new(),
        }
    }
}

impl MainPort {
    fn record(&mut self, op: &str) {
        self.action_log.push(op.to_string());
    }
}

pub fn parse_timeout(value: &str) -> Result<u64> {
    let value = value.trim();
    if value.is_empty() {
        return Err(MainError::ParseError("empty timeout".into()));
    }

    let (number, factor) = if let Some(raw) = value.strip_suffix("ms") {
        (raw, 1_000)
    } else if let Some(raw) = value.strip_suffix('s') {
        (raw, 1_000_000)
    } else if let Some(raw) = value.strip_suffix("min") {
        (raw, 60 * 1_000_000)
    } else {
        (value, 1)
    };

    let parsed = number
        .trim()
        .parse::<u64>()
        .map_err(|_| MainError::ParseError(format!("invalid timeout '{value}'")))?;
    Ok(parsed.saturating_mul(factor))
}

pub fn manager_find_user_config_paths(
    config_home: &str,
    conf_paths: &[&str],
) -> Result<ConfigPaths> {
    if config_home.is_empty() {
        return Err(MainError::MissingData("config_home"));
    }

    let mut dirs = vec![format!("{config_home}/systemd")];
    dirs.extend(conf_paths.iter().map(|p| (*p).to_string()));

    Ok(ConfigPaths {
        files: vec![
            format!("{}/user.conf", dirs[0]),
            "PKGSYSCONFDIR/user.conf".into(),
        ],
        dirs,
    })
}

pub fn save_console_winsize_in_environment(
    port: &mut MainPort,
    tty_fd: i32,
    cols: u16,
    rows: u16,
) -> Result<bool> {
    if tty_fd < 0 {
        return Err(MainError::InvalidArgument("tty_fd must be non-negative"));
    }

    if cols == 0 && rows == 0 {
        port.environment.remove("COLUMNS");
        port.environment.remove("LINES");
        port.record("save_console_winsize_in_environment:unset");
        return Ok(false);
    }

    port.environment.insert("COLUMNS".into(), cols.to_string());
    port.environment.insert("LINES".into(), rows.to_string());
    port.record("save_console_winsize_in_environment:set");
    Ok(true)
}

pub fn console_setup(port: &mut MainPort, is_pid1: bool, console_path: &str) -> Result<()> {
    if !is_pid1 {
        port.record("console_setup:skip");
        return Ok(());
    }
    if console_path.is_empty() {
        return Err(MainError::MissingData("console_path"));
    }
    port.environment
        .insert("SYSTEMD_CONSOLE".into(), console_path.into());
    port.record("console_setup");
    Ok(())
}

pub fn parse_configuration(
    port: &mut MainPort,
    saved_rlimit_nofile: Option<RlimitSnapshot>,
    saved_rlimit_memlock: Option<RlimitSnapshot>,
) -> Result<()> {
    port.rlimit_nofile = saved_rlimit_nofile;
    port.rlimit_memlock = saved_rlimit_memlock;
    port.record("parse_configuration");
    Ok(())
}

pub fn parse_proc_cmdline_item(port: &mut MainPort, key: &str, value: Option<&str>) -> Result<()> {
    match key {
        "systemd.unit" => port.default_unit = value.map(ToOwned::to_owned),
        "systemd.crash_reboot" => port.crash_reboot = matches!(value, Some("1" | "yes" | "true")),
        "systemd.default_timeout_abort" => {
            port.timeout_abort_usec = parse_timeout(value.unwrap_or_default())?;
        }
        _ => {}
    }
    port.record("parse_proc_cmdline_item");
    Ok(())
}

pub fn config_parse_default_timeout_abort(port: &mut MainPort, value: &str) -> Result<()> {
    port.timeout_abort_usec = parse_timeout(value)?;
    port.record("config_parse_default_timeout_abort");
    Ok(())
}

pub fn config_parse_oom_score_adjust(port: &mut MainPort, value: &str) -> Result<()> {
    port.oom_score_adjust = value
        .trim()
        .parse()
        .map_err(|_| MainError::ParseError(format!("invalid oom score '{value}'")))?;
    port.record("config_parse_oom_score_adjust");
    Ok(())
}

pub fn config_parse_crash_reboot(port: &mut MainPort, value: &str) -> Result<()> {
    let lowered = value.trim().to_ascii_lowercase();
    port.crash_reboot = matches!(lowered.as_str(), "1" | "yes" | "true" | "reboot");
    port.record("config_parse_crash_reboot");
    Ok(())
}

pub fn parse_config_file(port: &mut MainPort) -> Result<()> {
    port.record("parse_config_file");
    Ok(())
}

pub fn set_manager_defaults(port: &mut MainPort) {
    port.default_unit
        .get_or_insert_with(|| "default.target".into());
    port.record("set_manager_defaults");
}

pub fn set_manager_settings(port: &mut MainPort) {
    port.record("set_manager_settings");
}

pub fn parse_argv(port: &mut MainPort, argv: &[String]) -> Result<()> {
    if argv.is_empty() {
        return Err(MainError::MissingData("argv"));
    }
    port.argv = argv.to_vec();
    port.record("parse_argv");
    Ok(())
}

pub fn help() -> Result<String> {
    Ok("systemd [OPTIONS...]".into())
}

pub fn prepare_reexecute(port: &mut MainPort, fd_array: &[i32]) -> Result<ReexecutePlan> {
    if fd_array.iter().any(|fd| *fd < 0) {
        return Err(MainError::InvalidArgument(
            "fd_array must not contain negative fds",
        ));
    }
    port.record("prepare_reexecute");
    Ok(ReexecutePlan {
        fds: fd_array.to_vec(),
        switch_root_init: false,
        switch_root: None,
    })
}

pub fn bump_file_max_and_nr_open(port: &mut MainPort) {
    port.record("bump_file_max_and_nr_open");
}

pub fn bump_rlimit_nofile(port: &mut MainPort, saved_rlimit: Option<RlimitSnapshot>) -> Result<()> {
    port.rlimit_nofile = saved_rlimit;
    port.record("bump_rlimit_nofile");
    Ok(())
}

pub fn bump_rlimit_memlock(
    port: &mut MainPort,
    saved_rlimit: Option<RlimitSnapshot>,
) -> Result<()> {
    port.rlimit_memlock = saved_rlimit;
    port.record("bump_rlimit_memlock");
    Ok(())
}

pub fn enforce_syscall_archs(port: &mut MainPort, archs: &[&str]) -> Result<BTreeSet<String>> {
    if archs.is_empty() {
        return Err(MainError::MissingData("archs"));
    }
    port.record("enforce_syscall_archs");
    Ok(archs.iter().map(|s| (*s).to_string()).collect())
}

pub fn os_release_status(port: &mut MainPort) -> Result<String> {
    port.record("os_release_status");
    Ok("ok".into())
}

pub fn setup_os_release(port: &mut MainPort, scope: i32) -> Result<()> {
    if scope < 0 {
        return Err(MainError::InvalidArgument("scope must be non-negative"));
    }
    port.record("setup_os_release");
    Ok(())
}

pub fn write_container_id(port: &mut MainPort) -> Result<()> {
    port.record("write_container_id");
    Ok(())
}

pub fn write_boot_or_shutdown_osc(port: &mut MainPort, type_: &str) -> Result<()> {
    if type_.is_empty() {
        return Err(MainError::MissingData("type_"));
    }
    port.record(&format!("write_boot_or_shutdown_osc:{type_}"));
    Ok(())
}

pub fn bump_unix_max_dgram_qlen(port: &mut MainPort) -> Result<()> {
    port.unix_max_dgram_qlen_bumped = true;
    port.record("bump_unix_max_dgram_qlen");
    Ok(())
}

pub fn fixup_environment(port: &mut MainPort) -> Result<()> {
    port.environment.retain(|k, _| !k.is_empty());
    port.record("fixup_environment");
    Ok(())
}

fn objective_to_shutdown_verb(objective: i32) -> Option<&'static str> {
    match objective {
        MANAGER_EXIT => Some("exit"),
        MANAGER_REBOOT => Some("reboot"),
        MANAGER_POWEROFF => Some("poweroff"),
        MANAGER_HALT => Some("halt"),
        MANAGER_KEXEC => Some("kexec"),
        _ => None,
    }
}

fn objective_to_reboot_op(objective: i32, reboot_arg: Option<&str>) -> Option<String> {
    match objective {
        MANAGER_REBOOT => Some(match reboot_arg.filter(|arg| !arg.is_empty()) {
            Some(arg) => format!("reboot:auto:{arg}"),
            None => "reboot:auto".to_string(),
        }),
        MANAGER_POWEROFF => Some("reboot:poweroff".to_string()),
        MANAGER_HALT => Some("reboot:halt".to_string()),
        MANAGER_KEXEC => Some("reboot:kexec".to_string()),
        _ => None,
    }
}

fn queue_shutdown_target(port: &mut MainPort) {
    if !port.queued_jobs.iter().any(|u| u == "shutdown.target") {
        port.queued_jobs.push("shutdown.target".to_string());
    }
}

fn plan_stop_order(active_units_in_start_order: &[String]) -> Vec<String> {
    let mut stop_order = active_units_in_start_order.to_vec();
    stop_order.reverse();
    stop_order
}

pub fn execute_clean_shutdown(
    port: &mut MainPort,
    objective: i32,
    active_units_in_start_order: &[String],
    timeout_usec: u64,
    switch_root: Option<&str>,
    switch_root_init: Option<&str>,
    reboot_arg: Option<&str>,
) -> Result<()> {
    if !matches!(
        objective,
        MANAGER_REBOOT | MANAGER_POWEROFF | MANAGER_HALT | MANAGER_SOFT_REBOOT
    ) {
        return Err(MainError::InvalidArgument(
            "objective is not a shutdown mode",
        ));
    }

    port.objective = objective;
    queue_shutdown_target(port);
    port.stopped_units = plan_stop_order(active_units_in_start_order);
    port.wait_timeout_usec = Some(timeout_usec);
    port.sync_performed = port.sync_performed.saturating_add(1);

    if objective == MANAGER_SOFT_REBOOT {
        let plan = ReexecutePlan {
            fds: Vec::new(),
            switch_root_init: true,
            switch_root: Some(switch_root.unwrap_or("/run/nextroot").to_string()),
        };
        let init = switch_root_init.unwrap_or("/usr/lib/systemd/systemd");
        port.soft_reboot_plan = Some(plan);
        port.reboot_operations
            .push(format!("soft-reboot:exec:{init}"));
    } else if let Some(op) = objective_to_reboot_op(objective, reboot_arg) {
        port.reboot_operations.push(op);
    }

    port.record(&format!("execute_clean_shutdown:{objective}"));
    Ok(())
}

pub fn execute_emergency_stop(port: &mut MainPort, objective: i32) -> Result<()> {
    if !matches!(objective, MANAGER_REBOOT | MANAGER_POWEROFF | MANAGER_HALT) {
        return Err(MainError::InvalidArgument(
            "emergency stop objective must be reboot/poweroff/halt",
        ));
    }

    port.objective = objective;
    port.signal_broadcasts.push(SignalBroadcast {
        signal: libc::SIGTERM,
        wait_for_exit: true,
        send_sighup: true,
        timeout_usec: 30_000_000,
    });
    port.signal_broadcasts.push(SignalBroadcast {
        signal: libc::SIGKILL,
        wait_for_exit: false,
        send_sighup: false,
        timeout_usec: 0,
    });
    port.sync_performed = port.sync_performed.saturating_add(1);

    if let Some(op) = objective_to_reboot_op(objective, None) {
        port.reboot_operations.push(op);
    }

    port.record(&format!("execute_emergency_stop:{objective}"));
    Ok(())
}

pub fn become_shutdown(port: &mut MainPort, objective: i32, retval: i32) -> Result<i32> {
    let Some(verb) = objective_to_shutdown_verb(objective) else {
        return Err(MainError::InvalidArgument("invalid shutdown objective"));
    };

    port.objective = objective;
    let _ = write_boot_or_shutdown_osc(port, "shutdown");
    port.record(&format!("shutdown-binary:{verb}:exit={retval}"));
    port.record(&format!("become_shutdown:{objective}:{retval}"));
    Ok(retval)
}

pub fn initialize_clock_timewarp(port: &mut MainPort) {
    port.record("initialize_clock_timewarp");
}

pub fn apply_clock_update(port: &mut MainPort) {
    port.record("apply_clock_update");
}

pub fn cmdline_take_random_seed(port: &mut MainPort) {
    port.random_seed_taken = true;
    port.record("cmdline_take_random_seed");
}

pub fn initialize_coredump(port: &mut MainPort, skip_setup: bool) {
    port.record(if skip_setup {
        "initialize_coredump:skip"
    } else {
        "initialize_coredump"
    });
}

pub fn initialize_core_pattern(port: &mut MainPort, skip_setup: bool) {
    port.record(if skip_setup {
        "initialize_core_pattern:skip"
    } else {
        "initialize_core_pattern"
    });
}

pub fn apply_protect_system(port: &mut MainPort, skip_setup: bool) {
    port.record(if skip_setup {
        "apply_protect_system:skip"
    } else {
        "apply_protect_system"
    });
}

pub fn update_cpu_affinity(port: &mut MainPort, skip_setup: bool) {
    port.record(if skip_setup {
        "update_cpu_affinity:skip"
    } else {
        "update_cpu_affinity"
    });
}

pub fn update_numa_policy(port: &mut MainPort, skip_setup: bool) {
    port.record(if skip_setup {
        "update_numa_policy:skip"
    } else {
        "update_numa_policy"
    });
}

pub fn filter_args(port: &mut MainPort, argv: &[String], mask: u32) -> Vec<String> {
    port.record(&format!("filter_args:{mask}"));
    argv.iter()
        .filter(|arg| match mask & 1 {
            0 => true,
            _ => !arg.starts_with("--deserialize"),
        })
        .cloned()
        .collect()
}

pub fn finish_remaining_processes(port: &mut MainPort, objective: i32) {
    let timeout = if port.timeout_abort_usec > 0 {
        port.timeout_abort_usec
    } else {
        90_000_000
    };

    if matches!(objective, MANAGER_SWITCH_ROOT | MANAGER_SOFT_REBOOT) {
        port.signal_broadcasts.push(SignalBroadcast {
            signal: libc::SIGTERM,
            wait_for_exit: false,
            send_sighup: true,
            timeout_usec: timeout,
        });
    }

    if objective == MANAGER_SOFT_REBOOT {
        port.signal_broadcasts.push(SignalBroadcast {
            signal: libc::SIGKILL,
            wait_for_exit: false,
            send_sighup: false,
            timeout_usec: timeout,
        });
    }

    port.record(&format!("finish_remaining_processes:{objective}"));
}

pub fn reduce_vt(port: &mut MainPort, objective: i32) {
    if objective == MANAGER_SOFT_REBOOT {
        port.vt_reduced = true;
    }
    port.record(&format!("reduce_vt:{objective}"));
}

pub fn do_reexecute(
    port: &mut MainPort,
    fd_array: &[i32],
    switch_root_init: bool,
    switch_root: Option<&str>,
) -> Result<ReexecutePlan> {
    port.record("do_reexecute");
    Ok(ReexecutePlan {
        fds: fd_array.to_vec(),
        switch_root_init,
        switch_root: switch_root.map(ToOwned::to_owned),
    })
}

pub fn invoke_main_loop(port: &mut MainPort) -> Result<()> {
    port.record("invoke_main_loop");
    Ok(())
}

pub fn log_execution_mode(port: &mut MainPort) -> Result<bool> {
    port.record("log_execution_mode");
    Ok(port.first_boot)
}

pub fn initialize_runtime(port: &mut MainPort) -> Result<()> {
    port.runtime_initialized = true;
    port.record("initialize_runtime");
    Ok(())
}

pub fn do_queue_default_job(port: &mut MainPort) -> Result<Option<String>> {
    port.record("do_queue_default_job");
    Ok(port.default_unit.clone())
}

pub fn save_rlimits(
    port: &mut MainPort,
    saved_rlimit_nofile: RlimitSnapshot,
    saved_rlimit_memlock: RlimitSnapshot,
) {
    port.rlimit_nofile = Some(saved_rlimit_nofile);
    port.rlimit_memlock = Some(saved_rlimit_memlock);
    port.record("save_rlimits");
}

pub fn fallback_rlimit_nofile(port: &mut MainPort, saved_rlimit_nofile: Option<RlimitSnapshot>) {
    if port.rlimit_nofile.is_none() {
        port.rlimit_nofile = saved_rlimit_nofile;
    }
    port.record("fallback_rlimit_nofile");
}

pub fn fallback_rlimit_memlock(port: &mut MainPort, saved_rlimit_memlock: Option<RlimitSnapshot>) {
    if port.rlimit_memlock.is_none() {
        port.rlimit_memlock = saved_rlimit_memlock;
    }
    port.record("fallback_rlimit_memlock");
}

pub fn setenv_manager_environment(port: &mut MainPort) {
    for (k, v) in port.manager_environment.clone() {
        port.environment.insert(k, v);
    }
    port.record("setenv_manager_environment");
}

pub fn reset_arguments(port: &mut MainPort) {
    *port = MainPort::default();
    port.record("reset_arguments");
}

pub fn determine_default_oom_score_adjust(port: &mut MainPort) {
    if port.oom_score_adjust == 0 {
        port.oom_score_adjust = -1000;
    }
    port.record("determine_default_oom_score_adjust");
}

pub fn safety_checks(port: &mut MainPort) -> Result<()> {
    if port.default_unit.as_deref() == Some("") {
        return Err(MainError::InvalidArgument("default unit must not be empty"));
    }
    port.record("safety_checks");
    Ok(())
}

pub fn initialize_security(port: &mut MainPort) -> Result<()> {
    port.security_initialized = true;
    port.record("initialize_security");
    Ok(())
}

pub fn collect_fds(port: &mut MainPort, candidates: &[i32]) -> Result<Vec<i32>> {
    if candidates.iter().any(|fd| *fd < 0) {
        return Err(MainError::InvalidArgument("negative fd in candidates"));
    }
    port.record("collect_fds");
    Ok(candidates.to_vec())
}

pub fn setup_console_terminal(port: &mut MainPort, skip_setup: bool) {
    port.record(if skip_setup {
        "setup_console_terminal:skip"
    } else {
        "setup_console_terminal"
    });
}

pub fn early_skip_setup_check(skip_setup: bool, in_initrd: bool, in_container: bool) -> bool {
    skip_setup || in_initrd || in_container
}

pub fn save_env(port: &mut MainPort, env: &BTreeMap<String, String>) -> Result<()> {
    if env.is_empty() {
        return Err(MainError::MissingData("env"));
    }
    port.saved_env = env.clone();
    port.record("save_env");
    Ok(())
}

pub fn main(port: &mut MainPort, argv: &[String]) -> Result<i32> {
    reset_arguments(port);
    parse_argv(port, argv)?;
    parse_config_file(port)?;
    safety_checks(port)?;
    initialize_runtime(port)?;
    invoke_main_loop(port)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_timeout_suffixes() {
        assert_eq!(parse_timeout("5").unwrap(), 5);
        assert_eq!(parse_timeout("5ms").unwrap(), 5_000);
        assert_eq!(parse_timeout("2s").unwrap(), 2_000_000);
        assert_eq!(parse_timeout("1min").unwrap(), 60_000_000);
    }

    #[test]
    fn test_manager_find_user_config_paths() {
        let paths = manager_find_user_config_paths("/tmp/home/.config", &["/etc/systemd"]).unwrap();
        assert_eq!(paths.files[0], "/tmp/home/.config/systemd/user.conf");
        assert!(paths.dirs.contains(&"/etc/systemd".to_string()));
    }

    #[test]
    fn test_save_console_winsize_roundtrip() {
        let mut port = MainPort::default();
        assert!(save_console_winsize_in_environment(&mut port, 0, 120, 40).unwrap());
        assert_eq!(port.environment.get("COLUMNS"), Some(&"120".to_string()));
        assert_eq!(port.environment.get("LINES"), Some(&"40".to_string()));
    }

    #[test]
    fn test_parse_proc_cmdline_item_updates_unit() {
        let mut port = MainPort::default();
        parse_proc_cmdline_item(&mut port, "systemd.unit", Some("rescue.target")).unwrap();
        assert_eq!(port.default_unit.as_deref(), Some("rescue.target"));
    }

    #[test]
    fn test_filter_args_masks_deserialize() {
        let mut port = MainPort::default();
        let args = vec!["systemd".into(), "--deserialize=8".into(), "--test".into()];
        let filtered = filter_args(&mut port, &args, 1);
        assert_eq!(filtered, vec!["systemd", "--test"]);
    }

    #[test]
    fn test_main_flow_initializes_runtime() {
        let mut port = MainPort::default();
        let argv = vec!["/usr/lib/systemd/systemd".into()];
        assert_eq!(main(&mut port, &argv).unwrap(), 0);
        assert!(port.runtime_initialized);
    }

    #[test]
    fn test_execute_clean_shutdown_reboot_stops_units_and_reboots() {
        let mut port = MainPort::default();
        let units = vec![
            "basic.target".to_string(),
            "multi-user.target".to_string(),
            "sshd.service".to_string(),
        ];

        execute_clean_shutdown(
            &mut port,
            MANAGER_REBOOT,
            &units,
            45_000_000,
            None,
            None,
            Some("firmware-setup"),
        )
        .unwrap();

        assert_eq!(port.queued_jobs, vec!["shutdown.target"]);
        assert_eq!(
            port.stopped_units,
            vec![
                "sshd.service".to_string(),
                "multi-user.target".to_string(),
                "basic.target".to_string()
            ]
        );
        assert_eq!(port.wait_timeout_usec, Some(45_000_000));
        assert_eq!(port.sync_performed, 1);
        assert_eq!(port.reboot_operations, vec!["reboot:auto:firmware-setup"]);
    }

    #[test]
    fn test_execute_clean_shutdown_soft_reboot_creates_exec_plan() {
        let mut port = MainPort::default();
        let units = vec!["default.target".to_string()];

        execute_clean_shutdown(
            &mut port,
            MANAGER_SOFT_REBOOT,
            &units,
            20_000_000,
            Some("/run/nextroot"),
            Some("/usr/lib/systemd/systemd"),
            None,
        )
        .unwrap();

        assert_eq!(port.queued_jobs, vec!["shutdown.target"]);
        assert_eq!(port.stopped_units, vec!["default.target".to_string()]);
        assert_eq!(
            port.soft_reboot_plan,
            Some(ReexecutePlan {
                fds: vec![],
                switch_root_init: true,
                switch_root: Some("/run/nextroot".to_string()),
            })
        );
        assert_eq!(
            port.reboot_operations,
            vec!["soft-reboot:exec:/usr/lib/systemd/systemd"]
        );
    }

    #[test]
    fn test_emergency_stop_sends_sigterm_then_sigkill_and_syncs() {
        let mut port = MainPort::default();
        execute_emergency_stop(&mut port, MANAGER_POWEROFF).unwrap();

        assert_eq!(port.signal_broadcasts.len(), 2);
        assert_eq!(port.signal_broadcasts[0].signal, libc::SIGTERM);
        assert_eq!(port.signal_broadcasts[0].timeout_usec, 30_000_000);
        assert_eq!(port.signal_broadcasts[1].signal, libc::SIGKILL);
        assert_eq!(port.sync_performed, 1);
        assert_eq!(port.reboot_operations, vec!["reboot:poweroff"]);
    }

    #[test]
    fn test_finish_remaining_processes_matches_soft_reboot_rules() {
        let mut port = MainPort::default();
        finish_remaining_processes(&mut port, MANAGER_SOFT_REBOOT);
        assert_eq!(port.signal_broadcasts.len(), 2);
        assert_eq!(port.signal_broadcasts[0].signal, libc::SIGTERM);
        assert_eq!(port.signal_broadcasts[1].signal, libc::SIGKILL);

        reduce_vt(&mut port, MANAGER_SOFT_REBOOT);
        assert!(port.vt_reduced);
    }

    #[test]
    fn test_become_shutdown_rejects_unknown_objective() {
        let mut port = MainPort::default();
        assert!(become_shutdown(&mut port, 99, 0).is_err());
    }
}
