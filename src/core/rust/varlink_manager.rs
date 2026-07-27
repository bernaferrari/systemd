// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/varlink-manager.c

//! Compiled-but-disconnected varlink manager model.
//!
//! The live PID 1 transport must enqueue work for
//! [`crate::runtime_manager::RuntimeManager`]. This model remains isolated
//! until that adapter exists, while using the same manager objectives.

use std::collections::{BTreeMap, BTreeSet};

use crate::ffi::Errno;
pub use crate::manager_tables::ManagerObjective;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    Real(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarlinkManagerError {
    InvalidParameter,
    PermissionDenied,
    RateLimitReached,
    MethodNotImplemented,
}

impl VarlinkManagerError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::InvalidParameter => Errno::EINVAL.to_neg_errno(),
            Self::PermissionDenied => Errno::EACCES.to_neg_errno(),
            Self::RateLimitReached => Errno::EAGAIN.to_neg_errno(),
            Self::MethodNotImplemented => Errno::ENOSYS.to_neg_errno(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    pub interval_usec: u64,
    pub burst: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualTimestamp {
    pub realtime: u64,
    pub monotonic: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerDefaults {
    pub std_output: String,
    pub std_error: String,
    pub service_watchdogs: bool,
    pub timer_accuracy_usec: Option<u64>,
    pub timeout_start_usec: Option<u64>,
    pub timeout_stop_usec: Option<u64>,
    pub timeout_abort_usec: Option<u64>,
    pub device_timeout_usec: Option<u64>,
    pub restart_usec: Option<u64>,
    pub start_limit: RateLimit,
    pub io_accounting: bool,
    pub ip_accounting: bool,
    pub memory_accounting: bool,
    pub tasks_accounting: bool,
    pub tasks_max: u64,
    pub memory_pressure_threshold_usec: Option<u64>,
    pub memory_pressure_watch: String,
    pub oom_policy: String,
    pub oom_score_adjust: i64,
    pub restrict_suid_sgid: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManagerSnapshot {
    pub show_status: bool,
    pub log_target: String,
    pub log_levels: BTreeMap<String, String>,
    pub environment: Vec<String>,
    pub defaults: ManagerDefaults,
    pub reboot_watchdog_usec: Option<u64>,
    pub runtime_watchdog_usec: Option<u64>,
    pub kexec_watchdog_usec: Option<u64>,
    pub runtime_watchdog_pre_usec: Option<u64>,
    pub watchdog_pretimeout_governor: Option<String>,
    pub watchdog_device: Option<String>,
    pub cad_burst_action: String,
    pub confirm_spawn: Option<String>,
    pub cgroup_root: Option<String>,
    pub version: String,
    pub architecture: String,
    pub features: String,
    pub taints: Vec<String>,
    pub unit_path: Vec<String>,
    pub virtualization: String,
    pub confidential_virtualization: String,
    pub timestamps: BTreeMap<String, DualTimestamp>,
    pub n_names: u64,
    pub n_failed_units: u64,
    pub n_jobs: u64,
    pub n_installed_jobs: u64,
    pub n_failed_jobs: u64,
    pub transactions_with_cycle: BTreeSet<u64>,
    pub progress: f64,
    pub watchdog_last_ping: Option<DualTimestamp>,
    pub system_state: String,
    pub exit_code: u64,
    pub soft_reboots_count: u64,
    pub system_mode: bool,
    pub objective: Option<ManagerObjective>,
    pub switch_root: Option<String>,
    pub pending_reload_message: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedJobResult {
    pub unit_id: String,
    pub job_id: Option<u32>,
    pub error: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarlinkAction {
    Reply,
    ReplyLater,
    Disconnect,
}

pub fn manager_environment_build_json(
    manager: &ManagerSnapshot,
) -> Result<Option<JsonValue>, VarlinkManagerError> {
    if manager.environment.is_empty() {
        return Ok(None);
    }

    Ok(Some(JsonValue::Array(
        manager
            .environment
            .iter()
            .cloned()
            .map(JsonValue::String)
            .collect(),
    )))
}

pub fn log_level_build_json(manager: &ManagerSnapshot) -> Result<JsonValue, VarlinkManagerError> {
    Ok(JsonValue::Object(
        manager
            .log_levels
            .iter()
            .map(|(target, level)| (target.clone(), JsonValue::String(level.clone())))
            .collect(),
    ))
}

pub fn transactions_with_cycle_build_json(
    transactions: &BTreeSet<u64>,
) -> Result<JsonValue, VarlinkManagerError> {
    Ok(JsonValue::Array(
        transactions
            .iter()
            .copied()
            .map(JsonValue::Unsigned)
            .collect(),
    ))
}

pub fn manager_context_build_json(
    manager: &ManagerSnapshot,
) -> Result<JsonValue, VarlinkManagerError> {
    let mut object = BTreeMap::new();
    object.insert("ShowStatus".into(), JsonValue::Bool(manager.show_status));
    object.insert("LogLevel".into(), log_level_build_json(manager)?);
    object.insert(
        "LogTarget".into(),
        JsonValue::String(manager.log_target.clone()),
    );
    insert_optional(
        &mut object,
        "Environment",
        manager_environment_build_json(manager)?,
    );
    object.insert(
        "DefaultStandardOutput".into(),
        JsonValue::String(manager.defaults.std_output.clone()),
    );
    object.insert(
        "DefaultStandardError".into(),
        JsonValue::String(manager.defaults.std_error.clone()),
    );
    object.insert(
        "ServiceWatchdogs".into(),
        JsonValue::Bool(manager.defaults.service_watchdogs),
    );
    insert_optional_u64(
        &mut object,
        "DefaultTimerAccuracyUSec",
        manager.defaults.timer_accuracy_usec,
    );
    insert_optional_u64(
        &mut object,
        "DefaultTimeoutStartUSec",
        manager.defaults.timeout_start_usec,
    );
    insert_optional_u64(
        &mut object,
        "DefaultTimeoutStopUSec",
        manager.defaults.timeout_stop_usec,
    );
    insert_optional_u64(
        &mut object,
        "DefaultTimeoutAbortUSec",
        manager.defaults.timeout_abort_usec,
    );
    insert_optional_u64(
        &mut object,
        "DefaultDeviceTimeoutUSec",
        manager.defaults.device_timeout_usec,
    );
    insert_optional_u64(
        &mut object,
        "DefaultRestartUSec",
        manager.defaults.restart_usec,
    );
    object.insert(
        "DefaultStartLimit".into(),
        JsonValue::Object(BTreeMap::from([
            (
                "intervalUSec".into(),
                JsonValue::Unsigned(manager.defaults.start_limit.interval_usec),
            ),
            (
                "burst".into(),
                JsonValue::Unsigned(manager.defaults.start_limit.burst.into()),
            ),
        ])),
    );
    object.insert(
        "DefaultIOAccounting".into(),
        JsonValue::Bool(manager.defaults.io_accounting),
    );
    object.insert(
        "DefaultIPAccounting".into(),
        JsonValue::Bool(manager.defaults.ip_accounting),
    );
    object.insert(
        "DefaultMemoryAccounting".into(),
        JsonValue::Bool(manager.defaults.memory_accounting),
    );
    object.insert(
        "DefaultTasksAccounting".into(),
        JsonValue::Bool(manager.defaults.tasks_accounting),
    );
    object.insert(
        "DefaultTasksMax".into(),
        JsonValue::Unsigned(manager.defaults.tasks_max),
    );
    insert_optional_u64(
        &mut object,
        "DefaultMemoryPressureThresholdUSec",
        manager.defaults.memory_pressure_threshold_usec,
    );
    object.insert(
        "DefaultMemoryPressureWatch".into(),
        JsonValue::String(manager.defaults.memory_pressure_watch.clone()),
    );
    insert_optional_u64(
        &mut object,
        "RuntimeWatchdogUSec",
        manager.runtime_watchdog_usec,
    );
    insert_optional_u64(
        &mut object,
        "RebootWatchdogUSec",
        manager.reboot_watchdog_usec,
    );
    insert_optional_u64(
        &mut object,
        "KExecWatchdogUSec",
        manager.kexec_watchdog_usec,
    );
    insert_optional_u64(
        &mut object,
        "RuntimeWatchdogPreUSec",
        manager.runtime_watchdog_pre_usec,
    );
    insert_optional_string(
        &mut object,
        "RuntimeWatchdogPreGovernor",
        manager.watchdog_pretimeout_governor.clone(),
    );
    insert_optional_string(
        &mut object,
        "WatchdogDevice",
        manager.watchdog_device.clone(),
    );
    object.insert(
        "DefaultOOMPolicy".into(),
        JsonValue::String(manager.defaults.oom_policy.clone()),
    );
    object.insert(
        "DefaultOOMScoreAdjust".into(),
        JsonValue::Integer(manager.defaults.oom_score_adjust),
    );
    object.insert(
        "DefaultRestrictSUIDSGID".into(),
        JsonValue::Bool(manager.defaults.restrict_suid_sgid),
    );
    object.insert(
        "CtrlAltDelBurstAction".into(),
        JsonValue::String(manager.cad_burst_action.clone()),
    );
    insert_optional_string(&mut object, "ConfirmSpawn", manager.confirm_spawn.clone());
    insert_optional_string(&mut object, "ControlGroup", manager.cgroup_root.clone());
    Ok(JsonValue::Object(object))
}

pub fn manager_runtime_build_json(
    manager: &ManagerSnapshot,
) -> Result<JsonValue, VarlinkManagerError> {
    let mut object = BTreeMap::new();
    object.insert("Version".into(), JsonValue::String(manager.version.clone()));
    object.insert(
        "Architecture".into(),
        JsonValue::String(manager.architecture.clone()),
    );
    object.insert(
        "Features".into(),
        JsonValue::String(manager.features.clone()),
    );
    if !manager.taints.is_empty() {
        object.insert(
            "Taints".into(),
            JsonValue::Array(
                manager
                    .taints
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
    object.insert(
        "UnitPath".into(),
        JsonValue::Array(
            manager
                .unit_path
                .iter()
                .cloned()
                .map(JsonValue::String)
                .collect(),
        ),
    );
    object.insert(
        "Virtualization".into(),
        JsonValue::String(manager.virtualization.clone()),
    );
    object.insert(
        "ConfidentialVirtualization".into(),
        JsonValue::String(manager.confidential_virtualization.clone()),
    );
    for (name, timestamp) in &manager.timestamps {
        object.insert(name.clone(), dual_timestamp_json(timestamp));
    }
    object.insert("NNames".into(), JsonValue::Unsigned(manager.n_names));
    object.insert(
        "NFailedUnits".into(),
        JsonValue::Unsigned(manager.n_failed_units),
    );
    object.insert("NJobs".into(), JsonValue::Unsigned(manager.n_jobs));
    object.insert(
        "NInstalledJobs".into(),
        JsonValue::Unsigned(manager.n_installed_jobs),
    );
    object.insert(
        "NFailedJobs".into(),
        JsonValue::Unsigned(manager.n_failed_jobs),
    );
    if !manager.transactions_with_cycle.is_empty() {
        object.insert(
            "TransactionsWithOrderingCycle".into(),
            transactions_with_cycle_build_json(&manager.transactions_with_cycle)?,
        );
    }
    object.insert("Progress".into(), JsonValue::Real(manager.progress));
    if let Some(timestamp) = &manager.watchdog_last_ping {
        object.insert(
            "WatchdogLastPingTimestamp".into(),
            dual_timestamp_json(timestamp),
        );
    }
    object.insert(
        "SystemState".into(),
        JsonValue::String(manager.system_state.clone()),
    );
    object.insert("ExitCode".into(), JsonValue::Unsigned(manager.exit_code));
    object.insert(
        "SoftRebootsCount".into(),
        JsonValue::Unsigned(manager.soft_reboots_count),
    );
    Ok(JsonValue::Object(object))
}

pub fn describe_manager(manager: &ManagerSnapshot) -> Result<JsonValue, VarlinkManagerError> {
    Ok(JsonValue::Object(BTreeMap::from([
        ("context".into(), manager_context_build_json(manager)?),
        ("runtime".into(), manager_runtime_build_json(manager)?),
    ])))
}

pub fn reload_manager(
    manager: &mut ManagerSnapshot,
    authorized: bool,
    rate_limit_ok: bool,
) -> Result<VarlinkAction, VarlinkManagerError> {
    if !authorized {
        return Err(VarlinkManagerError::PermissionDenied);
    }
    if !rate_limit_ok {
        return Err(VarlinkManagerError::RateLimitReached);
    }

    manager.pending_reload_message = true;
    manager.objective = Some(ManagerObjective::Reload);
    Ok(VarlinkAction::ReplyLater)
}

pub fn reexecute_manager(
    manager: &mut ManagerSnapshot,
    authorized: bool,
    rate_limit_ok: bool,
) -> Result<VarlinkAction, VarlinkManagerError> {
    if !authorized {
        return Err(VarlinkManagerError::PermissionDenied);
    }
    if !rate_limit_ok {
        return Err(VarlinkManagerError::RateLimitReached);
    }

    manager.objective = Some(ManagerObjective::Reexecute);
    Ok(VarlinkAction::Disconnect)
}

pub fn enqueue_marked_jobs_manager(
    items: impl IntoIterator<Item = QueuedJobResult>,
) -> Result<Vec<JsonValue>, VarlinkManagerError> {
    let mut out = Vec::new();
    for item in items {
        let mut object = BTreeMap::new();
        object.insert("unitID".into(), JsonValue::String(item.unit_id));
        if let Some(job_id) = item.job_id {
            object.insert("jobID".into(), JsonValue::Unsigned(job_id.into()));
        }
        insert_optional_string(&mut object, "error", item.error);
        insert_optional_string(&mut object, "errorMessage", item.error_message);
        out.push(JsonValue::Object(object));
    }
    Ok(out)
}

pub fn set_objective(
    manager: &mut ManagerSnapshot,
    objective: ManagerObjective,
    authorized: bool,
    root: Option<&str>,
    can_do_root: bool,
) -> Result<VarlinkAction, VarlinkManagerError> {
    if !manager.system_mode {
        return Err(VarlinkManagerError::MethodNotImplemented);
    }
    if !authorized {
        return Err(VarlinkManagerError::PermissionDenied);
    }
    if objective.varlink_method_name().is_none() {
        return Err(VarlinkManagerError::InvalidParameter);
    }
    if root.is_some() && !can_do_root {
        return Err(VarlinkManagerError::InvalidParameter);
    }

    manager.switch_root = root.map(simplify_absolute_path).transpose()?;
    manager.objective = Some(objective);
    Ok(VarlinkAction::Reply)
}

fn dual_timestamp_json(timestamp: &DualTimestamp) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("realtime".into(), JsonValue::Unsigned(timestamp.realtime)),
        ("monotonic".into(), JsonValue::Unsigned(timestamp.monotonic)),
    ]))
}

fn insert_optional(target: &mut BTreeMap<String, JsonValue>, key: &str, value: Option<JsonValue>) {
    if let Some(value) = value {
        target.insert(key.to_string(), value);
    }
}

fn insert_optional_string(
    target: &mut BTreeMap<String, JsonValue>,
    key: &str,
    value: Option<String>,
) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        target.insert(key.to_string(), JsonValue::String(value));
    }
}

fn insert_optional_u64(target: &mut BTreeMap<String, JsonValue>, key: &str, value: Option<u64>) {
    if let Some(value) = value {
        target.insert(key.to_string(), JsonValue::Unsigned(value));
    }
}

fn simplify_absolute_path(path: &str) -> Result<String, VarlinkManagerError> {
    if !path.starts_with('/') {
        return Err(VarlinkManagerError::InvalidParameter);
    }

    let mut parts = Vec::<&str>::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }

    Ok(format!("/{}", parts.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> ManagerSnapshot {
        ManagerSnapshot {
            show_status: true,
            log_target: "journal".into(),
            log_levels: BTreeMap::from([("console".into(), "info".into())]),
            environment: vec!["A=B".into()],
            defaults: ManagerDefaults {
                std_output: "journal".into(),
                std_error: "inherit".into(),
                service_watchdogs: true,
                timer_accuracy_usec: Some(10),
                timeout_start_usec: Some(20),
                timeout_stop_usec: Some(30),
                timeout_abort_usec: Some(40),
                device_timeout_usec: Some(50),
                restart_usec: Some(60),
                start_limit: RateLimit {
                    interval_usec: 70,
                    burst: 3,
                },
                io_accounting: true,
                ip_accounting: false,
                memory_accounting: true,
                tasks_accounting: true,
                tasks_max: 99,
                memory_pressure_threshold_usec: Some(80),
                memory_pressure_watch: "auto".into(),
                oom_policy: "stop".into(),
                oom_score_adjust: 5,
                restrict_suid_sgid: true,
            },
            reboot_watchdog_usec: Some(90),
            runtime_watchdog_usec: Some(91),
            kexec_watchdog_usec: Some(92),
            runtime_watchdog_pre_usec: Some(93),
            watchdog_pretimeout_governor: Some("noop".into()),
            watchdog_device: Some("/dev/watchdog0".into()),
            cad_burst_action: "reboot-force".into(),
            confirm_spawn: Some("tty".into()),
            cgroup_root: Some("/sys/fs/cgroup".into()),
            version: "255".into(),
            architecture: "x86-64".into(),
            features: "+PAM".into(),
            taints: vec!["container".into()],
            unit_path: vec!["/etc/systemd/system".into()],
            virtualization: "kvm".into(),
            confidential_virtualization: "none".into(),
            timestamps: BTreeMap::from([(
                "KernelTimestamp".into(),
                DualTimestamp {
                    realtime: 1,
                    monotonic: 2,
                },
            )]),
            n_names: 5,
            n_failed_units: 1,
            n_jobs: 2,
            n_installed_jobs: 3,
            n_failed_jobs: 4,
            transactions_with_cycle: BTreeSet::from([7, 9]),
            progress: 0.5,
            watchdog_last_ping: Some(DualTimestamp {
                realtime: 11,
                monotonic: 12,
            }),
            system_state: "running".into(),
            exit_code: 0,
            soft_reboots_count: 1,
            system_mode: true,
            objective: None,
            switch_root: None,
            pending_reload_message: false,
        }
    }

    #[test]
    fn environment_json_is_omitted_when_empty() {
        let mut manager = manager();
        manager.environment.clear();
        assert_eq!(manager_environment_build_json(&manager).unwrap(), None);
    }

    #[test]
    fn log_level_json_is_object_shaped() {
        let JsonValue::Object(object) = log_level_build_json(&manager()).unwrap() else {
            panic!("expected object");
        };
        assert_eq!(
            object.get("console"),
            Some(&JsonValue::String("info".into()))
        );
    }

    #[test]
    fn context_json_contains_expected_fields() {
        let JsonValue::Object(object) = manager_context_build_json(&manager()).unwrap() else {
            panic!("expected object");
        };
        assert!(object.contains_key("ShowStatus"));
        assert!(object.contains_key("DefaultStartLimit"));
        assert!(object.contains_key("ConfirmSpawn"));
    }

    #[test]
    fn runtime_json_contains_transactions_and_timestamps() {
        let JsonValue::Object(object) = manager_runtime_build_json(&manager()).unwrap() else {
            panic!("expected object");
        };
        assert!(object.contains_key("TransactionsWithOrderingCycle"));
        assert!(object.contains_key("KernelTimestamp"));
    }

    #[test]
    fn describe_manager_builds_context_and_runtime() {
        let JsonValue::Object(object) = describe_manager(&manager()).unwrap() else {
            panic!("expected object");
        };
        assert!(object.contains_key("context"));
        assert!(object.contains_key("runtime"));
    }

    #[test]
    fn reload_sets_objective_and_defers_reply() {
        let mut manager = manager();
        assert_eq!(
            reload_manager(&mut manager, true, true).unwrap(),
            VarlinkAction::ReplyLater
        );
        assert_eq!(manager.objective, Some(ManagerObjective::Reload));
        assert!(manager.pending_reload_message);
    }

    #[test]
    fn reexecute_observes_rate_limit() {
        let mut manager = manager();
        assert_eq!(
            reexecute_manager(&mut manager, true, false).unwrap_err(),
            VarlinkManagerError::RateLimitReached
        );
    }

    #[test]
    fn set_objective_simplifies_root_when_allowed() {
        let mut manager = manager();
        assert_eq!(
            set_objective(
                &mut manager,
                ManagerObjective::SoftReboot,
                true,
                Some("/a/./b/../c"),
                true
            )
            .unwrap(),
            VarlinkAction::Reply
        );
        assert_eq!(manager.switch_root.as_deref(), Some("/a/c"));
    }

    #[test]
    fn set_objective_requires_system_mode() {
        let mut manager = manager();
        manager.system_mode = false;
        assert_eq!(
            set_objective(&mut manager, ManagerObjective::Poweroff, true, None, false).unwrap_err(),
            VarlinkManagerError::MethodNotImplemented
        );
    }

    #[test]
    fn set_objective_rejects_internal_lifecycle_outcomes() {
        let mut manager = manager();
        for objective in [
            ManagerObjective::Ok,
            ManagerObjective::Exit,
            ManagerObjective::SwitchRoot,
        ] {
            assert_eq!(
                set_objective(&mut manager, objective, true, None, false).unwrap_err(),
                VarlinkManagerError::InvalidParameter
            );
        }
    }

    #[test]
    fn enqueue_marked_jobs_preserves_error_shape() {
        let result = enqueue_marked_jobs_manager([QueuedJobResult {
            unit_id: "a.service".into(),
            job_id: None,
            error: Some("io.systemd.Unit.NoSuchUnit".into()),
            error_message: Some("missing".into()),
        }])
        .unwrap();
        let JsonValue::Object(object) = &result[0] else {
            panic!("expected object");
        };
        assert!(object.contains_key("error"));
        assert!(object.contains_key("errorMessage"));
    }
}
