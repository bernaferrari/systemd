// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/unit.c";

pub type Result<T> = std::result::Result<T, UnitError>;
pub type DependencyMask = u64;

pub(super) static UNIT_PATH: OnceLock<Mutex<Option<String>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitError {
    Invalid,
    Exists,
    Missing,
    Busy,
    Unsupported,
    StartLimitHit,
}

impl UnitError {
    pub const fn errno(self) -> Errno {
        match self {
            Self::Invalid => Errno::EINVAL,
            Self::Exists => Errno::EEXIST,
            Self::Missing => Errno::ENOENT,
            Self::Busy => Errno::EBUSY,
            Self::Unsupported => Errno::EOPNOTSUPP,
            Self::StartLimitHit => Errno::EAGAIN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnitType {
    Service,
    Socket,
    Target,
    Device,
    Mount,
    Automount,
    Swap,
    Timer,
    Path,
    Slice,
    Scope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActiveState {
    Inactive,
    Activating,
    Active,
    Refreshing,
    Reloading,
    Deactivating,
    Failed,
    Maintenance,
    Frozen,
}

impl ActiveState {
    pub const fn is_active_or_reloading(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Refreshing | Self::Reloading | Self::Frozen
        )
    }

    pub const fn is_active_or_activating(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Activating | Self::Refreshing | Self::Reloading | Self::Frozen
        )
    }

    pub const fn is_inactive_or_failed(self) -> bool {
        matches!(self, Self::Inactive | Self::Failed)
    }

    pub const fn is_inactive_or_deactivating(self) -> bool {
        matches!(self, Self::Inactive | Self::Failed | Self::Deactivating)
    }

    /// Rust models cgroup freezing explicitly while C's UnitActiveState stays
    /// `UNIT_ACTIVE`; both are exact-active for lifecycle queue predicates.
    pub const fn is_exact_active(self) -> bool {
        matches!(self, Self::Active | Self::Frozen)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Stub,
    Loaded,
    Error,
    Merged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueueKind {
    Cleanup,
    Dbus,
    Gc,
    Load,
    ReleaseResources,
    StartWhenUpheld,
    StopNotify,
    StopWhenBound,
    StopWhenUnneeded,
    TargetDeps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyKind {
    Wants,
    Requires,
    Requisite,
    BindsTo,
    Upholds,
    PartOf,
    Before,
    After,
    Conflicts,
    Triggers,
    TriggeredBy,
    OnSuccess,
    OnFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Start,
    Stop,
    Reload,
    Restart,
    VerifyActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitFileState {
    Invalid,
    Disabled,
    Enabled,
    Static,
    Transient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetAction {
    Invalid,
    Enable,
    Disable,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectMode {
    Inactive,
    InactiveOrFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitMountDependencyType {
    Wants,
    Requires,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OomPolicy {
    Continue,
    Stop,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezerState {
    Running,
    Freezing,
    Frozen,
    Thawing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnitMarker {
    NeedsDaemonReload,
    RefuseManualStart,
    RefuseManualStop,
    AllowIsolate,
    RestartScheduled,
    OomEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitStatusType {
    Status,
    Notice,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PidRef(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    pub interval_usec: u64,
    pub burst: usize,
    begin_usec: Option<u64>,
    num: usize,
}

impl RateLimit {
    pub fn new(interval_usec: u64, burst: usize) -> Self {
        Self {
            interval_usec,
            burst,
            begin_usec: None,
            num: 0,
        }
    }

    pub fn check(&mut self, now_usec: u64) -> Result<()> {
        if self.interval_usec == 0 || self.burst == 0 {
            return Ok(());
        }

        if self
            .begin_usec
            .is_none_or(|begin| now_usec.saturating_sub(begin) > self.interval_usec)
        {
            self.begin_usec = Some(now_usec);
            self.num = 1;
            return Ok(());
        }

        if self.num == usize::MAX {
            return Err(UnitError::StartLimitHit);
        }
        self.num += 1;
        (self.num <= self.burst)
            .then_some(())
            .ok_or(UnitError::StartLimitHit)
    }

    /// Earliest timestamp at which the oldest retained hit has expired.
    ///
    /// `check()` expires hits only when their age is strictly greater than the
    /// interval, hence the single-microsecond increment.
    pub fn retry_at_usec(&self) -> Option<u64> {
        self.begin_usec
            .map(|begin| begin.saturating_add(self.interval_usec).saturating_add(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerDefaults {
    pub start_limit_interval_usec: u64,
    pub start_limit_burst: usize,
    pub io_accounting: bool,
    pub memory_accounting: bool,
    pub tasks_accounting: bool,
    pub ip_accounting: bool,
    pub tasks_max: u64,
}

impl Default for ManagerDefaults {
    fn default() -> Self {
        Self {
            start_limit_interval_usec: 10_000_000,
            start_limit_burst: 5,
            io_accounting: false,
            memory_accounting: false,
            tasks_accounting: false,
            ip_accounting: false,
            tasks_max: 512,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagerRecord {
    pub defaults: ManagerDefaults,
    pub known_units: BTreeSet<String>,
    pub user_mode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecContext {
    pub nice: i32,
    pub log_level_max: i32,
    pub environment: BTreeMap<String, String>,
    /// The represented subset of C's terminal settings. These fields are
    /// enough for the generic `unit_needs_console()` fallback; service stdio
    /// routing remains owned by `runtime_manager::service_runtime`.
    pub tty_path: Option<String>,
    pub tty_reset: bool,
    pub tty_vhangup: bool,
    pub tty_vt_disallocate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KillContext {
    pub kill_signal: i32,
    pub final_kill_signal: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CgroupContext {
    pub io_accounting: bool,
    pub memory_accounting: bool,
    pub tasks_accounting: bool,
    pub ip_accounting: bool,
    pub tasks_max: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecRuntime {
    pub prepared: bool,
    pub invocation_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CgroupRuntime {
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitRef {
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivationDetails {
    pub env: BTreeMap<String, String>,
    pub pairs: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecQuotaStats {
    pub nice: i32,
    pub cpu_weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub manager: ManagerRecord,
    pub unit_type: UnitType,
    pub id: Option<String>,
    pub aliases: BTreeSet<String>,
    pub description: Option<String>,
    pub active_state: ActiveState,
    pub sub_state: String,
    pub load_state: LoadState,
    pub default_dependencies: bool,
    pub unit_file_state: UnitFileState,
    pub unit_file_preset: PresetAction,
    pub queues: BTreeSet<QueueKind>,
    pub dependencies: BTreeMap<DependencyKind, BTreeSet<String>>,
    pub markers: BTreeSet<UnitMarker>,
    pub watched_pids: BTreeSet<PidRef>,
    pub bus_names: BTreeSet<String>,
    pub merged_into: Option<String>,
    pub slice: Option<String>,
    pub invocation_id: Option<[u8; 16]>,
    pub start_ratelimit: RateLimit,
    pub auto_start_stop_ratelimit: RateLimit,
    pub exec_context: Option<ExecContext>,
    pub kill_context: Option<KillContext>,
    pub cgroup_context: Option<CgroupContext>,
    pub exec_runtime: Option<ExecRuntime>,
    pub cgroup_runtime: Option<CgroupRuntime>,
    /// The one authoritative installed non-NOP job for this unit.
    ///
    /// The manager owns the corresponding `job::Job`; the unit only retains
    /// its stable identity, matching `Unit.job` in the C manager without
    /// introducing a second lifecycle owner.
    pub current_job_id: Option<u32>,
    pub control_pid: Option<PidRef>,
    pub main_pid: Option<PidRef>,
    pub main_pid_alien: bool,
    pub ref_uid: Option<u32>,
    pub ref_gid: Option<u32>,
    pub status_history: Vec<String>,
    pub state_files: BTreeSet<String>,
    pub stop_pending: bool,
    pub debug_invocation: bool,
    pub transient: bool,
    pub freezer_state: FreezerState,
    pub cpu_weight: u64,
    pub exit_status: i32,
    pub failure_action_exit_status: i32,
    pub success_action_exit_status: i32,
    next_pid: u32,
}

impl Unit {
    pub fn new(manager: ManagerRecord, unit_type: UnitType) -> Self {
        let defaults = manager.defaults.clone();
        Self {
            manager,
            unit_type,
            id: None,
            aliases: BTreeSet::new(),
            description: None,
            active_state: ActiveState::Inactive,
            sub_state: "dead".into(),
            load_state: LoadState::Stub,
            default_dependencies: true,
            unit_file_state: UnitFileState::Invalid,
            unit_file_preset: PresetAction::Invalid,
            queues: BTreeSet::new(),
            dependencies: BTreeMap::new(),
            markers: BTreeSet::new(),
            watched_pids: BTreeSet::new(),
            bus_names: BTreeSet::new(),
            merged_into: None,
            slice: None,
            invocation_id: None,
            start_ratelimit: RateLimit::new(
                defaults.start_limit_interval_usec,
                defaults.start_limit_burst,
            ),
            auto_start_stop_ratelimit: RateLimit::new(10_000_000, 16),
            exec_context: Some(ExecContext::default()),
            kill_context: Some(KillContext::default()),
            cgroup_context: Some(CgroupContext {
                io_accounting: defaults.io_accounting,
                memory_accounting: defaults.memory_accounting,
                tasks_accounting: defaults.tasks_accounting,
                ip_accounting: defaults.ip_accounting,
                tasks_max: defaults.tasks_max,
            }),
            exec_runtime: None,
            cgroup_runtime: None,
            current_job_id: None,
            control_pid: None,
            main_pid: None,
            main_pid_alien: false,
            ref_uid: None,
            ref_gid: None,
            status_history: Vec::new(),
            state_files: BTreeSet::new(),
            stop_pending: false,
            debug_invocation: false,
            transient: false,
            freezer_state: FreezerState::Running,
            cpu_weight: 100,
            exit_status: 0,
            failure_action_exit_status: -1,
            success_action_exit_status: -1,
            next_pid: 1000,
        }
    }

    pub(super) fn push_status(&mut self, message: impl Into<String>) {
        self.status_history.push(message.into());
    }

    pub(super) fn queue(&mut self, kind: QueueKind) {
        self.queues.insert(kind);
    }

    pub fn dependency_set_mut(&mut self, kind: DependencyKind) -> &mut BTreeSet<String> {
        self.dependencies.entry(kind).or_default()
    }

    pub(super) fn new_pid(&mut self) -> PidRef {
        self.next_pid += 1;
        PidRef(self.next_pid)
    }
}

pub(super) fn is_valid_unit_name(name: &str) -> bool {
    !name.trim().is_empty()
        && !name.contains(char::is_whitespace)
        && name.contains('.')
        && !name.contains('/')
}

pub(super) fn is_canonical_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("//")
        && !path.contains("/../")
        && !path.ends_with("/..")
}

pub(super) fn sanitize_bus_path_fragment(value: &str) -> String {
    value
        .replace('.', "_2e")
        .replace('-', "_2d")
        .replace('/', "_")
}

pub(super) fn current_unit_path() -> Option<String> {
    UNIT_PATH
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|g| g.clone())
}
