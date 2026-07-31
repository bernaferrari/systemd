// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

#[cfg(target_os = "linux")]
use std::cell::RefCell;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::rc::{Rc, Weak};

use crate::ffi::Errno;
use crate::job::{Job, JobId, JobRegistry, UnitActiveState as JobUnitActiveState};
use crate::job_tables::JobType as CanonicalJobType;
use crate::service::{Manager as ServiceManager, Service, ServiceState, ServiceType};
use crate::socket_activation::{ListenerDescriptor, SocketActivationManager};
use crate::transaction::{
    AppliedTransaction, JobMode, JobType as TxJobType, Transaction, TransactionError, UnitSpec,
    UnitState,
};
use crate::unit::{
    ActiveState, DependencyKind, LoadState, ManagerRecord as UnitManagerRecord, Unit, UnitMarker,
    UnitType, unit_add_default_target_dependency, unit_add_slice_dependencies, unit_reset_failed,
    unit_set_default_slice,
};
use systemd_platform_rs::spawn::{self, ChildState, ProcessTracker};

pub type Result<T> = std::result::Result<T, Errno>;

/// A duplicated view of the manager-wide cgroup inotify instance.
///
/// `RuntimeManager` remains the authoritative owner. PID 1's event-source
/// layer owns this duplicate until it has removed the corresponding epoll
/// registration, preventing raw-fd reuse during cgroup teardown.
#[cfg(target_os = "linux")]
pub struct CgroupEventDescriptor(OwnedFd);

#[cfg(target_os = "linux")]
impl CgroupEventDescriptor {
    #[cfg(test)]
    pub(crate) fn from_fd(fd: OwnedFd) -> Self {
        Self(fd)
    }

    pub(crate) fn into_fd(self) -> OwnedFd {
        self.0
    }
}

/*
 * Keep the manager as the owner of units, jobs, aliases, and transactions. Unit-file decoding,
 * service process transitions, and cgroup filesystem side effects live behind focused submodules
 * so none of those domains can acquire a second manager state store.
 */
mod bound_liveness;
mod cgroup_runtime;
#[cfg(test)]
mod handoff;
mod job_runtime;
mod linux_cgroup;
mod service_jobs;
mod service_machine;
mod service_readiness;
mod service_runtime;
mod service_shutdown;
mod socket_runtime;
pub(crate) mod unit_file;
mod unit_load;
mod unit_specifier;

use cgroup_runtime::RealizedUnitCgroup;
use linux_cgroup::CgroupRoot;

#[cfg(test)]
#[path = "runtime_manager/service_test_events.rs"]
mod service_test_events;
#[cfg(test)]
mod tests;

pub use unit_file::{
    AutomountConfig, CgroupConfig, ExecCommandSpec, ExecContextConfig, FileDescriptorStorePreserve,
    InstallConfig, KillConfig, KillMode, MountConfig, PathConfig, ScopeConfig, ServiceConfig,
    ServiceRestartPolicy, SliceConfig, SocketConfig, SwapConfig, TimerConfig, UnitConditionConfig,
    UnitConditionExpression, UnitFileInfo,
};
use unit_file::{
    apply_cgroup_config, apply_exec_context_config, apply_kill_config, parse_unit_file,
    unit_search_paths,
};
use unit_load::{load_default_target_candidate, load_unit_file_with_dropins};

const DYNAMIC_UID_MIN: u32 = 61184;
const DYNAMIC_UID_MAX: u32 = 65519;
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

fn specs_or_single(specs: &[ExecCommandSpec], fallback: &Option<String>) -> Vec<ExecCommandSpec> {
    if !specs.is_empty() {
        return specs.to_vec();
    }

    fallback
        .as_ref()
        .map(|command| {
            vec![ExecCommandSpec {
                prefixes: String::new(),
                command: command.clone(),
            }]
        })
        .unwrap_or_default()
}

fn infer_service_type(info: &UnitFileInfo) -> ServiceType {
    if let Some(service_type) = info.service_type {
        return service_type;
    }
    if info.service.bus_name.is_some() {
        return ServiceType::Dbus;
    }
    if !info.service.exec_start.is_empty() || info.exec_start.is_some() {
        return ServiceType::Simple;
    }
    ServiceType::Oneshot
}

fn signal_token(signal: i32) -> Option<&'static str> {
    match signal {
        libc::SIGTERM => Some("SIGTERM"),
        libc::SIGKILL => Some("SIGKILL"),
        libc::SIGABRT => Some("SIGABRT"),
        libc::SIGINT => Some("SIGINT"),
        libc::SIGHUP => Some("SIGHUP"),
        libc::SIGQUIT => Some("SIGQUIT"),
        libc::SIGSEGV => Some("SIGSEGV"),
        libc::SIGPIPE => Some("SIGPIPE"),
        _ => None,
    }
}

fn child_state_tokens(state: ChildState) -> Vec<String> {
    match state {
        ChildState::ExitedCleanly => vec!["0".to_string()],
        ChildState::ExitedWithCode(code) => vec![code.to_string()],
        ChildState::KilledBySignal(sig) => {
            let mut values = vec![sig.to_string()];
            if let Some(token) = signal_token(sig) {
                values.push(token.to_string());
            }
            values
        }
        ChildState::Running => Vec::new(),
    }
}

fn status_list_matches(tokens: &[String], expected: &[String]) -> bool {
    tokens
        .iter()
        .any(|token| expected.iter().any(|item| item.eq_ignore_ascii_case(token)))
}

/// The meaning assigned to a signal exit by the service process that received it.
///
/// This mirrors `ExitClean` in `src/shared/exit-status.c`.  Service command
/// helpers are strict: a signal is a failure unless `SuccessExitStatus=` says
/// otherwise. Long-running daemons additionally regard the conventional
/// termination signals as clean, matching the upstream service SIGCHLD path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildExitCleanMode {
    Command,
    Daemon,
}

/// Return whether a child completion is clean under the requested process role.
///
/// `SuccessExitStatus=` applies in both modes. This intentionally does not
/// broaden command semantics: only daemons receive the upstream default clean
/// treatment for SIGHUP, SIGINT, SIGTERM, and SIGPIPE.
pub(crate) fn child_state_considered_clean_with_mode(
    state: ChildState,
    info: &UnitFileInfo,
    mode: ChildExitCleanMode,
) -> bool {
    if matches!(state, ChildState::ExitedCleanly) {
        return true;
    }

    if mode == ChildExitCleanMode::Daemon
        && matches!(
            state,
            ChildState::KilledBySignal(libc::SIGHUP | libc::SIGINT | libc::SIGTERM | libc::SIGPIPE)
        )
    {
        return true;
    }

    let tokens = child_state_tokens(state);
    status_list_matches(&tokens, &info.service.success_exit_status)
}

fn transaction_job_type_to_canonical(kind: TxJobType) -> CanonicalJobType {
    match kind {
        TxJobType::Start => CanonicalJobType::Start,
        TxJobType::VerifyActive => CanonicalJobType::VerifyActive,
        TxJobType::Stop => CanonicalJobType::Stop,
        TxJobType::Reload => CanonicalJobType::Reload,
        TxJobType::Restart => CanonicalJobType::Restart,
        TxJobType::TryRestart => CanonicalJobType::TryRestart,
        TxJobType::Nop => CanonicalJobType::Nop,
    }
}

fn canonical_job_type_to_transaction(kind: CanonicalJobType) -> Option<TxJobType> {
    match kind {
        CanonicalJobType::Start => Some(TxJobType::Start),
        CanonicalJobType::VerifyActive => Some(TxJobType::VerifyActive),
        CanonicalJobType::Stop => Some(TxJobType::Stop),
        CanonicalJobType::Reload => Some(TxJobType::Reload),
        CanonicalJobType::Restart => Some(TxJobType::Restart),
        CanonicalJobType::TryRestart => Some(TxJobType::TryRestart),
        CanonicalJobType::Nop => Some(TxJobType::Nop),
        CanonicalJobType::TryReload | CanonicalJobType::ReloadOrStart => None,
    }
}

fn active_state_to_job_state(state: ActiveState) -> JobUnitActiveState {
    match state {
        ActiveState::Inactive => JobUnitActiveState::Inactive,
        ActiveState::Activating => JobUnitActiveState::Activating,
        ActiveState::Active | ActiveState::Frozen => JobUnitActiveState::Active,
        ActiveState::Refreshing => JobUnitActiveState::Refreshing,
        ActiveState::Reloading => JobUnitActiveState::Reloading,
        ActiveState::Deactivating => JobUnitActiveState::Deactivating,
        ActiveState::Failed => JobUnitActiveState::Failed,
        ActiveState::Maintenance => JobUnitActiveState::Maintenance,
    }
}

/// A non-owning registration view of one child exec-status channel.
///
/// `RuntimeManager` remains the sole owner of the channel used to read the
/// protocol. PID 1's event-loop source owner holds the weak allocation identity
/// plus a duplicated registration descriptor, which lets it remove a stale
/// epoll source before either raw descriptor can be recycled.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct PendingExecStatusDescriptor {
    pid: u32,
    owner: Weak<RefCell<spawn::ExecStatusHandle>>,
}

/// A duplicated, manager-owned view of the alert side of a `Type=idle` gate.
///
/// The event-loop owner keeps this duplicate only for epoll registration. The
/// runtime remains the authority which acknowledges an alert by closing all
/// four pipe ends.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct IdlePipeAlertDescriptor {
    generation: u64,
    fd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl IdlePipeAlertDescriptor {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn into_fd(self) -> OwnedFd {
        self.fd
    }
}

/// The exact four-descriptor protocol allocated by C's
/// `manager_allocate_idle_pipe()`. The manager owns every endpoint until it
/// acknowledges either boot completion or a child timeout alert.
#[cfg(target_os = "linux")]
struct IdlePipeGate {
    child_wait: Option<OwnedFd>,
    manager_release: Option<OwnedFd>,
    manager_alert: Option<OwnedFd>,
    child_alert: Option<OwnedFd>,
    generation: u64,
}

#[cfg(target_os = "linux")]
impl IdlePipeGate {
    fn new(generation: u64) -> Result<Self> {
        use nix::fcntl::OFlag;
        use nix::unistd::pipe2;

        let flags = OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        let (child_wait, manager_release) = pipe2(flags).map_err(|_| Errno::EIO)?;
        let (manager_alert, child_alert) = pipe2(flags).map_err(|_| Errno::EIO)?;
        Ok(Self {
            child_wait: Some(child_wait),
            manager_release: Some(manager_release),
            manager_alert: Some(manager_alert),
            child_alert: Some(child_alert),
            generation,
        })
    }

    fn spawn_idle_pipe(&self) -> Option<spawn::IdlePipe> {
        Some(spawn::IdlePipe {
            child_wait_fd: self.child_wait.as_ref()?.as_raw_fd(),
            manager_release_fd: self.manager_release.as_ref()?.as_raw_fd(),
            manager_alert_fd: self.manager_alert.as_ref()?.as_raw_fd(),
            child_alert_fd: self.child_alert.as_ref()?.as_raw_fd(),
        })
    }

    fn alert_descriptor(&self) -> std::io::Result<Option<IdlePipeAlertDescriptor>> {
        self.manager_alert
            .as_ref()
            .map(|fd| {
                fd.as_fd()
                    .try_clone_to_owned()
                    .map(|fd| IdlePipeAlertDescriptor {
                        generation: self.generation,
                        fd,
                    })
            })
            .transpose()
    }

    /// Closing all four endpoints is the acknowledgement received by every
    /// idle child waiting on the first pipe. This mirrors
    /// `manager_close_idle_pipe()` rather than retaining one end accidentally
    /// and preventing POLLHUP forever.
    fn close(&mut self) {
        self.child_wait = None;
        self.manager_release = None;
        self.manager_alert = None;
        self.child_alert = None;
    }
}

#[cfg(target_os = "linux")]
impl PendingExecStatusDescriptor {
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn weak_owner(&self) -> &Weak<RefCell<spawn::ExecStatusHandle>> {
        &self.owner
    }

    /// Duplicate the manager-owned descriptor for stable epoll registration.
    ///
    /// The registration owner must retain this duplicate until after
    /// `EPOLL_CTL_DEL`. Retaining only a raw descriptor number would allow the
    /// manager to close it and the kernel to reuse that number for an unrelated
    /// source before reconciliation.
    pub(crate) fn clone_fd_for_registration(&self) -> std::io::Result<Option<OwnedFd>> {
        let Some(owner) = self.owner.upgrade() else {
            return Ok(None);
        };
        let duplicate = owner.borrow().as_fd().try_clone_to_owned();
        duplicate.map(Some)
    }

    pub(crate) fn is_live(&self) -> bool {
        self.owner.upgrade().is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitKillWho {
    Main,
    Control,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackedPidRole {
    Main,
    Control,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdioTargetMode {
    Inherit,
    Null,
    Tty,
    Journal,
    JournalAndConsole,
    Kmsg,
    KmsgAndConsole,
    Socket,
    NamedFd,
    File,
    Append,
    Truncate,
    Other,
}

#[derive(Debug, Clone)]
struct StdioSpec {
    mode: StdioTargetMode,
    payload: Option<String>,
}

#[derive(Debug, Default)]
struct PreparedStdio {
    stdio: spawn::SpawnStdio,
    /// Descriptors opened solely to configure one spawn. `SpawnStdio` keeps
    /// borrowed raw descriptor numbers because that is the platform spawn API,
    /// while this vector keeps their ownership explicit until the spawn call
    /// has duplicated them into the child.
    owned_fds: Vec<OwnedFd>,
}

impl PreparedStdio {
    fn retain_owned_fd(&mut self, fd: OwnedFd) -> RawFd {
        let raw_fd = fd.as_raw_fd();
        self.owned_fds.push(fd);
        raw_fd
    }
}

/// A service stdio target is either borrowed from manager-owned state or
/// freshly opened for one spawn. Only the latter is retained by
/// [`PreparedStdio`], preventing an accidental `OwnedFd` reconstruction for
/// listener, inherited, or named descriptors.
#[derive(Debug)]
enum StdioFd {
    Borrowed(RawFd),
    Owned(OwnedFd),
}

impl StdioFd {
    fn into_raw_for(self, prepared: &mut PreparedStdio) -> RawFd {
        match self {
            Self::Borrowed(fd) => fd,
            Self::Owned(fd) => prepared.retain_owned_fd(fd),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedDirectoryKind {
    Runtime,
    State,
    Cache,
    Logs,
    Configuration,
}

pub struct RuntimeManager {
    units: HashMap<String, Unit>,
    unit_files: HashMap<String, UnitFileInfo>,
    unit_name_map: HashMap<String, String>,
    job_registry: JobRegistry,
    /// Canonical installed jobs. Lifecycle decisions use this map and the
    /// owning unit's `current_job_id`.
    installed_jobs: BTreeMap<JobId, Job>,
    transaction_counter: u64,
    manager_record: UnitManagerRecord,
    process_tracker: ProcessTracker,
    /// Compatibility index for callers which have not migrated to the
    /// main/control PID slots. It is never authoritative for lifecycle
    /// decisions and must not replace a live main PID with a control PID.
    unit_pid_map: HashMap<String, u32>,
    pid_to_unit_map: HashMap<u32, String>,
    pid_role_map: HashMap<u32, TrackedPidRole>,
    service_command_sequences: HashMap<String, service_machine::ServiceCommandSequence>,
    service_operation_deadlines: HashMap<String, service_machine::ServiceOperationDeadline>,
    /// Installed jobs that were merged while their previous operation was
    /// running and must be dispatched again after that operation settles.
    job_redispatch_queue: BTreeSet<JobId>,
    /// Idempotent live dispatch queue. Ordering is evaluated against all
    /// canonical installed jobs when an ID is popped, never from transaction
    /// planner edges or a static topological order.
    job_run_queue: BTreeSet<JobId>,
    /// Dispatch callbacks can synchronously finish jobs and enqueue their
    /// neighbours. The outer drain owns iteration and observes those inserts.
    job_run_queue_dispatching: bool,
    /// Deferred, deduplicated post-transaction `BindsTo=` liveness checks.
    bound_stop_queue: BTreeMap<String, bound_liveness::BoundStopMode>,
    bound_stop_queue_dispatching: bool,
    bound_replace_dispatching: bool,
    bound_stop_retry_deadlines: HashMap<String, u64>,
    #[cfg(target_os = "linux")]
    bound_stop_retry_timer: Option<Rc<systemd_platform_rs::time::BoottimeTimerFd>>,
    /// Dispatch queue for the Start half of an explicit Restart. The installed
    /// canonical job remains the owner and keeps the same ID across both halves.
    service_restart_after_stop: BTreeSet<String>,
    /// Services retain this short-lived channel until the child either execs
    /// or reports a pre-exec failure. This keeps Type=simple asynchronous and
    /// gives Type=exec an event-driven readiness acknowledgement.
    #[cfg(target_os = "linux")]
    pending_exec_confirmations: HashMap<
        u32,
        (
            Rc<RefCell<spawn::ExecStatusHandle>>,
            spawn::SpawnConfirmation,
        ),
    >,
    /// Lazily allocated only while a `Type=idle` child needs the manager's
    /// pipe protocol. It is never a process-global sleep or a unit-name
    /// callback; the child and epoll source communicate solely through these
    /// inherited descriptors.
    #[cfg(target_os = "linux")]
    idle_pipe_gate: Option<IdlePipeGate>,
    #[cfg(target_os = "linux")]
    idle_pipe_generation: u64,
    /// Auto-restart is a manager event, never a blocking sleep in PID 1.
    /// A service remains in `AutoRestartQueued` until this deadline is due.
    service_restart_deadlines: HashMap<String, Instant>,
    service_runtime_deadlines: HashMap<String, Instant>,
    service_watchdog_deadlines: HashMap<String, Instant>,
    service_runtime_dirs: HashMap<String, Vec<PathBuf>>,
    dynamic_service_ids: HashMap<String, (u32, u32)>,
    cgroup_root: CgroupRoot,
    /// One manager-owned capability per successfully realized unit cgroup.
    /// `unit_cgroup_paths` remains a diagnostic/path-compatibility index;
    /// placement and population reads must use these preopened descriptors.
    unit_cgroups: HashMap<String, RealizedUnitCgroup>,
    unit_cgroup_paths: HashMap<String, PathBuf>,
    unit_cgroup_populated: HashMap<String, bool>,
    #[cfg(target_os = "linux")]
    cgroup_inotify_fd: Option<OwnedFd>,
    #[cfg(target_os = "linux")]
    cgroup_watch_by_wd: HashMap<i32, String>,
    #[cfg(target_os = "linux")]
    cgroup_watch_by_unit: HashMap<String, i32>,
    socket_mgr: SocketActivationManager,
    service_activation_sockets: HashMap<String, BTreeSet<String>>,
    services: HashMap<String, Service>,
    service_manager: ServiceManager,
}

/// Select the implicit boot target with the same fallback ordering as
/// `do_queue_default_job()` in `src/core/main.c`.
pub fn default_target_name(
    in_initrd: bool,
    initrd_target_present: bool,
    default_target_present: bool,
    fallback_default_target: &str,
) -> &str {
    if in_initrd && initrd_target_present {
        "initrd.target"
    } else if default_target_present || in_initrd {
        // In the initrd, a missing initrd.target falls back to default.target,
        // never to the host's configured build-time fallback.
        "default.target"
    } else {
        fallback_default_target
    }
}

impl RuntimeManager {
    pub fn new() -> Self {
        Self::new_with_cgroup_root(PathBuf::from(CGROUP_V2_ROOT))
    }

    /// Construct the manager beneath an already selected cgroup hierarchy.
    ///
    /// PID 1 must not rediscover this as the global cgroup mount after
    /// `manager_setup_cgroup()` has placed it in a delegated subtree. The
    /// retained [`CgroupRoot`] is an `O_PATH` descriptor capability, so this
    /// also keeps the selected cgroupfs mount pinned for the manager's
    /// lifetime instead of trusting the path after startup.
    pub fn new_at_cgroup_root(cgroup_root: PathBuf) -> Self {
        Self::new_with_cgroup_root(cgroup_root)
    }

    /// Verify that the manager's cgroup capability was opened successfully.
    ///
    /// C's `manager_new()` fails before startup when it cannot establish the
    /// manager cgroup.  `CgroupRoot` intentionally keeps construction
    /// infallible so unit-test managers can be assembled without a mounted
    /// cgroupfs, but PID 1 must make the failure explicit before it queues any
    /// boot job.  Keeping this check separate preserves the lightweight test
    /// constructor while preventing a production manager from silently
    /// running without cgroup accounting and process containment.
    pub fn validate_cgroup_root(&self) -> std::io::Result<()> {
        self.cgroup_root.handoff_fd().map(|_| ())
    }

    fn new_with_cgroup_root(cgroup_root: PathBuf) -> Self {
        #[cfg(target_os = "linux")]
        let bound_stop_retry_timer = match systemd_platform_rs::time::BoottimeTimerFd::new() {
            Ok(timer) => Some(Rc::new(timer)),
            Err(error) => {
                eprintln!(
                    "systemd: cannot create CLOCK_BOOTTIME timer for BindsTo= retries: {error}"
                );
                None
            }
        };

        Self {
            units: HashMap::new(),
            unit_files: HashMap::new(),
            unit_name_map: HashMap::new(),
            job_registry: JobRegistry::default(),
            installed_jobs: BTreeMap::new(),
            transaction_counter: 0,
            manager_record: UnitManagerRecord::default(),
            process_tracker: ProcessTracker::new(),
            unit_pid_map: HashMap::new(),
            pid_to_unit_map: HashMap::new(),
            pid_role_map: HashMap::new(),
            service_command_sequences: HashMap::new(),
            service_operation_deadlines: HashMap::new(),
            job_redispatch_queue: BTreeSet::new(),
            job_run_queue: BTreeSet::new(),
            job_run_queue_dispatching: false,
            bound_stop_queue: BTreeMap::new(),
            bound_stop_queue_dispatching: false,
            bound_replace_dispatching: false,
            bound_stop_retry_deadlines: HashMap::new(),
            #[cfg(target_os = "linux")]
            bound_stop_retry_timer,
            service_restart_after_stop: BTreeSet::new(),
            #[cfg(target_os = "linux")]
            pending_exec_confirmations: HashMap::new(),
            #[cfg(target_os = "linux")]
            idle_pipe_gate: None,
            #[cfg(target_os = "linux")]
            idle_pipe_generation: 0,
            service_restart_deadlines: HashMap::new(),
            service_runtime_deadlines: HashMap::new(),
            service_watchdog_deadlines: HashMap::new(),
            service_runtime_dirs: HashMap::new(),
            dynamic_service_ids: HashMap::new(),
            cgroup_root: CgroupRoot::new(cgroup_root),
            unit_cgroups: HashMap::new(),
            unit_cgroup_paths: HashMap::new(),
            unit_cgroup_populated: HashMap::new(),
            #[cfg(target_os = "linux")]
            cgroup_inotify_fd: None,
            #[cfg(target_os = "linux")]
            cgroup_watch_by_wd: HashMap::new(),
            #[cfg(target_os = "linux")]
            cgroup_watch_by_unit: HashMap::new(),
            socket_mgr: SocketActivationManager::new(),
            service_activation_sockets: HashMap::new(),
            services: HashMap::new(),
            service_manager: ServiceManager::default(),
        }
    }

    /// Clone only the timer capability needed by PID 1's event-source owner.
    /// The callback cannot retain or mutate the manager through this handle.
    #[cfg(target_os = "linux")]
    pub fn clone_bound_stop_retry_timer_for_registration(
        &self,
    ) -> Option<Rc<systemd_platform_rs::time::BoottimeTimerFd>> {
        self.bound_stop_retry_timer.clone()
    }

    /// Snapshot the manager-wide cgroup notification capability for epoll.
    ///
    /// The inotify instance is allocated lazily with the first realized unit
    /// cgroup. Duplicating it preserves the shared kernel event queue while
    /// giving the event-source owner an independent, CLOEXEC lifetime.
    #[cfg(target_os = "linux")]
    pub fn cgroup_event_descriptor(&self) -> std::io::Result<Option<CgroupEventDescriptor>> {
        self.cgroup_inotify_fd
            .as_ref()
            .map(|fd| fd.as_fd().try_clone_to_owned().map(CgroupEventDescriptor))
            .transpose()
    }

    /// Drain kernel cgroup notifications from the manager thread.
    ///
    /// Event-loop callbacks only set a bounded readiness bit. Dispatch stays
    /// here so cgroup-empty state transitions run after SIGCHLD metadata has
    /// been collected, matching C's deferred cgroup-empty ordering.
    #[cfg(target_os = "linux")]
    pub fn dispatch_cgroup_events(&mut self) {
        self.process_cgroup_events();
    }

    /// Allocate C's manager-owned `Type=idle` pipes on the first idle spawn
    /// of a gate and return their borrowed child view. Allocation happens
    /// before fork; the post-fork launcher only closes, polls, writes, and
    /// execs through these descriptors.
    #[cfg(target_os = "linux")]
    pub(crate) fn idle_pipe_for_spawn(&mut self) -> Result<spawn::IdlePipe> {
        if self.idle_pipe_gate.is_none() {
            self.idle_pipe_generation = self.idle_pipe_generation.wrapping_add(1);
            self.idle_pipe_gate = Some(IdlePipeGate::new(self.idle_pipe_generation)?);
        }
        self.idle_pipe_gate
            .as_ref()
            .and_then(IdlePipeGate::spawn_idle_pipe)
            .ok_or(Errno::EIO)
    }

    /// Clone the current alert reader for one epoll registration. A clone,
    /// rather than a raw FD number, lets the source owner remove stale gates
    /// without descriptor-reuse confusion.
    #[cfg(target_os = "linux")]
    pub fn idle_pipe_alert_descriptor(&self) -> Result<Option<IdlePipeAlertDescriptor>> {
        let Some(gate) = self.idle_pipe_gate.as_ref() else {
            return Ok(None);
        };
        gate.alert_descriptor().map_err(|_| Errno::EIO)
    }

    /// Acknowledge an idle child's timeout alert or normal boot completion.
    /// This is intentionally idempotent: a queued epoll alert after the first
    /// close is inert, just like C disabling the event source before closing
    /// the descriptor pairs.
    #[cfg(target_os = "linux")]
    pub fn close_idle_pipe(&mut self) {
        if let Some(gate) = self.idle_pipe_gate.as_mut() {
            gate.close();
        }
        self.idle_pipe_gate = None;
    }

    /// Equivalent to the idle-pipe portion of C's `manager_check_finished()`.
    /// PID 1 calls this only from its manager-loop turn, after the canonical
    /// job tables have drained; ordinary transaction submission must not
    /// release idle children merely because one nested dispatch returned.
    #[cfg(target_os = "linux")]
    pub fn close_idle_pipe_when_manager_idle(&mut self) {
        if self.installed_jobs.is_empty()
            && self.job_run_queue.is_empty()
            && self.job_redispatch_queue.is_empty()
            && !self.job_run_queue_dispatching
        {
            self.close_idle_pipe();
        }
    }

    #[cfg(test)]
    fn new_with_test_cgroup_root(cgroup_root: PathBuf) -> Self {
        fs::create_dir_all(&cgroup_root)
            .expect("test cgroup root must exist before its capability is opened");
        Self::new_with_cgroup_root(cgroup_root)
    }

    fn canonical_unit_name(&self, name: &str) -> String {
        self.unit_name_map
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    fn register_unit_alias(&mut self, alias: &str, canonical: &str) {
        self.unit_name_map
            .insert(alias.to_string(), canonical.to_string());
    }

    fn default_path_from_env(var: &str, fallback: &str) -> PathBuf {
        env::var_os(var)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(fallback))
    }

    fn runtime_directory_root() -> PathBuf {
        Self::default_path_from_env("SYSTEMD_RUNTIME_DIR_ROOT", "/run")
    }

    fn state_directory_root() -> PathBuf {
        Self::default_path_from_env("SYSTEMD_STATE_DIR_ROOT", "/var/lib")
    }

    fn cache_directory_root() -> PathBuf {
        Self::default_path_from_env("SYSTEMD_CACHE_DIR_ROOT", "/var/cache")
    }

    fn logs_directory_root() -> PathBuf {
        Self::default_path_from_env("SYSTEMD_LOGS_DIR_ROOT", "/var/log")
    }

    fn configuration_directory_root() -> PathBuf {
        Self::default_path_from_env("SYSTEMD_CONFIGURATION_DIR_ROOT", "/etc")
    }

    fn dynamic_uid_root() -> PathBuf {
        Self::default_path_from_env("SYSTEMD_DYNAMIC_UID_ROOT", "/run/systemd/dynamic-uid")
    }

    fn runtime_directory_is_preserved(exec: &ExecContextConfig) -> bool {
        exec.runtime_directory_preserve
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .is_some_and(|value| value == "yes" || value == "restart")
    }

    fn directory_mode_for(exec: &ExecContextConfig, kind: ManagedDirectoryKind) -> u32 {
        let mode = match kind {
            ManagedDirectoryKind::Runtime => exec.runtime_directory_mode,
            ManagedDirectoryKind::State => exec.state_directory_mode,
            ManagedDirectoryKind::Cache => exec.cache_directory_mode,
            ManagedDirectoryKind::Logs => exec.logs_directory_mode,
            ManagedDirectoryKind::Configuration => exec.configuration_directory_mode,
        }
        .or(exec.directory_mode)
        .unwrap_or(0o755);
        mode & 0o7777
    }

    fn normalize_exec_directory_item(item: &str) -> Option<PathBuf> {
        let trimmed = item.trim().trim_start_matches('/');
        if trimmed.is_empty() {
            return None;
        }

        let mut relative = PathBuf::new();
        for component in Path::new(trimmed).components() {
            match component {
                Component::Normal(part) => relative.push(part),
                _ => return None,
            }
        }

        if relative.as_os_str().is_empty() {
            None
        } else {
            Some(relative)
        }
    }

    fn parse_numeric_identity(value: Option<&String>) -> Option<u32> {
        value
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            // Match uid_is_valid()/gid_is_valid() in the C implementation:
            // both historical and native all-ones values are sentinels, not
            // identities that may be assigned to a service.
            .filter(|id| !matches!(*id, 0xffff | u32::MAX))
    }

    fn dynamic_uid_record_path(unit_name: &str) -> PathBuf {
        Self::dynamic_uid_root().join(format!("{}.uid", Self::cgroup_unit_component(unit_name)))
    }

    fn read_dynamic_uid_record(path: &Path) -> Option<(u32, u32)> {
        let content = fs::read_to_string(path).ok()?;
        let mut fields = content.trim().split(':');
        let uid = fields.next()?.trim().parse::<u32>().ok()?;
        let gid = fields.next()?.trim().parse::<u32>().ok()?;
        Some((uid, gid))
    }

    fn collect_used_dynamic_uids(root: &Path) -> BTreeSet<u32> {
        let mut used = BTreeSet::new();
        let Ok(entries) = fs::read_dir(root) else {
            return used;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some((uid, _gid)) = Self::read_dynamic_uid_record(&path) else {
                continue;
            };
            used.insert(uid);
        }

        used
    }

    fn allocate_dynamic_identity_for_unit(&mut self, unit_name: &str) -> Option<(u32, u32)> {
        if let Some(ids) = self.dynamic_service_ids.get(unit_name).copied() {
            return Some(ids);
        }

        let root = Self::dynamic_uid_root();
        fs::create_dir_all(&root).ok()?;

        let record_path = Self::dynamic_uid_record_path(unit_name);
        if let Some(ids) = Self::read_dynamic_uid_record(&record_path) {
            self.dynamic_service_ids.insert(unit_name.to_string(), ids);
            return Some(ids);
        }

        let used = Self::collect_used_dynamic_uids(&root);
        let span = DYNAMIC_UID_MAX
            .saturating_sub(DYNAMIC_UID_MIN)
            .saturating_add(1);
        if span == 0 {
            return None;
        }

        let mut hasher = DefaultHasher::new();
        unit_name.hash(&mut hasher);
        let start = (hasher.finish() as u32) % span;

        let mut selected = None;
        for offset in 0..span {
            let candidate = DYNAMIC_UID_MIN + ((start + offset) % span);
            if !used.contains(&candidate) {
                selected = Some(candidate);
                break;
            }
        }

        let uid = selected?;
        let gid = uid;
        fs::write(&record_path, format!("{uid}:{gid}\n")).ok()?;
        self.dynamic_service_ids
            .insert(unit_name.to_string(), (uid, gid));
        Some((uid, gid))
    }

    fn resolve_service_identity(
        &mut self,
        unit_name: &str,
        exec: &ExecContextConfig,
    ) -> Option<(Option<u32>, Option<u32>)> {
        if exec.dynamic_user.unwrap_or(false) {
            let (uid, gid) = self.allocate_dynamic_identity_for_unit(unit_name)?;
            return Some((Some(uid), Some(gid)));
        }

        // Named identity resolution still belongs to the remaining NSS/userdb
        // port. Until that exists, reject an explicitly configured identity
        // that is not a valid numeric UID/GID: silently treating `User=foo`
        // as no identity would otherwise launch the service as the manager.
        let user = match exec.user.as_ref() {
            Some(raw) => Some(Self::parse_numeric_identity(Some(raw))?),
            None => None,
        };
        let group = match exec.group.as_ref() {
            Some(raw) => Some(Self::parse_numeric_identity(Some(raw))?),
            None => user,
        };
        Some((user, group))
    }

    #[cfg(target_os = "linux")]
    fn maybe_apply_directory_owner(path: &Path, uid: Option<u32>, gid: Option<u32>) -> bool {
        if uid.is_none() && gid.is_none() {
            return true;
        }

        // SAFETY: geteuid() has no arguments, does not dereference memory, and
        // is safe to call from ordinary process context.
        if unsafe { libc::geteuid() } != 0 {
            return true;
        }
        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        let raw_uid = uid.unwrap_or(u32::MAX) as libc::uid_t;
        let raw_gid = gid.unwrap_or(u32::MAX) as libc::gid_t;

        // SAFETY: c_path is a live, NUL-terminated pathname for the duration
        // of the call. uid_t/gid_t all-ones are the documented "leave
        // unchanged" sentinels; every other value came from a validated u32.
        unsafe { libc::chown(c_path.as_ptr(), raw_uid, raw_gid) >= 0 }
    }

    #[cfg(not(target_os = "linux"))]
    fn maybe_apply_directory_owner(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) -> bool {
        true
    }

    fn ensure_exec_directories_for_kind(
        &self,
        root: &Path,
        entries: &[String],
        mode: u32,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Option<Vec<PathBuf>> {
        let mut created = Vec::new();
        for item in entries {
            let Some(relative) = Self::normalize_exec_directory_item(item) else {
                continue;
            };

            let full = root.join(relative);
            fs::create_dir_all(&full).ok()?;
            fs::set_permissions(&full, fs::Permissions::from_mode(mode)).ok()?;
            if !Self::maybe_apply_directory_owner(&full, uid, gid) {
                return None;
            }
            created.push(full);
        }
        Some(created)
    }

    fn setup_service_directories(&mut self, unit_name: &str, info: &UnitFileInfo) -> bool {
        let exec = &info.exec_context;
        let Some((uid, gid)) = self.resolve_service_identity(unit_name, exec) else {
            return false;
        };

        let runtime_mode = Self::directory_mode_for(exec, ManagedDirectoryKind::Runtime);
        let state_mode = Self::directory_mode_for(exec, ManagedDirectoryKind::State);
        let cache_mode = Self::directory_mode_for(exec, ManagedDirectoryKind::Cache);
        let logs_mode = Self::directory_mode_for(exec, ManagedDirectoryKind::Logs);
        let configuration_mode =
            Self::directory_mode_for(exec, ManagedDirectoryKind::Configuration);

        let runtime_dirs = self
            .ensure_exec_directories_for_kind(
                &Self::runtime_directory_root(),
                &exec.runtime_directory,
                runtime_mode,
                uid,
                gid,
            )
            .unwrap_or_default();
        if !exec.runtime_directory.is_empty() && runtime_dirs.is_empty() {
            return false;
        }

        if self
            .ensure_exec_directories_for_kind(
                &Self::state_directory_root(),
                &exec.state_directory,
                state_mode,
                uid,
                gid,
            )
            .is_none()
        {
            return false;
        }
        if self
            .ensure_exec_directories_for_kind(
                &Self::cache_directory_root(),
                &exec.cache_directory,
                cache_mode,
                uid,
                gid,
            )
            .is_none()
        {
            return false;
        }
        if self
            .ensure_exec_directories_for_kind(
                &Self::logs_directory_root(),
                &exec.logs_directory,
                logs_mode,
                uid,
                gid,
            )
            .is_none()
        {
            return false;
        }
        if self
            .ensure_exec_directories_for_kind(
                &Self::configuration_directory_root(),
                &exec.configuration_directory,
                configuration_mode,
                uid,
                gid,
            )
            .is_none()
        {
            return false;
        }

        if runtime_dirs.is_empty() {
            self.service_runtime_dirs.remove(unit_name);
        } else {
            self.service_runtime_dirs
                .insert(unit_name.to_string(), runtime_dirs);
        }
        true
    }

    pub(super) fn cleanup_runtime_directories_for_unit(
        &mut self,
        unit_name: &str,
        exec: &ExecContextConfig,
    ) {
        if Self::runtime_directory_is_preserved(exec) {
            return;
        }

        let Some(mut dirs) = self.service_runtime_dirs.remove(unit_name) else {
            return;
        };
        dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in dirs {
            let _ = fs::remove_dir_all(path);
        }
    }

    pub fn scan_unit_dirs(&mut self) -> Result<()> {
        for search_path in unit_search_paths() {
            let Ok(entries) = fs::read_dir(&search_path) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                match parse_unit_file(&path) {
                    Ok(Some(info)) => {
                        self.unit_files.entry(info.name.clone()).or_insert(info);
                    }
                    Ok(None) => {}
                    Err(_) => return Err(Errno::ENOEXEC),
                }
            }
        }
        Ok(())
    }

    fn submit_transaction_job(
        &mut self,
        name: &str,
        transaction_kind: TxJobType,
        mode: JobMode,
    ) -> Result<JobId> {
        let mut loading = BTreeSet::new();
        self.load_unit_recursive(name, &mut loading)?;
        let name = self.canonical_unit_name(name);

        let applied = self
            .build_transaction(&name, transaction_kind, mode)
            .map_err(|error| error.errno_value())?;
        let anchor_job = applied.anchor_job;
        let installed = self.execute_transaction(&applied)?;
        installed.get(&anchor_job).copied().ok_or(Errno::EIO)
    }

    #[cfg(test)]
    pub fn inject_test_unit(
        &mut self,
        name: &str,
        description: &str,
        active_state: ActiveState,
        sub_state: &str,
    ) {
        let mut unit = Unit::new(self.manager_record.clone(), UnitType::Target);
        unit.id = Some(name.to_string());
        unit.description = Some(description.to_string());
        unit.load_state = LoadState::Loaded;
        unit.active_state = active_state;
        unit.sub_state = sub_state.to_string();
        self.units.insert(name.to_string(), unit);
        self.unit_name_map
            .insert(name.to_string(), name.to_string());
    }

    #[cfg(test)]
    pub fn inject_test_installed_job(
        &mut self,
        id: JobId,
        unit_name: &str,
        kind: CanonicalJobType,
        state: crate::job_tables::JobState,
    ) {
        assert!(matches!(
            state,
            crate::job_tables::JobState::Waiting | crate::job_tables::JobState::Running
        ));
        assert!(self.job_registry.reserve_existing_id(id).is_ok());
        let mut job = Job::new(unit_name, kind, id);
        job.installed = true;
        job.set_state(state);
        self.installed_jobs.insert(id, job);
        self.units
            .get_mut(unit_name)
            .expect("test unit must exist before installing a job")
            .current_job_id = Some(id);
    }

    #[cfg(test)]
    pub fn inject_test_main_pid(&mut self, unit_name: &str, pid: u32) {
        if let Some(unit) = self.units.get_mut(unit_name) {
            unit.main_pid = Some(crate::unit::PidRef(pid));
            unit.control_pid = None;
            unit.watched_pids.insert(crate::unit::PidRef(pid));
            self.track_pid(unit_name, pid, TrackedPidRole::Main);
        }
    }

    #[cfg(test)]
    pub fn inject_test_invocation_id(&mut self, unit_name: &str, invocation_id: [u8; 16]) {
        if let Some(unit) = self.units.get_mut(unit_name) {
            unit.invocation_id = Some(invocation_id);
        }
    }

    pub fn load_unit(&mut self, name: &str) -> Result<()> {
        let key = self.canonical_unit_name(name);
        if self.units.contains_key(&key) {
            self.register_unit_alias(name, &key);
            return Ok(());
        }

        let search_paths = unit_search_paths();
        let loaded = load_unit_file_with_dropins(name, &search_paths)
            .map_err(|_| Errno::ENOEXEC)?
            .ok_or(Errno::ENOENT)?;
        let info = loaded.info;
        let key = info.name.clone();

        if self.units.contains_key(&key) {
            self.register_unit_alias(name, &key);
            if name != key
                && let Some(unit) = self.units.get_mut(&key)
            {
                unit.aliases.insert(name.to_string());
            }
            return Ok(());
        }

        self.unit_files.insert(key.clone(), info.clone());

        let mut unit = Unit::new(self.manager_record.clone(), info.unit_type);
        unit.id = Some(key.clone());
        unit.load_state = LoadState::Loaded;
        unit.description.clone_from(&info.description);
        unit.default_dependencies = info.default_dependencies;
        for alias in &loaded.aliases {
            unit.aliases.insert(alias.clone());
        }

        for dep_name in &info.requires {
            unit.dependency_set_mut(DependencyKind::Requires)
                .insert(dep_name.clone());
        }
        for dep_name in &info.requisite {
            unit.dependency_set_mut(DependencyKind::Requisite)
                .insert(dep_name.clone());
        }
        for dep_name in &info.wants {
            unit.dependency_set_mut(DependencyKind::Wants)
                .insert(dep_name.clone());
        }
        for dep_name in &info.binds_to {
            unit.dependency_set_mut(DependencyKind::BindsTo)
                .insert(dep_name.clone());
        }
        for dep_name in &info.upholds {
            unit.dependency_set_mut(DependencyKind::Upholds)
                .insert(dep_name.clone());
        }
        for dep_name in &info.part_of {
            unit.dependency_set_mut(DependencyKind::PartOf)
                .insert(dep_name.clone());
        }
        for dep_name in &info.after {
            unit.dependency_set_mut(DependencyKind::After)
                .insert(dep_name.clone());
        }
        for dep_name in &info.before {
            unit.dependency_set_mut(DependencyKind::Before)
                .insert(dep_name.clone());
        }
        for dep_name in &info.conflicts {
            unit.dependency_set_mut(DependencyKind::Conflicts)
                .insert(dep_name.clone());
        }
        for dep_name in &info.on_failure {
            unit.dependency_set_mut(DependencyKind::OnFailure)
                .insert(dep_name.clone());
        }
        for dep_name in &info.on_success {
            unit.dependency_set_mut(DependencyKind::OnSuccess)
                .insert(dep_name.clone());
        }

        if info.refuse_manual_start {
            unit.markers.insert(UnitMarker::RefuseManualStart);
        }
        if info.refuse_manual_stop {
            unit.markers.insert(UnitMarker::RefuseManualStop);
        }
        if info.allow_isolate {
            unit.markers.insert(UnitMarker::AllowIsolate);
        }

        if info.default_dependencies
            && matches!(
                info.unit_type,
                UnitType::Service
                    | UnitType::Socket
                    | UnitType::Mount
                    | UnitType::Swap
                    | UnitType::Path
                    | UnitType::Timer
                    | UnitType::Scope
            )
        {
            let _ = unit_set_default_slice(&mut unit);
            unit_add_slice_dependencies(&mut unit);
        }

        if matches!(
            info.unit_type,
            UnitType::Service | UnitType::Socket | UnitType::Mount | UnitType::Swap
        ) {
            apply_exec_context_config(&mut unit, &info.exec_context);
            apply_cgroup_config(&mut unit, &info.cgroup);
            apply_kill_config(&mut unit, &info.kill);
            if let Some(slice) = &info.cgroup.slice {
                unit.slice = Some(slice.clone());
            }
        }

        if info.unit_type == UnitType::Slice {
            apply_cgroup_config(&mut unit, &info.slice.cgroup);
        }

        if info.unit_type == UnitType::Scope {
            apply_cgroup_config(&mut unit, &info.scope.cgroup);
            let mut kill = unit.kill_context.clone().unwrap_or_default();
            if let Some(signal) = info.scope.kill_signal {
                kill.kill_signal = signal;
            }
            if let Some(signal) = info.scope.final_kill_signal {
                kill.final_kill_signal = signal;
            }
            unit.kill_context = Some(kill);
        }

        if info.unit_type == UnitType::Service {
            let mut svc = Service::default();
            crate::service::service_init(&mut svc, &self.service_manager);
            svc.service_type = infer_service_type(&info);
            if let Some(timeout) = info.service.timeout_start_sec {
                svc.timeout_start_usec = timeout.saturating_mul(1_000_000);
            }
            if let Some(timeout) = info.service.timeout_stop_sec {
                svc.timeout_stop_usec = timeout.saturating_mul(1_000_000);
            }
            if let Some(timeout) = info.service.timeout_abort_sec {
                svc.timeout_abort_usec = timeout.saturating_mul(1_000_000);
            }
            if let Some(restart) = info.service.restart_sec {
                svc.restart_usec = restart.saturating_mul(1_000_000);
            }
            if let Some(steps) = info.service.restart_steps {
                svc.restart_steps = steps;
            }
            if let Some(max_delay) = info.service.restart_max_delay_sec {
                svc.restart_max_delay_usec = max_delay.saturating_mul(1_000_000);
            }
            if let Some(runtime_max) = info.service.runtime_max_sec {
                svc.runtime_max_usec = runtime_max.saturating_mul(1_000_000);
            }
            if let Some(watchdog) = info.service.watchdog_sec {
                svc.watchdog_usec = watchdog.saturating_mul(1_000_000);
            }
            crate::service::service_configure_notify_access(
                &mut svc,
                info.service.notify_access,
                info.service.watchdog_sec,
                info.service.file_descriptor_store_max,
            );
            svc.state = ServiceState::Dead;
            self.services.insert(key.clone(), svc);
        }

        self.units.insert(key.clone(), unit);
        self.register_unit_alias(&key, &key);
        for alias in loaded.aliases {
            self.register_unit_alias(&alias, &key);
        }
        self.register_unit_alias(name, &key);
        Ok(())
    }

    fn load_unit_recursive(&mut self, name: &str, loading: &mut BTreeSet<String>) -> Result<()> {
        let loading_key = self.canonical_unit_name(name);
        if !loading.insert(loading_key.clone()) {
            return Ok(());
        }
        if !self.units.contains_key(&loading_key) {
            self.load_unit(name).inspect_err(|_| {
                loading.remove(&loading_key);
            })?;
        }
        if let Some(unit) = self.units.get(&loading_key).cloned() {
            for dep_kind in &[
                DependencyKind::Requires,
                DependencyKind::Requisite,
                DependencyKind::Wants,
                DependencyKind::BindsTo,
                DependencyKind::Upholds,
                DependencyKind::PartOf,
                DependencyKind::Conflicts,
            ] {
                if let Some(deps) = unit.dependencies.get(dep_kind) {
                    for dep_name in deps.clone() {
                        let _ = self.load_unit_recursive(&dep_name, loading);
                    }
                }
            }
        }

        loading.remove(&loading_key);
        Ok(())
    }

    pub fn load_all_units(&mut self) -> Result<()> {
        self.scan_unit_dirs()?;
        let names: Vec<String> = self.unit_files.keys().cloned().collect();
        let mut loading = BTreeSet::new();
        for name in &names {
            let _ = self.load_unit_recursive(name, &mut loading);
        }
        self.manager_record.known_units = self.units.keys().cloned().collect();
        Ok(())
    }

    fn unit_to_spec(&self, unit: &Unit) -> Option<UnitSpec> {
        let name = unit.id.as_deref()?;
        let state = match unit.active_state {
            ActiveState::Active
            | ActiveState::Refreshing
            | ActiveState::Reloading
            | ActiveState::Frozen => UnitState::Active,
            ActiveState::Activating => UnitState::Activating,
            ActiveState::Failed => UnitState::Failed,
            ActiveState::Maintenance => UnitState::Maintenance,
            _ => UnitState::Inactive,
        };
        let deps_start: Vec<String> = unit
            .dependencies
            .get(&DependencyKind::Requires)
            .into_iter()
            .flatten()
            .chain(
                unit.dependencies
                    .get(&DependencyKind::BindsTo)
                    .into_iter()
                    .flatten(),
            )
            .cloned()
            .collect();
        let deps_verify: Vec<String> = unit
            .dependencies
            .get(&DependencyKind::Requisite)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        let deps_start_ignored: Vec<String> = unit
            .dependencies
            .get(&DependencyKind::Wants)
            .into_iter()
            .flatten()
            .chain(
                unit.dependencies
                    .get(&DependencyKind::Upholds)
                    .into_iter()
                    .flatten(),
            )
            .cloned()
            .collect();
        let deps_stop: Vec<String> = self
            .units
            .values()
            .filter_map(|candidate| {
                let candidate_name = candidate.id.as_deref()?;
                [
                    DependencyKind::Requires,
                    DependencyKind::Requisite,
                    DependencyKind::BindsTo,
                    DependencyKind::PartOf,
                ]
                .into_iter()
                .any(|kind| {
                    candidate
                        .dependencies
                        .get(&kind)
                        .is_some_and(|dependencies| dependencies.contains(name))
                })
                .then_some(candidate_name.to_string())
            })
            .collect();
        let conflicts: Vec<String> = unit
            .dependencies
            .get(&DependencyKind::Conflicts)
            .into_iter()
            .flatten()
            .filter_map(|dependency| {
                let dependency = self.canonical_unit_name(dependency);
                self.units.contains_key(&dependency).then_some(dependency)
            })
            .collect();
        let conflicts_ignored: Vec<String> = self
            .units
            .values()
            .filter_map(|candidate| {
                let candidate_name = candidate.id.as_deref()?;
                candidate
                    .dependencies
                    .get(&DependencyKind::Conflicts)
                    .is_some_and(|dependencies| dependencies.contains(name))
                    .then_some(candidate_name.to_string())
            })
            .collect();
        let before: Vec<String> = unit
            .dependencies
            .get(&DependencyKind::Before)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        let after: Vec<String> = unit
            .dependencies
            .get(&DependencyKind::After)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        let triggered_by: Vec<String> = unit
            .dependencies
            .get(&DependencyKind::TriggeredBy)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        let parsed = self.unit_files.get(name);
        let mut deps_reload: BTreeSet<String> = parsed
            .into_iter()
            .flat_map(|info| info.propagates_reload_to.iter().cloned())
            .collect();
        deps_reload.extend(self.unit_files.values().filter_map(|candidate| {
            candidate
                .reload_propagated_from
                .iter()
                .any(|source| source == name)
                .then_some(candidate.name.clone())
        }));
        let installed_job = unit
            .current_job_id
            .and_then(|id| self.installed_jobs.get(&id))
            .and_then(|job| canonical_job_type_to_transaction(job.kind));
        Some(UnitSpec {
            id: name.to_string(),
            state,
            ignore_on_isolate: parsed.is_some_and(|info| info.ignore_on_isolate),
            installed_job,
            deps_start,
            deps_verify,
            deps_start_ignored,
            deps_stop,
            conflicts,
            conflicts_ignored,
            deps_reload: deps_reload.into_iter().collect(),
            before,
            after,
            triggered_by,
        })
    }

    pub fn build_transaction(
        &mut self,
        target: &str,
        job_type: TxJobType,
        mode: JobMode,
    ) -> std::result::Result<AppliedTransaction, TransactionError> {
        let mut loading = BTreeSet::new();
        let _ = self.load_unit_recursive(target, &mut loading);
        let target = self.canonical_unit_name(target);

        let specs: Vec<UnitSpec> = self
            .units
            .values()
            .filter_map(|u| self.unit_to_spec(u))
            .collect();

        let id = self.transaction_counter;
        self.transaction_counter += 1;

        if mode == JobMode::Isolate && job_type != TxJobType::Start {
            return Err(TransactionError::InvalidMode(
                "isolate mode requires start job".into(),
            ));
        }
        if mode == JobMode::Triggering && job_type != TxJobType::Stop {
            return Err(TransactionError::InvalidMode(
                "triggering mode requires stop job".into(),
            ));
        }
        if mode == JobMode::RestartDependencies && job_type != TxJobType::Start {
            return Err(TransactionError::InvalidMode(
                "restart-dependencies mode requires start job".into(),
            ));
        }

        let ignore_requirements = matches!(
            mode,
            JobMode::IgnoreDependencies | JobMode::IgnoreRequirements
        );
        let ignore_order = mode == JobMode::IgnoreDependencies;
        let restart_reverse_dependencies = mode == JobMode::RestartDependencies;

        let mut tx = Transaction::new(specs, mode == JobMode::ReplaceIrreversibly, id)?;
        tx.add_job_and_dependencies_with_policies(
            job_type,
            &target,
            None,
            true,
            false,
            ignore_order,
            ignore_requirements,
            restart_reverse_dependencies,
        )?;
        if mode == JobMode::Isolate {
            tx.add_isolate_jobs()?;
        }
        if mode == JobMode::Triggering {
            tx.add_triggering_jobs(&target)?;
        }
        let applied = tx.activate(mode)?;
        Ok(applied)
    }

    pub fn start_default_target(
        &mut self,
        in_initrd: bool,
        fallback_default_target: &str,
    ) -> Result<String> {
        // Match C: load the primary candidate and apply only its ENOENT fallback.
        let target = load_default_target_candidate(in_initrd, fallback_default_target, |name| {
            self.load_unit(name)
        })?;

        self.start_boot_target(&target)?;
        Ok(target)
    }

    /// Queue the initial boot target with the same isolation policy as
    /// `do_queue_default_job()` in `src/core/main.c`.
    ///
    /// The normal path is `JOB_ISOLATE`. C retries exactly once with
    /// `JOB_REPLACE` when isolation is refused, for example when a selected
    /// target has no `AllowIsolate=yes`.  Keep that exception here rather than
    /// weakening every named-target start to replacement semantics.
    pub fn start_boot_target(&mut self, target: &str) -> Result<()> {
        match self.start_named_target_with_mode(target, JobMode::Isolate) {
            Err(Errno::EPERM) => self.start_named_target_with_mode(target, JobMode::Replace),
            result => result,
        }
    }

    pub fn start_named_target(&mut self, target: &str) -> Result<()> {
        self.start_named_target_with_mode(target, JobMode::Replace)
    }

    fn start_named_target_with_mode(&mut self, target: &str, mode: JobMode) -> Result<()> {
        self.load_unit_recursive(target, &mut BTreeSet::new())?;
        let target = self.canonical_unit_name(target);
        // `manager_add_job(..., JOB_ISOLATE, ...)` rejects targets that do
        // not opt into isolation.  `start_boot_target()` owns C's explicit
        // EPERM-to-REPLACE compatibility retry; do not accidentally isolate
        // through a target that was never allowed to do so.
        if mode == JobMode::Isolate
            && !self
                .units
                .get(&target)
                .is_some_and(|unit| unit.markers.contains(&UnitMarker::AllowIsolate))
        {
            return Err(Errno::EPERM);
        }
        let target_dependency_names: BTreeSet<String> = self
            .units
            .get(&target)
            .ok_or(Errno::ENOENT)?
            .dependencies
            .iter()
            .filter(|(kind, _)| {
                matches!(
                    kind,
                    DependencyKind::Requires
                        | DependencyKind::Requisite
                        | DependencyKind::Wants
                        | DependencyKind::BindsTo
                        | DependencyKind::Upholds
                        | DependencyKind::PartOf
                )
            })
            .flat_map(|(_, dependencies)| dependencies.iter().cloned())
            .collect();
        let candidates: Vec<Unit> = target_dependency_names
            .iter()
            .filter_map(|name| {
                let canonical = self.canonical_unit_name(name);
                self.units.get(&canonical).cloned()
            })
            .collect();
        let target_unit = self.units.get_mut(&target).ok_or(Errno::ENOENT)?;
        for unit in &candidates {
            unit_add_default_target_dependency(unit, target_unit).map_err(|_| Errno::EIO)?;
        }

        let applied = self
            .build_transaction(&target, TxJobType::Start, mode)
            .map_err(|error| {
                eprintln!("systemd: cannot queue target {target}: {error}");
                error.errno_value()
            })?;
        let n = applied.jobs.len();
        self.execute_transaction(&applied)?;
        eprintln!("systemd: started {n} jobs for {target}");
        Ok(())
    }

    pub fn get_unit(&self, name: &str) -> Option<&Unit> {
        let name = self.canonical_unit_name(name);
        self.units.get(&name)
    }

    pub fn list_units(&self) -> Vec<&Unit> {
        self.units.values().collect()
    }

    pub fn start_unit(&mut self, name: &str) -> Result<()> {
        self.start_unit_with_mode(name, JobMode::Replace)
    }

    pub fn start_unit_with_mode(&mut self, name: &str, mode: JobMode) -> Result<()> {
        let mut loading = BTreeSet::new();
        self.load_unit_recursive(name, &mut loading)?;
        let name = self.canonical_unit_name(name);
        match self.build_transaction(&name, TxJobType::Start, mode) {
            Ok(applied) => self.execute_transaction(&applied).map(|_| ()),
            Err(error) => Err(error.errno_value()),
        }
    }

    pub fn stop_unit(&mut self, name: &str) -> Result<()> {
        self.stop_unit_with_mode(name, JobMode::Replace)
    }

    pub fn stop_unit_with_mode(&mut self, name: &str, mode: JobMode) -> Result<()> {
        let name = self.canonical_unit_name(name);
        match self.build_transaction(&name, TxJobType::Stop, mode) {
            Ok(applied) => self.execute_transaction(&applied).map(|_| ()),
            Err(error) => Err(error.errno_value()),
        }
    }

    pub fn restart_unit(&mut self, name: &str) -> Result<()> {
        self.restart_unit_with_mode(name, JobMode::Replace)
    }

    pub fn restart_unit_with_mode(&mut self, name: &str, mode: JobMode) -> Result<()> {
        let name = self.canonical_unit_name(name);
        match self.build_transaction(&name, TxJobType::Restart, mode) {
            Ok(applied) => self.execute_transaction(&applied).map(|_| ()),
            Err(error) => Err(error.errno_value()),
        }
    }

    pub fn reload_unit(&mut self, name: &str) -> Result<()> {
        let name = self.canonical_unit_name(name);
        match self.build_transaction(&name, TxJobType::Reload, JobMode::Replace) {
            Ok(applied) => self.execute_transaction(&applied).map(|_| ()),
            Err(error) => Err(error.errno_value()),
        }
    }

    pub fn isolate(&mut self, name: &str) -> Result<()> {
        let mut loading = BTreeSet::new();
        self.load_unit_recursive(name, &mut loading)?;
        let name = self.canonical_unit_name(name);

        let can_isolate = self
            .units
            .get(&name)
            .is_some_and(|unit| unit.markers.contains(&UnitMarker::AllowIsolate));
        if !can_isolate {
            return Err(Errno::EPERM);
        }

        match self.build_transaction(&name, TxJobType::Start, JobMode::Isolate) {
            Ok(applied) => {
                let keep_active: BTreeSet<String> = applied
                    .jobs
                    .iter()
                    .filter(|job| {
                        matches!(
                            job.job_type,
                            TxJobType::Start | TxJobType::Restart | TxJobType::Nop
                        )
                    })
                    .map(|job| job.unit.clone())
                    .collect();
                self.execute_transaction(&applied)?;

                let mut force_inactive = Vec::new();
                for (unit_name, unit) in &self.units {
                    let ignore_on_isolate = self
                        .unit_files
                        .get(unit_name)
                        .is_some_and(|info| info.ignore_on_isolate);
                    if keep_active.contains(unit_name) || ignore_on_isolate {
                        continue;
                    }

                    if unit.active_state == ActiveState::Active {
                        force_inactive.push(unit_name.clone());
                    }
                }
                for unit_name in force_inactive {
                    if self.services.contains_key(&unit_name) {
                        self.set_service_state(&unit_name, ServiceState::Dead);
                    } else {
                        self.publish_nonservice_state(&unit_name, ActiveState::Inactive);
                    }
                }
                Ok(())
            }
            Err(error) => Err(error.errno_value()),
        }
    }

    pub fn kill_unit(&mut self, name: &str, who: UnitKillWho, signal: i32) -> Result<usize> {
        let name = self.canonical_unit_name(name);
        let unit = self.units.get(&name).ok_or(Errno::ENOENT)?;
        let mut pids: BTreeSet<u32> = BTreeSet::new();

        if matches!(who, UnitKillWho::Main | UnitKillWho::All) {
            if let Some(pid) = self.unit_pid_map.get(&name).copied() {
                pids.insert(pid);
            }
            if let Some(pid) = unit.main_pid {
                pids.insert(pid.0);
            }
        }
        if matches!(who, UnitKillWho::Control | UnitKillWho::All)
            && let Some(pid) = unit.control_pid
        {
            pids.insert(pid.0);
        }
        if matches!(who, UnitKillWho::All) {
            for pid in &unit.watched_pids {
                pids.insert(pid.0);
            }
        }
        if pids.is_empty() {
            return Err(Errno::ENOENT);
        }

        let mut killed = 0usize;
        for pid in &pids {
            if self.process_tracker.signal(*pid, signal).is_ok() {
                killed += 1;
            }
        }
        if killed == 0 {
            return Err(Errno::ESRCH);
        }

        if let Some(unit) = self.units.get_mut(&name) {
            unit.stop_pending = true;
        }
        Ok(killed)
    }

    pub fn reset_failed(&mut self, name: &str) -> Result<()> {
        let name = self.canonical_unit_name(name);
        let unit = self.units.get_mut(&name).ok_or(Errno::ENOENT)?;
        unit_reset_failed(unit);
        if let Some(service) = self.services.get_mut(&name)
            && matches!(service.state, ServiceState::Failed)
        {
            service.state = ServiceState::Dead;
        }
        Ok(())
    }

    pub fn start_unit_async(&mut self, name: &str, mode: JobMode) -> Result<u32> {
        self.submit_transaction_job(name, TxJobType::Start, mode)
    }

    pub fn stop_unit_async(&mut self, name: &str, mode: JobMode) -> Result<u32> {
        self.submit_transaction_job(name, TxJobType::Stop, mode)
    }

    pub fn reload_unit_async(&mut self, name: &str) -> Result<u32> {
        self.submit_transaction_job(name, TxJobType::Reload, JobMode::Replace)
    }

    pub fn restart_unit_async(&mut self, name: &str, mode: JobMode) -> Result<u32> {
        self.submit_transaction_job(name, TxJobType::Restart, mode)
    }

    pub fn list_unit_files(&self) -> Vec<&UnitFileInfo> {
        self.unit_files.values().collect()
    }

    pub fn unit_count(&self) -> usize {
        self.units.len()
    }

    pub fn active_count(&self) -> usize {
        self.units
            .values()
            .filter(|u| u.active_state.is_active_or_reloading())
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.units
            .values()
            .filter(|u| u.active_state == ActiveState::Failed)
            .count()
    }

    /// Returns one non-owning event registration descriptor per listener.
    ///
    /// Callers must upgrade the weak owner immediately before registration or
    /// dispatch. A socket stop closes the manager-owned descriptor and makes
    /// every stale snapshot inert.
    pub fn get_socket_listeners(&self) -> Vec<ListenerDescriptor> {
        self.socket_mgr.listener_descriptors()
    }

    /// Return non-owning views of child exec-status channels awaiting a PID 1
    /// readiness event. The caller must never retain an owning descriptor or
    /// mutate a channel; only [`Self::observe_exec_status_ready`] advances it.
    #[cfg(target_os = "linux")]
    pub fn pending_exec_statuses(&self) -> Vec<PendingExecStatusDescriptor> {
        self.pending_exec_confirmations
            .iter()
            .map(|(&pid, (owner, _))| PendingExecStatusDescriptor {
                pid,
                owner: Rc::downgrade(owner),
            })
            .collect()
    }

    pub fn spawn_service_for_socket(&mut self, socket_unit: &str) -> Result<()> {
        let service_name = self
            .unit_files
            .get(socket_unit)
            .and_then(|info| {
                info.socket
                    .service
                    .clone()
                    .or_else(|| info.service_override.clone())
            })
            .unwrap_or_else(|| self.socket_mgr.associated_service(socket_unit));

        if self.socket_mgr.get(socket_unit).is_none() {
            eprintln!("systemd: socket activation: {socket_unit} is not listening");
            return Err(Errno::ENOTCONN);
        }
        // `Socket.Service=` is parsed as a service-only reference. Keep the public activation
        // boundary defensive as callers and tests can still construct UnitFileInfo directly.
        if !service_name.ends_with(".service") {
            eprintln!(
                "systemd: socket activation: {socket_unit} is associated with non-service unit {service_name}"
            );
            return Err(Errno::EINVAL);
        }
        self.load_unit(&service_name)?;
        if self
            .units
            .get(&service_name)
            .is_none_or(|unit| unit.unit_type != UnitType::Service)
        {
            eprintln!(
                "systemd: socket activation: {socket_unit} associated unit {service_name} did not load as a service"
            );
            return Err(Errno::EINVAL);
        }
        self.service_activation_sockets
            .entry(service_name.clone())
            .or_default()
            .insert(socket_unit.to_string());

        if self.units.get(&service_name).is_some_and(|unit| {
            matches!(
                unit.active_state,
                ActiveState::Activating
                    | ActiveState::Active
                    | ActiveState::Refreshing
                    | ActiveState::Reloading
                    | ActiveState::Frozen
            )
        }) {
            return Ok(());
        }

        self.start_unit_with_mode(&service_name, JobMode::Replace)?;
        if self
            .units
            .get(&service_name)
            .is_some_and(|unit| unit.active_state == ActiveState::Failed)
        {
            Err(Errno::ECHILD)
        } else {
            Ok(())
        }
    }

    /// Fail closed after a readiness-triggered activation error. Without the
    /// C trigger-rate-limit/job retry machinery, leaving a ready listener in
    /// epoll would create an unbounded PID 1 retry loop.
    pub fn fail_socket_activation(&mut self, socket_unit: &str) {
        self.execute_socket_stop(socket_unit);
        self.publish_nonservice_state(socket_unit, ActiveState::Failed);
    }
}

impl Default for RuntimeManager {
    fn default() -> Self {
        Self::new()
    }
}
