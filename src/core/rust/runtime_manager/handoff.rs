// SPDX-License-Identifier: LGPL-2.1-or-later

//! Duplicate-before-commit inventory for live manager handoff.
//!
//! This module intentionally has no serializer, adopter, or commit operation.
//! Preparation retains the exact `RuntimeManager` and duplicates transferable
//! kernel capabilities. Any validation or duplication failure returns that
//! original owner unchanged. A future versioned adopter must exist before a
//! point-of-no-return API can be added.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use super::RuntimeManager;
use super::cgroup_runtime::BorrowedCgroupFds;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandoffPurpose {
    ReloadInProcess,
    Reexecute,
    SwitchRoot,
    SoftReboot,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CgroupFdKind {
    Directory,
    ProcessesWrite,
    ProcessesRead,
    EventsRead,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum DescriptorRole {
    SocketListener { unit: String, port_index: usize },
    CgroupRoot,
    UnitCgroup { unit: String, kind: CgroupFdKind },
    CgroupInotify,
    BoundStopRetryTimer,
}

impl std::fmt::Display for DescriptorRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketListener { unit, port_index } => {
                write!(formatter, "socket listener {unit}[{port_index}]")
            }
            Self::CgroupRoot => formatter.write_str("manager cgroup root"),
            Self::UnitCgroup { unit, kind } => {
                write!(formatter, "unit cgroup {unit}/{kind:?}")
            }
            Self::CgroupInotify => formatter.write_str("cgroup inotify"),
            Self::BoundStopRetryTimer => formatter.write_str("BindsTo retry timer"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareHandoffError {
    DispatchInProgress,
    LiveJobUsesProcessLocalTime,
    JobRegistryNotQuiescent,
    InconsistentJobIndex,
    LiveProcessLacksStableIdentity,
    ServiceSequenceHasLiveProcessState,
    ServiceDeadlineUsesProcessLocalTime,
    PendingExecStatusParser,
    IdlePipeGateNeedsHandoff,
    UntypedServiceDescriptor {
        unit: String,
        field: &'static str,
        value: i32,
    },
    InconsistentCgroupIndex,
    InconsistentCgroupWatchIndex,
    ClosedSocketListener {
        unit: String,
        port_index: usize,
    },
    DuplicateDescriptorRole(String),
    DescriptorDuplication {
        role: String,
        raw_os_error: Option<i32>,
    },
}

impl std::fmt::Display for PrepareHandoffError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DispatchInProgress => {
                formatter.write_str("a manager dispatch queue is still executing")
            }
            Self::LiveJobUsesProcessLocalTime => {
                formatter.write_str("a live job contains process-local Instant timestamps")
            }
            Self::JobRegistryNotQuiescent => {
                formatter.write_str("the job ID registry retains untransferred ownership")
            }
            Self::InconsistentJobIndex => {
                formatter.write_str("unit job ownership indexes disagree")
            }
            Self::LiveProcessLacksStableIdentity => {
                formatter.write_str("a tracked process has no transferable pidfd identity")
            }
            Self::ServiceSequenceHasLiveProcessState => {
                formatter.write_str("a service command cursor retains live process state")
            }
            Self::ServiceDeadlineUsesProcessLocalTime => {
                formatter.write_str("a service deadline uses a process-local Instant")
            }
            Self::PendingExecStatusParser => {
                formatter.write_str("an exec-status pipe retains partial parser state")
            }
            Self::IdlePipeGateNeedsHandoff => formatter.write_str(
                "a Type=idle pipe gate has live manager-owned descriptors without a handoff format",
            ),
            Self::UntypedServiceDescriptor { unit, field, value } => write!(
                formatter,
                "{unit} retains untyped descriptor {field}={value}"
            ),
            Self::InconsistentCgroupIndex => {
                formatter.write_str("unit cgroup capability and path indexes disagree")
            }
            Self::InconsistentCgroupWatchIndex => {
                formatter.write_str("cgroup watch indexes are not a bijection")
            }
            Self::ClosedSocketListener { unit, port_index } => {
                write!(
                    formatter,
                    "socket listener {unit}[{port_index}] lost its owner"
                )
            }
            Self::DuplicateDescriptorRole(role) => {
                write!(formatter, "duplicate handoff descriptor role: {role}")
            }
            Self::DescriptorDuplication { role, raw_os_error } => {
                write!(formatter, "failed to duplicate {role}")?;
                if let Some(errno) = raw_os_error {
                    write!(formatter, ": errno {errno}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for PrepareHandoffError {}

pub(crate) struct RejectedLiveHandoff {
    runtime: Box<RuntimeManager>,
    error: PrepareHandoffError,
}

impl RejectedLiveHandoff {
    pub(crate) fn into_parts(self) -> (RuntimeManager, PrepareHandoffError) {
        (*self.runtime, self.error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandoffInventory {
    purpose: HandoffPurpose,
    unit_count: usize,
    job_count: usize,
    socket_listener_count: usize,
    unit_cgroup_count: usize,
    cgroup_watch_count: usize,
    descriptor_count: usize,
}

impl HandoffInventory {
    pub(crate) fn purpose(&self) -> HandoffPurpose {
        self.purpose
    }

    pub(crate) fn descriptor_count(&self) -> usize {
        self.descriptor_count
    }

    pub(crate) fn socket_listener_count(&self) -> usize {
        self.socket_listener_count
    }
}

struct DescriptorBundle(BTreeMap<DescriptorRole, OwnedFd>);

impl DescriptorBundle {
    fn insert(
        &mut self,
        role: DescriptorRole,
        descriptor: OwnedFd,
    ) -> Result<(), PrepareHandoffError> {
        match self.0.entry(role) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(descriptor);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(entry) => Err(
                PrepareHandoffError::DuplicateDescriptorRole(entry.key().to_string()),
            ),
        }
    }
}

#[must_use = "prepared handoff must be rolled back until a versioned adopter exists"]
pub(crate) struct PreparedLiveHandoff {
    original: RuntimeManager,
    inventory: HandoffInventory,
    _descriptors: DescriptorBundle,
}

impl PreparedLiveHandoff {
    pub(crate) fn inventory(&self) -> &HandoffInventory {
        &self.inventory
    }

    pub(crate) fn rollback(self) -> RuntimeManager {
        self.original
    }
}

fn reject(runtime: RuntimeManager, error: PrepareHandoffError) -> RejectedLiveHandoff {
    RejectedLiveHandoff {
        runtime: Box::new(runtime),
        error,
    }
}

fn validate_preflight(runtime: &RuntimeManager) -> Result<(), PrepareHandoffError> {
    // Keep this field list exhaustive and do not use `..`. Adding manager
    // state must fail compilation here until its handoff policy is explicit.
    let RuntimeManager {
        units,
        unit_files,
        unit_name_map,
        job_registry,
        installed_jobs,
        transaction_counter,
        manager_record,
        process_tracker,
        unit_pid_map,
        pid_to_unit_map,
        pid_role_map,
        service_command_sequences,
        service_operation_deadlines,
        job_redispatch_queue,
        job_run_queue,
        job_run_queue_dispatching,
        bound_stop_queue,
        bound_stop_queue_dispatching,
        bound_replace_dispatching,
        bound_stop_retry_deadlines,
        #[cfg(target_os = "linux")]
        bound_stop_retry_timer,
        service_restart_after_stop,
        #[cfg(target_os = "linux")]
        pending_exec_confirmations,
        #[cfg(target_os = "linux")]
        idle_pipe_gate,
        #[cfg(target_os = "linux")]
        idle_pipe_generation,
        service_restart_deadlines,
        service_runtime_deadlines,
        service_watchdog_deadlines,
        service_runtime_dirs,
        dynamic_service_ids,
        cgroup_root,
        unit_cgroups,
        unit_cgroup_paths,
        unit_cgroup_populated,
        #[cfg(target_os = "linux")]
        cgroup_inotify_fd,
        #[cfg(target_os = "linux")]
        cgroup_watch_by_wd,
        #[cfg(target_os = "linux")]
        cgroup_watch_by_unit,
        socket_mgr,
        service_activation_sockets,
        services,
        service_manager,
    } = runtime;

    // Scalar/path/configuration state remains owned by `original`. Listing it
    // here makes that retention policy explicit.
    let _retained_without_conversion = (
        unit_files,
        unit_name_map,
        transaction_counter,
        manager_record,
        bound_stop_queue,
        bound_stop_retry_deadlines,
        service_restart_after_stop,
        service_runtime_dirs,
        dynamic_service_ids,
        unit_cgroup_populated,
        socket_mgr,
        service_activation_sockets,
        service_manager,
    );
    let _duplicated_root_capability_owner = cgroup_root;
    #[cfg(target_os = "linux")]
    let _retained_linux_capability_owners = (
        bound_stop_retry_timer,
        cgroup_inotify_fd,
        idle_pipe_generation,
    );

    if *job_run_queue_dispatching || *bound_stop_queue_dispatching || *bound_replace_dispatching {
        return Err(PrepareHandoffError::DispatchInProgress);
    }
    if !installed_jobs.is_empty() || !job_redispatch_queue.is_empty() || !job_run_queue.is_empty() {
        return Err(PrepareHandoffError::LiveJobUsesProcessLocalTime);
    }
    if job_registry.has_allocated_ids() {
        return Err(PrepareHandoffError::JobRegistryNotQuiescent);
    }
    if units.values().any(|unit| unit.current_job_id.is_some())
        || !service_restart_after_stop.is_empty()
    {
        return Err(PrepareHandoffError::InconsistentJobIndex);
    }
    if !process_tracker.pids().is_empty()
        || !unit_pid_map.is_empty()
        || !pid_to_unit_map.is_empty()
        || !pid_role_map.is_empty()
        || units.iter().any(|(_, unit)| {
            !unit.watched_pids.is_empty() || unit.main_pid.is_some() || unit.control_pid.is_some()
        })
        || services
            .values()
            .any(|service| service.main_pid.is_some() || service.control_pid.is_some())
    {
        return Err(PrepareHandoffError::LiveProcessLacksStableIdentity);
    }
    if !service_command_sequences.is_empty() {
        return Err(PrepareHandoffError::ServiceSequenceHasLiveProcessState);
    }
    if !service_operation_deadlines.is_empty()
        || !service_restart_deadlines.is_empty()
        || !service_runtime_deadlines.is_empty()
        || !service_watchdog_deadlines.is_empty()
    {
        return Err(PrepareHandoffError::ServiceDeadlineUsesProcessLocalTime);
    }
    #[cfg(target_os = "linux")]
    if !pending_exec_confirmations.is_empty() {
        return Err(PrepareHandoffError::PendingExecStatusParser);
    }
    #[cfg(target_os = "linux")]
    if idle_pipe_gate.is_some() {
        return Err(PrepareHandoffError::IdlePipeGateNeedsHandoff);
    }

    for (unit, service) in services {
        for (field, value) in [
            ("socket_fd", service.socket_fd),
            ("stdin_fd", service.stdin_fd),
            ("stdout_fd", service.stdout_fd),
            ("stderr_fd", service.stderr_fd),
            ("root_directory_fd", service.root_directory_fd),
        ] {
            if value >= 0 {
                return Err(PrepareHandoffError::UntypedServiceDescriptor {
                    unit: unit.clone(),
                    field,
                    value,
                });
            }
        }
    }

    let cgroup_units = unit_cgroups.keys().collect::<BTreeSet<_>>();
    let cgroup_path_units = unit_cgroup_paths.keys().collect::<BTreeSet<_>>();
    let cgroup_populated_units = unit_cgroup_populated.keys().collect::<BTreeSet<_>>();
    if cgroup_units != cgroup_path_units
        || cgroup_units != cgroup_populated_units
        || unit_cgroups.iter().any(|(unit, cgroup)| {
            unit_cgroup_paths
                .get(unit)
                .is_none_or(|path| cgroup.path() != path)
        })
    {
        return Err(PrepareHandoffError::InconsistentCgroupIndex);
    }

    #[cfg(target_os = "linux")]
    {
        let watches_match = cgroup_watch_by_wd.len() == cgroup_watch_by_unit.len()
            && cgroup_watch_by_unit.len() == unit_cgroups.len()
            && cgroup_watch_by_wd.iter().all(|(watch, unit)| {
                *watch >= 0
                    && unit_cgroups.contains_key(unit)
                    && cgroup_watch_by_unit
                        .get(unit)
                        .is_some_and(|other| other == watch)
            })
            && cgroup_watch_by_unit.iter().all(|(unit, watch)| {
                *watch >= 0
                    && unit_cgroups.contains_key(unit)
                    && cgroup_watch_by_wd
                        .get(watch)
                        .is_some_and(|other| other == unit)
            });
        if !watches_match
            || (cgroup_inotify_fd.is_none()
                && (!cgroup_watch_by_wd.is_empty() || !cgroup_watch_by_unit.is_empty()))
        {
            return Err(PrepareHandoffError::InconsistentCgroupWatchIndex);
        }
    }

    Ok(())
}

fn duplication_error(role: &DescriptorRole, error: std::io::Error) -> PrepareHandoffError {
    PrepareHandoffError::DescriptorDuplication {
        role: role.to_string(),
        raw_os_error: error.raw_os_error(),
    }
}

fn duplicate_cgroup_fds<F>(
    bundle: &mut DescriptorBundle,
    unit: &str,
    fds: BorrowedCgroupFds<'_>,
    duplicate: &mut F,
) -> Result<(), PrepareHandoffError>
where
    F: for<'fd> FnMut(&DescriptorRole, BorrowedFd<'fd>) -> io::Result<OwnedFd>,
{
    for (kind, descriptor) in [
        (CgroupFdKind::Directory, fds.directory),
        (CgroupFdKind::ProcessesWrite, fds.processes_write),
        (CgroupFdKind::ProcessesRead, fds.processes_read),
        (CgroupFdKind::EventsRead, fds.events_read),
    ] {
        let role = DescriptorRole::UnitCgroup {
            unit: unit.to_string(),
            kind,
        };
        let descriptor =
            duplicate(&role, descriptor).map_err(|error| duplication_error(&role, error))?;
        bundle.insert(role, descriptor)?;
    }
    Ok(())
}

fn duplicate_descriptors_with<F>(
    runtime: &RuntimeManager,
    mut duplicate: F,
) -> Result<DescriptorBundle, PrepareHandoffError>
where
    F: for<'fd> FnMut(&DescriptorRole, BorrowedFd<'fd>) -> io::Result<OwnedFd>,
{
    let mut bundle = DescriptorBundle(BTreeMap::new());

    let role = DescriptorRole::CgroupRoot;
    let root = runtime
        .cgroup_root
        .handoff_fd()
        .map_err(|error| duplication_error(&role, error))?;
    let descriptor = duplicate(&role, root).map_err(|error| duplication_error(&role, error))?;
    bundle.insert(role, descriptor)?;

    for listener in runtime.socket_mgr.listener_descriptors() {
        let role = DescriptorRole::SocketListener {
            unit: listener.unit_name().to_string(),
            port_index: listener.port_index(),
        };
        let owner =
            listener
                .upgrade()
                .ok_or_else(|| PrepareHandoffError::ClosedSocketListener {
                    unit: listener.unit_name().to_string(),
                    port_index: listener.port_index(),
                })?;
        let descriptor =
            duplicate(&role, owner.as_fd()).map_err(|error| duplication_error(&role, error))?;
        bundle.insert(role, descriptor)?;
    }

    let mut cgroup_units = runtime.unit_cgroups.keys().collect::<Vec<_>>();
    cgroup_units.sort_unstable();
    for unit in cgroup_units {
        let cgroup = &runtime.unit_cgroups[unit];
        duplicate_cgroup_fds(&mut bundle, unit, cgroup.handoff_fds(), &mut duplicate)?;
    }

    #[cfg(target_os = "linux")]
    if let Some(inotify) = &runtime.cgroup_inotify_fd {
        let role = DescriptorRole::CgroupInotify;
        let descriptor =
            duplicate(&role, inotify.as_fd()).map_err(|error| duplication_error(&role, error))?;
        bundle.insert(role, descriptor)?;
    }

    #[cfg(target_os = "linux")]
    if let Some(timer) = &runtime.bound_stop_retry_timer {
        let role = DescriptorRole::BoundStopRetryTimer;
        let descriptor =
            duplicate(&role, timer.as_fd()).map_err(|error| duplication_error(&role, error))?;
        bundle.insert(role, descriptor)?;
    }

    Ok(bundle)
}

impl RuntimeManager {
    pub(crate) fn prepare_live_handoff(
        self,
        purpose: HandoffPurpose,
    ) -> Result<PreparedLiveHandoff, RejectedLiveHandoff> {
        self.prepare_live_handoff_with(purpose, |_, descriptor| descriptor.try_clone_to_owned())
    }

    fn prepare_live_handoff_with<F>(
        self,
        purpose: HandoffPurpose,
        duplicate: F,
    ) -> Result<PreparedLiveHandoff, RejectedLiveHandoff>
    where
        F: for<'fd> FnMut(&DescriptorRole, BorrowedFd<'fd>) -> io::Result<OwnedFd>,
    {
        if let Err(error) = validate_preflight(&self) {
            return Err(reject(self, error));
        }

        let descriptors = match duplicate_descriptors_with(&self, duplicate) {
            Ok(descriptors) => descriptors,
            Err(error) => return Err(reject(self, error)),
        };
        let inventory = HandoffInventory {
            purpose,
            unit_count: self.units.len(),
            job_count: self.installed_jobs.len(),
            socket_listener_count: self.socket_mgr.listener_descriptors().len(),
            unit_cgroup_count: self.unit_cgroups.len(),
            #[cfg(target_os = "linux")]
            cgroup_watch_count: self.cgroup_watch_by_wd.len(),
            #[cfg(not(target_os = "linux"))]
            cgroup_watch_count: 0,
            descriptor_count: descriptors.0.len(),
        };
        Ok(PreparedLiveHandoff {
            original: self,
            inventory,
            _descriptors: descriptors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::Service;
    use crate::unit::ActiveState;
    use std::sync::Weak;
    #[test]
    fn successful_preparation_can_only_roll_back_the_exact_manager() {
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "preserved.target",
            "preserved",
            ActiveState::Active,
            "active",
        );
        runtime
            .socket_mgr
            .register_socket("listener.socket", "127.0.0.1:0")
            .unwrap();
        let listener = runtime.socket_mgr.listener_descriptors().remove(0);
        let original_owner = listener.weak_fd().clone();
        assert_eq!(original_owner.strong_count(), 1);

        let prepared = runtime
            .prepare_live_handoff(HandoffPurpose::ReloadInProcess)
            .unwrap_or_else(|rejected| panic!("preparation rejected: {}", rejected.error));
        assert_eq!(
            prepared.inventory().purpose(),
            HandoffPurpose::ReloadInProcess
        );
        assert_eq!(prepared.inventory().socket_listener_count(), 1);
        assert!(prepared.inventory().descriptor_count() >= 1);

        let runtime = prepared.rollback();
        assert_eq!(
            runtime
                .get_unit("preserved.target")
                .map(|unit| unit.active_state),
            Some(ActiveState::Active)
        );
        let rolled_back_listener = runtime.socket_mgr.listener_descriptors().remove(0);
        assert!(Weak::ptr_eq(
            &original_owner,
            rolled_back_listener.weak_fd()
        ));
        assert_eq!(original_owner.strong_count(), 1);
        assert!(original_owner.upgrade().is_some());
    }

    #[test]
    fn rejection_returns_the_unchanged_manager_before_duplication() {
        let mut runtime = RuntimeManager::new();
        runtime.services.insert(
            "unsafe.service".to_string(),
            Service {
                socket_fd: 9,
                ..Service::default()
            },
        );

        let rejected = match runtime.prepare_live_handoff(HandoffPurpose::Reexecute) {
            Ok(_) => panic!("untyped descriptor must reject reexec"),
            Err(rejected) => rejected,
        };
        let (runtime, error) = rejected.into_parts();
        assert!(matches!(
            error,
            PrepareHandoffError::UntypedServiceDescriptor {
                field: "socket_fd",
                value: 9,
                ..
            }
        ));
        assert_eq!(runtime.services["unsafe.service"].socket_fd, 9);
    }

    #[test]
    fn dangling_unit_job_identity_rejects_handoff() {
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "dangling.service",
            "dangling",
            ActiveState::Inactive,
            "dead",
        );
        runtime
            .units
            .get_mut("dangling.service")
            .unwrap()
            .current_job_id = Some(7);

        let rejected = match runtime.prepare_live_handoff(HandoffPurpose::ReloadInProcess) {
            Ok(_) => panic!("dangling unit job identity must reject handoff"),
            Err(rejected) => rejected,
        };
        let (runtime, error) = rejected.into_parts();
        assert_eq!(error, PrepareHandoffError::InconsistentJobIndex);
        assert_eq!(runtime.units["dangling.service"].current_job_id, Some(7));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn partial_descriptor_duplication_failure_preserves_owners() {
        let mut runtime = RuntimeManager::new();
        runtime
            .socket_mgr
            .register_socket("first.socket", "127.0.0.1:0")
            .unwrap();
        runtime
            .socket_mgr
            .register_socket("second.socket", "127.0.0.1:0")
            .unwrap();
        let original_listeners = runtime
            .socket_mgr
            .listener_descriptors()
            .into_iter()
            .map(|listener| {
                (
                    (listener.unit_name().to_string(), listener.port_index()),
                    listener.weak_fd().clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(
            original_listeners
                .values()
                .all(|listener| listener.strong_count() == 1)
        );
        let mut duplicated = 0;

        let rejected = match runtime.prepare_live_handoff_with(
            HandoffPurpose::ReloadInProcess,
            |_, descriptor| {
                duplicated += 1;
                if duplicated == 2 {
                    Err(io::Error::other("injected descriptor duplication failure"))
                } else {
                    descriptor.try_clone_to_owned()
                }
            },
        ) {
            Ok(_) => panic!("injected second descriptor failure must reject handoff"),
            Err(rejected) => rejected,
        };
        let (runtime, error) = rejected.into_parts();
        assert!(matches!(
            error,
            PrepareHandoffError::DescriptorDuplication { .. }
        ));
        let rolled_back_listeners = runtime
            .socket_mgr
            .listener_descriptors()
            .into_iter()
            .map(|listener| {
                (
                    (listener.unit_name().to_string(), listener.port_index()),
                    listener.weak_fd().clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(rolled_back_listeners.len(), 2);
        for (role, original) in original_listeners {
            let rolled_back = &rolled_back_listeners[&role];
            assert!(Weak::ptr_eq(&original, rolled_back));
            assert_eq!(original.strong_count(), 1);
            assert!(original.upgrade().is_some());
        }
    }
}
