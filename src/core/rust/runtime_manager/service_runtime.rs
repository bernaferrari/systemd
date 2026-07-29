// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Own service state transitions, child tracking, deadlines, and process execution. Job and
 * transaction construction stays with RuntimeManager; cgroup realization stays in cgroup_runtime.
 */
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use super::unit_file::{ExecContextConfig, UnitFileInfo};
use super::unit_load::{UnitConditionEvaluation, unit_condition_evaluation};
use super::{
    ChildExitCleanMode, PreparedStdio, Result, RuntimeManager, StdioFd, StdioSpec, StdioTargetMode,
    TrackedPidRole, child_state_considered_clean_with_mode, infer_service_type, specs_or_single,
};
use crate::ffi::Errno;
use crate::service::{
    ServiceState, ServiceType, service_record_reload_result, service_record_result,
    service_reset_reload_result, service_reset_result, service_restart_usec_next,
};
use crate::service_tables::{ServiceExecCommand, ServiceResult};
use crate::transaction::{JobMode, JobType as TxJobType};
use crate::unit::DependencyKind;
use systemd_libsystemd_rs::sd_journal_send::sd_journal_stream_fd;
use systemd_platform_rs::spawn::{self, ChildProcess, ChildState};

use super::service_machine::{
    ServiceCommandSequence, ServiceOperationDeadline, ServiceOperationOwner, pid_role_for_command,
    start_post_after_fork,
};

impl RuntimeManager {
    pub(super) fn clear_service_tracking(&mut self, name: &str) {
        self.service_operation_deadlines.remove(name);
        self.service_runtime_deadlines.remove(name);
        self.service_watchdog_deadlines.remove(name);
    }

    pub(super) fn arm_running_deadlines(&mut self, name: &str, info: &UnitFileInfo) {
        self.service_operation_deadlines.remove(name);

        if let Some(runtime_max_sec) = info.service.runtime_max_sec {
            if runtime_max_sec > 0 {
                self.service_runtime_deadlines
                    .entry(name.to_string())
                    .or_insert_with(|| Instant::now() + Duration::from_secs(runtime_max_sec));
            } else {
                self.service_runtime_deadlines.remove(name);
            }
        } else {
            self.service_runtime_deadlines.remove(name);
        }

        if let Some(watchdog_sec) = info.service.watchdog_sec {
            if watchdog_sec > 0 {
                self.service_watchdog_deadlines
                    .entry(name.to_string())
                    .or_insert_with(|| Instant::now() + Duration::from_secs(watchdog_sec));
            } else {
                self.service_watchdog_deadlines.remove(name);
            }
        } else {
            self.service_watchdog_deadlines.remove(name);
        }
    }

    pub(super) fn trigger_dependency_units(&mut self, name: &str, kind: DependencyKind) {
        let units: Vec<String> = self
            .units
            .get(name)
            .and_then(|u| u.dependencies.get(&kind))
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        for dep in units {
            let _ = self.start_unit(&dep);
        }
    }

    pub(super) fn service_kill_signal(&self, name: &str, fallback: i32) -> i32 {
        self.units
            .get(name)
            .and_then(|u| u.kill_context.as_ref())
            .map(|k| k.kill_signal)
            .filter(|s| *s > 0)
            .unwrap_or(fallback)
    }

    pub(super) fn parse_stdio_spec(value: Option<&str>) -> StdioSpec {
        let raw = value.unwrap_or("inherit").trim();
        if raw.is_empty() || raw.eq_ignore_ascii_case("inherit") {
            return StdioSpec {
                mode: StdioTargetMode::Inherit,
                payload: None,
            };
        }
        if raw.eq_ignore_ascii_case("null") {
            return StdioSpec {
                mode: StdioTargetMode::Null,
                payload: None,
            };
        }
        if raw.eq_ignore_ascii_case("tty")
            || raw.eq_ignore_ascii_case("tty-force")
            || raw.eq_ignore_ascii_case("tty-fail")
        {
            return StdioSpec {
                mode: StdioTargetMode::Tty,
                payload: None,
            };
        }
        if raw.eq_ignore_ascii_case("journal") {
            return StdioSpec {
                mode: StdioTargetMode::Journal,
                payload: None,
            };
        }
        if raw.eq_ignore_ascii_case("journal+console") {
            return StdioSpec {
                mode: StdioTargetMode::JournalAndConsole,
                payload: None,
            };
        }
        if raw.eq_ignore_ascii_case("kmsg") {
            return StdioSpec {
                mode: StdioTargetMode::Kmsg,
                payload: None,
            };
        }
        if raw.eq_ignore_ascii_case("kmsg+console") {
            return StdioSpec {
                mode: StdioTargetMode::KmsgAndConsole,
                payload: None,
            };
        }
        if raw.eq_ignore_ascii_case("socket") {
            return StdioSpec {
                mode: StdioTargetMode::Socket,
                payload: None,
            };
        }
        if let Some(rest) = raw.strip_prefix("fd:") {
            return StdioSpec {
                mode: StdioTargetMode::NamedFd,
                payload: Some(rest.to_string()),
            };
        }
        if let Some(rest) = raw.strip_prefix("file:") {
            return StdioSpec {
                mode: StdioTargetMode::File,
                payload: Some(rest.to_string()),
            };
        }
        if let Some(rest) = raw.strip_prefix("append:") {
            return StdioSpec {
                mode: StdioTargetMode::Append,
                payload: Some(rest.to_string()),
            };
        }
        if let Some(rest) = raw.strip_prefix("truncate:") {
            return StdioSpec {
                mode: StdioTargetMode::Truncate,
                payload: Some(rest.to_string()),
            };
        }
        StdioSpec {
            mode: StdioTargetMode::Other,
            payload: Some(raw.to_string()),
        }
    }

    pub(super) fn parse_syslog_priority(level: Option<&str>) -> i32 {
        match level.unwrap_or("info").to_ascii_lowercase().as_str() {
            "emerg" | "panic" => 0,
            "alert" => 1,
            "crit" | "critical" => 2,
            "err" | "error" => 3,
            "warning" | "warn" => 4,
            "notice" => 5,
            "info" => 6,
            "debug" => 7,
            _ => 6,
        }
    }

    pub(super) fn open_read_fd(path: &str) -> Option<OwnedFd> {
        OpenOptions::new()
            .read(true)
            .open(path)
            .ok()
            .map(Into::into)
    }

    pub(super) fn open_write_fd(
        path: &str,
        create: bool,
        append: bool,
        truncate: bool,
    ) -> Option<OwnedFd> {
        OpenOptions::new()
            .write(true)
            .create(create)
            .append(append)
            .truncate(truncate)
            .open(path)
            .ok()
            .map(Into::into)
    }

    pub(super) fn socket_activation_fd_for_service(
        &self,
        unit_name: &str,
        info: &UnitFileInfo,
    ) -> Option<RawFd> {
        for socket in &info.service.sockets {
            if let Some(fd) = self.socket_mgr.get(socket).and_then(|s| s.raw_fd()) {
                return Some(fd);
            }
        }

        let implicit = unit_name
            .strip_suffix(".service")
            .map(|base| format!("{base}.socket"))?;
        self.socket_mgr.get(&implicit).and_then(|s| s.raw_fd())
    }

    pub(super) fn resolve_input_stdio_fd(
        &self,
        unit_name: &str,
        info: &UnitFileInfo,
        spec: &StdioSpec,
    ) -> Option<StdioFd> {
        match spec.mode {
            StdioTargetMode::Inherit => None,
            StdioTargetMode::Null => Self::open_read_fd("/dev/null").map(StdioFd::Owned),
            StdioTargetMode::Tty => {
                let tty = info
                    .exec_context
                    .tty_path
                    .as_deref()
                    .unwrap_or("/dev/console");
                Self::open_read_fd(tty).map(StdioFd::Owned)
            }
            StdioTargetMode::Socket => self
                .socket_activation_fd_for_service(unit_name, info)
                .map(StdioFd::Borrowed),
            StdioTargetMode::NamedFd => spec
                .payload
                .as_deref()
                .and_then(|value| value.parse::<i32>().ok())
                .map(StdioFd::Borrowed),
            StdioTargetMode::File | StdioTargetMode::Append | StdioTargetMode::Truncate => spec
                .payload
                .as_deref()
                .and_then(Self::open_read_fd)
                .map(StdioFd::Owned),
            _ => None,
        }
    }

    pub(super) fn resolve_output_stdio_fd(
        &self,
        unit_name: &str,
        info: &UnitFileInfo,
        spec: &StdioSpec,
    ) -> Option<(StdioFd, bool)> {
        match spec.mode {
            StdioTargetMode::Inherit => None,
            StdioTargetMode::Null => Self::open_write_fd("/dev/null", false, false, false)
                .map(|fd| (StdioFd::Owned(fd), false)),
            StdioTargetMode::Tty => {
                let tty = info
                    .exec_context
                    .tty_path
                    .as_deref()
                    .unwrap_or("/dev/console");
                Self::open_write_fd(tty, false, false, false).map(|fd| (StdioFd::Owned(fd), false))
            }
            StdioTargetMode::Journal | StdioTargetMode::JournalAndConsole => {
                let ident = info
                    .exec_context
                    .syslog_identifier
                    .as_deref()
                    .or(Some(unit_name));
                let prio = Self::parse_syslog_priority(info.exec_context.syslog_level.as_deref());
                let fd = Self::journal_stream_fd(ident, prio)
                    .or_else(|| Self::open_write_fd("/dev/null", false, false, false))?;
                Some((
                    StdioFd::Owned(fd),
                    matches!(spec.mode, StdioTargetMode::JournalAndConsole),
                ))
            }
            StdioTargetMode::Kmsg | StdioTargetMode::KmsgAndConsole => {
                let fd = Self::open_write_fd("/dev/kmsg", false, false, false)
                    .or_else(|| Self::open_write_fd("/dev/null", false, false, false))?;
                Some((
                    StdioFd::Owned(fd),
                    matches!(spec.mode, StdioTargetMode::KmsgAndConsole),
                ))
            }
            StdioTargetMode::Socket => self
                .socket_activation_fd_for_service(unit_name, info)
                .map(|fd| (StdioFd::Borrowed(fd), false)),
            StdioTargetMode::NamedFd => spec
                .payload
                .as_deref()
                .and_then(|value| value.parse::<i32>().ok())
                .map(|fd| (StdioFd::Borrowed(fd), false)),
            StdioTargetMode::File => spec
                .payload
                .as_deref()
                .and_then(|p| Self::open_write_fd(p, true, false, false))
                .map(|fd| (StdioFd::Owned(fd), false)),
            StdioTargetMode::Append => spec
                .payload
                .as_deref()
                .and_then(|p| Self::open_write_fd(p, true, true, false))
                .map(|fd| (StdioFd::Owned(fd), false)),
            StdioTargetMode::Truncate => spec
                .payload
                .as_deref()
                .and_then(|p| Self::open_write_fd(p, true, false, true))
                .map(|fd| (StdioFd::Owned(fd), false)),
            StdioTargetMode::Other => None,
        }
    }

    pub(super) fn prepare_service_stdio(
        &self,
        unit_name: &str,
        info: &UnitFileInfo,
    ) -> PreparedStdio {
        let mut prepared = PreparedStdio::default();
        let stdin_spec = Self::parse_stdio_spec(info.exec_context.standard_input.as_deref());
        if let Some(fd) = self.resolve_input_stdio_fd(unit_name, info, &stdin_spec) {
            prepared.stdio.stdin_fd = Some(fd.into_raw_for(&mut prepared));
        }

        let stdout_spec = Self::parse_stdio_spec(info.exec_context.standard_output.as_deref());
        let mut stdout_console_mirror = false;
        if let Some((fd, mirror)) = self.resolve_output_stdio_fd(unit_name, info, &stdout_spec) {
            prepared.stdio.stdout_fd = Some(fd.into_raw_for(&mut prepared));
            stdout_console_mirror = mirror;
        }

        let stderr_spec = Self::parse_stdio_spec(info.exec_context.standard_error.as_deref());
        if let Some((fd, _)) = self.resolve_output_stdio_fd(unit_name, info, &stderr_spec) {
            prepared.stdio.stderr_fd = Some(fd.into_raw_for(&mut prepared));
        } else if stdout_console_mirror {
            if let Some(fd) = Self::open_write_fd("/dev/console", false, false, false) {
                prepared.stdio.stderr_fd = Some(prepared.retain_owned_fd(fd));
            }
        }

        prepared
    }

    fn journal_stream_fd(ident: Option<&str>, priority: i32) -> Option<OwnedFd> {
        let fd = sd_journal_stream_fd(ident, priority, 1).ok()?;
        if fd < 0 {
            return None;
        }
        // SAFETY: sd_journal_stream_fd() returns a newly-created descriptor
        // on success. Convert its documented ownership to RAII immediately.
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub(super) fn build_spawn_security(
        &mut self,
        unit_name: &str,
        exec: &ExecContextConfig,
        command_prefixes: &str,
    ) -> spawn::SpawnSecurity {
        let mut system_call_filter = exec.system_call_filter.clone();
        system_call_filter.extend(exec.seccomp_filter.iter().cloned());
        let (resolved_uid, resolved_gid) = self
            .resolve_service_identity(unit_name, exec)
            .unwrap_or((None, None));

        let user = if exec.user.is_some() {
            exec.user.clone()
        } else {
            resolved_uid.map(|id| id.to_string())
        };
        let group = if exec.group.is_some() {
            exec.group.clone()
        } else {
            resolved_gid.map(|id| id.to_string())
        };

        spawn::SpawnSecurity {
            capability_bounding_set: exec.capability_bounding_set.clone(),
            ambient_capabilities: exec.ambient_capabilities.clone(),
            no_new_privileges: exec.no_new_privileges.unwrap_or(false),
            secure_bits: exec.secure_bits.clone(),
            system_call_filter,
            system_call_error_number: exec.system_call_error_number.clone(),
            system_call_architectures: exec.system_call_architectures.clone(),
            private_tmp: exec.private_tmp.unwrap_or(false),
            private_devices: exec.private_devices.unwrap_or(false),
            private_network: exec.private_network.unwrap_or(false),
            private_ipc: exec.private_ipc.unwrap_or(false),
            private_users: exec.private_users.unwrap_or(false),
            private_mounts: exec.private_mounts.unwrap_or(false),
            protect_system: exec.protect_system.clone(),
            protect_home: exec.protect_home.clone(),
            protect_hostname: exec.protect_hostname.unwrap_or(false),
            protect_kernel_tunables: exec.protect_kernel_tunables.unwrap_or(false),
            protect_kernel_modules: exec.protect_kernel_modules.unwrap_or(false),
            protect_control_groups: exec.protect_control_groups.unwrap_or(false),
            user,
            group,
            supplementary_groups: exec.supplementary_groups.clone(),
            environment: exec.environment.clone(),
            environment_file: exec.environment_file.clone(),
            pass_environment: exec.pass_environment.clone(),
            unset_environment: exec.unset_environment.clone(),
            working_directory: exec.working_directory.clone(),
            limits: exec.limits.clone(),
            nice: exec.nice,
            umask: exec.umask.clone(),
            oom_score_adjust: exec.oom_score_adjust,
            command_prefixes: command_prefixes.to_string(),
        }
    }

    pub(super) fn apply_tty_cleanup(&self, info: &UnitFileInfo) {
        let tty_path = info
            .exec_context
            .tty_path
            .as_deref()
            .unwrap_or("/dev/console");
        if info.exec_context.tty_reset.unwrap_or(false) {
            if let Some(fd) = Self::open_write_fd(tty_path, false, false, false) {
                // SAFETY: fd is owned and valid, and the escape sequence is a
                // valid four-byte buffer for the duration of this call.
                let _ = unsafe { libc::write(fd.as_raw_fd(), b"\x1bc\n".as_ptr().cast(), 4) };
            }
        }

        if info.exec_context.tty_vhangup.unwrap_or(false) {
            if let Some(fd) = Self::open_write_fd(tty_path, false, false, false) {
                #[cfg(target_os = "linux")]
                {
                    const TIOCVHANGUP_IOCTL: libc::c_ulong = 0x5437;
                    // SAFETY: fd is owned and valid; this ioctl takes only an
                    // integer argument and does not dereference the zero value.
                    let _ = unsafe { libc::ioctl(fd.as_raw_fd(), TIOCVHANGUP_IOCTL, 0) };
                }
            }
        }

        #[cfg(target_os = "linux")]
        if info.exec_context.tty_vt_disallocate.unwrap_or(false) {
            if let Some(fd) = Self::open_write_fd(tty_path, false, false, false) {
                const VT_DISALLOCATE: libc::c_ulong = 0x5608;
                // SAFETY: fd is owned and valid; this ioctl takes only an
                // integer argument and does not dereference the zero value.
                let _ = unsafe { libc::ioctl(fd.as_raw_fd(), VT_DISALLOCATE, 0) };
            }
        }
    }

    pub(super) fn track_pid(&mut self, unit_name: &str, pid: u32, role: TrackedPidRole) {
        // This compatibility index cannot represent main and control children
        // concurrently. Preserve a main PID once one exists; lifecycle code
        // uses Unit's two PID slots and the reverse maps below.
        if role == TrackedPidRole::Main || !self.unit_pid_map.contains_key(unit_name) {
            self.unit_pid_map.insert(unit_name.to_string(), pid);
        }
        self.pid_to_unit_map.insert(pid, unit_name.to_string());
        self.pid_role_map.insert(pid, role);
        self.update_unit_cgroup_population_from_tracking(unit_name);
    }

    pub(super) fn untrack_pid(&mut self, pid: u32) {
        #[cfg(target_os = "linux")]
        self.pending_exec_confirmations.remove(&pid);
        let unit_name = self.pid_to_unit_map.remove(&pid);
        self.pid_role_map.remove(&pid);
        if let Some(unit_name) = unit_name {
            let matches = self.unit_pid_map.get(&unit_name).copied() == Some(pid);
            if matches {
                self.unit_pid_map.remove(&unit_name);
            }
        }
    }

    pub(super) fn collect_reaped_children(&mut self) -> Vec<u32> {
        #[cfg(target_os = "linux")]
        {
            let mut changed = Vec::new();
            loop {
                let mut status: libc::c_int = 0;
                // SAFETY: status is a valid writable c_int for waitpid(), and
                // -1 with WNOHANG is a valid request to poll any child process.
                let pid =
                    unsafe { libc::waitpid(-1, &mut status as *mut libc::c_int, libc::WNOHANG) };
                if pid > 0 {
                    let pid_u = pid as u32;
                    let child_state = if libc::WIFEXITED(status) {
                        let code = libc::WEXITSTATUS(status);
                        if code == 0 {
                            ChildState::ExitedCleanly
                        } else {
                            ChildState::ExitedWithCode(code)
                        }
                    } else if libc::WIFSIGNALED(status) {
                        ChildState::KilledBySignal(libc::WTERMSIG(status))
                    } else {
                        ChildState::Running
                    };

                    if !matches!(child_state, ChildState::Running) {
                        if let Some(child) = self.process_tracker.get_mut(pid_u) {
                            child.state = child_state;
                            changed.push(pid_u);
                        }
                        continue;
                    }
                }

                if pid == 0 {
                    break;
                }

                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::ECHILD {
                    break;
                }
                if errno == libc::EINTR {
                    continue;
                }
                break;
            }
            changed
        }

        #[cfg(not(target_os = "linux"))]
        {
            spawn::check_children(&mut self.process_tracker)
        }
    }

    /// Consume one exec-status channel after its PID 1 epoll source reports
    /// readiness.
    ///
    /// A setup error is diagnostic here, not terminal ownership transfer. The
    /// child reports the failed pre-exec stage and exits with status 127, so
    /// SIGCHLD remains the single completion event which advances or unwinds
    /// the phase. Removing PID ownership here would race that event and could
    /// publish failure twice.
    #[cfg(target_os = "linux")]
    pub fn observe_exec_status_ready(
        &mut self,
        descriptor: super::PendingExecStatusDescriptor,
    ) -> Vec<String> {
        let mut changed = Vec::new();
        let pid = descriptor.pid();

        let observation =
            self.pending_exec_confirmations
                .get(&pid)
                .and_then(|(status, confirmation)| {
                    std::rc::Weak::ptr_eq(&std::rc::Rc::downgrade(status), descriptor.weak_owner())
                        .then(|| (status.borrow_mut().poll(), *confirmation))
                });
        match observation {
            Some((Ok(spawn::ExecStatus::Pending), _)) => {}
            Some((Ok(spawn::ExecStatus::Execed), confirmation)) => {
                self.pending_exec_confirmations.remove(&pid);
                let Some(name) = self.pid_to_unit_map.get(&pid).cloned() else {
                    return changed;
                };
                let Some(info) = self.unit_files.get(&name).cloned() else {
                    return changed;
                };
                if confirmation == spawn::SpawnConfirmation::Execed
                    && matches!(
                        self.services.get(&name).map(|service| service.state),
                        Some(ServiceState::Start)
                    )
                    && self
                        .units
                        .get(&name)
                        .and_then(|unit| unit.main_pid)
                        .is_some_and(|main_pid| main_pid.0 == pid)
                {
                    let _ = info;
                    self.enter_start_post(&name);
                    changed.push(name);
                }
            }
            Some((Err(_), _)) => {
                self.pending_exec_confirmations.remove(&pid);
                if let Some(name) = self.pid_to_unit_map.get(&pid) {
                    changed.push(name.clone());
                }
            }
            None => {}
        }

        changed
    }

    pub(super) fn mark_service_failed(&mut self, name: &str) {
        self.enter_dead(name, ServiceResult::FailureResources, true);
    }

    pub(super) fn complete_service_start(&mut self, name: &str, info: &UnitFileInfo) -> bool {
        let _ = info;
        self.enter_start_post(name);
        !matches!(
            self.services.get(name).map(|service| service.state),
            Some(ServiceState::Failed)
        )
    }

    pub(super) fn restart_delay_for(&mut self, name: &str) -> Duration {
        self.set_service_state(name, ServiceState::AutoRestartQueued);
        if let Some(service) = self.services.get_mut(name) {
            let delay_usec = service_restart_usec_next(service);
            service.n_restarts = service.n_restarts.saturating_add(1);
            return Duration::from_micros(delay_usec);
        }

        Duration::from_secs(0)
    }

    /// Queue an auto-restart without ever blocking the manager thread. The
    /// deadline is consumed from [`Self::reap_children`], which is part of the
    /// regular PID 1 event-loop turn.
    pub(super) fn schedule_service_restart(&mut self, name: String, delay: Duration) {
        self.service_restart_deadlines
            .insert(name, Instant::now() + delay);
    }

    /// Bound the next event-loop sleep by the earliest manager-owned runtime
    /// deadline. This covers service state-machine timers and deferred
    /// automatic BindsTo= retries without polling-sized latency.
    pub fn service_event_timeout(&self, maximum: Duration) -> Duration {
        let now = Instant::now();
        let service_timeout = self
            .service_operation_deadlines
            .values()
            .map(|deadline| &deadline.deadline)
            .chain(self.service_restart_deadlines.values())
            .chain(self.service_runtime_deadlines.values())
            .chain(self.service_watchdog_deadlines.values())
            .min()
            .map(|deadline| deadline.saturating_duration_since(now).min(maximum))
            .unwrap_or(maximum);
        let bound_timeout = systemd_platform_rs::time::boottime_usec()
            .ok()
            .and_then(|now_usec| {
                self.bound_stop_retry_deadlines
                    .values()
                    .min()
                    .map(|deadline| Duration::from_micros(deadline.saturating_sub(now_usec)))
            })
            .unwrap_or(maximum);
        service_timeout.min(bound_timeout).min(maximum)
    }

    fn process_due_service_restarts(&mut self) -> Vec<String> {
        let now = Instant::now();
        let due: Vec<String> = self
            .service_restart_deadlines
            .iter()
            .filter_map(|(name, deadline)| (now >= *deadline).then_some(name.clone()))
            .collect();

        for name in &due {
            self.service_restart_deadlines.remove(name);

            // A manual stop wins over a pending automatic restart. This must
            // be checked again when the timer fires, not just when it is
            // originally queued.
            if self.units.get(name).is_some_and(|unit| unit.stop_pending) {
                continue;
            }

            // `execute_service_start` owns failure reporting for this fresh
            // start attempt. Do not block or recursively retry here.
            let _ = self.start_unit_with_mode(name, JobMode::Replace);
        }

        due
    }

    /// Parse a forking daemon's PID file candidate. Identity acquisition and a
    /// descriptor-backed cgroup membership proof happen together in
    /// `adopt_forking_main_pid()` so a stale/reused numeric PID cannot be
    /// published as the unit's main process.
    #[cfg(target_os = "linux")]
    fn validated_forking_main_pid(&self, _name: &str, pid_file: &str) -> Option<u32> {
        let pid = fs::read_to_string(pid_file)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()?;
        if pid <= 1 || pid == std::process::id() || pid > i32::MAX as u32 {
            return None;
        }
        Some(pid)
    }

    #[cfg(not(target_os = "linux"))]
    fn validated_forking_main_pid(&self, _name: &str, _pid_file: &str) -> Option<u32> {
        // No pidfd/cgroup proof exists on this target.
        None
    }

    #[cfg(target_os = "linux")]
    fn guessed_forking_main_pid(&self, name: &str) -> Option<u32> {
        let manager_pid = std::process::id();
        let control_pid = self
            .units
            .get(name)
            .and_then(|unit| unit.control_pid)
            .map(|pid| pid.0);
        let members = self.read_unit_cgroup_pids(name).ok()?;
        let mut candidates = members
            .into_iter()
            .filter(|pid| *pid > 1 && *pid != manager_pid && Some(*pid) != control_pid);
        let candidate = candidates.next()?;
        candidates.next().is_none().then_some(candidate)
    }

    #[cfg(not(target_os = "linux"))]
    fn guessed_forking_main_pid(&self, _name: &str) -> Option<u32> {
        None
    }

    fn adopt_forking_main_pid(&mut self, name: &str, info: &UnitFileInfo) -> bool {
        if self
            .units
            .get(name)
            .and_then(|unit| unit.main_pid)
            .is_some()
        {
            return true;
        }
        let pid = match info.service.pid_file.as_deref() {
            Some(pid_file) => self.validated_forking_main_pid(name, pid_file),
            None => self.guessed_forking_main_pid(name),
        };
        let Some(pid) = pid else {
            return false;
        };
        let Ok(identity) = spawn::ProcessTracker::acquire_identity(pid) else {
            return false;
        };
        // A resource-exhaustion numeric identity is safe for a direct child
        // whose wait relationship PID 1 owns, but cannot pin a foreign daemon
        // across a cgroup membership read. Foreign adoption therefore fails
        // closed unless pidfd_open succeeded.
        if !identity.has_pidfd() {
            return false;
        }
        // Acquire the identity before the authoritative membership read. A
        // pidfd pins the exact process across that read.
        if identity.signal(0).is_err()
            || !self
                .read_unit_cgroup_pids(name)
                .is_ok_and(|members| members.contains(&pid))
        {
            return false;
        }
        if self.process_tracker.adopt_identity(identity).is_err() {
            return false;
        }
        if let Some(unit) = self.units.get_mut(name) {
            unit.main_pid = Some(crate::unit::PidRef(pid));
        }
        // A traditional forking daemon need not be our child. Retain its
        // identity independently without fabricating waitpid child ownership.
        self.track_pid(name, pid, TrackedPidRole::Main);
        true
    }

    pub(super) fn service_phase_specs(
        info: &UnitFileInfo,
        phase: ServiceExecCommand,
    ) -> Vec<super::ExecCommandSpec> {
        match phase {
            ServiceExecCommand::Condition => info.service.exec_condition.clone(),
            ServiceExecCommand::StartPre => info.service.exec_start_pre.clone(),
            ServiceExecCommand::Start => {
                specs_or_single(&info.service.exec_start, &info.exec_start)
            }
            ServiceExecCommand::StartPost => info.service.exec_start_post.clone(),
            ServiceExecCommand::Reload => {
                specs_or_single(&info.service.exec_reload, &info.exec_reload)
            }
            ServiceExecCommand::ReloadPost => info.service.exec_reload_post.clone(),
            ServiceExecCommand::Stop => specs_or_single(&info.service.exec_stop, &info.exec_stop),
            ServiceExecCommand::StopPost => info.service.exec_stop_post.clone(),
        }
    }

    fn phase_timeout(
        &self,
        name: &str,
        info: &UnitFileInfo,
        phase: ServiceExecCommand,
    ) -> Option<Duration> {
        let configured = match phase {
            ServiceExecCommand::Stop | ServiceExecCommand::StopPost => {
                info.service.timeout_stop_sec.or_else(|| {
                    self.services.get(name).map(|service| {
                        if service.timeout_stop_usec == u64::MAX {
                            0
                        } else {
                            service.timeout_stop_usec / 1_000_000
                        }
                    })
                })
            }
            _ => info.service.timeout_start_sec.or_else(|| {
                self.services.get(name).map(|service| {
                    if service.timeout_start_usec == u64::MAX {
                        0
                    } else {
                        service.timeout_start_usec / 1_000_000
                    }
                })
            }),
        }
        .unwrap_or(90);
        (configured > 0).then(|| Duration::from_secs(configured))
    }

    fn arm_operation_deadline(
        &mut self,
        name: &str,
        phase: ServiceExecCommand,
        pid: u32,
        info: &UnitFileInfo,
    ) {
        self.service_operation_deadlines.remove(name);
        let service_type = self
            .services
            .get(name)
            .map(|service| service.service_type)
            .unwrap_or_else(|| infer_service_type(info));
        if phase == ServiceExecCommand::Start
            && matches!(service_type, ServiceType::Simple | ServiceType::Idle)
        {
            return;
        }
        if let Some(timeout) = self.phase_timeout(name, info, phase) {
            self.service_operation_deadlines.insert(
                name.to_string(),
                ServiceOperationDeadline::command(phase, pid, Instant::now() + timeout),
            );
        }
    }

    pub(super) fn arm_signal_deadline(
        &mut self,
        name: &str,
        state: ServiceState,
        info: &UnitFileInfo,
    ) {
        self.service_operation_deadlines.remove(name);
        let timeout = if matches!(
            state,
            ServiceState::StopWatchdog | ServiceState::FinalWatchdog
        ) {
            let configured = info.service.timeout_abort_sec.or_else(|| {
                self.services.get(name).map(|service| {
                    if service.timeout_abort_usec == u64::MAX {
                        0
                    } else {
                        service.timeout_abort_usec / 1_000_000
                    }
                })
            });
            let configured = configured.unwrap_or(90);
            (configured > 0).then(|| Duration::from_secs(configured))
        } else {
            self.phase_timeout(name, info, ServiceExecCommand::Stop)
        };
        if let Some(timeout) = timeout {
            self.service_operation_deadlines.insert(
                name.to_string(),
                ServiceOperationDeadline::signal(state, Instant::now() + timeout),
            );
        }
    }

    pub(super) fn begin_command_sequence(
        &mut self,
        name: &str,
        phase: ServiceExecCommand,
        commands: Vec<super::ExecCommandSpec>,
    ) {
        self.service_command_sequences.remove(name);
        self.service_operation_deadlines.remove(name);
        self.set_service_state(name, super::service_machine::state_for_command(phase));
        let Some(sequence) = ServiceCommandSequence::new(phase, commands) else {
            self.complete_empty_phase(name, phase);
            return;
        };
        self.service_command_sequences
            .insert(name.to_string(), sequence);
        let _ = self.spawn_current_service_command(name);
    }

    fn spawn_current_service_command(&mut self, name: &str) -> bool {
        let Some((cursor, spec)) = self
            .service_command_sequences
            .get(name)
            .map(|sequence| (sequence.cursor(), sequence.current().clone()))
        else {
            return false;
        };
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.handle_phase_spawn_failure(name, cursor.phase);
            return false;
        };
        let service_type = self
            .services
            .get(name)
            .map(|service| service.service_type)
            .unwrap_or_else(|| infer_service_type(&info));
        let role = pid_role_for_command(cursor.phase, service_type);
        let prepared_stdio = self.prepare_service_stdio(name, &info);
        if let Some(service) = self.services.get_mut(name) {
            service.stdin_fd = prepared_stdio
                .stdio
                .stdin_fd
                .unwrap_or_else(|| Errno::EBADF.to_neg_errno());
            service.stdout_fd = prepared_stdio
                .stdio
                .stdout_fd
                .unwrap_or_else(|| Errno::EBADF.to_neg_errno());
            service.stderr_fd = prepared_stdio
                .stdio
                .stderr_fd
                .unwrap_or_else(|| Errno::EBADF.to_neg_errno());
        }
        let security = self.build_spawn_security(name, &info.exec_context, &spec.prefixes);
        let confirmation = if cursor.phase == ServiceExecCommand::Start
            && role == TrackedPidRole::Main
            && service_type == ServiceType::Exec
        {
            spawn::SpawnConfirmation::Execed
        } else {
            spawn::SpawnConfirmation::Forked
        };

        #[cfg(target_os = "linux")]
        let launch_result = {
            let activation_descriptors = if cursor.phase == ServiceExecCommand::Start {
                self.service_activation_sockets
                    .get(name)
                    .into_iter()
                    .flatten()
                    .filter_map(|socket_name| self.socket_mgr.get(socket_name))
                    .flat_map(|socket| socket.activation_fds())
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let activation = activation_descriptors
                .iter()
                .map(|descriptor| spawn::ActivationFd {
                    fd: descriptor.as_fd(),
                    name: descriptor.fd_name(),
                })
                .collect::<Vec<_>>();
            match self.unit_cgroup_spawn_fds(name, cursor.phase) {
                Ok(cgroup) => spawn::spawn_service_with_confirmation_and_activation_in_cgroup(
                    &spec.command,
                    prepared_stdio.stdio,
                    security,
                    &activation,
                    spawn::CgroupPlacement::new(
                        cgroup.delegate_root,
                        cgroup.target_directory,
                        cgroup.target_processes,
                        cgroup.delegated,
                        cgroup.recursive_target_access,
                    ),
                    confirmation,
                ),
                Err(error) => Err(error.to_string()),
            }
        };
        #[cfg(not(target_os = "linux"))]
        let launch_result = spawn::spawn_service_with_confirmation(
            &spec.command,
            prepared_stdio.stdio,
            security,
            confirmation,
        );
        drop(prepared_stdio);

        let mut launch = match launch_result {
            Ok(launch) => launch,
            Err(error) => {
                eprintln!(
                    "systemd: failed to spawn {} command {} for {name}: {error}",
                    cursor.phase.as_str(),
                    cursor.index.get()
                );
                // `-` applies only after a child has actually exited.
                self.handle_phase_spawn_failure(name, cursor.phase);
                return false;
            }
        };
        let pid = launch.pid;
        let Some(identity) = launch.take_process_identity() else {
            let _ = spawn::kill_process(pid, libc::SIGKILL);
            eprintln!(
                "systemd: spawned {} command {} for {name} without a process identity",
                cursor.phase.as_str(),
                cursor.index.get()
            );
            self.handle_phase_spawn_failure(name, cursor.phase);
            return false;
        };
        if self.process_tracker.identity(pid).is_some() {
            let _ = identity.signal(libc::SIGKILL);
            eprintln!(
                "systemd: refusing to replace the existing process identity for PID {pid} while spawning {name}"
            );
            self.handle_phase_spawn_failure(name, cursor.phase);
            return false;
        }
        if let Err(error) = self.process_tracker.insert_with_identity(
            ChildProcess {
                pid,
                command: spec.command,
                started: Instant::now(),
                state: ChildState::Running,
            },
            identity,
        ) {
            let _ = spawn::kill_process(pid, libc::SIGKILL);
            eprintln!("systemd: failed to retain process identity for {name}: {error}");
            self.handle_phase_spawn_failure(name, cursor.phase);
            return false;
        }
        if let Some(sequence) = self.service_command_sequences.get_mut(name) {
            sequence.set_active_pid(pid);
        }
        #[cfg(target_os = "linux")]
        if let Some(status) = launch.take_exec_status() {
            self.pending_exec_confirmations.insert(
                pid,
                (
                    std::rc::Rc::new(std::cell::RefCell::new(status)),
                    launch.confirmation(),
                ),
            );
        }
        if let Some(unit) = self.units.get_mut(name) {
            match role {
                TrackedPidRole::Main => unit.main_pid = Some(crate::unit::PidRef(pid)),
                TrackedPidRole::Control => unit.control_pid = Some(crate::unit::PidRef(pid)),
                TrackedPidRole::Unknown => {}
            }
            if cursor.phase == ServiceExecCommand::Start {
                unit.stop_pending = false;
            }
        }
        if let Some(service) = self.services.get_mut(name) {
            service.control_command_id = (role == TrackedPidRole::Control).then_some(cursor.phase);
        }
        self.track_pid(name, pid, role);
        self.set_unit_cgroup_populated(name, true);
        self.arm_operation_deadline(name, cursor.phase, pid, &info);

        if cursor.phase == ServiceExecCommand::Start
            && role == TrackedPidRole::Main
            && start_post_after_fork(service_type)
        {
            self.enter_start_post(name);
        }
        true
    }

    fn handle_phase_spawn_failure(&mut self, name: &str, phase: ServiceExecCommand) {
        match phase {
            ServiceExecCommand::Condition | ServiceExecCommand::StartPre => {
                self.enter_dead(name, ServiceResult::FailureResources, true);
            }
            ServiceExecCommand::Start => {
                self.begin_stop_signal(name, ServiceResult::FailureResources);
            }
            ServiceExecCommand::StartPost => {
                self.enter_stop(name, ServiceResult::FailureResources);
            }
            ServiceExecCommand::Reload | ServiceExecCommand::ReloadPost => {
                self.reload_finish(name, ServiceResult::FailureResources);
            }
            ServiceExecCommand::Stop => {
                self.begin_stop_signal(name, ServiceResult::FailureResources);
            }
            ServiceExecCommand::StopPost => {
                self.enter_final_signal(name, ServiceResult::FailureResources);
            }
        }
    }

    fn complete_empty_phase(&mut self, name: &str, phase: ServiceExecCommand) {
        match phase {
            ServiceExecCommand::Condition => self.enter_start_pre(name),
            ServiceExecCommand::StartPre => self.enter_start(name),
            ServiceExecCommand::Start => {
                let service_type = self
                    .services
                    .get(name)
                    .map(|service| service.service_type)
                    .unwrap_or(ServiceType::Invalid);
                if service_type == ServiceType::Oneshot {
                    self.enter_start_post(name);
                } else {
                    self.begin_stop_signal(name, ServiceResult::FailureProtocol);
                }
            }
            ServiceExecCommand::StartPost => self.finish_start_post(name),
            ServiceExecCommand::Reload => self.enter_reload_post(name),
            ServiceExecCommand::ReloadPost => self.reload_finish(name, ServiceResult::Success),
            ServiceExecCommand::Stop => self.begin_stop_signal(name, ServiceResult::Success),
            ServiceExecCommand::StopPost => self.enter_final_signal(name, ServiceResult::Success),
        }
    }

    fn enter_condition(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.enter_dead(name, ServiceResult::FailureResources, true);
            return;
        };
        self.begin_command_sequence(
            name,
            ServiceExecCommand::Condition,
            Self::service_phase_specs(&info, ServiceExecCommand::Condition),
        );
    }

    fn enter_start_pre(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.enter_dead(name, ServiceResult::FailureResources, true);
            return;
        };
        if !self.setup_service_directories(name, &info) {
            self.enter_dead(name, ServiceResult::FailureResources, true);
            return;
        }
        self.begin_command_sequence(
            name,
            ServiceExecCommand::StartPre,
            Self::service_phase_specs(&info, ServiceExecCommand::StartPre),
        );
    }

    fn enter_start(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.enter_dead(name, ServiceResult::FailureResources, true);
            return;
        };
        self.begin_command_sequence(
            name,
            ServiceExecCommand::Start,
            Self::service_phase_specs(&info, ServiceExecCommand::Start),
        );
    }

    fn enter_start_post(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.enter_dead(name, ServiceResult::FailureResources, true);
            return;
        };
        self.begin_command_sequence(
            name,
            ServiceExecCommand::StartPost,
            Self::service_phase_specs(&info, ServiceExecCommand::StartPost),
        );
    }

    fn finish_start_post(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.enter_dead(name, ServiceResult::FailureResources, true);
            return;
        };
        let service_type = self
            .services
            .get(name)
            .map(|service| service.service_type)
            .unwrap_or_else(|| infer_service_type(&info));
        // PIDFile= may legitimately be produced by ExecStartPost=. Validate
        // it only after that phase has completed.
        if service_type == ServiceType::Forking {
            let requires_main_pid =
                info.service.pid_file.is_some() || info.service.guess_main_pid.unwrap_or(true);
            if requires_main_pid && !self.adopt_forking_main_pid(name, &info) {
                self.enter_stop(name, ServiceResult::FailureProtocol);
                return;
            }
        }
        self.enter_running(name);
    }

    pub(super) fn enter_running(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.enter_dead(name, ServiceResult::FailureResources, true);
            return;
        };
        self.service_command_sequences.remove(name);
        self.service_operation_deadlines.remove(name);
        if let Some(service) = self.services.get_mut(name) {
            service.control_command_id = None;
        }
        let result = self
            .services
            .get(name)
            .map(|service| service.result)
            .unwrap_or(ServiceResult::FailureResources);
        if result != ServiceResult::Success {
            self.begin_stop_signal(name, result);
            return;
        }
        let service_type = self
            .services
            .get(name)
            .map(|service| service.service_type)
            .unwrap_or_else(|| infer_service_type(&info));
        let main_pid_alive = self
            .units
            .get(name)
            .and_then(|unit| unit.main_pid)
            .is_some();
        let cgroup_only_alive = service_type == ServiceType::Forking
            && !info.service.guess_main_pid.unwrap_or(true)
            && self.read_unit_cgroup_populated(name) == Some(true);
        let main_alive = main_pid_alive || cgroup_only_alive;
        if main_alive {
            self.set_service_state(name, ServiceState::Running);
            self.arm_running_deadlines(name, &info);
            self.dispatch_pending_installed_job(name);
        } else if info.service.remain_after_exit.unwrap_or(false) {
            self.set_service_state(name, ServiceState::Exited);
            self.arm_running_deadlines(name, &info);
            self.dispatch_pending_installed_job(name);
        } else if service_type == ServiceType::Oneshot {
            self.enter_dead(name, ServiceResult::Success, true);
        } else {
            self.enter_stop(name, ServiceResult::Success);
        }
    }

    fn enter_reload(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            return;
        };
        if let Some(service) = self.services.get_mut(name) {
            service_reset_reload_result(service);
        }
        self.begin_command_sequence(
            name,
            ServiceExecCommand::Reload,
            Self::service_phase_specs(&info, ServiceExecCommand::Reload),
        );
    }

    fn enter_reload_post(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            return;
        };
        self.begin_command_sequence(
            name,
            ServiceExecCommand::ReloadPost,
            Self::service_phase_specs(&info, ServiceExecCommand::ReloadPost),
        );
    }

    pub(super) fn reload_finish(&mut self, name: &str, result: ServiceResult) {
        if let Some(service) = self.services.get_mut(name) {
            service_record_reload_result(service, result);
            service.control_command_id = None;
        }
        self.service_command_sequences.remove(name);
        self.service_operation_deadlines.remove(name);
        // A merge received while this control sequence was running may have
        // changed the installed job type or requested one coalesced second
        // reload. Publish the settled Active state, then redispatch that same
        // job ID from enter_running().
        self.prepare_repeated_reload_for_redispatch(name);
        // Revalidate main-process/cgroup liveness before publishing Running.
        // The main process may have exited while the reload control command
        // was still in flight.
        self.enter_running(name);
    }

    pub(super) fn enter_stop(&mut self, name: &str, result: ServiceResult) {
        if let Some(service) = self.services.get_mut(name) {
            service_record_result(service, result);
        }
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.begin_stop_signal(name, ServiceResult::FailureResources);
            return;
        };
        self.begin_command_sequence(
            name,
            ServiceExecCommand::Stop,
            Self::service_phase_specs(&info, ServiceExecCommand::Stop),
        );
    }

    pub(super) fn execute_service_start(&mut self, unit_name: &str) {
        let Some(info) = self.unit_files.get(unit_name).cloned() else {
            return;
        };
        let prior_state = self.services.get(unit_name).map(|service| service.state);
        if matches!(
            prior_state,
            Some(
                ServiceState::Condition
                    | ServiceState::StartPre
                    | ServiceState::Start
                    | ServiceState::StartPost
                    | ServiceState::Running
                    | ServiceState::Exited
                    | ServiceState::Reload
                    | ServiceState::ReloadSignal
                    | ServiceState::ReloadNotify
                    | ServiceState::ReloadPost
                    | ServiceState::Stop
                    | ServiceState::StopWatchdog
                    | ServiceState::StopSigterm
                    | ServiceState::StopSigkill
                    | ServiceState::StopPost
                    | ServiceState::FinalWatchdog
                    | ServiceState::FinalSigterm
                    | ServiceState::FinalSigkill
            )
        ) {
            return;
        }
        self.service_restart_deadlines.remove(unit_name);
        let service_type = infer_service_type(&info);
        if let Some(service) = self.services.get_mut(unit_name) {
            service.service_type = service_type;
            service.guess_main_pid = info.service.guess_main_pid.unwrap_or(true);
            service_reset_result(service);
            service_reset_reload_result(service);
            service.control_command_id = None;
            if !matches!(
                prior_state,
                Some(ServiceState::AutoRestart | ServiceState::AutoRestartQueued)
            ) {
                service.n_restarts = 0;
            }
        }
        if let Some(unit) = self.units.get_mut(unit_name) {
            unit.stop_pending = false;
        }
        // Enter a nonterminal activation state before any fail-closed
        // readiness/cgroup check. That makes terminal publication idempotent
        // and prevents a start failure from looking like Dead→Dead.
        self.set_service_state(unit_name, ServiceState::Condition);

        // These types require manager-owned transports/gates which the Rust
        // PID 1 does not yet provide. Starting them and accepting a public
        // name-only callback would falsely claim readiness. Keep the reason
        // explicit: it is operationally important that a unit is rejected for
        // missing architecture, not diagnosed as an application crash.
        let readiness_rejection = match service_type {
            ServiceType::Idle => {
                Some("Type=idle requires the manager idle gate, which is not implemented")
            }
            ServiceType::Notify | ServiceType::NotifyReload => Some(
                "Type=notify requires an authenticated sd_notify transport, which is not implemented",
            ),
            ServiceType::Dbus
                if info
                    .service
                    .bus_name
                    .as_deref()
                    .map_or(true, |name| name.trim().is_empty()) =>
            {
                Some("Type=dbus requires a non-empty BusName=")
            }
            ServiceType::Dbus => Some(
                "Type=dbus requires authenticated BusName ownership tracking, which is not implemented",
            ),
            _ => None,
        };
        if let Some(reason) = readiness_rejection {
            eprintln!("systemd: refusing to start {unit_name}: {reason}");
            self.enter_dead(unit_name, ServiceResult::FailureProtocol, true);
            return;
        }
        if let Err(error) = self.ensure_unit_cgroup(unit_name, &info) {
            eprintln!("systemd: failed to realize cgroup for {unit_name}: {error}");
            self.enter_dead(unit_name, ServiceResult::FailureResources, true);
            return;
        }
        self.prepare_delegated_cgroup_start(unit_name);

        match unit_condition_evaluation(&info) {
            UnitConditionEvaluation::Passed => {}
            UnitConditionEvaluation::ConditionFailed => {
                self.enter_dead(unit_name, ServiceResult::SkipCondition, false);
                return;
            }
            UnitConditionEvaluation::AssertFailed => {
                self.enter_dead(unit_name, ServiceResult::FailureProtocol, true);
                return;
            }
        }
        self.enter_condition(unit_name);
    }

    pub(super) fn execute_service_stop(&mut self, unit_name: &str) {
        self.service_restart_deadlines.remove(unit_name);
        if let Some(unit) = self.units.get_mut(unit_name) {
            unit.stop_pending = true;
        }
        match self.services.get(unit_name).map(|service| service.state) {
            Some(
                ServiceState::Stop
                | ServiceState::StopSigterm
                | ServiceState::StopSigkill
                | ServiceState::StopPost
                | ServiceState::FinalWatchdog
                | ServiceState::FinalSigterm
                | ServiceState::FinalSigkill,
            ) => {}
            Some(ServiceState::AutoRestart | ServiceState::AutoRestartQueued) => {
                self.set_service_state(unit_name, ServiceState::Dead);
                if let Some(unit) = self.units.get_mut(unit_name) {
                    unit.stop_pending = false;
                }
            }
            Some(
                ServiceState::Condition
                | ServiceState::StartPre
                | ServiceState::Start
                | ServiceState::StartPost
                | ServiceState::Reload
                | ServiceState::ReloadSignal
                | ServiceState::ReloadNotify
                | ServiceState::ReloadPost
                | ServiceState::RefreshExtensions
                | ServiceState::RefreshCredentials
                | ServiceState::Mounting
                | ServiceState::StopWatchdog,
            ) => self.begin_stop_signal(unit_name, ServiceResult::Success),
            Some(ServiceState::Cleaning) => self.enter_signal(
                unit_name,
                ServiceState::FinalSigkill,
                ServiceResult::Success,
            ),
            Some(ServiceState::Running | ServiceState::Exited) => {
                self.enter_stop(unit_name, ServiceResult::Success)
            }
            Some(
                ServiceState::Dead
                | ServiceState::Failed
                | ServiceState::DeadBeforeAutoRestart
                | ServiceState::FailedBeforeAutoRestart
                | ServiceState::DeadResourcesPinned,
            )
            | None => {
                if let Some(unit) = self.units.get_mut(unit_name) {
                    unit.stop_pending = false;
                }
            }
        }
    }

    pub(super) fn execute_service_reload(&mut self, unit_name: &str) {
        if !matches!(
            self.services.get(unit_name).map(|service| service.state),
            Some(ServiceState::Running | ServiceState::Exited)
        ) {
            return;
        }
        let can_reload = self.unit_files.get(unit_name).is_some_and(|info| {
            !info.service.exec_reload.is_empty() || !info.service.exec_reload_post.is_empty()
        });
        if can_reload {
            self.enter_reload(unit_name);
        } else if let Some(service) = self.services.get_mut(unit_name) {
            service_record_reload_result(service, ServiceResult::FailureProtocol);
        }
    }

    fn command_exit_result(
        &self,
        info: &UnitFileInfo,
        state: ChildState,
        phase: ServiceExecCommand,
        prefixes: &str,
    ) -> ServiceResult {
        let clean_mode = if phase == ServiceExecCommand::Start
            && infer_service_type(info) != ServiceType::Oneshot
        {
            ChildExitCleanMode::Daemon
        } else {
            ChildExitCleanMode::Command
        };
        let mut result = if child_state_considered_clean_with_mode(state, info, clean_mode) {
            ServiceResult::Success
        } else {
            match state {
                ChildState::KilledBySignal(_) => ServiceResult::FailureSignal,
                ChildState::ExitedWithCode(_) => ServiceResult::FailureExitCode,
                ChildState::ExitedCleanly | ChildState::Running => ServiceResult::Success,
            }
        };
        // Like service.c, ignore-failure changes a completed child's result.
        // It never masks failure to construct or fork the child.
        if prefixes.contains('-') && result != ServiceResult::Success {
            result = ServiceResult::Success;
        }
        // C applies EXEC_COMMAND_IGNORE_FAILURE before ExecCondition's
        // skip-like classification. Thus a `-`-prefixed condition continues
        // activation instead of becoming SkipCondition.
        if phase == ServiceExecCommand::Condition
            && result == ServiceResult::FailureExitCode
            && matches!(state, ChildState::ExitedWithCode(code) if (1..=254).contains(&code))
        {
            result = ServiceResult::SkipCondition;
        }
        result
    }

    fn complete_command_phase(
        &mut self,
        name: &str,
        phase: ServiceExecCommand,
        result: ServiceResult,
    ) {
        if matches!(
            phase,
            ServiceExecCommand::Reload | ServiceExecCommand::ReloadPost
        ) {
            if let Some(service) = self.services.get_mut(name) {
                service_record_reload_result(service, result);
            }
        } else if let Some(service) = self.services.get_mut(name) {
            service_record_result(service, result);
        }
        if let Some(service) = self.services.get_mut(name) {
            service.control_command_id = None;
        }
        self.service_command_sequences.remove(name);

        match phase {
            ServiceExecCommand::Condition => match result {
                ServiceResult::Success => self.enter_start_pre(name),
                ServiceResult::SkipCondition => {
                    self.enter_dead(name, ServiceResult::SkipCondition, false)
                }
                _ => self.begin_stop_signal(name, result),
            },
            ServiceExecCommand::StartPre => {
                if result == ServiceResult::Success {
                    self.enter_start(name);
                } else {
                    self.begin_stop_signal(name, result);
                }
            }
            ServiceExecCommand::Start => {
                if result == ServiceResult::Success {
                    self.enter_start_post(name);
                } else {
                    self.begin_stop_signal(name, result);
                }
            }
            ServiceExecCommand::StartPost => {
                if result == ServiceResult::Success {
                    self.finish_start_post(name);
                } else {
                    self.begin_stop_signal(name, result);
                }
            }
            ServiceExecCommand::Reload => {
                if result == ServiceResult::Success {
                    self.enter_reload_post(name);
                } else {
                    self.reload_finish(name, result);
                }
            }
            ServiceExecCommand::ReloadPost => self.reload_finish(name, result),
            ServiceExecCommand::Stop => self.begin_stop_signal(name, result),
            ServiceExecCommand::StopPost => self.enter_final_signal(name, result),
        }
    }

    fn handle_command_child_exit(
        &mut self,
        name: &str,
        pid: u32,
        state: ChildState,
        info: &UnitFileInfo,
    ) -> bool {
        let Some((cursor, prefixes)) = self
            .service_command_sequences
            .get(name)
            .filter(|sequence| sequence.owns_pid(pid))
            .map(|sequence| (sequence.cursor(), sequence.current().prefixes.clone()))
        else {
            return false;
        };
        if self
            .service_operation_deadlines
            .get(name)
            .is_some_and(|deadline| {
                matches!(
                    deadline.owner,
                    ServiceOperationOwner::Command {
                        phase,
                        pid: deadline_pid,
                    } if phase == cursor.phase && deadline_pid == pid
                )
            })
        {
            self.service_operation_deadlines.remove(name);
        }
        let result = self.command_exit_result(info, state, cursor.phase, &prefixes);
        let advance = result == ServiceResult::Success
            && self
                .service_command_sequences
                .get_mut(name)
                .is_some_and(ServiceCommandSequence::advance);
        if advance {
            let _ = self.spawn_current_service_command(name);
        } else {
            self.complete_command_phase(name, cursor.phase, result);
        }
        true
    }

    fn handle_main_child_exit(
        &mut self,
        name: &str,
        pid: u32,
        state: ChildState,
        info: &UnitFileInfo,
        service_state: ServiceState,
    ) {
        if self
            .service_operation_deadlines
            .get(name)
            .is_some_and(|deadline| {
                matches!(
                    deadline.owner,
                    ServiceOperationOwner::Command {
                        phase: ServiceExecCommand::Start,
                        pid: deadline_pid,
                    } if deadline_pid == pid
                )
            })
        {
            self.service_operation_deadlines.remove(name);
        }
        let start_specs = Self::service_phase_specs(info, ServiceExecCommand::Start);
        let start_prefixes = start_specs
            .first()
            .map(|spec| spec.prefixes.as_str())
            .unwrap_or("");
        let result =
            self.command_exit_result(info, state, ServiceExecCommand::Start, start_prefixes);
        self.record_service_main_exit_status(name, state);
        if let Some(service) = self.services.get_mut(name) {
            service_record_result(service, result);
        }

        match service_state {
            ServiceState::StopSigterm
            | ServiceState::StopSigkill
            | ServiceState::StopWatchdog
            | ServiceState::StopPost
            | ServiceState::FinalSigterm
            | ServiceState::FinalSigkill
            | ServiceState::FinalWatchdog => {
                self.maybe_complete_service_kill_phase(name, service_state)
            }
            ServiceState::Stop => {
                // ExecStop= is still running; its completion owns the next
                // transition.
            }
            ServiceState::StartPost | ServiceState::Reload | ServiceState::ReloadPost => {
                let control_alive = self
                    .units
                    .get(name)
                    .and_then(|unit| unit.control_pid)
                    .is_some();
                if !control_alive {
                    self.enter_stop(name, result);
                }
            }
            ServiceState::Start => self.begin_stop_signal(name, result),
            ServiceState::Running | ServiceState::Exited => self.enter_running(name),
            _ => {
                if result != ServiceResult::Success {
                    self.enter_dead(name, result, true);
                }
            }
        }
    }

    pub(super) fn enforce_service_deadlines(
        &mut self,
        _restarts: &mut Vec<(String, Duration)>,
    ) -> Vec<String> {
        let now = Instant::now();
        let mut changed = Vec::new();

        let operation_expired: Vec<(String, ServiceOperationOwner)> = self
            .service_operation_deadlines
            .iter()
            .filter_map(|(name, deadline)| {
                (now >= deadline.deadline).then_some((name.clone(), deadline.owner))
            })
            .collect();
        for (name, owner) in operation_expired {
            if self
                .service_operation_deadlines
                .get(&name)
                .map(|deadline| deadline.owner)
                != Some(owner)
            {
                continue;
            }
            self.service_operation_deadlines.remove(&name);
            match owner {
                ServiceOperationOwner::Command { phase, pid } => {
                    // Revalidate the reverse identity immediately before
                    // signalling. A stale deadline never targets an unrelated
                    // reused numeric PID.
                    if self.pid_to_unit_map.get(&pid).map(String::as_str) != Some(name.as_str()) {
                        continue;
                    }
                    match phase {
                        ServiceExecCommand::Reload | ServiceExecCommand::ReloadPost => {
                            let _ = self.process_tracker.signal(pid, libc::SIGKILL);
                            self.reload_finish(&name, ServiceResult::FailureTimeout)
                        }
                        ServiceExecCommand::Condition
                        | ServiceExecCommand::StartPre
                        | ServiceExecCommand::Start
                        | ServiceExecCommand::StartPost
                        | ServiceExecCommand::Stop
                        | ServiceExecCommand::StopPost => {
                            let state = self
                                .services
                                .get(&name)
                                .map(|service| service.state)
                                .unwrap_or(ServiceState::Failed);
                            let _ = self.apply_service_timeout(&name, state);
                        }
                    }
                }
                ServiceOperationOwner::Signal(state) => {
                    if self.services.get(&name).map(|service| service.state) != Some(state) {
                        continue;
                    }
                    let _ = self.apply_service_timeout(&name, state);
                }
            }
            changed.push(name);
        }

        let runtime_expired: Vec<String> = self
            .service_runtime_deadlines
            .iter()
            .filter_map(|(name, deadline)| (now >= *deadline).then_some(name.clone()))
            .collect();
        for name in runtime_expired {
            self.service_runtime_deadlines.remove(&name);
            self.enter_stop(&name, ServiceResult::FailureTimeout);
            changed.push(name);
        }

        let watchdog_expired: Vec<String> = self
            .service_watchdog_deadlines
            .iter()
            .filter_map(|(name, deadline)| (now >= *deadline).then_some(name.clone()))
            .collect();
        for name in watchdog_expired {
            let Some(info) = self.unit_files.get(&name).cloned() else {
                continue;
            };
            self.service_watchdog_deadlines.remove(&name);
            let _ = info;
            self.enter_signal(
                &name,
                ServiceState::StopWatchdog,
                ServiceResult::FailureWatchdog,
            );
            changed.push(name);
        }

        changed
    }

    /// Apply one already-correlated SIGCHLD result to the canonical machine.
    ///
    /// Both the real reaper and test-only synthetic event ingress use this
    /// path. The latter must first prove the exact PID still belongs to the
    /// named unit; stale control children consequently cannot advance a newer
    /// command cursor.
    pub(super) fn dispatch_service_child_exit(
        &mut self,
        pid: u32,
        child_state: ChildState,
    ) -> Option<String> {
        let name = self.pid_to_unit_map.get(&pid)?.clone();
        let pid_role = self
            .pid_role_map
            .get(&pid)
            .copied()
            .unwrap_or(TrackedPidRole::Unknown);
        let Some(info) = self.unit_files.get(&name).cloned() else {
            self.untrack_pid(pid);
            let _ = self.process_tracker.remove(pid);
            self.update_unit_cgroup_population_from_tracking(&name);
            return Some(name);
        };
        let service_state = self
            .services
            .get(&name)
            .map(|service| service.state)
            .unwrap_or(ServiceState::Failed);
        let service_type = self
            .services
            .get(&name)
            .map(|service| service.service_type)
            .unwrap_or_else(|| infer_service_type(&info));
        if let Some(unit) = self.units.get_mut(&name) {
            match pid_role {
                TrackedPidRole::Main => {
                    if unit.main_pid.map(|p| p.0) == Some(pid) {
                        unit.main_pid = None;
                    }
                }
                TrackedPidRole::Control => {
                    if unit.control_pid.map(|p| p.0) == Some(pid) {
                        unit.control_pid = None;
                    }
                }
                TrackedPidRole::Unknown => {}
            }
            unit.watched_pids.retain(|watched_pid| watched_pid.0 != pid);
        }
        // Snapshot role/state/sequence first, then release all child ownership
        // exactly once before a transition can spawn its successor and occupy
        // the same Unit PID slot.
        self.untrack_pid(pid);
        let _ = self.process_tracker.remove(pid);
        let is_oneshot_main_sequence = pid_role == TrackedPidRole::Main
            && service_type == ServiceType::Oneshot
            && service_state == ServiceState::Start;
        if pid_role == TrackedPidRole::Control {
            let handled = self.handle_command_child_exit(&name, pid, child_state, &info);
            if !handled
                && matches!(
                    service_state,
                    ServiceState::StopSigterm
                        | ServiceState::StopSigkill
                        | ServiceState::StopWatchdog
                        | ServiceState::StopPost
                        | ServiceState::FinalSigterm
                        | ServiceState::FinalSigkill
                        | ServiceState::FinalWatchdog
                )
            {
                self.maybe_complete_service_kill_phase(&name, service_state);
            }
        } else if is_oneshot_main_sequence {
            self.record_service_main_exit_status(&name, child_state);
            if !self.handle_command_child_exit(&name, pid, child_state, &info) {
                self.handle_main_child_exit(&name, pid, child_state, &info, service_state);
            }
        } else {
            self.handle_main_child_exit(&name, pid, child_state, &info, service_state);
        }
        // Deliver cgroup population only after the exact SIGCHLD result has
        // advanced its command cursor/state. Otherwise an empty event can
        // terminalize StopPost before its exit status is recorded.
        self.update_unit_cgroup_population_from_tracking(&name);
        Some(name)
    }

    pub fn reap_children(&mut self) -> Vec<String> {
        let mut restart_queue: Vec<(String, Duration)> = Vec::new();
        let mut changed_units: BTreeSet<String> = BTreeSet::new();
        self.process_cgroup_events();
        self.process_due_bound_stop_retries();
        for unit in self.process_due_service_restarts() {
            changed_units.insert(unit);
        }
        for unit in self.enforce_service_deadlines(&mut restart_queue) {
            changed_units.insert(unit);
        }
        for pid in self.collect_reaped_children() {
            let Some(child_state) = self.process_tracker.get(pid).map(|child| child.state) else {
                continue;
            };
            if matches!(child_state, ChildState::Running) {
                continue;
            }
            if self.pid_to_unit_map.contains_key(&pid) {
                if let Some(name) = self.dispatch_service_child_exit(pid, child_state) {
                    changed_units.insert(name);
                }
            } else {
                let _ = self.process_tracker.remove(pid);
            }
        }
        for unit in self.process_due_service_restarts() {
            changed_units.insert(unit);
        }
        self.process_cgroup_events();
        changed_units.into_iter().collect()
    }

    /// Test-only state-machine injection. Production readiness must arrive
    /// from the authenticated sd_notify receiver, not from a unit name.
    #[cfg(test)]
    pub fn notify_service_ready(&mut self, name: &str) -> Result<()> {
        let name = self.canonical_unit_name(name);
        let info = self.unit_files.get(&name).cloned().ok_or(Errno::ENOENT)?;
        let service_type = self
            .services
            .get(&name)
            .map(|service| service.service_type)
            .ok_or(Errno::ENOENT)?;
        if !matches!(
            service_type,
            ServiceType::Notify | ServiceType::NotifyReload
        ) {
            return Err(Errno::EINVAL);
        }
        if !matches!(
            self.services.get(&name).map(|service| service.state),
            Some(ServiceState::Start | ServiceState::StartPost)
        ) {
            return Err(Errno::EALREADY);
        }
        if self.complete_service_start(&name, &info) {
            Ok(())
        } else {
            Err(Errno::EIO)
        }
    }

    /// Test-only state-machine injection. Production watchdog updates must be
    /// authenticated sd_notify datagrams.
    #[cfg(test)]
    pub fn notify_service_watchdog(&mut self, name: &str) -> Result<()> {
        let name = self.canonical_unit_name(name);
        let info = self.unit_files.get(&name).cloned().ok_or(Errno::ENOENT)?;
        if !matches!(
            self.services.get(&name).map(|service| service.state),
            Some(ServiceState::Running | ServiceState::Exited)
        ) {
            return Err(Errno::EINVAL);
        }
        if let Some(watchdog_sec) = info.service.watchdog_sec {
            if watchdog_sec > 0 {
                self.service_watchdog_deadlines.insert(
                    name.to_string(),
                    Instant::now() + Duration::from_secs(watchdog_sec),
                );
            }
        }
        Ok(())
    }

    /// Test-only state-machine injection. Production D-Bus readiness must be
    /// driven by a manager-owned BusName owner-change subscription.
    #[cfg(test)]
    pub fn notify_dbus_name_ready(&mut self, name: &str) -> Result<()> {
        let name = self.canonical_unit_name(name);
        let info = self.unit_files.get(&name).cloned().ok_or(Errno::ENOENT)?;
        let service_type = self
            .services
            .get(&name)
            .map(|service| service.service_type)
            .ok_or(Errno::ENOENT)?;
        if service_type != ServiceType::Dbus {
            return Err(Errno::EINVAL);
        }
        if !matches!(
            self.services.get(&name).map(|service| service.state),
            Some(ServiceState::Start)
        ) {
            return Err(Errno::EALREADY);
        }
        if self.complete_service_start(&name, &info) {
            Ok(())
        } else {
            Err(Errno::EIO)
        }
    }
}
