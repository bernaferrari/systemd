// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/service.c

//! Canonical shutdown, final-kill, restart, and cgroup-empty transitions.
//!
//! This is deliberately an `impl RuntimeManager`, rather than a second state
//! machine: `Service.state`, Unit PID slots, process indexes, and deadlines
//! remain owned by the manager.  Splitting this lifecycle tail only gives its
//! tightly coupled transition code a focused home.

use std::collections::BTreeSet;

use super::unit_file::{KillMode, ServiceRestartPolicy, ServiceTimeoutFailureMode, UnitFileInfo};
use super::{RuntimeManager, status_list_matches};
use crate::service::{ServiceExitStatus, ServiceState, ServiceType, service_record_result};
use crate::service_tables::{ServiceExecCommand, ServiceResult};
use crate::unit::DependencyKind;
use systemd_platform_rs::spawn::ChildState;

/// C service_dispatch_timer-compatible action for an already-expired service
/// operation. This is pure policy: PID correlation and signal delivery remain
/// in RuntimeManager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServiceTimeoutAction {
    Signal(ServiceState),
    Stop,
    StopPost,
    Dead { allow_restart: bool },
    Reload,
    Mount,
}

pub(super) fn service_timeout_action(
    state: ServiceState,
    start_mode: ServiceTimeoutFailureMode,
    stop_mode: ServiceTimeoutFailureMode,
    send_sigkill: bool,
) -> Option<ServiceTimeoutAction> {
    use ServiceTimeoutAction::*;
    use ServiceTimeoutFailureMode::*;

    let from_mode = |mode, terminate, abort, kill, no_kill| match mode {
        Terminate => Signal(terminate),
        Abort => Signal(abort),
        Kill if send_sigkill => Signal(kill),
        Kill => no_kill,
    };

    match state {
        ServiceState::Condition
        | ServiceState::StartPre
        | ServiceState::Start
        | ServiceState::StartPost => Some(from_mode(
            start_mode,
            ServiceState::StopSigterm,
            ServiceState::StopWatchdog,
            ServiceState::StopSigkill,
            StopPost,
        )),
        ServiceState::Reload
        | ServiceState::ReloadSignal
        | ServiceState::ReloadNotify
        | ServiceState::ReloadPost
        | ServiceState::RefreshExtensions
        | ServiceState::RefreshCredentials => Some(Reload),
        ServiceState::Running => Some(Stop),
        ServiceState::Mounting => Some(Mount),
        ServiceState::Stop => Some(from_mode(
            stop_mode,
            ServiceState::StopSigterm,
            ServiceState::StopWatchdog,
            ServiceState::StopSigkill,
            StopPost,
        )),
        ServiceState::StopWatchdog => Some(if send_sigkill {
            Signal(ServiceState::StopSigkill)
        } else {
            StopPost
        }),
        ServiceState::StopSigterm => Some(if stop_mode == Abort {
            Signal(ServiceState::StopWatchdog)
        } else if send_sigkill {
            Signal(ServiceState::StopSigkill)
        } else {
            StopPost
        }),
        ServiceState::StopSigkill => Some(StopPost),
        ServiceState::StopPost => Some(from_mode(
            stop_mode,
            ServiceState::FinalSigterm,
            ServiceState::FinalWatchdog,
            ServiceState::FinalSigkill,
            Dead {
                allow_restart: false,
            },
        )),
        ServiceState::FinalWatchdog => Some(if send_sigkill {
            Signal(ServiceState::FinalSigkill)
        } else {
            Dead {
                allow_restart: false,
            }
        }),
        ServiceState::FinalSigterm => Some(if stop_mode == Abort {
            Signal(ServiceState::FinalWatchdog)
        } else if send_sigkill {
            Signal(ServiceState::FinalSigkill)
        } else {
            Dead {
                allow_restart: false,
            }
        }),
        ServiceState::FinalSigkill => Some(Dead {
            allow_restart: true,
        }),
        _ => None,
    }
}

impl RuntimeManager {
    pub(super) fn timeout_failure_modes(
        &self,
        name: &str,
    ) -> (ServiceTimeoutFailureMode, ServiceTimeoutFailureMode) {
        let info = self.unit_files.get(name);
        (
            info.and_then(|info| info.service.timeout_start_failure_mode)
                .unwrap_or(ServiceTimeoutFailureMode::Terminate),
            info.and_then(|info| info.service.timeout_stop_failure_mode)
                .unwrap_or(ServiceTimeoutFailureMode::Terminate),
        )
    }

    pub(super) fn apply_service_timeout(&mut self, name: &str, state: ServiceState) -> bool {
        let (start_mode, stop_mode) = self.timeout_failure_modes(name);
        let send_sigkill = self
            .unit_files
            .get(name)
            .and_then(|info| info.kill.send_sigkill)
            .unwrap_or(true);
        let Some(action) = service_timeout_action(state, start_mode, stop_mode, send_sigkill)
        else {
            return false;
        };

        match action {
            ServiceTimeoutAction::Signal(next) => {
                self.enter_signal(name, next, ServiceResult::FailureTimeout)
            }
            ServiceTimeoutAction::Stop => self.enter_stop(name, ServiceResult::FailureTimeout),
            ServiceTimeoutAction::StopPost => self.enter_stop_post(name),
            ServiceTimeoutAction::Dead { allow_restart } => {
                self.enter_dead(name, ServiceResult::FailureTimeout, allow_restart)
            }
            ServiceTimeoutAction::Reload => {
                self.kill_service_control_process(name);
                self.reload_finish(name, ServiceResult::FailureTimeout);
            }
            ServiceTimeoutAction::Mount => {
                // RuntimeManager does not yet accept live-mount requests, so
                // there is no pending bus request to complete here. Still
                // mirror the observable process/state portion of C
                // service_dispatch_timer(): kill the mount helper and
                // re-evaluate service liveness.
                self.kill_service_control_process(name);
                self.enter_running(name);
            }
        }
        true
    }

    fn kill_service_control_process(&self, name: &str) {
        let control_pid = self
            .units
            .get(name)
            .and_then(|unit| unit.control_pid)
            .map(|pid| pid.0);
        if let Some(pid) = control_pid.filter(|pid| *pid > 1 && *pid != std::process::id()) {
            let _ = self.process_tracker.signal(pid, libc::SIGKILL);
        }
    }

    pub(super) fn record_service_main_exit_status(&mut self, name: &str, state: ChildState) {
        if let Some(service) = self.services.get_mut(name) {
            service.main_exec_status.last_exit = match state {
                ChildState::ExitedCleanly => Some(ServiceExitStatus::ExitCode(0)),
                ChildState::ExitedWithCode(code) => Some(ServiceExitStatus::ExitCode(code)),
                ChildState::KilledBySignal(signal) => Some(ServiceExitStatus::Signal(signal)),
                ChildState::Running => None,
            };
        }
    }

    pub(super) fn begin_stop_signal(&mut self, name: &str, result: ServiceResult) {
        self.enter_signal(name, ServiceState::StopSigterm, result);
    }

    pub(super) fn enter_final_signal(&mut self, name: &str, result: ServiceResult) {
        self.enter_signal(name, ServiceState::FinalSigterm, result);
    }

    fn signal_for_service_state(&self, name: &str, state: ServiceState) -> i32 {
        let info = self.unit_files.get(name);
        match state {
            ServiceState::StopWatchdog | ServiceState::FinalWatchdog => info
                .and_then(|info| info.kill.watchdog_signal)
                .unwrap_or(libc::SIGABRT),
            ServiceState::StopSigkill | ServiceState::FinalSigkill => info
                .and_then(|info| info.kill.final_kill_signal)
                .unwrap_or(libc::SIGKILL),
            _ => self.service_kill_signal(name, libc::SIGTERM),
        }
    }

    fn signal_state_is_cgroup_wide(&self, name: &str, state: ServiceState) -> bool {
        let kill_mode = self
            .unit_files
            .get(name)
            .and_then(|info| info.kill.kill_mode)
            .unwrap_or(KillMode::ControlGroup);
        kill_mode == KillMode::ControlGroup
            || (kill_mode == KillMode::Mixed
                && matches!(
                    state,
                    ServiceState::StopSigkill | ServiceState::FinalSigkill
                ))
    }

    fn signal_service_processes(&mut self, name: &str, state: ServiceState) -> bool {
        let signal = self.signal_for_service_state(name, state);
        let kill_mode = self
            .unit_files
            .get(name)
            .and_then(|info| info.kill.kill_mode)
            .unwrap_or(KillMode::ControlGroup);
        if kill_mode == KillMode::None {
            return false;
        }
        let (main_pid, control_pid, watched_pids) = self
            .units
            .get(name)
            .map(|unit| {
                (
                    unit.main_pid.map(|pid| pid.0),
                    unit.control_pid.map(|pid| pid.0),
                    unit.watched_pids
                        .iter()
                        .map(|pid| pid.0)
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap_or((None, None, Vec::new()));
        let cgroup_wide = self.signal_state_is_cgroup_wide(name, state);

        let mut targets = BTreeSet::new();
        // A superseded Exec* helper is manager-owned even with
        // KillMode=process and must not outlive the transaction which replaced
        // it. KillMode=none returned above and deliberately touches no process.
        if let Some(pid) = control_pid {
            targets.insert(pid);
        }
        if kill_mode != KillMode::None
            && let Some(pid) = main_pid
        {
            targets.insert(pid);
        }
        if cgroup_wide {
            match self.read_unit_cgroup_pids(name) {
                Ok(pids) => targets.extend(pids),
                Err(error) => {
                    // Failure to inspect a realized cgroup is not proof that it
                    // is empty. Retain the signal state until its deadline.
                    eprintln!("systemd: cannot enumerate processes for {name}: {error}");
                    for pid in watched_pids {
                        targets.insert(pid);
                    }
                }
            }
        }

        for pid in &targets {
            let _ = self.process_tracker.signal(*pid, signal);
        }

        if cgroup_wide {
            match self.read_unit_cgroup_populated(name) {
                Some(false) => false,
                Some(true) => true,
                None => !targets.is_empty() || self.unit_has_tracked_processes(name),
            }
        } else {
            !targets.is_empty()
        }
    }

    pub(super) fn maybe_complete_service_kill_phase(&mut self, name: &str, state: ServiceState) {
        if state == ServiceState::StopPost {
            let pids_gone = self
                .units
                .get(name)
                .is_none_or(|unit| unit.main_pid.is_none() && unit.control_pid.is_none());
            if pids_gone {
                self.enter_final_signal(name, ServiceResult::Success);
            }
            return;
        }

        if self.signal_state_is_cgroup_wide(name, state) {
            self.refresh_unit_cgroup_state(name);
            return;
        }

        let pids_gone = self
            .units
            .get(name)
            .is_none_or(|unit| unit.main_pid.is_none() && unit.control_pid.is_none());
        if pids_gone {
            self.advance_signal_state(name, state, ServiceResult::Success);
        }
    }

    pub(super) fn advance_signal_state(
        &mut self,
        name: &str,
        state: ServiceState,
        result: ServiceResult,
    ) {
        let send_sigkill = self
            .unit_files
            .get(name)
            .and_then(|info| info.kill.send_sigkill)
            .unwrap_or(true);
        match state {
            ServiceState::StopWatchdog | ServiceState::StopSigterm if send_sigkill => {
                self.enter_signal(name, ServiceState::StopSigkill, result)
            }
            ServiceState::StopWatchdog | ServiceState::StopSigterm | ServiceState::StopSigkill => {
                self.enter_stop_post(name)
            }
            ServiceState::FinalWatchdog | ServiceState::FinalSigterm if send_sigkill => {
                self.enter_signal(name, ServiceState::FinalSigkill, result)
            }
            ServiceState::FinalWatchdog
            | ServiceState::FinalSigterm
            | ServiceState::FinalSigkill => self.enter_dead(name, result, true),
            _ => {}
        }
    }

    pub(super) fn enter_signal(&mut self, name: &str, state: ServiceState, result: ServiceResult) {
        if let Some(service) = self.services.get_mut(name) {
            service_record_result(service, result);
            service.control_command_id = None;
        }
        self.service_command_sequences.remove(name);
        self.service_operation_deadlines.remove(name);
        self.set_service_state(name, state);
        let wait_required = self.signal_service_processes(name, state);
        if wait_required {
            if let Some(info) = self.unit_files.get(name).cloned() {
                self.arm_signal_deadline(name, state, &info);
            } else {
                self.advance_signal_state(name, state, ServiceResult::FailureResources);
            }
        } else {
            self.advance_signal_state(name, state, result);
        }
    }

    pub(super) fn enter_stop_post(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            self.enter_final_signal(name, ServiceResult::FailureResources);
            return;
        };
        self.begin_command_sequence(
            name,
            ServiceExecCommand::StopPost,
            Self::service_phase_specs(&info, ServiceExecCommand::StopPost),
        );
    }

    fn should_restart_for_terminal(
        &self,
        name: &str,
        info: &UnitFileInfo,
        result: ServiceResult,
    ) -> bool {
        let service = self.services.get(name);
        let main_status_tokens =
            match service.and_then(|service| service.main_exec_status.last_exit) {
                Some(ServiceExitStatus::ExitCode(code)) => vec![code.to_string()],
                Some(ServiceExitStatus::Signal(signal)) => {
                    let mut tokens = vec![signal.to_string()];
                    if let Some(name) = super::signal_token(signal) {
                        tokens.push(name.to_string());
                    }
                    tokens
                }
                None => Vec::new(),
            };
        if status_list_matches(
            &main_status_tokens,
            &info.service.restart_prevent_exit_status,
        ) {
            return false;
        }
        if status_list_matches(&main_status_tokens, &info.service.restart_force_exit_status) {
            let oneshot =
                service.is_some_and(|service| service.service_type == ServiceType::Oneshot);
            return !(oneshot && result == ServiceResult::Success);
        }

        let policy = info.service.restart.unwrap_or(ServiceRestartPolicy::No);
        match result {
            ServiceResult::SkipCondition => false,
            ServiceResult::Success => matches!(
                policy,
                ServiceRestartPolicy::Always | ServiceRestartPolicy::OnSuccess
            ),
            ServiceResult::FailureExitCode => matches!(
                policy,
                ServiceRestartPolicy::Always | ServiceRestartPolicy::OnFailure
            ),
            ServiceResult::FailureWatchdog => matches!(
                policy,
                ServiceRestartPolicy::Always
                    | ServiceRestartPolicy::OnFailure
                    | ServiceRestartPolicy::OnAbnormal
                    | ServiceRestartPolicy::OnWatchdog
            ),
            ServiceResult::FailureSignal | ServiceResult::FailureCoreDump => matches!(
                policy,
                ServiceRestartPolicy::Always
                    | ServiceRestartPolicy::OnFailure
                    | ServiceRestartPolicy::OnAbnormal
                    | ServiceRestartPolicy::OnAbort
            ),
            _ => matches!(
                policy,
                ServiceRestartPolicy::Always
                    | ServiceRestartPolicy::OnFailure
                    | ServiceRestartPolicy::OnAbnormal
            ),
        }
    }

    pub(super) fn enter_dead(&mut self, name: &str, result: ServiceResult, allow_restart: bool) {
        let current_state = self.services.get(name).map(|service| service.state);
        if current_state == Some(ServiceState::Failed)
            || (matches!(
                current_state,
                Some(ServiceState::Dead | ServiceState::DeadResourcesPinned)
            ) && matches!(
                result,
                ServiceResult::Success | ServiceResult::SkipCondition
            ))
        {
            return;
        }
        if let Some(service) = self.services.get_mut(name) {
            service_record_result(service, result);
            service.control_command_id = None;
        }
        let final_result = self
            .services
            .get(name)
            .map(|service| service.result)
            .unwrap_or(result);
        self.clear_service_tracking(name);
        self.service_command_sequences.remove(name);
        self.service_operation_deadlines.remove(name);
        if let Some(info) = self.unit_files.get(name).cloned() {
            self.apply_tty_cleanup(&info);
            self.cleanup_runtime_directories_for_unit(name, &info.exec_context);
        }
        self.socket_mgr.unregister_socket(name);

        let succeeded = matches!(
            final_result,
            ServiceResult::Success | ServiceResult::SkipCondition
        );
        self.set_service_state(
            name,
            if succeeded {
                ServiceState::Dead
            } else {
                ServiceState::Failed
            },
        );
        // A skipped condition is an inactive-to-inactive result, not a
        // successful activation, so it publishes neither OnSuccess nor
        // OnFailure.
        if final_result != ServiceResult::SkipCondition {
            self.trigger_dependency_units(
                name,
                if succeeded {
                    DependencyKind::OnSuccess
                } else {
                    DependencyKind::OnFailure
                },
            );
        }

        let explicit_restart = self.service_restart_after_stop.contains(name);
        let stop_pending = self.units.get(name).is_some_and(|unit| unit.stop_pending);
        if let Some(unit) = self.units.get_mut(name) {
            unit.stop_pending = false;
        }
        if explicit_restart {
            self.dispatch_pending_explicit_restart(name);
            return;
        }
        if !allow_restart || stop_pending {
            return;
        }
        let Some(info) = self.unit_files.get(name).cloned() else {
            return;
        };
        if self.should_restart_for_terminal(name, &info, final_result) {
            let delay = self.restart_delay_for(name);
            self.schedule_service_restart(name.to_string(), delay);
        }
    }

    /// Deliver authoritative cgroup-empty state to the service machine.
    ///
    /// Empty cgroups between consecutive control commands are expected and
    /// must not publish `Dead`. Running and stop/final states re-evaluate the
    /// canonical lifecycle because kernel emptiness is stronger evidence than
    /// a stale numeric PID slot.
    pub(super) fn service_cgroup_empty_event(&mut self, name: &str) {
        let alien_main = self
            .units
            .get(name)
            .and_then(|unit| unit.main_pid)
            .map(|pid| pid.0)
            .filter(|pid| self.process_tracker.get(*pid).is_none());
        if let Some(pid) = alien_main {
            if let Some(unit) = self.units.get_mut(name) {
                if unit.main_pid.map(|pidref| pidref.0) == Some(pid) {
                    unit.main_pid = None;
                }
                unit.watched_pids.retain(|pidref| pidref.0 != pid);
            }
            let _ = self.process_tracker.remove_adopted(pid);
            self.pid_to_unit_map.remove(&pid);
            self.pid_role_map.remove(&pid);
            if self.unit_pid_map.get(name).copied() == Some(pid) {
                self.unit_pid_map.remove(name);
            }
        }

        let pids_gone = self
            .units
            .get(name)
            .is_none_or(|unit| unit.main_pid.is_none() && unit.control_pid.is_none());
        match self.services.get(name).map(|service| service.state) {
            Some(ServiceState::Running) => self.enter_running(name),
            Some(
                ServiceState::StopSigterm | ServiceState::StopSigkill | ServiceState::StopWatchdog,
            ) if pids_gone => self.enter_stop_post(name),
            Some(ServiceState::StopPost) if pids_gone => {
                self.enter_dead(name, ServiceResult::Success, true)
            }
            Some(
                ServiceState::FinalSigterm
                | ServiceState::FinalSigkill
                | ServiceState::FinalWatchdog,
            ) if pids_gone => self.enter_dead(name, ServiceResult::Success, true),
            _ => {}
        }
    }
}
