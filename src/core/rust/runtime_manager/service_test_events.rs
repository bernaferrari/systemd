// SPDX-License-Identifier: LGPL-2.1-or-later

//! Test-only, deterministic ingress for the service event state machine.

use std::time::Instant;

use super::service_machine::{
    pid_role_for_command, state_for_command, ServiceCommandSequence, ServiceOperationDeadline,
};
use super::{infer_service_type, ExecCommandSpec, Result, RuntimeManager, TrackedPidRole};
use crate::ffi::Errno;
use crate::service::ServiceState;
use crate::service_tables::ServiceExecCommand;
use systemd_platform_rs::spawn::ChildState;

/// Synthetic event ingress for deterministic service-machine tests.
///
/// This module is compiled only for the crate's tests. Production child
/// completion, exec acknowledgement, deadlines, and cgroup changes continue
/// to arrive from their kernel/event-loop sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceTestEvent {
    ChildExited { pid: u32, state: ChildState },
    Execed { pid: u32 },
    Timeout,
    CgroupEmpty,
}

impl RuntimeManager {
    pub(crate) fn inject_test_service_event(
        &mut self,
        name: &str,
        event: ServiceTestEvent,
    ) -> bool {
        let name = self.canonical_unit_name(name);
        match event {
            ServiceTestEvent::ChildExited { pid, state }
                if self.pid_to_unit_map.get(&pid).map(String::as_str) == Some(name.as_str()) =>
            {
                self.dispatch_service_child_exit(pid, state).is_some()
            }
            ServiceTestEvent::Execed { pid }
                if self.pid_to_unit_map.get(&pid).map(String::as_str) == Some(name.as_str())
                    && matches!(
                        self.services.get(&name).map(|service| service.state),
                        Some(ServiceState::Start)
                    )
                    && self
                        .units
                        .get(&name)
                        .and_then(|unit| unit.main_pid)
                        .is_some_and(|main_pid| main_pid.0 == pid) =>
            {
                self.enter_start_post(&name);
                true
            }
            ServiceTestEvent::Timeout => {
                let Some(deadline) = self.service_operation_deadlines.get(&name).copied() else {
                    return false;
                };
                self.service_operation_deadlines.insert(
                    name.clone(),
                    ServiceOperationDeadline {
                        deadline: Instant::now(),
                        ..deadline
                    },
                );
                let mut restarts = Vec::new();
                self.enforce_service_deadlines(&mut restarts)
                    .into_iter()
                    .any(|changed| changed == name)
            }
            ServiceTestEvent::CgroupEmpty => {
                self.service_cgroup_empty_event(&name);
                true
            }
            _ => false,
        }
    }

    pub(crate) fn inject_test_service_command(
        &mut self,
        name: &str,
        phase: ServiceExecCommand,
        pid: u32,
        prefixes: &str,
    ) -> Result<()> {
        let name = self.canonical_unit_name(name);
        let info = self.unit_files.get(&name).cloned().ok_or(Errno::ENOENT)?;
        let service_type = self
            .services
            .get(&name)
            .map(|service| service.service_type)
            .unwrap_or_else(|| infer_service_type(&info));
        let role = pid_role_for_command(phase, service_type);
        let mut sequence = ServiceCommandSequence::new(
            phase,
            vec![ExecCommandSpec {
                prefixes: prefixes.to_string(),
                command: "/test/service-fsm".to_string(),
            }],
        )
        .expect("one synthetic command is non-empty");
        sequence.set_active_pid(pid);
        self.service_command_sequences
            .insert(name.clone(), sequence);
        self.set_service_state(&name, state_for_command(phase));
        if let Some(unit) = self.units.get_mut(&name) {
            match role {
                TrackedPidRole::Main => unit.main_pid = Some(crate::unit::PidRef(pid)),
                TrackedPidRole::Control => unit.control_pid = Some(crate::unit::PidRef(pid)),
                TrackedPidRole::Unknown => {}
            }
            unit.watched_pids.insert(crate::unit::PidRef(pid));
        }
        if let Some(service) = self.services.get_mut(&name) {
            service.control_command_id = (role == TrackedPidRole::Control).then_some(phase);
        }
        self.track_pid(&name, pid, role);
        self.arm_operation_deadline(&name, phase, pid, &info);
        Ok(())
    }

    pub(crate) fn inject_test_service_signal_deadline(
        &mut self,
        name: &str,
        state: ServiceState,
    ) -> Result<()> {
        let name = self.canonical_unit_name(name);
        if self.services.get(&name).map(|service| service.state) != Some(state) {
            return Err(Errno::EALREADY);
        }
        self.service_operation_deadlines.insert(
            name,
            ServiceOperationDeadline::signal(state, Instant::now()),
        );
        Ok(())
    }
}
