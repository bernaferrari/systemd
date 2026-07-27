// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/service.c

//! Transient command-list ownership for the canonical service state machine.
//!
//! `Service.state`, `Service.control_command_id`, `Service.result`, the Unit
//! main/control PID slots, and RuntimeManager's timers remain authoritative.
//! This module deliberately does not introduce a second lifecycle enum, PID
//! slot, result, or timer. It retains only the stable `Exec*` list snapshot and
//! its cursor, so daemon-reload cannot replace commands in a sequence already
//! in flight.

use crate::service::{ServiceState, ServiceType};
use crate::service_tables::ServiceExecCommand;

use super::{ExecCommandSpec, TrackedPidRole};
use std::time::Instant;

/// Whether successful `fork()` itself is the service's startup acknowledgement.
///
/// Oneshot must wait for the main command to exit, Exec waits for `execve()`,
/// forking waits for its starter, and notify/D-Bus types wait for authenticated
/// external readiness. Only simple/idle have fork-complete startup semantics.
pub(super) const fn start_post_after_fork(service_type: ServiceType) -> bool {
    matches!(service_type, ServiceType::Simple | ServiceType::Idle)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ServiceCommandIndex(usize);

impl ServiceCommandIndex {
    pub(super) const fn get(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ServiceControlCommand {
    pub(super) phase: ServiceExecCommand,
    pub(super) index: ServiceCommandIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServiceCommandSequence {
    phase: ServiceExecCommand,
    commands: Vec<ExecCommandSpec>,
    index: ServiceCommandIndex,
    /// Exact child currently executing this cursor. This is a transient
    /// correlation token, not a second lifecycle PID owner.
    active_pid: Option<u32>,
}

/// Identity of the operation which owns a service deadline.
///
/// Commands retain exact child identity. Signal phases are cgroup operations,
/// so their canonical `ServiceState` is the correlation token instead of one
/// arbitrarily selected PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServiceOperationOwner {
    Command { phase: ServiceExecCommand, pid: u32 },
    Signal(ServiceState),
}

/// One timeout tied to the exact command child or signal state which armed it.
///
/// Keeping this identity next to the deadline prevents a late timer from a
/// previous command (or a reused numeric PID) from failing the operation which
/// happens to be current when the timer is dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ServiceOperationDeadline {
    pub(super) owner: ServiceOperationOwner,
    pub(super) deadline: Instant,
}

impl ServiceOperationDeadline {
    pub(super) const fn command(phase: ServiceExecCommand, pid: u32, deadline: Instant) -> Self {
        Self {
            owner: ServiceOperationOwner::Command { phase, pid },
            deadline,
        }
    }

    pub(super) const fn signal(state: ServiceState, deadline: Instant) -> Self {
        Self {
            owner: ServiceOperationOwner::Signal(state),
            deadline,
        }
    }
}

impl ServiceCommandSequence {
    pub(super) fn new(phase: ServiceExecCommand, commands: Vec<ExecCommandSpec>) -> Option<Self> {
        (!commands.is_empty()).then_some(Self {
            phase,
            commands,
            index: ServiceCommandIndex(0),
            active_pid: None,
        })
    }

    pub(super) const fn cursor(&self) -> ServiceControlCommand {
        ServiceControlCommand {
            phase: self.phase,
            index: self.index,
        }
    }

    pub(super) fn current(&self) -> &ExecCommandSpec {
        // `new()` and `advance()` preserve this bound.
        &self.commands[self.index.0]
    }

    pub(super) fn set_active_pid(&mut self, pid: u32) {
        self.active_pid = Some(pid);
    }

    pub(super) fn owns_pid(&self, pid: u32) -> bool {
        self.active_pid == Some(pid)
    }

    /// Advance after the current child was successfully reaped.
    ///
    /// Returning false leaves the cursor at the final command so completion
    /// handling can still report the exact command which finished.
    pub(super) fn advance(&mut self) -> bool {
        let Some(next) = self.index.0.checked_add(1) else {
            return false;
        };
        if next >= self.commands.len() {
            return false;
        }
        self.index = ServiceCommandIndex(next);
        self.active_pid = None;
        true
    }
}

pub(super) const fn state_for_command(command: ServiceExecCommand) -> ServiceState {
    match command {
        ServiceExecCommand::Condition => ServiceState::Condition,
        ServiceExecCommand::StartPre => ServiceState::StartPre,
        ServiceExecCommand::Start => ServiceState::Start,
        ServiceExecCommand::StartPost => ServiceState::StartPost,
        ServiceExecCommand::Reload => ServiceState::Reload,
        ServiceExecCommand::ReloadPost => ServiceState::ReloadPost,
        ServiceExecCommand::Stop => ServiceState::Stop,
        ServiceExecCommand::StopPost => ServiceState::StopPost,
    }
}

pub(super) const fn pid_role_for_command(
    command: ServiceExecCommand,
    service_type: ServiceType,
) -> TrackedPidRole {
    if matches!(command, ServiceExecCommand::Start) && !matches!(service_type, ServiceType::Forking)
    {
        TrackedPidRole::Main
    } else {
        TrackedPidRole::Control
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(command: &str) -> ExecCommandSpec {
        ExecCommandSpec {
            prefixes: String::new(),
            command: command.to_string(),
        }
    }

    #[test]
    fn sequence_retains_a_stable_snapshot_and_exact_cursor() {
        let mut sequence = ServiceCommandSequence::new(
            ServiceExecCommand::StartPre,
            vec![spec("/bin/first"), spec("/bin/second")],
        )
        .unwrap();
        assert_eq!(sequence.cursor().phase, ServiceExecCommand::StartPre);
        assert_eq!(sequence.cursor().index.get(), 0);
        assert_eq!(sequence.current().command, "/bin/first");
        sequence.set_active_pid(41);
        assert!(sequence.owns_pid(41));
        assert!(!sequence.owns_pid(42));

        assert!(sequence.advance());
        assert!(!sequence.owns_pid(41));
        assert_eq!(sequence.cursor().index.get(), 1);
        assert_eq!(sequence.current().command, "/bin/second");
        assert!(!sequence.advance());
        assert_eq!(sequence.cursor().index.get(), 1);
    }

    #[test]
    fn start_pid_role_is_service_type_policy() {
        assert!(start_post_after_fork(ServiceType::Simple));
        assert!(start_post_after_fork(ServiceType::Idle));
        assert!(!start_post_after_fork(ServiceType::Oneshot));
        assert!(!start_post_after_fork(ServiceType::Exec));
        assert!(!start_post_after_fork(ServiceType::Forking));
        assert_eq!(
            pid_role_for_command(ServiceExecCommand::Start, ServiceType::Simple),
            TrackedPidRole::Main
        );
        assert_eq!(
            pid_role_for_command(ServiceExecCommand::Start, ServiceType::Oneshot),
            TrackedPidRole::Main
        );
        assert_eq!(
            pid_role_for_command(ServiceExecCommand::Start, ServiceType::Forking),
            TrackedPidRole::Control
        );
        assert_eq!(
            pid_role_for_command(ServiceExecCommand::StartPost, ServiceType::Simple),
            TrackedPidRole::Control
        );
    }

    #[test]
    fn reload_post_maps_to_the_canonical_reload_post_state() {
        assert_eq!(
            state_for_command(ServiceExecCommand::ReloadPost),
            ServiceState::ReloadPost
        );
    }
}
