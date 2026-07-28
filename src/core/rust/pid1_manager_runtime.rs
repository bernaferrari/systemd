// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/main.c invoke_main_loop()

//! Ownership policy between the manager event loop and PID 1's outer
//! lifecycle.
//!
//! C `manager_reload()` serializes manager state and its descriptor set before
//! a marked point of no return. Rust has no versioned serializer/adopter yet,
//! so reload is rejected before handoff preparation and the exact live manager
//! resumes unchanged. Every other objective remains terminal until its full
//! state-transfer contract exists.

use crate::pid1_lifecycle::{OuterLoopExit, outer_loop_exit};
use crate::pid1_manager_commands::PendingObjectiveRequest;
use crate::runtime_manager::RuntimeManager;

pub struct ManagerLoopExit {
    objective: OuterLoopExit,
    runtime: RuntimeManager,
    pending_reply: Option<PendingObjectiveRequest>,
}

impl ManagerLoopExit {
    pub fn from_signal(objective: OuterLoopExit, runtime: RuntimeManager) -> Self {
        Self {
            objective,
            runtime,
            pending_reply: None,
        }
    }

    pub fn from_command(runtime: RuntimeManager, request: PendingObjectiveRequest) -> Option<Self> {
        let objective = outer_loop_exit(request.objective())?;
        Some(Self {
            objective,
            runtime,
            pending_reply: Some(request),
        })
    }

    pub fn into_parts(
        self,
    ) -> (
        OuterLoopExit,
        RuntimeManager,
        Option<PendingObjectiveRequest>,
    ) {
        (self.objective, self.runtime, self.pending_reply)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadPreparationError {
    VersionedAdopterUnavailable,
}

impl std::fmt::Display for ReloadPreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionedAdopterUnavailable => formatter.write_str(
                "manager reload has no versioned state/descriptor adopter; request rejected before handoff preparation",
            ),
        }
    }
}

impl std::error::Error for ReloadPreparationError {}

pub enum ReloadPreparationResult {
    /// Preparation failed before the commit point. The exact live manager
    /// owner has not been dismantled and may re-enter normal dispatch.
    FailedBeforePointOfNoReturn {
        runtime: RuntimeManager,
        error: ReloadPreparationError,
        pending_reply: Option<PendingObjectiveRequest>,
    },
}

pub enum OuterLifecycleDisposition {
    ReloadPreparation(ReloadPreparationResult),
    /// This objective cannot safely resume the old manager.
    TerminalUnsupported(ManagerLoopExit),
}

fn prepare_reload(
    runtime: RuntimeManager,
    pending_reply: Option<PendingObjectiveRequest>,
) -> ReloadPreparationResult {
    // No manager state or descriptor ownership has changed. Do not run typed
    // handoff preflight or duplicate descriptors until a versioned adopter can
    // consume them and complete C's serialize/clear/deserialize transaction.
    ReloadPreparationResult::FailedBeforePointOfNoReturn {
        runtime,
        error: ReloadPreparationError::VersionedAdopterUnavailable,
        pending_reply,
    }
}

pub fn prepare_outer_lifecycle(exit: ManagerLoopExit) -> OuterLifecycleDisposition {
    match exit {
        ManagerLoopExit {
            objective: OuterLoopExit::Reload,
            runtime,
            pending_reply,
        } => OuterLifecycleDisposition::ReloadPreparation(prepare_reload(runtime, pending_reply)),
        terminal => OuterLifecycleDisposition::TerminalUnsupported(terminal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pid1_lifecycle::ShutdownObjective;
    use crate::unit::ActiveState;

    #[test]
    fn unsupported_reload_preparation_returns_the_same_live_manager_state() {
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "preserved.target",
            "preserved",
            ActiveState::Active,
            "active",
        );

        let disposition =
            prepare_outer_lifecycle(ManagerLoopExit::from_signal(OuterLoopExit::Reload, runtime));
        let OuterLifecycleDisposition::ReloadPreparation(
            ReloadPreparationResult::FailedBeforePointOfNoReturn { runtime, error, .. },
        ) = disposition
        else {
            panic!("reload must remain recoverable before the point of no return");
        };

        assert_eq!(error, ReloadPreparationError::VersionedAdopterUnavailable);
        assert_eq!(
            runtime
                .get_unit("preserved.target")
                .map(|unit| unit.active_state),
            Some(ActiveState::Active)
        );
    }

    #[test]
    fn state_transferring_and_shutdown_objectives_never_resume() {
        for objective in [
            OuterLoopExit::Reexecute,
            OuterLoopExit::SwitchRoot,
            OuterLoopExit::SoftReboot,
            OuterLoopExit::Exit,
            OuterLoopExit::Shutdown(ShutdownObjective::Halt),
            OuterLoopExit::Shutdown(ShutdownObjective::Poweroff),
            OuterLoopExit::Shutdown(ShutdownObjective::Reboot),
            OuterLoopExit::Shutdown(ShutdownObjective::Kexec),
        ] {
            assert!(matches!(
                prepare_outer_lifecycle(ManagerLoopExit::from_signal(
                    objective,
                    RuntimeManager::new(),
                )),
                OuterLifecycleDisposition::TerminalUnsupported(_)
            ));
        }
    }
}
