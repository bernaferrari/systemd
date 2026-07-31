// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/main.c invoke_main_loop()

//! Ownership policy between the manager event loop and PID 1's outer
//! lifecycle.
//!
//! C `manager_reload()` serializes manager state and its descriptor set before
//! a marked point of no return. Rust can non-destructively assess whether its
//! process-local state and descriptor roles are representable, but has no
//! versioned serializer/adopter yet. Reload is therefore rejected before
//! ownership changes and the exact live manager resumes unchanged. Every other
//! objective remains terminal until its full state-transfer contract exists.

use crate::pid1_lifecycle::{OuterLoopExit, outer_loop_exit};
use crate::pid1_manager_commands::PendingObjectiveRequest;
use crate::runtime_manager::{
    HandoffImageError, HandoffPrecommitImage, HandoffPurpose, PrepareHandoffError, RuntimeManager,
};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadPreparationError {
    RuntimeStateNotTransferable(PrepareHandoffError),
    /// Descriptor ownership has been duplicated and a versioned precommit
    /// image round-tripped, but the image advertises incomplete state
    /// coverage. The transaction was rolled back before returning this error.
    VersionedAdopterUnavailable {
        image: HandoffPrecommitImage,
        encoded_size: usize,
    },
}

impl std::fmt::Display for ReloadPreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeStateNotTransferable(error) => write!(
                formatter,
                "manager state cannot enter a live handoff: {error}"
            ),
            Self::VersionedAdopterUnavailable {
                image,
                encoded_size,
            } => write!(
                formatter,
                "manager reload prepared a {encoded_size}-byte versioned image for {} units, {} jobs, and {} descriptor roles, but complete manager-state adoption is unavailable",
                image.assessment().unit_count(),
                image.assessment().job_count(),
                image.descriptor_count(),
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
    // Match C's duplicate/serialize-before-commit shape, but stop before its
    // destructive re-enumeration phase. The prepared owner contains both the
    // exact live manager and CLOEXEC duplicates. Every failure rolls that
    // owner back; no descriptor flag or manager field is mutated.
    let (runtime, error) = match runtime.prepare_live_handoff(HandoffPurpose::ReloadInProcess) {
        Ok(prepared) => {
            let encoded = match prepared.image().encode() {
                Ok(encoded) => encoded,
                Err(error) => {
                    return ReloadPreparationResult::FailedBeforePointOfNoReturn {
                        runtime: prepared.rollback(),
                        error: ReloadPreparationError::RuntimeStateNotTransferable(
                            PrepareHandoffError::HandoffImage(error),
                        ),
                        pending_reply,
                    };
                }
            };
            let decoded = match HandoffPrecommitImage::decode(&encoded) {
                Ok(decoded) => decoded,
                Err(error) => {
                    return ReloadPreparationResult::FailedBeforePointOfNoReturn {
                        runtime: prepared.rollback(),
                        error: ReloadPreparationError::RuntimeStateNotTransferable(
                            PrepareHandoffError::HandoffImage(error),
                        ),
                        pending_reply,
                    };
                }
            };
            let descriptor_count = prepared.descriptor_count();
            if decoded != *prepared.image() {
                return ReloadPreparationResult::FailedBeforePointOfNoReturn {
                    runtime: prepared.rollback(),
                    error: ReloadPreparationError::RuntimeStateNotTransferable(
                        PrepareHandoffError::HandoffImage(HandoffImageError::RoundTripMismatch),
                    ),
                    pending_reply,
                };
            }
            match decoded.validate_for_adoption(HandoffPurpose::ReloadInProcess, descriptor_count) {
                Err(HandoffImageError::IncompleteStateCoverage) | Ok(()) => {}
                Err(error) => {
                    return ReloadPreparationResult::FailedBeforePointOfNoReturn {
                        runtime: prepared.rollback(),
                        error: ReloadPreparationError::RuntimeStateNotTransferable(
                            PrepareHandoffError::HandoffImage(error),
                        ),
                        pending_reply,
                    };
                }
            }
            let encoded_size = encoded.len();
            (
                prepared.rollback(),
                ReloadPreparationError::VersionedAdopterUnavailable {
                    image: decoded,
                    encoded_size,
                },
            )
        }
        Err(rejected) => {
            let (runtime, error) = rejected.into_parts();
            (
                runtime,
                ReloadPreparationError::RuntimeStateNotTransferable(error),
            )
        }
    };
    ReloadPreparationResult::FailedBeforePointOfNoReturn {
        runtime,
        error,
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

        let ReloadPreparationError::VersionedAdopterUnavailable {
            image,
            encoded_size,
        } = error
        else {
            panic!("quiescent manager must reach the adopter boundary");
        };
        assert_eq!(image.purpose(), HandoffPurpose::ReloadInProcess);
        assert!(image.descriptor_count() >= 1);
        assert!(encoded_size > 0);
        assert_eq!(
            image.validate_for_adoption(HandoffPurpose::ReloadInProcess, image.descriptor_count()),
            Err(HandoffImageError::IncompleteStateCoverage)
        );
        assert_eq!(
            runtime
                .get_unit("preserved.target")
                .map(|unit| unit.active_state),
            Some(ActiveState::Active)
        );
    }

    #[test]
    fn reload_preflight_rejects_untransferable_state_without_mutation() {
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit("running.service", "running", ActiveState::Active, "running");
        runtime.inject_test_main_pid("running.service", 19);

        let disposition =
            prepare_outer_lifecycle(ManagerLoopExit::from_signal(OuterLoopExit::Reload, runtime));
        let OuterLifecycleDisposition::ReloadPreparation(
            ReloadPreparationResult::FailedBeforePointOfNoReturn { runtime, error, .. },
        ) = disposition
        else {
            panic!("reload must remain recoverable before the point of no return");
        };

        assert!(matches!(
            error,
            ReloadPreparationError::RuntimeStateNotTransferable(
                PrepareHandoffError::LiveProcessLacksStableIdentity
            )
        ));
        assert_eq!(
            runtime
                .get_unit("running.service")
                .and_then(|unit| unit.main_pid)
                .map(|pid| pid.0),
            Some(19)
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
