// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus-manager.c (typed manager command handoff).

//! Transport-neutral commands for the single PID 1 [`RuntimeManager`] owner.
//!
//! A D-Bus server may enqueue work here after it has authenticated the peer,
//! but it must not construct another `RuntimeManager` or dispatch from its I/O
//! callback. The PID 1 event loop owns [`Pid1CommandInbox`] and applies every
//! command to the one live manager instance.

use std::num::NonZeroUsize;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::time::Duration;

use crate::ffi::Errno;
use crate::manager_tables::ManagerObjective;
use crate::runtime_manager::RuntimeManager;
use crate::transaction::JobMode;

/// Credentials supplied by a transport after it has authenticated its peer.
///
/// A future D-Bus adapter must populate this from the kernel-verified peer
/// credentials associated with the received message. It must never derive
/// these values from D-Bus payload fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pid: u32,
    uid: u32,
    gid: u32,
}

impl AuthenticatedPeer {
    /// Only core transport adapters may create an identity. This keeps callers
    /// outside the PID 1 crate from fabricating credentials.
    pub(crate) const fn from_kernel_peer_credentials(pid: u32, uid: u32, gid: u32) -> Self {
        Self { pid, uid, gid }
    }

    pub const fn pid(self) -> u32 {
        self.pid
    }

    pub const fn uid(self) -> u32 {
        self.uid
    }

    pub const fn gid(self) -> u32 {
        self.gid
    }
}

/// Identity retained with a queued command, rather than looked up again after
/// an asynchronous transport handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderIdentity(AuthenticatedPeer);

impl SenderIdentity {
    pub const fn from_authenticated_peer(peer: AuthenticatedPeer) -> Self {
        Self(peer)
    }

    pub const fn peer(self) -> AuthenticatedPeer {
        self.0
    }
}

/// Commands that already have a direct, typed runtime-manager equivalent.
///
/// This intentionally does not mirror the current incomplete D-Bus method
/// model. Protocol decoding and authorization belong in the transport adapter;
/// the single owner receives only semantic manager operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pid1ManagerCommand {
    /// Return the bounded developer-shadow interface description. This does
    /// not inspect or mutate the runtime manager.
    Introspect,
    /// Return the object path for an already-loaded unit. Unlike `LoadUnit`,
    /// this does not read unit files or otherwise mutate manager state. An
    /// empty name resolves the authenticated caller's unit, as it does in
    /// C's `bus_get_unit_by_name()`.
    GetUnit {
        name: String,
    },
    /// Return the object path for a PID belonging to an already-loaded unit.
    /// PID zero is resolved to the authenticated caller's PID, matching the
    /// C manager method; no unit is loaded while performing the lookup.
    GetUnitByPid {
        pid: u32,
    },
    /// Return the invocation-ID object path for an already-loaded unit.
    /// A null ID resolves the authenticated caller's unit, matching
    /// `method_get_unit_by_invocation_id()` in C. No unit is loaded while
    /// performing either lookup.
    GetUnitByInvocationId {
        invocation_id: [u8; 16],
    },
    /// Return the object path for an already-installed job. This is an
    /// observation-only lookup and must not create or otherwise alter a job.
    GetJob {
        id: u32,
    },
    LoadUnit {
        name: String,
    },
    StartUnit {
        name: String,
        mode: JobMode,
    },
    StopUnit {
        name: String,
        mode: JobMode,
    },
    ReloadUnit {
        name: String,
    },
    RestartUnit {
        name: String,
        mode: JobMode,
    },
    ResetFailed {
        name: String,
    },
    /// Reset the failure state of every loaded unit.
    ///
    /// This is the public manager's no-argument `ResetFailed` operation.
    /// It is deliberately distinct from the named helper above: an empty
    /// unit name must never be used as a lossy stand-in for the all-units
    /// operation.
    ResetAllFailed,
    /// Request that the event-loop owner stop normal dispatch and enter the
    /// outer manager lifecycle.
    ///
    /// This command remains a typed seam for the eventual complete manager
    /// implementation, but it is not an admission ticket to tear down the
    /// live event loop today. C can complete every objective after
    /// `manager_loop()` returns; Rust does not yet own the matching reload,
    /// descriptor-preserving reexec, root-switch, user exit, or shutdown
    /// handoff. Consequently dispatch rejects every value at present:
    /// `Ok` with `EINVAL`, all actual lifecycle objectives with
    /// `EOPNOTSUPP`. Signal-originated objectives remain explicitly handled
    /// by the outer PID 1 owner, where a failure cannot be reported to a
    /// request/reply client.
    RequestObjective {
        objective: ManagerObjective,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pid1ManagerReply {
    IntrospectionXml,
    UnitLoaded { path: String },
    JobFound { path: String },
    JobQueued { id: u32 },
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pid1CommandError {
    Unauthorized,
    /// `GetUnit` only observes the existing manager inventory. C returns
    /// `org.freedesktop.systemd1.NoSuchUnit` rather than loading the name.
    NoSuchUnit {
        name: String,
    },
    /// An empty `GetUnit` name asks for the kernel-authenticated caller's
    /// unit. C reports a miss as `NoSuchUnit` without including the PID.
    NoUnitForCaller,
    NoUnitForPid {
        pid: u32,
    },
    /// A non-null invocation ID has no loaded unit. C exposes this separately
    /// from `NoSuchUnit` and `NoUnitForPID`.
    NoUnitForInvocationId {
        invocation_id: [u8; 16],
    },
    /// A null invocation ID asks for the kernel-authenticated caller's unit.
    /// C reports this as `NoSuchUnit` with a caller-specific diagnostic.
    NoUnitForCallerPid {
        pid: u32,
    },
    NoSuchJob {
        id: u32,
    },
    Runtime(Errno),
    InboxFull,
    InboxClosed,
}

pub type Pid1CommandResult = Result<Pid1ManagerReply, Pid1CommandError>;

pub struct Pid1DispatchOutcome {
    pub dispatched: usize,
    pub objective: Option<PendingObjectiveRequest>,
}

pub struct PendingObjectiveRequest {
    objective: ManagerObjective,
    reply: SyncSender<Pid1CommandResult>,
}

impl PendingObjectiveRequest {
    pub const fn objective(&self) -> ManagerObjective {
        self.objective
    }

    pub fn reply(self, result: Pid1CommandResult) {
        let _ = self.reply.try_send(result);
    }
}

enum Pid1CommandEffect {
    Reply(Pid1ManagerReply),
    RequestObjective(ManagerObjective),
}

/// Authorization is intentionally a dependency of dispatch, not a boolean
/// claimed by the sender. C routes these operations through polkit helpers
/// (`manage-units`, `reload-daemon`, and related actions), some asynchronously.
/// The existing Rust D-Bus helper owns a shadow runtime and is therefore not a
/// valid authority for this seam.
pub trait Pid1CommandAuthorizer {
    fn authorize(
        &mut self,
        sender: SenderIdentity,
        command: &Pid1ManagerCommand,
    ) -> Result<(), Pid1CommandError>;
}

/// Safe default while no authenticated transport exists.
#[derive(Debug, Default)]
pub struct DenyAllPid1CommandAuthorizer;

impl Pid1CommandAuthorizer for DenyAllPid1CommandAuthorizer {
    fn authorize(
        &mut self,
        _sender: SenderIdentity,
        _command: &Pid1ManagerCommand,
    ) -> Result<(), Pid1CommandError> {
        Err(Pid1CommandError::Unauthorized)
    }
}

/// Authorization policy for the direct private manager socket.
///
/// C accepts that socket only from uid 0 or the manager's own effective uid.
/// The transport must still construct [`SenderIdentity`] from `SO_PEERCRED`;
/// payload data is never authoritative.
#[derive(Debug, Clone, Copy)]
pub struct PrivateBusPid1CommandAuthorizer {
    manager_uid: u32,
}

impl PrivateBusPid1CommandAuthorizer {
    pub const fn new(manager_uid: u32) -> Self {
        Self { manager_uid }
    }
}

impl Pid1CommandAuthorizer for PrivateBusPid1CommandAuthorizer {
    fn authorize(
        &mut self,
        sender: SenderIdentity,
        _command: &Pid1ManagerCommand,
    ) -> Result<(), Pid1CommandError> {
        let uid = sender.peer().uid();
        if uid == 0 || uid == self.manager_uid {
            Ok(())
        } else {
            Err(Pid1CommandError::Unauthorized)
        }
    }
}

struct QueuedCommand {
    sender: SenderIdentity,
    command: Pid1ManagerCommand,
    reply: SyncSender<Pid1CommandResult>,
}

/// Cloneable ingress retained by transports. It has no access to the runtime.
#[derive(Clone)]
pub struct Pid1CommandSender {
    sender: SyncSender<QueuedCommand>,
}

/// Exclusive reply ownership for one submitted command.
pub struct Pid1CommandReplyReceiver {
    receiver: Receiver<Pid1CommandResult>,
}

impl Pid1CommandReplyReceiver {
    pub fn try_recv(&self) -> Result<Pid1CommandResult, TryRecvError> {
        self.receiver.try_recv()
    }

    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Pid1CommandResult, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

impl Pid1CommandSender {
    /// Enqueue without blocking a transport callback. Both the manager inbox
    /// and the per-command reply slot are bounded.
    pub fn try_send(
        &self,
        sender: SenderIdentity,
        command: Pid1ManagerCommand,
    ) -> Result<Pid1CommandReplyReceiver, Pid1CommandError> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        let queued = QueuedCommand {
            sender,
            command,
            reply: reply_sender,
        };
        match self.sender.try_send(queued) {
            Ok(()) => Ok(Pid1CommandReplyReceiver {
                receiver: reply_receiver,
            }),
            Err(TrySendError::Full(_)) => Err(Pid1CommandError::InboxFull),
            Err(TrySendError::Disconnected(_)) => Err(Pid1CommandError::InboxClosed),
        }
    }
}

/// The event-loop-owned half of the bounded command channel.
pub struct Pid1CommandInbox {
    receiver: Receiver<QueuedCommand>,
}

/// Create a bounded command seam. The capacity is explicit to keep an
/// unresponsive transport from accumulating unbounded PID 1 work or replies.
pub fn pid1_manager_command_channel(
    capacity: NonZeroUsize,
) -> (Pid1CommandSender, Pid1CommandInbox) {
    let (sender, receiver) = mpsc::sync_channel(capacity.get());
    (Pid1CommandSender { sender }, Pid1CommandInbox { receiver })
}

impl Pid1CommandInbox {
    /// Dispatch at most `budget` queued requests. This bounds work per event
    /// loop turn so an eventual bus transport cannot starve signals or sockets.
    pub fn dispatch_pending<A: Pid1CommandAuthorizer + ?Sized>(
        &mut self,
        runtime: &mut RuntimeManager,
        authorizer: &mut A,
        budget: NonZeroUsize,
    ) -> Pid1DispatchOutcome {
        let mut dispatched = 0;
        while dispatched < budget.get() {
            let queued = match self.receiver.try_recv() {
                Ok(queued) => queued,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            };

            // The C D-Bus handlers reject requests that cannot be admitted in
            // the current manager context before security checks or an
            // objective write. The Rust lifecycle owner cannot complete any
            // outer objective yet, so reject it before invoking the mutable
            // authorization seam as well. This keeps the documented errno
            // stable and prevents a refused request from being an admission
            // path for authorizer-side state.
            let result = match reject_unavailable_lifecycle_request(&queued.command) {
                Some(error) => Err(error),
                None => authorizer
                    .authorize(queued.sender, &queued.command)
                    .and_then(|()| dispatch(runtime, queued.sender, queued.command)),
            };
            dispatched += 1;
            match result {
                Ok(Pid1CommandEffect::Reply(reply)) => {
                    let _ = queued.reply.try_send(Ok(reply));
                }
                Ok(Pid1CommandEffect::RequestObjective(objective)) => {
                    return Pid1DispatchOutcome {
                        dispatched,
                        objective: Some(PendingObjectiveRequest {
                            objective,
                            reply: queued.reply,
                        }),
                    };
                }
                Err(error) => {
                    let _ = queued.reply.try_send(Err(error));
                }
            }
        }
        Pid1DispatchOutcome {
            dispatched,
            objective: None,
        }
    }
}

fn reject_unavailable_lifecycle_request(command: &Pid1ManagerCommand) -> Option<Pid1CommandError> {
    let Pid1ManagerCommand::RequestObjective { objective } = command else {
        return None;
    };

    Some(Pid1CommandError::Runtime(
        if *objective == ManagerObjective::Ok {
            Errno::EINVAL
        } else {
            Errno::EOPNOTSUPP
        },
    ))
}

fn dispatch(
    runtime: &mut RuntimeManager,
    sender: SenderIdentity,
    command: Pid1ManagerCommand,
) -> Result<Pid1CommandEffect, Pid1CommandError> {
    let reply = match command {
        Pid1ManagerCommand::Introspect => Ok(Pid1ManagerReply::IntrospectionXml),
        Pid1ManagerCommand::GetUnit { name } => {
            let path = if name.is_empty() {
                crate::dbus_manager::manager_get_unit_path_by_pid(runtime, sender.peer().pid())
                    .map_err(|error| match error {
                        Errno::ENOENT => Pid1CommandError::NoUnitForCaller,
                        error => Pid1CommandError::Runtime(error),
                    })?
            } else {
                crate::dbus_manager::manager_get_unit_path(runtime, &name).map_err(|error| {
                    match error {
                        Errno::ENOENT => Pid1CommandError::NoSuchUnit { name },
                        error => Pid1CommandError::Runtime(error),
                    }
                })?
            };
            return Ok(Pid1CommandEffect::Reply(Pid1ManagerReply::UnitLoaded {
                path,
            }));
        }
        Pid1ManagerCommand::GetUnitByPid { pid } => {
            let pid = if pid == 0 { sender.peer().pid() } else { pid };
            return match crate::dbus_manager::manager_get_unit_path_by_pid(runtime, pid) {
                Ok(path) => Ok(Pid1CommandEffect::Reply(Pid1ManagerReply::UnitLoaded {
                    path,
                })),
                Err(Errno::ENOENT) => Err(Pid1CommandError::NoUnitForPid { pid }),
                Err(error) => Err(Pid1CommandError::Runtime(error)),
            };
        }
        Pid1ManagerCommand::GetUnitByInvocationId { invocation_id } => {
            let path = if invocation_id == [0; 16] {
                crate::dbus_manager::manager_get_unit_invocation_path_by_pid(
                    runtime,
                    sender.peer().pid(),
                )
                .map_err(|error| match error {
                    Errno::ENOENT => Pid1CommandError::NoUnitForCallerPid {
                        pid: sender.peer().pid(),
                    },
                    error => Pid1CommandError::Runtime(error),
                })?
            } else {
                crate::dbus_manager::manager_get_unit_invocation_path_by_id(runtime, invocation_id)
                    .map_err(|error| match error {
                        Errno::ENOENT => Pid1CommandError::NoUnitForInvocationId { invocation_id },
                        error => Pid1CommandError::Runtime(error),
                    })?
            };
            return Ok(Pid1CommandEffect::Reply(Pid1ManagerReply::UnitLoaded {
                path,
            }));
        }
        Pid1ManagerCommand::GetJob { id } => {
            return match crate::dbus_manager::manager_get_job_path(runtime, id) {
                Ok(path) => Ok(Pid1CommandEffect::Reply(Pid1ManagerReply::JobFound {
                    path,
                })),
                Err(Errno::ENOENT) => Err(Pid1CommandError::NoSuchJob { id }),
                Err(error) => Err(Pid1CommandError::Runtime(error)),
            };
        }
        Pid1ManagerCommand::LoadUnit { name } => runtime.load_unit(&name).and_then(|()| {
            crate::dbus_manager::manager_get_unit_path(runtime, &name)
                .map(|path| Pid1ManagerReply::UnitLoaded { path })
        }),
        Pid1ManagerCommand::StartUnit { name, mode } => runtime
            .start_unit_async(&name, mode)
            .map(|id| Pid1ManagerReply::JobQueued { id }),
        Pid1ManagerCommand::StopUnit { name, mode } => runtime
            .stop_unit_async(&name, mode)
            .map(|id| Pid1ManagerReply::JobQueued { id }),
        Pid1ManagerCommand::ReloadUnit { name } => runtime
            .reload_unit_async(&name)
            .map(|id| Pid1ManagerReply::JobQueued { id }),
        Pid1ManagerCommand::RestartUnit { name, mode } => runtime
            .restart_unit_async(&name, mode)
            .map(|id| Pid1ManagerReply::JobQueued { id }),
        Pid1ManagerCommand::ResetFailed { name } => {
            // `ResetFailedUnit` follows C's non-loading lookup path: an
            // unknown unit is a typed NoSuchUnit error rather than a generic
            // manager failure. Do not turn this into `LoadUnit`; an unloaded
            // unit cannot have retained failed state to clear.
            return match runtime.reset_failed(&name) {
                Ok(()) => Ok(Pid1CommandEffect::Reply(Pid1ManagerReply::Completed)),
                Err(Errno::ENOENT) => Err(Pid1CommandError::NoSuchUnit { name }),
                Err(error) => Err(Pid1CommandError::Runtime(error)),
            };
        }
        Pid1ManagerCommand::ResetAllFailed => runtime
            .reset_all_failed()
            .map(|()| Pid1ManagerReply::Completed),
        // `dispatch_pending()` rejects this before authorization. Keeping the
        // arm explicit makes a future lifecycle implementation add an
        // admission path intentionally, rather than silently authorizing it.
        Pid1ManagerCommand::RequestObjective { .. } => unreachable!(),
    }
    .map_err(Pid1CommandError::Runtime)?;

    Ok(Pid1CommandEffect::Reply(reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender_identity() -> SenderIdentity {
        SenderIdentity::from_authenticated_peer(AuthenticatedPeer::from_kernel_peer_credentials(
            42, 1000, 1000,
        ))
    }

    fn reset_failed() -> Pid1ManagerCommand {
        Pid1ManagerCommand::ResetFailed {
            name: "missing.service".to_string(),
        }
    }

    fn assert_no_objective(outcome: Pid1DispatchOutcome, dispatched: usize) {
        assert_eq!(outcome.dispatched, dispatched);
        assert!(outcome.objective.is_none());
    }

    #[derive(Default)]
    struct DenyAuthorizer {
        calls: usize,
    }

    impl Pid1CommandAuthorizer for DenyAuthorizer {
        fn authorize(
            &mut self,
            _sender: SenderIdentity,
            _command: &Pid1ManagerCommand,
        ) -> Result<(), Pid1CommandError> {
            self.calls += 1;
            Err(Pid1CommandError::Unauthorized)
        }
    }

    #[test]
    fn inbox_capacity_rejects_new_work_without_blocking() {
        let (sender, _inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());

        let _first_reply = sender.try_send(sender_identity(), reset_failed()).unwrap();
        assert!(matches!(
            sender.try_send(sender_identity(), reset_failed()),
            Err(Pid1CommandError::InboxFull)
        ));
    }

    #[test]
    fn authorization_happens_before_runtime_mutation() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender.try_send(sender_identity(), reset_failed()).unwrap();
        let mut runtime = RuntimeManager::new();
        let mut authorizer = DenyAuthorizer::default();

        assert_no_objective(
            inbox.dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap()),
            1,
        );
        assert_eq!(authorizer.calls, 1);
        // A missing unit would yield NoSuchUnit if dispatch reached the
        // manager. Unauthorized proves the authorizer ran first.
        assert_eq!(reply.try_recv(), Ok(Err(Pid1CommandError::Unauthorized)));
    }

    #[test]
    fn dispatch_budget_preserves_later_requests_for_the_next_turn() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(2).unwrap());
        let first = sender.try_send(sender_identity(), reset_failed()).unwrap();
        let second = sender.try_send(sender_identity(), reset_failed()).unwrap();
        let mut runtime = RuntimeManager::new();
        let mut authorizer = DenyAuthorizer::default();

        assert_no_objective(
            inbox.dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap()),
            1,
        );
        assert_eq!(first.try_recv(), Ok(Err(Pid1CommandError::Unauthorized)));
        assert_eq!(second.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(authorizer.calls, 1);

        assert_no_objective(
            inbox.dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap()),
            1,
        );
        assert_eq!(second.try_recv(), Ok(Err(Pid1CommandError::Unauthorized)));
        assert_eq!(authorizer.calls, 2);
    }

    #[test]
    fn dropped_reply_receiver_does_not_block_or_cancel_dispatch() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender.try_send(sender_identity(), reset_failed()).unwrap();
        drop(reply);
        let mut runtime = RuntimeManager::new();
        let mut authorizer = DenyAuthorizer::default();

        assert_no_objective(
            inbox.dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap()),
            1,
        );
        assert_eq!(authorizer.calls, 1);
    }

    #[derive(Default)]
    struct AllowAuthorizer;

    impl Pid1CommandAuthorizer for AllowAuthorizer {
        fn authorize(
            &mut self,
            _sender: SenderIdentity,
            _command: &Pid1ManagerCommand,
        ) -> Result<(), Pid1CommandError> {
            Ok(())
        }
    }

    #[test]
    fn unavailable_objective_is_rejected_without_tearing_down_following_work() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(2).unwrap());
        let objective_reply = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::RequestObjective {
                    objective: ManagerObjective::Reload,
                },
            )
            .unwrap();
        let later_reply = sender.try_send(sender_identity(), reset_failed()).unwrap();
        let mut runtime = RuntimeManager::new();

        let outcome = inbox.dispatch_pending(
            &mut runtime,
            &mut AllowAuthorizer,
            NonZeroUsize::new(2).unwrap(),
        );
        assert_eq!(outcome.dispatched, 2);
        assert!(outcome.objective.is_none());
        assert_eq!(
            objective_reply.try_recv(),
            Ok(Err(Pid1CommandError::Runtime(Errno::EOPNOTSUPP)))
        );
        assert_eq!(
            later_reply.try_recv(),
            Ok(Err(Pid1CommandError::NoSuchUnit {
                name: "missing.service".into(),
            }))
        );
    }

    #[test]
    fn named_reset_failed_uses_the_non_loading_no_such_unit_error() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender.try_send(sender_identity(), reset_failed()).unwrap();
        let mut runtime = RuntimeManager::new();

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(
            reply.try_recv(),
            Ok(Err(Pid1CommandError::NoSuchUnit {
                name: "missing.service".into(),
            }))
        );
    }

    #[test]
    fn reset_all_failed_is_a_distinct_completed_manager_operation() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(sender_identity(), Pid1ManagerCommand::ResetAllFailed)
            .unwrap();
        let mut runtime = RuntimeManager::new();

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(reply.try_recv(), Ok(Ok(Pid1ManagerReply::Completed)));
    }

    #[test]
    fn every_unavailable_outer_lifecycle_objective_is_rejected_at_ingress() {
        for (objective, error) in [
            (ManagerObjective::Ok, Errno::EINVAL),
            (ManagerObjective::Reload, Errno::EOPNOTSUPP),
            (ManagerObjective::Reexecute, Errno::EOPNOTSUPP),
            (ManagerObjective::Exit, Errno::EOPNOTSUPP),
            (ManagerObjective::Reboot, Errno::EOPNOTSUPP),
            (ManagerObjective::Poweroff, Errno::EOPNOTSUPP),
            (ManagerObjective::Halt, Errno::EOPNOTSUPP),
            (ManagerObjective::Kexec, Errno::EOPNOTSUPP),
            (ManagerObjective::SwitchRoot, Errno::EOPNOTSUPP),
            (ManagerObjective::SoftReboot, Errno::EOPNOTSUPP),
        ] {
            let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
            let reply = sender
                .try_send(
                    sender_identity(),
                    Pid1ManagerCommand::RequestObjective { objective },
                )
                .unwrap();
            let mut runtime = RuntimeManager::new();

            assert_no_objective(
                inbox.dispatch_pending(
                    &mut runtime,
                    &mut AllowAuthorizer,
                    NonZeroUsize::new(1).unwrap(),
                ),
                1,
            );
            assert_eq!(reply.try_recv(), Ok(Err(Pid1CommandError::Runtime(error))));
        }
    }

    #[test]
    fn unavailable_lifecycle_objectives_precede_authorization() {
        for objective in [
            ManagerObjective::Reload,
            ManagerObjective::Reexecute,
            ManagerObjective::Exit,
        ] {
            let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
            let reply = sender
                .try_send(
                    sender_identity(),
                    Pid1ManagerCommand::RequestObjective { objective },
                )
                .unwrap();
            let mut runtime = RuntimeManager::new();
            let mut authorizer = DenyAuthorizer::default();

            assert_no_objective(
                inbox.dispatch_pending(
                    &mut runtime,
                    &mut authorizer,
                    NonZeroUsize::new(1).unwrap(),
                ),
                1,
            );
            assert_eq!(authorizer.calls, 0);
            assert_eq!(
                reply.try_recv(),
                Ok(Err(Pid1CommandError::Runtime(Errno::EOPNOTSUPP)))
            );
        }
    }

    #[test]
    fn get_unit_returns_an_existing_path_without_loading_a_unit() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::GetUnit {
                    name: "example.target".into(),
                },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "example.target",
            "Example Target",
            crate::unit::ActiveState::Inactive,
            "dead",
        );

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(
            reply.try_recv(),
            Ok(Ok(Pid1ManagerReply::UnitLoaded {
                path: "/org/freedesktop/systemd1/unit/example_2etarget".into(),
            }))
        );
        assert_eq!(runtime.unit_count(), 1);
    }

    #[test]
    fn get_unit_missing_name_returns_no_such_unit_without_loading() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::GetUnit {
                    name: "missing.target".into(),
                },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(
            reply.try_recv(),
            Ok(Err(Pid1CommandError::NoSuchUnit {
                name: "missing.target".into(),
            }))
        );
        assert_eq!(runtime.unit_count(), 0);
    }

    #[test]
    fn get_unit_empty_name_resolves_the_callers_loaded_unit_without_loading() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::GetUnit {
                    name: String::new(),
                },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "example.service",
            "Example Service",
            crate::unit::ActiveState::Active,
            "running",
        );
        runtime.inject_test_main_pid("example.service", 42);

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(
            reply.try_recv(),
            Ok(Ok(Pid1ManagerReply::UnitLoaded {
                path: "/org/freedesktop/systemd1/unit/example_2eservice".into(),
            }))
        );
        assert_eq!(runtime.unit_count(), 1);
    }

    #[test]
    fn get_unit_empty_name_missing_returns_c_no_such_unit_without_loading() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::GetUnit {
                    name: String::new(),
                },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(reply.try_recv(), Ok(Err(Pid1CommandError::NoUnitForCaller)));
        assert_eq!(runtime.unit_count(), 0);
    }

    #[test]
    fn get_unit_by_pid_resolves_loaded_unit_and_pid_zero_from_sender() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(2).unwrap());
        let explicit = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::GetUnitByPid { pid: 4242 },
            )
            .unwrap();
        let caller = sender
            .try_send(
                SenderIdentity::from_authenticated_peer(
                    AuthenticatedPeer::from_kernel_peer_credentials(4242, 1000, 1000),
                ),
                Pid1ManagerCommand::GetUnitByPid { pid: 0 },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "example.service",
            "Example Service",
            crate::unit::ActiveState::Active,
            "running",
        );
        runtime.inject_test_main_pid("example.service", 4242);

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(2).unwrap(),
            ),
            2,
        );
        let expected = Pid1ManagerReply::UnitLoaded {
            path: "/org/freedesktop/systemd1/unit/example_2eservice".into(),
        };
        assert_eq!(explicit.try_recv(), Ok(Ok(expected.clone())));
        assert_eq!(caller.try_recv(), Ok(Ok(expected)));
    }

    #[test]
    fn get_unit_by_pid_missing_returns_c_error_shape_without_loading() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::GetUnitByPid { pid: 4242 },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(
            reply.try_recv(),
            Ok(Err(Pid1CommandError::NoUnitForPid { pid: 4242 }))
        );
        assert_eq!(runtime.unit_count(), 0);
    }

    #[test]
    fn get_unit_by_invocation_id_returns_its_id_stable_path_without_loading() {
        let invocation_id = [0xabu8; 16];
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::GetUnitByInvocationId { invocation_id },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "example.service",
            "Example Service",
            crate::unit::ActiveState::Active,
            "running",
        );
        runtime.inject_test_invocation_id("example.service", invocation_id);

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(
            reply.try_recv(),
            Ok(Ok(Pid1ManagerReply::UnitLoaded {
                path: "/org/freedesktop/systemd1/unit/abababababababababababababababab".into(),
            }))
        );
        assert_eq!(runtime.unit_count(), 1);
    }

    #[test]
    fn null_invocation_id_resolves_the_authenticated_caller_only() {
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(
                SenderIdentity::from_authenticated_peer(
                    AuthenticatedPeer::from_kernel_peer_credentials(4242, 1000, 1000),
                ),
                Pid1ManagerCommand::GetUnitByInvocationId {
                    invocation_id: [0; 16],
                },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "example.service",
            "Example Service",
            crate::unit::ActiveState::Active,
            "running",
        );
        runtime.inject_test_main_pid("example.service", 4242);
        runtime.inject_test_invocation_id("example.service", [0xcd; 16]);

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(
            reply.try_recv(),
            Ok(Ok(Pid1ManagerReply::UnitLoaded {
                path: "/org/freedesktop/systemd1/unit/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".into(),
            }))
        );
    }

    #[test]
    fn missing_invocation_id_preserves_the_distinct_c_error_without_loading() {
        let invocation_id = [0x42; 16];
        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        let reply = sender
            .try_send(
                sender_identity(),
                Pid1ManagerCommand::GetUnitByInvocationId { invocation_id },
            )
            .unwrap();
        let mut runtime = RuntimeManager::new();

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(1).unwrap(),
            ),
            1,
        );
        assert_eq!(
            reply.try_recv(),
            Ok(Err(Pid1CommandError::NoUnitForInvocationId {
                invocation_id
            }))
        );
        assert_eq!(runtime.unit_count(), 0);
    }

    #[test]
    fn get_job_observes_only_installed_jobs_and_preserves_no_such_job() {
        use crate::job_tables::{JobState, JobType};

        let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(2).unwrap());
        let existing = sender
            .try_send(sender_identity(), Pid1ManagerCommand::GetJob { id: 27 })
            .unwrap();
        let missing = sender
            .try_send(sender_identity(), Pid1ManagerCommand::GetJob { id: 28 })
            .unwrap();
        let mut runtime = RuntimeManager::new();
        runtime.inject_test_unit(
            "example.service",
            "Example Service",
            crate::unit::ActiveState::Active,
            "running",
        );
        runtime.inject_test_installed_job(27, "example.service", JobType::Start, JobState::Running);

        assert_no_objective(
            inbox.dispatch_pending(
                &mut runtime,
                &mut AllowAuthorizer,
                NonZeroUsize::new(2).unwrap(),
            ),
            2,
        );
        assert_eq!(
            existing.try_recv(),
            Ok(Ok(Pid1ManagerReply::JobFound {
                path: "/org/freedesktop/systemd1/job/27".into(),
            }))
        );
        assert_eq!(
            missing.try_recv(),
            Ok(Err(Pid1CommandError::NoSuchJob { id: 28 }))
        );
        assert_eq!(runtime.installed_jobs().len(), 1);
    }
}
