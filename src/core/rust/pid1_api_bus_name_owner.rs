// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (`bus_setup_api()`, `bus_done_api()`),
//            src/libsystemd/sd-bus/bus-control.c (`sd_bus_request_name_async()`)

//! Bounded ownership state for PID 1's API-bus well-known name.
//!
//! `bus_setup_api()` asks the broker for `org.freedesktop.systemd1` with
//! `REPLACE_EXISTING|ALLOW_REPLACEMENT` so a reexecuted manager can install a
//! new connection before the old one closes. A complete Rust API-bus transport
//! needs one manager-owned record of that request, its asynchronous result,
//! `NameOwnerChanged` loss, and the final close-driven release. This pure
//! state machine supplies that record without opening a bus, registering a
//! match, or claiming that Rust owns the production API bus.
//!
//! Each acquisition gets a monotonically increasing session token. Results
//! and owner-change notifications from an earlier bus connection cannot make
//! a replacement connection appear owned. Any malformed or terminal response
//! fails closed: the name is not considered owned and callers must not use it
//! to declare the API ready or a `Type=dbus` service started.

use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::rc::Rc;

use systemd_libsystemd_rs::bus_internal_types::service_name_is_valid;

/// The manager API's well-known name in C's `bus_setup_api()`.
pub const SYSTEMD_API_BUS_NAME: &str = "org.freedesktop.systemd1";

// `BUS_NAME_*` request bits from src/libsystemd/sd-bus/bus-protocol.h. Keep
// them local until the production Rust sd-bus control transport is compiled.
const BUS_NAME_ALLOW_REPLACEMENT: u64 = 1 << 0;
const BUS_NAME_REPLACE_EXISTING: u64 = 1 << 1;

/// C requests replacement during reexecution and permits a successor to do
/// the same. Deliberately do not set `SD_BUS_NAME_QUEUE`: a PID 1 API that is
/// merely queued behind a stale owner must not be treated as available.
pub const SYSTEMD_API_BUS_NAME_FLAGS: u64 = BUS_NAME_REPLACE_EXISTING | BUS_NAME_ALLOW_REPLACEMENT;

/// A manager-assigned identity for one API-bus connection lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiBusSessionId(NonZeroU64);

impl ApiBusSessionId {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact request a future authenticated API-bus transport must submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiBusNameAcquireRequest {
    pub session: ApiBusSessionId,
    pub name: &'static str,
    pub flags: u64,
}

/// The result codes returned by D-Bus' `RequestName` method.
///
/// These values are decoded by the future transport, rather than allowing a
/// raw untrusted integer to change ownership state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiBusNameAcquireResult {
    PrimaryOwner,
    InQueue,
    Exists,
    AlreadyOwner,
    /// A method error or malformed reply. The errno is diagnostic only; no
    /// errno value grants ownership.
    Failed(i32),
    Unexpected(u32),
}

/// Current state of the manager's intended API-bus name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiBusNameOwnership {
    Detached,
    Acquiring { session: ApiBusSessionId },
    Waiting { session: ApiBusSessionId },
    Owned { session: ApiBusSessionId },
    Lost { session: ApiBusSessionId },
    Released { session: ApiBusSessionId },
}

/// One observable outcome while advancing [`ApiBusNameOwner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiBusNameOwnerEvent {
    Acquiring(ApiBusNameAcquireRequest),
    Owned(ApiBusSessionId),
    Waiting(ApiBusSessionId),
    Lost(ApiBusSessionId),
    Released(ApiBusSessionId),
    IgnoredStaleSession(ApiBusSessionId),
}

/// Explicit close action corresponding to C's `bus_done_api()`.
///
/// C releases the broker name by closing the API-bus connection, not by
/// sending a best-effort `ReleaseName` method while the manager is tearing
/// down. The future transport must execute this close exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiBusNameRelease {
    pub session: ApiBusSessionId,
}

/// Fail-closed ownership errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiBusNameOwnerError {
    InvalidUniqueName,
    AcquisitionAlreadyActive,
    SessionExhausted,
    NoActiveSession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Lease {
    session: ApiBusSessionId,
    unique_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Detached,
    Acquiring(Lease),
    Waiting(Lease),
    Owned(Lease),
    Lost(Lease),
    Released(ApiBusSessionId),
}

/// Manager-owned lifecycle of `org.freedesktop.systemd1` on one API bus.
///
/// The `Rc` marker makes this state machine intentionally `!Send` and `!Sync`:
/// it must be driven by the one thread which owns the manager event loop and
/// authenticated API-bus connection. Future live integration should store it
/// next to that connection, not copy its result into service state from a bus
/// callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiBusNameOwner {
    next_session: u64,
    state: State,
    _owner_thread: PhantomData<Rc<()>>,
}

impl Default for ApiBusNameOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiBusNameOwner {
    pub const fn new() -> Self {
        Self {
            next_session: 1,
            state: State::Detached,
            _owner_thread: PhantomData,
        }
    }

    pub fn ownership(&self) -> ApiBusNameOwnership {
        match &self.state {
            State::Detached => ApiBusNameOwnership::Detached,
            State::Acquiring(lease) => ApiBusNameOwnership::Acquiring {
                session: lease.session,
            },
            State::Waiting(lease) => ApiBusNameOwnership::Waiting {
                session: lease.session,
            },
            State::Owned(lease) => ApiBusNameOwnership::Owned {
                session: lease.session,
            },
            State::Lost(lease) => ApiBusNameOwnership::Lost {
                session: lease.session,
            },
            State::Released(session) => ApiBusNameOwnership::Released { session: *session },
        }
    }

    /// Only this state authorizes an eventual API-bus owner to advertise the
    /// well-known manager name. `Acquiring` and `Waiting` stay false even
    /// though C has already queued the asynchronous request.
    pub fn is_owned(&self) -> bool {
        matches!(self.state, State::Owned(_))
    }

    /// Start a new API-bus lifetime and return C's exact name request.
    ///
    /// `unique_name` must be the authenticated bus-assigned unique name of
    /// this connection. It is bounded by sd-bus' name limit and is retained
    /// only to reject ownership notifications for a different connection.
    pub fn begin_acquire(
        &mut self,
        unique_name: &str,
    ) -> Result<ApiBusNameAcquireRequest, ApiBusNameOwnerError> {
        if !matches!(self.state, State::Detached | State::Released(_)) {
            return Err(ApiBusNameOwnerError::AcquisitionAlreadyActive);
        }
        if !valid_unique_name(unique_name) {
            return Err(ApiBusNameOwnerError::InvalidUniqueName);
        }

        let session = self.allocate_session()?;
        self.state = State::Acquiring(Lease {
            session,
            unique_name: unique_name.to_owned(),
        });
        Ok(ApiBusNameAcquireRequest {
            session,
            name: SYSTEMD_API_BUS_NAME,
            flags: SYSTEMD_API_BUS_NAME_FLAGS,
        })
    }

    /// Apply one decoded `RequestName` response for an exact API-bus session.
    ///
    /// The default sd-bus async handler permits primary owner, already owner,
    /// and in-queue outcomes. Only the first two actually prove ownership.
    /// An in-queue result stays non-ready until an authenticated
    /// `NameOwnerChanged` event names this connection; `Exists`, errors, and
    /// unknown replies fail closed.
    pub fn observe_acquire_result(
        &mut self,
        session: ApiBusSessionId,
        result: ApiBusNameAcquireResult,
    ) -> ApiBusNameOwnerEvent {
        let Some(lease) = self.pending_lease_for(session).cloned() else {
            return ApiBusNameOwnerEvent::IgnoredStaleSession(session);
        };

        match result {
            ApiBusNameAcquireResult::PrimaryOwner | ApiBusNameAcquireResult::AlreadyOwner => {
                self.state = State::Owned(lease);
                ApiBusNameOwnerEvent::Owned(session)
            }
            ApiBusNameAcquireResult::InQueue => {
                self.state = State::Waiting(lease);
                ApiBusNameOwnerEvent::Waiting(session)
            }
            ApiBusNameAcquireResult::Exists
            | ApiBusNameAcquireResult::Failed(_)
            | ApiBusNameAcquireResult::Unexpected(_) => {
                self.state = State::Lost(lease);
                ApiBusNameOwnerEvent::Lost(session)
            }
        }
    }

    /// Apply the filtered `NameOwnerChanged` signal for
    /// [`SYSTEMD_API_BUS_NAME`].
    ///
    /// The caller must derive this signal from the authenticated API bus and
    /// provide its session token. Malformed unique names, a departure from our
    /// known unique name, and stale results never make a manager appear owned.
    pub fn observe_name_owner_changed(
        &mut self,
        session: ApiBusSessionId,
        old_owner: &str,
        new_owner: &str,
    ) -> ApiBusNameOwnerEvent {
        let Some(lease) = self.active_lease_for(session).cloned() else {
            return ApiBusNameOwnerEvent::IgnoredStaleSession(session);
        };
        if matches!(self.state, State::Lost(_)) {
            return ApiBusNameOwnerEvent::Lost(session);
        }
        if !valid_optional_unique_name(old_owner) || !valid_optional_unique_name(new_owner) {
            self.state = State::Lost(lease);
            return ApiBusNameOwnerEvent::Lost(session);
        }

        if new_owner == lease.unique_name {
            self.state = State::Owned(lease);
            return ApiBusNameOwnerEvent::Owned(session);
        }
        if old_owner == lease.unique_name {
            self.state = State::Lost(lease);
            return ApiBusNameOwnerEvent::Lost(session);
        }

        match self.state {
            State::Waiting(_) => ApiBusNameOwnerEvent::Waiting(session),
            State::Lost(_) => ApiBusNameOwnerEvent::Lost(session),
            State::Acquiring(_) | State::Owned(_) => {
                ApiBusNameOwnerEvent::IgnoredStaleSession(session)
            }
            State::Detached | State::Released(_) => {
                ApiBusNameOwnerEvent::IgnoredStaleSession(session)
            }
        }
    }

    /// End this API-bus lifetime. The returned action represents close-driven
    /// release and must be consumed by the owner of the matching descriptor.
    pub fn release(
        &mut self,
        session: ApiBusSessionId,
    ) -> Result<ApiBusNameRelease, ApiBusNameOwnerError> {
        let Some(lease) = self.active_lease_for(session) else {
            return Err(ApiBusNameOwnerError::NoActiveSession);
        };
        let session = lease.session;
        self.state = State::Released(session);
        Ok(ApiBusNameRelease { session })
    }

    fn allocate_session(&mut self) -> Result<ApiBusSessionId, ApiBusNameOwnerError> {
        let raw = self.next_session;
        let next = raw
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(ApiBusNameOwnerError::SessionExhausted)?;
        self.next_session = next;
        let session = NonZeroU64::new(raw).ok_or(ApiBusNameOwnerError::SessionExhausted)?;
        Ok(ApiBusSessionId(session))
    }

    fn active_lease_for(&self, session: ApiBusSessionId) -> Option<&Lease> {
        let lease = match &self.state {
            State::Acquiring(lease)
            | State::Waiting(lease)
            | State::Owned(lease)
            | State::Lost(lease) => lease,
            State::Detached | State::Released(_) => return None,
        };
        (lease.session == session).then_some(lease)
    }

    fn pending_lease_for(&self, session: ApiBusSessionId) -> Option<&Lease> {
        let State::Acquiring(lease) = &self.state else {
            return None;
        };
        (lease.session == session).then_some(lease)
    }
}

fn valid_unique_name(name: &str) -> bool {
    name.starts_with(':') && service_name_is_valid(name)
}

fn valid_optional_unique_name(name: &str) -> bool {
    name.is_empty() || valid_unique_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acquire(owner: &mut ApiBusNameOwner) -> ApiBusNameAcquireRequest {
        owner.begin_acquire(":1.42").unwrap()
    }

    #[test]
    fn acquire_uses_c_reexec_flags_and_requires_a_valid_unique_name() {
        let mut owner = ApiBusNameOwner::new();
        assert_eq!(
            owner.begin_acquire("org.freedesktop.systemd1"),
            Err(ApiBusNameOwnerError::InvalidUniqueName)
        );

        let request = acquire(&mut owner);
        assert_eq!(request.name, SYSTEMD_API_BUS_NAME);
        assert_eq!(request.flags, SYSTEMD_API_BUS_NAME_FLAGS);
        assert_eq!(request.session.get(), 1);
        assert_eq!(
            owner.ownership(),
            ApiBusNameOwnership::Acquiring {
                session: request.session
            }
        );
        assert!(!owner.is_owned());
        assert_eq!(
            owner.begin_acquire(":1.43"),
            Err(ApiBusNameOwnerError::AcquisitionAlreadyActive)
        );
    }

    #[test]
    fn primary_and_already_owner_results_establish_ownership() {
        for result in [
            ApiBusNameAcquireResult::PrimaryOwner,
            ApiBusNameAcquireResult::AlreadyOwner,
        ] {
            let mut owner = ApiBusNameOwner::new();
            let request = acquire(&mut owner);
            assert_eq!(
                owner.observe_acquire_result(request.session, result),
                ApiBusNameOwnerEvent::Owned(request.session)
            );
            assert_eq!(
                owner.ownership(),
                ApiBusNameOwnership::Owned {
                    session: request.session
                }
            );
            assert!(owner.is_owned());
        }
    }

    #[test]
    fn queue_or_foreign_owner_never_claims_manager_api_readiness() {
        let mut owner = ApiBusNameOwner::new();
        let request = acquire(&mut owner);
        assert_eq!(
            owner.observe_acquire_result(request.session, ApiBusNameAcquireResult::InQueue),
            ApiBusNameOwnerEvent::Waiting(request.session)
        );
        assert!(!owner.is_owned());
        assert_eq!(
            owner.observe_name_owner_changed(request.session, ":1.8", ":1.9"),
            ApiBusNameOwnerEvent::Waiting(request.session)
        );
        assert!(!owner.is_owned());
    }

    #[test]
    fn exact_authenticated_owner_signal_establishes_and_losing_it_fails_closed() {
        let mut owner = ApiBusNameOwner::new();
        let request = acquire(&mut owner);
        assert_eq!(
            owner.observe_name_owner_changed(request.session, ":1.8", ":1.42"),
            ApiBusNameOwnerEvent::Owned(request.session)
        );
        assert!(owner.is_owned());
        assert_eq!(
            owner.observe_name_owner_changed(request.session, ":1.42", ":1.9"),
            ApiBusNameOwnerEvent::Lost(request.session)
        );
        assert!(!owner.is_owned());
    }

    #[test]
    fn terminal_results_and_malformed_owner_change_fail_closed() {
        for result in [
            ApiBusNameAcquireResult::Exists,
            ApiBusNameAcquireResult::Failed(-libc::EIO),
            ApiBusNameAcquireResult::Unexpected(99),
        ] {
            let mut owner = ApiBusNameOwner::new();
            let request = acquire(&mut owner);
            assert_eq!(
                owner.observe_acquire_result(request.session, result),
                ApiBusNameOwnerEvent::Lost(request.session)
            );
            assert!(!owner.is_owned());
        }

        let mut owner = ApiBusNameOwner::new();
        let request = acquire(&mut owner);
        assert_eq!(
            owner.observe_name_owner_changed(request.session, ":1.42", "not-a-unique-name"),
            ApiBusNameOwnerEvent::Lost(request.session)
        );
        assert!(!owner.is_owned());
        assert_eq!(
            owner.begin_acquire(":1.43"),
            Err(ApiBusNameOwnerError::AcquisitionAlreadyActive),
            "the failed connection must be closed before a replacement session starts"
        );
        assert_eq!(
            owner.release(request.session),
            Ok(ApiBusNameRelease {
                session: request.session
            })
        );
        assert!(owner.begin_acquire(":1.43").is_ok());
    }

    #[test]
    fn stale_events_cannot_reanimate_released_or_replaced_bus_lifetimes() {
        let mut owner = ApiBusNameOwner::new();
        let first = acquire(&mut owner);
        owner.observe_acquire_result(first.session, ApiBusNameAcquireResult::PrimaryOwner);
        assert_eq!(
            owner.release(first.session),
            Ok(ApiBusNameRelease {
                session: first.session
            })
        );
        assert_eq!(
            owner.ownership(),
            ApiBusNameOwnership::Released {
                session: first.session
            }
        );
        assert_eq!(
            owner.observe_name_owner_changed(first.session, ":1.9", ":1.42"),
            ApiBusNameOwnerEvent::IgnoredStaleSession(first.session)
        );

        let second = owner.begin_acquire(":1.43").unwrap();
        assert!(second.session > first.session);
        assert_eq!(
            owner.observe_acquire_result(first.session, ApiBusNameAcquireResult::PrimaryOwner),
            ApiBusNameOwnerEvent::IgnoredStaleSession(first.session)
        );
        assert!(!owner.is_owned());
        assert_eq!(
            owner.observe_name_owner_changed(second.session, ":1.42", ":1.43"),
            ApiBusNameOwnerEvent::Owned(second.session)
        );
    }

    #[test]
    fn delayed_acquire_result_cannot_reanimate_lost_session() {
        let mut owner = ApiBusNameOwner::new();
        let request = acquire(&mut owner);
        assert_eq!(
            owner.observe_acquire_result(request.session, ApiBusNameAcquireResult::Exists),
            ApiBusNameOwnerEvent::Lost(request.session)
        );
        assert_eq!(
            owner.observe_acquire_result(request.session, ApiBusNameAcquireResult::PrimaryOwner),
            ApiBusNameOwnerEvent::IgnoredStaleSession(request.session)
        );
        assert!(!owner.is_owned());
    }

    #[test]
    fn lost_owner_signal_cannot_reanimate_the_same_session() {
        let mut owner = ApiBusNameOwner::new();
        let request = acquire(&mut owner);
        assert_eq!(
            owner.observe_name_owner_changed(request.session, ":1.42", ":1.9"),
            ApiBusNameOwnerEvent::Lost(request.session)
        );
        assert_eq!(
            owner.observe_name_owner_changed(request.session, ":1.9", ":1.42"),
            ApiBusNameOwnerEvent::Lost(request.session)
        );
        assert!(!owner.is_owned());
    }
}
