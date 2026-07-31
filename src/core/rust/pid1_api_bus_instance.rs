// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (`bus_init_api()`, `api_bus_instance_id_reply()`)

//! One-shot API-bus instance validation before exposing manager vtables.
//!
//! C queries `org.freedesktop.DBus.GetId` asynchronously on every new API-bus
//! connection. Saved subscription names may be coldplugged only after that
//! reply, and only when they came from the same broker instance (or an older
//! state image did not record an instance ID). Query errors are deliberately
//! non-fatal to API setup, but consume and discard the saved subscriptions.
//!
//! This module models that ordering without opening a production bus. Session
//! tokens come from [`crate::pid1_api_bus_name_owner::ApiBusNameOwner`], so a
//! delayed reply from a replaced connection cannot validate new state.

use std::marker::PhantomData;
use std::rc::Rc;

use systemd_libsystemd_rs::id128_util::SdId128;
use systemd_libsystemd_rs::sd_id128_strings::sd_id128_from_string;

use crate::pid1_api_bus_name_owner::ApiBusSessionId;

pub const DBUS_BROKER_NAME: &str = "org.freedesktop.DBus";
pub const DBUS_BROKER_PATH: &str = "/org/freedesktop/DBus";
pub const DBUS_BROKER_INTERFACE: &str = "org.freedesktop.DBus";
pub const DBUS_GET_ID_MEMBER: &str = "GetId";

/// Exact asynchronous method request issued before C calls `bus_setup_api()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiBusGetIdRequest {
    pub session: ApiBusSessionId,
    pub destination: &'static str,
    pub path: &'static str,
    pub interface: &'static str,
    pub member: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiBusInstanceValidation {
    /// The live broker ID matched the serialized ID exactly.
    SameBroker,
    /// Historical state did not include a broker ID, matching C's backwards
    /// compatible coldplug behavior.
    UnversionedState,
    /// The state belongs to another broker instance and was discarded.
    DifferentBroker,
    /// Enqueuing the asynchronous query failed before a reply could exist.
    QueryEnqueueFailed(i32),
    /// The broker returned a method error.
    QueryFailed(i32),
    /// The broker returned a value which is not an sd-id128 string.
    InvalidReply,
}

/// The only output which permits the caller to proceed to `bus_setup_api()`.
///
/// `coldplug_subscriptions` is empty on every query failure or broker mismatch.
/// The names remain owned here so consuming pending state is explicit and
/// cannot be repeated by a later reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiBusSetupDecision {
    pub session: ApiBusSessionId,
    pub live_bus_id: Option<SdId128>,
    pub validation: ApiBusInstanceValidation,
    pub coldplug_subscriptions: Box<[String]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiBusInstanceEvent {
    Query(ApiBusGetIdRequest),
    Setup(ApiBusSetupDecision),
    IgnoredStaleSession(ApiBusSessionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiBusInstanceState {
    Detached,
    Querying {
        session: ApiBusSessionId,
    },
    Ready {
        session: ApiBusSessionId,
        live_bus_id: Option<SdId128>,
    },
    Released {
        session: ApiBusSessionId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiBusInstanceError {
    SessionAlreadyActive,
    NoActiveSession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingState {
    session: ApiBusSessionId,
    serialized_bus_id: Option<SdId128>,
    subscriptions: Box<[String]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Detached,
    Querying(PendingState),
    Ready {
        session: ApiBusSessionId,
        live_bus_id: Option<SdId128>,
    },
    Released(ApiBusSessionId),
}

/// Same-thread lifecycle for one asynchronous broker-ID query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiBusInstanceOwner {
    state: State,
    _owner_thread: PhantomData<Rc<()>>,
}

impl Default for ApiBusInstanceOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiBusInstanceOwner {
    pub const fn new() -> Self {
        Self {
            state: State::Detached,
            _owner_thread: PhantomData,
        }
    }

    pub fn state(&self) -> ApiBusInstanceState {
        match &self.state {
            State::Detached => ApiBusInstanceState::Detached,
            State::Querying(pending) => ApiBusInstanceState::Querying {
                session: pending.session,
            },
            State::Ready {
                session,
                live_bus_id,
            } => ApiBusInstanceState::Ready {
                session: *session,
                live_bus_id: *live_bus_id,
            },
            State::Released(session) => ApiBusInstanceState::Released { session: *session },
        }
    }

    /// Begin a new connection lifetime and consume its serialized subscription
    /// state into the one pending query.
    pub fn begin_query(
        &mut self,
        session: ApiBusSessionId,
        serialized_bus_id: Option<SdId128>,
        subscriptions: Vec<String>,
    ) -> Result<ApiBusInstanceEvent, ApiBusInstanceError> {
        if !matches!(self.state, State::Detached | State::Released(_)) {
            return Err(ApiBusInstanceError::SessionAlreadyActive);
        }
        self.state = State::Querying(PendingState {
            session,
            serialized_bus_id,
            subscriptions: subscriptions.into_boxed_slice(),
        });
        Ok(ApiBusInstanceEvent::Query(ApiBusGetIdRequest {
            session,
            destination: DBUS_BROKER_NAME,
            path: DBUS_BROKER_PATH,
            interface: DBUS_BROKER_INTERFACE,
            member: DBUS_GET_ID_MEMBER,
        }))
    }

    /// Mirror the immediate `sd_bus_call_method_async()` failure path: pending
    /// subscriptions are consumed without coldplug and API setup may proceed.
    pub fn query_enqueue_failed(
        &mut self,
        session: ApiBusSessionId,
        errno: i32,
    ) -> ApiBusInstanceEvent {
        self.finish(
            session,
            Err(ApiBusInstanceValidation::QueryEnqueueFailed(errno)),
        )
    }

    /// Consume the single asynchronous `GetId` reply.
    pub fn observe_reply(
        &mut self,
        session: ApiBusSessionId,
        reply: Result<&str, i32>,
    ) -> ApiBusInstanceEvent {
        let parsed = match reply {
            Ok(value) => {
                sd_id128_from_string(value).map_err(|_| ApiBusInstanceValidation::InvalidReply)
            }
            Err(errno) => Err(ApiBusInstanceValidation::QueryFailed(errno)),
        };
        self.finish(session, parsed)
    }

    /// Close this API-bus lifetime. A reply arriving afterward is stale.
    pub fn release(&mut self, session: ApiBusSessionId) -> Result<(), ApiBusInstanceError> {
        let active = match &self.state {
            State::Querying(pending) => pending.session,
            State::Ready { session, .. } => *session,
            State::Detached | State::Released(_) => {
                return Err(ApiBusInstanceError::NoActiveSession);
            }
        };
        if active != session {
            return Err(ApiBusInstanceError::NoActiveSession);
        }
        self.state = State::Released(session);
        Ok(())
    }

    fn finish(
        &mut self,
        session: ApiBusSessionId,
        result: Result<SdId128, ApiBusInstanceValidation>,
    ) -> ApiBusInstanceEvent {
        let State::Querying(pending) = &self.state else {
            return ApiBusInstanceEvent::IgnoredStaleSession(session);
        };
        if pending.session != session {
            return ApiBusInstanceEvent::IgnoredStaleSession(session);
        }

        let State::Querying(pending) = std::mem::replace(&mut self.state, State::Detached) else {
            unreachable!("querying state was checked above")
        };
        let (live_bus_id, validation, coldplug_subscriptions) = match result {
            Ok(live_bus_id) => match pending.serialized_bus_id {
                None => (
                    Some(live_bus_id),
                    ApiBusInstanceValidation::UnversionedState,
                    pending.subscriptions,
                ),
                Some(serialized_bus_id) if serialized_bus_id.is_null() => (
                    Some(live_bus_id),
                    ApiBusInstanceValidation::UnversionedState,
                    pending.subscriptions,
                ),
                Some(serialized_bus_id) if serialized_bus_id == live_bus_id => (
                    Some(live_bus_id),
                    ApiBusInstanceValidation::SameBroker,
                    pending.subscriptions,
                ),
                Some(_) => (
                    Some(live_bus_id),
                    ApiBusInstanceValidation::DifferentBroker,
                    Box::default(),
                ),
            },
            Err(validation) => (None, validation, Box::default()),
        };
        self.state = State::Ready {
            session,
            live_bus_id,
        };
        ApiBusInstanceEvent::Setup(ApiBusSetupDecision {
            session,
            live_bus_id,
            validation,
            coldplug_subscriptions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pid1_api_bus_name_owner::ApiBusNameOwner;

    const BUS_ID: &str = "0102030405060708090a0b0c0d0e0f10";
    const OTHER_BUS_ID: &str = "11111111111111111111111111111111";

    fn session() -> ApiBusSessionId {
        ApiBusNameOwner::new()
            .begin_acquire(":1.42")
            .unwrap()
            .session
    }

    fn subscriptions() -> Vec<String> {
        vec![":1.7".into(), ":1.9".into()]
    }

    #[test]
    fn query_uses_the_exact_broker_endpoint_and_blocks_reentry() {
        let session = session();
        let mut owner = ApiBusInstanceOwner::new();
        assert_eq!(
            owner.begin_query(session, None, subscriptions()).unwrap(),
            ApiBusInstanceEvent::Query(ApiBusGetIdRequest {
                session,
                destination: DBUS_BROKER_NAME,
                path: DBUS_BROKER_PATH,
                interface: DBUS_BROKER_INTERFACE,
                member: DBUS_GET_ID_MEMBER,
            })
        );
        assert_eq!(
            owner.begin_query(session, None, Vec::new()),
            Err(ApiBusInstanceError::SessionAlreadyActive)
        );
    }

    #[test]
    fn same_broker_coldplugs_saved_subscriptions_exactly_once() {
        let session = session();
        let bus_id = sd_id128_from_string(BUS_ID).unwrap();
        let mut owner = ApiBusInstanceOwner::new();
        owner
            .begin_query(session, Some(bus_id), subscriptions())
            .unwrap();
        assert_eq!(
            owner.observe_reply(session, Ok(BUS_ID)),
            ApiBusInstanceEvent::Setup(ApiBusSetupDecision {
                session,
                live_bus_id: Some(bus_id),
                validation: ApiBusInstanceValidation::SameBroker,
                coldplug_subscriptions: subscriptions().into_boxed_slice(),
            })
        );
        assert_eq!(
            owner.observe_reply(session, Ok(BUS_ID)),
            ApiBusInstanceEvent::IgnoredStaleSession(session)
        );
    }

    #[test]
    fn historical_state_without_bus_id_preserves_coldplug_compatibility() {
        for serialized_bus_id in [None, Some(SdId128::null())] {
            let session = session();
            let bus_id = sd_id128_from_string(BUS_ID).unwrap();
            let mut owner = ApiBusInstanceOwner::new();
            owner
                .begin_query(session, serialized_bus_id, subscriptions())
                .unwrap();
            assert_eq!(
                owner.observe_reply(session, Ok(BUS_ID)),
                ApiBusInstanceEvent::Setup(ApiBusSetupDecision {
                    session,
                    live_bus_id: Some(bus_id),
                    validation: ApiBusInstanceValidation::UnversionedState,
                    coldplug_subscriptions: subscriptions().into_boxed_slice(),
                })
            );
        }
    }

    #[test]
    fn different_broker_discards_subscriptions_but_retains_live_id() {
        let session = session();
        let old_id = sd_id128_from_string(OTHER_BUS_ID).unwrap();
        let live_id = sd_id128_from_string(BUS_ID).unwrap();
        let mut owner = ApiBusInstanceOwner::new();
        owner
            .begin_query(session, Some(old_id), subscriptions())
            .unwrap();
        assert_eq!(
            owner.observe_reply(session, Ok(BUS_ID)),
            ApiBusInstanceEvent::Setup(ApiBusSetupDecision {
                session,
                live_bus_id: Some(live_id),
                validation: ApiBusInstanceValidation::DifferentBroker,
                coldplug_subscriptions: Box::default(),
            })
        );
    }

    #[test]
    fn query_errors_and_malformed_ids_discard_pending_subscriptions() {
        for (reply, expected) in [
            (
                Err(-libc::EIO),
                ApiBusInstanceValidation::QueryFailed(-libc::EIO),
            ),
            (Ok("not-an-id"), ApiBusInstanceValidation::InvalidReply),
        ] {
            let session = session();
            let mut owner = ApiBusInstanceOwner::new();
            owner.begin_query(session, None, subscriptions()).unwrap();
            assert_eq!(
                owner.observe_reply(session, reply),
                ApiBusInstanceEvent::Setup(ApiBusSetupDecision {
                    session,
                    live_bus_id: None,
                    validation: expected,
                    coldplug_subscriptions: Box::default(),
                })
            );
        }
    }

    #[test]
    fn enqueue_failure_consumes_state_and_still_allows_api_setup() {
        let session = session();
        let mut owner = ApiBusInstanceOwner::new();
        owner.begin_query(session, None, subscriptions()).unwrap();
        assert_eq!(
            owner.query_enqueue_failed(session, -libc::ECONNRESET),
            ApiBusInstanceEvent::Setup(ApiBusSetupDecision {
                session,
                live_bus_id: None,
                validation: ApiBusInstanceValidation::QueryEnqueueFailed(-libc::ECONNRESET),
                coldplug_subscriptions: Box::default(),
            })
        );
    }

    #[test]
    fn released_or_replaced_sessions_reject_delayed_replies() {
        let first = session();
        let mut name_owner = ApiBusNameOwner::new();
        let first_name = name_owner.begin_acquire(":1.42").unwrap();
        let mut owner = ApiBusInstanceOwner::new();
        owner
            .begin_query(first_name.session, None, subscriptions())
            .unwrap();
        owner.release(first_name.session).unwrap();
        assert_eq!(
            owner.observe_reply(first_name.session, Ok(BUS_ID)),
            ApiBusInstanceEvent::IgnoredStaleSession(first_name.session)
        );

        name_owner.release(first_name.session).unwrap();
        let second = name_owner.begin_acquire(":1.43").unwrap().session;
        owner.begin_query(second, None, subscriptions()).unwrap();
        assert_eq!(
            owner.observe_reply(first, Ok(BUS_ID)),
            ApiBusInstanceEvent::IgnoredStaleSession(first)
        );
        assert!(matches!(
            owner.state(),
            ApiBusInstanceState::Querying { session } if session == second
        ));
    }
}
