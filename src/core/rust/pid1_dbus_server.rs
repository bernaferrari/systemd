// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (`bus_init_private()`, `bus_on_connection()`, `bus_done_private()`)

//! Concrete same-thread lifecycle and nonblocking I/O for PID 1's private bus.
//! PORT-SYNC: src/core/dbus.c (`bus_init_private()`, `bus_on_connection()`,
//! `sd_bus_attach_event()`, and `bus_done_private()`).
//!
//! The lower layers deliberately separate pathname binding, authentication,
//! bounded wire state, command handoff, reply ownership, and epoll readiness.
//! This module composes those pieces into the first complete descriptor
//! lifecycle: bind/register, authenticate, promote, read one checked frame,
//! submit one manager command, poll/write its reply, detach individual failed
//! peers, and unregister everything in C's teardown order.
//!
//! This owner still must not be advertised from production `main.rs`: the
//! checked Rust wire surface implements only a small manager-method subset and
//! does not yet provide the complete vtables, properties, signals,
//! subscriptions, SELinux/polkit policy, or protocol-error replies supplied by
//! sd-bus. [`Self::bind_system_private_if_pid1`] preserves C's PID-1
//! eligibility rule for the eventual integration, while tests and namespace
//! harnesses can use [`Self::bind_path`] without claiming API completeness.

#[cfg(target_os = "linux")]
mod imp {
    use std::num::NonZeroUsize;
    use std::path::Path;

    use systemd_event_loop_rs::loop_::EventLoop;

    use crate::pid1_dbus_command_adapter::Pid1DbusCommandAdapter;
    use crate::pid1_dbus_event_source::PrivateBusDispatchOutcome;
    use crate::pid1_dbus_listener::{
        PrivateBusBindError, PrivateBusConnectionId, PrivateBusListener,
    };
    use crate::pid1_dbus_transport::{
        PrivateBusTransportError, PrivateBusTransportOwner, PrivateBusWireDispatchOutcome,
        PrivateBusWireReadOutcome, PrivateBusWireSlotConfig, PrivateBusWireWriteOutcome,
    };
    use crate::pid1_dbus_wire_source::{
        PrivateBusWireInterest, PrivateBusWireSourceError, PrivateBusWireSourceOwner,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateBusServerTurnBudget {
        pub accepts: NonZeroUsize,
        pub authentication_steps: NonZeroUsize,
        pub promotions: NonZeroUsize,
        pub wire_events: NonZeroUsize,
        pub reply_polls_per_event: NonZeroUsize,
    }

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateBusServerTurnOutcome {
        pub admission: PrivateBusDispatchOutcome,
        pub promoted: usize,
        pub wire_events: usize,
        pub bytes_read: usize,
        pub bytes_written: usize,
        pub commands_submitted: usize,
        pub no_reply_rejections: usize,
        pub replies_inspected: usize,
        pub replies_enqueued: usize,
        pub connections_closed: usize,
        pub promotion_budget_exhausted: bool,
        pub wire_budget_exhausted: bool,
    }

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateBusReplySweepOutcome {
        pub slots_inspected: usize,
        pub replies_inspected: usize,
        pub replies_enqueued: usize,
        pub connections_closed: usize,
        pub slot_budget_exhausted: bool,
    }

    #[derive(Debug)]
    pub enum PrivateBusServerError {
        Bind(PrivateBusBindError),
        Transport(PrivateBusTransportError),
        WireSource(PrivateBusWireSourceError),
        InconsistentOwnership(PrivateBusConnectionId),
    }

    impl From<PrivateBusBindError> for PrivateBusServerError {
        fn from(error: PrivateBusBindError) -> Self {
            Self::Bind(error)
        }
    }

    impl From<PrivateBusTransportError> for PrivateBusServerError {
        fn from(error: PrivateBusTransportError) -> Self {
            Self::Transport(error)
        }
    }

    impl From<PrivateBusWireSourceError> for PrivateBusServerError {
        fn from(error: PrivateBusWireSourceError) -> Self {
            Self::WireSource(error)
        }
    }

    /// Owns the private listener, every accepted stream, and every epoll
    /// registration for their authentication and wire lifetimes.
    pub struct PrivateBusServer {
        transport: PrivateBusTransportOwner,
        wire_sources: PrivateBusWireSourceOwner,
        wire_config: PrivateBusWireSlotConfig,
        reply_poll_cursor: Option<PrivateBusConnectionId>,
    }

    impl PrivateBusServer {
        pub fn register(
            event_loop: &mut EventLoop,
            listener: PrivateBusListener,
            connection_limit: NonZeroUsize,
            wire_config: PrivateBusWireSlotConfig,
        ) -> Result<Self, PrivateBusServerError> {
            Ok(Self {
                transport: PrivateBusTransportOwner::register(
                    event_loop,
                    listener,
                    connection_limit,
                )?,
                wire_sources: PrivateBusWireSourceOwner::new(),
                wire_config,
                reply_poll_cursor: None,
            })
        }

        /// Bind a test/namespace pathname and register it with the manager
        /// event loop. The successful socket pathname follows C and remains
        /// after teardown for the next initialization to replace.
        pub fn bind_path(
            event_loop: &mut EventLoop,
            path: &Path,
            manager_effective_uid: u32,
            connection_limit: NonZeroUsize,
            wire_config: PrivateBusWireSlotConfig,
        ) -> Result<Self, PrivateBusServerError> {
            let listener = PrivateBusListener::bind_path(path, manager_effective_uid)?;
            Self::register(event_loop, listener, connection_limit, wire_config)
        }

        /// Bind `/run/systemd/private` only for the system manager running as
        /// PID 1, matching `bus_init_private()`. A non-PID-1 invocation is an
        /// ordinary skipped lifecycle, not an error and not a weaker path.
        pub fn bind_system_private_if_pid1(
            event_loop: &mut EventLoop,
            manager_effective_uid: u32,
            connection_limit: NonZeroUsize,
            wire_config: PrivateBusWireSlotConfig,
        ) -> Result<Option<Self>, PrivateBusServerError> {
            if std::process::id() != 1 {
                return Ok(None);
            }
            let listener = PrivateBusListener::bind_system_private(manager_effective_uid)?;
            Self::register(event_loop, listener, connection_limit, wire_config).map(Some)
        }

        pub fn retained_connection_count(&self) -> usize {
            self.transport.retained_connection_count()
        }

        pub fn wire_connection_count(&self) -> usize {
            self.transport.wire_connection_count()
        }

        /// Advance listener/authentication/wire readiness with finite work.
        ///
        /// Per-peer framing, I/O, or command failures detach only that peer,
        /// as `bus_on_connection()`/sd-bus disconnect handling does. Listener
        /// and event-source ownership errors remain fatal to this owner and
        /// are returned to the manager.
        pub fn dispatch_ready(
            &mut self,
            event_loop: &mut EventLoop,
            adapter: &Pid1DbusCommandAdapter,
            budget: PrivateBusServerTurnBudget,
            server_id: impl FnMut() -> Result<[u8; 16], nix::errno::Errno>,
        ) -> Result<PrivateBusServerTurnOutcome, PrivateBusServerError> {
            let mut outcome = PrivateBusServerTurnOutcome {
                admission: self.transport.dispatch_ready(
                    event_loop,
                    budget.accepts,
                    budget.authentication_steps,
                    server_id,
                )?,
                ..PrivateBusServerTurnOutcome::default()
            };

            for promotion in 0..budget.promotions.get() {
                let Some(id) = self
                    .transport
                    .promote_authenticated_to_wire(self.wire_config)?
                else {
                    break;
                };
                let slot = self
                    .transport
                    .wire_slot(id)
                    .ok_or(PrivateBusServerError::InconsistentOwnership(id))?;
                if let Err(error) = self.wire_sources.register(
                    event_loop,
                    id,
                    slot,
                    PrivateBusWireInterest::read_only(),
                ) {
                    self.transport.close_wire_slot(id);
                    return Err(error.into());
                }
                outcome.promoted += 1;
                if let Err(error) = self.refresh_interest(event_loop, id) {
                    let _ = self.wire_sources.unregister_one(event_loop, id);
                    self.transport.close_wire_slot(id);
                    return Err(error);
                }
                if promotion + 1 == budget.promotions.get()
                    && self.transport.handoff_connection_count() != 0
                {
                    outcome.promotion_budget_exhausted = true;
                }
            }

            for event_index in 0..budget.wire_events.get() {
                let Some((id, event)) = self.wire_sources.pop_ready()? else {
                    break;
                };
                outcome.wire_events += 1;

                if event.terminal {
                    self.close_wire_slot(event_loop, id)?;
                    outcome.connections_closed += 1;
                    continue;
                }

                let mut close = false;
                if event.readable {
                    match self.transport.read_wire_slot_once(id) {
                        Ok(PrivateBusWireReadOutcome::Read { bytes }) => {
                            outcome.bytes_read += bytes;
                        }
                        Ok(PrivateBusWireReadOutcome::Backpressured)
                        | Ok(PrivateBusWireReadOutcome::WouldBlock) => {}
                        Ok(PrivateBusWireReadOutcome::PeerClosed) | Err(_) => close = true,
                    }

                    if !close {
                        match self.transport.dispatch_wire_slot_once(id, adapter) {
                            Ok(PrivateBusWireDispatchOutcome::NoMessage) => {}
                            Ok(PrivateBusWireDispatchOutcome::Submitted { .. }) => {
                                outcome.commands_submitted += 1;
                            }
                            Ok(PrivateBusWireDispatchOutcome::RejectedNoReply { .. }) => {
                                outcome.no_reply_rejections += 1;
                            }
                            Err(_) => close = true,
                        }
                    }
                }

                if !close {
                    match self
                        .transport
                        .poll_wire_slot_replies(id, budget.reply_polls_per_event)
                    {
                        Ok(polled) => {
                            outcome.replies_inspected += polled.inspected;
                            outcome.replies_enqueued += polled.enqueued;
                        }
                        Err(_) => close = true,
                    }
                }

                if !close && event.writable {
                    match self.transport.write_wire_slot_once(id) {
                        Ok(PrivateBusWireWriteOutcome::Written { bytes, .. }) => {
                            outcome.bytes_written += bytes;
                        }
                        Ok(PrivateBusWireWriteOutcome::Idle)
                        | Ok(PrivateBusWireWriteOutcome::WouldBlock) => {}
                        Ok(PrivateBusWireWriteOutcome::PeerClosed) | Err(_) => close = true,
                    }
                }

                if close {
                    self.close_wire_slot(event_loop, id)?;
                    outcome.connections_closed += 1;
                } else {
                    self.refresh_interest(event_loop, id)?;
                }

                if event_index + 1 == budget.wire_events.get() && self.wire_sources.has_ready()? {
                    outcome.wire_budget_exhausted = true;
                }
            }

            Ok(outcome)
        }

        /// Poll manager results after the command inbox has mutated the live
        /// runtime, then enable `EPOLLOUT` for completed frames.
        ///
        /// This is a bounded, allocation-free round-robin scan. It closes only
        /// the peer whose reply channel/encoding became terminal.
        pub fn poll_manager_replies(
            &mut self,
            event_loop: &mut EventLoop,
            slot_budget: NonZeroUsize,
            reply_budget_per_slot: NonZeroUsize,
        ) -> Result<PrivateBusReplySweepOutcome, PrivateBusServerError> {
            let mut outcome = PrivateBusReplySweepOutcome::default();
            let retained_at_start = self.transport.wire_connection_count();
            if retained_at_start == 0 {
                self.reply_poll_cursor = None;
                return Ok(outcome);
            }
            let to_inspect = retained_at_start.min(slot_budget.get());
            outcome.slot_budget_exhausted = retained_at_start > to_inspect;

            for _ in 0..to_inspect {
                let Some(id) = self.next_poll_id() else {
                    self.reply_poll_cursor = None;
                    break;
                };
                outcome.slots_inspected += 1;
                self.reply_poll_cursor = Some(id);

                match self
                    .transport
                    .poll_wire_slot_replies(id, reply_budget_per_slot)
                {
                    Ok(polled) => {
                        outcome.replies_inspected += polled.inspected;
                        outcome.replies_enqueued += polled.enqueued;
                        self.refresh_interest(event_loop, id)?;
                    }
                    Err(_) => {
                        self.close_wire_slot(event_loop, id)?;
                        outcome.connections_closed += 1;
                    }
                }
            }
            Ok(outcome)
        }

        /// Detach all wire sources before closing slots, then detach
        /// authentication/listener sources. This is safe to repeat.
        pub fn unregister(
            &mut self,
            event_loop: &mut EventLoop,
        ) -> Result<(), PrivateBusServerError> {
            let wire_result = self.wire_sources.unregister(event_loop);
            let transport_result = self.transport.unregister(event_loop);
            self.reply_poll_cursor = None;
            if let Err(error) = wire_result {
                return Err(error.into());
            }
            transport_result.map_err(Into::into)
        }

        fn next_poll_id(&self) -> Option<PrivateBusConnectionId> {
            self.transport
                .next_wire_slot_id(self.reply_poll_cursor)
                .or_else(|| self.transport.next_wire_slot_id(None))
        }

        fn refresh_interest(
            &mut self,
            event_loop: &EventLoop,
            id: PrivateBusConnectionId,
        ) -> Result<(), PrivateBusServerError> {
            let readiness = self.transport.wire_slot_readiness(id)?;
            if readiness.terminal {
                return Err(PrivateBusServerError::InconsistentOwnership(id));
            }
            let dispatch_buffered = readiness.read_budget == 0 && readiness.can_track_reply;
            let interest = PrivateBusWireInterest::new(
                readiness.read_budget != 0 && readiness.can_track_reply,
                readiness.reply_write_pending,
            );
            self.wire_sources.set_interest(event_loop, id, interest)?;
            if dispatch_buffered {
                self.wire_sources.schedule_buffered_read(id)?;
            }
            Ok(())
        }

        fn close_wire_slot(
            &mut self,
            event_loop: &mut EventLoop,
            id: PrivateBusConnectionId,
        ) -> Result<(), PrivateBusServerError> {
            let unregister = self.wire_sources.unregister_one(event_loop, id);
            let closed = self.transport.close_wire_slot(id);
            if !closed {
                return Err(PrivateBusServerError::InconsistentOwnership(id));
            }
            unregister.map_err(Into::into)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::path::PathBuf;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        use nix::unistd::geteuid;

        use super::*;
        use crate::pid1_bus_source::pid1_bus_command_channel;
        use crate::pid1_manager_commands::DenyAllPid1CommandAuthorizer;
        use crate::runtime_manager::RuntimeManager;

        fn socket_path(name: &str) -> PathBuf {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "systemd-rust-private-bus-server-{name}-{}-{stamp}.socket",
                std::process::id()
            ))
        }

        fn config() -> PrivateBusWireSlotConfig {
            PrivateBusWireSlotConfig::new(4096, NonZeroUsize::new(4).unwrap(), 1024, 4096)
        }

        fn budget() -> PrivateBusServerTurnBudget {
            PrivateBusServerTurnBudget {
                accepts: NonZeroUsize::new(8).unwrap(),
                authentication_steps: NonZeroUsize::new(8).unwrap(),
                promotions: NonZeroUsize::new(8).unwrap(),
                wire_events: NonZeroUsize::new(8).unwrap(),
                reply_polls_per_event: NonZeroUsize::new(4).unwrap(),
            }
        }

        fn external_token() -> Vec<u8> {
            geteuid()
                .as_raw()
                .to_string()
                .bytes()
                .flat_map(|byte| {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0xf)]]
                })
                .collect()
        }

        fn push_padding(bytes: &mut Vec<u8>, alignment: usize) {
            let padding = (alignment - bytes.len() % alignment) % alignment;
            bytes.resize(bytes.len() + padding, 0);
        }

        fn push_text(bytes: &mut Vec<u8>, value: &str, signature: bool) {
            if signature {
                bytes.push(u8::try_from(value.len()).unwrap());
            } else {
                push_padding(bytes, 4);
                bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
            }
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }

        fn push_header(fields: &mut Vec<u8>, code: u8, kind: u8, value: &str) {
            push_padding(fields, 8);
            fields.extend_from_slice(&[code, 1, kind, 0]);
            push_text(fields, value, kind == b'g');
        }

        fn load_unit_call(serial: u32) -> Vec<u8> {
            let mut fields = Vec::new();
            push_header(&mut fields, 1, b'o', "/org/freedesktop/systemd1");
            push_header(&mut fields, 2, b's', "org.freedesktop.systemd1.Manager");
            push_header(&mut fields, 3, b's', "LoadUnit");
            push_header(&mut fields, 8, b'g', "s");

            let mut body = Vec::new();
            push_text(&mut body, "missing.service", false);
            let mut output = vec![b'l', 1, 0, 1];
            output.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            output.extend_from_slice(&serial.to_le_bytes());
            output.extend_from_slice(&u32::try_from(fields.len()).unwrap().to_le_bytes());
            output.extend_from_slice(&fields);
            push_padding(&mut output, 8);
            output.extend_from_slice(&body);
            output
        }

        fn turn(
            server: &mut PrivateBusServer,
            event_loop: &mut EventLoop,
            adapter: &Pid1DbusCommandAdapter,
        ) -> PrivateBusServerTurnOutcome {
            server
                .dispatch_ready(event_loop, adapter, budget(), || Ok([0x5a; 16]))
                .unwrap()
        }

        #[test]
        fn system_private_lifecycle_is_skipped_outside_pid1() {
            if std::process::id() == 1 {
                return;
            }
            let mut event_loop = EventLoop::new().unwrap();
            assert!(
                PrivateBusServer::bind_system_private_if_pid1(
                    &mut event_loop,
                    geteuid().as_raw(),
                    NonZeroUsize::new(1).unwrap(),
                    config(),
                )
                .unwrap()
                .is_none()
            );
        }

        #[test]
        fn complete_nonblocking_lifecycle_delivers_the_manager_reply() {
            let path = socket_path("roundtrip");
            let mut event_loop = EventLoop::new().unwrap();
            let mut server = PrivateBusServer::bind_path(
                &mut event_loop,
                &path,
                geteuid().as_raw(),
                NonZeroUsize::new(2).unwrap(),
                config(),
            )
            .unwrap();
            let (command_sender, mut command_inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(4).unwrap()).unwrap();
            command_inbox.register(&mut event_loop).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);
            let mut client = UnixStream::connect(&path).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();

            event_loop.run_once(0).unwrap();
            assert_eq!(
                turn(&mut server, &mut event_loop, &adapter)
                    .admission
                    .accepted,
                1
            );

            client.write_all(b"\0AUTH EXTERNAL\r\n").unwrap();
            for _ in 0..2 {
                event_loop.run_once(0).unwrap();
                turn(&mut server, &mut event_loop, &adapter);
            }
            let mut challenge = [0_u8; 6];
            client.read_exact(&mut challenge).unwrap();
            assert_eq!(&challenge, b"DATA\r\n");

            let call_serial = 17;
            let call = load_unit_call(call_serial);
            let mut response = b"DATA ".to_vec();
            response.extend_from_slice(&external_token());
            response.extend_from_slice(b"\r\nBEGIN\r\n");
            response.extend_from_slice(&call);
            client.write_all(&response).unwrap();

            let mut submitted = 0;
            for _ in 0..4 {
                event_loop.run_once(0).unwrap();
                submitted += turn(&mut server, &mut event_loop, &adapter).commands_submitted;
                if submitted != 0 {
                    break;
                }
            }
            assert_eq!(submitted, 1);
            assert_eq!(server.wire_connection_count(), 1);
            let mut auth_ok = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                client.read_exact(&mut byte).unwrap();
                auth_ok.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            assert!(auth_ok.starts_with(b"OK "));
            assert!(auth_ok.ends_with(b"\r\n"));

            event_loop.run_once(0).unwrap();
            let mut runtime = RuntimeManager::new();
            let mut authorizer = DenyAllPid1CommandAuthorizer;
            assert_eq!(
                command_inbox
                    .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(4).unwrap(),)
                    .unwrap()
                    .dispatched,
                1
            );
            let sweep = server
                .poll_manager_replies(
                    &mut event_loop,
                    NonZeroUsize::new(2).unwrap(),
                    NonZeroUsize::new(4).unwrap(),
                )
                .unwrap();
            assert_eq!(sweep.replies_enqueued, 1);

            event_loop.run_once(0).unwrap();
            assert!(turn(&mut server, &mut event_loop, &adapter).bytes_written > 0);
            let mut header = [0_u8; 16];
            client.read_exact(&mut header).unwrap();
            assert_eq!(header[0], b'l');
            assert_eq!(header[1], 3, "authorization failure is a D-Bus error");
            let body_len =
                usize::try_from(u32::from_le_bytes(header[4..8].try_into().unwrap())).unwrap();
            let fields_len =
                usize::try_from(u32::from_le_bytes(header[12..16].try_into().unwrap())).unwrap();
            let total = (16 + fields_len).next_multiple_of(8) + body_len;
            let mut remainder = vec![0_u8; total - header.len()];
            client.read_exact(&mut remainder).unwrap();

            server.unregister(&mut event_loop).unwrap();
            assert_eq!(server.retained_connection_count(), 0);
            assert!(std::fs::symlink_metadata(&path).is_ok());
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn peer_disconnect_detaches_its_wire_source_and_frees_the_cap() {
            let path = socket_path("disconnect");
            let mut event_loop = EventLoop::new().unwrap();
            let mut server = PrivateBusServer::bind_path(
                &mut event_loop,
                &path,
                geteuid().as_raw(),
                NonZeroUsize::new(1).unwrap(),
                config(),
            )
            .unwrap();
            let (command_sender, _command_inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);
            let mut client = UnixStream::connect(&path).unwrap();

            event_loop.run_once(0).unwrap();
            turn(&mut server, &mut event_loop, &adapter);
            client.write_all(b"\0AUTH EXTERNAL\r\n").unwrap();
            for _ in 0..2 {
                event_loop.run_once(0).unwrap();
                turn(&mut server, &mut event_loop, &adapter);
            }
            let mut challenge = [0_u8; 6];
            client.read_exact(&mut challenge).unwrap();
            let mut response = b"DATA ".to_vec();
            response.extend_from_slice(&external_token());
            response.extend_from_slice(b"\r\nBEGIN\r\n");
            client.write_all(&response).unwrap();
            for _ in 0..3 {
                event_loop.run_once(0).unwrap();
                turn(&mut server, &mut event_loop, &adapter);
                if server.wire_connection_count() == 1 {
                    break;
                }
            }
            assert_eq!(server.wire_connection_count(), 1);

            drop(client);
            event_loop.run_once(0).unwrap();
            let outcome = turn(&mut server, &mut event_loop, &adapter);
            assert_eq!(outcome.connections_closed, 1);
            assert_eq!(server.retained_connection_count(), 0);

            server.unregister(&mut event_loop).unwrap();
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;
