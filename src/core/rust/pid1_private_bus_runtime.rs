// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (`manager_setup_bus()`, `bus_init_private()`, `bus_done_private()`)
//
//! The ownership seam between PID 1's event loop and the private D-Bus server.
// PORT-SYNC: src/core/dbus.c (`manager_setup_bus()`, `bus_init_private()`,
// `bus_on_connection()`, and `bus_done_private()`).
//!
//! C attaches the private listener and each accepted `sd_bus` directly to its
//! one `Manager` event loop. Rust deliberately keeps the corresponding
//! ordering explicit: after one epoll dispatch, admit/authenticate/decode
//! peers; then mutate the one live [`RuntimeManager`]; then poll the reply
//! receivers and arm output interest. This type is the single future
//! production hand-off point for those owners.
//!
//! It is intentionally *not* constructed by `main.rs` yet. The checked wire
//! surface remains only a small subset of `org.freedesktop.systemd1`, so
//! binding `/run/systemd/private` would advertise an incompatible manager API.
//! Keeping the complete ownership turn here lets the eventual API-complete
//! implementation make that startup change without recreating or splitting
//! manager, command-channel, or event-loop ownership.

#[cfg(target_os = "linux")]
mod imp {
    use std::num::NonZeroUsize;
    use std::path::Path;

    use systemd_event_loop_rs::loop_::EventLoop;

    use crate::pid1_bus_source::{Pid1BusCommandInbox, Pid1BusCommandSender};
    use crate::pid1_dbus_command_adapter::Pid1DbusCommandAdapter;
    use crate::pid1_dbus_server::{
        PrivateBusReplySweepOutcome, PrivateBusServer, PrivateBusServerError,
        PrivateBusServerTurnBudget, PrivateBusServerTurnOutcome,
    };
    use crate::pid1_dbus_transport::PrivateBusWireSlotConfig;
    use crate::pid1_manager_commands::{Pid1CommandAuthorizer, Pid1DispatchOutcome};
    use crate::runtime_manager::RuntimeManager;

    /// All finite work limits used by one complete private-bus manager turn.
    ///
    /// The manager command budget is intentionally separate from the wire
    /// ingress budget: one busy peer must not make signals, socket sources, or
    /// already-queued manager work unbounded.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Pid1PrivateBusTurnBudget {
        pub server: PrivateBusServerTurnBudget,
        pub manager_commands: NonZeroUsize,
        pub reply_slots: NonZeroUsize,
        pub reply_polls_per_slot: NonZeroUsize,
    }

    /// The observable work completed in one complete private-bus manager turn.
    ///
    /// `manager` retains a possible lifecycle objective so the outer PID 1
    /// loop can preserve its existing objective hand-off semantics.
    pub struct Pid1PrivateBusTurnOutcome {
        pub ingress: PrivateBusServerTurnOutcome,
        pub manager: Pid1DispatchOutcome,
        pub replies: PrivateBusReplySweepOutcome,
    }

    /// Errors at the event-loop/manager ownership boundary.
    #[derive(Debug)]
    pub enum Pid1PrivateBusRuntimeError {
        Server(PrivateBusServerError),
        CommandInbox(nix::errno::Errno),
    }

    impl From<PrivateBusServerError> for Pid1PrivateBusRuntimeError {
        fn from(error: PrivateBusServerError) -> Self {
            Self::Server(error)
        }
    }

    /// Owns the private D-Bus transport plus its only valid command adapter.
    ///
    /// The adapter is built from the same wake-aware sender whose inbox is
    /// passed to [`Self::dispatch_turn`]. Consequently accepted peer work can
    /// only be executed by the caller's exact `RuntimeManager`; no shadow
    /// manager or background dispatcher can be introduced accidentally.
    pub struct Pid1PrivateBusRuntime {
        server: PrivateBusServer,
        adapter: Pid1DbusCommandAdapter,
    }

    impl Pid1PrivateBusRuntime {
        /// Bind a test or PID-namespace pathname and compose it with the
        /// caller's already-created PID 1 command channel.
        pub fn bind_path(
            event_loop: &mut EventLoop,
            path: &Path,
            manager_effective_uid: u32,
            command_sender: Pid1BusCommandSender,
            connection_limit: NonZeroUsize,
            wire_config: PrivateBusWireSlotConfig,
        ) -> Result<Self, Pid1PrivateBusRuntimeError> {
            let server = PrivateBusServer::bind_path(
                event_loop,
                path,
                manager_effective_uid,
                connection_limit,
                wire_config,
            )?;
            Ok(Self {
                server,
                adapter: Pid1DbusCommandAdapter::new(command_sender),
            })
        }

        /// Apply C's system-manager PID-1 eligibility rule at the eventual
        /// production bind site. `None` means the caller is not PID 1 and no
        /// descriptor or pathname was created.
        pub fn bind_system_private_if_pid1(
            event_loop: &mut EventLoop,
            manager_effective_uid: u32,
            command_sender: Pid1BusCommandSender,
            connection_limit: NonZeroUsize,
            wire_config: PrivateBusWireSlotConfig,
        ) -> Result<Option<Self>, Pid1PrivateBusRuntimeError> {
            let Some(server) = PrivateBusServer::bind_system_private_if_pid1(
                event_loop,
                manager_effective_uid,
                connection_limit,
                wire_config,
            )?
            else {
                return Ok(None);
            };
            Ok(Some(Self {
                server,
                adapter: Pid1DbusCommandAdapter::new(command_sender),
            }))
        }

        pub fn retained_connection_count(&self) -> usize {
            self.server.retained_connection_count()
        }

        /// Execute the only safe event-loop ordering for a private-bus turn.
        ///
        /// Call this after `EventLoop::run_once()`: ingress sees the batch of
        /// ready descriptors; manager dispatch mutates the supplied live
        /// runtime exactly once; reply polling then observes results from that
        /// same dispatch before the next epoll wait. A returned objective is
        /// deliberately not consumed here, because the outer lifecycle owner
        /// must retain and classify it.
        pub fn dispatch_turn<A: Pid1CommandAuthorizer + ?Sized>(
            &mut self,
            event_loop: &mut EventLoop,
            command_inbox: &mut Pid1BusCommandInbox,
            runtime: &mut RuntimeManager,
            command_authorizer: &mut A,
            budget: Pid1PrivateBusTurnBudget,
            server_id: impl FnMut() -> Result<[u8; 16], nix::errno::Errno>,
        ) -> Result<Pid1PrivateBusTurnOutcome, Pid1PrivateBusRuntimeError> {
            let ingress =
                self.server
                    .dispatch_ready(event_loop, &self.adapter, budget.server, server_id)?;
            let manager = command_inbox
                .dispatch_pending(runtime, command_authorizer, budget.manager_commands)
                .map_err(Pid1PrivateBusRuntimeError::CommandInbox)?;
            let replies = self.server.poll_manager_replies(
                event_loop,
                budget.reply_slots,
                budget.reply_polls_per_slot,
            )?;
            Ok(Pid1PrivateBusTurnOutcome {
                ingress,
                manager,
                replies,
            })
        }

        /// Mirror C's shutdown ordering: detach all epoll sources before
        /// closing the private streams and listener. Safe to repeat.
        pub fn unregister(
            &mut self,
            event_loop: &mut EventLoop,
        ) -> Result<(), Pid1PrivateBusRuntimeError> {
            self.server.unregister(event_loop)?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::path::PathBuf;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        use nix::unistd::geteuid;
        use systemd_event_loop_rs::loop_::EventLoop;

        use super::*;
        use crate::pid1_bus_source::pid1_bus_command_channel;
        use crate::pid1_manager_commands::PrivateBusPid1CommandAuthorizer;

        fn socket_path() -> PathBuf {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "systemd-rust-private-bus-runtime-{}-{stamp}.socket",
                std::process::id()
            ))
        }

        fn wire_config() -> PrivateBusWireSlotConfig {
            PrivateBusWireSlotConfig::new(4096, NonZeroUsize::new(4).unwrap(), 1024, 4096)
        }

        fn budget() -> Pid1PrivateBusTurnBudget {
            Pid1PrivateBusTurnBudget {
                server: PrivateBusServerTurnBudget {
                    accepts: NonZeroUsize::new(8).unwrap(),
                    authentication_steps: NonZeroUsize::new(8).unwrap(),
                    promotions: NonZeroUsize::new(8).unwrap(),
                    wire_events: NonZeroUsize::new(8).unwrap(),
                    reply_polls_per_event: NonZeroUsize::new(4).unwrap(),
                },
                manager_commands: NonZeroUsize::new(8).unwrap(),
                reply_slots: NonZeroUsize::new(8).unwrap(),
                reply_polls_per_slot: NonZeroUsize::new(4).unwrap(),
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
            runtime: &mut Pid1PrivateBusRuntime,
            event_loop: &mut EventLoop,
            command_inbox: &mut Pid1BusCommandInbox,
            manager: &mut RuntimeManager,
            authorizer: &mut PrivateBusPid1CommandAuthorizer,
        ) -> Pid1PrivateBusTurnOutcome {
            runtime
                .dispatch_turn(
                    event_loop,
                    command_inbox,
                    manager,
                    authorizer,
                    budget(),
                    || Ok([0x5a; 16]),
                )
                .unwrap()
        }

        #[test]
        fn complete_turn_owns_ingress_manager_dispatch_and_reply_sweep() {
            let path = socket_path();
            let mut event_loop = EventLoop::new().unwrap();
            let (command_sender, mut command_inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(4).unwrap()).unwrap();
            command_inbox.register(&mut event_loop).unwrap();
            let mut private_bus = Pid1PrivateBusRuntime::bind_path(
                &mut event_loop,
                &path,
                geteuid().as_raw(),
                command_sender,
                NonZeroUsize::new(2).unwrap(),
                wire_config(),
            )
            .unwrap();
            let mut manager = RuntimeManager::new();
            let mut authorizer = PrivateBusPid1CommandAuthorizer::new(geteuid().as_raw());
            let mut client = UnixStream::connect(&path).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();

            event_loop.run_once(0).unwrap();
            assert_eq!(
                turn(
                    &mut private_bus,
                    &mut event_loop,
                    &mut command_inbox,
                    &mut manager,
                    &mut authorizer,
                )
                .ingress
                .admission
                .accepted,
                1
            );

            client.write_all(b"\0AUTH EXTERNAL\r\n").unwrap();
            for _ in 0..2 {
                event_loop.run_once(0).unwrap();
                turn(
                    &mut private_bus,
                    &mut event_loop,
                    &mut command_inbox,
                    &mut manager,
                    &mut authorizer,
                );
            }
            let mut challenge = [0_u8; 6];
            client.read_exact(&mut challenge).unwrap();
            assert_eq!(&challenge, b"DATA\r\n");

            let mut request = b"DATA ".to_vec();
            request.extend_from_slice(&external_token());
            request.extend_from_slice(b"\r\nBEGIN\r\n");
            request.extend_from_slice(&load_unit_call(17));
            client.write_all(&request).unwrap();

            let mut completed = false;
            for _ in 0..4 {
                event_loop.run_once(0).unwrap();
                let outcome = turn(
                    &mut private_bus,
                    &mut event_loop,
                    &mut command_inbox,
                    &mut manager,
                    &mut authorizer,
                );
                completed |=
                    outcome.manager.dispatched == 1 && outcome.replies.replies_enqueued == 1;
                if completed {
                    break;
                }
            }
            assert!(
                completed,
                "one turn must submit, mutate the same manager, then retain its reply"
            );

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

            event_loop.run_once(0).unwrap();
            let outcome = turn(
                &mut private_bus,
                &mut event_loop,
                &mut command_inbox,
                &mut manager,
                &mut authorizer,
            );
            assert!(outcome.ingress.bytes_written > 0);
            let mut header = [0_u8; 16];
            client.read_exact(&mut header).unwrap();
            assert_eq!(header[0], b'l');
            assert_eq!(
                header[1], 3,
                "the RuntimeManager error is correlated back to this peer"
            );

            private_bus.unregister(&mut event_loop).unwrap();
            assert_eq!(private_bus.retained_connection_count(), 0);
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn system_private_startup_is_a_noop_outside_pid1() {
            if std::process::id() == 1 {
                return;
            }
            let mut event_loop = EventLoop::new().unwrap();
            let (command_sender, _command_inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            assert!(
                Pid1PrivateBusRuntime::bind_system_private_if_pid1(
                    &mut event_loop,
                    geteuid().as_raw(),
                    command_sender,
                    NonZeroUsize::new(1).unwrap(),
                    wire_config(),
                )
                .unwrap()
                .is_none()
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;
