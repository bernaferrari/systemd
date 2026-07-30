// SPDX-License-Identifier: LGPL-2.1-or-later

//! Socket-unit policy owned by the runtime manager.
//!
//! This deliberately contains only the bounded socket-unit state machine:
//! manager-owned listener registration, service association, and fail-closed
//! state transitions. Descriptor creation and service spawning remain in their
//! respective focused subsystems.

use super::RuntimeManager;
use crate::transaction::JobType as TxJobType;
use crate::unit::{ActiveState, UnitType};

impl RuntimeManager {
    fn fail_socket_start(&mut self, unit_name: &str, reason: &str) {
        self.socket_mgr.unregister_socket(unit_name);
        self.service_activation_sockets.retain(|_, sockets| {
            sockets.remove(unit_name);
            !sockets.is_empty()
        });
        self.publish_nonservice_state(unit_name, ActiveState::Failed);
        eprintln!("systemd: socket unit {unit_name} failed: {reason}");
    }

    /// Start the deliberately bounded `Accept=no`/`ListenStream=` socket
    /// runtime. Unsupported modes fail before the unit is reported active.
    fn execute_socket_start(&mut self, unit_name: &str) {
        let Some(info) = self.unit_files.get(unit_name).cloned() else {
            self.fail_socket_start(unit_name, "unit file metadata is unavailable");
            return;
        };

        if info.unit_type != UnitType::Socket {
            self.fail_socket_start(unit_name, "unit is not a socket");
            return;
        }
        if info.socket.accept.unwrap_or(false) {
            self.fail_socket_start(
                unit_name,
                "Accept=yes needs per-connection service ownership and is not implemented",
            );
            return;
        }
        if !info.socket.listen_datagram.is_empty()
            || !info.socket.listen_sequential_packet.is_empty()
            || !info.socket.listen_fifo.is_empty()
            || !info.socket.listen_special.is_empty()
            || !info.socket.listen_netlink.is_empty()
            || !info.socket.listen_message_queue.is_empty()
            || !info.socket.listen_usb_function.is_empty()
        {
            self.fail_socket_start(
                unit_name,
                "only ListenStream= is implemented by the socket runtime",
            );
            return;
        }
        if info.socket.listen_stream.is_empty() {
            self.fail_socket_start(unit_name, "no ListenStream= endpoint is configured");
            return;
        }
        if info
            .socket
            .listen_stream
            .iter()
            .any(|endpoint| endpoint.trim_start().starts_with('/'))
        {
            self.fail_socket_start(
                unit_name,
                "filesystem AF_UNIX lifecycle is not implemented safely",
            );
            return;
        }

        let service_name = info
            .socket
            .service
            .clone()
            .or_else(|| info.service_override.clone())
            .unwrap_or_else(|| self.socket_mgr.associated_service(unit_name));
        if self.load_unit(&service_name).is_err() {
            self.fail_socket_start(
                unit_name,
                &format!("associated service {service_name} could not be loaded"),
            );
            return;
        }

        if self.socket_mgr.get(unit_name).is_none()
            && let Err(error) = self.socket_mgr.register_listen_streams(
                unit_name,
                &info.socket.listen_stream,
                info.socket.file_descriptor_name.as_deref(),
            )
        {
            self.fail_socket_start(unit_name, &error);
            return;
        }
        self.service_activation_sockets
            .entry(service_name)
            .or_default()
            .insert(unit_name.to_string());

        self.publish_nonservice_state(unit_name, ActiveState::Active);
    }

    pub(super) fn execute_socket_stop(&mut self, unit_name: &str) {
        self.socket_mgr.unregister_socket(unit_name);
        self.service_activation_sockets.retain(|_, sockets| {
            sockets.remove(unit_name);
            !sockets.is_empty()
        });
        self.publish_nonservice_state(unit_name, ActiveState::Inactive);
    }

    /// Apply a non-service job only when it belongs to a socket unit.
    ///
    /// Returning `true` means the caller must not apply generic non-service
    /// state changes afterwards; socket failures are already represented by
    /// this helper's manager-owned state transition.
    pub(super) fn execute_socket_job(&mut self, unit_name: &str, job_type: TxJobType) -> bool {
        let is_socket = self
            .units
            .get(unit_name)
            .is_some_and(|unit| unit.unit_type == UnitType::Socket);
        if !is_socket {
            return false;
        }

        match job_type {
            TxJobType::Start => self.execute_socket_start(unit_name),
            TxJobType::Restart => {
                self.execute_socket_stop(unit_name);
                self.execute_socket_start(unit_name);
            }
            TxJobType::Stop => self.execute_socket_stop(unit_name),
            TxJobType::Reload => self.fail_socket_start(
                unit_name,
                "socket reload is not implemented; restart the unit instead",
            ),
            _ => {}
        }
        true
    }
}
