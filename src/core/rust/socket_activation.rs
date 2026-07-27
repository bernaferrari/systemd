// SPDX-License-Identifier: LGPL-2.1-or-later

//! Owned listener state for the deliberately small `Accept=no` activation slice.
//!
//! This module owns listening descriptors but never accepts a connection.  That distinction is
//! essential: for `Accept=no`, the service receives the *listening* descriptors and removes
//! queued work itself.  `Accept=yes` needs a different state machine which transfers an accepted
//! client descriptor to a per-connection service instance; it is intentionally not represented
//! here.

use std::collections::HashMap;
use std::net::TcpListener;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Weak};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddress {
    Stream(String),
    Datagram(String),
}

/// The only activation semantic implemented by this ownership layer.
///
/// Do not add an `AcceptYes` variant until the caller can move an accepted `OwnedFd` into an
/// instantiated service unit and account for connection limits and teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketActivationMode {
    AcceptNo,
}

/// A non-owning, stable description of one listener suitable for event-source registration.
///
/// The descriptor intentionally carries a `Weak` rather than a raw FD.  A consumer must upgrade
/// it immediately before registering or dispatching, so closing a socket unit cannot turn a
/// queued callback into use of a reused numeric descriptor.
#[derive(Clone)]
pub struct ListenerDescriptor {
    unit_name: String,
    port_index: usize,
    fd_name: String,
    fd: Weak<OwnedFd>,
}

impl ListenerDescriptor {
    pub fn unit_name(&self) -> &str {
        &self.unit_name
    }

    pub fn port_index(&self) -> usize {
        self.port_index
    }

    /// The name to place at this descriptor's position in `LISTEN_FDNAMES`.
    pub fn fd_name(&self) -> &str {
        &self.fd_name
    }

    pub fn weak_fd(&self) -> &Weak<OwnedFd> {
        &self.fd
    }

    /// Keeps the listener alive for a short, explicit operation such as `epoll_ctl`.
    pub fn upgrade(&self) -> Option<Arc<OwnedFd>> {
        self.fd.upgrade()
    }
}

/// A short-lived borrow used by the process-spawn boundary.
///
/// The owner remains in `ActivatedSocket`; a spawn implementation must duplicate/remap this
/// borrowed descriptor in the child before `exec`, rather than taking ownership from PID 1.
#[derive(Clone, Copy)]
pub struct ActivationFd<'a> {
    fd: BorrowedFd<'a>,
    fd_name: &'a str,
}

impl ActivationFd<'_> {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd
    }

    pub fn fd_name(&self) -> &str {
        self.fd_name
    }
}

struct ActivatedListener {
    address: SocketAddress,
    // The manager is the sole long-lived owner. Event callbacks retain a `Weak` through a
    // `ListenerDescriptor`, never an integer copied from this descriptor.
    fd: Arc<OwnedFd>,
}

pub struct ActivatedSocket {
    /// Compatibility view of the first stream address. New code must use `listeners()` so it
    /// cannot silently discard additional `ListenStream=` entries.
    pub address: SocketAddress,
    pub unit_name: String,
    pub service_name: String,
    activation_mode: SocketActivationMode,
    fd_name: String,
    listeners: Vec<ActivatedListener>,
}

impl ActivatedSocket {
    fn new(unit_name: &str, fd_name: String, listeners: Vec<ActivatedListener>) -> Self {
        debug_assert!(!listeners.is_empty());
        let address = listeners[0].address.clone();
        let service_name = unit_name
            .strip_suffix(".socket")
            .unwrap_or(unit_name)
            .to_string()
            + ".service";

        Self {
            address,
            unit_name: unit_name.to_string(),
            service_name,
            activation_mode: SocketActivationMode::AcceptNo,
            fd_name,
            listeners,
        }
    }

    pub fn activation_mode(&self) -> SocketActivationMode {
        self.activation_mode
    }

    pub fn fd_name(&self) -> &str {
        &self.fd_name
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    pub fn listeners(&self) -> impl Iterator<Item = &SocketAddress> {
        self.listeners.iter().map(|listener| &listener.address)
    }

    /// Compatibility helper for older callers which only understood one listener.
    pub fn raw_fd(&self) -> Option<RawFd> {
        self.listeners
            .first()
            .map(|listener| listener.fd.as_ref().as_raw_fd())
    }

    /// Compatibility helper for older callers which only understood one listener.
    pub fn weak_fd(&self) -> Option<Weak<OwnedFd>> {
        self.listeners
            .first()
            .map(|listener| Arc::downgrade(&listener.fd))
    }

    pub fn listener_descriptors(&self) -> Vec<ListenerDescriptor> {
        self.listeners
            .iter()
            .enumerate()
            .map(|(port_index, listener)| ListenerDescriptor {
                unit_name: self.unit_name.clone(),
                port_index,
                fd_name: self.fd_name.clone(),
                fd: Arc::downgrade(&listener.fd),
            })
            .collect()
    }

    /// Borrows every listener in its `LISTEN_FDS` order for the immediate child-spawn operation.
    pub fn activation_fds(&self) -> Vec<ActivationFd<'_>> {
        self.listeners
            .iter()
            .map(|listener| ActivationFd {
                fd: listener.fd.as_ref().as_fd(),
                fd_name: &self.fd_name,
            })
            .collect()
    }

    /// Build only the activation environment. The spawn boundary remains responsible for mapping
    /// `activation_fds()` to FDs 3.. and must install this environment *in the child before exec*.
    pub fn activation_environment(&self, child_pid: u32) -> Vec<(String, String)> {
        SocketActivationManager::build_env_for_fd_names(
            self.activation_fds()
                .iter()
                .map(|descriptor| descriptor.fd_name()),
            child_pid,
        )
    }
}

pub struct SocketActivationManager {
    sockets: HashMap<String, ActivatedSocket>,
}

impl SocketActivationManager {
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
        }
    }

    fn bind_stream(listen_stream: &str) -> Result<ActivatedListener, String> {
        let listen_path = listen_stream.trim();
        if listen_path.is_empty() {
            return Err(
                "ListenStream= may not be empty when opening an activation listener".into(),
            );
        }

        let address = SocketAddress::Stream(listen_path.to_string());
        if listen_path.starts_with('/') {
            // Do not unlink an existing path here. Safe replacement/removal of AF_UNIX endpoints
            // is a socket-unit lifecycle operation governed by RemoveOnStop=, ownership checks,
            // and filesystem labels; this low-level owner must fail closed instead.
            let listener = UnixListener::bind(listen_path)
                .map_err(|error| format!("bind {listen_path} failed: {error}"))?;
            Ok(ActivatedListener {
                address,
                fd: Arc::new(listener.into()),
            })
        } else {
            let listener = TcpListener::bind(listen_path)
                .map_err(|error| format!("bind {listen_path} failed: {error}"))?;
            Ok(ActivatedListener {
                address,
                fd: Arc::new(listener.into()),
            })
        }
    }

    /// Adds all supplied `ListenStream=` endpoints atomically for a unit.
    ///
    /// Every endpoint is opened before the unit's state changes. If one bind fails, the newly
    /// opened `OwnedFd`s drop and existing listeners remain intact. Repeated calls append ports;
    /// this preserves compatibility with the old one-at-a-time API without overwriting earlier
    /// listeners.
    pub fn register_listen_streams(
        &mut self,
        unit_name: &str,
        listen_streams: &[String],
        fd_name: Option<&str>,
    ) -> Result<(), String> {
        if unit_name.is_empty() {
            return Err("socket unit name may not be empty".into());
        }
        if listen_streams.is_empty() {
            return Err(format!(
                "{unit_name}: no ListenStream= endpoints configured"
            ));
        }

        let requested_fd_name = fd_name
            .filter(|name| !name.is_empty())
            .unwrap_or(unit_name)
            .to_string();

        if let Some(existing) = self.sockets.get(unit_name) {
            if existing.fd_name != requested_fd_name {
                return Err(format!(
                    "{unit_name}: cannot change FileDescriptorName= while listeners are active"
                ));
            }
        }

        // Bind first, then mutate. `new_listeners` owns all work until this operation commits.
        let mut new_listeners = Vec::with_capacity(listen_streams.len());
        for listen_stream in listen_streams {
            new_listeners.push(Self::bind_stream(listen_stream)?);
        }

        match self.sockets.get_mut(unit_name) {
            Some(existing) => existing.listeners.append(&mut new_listeners),
            None => {
                self.sockets.insert(
                    unit_name.to_string(),
                    ActivatedSocket::new(unit_name, requested_fd_name, new_listeners),
                );
            }
        }
        Ok(())
    }

    /// Compatibility entry point for the old one-listener caller. Prefer
    /// `register_listen_streams()` for a complete socket unit.
    pub fn register_socket(&mut self, unit_name: &str, listen_stream: &str) -> Result<(), String> {
        self.register_listen_streams(unit_name, &[listen_stream.to_string()], None)
    }

    pub fn unregister_socket(&mut self, unit_name: &str) {
        // Removing the entry drops every owned listener exactly once. Event-loop integrations
        // must remove their sources before this call; queued callbacks hold Weak descriptors and
        // therefore become no-ops if they still run.
        self.sockets.remove(unit_name);
    }

    pub fn associated_service(&self, socket_name: &str) -> String {
        socket_name
            .strip_suffix(".socket")
            .unwrap_or(socket_name)
            .to_string()
            + ".service"
    }

    /// Legacy single-name environment builder. For a real spawn, obtain the live socket and use
    /// `ActivatedSocket::activation_environment()` so explicit `FileDescriptorName=` values and
    /// multi-port ordering are retained.
    pub fn build_env_for_service(
        unit_name: &str,
        listen_fds: usize,
        child_pid: u32,
    ) -> Vec<(String, String)> {
        Self::build_env_for_fd_names(std::iter::repeat(unit_name).take(listen_fds), child_pid)
    }

    pub fn build_env_for_fd_names<'a, I>(fd_names: I, child_pid: u32) -> Vec<(String, String)>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let fd_names: Vec<&str> = fd_names.into_iter().collect();
        vec![
            ("LISTEN_FDS".to_string(), fd_names.len().to_string()),
            ("LISTEN_PID".to_string(), child_pid.to_string()),
            ("LISTEN_FDNAMES".to_string(), fd_names.join(":")),
        ]
    }

    pub fn active_socket_names(&self) -> Vec<String> {
        self.sockets.keys().cloned().collect()
    }

    /// Returns a descriptor per listener, not per socket unit.
    pub fn listener_descriptors(&self) -> Vec<ListenerDescriptor> {
        let mut names: Vec<&String> = self.sockets.keys().collect();
        names.sort_unstable();
        names
            .into_iter()
            .filter_map(|name| self.sockets.get(name))
            .flat_map(ActivatedSocket::listener_descriptors)
            .collect()
    }

    pub fn get(&self, name: &str) -> Option<&ActivatedSocket> {
        self.sockets.get(name)
    }
}

impl Default for SocketActivationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregister_socket_invalidates_borrowed_listener_handle() {
        let mut manager = SocketActivationManager::new();
        manager
            .register_socket("listener.socket", "127.0.0.1:0")
            .unwrap();
        let listener = manager
            .get("listener.socket")
            .and_then(ActivatedSocket::weak_fd)
            .unwrap();
        assert!(listener.upgrade().is_some());

        manager.unregister_socket("listener.socket");

        assert!(listener.upgrade().is_none());
    }

    #[test]
    fn multiple_streams_keep_distinct_owned_listeners_and_fd_names() {
        let mut manager = SocketActivationManager::new();
        manager
            .register_listen_streams(
                "listener.socket",
                &["127.0.0.1:0".to_string(), "127.0.0.1:0".to_string()],
                Some("api"),
            )
            .unwrap();

        let socket = manager.get("listener.socket").unwrap();
        assert_eq!(socket.activation_mode(), SocketActivationMode::AcceptNo);
        assert_eq!(socket.listener_count(), 2);
        assert_eq!(socket.fd_name(), "api");
        assert_eq!(socket.listener_descriptors().len(), 2);
        assert_eq!(
            socket.activation_environment(42),
            vec![
                ("LISTEN_FDS".to_string(), "2".to_string()),
                ("LISTEN_PID".to_string(), "42".to_string()),
                ("LISTEN_FDNAMES".to_string(), "api:api".to_string()),
            ]
        );
    }

    #[test]
    fn failed_multi_listener_registration_does_not_replace_existing_ports() {
        let mut manager = SocketActivationManager::new();
        manager
            .register_socket("listener.socket", "127.0.0.1:0")
            .unwrap();

        assert!(manager
            .register_listen_streams(
                "listener.socket",
                &[
                    "127.0.0.1:0".to_string(),
                    "not-a-socket-address".to_string()
                ],
                None,
            )
            .is_err());
        assert_eq!(manager.get("listener.socket").unwrap().listener_count(), 1);
    }
}
