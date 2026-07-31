// SPDX-License-Identifier: LGPL-2.1-or-later

//! Safe, same-thread admission stage for PID 1's private D-Bus socket.
//!
//! This module deliberately starts with an already-bound [`UnixListener`].
//! Creating and replacing `/run/systemd/private` has pathname, umask, and
//! ownership requirements which belong to a later production integration
//! stage. Here, accepting a stream, obtaining its Linux `SO_PEERCRED`, applying
//! the C manager's uid gate, and retaining bounded connection ownership form
//! one reviewable unit.
//!
//! This is not a complete D-Bus server. Admitted connections still need
//! nonblocking authentication and wire event sources, reply routing, vtables,
//! disconnect handling, and lifecycle integration before the private manager
//! API can be advertised.

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::BTreeMap;
    use std::io;
    use std::os::fd::{AsFd, BorrowedFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::rc::Rc;

    use nix::sys::socket::{getsockopt, sockopt};

    use crate::pid1_dbus_auth::{PrivateBusServerAuth, ServerAuthError};
    use crate::pid1_manager_commands::AuthenticatedPeer;

    /// Matches `CONNECTIONS_MAX` in `src/core/dbus.c`.
    pub const PRIVATE_BUS_CONNECTIONS_MAX: usize = 4096;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PrivateBusConnectionId(u64);

    #[derive(Debug)]
    pub enum PrivateBusAcceptError {
        Io(io::Error),
        PeerCredentials(nix::errno::Errno),
        InvalidPeerPid,
        Authentication(ServerAuthError),
        ConnectionLimit,
        ConnectionIdExhausted,
    }

    /// One accepted stream whose identity came only from Linux `SO_PEERCRED`.
    #[derive(Debug)]
    pub struct AdmittedPrivateBusConnection {
        stream: UnixStream,
        peer: AuthenticatedPeer,
        auth: PrivateBusServerAuth,
    }

    impl AdmittedPrivateBusConnection {
        pub const fn peer(&self) -> AuthenticatedPeer {
            self.peer
        }

        pub fn stream(&self) -> &UnixStream {
            &self.stream
        }

        pub fn auth(&self) -> &PrivateBusServerAuth {
            &self.auth
        }

        pub fn auth_mut(&mut self) -> &mut PrivateBusServerAuth {
            &mut self.auth
        }
    }

    /// Listener and admitted-connection ownership for one PID 1 event thread.
    ///
    /// The `Rc` marker intentionally makes this type `!Send` and `!Sync`.
    /// Authentication and message dispatch must remain on the thread which
    /// owns the live manager, matching `sd_bus_attach_event()` in C.
    pub struct PrivateBusListener {
        listener: UnixListener,
        manager_effective_uid: u32,
        connection_limit: usize,
        next_connection_id: u64,
        connections: BTreeMap<PrivateBusConnectionId, AdmittedPrivateBusConnection>,
        same_thread: Rc<()>,
    }

    impl PrivateBusListener {
        /// Adopt an already-bound listener without changing its filesystem
        /// pathname. The descriptor is made nonblocking before it can be
        /// exposed to an event loop.
        pub fn from_bound_listener(
            listener: UnixListener,
            manager_effective_uid: u32,
        ) -> Result<Self, PrivateBusAcceptError> {
            Self::from_bound_listener_with_limit(
                listener,
                manager_effective_uid,
                PRIVATE_BUS_CONNECTIONS_MAX,
            )
        }

        fn from_bound_listener_with_limit(
            listener: UnixListener,
            manager_effective_uid: u32,
            connection_limit: usize,
        ) -> Result<Self, PrivateBusAcceptError> {
            listener
                .set_nonblocking(true)
                .map_err(PrivateBusAcceptError::Io)?;
            Ok(Self {
                listener,
                manager_effective_uid,
                connection_limit,
                next_connection_id: 0,
                connections: BTreeMap::new(),
                same_thread: Rc::new(()),
            })
        }

        pub fn listener_fd(&self) -> BorrowedFd<'_> {
            self.listener.as_fd()
        }

        pub fn connection_count(&self) -> usize {
            self.connections.len()
        }

        pub fn connection(
            &self,
            id: PrivateBusConnectionId,
        ) -> Option<&AdmittedPrivateBusConnection> {
            self.connections.get(&id)
        }

        pub fn connection_mut(
            &mut self,
            id: PrivateBusConnectionId,
        ) -> Option<&mut AdmittedPrivateBusConnection> {
            self.connections.get_mut(&id)
        }

        pub fn remove_connection(
            &mut self,
            id: PrivateBusConnectionId,
        ) -> Option<AdmittedPrivateBusConnection> {
            self.connections.remove(&id)
        }

        /// Accept and admit at most one pending connection.
        ///
        /// `WouldBlock` remains an ordinary I/O result so an epoll callback can
        /// stop draining the listener. A connection accepted after the table
        /// reached its cap is immediately dropped, matching C's refusal after
        /// `accept4()`. The caller supplies a freshly randomized D-Bus server
        /// id for this connection, matching C's per-connection
        /// `sd_id128_randomize()`.
        pub fn accept_one(
            &mut self,
            server_id: [u8; 16],
        ) -> Result<PrivateBusConnectionId, PrivateBusAcceptError> {
            let (stream, _) = self.listener.accept().map_err(PrivateBusAcceptError::Io)?;
            stream
                .set_nonblocking(true)
                .map_err(PrivateBusAcceptError::Io)?;

            if self.connections.len() >= self.connection_limit {
                return Err(PrivateBusAcceptError::ConnectionLimit);
            }

            let credentials = getsockopt(&stream, sockopt::PeerCredentials)
                .map_err(PrivateBusAcceptError::PeerCredentials)?;
            let pid = u32::try_from(credentials.pid())
                .map_err(|_| PrivateBusAcceptError::InvalidPeerPid)?;
            let peer = AuthenticatedPeer::from_kernel_peer_credentials(
                pid,
                credentials.uid(),
                credentials.gid(),
            );
            let auth = PrivateBusServerAuth::new(peer, self.manager_effective_uid, server_id)
                .map_err(PrivateBusAcceptError::Authentication)?;

            let id = PrivateBusConnectionId(self.next_connection_id);
            self.next_connection_id = self
                .next_connection_id
                .checked_add(1)
                .ok_or(PrivateBusAcceptError::ConnectionIdExhausted)?;
            let connection = AdmittedPrivateBusConnection { stream, peer, auth };
            debug_assert!(self.connections.insert(id, connection).is_none());
            Ok(id)
        }
    }

    impl std::fmt::Debug for PrivateBusListener {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("PrivateBusListener")
                .field("listener", &self.listener)
                .field("manager_effective_uid", &self.manager_effective_uid)
                .field("connection_limit", &self.connection_limit)
                .field("next_connection_id", &self.next_connection_id)
                .field("connection_count", &self.connections.len())
                .field("same_thread_owners", &Rc::strong_count(&self.same_thread))
                .finish_non_exhaustive()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::net::UnixStream;
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        use nix::unistd::{getegid, geteuid, getpid};

        use super::*;

        fn socket_path(name: &str) -> PathBuf {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "systemd-rust-private-bus-{name}-{}-{stamp}.socket",
                std::process::id()
            ))
        }

        fn listener_with_limit(name: &str, limit: usize) -> (PathBuf, PrivateBusListener) {
            let path = socket_path(name);
            let listener = UnixListener::bind(&path).unwrap();
            let listener = PrivateBusListener::from_bound_listener_with_limit(
                listener,
                geteuid().as_raw(),
                limit,
            )
            .unwrap();
            (path, listener)
        }

        #[test]
        fn accepted_identity_comes_from_peer_credentials() {
            let (path, mut listener) = listener_with_limit("credentials", 1);
            let client = UnixStream::connect(&path).unwrap();

            let id = listener.accept_one([0x5a; 16]).unwrap();
            let connection = listener.connection(id).unwrap();
            assert_eq!(connection.peer().pid(), getpid().as_raw() as u32);
            assert_eq!(connection.peer().uid(), geteuid().as_raw());
            assert_eq!(connection.peer().gid(), getegid().as_raw());
            assert!(connection.stream().peer_addr().is_ok());
            assert_eq!(connection.auth().pending_output(), b"");

            drop(client);
            drop(listener);
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn full_table_accepts_then_refuses_without_retaining_the_stream() {
            let (path, mut listener) = listener_with_limit("limit", 1);
            let first_client = UnixStream::connect(&path).unwrap();
            let first = listener.accept_one([0x5a; 16]).unwrap();
            let second_client = UnixStream::connect(&path).unwrap();

            assert!(matches!(
                listener.accept_one([0x5b; 16]),
                Err(PrivateBusAcceptError::ConnectionLimit)
            ));
            assert_eq!(listener.connection_count(), 1);
            assert!(listener.connection(first).is_some());

            drop((first_client, second_client));
            drop(listener);
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn removal_drops_ownership_and_nonblocking_empty_accept_is_explicit() {
            let (path, mut listener) = listener_with_limit("remove", 1);
            assert!(matches!(
                listener.accept_one([0x5a; 16]),
                Err(PrivateBusAcceptError::Io(error))
                    if error.kind() == io::ErrorKind::WouldBlock
            ));

            let client = UnixStream::connect(&path).unwrap();
            let id = listener.accept_one([0x5a; 16]).unwrap();
            assert!(listener.remove_connection(id).is_some());
            assert_eq!(listener.connection_count(), 0);

            drop(client);
            drop(listener);
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;
