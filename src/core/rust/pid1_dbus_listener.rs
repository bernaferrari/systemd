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
    use std::io::{self, Read, Write};
    use std::os::fd::{AsFd, BorrowedFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::rc::Rc;

    use nix::sys::socket::{getsockopt, sockopt};

    use crate::pid1_dbus_auth::{
        AuthenticatedPrivateBusStream, PrivateBusServerAuth, ServerAuthError, ServerAuthProgress,
    };
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PrivateBusAuthIoProgress {
        NeedsRead,
        NeedsWrite,
        Authenticated,
        PeerClosed,
    }

    #[derive(Debug)]
    pub enum PrivateBusAuthIoError {
        Io(io::Error),
        Authentication(ServerAuthError),
        IncompleteHandoff,
    }

    /// One accepted stream whose identity came only from Linux `SO_PEERCRED`.
    #[derive(Debug)]
    pub struct AdmittedPrivateBusConnection {
        stream: UnixStream,
        peer: AuthenticatedPeer,
        auth: Option<PrivateBusServerAuth>,
        authenticated: Option<AuthenticatedPrivateBusStream>,
    }

    impl AdmittedPrivateBusConnection {
        const AUTH_READ_CHUNK: usize = 8 * 1024;

        pub const fn peer(&self) -> AuthenticatedPeer {
            self.peer
        }

        pub fn stream(&self) -> &UnixStream {
            &self.stream
        }

        pub fn auth(&self) -> Option<&PrivateBusServerAuth> {
            self.auth.as_ref()
        }

        pub fn authenticated(&self) -> Option<&AuthenticatedPrivateBusStream> {
            self.authenticated.as_ref()
        }

        /// Perform at most one successful socket read or write for the D-Bus
        /// authentication phase.
        ///
        /// This is deliberately an event-loop adapter, not a blocking helper:
        /// `WouldBlock` is converted to the current read/write interest,
        /// partial writes are retained by [`PrivateBusServerAuth`], and each
        /// read is capped by both a small stack buffer and the 64 KiB
        /// authentication limit. On successful `BEGIN`, kernel-derived sender
        /// identity and pipelined binary bytes are moved together into
        /// [`AuthenticatedPrivateBusStream`].
        pub fn drive_authentication(
            &mut self,
        ) -> Result<PrivateBusAuthIoProgress, PrivateBusAuthIoError> {
            let Some(auth) = self.auth.as_mut() else {
                return if self.authenticated.is_some() {
                    Ok(PrivateBusAuthIoProgress::Authenticated)
                } else {
                    Err(PrivateBusAuthIoError::IncompleteHandoff)
                };
            };

            if !auth.pending_output().is_empty() {
                let mut stream = &self.stream;
                match stream.write(auth.pending_output()) {
                    Ok(0) => return Ok(PrivateBusAuthIoProgress::PeerClosed),
                    Ok(written) => {
                        auth.consume_output(written)
                            .map_err(PrivateBusAuthIoError::Authentication)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(PrivateBusAuthIoProgress::NeedsWrite);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        return Ok(PrivateBusAuthIoProgress::NeedsWrite);
                    }
                    Err(error) => return Err(PrivateBusAuthIoError::Io(error)),
                }
            } else {
                let capacity = auth.remaining_input_capacity();
                if capacity == 0 {
                    return Err(PrivateBusAuthIoError::Authentication(
                        ServerAuthError::InputTooLarge,
                    ));
                }

                let mut bytes = [0_u8; Self::AUTH_READ_CHUNK];
                let mut stream = &self.stream;
                match stream.read(&mut bytes[..capacity.min(Self::AUTH_READ_CHUNK)]) {
                    Ok(0) => return Ok(PrivateBusAuthIoProgress::PeerClosed),
                    Ok(read) => {
                        auth.receive(&bytes[..read])
                            .map_err(PrivateBusAuthIoError::Authentication)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(PrivateBusAuthIoProgress::NeedsRead);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        return Ok(PrivateBusAuthIoProgress::NeedsRead);
                    }
                    Err(error) => return Err(PrivateBusAuthIoError::Io(error)),
                }
            }

            self.finish_authentication()
        }

        fn finish_authentication(
            &mut self,
        ) -> Result<PrivateBusAuthIoProgress, PrivateBusAuthIoError> {
            let Some(auth) = self.auth.as_ref() else {
                return Ok(PrivateBusAuthIoProgress::Authenticated);
            };
            if auth.progress() != ServerAuthProgress::Authenticated {
                return Ok(if auth.pending_output().is_empty() {
                    PrivateBusAuthIoProgress::NeedsRead
                } else {
                    PrivateBusAuthIoProgress::NeedsWrite
                });
            }
            if !auth.pending_output().is_empty() {
                return Ok(PrivateBusAuthIoProgress::NeedsWrite);
            }

            let auth = self
                .auth
                .take()
                .ok_or(PrivateBusAuthIoError::IncompleteHandoff)?;
            match auth.into_authenticated() {
                Ok(authenticated) => {
                    self.authenticated = Some(authenticated);
                    Ok(PrivateBusAuthIoProgress::Authenticated)
                }
                Err(auth) => {
                    self.auth = Some(auth);
                    Err(PrivateBusAuthIoError::IncompleteHandoff)
                }
            }
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
            let connection = AdmittedPrivateBusConnection {
                stream,
                peer,
                auth: Some(auth),
                authenticated: None,
            };
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
        use std::io::{Read, Write};
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
            assert_eq!(connection.auth().unwrap().pending_output(), b"");
            assert!(connection.authenticated().is_none());

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

        #[test]
        fn nonblocking_auth_driver_preserves_identity_and_pipelined_wire_bytes() {
            let (path, mut listener) = listener_with_limit("auth-driver", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            let id = listener.accept_one([0x5a; 16]).unwrap();

            assert_eq!(
                listener
                    .connection_mut(id)
                    .unwrap()
                    .drive_authentication()
                    .unwrap(),
                PrivateBusAuthIoProgress::NeedsRead
            );

            client.write_all(b"\0AUTH EXTERNAL\r\n").unwrap();
            assert_eq!(
                listener
                    .connection_mut(id)
                    .unwrap()
                    .drive_authentication()
                    .unwrap(),
                PrivateBusAuthIoProgress::NeedsWrite
            );
            assert_eq!(
                listener
                    .connection_mut(id)
                    .unwrap()
                    .drive_authentication()
                    .unwrap(),
                PrivateBusAuthIoProgress::NeedsRead
            );
            let mut challenge = [0_u8; 6];
            client.read_exact(&mut challenge).unwrap();
            assert_eq!(&challenge, b"DATA\r\n");

            let token = geteuid()
                .as_raw()
                .to_string()
                .into_bytes()
                .into_iter()
                .flat_map(|byte| {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0xf)]]
                })
                .collect::<Vec<_>>();
            let mut reply = b"DATA ".to_vec();
            reply.extend_from_slice(&token);
            reply.extend_from_slice(b"\r\nBEGIN\r\nbinary");
            client.write_all(&reply).unwrap();

            assert_eq!(
                listener
                    .connection_mut(id)
                    .unwrap()
                    .drive_authentication()
                    .unwrap(),
                PrivateBusAuthIoProgress::NeedsWrite
            );
            assert_eq!(
                listener
                    .connection_mut(id)
                    .unwrap()
                    .drive_authentication()
                    .unwrap(),
                PrivateBusAuthIoProgress::Authenticated
            );

            let mut ok = [0_u8; 37];
            client.read_exact(&mut ok).unwrap();
            assert_eq!(&ok[..3], b"OK ");
            assert_eq!(&ok[35..], b"\r\n");

            let connection = listener.connection(id).unwrap();
            assert!(connection.auth().is_none());
            let authenticated = connection.authenticated().unwrap();
            assert_eq!(authenticated.sender().peer(), connection.peer());
            assert_eq!(authenticated.buffered(), b"binary");

            drop(client);
            drop(listener);
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn auth_driver_reports_peer_close_without_losing_connection_ownership() {
            let (path, mut listener) = listener_with_limit("auth-eof", 1);
            let client = UnixStream::connect(&path).unwrap();
            let id = listener.accept_one([0x5a; 16]).unwrap();
            drop(client);

            assert_eq!(
                listener
                    .connection_mut(id)
                    .unwrap()
                    .drive_authentication()
                    .unwrap(),
                PrivateBusAuthIoProgress::PeerClosed
            );
            assert!(listener.connection(id).is_some());

            drop(listener);
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;
