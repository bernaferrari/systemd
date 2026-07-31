// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/manager.c, src/shared/notify-recv.c

//! Bounded, credential-authenticated ingress for `sd_notify()` datagrams.
//!
//! This deliberately stops before service state mutation. C's full notify
//! handler routes an authenticated `PidRef` to all matching units, checks each
//! unit's `NotifyAccess=`, processes FDSTORE and barrier descriptors, and then
//! invokes the service state machine. Until those pieces share one manager
//! owner, this source may only hand an authenticated, bounded datagram to that
//! owner. In particular, it must not make `Type=notify` startable by itself.

#[cfg(target_os = "linux")]
mod imp {
    use std::cell::RefCell;
    use std::io::{self, IoSliceMut};
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::net::UnixDatagram;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use nix::errno::Errno;
    use nix::sys::epoll::EpollFlags;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, UnixAddr, recvmsg, setsockopt, sockopt};
    use systemd_event_loop_rs::loop_::EventLoop;

    /// C uses `NOTIFY_BUFFER_MAX` for one datagram, keeping notification
    /// parsing bounded independently of any unit's input.
    pub const NOTIFY_BUFFER_MAX: usize = 4096;

    // Keep this source outside the fixed main-loop IDs and dynamic socket/exec
    // source ranges. EventLoop also rejects collisions defensively.
    const NOTIFY_SOURCE_ID: u64 = (1 << 33) + 2;

    /// Credentials supplied by the kernel in `SCM_CREDENTIALS`.
    ///
    /// These must never be derived from a notification field such as
    /// `MAINPID=`. The source does not resolve a `PidRef` or unit yet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NotifyPeerCredentials {
        pub pid: u32,
        pub uid: u32,
        pub gid: u32,
    }

    /// One accepted `sd_notify()` payload. Its text is valid UTF-8 and has no
    /// embedded NUL bytes; one trailing NUL is removed to match C's accepted
    /// input convention.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AuthenticatedNotifyDatagram {
        pub peer: NotifyPeerCredentials,
        pub text: String,
    }

    /// Errors that make a notification inadmissible. Callers should drop one
    /// such datagram and continue serving later datagrams, as C treats malformed
    /// messages as recoverable rather than disabling the socket.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum NotifyReceiveError {
        WouldBlock,
        Truncated,
        MissingCredentials,
        InvalidCredentials,
        UnexpectedFileDescriptors,
        EmptyPayload,
        EmbeddedNul,
        InvalidUtf8,
        Io(Errno),
    }

    /// A manager-owned notification socket plus an epoll duplicate and a
    /// one-bit readiness inbox. It intentionally never unlinks `path` on drop:
    /// pathname cleanup must be performed by a future manager lifecycle that
    /// can prove it still owns the filesystem entry.
    #[derive(Debug)]
    pub struct NotifySourceOwner {
        socket: UnixDatagram,
        path: PathBuf,
        ready: Rc<RefCell<bool>>,
        registered: Option<OwnedFd>,
    }

    impl NotifySourceOwner {
        /// Bind a fresh pathname notification socket with kernel credentials
        /// enabled. Existing filesystem entries are refused, never removed.
        pub fn bind(path: &Path) -> io::Result<Self> {
            if !path.is_absolute() || path.as_os_str().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "notify socket path must be absolute",
                ));
            }
            if path.try_exists()? {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace an existing notify socket path",
                ));
            }

            let socket = UnixDatagram::bind(path)?;
            socket.set_nonblocking(true)?;
            setsockopt(&socket, sockopt::PassCred, &true)
                .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
            Ok(Self {
                socket,
                path: path.to_path_buf(),
                ready: Rc::new(RefCell::new(false)),
                registered: None,
            })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Register a duplicate descriptor. The callback never reads a
        /// datagram or changes service state: the manager turn owns both.
        pub fn register(&mut self, event_loop: &mut EventLoop) -> Result<(), Errno> {
            if self.registered.is_some() {
                return Ok(());
            }
            let fd = self
                .socket
                .as_fd()
                .try_clone_to_owned()
                .map_err(|error| Errno::from_raw(error.raw_os_error().unwrap_or(libc::EIO)))?;
            let callback_ready = Rc::clone(&self.ready);
            event_loop.add_source(
                &fd,
                EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
                NOTIFY_SOURCE_ID,
                Box::new(move |events, _data| {
                    let events = EpollFlags::from_bits_truncate(events as i32);
                    if events.intersects(
                        EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
                    ) {
                        *callback_ready.try_borrow_mut().map_err(|_| Errno::EBUSY)? = true;
                    }
                    Ok(())
                }),
            )?;
            self.registered = Some(fd);
            Ok(())
        }

        /// Consume the coalesced readiness bit. A true return means callers
        /// should call [`Self::recv_one`] until it returns `WouldBlock`.
        pub fn take_ready(&self) -> Result<bool, Errno> {
            let mut ready = self.ready.try_borrow_mut().map_err(|_| Errno::EBUSY)?;
            let value = *ready;
            *ready = false;
            Ok(value)
        }

        /// Receive one bounded datagram and retain only kernel-provided
        /// credentials. SCM_RIGHTS is intentionally rejected and closed: FD
        /// storage requires a separate, fully modeled ownership contract.
        pub fn recv_one(&self) -> Result<AuthenticatedNotifyDatagram, NotifyReceiveError> {
            let mut payload = [0_u8; NOTIFY_BUFFER_MAX];
            let (bytes, flags, credentials, received_fds) = {
                let mut iov = [IoSliceMut::new(&mut payload)];
                let mut cmsg_space = nix::cmsg_space!(libc::ucred, [libc::c_int; 16]);
                let message = recvmsg::<UnixAddr>(
                    self.socket.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg_space),
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
                )
                .map_err(|error| match error {
                    Errno::EAGAIN => NotifyReceiveError::WouldBlock,
                    error => NotifyReceiveError::Io(error),
                })?;

                let mut credentials = None;
                let mut received_fds = Vec::new();
                for cmsg in message.cmsgs().map_err(NotifyReceiveError::Io)? {
                    match cmsg {
                        ControlMessageOwned::ScmCredentials(cred) => {
                            if credentials.is_some() {
                                return Err(NotifyReceiveError::InvalidCredentials);
                            }
                            credentials = Some(NotifyPeerCredentials {
                                pid: u32::try_from(cred.pid())
                                    .map_err(|_| NotifyReceiveError::InvalidCredentials)?,
                                uid: cred.uid(),
                                gid: cred.gid(),
                            });
                        }
                        ControlMessageOwned::ScmRights(fds) => received_fds.extend(fds),
                        _ => {}
                    }
                }
                (message.bytes, message.flags, credentials, received_fds)
            };

            // `recvmsg` hands SCM_RIGHTS descriptors to this process. Close
            // every one before returning an error so malformed input cannot
            // exhaust PID 1's descriptor table.
            if !received_fds.is_empty() {
                for fd in received_fds {
                    let _ = nix::unistd::close(fd);
                }
                return Err(NotifyReceiveError::UnexpectedFileDescriptors);
            }
            if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
                return Err(NotifyReceiveError::Truncated);
            }
            let peer = credentials.ok_or(NotifyReceiveError::MissingCredentials)?;
            if peer.pid == 0 {
                return Err(NotifyReceiveError::InvalidCredentials);
            }
            if bytes == 0 {
                return Err(NotifyReceiveError::EmptyPayload);
            }
            let bytes = &payload[..bytes];
            if bytes.len() > 1 && bytes[..bytes.len() - 1].contains(&0) {
                return Err(NotifyReceiveError::EmbeddedNul);
            }
            let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
            let text = std::str::from_utf8(bytes)
                .map_err(|_| NotifyReceiveError::InvalidUtf8)?
                .to_owned();
            Ok(AuthenticatedNotifyDatagram { peer, text })
        }

        /// Detach the epoll duplicate while retaining the manager-owned
        /// socket for a later event-loop invocation.
        pub fn unregister(&mut self, event_loop: &mut EventLoop) -> Result<(), Errno> {
            *self.ready.try_borrow_mut().map_err(|_| Errno::EBUSY)? = false;
            let Some(fd) = self.registered.as_ref() else {
                return Ok(());
            };
            event_loop.remove_source(fd, NOTIFY_SOURCE_ID)?;
            self.registered = None;
            Ok(())
        }

        pub fn registered(&self) -> bool {
            self.registered.is_some()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use nix::unistd::{getgid, getpid, getuid};

        fn socket_path(name: &str) -> PathBuf {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "systemd-rust-notify-{name}-{}-{stamp}.socket",
                std::process::id()
            ))
        }

        #[test]
        fn authenticated_datagram_is_epoll_woken_and_carries_kernel_credentials() {
            let path = socket_path("credentials");
            let mut owner = NotifySourceOwner::bind(&path).unwrap();
            let mut event_loop = EventLoop::new().unwrap();
            owner.register(&mut event_loop).unwrap();
            let sender = UnixDatagram::unbound().unwrap();
            sender.connect(&path).unwrap();
            assert_eq!(sender.send(b"READY=1\nSTATUS=ready").unwrap(), 20);

            assert!(event_loop.run_once(100).unwrap());
            assert!(owner.take_ready().unwrap());
            assert!(!owner.take_ready().unwrap());
            assert_eq!(
                owner.recv_one().unwrap(),
                AuthenticatedNotifyDatagram {
                    peer: NotifyPeerCredentials {
                        pid: getpid().as_raw() as u32,
                        uid: getuid().as_raw(),
                        gid: getgid().as_raw(),
                    },
                    text: "READY=1\nSTATUS=ready".into(),
                }
            );
            assert_eq!(owner.recv_one(), Err(NotifyReceiveError::WouldBlock));

            owner.unregister(&mut event_loop).unwrap();
            assert!(!owner.registered());
            drop((sender, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn malformed_payload_is_rejected_without_disabling_later_datagrams() {
            let path = socket_path("malformed");
            let owner = NotifySourceOwner::bind(&path).unwrap();
            let sender = UnixDatagram::unbound().unwrap();
            sender.connect(&path).unwrap();
            sender.send(b"READY=1\0STATUS=forged").unwrap();
            assert_eq!(owner.recv_one(), Err(NotifyReceiveError::EmbeddedNul));
            sender.send(b"READY=1\0").unwrap();
            assert_eq!(owner.recv_one().unwrap().text, "READY=1");

            drop((sender, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn binding_refuses_to_replace_existing_path() {
            let path = socket_path("exists");
            std::fs::write(&path, b"not a socket").unwrap();
            assert_eq!(
                NotifySourceOwner::bind(&path)
                    .expect_err("an existing pathname must be refused")
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;
