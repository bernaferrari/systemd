// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus.c (private-peer ancillary-data ownership).

//! Bounded Linux-only SCM_RIGHTS reception for a future private-bus reader.
//!
//! This module deliberately does not associate ancillary data with D-Bus
//! stream-frame offsets. Until that ordering contract is modeled, the live
//! stream path continues to reject the Unix-FD header.

#[cfg(target_os = "linux")]
mod imp {
    use std::io::IoSliceMut;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use nix::errno::Errno;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, UnixAddr, recvmsg};

    use crate::pid1_dbus_wire::{ReceivedUnixFds, WireError};

    pub const MAX_ANCILLARY_BYTES: usize = 64 * 1024;
    pub const MAX_ANCILLARY_FDS: usize = 16;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AncillaryReceiveError {
        InvalidLimits,
        WouldBlock,
        Truncated,
        DescriptorCountMismatch { expected: usize, received: usize },
        Io(Errno),
    }

    /// One recvmsg result. Descriptors can be taken only once, and dropping
    /// this value closes every descriptor that was not explicitly transferred.
    #[derive(Debug)]
    pub struct AncillaryReceive {
        bytes: Vec<u8>,
        descriptors: ReceivedUnixFds,
    }

    impl AncillaryReceive {
        pub fn bytes(&self) -> &[u8] {
            &self.bytes
        }

        pub const fn fd_count(&self) -> usize {
            self.descriptors.len()
        }

        pub fn take_fd(&mut self, index: u32) -> Result<OwnedFd, WireError> {
            self.descriptors.take(index)
        }
    }

    pub fn recv_bounded(
        socket: impl std::os::fd::AsFd,
        max_bytes: usize,
        expected_fds: usize,
    ) -> Result<AncillaryReceive, AncillaryReceiveError> {
        if max_bytes == 0 || max_bytes > MAX_ANCILLARY_BYTES || expected_fds > MAX_ANCILLARY_FDS {
            return Err(AncillaryReceiveError::InvalidLimits);
        }
        let mut bytes = vec![0_u8; max_bytes];
        let (received_bytes, flags, fds) = {
            let mut iov = [IoSliceMut::new(&mut bytes)];
            let mut cmsg_space = nix::cmsg_space!([RawFd; MAX_ANCILLARY_FDS]);
            let message = recvmsg::<UnixAddr>(
                socket.as_fd().as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_space),
                MsgFlags::MSG_CMSG_CLOEXEC,
            )
            .map_err(|error| match error {
                Errno::EAGAIN => AncillaryReceiveError::WouldBlock,
                error => AncillaryReceiveError::Io(error),
            })?;
            let mut fds = Vec::new();
            for cmsg in message.cmsgs().map_err(AncillaryReceiveError::Io)? {
                if let ControlMessageOwned::ScmRights(rights) = cmsg {
                    for fd in rights {
                        // SAFETY: SCM_RIGHTS created this descriptor in this
                        // process; this is its sole Rust owner.
                        fds.push(crate::unsafe_ffi!(OwnedFd::from_raw_fd(fd)));
                    }
                }
            }
            (message.bytes, message.flags, fds)
        };
        if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
            return Err(AncillaryReceiveError::Truncated);
        }
        if fds.len() != expected_fds {
            return Err(AncillaryReceiveError::DescriptorCountMismatch {
                expected: expected_fds,
                received: fds.len(),
            });
        }
        bytes.truncate(received_bytes);
        Ok(AncillaryReceive {
            bytes,
            descriptors: ReceivedUnixFds::new(fds),
        })
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs::File;
    use std::io::IoSlice;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::net::UnixDatagram;

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::sys::socket::{ControlMessage, MsgFlags, UnixAddr, sendmsg};

    use super::*;
    use crate::pid1_dbus_wire::WireError;

    fn send_rights(socket: &UnixDatagram, payload: &[u8], fds: &[OwnedFd]) {
        let iov = [IoSlice::new(payload)];
        let raw = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let cmsgs = [ControlMessage::ScmRights(&raw)];
        sendmsg::<UnixAddr>(socket.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None).unwrap();
    }

    #[test]
    fn bounded_receive_transfers_cloexec_fd_once() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let fd: OwnedFd = File::open("/dev/null").unwrap().into();
        send_rights(&sender, b"fd", &[fd]);

        let mut received = recv_bounded(receiver.as_fd(), 32, 1).unwrap();
        assert_eq!(received.bytes(), b"fd");
        assert_eq!(received.fd_count(), 1);
        let fd = received.take_fd(0).unwrap();
        assert!(
            FdFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFD).unwrap())
                .contains(FdFlag::FD_CLOEXEC)
        );
        assert!(matches!(
            received.take_fd(0),
            Err(WireError::InvalidUnixFdIndex(0))
        ));
    }

    #[test]
    fn bounded_receive_drops_count_mismatch_and_rejects_limits() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let first: OwnedFd = File::open("/dev/null").unwrap().into();
        let second: OwnedFd = File::open("/dev/null").unwrap().into();
        send_rights(&sender, b"two", &[first, second]);
        assert!(matches!(
            recv_bounded(receiver.as_fd(), 32, 1),
            Err(AncillaryReceiveError::DescriptorCountMismatch {
                expected: 1,
                received: 2
            })
        ));
        assert!(matches!(
            recv_bounded(receiver.as_fd(), MAX_ANCILLARY_BYTES + 1, 0),
            Err(AncillaryReceiveError::InvalidLimits)
        ));
    }

    #[test]
    fn bounded_receive_rejects_truncated_bytes() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        sender.send(b"too long").unwrap();
        assert!(matches!(
            recv_bounded(receiver.as_fd(), 2, 0),
            Err(AncillaryReceiveError::Truncated)
        ));
    }
}
