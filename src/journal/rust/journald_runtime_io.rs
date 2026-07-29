// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

#[cfg(target_os = "linux")]
// Defined by Linux UAPI <linux/socket.h>, but not yet exposed by libc on all
// supported toolchains (see src/include/override/sys/socket.h).
const SCM_SECURITY: libc::c_int = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StdoutStreamState {
    Identifier,
    UnitId,
    Priority,
    LevelPrefix,
    ForwardToSyslog,
    ForwardToKmsg,
    ForwardToConsole,
    Running,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StdoutLineBreak {
    Newline,
    Nul,
    LineMax,
    Eof,
    PidChange,
}

#[derive(Debug)]
pub(super) enum StdoutStreamRead {
    Data {
        payload: Vec<u8>,
        creds: Option<PeerCredentials>,
    },
    Eof,
}

#[derive(Debug)]
pub(super) struct StdoutStreamConnection {
    pub(super) stream: UnixStream,
    pub(super) buffer: Vec<u8>,
    pub(super) state: StdoutStreamState,
    pub(super) creds: Option<PeerCredentials>,
    pub(super) selinux_label: Option<String>,
    pub(super) identifier: Option<String>,
    pub(super) unit_id: Option<String>,
    pub(super) priority: u32,
    pub(super) level_prefix: bool,
    pub(super) forward_to_syslog: bool,
    pub(super) forward_to_kmsg: bool,
    pub(super) forward_to_console: bool,
    pub(super) fdstore: bool,
    pub(super) state_file: Option<PathBuf>,
    pub(super) stream_id: String,
}

pub(super) struct PreparedDaemonSockets {
    pub(super) native_socket: UnixDatagram,
    pub(super) native_guard: Option<SocketPathGuard>,
    pub(super) syslog_socket: UnixDatagram,
    pub(super) syslog_guard: Option<SocketPathGuard>,
    pub(super) stdout_listener: UnixListener,
    pub(super) stdout_guard: Option<SocketPathGuard>,
    pub(super) restored_stdout_fds: Vec<libc::c_int>,
}

extern "C" fn shutdown_signal_handler(_sig: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

#[derive(Debug, Clone)]
pub(super) struct SignalHandlerGuard {
    old_sigterm: SigAction,
    old_sigint: SigAction,
}

impl Drop for SignalHandlerGuard {
    fn drop(&mut self) {
        // SAFETY: restores process signal handlers to previously returned values.
        let _ = unsafe { sigaction(Signal::SIGTERM, &self.old_sigterm) };
        // SAFETY: restores process signal handlers to previously returned values.
        let _ = unsafe { sigaction(Signal::SIGINT, &self.old_sigint) };
    }
}

pub(super) fn install_shutdown_signal_handlers() -> Result<SignalHandlerGuard, JournaldError> {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    let action = SigAction::new(
        SigHandler::Handler(shutdown_signal_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );
    // SAFETY: installs a signal handler function with C ABI and valid Signal values.
    let old_sigterm = unsafe { sigaction(Signal::SIGTERM, &action) }
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
    // SAFETY: installs a signal handler function with C ABI and valid Signal values.
    let old_sigint = unsafe { sigaction(Signal::SIGINT, &action) }
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
    Ok(SignalHandlerGuard {
        old_sigterm,
        old_sigint,
    })
}

pub(super) struct SocketPathGuard {
    path: PathBuf,
}

impl SocketPathGuard {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl StdoutStreamConnection {
    pub(super) fn new(stream: UnixStream) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let creds = Some(capture_stream_peer_credentials(&stream)?);
        #[cfg(not(target_os = "linux"))]
        let creds = None;
        #[cfg(target_os = "linux")]
        let selinux_label = capture_stream_peer_selinux_label(&stream).unwrap_or(None);
        #[cfg(not(target_os = "linux"))]
        let selinux_label = None;

        let _ = stream.shutdown(Shutdown::Write);
        Ok(Self {
            creds,
            selinux_label,
            stream,
            buffer: Vec::new(),
            state: StdoutStreamState::Identifier,
            identifier: None,
            unit_id: None,
            priority: 6,
            level_prefix: false,
            forward_to_syslog: false,
            forward_to_kmsg: false,
            forward_to_console: false,
            fdstore: false,
            state_file: None,
            stream_id: generate_stream_id(),
        })
    }

    pub(super) fn next_frame(
        &mut self,
        line_max: usize,
        force_flush: Option<StdoutLineBreak>,
    ) -> Option<(Vec<u8>, StdoutLineBreak)> {
        let limit = self.buffer.len().min(line_max);
        let mut newline_index = None;
        let mut nul_index = None;

        for (index, byte) in self.buffer[..limit].iter().enumerate() {
            match *byte {
                b'\n' => {
                    newline_index = Some(index);
                    break;
                }
                b'\0' => {
                    nul_index = Some(index);
                    break;
                }
                _ => {}
            }
        }

        if let Some(index) = nul_index {
            let line = self.buffer.drain(..index).collect::<Vec<_>>();
            self.buffer.drain(..1);
            return Some((line, StdoutLineBreak::Nul));
        }
        if let Some(index) = newline_index {
            let line = self.buffer.drain(..index).collect::<Vec<_>>();
            self.buffer.drain(..1);
            return Some((line, StdoutLineBreak::Newline));
        }
        if self.buffer.len() >= line_max {
            return Some((
                self.buffer.drain(..line_max).collect::<Vec<_>>(),
                StdoutLineBreak::LineMax,
            ));
        }
        if let Some(line_break) = force_flush {
            if !self.buffer.is_empty() {
                return Some((self.buffer.drain(..).collect::<Vec<_>>(), line_break));
            }
        }

        None
    }
}

pub(super) struct DevKmsgReader {
    file: File,
    buffer: [u8; 8192],
}

impl DevKmsgReader {
    pub(super) fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/kmsg")?;
        Ok(Self {
            file,
            buffer: [0; 8192],
        })
    }

    pub(super) fn read_record(&mut self) -> io::Result<Option<&[u8]>> {
        match self.file.read(&mut self.buffer) {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(&self.buffer[..n])),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) struct AuditNetlinkReceiver {
    fd: OwnedFd,
    buffer: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl AuditNetlinkReceiver {
    pub(super) fn open() -> io::Result<Self> {
        // SAFETY: socket(2) receives only constant domain/type/protocol values;
        // its returned descriptor is checked before use.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                NETLINK_AUDIT_PROTOCOL,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: all-zero is a valid sockaddr_nl initializer; nl_pad must
        // remain zero, and the public fields below fully specify this address.
        let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = AUDIT_NLGRP_READLOG;
        // SAFETY: addr is initialized for AF_NETLINK and the pointer/length
        // describe exactly that live stack value.
        let bind_result = unsafe {
            libc::bind(
                fd,
                (&mut addr as *mut libc::sockaddr_nl).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_result < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: fd is still owned by this error path.
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        let passcred: libc::c_int = 1;
        // SAFETY: fd is live and the option pointer/length describe passcred.
        let opt_result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&passcred as *const libc::c_int).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if opt_result < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: fd is still owned by this error path.
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        // SAFETY: the checked descriptor is uniquely owned and ownership is
        // transferred exactly once to OwnedFd.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd,
            buffer: vec![0_u8; 65_536],
        })
    }

    pub(super) fn recv_message(&mut self) -> io::Result<Option<(u16, Vec<u8>)>> {
        use nix::sys::socket::{ControlMessageOwned, MsgFlags, NetlinkAddr, recvmsg};

        let mut iov = [io::IoSliceMut::new(&mut self.buffer)];
        let mut cmsg_space = nix::cmsg_space!(libc::ucred);
        let (bytes, sender_pid, addr_pid) = {
            let msg = recvmsg::<NetlinkAddr>(
                self.fd.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_space),
                MsgFlags::MSG_DONTWAIT,
            )
            .map_err(|errno| io::Error::from_raw_os_error(errno as i32));
            let msg = match msg {
                Ok(msg) => msg,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };

            if msg.bytes == 0 {
                return Ok(None);
            }

            let mut sender_pid = None;
            for cmsg in msg
                .cmsgs()
                .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?
            {
                if let ControlMessageOwned::ScmCredentials(cred) = cmsg {
                    sender_pid = Some(cred.pid());
                }
            }
            let addr_pid = msg.address.as_ref().map(|addr| addr.pid());
            (msg.bytes, sender_pid, addr_pid)
        };
        drop(iov);

        if !is_valid_kernel_audit_sender(sender_pid, addr_pid) {
            return Ok(None);
        }

        let Some((msg_type, payload_range)) = parse_audit_netlink_datagram(&self.buffer, bytes)
        else {
            return Ok(None);
        };
        let payload = self.buffer[payload_range].to_vec();
        Ok(Some((msg_type, payload)))
    }
}

pub(super) fn parse_stream_boolean(text: &str) -> Option<bool> {
    match text {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

pub(super) fn boolean_digit(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

pub(super) fn parse_stream_state_file_name(name: &str) -> Option<(u64, u64)> {
    let (dev, ino) = name.split_once(':')?;
    Some((dev.parse::<u64>().ok()?, ino.parse::<u64>().ok()?))
}

pub(super) fn socket_identity_from_fd(fd: libc::c_int) -> io::Result<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage and fstat initializes it on
    // success.
    let rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful fstat above initialized the full stat value.
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

pub(super) fn safe_close_fd(fd: libc::c_int) {
    if fd >= 0 {
        // SAFETY: callers transfer ownership of non-negative descriptors to
        // this close helper and do not use them afterward.
        let _ = unsafe { libc::close(fd) };
    }
}

pub(super) fn stdout_stream_line_max(state: StdoutStreamState) -> usize {
    match state {
        StdoutStreamState::Running => DEFAULT_STDOUT_STREAM_LINE_MAX,
        _ => STDOUT_STREAM_SETUP_PROTOCOL_LINE_MAX,
    }
}

pub(super) fn parse_stdout_priority_prefix(
    message: &str,
    default_priority: u32,
    level_prefix: bool,
) -> (u32, String) {
    if !level_prefix || !message.starts_with('<') {
        return (default_priority, message.to_string());
    }

    let Some(end) = message.find('>') else {
        return (default_priority, message.to_string());
    };
    let Ok(priority) = message[1..end].parse::<u32>() else {
        return (default_priority, message.to_string());
    };
    if priority > 999 {
        return (default_priority, message.to_string());
    }

    (priority, message[end + 1..].to_string())
}

pub(super) fn generate_stream_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:032x}")
}

#[cfg(target_os = "linux")]
pub(super) fn capture_stream_peer_credentials(_stream: &UnixStream) -> io::Result<PeerCredentials> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the stream fd is live and ucred/len point to writable values of
    // the declared sizes.
    let rc = unsafe {
        libc::getsockopt(
            _stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut ucred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc == 0 {
        return Ok(PeerCredentials {
            pid: ucred.pid,
            uid: ucred.uid,
            gid: ucred.gid,
        });
    }
    Err(io::Error::last_os_error())
}

#[cfg(target_os = "linux")]
pub(super) fn set_socket_bool_option(
    fd: libc::c_int,
    option: libc::c_int,
    value: bool,
) -> io::Result<()> {
    let value: libc::c_int = if value { 1 } else { 0 };
    // SAFETY: fd is live and the option pointer/length describe value exactly.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn enable_stream_passcred(_fd: libc::c_int) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn capture_stream_peer_selinux_label(stream: &UnixStream) -> io::Result<Option<String>> {
    let mut len = 256_usize;

    loop {
        let mut buf = vec![0_u8; len];
        let mut optlen = buf.len() as libc::socklen_t;
        // SAFETY: the stream fd is live and buf/optlen describe writable
        // storage for SO_PEERSEC.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERSEC,
                buf.as_mut_ptr().cast(),
                &mut optlen,
            )
        };
        if rc == 0 {
            buf.truncate(optlen as usize);
            let label = parse_selinux_label_bytes(&buf);
            return Ok((!label.is_empty()).then_some(label));
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ERANGE) => {
                len = (optlen as usize).max(len.saturating_mul(2)).max(1);
            }
            Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP) => return Ok(None),
            _ => return Err(err),
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn enable_stream_passcred(fd: libc::c_int) -> io::Result<()> {
    set_socket_bool_option(fd, libc::SO_PASSCRED, true)
}

#[cfg(target_os = "linux")]
pub(super) fn recv_stdout_stream_message(
    stream: &UnixStream,
) -> io::Result<Option<StdoutStreamRead>> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, UnixAddr, recvmsg};

    let mut buf = [0_u8; 8192];
    let mut iov = [io::IoSliceMut::new(&mut buf)];
    let mut cmsg_space = nix::cmsg_space!(libc::ucred);
    let (bytes, creds) = {
        let msg = recvmsg::<UnixAddr>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32));
        let msg = match msg {
            Ok(msg) => msg,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        };

        if msg.bytes == 0 {
            return Ok(Some(StdoutStreamRead::Eof));
        }

        let mut creds = None;
        for cmsg in msg
            .cmsgs()
            .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?
        {
            if let ControlMessageOwned::ScmCredentials(cred) = cmsg {
                creds = Some(PeerCredentials {
                    pid: cred.pid(),
                    uid: cred.uid(),
                    gid: cred.gid(),
                });
            }
        }
        (msg.bytes, creds)
    };
    drop(iov);

    Ok(Some(StdoutStreamRead::Data {
        payload: buf[..bytes].to_vec(),
        creds,
    }))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn recv_stdout_stream_message(
    stream: &UnixStream,
) -> io::Result<Option<StdoutStreamRead>> {
    let mut buf = [0_u8; 8192];
    match (&*stream).read(&mut buf) {
        Ok(0) => Ok(Some(StdoutStreamRead::Eof)),
        Ok(bytes) => Ok(Some(StdoutStreamRead::Data {
            payload: buf[..bytes].to_vec(),
            creds: None,
        })),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn recv_datagram_with_metadata(
    socket: &UnixDatagram,
    buf: &mut [u8],
) -> Result<(usize, Option<PathBuf>, DatagramMetadata), io::Error> {
    use std::os::fd::AsRawFd;
    let mut metadata = DatagramMetadata::default();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: all-zero is a valid initial sockaddr_un output buffer for
    // recvmsg, which supplies the actual address length.
    let mut name = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    // SAFETY: CMSG_SPACE performs libc layout calculations only and does not
    // dereference memory.
    let control_len = unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32) as usize
            + libc::CMSG_SPACE(std::mem::size_of::<libc::timeval>() as u32) as usize
            + libc::CMSG_SPACE(SELINUX_CMSG_MAX as u32) as usize
    };
    let mut control = vec![0_u8; control_len];
    // SAFETY: all-zero is a valid initial msghdr before its fields are filled
    // below.
    let mut hdr = unsafe { std::mem::zeroed::<libc::msghdr>() };
    hdr.msg_name = (&mut name as *mut libc::sockaddr_un).cast();
    hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.as_mut_ptr().cast();
    hdr.msg_controllen = control.len();

    // SAFETY: hdr references live writable name, iovec, and control buffers
    // for the duration of recvmsg.
    let n = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &mut hdr,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: recvmsg populated hdr and msg_controllen; libc returns either a
    // pointer into that control buffer or null.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&hdr) };
    while !cmsg.is_null() {
        // SAFETY: cmsg was returned by the CMSG traversal macros for hdr.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET {
            match header.cmsg_type {
                libc::SCM_CREDENTIALS
                    if header.cmsg_len as usize
                        // SAFETY: CMSG_LEN is a pure layout calculation.
                        >= unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize } =>
                {
                    // SAFETY: the length guard proves a complete ucred payload
                    // is present; read handles the C buffer's alignment.
                    let cred = unsafe { libc::CMSG_DATA(cmsg).cast::<libc::ucred>().read() };
                    metadata.creds = Some(PeerCredentials {
                        pid: cred.pid,
                        uid: cred.uid,
                        gid: cred.gid,
                    });
                }
                libc::SCM_TIMESTAMP
                    if header.cmsg_len as usize
                        // SAFETY: CMSG_LEN is a pure layout calculation.
                        >= unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::timeval>() as u32) as usize } =>
                {
                    // SAFETY: the length guard proves a complete timeval
                    // payload is present; read handles the C buffer's alignment.
                    let tv = unsafe { libc::CMSG_DATA(cmsg).cast::<libc::timeval>().read() };
                    metadata.source_realtime_timestamp_usec = Some(timeval_to_usec(tv));
                }
                SCM_SECURITY => {
                    // SAFETY: CMSG_LEN is a pure layout calculation.
                    let data_offset = unsafe { libc::CMSG_LEN(0) as usize };
                    if let Some(payload_len) = (header.cmsg_len as usize).checked_sub(data_offset) {
                        // SAFETY: payload_len is bounded by the kernel-validated
                        // cmsghdr length returned in hdr's control buffer.
                        let bytes = unsafe {
                            std::slice::from_raw_parts(
                                libc::CMSG_DATA(cmsg).cast::<u8>(),
                                payload_len,
                            )
                        };
                        let label = parse_selinux_label_bytes(bytes);
                        if !label.is_empty() {
                            metadata.selinux_label = Some(label);
                        }
                    }
                }
                _ => {}
            }
        }
        // SAFETY: cmsg is the current pointer from this same hdr traversal;
        // libc returns the next in-bounds header or null.
        cmsg = unsafe { libc::CMSG_NXTHDR(&hdr, cmsg) };
    }

    Ok((
        n as usize,
        sockaddr_un_path(&name, hdr.msg_namelen),
        metadata,
    ))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn recv_datagram_with_metadata(
    socket: &UnixDatagram,
    buf: &mut [u8],
) -> Result<(usize, Option<PathBuf>, DatagramMetadata), io::Error> {
    let (n, peer) = socket.recv_from(buf)?;
    Ok((
        n,
        peer.as_pathname().map(|path| path.to_path_buf()),
        DatagramMetadata::default(),
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn timeval_to_usec(tv: libc::timeval) -> u64 {
    (tv.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add((tv.tv_usec as u64).min(999_999))
}

#[cfg(target_os = "linux")]
pub(super) fn parse_selinux_label_bytes(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\0')
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(target_os = "linux")]
pub(super) fn sockaddr_un_path(
    addr: &libc::sockaddr_un,
    namelen: libc::socklen_t,
) -> Option<PathBuf> {
    let path_offset = std::mem::size_of::<libc::sa_family_t>();
    if namelen as usize <= path_offset {
        return None;
    }

    let path_len = (namelen as usize - path_offset).min(addr.sun_path.len());
    // SAFETY: path_len is capped to sun_path's allocation and the reference
    // cannot outlive addr.
    let bytes =
        unsafe { std::slice::from_raw_parts(addr.sun_path.as_ptr().cast::<u8>(), path_len) };
    if bytes.first().copied() == Some(0) {
        return None;
    }

    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }

    Some(PathBuf::from(OsStr::from_bytes(&bytes[..end])))
}
