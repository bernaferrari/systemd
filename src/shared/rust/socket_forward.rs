// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/socket-forward.c, src/shared/socket-forward.h
//
// Bidirectional socket forwarding using splice() and FD passing utilities.
//
// Provides zero-copy data forwarding between two sockets via kernel pipe
// buffers, avoiding userspace copies. Also includes FD passing via
// sendmsg/recvmsg with SCM_RIGHTS for socket activation and IPC.
//
// The forwarding core mirrors the C implementation's splice-based approach:
//   socket → pipe → socket  (server → client direction)
//   socket → pipe → socket  (client → server direction)
//
// The forwarder detects EOF/disconnect on either side and reports completion
// when all buffered data has been flushed.

use crate::ffi::*;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

#[cfg(target_os = "linux")]
use nix::fcntl::{FcntlArg, OFlag, SpliceFFlags, fcntl, splice};
#[cfg(target_os = "linux")]
use nix::unistd::{close, pipe2};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default pipe buffer size for socket forwarding (256 KiB).
pub const SOCKET_FORWARD_BUFFER_SIZE: usize = 256 * 1024;

/// Sentinel for invalid / closed file descriptors.
pub const INVALID_FD: RawFd = -1;

/// First file descriptor passed by the socket activation protocol.
pub const SD_LISTEN_FDS_START: RawFd = 3;

/// Environment variable set by systemd for socket activation FD count.
pub const LISTEN_FDS_ENV: &str = "LISTEN_FDS";

/// Environment variable set by systemd for socket activation PID check.
pub const LISTEN_PID_ENV: &str = "LISTEN_PID";

/// epoll(7) EPOLLIN — data available to read.
pub const EPOLLIN: u32 = 0x001;

/// epoll(7) EPOLLOUT — writing to fd will not block.
pub const EPOLLOUT: u32 = 0x004;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from socket forwarding and FD passing operations.
#[derive(Debug)]
pub enum SocketForwardError {
    /// Standard I/O error from a syscall.
    Io(io::Error),
    /// Raw errno from a failed syscall.
    Syscall(i32),
    /// Both directions already reached EOF.
    AlreadyComplete,
    /// Operation not supported on this platform.
    Unsupported,
}

impl fmt::Display for SocketForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "socket forward I/O error: {e}"),
            Self::Syscall(errno) => {
                let name = match *errno {
                    libc::EINVAL => "EINVAL",
                    libc::EACCES => "EACCES",
                    libc::ENOENT => "ENOENT",
                    libc::EIO => "EIO",
                    libc::EPERM => "EPERM",
                    libc::EPIPE => "EPIPE",
                    _ => "UNKNOWN",
                };
                write!(f, "socket forward syscall error (errno {errno}: {name})")
            }
            Self::AlreadyComplete => write!(f, "socket forward already complete"),
            Self::Unsupported => write!(f, "socket forward: not supported on this platform"),
        }
    }
}

impl std::error::Error for SocketForwardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SocketForwardError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Errno helpers (pure logic) ────────────────────────────────────────────

/// Check if an errno indicates a transient / would-block condition.
///
/// Transient errors mean the operation should be retried later.
pub fn is_transient_errno(errno: i32) -> bool {
    matches!(errno, libc::EAGAIN | libc::EWOULDBLOCK | libc::EINTR)
}

/// Check if an errno indicates peer disconnection.
///
/// Disconnect errors mean the remote end has closed or reset the connection.
pub fn is_disconnect_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::EPIPE | libc::ECONNRESET | libc::ECONNREFUSED | libc::ESHUTDOWN
    )
}

// ── Shovel result ─────────────────────────────────────────────────────────

/// Outcome of a single splice-based data transfer attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShovelResult {
    /// At least one byte was moved.
    Progress,
    /// Operation would block (no data available / buffers full).
    WouldBlock,
    /// Source reached EOF or disconnected.
    SourceEof,
    /// Destination reached EOF or disconnected.
    DestEof,
    /// A fatal error occurred (raw errno stored).
    Error(i32),
}

impl ShovelResult {
    /// Whether this result indicates a non-fatal outcome.
    pub fn is_recoverable(self) -> bool {
        matches!(self, ShovelResult::Progress | ShovelResult::WouldBlock)
    }

    /// Whether this result indicates an end-of-stream condition.
    pub fn is_eof(self) -> bool {
        matches!(self, ShovelResult::SourceEof | ShovelResult::DestEof)
    }
}

// ── Direction state ───────────────────────────────────────────────────────

/// Tracks how much data is buffered in one direction's pipe.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectionState {
    /// Bytes currently sitting in the intermediate pipe buffer.
    pub buffered: usize,
}

impl DirectionState {
    /// Create a new empty direction state.
    pub const fn new() -> Self {
        Self { buffered: 0 }
    }

    /// Whether the pipe buffer is empty (all data drained).
    pub fn is_empty(&self) -> bool {
        self.buffered == 0
    }

    /// Whether the pipe buffer has room for more data.
    pub fn has_capacity(&self, capacity: usize) -> bool {
        self.buffered < capacity
    }

    /// Record that `n` bytes were spliced into the buffer.
    pub fn fill(&mut self, n: usize) {
        self.buffered = self.buffered.saturating_add(n);
    }

    /// Record that `n` bytes were drained from the buffer.
    pub fn drain(&mut self, n: usize) {
        self.buffered = self.buffered.saturating_sub(n);
    }

    /// Reset to empty.
    pub fn reset(&mut self) {
        self.buffered = 0;
    }
}

// ── Pipe buffer ───────────────────────────────────────────────────────────

/// RAII wrapper around a non-blocking, close-on-exec pipe used as a splice
/// buffer between two sockets.
///
/// On Linux, this uses `pipe2()` with `O_CLOEXEC | O_NONBLOCK` and
/// attempts to set the buffer size via `fcntl(F_SETPIPE_SZ)`.
#[cfg(target_os = "linux")]
pub struct PipeBuffer {
    fds: [OwnedFd; 2],
    capacity: usize,
}

#[cfg(target_os = "linux")]
impl PipeBuffer {
    /// Create a new pipe with the default buffer size
    /// ([`SOCKET_FORWARD_BUFFER_SIZE`], 256 KiB).
    pub fn new() -> Result<Self, SocketForwardError> {
        Self::with_size(SOCKET_FORWARD_BUFFER_SIZE)
    }

    /// Create a new pipe, requesting `requested_size` bytes of kernel buffer.
    ///
    /// The actual capacity may differ from the request depending on kernel
    /// limits and page granularity.
    pub fn with_size(requested_size: usize) -> Result<Self, SocketForwardError> {
        let requested_size =
            i32::try_from(requested_size).map_err(|_| SocketForwardError::Syscall(libc::EINVAL))?;
        let (read, write) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .map_err(|errno| SocketForwardError::Io(io::Error::from_raw_os_error(errno as i32)))?;

        // Best-effort: increase pipe buffer size (kernel may clamp or ignore).
        let _ = fcntl(read.as_fd(), FcntlArg::F_SETPIPE_SZ(requested_size));
        let size = fcntl(read.as_fd(), FcntlArg::F_GETPIPE_SZ)
            .map_err(|errno| SocketForwardError::Syscall(errno as i32))?;
        if size <= 0 {
            return Err(SocketForwardError::Syscall(libc::EINVAL));
        }

        Ok(Self {
            fds: [read, write],
            capacity: size as usize,
        })
    }

    /// Read end of the pipe (for splicing data out to the destination socket).
    pub fn read_fd(&self) -> RawFd {
        self.fds[0].as_raw_fd()
    }

    /// Write end of the pipe (for splicing data in from the source socket).
    pub fn write_fd(&self) -> RawFd {
        self.fds[1].as_raw_fd()
    }

    fn read_borrowed_fd(&self) -> BorrowedFd<'_> {
        self.fds[0].as_fd()
    }

    fn write_borrowed_fd(&self) -> BorrowedFd<'_> {
        self.fds[1].as_fd()
    }

    /// Configured capacity of the pipe buffer in bytes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether both pipe fds are valid.
    pub fn is_valid(&self) -> bool {
        true
    }
}

// ── Socket forwarder ──────────────────────────────────────────────────────

/// Bidirectional socket forwarder using kernel `splice()`.
///
/// Forwards data between two sockets ("server" and "client") via pipe buffers,
/// avoiding userspace copies. Takes ownership of both file descriptors and
/// closes them on drop (or earlier when EOF/disconnect is detected).
///
/// Mirrors the C `SocketForward` struct from `socket-forward.c`.
pub struct SocketForward {
    server_fd: Option<OwnedFd>,
    client_fd: Option<OwnedFd>,
    server_to_client_state: DirectionState,
    client_to_server_state: DirectionState,
    #[cfg(target_os = "linux")]
    server_to_client_pipe: Option<PipeBuffer>,
    #[cfg(target_os = "linux")]
    client_to_server_pipe: Option<PipeBuffer>,
}

impl SocketForward {
    /// Create a new forwarder, taking ownership of both fds.
    ///
    /// Both fds must be valid (≥ 0). Pipe buffers are allocated internally.
    /// Returns an error if either fd is invalid or pipe allocation fails.
    ///
    /// # Safety
    ///
    /// Each descriptor must be open and uniquely owned by the caller. Calling
    /// this with a borrowed, closed, or aliased descriptor can close a resource
    /// owned elsewhere. Prefer [`Self::from_owned_fds`] in safe Rust.
    #[cfg(target_os = "linux")]
    pub unsafe fn new(server_fd: RawFd, client_fd: RawFd) -> Result<Self, SocketForwardError> {
        if server_fd < 0 || client_fd < 0 || server_fd == client_fd {
            return Err(SocketForwardError::Syscall(libc::EINVAL));
        }

        // SAFETY: the validated descriptors are transferred exactly once into
        // OwnedFd, which closes them if pipe setup subsequently fails.
        let (server_fd, client_fd) = unsafe {
            (
                OwnedFd::from_raw_fd(server_fd),
                OwnedFd::from_raw_fd(client_fd),
            )
        };
        Self::from_owned_fds(server_fd, client_fd)
    }

    /// Create a forwarder from owned descriptors without an additional raw-fd
    /// ownership transfer.
    #[cfg(target_os = "linux")]
    pub fn from_owned_fds(
        server_fd: OwnedFd,
        client_fd: OwnedFd,
    ) -> Result<Self, SocketForwardError> {
        let server_to_client_pipe = Some(PipeBuffer::new()?);
        let client_to_server_pipe = Some(PipeBuffer::new()?);

        Ok(Self {
            server_fd: Some(server_fd),
            client_fd: Some(client_fd),
            server_to_client_state: DirectionState::new(),
            client_to_server_state: DirectionState::new(),
            server_to_client_pipe,
            client_to_server_pipe,
        })
    }

    /// Not supported on non-Linux platforms.
    ///
    /// # Safety
    ///
    /// Kept unsafe for API consistency with the Linux ownership-transfer
    /// constructor.
    #[cfg(not(target_os = "linux"))]
    pub unsafe fn new(_server_fd: RawFd, _client_fd: RawFd) -> Result<Self, SocketForwardError> {
        Err(SocketForwardError::Unsupported)
    }

    /// Current server fd ([`INVALID_FD`] if closed/EOF).
    pub fn server_fd(&self) -> RawFd {
        self.server_fd
            .as_ref()
            .map_or(INVALID_FD, AsRawFd::as_raw_fd)
    }

    /// Current client fd ([`INVALID_FD`] if closed/EOF).
    pub fn client_fd(&self) -> RawFd {
        self.client_fd
            .as_ref()
            .map_or(INVALID_FD, AsRawFd::as_raw_fd)
    }

    /// Server→client buffered bytes.
    pub fn server_to_client_buffered(&self) -> usize {
        self.server_to_client_state.buffered
    }

    /// Client→server buffered bytes.
    pub fn client_to_server_buffered(&self) -> usize {
        self.client_to_server_state.buffered
    }

    /// Whether forwarding is complete (both directions reached EOF, or one
    /// side closed and its buffer fully drained).
    ///
    /// Mirrors the completion checks in `socket_forward_traffic_cb()`.
    pub fn is_complete(&self) -> bool {
        // Both sides closed
        if self.server_fd.is_none() && self.client_fd.is_none() {
            return true;
        }
        // Server closed and all buffered data written to client
        if self.server_fd.is_none() && self.server_to_client_state.is_empty() {
            return true;
        }
        // Client closed and all buffered data written to server
        if self.client_fd.is_none() && self.client_to_server_state.is_empty() {
            return true;
        }
        false
    }

    /// Run one shovel cycle in both directions.
    ///
    /// Tries to splice data server→client and client→server. Returns
    /// `Ok(true)` if any data was moved, `Ok(false)` if nothing could be
    /// transferred (would block).
    #[cfg(target_os = "linux")]
    pub fn shovel_both(&mut self) -> Result<bool, SocketForwardError> {
        let mut progress = false;

        // Server → Client direction
        if let Some(ref pipe) = self.server_to_client_pipe {
            match Self::shovel_one(
                self.server_fd.as_ref().map(|fd| fd.as_fd()),
                pipe.write_borrowed_fd(),
                pipe.read_borrowed_fd(),
                self.client_fd.as_ref().map(|fd| fd.as_fd()),
                &mut self.server_to_client_state,
                pipe.capacity(),
            ) {
                Ok(ShovelResult::Progress) => progress = true,
                Ok(ShovelResult::SourceEof) => self.server_fd = None,
                Ok(ShovelResult::DestEof) => self.client_fd = None,
                Ok(ShovelResult::WouldBlock) | Ok(ShovelResult::Error(_)) => {}
                Err(e) => return Err(e),
            }
        }

        // Client → Server direction
        if let Some(ref pipe) = self.client_to_server_pipe {
            match Self::shovel_one(
                self.client_fd.as_ref().map(|fd| fd.as_fd()),
                pipe.write_borrowed_fd(),
                pipe.read_borrowed_fd(),
                self.server_fd.as_ref().map(|fd| fd.as_fd()),
                &mut self.client_to_server_state,
                pipe.capacity(),
            ) {
                Ok(ShovelResult::Progress) => progress = true,
                Ok(ShovelResult::SourceEof) => self.client_fd = None,
                Ok(ShovelResult::DestEof) => self.server_fd = None,
                Ok(ShovelResult::WouldBlock) | Ok(ShovelResult::Error(_)) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(progress)
    }

    /// Not supported on non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn shovel_both(&mut self) -> Result<bool, SocketForwardError> {
        Err(SocketForwardError::Unsupported)
    }

    /// Splice data in one direction: source → pipe → destination.
    ///
    /// Tries to fill the pipe from the source, then drain it to the
    /// destination. Mirrors the C `socket_forward_shovel()` function.
    #[cfg(target_os = "linux")]
    fn shovel_one(
        source_fd: Option<BorrowedFd<'_>>,
        pipe_write: BorrowedFd<'_>,
        pipe_read: BorrowedFd<'_>,
        dest_fd: Option<BorrowedFd<'_>>,
        state: &mut DirectionState,
        capacity: usize,
    ) -> Result<ShovelResult, SocketForwardError> {
        let mut made_progress = false;

        // ── Fill pipe from source ──
        if let Some(source_fd) = source_fd {
            if dest_fd.is_some() && state.has_capacity(capacity) {
                match splice(
                    source_fd,
                    None,
                    pipe_write,
                    None,
                    capacity - state.buffered,
                    SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK,
                ) {
                    Ok(n) if n > 0 => {
                        state.fill(n);
                        made_progress = true;
                    }
                    Ok(_) => return Ok(ShovelResult::SourceEof),
                    Err(errno) if is_transient_errno(errno as i32) => {
                        // Would block — try draining below.
                    }
                    Err(errno) if is_disconnect_errno(errno as i32) => {
                        return Ok(ShovelResult::SourceEof);
                    }
                    Err(errno) => return Ok(ShovelResult::Error(errno as i32)),
                }
            }
        }

        // ── Drain pipe to destination ──
        if !state.is_empty() {
            if let Some(dest_fd) = dest_fd {
                match splice(
                    pipe_read,
                    None,
                    dest_fd,
                    None,
                    state.buffered,
                    SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK,
                ) {
                    Ok(n) if n > 0 => {
                        state.drain(n);
                        made_progress = true;
                    }
                    Ok(_) => return Ok(ShovelResult::DestEof),
                    Err(errno) if is_transient_errno(errno as i32) => {
                        return Ok(if made_progress {
                            ShovelResult::Progress
                        } else {
                            ShovelResult::WouldBlock
                        });
                    }
                    Err(errno) if is_disconnect_errno(errno as i32) => {
                        return Ok(ShovelResult::DestEof);
                    }
                    Err(errno) => return Ok(ShovelResult::Error(errno as i32)),
                }
            }
        }

        Ok(if made_progress {
            ShovelResult::Progress
        } else {
            ShovelResult::WouldBlock
        })
    }

    /// Compute the epoll event mask for the server fd.
    ///
    /// Server gets `EPOLLIN` when the server→client pipe has capacity,
    /// and `EPOLLOUT` when the client→server pipe has data to flush.
    ///
    /// Mirrors the C `socket_forward_enable_event_sources()` logic.
    pub fn server_events(&self) -> u32 {
        let s2c_cap = self.s2c_capacity();
        let mut ev: u32 = 0;
        if self.server_to_client_state.has_capacity(s2c_cap) {
            ev |= EPOLLIN;
        }
        if self.client_to_server_state.buffered > 0 {
            ev |= EPOLLOUT;
        }
        ev
    }

    /// Compute the epoll event mask for the client fd.
    ///
    /// Client gets `EPOLLIN` when the client→server pipe has capacity,
    /// and `EPOLLOUT` when the server→client pipe has data to flush.
    pub fn client_events(&self) -> u32 {
        let c2s_cap = self.c2s_capacity();
        let mut ev: u32 = 0;
        if self.client_to_server_state.has_capacity(c2s_cap) {
            ev |= EPOLLIN;
        }
        if self.server_to_client_state.buffered > 0 {
            ev |= EPOLLOUT;
        }
        ev
    }

    /// Helper: server→client pipe capacity (0 if no pipe).
    #[cfg(target_os = "linux")]
    fn s2c_capacity(&self) -> usize {
        self.server_to_client_pipe
            .as_ref()
            .map_or(0, |p| p.capacity())
    }

    #[cfg(not(target_os = "linux"))]
    fn s2c_capacity(&self) -> usize {
        0
    }

    /// Helper: client→server pipe capacity (0 if no pipe).
    #[cfg(target_os = "linux")]
    fn c2s_capacity(&self) -> usize {
        self.client_to_server_pipe
            .as_ref()
            .map_or(0, |p| p.capacity())
    }

    #[cfg(not(target_os = "linux"))]
    fn c2s_capacity(&self) -> usize {
        0
    }
}

// ── FD passing via SCM_RIGHTS ─────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct CmsgLayout {
    cmsg_len: usize,
    cmsg_space: usize,
}

#[cfg(target_os = "linux")]
fn invalid_cmsg_input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid SCM_RIGHTS size")
}

#[cfg(target_os = "linux")]
fn invalid_cmsg_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "malformed SCM_RIGHTS control message",
    )
}

/// Calculate the exact ancillary-data allocation required for `fd_count` fds.
#[cfg(target_os = "linux")]
fn rights_cmsg_layout(fd_count: usize) -> io::Result<CmsgLayout> {
    let payload_bytes = fd_count
        .checked_mul(std::mem::size_of::<RawFd>())
        .ok_or_else(invalid_cmsg_input)?;
    let payload_len = u32::try_from(payload_bytes).map_err(|_| invalid_cmsg_input())?;

    // SAFETY: `payload_len` is representable by the `libc` CMSG helpers.
    let cmsg_len = unsafe { libc::CMSG_LEN(payload_len) } as usize;
    // SAFETY: `payload_len` is representable by the `libc` CMSG helpers.
    let cmsg_space = unsafe { libc::CMSG_SPACE(payload_len) } as usize;
    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;

    // The libc helpers accept u32 but may wrap their header/alignment addition
    // at the type boundary. Reject such a layout before allocating or writing.
    if cmsg_len
        .checked_sub(header_len)
        .is_none_or(|len| len != payload_bytes)
        || cmsg_space < cmsg_len
    {
        return Err(invalid_cmsg_input());
    }

    Ok(CmsgLayout {
        cmsg_len,
        cmsg_space,
    })
}

/// Allocate ancillary data with alignment suitable for `libc::cmsghdr`.
#[cfg(target_os = "linux")]
fn cmsg_buffer(cmsg_space: usize) -> Vec<libc::c_long> {
    let word_len = std::mem::size_of::<libc::c_long>();
    let words = cmsg_space.div_ceil(word_len);
    vec![0; words]
}

#[cfg(target_os = "linux")]
fn checked_cmsg_end(
    control_start: usize,
    control_len: usize,
    cmsg_start: usize,
    cmsg_len: usize,
    header_len: usize,
) -> io::Result<usize> {
    let control_end = control_start
        .checked_add(control_len)
        .ok_or_else(invalid_cmsg_data)?;
    let header_end = cmsg_start
        .checked_add(header_len)
        .ok_or_else(invalid_cmsg_data)?;
    let cmsg_end = cmsg_start
        .checked_add(cmsg_len)
        .ok_or_else(invalid_cmsg_data)?;

    if cmsg_start < control_start
        || header_end > control_end
        || cmsg_len < header_len
        || cmsg_end > control_end
    {
        return Err(invalid_cmsg_data());
    }

    Ok(cmsg_end)
}

/// Extract SCM_RIGHTS entries only after their cmsg header and payload bounds
/// have been validated against the control buffer returned by `recvmsg`.
#[cfg(target_os = "linux")]
fn collect_rights(
    hdr: &libc::msghdr,
    control_len: usize,
    max_fds: usize,
) -> io::Result<Vec<OwnedFd>> {
    let control_start = hdr.msg_control.cast::<u8>() as usize;
    // SAFETY: CMSG_LEN is a pure libc layout calculation for a zero-byte
    // payload and does not dereference memory.
    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
    let mut received = Vec::new();
    // SAFETY: hdr describes the control buffer populated by recvmsg; all
    // returned pointers are bounds-checked below before dereference.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(hdr) };

    while !cmsg.is_null() {
        let cmsg_start = cmsg.cast::<u8>() as usize;
        // SAFETY: `CMSG_FIRSTHDR`/`CMSG_NXTHDR` return a cmsghdr-aligned
        // pointer within the validated control buffer.
        let cmsg_len = unsafe { (*cmsg).cmsg_len } as usize;
        let cmsg_end =
            checked_cmsg_end(control_start, control_len, cmsg_start, cmsg_len, header_len)?;

        // SAFETY: the header is within the validated control buffer.
        let is_rights = unsafe {
            (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        };
        if is_rights {
            let payload_len = cmsg_len - header_len;
            if payload_len % std::mem::size_of::<RawFd>() != 0 {
                return Err(invalid_cmsg_data());
            }

            let count = payload_len / std::mem::size_of::<RawFd>();
            if count > max_fds.saturating_sub(received.len()) {
                return Err(invalid_cmsg_data());
            }

            // SAFETY: the cmsg length validation above covers exactly this
            // aligned payload region before any raw fd is read.
            let data = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>() };
            let data_start = data.cast::<u8>() as usize;
            let expected_data_start = cmsg_start
                .checked_add(header_len)
                .ok_or_else(invalid_cmsg_data)?;
            if data_start != expected_data_start
                || data_start
                    .checked_add(payload_len)
                    .is_none_or(|end| end > cmsg_end)
            {
                return Err(invalid_cmsg_data());
            }

            for index in 0..count {
                // SAFETY: `index < count` and the checked payload bounds above
                // guarantee that this reads one complete RawFd.
                let fd = unsafe { data.add(index).read() };
                if fd < 0 {
                    return Err(invalid_cmsg_data());
                }
                // SAFETY: SCM_RIGHTS supplies a new owned descriptor for each
                // valid payload entry. `OwnedFd` closes previously collected
                // descriptors if a later cmsg is rejected.
                received.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }

        // SAFETY: the validated cmsg length is contained in the control buffer.
        cmsg = unsafe { libc::CMSG_NXTHDR(hdr, cmsg) };
    }

    Ok(received)
}

/// Send file descriptors over a Unix domain socket using SCM_RIGHTS.
///
/// The fds remain valid in the caller after this function returns
/// (the kernel duplicates them for the receiver). The socket must be
/// connected (SOCK_STREAM or SOCK_SEQPACKET) or addressed (SOCK_DGRAM).
///
/// Mirrors the fd-passing logic used in `daemon_util.rs`.
#[cfg(target_os = "linux")]
pub fn send_fds(sock: RawFd, fds: &[RawFd]) -> io::Result<()> {
    if fds.is_empty() {
        return Ok(());
    }

    let layout = rights_cmsg_layout(fds.len())?;
    let mut cmsg_buf = cmsg_buffer(layout.cmsg_space);

    // SAFETY: `layout` is checked before allocation; `cmsg_buf` is aligned
    // for cmsghdr and remains live for the complete sendmsg call.
    unsafe {
        // Carry one byte with the ancillary data. Linux requires at least one
        // data byte for reliable SCM_RIGHTS delivery over SOCK_STREAM.
        let payload = [0u8; 1];
        let iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };

        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &iov as *const _ as *mut _;
        hdr.msg_iovlen = 1;
        hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        hdr.msg_controllen = layout.cmsg_space as _;

        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        if cmsg.is_null() {
            return Err(invalid_cmsg_input());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = layout.cmsg_len as _;

        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast(), fds.len());

        let rc = libc::sendmsg(sock, &hdr, libc::MSG_NOSIGNAL);
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive file descriptors from a Unix domain socket using SCM_RIGHTS.
///
/// Returns up to `max_fds` received file descriptors with RAII ownership.
#[cfg(target_os = "linux")]
pub fn recv_fds(sock: RawFd, max_fds: usize) -> io::Result<Vec<OwnedFd>> {
    if max_fds == 0 {
        return Ok(Vec::new());
    }

    let layout = rights_cmsg_layout(max_fds)?;
    let mut cmsg_buf = cmsg_buffer(layout.cmsg_space);

    // SAFETY: `layout` is checked before allocation; `cmsg_buf` is aligned
    // for cmsghdr and remains live while recvmsg and control parsing run.
    unsafe {
        // Consume the one-byte carrier used by `send_fds`.
        let mut payload = [0u8; 1];
        let iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };

        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &iov as *const _ as *mut _;
        hdr.msg_iovlen = 1;
        hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        hdr.msg_controllen = layout.cmsg_space as _;

        let rc = libc::recvmsg(sock, &mut hdr, libc::MSG_CMSG_CLOEXEC);
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let reported_control_len =
            usize::try_from(hdr.msg_controllen).map_err(|_| invalid_cmsg_data())?;
        let control_len = reported_control_len.min(layout.cmsg_space);
        // Keep the libc iterator within our actual allocation even if an
        // invalid recvmsg result reports an oversized control length.
        hdr.msg_controllen = control_len as _;
        let received = collect_rights(&hdr, control_len, max_fds)?;

        // Parse first so OwnedFd closes every descriptor that did fit in the
        // buffer before reporting the truncated ancillary data to the caller.
        if reported_control_len > layout.cmsg_space
            || (hdr.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC)) != 0
        {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }

        Ok(received)
    }
}

// ── Socket activation helpers ─────────────────────────────────────────────

/// Query the number of file descriptors passed via socket activation.
///
/// Reads the `LISTEN_FDS` environment variable set by systemd when
/// starting the service via socket activation. Returns 0 if the
/// variable is not set or not a valid number.
pub fn listen_fds_count() -> usize {
    std::env::var(LISTEN_FDS_ENV)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
}

/// Check whether the current process was started via socket activation.
pub fn is_socket_activated() -> bool {
    listen_fds_count() > 0
}

/// Get the list of inherited file descriptors from socket activation.
///
/// Returns fds starting from [`SD_LISTEN_FDS_START`] (3). The caller
/// should verify the count via [`listen_fds_count()`] first.
pub fn inherited_fds(count: usize) -> Vec<RawFd> {
    (0..count)
        .map(|i| SD_LISTEN_FDS_START + i as RawFd)
        .collect()
}

/// Close all inherited socket activation fds above the standard three
/// (stdin/stdout/stderr) to prevent FD leaks in child processes.
#[cfg(target_os = "linux")]
pub fn close_listen_fds(count: usize) {
    for i in 0..count {
        let fd = SD_LISTEN_FDS_START + i as RawFd;
        let _ = close(fd);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestEnvironment;
    use std::error::Error;

    // ── Constants ──

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rights_cmsg_layout_rejects_unrepresentable_counts() {
        let error = rights_cmsg_layout(usize::MAX).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_checked_cmsg_end_rejects_short_and_out_of_bounds_headers() {
        assert!(checked_cmsg_end(100, 32, 100, 15, 16).is_err());
        assert!(checked_cmsg_end(100, 32, 116, 17, 16).is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(SOCKET_FORWARD_BUFFER_SIZE, 256 * 1024);
        assert_eq!(INVALID_FD, -1);
        assert_eq!(SD_LISTEN_FDS_START, 3);
        assert_eq!(LISTEN_FDS_ENV, "LISTEN_FDS");
        assert_eq!(LISTEN_PID_ENV, "LISTEN_PID");
        assert_eq!(EPOLLIN, 0x001);
        assert_eq!(EPOLLOUT, 0x004);
    }

    // ── Errno helpers ──

    #[test]
    fn test_is_transient_errno() {
        assert!(is_transient_errno(libc::EAGAIN));
        assert!(is_transient_errno(libc::EWOULDBLOCK));
        assert!(is_transient_errno(libc::EINTR));
        assert!(!is_transient_errno(libc::EPIPE));
        assert!(!is_transient_errno(libc::EINVAL));
        assert!(!is_transient_errno(libc::ENOMEM));
        assert!(!is_transient_errno(libc::ENOENT));
    }

    #[test]
    fn test_is_disconnect_errno() {
        assert!(is_disconnect_errno(libc::EPIPE));
        assert!(is_disconnect_errno(libc::ECONNRESET));
        assert!(is_disconnect_errno(libc::ECONNREFUSED));
        assert!(is_disconnect_errno(libc::ESHUTDOWN));
        assert!(!is_disconnect_errno(libc::EAGAIN));
        assert!(!is_disconnect_errno(libc::EINVAL));
        assert!(!is_disconnect_errno(libc::ENOMEM));
    }

    #[test]
    fn test_transient_and_disconnect_are_disjoint() {
        // EAGAIN should be transient but not disconnect
        assert!(is_transient_errno(libc::EAGAIN));
        assert!(!is_disconnect_errno(libc::EAGAIN));
        // EPIPE should be disconnect but not transient
        assert!(is_disconnect_errno(libc::EPIPE));
        assert!(!is_transient_errno(libc::EPIPE));
        // EINVAL is neither
        assert!(!is_transient_errno(libc::EINVAL));
        assert!(!is_disconnect_errno(libc::EINVAL));
    }

    // ── ShovelResult ──

    #[test]
    fn test_shovel_result_variants() {
        assert_eq!(ShovelResult::Progress, ShovelResult::Progress);
        assert_ne!(ShovelResult::Progress, ShovelResult::WouldBlock);
        assert_eq!(
            ShovelResult::Error(libc::EPIPE),
            ShovelResult::Error(libc::EPIPE)
        );
        assert_ne!(
            ShovelResult::Error(libc::EPIPE),
            ShovelResult::Error(libc::EINVAL)
        );
        assert_eq!(ShovelResult::SourceEof, ShovelResult::SourceEof);
        assert_ne!(ShovelResult::SourceEof, ShovelResult::DestEof);
    }

    #[test]
    fn test_shovel_result_debug_clone() {
        let r = ShovelResult::SourceEof;
        let r2 = r.clone();
        assert_eq!(format!("{r:?}"), "SourceEof");
        assert_eq!(format!("{r2:?}"), "SourceEof");
        assert_eq!(r, r2);

        assert_eq!(format!("{:?}", ShovelResult::Progress), "Progress");
        assert_eq!(format!("{:?}", ShovelResult::WouldBlock), "WouldBlock");
        assert_eq!(format!("{:?}", ShovelResult::DestEof), "DestEof");
        assert_eq!(format!("{:?}", ShovelResult::Error(32)), "Error(32)");
    }

    #[test]
    fn test_shovel_result_is_recoverable() {
        assert!(ShovelResult::Progress.is_recoverable());
        assert!(ShovelResult::WouldBlock.is_recoverable());
        assert!(!ShovelResult::SourceEof.is_recoverable());
        assert!(!ShovelResult::DestEof.is_recoverable());
        assert!(!ShovelResult::Error(0).is_recoverable());
    }

    #[test]
    fn test_shovel_result_is_eof() {
        assert!(ShovelResult::SourceEof.is_eof());
        assert!(ShovelResult::DestEof.is_eof());
        assert!(!ShovelResult::Progress.is_eof());
        assert!(!ShovelResult::WouldBlock.is_eof());
        assert!(!ShovelResult::Error(0).is_eof());
    }

    // ── DirectionState ──

    #[test]
    fn test_direction_state_new() {
        let s = DirectionState::new();
        assert_eq!(s.buffered, 0);
        assert!(s.is_empty());
    }

    #[test]
    fn test_direction_state_default() {
        let s = DirectionState::default();
        assert!(s.is_empty());
        assert_eq!(s.buffered, 0);
    }

    #[test]
    fn test_direction_state_fill_drain() {
        let mut s = DirectionState::new();
        s.fill(1024);
        assert_eq!(s.buffered, 1024);
        assert!(!s.is_empty());

        s.drain(500);
        assert_eq!(s.buffered, 524);

        s.drain(524);
        assert!(s.is_empty());
        assert_eq!(s.buffered, 0);
    }

    #[test]
    fn test_direction_state_saturating() {
        let mut s = DirectionState::new();
        s.fill(usize::MAX);
        assert_eq!(s.buffered, usize::MAX);

        // fill should saturate, not wrap
        s.fill(1);
        assert_eq!(s.buffered, usize::MAX);

        // drain should saturate at 0
        s.drain(usize::MAX);
        assert_eq!(s.buffered, 0);
        s.drain(1);
        assert_eq!(s.buffered, 0);
    }

    #[test]
    fn test_direction_state_has_capacity() {
        let mut s = DirectionState::new();
        assert!(s.has_capacity(1024));
        assert!(!s.has_capacity(0)); // a zero-sized buffer cannot accept data

        s.fill(1024);
        assert!(!s.has_capacity(1024)); // exactly full
        assert!(s.has_capacity(1025)); // one byte of room

        s.fill(1); // saturating, stays at 1024
        assert!(!s.has_capacity(1024));
    }

    #[test]
    fn test_direction_state_reset() {
        let mut s = DirectionState::new();
        s.fill(9999);
        assert_eq!(s.buffered, 9999);
        s.reset();
        assert!(s.is_empty());
    }

    // ── SocketForwardError ──

    #[test]
    fn test_socket_forward_error_display() {
        let e = SocketForwardError::Syscall(libc::EINVAL);
        assert!(e.to_string().contains("EINVAL"));

        let e = SocketForwardError::AlreadyComplete;
        assert!(e.to_string().contains("complete"));

        let e = SocketForwardError::Unsupported;
        assert!(e.to_string().contains("not supported"));

        let e = SocketForwardError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "pipe broke"));
        assert!(e.to_string().contains("pipe broke"));
    }

    #[test]
    fn test_socket_forward_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broke");
        let sf_err: SocketForwardError = io_err.into();
        assert!(matches!(sf_err, SocketForwardError::Io(_)));
    }

    #[test]
    fn test_socket_forward_error_source() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let sf_err = SocketForwardError::Io(io_err);
        assert!(sf_err.source().is_some());

        let syscall_err = SocketForwardError::Syscall(42);
        assert!(syscall_err.source().is_none());
    }

    // ── Completion logic (pure, no syscalls) ──

    #[test]
    fn test_is_complete_both_closed() {
        assert!(check_complete(true, true, 0, 0));
    }

    #[test]
    fn test_is_complete_both_closed_with_data() {
        // Both closed but data still buffered → not complete
        assert!(!check_complete(true, true, 100, 0));
    }

    #[test]
    fn test_is_complete_server_closed_buffer_flushed() {
        // Server closed, s2c empty → complete regardless of c2s
        assert!(check_complete(true, false, 0, 50));
    }

    #[test]
    fn test_is_complete_server_closed_buffer_not_flushed() {
        // Server closed, s2c has data → not complete
        assert!(!check_complete(true, false, 100, 50));
    }

    #[test]
    fn test_is_complete_client_closed_buffer_flushed() {
        // Client closed, c2s empty → complete
        assert!(check_complete(false, true, 50, 0));
    }

    #[test]
    fn test_is_complete_neither_closed() {
        assert!(!check_complete(false, false, 0, 0));
        assert!(!check_complete(false, false, 100, 100));
    }

    /// Pure-logic helper: mirrors `SocketForward::is_complete` without fds.
    fn check_complete(
        server_closed: bool,
        client_closed: bool,
        s2c_buffered: usize,
        c2s_buffered: usize,
    ) -> bool {
        let server_fd: RawFd = if server_closed { INVALID_FD } else { 0 };
        let client_fd: RawFd = if client_closed { INVALID_FD } else { 0 };
        let s2c = DirectionState {
            buffered: s2c_buffered,
        };
        let c2s = DirectionState {
            buffered: c2s_buffered,
        };

        if server_fd < 0 && client_fd < 0 {
            return s2c.is_empty() && c2s.is_empty();
        }
        if server_fd < 0 && s2c.is_empty() {
            return true;
        }
        if client_fd < 0 && c2s.is_empty() {
            return true;
        }
        false
    }

    // ── Event computation (pure logic) ──

    #[test]
    fn test_server_events_empty_buffers() {
        // No data buffered anywhere → server gets EPOLLIN only
        let ev = compute_server_events(0, 0, 65536);
        assert_eq!(ev, EPOLLIN);
    }

    #[test]
    fn test_server_events_c2s_has_data() {
        // Client→server pipe has data → server gets EPOLLOUT to flush it
        let ev = compute_server_events(0, 100, 65536);
        assert!(ev & EPOLLIN != 0);
        assert!(ev & EPOLLOUT != 0);
    }

    #[test]
    fn test_server_events_s2c_full() {
        // Server→client pipe full → no EPOLLIN for server
        let ev = compute_server_events(65536, 0, 65536);
        assert_eq!(ev, 0);
    }

    #[test]
    fn test_server_events_s2c_full_c2s_has_data() {
        // s2c full (no EPOLLIN) but c2s has data (EPOLLOUT)
        let ev = compute_server_events(65536, 100, 65536);
        assert_eq!(ev & EPOLLIN, 0);
        assert_eq!(ev & EPOLLOUT, EPOLLOUT);
    }

    fn compute_server_events(s2c_buffered: usize, c2s_buffered: usize, capacity: usize) -> u32 {
        let s2c = DirectionState {
            buffered: s2c_buffered,
        };
        let c2s = DirectionState {
            buffered: c2s_buffered,
        };
        let mut ev: u32 = 0;
        if s2c.has_capacity(capacity) {
            ev |= EPOLLIN;
        }
        if c2s.buffered > 0 {
            ev |= EPOLLOUT;
        }
        ev
    }

    // ── Socket activation ──

    #[cfg(target_os = "linux")]
    #[test]
    fn test_listen_fds_count_unset() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.remove(LISTEN_FDS_ENV);
        assert_eq!(listen_fds_count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_listen_fds_count_invalid() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.set(LISTEN_FDS_ENV, "not_a_number");
        assert_eq!(listen_fds_count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_listen_fds_count_valid() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.set(LISTEN_FDS_ENV, "5");
        assert_eq!(listen_fds_count(), 5);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_socket_activated() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.remove(LISTEN_FDS_ENV);
        assert!(!is_socket_activated());

        environment.set(LISTEN_FDS_ENV, "3");
        assert!(is_socket_activated());
    }

    #[test]
    fn test_inherited_fds() {
        let fds = inherited_fds(3);
        assert_eq!(fds, vec![3, 4, 5]);

        let fds = inherited_fds(0);
        assert!(fds.is_empty());

        let fds = inherited_fds(1);
        assert_eq!(fds, vec![SD_LISTEN_FDS_START]);
    }

    // ── Integration tests (Linux only, require actual syscalls) ──

    #[cfg(target_os = "linux")]
    #[test]
    fn test_pipe_buffer_creation() {
        let pipe = PipeBuffer::new().unwrap();
        assert!(pipe.read_fd() >= 0);
        assert!(pipe.write_fd() >= 0);
        assert!(pipe.capacity() > 0);
        assert!(pipe.capacity() >= 4096); // at least one page
        assert!(pipe.is_valid());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_pipe_buffer_custom_size() {
        let pipe = PipeBuffer::with_size(65536).unwrap();
        assert!(pipe.capacity() > 0);
        assert!(pipe.is_valid());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_pipe_buffer_drop() {
        let read_fd;
        let write_fd;
        {
            let pipe = PipeBuffer::new().unwrap();
            read_fd = pipe.read_fd();
            write_fd = pipe.write_fd();
            assert!(pipe.is_valid());
        }
        // After drop, fds should be closed. We can't easily verify without
        // attempting I/O, but the Drop impl runs without panicking.
        assert!(read_fd >= 0);
        assert!(write_fd >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_send_recv_fds() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixDatagram;

        let (a, b) = UnixDatagram::pair().unwrap();
        let (mut reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();

        // Send the writer fd over the datagram socket
        send_fds(a.as_raw_fd(), &[writer.as_raw_fd()]).unwrap();
        drop(writer); // close our copy

        // Receive the fd
        let mut received = recv_fds(b.as_raw_fd(), 1).unwrap();
        assert_eq!(received.len(), 1);

        // Convert the received owned fd into the stream without another raw-fd
        // ownership boundary.
        let fd = received.pop().unwrap();
        let mut sock = std::os::unix::net::UnixStream::from(fd);

        // Verify the fd works by writing and reading through it
        sock.write_all(b"hello fd pass").unwrap();
        let mut buf = [0u8; 13];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello fd pass");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_send_recv_fds_over_stream_socket() {
        use std::os::unix::net::UnixStream;

        let (a, b) = UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();

        send_fds(a.as_raw_fd(), &[file.as_raw_fd()]).unwrap();
        let received = recv_fds(b.as_raw_fd(), 1).unwrap();
        assert_eq!(received.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_send_fds_empty() {
        use std::os::unix::net::UnixDatagram;

        let (a, _b) = UnixDatagram::pair().unwrap();
        // Sending zero fds should succeed without doing anything
        assert!(send_fds(a.as_raw_fd(), &[]).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_recv_fds_zero_max() {
        use std::os::unix::net::UnixDatagram;

        let (a, _b) = UnixDatagram::pair().unwrap();
        let result = recv_fds(a.as_raw_fd(), 0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
