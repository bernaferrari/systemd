// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-daemon/sd-daemon.c

use std::collections::BTreeMap;
use std::env;
use std::ffi::CString;
use std::mem::{offset_of, size_of, zeroed};
use std::os::fd::RawFd;
use std::path::Path;
#[cfg(target_os = "linux")]
use systemd_basic_rs::socket_util::{SocketAddress, SocketType, socket_address_parse_vsock};

pub type Result<T> = std::result::Result<T, DaemonCheckError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonCheckError {
    BadFd,
    InvalidInput(&'static str),
    Parse(&'static str),
    Io(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassedFd {
    pub fd: RawFd,
    pub name: String,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct MqAttr {
    mq_flags: libc::c_long,
    mq_maxmsg: libc::c_long,
    mq_msgsize: libc::c_long,
    mq_curmsgs: libc::c_long,
}

#[cfg(target_os = "linux")]
type MqdT = libc::c_int;

#[cfg(target_os = "linux")]
// SAFETY: these declarations mirror Linux librt's mqueue ABI and use the local
// repr(C) mq_attr layout; all call sites validate names, descriptors, and slots.
unsafe extern "C" {
    fn mq_getattr(mqdes: MqdT, attr: *mut MqAttr) -> libc::c_int;
    fn mq_open(
        name: *const libc::c_char,
        oflag: libc::c_int,
        mode: libc::c_uint,
        attr: *const MqAttr,
    ) -> MqdT;
    fn mq_close(mqdes: MqdT) -> libc::c_int;
    fn mq_unlink(name: *const libc::c_char) -> libc::c_int;
}

pub const SD_LISTEN_FDS_START: RawFd = 3;
const LISTEN_ENV_VARS: [&str; 4] = [
    "LISTEN_PID",
    "LISTEN_PIDFDID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
];
const WATCHDOG_ENV_VARS: [&str; 2] = ["WATCHDOG_USEC", "WATCHDOG_PID"];
const NOTIFY_ENV_VAR: &str = "NOTIFY_SOCKET";

fn collect_listen_env() -> BTreeMap<String, String> {
    LISTEN_ENV_VARS
        .iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_string(), value)))
        .collect()
}

/// Remove socket-activation variables from the process environment.
///
/// # Safety
///
/// The caller must ensure that no other thread reads or mutates the process
/// environment until this function returns.
unsafe fn unsetenv_listen() {
    for key in LISTEN_ENV_VARS {
        // SAFETY: upheld by the caller as required by this function's contract.
        unsafe { env::remove_var(key) };
    }
}

fn collect_watchdog_env() -> BTreeMap<String, String> {
    WATCHDOG_ENV_VARS
        .iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_string(), value)))
        .collect()
}

/// Remove watchdog variables from the process environment.
///
/// # Safety
///
/// The caller must ensure that no other thread reads or mutates the process
/// environment until this function returns.
unsafe fn unsetenv_watchdog() {
    for key in WATCHDOG_ENV_VARS {
        // SAFETY: upheld by the caller as required by this function's contract.
        unsafe { env::remove_var(key) };
    }
}

/// Remove the notify socket from the process environment.
///
/// # Safety
///
/// The caller must ensure that no other thread reads or mutates the process
/// environment until this function returns.
unsafe fn unsetenv_notify() {
    // SAFETY: upheld by the caller as required by this function's contract.
    unsafe { env::remove_var(NOTIFY_ENV_VAR) };
}

pub fn listen_fds_from_env(
    env: &BTreeMap<String, String>,
    current_pid: libc::pid_t,
    own_pidfdid: Option<u64>,
) -> Result<Vec<RawFd>> {
    let listen_pid = match env.get("LISTEN_PID") {
        Some(value) => value
            .parse::<libc::pid_t>()
            .map_err(|_| DaemonCheckError::Parse("LISTEN_PID"))?,
        None => return Ok(Vec::new()),
    };

    if listen_pid != current_pid {
        return Ok(Vec::new());
    }

    if let Some(expected) = env.get("LISTEN_PIDFDID") {
        let expected = expected
            .parse::<u64>()
            .map_err(|_| DaemonCheckError::Parse("LISTEN_PIDFDID"))?;

        if let Some(actual) = own_pidfdid
            && expected != actual
        {
            return Ok(Vec::new());
        }
    }

    let n_fds = match env.get("LISTEN_FDS") {
        Some(value) => value
            .parse::<i32>()
            .map_err(|_| DaemonCheckError::Parse("LISTEN_FDS"))?,
        None => return Ok(Vec::new()),
    };

    if n_fds <= 0 {
        return Err(DaemonCheckError::InvalidInput("LISTEN_FDS"));
    }
    if n_fds > i32::MAX - SD_LISTEN_FDS_START {
        return Err(DaemonCheckError::InvalidInput("LISTEN_FDS"));
    }

    Ok((SD_LISTEN_FDS_START..SD_LISTEN_FDS_START + n_fds).collect())
}

/// Parse descriptors passed through the socket-activation environment.
///
/// # Safety
///
/// When `unset_environment` is true, the caller must ensure that no other
/// thread reads or mutates the process environment until this function returns.
pub unsafe fn sd_listen_fds(unset_environment: bool) -> Result<i32> {
    let result = (|| {
        let env = collect_listen_env();
        // SAFETY: `libc::getpid` has no preconditions and does not dereference pointers.
        let fds = listen_fds_from_env(&env, unsafe { libc::getpid() }, None)?;

        for fd in &fds {
            set_fd_cloexec(*fd)?;
        }

        i32::try_from(fds.len()).map_err(|_| DaemonCheckError::InvalidInput("LISTEN_FDS"))
    })();

    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe { unsetenv_listen() };
    }

    result
}

/// Parse descriptors without changing the process environment.
pub fn sd_listen_fds_preserve_environment() -> Result<i32> {
    // SAFETY: false disables the only process-environment mutation.
    unsafe { sd_listen_fds(false) }
}

pub fn listen_fds_with_names_from_env(
    env: &BTreeMap<String, String>,
    current_pid: libc::pid_t,
    own_pidfdid: Option<u64>,
) -> Result<Vec<PassedFd>> {
    let fds = listen_fds_from_env(env, current_pid, own_pidfdid)?;
    let names = env
        .get("LISTEN_FDNAMES")
        .map(|value| value.split(':').map(ToOwned::to_owned).collect::<Vec<_>>())
        .unwrap_or_else(|| vec!["unknown".to_string(); fds.len()]);

    if names.len() != fds.len() {
        return Err(DaemonCheckError::InvalidInput("LISTEN_FDNAMES"));
    }

    Ok(fds
        .into_iter()
        .zip(names)
        .map(|(fd, name)| PassedFd { fd, name })
        .collect())
}

/// Parse named descriptors passed through the socket-activation environment.
///
/// # Safety
///
/// When `unset_environment` is true, the caller must ensure that no other
/// thread reads or mutates the process environment until this function returns.
pub unsafe fn sd_listen_fds_with_names(unset_environment: bool) -> Result<Vec<PassedFd>> {
    let result = (|| {
        let env = collect_listen_env();
        // SAFETY: `libc::getpid` has no preconditions and does not dereference pointers.
        let passed = listen_fds_with_names_from_env(&env, unsafe { libc::getpid() }, None)?;

        for passed_fd in &passed {
            set_fd_cloexec(passed_fd.fd)?;
        }

        Ok(passed)
    })();

    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe { unsetenv_listen() };
    }

    result
}

/// Parse named descriptors without changing the process environment.
pub fn sd_listen_fds_with_names_preserve_environment() -> Result<Vec<PassedFd>> {
    // SAFETY: false disables the only process-environment mutation.
    unsafe { sd_listen_fds_with_names(false) }
}

pub fn watchdog_enabled_from_env(
    env: &BTreeMap<String, String>,
    current_pid: libc::pid_t,
) -> Result<Option<u64>> {
    let usec = match env.get("WATCHDOG_USEC") {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| DaemonCheckError::Parse("WATCHDOG_USEC"))?,
        None => return Ok(None),
    };

    if usec == 0 {
        return Err(DaemonCheckError::InvalidInput("WATCHDOG_USEC"));
    }

    if let Some(pid) = env.get("WATCHDOG_PID") {
        let pid = pid
            .parse::<libc::pid_t>()
            .map_err(|_| DaemonCheckError::Parse("WATCHDOG_PID"))?;
        if pid != current_pid {
            return Ok(None);
        }
    }

    Ok(Some(usec))
}

/// Read the watchdog interval from the process environment.
///
/// # Safety
///
/// When `unset_environment` is true, the caller must ensure that no other
/// thread reads or mutates the process environment until this function returns.
pub unsafe fn sd_watchdog_enabled(unset_environment: bool) -> Result<Option<u64>> {
    // SAFETY: `libc::getpid` has no preconditions and does not dereference pointers.
    let result = watchdog_enabled_from_env(&collect_watchdog_env(), unsafe { libc::getpid() });

    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe { unsetenv_watchdog() };
    }

    result
}

/// Read the watchdog interval without changing the process environment.
pub fn sd_watchdog_enabled_preserve_environment() -> Result<Option<u64>> {
    // SAFETY: false disables the only process-environment mutation.
    unsafe { sd_watchdog_enabled(false) }
}

/// Send an sd_notify message to the service manager.
///
/// # Safety
///
/// When `unset_environment` is true, the caller must ensure that no other
/// thread reads or mutates the process environment until this function returns.
pub unsafe fn sd_notify(unset_environment: bool, state: &str) -> Result<bool> {
    let result = (|| {
        let notify_socket = match env::var(NOTIFY_ENV_VAR) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Ok(false),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET"));
            }
        };

        send_notify_message(&notify_socket, state.as_bytes())?;
        Ok(true)
    })();

    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe { unsetenv_notify() };
    }

    result
}

/// Send an sd_notify message without changing the process environment.
pub fn sd_notify_preserve_environment(state: &str) -> Result<bool> {
    // SAFETY: false disables the only process-environment mutation.
    unsafe { sd_notify(false, state) }
}

/// Format and send an sd_notify message to the service manager.
///
/// # Safety
///
/// When `unset_environment` is true, the caller must ensure that no other
/// thread reads or mutates the process environment until this function returns.
pub unsafe fn sd_notifyf(unset_environment: bool, args: std::fmt::Arguments<'_>) -> Result<bool> {
    let message = args.to_string();
    // SAFETY: this function has the same environment-mutation contract.
    unsafe { sd_notify(unset_environment, &message) }
}

pub fn booted_at(path: &Path) -> Result<bool> {
    match path.try_exists() {
        Ok(value) => Ok(value),
        Err(err) => Err(DaemonCheckError::Io(
            err.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

pub fn is_fifo(fd: RawFd, path: Option<&Path>) -> Result<bool> {
    let fd_stat = fstat(fd)?;
    if (fd_stat.st_mode & libc::S_IFMT) != libc::S_IFIFO {
        return Ok(false);
    }

    match path {
        Some(path) => match stat_path(path) {
            Ok(path_stat) => Ok(same_inode(&fd_stat, &path_stat)),
            Err(DaemonCheckError::Io(libc::ENOENT | libc::ENOTDIR)) => Ok(false),
            Err(err) => Err(err),
        },
        None => Ok(true),
    }
}

pub fn is_special(fd: RawFd, path: Option<&Path>) -> Result<bool> {
    let fd_stat = fstat(fd)?;
    let kind = fd_stat.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG && kind != libc::S_IFCHR {
        return Ok(false);
    }

    let Some(path) = path else {
        return Ok(true);
    };

    match stat_path(path) {
        Ok(path_stat) => {
            let path_kind = path_stat.st_mode & libc::S_IFMT;
            Ok(match (kind, path_kind) {
                (libc::S_IFREG, libc::S_IFREG) => same_inode(&fd_stat, &path_stat),
                (libc::S_IFCHR, libc::S_IFCHR) => fd_stat.st_rdev == path_stat.st_rdev,
                _ => false,
            })
        }
        Err(DaemonCheckError::Io(libc::ENOENT | libc::ENOTDIR)) => Ok(false),
        Err(err) => Err(err),
    }
}

pub fn sd_is_socket(
    fd: RawFd,
    family: Option<i32>,
    sock_type: Option<i32>,
    listening: Option<bool>,
) -> Result<bool> {
    if fd < 0 {
        return Err(DaemonCheckError::BadFd);
    }
    if let Some(family) = family
        && family < 0
    {
        return Err(DaemonCheckError::InvalidInput("family"));
    }

    if !is_socket_internal(fd, sock_type, listening)? {
        return Ok(false);
    }

    if let Some(expected_family) = family {
        if expected_family == 0 {
            return Ok(true);
        }
        let (storage, _len) = getsockname(fd)?;
        return Ok(sockaddr_family(&storage) == expected_family);
    }

    Ok(true)
}

pub fn is_socket(
    fd: RawFd,
    family: Option<i32>,
    sock_type: Option<i32>,
    listening: Option<bool>,
) -> Result<bool> {
    sd_is_socket(fd, family, sock_type, listening)
}

pub fn sd_is_socket_inet(
    fd: RawFd,
    family: Option<i32>,
    sock_type: Option<i32>,
    listening: Option<bool>,
    port: Option<u16>,
) -> Result<bool> {
    if fd < 0 {
        return Err(DaemonCheckError::BadFd);
    }
    if let Some(family) = family
        && !matches!(family, 0 | libc::AF_INET | libc::AF_INET6)
    {
        return Err(DaemonCheckError::InvalidInput("family"));
    }
    if !is_socket_internal(fd, sock_type, listening)? {
        return Ok(false);
    }

    let (storage, _) = getsockname(fd)?;
    let actual_family = sockaddr_family(&storage);
    if actual_family != libc::AF_INET && actual_family != libc::AF_INET6 {
        return Ok(false);
    }
    if let Some(family) = family
        && family != 0
        && family != actual_family
    {
        return Ok(false);
    }

    if let Some(port) = port.filter(|port| *port > 0) {
        return Ok(socket_port(&storage)? == port);
    }

    Ok(true)
}

pub fn is_socket_inet(
    fd: RawFd,
    family: Option<i32>,
    sock_type: Option<i32>,
    listening: Option<bool>,
    port: Option<u16>,
) -> Result<bool> {
    sd_is_socket_inet(fd, family, sock_type, listening, port)
}

pub fn sd_is_socket_sockaddr(
    fd: RawFd,
    sock_type: Option<i32>,
    addr: Option<&libc::sockaddr>,
    addr_len: usize,
    listening: Option<bool>,
) -> Result<bool> {
    if fd < 0 {
        return Err(DaemonCheckError::BadFd);
    }
    if addr.is_none() {
        return Err(DaemonCheckError::InvalidInput("addr"));
    }
    if addr_len < size_of::<libc::sa_family_t>() {
        return Err(DaemonCheckError::InvalidInput("addr_len"));
    }

    let addr = addr.unwrap();
    match addr.sa_family as i32 {
        libc::AF_INET | libc::AF_INET6 => {}
        _ => return Err(DaemonCheckError::InvalidInput("family")),
    }

    if !is_socket_internal(fd, sock_type, listening)? {
        return Ok(false);
    }

    let (storage, actual_len) = getsockname(fd)?;
    if actual_len < size_of::<libc::sa_family_t>() as libc::socklen_t {
        return Err(DaemonCheckError::InvalidInput("sockaddr"));
    }

    if sockaddr_family(&storage) != addr.sa_family as i32 {
        return Ok(false);
    }

    match addr.sa_family as i32 {
        libc::AF_INET => {
            if addr_len < size_of::<libc::sockaddr_in>()
                || actual_len < size_of::<libc::sockaddr_in>() as libc::socklen_t
            {
                return Err(DaemonCheckError::InvalidInput("addr_len"));
            }
            // SAFETY: arguments satisfy the libc `sockaddr_in` contract and any passed pointers remain valid for the call.
            let expected = unsafe { &*(addr as *const _ as *const libc::sockaddr_in) };
            // SAFETY: arguments satisfy the libc `sockaddr_in` contract and any passed pointers remain valid for the call.
            let actual = unsafe { &*(&storage as *const _ as *const libc::sockaddr_in) };
            if expected.sin_port != 0 && actual.sin_port != expected.sin_port {
                return Ok(false);
            }
            Ok(actual.sin_addr.s_addr == expected.sin_addr.s_addr)
        }
        libc::AF_INET6 => {
            if addr_len < size_of::<libc::sockaddr_in6>()
                || actual_len < size_of::<libc::sockaddr_in6>() as libc::socklen_t
            {
                return Err(DaemonCheckError::InvalidInput("addr_len"));
            }
            // SAFETY: arguments satisfy the libc `sockaddr_in6` contract and any passed pointers remain valid for the call.
            let expected = unsafe { &*(addr as *const _ as *const libc::sockaddr_in6) };
            // SAFETY: arguments satisfy the libc `sockaddr_in6` contract and any passed pointers remain valid for the call.
            let actual = unsafe { &*(&storage as *const _ as *const libc::sockaddr_in6) };

            if expected.sin6_port != 0 && actual.sin6_port != expected.sin6_port {
                return Ok(false);
            }
            if expected.sin6_flowinfo != 0 && actual.sin6_flowinfo != expected.sin6_flowinfo {
                return Ok(false);
            }
            if expected.sin6_scope_id != 0 && actual.sin6_scope_id != expected.sin6_scope_id {
                return Ok(false);
            }

            Ok(actual.sin6_addr.s6_addr == expected.sin6_addr.s6_addr)
        }
        _ => unreachable!(),
    }
}

pub fn is_socket_sockaddr(
    fd: RawFd,
    sock_type: Option<i32>,
    addr: Option<&libc::sockaddr>,
    addr_len: usize,
    listening: Option<bool>,
) -> Result<bool> {
    sd_is_socket_sockaddr(fd, sock_type, addr, addr_len, listening)
}

pub fn sd_is_socket_unix(
    fd: RawFd,
    sock_type: Option<i32>,
    listening: Option<bool>,
    path: Option<&[u8]>,
) -> Result<bool> {
    if !is_socket_internal(fd, sock_type, listening)? {
        return Ok(false);
    }
    let (storage, len) = getsockname(fd)?;
    if sockaddr_family(&storage) != libc::AF_UNIX {
        return Ok(false);
    }

    let Some(path) = path else {
        return Ok(true);
    };

    // SAFETY: `storage` was populated by `getsockname`, family was validated as `AF_UNIX`, and we only read fields.
    let addr = unsafe { &*(&storage as *const _ as *const libc::sockaddr_un) };
    let actual_len =
        usize::try_from(len).map_err(|_| DaemonCheckError::InvalidInput("sockaddr"))?;
    let path_offset = offset_of!(libc::sockaddr_un, sun_path);
    if actual_len < path_offset {
        return Err(DaemonCheckError::InvalidInput("sockaddr"));
    }
    let actual_path_len = actual_len - path_offset;
    let actual_path =
        // SAFETY: the pointer and length originate from validated storage and produce a temporary slice within bounds.
        unsafe { std::slice::from_raw_parts(addr.sun_path.as_ptr().cast::<u8>(), actual_path_len) };

    Ok(unix_socket_path_matches(actual_path, path))
}

pub fn is_socket_unix(
    fd: RawFd,
    sock_type: Option<i32>,
    listening: Option<bool>,
    path: Option<&[u8]>,
) -> Result<bool> {
    sd_is_socket_unix(fd, sock_type, listening, path)
}

#[cfg(target_os = "linux")]
pub fn sd_is_mq(fd: RawFd, path: Option<&Path>) -> Result<bool> {
    let fd = validate_fd(fd)?;
    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
    let mut attr = unsafe { zeroed::<MqAttr>() };
    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
    let r = unsafe { mq_getattr(fd as MqdT, &mut attr) };
    if r < 0 {
        let errno = last_errno();
        if errno == libc::EBADF {
            return Ok(false);
        }
        return Err(DaemonCheckError::Io(errno));
    }

    if let Some(path) = path {
        if !path.is_absolute() {
            return Err(DaemonCheckError::InvalidInput("path"));
        }

        let dev_mqueue = Path::new("/dev/mqueue").join(path.strip_prefix(Path::new("/")).unwrap());

        let fd_stat = fstat(fd)?;
        let path_stat = stat_path(&dev_mqueue)?;
        if !same_inode(&fd_stat, &path_stat) {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(not(target_os = "linux"))]
pub fn sd_is_mq(_fd: RawFd, _path: Option<&Path>) -> Result<bool> {
    Err(DaemonCheckError::InvalidInput("platform"))
}

pub fn is_mq(fd: RawFd, path: Option<&Path>) -> Result<bool> {
    sd_is_mq(fd, path)
}

fn is_socket_internal(fd: RawFd, sock_type: Option<i32>, listening: Option<bool>) -> Result<bool> {
    let fd_stat = fstat(fd)?;
    if (fd_stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
        return Ok(false);
    }

    if let Some(sock_type) = sock_type {
        if sock_type < 0 {
            return Err(DaemonCheckError::InvalidInput("type"));
        }
        if sock_type != 0 {
            let actual = getsockopt_int(fd, libc::SO_TYPE)?;
            if actual != sock_type {
                return Ok(false);
            }
        }
    }

    if let Some(listening) = listening {
        let accepting = getsockopt_int(fd, libc::SO_ACCEPTCONN)? != 0;
        if accepting != listening {
            return Ok(false);
        }
    }

    Ok(true)
}

fn same_inode(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

fn fstat(fd: RawFd) -> Result<libc::stat> {
    if fd < 0 {
        return Err(DaemonCheckError::BadFd);
    }
    // SAFETY: `libc::stat` is a POD C struct and may be zero-initialized before `fstat` fills it.
    let mut st = unsafe { zeroed::<libc::stat>() };
    // SAFETY: arguments satisfy the libc `fstat` contract and any passed pointers remain valid for the call.
    let r = unsafe { libc::fstat(fd, &mut st) };
    if r < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }
    Ok(st)
}

fn stat_path(path: &Path) -> Result<libc::stat> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| DaemonCheckError::InvalidInput("path"))?;
    // SAFETY: `libc::stat` is a POD C struct and may be zero-initialized before `stat` fills it.
    let mut st = unsafe { zeroed::<libc::stat>() };
    // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
    let r = unsafe { libc::stat(path.as_ptr(), &mut st) };
    if r < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }
    Ok(st)
}

fn validate_fd(fd: RawFd) -> Result<RawFd> {
    if fd < 0 {
        return Err(DaemonCheckError::BadFd);
    }

    // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
    let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if r < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }

    Ok(fd)
}

fn set_fd_cloexec(fd: RawFd) -> Result<()> {
    if fd < 0 {
        return Err(DaemonCheckError::BadFd);
    }

    // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }

    // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }

    Ok(())
}

fn send_notify_message(notify_socket: &str, payload: &[u8]) -> Result<()> {
    if let Ok((mut addr, addr_len)) = parse_notify_socket_unix(notify_socket) {
        let fd = create_socket_cloexec(libc::AF_UNIX, libc::SOCK_DGRAM)?;
        // SAFETY: arguments satisfy the libc `sendto` contract and any passed pointers remain valid for the call.
        let sent = unsafe {
            libc::sendto(
                fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                libc::MSG_NOSIGNAL,
                &mut addr as *mut _ as *const libc::sockaddr,
                addr_len,
            )
        };
        let send_result = if sent < 0 {
            Err(DaemonCheckError::Io(last_errno()))
        } else if sent as usize != payload.len() {
            Err(DaemonCheckError::Io(libc::EIO))
        } else {
            Ok(())
        };
        // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
        unsafe { libc::close(fd) };
        return send_result;
    }

    #[cfg(target_os = "linux")]
    {
        if let Some((mut addr, addr_len, sock_type)) = parse_notify_socket_vsock(notify_socket)? {
            let fd = create_socket_cloexec(libc::AF_VSOCK, sock_type)?;
            // SAFETY: arguments satisfy the libc `sendto` contract and any passed pointers remain valid for the call.
            let sent = unsafe {
                libc::sendto(
                    fd,
                    payload.as_ptr() as *const libc::c_void,
                    payload.len(),
                    libc::MSG_NOSIGNAL,
                    &mut addr as *mut _ as *const libc::sockaddr,
                    addr_len,
                )
            };
            let send_result = if sent < 0 {
                Err(DaemonCheckError::Io(last_errno()))
            } else if sent as usize != payload.len() {
                Err(DaemonCheckError::Io(libc::EIO))
            } else {
                Ok(())
            };
            // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
            unsafe { libc::close(fd) };
            return send_result;
        }
    }

    Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET"))
}

fn create_socket_cloexec(family: libc::c_int, sock_type: libc::c_int) -> Result<RawFd> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: arguments satisfy the libc `socket` contract and any passed pointers remain valid for the call.
        let fd = unsafe { libc::socket(family, sock_type | libc::SOCK_CLOEXEC, 0) };
        if fd >= 0 {
            return Ok(fd);
        }
    }

    // SAFETY: arguments satisfy the libc `socket` contract and any passed pointers remain valid for the call.
    let fd = unsafe { libc::socket(family, sock_type, 0) };
    if fd < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }
    if let Err(e) = set_fd_cloexec(fd) {
        // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

fn parse_notify_socket_unix(address: &str) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    if !(address.starts_with('/') || address.starts_with('@')) {
        return Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET"));
    }

    // SAFETY: `libc::sockaddr_un` is POD and may be zero-initialized before filling `sun_family/sun_path`.
    let mut sockaddr = unsafe { zeroed::<libc::sockaddr_un>() };
    sockaddr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_offset = offset_of!(libc::sockaddr_un, sun_path);
    let max_len = sockaddr.sun_path.len();

    if let Some(abstract_name) = address.strip_prefix('@') {
        let name_bytes = abstract_name.as_bytes();
        if name_bytes.len() + 1 > max_len {
            return Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET"));
        }
        sockaddr.sun_path[0] = 0;
        for (i, b) in name_bytes.iter().enumerate() {
            sockaddr.sun_path[i + 1] = *b as libc::c_char;
        }

        let len = path_offset + 1 + name_bytes.len();
        return Ok((
            sockaddr,
            libc::socklen_t::try_from(len)
                .map_err(|_| DaemonCheckError::InvalidInput("NOTIFY_SOCKET"))?,
        ));
    }

    let path_bytes = address.as_bytes();
    if path_bytes.len() + 1 > max_len {
        return Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET"));
    }
    for (i, b) in path_bytes.iter().enumerate() {
        sockaddr.sun_path[i] = *b as libc::c_char;
    }
    sockaddr.sun_path[path_bytes.len()] = 0;

    let len = path_offset + path_bytes.len() + 1;
    Ok((
        sockaddr,
        libc::socklen_t::try_from(len)
            .map_err(|_| DaemonCheckError::InvalidInput("NOTIFY_SOCKET"))?,
    ))
}

#[cfg(target_os = "linux")]
fn parse_notify_socket_vsock(
    address: &str,
) -> Result<Option<(libc::sockaddr_vm, libc::socklen_t, libc::c_int)>> {
    let parsed = match socket_address_parse_vsock(address) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(None),
    };

    let SocketAddress::Vsock {
        cid,
        port,
        sock_type,
    } = parsed
    else {
        return Ok(None);
    };

    let sock_type = match sock_type {
        Some(SocketType::Datagram) | None => libc::SOCK_DGRAM,
        Some(SocketType::Stream) => libc::SOCK_STREAM,
        Some(SocketType::SeqPacket) => libc::SOCK_SEQPACKET,
        Some(SocketType::Raw) => return Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET")),
    };

    let sockaddr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    };

    Ok(Some((
        sockaddr,
        libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>())
            .map_err(|_| DaemonCheckError::InvalidInput("NOTIFY_SOCKET"))?,
        sock_type,
    )))
}

fn getsockopt_int(fd: RawFd, opt: i32) -> Result<i32> {
    let mut value = 0i32;
    let mut len = size_of::<i32>() as libc::socklen_t;
    // SAFETY: arguments satisfy the libc `getsockopt` contract and any passed pointers remain valid for the call.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }
    if len != size_of::<i32>() as libc::socklen_t {
        return Err(DaemonCheckError::InvalidInput("getsockopt length"));
    }
    Ok(value)
}

fn getsockname(fd: RawFd) -> Result<(libc::sockaddr_storage, libc::socklen_t)> {
    // SAFETY: `libc::sockaddr_storage` is POD and may be zero-initialized before `getsockname` writes it.
    let mut storage = unsafe { zeroed::<libc::sockaddr_storage>() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let r =
        // SAFETY: arguments satisfy the libc `getsockname` contract and any passed pointers remain valid for the call.
        unsafe { libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) };
    if r < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }
    if len < size_of::<libc::sa_family_t>() as libc::socklen_t {
        return Err(DaemonCheckError::InvalidInput("sockaddr"));
    }
    Ok((storage, len))
}

fn sockaddr_family(storage: &libc::sockaddr_storage) -> i32 {
    // SAFETY: `storage` came from `getsockname`; reading its `sa_family` via `sockaddr` view is valid.
    unsafe { (*(storage as *const _ as *const libc::sockaddr)).sa_family as i32 }
}

fn unix_socket_path_matches(actual_path: &[u8], expected_path: &[u8]) -> bool {
    if expected_path.is_empty() {
        return actual_path.is_empty();
    }

    if expected_path[0] == 0 {
        return actual_path == expected_path;
    }

    actual_path.len() > expected_path.len()
        && actual_path.starts_with(expected_path)
        && actual_path[expected_path.len()] == 0
}

fn socket_port(storage: &libc::sockaddr_storage) -> Result<u16> {
    match sockaddr_family(storage) {
        libc::AF_INET => {
            // SAFETY: `storage` came from `getsockname`, family is `AF_INET`, and we only read fields.
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Ok(u16::from_be(addr.sin_port))
        }
        libc::AF_INET6 => {
            // SAFETY: `storage` came from `getsockname`, family is `AF_INET6`, and we only read fields.
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Ok(u16::from_be(addr.sin6_port))
        }
        _ => Err(DaemonCheckError::InvalidInput("family")),
    }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestEnvironment;
    use std::fs::{self, File};
    use std::net::{SocketAddr, TcpListener, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixDatagram;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("systemd-rs-{name}-{nanos}"))
    }

    fn save_fd_if_open(fd: RawFd) -> Option<RawFd> {
        // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 128) };
        if duplicated >= 0 {
            return Some(duplicated);
        }

        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if errno == libc::EBADF {
            None
        } else {
            panic!("failed to duplicate fd {fd}: errno={errno}");
        }
    }

    fn replace_fd_with(source: RawFd, target: RawFd) -> Option<RawFd> {
        let saved = save_fd_if_open(target);
        // SAFETY: arguments satisfy the libc `dup2` contract and any passed pointers remain valid for the call.
        let r = unsafe { libc::dup2(source, target) };
        assert!(r >= 0, "dup2({source}, {target}) failed");
        saved
    }

    fn restore_fd(target: RawFd, saved: Option<RawFd>) {
        match saved {
            Some(saved_fd) => {
                // SAFETY: arguments satisfy the libc `dup2` contract and any passed pointers remain valid for the call.
                let r = unsafe { libc::dup2(saved_fd, target) };
                assert!(r >= 0, "failed to restore fd {target}");
                // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
                unsafe { libc::close(saved_fd) };
            }
            None => {
                // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
                unsafe { libc::close(target) };
            }
        }
    }

    fn fd_cloexec_set(fd: RawFd) -> bool {
        // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed for fd {fd}");
        (flags & libc::FD_CLOEXEC) != 0
    }

    fn close_if_not_kept(fd: RawFd, keep_a: RawFd, keep_b: RawFd) {
        if fd != keep_a && fd != keep_b {
            // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn listen_fds_accepts_matching_pid() {
        let env = BTreeMap::from([
            ("LISTEN_PID".into(), "100".into()),
            ("LISTEN_FDS".into(), "2".into()),
        ]);
        assert_eq!(listen_fds_from_env(&env, 100, None).unwrap(), vec![3, 4]);
    }

    #[test]
    fn listen_fds_rejects_mismatched_pid() {
        let env = BTreeMap::from([
            ("LISTEN_PID".into(), "100".into()),
            ("LISTEN_FDS".into(), "2".into()),
        ]);
        assert!(listen_fds_from_env(&env, 101, None).unwrap().is_empty());
    }

    #[test]
    fn listen_fds_with_names_defaults_to_unknown() {
        let env = BTreeMap::from([
            ("LISTEN_PID".into(), "5".into()),
            ("LISTEN_FDS".into(), "2".into()),
        ]);
        let named = listen_fds_with_names_from_env(&env, 5, None).unwrap();
        assert_eq!(named[0].name, "unknown");
        assert_eq!(named[1].fd, 4);
    }

    #[test]
    fn sd_listen_fds_sets_cloexec_and_unsets_environment() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe { TestEnvironment::lock() };
        for key in LISTEN_ENV_VARS {
            environment.remove(key);
        }

        let mut pipe_a = [0; 2];
        let mut pipe_b = [0; 2];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(unsafe { libc::pipe(pipe_a.as_mut_ptr()) }, 0);
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(unsafe { libc::pipe(pipe_b.as_mut_ptr()) }, 0);

        let saved3 = replace_fd_with(pipe_a[0], SD_LISTEN_FDS_START);
        let saved4 = replace_fd_with(pipe_b[0], SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_a[0], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_a[1], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_b[0], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_b[1], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);

        // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
        unsafe {
            libc::fcntl(SD_LISTEN_FDS_START, libc::F_SETFD, 0);
            libc::fcntl(SD_LISTEN_FDS_START + 1, libc::F_SETFD, 0);
        }

        // SAFETY: arguments satisfy the libc `getpid` contract and any passed pointers remain valid for the call.
        environment.set("LISTEN_PID", unsafe { libc::getpid() }.to_string());
        environment.set("LISTEN_FDS", "2");
        environment.set("LISTEN_FDNAMES", "alpha:beta");

        // SAFETY: TestEnvironment upholds the environment mutation contract.
        let n = unsafe { sd_listen_fds(true) }.unwrap();
        assert_eq!(n, 2);
        assert!(fd_cloexec_set(SD_LISTEN_FDS_START));
        assert!(fd_cloexec_set(SD_LISTEN_FDS_START + 1));
        assert!(env::var("LISTEN_PID").is_err());
        assert!(env::var("LISTEN_FDS").is_err());
        assert!(env::var("LISTEN_FDNAMES").is_err());

        restore_fd(SD_LISTEN_FDS_START, saved3);
        restore_fd(SD_LISTEN_FDS_START + 1, saved4);
    }

    #[test]
    fn sd_listen_fds_with_names_reads_env_and_sets_cloexec() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe { TestEnvironment::lock() };
        for key in LISTEN_ENV_VARS {
            environment.remove(key);
        }

        let mut pipe_a = [0; 2];
        let mut pipe_b = [0; 2];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(unsafe { libc::pipe(pipe_a.as_mut_ptr()) }, 0);
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(unsafe { libc::pipe(pipe_b.as_mut_ptr()) }, 0);

        let saved3 = replace_fd_with(pipe_a[0], SD_LISTEN_FDS_START);
        let saved4 = replace_fd_with(pipe_b[0], SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_a[0], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_a[1], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_b[0], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_b[1], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
        unsafe {
            libc::fcntl(SD_LISTEN_FDS_START, libc::F_SETFD, 0);
            libc::fcntl(SD_LISTEN_FDS_START + 1, libc::F_SETFD, 0);
        }

        // SAFETY: arguments satisfy the libc `getpid` contract and any passed pointers remain valid for the call.
        environment.set("LISTEN_PID", unsafe { libc::getpid() }.to_string());
        environment.set("LISTEN_FDS", "2");
        environment.set("LISTEN_FDNAMES", "first:second");

        let named = sd_listen_fds_with_names_preserve_environment().unwrap();
        assert_eq!(named.len(), 2);
        assert_eq!(named[0].fd, SD_LISTEN_FDS_START);
        assert_eq!(named[1].fd, SD_LISTEN_FDS_START + 1);
        assert_eq!(named[0].name, "first");
        assert_eq!(named[1].name, "second");
        assert!(fd_cloexec_set(SD_LISTEN_FDS_START));
        assert!(fd_cloexec_set(SD_LISTEN_FDS_START + 1));
        assert!(env::var("LISTEN_PID").is_ok());
        assert!(env::var("LISTEN_FDS").is_ok());

        for key in LISTEN_ENV_VARS {
            environment.remove(key);
        }
        restore_fd(SD_LISTEN_FDS_START, saved3);
        restore_fd(SD_LISTEN_FDS_START + 1, saved4);
    }

    #[test]
    fn watchdog_parsing_respects_pid() {
        let env = BTreeMap::from([
            ("WATCHDOG_USEC".into(), "5000000".into()),
            ("WATCHDOG_PID".into(), "77".into()),
        ]);
        assert_eq!(
            watchdog_enabled_from_env(&env, 77).unwrap(),
            Some(5_000_000)
        );
        assert_eq!(watchdog_enabled_from_env(&env, 78).unwrap(), None);
    }

    #[test]
    fn sd_watchdog_enabled_reads_and_unsets_environment() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe { TestEnvironment::lock() };
        for key in WATCHDOG_ENV_VARS {
            environment.remove(key);
        }

        environment.set("WATCHDOG_USEC", "777000");
        // SAFETY: arguments satisfy the libc `getpid` contract and any passed pointers remain valid for the call.
        environment.set("WATCHDOG_PID", unsafe { libc::getpid() }.to_string());

        // SAFETY: TestEnvironment upholds the environment mutation contract.
        let enabled = unsafe { sd_watchdog_enabled(true) }.unwrap();
        assert_eq!(enabled, Some(777000));
        assert!(env::var("WATCHDOG_USEC").is_err());
        assert!(env::var("WATCHDOG_PID").is_err());
    }

    #[test]
    fn sd_watchdog_enabled_missing_var_returns_none() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe { TestEnvironment::lock() };
        for key in WATCHDOG_ENV_VARS {
            environment.remove(key);
        }
        assert_eq!(sd_watchdog_enabled_preserve_environment().unwrap(), None);
    }

    #[test]
    fn sd_notify_missing_socket_returns_zero_like_false() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe { TestEnvironment::lock() };
        environment.remove(NOTIFY_ENV_VAR);
        assert!(!sd_notify_preserve_environment("READY=1").unwrap());
    }

    #[test]
    fn sd_notify_sends_to_unix_datagram_socket() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe { TestEnvironment::lock() };
        environment.remove(NOTIFY_ENV_VAR);

        let socket_path = unique_path("notify.sock");
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        environment.set(
            "NOTIFY_SOCKET",
            socket_path.as_os_str().to_string_lossy().to_string(),
        );

        // SAFETY: TestEnvironment upholds the environment mutation contract.
        let sent = unsafe { sd_notify(true, "READY=1\nSTATUS=ok") }.unwrap();
        assert!(sent);

        let mut buf = [0u8; 128];
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=ok");
        assert!(env::var("NOTIFY_SOCKET").is_err());

        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn sd_notifyf_formats_and_sends_message() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe { TestEnvironment::lock() };
        environment.remove(NOTIFY_ENV_VAR);

        let socket_path = unique_path("notifyf.sock");
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        environment.set(
            "NOTIFY_SOCKET",
            socket_path.as_os_str().to_string_lossy().to_string(),
        );

        // SAFETY: TestEnvironment upholds the environment mutation contract.
        let sent = unsafe { sd_notifyf(true, format_args!("MAINPID={}", 1234)) }.unwrap();
        assert!(sent);

        let mut buf = [0u8; 64];
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"MAINPID=1234");
        assert!(env::var("NOTIFY_SOCKET").is_err());

        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn booted_at_reports_existing_directory() {
        let path = unique_path("booted");
        fs::create_dir_all(&path).unwrap();
        assert!(booted_at(&path).unwrap());
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn fifo_check_matches_same_inode() {
        let path = unique_path("fifo");
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        assert!(is_fifo(file.as_raw_fd(), Some(&path)).unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn special_check_matches_regular_file() {
        let path = unique_path("special");
        fs::write(&path, b"data").unwrap();
        let file = File::open(&path).unwrap();
        assert!(is_special(file.as_raw_fd(), Some(&path)).unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn fifo_and_special_missing_path_return_false() {
        let fifo_path = unique_path("missing-fifo");
        let fifo_c = CString::new(fifo_path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        let fifo = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path)
            .unwrap();
        let missing_fifo = unique_path("fifo-missing-target");
        assert!(!is_fifo(fifo.as_raw_fd(), Some(&missing_fifo)).unwrap());
        let _ = fs::remove_file(&fifo_path);

        let regular_path = unique_path("missing-regular");
        fs::write(&regular_path, b"data").unwrap();
        let regular = File::open(&regular_path).unwrap();
        let missing_regular = unique_path("regular-missing-target");
        assert!(!is_special(regular.as_raw_fd(), Some(&missing_regular)).unwrap());
        let _ = fs::remove_file(&regular_path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inet_socket_check_validates_family_and_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(
            is_socket_inet(
                listener.as_raw_fd(),
                Some(libc::AF_INET),
                Some(libc::SOCK_STREAM),
                Some(true),
                Some(port)
            )
            .unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inet_socket_sockaddr_matches_expected_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let SocketAddr::V4(v4) = local else {
            panic!("expected IPv4 listener");
        };

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            },
            sin_zero: [0; 8],
        };

        assert!(
            sd_is_socket_sockaddr(
                listener.as_raw_fd(),
                Some(libc::SOCK_STREAM),
                // SAFETY: arguments satisfy the libc `sockaddr` contract and any passed pointers remain valid for the call.
                Some(unsafe { &*(&addr as *const _ as *const libc::sockaddr) }),
                std::mem::size_of::<libc::sockaddr_in>(),
                Some(true),
            )
            .unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_socket_check_detects_bound_path() {
        let path = unique_path("unix.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let bytes = path.as_os_str().as_encoded_bytes();
        assert!(
            is_socket_unix(
                listener.as_raw_fd(),
                Some(libc::SOCK_STREAM),
                Some(true),
                Some(bytes)
            )
            .unwrap()
        );
        let _ = fs::remove_file(path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_socket_check_requires_exact_path_match() {
        let path = unique_path("unix-exact.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let bytes = path.as_os_str().as_encoded_bytes();
        assert!(
            !sd_is_socket_unix(
                listener.as_raw_fd(),
                Some(libc::SOCK_STREAM),
                Some(true),
                Some(&[]),
            )
            .unwrap()
        );
        assert!(
            sd_is_socket_unix(
                listener.as_raw_fd(),
                Some(libc::SOCK_STREAM),
                Some(true),
                Some(bytes),
            )
            .unwrap()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unix_socket_path_helper_accepts_trailing_bytes_after_nul() {
        assert!(unix_socket_path_matches(
            b"/run/demo.sock\0ignored",
            b"/run/demo.sock"
        ));
        assert!(unix_socket_path_matches(b"\0abstract", b"\0abstract"));
        assert!(!unix_socket_path_matches(
            b"/run/demo.sock",
            b"/run/demo.sock"
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inet_socket_sockaddr_allows_wildcard_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let SocketAddr::V4(v4) = local else {
            panic!("expected IPv4 listener");
        };

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            },
            sin_zero: [0; 8],
        };

        assert!(
            sd_is_socket_sockaddr(
                listener.as_raw_fd(),
                Some(libc::SOCK_STREAM),
                // SAFETY: arguments satisfy the libc `sockaddr` contract and any passed pointers remain valid for the call.
                Some(unsafe { &*(&addr as *const _ as *const libc::sockaddr) }),
                std::mem::size_of::<libc::sockaddr_in>(),
                Some(true),
            )
            .unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn datagram_socket_is_detected_as_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(
            sd_is_socket(
                socket.as_raw_fd(),
                Some(libc::AF_INET),
                Some(libc::SOCK_DGRAM),
                Some(false)
            )
            .unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mq_check_matches_path_and_descriptor() {
        let name = format!(
            "/systemd-rs-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let c_name = CString::new(name.clone()).unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let fd = unsafe {
            mq_open(
                c_name.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
                std::ptr::null::<MqAttr>(),
            )
        };
        assert_ne!(fd, -1);
        let queue_path = PathBuf::from(name);
        let result = sd_is_mq(fd, Some(&queue_path)).unwrap();
        assert!(result);
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe {
            mq_close(fd);
            mq_unlink(c_name.as_ptr());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mq_check_requires_absolute_path() {
        let name = format!(
            "/systemd-rs-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let c_name = CString::new(name.clone()).unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let fd = unsafe {
            mq_open(
                c_name.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
                std::ptr::null::<MqAttr>(),
            )
        };
        assert_ne!(fd, -1);

        let result = sd_is_mq(fd, Some(Path::new("relative-name")));
        assert!(matches!(
            result,
            Err(DaemonCheckError::InvalidInput("path"))
        ));

        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe {
            mq_close(fd);
            mq_unlink(c_name.as_ptr());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mq_check_rejects_regular_files() {
        let path = unique_path("regular-fd");
        fs::write(&path, b"data").unwrap();
        let file = File::open(&path).unwrap();
        assert!(!sd_is_mq(file.as_raw_fd(), None).unwrap());
        let _ = fs::remove_file(path);
    }
}
