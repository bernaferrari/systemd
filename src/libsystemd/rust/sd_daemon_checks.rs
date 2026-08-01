// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-daemon/sd-daemon.c

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
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

pub const SD_LISTEN_FDS_START: RawFd = 3;
const LISTEN_ENV_VARS: [&str; 4] = [
    "LISTEN_PID",
    "LISTEN_PIDFDID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
];
const WATCHDOG_ENV_VARS: [&str; 2] = ["WATCHDOG_USEC", "WATCHDOG_PID"];
const NOTIFY_ENV_VAR: &str = "NOTIFY_SOCKET";

fn parse_with_c<T: Default>(
    value: &str,
    variable: &'static str,
    // SAFETY: callers pass the matching exported parser for `T`; the adapter
    // validates the string and output storage before invoking it.
    parser: unsafe extern "C" fn(*const libc::c_char, *mut T) -> i32,
) -> Result<T> {
    let value = CString::new(value).map_err(|_| DaemonCheckError::Parse(variable))?;
    let mut parsed = T::default();
    // SAFETY: the private callers supply a parser matching `T`; `value` is
    // NUL-terminated and `parsed` is writable for the duration of the call.
    let r = unsafe_ffi!(parser(value.as_ptr(), &mut parsed));
    if r < 0 {
        return Err(DaemonCheckError::Parse(variable));
    }
    Ok(parsed)
}

fn current_pid() -> libc::pid_t {
    std::process::id() as libc::pid_t
}

/// Parse a PID with the same grammar and validity checks as C `parse_pid()`.
fn parse_pid(value: &str, variable: &'static str) -> Result<libc::pid_t> {
    let parsed = parse_with_c(value, variable, systemd_basic_rs::parse_util::rs_safe_atolu)?;
    let pid = libc::pid_t::try_from(parsed).map_err(|_| DaemonCheckError::Parse(variable))?;
    if pid <= 0 {
        return Err(DaemonCheckError::Parse(variable));
    }
    Ok(pid)
}

/// Parse an i32 with C `safe_atoi()`'s base-zero grammar.
fn parse_i32(value: &str, variable: &'static str) -> Result<i32> {
    parse_with_c(value, variable, systemd_basic_rs::parse_util::rs_safe_atoi)
}

/// Parse a u64 with C `safe_atou64()`'s base-zero grammar.
fn parse_u64(value: &str, variable: &'static str) -> Result<u64> {
    parse_with_c(
        value,
        variable,
        systemd_basic_rs::parse_util::rs_safe_atou64,
    )
}

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
        unsafe_ffi!(env::remove_var(key));
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
        unsafe_ffi!(env::remove_var(key));
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
    unsafe_ffi!(env::remove_var(NOTIFY_ENV_VAR));
}

pub fn listen_fds_from_env(
    env: &BTreeMap<String, String>,
    current_pid: libc::pid_t,
    own_pidfdid: Option<u64>,
) -> Result<Vec<RawFd>> {
    let listen_pid = match env.get("LISTEN_PID") {
        Some(value) => parse_pid(value, "LISTEN_PID")?,
        None => return Ok(Vec::new()),
    };

    if listen_pid != current_pid {
        return Ok(Vec::new());
    }

    if let Some(expected) = env.get("LISTEN_PIDFDID") {
        let expected = parse_u64(expected, "LISTEN_PIDFDID")?;

        if let Some(actual) = own_pidfdid
            && expected != actual
        {
            return Ok(Vec::new());
        }
    }

    let n_fds = match env.get("LISTEN_FDS") {
        Some(value) => parse_i32(value, "LISTEN_FDS")?,
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
    let result = listen_fds_from_process_env();

    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe_ffi!(unsetenv_listen());
    }

    result
}

/// Parse descriptors without changing the process environment.
pub fn sd_listen_fds_preserve_environment() -> Result<i32> {
    listen_fds_from_process_env()
}

fn listen_fds_from_process_env() -> Result<i32> {
    let env = collect_listen_env();
    let fds = listen_fds_from_env(&env, current_pid(), None)?;

    for fd in &fds {
        set_fd_cloexec(*fd)?;
    }

    i32::try_from(fds.len()).map_err(|_| DaemonCheckError::InvalidInput("LISTEN_FDS"))
}

pub fn listen_fds_with_names_from_env(
    env: &BTreeMap<String, String>,
    current_pid: libc::pid_t,
    own_pidfdid: Option<u64>,
) -> Result<Vec<PassedFd>> {
    let fds = listen_fds_from_env(env, current_pid, own_pidfdid)?;
    if fds.is_empty() {
        // The C implementation returns early when sd_listen_fds() yields no
        // descriptors, without requiring a stray LISTEN_FDNAMES value to be
        // well-formed or empty.
        return Ok(Vec::new());
    }

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
    let result = listen_fds_with_names_from_process_env();

    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe_ffi!(unsetenv_listen());
    }

    result
}

/// Parse named descriptors without changing the process environment.
pub fn sd_listen_fds_with_names_preserve_environment() -> Result<Vec<PassedFd>> {
    listen_fds_with_names_from_process_env()
}

fn listen_fds_with_names_from_process_env() -> Result<Vec<PassedFd>> {
    let env = collect_listen_env();
    let passed = listen_fds_with_names_from_env(&env, current_pid(), None)?;

    for passed_fd in &passed {
        set_fd_cloexec(passed_fd.fd)?;
    }

    Ok(passed)
}

pub fn watchdog_enabled_from_env(
    env: &BTreeMap<String, String>,
    current_pid: libc::pid_t,
) -> Result<Option<u64>> {
    let usec = match env.get("WATCHDOG_USEC") {
        Some(value) => parse_u64(value, "WATCHDOG_USEC")?,
        None => return Ok(None),
    };

    if usec == 0 {
        return Err(DaemonCheckError::InvalidInput("WATCHDOG_USEC"));
    }

    if let Some(pid) = env.get("WATCHDOG_PID") {
        let pid = parse_pid(pid, "WATCHDOG_PID")?;
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
    let result = watchdog_enabled_from_process_env();

    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe_ffi!(unsetenv_watchdog());
    }

    result
}

/// Read the watchdog interval without changing the process environment.
pub fn sd_watchdog_enabled_preserve_environment() -> Result<Option<u64>> {
    watchdog_enabled_from_process_env()
}

fn watchdog_enabled_from_process_env() -> Result<Option<u64>> {
    watchdog_enabled_from_env(&collect_watchdog_env(), current_pid())
}

/// Send an sd_notify message to the service manager.
///
/// # Safety
///
/// When `unset_environment` is true, the caller must ensure that no other
/// thread reads or mutates the process environment until this function returns.
pub unsafe fn sd_notify(unset_environment: bool, state: &str) -> Result<bool> {
    let result = notify_from_process_env(state);

    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe_ffi!(unsetenv_notify());
    }

    result
}

/// Send an sd_notify message without changing the process environment.
pub fn sd_notify_preserve_environment(state: &str) -> Result<bool> {
    notify_from_process_env(state)
}

fn notify_from_process_env(state: &str) -> Result<bool> {
    let notify_socket = match env::var(NOTIFY_ENV_VAR) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(false),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET"));
        }
    };

    send_notify_message(&notify_socket, state.as_bytes())?;
    Ok(true)
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
    unsafe_ffi!(sd_notify(unset_environment, &message))
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

#[derive(Clone, Copy)]
enum InetSocketAddress {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl InetSocketAddress {
    fn family(self) -> i32 {
        match self {
            Self::V4(_) => libc::AF_INET,
            Self::V6(_) => libc::AF_INET6,
        }
    }
}

/// # Safety
///
/// `addr` must be readable for `addr_len` bytes and aligned for the already
/// validated internet address `family`.
unsafe fn read_inet_socket_address(
    addr: *const libc::sockaddr,
    addr_len: usize,
    family: i32,
) -> Result<InetSocketAddress> {
    // SAFETY: the helper contract guarantees alignment and `addr_len` readable
    // bytes. Full struct reads occur only after their length checks.
    unsafe_ffi!({
        match family {
            libc::AF_INET => {
                if addr_len < size_of::<libc::sockaddr_in>() {
                    return Err(DaemonCheckError::InvalidInput("addr_len"));
                }
                Ok(InetSocketAddress::V4(std::ptr::read(
                    addr.cast::<libc::sockaddr_in>(),
                )))
            }
            libc::AF_INET6 => {
                if addr_len < size_of::<libc::sockaddr_in6>() {
                    return Err(DaemonCheckError::InvalidInput("addr_len"));
                }
                Ok(InetSocketAddress::V6(std::ptr::read(
                    addr.cast::<libc::sockaddr_in6>(),
                )))
            }
            _ => Err(DaemonCheckError::InvalidInput("family")),
        }
    })
}

fn read_inet_socket_address_from_storage(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Result<InetSocketAddress> {
    let family = sockaddr_family(storage);
    let min_len = match family {
        libc::AF_INET => size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => size_of::<libc::sockaddr_in6>(),
        _ => return Err(DaemonCheckError::InvalidInput("family")),
    };
    if len < min_len as libc::socklen_t {
        return Err(DaemonCheckError::InvalidInput("addr_len"));
    }

    // SAFETY: `getsockname` initialized `storage` as the checked family and
    // supplied at least the complete corresponding address length.
    Ok(unsafe_ffi!({
        match family {
            libc::AF_INET => InetSocketAddress::V4(std::ptr::read(
                std::ptr::from_ref(storage).cast::<libc::sockaddr_in>(),
            )),
            libc::AF_INET6 => InetSocketAddress::V6(std::ptr::read(
                std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>(),
            )),
            _ => unreachable!("family was validated above"),
        }
    }))
}

fn inet_socket_address_matches(actual: InetSocketAddress, expected: InetSocketAddress) -> bool {
    match (actual, expected) {
        (InetSocketAddress::V4(actual), InetSocketAddress::V4(expected)) => {
            (expected.sin_port == 0 || actual.sin_port == expected.sin_port)
                && actual.sin_addr.s_addr == expected.sin_addr.s_addr
        }
        (InetSocketAddress::V6(actual), InetSocketAddress::V6(expected)) => {
            (expected.sin6_port == 0 || actual.sin6_port == expected.sin6_port)
                && (expected.sin6_flowinfo == 0 || actual.sin6_flowinfo == expected.sin6_flowinfo)
                && (expected.sin6_scope_id == 0 || actual.sin6_scope_id == expected.sin6_scope_id)
                && actual.sin6_addr.s6_addr == expected.sin6_addr.s6_addr
        }
        _ => false,
    }
}

/// Check whether `fd` is an internet socket matching `addr`.
///
/// # Safety
///
/// `addr` must be null or point to a live socket-address object readable for
/// `addr_len` bytes for the duration of this call. When non-null, it must be
/// properly aligned for its declared address family.
pub unsafe fn sd_is_socket_sockaddr(
    fd: RawFd,
    sock_type: Option<i32>,
    addr: *const libc::sockaddr,
    addr_len: usize,
    listening: Option<bool>,
) -> Result<bool> {
    if fd < 0 {
        return Err(DaemonCheckError::BadFd);
    }
    if addr.is_null() {
        return Err(DaemonCheckError::InvalidInput("addr"));
    }
    if addr_len < size_of::<libc::sa_family_t>() {
        return Err(DaemonCheckError::InvalidInput("addr_len"));
    }
    // SAFETY: upheld by this function's caller: `addr` designates at least a
    // `sa_family_t`, and `read_unaligned` does not impose stronger alignment.
    let addr_family =
        unsafe_ffi!(std::ptr::read_unaligned(addr.cast::<libc::sa_family_t>())) as i32;
    match addr_family {
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

    if sockaddr_family(&storage) != addr_family {
        return Ok(false);
    }

    // SAFETY: after the existing family and length checks, this export's raw
    // address contract supplies a readable, aligned complete address object.
    let expected = unsafe_ffi!(read_inet_socket_address(addr, addr_len, addr_family))?;
    let actual = read_inet_socket_address_from_storage(&storage, actual_len)?;
    Ok(inet_socket_address_matches(actual, expected))
}

/// # Safety
///
/// This has the same raw-address requirements as `sd_is_socket_sockaddr()`.
pub unsafe fn is_socket_sockaddr(
    fd: RawFd,
    sock_type: Option<i32>,
    addr: *const libc::sockaddr,
    addr_len: usize,
    listening: Option<bool>,
) -> Result<bool> {
    // SAFETY: this wrapper preserves the raw address contract documented above.
    unsafe_ffi!(sd_is_socket_sockaddr(
        fd, sock_type, addr, addr_len, listening
    ))
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

    let actual_len =
        usize::try_from(len).map_err(|_| DaemonCheckError::InvalidInput("sockaddr"))?;
    let path_offset = offset_of!(libc::sockaddr_un, sun_path);
    if actual_len < path_offset {
        return Err(DaemonCheckError::InvalidInput("sockaddr"));
    }
    let actual_path_len = actual_len - path_offset;
    let actual_path =
        // SAFETY: `path_offset` and `actual_path_len` were checked against the
        // sockaddr bytes initialized by `getsockname` above.
        unsafe_ffi!({
            std::slice::from_raw_parts(
                std::ptr::from_ref(&storage)
                    .cast::<u8>()
                    .add(path_offset),
                actual_path_len,
            )
        });

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
    // SAFETY: `libc::mq_attr` and `mq_getattr` come from the target libc ABI;
    // `fd` was validated and `attr` is writable for the duration of the call.
    let mut attr = unsafe_ffi!(zeroed::<libc::mq_attr>());
    // SAFETY: `fd` was validated and `attr` is a live writable target-libc value.
    let r = unsafe_ffi!(libc::mq_getattr(fd, &mut attr));
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
    if fd < 0 {
        return Err(DaemonCheckError::BadFd);
    }
    if let Some(sock_type) = sock_type
        && sock_type < 0
    {
        return Err(DaemonCheckError::InvalidInput("type"));
    }

    let fd_stat = fstat(fd)?;
    if (fd_stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
        return Ok(false);
    }

    if let Some(sock_type) = sock_type
        && sock_type != 0
    {
        let actual = getsockopt_int(fd, libc::SO_TYPE)?;
        if actual != sock_type {
            return Ok(false);
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
    let mut st = unsafe_ffi!(zeroed::<libc::stat>());
    // SAFETY: arguments satisfy the libc `fstat` contract and any passed pointers remain valid for the call.
    let r = unsafe_ffi!(libc::fstat(fd, &mut st));
    if r < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }
    Ok(st)
}

fn stat_path(path: &Path) -> Result<libc::stat> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| DaemonCheckError::InvalidInput("path"))?;
    // SAFETY: `libc::stat` is a POD C struct and may be zero-initialized before `stat` fills it.
    let mut st = unsafe_ffi!(zeroed::<libc::stat>());
    // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
    let r = unsafe_ffi!(libc::stat(path.as_ptr(), &mut st));
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
    let r = unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD));
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
    let flags = unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD));
    if flags < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }

    // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
    if unsafe_ffi!(libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC)) < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }

    Ok(())
}

enum NotifySocketAddress<'a> {
    Unix(&'a libc::sockaddr_un, libc::socklen_t),
    #[cfg(target_os = "linux")]
    Vsock(&'a libc::sockaddr_vm, libc::socklen_t),
}

impl NotifySocketAddress<'_> {
    fn as_raw_parts(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::Unix(address, len) => (std::ptr::from_ref(*address).cast(), *len),
            #[cfg(target_os = "linux")]
            Self::Vsock(address, len) => (std::ptr::from_ref(*address).cast(), *len),
        }
    }
}

struct NotifySocketFd(RawFd);

fn close_fd(fd: RawFd) {
    // SAFETY: `close` accepts any integer descriptor; callers intentionally
    // ignore the close result to preserve the existing cleanup behavior.
    unsafe_ffi!(libc::close(fd));
}

impl Drop for NotifySocketFd {
    fn drop(&mut self) {
        close_fd(self.0);
    }
}

fn send_notify_datagram(fd: RawFd, payload: &[u8], address: NotifySocketAddress<'_>) -> Result<()> {
    let (address, address_len) = address.as_raw_parts();
    // SAFETY: the typed address reference remains live for the call and its
    // matching socket length is carried with it; payload is a live byte slice.
    let sent = unsafe_ffi!({
        libc::sendto(
            fd,
            payload.as_ptr().cast(),
            payload.len(),
            libc::MSG_NOSIGNAL,
            address,
            address_len,
        )
    });
    if sent < 0 {
        Err(DaemonCheckError::Io(last_errno()))
    } else if sent as usize != payload.len() {
        Err(DaemonCheckError::Io(libc::EIO))
    } else {
        Ok(())
    }
}

fn send_notify_message(notify_socket: &str, payload: &[u8]) -> Result<()> {
    if let Ok((addr, addr_len)) = parse_notify_socket_unix(notify_socket) {
        let fd = NotifySocketFd(create_socket_cloexec(libc::AF_UNIX, libc::SOCK_DGRAM)?);
        return send_notify_datagram(fd.0, payload, NotifySocketAddress::Unix(&addr, addr_len));
    }

    #[cfg(target_os = "linux")]
    {
        if let Some((addr, addr_len, sock_type)) = parse_notify_socket_vsock(notify_socket)? {
            let fd = NotifySocketFd(create_socket_cloexec(libc::AF_VSOCK, sock_type)?);
            return send_notify_datagram(
                fd.0,
                payload,
                NotifySocketAddress::Vsock(&addr, addr_len),
            );
        }
    }

    Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET"))
}

fn create_socket_cloexec(family: libc::c_int, sock_type: libc::c_int) -> Result<RawFd> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: arguments satisfy the libc `socket` contract and any passed pointers remain valid for the call.
        let fd = unsafe_ffi!(libc::socket(family, sock_type | libc::SOCK_CLOEXEC, 0));
        if fd >= 0 {
            return Ok(fd);
        }
    }

    // SAFETY: arguments satisfy the libc `socket` contract and any passed pointers remain valid for the call.
    let fd = unsafe_ffi!(libc::socket(family, sock_type, 0));
    if fd < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }
    if let Err(e) = set_fd_cloexec(fd) {
        close_fd(fd);
        return Err(e);
    }
    Ok(fd)
}

fn parse_notify_socket_unix(address: &str) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    if !(address.starts_with('/') || address.starts_with('@')) {
        return Err(DaemonCheckError::InvalidInput("NOTIFY_SOCKET"));
    }

    // SAFETY: `libc::sockaddr_un` is POD and may be zero-initialized before filling `sun_family/sun_path`.
    let mut sockaddr = unsafe_ffi!(zeroed::<libc::sockaddr_un>());
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
    let r = unsafe_ffi!({
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    });
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
    let mut storage = unsafe_ffi!(zeroed::<libc::sockaddr_storage>());
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let r =
        // SAFETY: arguments satisfy the libc `getsockname` contract and any passed pointers remain valid for the call.
        unsafe_ffi!( libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) );
    if r < 0 {
        return Err(DaemonCheckError::Io(last_errno()));
    }
    if len < size_of::<libc::sa_family_t>() as libc::socklen_t {
        return Err(DaemonCheckError::InvalidInput("sockaddr"));
    }
    Ok((storage, len))
}

fn sockaddr_family(storage: &libc::sockaddr_storage) -> i32 {
    storage.ss_family as i32
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
    match read_inet_socket_address_from_storage(
        storage,
        size_of::<libc::sockaddr_storage>() as libc::socklen_t,
    )? {
        InetSocketAddress::V4(addr) => Ok(u16::from_be(addr.sin_port)),
        InetSocketAddress::V6(addr) => Ok(u16::from_be(addr.sin6_port)),
    }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(test)]
mod tests {
    // Keep the test-only FFI boundary explicit while allowing assertions to stay in safe Rust.
    macro_rules! test_ffi {
        ($expression:expr) => {{
            // SAFETY: test inputs are constructed in this module and satisfy the
            // documented C ABI preconditions of the exercised facade.
            unsafe_ffi!({ $expression })
        }};
    }
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
        let duplicated = test_ffi!(libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 128));
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
        let r = test_ffi!(libc::dup2(source, target));
        assert!(r >= 0, "dup2({source}, {target}) failed");
        saved
    }

    fn restore_fd(target: RawFd, saved: Option<RawFd>) {
        match saved {
            Some(saved_fd) => {
                // SAFETY: arguments satisfy the libc `dup2` contract and any passed pointers remain valid for the call.
                let r = test_ffi!(libc::dup2(saved_fd, target));
                assert!(r >= 0, "failed to restore fd {target}");
                // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
                test_ffi!(libc::close(saved_fd));
            }
            None => {
                // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
                test_ffi!(libc::close(target));
            }
        }
    }

    fn fd_cloexec_set(fd: RawFd) -> bool {
        // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
        let flags = test_ffi!(libc::fcntl(fd, libc::F_GETFD));
        assert!(flags >= 0, "F_GETFD failed for fd {fd}");
        (flags & libc::FD_CLOEXEC) != 0
    }

    fn close_if_not_kept(fd: RawFd, keep_a: RawFd, keep_b: RawFd) {
        if fd != keep_a && fd != keep_b {
            // SAFETY: arguments satisfy the libc `close` contract and any passed pointers remain valid for the call.
            test_ffi!(libc::close(fd));
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
    fn activation_environment_uses_systemd_numeric_grammars() {
        let env = BTreeMap::from([
            ("LISTEN_PID".into(), " 010".into()),
            ("LISTEN_PIDFDID".into(), "0x2a".into()),
            ("LISTEN_FDS".into(), "0b10".into()),
        ]);
        assert_eq!(listen_fds_from_env(&env, 8, Some(42)).unwrap(), vec![3, 4]);

        let invalid_pid = BTreeMap::from([
            ("LISTEN_PID".into(), "0".into()),
            ("LISTEN_FDS".into(), "1".into()),
        ]);
        assert!(matches!(
            listen_fds_from_env(&invalid_pid, 8, None),
            Err(DaemonCheckError::Parse("LISTEN_PID"))
        ));

        let watchdog = BTreeMap::from([
            ("WATCHDOG_USEC".into(), "0x10".into()),
            ("WATCHDOG_PID".into(), "010".into()),
        ]);
        assert_eq!(watchdog_enabled_from_env(&watchdog, 8).unwrap(), Some(16));
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
    fn listen_fds_with_names_ignores_stray_names_without_descriptors() {
        let env = BTreeMap::from([("LISTEN_FDNAMES".into(), "stale".into())]);
        assert!(
            listen_fds_with_names_from_env(&env, 5, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn sd_listen_fds_sets_cloexec_and_unsets_environment() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = test_ffi!(TestEnvironment::lock());
        for key in LISTEN_ENV_VARS {
            environment.remove(key);
        }

        let mut pipe_a = [0; 2];
        let mut pipe_b = [0; 2];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(test_ffi!(libc::pipe(pipe_a.as_mut_ptr())), 0);
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(test_ffi!(libc::pipe(pipe_b.as_mut_ptr())), 0);

        let saved3 = replace_fd_with(pipe_a[0], SD_LISTEN_FDS_START);
        let saved4 = replace_fd_with(pipe_b[0], SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_a[0], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_a[1], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_b[0], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_b[1], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);

        // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
        unsafe_ffi!({
            libc::fcntl(SD_LISTEN_FDS_START, libc::F_SETFD, 0);
            libc::fcntl(SD_LISTEN_FDS_START + 1, libc::F_SETFD, 0);
        });

        // SAFETY: arguments satisfy the libc `getpid` contract and any passed pointers remain valid for the call.
        environment.set("LISTEN_PID", test_ffi!(libc::getpid()).to_string());
        environment.set("LISTEN_FDS", "2");
        environment.set("LISTEN_FDNAMES", "alpha:beta");

        // SAFETY: TestEnvironment upholds the environment mutation contract.
        let n = test_ffi!(sd_listen_fds(true)).unwrap();
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
        let environment = test_ffi!(TestEnvironment::lock());
        for key in LISTEN_ENV_VARS {
            environment.remove(key);
        }

        let mut pipe_a = [0; 2];
        let mut pipe_b = [0; 2];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(test_ffi!(libc::pipe(pipe_a.as_mut_ptr())), 0);
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(test_ffi!(libc::pipe(pipe_b.as_mut_ptr())), 0);

        let saved3 = replace_fd_with(pipe_a[0], SD_LISTEN_FDS_START);
        let saved4 = replace_fd_with(pipe_b[0], SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_a[0], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_a[1], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_b[0], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        close_if_not_kept(pipe_b[1], SD_LISTEN_FDS_START, SD_LISTEN_FDS_START + 1);
        // SAFETY: arguments satisfy the libc `fcntl` contract and any passed pointers remain valid for the call.
        unsafe_ffi!({
            libc::fcntl(SD_LISTEN_FDS_START, libc::F_SETFD, 0);
            libc::fcntl(SD_LISTEN_FDS_START + 1, libc::F_SETFD, 0);
        });

        // SAFETY: arguments satisfy the libc `getpid` contract and any passed pointers remain valid for the call.
        environment.set("LISTEN_PID", test_ffi!(libc::getpid()).to_string());
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
        let environment = test_ffi!(TestEnvironment::lock());
        for key in WATCHDOG_ENV_VARS {
            environment.remove(key);
        }

        environment.set("WATCHDOG_USEC", "777000");
        // SAFETY: arguments satisfy the libc `getpid` contract and any passed pointers remain valid for the call.
        environment.set("WATCHDOG_PID", test_ffi!(libc::getpid()).to_string());

        // SAFETY: TestEnvironment upholds the environment mutation contract.
        let enabled = test_ffi!(sd_watchdog_enabled(true)).unwrap();
        assert_eq!(enabled, Some(777000));
        assert!(env::var("WATCHDOG_USEC").is_err());
        assert!(env::var("WATCHDOG_PID").is_err());
    }

    #[test]
    fn sd_watchdog_enabled_missing_var_returns_none() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = test_ffi!(TestEnvironment::lock());
        for key in WATCHDOG_ENV_VARS {
            environment.remove(key);
        }
        assert_eq!(sd_watchdog_enabled_preserve_environment().unwrap(), None);
    }

    #[test]
    fn sd_notify_missing_socket_returns_zero_like_false() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(NOTIFY_ENV_VAR);
        assert!(!sd_notify_preserve_environment("READY=1").unwrap());
    }

    #[test]
    fn sd_notify_sends_to_unix_datagram_socket() {
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(NOTIFY_ENV_VAR);

        let socket_path = unique_path("notify.sock");
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        environment.set(
            "NOTIFY_SOCKET",
            socket_path.as_os_str().to_string_lossy().to_string(),
        );

        // SAFETY: TestEnvironment upholds the environment mutation contract.
        let sent = test_ffi!(sd_notify(true, "READY=1\nSTATUS=ok")).unwrap();
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
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(NOTIFY_ENV_VAR);

        let socket_path = unique_path("notifyf.sock");
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        environment.set(
            "NOTIFY_SOCKET",
            socket_path.as_os_str().to_string_lossy().to_string(),
        );

        // SAFETY: TestEnvironment upholds the environment mutation contract.
        let sent = unsafe_ffi!(sd_notifyf(true, format_args!("MAINPID={}", 1234))).unwrap();
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
        test_ffi!(libc::mkfifo(c_path.as_ptr(), 0o600));
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
        test_ffi!(libc::mkfifo(fifo_c.as_ptr(), 0o600));
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

        // SAFETY: `addr` remains live and is a correctly sized/aligned IPv4
        // socket address for the duration of this synchronous call.
        assert!(unsafe_ffi!({
            sd_is_socket_sockaddr(
                listener.as_raw_fd(),
                Some(libc::SOCK_STREAM),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>(),
                Some(true),
            )
            .unwrap()
        }));
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

        // SAFETY: `addr` remains live and is a correctly sized/aligned IPv4
        // socket address for the duration of this synchronous call.
        assert!(unsafe_ffi!({
            sd_is_socket_sockaddr(
                listener.as_raw_fd(),
                Some(libc::SOCK_STREAM),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>(),
                Some(true),
            )
            .unwrap()
        }));
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

    #[test]
    fn socket_check_rejects_negative_type_before_classifying_fd() {
        let path = unique_path("socket-type-validation");
        fs::write(&path, b"data").unwrap();
        let file = File::open(&path).unwrap();
        assert!(matches!(
            sd_is_socket(file.as_raw_fd(), None, Some(-1), None),
            Err(DaemonCheckError::InvalidInput("type"))
        ));
        let _ = fs::remove_file(path);
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
        let fd = unsafe_ffi!({
            libc::mq_open(
                c_name.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
                std::ptr::null::<libc::mq_attr>(),
            )
        });
        assert_ne!(fd, -1);
        let queue_path = PathBuf::from(name);
        let result = sd_is_mq(fd, Some(&queue_path)).unwrap();
        assert!(result);
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            libc::mq_close(fd);
            libc::mq_unlink(c_name.as_ptr());
        })
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
        let fd = unsafe_ffi!({
            libc::mq_open(
                c_name.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
                std::ptr::null::<libc::mq_attr>(),
            )
        });
        assert_ne!(fd, -1);

        let result = sd_is_mq(fd, Some(Path::new("relative-name")));
        assert!(matches!(
            result,
            Err(DaemonCheckError::InvalidInput("path"))
        ));

        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            libc::mq_close(fd);
            libc::mq_unlink(c_name.as_ptr());
        })
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
