// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/ask-password-api.c, src/shared/ask-password-api.h

use crate::ffi::*;
use std::collections::BTreeSet;
use std::env;
use std::ffi::{CString, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;

pub const SYSTEM_ASK_PASSWORD_DIR: &str = "/run/systemd/ask-password/";
pub const KEYRING_TIMEOUT_DEFAULT: Duration = Duration::from_secs(150);
pub const NO_ECHO: &str = "(no echo) ";
pub const PRESS_TAB: &str = "(press TAB for no echo) ";
pub const SKIPPED: &str = "(skipped)";
const LINE_MAX: usize = 2048;

const KEY_SPEC_THREAD_KEYRING: i32 = -1;
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_USER_KEYRING: i32 = -4;
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
const KEY_SPEC_GROUP_KEYRING: i32 = -6;

#[cfg(target_os = "linux")]
const KEYCTL_SET_TIMEOUT: libc::c_long = 15;
#[cfg(target_os = "linux")]
const KEYCTL_READ: libc::c_long = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskPasswordError {
    Timeout,
    NotAvailable,
    NoEnt,
    Canceled,
    Interrupted,
    NoExec,
    ConnReset,
    NotSupported,
    NoKey,
    Io(io::ErrorKind),
}

impl std::fmt::Display for AskPasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "password query timed out"),
            Self::NotAvailable => write!(f, "password query unavailable"),
            Self::NoEnt => write!(f, "required file or item disappeared"),
            Self::Canceled => write!(f, "password query cancelled"),
            Self::Interrupted => write!(f, "password query interrupted"),
            Self::NoExec => write!(f, "interactive password query disabled"),
            Self::ConnReset => write!(f, "connection reset"),
            Self::NotSupported => write!(f, "operation not supported"),
            Self::NoKey => write!(f, "no password available"),
            Self::Io(kind) => write!(f, "i/o error: {kind:?}"),
        }
    }
}

impl std::error::Error for AskPasswordError {}

impl From<io::Error> for AskPasswordError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::NotFound => Self::NoEnt,
            io::ErrorKind::Interrupted => Self::Interrupted,
            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => Self::ConnReset,
            kind => Self::Io(kind),
        }
    }
}

pub type AskPasswordResult<T> = Result<T, AskPasswordError>;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AskPasswordFlags: u64 {
        const ACCEPT_CACHED   = 1 << 0;
        const PUSH_CACHE      = 1 << 1;
        const ECHO            = 1 << 2;
        const SILENT          = 1 << 3;
        const NO_TTY          = 1 << 4;
        const NO_AGENT        = 1 << 5;
        const CONSOLE_COLOR   = 1 << 6;
        const NO_CREDENTIAL   = 1 << 7;
        const HIDE_EMOJI      = 1 << 8;
        const HEADLESS        = 1 << 9;
        const USER            = 1 << 10;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringType {
    Thread,
    Process,
    Session,
    User,
    UserSession,
    Group,
}

impl KeyringType {
    pub fn from_env_value(value: &str) -> Option<Self> {
        match value {
            "thread" => Some(Self::Thread),
            "process" => Some(Self::Process),
            "session" => Some(Self::Session),
            "user" => Some(Self::User),
            "user-session" => Some(Self::UserSession),
            "group" => Some(Self::Group),
            _ => None,
        }
    }

    fn serial(self) -> i32 {
        match self {
            Self::Thread => KEY_SPEC_THREAD_KEYRING,
            Self::Process => KEY_SPEC_PROCESS_KEYRING,
            Self::Session => KEY_SPEC_SESSION_KEYRING,
            Self::User => KEY_SPEC_USER_KEYRING,
            Self::UserSession => KEY_SPEC_USER_SESSION_KEYRING,
            Self::Group => KEY_SPEC_GROUP_KEYRING,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringDestination {
    Serial(i32),
    Special(KeyringType),
}

impl KeyringDestination {
    fn serial(self) -> i32 {
        match self {
            Self::Serial(v) => v,
            Self::Special(v) => v.serial(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskPasswordRequest {
    pub message: Option<String>,
    pub keyring: Option<String>,
    pub icon: Option<String>,
    pub id: Option<String>,
    pub credential: Option<String>,
    pub flag_file: Option<PathBuf>,
    pub tty_fd: RawFd,
    pub hup_fd: RawFd,
    pub until: Option<Duration>,
}

impl Default for AskPasswordRequest {
    fn default() -> Self {
        Self {
            message: None,
            keyring: None,
            icon: None,
            id: None,
            credential: None,
            flag_file: None,
            tty_fd: -1,
            hup_fd: -1,
            until: None,
        }
    }
}

#[derive(Debug, Clone)]
struct FallbackCacheEntry {
    passwords: Vec<String>,
    expires_at: Option<Instant>,
}

static FALLBACK_KEYRING: LazyLock<Mutex<std::collections::HashMap<String, FallbackCacheEntry>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn default_message(req: &AskPasswordRequest) -> &str {
    req.message.as_deref().unwrap_or("Password:")
}

fn timeout_deadline(req: &AskPasswordRequest) -> Option<Instant> {
    req.until.map(|d| Instant::now() + d)
}

fn poll_timeout_ms(deadline: Option<Instant>) -> i32 {
    match deadline {
        None => -1,
        Some(deadline) => {
            let now = Instant::now();
            if now >= deadline {
                0
            } else {
                deadline
                    .duration_since(now)
                    .as_millis()
                    .min(i32::MAX as u128) as i32
            }
        }
    }
}

fn unique_u64() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn map_errno(errno: i32) -> AskPasswordError {
    match errno {
        libc::ETIME => AskPasswordError::Timeout,
        libc::ENOENT => AskPasswordError::NoEnt,
        ENOKEY => AskPasswordError::NoKey,
        libc::ENOTSUP | libc::EOPNOTSUPP | libc::ENOSYS => AskPasswordError::NotSupported,
        libc::EINTR => AskPasswordError::Interrupted,
        libc::ECANCELED => AskPasswordError::Canceled,
        libc::ECONNRESET => AskPasswordError::ConnReset,
        _ => AskPasswordError::Io(io::Error::from_raw_os_error(errno).kind()),
    }
}

fn errno_result<T>() -> AskPasswordResult<T> {
    Err(map_errno(
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    ))
}

fn check_flag_file(req: &AskPasswordRequest) -> AskPasswordResult<()> {
    if let Some(path) = &req.flag_file {
        if !path.exists() {
            return Err(AskPasswordError::NoEnt);
        }
    }
    Ok(())
}

fn write_all_fd(fd: RawFd, data: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        // SAFETY: slice pointer/length are valid for the duration of the call.
        let n = unsafe {
            libc::write(
                fd,
                data[offset..].as_ptr().cast::<c_void>(),
                data.len() - offset,
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        offset += n as usize;
    }
    Ok(())
}

fn read_one_byte(fd: RawFd) -> io::Result<Option<u8>> {
    let mut byte = 0u8;
    // SAFETY: byte points to a valid output buffer.
    let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast::<c_void>(), 1) };
    if n < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return read_one_byte(fd);
        }
        return Err(error);
    }
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(byte))
}

fn parse_nulstr(data: &[u8]) -> Vec<String> {
    data.split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

fn make_nulstr(strings: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, value) in strings.iter().enumerate() {
        out.extend_from_slice(value.as_bytes());
        if index + 1 < strings.len() {
            out.push(0);
        }
    }
    out
}

fn previous_char_boundary(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }

    let mut index = bytes.len() - 1;
    while index > 0 && (bytes[index] & 0b1100_0000) == 0b1000_0000 {
        index -= 1;
    }

    if std::str::from_utf8(&bytes[index..])
        .ok()
        .and_then(|s| s.chars().next())
        .is_some()
    {
        index
    } else {
        bytes.len() - 1
    }
}

fn backspace_chars(count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count * 3);
    for _ in 0..count {
        out.extend_from_slice(b"\x08 \x08");
    }
    out
}

fn backspace_string_count(value: &str) -> usize {
    value.chars().count()
}

fn poll_readable(fd: RawFd, hup_fd: RawFd, deadline: Option<Instant>) -> AskPasswordResult<()> {
    let mut pollfds = [
        libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: hup_fd,
            events: libc::POLLHUP,
            revents: 0,
        },
    ];
    let nfds = if hup_fd >= 0 { 2 } else { 1 };

    loop {
        let timeout = poll_timeout_ms(deadline);
        if timeout == 0 {
            return Err(AskPasswordError::Timeout);
        }

        // SAFETY: pollfds is initialized for the selected nfds entries.
        let n = unsafe { libc::poll(pollfds.as_mut_ptr(), nfds as libc::nfds_t, timeout) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if n == 0 {
            return Err(AskPasswordError::Timeout);
        }
        if hup_fd >= 0 && (pollfds[1].revents & libc::POLLHUP) != 0 {
            return Err(AskPasswordError::ConnReset);
        }
        if (pollfds[0].revents & libc::POLLIN) != 0 {
            return Ok(());
        }
    }
}

pub fn acquire_user_ask_password_directory() -> AskPasswordResult<Option<PathBuf>> {
    match env::var_os("XDG_RUNTIME_DIR") {
        Some(value) => Ok(Some(PathBuf::from(value).join("systemd/ask-password"))),
        None => Ok(None),
    }
}

pub fn get_ask_password_directory_for_flags(
    flags: AskPasswordFlags,
) -> AskPasswordResult<Option<PathBuf>> {
    if flags.contains(AskPasswordFlags::USER) {
        return acquire_user_ask_password_directory();
    }
    Ok(Some(PathBuf::from(SYSTEM_ASK_PASSWORD_DIR)))
}

pub fn touch_ask_password_directory(flags: AskPasswordFlags) -> AskPasswordResult<bool> {
    let Some(path) = get_ask_password_directory_for_flags(flags)? else {
        return Ok(false);
    };

    fs::create_dir_all(&path).map_err(AskPasswordError::from)?;
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| AskPasswordError::Io(io::ErrorKind::InvalidInput))?;

    // SAFETY: path is a valid NUL-terminated path; NULL means "set to current time".
    let r = unsafe { libc::utimes(path.as_ptr(), std::ptr::null()) };
    if r < 0 {
        return errno_result();
    }

    Ok(true)
}

pub fn keyring_cache_timeout() -> Duration {
    env::var("SYSTEMD_ASK_PASSWORD_KEYRING_TIMEOUT_SEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(KEYRING_TIMEOUT_DEFAULT)
}

pub fn keyring_cache_type() -> KeyringDestination {
    let Some(value) = env::var("SYSTEMD_ASK_PASSWORD_KEYRING_TYPE").ok() else {
        return KeyringDestination::Special(KeyringType::User);
    };

    if let Ok(serial) = value.parse::<i32>() {
        if serial >= 0 {
            return KeyringDestination::Serial(serial);
        }
        return KeyringDestination::Special(match serial {
            KEY_SPEC_THREAD_KEYRING => KeyringType::Thread,
            KEY_SPEC_PROCESS_KEYRING => KeyringType::Process,
            KEY_SPEC_SESSION_KEYRING => KeyringType::Session,
            KEY_SPEC_USER_KEYRING => KeyringType::User,
            KEY_SPEC_USER_SESSION_KEYRING => KeyringType::UserSession,
            KEY_SPEC_GROUP_KEYRING => KeyringType::Group,
            _ => KeyringType::User,
        });
    }

    KeyringType::from_env_value(&value)
        .map(KeyringDestination::Special)
        .unwrap_or(KeyringDestination::Special(KeyringType::User))
}

#[cfg(target_os = "linux")]
fn request_key_serial(keyname: &str) -> AskPasswordResult<i32> {
    let kind = CString::new("user").expect("static string has no interior NUL");
    let name =
        CString::new(keyname).map_err(|_| AskPasswordError::Io(io::ErrorKind::InvalidInput))?;

    // SAFETY: syscall arguments are valid C strings and scalar values.
    let serial = unsafe {
        libc::syscall(
            libc::SYS_request_key as libc::c_long,
            kind.as_ptr(),
            name.as_ptr(),
            std::ptr::null::<c_void>(),
            0usize,
        )
    };
    if serial < 0 {
        return errno_result();
    }
    Ok(serial as i32)
}

#[cfg(not(target_os = "linux"))]
fn request_key_serial(_keyname: &str) -> AskPasswordResult<i32> {
    Err(AskPasswordError::NotSupported)
}

#[cfg(target_os = "linux")]
fn read_key_payload(serial: i32) -> AskPasswordResult<Vec<u8>> {
    // SAFETY: query form of keyctl read; kernel only inspects arguments.
    let size = unsafe {
        libc::syscall(
            libc::SYS_keyctl as libc::c_long,
            KEYCTL_READ,
            serial as libc::c_long,
            std::ptr::null_mut::<c_void>(),
            0usize,
        )
    };
    if size < 0 {
        return errno_result();
    }

    let mut buffer = vec![0u8; size as usize];
    // SAFETY: buffer is writable for its full length.
    let n = unsafe {
        libc::syscall(
            libc::SYS_keyctl as libc::c_long,
            KEYCTL_READ,
            serial as libc::c_long,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len(),
        )
    };
    if n < 0 {
        return errno_result();
    }
    buffer.truncate(n as usize);
    Ok(buffer)
}

#[cfg(not(target_os = "linux"))]
fn read_key_payload(_serial: i32) -> AskPasswordResult<Vec<u8>> {
    Err(AskPasswordError::NotSupported)
}

#[cfg(target_os = "linux")]
fn add_key_payload(
    keyname: &str,
    payload: &[u8],
    destination: KeyringDestination,
) -> AskPasswordResult<i32> {
    let kind = CString::new("user").expect("static string has no interior NUL");
    let name =
        CString::new(keyname).map_err(|_| AskPasswordError::Io(io::ErrorKind::InvalidInput))?;

    // SAFETY: syscall arguments are valid pointers and scalar values.
    let serial = unsafe {
        libc::syscall(
            libc::SYS_add_key as libc::c_long,
            kind.as_ptr(),
            name.as_ptr(),
            payload.as_ptr().cast::<c_void>(),
            payload.len(),
            destination.serial() as libc::c_long,
        )
    };
    if serial < 0 {
        return errno_result();
    }
    Ok(serial as i32)
}

#[cfg(not(target_os = "linux"))]
fn add_key_payload(
    _keyname: &str,
    _payload: &[u8],
    _destination: KeyringDestination,
) -> AskPasswordResult<i32> {
    Err(AskPasswordError::NotSupported)
}

#[cfg(target_os = "linux")]
fn set_key_timeout(serial: i32, timeout: Duration) -> AskPasswordResult<()> {
    let seconds = timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() > 0));
    // SAFETY: scalar keyctl arguments only.
    let r = unsafe {
        libc::syscall(
            libc::SYS_keyctl as libc::c_long,
            KEYCTL_SET_TIMEOUT,
            serial as libc::c_long,
            seconds as libc::c_long,
            0usize,
            0usize,
        )
    };
    if r < 0 {
        return errno_result();
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_key_timeout(_serial: i32, _timeout: Duration) -> AskPasswordResult<()> {
    Err(AskPasswordError::NotSupported)
}

fn read_fallback_key(keyname: &str) -> AskPasswordResult<Vec<String>> {
    let mut cache = FALLBACK_KEYRING
        .lock()
        .expect("fallback keyring mutex poisoned");
    let expired = cache
        .get(keyname)
        .and_then(|entry| entry.expires_at)
        .is_some_and(|deadline| Instant::now() >= deadline);
    if expired {
        cache.remove(keyname);
    }

    let Some(entry) = cache.get(keyname) else {
        return Err(AskPasswordError::NoKey);
    };
    if entry.passwords.is_empty() {
        return Err(AskPasswordError::NoKey);
    }
    Ok(entry.passwords.clone())
}

fn write_fallback_key(keyname: &str, passwords: &[String], timeout: Duration) -> bool {
    let mut set = BTreeSet::new();
    let mut cache = FALLBACK_KEYRING
        .lock()
        .expect("fallback keyring mutex poisoned");
    if let Some(existing) = cache.get(keyname) {
        set.extend(existing.passwords.iter().cloned());
    }
    let original_len = set.len();
    set.extend(passwords.iter().cloned());
    let changed = set.len() != original_len;
    if changed {
        cache.insert(
            keyname.to_string(),
            FallbackCacheEntry {
                passwords: set.into_iter().collect(),
                expires_at: if timeout == Duration::MAX {
                    None
                } else {
                    Some(Instant::now() + timeout)
                },
            },
        );
    }
    changed
}

pub fn clear_cached_passwords_for_tests(keyname: &str) {
    FALLBACK_KEYRING
        .lock()
        .expect("fallback keyring mutex poisoned")
        .remove(keyname);
}

pub fn add_to_keyring(
    keyname: &str,
    flags: AskPasswordFlags,
    passwords: &[String],
) -> AskPasswordResult<bool> {
    if !flags.contains(AskPasswordFlags::PUSH_CACHE) || passwords.is_empty() {
        return Ok(false);
    }

    let timeout = keyring_cache_timeout();
    if timeout.is_zero() {
        return Ok(false);
    }

    let mut merged = match ask_password_keyring(
        &AskPasswordRequest {
            keyring: Some(keyname.to_string()),
            ..Default::default()
        },
        AskPasswordFlags::ACCEPT_CACHED,
    ) {
        Ok(existing) => existing,
        Err(AskPasswordError::NoKey | AskPasswordError::NotSupported) => Vec::new(),
        Err(error) => return Err(error),
    };

    let mut seen = BTreeSet::new();
    let mut deduplicated = Vec::new();
    for password in merged.drain(..).chain(passwords.iter().cloned()) {
        if seen.insert(password.clone()) {
            deduplicated.push(password);
        }
    }
    if deduplicated.is_empty() {
        return Ok(false);
    }

    let payload = make_nulstr(&deduplicated);
    let changed = deduplicated
        != ask_password_keyring(
            &AskPasswordRequest {
                keyring: Some(keyname.to_string()),
                ..Default::default()
            },
            AskPasswordFlags::ACCEPT_CACHED,
        )
        .unwrap_or_default();

    match add_key_payload(keyname, &payload, keyring_cache_type()) {
        Ok(serial) => {
            if timeout != Duration::MAX {
                let _ = set_key_timeout(serial, timeout);
            }
        }
        Err(AskPasswordError::NotSupported) => {
            let _ = write_fallback_key(keyname, &deduplicated, timeout);
        }
        Err(error) => return Err(error),
    }

    let _ = touch_ask_password_directory(flags);
    Ok(changed)
}

pub fn add_to_keyring_and_log(
    keyname: &str,
    flags: AskPasswordFlags,
    passwords: &[String],
) -> AskPasswordResult<bool> {
    add_to_keyring(keyname, flags, passwords)
}

pub fn ask_password_keyring(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> AskPasswordResult<Vec<String>> {
    if !flags.contains(AskPasswordFlags::ACCEPT_CACHED) {
        return Err(AskPasswordError::NotAvailable);
    }

    let Some(keyname) = req.keyring.as_deref() else {
        return Err(AskPasswordError::NoKey);
    };

    match request_key_serial(keyname) {
        Ok(serial) => {
            let passwords = parse_nulstr(&read_key_payload(serial)?);
            if passwords.is_empty() {
                Err(AskPasswordError::NoKey)
            } else {
                Ok(passwords)
            }
        }
        Err(AskPasswordError::NoKey | AskPasswordError::NotSupported) => read_fallback_key(keyname),
        Err(AskPasswordError::Io(io::ErrorKind::PermissionDenied)) => Err(AskPasswordError::NoKey),
        Err(error) => Err(error),
    }
}

fn check_cache_again(req: &AskPasswordRequest, flags: AskPasswordFlags) -> Option<Vec<String>> {
    if flags.contains(AskPasswordFlags::ACCEPT_CACHED) && req.keyring.is_some() {
        ask_password_keyring(req, flags).ok()
    } else {
        None
    }
}

fn prompt_for_tty(fd: RawFd, message: &str, flags: AskPasswordFlags) {
    let _ = write_all_fd(fd, message.as_bytes());
    let _ = write_all_fd(fd, b" ");
    if !flags.contains(AskPasswordFlags::SILENT) && !flags.contains(AskPasswordFlags::ECHO) {
        let _ = write_all_fd(fd, PRESS_TAB.as_bytes());
    }
}

fn set_terminal_echo(fd: RawFd, enabled: bool) -> io::Result<Option<libc::termios>> {
    let mut termios = MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr initializes termios on success.
    if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } < 0 {
        return Ok(None);
    }

    // SAFETY: initialized above.
    let old = unsafe { termios.assume_init() };
    let mut new = old;
    if enabled {
        new.c_lflag |= libc::ECHO;
    } else {
        new.c_lflag &= !libc::ECHO;
    }
    // SAFETY: fd and termios pointer are valid.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &new) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(old))
}

fn restore_terminal(fd: RawFd, old: Option<libc::termios>) {
    if let Some(old) = old {
        // SAFETY: fd and previously obtained termios are valid.
        let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    }
}

fn ask_password_tty_on_fds(
    req: &AskPasswordRequest,
    mut flags: AskPasswordFlags,
    read_fd: RawFd,
    tty_fd: RawFd,
) -> AskPasswordResult<Vec<String>> {
    if flags.contains(AskPasswordFlags::HEADLESS) {
        return Err(AskPasswordError::NoExec);
    }
    if flags.contains(AskPasswordFlags::NO_TTY) {
        return Err(AskPasswordError::NotAvailable);
    }
    if let Some(passwords) = check_cache_again(req, flags) {
        return Ok(passwords);
    }

    let deadline = timeout_deadline(req);
    let message = default_message(req);
    let mut old_termios = None;
    let mut passphrase = Vec::<u8>::new();
    let mut dirty = false;
    let mut codepoint_start = 0usize;
    let mut press_tab_visible = false;

    if tty_fd >= 0 {
        prompt_for_tty(tty_fd, message, flags);
        press_tab_visible =
            !flags.contains(AskPasswordFlags::SILENT) && !flags.contains(AskPasswordFlags::ECHO);
        old_termios = set_terminal_echo(tty_fd, false).ok().flatten();
    }

    loop {
        check_flag_file(req)?;
        if let Some(passwords) = check_cache_again(req, flags) {
            if tty_fd >= 0 {
                let _ = write_all_fd(tty_fd, b"\n");
            }
            restore_terminal(tty_fd, old_termios);
            return Ok(passwords);
        }

        poll_readable(read_fd, req.hup_fd, deadline)?;
        let c = match read_one_byte(read_fd).map_err(AskPasswordError::from)? {
            Some(byte) => byte,
            None => break,
        };

        if press_tab_visible && tty_fd >= 0 {
            let _ = write_all_fd(tty_fd, &backspace_chars(backspace_string_count(PRESS_TAB)));
            press_tab_visible = false;
        }

        if c == b'\n' || c == 0 {
            break;
        }
        if c == 4 {
            if tty_fd >= 0 {
                let _ = write_all_fd(tty_fd, SKIPPED.as_bytes());
                let _ = write_all_fd(tty_fd, b"\n");
            }
            restore_terminal(tty_fd, old_termios);
            return Err(AskPasswordError::Canceled);
        }
        if c == 21 {
            if !flags.contains(AskPasswordFlags::SILENT) && tty_fd >= 0 {
                let _ = write_all_fd(
                    tty_fd,
                    &backspace_chars(backspace_string_count(&String::from_utf8_lossy(
                        &passphrase,
                    ))),
                );
            }
            passphrase.clear();
            codepoint_start = 0;
            continue;
        }
        if matches!(c, 8 | 127) {
            if !passphrase.is_empty() {
                if !flags.contains(AskPasswordFlags::SILENT) && tty_fd >= 0 {
                    let _ = write_all_fd(tty_fd, &backspace_chars(1));
                }
                passphrase.truncate(previous_char_boundary(&passphrase));
                codepoint_start = passphrase.len();
            } else if !dirty && !flags.contains(AskPasswordFlags::SILENT) {
                flags |= AskPasswordFlags::SILENT;
                if tty_fd >= 0 {
                    let _ = write_all_fd(tty_fd, NO_ECHO.as_bytes());
                }
            } else if tty_fd >= 0 {
                let _ = write_all_fd(tty_fd, b"\x07");
            }
            continue;
        }
        if c == b'\t' && !flags.contains(AskPasswordFlags::SILENT) {
            if tty_fd >= 0 {
                let _ = write_all_fd(
                    tty_fd,
                    &backspace_chars(backspace_string_count(&String::from_utf8_lossy(
                        &passphrase,
                    ))),
                );
                let _ = write_all_fd(tty_fd, NO_ECHO.as_bytes());
            }
            flags |= AskPasswordFlags::SILENT;
            continue;
        }
        if c.is_ascii_control() || passphrase.len() >= LINE_MAX {
            if tty_fd >= 0 {
                let _ = write_all_fd(tty_fd, b"\x07");
            }
            continue;
        }

        passphrase.push(c);
        if !flags.contains(AskPasswordFlags::SILENT) && tty_fd >= 0 {
            let pending = &passphrase[codepoint_start..];
            if let Ok(text) = std::str::from_utf8(pending) {
                if let Some(ch) = text.chars().next() {
                    if ch.len_utf8() == pending.len() {
                        if flags.contains(AskPasswordFlags::ECHO) {
                            let _ = write_all_fd(tty_fd, pending);
                        } else {
                            let _ = write_all_fd(tty_fd, "•".as_bytes());
                        }
                        codepoint_start = passphrase.len();
                    }
                }
            }
        }
        dirty = true;
    }

    if tty_fd >= 0 {
        let _ = write_all_fd(tty_fd, b"\n");
    }
    restore_terminal(tty_fd, old_termios);

    let password = String::from_utf8_lossy(&passphrase).into_owned();
    let result = vec![password];
    if let Some(keyname) = &req.keyring {
        let _ = add_to_keyring_and_log(keyname, flags, &result);
    }
    Ok(result)
}

pub fn ask_password_tty(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> AskPasswordResult<Vec<String>> {
    let owned_tty = if req.tty_fd < 0 {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
            .open("/dev/tty")
            .ok()
    } else {
        None
    };

    let tty_fd = owned_tty.as_ref().map_or(req.tty_fd, AsRawFd::as_raw_fd);
    let read_fd = if tty_fd >= 0 {
        tty_fd
    } else {
        libc::STDIN_FILENO
    };
    ask_password_tty_on_fds(req, flags, read_fd, tty_fd)
}

fn plymouth_socket_path() -> PathBuf {
    env::var_os("SYSTEMD_ASK_PASSWORD_PLYMOUTH_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/plymouth/pid1"))
}

fn plymouth_read_packet(
    stream: &mut UnixStream,
    req: &AskPasswordRequest,
    deadline: Option<Instant>,
) -> AskPasswordResult<Vec<String>> {
    let mut buffer = Vec::new();

    loop {
        check_flag_file(req)?;
        poll_readable(stream.as_raw_fd(), req.hup_fd, deadline)?;

        let mut chunk = [0u8; LINE_MAX];
        let n = stream.read(&mut chunk).map_err(AskPasswordError::from)?;
        if n == 0 {
            return Err(AskPasswordError::Io(io::ErrorKind::UnexpectedEof));
        }
        buffer.extend_from_slice(&chunk[..n]);

        match buffer.first().copied() {
            Some(5) => return Err(AskPasswordError::NoKey),
            Some(2 | 9) if buffer.len() >= 5 => {
                let size =
                    u32::from_le_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
                if size + 5 > LINE_MAX {
                    return Err(AskPasswordError::Io(io::ErrorKind::InvalidData));
                }
                if buffer.len() < size + 5 {
                    continue;
                }

                let passwords = parse_nulstr(&buffer[5..5 + size]);
                if passwords.is_empty() {
                    return Err(AskPasswordError::Canceled);
                }
                return Ok(passwords);
            }
            Some(_) => return Err(AskPasswordError::Io(io::ErrorKind::InvalidData)),
            None => continue,
        }
    }
}

pub fn ask_password_plymouth(
    req: &AskPasswordRequest,
    mut flags: AskPasswordFlags,
) -> AskPasswordResult<Vec<String>> {
    if flags.contains(AskPasswordFlags::HEADLESS) {
        return Err(AskPasswordError::NoExec);
    }

    let message = default_message(req);
    let prompt_packet = plymouth_prompt_packet(message)?;
    let mut stream = UnixStream::connect(plymouth_socket_path()).map_err(AskPasswordError::from)?;
    let deadline = timeout_deadline(req);

    if flags.contains(AskPasswordFlags::ACCEPT_CACHED) {
        stream.write_all(b"c\0").map_err(AskPasswordError::from)?;
        match plymouth_read_packet(&mut stream, req, deadline) {
            Ok(passwords) => return Ok(passwords),
            Err(AskPasswordError::NoKey) => flags.remove(AskPasswordFlags::ACCEPT_CACHED),
            Err(error) => return Err(error),
        }
    }

    stream
        .write_all(&prompt_packet)
        .map_err(AskPasswordError::from)?;
    match plymouth_read_packet(&mut stream, req, deadline) {
        Err(AskPasswordError::NoKey) if !flags.contains(AskPasswordFlags::ACCEPT_CACHED) => {
            Err(AskPasswordError::NoEnt)
        }
        other => other,
    }
}

/// Build a Plymouth ask-for-password packet.
///
/// The protocol stores the NUL-terminated prompt length in one byte.
fn plymouth_prompt_packet(message: &str) -> AskPasswordResult<Vec<u8>> {
    let length = message
        .len()
        .checked_add(1)
        .ok_or(AskPasswordError::Io(io::ErrorKind::InvalidInput))?;
    let length =
        u8::try_from(length).map_err(|_| AskPasswordError::Io(io::ErrorKind::InvalidInput))?;

    let mut packet = Vec::with_capacity(3 + message.len() + 1);
    packet.extend_from_slice(&[b'*', 0x02, length]);
    packet.extend_from_slice(message.as_bytes());
    packet.push(0);
    Ok(packet)
}

pub fn create_socket(askpwdir: &Path) -> AskPasswordResult<(OwnedFd, PathBuf)> {
    fs::create_dir_all(askpwdir).map_err(AskPasswordError::from)?;
    let path = askpwdir.join(format!("sck.{:x}", unique_u64()));

    // SAFETY: socket returns a new file descriptor on success.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return errno_result();
    }
    // SAFETY: fd is owned here and valid on success path above.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let one: i32 = 1;
    // SAFETY: setsockopt only reads the provided integer option value.
    if unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PASSCRED,
            (&one as *const i32).cast::<c_void>(),
            mem::size_of_val(&one) as libc::socklen_t,
        )
    } < 0
    {
        return errno_result();
    }

    // SAFETY: zeroed sockaddr_un is a valid starting state.
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(AskPasswordError::Io(io::ErrorKind::InvalidInput));
    }
    for (index, byte) in bytes.iter().enumerate() {
        addr.sun_path[index] = *byte as libc::c_char;
    }

    let len = (mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: addr contains a valid pathname sockaddr_un.
    if unsafe {
        libc::bind(
            owned.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            len,
        )
    } < 0
    {
        return errno_result();
    }

    Ok((owned, path))
}

struct PathCleanup {
    path: PathBuf,
    armed: bool,
}

impl PathCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PathCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(target_os = "linux")]
struct SignalGuard {
    signalfd: OwnedFd,
    oldmask: libc::sigset_t,
}

#[cfg(target_os = "linux")]
impl SignalGuard {
    fn new() -> io::Result<Self> {
        // SAFETY: sigset_t is immediately initialized by libc functions below.
        let mut mask = unsafe { mem::zeroed::<libc::sigset_t>() };
        // SAFETY: pointers are valid.
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGINT);
            libc::sigaddset(&mut mask, libc::SIGTERM);
        }

        // SAFETY: output parameter is valid.
        let mut oldmask = unsafe { mem::zeroed::<libc::sigset_t>() };
        // SAFETY: pointers are valid.
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, &mut oldmask) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: signalfd returns a new descriptor on success.
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            // SAFETY: fd is newly created and owned here.
            signalfd: unsafe { OwnedFd::from_raw_fd(fd) },
            oldmask,
        })
    }

    fn fd(&self) -> RawFd {
        self.signalfd.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
impl Drop for SignalGuard {
    fn drop(&mut self) {
        // SAFETY: oldmask was returned by sigprocmask above.
        let _ =
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.oldmask, std::ptr::null_mut()) };
    }
}

#[cfg(not(target_os = "linux"))]
struct SignalGuard;

#[cfg(not(target_os = "linux"))]
impl SignalGuard {
    fn new() -> io::Result<Self> {
        Ok(Self)
    }

    fn fd(&self) -> RawFd {
        -1
    }
}

fn rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
    if dst.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    fs::rename(src, dst)
}

fn write_ask_file(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
    dir: &Path,
    socket_name: &Path,
) -> AskPasswordResult<PathBuf> {
    let final_name = format!("ask.{:x}", unique_u64());
    let temp_name = format!(".{final_name}.tmp");
    let temp_path = dir.join(temp_name);
    let final_path = dir.join(final_name);

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(AskPasswordError::from)?;

    writeln!(file, "[Ask]").map_err(AskPasswordError::from)?;
    writeln!(file, "PID={}", std::process::id()).map_err(AskPasswordError::from)?;
    writeln!(file, "Socket={}", socket_name.display()).map_err(AskPasswordError::from)?;
    writeln!(
        file,
        "AcceptCached={}",
        i32::from(flags.contains(AskPasswordFlags::ACCEPT_CACHED))
    )
    .map_err(AskPasswordError::from)?;
    writeln!(
        file,
        "Echo={}",
        i32::from(flags.contains(AskPasswordFlags::ECHO))
    )
    .map_err(AskPasswordError::from)?;
    writeln!(file, "NotAfter={}", req.until.map_or(0, |d| d.as_micros()))
        .map_err(AskPasswordError::from)?;
    writeln!(
        file,
        "Silent={}",
        i32::from(flags.contains(AskPasswordFlags::SILENT))
    )
    .map_err(AskPasswordError::from)?;
    if let Some(message) = &req.message {
        writeln!(file, "Message={message}").map_err(AskPasswordError::from)?;
    }
    if let Some(icon) = &req.icon {
        writeln!(file, "Icon={icon}").map_err(AskPasswordError::from)?;
    }
    if let Some(id) = &req.id {
        writeln!(file, "Id={id}").map_err(AskPasswordError::from)?;
    }
    file.flush().map_err(AskPasswordError::from)?;
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(AskPasswordError::from)?;
    drop(file);

    rename_noreplace(&temp_path, &final_path).map_err(AskPasswordError::from)?;
    Ok(final_path)
}

fn parse_agent_reply(data: &[u8]) -> AskPasswordResult<Vec<String>> {
    match data.first().copied() {
        Some(b'-') => Err(AskPasswordError::Canceled),
        Some(b'+') if data.len() == 1 => Ok(vec![String::new()]),
        Some(b'+') => {
            let passwords = parse_nulstr(&data[1..]);
            if passwords.is_empty() {
                Err(AskPasswordError::Io(io::ErrorKind::InvalidData))
            } else {
                Ok(passwords)
            }
        }
        _ => Err(AskPasswordError::Io(io::ErrorKind::InvalidData)),
    }
}

fn receive_agent_message(socket_fd: RawFd) -> AskPasswordResult<Option<Vec<String>>> {
    let mut payload = [0u8; LINE_MAX + 1];
    let mut cred_buf =
        [0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<crate::ffi::ucred>() as u32) } as usize];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<c_void>(),
        iov_len: payload.len(),
    };

    // SAFETY: zeroed msghdr is then fully initialized below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cred_buf.as_mut_ptr().cast::<c_void>();
    msg.msg_controllen = cred_buf.len() as _;

    // SAFETY: recvmsg writes into the provided payload/control buffers.
    let n = unsafe { libc::recvmsg(socket_fd, &mut msg, 0) };
    if n < 0 {
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Ok(None);
        }
        return Err(error.into());
    }
    if n == 0 {
        return Ok(None);
    }
    if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
        return Ok(None);
    }
    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
        return Ok(None);
    }

    let mut uid_ok = false;
    // SAFETY: msg contains control data written by recvmsg.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        // SAFETY: cmsg points to a cmsghdr inside msg_control.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == SCM_CREDENTIALS {
            // SAFETY: SCM_CREDENTIALS payload is crate::ffi::ucred.
            let ucred = unsafe { libc::CMSG_DATA(cmsg).cast::<crate::ffi::ucred>().read() };
            // SAFETY: getuid has no preconditions.
            uid_ok = ucred.uid == unsafe { libc::getuid() } || ucred.uid == 0;
            break;
        }
        // SAFETY: iteration over ancillary data produced by recvmsg.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    if !uid_ok {
        return Ok(None);
    }

    parse_agent_reply(&payload[..n as usize]).map(Some)
}

pub fn ask_password_agent(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> AskPasswordResult<Vec<String>> {
    if flags.contains(AskPasswordFlags::HEADLESS) {
        return Err(AskPasswordError::NoExec);
    }
    if flags.contains(AskPasswordFlags::NO_AGENT) {
        return Err(AskPasswordError::NotAvailable);
    }
    if req.flag_file.is_some() {
        return Err(AskPasswordError::NotSupported);
    }

    let Some(askpwdir) = get_ask_password_directory_for_flags(flags)? else {
        return Err(AskPasswordError::NoEnt);
    };
    fs::create_dir_all(&askpwdir).map_err(AskPasswordError::from)?;

    if let Some(passwords) = check_cache_again(req, flags) {
        return Ok(passwords);
    }

    let signal_guard = SignalGuard::new().map_err(AskPasswordError::from)?;
    let (socket_fd, socket_name) = create_socket(&askpwdir)?;
    let mut socket_cleanup = PathCleanup::new(socket_name.clone());
    let ask_file = write_ask_file(req, flags, &askpwdir, &socket_name)?;
    let mut ask_cleanup = PathCleanup::new(ask_file);
    let deadline = timeout_deadline(req);

    loop {
        if let Some(passwords) = check_cache_again(req, flags) {
            ask_cleanup.disarm();
            socket_cleanup.disarm();
            let _ = fs::remove_file(&ask_cleanup.path);
            let _ = fs::remove_file(&socket_cleanup.path);
            return Ok(passwords);
        }

        let mut pollfds = [
            libc::pollfd {
                fd: socket_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signal_guard.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: req.hup_fd,
                events: libc::POLLHUP,
                revents: 0,
            },
        ];
        let nfds = 1 + usize::from(signal_guard.fd() >= 0) + usize::from(req.hup_fd >= 0);
        let timeout = poll_timeout_ms(deadline);
        if timeout == 0 {
            return Err(AskPasswordError::Timeout);
        }

        // SAFETY: selected pollfd entries are initialized.
        let n = unsafe { libc::poll(pollfds.as_mut_ptr(), nfds as libc::nfds_t, timeout) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if n == 0 {
            return Err(AskPasswordError::Timeout);
        }

        if signal_guard.fd() >= 0 && (pollfds[1].revents & libc::POLLIN) != 0 {
            return Err(AskPasswordError::Interrupted);
        }

        let hup_index = if signal_guard.fd() >= 0 { 2 } else { 1 };
        if req.hup_fd >= 0 && (pollfds[hup_index].revents & libc::POLLHUP) != 0 {
            return Err(AskPasswordError::ConnReset);
        }
        if (pollfds[0].revents & libc::POLLIN) == 0 {
            continue;
        }

        match receive_agent_message(socket_fd.as_raw_fd())? {
            Some(passwords) => {
                if let Some(keyname) = &req.keyring {
                    let _ = add_to_keyring_and_log(keyname, flags, &passwords);
                }
                ask_cleanup.disarm();
                socket_cleanup.disarm();
                let _ = fs::remove_file(&ask_cleanup.path);
                let _ = fs::remove_file(&socket_cleanup.path);
                return Ok(passwords);
            }
            None => continue,
        }
    }
}

pub fn ask_password_credential(
    req: &AskPasswordRequest,
    _flags: AskPasswordFlags,
) -> AskPasswordResult<Vec<String>> {
    let Some(name) = req.credential.as_deref() else {
        return Err(AskPasswordError::NoKey);
    };

    let Some(directory) = env::var_os("CREDENTIALS_DIRECTORY") else {
        return Err(AskPasswordError::NoKey);
    };

    let data = match fs::read(PathBuf::from(directory).join(name)) {
        Ok(bytes) => bytes,
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound) => {
            return Err(AskPasswordError::NoKey);
        }
        Err(error) => return Err(error.into()),
    };

    let passwords = parse_nulstr(&data);
    if passwords.is_empty() {
        return Err(AskPasswordError::NoKey);
    }
    Ok(passwords)
}

pub fn isatty_safe(fd: RawFd) -> bool {
    if fd < 0 {
        return false;
    }
    // SAFETY: isatty only inspects the file descriptor.
    unsafe { libc::isatty(fd) != 0 }
}

pub fn ask_password_auto(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> AskPasswordResult<Vec<String>> {
    if !flags.contains(AskPasswordFlags::NO_CREDENTIAL) && req.credential.is_some() {
        match ask_password_credential(req, flags) {
            Ok(passwords) => return Ok(passwords),
            Err(AskPasswordError::NoKey) => {}
            Err(error) => return Err(error),
        }
    }

    if flags.contains(AskPasswordFlags::ACCEPT_CACHED)
        && req.keyring.is_some()
        && (flags.contains(AskPasswordFlags::NO_TTY) || !isatty_safe(libc::STDIN_FILENO))
        && flags.contains(AskPasswordFlags::NO_AGENT)
    {
        match ask_password_keyring(req, flags) {
            Ok(passwords) => return Ok(passwords),
            Err(AskPasswordError::NoKey) => {}
            Err(error) => return Err(error),
        }
    }

    if !flags.contains(AskPasswordFlags::NO_TTY) && isatty_safe(libc::STDIN_FILENO) {
        return ask_password_tty(req, flags);
    }
    if !flags.contains(AskPasswordFlags::NO_AGENT) {
        return ask_password_agent(req, flags);
    }
    Err(AskPasswordError::NotAvailable)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::tests::TestEnvironment;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::net::{UnixDatagram, UnixListener};
    use std::thread;
    use tempfile::TempDir;

    fn make_pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: pipe initializes both file descriptors on success.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // SAFETY: fds are freshly created and owned here.
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: fds are freshly created and owned here.
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        (read_fd, write_fd)
    }

    fn with_env_var<T>(key: &str, value: Option<&Path>, f: impl FnOnce() -> T) -> T {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        match value {
            Some(path) => environment.set(key, path),
            None => environment.remove(key),
        }
        f()
    }

    #[test]
    fn flags_match_header() {
        assert_eq!(AskPasswordFlags::ACCEPT_CACHED.bits(), 1 << 0);
        assert_eq!(AskPasswordFlags::PUSH_CACHE.bits(), 1 << 1);
        assert_eq!(AskPasswordFlags::ECHO.bits(), 1 << 2);
        assert_eq!(AskPasswordFlags::SILENT.bits(), 1 << 3);
        assert_eq!(AskPasswordFlags::NO_TTY.bits(), 1 << 4);
        assert_eq!(AskPasswordFlags::NO_AGENT.bits(), 1 << 5);
        assert_eq!(AskPasswordFlags::USER.bits(), 1 << 10);
    }

    #[test]
    fn keyring_type_parses_names_and_values() {
        assert_eq!(KeyringType::from_env_value("user"), Some(KeyringType::User));
        assert_eq!(
            KeyringType::from_env_value("group"),
            Some(KeyringType::Group)
        );
        assert_eq!(KeyringType::from_env_value("bogus"), None);
        assert_eq!(keyring_cache_type().serial(), KEY_SPEC_USER_KEYRING);
    }

    #[test]
    fn acquire_user_directory_returns_none_without_runtime_dir() {
        with_env_var("XDG_RUNTIME_DIR", None, || {
            assert_eq!(acquire_user_ask_password_directory().unwrap(), None);
        });
    }

    #[test]
    fn acquire_user_directory_uses_runtime_dir() {
        let dir = TempDir::new().unwrap();
        with_env_var("XDG_RUNTIME_DIR", Some(dir.path()), || {
            let path = acquire_user_ask_password_directory().unwrap().unwrap();
            assert!(path.ends_with("systemd/ask-password"));
        });
    }

    #[test]
    fn keyring_timeout_reads_environment() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.set("SYSTEMD_ASK_PASSWORD_KEYRING_TIMEOUT_SEC", "5");
        assert_eq!(keyring_cache_timeout(), Duration::from_secs(5));
    }

    #[test]
    fn parse_and_make_nulstr_roundtrip() {
        let values = vec!["alpha".to_string(), "beta".to_string()];
        let encoded = make_nulstr(&values);
        assert_eq!(parse_nulstr(&encoded), values);
    }

    #[test]
    fn backspace_helpers_work_for_unicode() {
        assert_eq!(backspace_string_count("🔒é"), 2);
        assert_eq!(backspace_chars(2), b"\x08 \x08\x08 \x08");
    }

    #[test]
    fn add_to_keyring_deduplicates() {
        clear_cached_passwords_for_tests("dedup");
        add_to_keyring("dedup", AskPasswordFlags::PUSH_CACHE, &["one".into()]).unwrap();
        assert!(!add_to_keyring("dedup", AskPasswordFlags::PUSH_CACHE, &["one".into()]).unwrap());
        let req = AskPasswordRequest {
            keyring: Some("dedup".into()),
            ..Default::default()
        };
        assert_eq!(
            ask_password_keyring(&req, AskPasswordFlags::ACCEPT_CACHED).unwrap(),
            vec!["one"]
        );
        clear_cached_passwords_for_tests("dedup");
    }

    #[test]
    fn ask_password_keyring_requires_accept_cached() {
        let req = AskPasswordRequest {
            keyring: Some("missing".into()),
            ..Default::default()
        };
        assert_eq!(
            ask_password_keyring(&req, AskPasswordFlags::empty()),
            Err(AskPasswordError::NotAvailable)
        );
    }

    #[test]
    fn ask_password_credential_reads_nulstr() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("pw"), b"one\0two").unwrap();
        with_env_var("CREDENTIALS_DIRECTORY", Some(dir.path()), || {
            let req = AskPasswordRequest {
                credential: Some("pw".into()),
                ..Default::default()
            };
            assert_eq!(
                ask_password_credential(&req, AskPasswordFlags::empty()).unwrap(),
                vec!["one", "two"]
            );
        });
    }

    #[test]
    fn ask_password_credential_missing_is_nokey() {
        let req = AskPasswordRequest {
            credential: Some("missing".into()),
            ..Default::default()
        };
        assert_eq!(
            ask_password_credential(&req, AskPasswordFlags::empty()),
            Err(AskPasswordError::NoKey)
        );
    }

    #[test]
    fn ask_password_tty_reads_password() {
        let (read_fd, write_fd) = make_pipe();
        let (tty_read, tty_write) = make_pipe();
        write_all_fd(write_fd.as_raw_fd(), b"secret\n").unwrap();
        drop(write_fd);
        let result = ask_password_tty_on_fds(
            &AskPasswordRequest::default(),
            AskPasswordFlags::ECHO,
            read_fd.as_raw_fd(),
            tty_write.as_raw_fd(),
        )
        .unwrap();
        assert_eq!(result, vec!["secret"]);
        drop(tty_write);
        let mut output = Vec::new();
        File::from(tty_read).read_to_end(&mut output).unwrap();
        assert!(String::from_utf8_lossy(&output).contains("Password:"));
    }

    #[test]
    fn ask_password_tty_handles_ctrl_u_and_backspace() {
        let (read_fd, write_fd) = make_pipe();
        let (_tty_read, tty_write) = make_pipe();
        write_all_fd(write_fd.as_raw_fd(), b"ab\x15xy\x7fz\n").unwrap();
        drop(write_fd);
        let result = ask_password_tty_on_fds(
            &AskPasswordRequest::default(),
            AskPasswordFlags::ECHO,
            read_fd.as_raw_fd(),
            tty_write.as_raw_fd(),
        )
        .unwrap();
        assert_eq!(result, vec!["xz"]);
    }

    #[test]
    fn ask_password_tty_ctrl_d_cancels() {
        let (read_fd, write_fd) = make_pipe();
        let (_tty_read, tty_write) = make_pipe();
        write_all_fd(write_fd.as_raw_fd(), b"\x04").unwrap();
        drop(write_fd);
        assert_eq!(
            ask_password_tty_on_fds(
                &AskPasswordRequest::default(),
                AskPasswordFlags::empty(),
                read_fd.as_raw_fd(),
                tty_write.as_raw_fd(),
            ),
            Err(AskPasswordError::Canceled)
        );
    }

    #[test]
    fn ask_password_tty_missing_flag_file_fails() {
        let (read_fd, _write_fd) = make_pipe();
        let (_tty_read, tty_write) = make_pipe();
        let req = AskPasswordRequest {
            flag_file: Some(PathBuf::from("/definitely/not/present")),
            ..Default::default()
        };
        assert_eq!(
            ask_password_tty_on_fds(
                &req,
                AskPasswordFlags::empty(),
                read_fd.as_raw_fd(),
                tty_write.as_raw_fd()
            ),
            Err(AskPasswordError::NoEnt)
        );
    }

    #[test]
    fn ask_password_tty_tab_switches_to_silent() {
        let (read_fd, write_fd) = make_pipe();
        let (tty_read, tty_write) = make_pipe();
        write_all_fd(write_fd.as_raw_fd(), b"ab\tcd\n").unwrap();
        drop(write_fd);
        let result = ask_password_tty_on_fds(
            &AskPasswordRequest::default(),
            AskPasswordFlags::empty(),
            read_fd.as_raw_fd(),
            tty_write.as_raw_fd(),
        )
        .unwrap();
        assert_eq!(result, vec!["abcd"]);
        drop(tty_write);
        let mut output = Vec::new();
        File::from(tty_read).read_to_end(&mut output).unwrap();
        assert!(String::from_utf8_lossy(&output).contains(NO_ECHO));
    }

    #[test]
    fn ask_password_plymouth_retries_after_cached_miss() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("plymouth.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut first = [0u8; 16];
            let n = stream.read(&mut first).unwrap();
            assert_eq!(&first[..n], b"c\0");
            stream.write_all(&[5]).unwrap();

            let mut second = [0u8; 64];
            let n = stream.read(&mut second).unwrap();
            assert!(second[..n].starts_with(b"*\x02"));

            let body = b"pw";
            let mut response = vec![2];
            response.extend_from_slice(&(body.len() as u32).to_le_bytes());
            response.extend_from_slice(body);
            stream.write_all(&response).unwrap();
        });

        with_env_var(
            "SYSTEMD_ASK_PASSWORD_PLYMOUTH_SOCKET",
            Some(&socket_path),
            || {
                let result = ask_password_plymouth(
                    &AskPasswordRequest::default(),
                    AskPasswordFlags::ACCEPT_CACHED,
                )
                .unwrap();
                assert_eq!(result, vec!["pw"]);
            },
        );
        handle.join().unwrap();
    }

    #[test]
    fn plymouth_prompt_packet_accepts_largest_encodable_message() {
        let message = "x".repeat((u8::MAX - 1) as usize);
        let packet = plymouth_prompt_packet(&message).unwrap();

        assert_eq!(packet[..3], [b'*', 0x02, u8::MAX]);
        assert_eq!(&packet[3..packet.len() - 1], message.as_bytes());
        assert_eq!(packet.last(), Some(&0));
    }

    #[test]
    fn plymouth_prompt_packet_rejects_oversize_message() {
        let message = "x".repeat(u8::MAX as usize);
        assert_eq!(
            plymouth_prompt_packet(&message),
            Err(AskPasswordError::Io(std::io::ErrorKind::InvalidInput))
        );
    }

    #[test]
    fn parse_agent_reply_handles_empty_password() {
        assert_eq!(parse_agent_reply(b"+").unwrap(), vec![String::new()]);
    }

    #[test]
    fn create_socket_creates_unique_path() {
        let dir = TempDir::new().unwrap();
        let (_fd, path) = create_socket(dir.path()).unwrap();
        assert!(path.exists());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ask_password_agent_rejects_flag_file_mode() {
        let req = AskPasswordRequest {
            flag_file: Some(PathBuf::from("/tmp/x")),
            ..Default::default()
        };
        assert_eq!(
            ask_password_agent(&req, AskPasswordFlags::empty()),
            Err(AskPasswordError::NotSupported)
        );
    }

    #[test]
    fn ask_password_agent_roundtrips_response() {
        let runtime = TempDir::new().unwrap();
        let ask_dir = runtime.path().join("systemd/ask-password");
        fs::create_dir_all(&ask_dir).unwrap();

        let worker_dir = ask_dir.clone();
        let handle = thread::spawn(move || {
            loop {
                let entries: Vec<_> = fs::read_dir(&worker_dir)
                    .unwrap()
                    .filter_map(Result::ok)
                    .collect();

                if let Some(ask) = entries
                    .iter()
                    .find(|entry| entry.file_name().to_string_lossy().starts_with("ask."))
                {
                    let text = fs::read_to_string(ask.path()).unwrap();
                    let socket = text
                        .lines()
                        .find_map(|line| line.strip_prefix("Socket="))
                        .unwrap();
                    let client = UnixDatagram::unbound().unwrap();
                    client.send_to(b"+secret", socket).unwrap();
                    break;
                }

                thread::sleep(Duration::from_millis(10));
            }
        });

        with_env_var("XDG_RUNTIME_DIR", Some(runtime.path()), || {
            let result =
                ask_password_agent(&AskPasswordRequest::default(), AskPasswordFlags::USER).unwrap();
            assert_eq!(result, vec!["secret"]);
        });
        handle.join().unwrap();
    }

    #[test]
    fn ask_password_auto_prefers_credentials() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("pw"), b"cred").unwrap();
        with_env_var("CREDENTIALS_DIRECTORY", Some(dir.path()), || {
            let req = AskPasswordRequest {
                credential: Some("pw".into()),
                ..Default::default()
            };
            let result =
                ask_password_auto(&req, AskPasswordFlags::NO_AGENT | AskPasswordFlags::NO_TTY)
                    .unwrap();
            assert_eq!(result, vec!["cred"]);
        });
    }

    #[test]
    fn ask_password_auto_uses_cached_key_when_noninteractive() {
        clear_cached_passwords_for_tests("auto-cache");
        add_to_keyring(
            "auto-cache",
            AskPasswordFlags::PUSH_CACHE,
            &["cached".to_string()],
        )
        .unwrap();

        let req = AskPasswordRequest {
            keyring: Some("auto-cache".into()),
            ..Default::default()
        };
        let result = ask_password_auto(
            &req,
            AskPasswordFlags::ACCEPT_CACHED | AskPasswordFlags::NO_TTY | AskPasswordFlags::NO_AGENT,
        )
        .unwrap();
        assert_eq!(result, vec!["cached"]);
        clear_cached_passwords_for_tests("auto-cache");
    }
}
