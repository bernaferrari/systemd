// SPDX-License-Identifier: LGPL-2.1-or-later

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use bitflags::bitflags;

pub const SOURCE_PATH: &str = "src/shared/ask-password-api.c";
pub const SOURCE_TEXT: &str = include_str!("../ask-password-api.c");

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskPasswordRequest {
    pub message: String,
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
            message: "Password:".to_string(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringType {
    Thread = -1,
    Process = -2,
    Session = -3,
    User = -4,
    UserSession = -5,
    Group = -6,
}

static MEMORY_CACHE: LazyLock<Mutex<HashMap<String, Vec<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn get_ask_password_directory_for_flags(flags: AskPasswordFlags) -> PathBuf {
    if flags.contains(AskPasswordFlags::USER) {
        if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
            return PathBuf::from(runtime_dir).join("systemd/ask-password");
        }
    }

    PathBuf::from("/run/systemd/ask-password")
}

pub fn touch_ask_password_directory(flags: AskPasswordFlags) -> io::Result<()> {
    let path = get_ask_password_directory_for_flags(flags);
    let directory = open_or_create_ask_password_directory(&path)?;
    touch_directory(&directory)
}

/// Open the final ask-password directory, creating it with C's `0755` mode if absent.
///
/// `open_mkdir()` in the C implementation creates only the final component. Keeping the
/// descriptor avoids a path re-resolution between creation and the timestamp update.
fn open_or_create_ask_password_directory(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY);

    match options.open(path) {
        Ok(directory) => Ok(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o755);
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            options.open(path)
        }
        Err(error) => Err(error),
    }
}

/// Update the descriptor's timestamps exactly as C's `touch_fd(..., USEC_INFINITY)` does.
fn touch_directory(directory: &fs::File) -> io::Result<()> {
    // SAFETY: `directory` owns a live descriptor for the just-opened directory. A null
    // timespec pointer is explicitly specified by futimens(3) to request the current time.
    let r = unsafe_ffi!(libc::futimens(directory.as_raw_fd(), std::ptr::null()));
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn keyring_cache_timeout() -> Duration {
    env::var("SYSTEMD_ASK_PASSWORD_KEYRING_TIMEOUT_SEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(150))
}

pub fn keyring_cache_type() -> KeyringType {
    let default = KeyringType::User;
    let env_val = match env::var("SYSTEMD_ASK_PASSWORD_KEYRING_TYPE") {
        Ok(v) => v,
        Err(_) => return default,
    };

    if let Ok(id) = env_val.parse::<i32>() {
        if id >= 0 {
            return default;
        }
        return match id {
            -1 => KeyringType::Thread,
            -2 => KeyringType::Process,
            -3 => KeyringType::Session,
            -4 => KeyringType::User,
            -5 => KeyringType::UserSession,
            -6 => KeyringType::Group,
            _ => default,
        };
    }

    match env_val.to_lowercase().as_str() {
        "thread" => KeyringType::Thread,
        "process" => KeyringType::Process,
        "session" => KeyringType::Session,
        "user" => KeyringType::User,
        "user-session" => KeyringType::UserSession,
        "group" => KeyringType::Group,
        _ => default,
    }
}

pub fn add_to_keyring(
    keyname: &str,
    flags: AskPasswordFlags,
    passwords: &[String],
) -> io::Result<bool> {
    if !flags.contains(AskPasswordFlags::PUSH_CACHE) || passwords.is_empty() {
        return Ok(false);
    }

    if keyring_cache_timeout().is_zero() {
        return Ok(false);
    }

    let mut cache = MEMORY_CACHE
        .lock()
        .expect("ask-password cache mutex poisoned");
    let cached = cache.entry(keyname.to_string()).or_default();
    for password in passwords {
        if !cached.contains(password) {
            cached.push(password.clone());
        }
    }

    // The C implementation treats this as a best-effort notification after the cache
    // update, so a failure to touch the directory must not discard the cached password.
    let _ = touch_ask_password_directory(flags);
    Ok(true)
}

pub fn add_to_keyring_and_log(
    keyname: &str,
    flags: AskPasswordFlags,
    passwords: &[String],
) -> io::Result<bool> {
    add_to_keyring(keyname, flags, passwords)
}

pub fn retrieve_from_cache(keyname: &str) -> Vec<String> {
    MEMORY_CACHE
        .lock()
        .expect("ask-password cache mutex poisoned")
        .get(keyname)
        .cloned()
        .unwrap_or_default()
}

pub fn ask_password_keyring(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> io::Result<Vec<String>> {
    if !flags.contains(AskPasswordFlags::ACCEPT_CACHED) {
        return Err(io::Error::from_raw_os_error(libc::EUNATCH));
    }

    let keyring = req
        .keyring
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no keyring name specified"))?;

    let cached = retrieve_from_cache(keyring);
    if !cached.is_empty() {
        return Ok(cached);
    }

    Err(io::Error::from_raw_os_error(libc::ENOKEY))
}

/// Fill complete three-byte backspace sequences, up to the supplied buffer capacity.
///
/// The C helper allocates `3 * count` bytes itself. This safe slice-based equivalent
/// deliberately stops at the available complete sequences rather than panicking on a
/// shorter caller buffer.
pub fn backspace_chars(buf: &mut [u8], count: usize) {
    for slot in buf.chunks_exact_mut(3).take(count) {
        slot.copy_from_slice(b"\x08 \x08");
    }
}

pub fn backspace_string(s: &str) -> usize {
    let len = s.chars().count();
    if len == 0 { 0 } else { len }
}

pub fn acquire_user_ask_password_directory() -> io::Result<PathBuf> {
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(runtime_dir).join("systemd/ask-password");
        Ok(dir)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "XDG_RUNTIME_DIR not set",
        ))
    }
}

pub fn create_socket(askpwdir: &Path) -> io::Result<UnixDatagram> {
    let socket = UnixDatagram::bind(askpwdir.join("sck.rust"))?;
    Ok(socket)
}

/// Translate the compatibility facade's request into the implementation request.
///
/// The facade predates `ask_password_agent`, but it is still the public API used by
/// the cryptsetup Rust ports. Keeping this conversion in one place lets the facade
/// retain its stable, non-optional prompt while the protocol implementation follows
/// C's nullable `message` field.
fn agent_request(req: &AskPasswordRequest) -> crate::ask_password_agent::AskPasswordRequest {
    crate::ask_password_agent::AskPasswordRequest {
        message: Some(req.message.clone()),
        keyring: req.keyring.clone(),
        icon: req.icon.clone(),
        id: req.id.clone(),
        credential: req.credential.clone(),
        flag_file: req.flag_file.clone(),
        tty_fd: req.tty_fd,
        hup_fd: req.hup_fd,
        until: req.until,
    }
}

/// The two modules deliberately use distinct bitflag types, so converting by the
/// shared C bit representation avoids maintaining a second list of flag mappings.
fn agent_flags(flags: AskPasswordFlags) -> crate::ask_password_agent::AskPasswordFlags {
    crate::ask_password_agent::AskPasswordFlags::from_bits_retain(flags.bits())
}

/// Preserve the facade's `io::Result` contract at the boundary to the richer
/// implementation. The explicit mappings are the errno values returned by the C
/// entry points; `Io` retains its original Rust error kind.
fn agent_error(error: crate::ask_password_agent::AskPasswordError) -> io::Error {
    let errno = match error {
        crate::ask_password_agent::AskPasswordError::Timeout => libc::ETIME,
        crate::ask_password_agent::AskPasswordError::NotAvailable => libc::EUNATCH,
        crate::ask_password_agent::AskPasswordError::NoEnt => libc::ENOENT,
        crate::ask_password_agent::AskPasswordError::Canceled => libc::ECANCELED,
        crate::ask_password_agent::AskPasswordError::Interrupted => libc::EINTR,
        crate::ask_password_agent::AskPasswordError::NoExec => libc::ENOEXEC,
        crate::ask_password_agent::AskPasswordError::ConnReset => libc::ECONNRESET,
        crate::ask_password_agent::AskPasswordError::NotSupported => libc::EOPNOTSUPP,
        crate::ask_password_agent::AskPasswordError::NoKey => libc::ENOKEY,
        crate::ask_password_agent::AskPasswordError::Io(kind) => return io::Error::from(kind),
    };
    io::Error::from_raw_os_error(errno)
}

pub fn ask_password_agent(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> io::Result<Vec<String>> {
    crate::ask_password_agent::ask_password_agent(&agent_request(req), agent_flags(flags))
        .map_err(agent_error)
}

pub fn ask_password_tty(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> io::Result<Vec<String>> {
    crate::ask_password_agent::ask_password_tty(&agent_request(req), agent_flags(flags))
        .map_err(agent_error)
}

pub fn ask_password_plymouth(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> io::Result<Vec<String>> {
    crate::ask_password_agent::ask_password_plymouth(&agent_request(req), agent_flags(flags))
        .map_err(agent_error)
}

pub fn ask_password_credential(
    req: &AskPasswordRequest,
    _flags: AskPasswordFlags,
) -> io::Result<Vec<String>> {
    let cred_name = req
        .credential
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no credential specified"))?;

    // Reuse the shared credential capability: it validates the name, pins the
    // directory FD, and bounds the read instead of allowing an absolute or
    // traversal path to escape $CREDENTIALS_DIRECTORY.
    let data = match crate::creds_util::read_credential(cred_name) {
        Ok(data) => data,
        Err(error) if error == -libc::ENXIO || error == -libc::ENOENT => {
            return Err(io::Error::from_raw_os_error(libc::ENOKEY));
        }
        Err(error) => return Err(io::Error::from_raw_os_error(-error)),
    };

    let passwords = parse_nulstr(data.as_ref());

    if passwords.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOKEY));
    }

    Ok(passwords)
}

pub fn ask_password_auto(
    req: &AskPasswordRequest,
    flags: AskPasswordFlags,
) -> io::Result<Vec<String>> {
    if !flags.contains(AskPasswordFlags::NO_CREDENTIAL) && req.credential.is_some() {
        match ask_password_credential(req, flags) {
            Ok(result) => return Ok(result),
            Err(error) if error.raw_os_error() == Some(libc::ENOKEY) => {}
            Err(error) => return Err(error),
        }
    }

    if flags.contains(AskPasswordFlags::ACCEPT_CACHED)
        && req.keyring.is_some()
        && (flags.contains(AskPasswordFlags::NO_TTY) || !isatty_safe(libc::STDIN_FILENO))
        && flags.contains(AskPasswordFlags::NO_AGENT)
    {
        match ask_password_keyring(req, flags) {
            Ok(result) => return Ok(result),
            Err(error) if error.raw_os_error() == Some(libc::ENOKEY) => {}
            Err(error) => return Err(error),
        }
    }

    if !flags.contains(AskPasswordFlags::NO_TTY) && isatty_safe(libc::STDIN_FILENO) {
        return ask_password_tty(req, flags);
    }

    if !flags.contains(AskPasswordFlags::NO_AGENT) {
        return ask_password_agent(req, flags);
    }

    Err(io::Error::from_raw_os_error(libc::EUNATCH))
}

fn isatty_safe(fd: RawFd) -> bool {
    if fd < 0 {
        return false;
    }
    // SAFETY: isatty(3) only inspects this borrowed file-descriptor number and
    // does not retain it or dereference Rust memory.
    unsafe_ffi!(libc::isatty(fd) != 0)
}

pub fn source_lines() -> usize {
    SOURCE_TEXT.lines().count()
}

pub fn parse_nulstr(data: &[u8]) -> Vec<String> {
    data.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::tests::TestEnvironment;

    #[test]
    fn source_is_embedded() {
        assert!(!super::SOURCE_TEXT.is_empty());
    }

    #[test]
    fn source_lines_count() {
        assert!(source_lines() > 1000);
    }

    #[test]
    fn flags_default_empty() {
        let flags = AskPasswordFlags::empty();
        assert!(flags.is_empty());
        assert!(!flags.contains(AskPasswordFlags::USER));
    }

    #[test]
    fn flags_user_set() {
        let flags = AskPasswordFlags::USER;
        assert!(flags.contains(AskPasswordFlags::USER));
    }

    #[test]
    fn flags_push_cache_set() {
        let flags = AskPasswordFlags::PUSH_CACHE;
        assert!(flags.contains(AskPasswordFlags::PUSH_CACHE));
    }

    #[test]
    fn flags_combined() {
        let flags = AskPasswordFlags::USER | AskPasswordFlags::PUSH_CACHE;
        assert!(flags.contains(AskPasswordFlags::USER));
        assert!(flags.contains(AskPasswordFlags::PUSH_CACHE));
        assert!(!flags.contains(AskPasswordFlags::ACCEPT_CACHED));
    }

    #[test]
    fn get_ask_password_directory_system() {
        let dir = get_ask_password_directory_for_flags(AskPasswordFlags::empty());
        assert_eq!(dir, PathBuf::from("/run/systemd/ask-password"));
    }

    #[test]
    fn get_ask_password_directory_user() {
        let dir = get_ask_password_directory_for_flags(AskPasswordFlags::USER);
        assert!(dir.to_string_lossy().contains("ask-password"));
    }

    #[test]
    fn keyring_cache_timeout_default() {
        let timeout = keyring_cache_timeout();
        assert_eq!(timeout, Duration::from_secs(150));
    }

    #[test]
    fn keyring_cache_type_default() {
        assert_eq!(keyring_cache_type(), KeyringType::User);
    }

    #[test]
    fn add_and_retrieve_from_cache() {
        let key = "test-key-add-retrieve";
        // clear any previous test data
        MEMORY_CACHE.lock().unwrap().remove(key);

        let result = add_to_keyring(
            key,
            AskPasswordFlags::PUSH_CACHE,
            &["secret1".to_string(), "secret2".to_string()],
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        let cached = retrieve_from_cache(key);
        assert_eq!(cached, vec!["secret1", "secret2"]);

        // cleanup
        MEMORY_CACHE.lock().unwrap().remove(key);
    }

    #[test]
    fn add_to_keyring_no_push_cache() {
        let result = add_to_keyring(
            "test-no-push",
            AskPasswordFlags::empty(),
            &["secret".to_string()],
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn add_to_keyring_empty_passwords() {
        let result = add_to_keyring("test-empty-pw", AskPasswordFlags::PUSH_CACHE, &[]);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn retrieve_from_empty_cache() {
        let cached = retrieve_from_cache("nonexistent-key-xyz");
        assert!(cached.is_empty());
    }

    #[test]
    fn backspace_chars_produces_correct_sequence() {
        let mut buf = vec![0u8; 9];
        backspace_chars(&mut buf, 3);
        assert_eq!(&buf[..9], b"\x08 \x08\x08 \x08\x08 \x08");
    }

    #[test]
    fn backspace_chars_zero_count() {
        let mut buf = vec![0u8; 9];
        backspace_chars(&mut buf, 0);
        // nothing written
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn backspace_string_ascii() {
        assert_eq!(backspace_string("hello"), 5);
    }

    #[test]
    fn backspace_string_empty() {
        assert_eq!(backspace_string(""), 0);
    }

    #[test]
    fn backspace_string_unicode() {
        assert_eq!(backspace_string("café"), 4);
    }

    #[test]
    fn parse_nulstr_simple() {
        let data = b"hello\0world\0";
        let result = parse_nulstr(data);
        assert_eq!(result, vec!["hello", "world"]);
    }

    #[test]
    fn parse_nulstr_empty() {
        let data = b"";
        let result = parse_nulstr(data);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_nulstr_trailing_nul() {
        let data = b"hello\0";
        let result = parse_nulstr(data);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn parse_nulstr_only_nuls() {
        let data = b"\0\0\0";
        let result = parse_nulstr(data);
        assert!(result.is_empty());
    }

    #[test]
    fn request_default_values() {
        let req = AskPasswordRequest::default();
        assert_eq!(req.message, "Password:");
        assert!(req.keyring.is_none());
        assert!(req.icon.is_none());
        assert!(req.id.is_none());
        assert!(req.credential.is_none());
        assert!(req.flag_file.is_none());
        assert_eq!(req.tty_fd, -1);
        assert_eq!(req.hup_fd, -1);
        assert!(req.until.is_none());
    }

    #[test]
    fn ask_password_credential_no_credential_set() {
        let req = AskPasswordRequest::default();
        let result = ask_password_credential(&req, AskPasswordFlags::empty());
        assert!(result.is_err());
    }

    #[test]
    fn ask_password_keyring_no_accept_cached() {
        let req = AskPasswordRequest::default();
        let result = ask_password_keyring(&req, AskPasswordFlags::empty());
        assert!(result.is_err());
    }

    #[test]
    fn ask_password_keyring_no_keyring_name() {
        let req = AskPasswordRequest::default();
        let result = ask_password_keyring(&req, AskPasswordFlags::ACCEPT_CACHED);
        assert!(result.is_err());
    }

    #[test]
    fn add_and_retrieve_extend() {
        let key = "test-extend-key";
        MEMORY_CACHE.lock().unwrap().remove(key);

        let _ = add_to_keyring(key, AskPasswordFlags::PUSH_CACHE, &["first".to_string()]);
        let _ = add_to_keyring(key, AskPasswordFlags::PUSH_CACHE, &["second".to_string()]);

        let cached = retrieve_from_cache(key);
        assert!(cached.contains(&"first".to_string()));
        assert!(cached.contains(&"second".to_string()));

        MEMORY_CACHE.lock().unwrap().remove(key);
    }

    #[test]
    fn keyring_type_from_string() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.remove("SYSTEMD_ASK_PASSWORD_KEYRING_TYPE");
        assert_eq!(keyring_cache_type(), KeyringType::User);
    }

    #[test]
    fn flags_bit_positions_match_c_header() {
        assert_eq!(AskPasswordFlags::ACCEPT_CACHED.bits(), 1 << 0);
        assert_eq!(AskPasswordFlags::PUSH_CACHE.bits(), 1 << 1);
        assert_eq!(AskPasswordFlags::ECHO.bits(), 1 << 2);
        assert_eq!(AskPasswordFlags::SILENT.bits(), 1 << 3);
        assert_eq!(AskPasswordFlags::NO_TTY.bits(), 1 << 4);
        assert_eq!(AskPasswordFlags::NO_AGENT.bits(), 1 << 5);
        assert_eq!(AskPasswordFlags::CONSOLE_COLOR.bits(), 1 << 6);
        assert_eq!(AskPasswordFlags::NO_CREDENTIAL.bits(), 1 << 7);
        assert_eq!(AskPasswordFlags::HIDE_EMOJI.bits(), 1 << 8);
        assert_eq!(AskPasswordFlags::HEADLESS.bits(), 1 << 9);
        assert_eq!(AskPasswordFlags::USER.bits(), 1 << 10);
    }
}
