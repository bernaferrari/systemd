// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/hostname-setup.c, src/shared/hostname-setup.h
//
// Hostname setup and management utilities.
//
// Handles reading/writing /etc/hostname, setting the system hostname
// via the sethostname syscall, wildcard substitution for automatic
// hostname derivation from machine-id, and the main hostname_setup
// orchestration logic.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::*;
use std::ffi::CStr;
use std::fmt;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum length for a Linux hostname (64 chars, kernel buffer is 65 with NUL).
pub const LINUX_HOST_NAME_MAX: usize = 64;

/// Default fallback hostname used when no hostname is configured.
pub const FALLBACK_HOSTNAME: &str = "localhost";

/// Default path to the hostname configuration file.
pub const ETC_HOSTNAME_PATH: &str = "/etc/hostname";

/// Path written by hostnamed to indicate the hostname is the default.
pub const DEFAULT_HOSTNAME_HINT_PATH: &str = "/run/systemd/default-hostname";

/// Path to the machine-id file (primary).
const MACHINE_ID_PATH: &str = "/etc/machine-id";

/// Path to the machine-id file (fallback, for containers).
const MACHINE_ID_FALLBACK_PATH: &str = "/run/host/machine-id";

/// SipHash-2-4 key used for hostname wildcard substitution.
/// Matches SD_ID128_MAKE(98,10,ad,df,8d,7d,4f,b5,89,1b,4b,56,ac,c2,26,8f).
const WILDCARD_SIPHASH_KEY: [u8; 16] = [
    0x98, 0x10, 0xad, 0xdf, 0x8d, 0x7d, 0x4f, 0xb5, 0x89, 0x1b, 0x4b, 0x56, 0xac, 0xc2, 0x26, 0x8f,
];

// ── Enums ─────────────────────────────────────────────────────────────────

/// Source of a hostname configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum HostnameSource {
    /// Configured in /etc/hostname.
    Static = 0,
    /// Set transiently (e.g., via kernel command line or credential).
    Transient = 1,
    /// Automatically generated default.
    Default = 2,
}

impl HostnameSource {
    /// Convert to the string representation used in the string table.
    pub const fn to_str(self) -> &'static str {
        match self {
            HostnameSource::Static => "static",
            HostnameSource::Transient => "transient",
            HostnameSource::Default => "default",
        }
    }

    /// Parse from a string representation.
    #[expect(
        clippy::should_implement_trait,
        reason = "retain the C-parity inherent API alongside FromStr"
    )]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "static" => Some(HostnameSource::Static),
            "transient" => Some(HostnameSource::Transient),
            "default" => Some(HostnameSource::Default),
            _ => None,
        }
    }
}

impl std::str::FromStr for HostnameSource {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HostnameSource::from_str(s).ok_or(())
    }
}

impl fmt::Display for HostnameSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

/// Result of an idempotent sethostname operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SethostnameResult {
    /// Hostname was already set to the requested value (no change needed).
    AlreadySet,
    /// Hostname was changed (or would have been changed if `really` was false).
    Changed,
}

bitflags::bitflags! {
    /// Flags for [`gethostname_full`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GetHostnameFlags: u32 {
        /// Accept "localhost" and its variants as a valid hostname.
        const ALLOW_LOCALHOST  = 1 << 0;
        /// Fall back to the default hostname when the current one is unusable.
        const FALLBACK_DEFAULT = 1 << 1;
        /// Return only the short hostname (truncate at first dot).
        const SHORT            = 1 << 2;
    }
}

bitflags::bitflags! {
    /// Flags for [`hostname_is_valid`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ValidHostnameFlags: u32 {
        /// Allow a single trailing dot (FQDN notation).
        const TRAILING_DOT      = 1 << 0;
        /// Allow the special ".host" name.
        const DOT_HOST          = 1 << 1;
        /// Allow '?' wildcard characters.
        const QUESTION_MARK     = 1 << 2;
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from hostname operations.
#[derive(Debug)]
pub enum HostnameError {
    /// I/O error (file not found, permission denied, etc.).
    Io(io::Error),
    /// The hostname string fails validation.
    InvalidHostname(String),
    /// No hostname could be found (ENOENT / ENXIO).
    NotFound,
    /// Credential contents are malformed (EBADMSG).
    BadMessage(String),
    /// Name is unacceptably overlong even after shortening (EDOM).
    DomainError,
    /// Protocol-level error in IPC (EPROTO).
    ProtocolError,
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostnameError::Io(e) => write!(f, "I/O error: {e}"),
            HostnameError::InvalidHostname(s) => write!(f, "invalid hostname: {s}"),
            HostnameError::NotFound => write!(f, "hostname not found"),
            HostnameError::BadMessage(s) => write!(f, "bad hostname in credential: {s}"),
            HostnameError::DomainError => write!(f, "hostname is too long even after shortening"),
            HostnameError::ProtocolError => write!(f, "protocol error reading hostname"),
        }
    }
}

impl std::error::Error for HostnameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HostnameError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for HostnameError {
    fn from(e: io::Error) -> Self {
        HostnameError::Io(e)
    }
}

// ── Hostname validation ───────────────────────────────────────────────────

/// Check whether a character is a valid LDH (letter-digit-hyphen) character.
#[inline]
fn valid_ldh_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Validate a hostname string according to RFC 952 / RFC 1123.
///
/// Labels must consist only of LDH characters, must not start or end with
/// a hyphen, and must be separated by single dots. The overall length must
/// not exceed [`LINUX_HOST_NAME_MAX`].
pub fn hostname_is_valid(s: &str, flags: ValidHostnameFlags) -> bool {
    if s.is_empty() {
        return false;
    }

    if s.len() > LINUX_HOST_NAME_MAX {
        return false;
    }

    // Special case: ".host" is only valid with the DOT_HOST flag.
    if s == ".host" {
        return flags.contains(ValidHostnameFlags::DOT_HOST);
    }

    let mut n_dots: usize = 0;
    let mut at_dot = true; // start of string is like a dot boundary
    let mut at_hyphen = false;

    for c in s.chars() {
        match c {
            '.' => {
                if at_dot || at_hyphen {
                    return false;
                }
                at_dot = true;
                at_hyphen = false;
                n_dots += 1;
            }
            '-' => {
                if at_dot {
                    return false;
                }
                at_dot = false;
                at_hyphen = true;
            }
            '?' => {
                if !flags.contains(ValidHostnameFlags::QUESTION_MARK) {
                    return false;
                }
                at_dot = false;
                at_hyphen = false;
            }
            _ => {
                if !valid_ldh_char(c) {
                    return false;
                }
                at_dot = false;
                at_hyphen = false;
            }
        }
    }

    // Trailing dot is only valid with TRAILING_DOT and requires at least 2 dots
    // (i.e., at least two labels before the trailing dot: "a.b.").
    if at_dot {
        if n_dots < 2 || !flags.contains(ValidHostnameFlags::TRAILING_DOT) {
            return false;
        }
    }

    // Trailing hyphen is never valid.
    if at_hyphen {
        return false;
    }

    true
}

// ── Hostname cleanup ──────────────────────────────────────────────────────

/// Normalize a hostname string in-place.
///
/// Removes non-LDH characters, collapses consecutive dots, strips leading
/// dots and trailing hyphens/dots, and truncates to [`LINUX_HOST_NAME_MAX`].
pub fn hostname_cleanup(s: &mut String) {
    let mut result = String::with_capacity(s.len().min(LINUX_HOST_NAME_MAX));
    let mut at_dot = true;
    let mut at_hyphen = false;

    for c in s.chars() {
        if result.len() >= LINUX_HOST_NAME_MAX {
            break;
        }
        match c {
            '.' => {
                if at_dot || at_hyphen {
                    continue;
                }
                result.push('.');
                at_dot = true;
                at_hyphen = false;
            }
            '-' => {
                if at_dot {
                    continue;
                }
                result.push('-');
                at_dot = false;
                at_hyphen = true;
            }
            c if valid_ldh_char(c) || c == '?' => {
                result.push(c);
                at_dot = false;
                at_hyphen = false;
            }
            _ => continue,
        }
    }

    // Strip trailing hyphens and dots.
    while let Some(&last) = result.as_bytes().last() {
        if last == b'-' || last == b'.' {
            result.pop();
        } else {
            break;
        }
    }

    *s = result;
}

// ── Localhost detection ───────────────────────────────────────────────────

/// Check whether a hostname is a "localhost" variant.
///
/// Recognises `localhost`, `localhost.`, `localhost.localdomain`,
/// `localhost.localdomain.`, and any hostname ending in `.localhost`,
/// `.localhost.`, `.localhost.localdomain`, or `.localhost.localdomain.`.
/// Matching is case-insensitive.
pub fn is_localhost(hostname: &str) -> bool {
    let lower = hostname.to_ascii_lowercase();

    let exact = [
        "localhost",
        "localhost.",
        "localhost.localdomain",
        "localhost.localdomain.",
    ];
    if exact.contains(&lower.as_str()) {
        return true;
    }

    let suffixes = [
        ".localhost",
        ".localhost.",
        ".localhost.localdomain",
        ".localhost.localdomain.",
    ];
    suffixes.iter().any(|suf| lower.ends_with(suf))
}

// ── System hostname syscalls ──────────────────────────────────────────────

/// Retrieve the current system hostname via `uname(2)`.
fn sys_uname_nodename() -> io::Result<String> {
    let mut utsname = MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `utsname` points to writable, properly aligned storage for the
    // complete `libc::utsname` output struct.
    let ret = unsafe_ffi!(libc::uname(utsname.as_mut_ptr()));
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: a successful `uname(2)` initialized every field of the output
    // struct, including `nodename`.
    let utsname = unsafe_ffi!(utsname.assume_init());
    let nodename_bytes: Vec<u8> = utsname.nodename.iter().map(|&byte| byte as u8).collect();
    let nodename = CStr::from_bytes_until_nul(&nodename_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "uname(2) returned a hostname without a NUL terminator",
        )
    })?;
    Ok(nodename.to_string_lossy().into_owned())
}

/// Set the system hostname via `sethostname(2)`.
fn sys_sethostname(hostname: &[u8]) -> io::Result<()> {
    // SAFETY: `hostname` is a valid byte slice whose pointer remains readable
    // for exactly `hostname.len()` bytes throughout the syscall.
    let ret = unsafe_ffi!(libc::sethostname(
        hostname.as_ptr() as *const _,
        hostname.len()
    ));
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ── sethostname idempotent ────────────────────────────────────────────────

/// Set the system hostname, but only if it differs from the current value.
///
/// When `really` is `false`, the function checks whether a change *would* be
/// needed but does not actually call `sethostname(2)`.
///
/// Returns [`SethostnameResult::AlreadySet`] if the hostname already matches,
/// or [`SethostnameResult::Changed`] if it was (or would be) updated.
pub fn sethostname_idempotent_full(
    hostname: &str,
    really: bool,
) -> Result<SethostnameResult, HostnameError> {
    let current = sys_uname_nodename()?;
    if current == hostname {
        return Ok(SethostnameResult::AlreadySet);
    }
    if really {
        sys_sethostname(hostname.as_bytes())?;
    }
    Ok(SethostnameResult::Changed)
}

/// Equivalent to `sethostname_idempotent_full(hostname, true)`.
pub fn sethostname_idempotent(hostname: &str) -> Result<SethostnameResult, HostnameError> {
    sethostname_idempotent_full(hostname, true)
}

// ── Shorten overlong hostname ─────────────────────────────────────────────

/// Result of [`shorten_overlong`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShortenResult {
    /// Hostname was already valid — returned unchanged.
    Unchanged(String),
    /// Hostname was shortened (truncated at first dot and/or to max length).
    Shortened(String),
}

/// Shorten an overlong hostname to [`LINUX_HOST_NAME_MAX`] or to the first dot,
/// whichever comes earlier.
///
/// If the name is already valid it is returned unchanged. If shortening still
/// yields an invalid name, returns [`HostnameError::DomainError`].
pub fn shorten_overlong(s: &str) -> Result<ShortenResult, HostnameError> {
    if hostname_is_valid(s, ValidHostnameFlags::empty()) {
        return Ok(ShortenResult::Unchanged(s.to_string()));
    }

    // Truncate at first dot.
    let mut shortened = if let Some(dot_pos) = s.find('.') {
        s[..dot_pos].to_string()
    } else {
        s.to_string()
    };

    // Then truncate to max length.
    if shortened.len() > LINUX_HOST_NAME_MAX {
        shortened.truncate(LINUX_HOST_NAME_MAX);
    }

    if !hostname_is_valid(&shortened, ValidHostnameFlags::empty()) {
        return Err(HostnameError::DomainError);
    }

    Ok(ShortenResult::Shortened(shortened))
}

// ── SipHash-2-4 ───────────────────────────────────────────────────────────

/// A single SipHash round (used in both compression and finalization).
#[inline(always)]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Compute SipHash-2-4 over `msg` with the given 16-byte key.
fn siphash24(key: &[u8; 16], msg: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let (blocks, remainder) = msg.as_chunks::<8>();

    for block in blocks {
        let m = u64::from_le_bytes(*block);
        v3 ^= m;
        // c = 2 compression rounds
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    // Build the last word: remaining bytes in low positions, message length in top byte.
    let mut last = [0u8; 8];
    last[..remainder.len()].copy_from_slice(remainder);
    last[7] = (msg.len() & 0xff) as u8;
    let m = u64::from_le_bytes(last);

    v3 ^= m;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m;

    // Finalization: d = 4 rounds
    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

// ── Machine-id reading ────────────────────────────────────────────────────

/// Read the 128-bit machine-id from `/etc/machine-id` (falling back to
/// `/run/host/machine-id`). Returns the raw 16 bytes.
fn read_machine_id() -> Result<[u8; 16], HostnameError> {
    let content = match fs::read_to_string(MACHINE_ID_PATH) {
        Ok(c) => c,
        Err(_) => fs::read_to_string(MACHINE_ID_FALLBACK_PATH)?,
    };

    let hex = content.trim();
    if hex.len() != 32 {
        return Err(HostnameError::InvalidHostname(
            "machine-id has wrong length".into(),
        ));
    }

    let mut id = [0u8; 16];
    for i in 0..16 {
        id[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            HostnameError::InvalidHostname("machine-id contains non-hex characters".into())
        })?;
    }
    Ok(id)
}

// ── Wildcard substitution ─────────────────────────────────────────────────

/// Replace every `'?'` in `name` with a hex nibble derived from a SipHash of
/// the machine-id.
///
/// The machine-id is **not** used directly (it is not meant to be public),
/// but a SipHash-2-4 of the machine-id is used in counter mode to generate
/// one nibble (4 bits) per `'?'` character.
///
/// This is the public version that reads the machine-id from disk. For
/// deterministic testing, use [`hostname_substitute_wildcards_with_id`].
pub fn hostname_substitute_wildcards(name: &mut String) -> Result<(), HostnameError> {
    let mid = read_machine_id()?;
    hostname_substitute_wildcards_with_id(name, &mid);
    Ok(())
}

/// Deterministic version of [`hostname_substitute_wildcards`] that accepts
/// an explicit machine-id. Useful for testing.
pub fn hostname_substitute_wildcards_with_id(name: &mut String, machine_id: &[u8; 16]) {
    if !name.contains('?') {
        return;
    }

    let mut counter: u64 = 0;
    let mut h: u64 = 0;
    let mut left_bits: u32 = 0;

    let mut result = String::with_capacity(name.len());

    for c in name.chars() {
        if c == '?' {
            if left_bits == 0 {
                // Hash: machine_id (16 bytes LE) || counter (8 bytes LE) = 24 bytes.
                let mut msg = [0u8; 24];
                msg[..16].copy_from_slice(machine_id);
                msg[16..24].copy_from_slice(&counter.to_le_bytes());
                h = siphash24(&WILDCARD_SIPHASH_KEY, &msg);
                left_bits = 64;
                counter += 1;
            }
            result.push(hex_digit(h & 0xf));
            h >>= 4;
            left_bits -= 4;
        } else {
            result.push(c);
        }
    }

    *name = result;
}

/// Convert a 4-bit value to a lowercase hex character.
#[inline]
fn hex_digit(nibble: u64) -> char {
    let b = nibble as u8;
    if b < 10 {
        (b'0' + b) as char
    } else {
        (b'a' + b - 10) as char
    }
}

// ── Default hostname ──────────────────────────────────────────────────────

/// Read the default hostname from `/etc/hostname` (raw, before wildcard
/// substitution) and substitute wildcards. If that fails, return
/// [`FALLBACK_HOSTNAME`].
///
/// This is the Rust equivalent of `get_default_hostname()` in the C source.
pub fn get_default_hostname() -> Result<String, HostnameError> {
    let raw = match read_etc_hostname_raw() {
        Ok(r) => r,
        Err(_) => return Ok(FALLBACK_HOSTNAME.to_string()),
    };

    let mut hostname = raw;
    if hostname_substitute_wildcards(&mut hostname).is_err() {
        return Ok(FALLBACK_HOSTNAME.to_string());
    }

    Ok(hostname)
}

// ── /etc/hostname reading ─────────────────────────────────────────────────

/// Read the raw first non-empty, non-comment line from `/etc/hostname`
/// (or the file at `path`), without wildcard substitution or validation.
fn read_etc_hostname_raw() -> Result<String, HostnameError> {
    let content = fs::read_to_string(ETC_HOSTNAME_PATH)?;
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            return Ok(trimmed.to_string());
        }
    }
    Err(HostnameError::NotFound)
}

/// Read the hostname from `/etc/hostname` (or a custom path).
///
/// Reads the first non-empty, non-comment line. When `substitute_wildcards`
/// is true, `'?'` characters are replaced with hashed nibbles from the
/// machine-id before validation. The hostname is cleaned up and validated;
/// an empty file is treated as if it does not exist ([`HostnameError::NotFound`]).
pub fn read_etc_hostname(
    path: Option<&str>,
    substitute_wildcards: bool,
) -> Result<String, HostnameError> {
    let filepath = path.unwrap_or(ETC_HOSTNAME_PATH);
    let content = fs::read_to_string(filepath)?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut hostname = trimmed.to_string();

        if substitute_wildcards {
            hostname_substitute_wildcards(&mut hostname)?;
        }

        hostname_cleanup(&mut hostname);

        let valid_flags = ValidHostnameFlags::TRAILING_DOT
            | if substitute_wildcards {
                ValidHostnameFlags::empty()
            } else {
                ValidHostnameFlags::QUESTION_MARK
            };

        if !hostname_is_valid(&hostname, valid_flags) {
            return Err(HostnameError::BadMessage(hostname));
        }

        return Ok(hostname);
    }

    // Empty file → treat as ENOENT.
    Err(HostnameError::NotFound)
}

// ── Hostname source hint ──────────────────────────────────────────────────

/// Write (or remove) a file at [`DEFAULT_HOSTNAME_HINT_PATH`] indicating
/// whether the current hostname is the default.
///
/// When the source is [`HostnameSource::Default`], the hostname is written to
/// the hint file so that hostnamed can detect if the hostname was changed
/// out-of-band. For any other source, the hint file is removed.
pub fn hostname_update_source_hint(
    hostname: &str,
    source: HostnameSource,
) -> Result<(), HostnameError> {
    match source {
        HostnameSource::Default => {
            if let Some(parent) = Path::new(DEFAULT_HOSTNAME_HINT_PATH).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(DEFAULT_HOSTNAME_HINT_PATH, hostname)?;
        }
        _ => {
            // Best-effort removal.
            let _ = fs::remove_file(DEFAULT_HOSTNAME_HINT_PATH);
        }
    }
    Ok(())
}

// ── Kernel command line ───────────────────────────────────────────────────

/// Try to read the hostname from the kernel command line parameter
/// `systemd.hostname=`.
fn proc_cmdline_get_hostname() -> Result<Option<String>, HostnameError> {
    let content = match fs::read_to_string("/proc/cmdline") {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    for param in content.split_whitespace() {
        if let Some(value) = param.strip_prefix("systemd.hostname=") {
            if hostname_is_valid(value, ValidHostnameFlags::TRAILING_DOT) {
                return Ok(Some(value.to_string()));
            }
            // Invalid hostname on the kernel cmdline → ignore.
            return Ok(None);
        }
    }

    Ok(None)
}

// ── Credential reading ────────────────────────────────────────────────────

/// Try to acquire a hostname from the `system.hostname` credential.
///
/// Looks for the credential in standard mount paths. Returns `Ok(None)`
/// if no credential is available.
fn acquire_hostname_from_credential() -> Result<Option<String>, HostnameError> {
    let paths = [
        "/run/credentials/system.hostname",
        "/run/credentials/systemd-hostnamed.service/system.hostname",
    ];

    for path in &paths {
        if let Ok(content) = fs::read_to_string(path) {
            let hostname = content.trim().to_string();
            if hostname.is_empty() {
                continue;
            }
            if !hostname_is_valid(&hostname, ValidHostnameFlags::TRAILING_DOT) {
                return Err(HostnameError::BadMessage(hostname));
            }
            return Ok(Some(hostname));
        }
    }

    Ok(None)
}

// ── Initrd detection ──────────────────────────────────────────────────────

/// Simple heuristic to detect whether we are running in the initrd.
fn in_initrd() -> bool {
    Path::new("/run/initramfs").exists()
}

// ── Hostname setup (main orchestrator) ────────────────────────────────────

/// Set up the system hostname from the highest-priority source.
///
/// Priority order (mirrors the C implementation):
/// 1. Kernel command line (`systemd.hostname=`)
/// 2. `/etc/hostname` (with wildcard substitution)
/// 3. Encrypted credential (`system.hostname`)
/// 4. Current hostname via `uname(2)` (leave in place)
/// 5. Default hostname
///
/// When `really` is `false`, no actual `sethostname(2)` call is made
/// (dry-run mode).
pub fn hostname_setup(really: bool) -> Result<(), HostnameError> {
    let mut hostname: Option<String> = None;
    let mut source = HostnameSource::Default;

    // 1. Kernel command line.
    if let Ok(Some(hn)) = proc_cmdline_get_hostname() {
        hostname = Some(hn);
        source = HostnameSource::Transient;
    }

    // 2. /etc/hostname.
    if hostname.is_none() {
        match read_etc_hostname(None, true) {
            Ok(hn) => {
                hostname = Some(hn);
                source = HostnameSource::Static;
            }
            Err(HostnameError::NotFound) => {}
            Err(_) => {
                // Warning logged by caller; ignore.
            }
        }
    }

    // 3. Credential.
    if hostname.is_none() {
        if let Ok(Some(hn)) = acquire_hostname_from_credential() {
            hostname = Some(hn);
            source = HostnameSource::Transient;
        }
    }

    // 4. Current hostname via uname.
    if hostname.is_none() {
        match sys_uname_nodename() {
            Ok(current) if !current.is_empty() && current != "(none)" => {
                // No hostname configured — leave existing in place.
                hostname = Some(current);
                // source stays Default, we skip the sethostname below.
            }
            _ => {
                // uname failed or returned useless value.
            }
        }
    }

    // 5. Fall back to default.
    if hostname.is_none() {
        match get_default_hostname() {
            Ok(hn) => {
                hostname = Some(hn);
                source = HostnameSource::Default;
            }
            Err(_) => {
                hostname = Some(FALLBACK_HOSTNAME.to_string());
                source = HostnameSource::Default;
            }
        }
    }

    let hn = hostname.unwrap();

    // Apply the hostname if it actually needs changing.
    match sethostname_idempotent_full(&hn, really)? {
        SethostnameResult::AlreadySet => { /* already correct */ }
        SethostnameResult::Changed => { /* applied (or would apply) */ }
    }

    // Write the source hint file.
    if really {
        hostname_update_source_hint(&hn, source)?;
    }

    Ok(())
}

// ── gethostname_full ──────────────────────────────────────────────────────

/// Retrieve the current hostname, with optional transformations.
///
/// - `ALLOW_LOCALHOST`: accept "localhost" variants instead of rejecting them.
/// - `FALLBACK_DEFAULT`: if the hostname is empty / "(none)" / localhost (when
///   not allowed), substitute the default hostname.
/// - `SHORT`: return only the part before the first dot.
pub fn gethostname_full(flags: GetHostnameFlags) -> Result<String, HostnameError> {
    let nodename = sys_uname_nodename()?;

    let effective = if nodename.is_empty()
        || nodename == "(none)"
        || (!flags.contains(GetHostnameFlags::ALLOW_LOCALHOST) && is_localhost(&nodename))
        || (flags.contains(GetHostnameFlags::SHORT) && nodename.starts_with('.'))
    {
        if !flags.contains(GetHostnameFlags::FALLBACK_DEFAULT) {
            return Err(HostnameError::NotFound);
        }

        let fallback = get_default_hostname()?;
        if flags.contains(GetHostnameFlags::SHORT) && fallback.starts_with('.') {
            return Err(HostnameError::NotFound);
        }
        fallback
    } else {
        nodename
    };

    let result = if flags.contains(GetHostnameFlags::SHORT) {
        match effective.find('.') {
            Some(pos) => effective[..pos].to_string(),
            None => effective,
        }
    } else {
        effective
    };

    Ok(result)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── hostname_is_valid ──────────────────────────────────────────────

    #[test]
    fn test_hostname_valid_simple() {
        assert!(hostname_is_valid("myhost", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("my-host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("my-host-01", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("a", ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_valid_fqdn() {
        assert!(hostname_is_valid(
            "myhost.example.com",
            ValidHostnameFlags::empty()
        ));
        assert!(hostname_is_valid(
            "my-host.example.org",
            ValidHostnameFlags::empty()
        ));
    }

    #[test]
    fn test_hostname_valid_trailing_dot() {
        assert!(!hostname_is_valid(
            "example.com.",
            ValidHostnameFlags::empty()
        ));
        assert!(hostname_is_valid(
            "example.com.",
            ValidHostnameFlags::TRAILING_DOT
        ));
        // Single label with trailing dot → needs at least 2 dots.
        assert!(!hostname_is_valid(
            "host.",
            ValidHostnameFlags::TRAILING_DOT
        ));
        // Two labels with trailing dot → valid.
        assert!(hostname_is_valid("a.b.", ValidHostnameFlags::TRAILING_DOT));
    }

    #[test]
    fn test_hostname_valid_dot_host() {
        assert!(!hostname_is_valid(".host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(".host", ValidHostnameFlags::DOT_HOST));
    }

    #[test]
    fn test_hostname_valid_question_mark() {
        assert!(!hostname_is_valid("my??host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(
            "my??host",
            ValidHostnameFlags::QUESTION_MARK
        ));
    }

    #[test]
    fn test_hostname_invalid_empty_and_long() {
        assert!(!hostname_is_valid("", ValidHostnameFlags::empty()));
        let long = "a".repeat(65);
        assert!(!hostname_is_valid(&long, ValidHostnameFlags::empty()));
        let exact_max = "a".repeat(64);
        assert!(hostname_is_valid(&exact_max, ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_invalid_patterns() {
        assert!(!hostname_is_valid(
            ".example.com",
            ValidHostnameFlags::empty()
        )); // leading dot
        assert!(!hostname_is_valid("my..host", ValidHostnameFlags::empty())); // consecutive dots
        assert!(!hostname_is_valid("-myhost", ValidHostnameFlags::empty())); // leading hyphen
        assert!(!hostname_is_valid("myhost-", ValidHostnameFlags::empty())); // trailing hyphen
        assert!(!hostname_is_valid("my.-host", ValidHostnameFlags::empty())); // hyphen after dot
        assert!(!hostname_is_valid("my host", ValidHostnameFlags::empty())); // space
        assert!(!hostname_is_valid("my_host", ValidHostnameFlags::empty())); // underscore
    }

    // ── hostname_cleanup ───────────────────────────────────────────────

    #[test]
    fn test_cleanup_preserves_valid() {
        let mut s = String::from("my-host");
        hostname_cleanup(&mut s);
        assert_eq!(s, "my-host");
    }

    #[test]
    fn test_cleanup_strips_spaces_and_invalid() {
        let mut s = String::from("my host");
        hostname_cleanup(&mut s);
        assert_eq!(s, "myhost");
    }

    #[test]
    fn test_cleanup_collapses_dots() {
        let mut s = String::from("my..host");
        hostname_cleanup(&mut s);
        assert_eq!(s, "my.host");
    }

    #[test]
    fn test_cleanup_removes_leading_dot() {
        let mut s = String::from(".myhost");
        hostname_cleanup(&mut s);
        assert_eq!(s, "myhost");
    }

    #[test]
    fn test_cleanup_strips_trailing() {
        let mut s = String::from("myhost.");
        hostname_cleanup(&mut s);
        assert_eq!(s, "myhost");

        let mut s = String::from("myhost-");
        hostname_cleanup(&mut s);
        assert_eq!(s, "myhost");
    }

    #[test]
    fn test_cleanup_truncates_long() {
        let mut s = "a".repeat(200);
        hostname_cleanup(&mut s);
        assert_eq!(s.len(), LINUX_HOST_NAME_MAX);
    }

    // ── is_localhost ───────────────────────────────────────────────────

    #[test]
    fn test_localhost_exact_variants() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("localhost."));
        assert!(is_localhost("localhost.localdomain"));
        assert!(is_localhost("localhost.localdomain."));
    }

    #[test]
    fn test_localhost_case_insensitive() {
        assert!(is_localhost("LocalHost"));
        assert!(is_localhost("LOCALHOST"));
    }

    #[test]
    fn test_localhost_suffix_match() {
        assert!(is_localhost("my.localhost"));
        assert!(is_localhost("host.localhost.localdomain"));
        assert!(!is_localhost("myhost"));
        assert!(!is_localhost("example.com"));
    }

    // ── shorten_overlong ───────────────────────────────────────────────

    #[test]
    fn test_shorten_valid_passthrough() {
        let r = shorten_overlong("myhost").unwrap();
        assert_eq!(r, ShortenResult::Unchanged("myhost".to_string()));
    }

    #[test]
    fn test_shorten_at_dot() {
        let long = format!("{}.example.com", "a".repeat(100));
        let r = shorten_overlong(&long).unwrap();
        match r {
            ShortenResult::Shortened(s) => {
                assert!(s.len() <= LINUX_HOST_NAME_MAX);
                assert!(!s.contains('.'));
            }
            _ => panic!("expected Shortened"),
        }
    }

    #[test]
    fn test_shorten_truncates() {
        let long = "a".repeat(100);
        let r = shorten_overlong(&long).unwrap();
        match r {
            ShortenResult::Shortened(s) => {
                assert_eq!(s.len(), LINUX_HOST_NAME_MAX);
            }
            _ => panic!("expected Shortened"),
        }
    }

    #[test]
    fn test_shorten_invalid_after_truncate() {
        // Starts with hyphen → invalid even after truncation.
        let r = shorten_overlong(&"-".repeat(100));
        assert!(r.is_err());
    }

    // ── HostnameSource ─────────────────────────────────────────────────

    #[test]
    fn test_hostname_source_roundtrip() {
        for src in [
            HostnameSource::Static,
            HostnameSource::Transient,
            HostnameSource::Default,
        ] {
            let s = src.to_str();
            assert_eq!(HostnameSource::from_str(s), Some(src));
            assert_eq!(format!("{src}"), s);
        }
        assert_eq!(HostnameSource::from_str("bogus"), None);
        assert_eq!("static".parse(), Ok(HostnameSource::Static));
        assert_eq!("bogus".parse::<HostnameSource>(), Err(()));
    }

    #[test]
    fn test_hostname_source_repr_values() {
        assert_eq!(HostnameSource::Static as i32, 0);
        assert_eq!(HostnameSource::Transient as i32, 1);
        assert_eq!(HostnameSource::Default as i32, 2);
    }

    // ── SipHash-2-4 determinism ────────────────────────────────────────

    #[test]
    fn test_siphash24_deterministic() {
        let key = [0u8; 16];
        let msg = b"hello world";
        let h1 = siphash24(&key, msg);
        let h2 = siphash24(&key, msg);
        assert_eq!(h1, h2);
        // Different key → different hash.
        let mut key2 = [0u8; 16];
        key2[0] = 1;
        assert_ne!(h1, siphash24(&key2, msg));
    }

    #[test]
    fn test_siphash24_empty_message() {
        let key = WILDCARD_SIPHASH_KEY;
        let h = siphash24(&key, &[]);
        // Should not panic and should produce a value.
        assert_ne!(h, 0);
    }

    // ── Wildcard substitution ──────────────────────────────────────────

    #[test]
    fn test_wildcard_substitution_deterministic() {
        let mid = [0xAB; 16];
        let mut a = String::from("host-??");
        let mut b = String::from("host-??");
        hostname_substitute_wildcards_with_id(&mut a, &mid);
        hostname_substitute_wildcards_with_id(&mut b, &mid);
        assert_eq!(a, b);
        assert!(!a.contains('?'));
        assert_eq!(a.len(), 7); // "host-" (5) + 2 hex digits
    }

    #[test]
    fn test_wildcard_substitution_many_questions() {
        let mid = [0x42; 16];
        let mut name = String::from("????????????????"); // 16 '?'
        hostname_substitute_wildcards_with_id(&mut name, &mid);
        assert!(!name.contains('?'));
        assert_eq!(name.len(), 16);
        // All characters should be lowercase hex.
        assert!(name.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_wildcard_substitution_no_questions() {
        let mid = [0u8; 16];
        let mut name = String::from("plain-hostname");
        let original = name.clone();
        hostname_substitute_wildcards_with_id(&mut name, &mid);
        assert_eq!(name, original);
    }

    #[test]
    fn test_wildcard_substitution_counter_mode() {
        // The first 16 '?' should come from hash(mid || 0).
        // The next '?' should come from hash(mid || 1), which must differ.
        let mid = [0x55; 16];
        let mut name = String::from("?????????????????");
        hostname_substitute_wildcards_with_id(&mut name, &mid);
        // 17 '?' → first 16 from one hash, 17th from next.
        // Verify at least some differ (extremely unlikely all 17 are same char).
        let chars: Vec<char> = name.chars().collect();
        assert!(chars.windows(2).any(|w| w[0] != w[1]));
    }

    // ── read_etc_hostname ──────────────────────────────────────────────

    #[test]
    fn test_read_etc_hostname_missing() {
        let r = read_etc_hostname(Some("/nonexistent/path/hostname"), false);
        assert!(r.is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(LINUX_HOST_NAME_MAX, 64);
        assert_eq!(FALLBACK_HOSTNAME, "localhost");
        assert_eq!(ETC_HOSTNAME_PATH, "/etc/hostname");
    }

    // ── hex_digit ──────────────────────────────────────────────────────

    #[test]
    fn test_hex_digit() {
        assert_eq!(hex_digit(0), '0');
        assert_eq!(hex_digit(9), '9');
        assert_eq!(hex_digit(10), 'a');
        assert_eq!(hex_digit(15), 'f');
    }

    // ── GetHostnameFlags ───────────────────────────────────────────────

    #[test]
    fn test_get_hostname_flags() {
        let f = GetHostnameFlags::ALLOW_LOCALHOST | GetHostnameFlags::SHORT;
        assert!(f.contains(GetHostnameFlags::ALLOW_LOCALHOST));
        assert!(f.contains(GetHostnameFlags::SHORT));
        assert!(!f.contains(GetHostnameFlags::FALLBACK_DEFAULT));
    }

    // ── sethostname_idempotent_full (non-really) ───────────────────────

    #[test]
    fn test_sethostname_idempotent_non_really() {
        // With really=false, this should never call sethostname.
        let r = sethostname_idempotent_full("test-hostname-does-not-exist", false);
        assert!(r.is_ok());
        // It should report Changed since the current hostname almost certainly differs.
        assert_eq!(r.unwrap(), SethostnameResult::Changed);
    }
}
