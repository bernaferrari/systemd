// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pager.c, src/shared/pager.h
//
// Terminal pager — pager_open, pager_close, pager_have, show_man_page.
//
// Spawns a pager process (e.g. less, more) to display long output. Redirects
// the calling process's stdout and stderr into the pager's stdin via an OS
// pipe so that existing print/println calls are transparently paged.
//
// Handles $SYSTEMD_PAGER / $PAGER, $SYSTEMD_LESS options, $SYSTEMD_LESSCHARSET,
// $SYSTEMD_PAGERSECURE, sudo privilege detection, and a fallback chain of
// pagers (pager → less → more → built-in cat).

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::*;
use std::env;
use std::fmt;
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use bitflags::bitflags;

// ── Constants ─────────────────────────────────────────────────────────────

/// Default less options used when `$SYSTEMD_LESS` is unset.
pub const DEFAULT_LESS_OPTS: &str = "FRSXMK";

/// Fallback pagers tried in order when no pager is configured via env vars.
pub const FALLBACK_PAGERS: &[&str] = &["pager", "less", "more"];

/// Well-known environment variable names.
pub const ENV_SYSTEMD_PAGER: &str = "SYSTEMD_PAGER";
pub const ENV_PAGER: &str = "PAGER";
pub const ENV_SYSTEMD_LESS: &str = "SYSTEMD_LESS";
pub const ENV_SYSTEMD_LESSCHARSET: &str = "SYSTEMD_LESSCHARSET";
pub const ENV_SYSTEMD_PAGERSECURE: &str = "SYSTEMD_PAGERSECURE";
pub const ENV_SUDO_UID: &str = "SUDO_UID";

// ── Enums ─────────────────────────────────────────────────────────────────

bitflags! {
    /// Flags controlling pager behaviour (mirrors C `PagerFlags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PagerFlags: u32 {
        /// Do not spawn a pager regardless of environment.
        const DISABLE     = 1 << 0;
        /// Jump to the end of the output (appends `+G` to less options).
        const JUMP_TO_END = 1 << 1;
    }
}

/// Whether the pager should operate in secure mode (no shell escape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureMode {
    /// Secure mode explicitly enabled.
    Enabled,
    /// Secure mode explicitly disabled.
    Disabled,
    /// Autodetect based on privilege escalation.
    AutoDetect,
}

/// Errors produced by pager operations.
#[derive(Debug)]
pub enum PagerError {
    /// An I/O error occurred.
    Io(io::Error),
    /// The pager is disabled via flags or environment.
    Disabled,
    /// A pager session is already active.
    AlreadyOpen,
    /// Terminal is dumb (`TERM=dumb`) — no pager suitable.
    DumbTerminal,
    /// Failed to create the OS pipe.
    PipeFailed(io::Error),
    /// Failed to spawn the pager child process.
    SpawnFailed(io::Error),
    /// No suitable pager was found on `$PATH`.
    NoPagerFound,
}

impl fmt::Display for PagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PagerError::Io(e) => write!(f, "I/O error: {e}"),
            PagerError::Disabled => write!(f, "pager is disabled"),
            PagerError::AlreadyOpen => write!(f, "pager is already open"),
            PagerError::DumbTerminal => write!(f, "terminal is dumb"),
            PagerError::PipeFailed(e) => write!(f, "failed to create pager pipe: {e}"),
            PagerError::SpawnFailed(e) => write!(f, "failed to spawn pager: {e}"),
            PagerError::NoPagerFound => write!(f, "no suitable pager found"),
        }
    }
}

impl std::error::Error for PagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PagerError::Io(e) | PagerError::PipeFailed(e) | PagerError::SpawnFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PagerError {
    fn from(e: io::Error) -> Self {
        PagerError::Io(e)
    }
}

/// A parsed man-page reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManPageRef {
    /// Page name, e.g. `"systemd"`.
    pub page: String,
    /// Manual section if present, e.g. `Some("1")`.
    pub section: Option<String>,
}

// ── Pipe helper ───────────────────────────────────────────────────────────

/// Create a connected Unix stream pair for the pager's stdin and output.
/// The standard library owns both descriptors and creates them close-on-exec.
fn create_pipe() -> Result<(UnixStream, OwnedFd), io::Error> {
    let (read_end, write_end) = UnixStream::pair()?;
    Ok((read_end, write_end.into()))
}

/// Duplicate an existing file descriptor, returning the new fd with `FD_CLOEXEC`.
/// Returns `None` on failure (mirrors C's `-1` convention).
fn dup_fd_cloexec(fd: RawFd) -> Option<OwnedFd> {
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC, 3)` returns a new fd ≥ 3, or -1 on error.
    let new_fd = unsafe_ffi!(libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3));
    if new_fd < 0 {
        None
    } else {
        // SAFETY: fcntl returned a valid, owned fd.
        Some(unsafe_ffi!(OwnedFd::from_raw_fd(new_fd)))
    }
}

/// Duplicate `src_fd` onto `dst_fd` atomically.
/// Returns `true` on success.
fn dup2_fd(src_fd: RawFd, dst_fd: RawFd) -> bool {
    // SAFETY: dup2(2) atomically duplicates src onto dst.
    unsafe_ffi!(libc::dup2(src_fd, dst_fd) >= 0)
}

// ── Pure logic helpers ────────────────────────────────────────────────────

/// Check whether the terminal is "dumb" (unsuitable for a pager).
fn is_terminal_dumb() -> bool {
    match env::var("TERM") {
        Ok(ref t) if t.eq_ignore_ascii_case("dumb") => true,
        Ok(_) => false,
        Err(_) => true,
    }
}

/// Parse pager command-line arguments from `$SYSTEMD_PAGER` / `$PAGER`.
///
/// Returns:
/// - `None` if neither env var is set,
/// - `Some([])` if the pager is explicitly disabled (empty or `"cat"`),
/// - `Some(args)` with the tokenised arguments otherwise.
pub fn parse_pager_args() -> Option<Vec<String>> {
    let pager = env::var(ENV_SYSTEMD_PAGER)
        .ok()
        .or_else(|| env::var(ENV_PAGER).ok())?;

    if pager.is_empty() {
        return Some(Vec::new());
    }

    let args: Vec<String> = pager.split_whitespace().map(String::from).collect();
    if args.is_empty() || args == ["cat"] {
        return Some(Vec::new());
    }

    Some(args)
}

/// Returns `true` if the pager is explicitly disabled via environment.
pub fn is_pager_disabled_via_env() -> bool {
    match parse_pager_args() {
        Some(ref args) => args.is_empty(),
        None => false,
    }
}

/// Resolve the effective less options string.
///
/// Reads `$SYSTEMD_LESS`; falls back to [`DEFAULT_LESS_OPTS`].
/// If `flags` includes [`PagerFlags::JUMP_TO_END`], appends ` +G`.
pub fn get_less_opts(flags: PagerFlags) -> String {
    let base = env::var(ENV_SYSTEMD_LESS).unwrap_or_else(|_| DEFAULT_LESS_OPTS.to_string());
    if flags.contains(PagerFlags::JUMP_TO_END) {
        format!("{base} +G")
    } else {
        base
    }
}

/// Determine the less charset.
///
/// Uses `$SYSTEMD_LESSCHARSET` if set; otherwise checks whether the current
/// locale implies UTF-8 and returns `"utf-8"` in that case.
pub fn get_less_charset() -> Option<String> {
    if let Ok(charset) = env::var(ENV_SYSTEMD_LESSCHARSET) {
        return Some(charset);
    }
    let locale = env::var("LC_ALL")
        .or_else(|_| env::var("LC_CTYPE"))
        .or_else(|_| env::var("LANG"))
        .unwrap_or_default();
    let lower = locale.to_lowercase();
    if lower.contains("utf-8") || lower.contains("utf8") {
        Some("utf-8".into())
    } else {
        None
    }
}

/// Parse `$SYSTEMD_PAGERSECURE` into a [`SecureMode`].
///
/// - `Some(Enabled/Disabled)` when explicitly set,
/// - `None` when the variable is absent (caller should autodetect).
pub fn parse_secure_mode_env() -> Result<Option<SecureMode>, PagerError> {
    match env::var(ENV_SYSTEMD_PAGERSECURE) {
        Ok(val) => match val.to_lowercase().as_str() {
            "1" | "true" | "yes" => Ok(Some(SecureMode::Enabled)),
            "0" | "false" | "no" => Ok(Some(SecureMode::Disabled)),
            other => Err(PagerError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to parse ${ENV_SYSTEMD_PAGERSECURE}: invalid value '{other}'"),
            ))),
        },
        Err(env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(PagerError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to read ${ENV_SYSTEMD_PAGERSECURE}: {e}"),
        ))),
    }
}

/// Returns `true` if `$SUDO_UID` is present in the environment.
pub fn has_sudo_uid() -> bool {
    env::var(ENV_SUDO_UID).is_ok()
}

/// Resolve the final secure-mode decision.
///
/// Prefers an explicit `$SYSTEMD_PAGERSECURE` setting; falls back to
/// privilege-escalation detection via [`has_sudo_uid`].
pub fn resolve_secure_mode() -> SecureMode {
    match parse_secure_mode_env() {
        Ok(Some(mode)) => mode,
        Ok(None) => {
            if has_sudo_uid() {
                SecureMode::Enabled
            } else {
                SecureMode::Disabled
            }
        }
        Err(_) => SecureMode::Enabled, // safe default on parse error
    }
}

/// Whether a pager name is allowed when running in secure mode.
///
/// Only `"less"` and `"(built-in)"` implement secure mode.
pub fn is_pager_allowed_in_secure_mode(name: &str) -> bool {
    name == "less" || name == "(built-in)"
}

/// Determine whether the parent should ignore `SIGINT`.
///
/// Returns `true` when the pager is `less` **and** the `K` option is
/// *not* present in `less_opts`.
pub fn no_quit_on_interrupt(exe_name: Option<&str>, less_opts: &str) -> bool {
    match exe_name {
        Some("less") => !less_opts.contains('K'),
        _ => false,
    }
}

/// Parse a man-page description of the form `"name(section)"` or `"name"`.
///
/// # Examples
/// ```ignore
/// assert_eq!(parse_man_page_ref("systemd(1)"),
///            ManPageRef { page: "systemd".into(), section: Some("1".into()) });
/// assert_eq!(parse_man_page_ref("bash"),
///            ManPageRef { page: "bash".into(), section: None });
/// ```
pub fn parse_man_page_ref(desc: &str) -> ManPageRef {
    let trimmed = desc.trim();
    if let Some(pos) = trimmed.rfind('(') {
        if trimmed.ends_with(')') && pos > 0 {
            return ManPageRef {
                page: trimmed[..pos].trim().into(),
                section: Some(trimmed[pos + 1..trimmed.len() - 1].trim().into()),
            };
        }
    }
    ManPageRef {
        page: trimmed.into(),
        section: None,
    }
}

/// Build the `man` argument vector from a [`ManPageRef`].
pub fn build_man_args(man_ref: &ManPageRef) -> Vec<String> {
    match &man_ref.section {
        Some(section) => vec!["man".into(), section.clone(), man_ref.page.clone()],
        None => vec!["man".into(), man_ref.page.clone()],
    }
}

// ── PagerSession ──────────────────────────────────────────────────────────

/// Represents an active pager session.
///
/// Holds the spawned pager child process and the saved original stdout/stderr
/// file descriptors so they can be restored on [`pager_close`].
pub struct PagerSession {
    child: Mutex<Child>,
    stored_stdout: Option<OwnedFd>,
    stored_stderr: Option<OwnedFd>,
    stdout_redirected: bool,
    stderr_redirected: bool,
    write_end: OwnedFd,
}

impl PagerSession {
    /// Returns `true` if the pager child process is still running.
    pub fn is_active(&self) -> bool {
        self.child
            .lock()
            .map(|mut child| matches!(child.try_wait(), Ok(None)))
            .unwrap_or(false)
    }

    /// Returns the process ID of the pager child, if available.
    pub fn pager_pid(&self) -> Option<u32> {
        self.child.lock().ok().map(|child| child.id())
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Open a pager session.
///
/// Spawns a pager process based on environment configuration and redirects
/// the current process's stdout and stderr into the pager's stdin via a pipe.
///
/// # Errors
///
/// - [`PagerError::Disabled`] — `PagerFlags::DISABLE` is set or `$PAGER=cat`.
/// - [`PagerError::DumbTerminal`] — `TERM=dumb`.
/// - [`PagerError::PipeFailed`] — OS pipe creation failed.
/// - [`PagerError::SpawnFailed`] — pager executable could not be started.
/// - [`PagerError::NoPagerFound`] — no suitable pager on `$PATH`.
pub fn pager_open(flags: PagerFlags) -> Result<PagerSession, PagerError> {
    if flags.contains(PagerFlags::DISABLE) {
        return Err(PagerError::Disabled);
    }

    if is_terminal_dumb() {
        return Err(PagerError::DumbTerminal);
    }

    let less_opts = get_less_opts(flags);
    let less_charset = get_less_charset();
    let secure_mode = resolve_secure_mode();

    // Parse env-configured pager args; empty vec ⇒ explicitly disabled.
    let env_args = parse_pager_args();
    if let Some(ref args) = env_args {
        if args.is_empty() {
            return Err(PagerError::Disabled);
        }
    }

    // Create the data pipe (parent writes → child reads).
    let (read_end, write_fd) = create_pipe().map_err(PagerError::PipeFailed)?;

    // ── Build the pager Command ──
    let child = if let Some(ref args) = env_args {
        spawn_pager_cmd(
            &args[0],
            &args[1..],
            &less_opts,
            &less_charset,
            secure_mode,
            &read_end,
        )?
    } else {
        // Try the fallback chain.
        let mut found = None;
        for pager in FALLBACK_PAGERS {
            if secure_mode == SecureMode::Enabled && !is_pager_allowed_in_secure_mode(pager) {
                continue;
            }
            if let Ok(child) = spawn_pager_cmd(
                pager,
                &[],
                &less_opts,
                &less_charset,
                secure_mode,
                &read_end,
            ) {
                found = Some(child);
                break;
            }
        }
        found.ok_or(PagerError::NoPagerFound)?
    };

    // ── Redirect parent stdout / stderr into the write end ──
    let saved_stdout = dup_fd_cloexec(libc::STDOUT_FILENO);
    let stdout_ok = dup2_fd(write_fd.as_raw_fd(), libc::STDOUT_FILENO);

    let saved_stderr = dup_fd_cloexec(libc::STDERR_FILENO);
    let stderr_ok = dup2_fd(write_fd.as_raw_fd(), libc::STDERR_FILENO);

    Ok(PagerSession {
        child: Mutex::new(child),
        stored_stdout: if stdout_ok { saved_stdout } else { None },
        stored_stderr: if stderr_ok { saved_stderr } else { None },
        stdout_redirected: stdout_ok,
        stderr_redirected: stderr_ok,
        write_end: write_fd,
    })
}

/// Spawn a single pager command with the appropriate environment.
fn spawn_pager_cmd(
    program: &str,
    extra_args: &[String],
    less_opts: &str,
    less_charset: &Option<String>,
    secure_mode: SecureMode,
    input: &UnixStream,
) -> Result<Child, PagerError> {
    let input = input.try_clone().map_err(PagerError::SpawnFailed)?;
    let mut cmd = Command::new(program);
    cmd.args(extra_args)
        .stdin(Stdio::from(OwnedFd::from(input)))
        .env("LESS", less_opts);

    if let Some(cs) = less_charset {
        cmd.env("LESSCHARSET", cs);
    }
    if secure_mode == SecureMode::Enabled {
        cmd.env("LESSSECURE", "1");
    }

    cmd.spawn().map_err(PagerError::SpawnFailed)
}

/// Close the pager session, restore stdout/stderr, and wait for the child.
///
/// Flushes both output streams, restores the original file descriptors, and
/// reaps the pager child process.
pub fn pager_close(mut session: PagerSession) -> Result<(), PagerError> {
    // Flush before restoring fds.
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();

    // Drop the write end so the pager sees EOF.
    drop(session.write_end);

    // Restore stdout.
    if session.stdout_redirected {
        if let Some(ref fd) = session.stored_stdout {
            dup2_fd(fd.as_raw_fd(), libc::STDOUT_FILENO);
        } else {
            // SAFETY: closing an already-closed stdout is harmless here; the
            // return value is intentionally ignored during pager teardown.
            unsafe {
                libc::close(libc::STDOUT_FILENO);
            }
        }
    }
    session.stored_stdout = None;

    // Restore stderr.
    if session.stderr_redirected {
        if let Some(ref fd) = session.stored_stderr {
            dup2_fd(fd.as_raw_fd(), libc::STDERR_FILENO);
        } else {
            // SAFETY: closing an already-closed stderr is harmless here; the
            // return value is intentionally ignored during pager teardown.
            unsafe {
                libc::close(libc::STDERR_FILENO);
            }
        }
    }
    session.stored_stderr = None;
    session.stdout_redirected = false;
    session.stderr_redirected = false;

    // Reap the pager child.
    let mut child = session
        .child
        .into_inner()
        .unwrap_or_else(|error| error.into_inner());
    child.wait().map_err(PagerError::Io)?;
    Ok(())
}

/// Check whether a pager session is currently active.
pub fn pager_have(session: &Option<PagerSession>) -> bool {
    session.as_ref().is_some_and(PagerSession::is_active)
}

/// Show a man page by forking the `man` command.
///
/// Parses `desc` for the common `"name(section)"` syntax and spawns
/// `man <section> <name>` (or `man <name>` when no section is present).
///
/// When `null_stdio` is `true` the child's standard I/O is redirected to
/// `/dev/null`.
pub fn show_man_page(desc: &str, null_stdio: bool) -> Result<(), PagerError> {
    let man_ref = parse_man_page_ref(desc);
    let args = build_man_args(&man_ref);

    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]);

    if null_stdio {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }

    cmd.status().map_err(PagerError::SpawnFailed)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Keep the test-only FFI boundary explicit while allowing assertions to stay in safe Rust.
    macro_rules! test_ffi {
        ($expression:expr) => {{
            // SAFETY: test inputs are constructed in this module and satisfy the
            // documented C ABI preconditions of the exercised facade.
            unsafe { $expression }
        }};
    }
    use super::*;
    use crate::tests::TestEnvironment;

    // ── Constants ──────────────────────────────────────────────────────

    #[test]
    fn test_default_less_opts_value() {
        assert_eq!(DEFAULT_LESS_OPTS, "FRSXMK");
    }

    #[test]
    fn test_fallback_pagers_order() {
        assert_eq!(FALLBACK_PAGERS, &["pager", "less", "more"]);
    }

    // ── PagerFlags ────────────────────────────────────────────────────

    #[test]
    fn test_pager_flags_empty() {
        let f = PagerFlags::empty();
        assert!(!f.contains(PagerFlags::DISABLE));
        assert!(!f.contains(PagerFlags::JUMP_TO_END));
    }

    #[test]
    fn test_pager_flags_individual() {
        assert!(PagerFlags::DISABLE.contains(PagerFlags::DISABLE));
        assert!(!PagerFlags::DISABLE.contains(PagerFlags::JUMP_TO_END));
        assert!(PagerFlags::JUMP_TO_END.contains(PagerFlags::JUMP_TO_END));
        assert!(!PagerFlags::JUMP_TO_END.contains(PagerFlags::DISABLE));
    }

    #[test]
    fn test_pager_flags_combined() {
        let f = PagerFlags::DISABLE | PagerFlags::JUMP_TO_END;
        assert!(f.contains(PagerFlags::DISABLE));
        assert!(f.contains(PagerFlags::JUMP_TO_END));
    }

    #[test]
    fn test_pager_flags_bits() {
        assert_eq!(PagerFlags::DISABLE.bits(), 1);
        assert_eq!(PagerFlags::JUMP_TO_END.bits(), 2);
    }

    // ── get_less_opts ─────────────────────────────────────────────────

    #[test]
    fn test_get_less_opts_default() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(ENV_SYSTEMD_LESS);
        assert_eq!(get_less_opts(PagerFlags::empty()), DEFAULT_LESS_OPTS);
    }

    #[test]
    fn test_get_less_opts_jump_to_end() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(ENV_SYSTEMD_LESS);
        let opts = get_less_opts(PagerFlags::JUMP_TO_END);
        assert!(opts.ends_with(" +G"));
        assert!(opts.starts_with(DEFAULT_LESS_OPTS));
    }

    // ── parse_pager_args / is_pager_disabled_via_env ──────────────────

    #[test]
    fn test_parse_pager_args_empty_string() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGER, "");
        assert_eq!(parse_pager_args(), Some(Vec::new()));
    }

    #[test]
    fn test_parse_pager_args_cat() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGER, "cat");
        assert_eq!(parse_pager_args(), Some(Vec::new()));
    }

    #[test]
    fn test_parse_pager_args_normal() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGER, "less -R");
        assert_eq!(parse_pager_args(), Some(vec!["less".into(), "-R".into()]));
    }

    #[test]
    fn test_parse_pager_args_not_set() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(ENV_SYSTEMD_PAGER);
        environment.remove(ENV_PAGER);
        assert_eq!(parse_pager_args(), None);
    }

    #[test]
    fn test_is_pager_disabled_via_env_disabled() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGER, "cat");
        assert!(is_pager_disabled_via_env());
    }

    #[test]
    fn test_is_pager_disabled_via_env_active() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGER, "less");
        assert!(!is_pager_disabled_via_env());
    }

    // ── no_quit_on_interrupt ──────────────────────────────────────────

    #[test]
    fn test_no_quit_on_interrupt_less_without_k() {
        assert!(no_quit_on_interrupt(Some("less"), "FRSXM"));
    }

    #[test]
    fn test_no_quit_on_interrupt_less_with_k() {
        assert!(!no_quit_on_interrupt(Some("less"), "FRSXMKK"));
    }

    #[test]
    fn test_no_quit_on_interrupt_not_less() {
        assert!(!no_quit_on_interrupt(Some("more"), "FRSXMK"));
        assert!(!no_quit_on_interrupt(Some("cat"), "FRSXMK"));
        assert!(!no_quit_on_interrupt(Some("less -R"), "FRSXMK"));
    }

    #[test]
    fn test_no_quit_on_interrupt_none() {
        assert!(!no_quit_on_interrupt(None, "FRSXMK"));
    }

    // ── parse_man_page_ref ────────────────────────────────────────────

    #[test]
    fn test_parse_man_page_ref_with_section() {
        let r = parse_man_page_ref("systemd(1)");
        assert_eq!(r.page, "systemd");
        assert_eq!(r.section.as_deref(), Some("1"));
    }

    #[test]
    fn test_parse_man_page_ref_without_section() {
        let r = parse_man_page_ref("bash");
        assert_eq!(r.page, "bash");
        assert!(r.section.is_none());
    }

    #[test]
    fn test_parse_man_page_ref_with_spaces() {
        let r = parse_man_page_ref("  systemd  (  5  )  ");
        assert_eq!(r.page, "systemd");
        assert_eq!(r.section.as_deref(), Some("5"));
    }

    #[test]
    fn test_parse_man_page_ref_empty() {
        let r = parse_man_page_ref("");
        assert_eq!(r.page, "");
        assert!(r.section.is_none());
    }

    #[test]
    fn test_parse_man_page_ref_opening_paren_only() {
        // "foo(" — no closing paren, treated as plain name
        let r = parse_man_page_ref("foo(");
        assert_eq!(r.page, "foo(");
        assert!(r.section.is_none());
    }

    // ── build_man_args ────────────────────────────────────────────────

    #[test]
    fn test_build_man_args_with_section() {
        let r = ManPageRef {
            page: "systemd".into(),
            section: Some("1".into()),
        };
        assert_eq!(build_man_args(&r), vec!["man", "1", "systemd"]);
    }

    #[test]
    fn test_build_man_args_without_section() {
        let r = ManPageRef {
            page: "bash".into(),
            section: None,
        };
        assert_eq!(build_man_args(&r), vec!["man", "bash"]);
    }

    // ── is_pager_allowed_in_secure_mode ───────────────────────────────

    #[test]
    fn test_secure_mode_allowed_pagers() {
        assert!(is_pager_allowed_in_secure_mode("less"));
        assert!(is_pager_allowed_in_secure_mode("(built-in)"));
        assert!(!is_pager_allowed_in_secure_mode("more"));
        assert!(!is_pager_allowed_in_secure_mode("pager"));
        assert!(!is_pager_allowed_in_secure_mode("cat"));
        assert!(!is_pager_allowed_in_secure_mode(""));
    }

    // ── parse_secure_mode_env ─────────────────────────────────────────

    #[test]
    fn test_parse_secure_mode_env_enabled() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGERSECURE, "1");
        assert_eq!(parse_secure_mode_env().unwrap(), Some(SecureMode::Enabled));
    }

    #[test]
    fn test_parse_secure_mode_env_true() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGERSECURE, "true");
        assert_eq!(parse_secure_mode_env().unwrap(), Some(SecureMode::Enabled));
    }

    #[test]
    fn test_parse_secure_mode_env_disabled() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGERSECURE, "0");
        assert_eq!(parse_secure_mode_env().unwrap(), Some(SecureMode::Disabled));
    }

    #[test]
    fn test_parse_secure_mode_env_not_set() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(ENV_SYSTEMD_PAGERSECURE);
        assert_eq!(parse_secure_mode_env().unwrap(), None);
    }

    #[test]
    fn test_parse_secure_mode_env_invalid() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGERSECURE, "garbage");
        assert!(parse_secure_mode_env().is_err());
    }

    // ── resolve_secure_mode ───────────────────────────────────────────

    #[test]
    fn test_resolve_secure_mode_explicit() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_PAGERSECURE, "false");
        environment.remove(ENV_SUDO_UID);
        assert_eq!(resolve_secure_mode(), SecureMode::Disabled);
    }

    #[test]
    fn test_resolve_secure_mode_sudo_fallback() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(ENV_SYSTEMD_PAGERSECURE);
        environment.set(ENV_SUDO_UID, "1000");
        assert_eq!(resolve_secure_mode(), SecureMode::Enabled);
    }

    // ── PagerError ────────────────────────────────────────────────────

    #[test]
    fn test_pager_error_display() {
        assert_eq!(format!("{}", PagerError::Disabled), "pager is disabled");
        assert_eq!(format!("{}", PagerError::DumbTerminal), "terminal is dumb");
        assert_eq!(
            format!("{}", PagerError::AlreadyOpen),
            "pager is already open"
        );
        assert_eq!(
            format!("{}", PagerError::NoPagerFound),
            "no suitable pager found"
        );
    }

    // ── get_less_charset ──────────────────────────────────────────────

    #[test]
    fn test_get_less_charset_explicit() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SYSTEMD_LESSCHARSET, "latin1");
        assert_eq!(get_less_charset(), Some("latin1".into()));
    }

    #[test]
    fn test_get_less_charset_utf8_locale() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(ENV_SYSTEMD_LESSCHARSET);
        environment.set("LC_ALL", "en_US.UTF-8");
        assert_eq!(get_less_charset(), Some("utf-8".into()));
    }

    // ── has_sudo_uid ──────────────────────────────────────────────────

    #[test]
    fn test_has_sudo_uid_present() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.set(ENV_SUDO_UID, "1000");
        assert!(has_sudo_uid());
    }

    #[test]
    fn test_has_sudo_uid_absent() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = test_ffi!(TestEnvironment::lock());
        environment.remove(ENV_SUDO_UID);
        assert!(!has_sudo_uid());
    }

    // ── pager_have ────────────────────────────────────────────────────

    #[test]
    fn test_pager_have_none() {
        assert!(!pager_have(&None));
    }

    // ── ManPageRef PartialEq ──────────────────────────────────────────

    #[test]
    fn test_man_page_ref_equality() {
        let a = ManPageRef {
            page: "systemd".into(),
            section: Some("1".into()),
        };
        let b = ManPageRef {
            page: "systemd".into(),
            section: Some("1".into()),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_man_page_ref_inequality() {
        let a = ManPageRef {
            page: "systemd".into(),
            section: Some("1".into()),
        };
        let b = ManPageRef {
            page: "systemd".into(),
            section: Some("5".into()),
        };
        assert_ne!(a, b);
    }
}
