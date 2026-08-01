// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/exec-util.c, src/core/manager.c

//! Bounded execution for unit generators.
//!
//! The C implementation runs generators in a dedicated executor process. It
//! deliberately tolerates an individual generator failure, gives the whole
//! batch one deadline, and sets `SYSTEMD_EXEC_PID` in each child. This module
//! keeps those semantics explicit. System-manager execution currently gives
//! each child an independently prepared mount namespace: slave propagation,
//! private `/tmp` when available, and a best-effort read-only remount excluding
//! the documented API/output paths. This keeps the manager's namespace
//! untouched and makes partial setup fail closed. C shares one sandbox
//! namespace across the whole batch; the per-child form is therefore a safe
//! intermediate seam, not a claim of complete generator parity. The
//! unsandboxed mode remains a deliberately named fallback that is permitted
//! only when namespace creation itself fails for the narrow reasons accepted
//! by C.

use crate::generator_setup::{
    GeneratorInvocation, GeneratorRunError, GeneratorRunOutcome, LookupPaths, PreparedGeneratorRun,
    discover_generator_executables, run_generators_with,
};
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::{Duration, Instant};
use systemd_basic_rs::env_util::{env_name_is_valid, env_value_is_valid};

/// The default `DEFAULT_TIMEOUT_USEC` value used by the generator executor.
pub const DEFAULT_GENERATOR_TIMEOUT: Duration = Duration::from_secs(90);

/// Maximum amount of one environment generator's stdout retained in memory.
///
/// C reads the generator's serialization file as one environment file. Rust
/// keeps the same one-megabyte line ceiling used by `LONG_LINE_MAX`, but also
/// bounds the *total* retained stream so a broken generator cannot turn PID 1
/// startup into an unbounded allocation. The reader continues draining after
/// the limit so the child cannot deadlock on a full stdout pipe.
pub const MAX_ENVIRONMENT_GENERATOR_OUTPUT: usize = 1024 * 1024;

/// The only permitted direct-execution contexts.
///
/// `SystemFallbackNoSandbox` is intentionally wordy: it may only be chosen by
/// the PID 1 owner after a failed attempt to create the isolated namespace due
/// to a privilege or `CLONE_NEWNS`-availability failure, matching C's narrow
/// fallback. It is not a replacement for [`Self::SystemIsolated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorSandbox {
    /// User managers run generators directly, as in `manager_run_generators()`.
    UserManagerDirect,
    /// System-manager execution in a bounded per-child mount namespace.
    /// Generators receive slave propagation, a private `/tmp` when the
    /// directory exists, and the C implementation's best-effort read-only
    /// remount exclusions. The output directories remain shared, but C uses a
    /// single sandbox namespace for the batch; callers must not treat this
    /// variant as complete parity for generators that communicate via `/tmp`.
    SystemIsolated,
    /// Explicit C-compatible fallback after an allowed system sandbox failure.
    SystemFallbackNoSandbox,
    /// Refuse to execute a system generator before the namespace owner has
    /// supplied the required isolation.
    SystemIsolationRequired,
}

/// Execution configuration that is entirely prepared in the parent before
/// the narrow post-fork child setup runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorExecutionOptions {
    pub sandbox: GeneratorSandbox,
    pub timeout: Duration,
    /// Manager environment after `build_generator_environment()`. It is
    /// layered on the inherited manager environment exactly as C's `putenv()`
    /// calls do; `SYSTEMD_EXEC_PID` is overwritten in the child.
    pub environment: BTreeMap<String, String>,
}

impl Default for GeneratorExecutionOptions {
    fn default() -> Self {
        Self {
            sandbox: GeneratorSandbox::SystemIsolationRequired,
            timeout: DEFAULT_GENERATOR_TIMEOUT,
            environment: BTreeMap::new(),
        }
    }
}

/// Result for an individual child. Generator exit failures are reported but
/// do not fail the batch, matching `EXEC_DIR_IGNORE_ERRORS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorChildReport {
    pub executable: PathBuf,
    pub status: GeneratorChildStatus,
    pub world_writable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorChildStatus {
    Exited(i32),
    Signaled(i32),
}

/// Parent-observable execution facts. Callers should log world-writable
/// entries and abnormal child status at warning level, as C does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeneratorExecutionReport {
    pub children: Vec<GeneratorChildReport>,
}

impl GeneratorExecutionReport {
    pub fn has_abnormal_children(&self) -> bool {
        self.children
            .iter()
            .any(|child| !matches!(child.status, GeneratorChildStatus::Exited(0)))
    }
}

/// A non-fatal diagnostic produced while consuming an environment generator's
/// stdout. C's `gather_environment_generate()` ignores malformed assignments
/// and invalid names after logging them; retaining that information makes the
/// PID 1 owner responsible for the corresponding warning without changing the
/// generated environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentGeneratorDiagnostic {
    MalformedAssignment { line: usize },
    InvalidUtf8 { line: usize },
    InvalidVariableName { line: usize, name: String },
}

/// The result of serially executing the environment-generator directory.
///
/// `transient_environment` is both the map that must be installed into the
/// manager and the exact layer passed to the next generator. It deliberately
/// does not mutate Rust's process-global environment: in edition 2024 that is
/// unsafe in a multi-threaded process, and the PID 1 startup owner can make
/// the one, controlled publication after it has accepted this report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentGeneratorExecutionReport {
    pub transient_environment: BTreeMap<String, String>,
    pub children: Vec<GeneratorChildReport>,
    pub diagnostics: Vec<(PathBuf, EnvironmentGeneratorDiagnostic)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorExecutionError {
    UnsupportedPlatform,
    IsolationRequired,
    /// Creating `CLONE_NEWNS` failed for a reason for which the C manager
    /// permits its explicit unsandboxed fallback.
    IsolationUnavailable {
        errno: i32,
        message: Box<str>,
    },
    /// Namespace creation worked, but the required propagation/private-tmp
    /// setup did not. This must never authorize the unsandboxed fallback.
    IsolationSetup {
        message: Box<str>,
    },
    InvalidInvocation {
        executable: PathBuf,
        reason: Box<str>,
    },
    InvalidEnvironment {
        name: String,
    },
    Spawn {
        executable: PathBuf,
        message: Box<str>,
    },
    Wait {
        executable: PathBuf,
        message: Box<str>,
    },
    OutputLimitExceeded {
        executable: PathBuf,
        limit: usize,
    },
    TimedOut {
        report: Box<GeneratorExecutionReport>,
    },
}

impl fmt::Display for GeneratorExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str("generator execution requires Linux"),
            Self::IsolationRequired => formatter.write_str(
                "refusing system generator execution without the required isolated mount namespace",
            ),
            Self::IsolationUnavailable { errno, message } => write!(
                formatter,
                "generator mount namespace is unavailable (errno {errno}): {message}"
            ),
            Self::IsolationSetup { message } => {
                write!(
                    formatter,
                    "failed to set up generator mount namespace: {message}"
                )
            }
            Self::InvalidInvocation { executable, reason } => {
                write!(
                    formatter,
                    "invalid generator {}: {reason}",
                    executable.display()
                )
            }
            Self::InvalidEnvironment { name } => {
                write!(formatter, "invalid generator environment variable {name:?}")
            }
            Self::Spawn {
                executable,
                message,
            } => {
                write!(
                    formatter,
                    "failed to spawn generator {}: {message}",
                    executable.display()
                )
            }
            Self::Wait {
                executable,
                message,
            } => {
                write!(
                    formatter,
                    "failed to wait for generator {}: {message}",
                    executable.display()
                )
            }
            Self::OutputLimitExceeded { executable, limit } => write!(
                formatter,
                "environment generator {} exceeded the {}-byte stdout limit",
                executable.display(),
                limit,
            ),
            Self::TimedOut { .. } => formatter.write_str("generator batch exceeded its deadline"),
        }
    }
}

impl std::error::Error for GeneratorExecutionError {}

impl GeneratorExecutionError {
    /// Whether this is precisely the privilege/`EINVAL` namespace-creation
    /// failure for which C retries generator execution without a sandbox.
    pub fn permits_system_fallback(&self) -> bool {
        matches!(self, Self::IsolationUnavailable { .. })
    }
}

struct RunningGenerator {
    executable: PathBuf,
    child: Child,
    world_writable: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct PreparedGeneratorSandbox {
    private_tmp: bool,
    read_only_mounts: Arc<[PreparedReadOnlyMount]>,
}

#[cfg(target_os = "linux")]
struct PreparedReadOnlyMount {
    target: CString,
    current_flags: libc::c_ulong,
}

#[cfg(target_os = "linux")]
impl PreparedGeneratorSandbox {
    fn prepare() -> Self {
        let private_tmp = fs::symlink_metadata("/tmp")
            .map(|metadata| metadata.file_type().is_dir())
            .unwrap_or(false);
        let read_only_mounts = fs::read("/proc/self/mountinfo")
            .map(|mountinfo| parse_read_only_mounts(&mountinfo))
            // The C remount is warning-only. Failure to read mountinfo must
            // not weaken the mount-namespace/private-tmp boundary or abort an
            // otherwise usable boot.
            .unwrap_or_default()
            .into();
        Self {
            private_tmp,
            read_only_mounts,
        }
    }

    fn apply_after_unshare(&self) -> std::io::Result<()> {
        child_mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_SLAVE | libc::MS_REC) as libc::c_ulong,
            std::ptr::null(),
        )?;

        if self.private_tmp {
            child_mount(
                c"tmpfs".as_ptr(),
                c"/tmp".as_ptr(),
                c"tmpfs".as_ptr(),
                (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
                c"mode=01777,size=20%,nr_inodes=800k".as_ptr().cast(),
            )?;
        }

        // manager_execute_generators() treats this hardening pass as
        // best-effort. Preserve the original mount's VFS flags while adding
        // MS_RDONLY, and continue across transient/autofs/network failures.
        for mount in self.read_only_mounts.iter() {
            let flags = ((mount.current_flags & !(libc::MS_RDONLY as libc::c_ulong))
                | libc::MS_BIND as libc::c_ulong
                | libc::MS_REMOUNT as libc::c_ulong
                | libc::MS_RDONLY as libc::c_ulong)
                & !(libc::MS_RELATIME as libc::c_ulong);
            let _ = child_mount(
                std::ptr::null(),
                mount.target.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn child_unshare_mount_namespace() -> std::io::Result<()> {
    // SAFETY: CLONE_NEWNS is a valid unshare(2) flag and changes only the
    // calling post-fork child. No Rust-owned memory crosses the syscall.
    if unsafe_ffi!(libc::unshare(libc::CLONE_NEWNS)) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn child_mount(
    source: *const libc::c_char,
    target: *const libc::c_char,
    filesystem: *const libc::c_char,
    flags: libc::c_ulong,
    data: *const libc::c_void,
) -> std::io::Result<()> {
    // SAFETY: callers pass null or retained NUL-terminated strings prepared
    // in the parent. mount(2) borrows them only for the duration of the call.
    if unsafe_ffi!(libc::mount(source, target, filesystem, flags, data)) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn path_is_within(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix || (path.starts_with(prefix) && path.get(prefix.len()).copied() == Some(b'/'))
}

#[cfg(target_os = "linux")]
fn parse_read_only_mounts(mountinfo: &[u8]) -> Vec<PreparedReadOnlyMount> {
    const EXCEPTIONS: [&[u8]; 5] = [b"/sys", b"/run", b"/proc", b"/dev/shm", b"/tmp"];
    let mut mounts = BTreeMap::<Vec<u8>, libc::c_ulong>::new();

    for line in mountinfo.split(|byte| *byte == b'\n') {
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.len() < 7 {
            continue;
        }
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            continue;
        };
        if fields.get(separator + 1).copied() == Some(b"autofs") {
            continue;
        }
        let Some(target) = decode_mountinfo_path(fields[4]) else {
            continue;
        };
        if !target.starts_with(b"/")
            || EXCEPTIONS
                .iter()
                .any(|exception| path_is_within(&target, exception))
        {
            continue;
        }
        mounts.insert(target, parse_mount_options(fields[5]));
    }

    mounts
        .into_iter()
        .filter_map(|(target, current_flags)| {
            CString::new(target)
                .ok()
                .map(|target| PreparedReadOnlyMount {
                    target,
                    current_flags,
                })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] != b'\\' {
            decoded.push(encoded[index]);
            index += 1;
            continue;
        }
        let octal = encoded.get(index + 1..index + 4)?;
        if !octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
            return None;
        }
        decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
        index += 4;
    }
    Some(decoded)
}

#[cfg(target_os = "linux")]
fn parse_mount_options(options: &[u8]) -> libc::c_ulong {
    options
        .split(|byte| *byte == b',')
        .fold(0, |flags, option| {
            flags
                | match option {
                    b"ro" => libc::MS_RDONLY,
                    b"nosuid" => libc::MS_NOSUID,
                    b"nodev" => libc::MS_NODEV,
                    b"noexec" => libc::MS_NOEXEC,
                    b"sync" => libc::MS_SYNCHRONOUS,
                    b"dirsync" => libc::MS_DIRSYNC,
                    b"noatime" => libc::MS_NOATIME,
                    b"nodiratime" => libc::MS_NODIRATIME,
                    b"relatime" => libc::MS_RELATIME,
                    b"strictatime" => libc::MS_STRICTATIME,
                    b"lazytime" => libc::MS_LAZYTIME,
                    _ => 0,
                } as libc::c_ulong
        })
}

/// Fully allocated execve inputs. All heap work happens in the parent;
/// `exec_in_child()` only patches preallocated pointer slots and calls execve.
#[cfg(target_os = "linux")]
struct PreparedGeneratorExec {
    executable: CString,
    argv_storage: Vec<CString>,
    // `CommandExt::pre_exec` requires its closure to be Send + Sync. Store
    // addresses as integers until the post-fork hook reconstructs the exact
    // C pointer arrays; no pointer is dereferenced before that conversion.
    argv: Vec<usize>,
    environment_storage: Vec<CString>,
    environment: Vec<usize>,
    exec_pid_assignment: [u8; 64],
}

#[cfg(target_os = "linux")]
impl PreparedGeneratorExec {
    fn for_unit_generator(
        invocation: &GeneratorInvocation,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        validate_invocation(invocation)?;
        Self::with_argv(
            &invocation.executable,
            [
                invocation.executable.as_path(),
                invocation.output_directory.as_path(),
                invocation.early_output_directory.as_path(),
                invocation.late_output_directory.as_path(),
            ],
            environment,
        )
    }

    /// Environment generators intentionally receive no positional output
    /// directories. C's `do_spawn()` creates `argv = { path, NULL }` when
    /// `execute_directories()` is called with a null argv vector.
    fn for_environment_generator(
        executable: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        validate_environment_generator(executable)?;
        Self::with_argv(executable, [executable], environment)
    }

    fn with_argv<'a>(
        executable_path: &Path,
        argv_paths: impl IntoIterator<Item = &'a Path>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let executable = path_to_cstring(executable_path)?;
        let argv_storage = argv_paths
            .into_iter()
            .map(path_to_cstring)
            .collect::<Result<Vec<_>, _>>()?;

        // C starts from the manager environment and overwrites assignments
        // supplied by build_generator_environment(). Capture that complete
        // environment before fork, then reserve the authoritative child PID
        // assignment which cannot be known in the parent.
        let mut merged_environment = BTreeMap::new();
        for (name, value) in std::env::vars_os() {
            merged_environment.insert(name.into_encoded_bytes(), value.into_encoded_bytes());
        }
        for (name, value) in environment {
            merged_environment.insert(name.as_bytes().to_vec(), value.as_bytes().to_vec());
        }
        merged_environment.remove(b"SYSTEMD_EXEC_PID".as_slice());

        let mut environment_storage = Vec::with_capacity(merged_environment.len());
        for (name, value) in merged_environment {
            let mut assignment = name;
            assignment.push(b'=');
            assignment.extend(value);
            environment_storage.push(
                CString::new(assignment)
                    .map_err(|_| "environment contains an interior NUL".to_string())?,
            );
        }

        Ok(Self {
            executable,
            argv: vec![0; argv_storage.len() + 1],
            argv_storage,
            environment: vec![0; environment_storage.len() + 2],
            environment_storage,
            exec_pid_assignment: [0; 64],
        })
    }

    fn exec_in_child(&mut self) -> std::io::Result<()> {
        for (slot, value) in self.argv.iter_mut().zip(&self.argv_storage) {
            *slot = value.as_ptr() as usize;
        }
        for (slot, value) in self.environment.iter_mut().zip(&self.environment_storage) {
            *slot = value.as_ptr() as usize;
        }
        // SAFETY: getpid has no pointer or lifetime preconditions and cannot
        // fail; it returns the process that is about to exec this generator.
        let pid = unsafe_ffi!(libc::getpid());
        set_systemd_exec_pid(&mut self.exec_pid_assignment, pid)?;
        self.environment[self.environment_storage.len()] =
            self.exec_pid_assignment.as_ptr() as usize;
        // SAFETY: argv and environment are NUL-terminated pointer arrays into
        // parent-prepared, still-live CString/fixed storage. On success execve
        // does not return; on failure the errno is immediately preserved.
        if unsafe_ffi!({
            libc::execve(
                self.executable.as_ptr(),
                self.argv.as_ptr().cast(),
                self.environment.as_ptr().cast(),
            )
        }) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        unreachable!("successful execve never returns")
    }
}

#[cfg(target_os = "linux")]
fn path_to_cstring(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("path {} contains an interior NUL", path.display()))
}

/// Execute an already prepared generator plan.
///
/// This function is intentionally synchronous: C blocks the manager while its
/// dedicated generator executor waits for the parallel children. The deadline
/// applies to the whole batch, not once per executable.
pub fn execute_prepared_generators(
    prepared: &PreparedGeneratorRun,
    options: &GeneratorExecutionOptions,
) -> Result<GeneratorExecutionReport, GeneratorExecutionError> {
    let system_sandbox = match options.sandbox {
        GeneratorSandbox::SystemIsolationRequired => {
            return Err(GeneratorExecutionError::IsolationRequired);
        }
        #[cfg(target_os = "linux")]
        GeneratorSandbox::SystemIsolated => {
            let sandbox = PreparedGeneratorSandbox::prepare();
            probe_system_sandbox(&sandbox)?;
            Some(sandbox)
        }
        #[cfg(not(target_os = "linux"))]
        GeneratorSandbox::SystemIsolated => {
            return Err(GeneratorExecutionError::UnsupportedPlatform);
        }
        GeneratorSandbox::UserManagerDirect | GeneratorSandbox::SystemFallbackNoSandbox => None,
    };

    validate_environment(&options.environment)?;
    let deadline = Instant::now()
        .checked_add(options.timeout)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(365 * 24 * 60 * 60));
    let mut running = Vec::with_capacity(prepared.invocations.len());

    for invocation in &prepared.invocations {
        if let Err(reason) = validate_invocation(invocation) {
            terminate_generators(&mut running);
            return Err(GeneratorExecutionError::InvalidInvocation {
                executable: invocation.executable.clone(),
                reason: reason.into(),
            });
        }
        let world_writable = generator_is_world_writable(&invocation.executable);
        let child = match spawn_generator(
            invocation,
            &options.environment,
            #[cfg(target_os = "linux")]
            system_sandbox.clone(),
        ) {
            Ok(child) => child,
            Err(message) => {
                terminate_generators(&mut running);
                return Err(GeneratorExecutionError::Spawn {
                    executable: invocation.executable.clone(),
                    message: message.into(),
                });
            }
        };
        running.push(RunningGenerator {
            executable: invocation.executable.clone(),
            child,
            world_writable,
        });
    }

    wait_for_generators(running, deadline)
}

/// Execute system-manager generators with C's narrowly scoped fallback.
///
/// The caller cannot accidentally turn an arbitrary namespace setup error
/// into an unsandboxed run: only `IsolationUnavailable` (privilege or
/// `EINVAL`/`CLONE_NEWNS` refusal) authorizes the retry. Mount, descriptor,
/// validation, spawn, and timeout failures remain errors.
pub fn execute_system_generators_with_fallback(
    prepared: &PreparedGeneratorRun,
    options: &GeneratorExecutionOptions,
) -> Result<GeneratorExecutionReport, GeneratorExecutionError> {
    let mut isolated = options.clone();
    isolated.sandbox = GeneratorSandbox::SystemIsolated;
    match execute_prepared_generators(prepared, &isolated) {
        Err(error) if error.permits_system_fallback() => {
            let mut fallback = options.clone();
            fallback.sandbox = GeneratorSandbox::SystemFallbackNoSandbox;
            execute_prepared_generators(prepared, &fallback)
        }
        result => result,
    }
}

/// Compose discovery/setup, child execution, and unconditional output trim.
pub fn run_generator_lifecycle(
    paths: &LookupPaths,
    search_directories: &[PathBuf],
    options: &GeneratorExecutionOptions,
) -> Result<GeneratorRunOutcome<GeneratorExecutionReport>, GeneratorRunError<GeneratorExecutionError>>
{
    run_generators_with(paths, search_directories, |prepared| {
        execute_prepared_generators(prepared, options)
    })
}

/// Compose the system-manager lifecycle with the explicit C-compatible
/// namespace fallback policy.
pub fn run_system_generator_lifecycle_with_fallback(
    paths: &LookupPaths,
    search_directories: &[PathBuf],
    options: &GeneratorExecutionOptions,
) -> Result<GeneratorRunOutcome<GeneratorExecutionReport>, GeneratorRunError<GeneratorExecutionError>>
{
    run_generators_with(paths, search_directories, |prepared| {
        execute_system_generators_with_fallback(prepared, options)
    })
}

/// Execute environment generators serially and return the accumulated
/// transient environment.
///
/// `execute_directories()` is passed `EXEC_DIR_PARALLEL` by
/// `manager_run_environment_generators()`, but its stdout callbacks make
/// `do_execute()` deliberately select serial execution. Each child therefore
/// observes every valid assignment emitted by its predecessors. Unlike unit
/// generators these executables receive argv containing only argv[0] and
/// communicate solely through stdout.
pub fn execute_environment_generators(
    search_directories: &[PathBuf],
    initial_environment: BTreeMap<String, String>,
    options: &GeneratorExecutionOptions,
) -> Result<EnvironmentGeneratorExecutionReport, GeneratorExecutionError> {
    let system_sandbox = match options.sandbox {
        GeneratorSandbox::SystemIsolationRequired => {
            return Err(GeneratorExecutionError::IsolationRequired);
        }
        #[cfg(target_os = "linux")]
        GeneratorSandbox::SystemIsolated => {
            let sandbox = PreparedGeneratorSandbox::prepare();
            probe_system_sandbox(&sandbox)?;
            Some(sandbox)
        }
        #[cfg(not(target_os = "linux"))]
        GeneratorSandbox::SystemIsolated => {
            return Err(GeneratorExecutionError::UnsupportedPlatform);
        }
        GeneratorSandbox::UserManagerDirect | GeneratorSandbox::SystemFallbackNoSandbox => None,
    };

    validate_environment(&initial_environment)?;
    let deadline = Instant::now()
        .checked_add(options.timeout)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(365 * 24 * 60 * 60));
    let discovery = discover_generator_executables(search_directories);
    let mut report = EnvironmentGeneratorExecutionReport {
        transient_environment: initial_environment,
        ..EnvironmentGeneratorExecutionReport::default()
    };

    for executable in discovery.executables {
        validate_environment_generator(&executable).map_err(|reason| {
            GeneratorExecutionError::InvalidInvocation {
                executable: executable.clone(),
                reason: reason.into(),
            }
        })?;
        let world_writable = generator_is_world_writable(&executable);
        let (mut child, stdout) = spawn_environment_generator(
            &executable,
            &report.transient_environment,
            #[cfg(target_os = "linux")]
            system_sandbox.clone(),
        )
        .map_err(|message| GeneratorExecutionError::Spawn {
            executable: executable.clone(),
            message: message.into(),
        })?;
        let reader = std::thread::spawn(move || read_bounded_generator_stdout(stdout));
        let status = match wait_for_environment_generator(&mut child, deadline) {
            Ok(status) => status,
            Err(()) => {
                terminate_generator_process_group(&mut child);
                let _ = reader.join();
                let mut timed_out = GeneratorExecutionReport::default();
                timed_out.children.push(GeneratorChildReport {
                    executable,
                    status: GeneratorChildStatus::Signaled(libc::SIGKILL),
                    world_writable,
                });
                return Err(GeneratorExecutionError::TimedOut {
                    report: Box::new(timed_out),
                });
            }
        };
        let output = reader
            .join()
            .map_err(|_| GeneratorExecutionError::Wait {
                executable: executable.clone(),
                message: "environment generator stdout reader panicked".into(),
            })?
            .map_err(|error| GeneratorExecutionError::Wait {
                executable: executable.clone(),
                message: format!("failed to read environment generator stdout: {error}").into(),
            })?;
        if output.truncated {
            return Err(GeneratorExecutionError::OutputLimitExceeded {
                executable,
                limit: MAX_ENVIRONMENT_GENERATOR_OUTPUT,
            });
        }

        report.children.push(GeneratorChildReport {
            executable: executable.clone(),
            status: classify_exit_status(status),
            world_writable,
        });
        let parsed = parse_environment_generator_output(&output.bytes);
        for (name, value) in parsed.assignments {
            report.transient_environment.insert(name, value);
        }
        report.diagnostics.extend(
            parsed
                .diagnostics
                .into_iter()
                .map(|diagnostic| (executable.clone(), diagnostic)),
        );
    }
    Ok(report)
}

/// System-manager environment generator execution with the same narrow
/// mount-namespace fallback policy as unit generators.
pub fn execute_system_environment_generators_with_fallback(
    search_directories: &[PathBuf],
    initial_environment: BTreeMap<String, String>,
    options: &GeneratorExecutionOptions,
) -> Result<EnvironmentGeneratorExecutionReport, GeneratorExecutionError> {
    let mut isolated = options.clone();
    isolated.sandbox = GeneratorSandbox::SystemIsolated;
    match execute_environment_generators(search_directories, initial_environment.clone(), &isolated)
    {
        Err(error) if error.permits_system_fallback() => {
            let mut fallback = options.clone();
            fallback.sandbox = GeneratorSandbox::SystemFallbackNoSandbox;
            execute_environment_generators(search_directories, initial_environment, &fallback)
        }
        result => result,
    }
}

fn validate_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), GeneratorExecutionError> {
    for (name, value) in environment {
        if name.is_empty()
            || name.contains('=')
            || name.as_bytes().contains(&0)
            || value.as_bytes().contains(&0)
        {
            return Err(GeneratorExecutionError::InvalidEnvironment { name: name.clone() });
        }
    }
    Ok(())
}

fn validate_invocation(invocation: &GeneratorInvocation) -> Result<(), String> {
    if !invocation.executable.is_absolute() {
        return Err("executable path is not absolute".to_string());
    }
    for (label, path) in [
        ("output", &invocation.output_directory),
        ("early output", &invocation.early_output_directory),
        ("late output", &invocation.late_output_directory),
    ] {
        if !path.is_absolute() {
            return Err(format!("{label} directory is not absolute"));
        }
    }
    Ok(())
}

fn validate_environment_generator(executable: &Path) -> Result<(), String> {
    if !executable.is_absolute() {
        return Err("executable path is not absolute".to_string());
    }
    Ok(())
}

struct BoundedGeneratorOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded_generator_stdout(
    mut stdout: std::process::ChildStdout,
) -> std::io::Result<BoundedGeneratorOutput> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stdout.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_ENVIRONMENT_GENERATOR_OUTPUT.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained != read;
    }
    Ok(BoundedGeneratorOutput { bytes, truncated })
}

struct ParsedEnvironmentGeneratorOutput {
    assignments: Vec<(String, String)>,
    diagnostics: Vec<EnvironmentGeneratorDiagnostic>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EnvironmentParseState {
    PreKey,
    Key,
    PreValue,
    Value,
    ValueEscape,
    SingleQuoteValue,
    DoubleQuoteValue,
    DoubleQuoteValueEscape,
    Comment,
    CommentEscape,
}

fn environment_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn environment_newline(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r')
}

fn finish_environment_assignment(
    key: &mut Vec<u8>,
    value: &mut Vec<u8>,
    key_trailing_whitespace: Option<usize>,
    value_trailing_whitespace: Option<usize>,
    trim_value: bool,
    line: usize,
    parsed: &mut ParsedEnvironmentGeneratorOutput,
) {
    if let Some(index) = key_trailing_whitespace {
        key.truncate(index);
    }
    if trim_value && let Some(index) = value_trailing_whitespace {
        value.truncate(index);
    }
    let Ok(name) = std::str::from_utf8(key) else {
        parsed
            .diagnostics
            .push(EnvironmentGeneratorDiagnostic::InvalidUtf8 { line });
        return;
    };
    let Ok(value) = std::str::from_utf8(value) else {
        parsed
            .diagnostics
            .push(EnvironmentGeneratorDiagnostic::InvalidUtf8 { line });
        return;
    };
    if !env_name_is_valid(name) {
        parsed
            .diagnostics
            .push(EnvironmentGeneratorDiagnostic::InvalidVariableName {
                line,
                name: name.to_string(),
            });
        return;
    }
    if !env_value_is_valid(value) {
        parsed
            .diagnostics
            .push(EnvironmentGeneratorDiagnostic::MalformedAssignment { line });
        return;
    }
    parsed
        .assignments
        .push((name.to_string(), value.to_string()));
}

/// Parse stdout with the state machine used by C's `load_env_file_pairs()`.
///
/// Quotes, backslash continuations, and comments are deliberately parsed
/// before environment-name validation: a generator can safely print ordinary
/// `NAME=value` records, while malformed input is ignored with diagnostics as
/// `gather_environment_generate()` does after logging it.
fn parse_environment_generator_output(bytes: &[u8]) -> ParsedEnvironmentGeneratorOutput {
    let mut parsed = ParsedEnvironmentGeneratorOutput {
        assignments: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut state = EnvironmentParseState::PreKey;
    let mut key = Vec::new();
    let mut value = Vec::new();
    let mut line = 1;
    let mut key_line = 1;
    let mut key_trailing_whitespace = None;
    let mut value_trailing_whitespace = None;

    for &byte in bytes {
        match state {
            EnvironmentParseState::PreKey => {
                if matches!(byte, b'#' | b';') {
                    state = EnvironmentParseState::Comment;
                } else if !environment_whitespace(byte) {
                    state = EnvironmentParseState::Key;
                    key.clear();
                    value.clear();
                    key.push(byte);
                    key_line = line;
                    key_trailing_whitespace = None;
                } else if environment_newline(byte) {
                    line += 1;
                }
            }
            EnvironmentParseState::Key => {
                if environment_newline(byte) {
                    parsed
                        .diagnostics
                        .push(EnvironmentGeneratorDiagnostic::MalformedAssignment {
                            line: key_line,
                        });
                    state = EnvironmentParseState::PreKey;
                    line += 1;
                } else if byte == b'=' {
                    state = EnvironmentParseState::PreValue;
                    value_trailing_whitespace = None;
                } else {
                    if environment_whitespace(byte) {
                        key_trailing_whitespace.get_or_insert(key.len());
                    } else {
                        key_trailing_whitespace = None;
                    }
                    key.push(byte);
                }
            }
            EnvironmentParseState::PreValue => {
                if environment_newline(byte) {
                    finish_environment_assignment(
                        &mut key,
                        &mut value,
                        key_trailing_whitespace,
                        None,
                        false,
                        key_line,
                        &mut parsed,
                    );
                    state = EnvironmentParseState::PreKey;
                    line += 1;
                } else if byte == b'\'' {
                    state = EnvironmentParseState::SingleQuoteValue;
                } else if byte == b'"' {
                    state = EnvironmentParseState::DoubleQuoteValue;
                } else if byte == b'\\' {
                    state = EnvironmentParseState::ValueEscape;
                } else if !environment_whitespace(byte) {
                    state = EnvironmentParseState::Value;
                    value.push(byte);
                }
            }
            EnvironmentParseState::Value => {
                if environment_newline(byte) {
                    finish_environment_assignment(
                        &mut key,
                        &mut value,
                        key_trailing_whitespace,
                        value_trailing_whitespace,
                        true,
                        key_line,
                        &mut parsed,
                    );
                    state = EnvironmentParseState::PreKey;
                    line += 1;
                } else if byte == b'\\' {
                    state = EnvironmentParseState::ValueEscape;
                    value_trailing_whitespace = None;
                } else {
                    if environment_whitespace(byte) {
                        value_trailing_whitespace.get_or_insert(value.len());
                    } else {
                        value_trailing_whitespace = None;
                    }
                    value.push(byte);
                }
            }
            EnvironmentParseState::ValueEscape => {
                state = EnvironmentParseState::Value;
                if !environment_newline(byte) {
                    value.push(byte);
                }
            }
            EnvironmentParseState::SingleQuoteValue => {
                if byte == b'\'' {
                    state = EnvironmentParseState::PreValue;
                } else {
                    value.push(byte);
                }
            }
            EnvironmentParseState::DoubleQuoteValue => {
                if byte == b'"' {
                    state = EnvironmentParseState::PreValue;
                } else if byte == b'\\' {
                    state = EnvironmentParseState::DoubleQuoteValueEscape;
                } else {
                    value.push(byte);
                }
            }
            EnvironmentParseState::DoubleQuoteValueEscape => {
                state = EnvironmentParseState::DoubleQuoteValue;
                if matches!(byte, b'"' | b'\\' | b'`' | b'$') {
                    value.push(byte);
                } else if !environment_newline(byte) {
                    value.push(b'\\');
                    value.push(byte);
                }
            }
            EnvironmentParseState::Comment => {
                if byte == b'\\' {
                    state = EnvironmentParseState::CommentEscape;
                } else if environment_newline(byte) {
                    state = EnvironmentParseState::PreKey;
                    line += 1;
                }
            }
            EnvironmentParseState::CommentEscape => {
                if environment_newline(byte) {
                    state = EnvironmentParseState::PreKey;
                    line += 1;
                } else {
                    state = EnvironmentParseState::Comment;
                }
            }
        }
    }

    match state {
        EnvironmentParseState::PreValue
        | EnvironmentParseState::Value
        | EnvironmentParseState::ValueEscape
        | EnvironmentParseState::SingleQuoteValue
        | EnvironmentParseState::DoubleQuoteValue
        | EnvironmentParseState::DoubleQuoteValueEscape => finish_environment_assignment(
            &mut key,
            &mut value,
            key_trailing_whitespace,
            value_trailing_whitespace,
            state == EnvironmentParseState::Value,
            key_line,
            &mut parsed,
        ),
        EnvironmentParseState::Key => parsed
            .diagnostics
            .push(EnvironmentGeneratorDiagnostic::MalformedAssignment { line: key_line }),
        EnvironmentParseState::PreKey
        | EnvironmentParseState::Comment
        | EnvironmentParseState::CommentEscape => {}
    }
    parsed
}

#[cfg(target_os = "linux")]
fn generator_is_world_writable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o002 != 0)
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn generator_is_world_writable(_path: &Path) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn spawn_generator(
    invocation: &GeneratorInvocation,
    environment: &BTreeMap<String, String>,
    sandbox: Option<PreparedGeneratorSandbox>,
) -> Result<Child, String> {
    validate_invocation(invocation).map_err(|reason| reason.to_string())?;

    let prepared_exec = PreparedGeneratorExec::for_unit_generator(invocation, environment)?;
    // Command supplies only the fork/error-pipe mechanics. The pre-exec hook
    // invokes the prepared execve itself so SYSTEMD_EXEC_PID is part of the
    // exact envp passed to the generator (putenv alone would not modify the
    // envp that std::process::Command prepared before fork).
    let mut command = Command::new(&invocation.executable);
    configure_generator_child(&mut command, prepared_exec, sandbox);
    command.spawn().map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn spawn_environment_generator(
    executable: &Path,
    environment: &BTreeMap<String, String>,
    sandbox: Option<PreparedGeneratorSandbox>,
) -> Result<(Child, std::process::ChildStdout), String> {
    validate_environment_generator(executable)?;
    let prepared_exec = PreparedGeneratorExec::for_environment_generator(executable, environment)?;
    let mut command = Command::new(executable);
    // stdout is installed as fd 1 before `pre_exec`; descriptor hygiene keeps
    // 0/1/2 while atomically closing every inherited manager descriptor.
    command.stdin(Stdio::null()).stdout(Stdio::piped());
    configure_generator_child(&mut command, prepared_exec, sandbox);
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "generator stdout pipe was not installed".to_string())?;
    Ok((child, stdout))
}

#[cfg(not(target_os = "linux"))]
fn spawn_generator(
    _invocation: &GeneratorInvocation,
    _environment: &BTreeMap<String, String>,
) -> Result<Child, String> {
    Err(GeneratorExecutionError::UnsupportedPlatform.to_string())
}

#[cfg(not(target_os = "linux"))]
fn spawn_environment_generator(
    _executable: &Path,
    _environment: &BTreeMap<String, String>,
) -> Result<(Child, std::process::ChildStdout), String> {
    Err(GeneratorExecutionError::UnsupportedPlatform.to_string())
}

/// Install the small C-equivalent child setup that must happen after fork and
/// before exec. All parent-derived data has already been validated and copied
/// into `Command` before this hook is registered.
#[cfg(target_os = "linux")]
fn configure_generator_child(
    command: &mut Command,
    mut prepared_exec: PreparedGeneratorExec,
    sandbox: Option<PreparedGeneratorSandbox>,
) {
    // The closure only uses async-signal-safe process/signal primitives plus
    // `putenv`, which is the same narrowly scoped post-fork environment step
    // performed by C's `do_spawn()`. The fixed buffer is owned by the closure
    // until exec, so `putenv` never receives a dangling pointer. Do not add
    // allocation, formatting, locks, filesystem access, or Rust panics here.
    // SAFETY: CommandExt requires the caller to ensure post-fork safety. The
    // closure is intentionally restricted as documented above, and every
    // fallible syscall is translated to an io::Error before returning.
    unsafe_ffi!({
        command.pre_exec(move || {
            close_inherited_file_descriptors()?;
            reset_signal_state()?;
            if let Some(sandbox) = &sandbox {
                child_unshare_mount_namespace()?;
                sandbox.apply_after_unshare()?;
            }
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::umask(0o022);
            prepared_exec.exec_in_child()
        });
    })
}

#[cfg(target_os = "linux")]
fn probe_system_sandbox(sandbox: &PreparedGeneratorSandbox) -> Result<(), GeneratorExecutionError> {
    // Probe namespace creation separately. This preserves the C fallback
    // boundary: only clone/unshare privilege and EINVAL failures permit a
    // deliberate unsandboxed retry.
    if let Err(error) = run_sandbox_probe(None) {
        let errno = error.raw_os_error().unwrap_or(libc::EIO);
        if matches!(errno, libc::EPERM | libc::EACCES | libc::EINVAL) {
            return Err(GeneratorExecutionError::IsolationUnavailable {
                errno,
                message: error.to_string().into(),
            });
        }
        return Err(GeneratorExecutionError::IsolationSetup {
            message: error.to_string().into(),
        });
    }

    // Once CLONE_NEWNS itself is known to work, propagation/private-tmp
    // failures are setup failures and must remain fail-closed.
    run_sandbox_probe(Some(sandbox.clone())).map_err(|error| {
        GeneratorExecutionError::IsolationSetup {
            message: error.to_string().into(),
        }
    })
}

#[cfg(target_os = "linux")]
fn run_sandbox_probe(sandbox: Option<PreparedGeneratorSandbox>) -> std::io::Result<()> {
    // The executable is never reached: the pre-exec hook exits after the
    // syscall-only probe succeeds. `/proc/self/exe` merely gives Command a
    // stable absolute executable spelling without an initrd dependency.
    let mut command = Command::new("/proc/self/exe");
    // SAFETY: after fork the closure performs only unshare/mount/_exit and
    // reads parent-prepared storage. It neither allocates nor touches locks.
    unsafe_ffi!({
        command.pre_exec(move || {
            child_unshare_mount_namespace()?;
            if let Some(sandbox) = &sandbox {
                sandbox.apply_after_unshare()?;
            }
            libc::_exit(0)
        });
    });
    let mut child = command.spawn()?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(libc::EPROTO))
    }
}

/// Make every manager descriptor other than stdio close across the generator
/// `execve`. C's `FORK_CLOSE_ALL_FDS` is a hard isolation boundary: a
/// generator must not inherit PID 1's event-loop, bus, cgroup, or notify
/// descriptors. Linux 5.9+ provides an atomic close-on-exec range operation;
/// refusing older kernels is safer than silently leaking a capability.
#[cfg(target_os = "linux")]
fn close_inherited_file_descriptors() -> std::io::Result<()> {
    // SAFETY: close_range only mutates the calling child process's descriptor
    // table. The range starts above stdio, and CLOSE_RANGE_CLOEXEC preserves
    // the descriptors until the immediately following execve, where they are
    // closed atomically.
    // SAFETY: this syscall only changes the child descriptor table and does
    // not dereference any Rust pointer.
    let result = unsafe_ffi!({
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            1_u32 << 2, // CLOSE_RANGE_CLOEXEC from linux/close_range.h
        )
    });
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reset_signal_state() -> std::io::Result<()> {
    // SAFETY: sigemptyset and sigaction are called on initialized local
    // storage. SIGKILL and SIGSTOP are explicitly skipped because Linux does
    // not permit changing their dispositions.
    unsafe_ffi!({
        let mut signal_set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        if libc::sigemptyset(signal_set.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let signal_set = signal_set.assume_init();
        let action = libc::sigaction {
            sa_sigaction: libc::SIG_DFL,
            sa_mask: signal_set,
            sa_flags: 0,
            sa_restorer: None,
        };
        // SIGRTMAX is runtime-dependent on glibc. Iterating through it also
        // covers every standard signal while allowing the two glibc-reserved
        // real-time numbers to report EINVAL below.
        for signal in 1..=libc::SIGRTMAX() {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP {
                continue;
            }
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINVAL) {
                    continue;
                }
                return Err(error);
            }
        }
        if libc::sigprocmask(libc::SIG_SETMASK, &signal_set, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    });
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_systemd_exec_pid(storage: &mut [u8; 64], pid: libc::pid_t) -> std::io::Result<()> {
    const PREFIX: &[u8] = b"SYSTEMD_EXEC_PID=";
    storage[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut number = pid.unsigned_abs() as u64;
    let mut digits = [0_u8; 20];
    let mut count = 0;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    let start = PREFIX.len();
    if start + count + 1 > storage.len() {
        return Err(std::io::Error::from_raw_os_error(libc::EOVERFLOW));
    }
    for index in 0..count {
        storage[start + index] = digits[count - index - 1];
    }
    storage[start + count] = 0;
    Ok(())
}

fn wait_for_generators(
    mut running: Vec<RunningGenerator>,
    deadline: Instant,
) -> Result<GeneratorExecutionReport, GeneratorExecutionError> {
    let mut report = GeneratorExecutionReport::default();
    while !running.is_empty() {
        let mut index = 0;
        while index < running.len() {
            match running[index].child.try_wait() {
                Ok(Some(status)) => {
                    let child = running.swap_remove(index);
                    report.children.push(GeneratorChildReport {
                        executable: child.executable,
                        status: classify_exit_status(status),
                        world_writable: child.world_writable,
                    });
                }
                Ok(None) => index += 1,
                Err(error) => {
                    let mut child = running.swap_remove(index);
                    // Keep the child that produced the wait error in the
                    // cleanup set as well. A failed `try_wait()` is not proof
                    // that the process is gone; dropping it here could leave
                    // a running generator or an unreaped zombie behind while
                    // the remaining batch is terminated.
                    terminate_generators(std::slice::from_mut(&mut child));
                    terminate_generators(&mut running);
                    return Err(GeneratorExecutionError::Wait {
                        executable: child.executable,
                        message: error.to_string().into(),
                    });
                }
            }
        }

        if running.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            terminate_generators(&mut running);
            return Err(GeneratorExecutionError::TimedOut {
                report: Box::new(report),
            });
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    report
        .children
        .sort_by(|left, right| left.executable.cmp(&right.executable));
    Ok(report)
}

/// Wait for one serial environment generator without resetting the batch
/// deadline. `Err(())` means the caller must terminate its process group.
fn wait_for_environment_generator(child: &mut Child, deadline: Instant) -> Result<ExitStatus, ()> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() >= deadline => return Err(()),
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(_) => return Err(()),
        }
    }
}

fn terminate_generator_process_group(child: &mut Child) {
    #[cfg(target_os = "linux")]
    {
        let pid = child.id() as i32;
        // Every generator's pre-exec hook gives it a distinct process group,
        // so this also reaps helpers holding the stdout pipe open.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-pid),
            nix::sys::signal::Signal::SIGTERM,
        );
        std::thread::sleep(Duration::from_millis(10));
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let _ = child.wait();
}

fn terminate_generators(running: &mut [RunningGenerator]) {
    #[cfg(target_os = "linux")]
    for generator in running.iter_mut() {
        let pid = generator.child.id() as i32;
        // The pre-exec hook created one process group per generator. Negative
        // pid targets that group, preventing a shell generator from leaving a
        // timed-out helper behind.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-pid),
            nix::sys::signal::Signal::SIGTERM,
        );
    }
    std::thread::sleep(Duration::from_millis(10));
    #[cfg(target_os = "linux")]
    for generator in running.iter_mut() {
        let pid = generator.child.id() as i32;
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    for generator in running.iter_mut() {
        let _ = generator.child.wait();
    }
}

#[cfg(target_os = "linux")]
fn classify_exit_status(status: ExitStatus) -> GeneratorChildStatus {
    use std::os::unix::process::ExitStatusExt;

    match status.code() {
        Some(code) => GeneratorChildStatus::Exited(code),
        None => GeneratorChildStatus::Signaled(status.signal().unwrap_or(0)),
    }
}

#[cfg(not(target_os = "linux"))]
fn classify_exit_status(status: ExitStatus) -> GeneratorChildStatus {
    GeneratorChildStatus::Exited(status.code().unwrap_or(1))
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use crate::generator_setup::{GeneratorRunOutcome, LookupPaths};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root_beneath(base: &Path, name: &str) -> std::io::Result<PathBuf> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time must advance")
            .as_nanos();
        let root = base.join(format!(
            "systemd-core-rs-generator-runtime-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn temp_root(name: &str) -> PathBuf {
        temp_root_beneath(&std::env::temp_dir(), name).expect("must create temporary root")
    }

    fn paths(root: &Path) -> LookupPaths {
        LookupPaths {
            generator: Some(root.join("out")),
            generator_early: Some(root.join("out.early")),
            generator_late: Some(root.join("out.late")),
            ..LookupPaths::default()
        }
    }

    fn generator(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).expect("must write generator");
        fs::set_permissions(path, PermissionsExt::from_mode(0o755)).expect("must make executable");
    }

    fn direct_options() -> GeneratorExecutionOptions {
        GeneratorExecutionOptions {
            sandbox: GeneratorSandbox::UserManagerDirect,
            timeout: Duration::from_secs(2),
            environment: BTreeMap::from([(
                "RUST_GENERATOR_TEST".to_string(),
                "present".to_string(),
            )]),
        }
    }

    #[test]
    fn direct_lifecycle_uses_c_argv_environment_pid_and_umask_contract() {
        let root = temp_root("contract");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(
            &binaries.join("50-contract"),
            "printf '%s|%s|%s|%s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" \"$RUST_GENERATOR_TEST\" \"$SYSTEMD_EXEC_PID\" \"$$\" \"$(umask)\" > \"$1/contract\"",
        );
        let lookup = paths(&root);

        let outcome = run_generator_lifecycle(&lookup, &[binaries], &direct_options()).unwrap();
        let GeneratorRunOutcome::Executed { value: report, .. } = outcome else {
            panic!("generator search path must execute");
        };
        assert_eq!(report.children.len(), 1);
        assert_eq!(report.children[0].status, GeneratorChildStatus::Exited(0));
        let line = fs::read_to_string(lookup.generator.as_ref().unwrap().join("contract")).unwrap();
        let values: Vec<_> = line.trim_end().split('|').collect();
        assert_eq!(
            values[0],
            lookup.generator.as_ref().unwrap().to_string_lossy()
        );
        assert_eq!(
            values[1],
            lookup.generator_early.as_ref().unwrap().to_string_lossy()
        );
        assert_eq!(
            values[2],
            lookup.generator_late.as_ref().unwrap().to_string_lossy()
        );
        assert_eq!(values[3], "present");
        assert!(values[4].parse::<u32>().is_ok());
        assert_eq!(values[4], values[5]);
        assert_eq!(values[6], "0022");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn individual_generator_failure_is_reported_but_does_not_abort_parallel_batch() {
        let root = temp_root("ignore-errors");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(&binaries.join("10-fails"), "exit 7");
        generator(
            &binaries.join("20-succeeds"),
            "printf ok > \"$1/generated.service\"",
        );
        let lookup = paths(&root);

        let outcome = run_generator_lifecycle(&lookup, &[binaries], &direct_options()).unwrap();
        let GeneratorRunOutcome::Executed { value: report, .. } = outcome else {
            panic!("must execute");
        };
        assert!(report.has_abnormal_children());
        assert!(
            report
                .children
                .iter()
                .any(|child| child.status == GeneratorChildStatus::Exited(7))
        );
        assert!(
            report
                .children
                .iter()
                .any(|child| child.status == GeneratorChildStatus::Exited(0))
        );
        assert!(
            lookup
                .generator
                .as_ref()
                .unwrap()
                .join("generated.service")
                .is_file()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn timeout_kills_the_generator_process_group_and_reports_partial_batch() {
        let root = temp_root("timeout");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(&binaries.join("10-slow"), "sleep 5 & wait");
        let lookup = paths(&root);
        let mut options = direct_options();
        options.timeout = Duration::from_millis(20);

        let error = run_generator_lifecycle(&lookup, &[binaries], &options)
            .expect_err("slow generator must time out");
        assert!(matches!(
            error,
            GeneratorRunError::Execution {
                error: GeneratorExecutionError::TimedOut { .. },
                ..
            }
        ));
        assert!(!lookup.generator.as_ref().unwrap().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn system_execution_fails_closed_without_isolation() {
        let root = temp_root("isolation-required");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(&binaries.join("10-never"), "exit 0");
        let lookup = paths(&root);

        let error =
            run_generator_lifecycle(&lookup, &[binaries], &GeneratorExecutionOptions::default())
                .expect_err("system generator must require isolation");
        assert!(matches!(
            error,
            GeneratorRunError::Execution {
                error: GeneratorExecutionError::IsolationRequired,
                ..
            }
        ));
        assert!(!lookup.generator.as_ref().unwrap().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn isolated_mode_executes_or_returns_only_the_explicit_fallback_boundary() {
        // A successful private-/tmp sandbox intentionally hides the host
        // /tmp. Put both the fixture and output below C's writable /run
        // exception when the test has permission to exercise that path.
        let root = temp_root_beneath(Path::new("/run"), "isolated")
            .unwrap_or_else(|_| temp_root("isolated-fallback"));
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(&binaries.join("10-isolated"), "touch \"$1/isolated\"");
        let lookup = paths(&root);
        let mut options = direct_options();
        options.sandbox = GeneratorSandbox::SystemIsolated;

        match run_generator_lifecycle(&lookup, &[binaries], &options) {
            Ok(GeneratorRunOutcome::Executed { value: report, .. }) => {
                assert_eq!(report.children[0].status, GeneratorChildStatus::Exited(0));
                assert!(
                    lookup
                        .generator
                        .as_ref()
                        .unwrap()
                        .join("isolated")
                        .is_file()
                );
            }
            Err(GeneratorRunError::Execution { error, .. }) => {
                assert!(error.permits_system_fallback(), "unexpected error: {error}");
                assert!(!lookup.generator.as_ref().unwrap().exists());
            }
            outcome => panic!("unexpected isolated outcome: {outcome:?}"),
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mountinfo_parser_preserves_flags_and_excludes_api_subtrees() {
        let mountinfo = b"36 25 0:32 / / rw,nosuid,relatime - tmpfs tmpfs rw\n\
            37 36 0:5 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
            38 36 0:6 / /run rw,nosuid,nodev - tmpfs tmpfs rw\n\
            39 36 8:1 /usr /usr ro,nodev - ext4 /dev/root ro\n\
            40 36 0:40 / /path\\040with\\040spaces rw,noexec - tmpfs tmpfs rw\n\
            41 36 0:41 / /automount rw - autofs systemd-1 rw\n";
        let mounts = parse_read_only_mounts(mountinfo);

        assert_eq!(mounts.len(), 3);
        let by_path = mounts
            .iter()
            .map(|mount| (mount.target.as_bytes().to_vec(), mount.current_flags))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_path[b"/".as_slice()] & libc::MS_NOSUID as libc::c_ulong,
            libc::MS_NOSUID as libc::c_ulong
        );
        assert_eq!(
            by_path[b"/usr".as_slice()] & libc::MS_RDONLY as libc::c_ulong,
            libc::MS_RDONLY as libc::c_ulong
        );
        assert!(by_path.contains_key(b"/path with spaces".as_slice()));
        assert!(!by_path.contains_key(b"/proc".as_slice()));
        assert!(!by_path.contains_key(b"/run".as_slice()));
        assert!(!by_path.contains_key(b"/automount".as_slice()));
    }

    #[test]
    fn malformed_environment_fails_before_any_child_starts() {
        let root = temp_root("bad-environment");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(&binaries.join("10-never"), "touch \"$1/should-not-exist\"");
        let lookup = paths(&root);
        let mut options = direct_options();
        options
            .environment
            .insert("BAD=NAME".to_string(), "value".to_string());

        let error = run_generator_lifecycle(&lookup, &[binaries], &options)
            .expect_err("invalid environment must refuse execution");
        assert!(matches!(
            error,
            GeneratorRunError::Execution {
                error: GeneratorExecutionError::InvalidEnvironment { .. },
                ..
            }
        ));
        assert!(!lookup.generator.as_ref().unwrap().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn generator_does_not_inherit_manager_descriptors() {
        use std::os::fd::AsRawFd;

        let root = temp_root("close-fds");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        let (read_end, _write_end) = nix::unistd::pipe().unwrap();
        let inherited_fd = read_end.as_raw_fd().to_string();
        generator(
            &binaries.join("10-close-fds"),
            "test ! -e \"/proc/self/fd/$RUST_GENERATOR_INHERITED_FD\" && touch \"$1/closed\"",
        );
        let lookup = paths(&root);
        let mut options = direct_options();
        options
            .environment
            .insert("RUST_GENERATOR_INHERITED_FD".into(), inherited_fd);

        let outcome = run_generator_lifecycle(&lookup, &[binaries], &options).unwrap();
        let GeneratorRunOutcome::Executed { value: report, .. } = outcome else {
            panic!("must execute");
        };
        assert_eq!(report.children[0].status, GeneratorChildStatus::Exited(0));
        assert!(lookup.generator.as_ref().unwrap().join("closed").is_file());
        drop(read_end);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn environment_output_parser_matches_env_file_quotes_and_ignores_bad_records() {
        let parsed = parse_environment_generator_output(
            b"# ignored\nFOO=plain  \nBAR='two words'\nBAZ=\"one\\$two\"\nJOIN=left\\\nright\n1BAD=no\nNO_EQUALS\n",
        );
        assert_eq!(
            parsed.assignments,
            vec![
                ("FOO".to_string(), "plain".to_string()),
                ("BAR".to_string(), "two words".to_string()),
                ("BAZ".to_string(), "one$two".to_string()),
                ("JOIN".to_string(), "leftright".to_string()),
            ]
        );
        assert!(parsed.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            EnvironmentGeneratorDiagnostic::InvalidVariableName { name, .. } if name == "1BAD"
        )));
        assert!(parsed.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            EnvironmentGeneratorDiagnostic::MalformedAssignment { .. }
        )));
    }

    #[test]
    fn environment_generators_feed_valid_assignments_to_later_children_serially() {
        let root = temp_root("environment-serial");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(
            &binaries.join("10-first"),
            "printf 'FIRST=one\\nSPACE=\"two words\"\\n'",
        );
        generator(
            &binaries.join("20-second"),
            "test \"$FIRST\" = one\nprintf 'SECOND=%s\\n' \"$SPACE\"",
        );

        let report = execute_environment_generators(
            &[binaries],
            BTreeMap::from([("INITIAL".to_string(), "present".to_string())]),
            &direct_options(),
        )
        .unwrap();
        assert_eq!(report.children.len(), 2);
        assert!(
            report
                .children
                .iter()
                .all(|child| { matches!(child.status, GeneratorChildStatus::Exited(0)) })
        );
        assert_eq!(
            report.transient_environment.get("INITIAL"),
            Some(&"present".into())
        );
        assert_eq!(
            report.transient_environment.get("FIRST"),
            Some(&"one".into())
        );
        assert_eq!(
            report.transient_environment.get("SPACE"),
            Some(&"two words".into())
        );
        assert_eq!(
            report.transient_environment.get("SECOND"),
            Some(&"two words".into())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn environment_generator_exit_failure_is_ignored_but_output_is_consumed() {
        let root = temp_root("environment-exit");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(
            &binaries.join("10-fails"),
            "printf 'FROM_FAILED=yes\\n'\nexit 7",
        );
        generator(
            &binaries.join("20-follows"),
            "test \"$FROM_FAILED\" = yes\nprintf 'FOLLOWED=yes\\n'",
        );

        let report =
            execute_environment_generators(&[binaries], BTreeMap::new(), &direct_options())
                .unwrap();
        assert!(
            report
                .children
                .iter()
                .any(|child| child.status == GeneratorChildStatus::Exited(7))
        );
        assert_eq!(
            report.transient_environment.get("FROM_FAILED"),
            Some(&"yes".into())
        );
        assert_eq!(
            report.transient_environment.get("FOLLOWED"),
            Some(&"yes".into())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn environment_generator_timeout_uses_the_global_deadline() {
        let root = temp_root("environment-timeout");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(&binaries.join("10-slow"), "sleep 5 & wait");
        let mut options = direct_options();
        options.timeout = Duration::from_millis(20);

        assert!(matches!(
            execute_environment_generators(&[binaries], BTreeMap::new(), &options),
            Err(GeneratorExecutionError::TimedOut { .. })
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn environment_generator_stdout_is_bounded_without_deadlocking_the_child() {
        let root = temp_root("environment-output-limit");
        let binaries = root.join("bin");
        fs::create_dir_all(&binaries).unwrap();
        generator(
            &binaries.join("10-too-much"),
            "dd if=/dev/zero bs=1024 count=1025 2>/dev/null",
        );

        assert!(matches!(
            execute_environment_generators(&[binaries], BTreeMap::new(), &direct_options()),
            Err(GeneratorExecutionError::OutputLimitExceeded {
                limit: MAX_ENVIRONMENT_GENERATOR_OUTPUT,
                ..
            })
        ));
        let _ = fs::remove_dir_all(root);
    }
}
