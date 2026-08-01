// SPDX-License-Identifier: LGPL-2.1-or-later

//! Linux's post-fork service-launch path.
//!
//! This module keeps the deliberately small, failure-sensitive region between
//! `fork()` and `execve()` separate from parent-side launch-plan preparation.
//! The child performs no Rust heap allocation, formatting, environment access,
//! NSS lookup, lazy initialization, or mutex acquisition. Its remaining
//! nix/libc entry points are descriptor and process-control syscall wrappers;
//! identity changes use raw syscalls to avoid glibc's NPTL setxid machinery.

// Centralized unsafe expression boundary for this low-level adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper validates descriptors, pointers, and
        // ownership before evaluating this expression.
        unsafe { $expression }
    }};
}
use super::{
    ProcessIdentity, SpawnConfirmation, SpawnSecurity, SpawnStdio, SpawnedService, parse_command,
};
use caps::CapSet;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::SigSet;
use nix::unistd::{Pid, pipe2, read, setsid};
use seccompiler::BpfProgram;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

#[path = "linux_cgroup.rs"]
mod cgroup;
#[path = "linux_environment.rs"]
mod environment;
#[path = "linux_exec_status.rs"]
mod exec_status;
#[path = "linux_hygiene.rs"]
mod hygiene;
#[path = "linux_idle.rs"]
mod idle;
#[path = "linux_process.rs"]
mod process;
use cgroup::delegate_cgroup_access;
use environment::prepare_environment;
use exec_status::consume_exec_status_bytes;
use hygiene::{
    child_sanitize_inherited_fds, close_original_activation_fds, duplicate_activation_fds,
    duplicate_child_fd_cloexec, install_activation_fds, redirect_child_stdio,
    reset_child_signal_dispositions,
};
use process::{ServiceFork, spawn_process, terminate_unconfirmed_child};

// Keep the process-identity operations private to the Linux launch
// implementation while making the parent-side spawn API available to the
// sibling module. A direct `pub(super) use` would try to widen the visibility
// of the child module's `pub(super)` functions and is rejected by Rust's
// privacy rules.
pub(super) fn acquire_process_identity(pid: u32) -> Result<ProcessIdentity, String> {
    process::acquire_process_identity(pid)
}

pub(super) fn signal_process_identity(
    identity: &ProcessIdentity,
    signal: i32,
) -> Result<(), String> {
    process::signal_process_identity(identity, signal)
}

/// A socket-activation descriptor borrowed from the manager for the duration
/// of a single spawn. The child duplicates it before changing any descriptor
/// numbers, so this type never transfers ownership away from the manager.
///
/// The child exposes descriptors in slice order as 3, 4, ... and exports the
/// corresponding names through `LISTEN_FDNAMES`.
#[derive(Debug)]
pub struct ActivationFd<'fd> {
    pub fd: BorrowedFd<'fd>,
    pub name: &'fd str,
}

/// Preopened unit-cgroup capabilities borrowed from PID 1.
///
/// The launcher never opens a cgroup by path and never takes ownership of this
/// set. `target_directory` is the `clone3(CLONE_INTO_CGROUP)` target and
/// `target_procs` is retained for fork-compatible self-placement. For
/// delegated units, `delegate_root` remains distinct from a payload or
/// `.control` target so access can be granted without confusing ownership
/// boundaries. Duplicates are CLOEXEC and never survive `execve`.
#[derive(Debug, Clone, Copy)]
pub struct CgroupPlacement<'fd> {
    delegate_root: BorrowedFd<'fd>,
    target_directory: BorrowedFd<'fd>,
    target_procs: BorrowedFd<'fd>,
    delegated: bool,
    recursive_target_access: bool,
}

impl<'fd> CgroupPlacement<'fd> {
    pub fn new(
        delegate_root: BorrowedFd<'fd>,
        target_directory: BorrowedFd<'fd>,
        target_procs: BorrowedFd<'fd>,
        delegated: bool,
        recursive_target_access: bool,
    ) -> Self {
        Self {
            delegate_root,
            target_directory,
            target_procs,
            delegated,
            recursive_target_access,
        }
    }
}

/// The current state of an asynchronously acknowledged launch's status channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStatus {
    Pending,
    Execed,
}

const EXEC_STATUS_EXEC_ATTEMPT: u8 = 1;
const EXEC_STATUS_FAILURE: u8 = 2;

/// Parent-owned state for observing a launched child. The descriptor is
/// nonblocking, so PID 1 can poll it from its normal child-reap path without
/// delaying unrelated jobs.
#[derive(Debug)]
pub struct ExecStatusHandle {
    status_read: OwnedFd,
    exec_attempted: bool,
    failure_started: bool,
    bytes: [u8; std::mem::size_of::<ChildSpawnFailure>()],
    received: usize,
}

impl AsFd for ExecStatusHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.status_read.as_fd()
    }
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub(super) enum ChildSpawnStage {
    SignalDisposition = 1,
    SignalMask = 2,
    StatusPipe = 3,
    ActivationFd = 4,
    ActivationRemap = 5,
    StandardInput = 6,
    StandardOutput = 7,
    StandardError = 8,
    Session = 9,
    Security = 10,
    Cgroup = 11,
    DescriptorHygiene = 12,
    Exec = 13,
}

impl ChildSpawnStage {
    fn description(raw: u32) -> &'static str {
        match raw {
            1 => "resetting the child signal dispositions",
            2 => "resetting the child signal mask",
            3 => "preparing the exec-status pipe",
            4 => "duplicating socket-activation descriptors",
            5 => "remapping socket-activation descriptors",
            6 => "redirecting standard input",
            7 => "redirecting standard output",
            8 => "redirecting standard error",
            9 => "creating the child session",
            10 => "applying child security setup",
            11 => "placing the child in its unit cgroup",
            12 => "sanitizing inherited file descriptors",
            13 => "executing the service command",
            _ => "performing unknown child setup",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ChildSpawnFailure {
    stage: u32,
    errno: i32,
}

struct PreparedActivation {
    source_fds: Vec<RawFd>,
    listen_fds_assignment: CString,
    listen_fd_names_assignment: CString,
    first_temporary_fd: RawFd,
}

#[derive(Clone, Copy)]
struct PreparedCapabilityState {
    effective: u64,
    permitted: u64,
    inheritable: u64,
}

struct PreparedCapabilities {
    bounding_allowed: Option<u64>,
    cap_last_cap: i32,
    state: PreparedCapabilityState,
    ambient: u64,
    ambient_configured: bool,
    keep_across_uid_change: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProtectHomeMode {
    None,
    ReadOnly,
    InaccessibleTmpfs,
}

struct PreparedNamespace {
    unshare_flags: libc::c_int,
    needs_mount_namespace: bool,
    private_users: bool,
    private_tmp: bool,
    private_devices: bool,
    protect_system_paths: Vec<CString>,
    protect_home: ProtectHomeMode,
    protect_kernel_tunables: bool,
    protect_kernel_modules: bool,
    protect_control_groups: bool,
    home_paths: Vec<CString>,
    device_paths: Vec<(CString, u32, u32)>,
}

struct PreparedExecContext {
    skip: bool,
    has_watchdog: bool,
    environment: Vec<CString>,
    working_directory: Option<CString>,
    oom_score_adjust: Option<Vec<u8>>,
    nice: Option<i32>,
    umask: Option<libc::mode_t>,
    limits: Vec<(libc::__rlimit_resource_t, libc::rlimit)>,
    uid: Option<libc::uid_t>,
    gid: Option<libc::gid_t>,
    supplementary_groups: Vec<libc::gid_t>,
}

struct PreparedSecurity {
    namespace: PreparedNamespace,
    capabilities: Option<PreparedCapabilities>,
    secure_bits: Option<u32>,
    exec_context: PreparedExecContext,
    no_new_privileges: bool,
    seccomp_filter: Option<BpfProgram>,
}

struct PreparedEnvironment {
    storage: Vec<CString>,
    has_activation: bool,
    has_watchdog: bool,
}

struct ChildScratch {
    activation_temporary_fds: Vec<RawFd>,
    pointers: Vec<*const libc::c_char>,
    main_pid: [u8; 32],
    listen_pid: [u8; 32],
    watchdog_pid: [u8; 32],
    main_pid_index: usize,
    listen_pid_index: Option<usize>,
    watchdog_pid_index: Option<usize>,
}

struct PreparedLaunch {
    // Keeps every pointer in `argv` live through execve.
    _argv_storage: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    executable_candidates: Vec<CString>,
    environment: PreparedEnvironment,
    activation: PreparedActivation,
    cgroup_directory_fd: Option<OwnedFd>,
    cgroup_threaded: bool,
    cgroup_procs_fd: Option<OwnedFd>,
    stdio: SpawnStdio,
    security: PreparedSecurity,
}

fn reset_child_signal_mask() -> Result<(), nix::errno::Errno> {
    SigSet::empty().thread_set_mask()
}

fn prepare_activation_fds(
    activation_fds: &[ActivationFd<'_>],
) -> Result<PreparedActivation, String> {
    if activation_fds.len() > (i32::MAX as usize - libc::STDERR_FILENO as usize) {
        return Err("too many socket-activation descriptors".to_string());
    }

    let mut names = Vec::with_capacity(activation_fds.len());
    let mut source_fds = Vec::with_capacity(activation_fds.len());

    for activation_fd in activation_fds {
        if activation_fd.name.is_empty()
            || activation_fd.name.contains(':')
            || activation_fd.name.as_bytes().contains(&0)
        {
            return Err(format!(
                "invalid socket-activation descriptor name {:?}; names must be nonempty and contain neither ':' nor NUL",
                activation_fd.name
            ));
        }

        let source_fd = activation_fd.fd.as_raw_fd();
        fcntl(activation_fd.fd, FcntlArg::F_GETFD).map_err(|error| {
            format!(
                "invalid socket-activation descriptor {} ({}): {error}",
                activation_fd.name, source_fd
            )
        })?;
        source_fds.push(source_fd);
        names.push(activation_fd.name);
    }

    let listen_fds_assignment = CString::new(format!("LISTEN_FDS={}", activation_fds.len()))
        .map_err(|error| format!("failed to encode LISTEN_FDS: {error}"))?;
    let listen_fd_names_assignment = CString::new(format!("LISTEN_FDNAMES={}", names.join(":")))
        .map_err(|error| format!("failed to encode LISTEN_FDNAMES: {error}"))?;
    let first_temporary_fd = (libc::STDERR_FILENO + 1)
        .checked_add(source_fds.len() as RawFd)
        .ok_or_else(|| "socket-activation descriptor layout overflows RawFd".to_string())?;

    Ok(PreparedActivation {
        source_fds,
        listen_fds_assignment,
        listen_fd_names_assignment,
        first_temporary_fd,
    })
}

fn validate_stdio_fds(stdio: SpawnStdio) -> Result<(), String> {
    for (label, fd) in [
        ("stdin", stdio.stdin_fd),
        ("stdout", stdio.stdout_fd),
        ("stderr", stdio.stderr_fd),
    ] {
        if let Some(fd) = fd {
            // SAFETY: F_GETFD accepts any integer descriptor and is the
            // operation used here to determine whether the raw descriptor is
            // valid; constructing BorrowedFd before that check would violate
            // its validity contract.
            // SAFETY: F_GETFD accepts the raw integer specifically to validate it.
            if unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD)) < 0 {
                return Err(format!(
                    "invalid {label} descriptor {fd}: {}",
                    nix::errno::Errno::last()
                ));
            }
        }
    }
    if let Some(idle_pipe) = stdio.idle_pipe {
        for (label, fd) in [
            ("idle child wait", idle_pipe.child_wait_fd),
            ("idle manager release", idle_pipe.manager_release_fd),
            ("idle manager alert", idle_pipe.manager_alert_fd),
            ("idle child alert", idle_pipe.child_alert_fd),
        ] {
            // SAFETY: F_GETFD validates this raw descriptor before the
            // child-side protocol uses it after fork.
            if unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD)) < 0 {
                return Err(format!(
                    "invalid {label} descriptor {fd}: {}",
                    nix::errno::Errno::last()
                ));
            }
        }
    }
    Ok(())
}

fn capability_mask(set: &caps::CapsHashSet) -> u64 {
    set.iter().fold(0u64, |mask, capability| {
        let index = capability.index() as u32;
        if index < u64::BITS {
            mask | (1u64 << index)
        } else {
            mask
        }
    })
}

fn read_capability_state() -> Result<PreparedCapabilityState, String> {
    Ok(PreparedCapabilityState {
        effective: capability_mask(
            &caps::read(None, CapSet::Effective)
                .map_err(|error| format!("failed to read effective capabilities: {error}"))?,
        ),
        permitted: capability_mask(
            &caps::read(None, CapSet::Permitted)
                .map_err(|error| format!("failed to read permitted capabilities: {error}"))?,
        ),
        inheritable: capability_mask(
            &caps::read(None, CapSet::Inheritable)
                .map_err(|error| format!("failed to read inheritable capabilities: {error}"))?,
        ),
    })
}

fn prepare_capabilities(
    security: &SpawnSecurity,
    changes_uid: bool,
) -> Result<Option<PreparedCapabilities>, String> {
    if security.capability_bounding_set.is_empty() && security.ambient_capabilities.is_empty() {
        return Ok(None);
    }

    let mut state = read_capability_state()?;
    let bounding_allowed = if security.capability_bounding_set.is_empty() {
        None
    } else {
        let allowed = capability_mask(&super::parse_capability_rule_set(
            &security.capability_bounding_set,
        )?);
        state.effective &= allowed;
        state.permitted &= allowed;
        state.inheritable &= allowed;
        Some(allowed)
    };

    let ambient = if security.ambient_capabilities.is_empty() {
        0
    } else {
        capability_mask(&super::parse_capability_rule_set(
            &security.ambient_capabilities,
        )?)
    };
    state.effective |= ambient;
    state.permitted |= ambient;
    state.inheritable |= ambient;

    Ok(Some(PreparedCapabilities {
        bounding_allowed,
        cap_last_cap: super::cap_last_cap(),
        state,
        ambient,
        ambient_configured: !security.ambient_capabilities.is_empty(),
        keep_across_uid_change: changes_uid && ambient != 0,
    }))
}

fn prepare_namespace(security: &SpawnSecurity) -> Result<PreparedNamespace, String> {
    let needs_mount_namespace = security.private_tmp
        || security.private_devices
        || security.private_mounts
        || security.protect_system.is_some()
        || security.protect_home.is_some()
        || security.protect_kernel_tunables
        || security.protect_kernel_modules
        || security.protect_control_groups;

    let mut unshare_flags = 0;
    if needs_mount_namespace {
        unshare_flags |= libc::CLONE_NEWNS;
    }
    if security.private_network {
        unshare_flags |= libc::CLONE_NEWNET;
    }
    if security.private_ipc {
        unshare_flags |= libc::CLONE_NEWIPC;
    }
    if security.protect_hostname {
        unshare_flags |= libc::CLONE_NEWUTS;
    }
    if security.private_users {
        unshare_flags |= libc::CLONE_NEWUSER;
    }

    let protect_system_paths = match security
        .protect_system
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("") | Some("no" | "false" | "off" | "0") => Vec::new(),
        Some("full") => vec!["/usr", "/boot"],
        Some("strict") => vec!["/usr", "/boot", "/"],
        Some(_) => vec!["/usr"],
    }
    .into_iter()
    .map(CString::new)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| format!("invalid ProtectSystem path: {error}"))?;

    let protect_home = match security
        .protect_home
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("read-only") => ProtectHomeMode::ReadOnly,
        Some("yes" | "true" | "on" | "1" | "tmpfs") => ProtectHomeMode::InaccessibleTmpfs,
        _ => ProtectHomeMode::None,
    };

    let home_paths = ["/home", "/root", "/run/user"]
        .into_iter()
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid ProtectHome path: {error}"))?;
    let device_paths = [
        ("/dev/null", 1, 3),
        ("/dev/zero", 1, 5),
        ("/dev/random", 1, 8),
        ("/dev/urandom", 1, 9),
        ("/dev/full", 1, 7),
        ("/dev/tty", 5, 0),
    ]
    .into_iter()
    .map(|(path, major, minor)| {
        CString::new(path)
            .map(|path| (path, major, minor))
            .map_err(|error| format!("invalid private device path: {error}"))
    })
    .collect::<Result<Vec<_>, _>>()?;

    Ok(PreparedNamespace {
        unshare_flags,
        needs_mount_namespace,
        private_users: security.private_users,
        private_tmp: security.private_tmp,
        private_devices: security.private_devices,
        protect_system_paths,
        protect_home,
        protect_kernel_tunables: security.protect_kernel_tunables,
        protect_kernel_modules: security.protect_kernel_modules,
        protect_control_groups: security.protect_control_groups,
        home_paths,
        device_paths,
    })
}

fn prepare_exec_context(security: &SpawnSecurity) -> Result<PreparedExecContext, String> {
    let skip = security.command_prefixes.contains("!!");
    let (environment, has_watchdog) = prepare_environment(security, skip)?;
    if skip {
        return Ok(PreparedExecContext {
            skip,
            has_watchdog,
            environment,
            working_directory: None,
            oom_score_adjust: None,
            nice: None,
            umask: None,
            limits: Vec::new(),
            uid: None,
            gid: None,
            supplementary_groups: Vec::new(),
        });
    }

    let working_directory = security
        .working_directory
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(CString::new)
        .transpose()
        .map_err(|error| format!("invalid WorkingDirectory: {error}"))?;
    let oom_score_adjust = security
        .oom_score_adjust
        .map(|value| format!("{value}\n").into_bytes());
    let umask = match security.umask.as_deref() {
        Some(raw) => Some(
            super::parse_umask_value(raw).ok_or_else(|| format!("invalid UMask value: {raw}"))?
                as libc::mode_t,
        ),
        None => None,
    };

    let mut limits = Vec::with_capacity(security.limits.len());
    for (name, raw) in &security.limits {
        let Some(resource) = super::limit_name_to_resource(name) else {
            continue;
        };
        let limit = super::parse_limit_value(raw)
            .ok_or_else(|| format!("invalid {name} resource limit: {raw}"))?;
        limits.push((
            resource,
            libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            },
        ));
    }

    let changes_identity = !security.command_prefixes.contains('+');
    let (uid, gid, supplementary_groups) = if changes_identity {
        let (uid, gid) =
            super::resolve_uid_gid(security.user.as_deref(), security.group.as_deref())?;
        let groups = super::resolve_supplementary_groups(&security.supplementary_groups)?
            .into_iter()
            .map(|group| group as libc::gid_t)
            .collect();
        (
            uid.map(|uid| uid as libc::uid_t),
            gid.map(|gid| gid as libc::gid_t),
            groups,
        )
    } else {
        (None, None, Vec::new())
    };

    Ok(PreparedExecContext {
        skip,
        has_watchdog,
        environment,
        working_directory,
        oom_score_adjust,
        nice: security.nice,
        umask,
        limits,
        uid,
        gid,
        supplementary_groups,
    })
}

fn prepare_security(security: &SpawnSecurity) -> Result<PreparedSecurity, String> {
    super::enforce_system_call_architectures(&security.system_call_architectures)?;
    let exec_context = prepare_exec_context(security)?;
    let capabilities = prepare_capabilities(security, exec_context.uid.is_some())?;
    let secure_bits = if security.secure_bits.is_empty() {
        None
    } else {
        let mut bits = 0u32;
        for rule in &security.secure_bits {
            bits |= super::secure_bit_mask(rule)
                .ok_or_else(|| format!("unknown SecureBits token: {rule}"))?;
        }
        Some(bits)
    };
    let no_new_privileges = security.no_new_privileges
        || (security.command_prefixes.contains('!') && !security.command_prefixes.contains("!!"));
    let seccomp_filter = super::prepare_system_call_filter(
        &security.system_call_filter,
        security.system_call_error_number.as_deref(),
    )?;
    if seccomp_filter
        .as_ref()
        .is_some_and(|filter| filter.len() > u16::MAX as usize)
    {
        return Err("compiled seccomp filter exceeds Linux sock_fprog length".to_string());
    }

    Ok(PreparedSecurity {
        namespace: prepare_namespace(security)?,
        capabilities,
        secure_bits,
        exec_context,
        no_new_privileges,
        seccomp_filter,
    })
}

fn environment_path(environment: &[CString]) -> &[u8] {
    environment
        .iter()
        .find_map(|entry| entry.as_bytes().strip_prefix(b"PATH="))
        .unwrap_or(b"/bin:/usr/bin")
}

fn prepare_executable_candidates(
    program: &CString,
    environment: &[CString],
) -> Result<Vec<CString>, String> {
    if program.as_bytes().contains(&b'/') {
        return Ok(vec![program.clone()]);
    }

    let mut candidates = Vec::new();
    for directory in environment_path(environment).split(|byte| *byte == b':') {
        let directory = if directory.is_empty() {
            b".".as_slice()
        } else {
            directory
        };
        let mut candidate = Vec::with_capacity(directory.len() + 1 + program.as_bytes().len());
        candidate.extend_from_slice(directory);
        candidate.push(b'/');
        candidate.extend_from_slice(program.as_bytes());
        candidates.push(
            CString::new(candidate)
                .map_err(|error| format!("invalid executable search path: {error}"))?,
        );
    }
    Ok(candidates)
}

impl ChildScratch {
    fn new(launch: &PreparedLaunch) -> Self {
        let mut pointers = Vec::with_capacity(
            launch.environment.storage.len()
                + if launch.environment.has_activation {
                    5
                } else {
                    2
                }
                + usize::from(launch.environment.has_watchdog),
        );
        pointers.extend(
            launch
                .environment
                .storage
                .iter()
                .map(|entry| entry.as_ptr()),
        );

        let main_pid_index = pointers.len();
        pointers.push(std::ptr::null());
        let listen_pid_index = if !launch.environment.has_activation {
            None
        } else {
            let index = pointers.len();
            pointers.push(std::ptr::null());
            pointers.push(launch.activation.listen_fds_assignment.as_ptr());
            pointers.push(launch.activation.listen_fd_names_assignment.as_ptr());
            Some(index)
        };
        let watchdog_pid_index = if launch.environment.has_watchdog {
            let index = pointers.len();
            pointers.push(std::ptr::null());
            Some(index)
        } else {
            None
        };
        pointers.push(std::ptr::null());

        Self {
            activation_temporary_fds: vec![-1; launch.activation.source_fds.len()],
            pointers,
            main_pid: [0; 32],
            listen_pid: [0; 32],
            watchdog_pid: [0; 32],
            main_pid_index,
            listen_pid_index,
            watchdog_pid_index,
        }
    }

    fn prepare_pid_environment(&mut self, pid: libc::pid_t) {
        write_decimal_assignment(&mut self.main_pid, b"MAINPID=", pid as u32);
        self.pointers[self.main_pid_index] = self.main_pid.as_ptr().cast();
        if let Some(index) = self.listen_pid_index {
            write_decimal_assignment(&mut self.listen_pid, b"LISTEN_PID=", pid as u32);
            self.pointers[index] = self.listen_pid.as_ptr().cast();
        }
        if let Some(index) = self.watchdog_pid_index {
            write_decimal_assignment(&mut self.watchdog_pid, b"WATCHDOG_PID=", pid as u32);
            self.pointers[index] = self.watchdog_pid.as_ptr().cast();
        }
    }
}

fn write_decimal_assignment(output: &mut [u8; 32], prefix: &[u8], value: u32) {
    output.fill(0);
    output[..prefix.len()].copy_from_slice(prefix);

    let mut reversed = [0u8; 10];
    let mut digits = 0;
    let mut remaining = value;
    loop {
        reversed[digits] = b'0' + (remaining % 10) as u8;
        digits += 1;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    for index in 0..digits {
        output[prefix.len() + index] = reversed[digits - index - 1];
    }
}

impl PreparedLaunch {
    fn new(
        exec_start: &str,
        stdio: SpawnStdio,
        security: SpawnSecurity,
        activation_fds: &[ActivationFd<'_>],
        cgroup: Option<CgroupPlacement<'_>>,
    ) -> Result<Self, String> {
        let (program, command_args) = parse_command(exec_start);
        if program.is_empty() {
            return Err("empty command".to_string());
        }

        let program =
            CString::new(program).map_err(|error| format!("invalid executable path: {error}"))?;
        let command_args = command_args
            .into_iter()
            .map(CString::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("invalid executable argument: {error}"))?;
        let mut argv_storage = Vec::with_capacity(command_args.len() + 1);
        argv_storage.push(program);
        argv_storage.extend(command_args);
        let mut argv = argv_storage
            .iter()
            .map(|argument| argument.as_ptr())
            .collect::<Vec<_>>();
        argv.push(std::ptr::null());

        let activation = prepare_activation_fds(activation_fds)?;
        let cgroup_delegate_root_fd = cgroup
            .filter(|placement| placement.delegated)
            .map(|placement| placement.delegate_root)
            .map(|fd| {
                fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(3))
                    .map_err(|error| {
                        format!("failed to retain delegated cgroup root descriptor: {error}")
                    })
                    // SAFETY: F_DUPFD_CLOEXEC returns a new owned descriptor.
                    .map(|fd| unsafe_ffi!(OwnedFd::from_raw_fd(fd)))
            })
            .transpose()?;
        let cgroup_directory_fd = cgroup
            .map(|placement| placement.target_directory)
            .map(|fd| {
                fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(3))
                    .map_err(|error| {
                        format!("failed to retain preopened cgroup directory descriptor: {error}")
                    })
                    // SAFETY: F_DUPFD_CLOEXEC returns a new owned descriptor.
                    .map(|fd| unsafe_ffi!(OwnedFd::from_raw_fd(fd)))
            })
            .transpose()?;
        let cgroup_threaded = cgroup_directory_fd
            .as_ref()
            .map(|directory| cgroup_is_threaded(directory.as_fd()))
            .transpose()?
            .unwrap_or(false);
        let cgroup_procs_fd = cgroup
            .map(|placement| placement.target_procs)
            .map(|fd| {
                fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(3))
                    .map_err(|error| {
                        format!("failed to retain preopened cgroup.procs descriptor: {error}")
                    })
                    // SAFETY: F_DUPFD_CLOEXEC returns a new owned descriptor.
                    .map(|fd| unsafe_ffi!(OwnedFd::from_raw_fd(fd)))
            })
            .transpose()?;
        validate_stdio_fds(stdio)?;
        let mut security = prepare_security(&security)?;
        let cgroup_delegated = cgroup.is_some_and(|placement| placement.delegated);
        if cgroup_delegated {
            let uid = security.exec_context.uid;
            let gid = security.exec_context.gid;
            if uid.is_some() || gid.is_some() {
                delegate_cgroup_access(
                    cgroup_delegate_root_fd
                        .as_ref()
                        .expect("delegated placement retains its root")
                        .as_fd(),
                    cgroup_directory_fd
                        .as_ref()
                        .expect("cgroup placement retains its target")
                        .as_fd(),
                    uid,
                    gid,
                    cgroup.is_some_and(|placement| placement.recursive_target_access),
                )?;
            }
        }
        let has_watchdog = security.exec_context.has_watchdog;
        let environment_storage = std::mem::take(&mut security.exec_context.environment);
        let executable_candidates =
            prepare_executable_candidates(&argv_storage[0], &environment_storage)?;
        let environment = PreparedEnvironment {
            storage: environment_storage,
            has_activation: !activation.source_fds.is_empty(),
            has_watchdog,
        };

        Ok(Self {
            _argv_storage: argv_storage,
            argv,
            executable_candidates,
            environment,
            activation,
            cgroup_directory_fd,
            cgroup_threaded,
            cgroup_procs_fd,
            stdio,
            security,
        })
    }
}

fn cgroup_is_threaded(directory: BorrowedFd<'_>) -> Result<bool, String> {
    // SAFETY: directory is a live descriptor, the filename is a static
    // NUL-terminated component, and openat returns a new descriptor.
    let fd = unsafe_ffi!({
        libc::openat(
            directory.as_raw_fd(),
            c"cgroup.type".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    });
    if fd < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL);
        if errno == libc::ENOENT {
            return Ok(false);
        }
        return Err(format!(
            "failed to inspect preopened cgroup type: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    // SAFETY: openat returned a new descriptor with no existing owner.
    let fd = unsafe_ffi!(OwnedFd::from_raw_fd(fd));
    let mut contents = [0u8; 64];
    let mut used = 0usize;
    loop {
        if used == contents.len() {
            return Err("cgroup.type exceeded its bounded launch-time read".to_string());
        }
        match read(fd.as_fd(), &mut contents[used..]) {
            Ok(0) => break,
            Ok(size) => used += size,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(format!("failed to read cgroup.type: {error}")),
        }
    }
    let content = std::str::from_utf8(&contents[..used])
        .map_err(|_| "cgroup.type contains non-UTF-8 data".to_string())?;
    Ok(content
        .split_ascii_whitespace()
        .any(|word| matches!(word, "threaded" | "invalid")))
}

pub(super) fn child_errno_or_invalid_argument() -> i32 {
    // SAFETY: Linux exposes the calling thread's errno through this pointer.
    // The child reads it immediately after a failed libc operation.
    let errno = unsafe_ffi!(*libc::__errno_location());
    if errno == 0 { libc::EINVAL } else { errno }
}

pub(super) fn child_report_failure(status_fd: RawFd, stage: ChildSpawnStage, errno: i32) -> ! {
    let failure = ChildSpawnFailure {
        stage: stage as u32,
        errno: if errno == 0 { libc::EINVAL } else { errno },
    };
    let mut bytes = [0; std::mem::size_of::<ChildSpawnFailure>()];
    bytes[0..4].copy_from_slice(&failure.stage.to_ne_bytes());
    bytes[4..8].copy_from_slice(&failure.errno.to_ne_bytes());
    let _ = child_write_all(status_fd, &[EXEC_STATUS_FAILURE]);
    let _ = child_write_all(status_fd, &bytes);

    // SAFETY: after fork, `_exit` is the only termination primitive that does
    // not run parent-owned Rust destructors or flush parent-owned stdio state.
    unsafe_ffi!(libc::_exit(127))
}

fn child_write_all(status_fd: RawFd, bytes: &[u8]) -> Result<(), i32> {
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: the slice is valid for the requested length and the file
        // descriptor is used only by this child after fork.
        let result = unsafe_ffi!({
            libc::write(
                status_fd,
                bytes[written..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - written,
            )
        });
        if result > 0 {
            written += result as usize;
            continue;
        }
        if result < 0 && child_errno_or_invalid_argument() == libc::EINTR {
            continue;
        }
        return Err(child_errno_or_invalid_argument());
    }
    Ok(())
}

fn child_write_cgroup_procs(cgroup_procs_fd: RawFd) -> Result<(), i32> {
    let bytes = b"0\n";
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: this is the async-signal-safe Linux write syscall. The
        // descriptor and static byte slice were prepared before fork.
        let result = unsafe_ffi!({
            libc::syscall(
                libc::SYS_write,
                cgroup_procs_fd,
                bytes[written..].as_ptr(),
                bytes.len() - written,
            )
        });
        if result > 0 {
            written += result as usize;
            continue;
        }
        let errno = child_errno_or_invalid_argument();
        if result < 0 && errno == libc::EINTR {
            continue;
        }
        return Err(errno);
    }
    Ok(())
}

fn parent_place_child_best_effort(cgroup_procs_fd: BorrowedFd<'_>, child: Pid) {
    // The child-side "0\n" write and its status record are authoritative.
    // This PID write only narrows the fork-to-placement race, mirroring
    // systemd's parent-side backstop without turning its result into success.
    let line = format!("{}\n", child.as_raw());
    let mut written = 0usize;
    while written < line.len() {
        match nix::unistd::write(cgroup_procs_fd, &line.as_bytes()[written..]) {
            Ok(0) | Err(_) => return,
            Ok(size) => written += size,
        }
    }
}

fn child_mark_exec_attempt(status_fd: RawFd) {
    if let Err(errno) = child_write_all(status_fd, &[EXEC_STATUS_EXEC_ATTEMPT]) {
        child_report_failure(status_fd, ChildSpawnStage::StatusPipe, errno);
    }
}

fn child_path_exists(path: &CStr) -> bool {
    // SAFETY: `path` is a live, NUL-terminated string prepared before fork.
    unsafe_ffi!(libc::access(path.as_ptr(), libc::F_OK) == 0)
}

fn child_mount(
    source: Option<&CStr>,
    target: &CStr,
    filesystem: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> Result<(), i32> {
    // SAFETY: all pointers either refer to live prepared C strings or are null.
    let result = unsafe_ffi!({
        libc::mount(
            source.map_or(std::ptr::null(), CStr::as_ptr),
            target.as_ptr(),
            filesystem.map_or(std::ptr::null(), CStr::as_ptr),
            flags,
            data.map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    });
    if result == 0 {
        Ok(())
    } else {
        Err(child_errno_or_invalid_argument())
    }
}

fn child_ensure_directory(path: &CStr, mode: libc::mode_t) -> Result<(), i32> {
    if child_path_exists(path) {
        return Ok(());
    }
    // SAFETY: `path` remains valid for the duration of mkdir.
    let result = unsafe_ffi!(libc::mkdir(path.as_ptr(), mode));
    if result == 0 || child_errno_or_invalid_argument() == libc::EEXIST {
        Ok(())
    } else {
        Err(child_errno_or_invalid_argument())
    }
}

fn child_write_file(path: &CStr, content: &[u8]) -> Result<(), i32> {
    // SAFETY: `path` is NUL terminated; no O_CREAT mode argument is needed.
    let fd = unsafe_ffi!(libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC));
    if fd < 0 {
        return Err(child_errno_or_invalid_argument());
    }
    let result = child_write_all(fd, content);
    // SAFETY: `fd` was opened above and is no longer used after this close.
    unsafe_ffi!({
        libc::close(fd);
    });
    result
}

fn child_remount_read_only(path: &CStr) -> Result<(), i32> {
    if !child_path_exists(path) {
        return Ok(());
    }
    child_mount(
        None,
        path,
        None,
        (libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY) as libc::c_ulong,
        None,
    )
}

fn child_mount_tmpfs(path: &CStr, options: &CStr) -> Result<(), i32> {
    child_ensure_directory(path, 0o755)?;
    let tmpfs = c"tmpfs";
    child_mount(Some(tmpfs), path, Some(tmpfs), 0, Some(options))
}

fn child_apply_namespace(namespace: &PreparedNamespace) -> Result<(), i32> {
    if namespace.unshare_flags != 0 {
        // SAFETY: the flags are a validated OR of CLONE_NEW* constants.
        if unsafe_ffi!(libc::unshare(namespace.unshare_flags)) < 0 {
            return Err(child_errno_or_invalid_argument());
        }
    }

    if namespace.private_users {
        let setgroups = c"/proc/self/setgroups";
        let uid_map = c"/proc/self/uid_map";
        let gid_map = c"/proc/self/gid_map";
        let _ = child_write_file(setgroups, b"deny\n");
        child_write_file(uid_map, b"0 65534 1\n")?;
        child_write_file(gid_map, b"0 65534 1\n")?;
    }

    if namespace.needs_mount_namespace {
        let root = c"/";
        child_mount(
            None,
            root,
            None,
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            None,
        )?;
    }

    let tmp = c"/tmp";
    let var_tmp = c"/var/tmp";
    let dev = c"/dev";
    let tmp_options = c"mode=1777,nosuid,nodev";
    let dev_options = c"mode=0755,nosuid,noexec";
    let inaccessible_options = c"mode=000,nosuid,nodev,noexec";

    if namespace.private_tmp {
        child_mount_tmpfs(tmp, tmp_options)?;
        child_mount_tmpfs(var_tmp, tmp_options)?;
    }

    if namespace.private_devices {
        child_mount_tmpfs(dev, dev_options)?;
        for (path, major, minor) in &namespace.device_paths {
            // SAFETY: prepared paths remain valid. Ignoring unlink failure
            // matches the previous implementation before mknod.
            unsafe_ffi!({
                libc::unlink(path.as_ptr());
            });
            let mode = libc::S_IFCHR as libc::mode_t | 0o666;
            // SAFETY: the path is prepared and makedev receives bounded u32s.
            if unsafe_ffi!(libc::mknod(
                path.as_ptr(),
                mode,
                libc::makedev(*major, *minor)
            )) < 0
            {
                return Err(child_errno_or_invalid_argument());
            }
        }
    }

    for path in &namespace.protect_system_paths {
        child_remount_read_only(path)?;
    }
    match namespace.protect_home {
        ProtectHomeMode::None => {}
        ProtectHomeMode::ReadOnly => {
            for path in &namespace.home_paths {
                child_remount_read_only(path)?;
            }
        }
        ProtectHomeMode::InaccessibleTmpfs => {
            for path in &namespace.home_paths {
                child_mount_tmpfs(path, inaccessible_options)?;
            }
        }
    }

    if namespace.protect_kernel_tunables {
        let proc_sys = c"/proc/sys";
        child_remount_read_only(proc_sys)?;
    }
    if namespace.protect_kernel_modules {
        let proc_modules = c"/proc/modules";
        let dev_null = c"/dev/null";
        if child_path_exists(proc_modules) {
            child_mount(
                Some(dev_null),
                proc_modules,
                None,
                libc::MS_BIND as libc::c_ulong,
                None,
            )?;
            child_remount_read_only(proc_modules)?;
        }
    }
    if namespace.protect_control_groups {
        let cgroup = c"/sys/fs/cgroup";
        child_remount_read_only(cgroup)?;
    }

    Ok(())
}

#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn child_set_capability_state(state: PreparedCapabilityState) -> Result<(), i32> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        LinuxCapabilityData {
            effective: state.effective as u32,
            permitted: state.permitted as u32,
            inheritable: state.inheritable as u32,
        },
        LinuxCapabilityData {
            effective: (state.effective >> 32) as u32,
            permitted: (state.permitted >> 32) as u32,
            inheritable: (state.inheritable >> 32) as u32,
        },
    ];
    // SAFETY: header/data use the Linux capability v3 ABI and remain live for
    // the duration of the capset syscall.
    let result = unsafe_ffi!(libc::syscall(libc::SYS_capset, &header, data.as_ptr()));
    if result == 0 {
        Ok(())
    } else {
        Err(child_errno_or_invalid_argument())
    }
}

fn child_raise_ambient_capabilities(mask: u64) -> Result<(), i32> {
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL accepts zero in all remaining slots.
    if unsafe_ffi!({
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    }) < 0
    {
        return Err(child_errno_or_invalid_argument());
    }
    for capability in 0..u64::BITS {
        if mask & (1u64 << capability) == 0 {
            continue;
        }
        // SAFETY: capability is in the representable kernel capability range.
        if unsafe_ffi!({
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE,
                capability as libc::c_ulong,
                0,
                0,
            )
        }) < 0
        {
            return Err(child_errno_or_invalid_argument());
        }
    }
    Ok(())
}

fn child_apply_capabilities(capabilities: &PreparedCapabilities) -> Result<(), i32> {
    if capabilities.keep_across_uid_change {
        // SAFETY: PR_SET_KEEPCAPS accepts a boolean scalar.
        if unsafe_ffi!(libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0)) < 0 {
            return Err(child_errno_or_invalid_argument());
        }
    }
    if let Some(allowed) = capabilities.bounding_allowed {
        for capability in 0..=capabilities.cap_last_cap {
            if capability < u64::BITS as i32 && allowed & (1u64 << capability) != 0 {
                continue;
            }
            // SAFETY: capability comes from the kernel's cap_last_cap bound.
            if unsafe_ffi!(libc::prctl(
                libc::PR_CAPBSET_DROP,
                capability as libc::c_ulong,
                0,
                0,
                0
            )) < 0
            {
                return Err(child_errno_or_invalid_argument());
            }
        }
    }
    child_set_capability_state(capabilities.state)?;
    if capabilities.ambient_configured {
        child_raise_ambient_capabilities(capabilities.ambient)?;
    }
    Ok(())
}

fn child_reapply_capabilities_after_uid(capabilities: &PreparedCapabilities) -> Result<(), i32> {
    if !capabilities.keep_across_uid_change {
        return Ok(());
    }
    child_set_capability_state(capabilities.state)?;
    if capabilities.ambient_configured {
        child_raise_ambient_capabilities(capabilities.ambient)?;
    }
    // SAFETY: PR_SET_KEEPCAPS accepts a boolean scalar.
    if unsafe_ffi!(libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0)) < 0 {
        return Err(child_errno_or_invalid_argument());
    }
    Ok(())
}

#[repr(C)]
struct LinuxSockFprog {
    len: libc::c_ushort,
    filter: *const seccompiler::sock_filter,
}

fn child_install_seccomp_filter(filter: &BpfProgram) -> Result<(), i32> {
    if filter.is_empty() || filter.len() > u16::MAX as usize {
        return Err(libc::EINVAL);
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS accepts a boolean scalar.
    if unsafe_ffi!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) < 0 {
        return Err(child_errno_or_invalid_argument());
    }
    let program = LinuxSockFprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr(),
    };
    // SAFETY: `program` and its already-compiled instruction slice remain live
    // through the syscall; the kernel copies both before returning.
    let result = unsafe_ffi!({
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &program,
        )
    });
    if result == 0 {
        Ok(())
    } else {
        Err(child_errno_or_invalid_argument())
    }
}

fn child_apply_exec_context(context: &PreparedExecContext) -> Result<(), i32> {
    if context.skip {
        return Ok(());
    }

    if let Some(content) = &context.oom_score_adjust {
        let path = c"/proc/self/oom_score_adj";
        child_write_file(path, content)?;
    }
    if let Some(nice) = context.nice {
        // SAFETY: raw setpriority targets the calling process and uses scalars.
        if unsafe_ffi!(libc::syscall(
            libc::SYS_setpriority,
            libc::PRIO_PROCESS,
            0,
            nice
        )) < 0
        {
            return Err(child_errno_or_invalid_argument());
        }
    }
    if let Some(mask) = context.umask {
        // SAFETY: raw umask accepts any mode_t and cannot fail.
        unsafe_ffi!({
            libc::syscall(libc::SYS_umask, mask);
        })
    }
    for (resource, limit) in &context.limits {
        // SAFETY: `limit` remains live throughout setrlimit.
        if unsafe_ffi!(libc::setrlimit(*resource, limit)) < 0 {
            return Err(child_errno_or_invalid_argument());
        }
    }
    if !context.supplementary_groups.is_empty() {
        // SAFETY: the slice is live and uses kernel gid_t elements. A direct
        // syscall avoids glibc's multi-thread setxid coordination after fork.
        if unsafe_ffi!({
            libc::syscall(
                libc::SYS_setgroups,
                context.supplementary_groups.len(),
                context.supplementary_groups.as_ptr(),
            )
        }) < 0
        {
            return Err(child_errno_or_invalid_argument());
        }
    }
    if let Some(gid) = context.gid {
        // SAFETY: gid was resolved before fork; raw syscall avoids NPTL locks.
        if unsafe_ffi!(libc::syscall(libc::SYS_setgid, gid)) < 0 {
            return Err(child_errno_or_invalid_argument());
        }
    }
    if let Some(uid) = context.uid {
        // SAFETY: uid was resolved before fork; raw syscall avoids NPTL locks.
        if unsafe_ffi!(libc::syscall(libc::SYS_setuid, uid)) < 0 {
            return Err(child_errno_or_invalid_argument());
        }
    }
    if let Some(path) = &context.working_directory {
        // SAFETY: path is a live, NUL-terminated C string.
        if unsafe_ffi!(libc::syscall(libc::SYS_chdir, path.as_ptr())) < 0 {
            return Err(child_errno_or_invalid_argument());
        }
    }
    Ok(())
}

fn child_apply_security(security: &PreparedSecurity) -> Result<(), i32> {
    child_apply_namespace(&security.namespace)?;
    if let Some(capabilities) = &security.capabilities {
        child_apply_capabilities(capabilities)?;
    }
    if let Some(bits) = security.secure_bits {
        // SAFETY: bits is composed exclusively from validated secure-bit masks.
        if unsafe_ffi!(libc::prctl(
            libc::PR_SET_SECUREBITS,
            bits as libc::c_ulong,
            0,
            0,
            0
        )) < 0
        {
            return Err(child_errno_or_invalid_argument());
        }
    }
    child_apply_exec_context(&security.exec_context)?;
    if let Some(capabilities) = &security.capabilities {
        child_reapply_capabilities_after_uid(capabilities)?;
    }
    if security.no_new_privileges {
        // SAFETY: PR_SET_NO_NEW_PRIVS accepts a boolean scalar.
        if unsafe_ffi!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) < 0 {
            return Err(child_errno_or_invalid_argument());
        }
    }
    if let Some(filter) = &security.seccomp_filter {
        child_install_seccomp_filter(filter)?;
    }
    Ok(())
}

impl ExecStatusHandle {
    /// Advance a nonblocking exec-status read. The child emits an attempt
    /// marker immediately before `execve`; only a following CLOEXEC EOF is a
    /// successful-exec acknowledgement. This avoids treating an early child
    /// death as a successful launch merely because its pipe endpoint closed.
    pub fn poll(&mut self) -> Result<ExecStatus, String> {
        let mut input = [0u8; 32];
        loop {
            match read(self.status_read.as_fd(), &mut input) {
                Ok(0) if self.failure_started => {
                    return Err(
                        "child exec-status pipe closed with a truncated failure record".to_string(),
                    );
                }
                Ok(0) if self.exec_attempted => return Ok(ExecStatus::Execed),
                Ok(0) => {
                    return Err("child exited before attempting exec".to_string());
                }
                Ok(count) => {
                    consume_exec_status_bytes(
                        &mut self.exec_attempted,
                        &mut self.failure_started,
                        &mut self.bytes,
                        &mut self.received,
                        &input[..count],
                    )?;
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(nix::errno::Errno::EAGAIN) => return Ok(ExecStatus::Pending),
                Err(error) => {
                    return Err(format!("failed to read child exec-status pipe: {error}"));
                }
            }
        }
    }
}

fn make_status_read_nonblocking(status_read: &OwnedFd) -> Result<(), nix::errno::Errno> {
    let current = fcntl(status_read.as_fd(), FcntlArg::F_GETFL)?;
    let flags = OFlag::from_bits_truncate(current) | OFlag::O_NONBLOCK;
    fcntl(status_read.as_fd(), FcntlArg::F_SETFL(flags))?;
    Ok(())
}

fn wait_for_exec_status(
    status_read: OwnedFd,
    child: Pid,
    identity: &ProcessIdentity,
) -> Result<(), String> {
    let mut status = ExecStatusHandle {
        status_read,
        exec_attempted: false,
        failure_started: false,
        bytes: [0; std::mem::size_of::<ChildSpawnFailure>()],
        received: 0,
    };

    loop {
        match status.poll() {
            Ok(ExecStatus::Execed) => return Ok(()),
            // The descriptor is intentionally blocking in this path. Keep
            // this branch defensive in case that invariant changes.
            Ok(ExecStatus::Pending) => continue,
            Err(error) => {
                terminate_unconfirmed_child(child, identity);
                return Err(error);
            }
        }
    }
}

pub(super) fn spawn_service_with_options_and_activation(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
) -> Result<u32, String> {
    spawn_service_inner(
        exec_start,
        stdio,
        security,
        activation_fds,
        None,
        SpawnConfirmation::Execed,
        true,
    )
    .map(|launch| launch.pid)
}

pub(super) fn spawn_service_with_options_and_activation_in_cgroup(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
    cgroup: CgroupPlacement<'_>,
) -> Result<u32, String> {
    spawn_service_inner(
        exec_start,
        stdio,
        security,
        activation_fds,
        Some(cgroup),
        SpawnConfirmation::Execed,
        true,
    )
    .map(|launch| launch.pid)
}

pub(super) fn spawn_service_with_confirmation_and_activation(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
    confirmation: SpawnConfirmation,
) -> Result<SpawnedService, String> {
    // The manager owns the asynchronous transition. The selected policy is
    // returned alongside the status handle and decides whether EOF advances
    // StartPost; this launcher intentionally never blocks PID 1.
    spawn_service_inner(
        exec_start,
        stdio,
        security,
        activation_fds,
        None,
        confirmation,
        false,
    )
}

pub(super) fn spawn_service_with_confirmation_and_activation_in_cgroup(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
    cgroup: CgroupPlacement<'_>,
    confirmation: SpawnConfirmation,
) -> Result<SpawnedService, String> {
    spawn_service_inner(
        exec_start,
        stdio,
        security,
        activation_fds,
        Some(cgroup),
        confirmation,
        false,
    )
}

fn spawn_service_inner(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
    cgroup: Option<CgroupPlacement<'_>>,
    confirmation: SpawnConfirmation,
    await_exec: bool,
) -> Result<SpawnedService, String> {
    let launch = PreparedLaunch::new(exec_start, stdio, security, activation_fds, cgroup)?;
    // All backing storage is allocated before fork. Only these fixed-capacity
    // buffers are mutated by the child; launch policy remains immutable.
    let mut child_scratch = ChildScratch::new(&launch);
    let (status_read, status_write) = pipe2(OFlag::O_CLOEXEC)
        .map_err(|error| format!("failed to create exec-status pipe: {error}"))?;

    match spawn_process(
        launch
            .cgroup_directory_fd
            .as_ref()
            .map(|directory| directory.as_fd()),
        launch.cgroup_threaded,
    )? {
        ServiceFork::Parent {
            child,
            identity,
            cloned_into_cgroup,
        } => {
            drop(status_write);
            if !cloned_into_cgroup && let Some(cgroup_procs_fd) = launch.cgroup_procs_fd.as_ref() {
                parent_place_child_best_effort(cgroup_procs_fd.as_fd(), child);
            }
            if await_exec {
                wait_for_exec_status(status_read, child, &identity)?;
                return Ok(SpawnedService {
                    pid: child.as_raw() as u32,
                    confirmation,
                    identity: Some(identity),
                    exec_status: None,
                });
            }
            if let Err(error) = make_status_read_nonblocking(&status_read) {
                terminate_unconfirmed_child(child, &identity);
                return Err(format!(
                    "failed to make child exec-status pipe nonblocking: {error}"
                ));
            }
            Ok(SpawnedService {
                pid: child.as_raw() as u32,
                confirmation,
                identity: Some(identity),
                exec_status: Some(ExecStatusHandle {
                    status_read,
                    exec_attempted: false,
                    failure_started: false,
                    bytes: [0; std::mem::size_of::<ChildSpawnFailure>()],
                    received: 0,
                }),
            })
        }
        ServiceFork::Child => {
            drop(status_read);
            if let Err(errno) = reset_child_signal_dispositions() {
                child_report_failure(
                    status_write.as_raw_fd(),
                    ChildSpawnStage::SignalDisposition,
                    errno,
                );
            }
            if let Err(error) = reset_child_signal_mask() {
                child_report_failure(
                    status_write.as_raw_fd(),
                    ChildSpawnStage::SignalMask,
                    error as i32,
                );
            }

            if let Some(idle_pipe) = launch.stdio.idle_pipe {
                idle::child_do_idle_pipe_dance(idle_pipe);
            }

            let status_fd = match duplicate_child_fd_cloexec(
                status_write.as_raw_fd(),
                launch.activation.first_temporary_fd,
            ) {
                Ok(fd) => fd,
                Err(error) => child_report_failure(
                    status_write.as_raw_fd(),
                    ChildSpawnStage::StatusPipe,
                    error as i32,
                ),
            };
            drop(status_write);

            if let Some(cgroup_procs_fd) = launch.cgroup_procs_fd.as_ref()
                && let Err(errno) = child_write_cgroup_procs(cgroup_procs_fd.as_raw_fd())
            {
                child_report_failure(status_fd, ChildSpawnStage::Cgroup, errno);
            }

            if let Err(error) = duplicate_activation_fds(
                &launch.activation.source_fds,
                &mut child_scratch.activation_temporary_fds,
            ) {
                child_report_failure(status_fd, error.0, error.1);
            }
            if let Err(error) = setsid() {
                child_report_failure(status_fd, ChildSpawnStage::Session, error as i32);
            }

            redirect_child_stdio(
                launch.stdio.stdin_fd,
                libc::STDIN_FILENO,
                ChildSpawnStage::StandardInput,
                status_fd,
            );
            redirect_child_stdio(
                launch.stdio.stdout_fd,
                libc::STDOUT_FILENO,
                ChildSpawnStage::StandardOutput,
                status_fd,
            );
            redirect_child_stdio(
                launch.stdio.stderr_fd,
                libc::STDERR_FILENO,
                ChildSpawnStage::StandardError,
                status_fd,
            );

            close_original_activation_fds(&launch.activation.source_fds);
            if let Err(error) =
                install_activation_fds(&child_scratch.activation_temporary_fds, status_fd)
            {
                child_report_failure(status_fd, error.0, error.1);
            }

            if let Err(errno) =
                child_sanitize_inherited_fds(launch.activation.first_temporary_fd, status_fd)
            {
                child_report_failure(status_fd, ChildSpawnStage::DescriptorHygiene, errno);
            }

            if let Err(errno) = child_apply_security(&launch.security) {
                child_report_failure(status_fd, ChildSpawnStage::Security, errno);
            }

            // SAFETY: raw getpid has no preconditions.
            let child_pid = unsafe_ffi!(libc::syscall(libc::SYS_getpid) as libc::pid_t);
            child_scratch.prepare_pid_environment(child_pid);

            child_mark_exec_attempt(status_fd);
            let mut exec_errno = libc::ENOENT;
            let mut saw_access_denied = false;
            for executable in &launch.executable_candidates {
                // SAFETY: executable, argv, and envp point into allocations
                // owned by `launch` and all pointer arrays are NUL terminated.
                unsafe_ffi!({
                    libc::execve(
                        executable.as_ptr(),
                        launch.argv.as_ptr(),
                        child_scratch.pointers.as_ptr(),
                    );
                });
                exec_errno = child_errno_or_invalid_argument();
                match exec_errno {
                    libc::EACCES => saw_access_denied = true,
                    libc::ENOENT | libc::ENOTDIR => {}
                    _ => break,
                }
            }
            if saw_access_denied && matches!(exec_errno, libc::ENOENT | libc::ENOTDIR) {
                exec_errno = libc::EACCES;
            }
            child_report_failure(status_fd, ChildSpawnStage::Exec, exec_errno);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::FdFlag;
    use nix::sys::wait::{WaitStatus, waitpid};
    use std::fs::File;
    use std::sync::Mutex;

    static SIGNAL_DISPOSITION_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn ignore_sigpipe_for_test() -> libc::sigaction {
        // SAFETY: sigemptyset initializes the action mask. `previous` is
        // initialized by the successful sigaction call before it is returned,
        // and SIGPIPE has a mutable disposition on Linux.
        unsafe_ffi!({
            let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            assert_eq!(libc::sigemptyset(mask.as_mut_ptr()), 0);
            let action = libc::sigaction {
                sa_sigaction: libc::SIG_IGN,
                sa_mask: mask.assume_init(),
                sa_flags: 0,
                sa_restorer: None,
            };
            let mut previous = std::mem::MaybeUninit::<libc::sigaction>::uninit();
            assert_eq!(
                libc::sigaction(libc::SIGPIPE, &action, previous.as_mut_ptr()),
                0
            );
            previous.assume_init()
        })
    }

    fn restore_sigpipe_after_test(previous: &libc::sigaction) {
        // SAFETY: `previous` came from sigaction for SIGPIPE in this process
        // and is passed back unchanged to restore the test process state.
        assert_eq!(
            unsafe_ffi!(libc::sigaction(
                libc::SIGPIPE,
                previous,
                std::ptr::null_mut()
            )),
            0
        );
    }

    fn clear_close_on_exec(descriptor: &File) {
        fcntl(descriptor.as_fd(), FcntlArg::F_SETFD(FdFlag::empty()))
            .expect("clear FD_CLOEXEC on the parent-owned test descriptor");
    }

    fn assert_service_exited_cleanly(pid: u32) {
        loop {
            match waitpid(Pid::from_raw(pid as i32), None) {
                Ok(WaitStatus::Exited(_, 0)) => return,
                Ok(status) => panic!("service {pid} did not exit cleanly: {status:?}"),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => panic!("failed to wait for service {pid}: {error}"),
            }
        }
    }

    fn failure_payload(stage: u32, errno: i32) -> [u8; std::mem::size_of::<ChildSpawnFailure>()] {
        let mut payload = [0; std::mem::size_of::<ChildSpawnFailure>()];
        payload[0..4].copy_from_slice(&stage.to_ne_bytes());
        payload[4..8].copy_from_slice(&errno.to_ne_bytes());
        payload
    }

    #[test]
    fn exec_attempt_then_failure_is_not_an_exec_acknowledgement() {
        let mut attempted = false;
        let mut failure_started = false;
        let mut failure = [0; std::mem::size_of::<ChildSpawnFailure>()];
        let mut received = 0;
        let payload = failure_payload(ChildSpawnStage::Exec as u32, libc::ENOENT);
        let mut input = Vec::with_capacity(2 + payload.len());
        input.push(EXEC_STATUS_EXEC_ATTEMPT);
        input.push(EXEC_STATUS_FAILURE);
        input.extend_from_slice(&payload);

        let error = consume_exec_status_bytes(
            &mut attempted,
            &mut failure_started,
            &mut failure,
            &mut received,
            &input,
        )
        .expect_err("exec failure record must not acknowledge the launch");

        assert!(attempted);
        assert!(error.contains("executing the service command"));
    }

    #[test]
    fn duplicate_exec_attempt_marker_is_rejected() {
        let mut attempted = false;
        let mut failure_started = false;
        let mut failure = [0; std::mem::size_of::<ChildSpawnFailure>()];
        let mut received = 0;

        let error = consume_exec_status_bytes(
            &mut attempted,
            &mut failure_started,
            &mut failure,
            &mut received,
            &[EXEC_STATUS_EXEC_ATTEMPT, EXEC_STATUS_EXEC_ATTEMPT],
        )
        .expect_err("duplicate marker must be malformed");

        assert!(error.contains("duplicate exec-attempt marker"));
    }

    #[test]
    fn decimal_environment_assignment_uses_fixed_storage() {
        let mut output = [0xff; 32];
        write_decimal_assignment(&mut output, b"MAINPID=", 4_294_967_295);
        let terminator = output
            .iter()
            .position(|byte| *byte == 0)
            .expect("assignment is NUL terminated");
        assert_eq!(&output[..terminator], b"MAINPID=4294967295");
        assert!(output[terminator..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn executable_candidates_follow_prepared_path_without_execvp() {
        let program = CString::new("daemon").unwrap();
        let environment = vec![CString::new("PATH=/opt/bin::/usr/bin").unwrap()];
        let candidates = prepare_executable_candidates(&program, &environment).unwrap();
        let rendered = candidates
            .iter()
            .map(|candidate| candidate.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rendered, ["/opt/bin/daemon", "./daemon", "/usr/bin/daemon"]);
    }

    #[test]
    fn manager_notify_socket_overrides_unit_environment_transformations() {
        let security = SpawnSecurity {
            environment: vec!["NOTIFY_SOCKET=/unit-controlled".to_owned()],
            unset_environment: vec!["NOTIFY_SOCKET".to_owned()],
            notify_socket: Some("/run/systemd/notify".to_owned()),
            ..SpawnSecurity::default()
        };
        let (environment, has_watchdog) =
            prepare_environment(&security, false).expect("prepare environment");
        assert!(!has_watchdog);
        let notify_entries = environment
            .iter()
            .filter_map(|entry| entry.to_str().ok())
            .filter(|entry| entry.starts_with("NOTIFY_SOCKET="))
            .collect::<Vec<_>>();
        assert_eq!(notify_entries, ["NOTIFY_SOCKET=/run/systemd/notify"]);
    }

    #[test]
    fn manager_notify_socket_requires_an_absolute_non_nul_path() {
        let security = SpawnSecurity {
            notify_socket: Some("relative.socket".to_owned()),
            ..SpawnSecurity::default()
        };
        assert!(prepare_environment(&security, false).is_err());
    }

    #[test]
    fn manager_watchdog_environment_overrides_unit_values() {
        let security = SpawnSecurity {
            environment: vec!["WATCHDOG_USEC=unit-controlled".to_owned()],
            unset_environment: vec!["WATCHDOG_USEC".to_owned()],
            watchdog_usec: Some(1_500_000),
            ..SpawnSecurity::default()
        };
        let (environment, has_watchdog) =
            prepare_environment(&security, false).expect("prepare environment");
        let watchdog_entries = environment
            .iter()
            .filter_map(|entry| entry.to_str().ok())
            .filter(|entry| entry.starts_with("WATCHDOG_USEC="))
            .collect::<Vec<_>>();
        assert_eq!(watchdog_entries, ["WATCHDOG_USEC=1500000"]);
        assert!(has_watchdog);

        let (_, skipped_watchdog) = prepare_environment(
            &SpawnSecurity {
                command_prefixes: "!!".to_owned(),
                watchdog_usec: Some(1_500_000),
                ..security
            },
            true,
        )
        .expect("prepare skipped environment");
        assert!(!skipped_watchdog);
    }

    #[test]
    fn service_exec_closes_unlisted_parent_descriptors() {
        let inherited = File::open("/dev/null").expect("open inherited test descriptor");
        clear_close_on_exec(&inherited);
        let raw = inherited.as_raw_fd();
        assert!(raw > libc::STDERR_FILENO);

        let command =
            format!("/bin/sh -c 'if [ -e /proc/self/fd/{raw} ]; then exit 41; else exit 0; fi'");
        let pid = spawn_service_with_options_and_activation(
            &command,
            SpawnStdio::default(),
            SpawnSecurity::default(),
            &[],
        )
        .expect("spawn service with inherited manager descriptor");

        assert_service_exited_cleanly(pid);
    }

    #[test]
    fn service_exec_preserves_only_remapped_activation_descriptors() {
        let activation_source = File::open("/dev/null").expect("open activation test descriptor");
        clear_close_on_exec(&activation_source);
        let activation = [ActivationFd {
            fd: activation_source.as_fd(),
            name: "test-activation",
        }];

        let command = "/bin/sh -c 'test -e /proc/self/fd/3 && test \"$LISTEN_FDS\" = 1 && test \"$LISTEN_FDNAMES\" = test-activation'";
        let pid = spawn_service_with_options_and_activation(
            command,
            SpawnStdio::default(),
            SpawnSecurity::default(),
            &activation,
        )
        .expect("spawn service with activation descriptor");

        assert_service_exited_cleanly(pid);
    }

    #[test]
    fn service_exec_restores_pid1_sigpipe_disposition() {
        let _guard = SIGNAL_DISPOSITION_TEST_LOCK
            .lock()
            .expect("signal-disposition test lock must not be poisoned");
        let previous = ignore_sigpipe_for_test();

        let spawned = spawn_service_with_options_and_activation(
            "/bin/sh -c 'kill -PIPE $$; exit 91'",
            SpawnStdio::default(),
            SpawnSecurity::default(),
            &[],
        );
        restore_sigpipe_after_test(&previous);
        let pid = spawned.expect("spawn service after making the manager ignore SIGPIPE");

        match waitpid(Pid::from_raw(pid as i32), None) {
            Ok(WaitStatus::Signaled(_, nix::sys::signal::Signal::SIGPIPE, _)) => {}
            Ok(status) => panic!("service inherited SIGPIPE ignore state: {status:?}"),
            Err(error) => panic!("failed to wait for SIGPIPE service: {error}"),
        }
    }
}
