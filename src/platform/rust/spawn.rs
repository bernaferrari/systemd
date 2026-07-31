// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

#[cfg(target_os = "linux")]
use caps::{self, Capability, CapsHashSet};
#[cfg(target_os = "linux")]
use nix::sys::signal::{SigSet, Signal};
#[cfg(target_os = "linux")]
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
#[cfg(target_os = "linux")]
use nix::unistd::{Group, Pid, User};
#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, TargetArch, compile_from_json};
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(not(target_os = "linux"))]
use std::os::fd::FromRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(not(target_os = "linux"))]
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{ActivationFd, CgroupPlacement, ExecStatus, ExecStatusHandle};

/// Selects the point at which a service launch is acknowledged to the unit
/// state machine. `Type=exec` needs an exec acknowledgement; `Type=simple`
/// deliberately does not. Both retain an asynchronous status pipe so a
/// pre-exec setup failure is not mistaken for a running service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnConfirmation {
    Forked,
    Execed,
}

/// A launched child plus, on Linux, the asynchronous exec-status channel
/// consumed by PID 1's service state machine.
#[derive(Debug)]
pub struct SpawnedService {
    pub pid: u32,
    confirmation: SpawnConfirmation,
    identity: Option<ProcessIdentity>,
    #[cfg(target_os = "linux")]
    exec_status: Option<linux::ExecStatusHandle>,
}

impl SpawnedService {
    pub fn confirmation(&self) -> SpawnConfirmation {
        self.confirmation
    }

    pub fn take_process_identity(&mut self) -> Option<ProcessIdentity> {
        self.identity.take()
    }

    #[cfg(target_os = "linux")]
    pub fn take_exec_status(&mut self) -> Option<linux::ExecStatusHandle> {
        self.exec_status.take()
    }
}

/// Manager-owned identity for a process.
///
/// Linux callers retain a pidfd whenever the kernel can provide one. A
/// numeric-only identity is permitted solely when pidfd acquisition failed
/// because the system ran out of descriptors or memory, matching C
/// `pidref_set_pid()` degradation.
#[derive(Debug)]
pub struct ProcessIdentity {
    pid: u32,
    #[cfg(target_os = "linux")]
    pidfd: Option<OwnedFd>,
}

impl ProcessIdentity {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[cfg(target_os = "linux")]
    pub fn has_pidfd(&self) -> bool {
        self.pidfd.is_some()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn has_pidfd(&self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    pub fn as_pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.pidfd.as_ref().map(AsFd::as_fd)
    }

    fn numeric(pid: u32) -> Self {
        Self {
            pid,
            #[cfg(target_os = "linux")]
            pidfd: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn with_pidfd(pid: u32, pidfd: OwnedFd) -> Self {
        Self {
            pid,
            pidfd: Some(pidfd),
        }
    }

    pub fn signal(&self, signal: i32) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            linux::signal_process_identity(self, signal)
        }

        #[cfg(not(target_os = "linux"))]
        kill_process(self.pid, signal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    Running,
    ExitedCleanly,
    ExitedWithCode(i32),
    KilledBySignal(i32),
}

pub struct ChildProcess {
    pub pid: u32,
    pub command: String,
    pub started: Instant,
    pub state: ChildState,
}

struct TrackedProcess {
    identity: ProcessIdentity,
    child: Option<ChildProcess>,
}

pub struct ProcessTracker {
    processes: HashMap<u32, TrackedProcess>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpawnStdio {
    pub stdin_fd: Option<i32>,
    pub stdout_fd: Option<i32>,
    pub stderr_fd: Option<i32>,
    /// The four manager-owned descriptors used by C's `Type=idle` protocol.
    /// They remain borrowed by the manager; the post-fork child closes the
    /// two manager ends before waiting on `child_wait_fd` for HUP.
    pub idle_pipe: Option<IdlePipe>,
}

/// Borrowed descriptors for the `Type=idle` pipe protocol from
/// `manager_allocate_idle_pipe()` / `do_idle_pipe_dance()`.
///
/// The manager owns all four descriptors for the lifetime of one gate. The
/// child inherits them across fork, closes the manager ends, waits for the
/// release writer to close, and uses the alert writer after the initial
/// bounded wait. None may survive exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdlePipe {
    pub child_wait_fd: i32,
    pub manager_release_fd: i32,
    pub manager_alert_fd: i32,
    pub child_alert_fd: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpawnSecurity {
    pub capability_bounding_set: Vec<String>,
    pub ambient_capabilities: Vec<String>,
    pub no_new_privileges: bool,
    pub secure_bits: Vec<String>,
    pub system_call_filter: Vec<String>,
    pub system_call_error_number: Option<String>,
    pub system_call_architectures: Vec<String>,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub private_network: bool,
    pub private_ipc: bool,
    pub private_users: bool,
    pub private_mounts: bool,
    pub protect_system: Option<String>,
    pub protect_home: Option<String>,
    pub protect_hostname: bool,
    pub protect_kernel_tunables: bool,
    pub protect_kernel_modules: bool,
    pub protect_control_groups: bool,
    pub user: Option<String>,
    pub group: Option<String>,
    pub supplementary_groups: Vec<String>,
    pub environment: Vec<String>,
    pub environment_file: Vec<String>,
    pub pass_environment: Vec<String>,
    pub unset_environment: Vec<String>,
    /// A manager-owned notification endpoint. Unlike unit supplied
    /// `Environment=NOTIFY_SOCKET=…`, this is injected after all unit
    /// environment transformations so a service cannot redirect its own
    /// lifecycle protocol to an arbitrary peer.
    pub notify_socket: Option<String>,
    pub working_directory: Option<String>,
    pub limits: BTreeMap<String, String>,
    pub nice: Option<i32>,
    pub umask: Option<String>,
    pub oom_score_adjust: Option<i32>,
    pub command_prefixes: String,
}

/// Arrange for a `std::process::Command` child to start with an empty signal
/// mask. PID 1 owns a broad signalfd mask which must never leak into services.
#[cfg(target_os = "linux")]
pub fn configure_exec_signal_mask(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    let empty_mask = SigSet::empty();
    // SAFETY: the closure performs only pthread_sigmask through nix and creates
    // no borrowed references into parent state. It returns before exec and
    // satisfies CommandExt::pre_exec's post-fork restrictions.
    unsafe {
        command.pre_exec(move || {
            empty_mask
                .thread_set_mask()
                .map_err(|error| std::io::Error::from_raw_os_error(error as std::os::raw::c_int))
        });
    }
}

#[cfg(not(target_os = "linux"))]
pub fn configure_exec_signal_mask(_command: &mut std::process::Command) {}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    pub fn insert_with_identity(
        &mut self,
        child: ChildProcess,
        identity: ProcessIdentity,
    ) -> Result<(), String> {
        if child.pid != identity.pid() {
            return Err(format!(
                "child PID {} does not match identity PID {}",
                child.pid,
                identity.pid()
            ));
        }
        if self.processes.contains_key(&child.pid) {
            return Err(format!("PID {} is already tracked", child.pid));
        }
        self.processes.insert(
            child.pid,
            TrackedProcess {
                identity,
                child: Some(child),
            },
        );
        Ok(())
    }

    pub fn acquire_identity(pid: u32) -> Result<ProcessIdentity, String> {
        #[cfg(target_os = "linux")]
        {
            linux::acquire_process_identity(pid)
        }

        #[cfg(not(target_os = "linux"))]
        Ok(ProcessIdentity::numeric(pid))
    }

    pub fn adopt_identity(&mut self, identity: ProcessIdentity) -> Result<(), String> {
        let pid = identity.pid();
        #[cfg(target_os = "linux")]
        if !identity.has_pidfd() {
            return Err(format!(
                "refusing to adopt foreign PID {pid} without a pidfd identity"
            ));
        }
        if self.processes.contains_key(&pid) {
            return Err(format!("PID {pid} is already tracked"));
        }
        self.processes.insert(
            pid,
            TrackedProcess {
                identity,
                child: None,
            },
        );
        Ok(())
    }

    /// Stop tracking a foreign process which has no waitable child record.
    ///
    /// Direct children must leave through `remove()` so their exit status
    /// cannot be detached from the identity which pins the PID.
    pub fn remove_adopted(&mut self, pid: u32) -> bool {
        let is_adopted = self
            .processes
            .get(&pid)
            .is_some_and(|process| process.child.is_none());
        if is_adopted {
            self.processes.remove(&pid);
        }
        is_adopted
    }

    pub fn identity(&self, pid: u32) -> Option<&ProcessIdentity> {
        self.processes.get(&pid).map(|process| &process.identity)
    }

    pub fn signal(&self, pid: u32, signal: i32) -> Result<(), String> {
        match self.processes.get(&pid) {
            Some(process) => process.identity.signal(signal),
            None => Err(format!(
                "refusing to signal PID {pid} without a tracked process identity"
            )),
        }
    }

    pub fn remove(&mut self, pid: u32) -> Option<ChildProcess> {
        self.processes
            .remove(&pid)
            .and_then(|process| process.child)
    }

    pub fn get(&self, pid: u32) -> Option<&ChildProcess> {
        self.processes
            .get(&pid)
            .and_then(|process| process.child.as_ref())
    }

    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ChildProcess> {
        self.processes
            .get_mut(&pid)
            .and_then(|process| process.child.as_mut())
    }

    pub fn pids(&self) -> Vec<u32> {
        self.processes.keys().copied().collect()
    }

    pub fn running_pids(&self) -> Vec<u32> {
        self.processes
            .values()
            .filter_map(|process| process.child.as_ref())
            .filter(|child| child.state == ChildState::Running)
            .map(|child| child.pid)
            .collect()
    }
}

impl Default for ProcessTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_command(cmd: &str) -> (String, Vec<String>) {
    let cmd = cmd.trim();
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';

    for ch in cmd.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = true;
            quote_char = ch;
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                args.push(current.clone());
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        args.push(current);
    }

    if args.is_empty() {
        return (String::new(), Vec::new());
    }

    let program = args.remove(0);
    (program, args)
}

#[cfg(target_os = "linux")]
fn normalize_capability_name(name: &str) -> Option<String> {
    let normalized = name.trim().trim_start_matches('~').to_ascii_uppercase();
    if normalized.is_empty() {
        return None;
    }
    Some(if normalized.starts_with("CAP_") {
        normalized
    } else {
        format!("CAP_{normalized}")
    })
}

#[cfg(target_os = "linux")]
fn capability_from_name(name: &str) -> Option<Capability> {
    let normalized = normalize_capability_name(name)?;
    normalized.parse::<Capability>().ok()
}

#[cfg(target_os = "linux")]
fn parse_capability_rule_set(rules: &[String]) -> Result<CapsHashSet, String> {
    if rules.is_empty() {
        return Ok(CapsHashSet::new());
    }

    let start_all = rules
        .first()
        .map(|rule| rule.trim_start().starts_with('~'))
        .unwrap_or(false);
    let mut set = if start_all {
        caps::all()
    } else {
        CapsHashSet::new()
    };

    for rule in rules {
        let trimmed = rule.trim();
        if trimmed.is_empty() {
            continue;
        }

        let invert = trimmed.starts_with('~');
        let token = trimmed.trim_start_matches('~');
        if token.eq_ignore_ascii_case("all") {
            if invert {
                set.clear();
            } else {
                set = caps::all();
            }
            continue;
        }

        let Some(cap) = capability_from_name(token) else {
            return Err(format!("unknown capability token: {rule}"));
        };

        if invert {
            set.remove(&cap);
        } else {
            set.insert(cap);
        }
    }

    Ok(set)
}

#[cfg(target_os = "linux")]
fn secure_bit_mask(name: &str) -> Option<u32> {
    match name.trim().to_ascii_lowercase().as_str() {
        "noroot" => Some(1u32 << 0),
        "noroot-locked" => Some(1u32 << 1),
        "no-setuid-fixup" => Some(1u32 << 2),
        "no-setuid-fixup-locked" => Some(1u32 << 3),
        "keep-caps" => Some(1u32 << 4),
        "keep-caps-locked" => Some(1u32 << 5),
        "no-cap-ambient-raise" => Some(1u32 << 6),
        "no-cap-ambient-raise-locked" => Some(1u32 << 7),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn native_arch_aliases() -> &'static [&'static str] {
    #[cfg(target_arch = "x86_64")]
    {
        return &["native", "x86-64", "x86_64", "amd64"];
    }
    #[cfg(target_arch = "aarch64")]
    {
        return &["native", "aarch64", "arm64"];
    }
    #[cfg(target_arch = "x86")]
    {
        return &["native", "x86", "i386", "i686"];
    }
    #[cfg(target_arch = "arm")]
    {
        return &["native", "arm"];
    }
    #[allow(unreachable_code)]
    &["native"]
}

#[cfg(target_os = "linux")]
fn architecture_matches_native(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    native_arch_aliases()
        .iter()
        .any(|candidate| normalized == candidate.to_ascii_lowercase())
}

#[cfg(target_os = "linux")]
fn enforce_system_call_architectures(rules: &[String]) -> Result<(), String> {
    if rules.is_empty() {
        return Ok(());
    }

    for rule in rules {
        if rule.trim_start().starts_with('~') {
            return Err(format!(
                "invalid SystemCallArchitectures entry (deny-list is unsupported): {rule}"
            ));
        }
    }

    if rules.iter().any(|rule| architecture_matches_native(rule)) {
        return Ok(());
    }

    Err("native architecture not allowed by SystemCallArchitectures".to_string())
}

#[cfg(target_os = "linux")]
fn cap_last_cap() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|raw| raw.trim().parse::<i32>().ok())
        .unwrap_or(63)
}

#[cfg(target_os = "linux")]
fn resolve_uid_gid(
    user: Option<&str>,
    group: Option<&str>,
) -> Result<(Option<u32>, Option<u32>), String> {
    let mut uid = None;
    let mut gid = None;

    if let Some(raw_user) = user.map(str::trim).filter(|v| !v.is_empty()) {
        if let Ok(parsed) = raw_user.parse::<u32>() {
            uid = Some(parsed);
        } else {
            let Some(record) = User::from_name(raw_user)
                .map_err(|e| format!("failed to resolve user {raw_user}: {e}"))?
            else {
                return Err(format!("unknown user: {raw_user}"));
            };
            uid = Some(record.uid.as_raw());
            gid = Some(record.gid.as_raw());
        }
    }

    if let Some(raw_group) = group.map(str::trim).filter(|v| !v.is_empty()) {
        if let Ok(parsed) = raw_group.parse::<u32>() {
            gid = Some(parsed);
        } else {
            let Some(record) = Group::from_name(raw_group)
                .map_err(|e| format!("failed to resolve group {raw_group}: {e}"))?
            else {
                return Err(format!("unknown group: {raw_group}"));
            };
            gid = Some(record.gid.as_raw());
        }
    }

    if gid.is_none() {
        gid = uid;
    }

    Ok((uid, gid))
}

#[cfg(target_os = "linux")]
fn resolve_supplementary_groups(groups: &[String]) -> Result<Vec<u32>, String> {
    let mut resolved = Vec::new();
    for group in groups {
        let trimmed = group.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(id) = trimmed.parse::<u32>() {
            resolved.push(id);
            continue;
        }

        let Some(record) = Group::from_name(trimmed)
            .map_err(|e| format!("failed to resolve supplementary group {trimmed}: {e}"))?
        else {
            return Err(format!("unknown supplementary group: {trimmed}"));
        };
        resolved.push(record.gid.as_raw());
    }
    Ok(resolved)
}

#[cfg(target_os = "linux")]
fn parse_umask_value(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(raw) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        return u32::from_str_radix(raw, 8).ok();
    }
    if trimmed.starts_with('0') && trimmed.len() > 1 {
        return u32::from_str_radix(trimmed, 8).ok();
    }
    trimmed.parse::<u32>().ok()
}

#[cfg(target_os = "linux")]
fn parse_limit_value(value: &str) -> Option<libc::rlim_t> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "infinity" | "infinite" | "inf"
    ) {
        return Some(libc::RLIM_INFINITY);
    }
    trimmed.parse::<u64>().ok().map(|v| v as libc::rlim_t)
}

#[cfg(target_os = "linux")]
fn limit_name_to_resource(name: &str) -> Option<libc::__rlimit_resource_t> {
    Some(match name {
        "LimitCPU" => libc::RLIMIT_CPU,
        "LimitFSIZE" => libc::RLIMIT_FSIZE,
        "LimitDATA" => libc::RLIMIT_DATA,
        "LimitSTACK" => libc::RLIMIT_STACK,
        "LimitCORE" => libc::RLIMIT_CORE,
        "LimitRSS" => libc::RLIMIT_RSS,
        "LimitNOFILE" => libc::RLIMIT_NOFILE,
        "LimitAS" => libc::RLIMIT_AS,
        "LimitNPROC" => libc::RLIMIT_NPROC,
        "LimitMEMLOCK" => libc::RLIMIT_MEMLOCK,
        "LimitLOCKS" => libc::RLIMIT_LOCKS,
        "LimitSIGPENDING" => libc::RLIMIT_SIGPENDING,
        "LimitMSGQUEUE" => libc::RLIMIT_MSGQUEUE,
        "LimitNICE" => libc::RLIMIT_NICE,
        "LimitRTPRIO" => libc::RLIMIT_RTPRIO,
        "LimitRTTIME" => libc::RLIMIT_RTTIME,
        _ => return None,
    })
}

#[cfg(target_os = "linux")]
fn parse_environment_file(
    path: &str,
    env_map: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read EnvironmentFile {path}: {e}"))?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            env_map.insert(key.to_string(), value.trim().to_string());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const SECCOMP_GROUP_SOURCE: &str = include_str!("../../shared/seccomp-util.c");

#[cfg(target_os = "linux")]
fn parse_seccomp_group_table() -> HashMap<String, Vec<String>> {
    let mut groups = HashMap::new();
    let mut current_group: Option<String> = None;
    let mut current_values: Vec<String> = Vec::new();
    let mut collecting_values = false;

    for line in SECCOMP_GROUP_SOURCE.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with(".name") {
            if let Some(group) = current_group.take() {
                groups.insert(group, current_values.clone());
                current_values.clear();
            }

            let mut quoted = trimmed.split('"');
            let _ = quoted.next();
            let name = quoted.next().unwrap_or_default();
            if name.starts_with('@') {
                current_group = Some(name.to_string());
            } else {
                current_group = None;
            }
            collecting_values = false;
            continue;
        }

        if current_group.is_none() {
            continue;
        }

        if trimmed.starts_with(".value") {
            collecting_values = true;
        } else if collecting_values
            && (trimmed == "}," || trimmed == "}" || trimmed.starts_with("},"))
        {
            if let Some(group) = current_group.take() {
                groups.insert(group, current_values.clone());
                current_values.clear();
            }
            collecting_values = false;
            continue;
        } else if !collecting_values {
            continue;
        }

        for quoted in trimmed.split('"').skip(1).step_by(2) {
            for syscall in quoted.split("\\0") {
                let syscall = syscall.trim();
                if !syscall.is_empty() {
                    current_values.push(syscall.to_string());
                }
            }
        }
    }

    if let Some(group) = current_group {
        groups.insert(group, current_values);
    }

    groups
}

#[cfg(target_os = "linux")]
fn syscall_group_table() -> &'static HashMap<String, Vec<String>> {
    static TABLE: OnceLock<HashMap<String, Vec<String>>> = OnceLock::new();
    TABLE.get_or_init(parse_seccomp_group_table)
}

#[cfg(target_os = "linux")]
fn expand_syscall_token(
    token: &str,
    output: &mut Vec<String>,
    visiting: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !token.starts_with('@') {
        output.push(token.to_string());
        return Ok(());
    }

    let table = syscall_group_table();
    let Some(entries) = table.get(token) else {
        return Ok(());
    };

    if !visiting.insert(token.to_string()) {
        return Err(format!(
            "recursive SystemCallFilter group reference: {token}"
        ));
    }
    for entry in entries {
        expand_syscall_token(entry, output, visiting)?;
    }
    visiting.remove(token);
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_errno_token(token: &str) -> Option<u32> {
    if let Ok(value) = token.parse::<i32>()
        && value > 0
    {
        return Some(value as u32);
    }

    Some(match token.to_ascii_uppercase().as_str() {
        "EPERM" => libc::EPERM as u32,
        "ENOENT" => libc::ENOENT as u32,
        "EINTR" => libc::EINTR as u32,
        "EIO" => libc::EIO as u32,
        "EAGAIN" => libc::EAGAIN as u32,
        "ENOMEM" => libc::ENOMEM as u32,
        "EACCES" => libc::EACCES as u32,
        "EBUSY" => libc::EBUSY as u32,
        "EEXIST" => libc::EEXIST as u32,
        "EINVAL" => libc::EINVAL as u32,
        "ENOSYS" => libc::ENOSYS as u32,
        _ => return None,
    })
}

#[cfg(target_os = "linux")]
fn negative_seccomp_action(error_number: Option<&str>) -> Result<SeccompAction, String> {
    let Some(token) = error_number
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(SeccompAction::KillProcess);
    };

    if token.eq_ignore_ascii_case("kill") {
        return Ok(SeccompAction::KillProcess);
    }

    let Some(errno_number) = parse_errno_token(token) else {
        return Err(format!("invalid SystemCallErrorNumber: {token}"));
    };
    Ok(SeccompAction::Errno(errno_number))
}

#[cfg(target_os = "linux")]
fn seccomp_action_json(action: &SeccompAction) -> String {
    match action {
        SeccompAction::Allow => "\"allow\"".to_string(),
        SeccompAction::KillProcess => "\"kill_process\"".to_string(),
        SeccompAction::Errno(errno) => format!("{{\"errno\":{errno}}}"),
        _ => "\"kill_process\"".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn seccomp_arch() -> Result<TargetArch, String> {
    std::env::consts::ARCH.try_into().map_err(|_| {
        format!(
            "unsupported architecture for seccomp filter generation: {}",
            std::env::consts::ARCH
        )
    })
}

#[cfg(target_os = "linux")]
fn syscall_support_cache() -> &'static Mutex<BTreeMap<String, bool>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, bool>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(target_os = "linux")]
fn is_syscall_supported(arch: TargetArch, syscall: &str) -> bool {
    let key = format!("{:?}:{syscall}", arch);
    if let Ok(cache) = syscall_support_cache().lock()
        && let Some(cached) = cache.get(&key)
    {
        return *cached;
    }

    let probe_json = format!(
        "{{\"probe\":{{\"mismatch_action\":\"trap\",\"match_action\":\"allow\",\"filter\":[{{\"syscall\":\"{syscall}\"}}]}}}}"
    );
    let known = compile_from_json(probe_json.as_bytes(), arch).is_ok();

    if let Ok(mut cache) = syscall_support_cache().lock() {
        cache.insert(key, known);
    }
    known
}

#[cfg(target_os = "linux")]
fn prepare_system_call_filter(
    rules: &[String],
    error_number: Option<&str>,
) -> Result<Option<BpfProgram>, String> {
    if rules.is_empty() {
        return Ok(None);
    }

    let allow_list = !rules
        .first()
        .map(|rule| rule.trim_start().starts_with('~'))
        .unwrap_or(false);
    let negative_action = negative_seccomp_action(error_number)?;
    let (default_action, match_action) = if allow_list {
        (negative_action.clone(), SeccompAction::Allow)
    } else {
        (SeccompAction::Allow, negative_action.clone())
    };

    let mut selected: BTreeSet<String> = BTreeSet::new();
    let mut visiting = BTreeSet::new();

    let mut apply_rule = |rule: &str, invert: bool| -> Result<(), String> {
        let (name, _) = rule.split_once(':').unwrap_or((rule, ""));
        if name.is_empty() {
            return Ok(());
        }

        let mut expanded = Vec::new();
        expand_syscall_token(name, &mut expanded, &mut visiting)?;
        for syscall in expanded {
            if invert != allow_list {
                selected.insert(syscall);
            } else {
                selected.remove(&syscall);
            }
        }
        Ok(())
    };

    if allow_list {
        apply_rule("@default", false)?;
    }

    for rule in rules {
        let trimmed = rule.trim();
        if trimmed.is_empty() {
            continue;
        }
        let invert = trimmed.starts_with('~');
        apply_rule(trimmed.trim_start_matches('~').trim(), invert)?;
    }

    // The child must report setup/exec failures through the CLOEXEC status
    // pipe after installing the filter. This mirrors execute.c's exec_fd
    // exemption and prevents an allow-list from making launch acknowledgement
    // ambiguous.
    if allow_list {
        selected.insert("write".to_string());
    }

    let arch = seccomp_arch()?;
    let filtered: Vec<String> = selected
        .into_iter()
        .filter(|syscall| is_syscall_supported(arch, syscall))
        .collect();
    if filtered.is_empty() {
        return Err("SystemCallFilter produced no architecture-supported syscalls".to_string());
    }

    let filter_entries = filtered
        .iter()
        .map(|syscall| format!("{{\"syscall\":\"{syscall}\"}}"))
        .collect::<Vec<_>>()
        .join(",");
    let filter_json = format!(
        "{{\"main_thread\":{{\"mismatch_action\":{},\"match_action\":{},\"filter\":[{}]}}}}",
        seccomp_action_json(&default_action),
        seccomp_action_json(&match_action),
        filter_entries
    );
    let compiled = compile_from_json(filter_json.as_bytes(), arch)
        .map_err(|e| format!("failed to compile seccomp filter: {e}"))?;
    let program = compiled
        .get("main_thread")
        .ok_or_else(|| "compiled seccomp profile missing main_thread entry".to_string())?;
    Ok(Some(program.clone()))
}

#[cfg(target_os = "linux")]
pub fn spawn_service_with_options_and_activation(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
) -> Result<u32, String> {
    linux::spawn_service_with_options_and_activation(exec_start, stdio, security, activation_fds)
}

/// Launch a service after binding it to a manager-realized unit cgroup.
///
/// This is the PID 1 entry point. Compatibility callers that have no unit
/// cgroup continue to use [`spawn_service_with_options_and_activation`].
#[cfg(target_os = "linux")]
pub fn spawn_service_with_options_and_activation_in_cgroup(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
    cgroup: CgroupPlacement<'_>,
) -> Result<u32, String> {
    linux::spawn_service_with_options_and_activation_in_cgroup(
        exec_start,
        stdio,
        security,
        activation_fds,
        cgroup,
    )
}

/// Launch a service with an explicit acknowledgement policy.
///
/// The compatibility APIs above continue to wait for exec. PID 1 uses this
/// lower-level entry point for service-type-specific state transitions.
#[cfg(target_os = "linux")]
pub fn spawn_service_with_confirmation_and_activation(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
    confirmation: SpawnConfirmation,
) -> Result<SpawnedService, String> {
    linux::spawn_service_with_confirmation_and_activation(
        exec_start,
        stdio,
        security,
        activation_fds,
        confirmation,
    )
}

/// Launch a service asynchronously with mandatory preopened cgroup placement.
///
/// The parent PID write is best effort. Only the child's exec-status channel
/// can acknowledge placement and the remaining pre-exec stages.
#[cfg(target_os = "linux")]
pub fn spawn_service_with_confirmation_and_activation_in_cgroup(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    activation_fds: &[ActivationFd<'_>],
    cgroup: CgroupPlacement<'_>,
    confirmation: SpawnConfirmation,
) -> Result<SpawnedService, String> {
    linux::spawn_service_with_confirmation_and_activation_in_cgroup(
        exec_start,
        stdio,
        security,
        activation_fds,
        cgroup,
        confirmation,
    )
}

#[cfg(target_os = "linux")]
pub fn spawn_service_with_options(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
) -> Result<u32, String> {
    spawn_service_with_options_and_activation(exec_start, stdio, security, &[])
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_service_with_confirmation(
    exec_start: &str,
    stdio: SpawnStdio,
    security: SpawnSecurity,
    confirmation: SpawnConfirmation,
) -> Result<SpawnedService, String> {
    spawn_service_with_options(exec_start, stdio, security).map(|pid| SpawnedService {
        pid,
        confirmation,
        identity: Some(ProcessIdentity::numeric(pid)),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_service_with_options(
    exec_start: &str,
    stdio: SpawnStdio,
    _security: SpawnSecurity,
) -> Result<u32, String> {
    let (program, args) = parse_command(exec_start);
    if program.is_empty() {
        return Err("empty command".to_string());
    }

    let mut cmd = std::process::Command::new(&program);
    cmd.args(&args);
    cmd.env("MAINPID", "0");
    if let Some(fd) = stdio.stdin_fd {
        // SAFETY: arguments satisfy the libc `dup` contract and any passed pointers remain valid for the call.
        let dupfd = unsafe { libc::dup(fd) };
        if dupfd < 0 {
            return Err("dup stdin failed".to_string());
        }
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        cmd.stdin(unsafe { Stdio::from_raw_fd(dupfd) });
    }
    if let Some(fd) = stdio.stdout_fd {
        // SAFETY: arguments satisfy the libc `dup` contract and any passed pointers remain valid for the call.
        let dupfd = unsafe { libc::dup(fd) };
        if dupfd < 0 {
            return Err("dup stdout failed".to_string());
        }
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        cmd.stdout(unsafe { Stdio::from_raw_fd(dupfd) });
    }
    if let Some(fd) = stdio.stderr_fd {
        // SAFETY: arguments satisfy the libc `dup` contract and any passed pointers remain valid for the call.
        let dupfd = unsafe { libc::dup(fd) };
        if dupfd < 0 {
            return Err("dup stderr failed".to_string());
        }
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        cmd.stderr(unsafe { Stdio::from_raw_fd(dupfd) });
    }

    let child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    Ok(child.id())
}

pub fn spawn_service_with_stdio(exec_start: &str, stdio: SpawnStdio) -> Result<u32, String> {
    spawn_service_with_options(exec_start, stdio, SpawnSecurity::default())
}

pub fn spawn_service(exec_start: &str) -> Result<u32, String> {
    spawn_service_with_options(exec_start, SpawnStdio::default(), SpawnSecurity::default())
}

#[cfg(target_os = "linux")]
pub fn check_children(tracker: &mut ProcessTracker) -> Vec<u32> {
    let mut changed = Vec::new();
    let pids: Vec<u32> = tracker
        .processes
        .iter()
        .filter_map(|(pid, process)| process.child.as_ref().map(|_| *pid))
        .collect();

    for pid in pids {
        if let Some(child) = tracker.get_mut(pid) {
            if child.state != ChildState::Running {
                continue;
            }

            let nix_pid = Pid::from_raw(pid as i32);
            if let Ok(status) = waitpid(nix_pid, Some(WaitPidFlag::WNOHANG)) {
                match status {
                    WaitStatus::Exited(_, code) => {
                        child.state = if code == 0 {
                            ChildState::ExitedCleanly
                        } else {
                            ChildState::ExitedWithCode(code)
                        };
                        changed.push(pid);
                    }
                    WaitStatus::Signaled(_, sig, _) => {
                        child.state = ChildState::KilledBySignal(sig as i32);
                        changed.push(pid);
                    }
                    WaitStatus::StillAlive => {}
                    _ => {}
                }
            }
        }
    }

    changed
}

#[cfg(not(target_os = "linux"))]
pub fn check_children(tracker: &mut ProcessTracker) -> Vec<u32> {
    let mut changed = Vec::new();
    let pids: Vec<u32> = tracker
        .processes
        .iter()
        .filter_map(|(pid, process)| process.child.as_ref().map(|_| *pid))
        .collect();

    for pid in pids {
        if let Some(child) = tracker.get_mut(pid) {
            if child.state != ChildState::Running {
                continue;
            }

            if let Ok(mut proc) = std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                match proc.try_wait() {
                    Ok(Some(status)) => {
                        child.state = if status.success() {
                            ChildState::Running
                        } else {
                            ChildState::ExitedCleanly
                        };
                        if child.state != ChildState::Running {
                            changed.push(pid);
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        child.state = ChildState::ExitedCleanly;
                        changed.push(pid);
                    }
                }
            }
        }
    }

    changed
}

#[cfg(target_os = "linux")]
pub fn kill_process(pid: u32, sig: i32) -> Result<(), String> {
    let signal = match sig {
        9 | 37 => Signal::SIGKILL,
        15 | 30 => Signal::SIGTERM,
        1 => Signal::SIGHUP,
        2 => Signal::SIGINT,
        _ => Signal::SIGTERM,
    };
    nix::sys::signal::kill(Pid::from_raw(pid as i32), signal)
        .map_err(|e| format!("kill({pid}) failed: {e}"))
}

#[cfg(not(target_os = "linux"))]
pub fn kill_process(pid: u32, _sig: i32) -> Result<(), String> {
    std::process::Command::new("kill")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|_| ())
        .map_err(|e| format!("kill({pid}) failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_command_simple() {
        let (prog, args) = parse_command("/usr/bin/nginx -g 'daemon off;'");
        assert_eq!(prog, "/usr/bin/nginx");
        assert_eq!(args, vec!["-g", "daemon off;"]);
    }

    #[test]
    fn test_parse_command_no_args() {
        let (prog, args) = parse_command("/usr/bin/test");
        assert_eq!(prog, "/usr/bin/test");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_command_with_env_var() {
        let (prog, args) = parse_command("/bin/kill -s HUP $MAINPID");
        assert_eq!(prog, "/bin/kill");
        assert_eq!(args, vec!["-s", "HUP", "$MAINPID"]);
    }

    #[test]
    fn test_process_tracker_new() {
        let tracker = ProcessTracker::new();
        assert!(tracker.pids().is_empty());
        assert!(tracker.running_pids().is_empty());
    }

    #[test]
    fn test_process_tracker_keeps_child_and_identity_atomic() {
        let mut tracker = ProcessTracker::new();
        tracker
            .insert_with_identity(
                ChildProcess {
                    pid: 4242,
                    command: "/bin/true".to_string(),
                    started: Instant::now(),
                    state: ChildState::Running,
                },
                ProcessIdentity::numeric(4242),
            )
            .unwrap();

        assert_eq!(tracker.pids(), vec![4242]);
        assert_eq!(tracker.running_pids(), vec![4242]);
        assert!(tracker.identity(4242).is_some());
        assert!(!tracker.remove_adopted(4242));
        assert!(tracker.get(4242).is_some());

        let child = tracker.remove(4242).unwrap();
        assert_eq!(child.pid, 4242);
        assert!(tracker.identity(4242).is_none());
        assert!(tracker.pids().is_empty());
    }
}
