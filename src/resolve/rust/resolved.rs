// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved.c
//
// systemd-resolved daemon: main entry point that initializes logging,
// parses service arguments, drops privileges to the systemd-resolve user,
// creates and starts the DNS resolution manager, writes resolv.conf,
// and enters the sd-event loop.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "linux")]
use nix::unistd::{
    Gid, Uid, User, chown, geteuid, getgroups, getresgid, getresuid, setgroups, setresgid,
    setresuid,
};

use crate::resolved_conf::{DnsStubListenerMode, ResolvedConfig};

// ── Constants ─────────────────────────────────────────────────────────────

pub const SERVICE_NAME: &str = "systemd-resolved.service";
pub const SERVICE_DESCRIPTION: &str =
    "Provide name resolution with caching using DNS, mDNS, LLMNR.";
pub const RESOLVE_USER: &str = "systemd-resolve";
pub const RUNTIME_DIR: &str = "/run/systemd/resolve";
pub const RUNTIME_DIR_MODE: u32 = 0o755;
pub const RESOLV_CONF_MODE: u32 = 0o644;
pub const DEFAULT_UMASK: u32 = 0o022;
const RESOLV_CONF_FILENAME: &str = "resolv.conf";

pub const CAP_NET_RAW: u64 = 1 << 17;
pub const CAP_NET_BIND_SERVICE: u64 = 1 << 10;
pub const REQUIRED_CAPS: u64 = CAP_NET_RAW | CAP_NET_BIND_SERVICE;
#[cfg(target_os = "linux")]
const CAP_SETGID: u64 = 1 << 6;
#[cfg(target_os = "linux")]
const CAP_SETUID: u64 = 1 << 7;
#[cfg(target_os = "linux")]
const CAP_SETPCAP: u64 = 1 << 8;
#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

pub const NOTIFY_READY: &str = "READY=1";
pub const NOTIFY_STOPPING: &str = "STOPPING=1";

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedError {
    ArgumentParseFailed(String),
    MacInitFailed(String),
    UserResolveFailed(String),
    RuntimeDirCreateFailed(String),
    PrivilegeDropFailed(String),
    ManagerCreateFailed(String),
    ManagerStartFailed(String),
    ResolvConfWriteFailed(String),
    ResolvConfCheckFailed(String),
    EventLoopFailed(String),
}

impl fmt::Display for ResolvedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolvedError::ArgumentParseFailed(s) => {
                write!(f, "Failed to parse arguments: {}", s)
            }
            ResolvedError::MacInitFailed(s) => {
                write!(f, "MAC initialization failed: {}", s)
            }
            ResolvedError::UserResolveFailed(s) => {
                write!(f, "Cannot resolve user name: {}", s)
            }
            ResolvedError::RuntimeDirCreateFailed(s) => {
                write!(f, "Could not create runtime directory: {}", s)
            }
            ResolvedError::PrivilegeDropFailed(s) => {
                write!(f, "Failed to drop privileges: {}", s)
            }
            ResolvedError::ManagerCreateFailed(s) => {
                write!(f, "Could not create manager: {}", s)
            }
            ResolvedError::ManagerStartFailed(s) => {
                write!(f, "Failed to start manager: {}", s)
            }
            ResolvedError::ResolvConfWriteFailed(s) => {
                write!(f, "Failed to write resolv.conf: {}", s)
            }
            ResolvedError::ResolvConfCheckFailed(s) => {
                write!(f, "Failed to check resolv.conf: {}", s)
            }
            ResolvedError::EventLoopFailed(s) => {
                write!(f, "Event loop failed: {}", s)
            }
        }
    }
}

impl std::error::Error for ResolvedError {}

// ── Privilege info ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCreds {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
}

// ── Manager state ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerState {
    Created,
    Started,
    Running,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone)]
pub struct Manager {
    pub state: ManagerState,
    pub is_running_as_root: bool,
    pub runtime_dir: String,
    pub config: ResolvedConfig,
    pub resolve_user: Option<UserCreds>,
    pub retained_caps: u64,
    pub event_iterations: u64,
}

impl Manager {
    pub fn new(is_root: bool) -> Result<Self, ResolvedError> {
        let mut config = ResolvedConfig::new();
        let _ = config.finalize(true, true);

        Ok(Manager {
            state: ManagerState::Created,
            is_running_as_root: is_root,
            runtime_dir: default_runtime_dir(is_root).to_string_lossy().into_owned(),
            config,
            resolve_user: None,
            retained_caps: 0,
            event_iterations: 0,
        })
    }

    pub fn start(&mut self) -> Result<(), ResolvedError> {
        if self.state != ManagerState::Created {
            return Err(ResolvedError::ManagerStartFailed(
                "manager not in created state".to_string(),
            ));
        }
        self.state = ManagerState::Started;
        Ok(())
    }

    pub fn write_resolv_conf(&self) -> Result<(), ResolvedError> {
        self.ensure_runtime_dir()?;
        write_resolv_conf_file(
            &self.resolv_conf_path(),
            &self.render_resolv_conf_contents(),
        )
    }

    pub fn check_resolv_conf(&self) -> Result<(), ResolvedError> {
        let path = self.resolv_conf_path();
        let content = fs::read_to_string(&path).map_err(|e| {
            ResolvedError::ResolvConfCheckFailed(format!("{}: {}", path.display(), e))
        })?;
        let expected = self.render_resolv_conf_contents();

        if content != expected {
            return Err(ResolvedError::ResolvConfCheckFailed(format!(
                "{} content mismatch",
                path.display()
            )));
        }

        Ok(())
    }

    pub fn run_event_step(&mut self) -> bool {
        match self.state {
            ManagerState::Running => {
                self.event_iterations += 1;
                true
            }
            ManagerState::Stopping => {
                self.state = ManagerState::Stopped;
                false
            }
            _ => false,
        }
    }

    pub fn enter_loop(&mut self) -> Result<(), ResolvedError> {
        if self.state == ManagerState::Stopped {
            return Err(ResolvedError::EventLoopFailed(
                "manager already stopped".to_string(),
            ));
        }

        self.state = ManagerState::Running;
        Ok(())
    }

    fn ensure_runtime_dir(&self) -> Result<(), ResolvedError> {
        let path = Path::new(&self.runtime_dir);
        let metadata = fs::symlink_metadata(path).map_err(|e| {
            ResolvedError::RuntimeDirCreateFailed(format!("{}: {}", path.display(), e))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ResolvedError::RuntimeDirCreateFailed(format!(
                "{} is not a real directory",
                path.display()
            )));
        }
        Ok(())
    }

    fn resolv_conf_path(&self) -> PathBuf {
        Path::new(&self.runtime_dir).join(RESOLV_CONF_FILENAME)
    }

    fn render_resolv_conf_contents(&self) -> String {
        render_resolv_conf_contents(&self.config)
    }
}

// ── Capability computation ─────────────────────────────────────────────────

pub fn compute_required_capabilities() -> u64 {
    REQUIRED_CAPS
}

pub fn has_cap(cap_flags: u64, cap: u64) -> bool {
    (cap_flags & cap) != 0
}

// ── Service argument parsing ───────────────────────────────────────────────

pub fn service_parse_argv(args: &[&str]) -> Result<(), ResolvedError> {
    for arg in args.iter().skip(1) {
        match *arg {
            "--help" | "-h" => return Ok(()),
            "--version" => return Ok(()),
            s if s.starts_with('-') => {
                return Err(ResolvedError::ArgumentParseFailed(format!(
                    "unknown option: {}",
                    s
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

// ── Privilege dropping ─────────────────────────────────────────────────────

pub fn drop_privileges(
    is_root: bool,
    user_name: &str,
    keep_caps: u64,
) -> Result<Option<UserCreds>, ResolvedError> {
    if !is_root {
        return Ok(None);
    }

    #[cfg(target_os = "linux")]
    {
        if !geteuid().is_root() {
            return Err(ResolvedError::PrivilegeDropFailed(
                "caller claimed root startup but effective UID is not root; refusing to mutate credentials"
                    .to_string(),
            ));
        }

        let credentials = resolve_user_creds(user_name)?;
        drop_privileges_to(&credentials, keep_caps)?;
        Ok(Some(credentials))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (user_name, keep_caps);
        Err(ResolvedError::PrivilegeDropFailed(
            "capability-retaining privilege drop is only implemented on Linux; refusing to mutate credentials"
                .to_string(),
        ))
    }
}

pub fn resolve_user_creds(name: &str) -> Result<UserCreds, ResolvedError> {
    #[cfg(target_os = "linux")]
    {
        let user = User::from_name(name)
            .map_err(|e| ResolvedError::UserResolveFailed(format!("{name}: {e}")))?
            .ok_or_else(|| ResolvedError::UserResolveFailed(format!("unknown user: {name}")))?;
        Ok(UserCreds {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            name: user.name,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err(ResolvedError::UserResolveFailed(
            "passwd lookup is not implemented on this platform".to_string(),
        ))
    }
}

// ── Runtime directory creation ─────────────────────────────────────────────

pub fn create_runtime_dir(is_root: bool, uid: u32, gid: u32) -> Result<String, ResolvedError> {
    let runtime_dir = default_runtime_dir(is_root);
    let runtime_dir = create_runtime_dir_at(&runtime_dir, is_root, uid, gid)?;
    Ok(runtime_dir.to_string_lossy().into_owned())
}

/// Perform the C startup ordering: resolve the service account, create and
/// assign its runtime directory while still privileged, then irreversibly drop
/// IDs and all capabilities except the two needed by the resolver.
pub fn prepare_runtime_and_drop_privileges(
    is_root: bool,
) -> Result<(Option<UserCreds>, String), ResolvedError> {
    if !is_root {
        return Ok((None, RUNTIME_DIR.to_string()));
    }

    #[cfg(target_os = "linux")]
    {
        if !geteuid().is_root() {
            return Err(ResolvedError::PrivilegeDropFailed(
                "caller claimed root startup but effective UID is not root".to_string(),
            ));
        }
    }

    let credentials = resolve_user_creds(RESOLVE_USER)?;
    #[cfg(target_os = "linux")]
    preflight_linux_privilege_transition(&credentials, compute_required_capabilities())?;
    let runtime_dir = create_runtime_dir(true, credentials.uid, credentials.gid)?;
    #[cfg(target_os = "linux")]
    drop_privileges_to(&credentials, compute_required_capabilities())?;
    #[cfg(not(target_os = "linux"))]
    return Err(ResolvedError::PrivilegeDropFailed(
        "capability-retaining privilege drop is only implemented on Linux".to_string(),
    ));
    Ok((Some(credentials), runtime_dir))
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct LinuxCapabilities {
    effective: u64,
    permitted: u64,
    inheritable: u64,
}

#[cfg(target_os = "linux")]
fn apply_linux_privilege_transition(
    credentials: &UserCreds,
    keep_caps: u64,
) -> Result<(), ResolvedError> {
    let last_capability = preflight_linux_privilege_transition(credentials, keep_caps)?;

    let uid = Uid::from_raw(credentials.uid);
    let gid = Gid::from_raw(credentials.gid);
    setgroups(&[]).map_err(|e| ResolvedError::PrivilegeDropFailed(format!("setgroups: {e}")))?;
    setresgid(gid, gid, gid)
        .map_err(|e| ResolvedError::PrivilegeDropFailed(format!("setresgid: {e}")))?;
    prctl_noargs(libc::PR_SET_KEEPCAPS, 1)
        .map_err(|e| ResolvedError::PrivilegeDropFailed(format!("PR_SET_KEEPCAPS=1: {e}")))?;
    setresuid(uid, uid, uid)
        .map_err(|e| ResolvedError::PrivilegeDropFailed(format!("setresuid: {e}")))?;
    prctl_noargs(libc::PR_SET_KEEPCAPS, 0)
        .map_err(|e| ResolvedError::PrivilegeDropFailed(format!("PR_SET_KEEPCAPS=0: {e}")))?;
    prctl_two_args(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_CLEAR_ALL as u64,
        0,
    )
    .map_err(|e| ResolvedError::PrivilegeDropFailed(format!("PR_CAP_AMBIENT_CLEAR_ALL: {e}")))?;

    let retained = read_capabilities()?;
    if retained.permitted & (keep_caps | CAP_SETPCAP) != keep_caps | CAP_SETPCAP {
        return privilege_error(format!(
            "capabilities needed to finish the transition were lost ({:#x})",
            retained.permitted
        ));
    }
    write_capabilities(retained.permitted, retained.permitted, 0)?;

    for capability in 0..=last_capability {
        if keep_caps & (1_u64 << capability) == 0 && capability_bounding_set_contains(capability)? {
            prctl_noargs(libc::PR_CAPBSET_DROP, u64::from(capability)).map_err(|e| {
                ResolvedError::PrivilegeDropFailed(format!(
                    "failed to drop capability {capability} from bounding set: {e}"
                ))
            })?;
        }
    }
    write_capabilities(keep_caps, keep_caps, 0)?;
    verify_linux_privilege_transition(credentials, keep_caps, last_capability)
}

#[cfg(target_os = "linux")]
fn drop_privileges_to(credentials: &UserCreds, keep_caps: u64) -> Result<(), ResolvedError> {
    if !geteuid().is_root() {
        return Err(ResolvedError::PrivilegeDropFailed(
            "effective UID is not root; refusing to mutate credentials".to_string(),
        ));
    }
    apply_linux_privilege_transition(credentials, keep_caps)
}

#[cfg(target_os = "linux")]
fn preflight_linux_privilege_transition(
    credentials: &UserCreds,
    keep_caps: u64,
) -> Result<u32, ResolvedError> {
    if credentials.uid == 0 {
        return privilege_error(format!(
            "target account {} resolves to UID 0; refusing a no-op privilege drop",
            credentials.name
        ));
    }

    let last_capability = read_last_capability()?;
    let supported_mask = if last_capability == 63 {
        u64::MAX
    } else {
        (1_u64 << (last_capability + 1)) - 1
    };
    if keep_caps & !supported_mask != 0 {
        return privilege_error(format!(
            "requested capability mask {keep_caps:#x} exceeds kernel cap_last_cap {last_capability}"
        ));
    }

    let initial = read_capabilities()?;
    let transition_caps = CAP_SETGID | CAP_SETUID;
    if initial.effective & transition_caps != transition_caps {
        return privilege_error(format!(
            "missing effective setuid/setgid capabilities before transition (effective={:#x})",
            initial.effective
        ));
    }
    if initial.permitted & (keep_caps | CAP_SETPCAP) != keep_caps | CAP_SETPCAP {
        return privilege_error(format!(
            "requested capabilities are not available in the permitted set ({:#x})",
            initial.permitted
        ));
    }
    let securebits = prctl_noargs(libc::PR_GET_SECUREBITS, 0)
        .map_err(|e| ResolvedError::PrivilegeDropFailed(format!("PR_GET_SECUREBITS: {e}")))?;
    if securebits & libc::SECBIT_KEEP_CAPS_LOCKED != 0 {
        return privilege_error(
            "SECBIT_KEEP_CAPS_LOCKED prevents the required keep-caps transition".to_string(),
        );
    }
    prctl_two_args(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET as u64, 0).map_err(|e| {
        ResolvedError::PrivilegeDropFailed(format!("ambient-capability preflight: {e}"))
    })?;

    for capability in 0..=last_capability {
        let present = capability_bounding_set_contains(capability)?;
        if keep_caps & (1_u64 << capability) != 0 && !present {
            return privilege_error(format!(
                "requested capability {capability} is absent from the bounding set"
            ));
        }
    }
    Ok(last_capability)
}

#[cfg(target_os = "linux")]
fn verify_linux_privilege_transition(
    credentials: &UserCreds,
    keep_caps: u64,
    last_capability: u32,
) -> Result<(), ResolvedError> {
    let expected_uid = Uid::from_raw(credentials.uid);
    let expected_gid = Gid::from_raw(credentials.gid);
    let actual_uid =
        getresuid().map_err(|e| ResolvedError::PrivilegeDropFailed(format!("getresuid: {e}")))?;
    let actual_gid =
        getresgid().map_err(|e| ResolvedError::PrivilegeDropFailed(format!("getresgid: {e}")))?;
    if actual_uid.real != expected_uid
        || actual_uid.effective != expected_uid
        || actual_uid.saved != expected_uid
        || actual_gid.real != expected_gid
        || actual_gid.effective != expected_gid
        || actual_gid.saved != expected_gid
    {
        return privilege_error(format!(
            "credential verification failed: uid={actual_uid:?}, gid={actual_gid:?}"
        ));
    }

    let groups =
        getgroups().map_err(|e| ResolvedError::PrivilegeDropFailed(format!("getgroups: {e}")))?;
    if !groups.is_empty() {
        return privilege_error(format!(
            "supplementary groups remain after privilege drop: {groups:?}"
        ));
    }

    let capabilities = read_capabilities()?;
    if capabilities.effective != keep_caps
        || capabilities.permitted != keep_caps
        || capabilities.inheritable != 0
    {
        return privilege_error(format!(
            "capability verification failed: effective={:#x}, permitted={:#x}, inheritable={:#x}",
            capabilities.effective, capabilities.permitted, capabilities.inheritable
        ));
    }
    for capability in 0..=last_capability {
        let expected = keep_caps & (1_u64 << capability) != 0;
        if capability_bounding_set_contains(capability)? != expected {
            return privilege_error(format!(
                "bounding-set verification failed for capability {capability}"
            ));
        }
        let ambient = prctl_two_args(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_IS_SET as u64,
            u64::from(capability),
        )
        .map_err(|e| {
            ResolvedError::PrivilegeDropFailed(format!("PR_CAP_AMBIENT_IS_SET({capability}): {e}"))
        })?;
        if ambient != 0 {
            return privilege_error(format!(
                "ambient capability {capability} remains after privilege drop"
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_last_capability() -> Result<u32, ResolvedError> {
    let value = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|e| ResolvedError::PrivilegeDropFailed(format!("read cap_last_cap: {e}")))?;
    let capability = value
        .trim()
        .parse::<u32>()
        .map_err(|e| ResolvedError::PrivilegeDropFailed(format!("parse cap_last_cap: {e}")))?;
    if capability > 63 {
        return privilege_error(format!(
            "kernel cap_last_cap {capability} cannot be represented by the 64-bit capability mask"
        ));
    }
    Ok(capability)
}

#[cfg(target_os = "linux")]
fn read_capabilities() -> Result<LinuxCapabilities, ResolvedError> {
    let mut header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [LinuxCapabilityData::default(); 2];
    // SAFETY: SYS_capget receives pointers to the kernel-defined v3 header and
    // two-element data array, both writable and live for the complete syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut LinuxCapabilityHeader,
            data.as_mut_ptr(),
        )
    };
    if result < 0 {
        return privilege_error(format!("capget: {}", std::io::Error::last_os_error()));
    }
    Ok(LinuxCapabilities {
        effective: u64::from(data[0].effective) | (u64::from(data[1].effective) << 32),
        permitted: u64::from(data[0].permitted) | (u64::from(data[1].permitted) << 32),
        inheritable: u64::from(data[0].inheritable) | (u64::from(data[1].inheritable) << 32),
    })
}

#[cfg(target_os = "linux")]
fn write_capabilities(
    effective: u64,
    permitted: u64,
    inheritable: u64,
) -> Result<(), ResolvedError> {
    let mut header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        LinuxCapabilityData {
            effective: effective as u32,
            permitted: permitted as u32,
            inheritable: inheritable as u32,
        },
        LinuxCapabilityData {
            effective: (effective >> 32) as u32,
            permitted: (permitted >> 32) as u32,
            inheritable: (inheritable >> 32) as u32,
        },
    ];
    // SAFETY: SYS_capset receives pointers to the kernel-defined v3 header and
    // two initialized data records. The kernel copies them during this call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut LinuxCapabilityHeader,
            data.as_ptr(),
        )
    };
    if result < 0 {
        return privilege_error(format!("capset: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn capability_bounding_set_contains(capability: u32) -> Result<bool, ResolvedError> {
    prctl_noargs(libc::PR_CAPBSET_READ, u64::from(capability))
        .map(|result| result != 0)
        .map_err(|e| {
            ResolvedError::PrivilegeDropFailed(format!("PR_CAPBSET_READ({capability}): {e}"))
        })
}

#[cfg(target_os = "linux")]
fn prctl_noargs(operation: i32, argument: u64) -> std::io::Result<i32> {
    prctl_two_args(operation, argument, 0)
}

#[cfg(target_os = "linux")]
fn prctl_two_args(operation: i32, argument: u64, second_argument: u64) -> std::io::Result<i32> {
    // SAFETY: these prctl operations accept one integer argument followed by
    // integer/zero arguments and do not dereference userspace pointers.
    let result = unsafe {
        libc::prctl(
            operation,
            argument as libc::c_ulong,
            second_argument as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(target_os = "linux")]
fn privilege_error<T>(message: String) -> Result<T, ResolvedError> {
    Err(ResolvedError::PrivilegeDropFailed(message))
}

fn render_resolv_conf_contents(config: &ResolvedConfig) -> String {
    let mut out = String::from("# Managed by systemd-resolved-rs\n");
    let mut nameservers: Vec<String> = Vec::new();

    if config.stub_listener_mode != DnsStubListenerMode::No {
        nameservers.push("127.0.0.53".to_string());
    } else if !config.dns_servers.is_empty() {
        nameservers.extend(config.dns_servers.iter().cloned());
    } else if !config.fallback_servers.is_empty() {
        nameservers.extend(config.fallback_servers.iter().cloned());
    } else {
        nameservers.push("127.0.0.53".to_string());
    }

    for nameserver in nameservers {
        out.push_str("nameserver ");
        out.push_str(&nameserver);
        out.push('\n');
    }

    out.push_str("options edns0 trust-ad\n");

    if config.search_domains.is_empty() {
        out.push_str("search .\n");
    } else {
        out.push_str("search ");
        out.push_str(&config.search_domains.join(" "));
        out.push('\n');
    }

    out
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_service_parse_argv_empty() {
        assert!(service_parse_argv(&["systemd-resolved"]).is_ok());
    }

    #[test]
    fn test_service_parse_argv_help() {
        assert!(service_parse_argv(&["systemd-resolved", "--help"]).is_ok());
    }

    #[test]
    fn test_service_parse_argv_version() {
        assert!(service_parse_argv(&["systemd-resolved", "--version"]).is_ok());
    }

    #[test]
    fn test_service_parse_argv_unknown() {
        let result = service_parse_argv(&["systemd-resolved", "--bogus"]);
        assert!(matches!(result, Err(ResolvedError::ArgumentParseFailed(_))));
    }

    #[test]
    fn test_compute_required_capabilities() {
        let caps = compute_required_capabilities();
        assert!(has_cap(caps, CAP_NET_RAW));
        assert!(has_cap(caps, CAP_NET_BIND_SERVICE));
        assert!(!has_cap(caps, 0));
    }

    #[test]
    fn test_has_cap() {
        assert!(has_cap(CAP_NET_RAW, CAP_NET_RAW));
        assert!(!has_cap(CAP_NET_RAW, CAP_NET_BIND_SERVICE));
    }

    #[test]
    fn test_drop_privileges_nonroot() {
        let result = drop_privileges(false, "systemd-resolve", REQUIRED_CAPS).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_unknown_user_lookup_fails_without_mutating_credentials() {
        let result = resolve_user_creds("systemd-resolve-user-that-does-not-exist");
        assert!(matches!(result, Err(ResolvedError::UserResolveFailed(_))));
    }

    #[test]
    fn test_manager_new() {
        let mgr = Manager::new(true).unwrap();
        assert_eq!(mgr.state, ManagerState::Created);
        assert!(mgr.is_running_as_root);
    }

    #[test]
    fn test_manager_start() {
        let mut mgr = Manager::new(true).unwrap();
        mgr.start().unwrap();
        assert_eq!(mgr.state, ManagerState::Started);
    }

    #[test]
    fn test_manager_start_twice_fails() {
        let mut mgr = Manager::new(true).unwrap();
        mgr.start().unwrap();
        let result = mgr.start();
        assert!(matches!(result, Err(ResolvedError::ManagerStartFailed(_))));
    }

    #[test]
    fn test_manager_event_loop() {
        let mut mgr = Manager::new(true).unwrap();
        mgr.start().unwrap();
        mgr.enter_loop().unwrap();
        assert_eq!(mgr.state, ManagerState::Running);
        assert!(mgr.run_event_step());
        assert_eq!(mgr.event_iterations, 1);
    }

    #[test]
    fn test_create_runtime_dir_temp_path() {
        let dir = create_runtime_dir(false, 1000, 1000).unwrap();
        assert!(!dir.is_empty());
        assert!(PathBuf::from(&dir).starts_with(std::env::temp_dir()));
    }

    #[test]
    fn test_runtime_dir_creation_at_temp_path() {
        let dir = temp_test_dir("runtime-dir");
        #[cfg(target_os = "linux")]
        let (uid, gid) = (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        );
        #[cfg(not(target_os = "linux"))]
        let (uid, gid) = (0, 0);
        let created = create_runtime_dir_at(&dir, true, uid, gid).unwrap();

        assert_eq!(created, dir);
        assert!(dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, RUNTIME_DIR_MODE);
        }
    }

    #[test]
    fn test_resolv_conf_write_and_check_success() {
        let runtime_dir = temp_test_dir("resolv-conf-ok");
        fs::create_dir_all(&runtime_dir).unwrap();
        let mut mgr = Manager::new(true).unwrap();
        mgr.runtime_dir = runtime_dir.to_string_lossy().into_owned();
        mgr.start().unwrap();

        mgr.write_resolv_conf().unwrap();
        mgr.check_resolv_conf().unwrap();

        let content = fs::read_to_string(runtime_dir.join(RESOLV_CONF_FILENAME)).unwrap();
        assert_eq!(content, mgr.render_resolv_conf_contents());
        assert!(runtime_dir.is_dir());
    }

    #[test]
    fn test_resolv_conf_uses_upstream_servers_when_stub_disabled() {
        let runtime_dir = temp_test_dir("resolv-conf-upstream");
        fs::create_dir_all(&runtime_dir).unwrap();
        let mut mgr = Manager::new(true).unwrap();
        mgr.runtime_dir = runtime_dir.to_string_lossy().into_owned();
        mgr.config.stub_listener_mode = DnsStubListenerMode::No;
        mgr.config.dns_servers = vec!["9.9.9.9".into(), "1.1.1.1".into()];
        mgr.config.search_domains = vec!["example.com".into()];
        mgr.start().unwrap();
        mgr.write_resolv_conf().unwrap();

        let content = fs::read_to_string(runtime_dir.join(RESOLV_CONF_FILENAME)).unwrap();
        assert!(content.contains("nameserver 9.9.9.9"));
        assert!(content.contains("nameserver 1.1.1.1"));
        assert!(content.contains("search example.com"));
    }

    #[test]
    fn test_resolv_conf_check_missing_and_invalid() {
        let runtime_dir = temp_test_dir("resolv-conf-check");
        fs::create_dir_all(&runtime_dir).unwrap();

        let mut mgr = Manager::new(true).unwrap();
        mgr.runtime_dir = runtime_dir.to_string_lossy().into_owned();

        let missing = mgr.check_resolv_conf();
        assert!(matches!(
            missing,
            Err(ResolvedError::ResolvConfCheckFailed(_))
        ));

        fs::write(
            runtime_dir.join(RESOLV_CONF_FILENAME),
            "nameserver 1.1.1.1\n",
        )
        .unwrap();

        let invalid = mgr.check_resolv_conf();
        assert!(matches!(
            invalid,
            Err(ResolvedError::ResolvConfCheckFailed(_))
        ));
    }

    #[test]
    fn test_manager_lifecycle() {
        let runtime_dir = temp_test_dir("manager-lifecycle");
        fs::create_dir_all(&runtime_dir).unwrap();
        let mut mgr = Manager::new(true).unwrap();
        mgr.runtime_dir = runtime_dir.to_string_lossy().into_owned();
        assert_eq!(mgr.state, ManagerState::Created);
        mgr.start().unwrap();
        assert_eq!(mgr.state, ManagerState::Started);
        mgr.write_resolv_conf().unwrap();
        mgr.check_resolv_conf().unwrap();
        assert!(mgr.enter_loop().is_ok());
        assert_eq!(mgr.state, ManagerState::Running);
    }

    #[test]
    fn test_enter_loop_is_persistent_without_cutoff() {
        let mut mgr = Manager::new(true).unwrap();
        mgr.start().unwrap();
        mgr.enter_loop().unwrap();

        for _ in 0..1_001 {
            assert!(mgr.run_event_step());
        }

        assert_eq!(mgr.event_iterations, 1_001);
        assert_eq!(mgr.state, ManagerState::Running);

        mgr.state = ManagerState::Stopping;
        assert!(!mgr.run_event_step());
        assert_eq!(mgr.state, ManagerState::Stopped);
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock went backwards")
            .as_nanos();
        path.push(format!(
            "systemd-resolve-rs-{label}-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }
}

fn default_runtime_dir(is_root: bool) -> PathBuf {
    if is_root {
        PathBuf::from(RUNTIME_DIR)
    } else {
        #[cfg(test)]
        {
            return unique_test_runtime_dir();
        }

        #[cfg(not(test))]
        {
            return PathBuf::from(RUNTIME_DIR);
        }
    }
}

fn unique_test_runtime_dir() -> PathBuf {
    static TEST_RUNTIME_DIR: OnceLock<PathBuf> = OnceLock::new();

    TEST_RUNTIME_DIR
        .get_or_init(|| {
            let mut path = std::env::temp_dir();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock went backwards")
                .as_nanos();
            path.push(format!(
                "systemd-resolve-rs-test-{}-{nanos}",
                std::process::id()
            ));
            path
        })
        .clone()
}

fn create_runtime_dir_at(
    path: &Path,
    is_root: bool,
    uid: u32,
    gid: u32,
) -> Result<PathBuf, ResolvedError> {
    if !is_root {
        return Ok(path.to_path_buf());
    }

    fs::create_dir_all(path)
        .map_err(|e| ResolvedError::RuntimeDirCreateFailed(format!("{}: {}", path.display(), e)))?;

    let metadata = fs::symlink_metadata(path)
        .map_err(|e| ResolvedError::RuntimeDirCreateFailed(format!("{}: {}", path.display(), e)))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ResolvedError::RuntimeDirCreateFailed(format!(
            "{} is not a real directory",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(RUNTIME_DIR_MODE)).map_err(|e| {
            ResolvedError::RuntimeDirCreateFailed(format!("{}: {}", path.display(), e))
        })?;
    }

    #[cfg(target_os = "linux")]
    chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|e| {
        ResolvedError::RuntimeDirCreateFailed(format!("chown {}: {}", path.display(), e))
    })?;

    Ok(path.to_path_buf())
}

fn write_resolv_conf_file(path: &Path, contents: &str) -> Result<(), ResolvedError> {
    let parent = path.parent().ok_or_else(|| {
        ResolvedError::ResolvConfWriteFailed(format!("{} has no parent directory", path.display()))
    })?;

    fs::create_dir_all(parent).map_err(|e| {
        ResolvedError::ResolvConfWriteFailed(format!("{}: {}", parent.display(), e))
    })?;

    let mut last_error = None;

    for attempt in 0..64u32 {
        let temp_path = parent.join(format!(
            ".{}.{}.{}.tmp",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("resolv.conf"),
            std::process::id(),
            attempt
        ));

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(mut file) => {
                let write_result = (|| -> std::io::Result<()> {
                    #[cfg(unix)]
                    {
                        file.set_permissions(fs::Permissions::from_mode(RESOLV_CONF_MODE))?;
                    }

                    file.write_all(contents.as_bytes())?;
                    file.sync_all()?;
                    drop(file);
                    fs::rename(&temp_path, path)?;
                    Ok(())
                })();

                if let Err(err) = write_result {
                    let _ = fs::remove_file(&temp_path);
                    return Err(ResolvedError::ResolvConfWriteFailed(format!(
                        "{}: {}",
                        path.display(),
                        err
                    )));
                }

                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(err);
                continue;
            }
            Err(err) => {
                return Err(ResolvedError::ResolvConfWriteFailed(format!(
                    "{}: {}",
                    temp_path.display(),
                    err
                )));
            }
        }
    }

    Err(ResolvedError::ResolvConfWriteFailed(format!(
        "failed to create unique temporary file for {}{}",
        path.display(),
        last_error
            .as_ref()
            .map(|err| format!(": {}", err))
            .unwrap_or_default()
    )))
}
