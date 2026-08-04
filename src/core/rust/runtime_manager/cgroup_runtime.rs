// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Own cgroup path derivation, controller realization, population watches, and empty-cgroup
 * handling. RuntimeManager remains the sole owner of unit and service state.
 */
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

use super::RuntimeManager;
use super::linux_cgroup::{self, CgroupDirectory};
use super::unit_file::{CgroupIoLimitKind, UnitFileInfo};
use crate::service_tables::ServiceExecCommand;
use crate::unit::ActiveState;
use systemd_shared_rs::cpu_set_util::CpuSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CgroupRealizationOperation {
    CreateDirectory,
    EnableControllers,
    NormalizeControl,
    ApplyControl,
    CreateDelegateSubgroup,
    OpenDirectory,
    OpenProcesses,
    OpenEvents,
    WatchEvents,
    PublishRealization,
    ReadProcesses,
    ReadEvents,
    UnsupportedSetting,
    MissingRealization,
}

#[derive(Debug)]
pub(crate) struct CgroupRealizationError {
    operation: CgroupRealizationOperation,
    path: PathBuf,
    source: Option<io::Error>,
}

impl CgroupRealizationError {
    fn io(operation: CgroupRealizationOperation, path: PathBuf, source: io::Error) -> Self {
        Self {
            operation,
            path,
            source: Some(source),
        }
    }

    fn missing(unit_name: &str) -> Self {
        Self {
            operation: CgroupRealizationOperation::MissingRealization,
            path: PathBuf::from(unit_name),
            source: None,
        }
    }

    fn unsupported(setting: &str) -> Self {
        Self {
            operation: CgroupRealizationOperation::UnsupportedSetting,
            path: PathBuf::from(setting),
            source: None,
        }
    }

    fn invalid(setting: &str, detail: impl Into<String>) -> Self {
        Self::io(
            CgroupRealizationOperation::NormalizeControl,
            PathBuf::from(setting),
            io::Error::new(io::ErrorKind::InvalidInput, detail.into()),
        )
    }

    fn inconsistent(unit_name: &str, detail: impl Into<String>) -> Self {
        Self::io(
            CgroupRealizationOperation::PublishRealization,
            PathBuf::from(unit_name),
            io::Error::new(io::ErrorKind::InvalidData, detail.into()),
        )
    }

    pub(crate) fn operation(&self) -> CgroupRealizationOperation {
        self.operation
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Display for CgroupRealizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action = match self.operation {
            CgroupRealizationOperation::CreateDirectory => "creating cgroup directory",
            CgroupRealizationOperation::EnableControllers => "enabling cgroup controllers",
            CgroupRealizationOperation::NormalizeControl => "normalizing cgroup control",
            CgroupRealizationOperation::ApplyControl => "applying cgroup control",
            CgroupRealizationOperation::CreateDelegateSubgroup => {
                "creating delegated cgroup subgroup"
            }
            CgroupRealizationOperation::OpenDirectory => "opening cgroup directory",
            CgroupRealizationOperation::OpenProcesses => "opening cgroup.procs",
            CgroupRealizationOperation::OpenEvents => "opening cgroup.events",
            CgroupRealizationOperation::WatchEvents => "watching cgroup.events",
            CgroupRealizationOperation::PublishRealization => "publishing cgroup realization",
            CgroupRealizationOperation::ReadProcesses => "reading cgroup.procs",
            CgroupRealizationOperation::ReadEvents => "reading cgroup.events",
            CgroupRealizationOperation::UnsupportedSetting => {
                "applying unsupported cgroup-backed setting"
            }
            CgroupRealizationOperation::MissingRealization => "looking up realized unit cgroup",
        };
        write!(formatter, "{action} at {}", self.path.display())?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CgroupRealizationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Manager-owned capability for one realized unit cgroup.
///
/// The diagnostic path is retained for logs, inotify, and the still-path-based
/// compatibility index. Hierarchy traversal, control access, placement, and
/// population reads use descriptors resolved beneath the manager's preopened
/// root capability. Closing these files is automatic when RuntimeManager
/// forgets the unit.
#[derive(Debug)]
pub(super) struct RealizedUnitCgroup {
    path: PathBuf,
    base: RealizedCgroupTarget,
    processes_read: File,
    events: File,
    delegated: bool,
    delegate_subgroup: Option<String>,
    payload: Option<RealizedCgroupTarget>,
    control: Option<RealizedCgroupTarget>,
}

#[derive(Debug)]
struct RealizedCgroupTarget {
    directory: CgroupDirectory,
    processes: File,
}

pub(super) struct BorrowedCgroupFds<'a> {
    pub(super) directory: BorrowedFd<'a>,
    pub(super) processes_write: BorrowedFd<'a>,
    pub(super) processes_read: BorrowedFd<'a>,
    pub(super) events_read: BorrowedFd<'a>,
}

pub(super) struct BorrowedCgroupSpawnFds<'a> {
    pub(super) delegate_root: BorrowedFd<'a>,
    pub(super) target_directory: BorrowedFd<'a>,
    pub(super) target_processes: BorrowedFd<'a>,
    pub(super) delegated: bool,
    pub(super) recursive_target_access: bool,
}

#[cfg(target_os = "linux")]
struct PreparedCgroupWatch {
    descriptor: i32,
    new_inotify: Option<OwnedFd>,
}

#[cfg(not(target_os = "linux"))]
struct PreparedCgroupWatch;

impl RealizedUnitCgroup {
    // cgroup.procs is kernel-generated, but a unit may still contain enough
    // processes that an unconstrained read is inappropriate in manager code.
    // Treat a full buffer as indeterminate rather than returning a truncated
    // candidate set to a safety-sensitive caller such as Type=forking PID
    // adoption.
    const MAX_PROCESSES_BYTES: usize = 64 * 1024;

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn handoff_fds(&self) -> BorrowedCgroupFds<'_> {
        BorrowedCgroupFds {
            directory: self.base.directory.as_fd(),
            processes_write: self.base.processes.as_fd(),
            processes_read: self.processes_read.as_fd(),
            events_read: self.events.as_fd(),
        }
    }

    fn open(
        path: PathBuf,
        directory: CgroupDirectory,
        delegated: bool,
        delegate_subgroup: Option<String>,
        payload: Option<(PathBuf, CgroupDirectory)>,
        control: Option<(PathBuf, CgroupDirectory)>,
    ) -> Result<Self, CgroupRealizationError> {
        let processes_path = path.join("cgroup.procs");
        let processes_read = directory
            .open_file("cgroup.procs", libc::O_RDONLY)
            .map(File::from)
            .map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::OpenProcesses,
                    processes_path.clone(),
                    source,
                )
            })?;
        let events_path = path.join("cgroup.events");
        let events = directory
            .open_file("cgroup.events", libc::O_RDONLY)
            .map(File::from)
            .map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::OpenEvents,
                    events_path,
                    source,
                )
            })?;
        let base = RealizedCgroupTarget::open(path.clone(), directory)?;

        Ok(Self {
            path,
            base,
            processes_read,
            events,
            delegated,
            delegate_subgroup,
            payload: payload
                .map(|(path, directory)| RealizedCgroupTarget::open(path, directory))
                .transpose()?,
            control: control
                .map(|(path, directory)| RealizedCgroupTarget::open(path, directory))
                .transpose()?,
        })
    }

    fn spawn_fds(
        &self,
        command: ServiceExecCommand,
    ) -> Result<BorrowedCgroupSpawnFds<'_>, CgroupRealizationError> {
        let (target, recursive_target_access) = if !self.delegated {
            (&self.base, false)
        } else if command == ServiceExecCommand::Start {
            match self.payload.as_ref() {
                Some(payload) => (payload, true),
                None => (&self.base, false),
            }
        } else if self.delegate_subgroup.is_some()
            || matches!(
                command,
                ServiceExecCommand::StartPost
                    | ServiceExecCommand::Reload
                    | ServiceExecCommand::ReloadPost
                    | ServiceExecCommand::Stop
                    | ServiceExecCommand::StopPost
            )
        {
            (
                self.control.as_ref().ok_or_else(|| {
                    CgroupRealizationError::inconsistent(
                        self.path.to_string_lossy().as_ref(),
                        "delegated control command has no owned .control capability",
                    )
                })?,
                true,
            )
        } else {
            (&self.base, false)
        };

        Ok(BorrowedCgroupSpawnFds {
            delegate_root: self.base.directory.as_fd(),
            target_directory: target.directory.as_fd(),
            target_processes: target.processes.as_fd(),
            delegated: self.delegated,
            recursive_target_access,
        })
    }

    pub(super) fn events_fd(&self) -> BorrowedFd<'_> {
        self.events.as_fd()
    }

    fn events_identity(&self) -> io::Result<(u64, u64)> {
        let metadata = self.events.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }

    #[cfg(test)]
    fn set_test_populated(&self, populated: bool) -> io::Result<()> {
        self.base.directory.create_test_file(
            "cgroup.events",
            if populated {
                b"populated 1\nfrozen 0\n"
            } else {
                b"populated 0\nfrozen 0\n"
            },
        )
    }

    fn pids(&self) -> Result<Vec<u32>, CgroupRealizationError> {
        let snapshots = self
            .base
            .directory
            .read_processes_recursive(Self::MAX_PROCESSES_BYTES)
            .map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::ReadProcesses,
                    self.path.join("cgroup.procs"),
                    source,
                )
            })?;
        let mut pids = BTreeSet::new();
        for snapshot in snapshots {
            let content = std::str::from_utf8(&snapshot).map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::ReadProcesses,
                    self.path.join("cgroup.procs"),
                    io::Error::new(io::ErrorKind::InvalidData, source),
                )
            })?;
            let parsed = Self::parse_pids(content).ok_or_else(|| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::ReadProcesses,
                    self.path.join("cgroup.procs"),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "kernel cgroup.procs contained malformed or unsafe PID data",
                    ),
                )
            })?;
            // A process can move while a non-atomic recursive snapshot is
            // collected and consequently appear in two files. De-duplicate
            // that race without admitting any PID not supplied by cgroupfs.
            pids.extend(parsed);
        }
        Ok(pids.into_iter().collect())
    }

    fn parse_pids(content: &str) -> Option<Vec<u32>> {
        if content.is_empty() {
            return Some(Vec::new());
        }

        let mut pids = Vec::new();
        let mut seen = BTreeSet::new();
        for line in content.lines() {
            // cgroup.procs is one unsigned decimal PID per line. Do not trim
            // or accept a partial value: callers use this as proof of process
            // ownership, so ambiguity must fail closed.
            if line.is_empty() || !line.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let pid = line.parse::<u32>().ok()?;
            if pid == 0 || pid > i32::MAX as u32 || !seen.insert(pid) {
                return None;
            }
            pids.push(pid);
        }
        Some(pids)
    }

    fn populated(&self) -> Result<bool, CgroupRealizationError> {
        // cgroup.events is a small kernel-generated pseudo-file. A fixed
        // buffer avoids mutating the shared file offset and keeps the
        // capability bound to the object opened during realization.
        let mut buffer = [0u8; 4096];
        let size = self.events.read_at(&mut buffer, 0).map_err(|source| {
            CgroupRealizationError::io(
                CgroupRealizationOperation::ReadEvents,
                self.path.join("cgroup.events"),
                source,
            )
        })?;
        let content = std::str::from_utf8(&buffer[..size]).map_err(|source| {
            CgroupRealizationError::io(
                CgroupRealizationOperation::ReadEvents,
                self.path.join("cgroup.events"),
                io::Error::new(io::ErrorKind::InvalidData, source),
            )
        })?;
        RuntimeManager::parse_populated_from_events(content).ok_or_else(|| {
            CgroupRealizationError::io(
                CgroupRealizationOperation::ReadEvents,
                self.path.join("cgroup.events"),
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kernel cgroup.events omitted a valid populated field",
                ),
            )
        })
    }
}

impl RealizedCgroupTarget {
    fn open(path: PathBuf, directory: CgroupDirectory) -> Result<Self, CgroupRealizationError> {
        let processes_path = path.join("cgroup.procs");
        let processes = directory
            .open_file("cgroup.procs", libc::O_WRONLY)
            .map(File::from)
            .map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::OpenProcesses,
                    processes_path,
                    source,
                )
            })?;
        Ok(Self {
            directory,
            processes,
        })
    }
}

impl RuntimeManager {
    pub(super) fn cgroup_needs_escape(name: &str) -> bool {
        if name.is_empty() || name.contains('/') {
            return true;
        }

        if matches!(name.chars().next(), Some('_' | '.')) {
            return true;
        }

        if matches!(name, "notify_on_release" | "release_agent" | "tasks") {
            return true;
        }

        if name.starts_with("cgroup.") {
            return true;
        }

        // Keep this table aligned with CGroupController. These prefixes are
        // reserved kernel/systemd attribute namespaces and therefore cannot
        // be used verbatim as a delegated subgroup name.
        const CONTROLLERS: &[&str] = &[
            "cpu",
            "cpuacct",
            "cpuset",
            "io",
            "blkio",
            "memory",
            "devices",
            "pids",
            "bpf-firewall",
            "bpf-devices",
            "bpf-foreign",
            "bpf-socket-bind",
            "bpf-restrict-network-interfaces",
            "bpf-bind-network-interface",
        ];
        CONTROLLERS
            .iter()
            .any(|controller| name.starts_with(&format!("{controller}.")))
    }

    pub(super) fn cgroup_unit_component(name: &str) -> String {
        let safe = name.replace('/', "-");
        if Self::cgroup_needs_escape(&safe) {
            format!("_{safe}")
        } else {
            safe
        }
    }

    pub(super) fn cgroup_slice_components(slice_name: &str) -> Option<Vec<String>> {
        if slice_name == "-.slice" {
            return Some(Vec::new());
        }
        if !slice_name.ends_with(".slice") {
            return None;
        }

        let prefix = &slice_name[..slice_name.len().saturating_sub(".slice".len())];
        if prefix.is_empty() || prefix.starts_with('-') || prefix.ends_with('-') {
            return None;
        }

        let mut names = Vec::new();
        for (idx, ch) in prefix.char_indices() {
            if ch != '-' {
                continue;
            }
            let parent = &prefix[..idx];
            if parent.is_empty() || parent.ends_with('-') {
                return None;
            }
            names.push(format!("{parent}.slice"));
        }
        names.push(slice_name.to_string());

        Some(
            names
                .into_iter()
                .map(|name| Self::cgroup_unit_component(&name))
                .collect(),
        )
    }

    pub(super) fn cgroup_subtree_control_file(path: &Path) -> PathBuf {
        path.join("cgroup.subtree_control")
    }

    pub(super) fn parse_populated_from_events(content: &str) -> Option<bool> {
        content.lines().find_map(|line| {
            let mut parts = line.split_whitespace();
            let key = parts.next()?;
            let value = parts.next()?;
            if key != "populated" {
                return None;
            }
            match value {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            }
        })
    }

    pub(super) fn unit_parent_slice_for(unit_name: &str, info: &UnitFileInfo) -> Option<String> {
        if unit_name == "-.slice" {
            return None;
        }

        if unit_name.ends_with(".slice") {
            let prefix = unit_name.trim_end_matches(".slice");
            return prefix
                .rsplit_once('-')
                .map(|(parent, _)| format!("{parent}.slice"))
                .or_else(|| Some("-.slice".to_string()));
        }

        info.cgroup
            .slice
            .clone()
            .or_else(|| Some("system.slice".to_string()))
    }

    fn unit_cgroup_components_for(unit_name: &str, info: &UnitFileInfo) -> Vec<String> {
        if unit_name == "-.slice" {
            return Vec::new();
        }

        let mut components = Vec::new();
        if let Some(parent_slice) = Self::unit_parent_slice_for(unit_name, info)
            && let Some(slice_components) = Self::cgroup_slice_components(&parent_slice)
        {
            components.extend(slice_components);
        }
        components.push(Self::cgroup_unit_component(unit_name));
        components
    }

    pub(super) fn unit_cgroup_path_for(&self, unit_name: &str, info: &UnitFileInfo) -> PathBuf {
        let mut path = self.cgroup_root.path().to_path_buf();
        path.extend(Self::unit_cgroup_components_for(unit_name, info));
        path
    }

    pub(super) fn collect_needed_cgroup_controllers(info: &UnitFileInfo) -> BTreeSet<&'static str> {
        let c = &info.cgroup;
        let mut controllers = BTreeSet::new();

        for controller in &c.delegate_controllers {
            if let Some(controller) = match controller.as_str() {
                "cpu" => Some("cpu"),
                "cpuset" => Some("cpuset"),
                "io" => Some("io"),
                "memory" => Some("memory"),
                "pids" => Some("pids"),
                _ => None,
            } {
                controllers.insert(controller);
            }
        }

        if c.cpu_accounting == Some(true)
            || c.cpu_weight.is_some()
            || c.cpu_quota.is_some()
            || c.cpu_quota_period_usec.is_some()
        {
            controllers.insert("cpu");
        }
        if c.allowed_cpus.is_some() {
            controllers.insert("cpuset");
        }
        if c.io_accounting == Some(true)
            || c.io_weight.is_some()
            || !c.io_device_weight.is_empty()
            || !c.io_limits.is_empty()
        {
            controllers.insert("io");
        }
        if c.memory_accounting == Some(true)
            || c.memory_min.is_some()
            || c.memory_low.is_some()
            || c.memory_high.is_some()
            || c.memory_max.is_some()
            || c.memory_swap_max.is_some()
            || c.memory_zswap_max.is_some()
        {
            controllers.insert("memory");
        }
        if c.tasks_accounting == Some(true) || c.tasks_max.is_some() {
            controllers.insert("pids");
        }

        controllers
    }

    fn unsupported_cgroup_setting(info: &UnitFileInfo) -> Option<&'static str> {
        let c = &info.cgroup;
        [
            (c.ip_accounting == Some(true), "IPAccounting"),
            (!c.ip_address_allow.is_empty(), "IPAddressAllow"),
            (!c.ip_address_deny.is_empty(), "IPAddressDeny"),
            (!c.bpf_program.is_empty(), "BPFProgram"),
            (!c.socket_bind_allow.is_empty(), "SocketBindAllow"),
            (!c.socket_bind_deny.is_empty(), "SocketBindDeny"),
            (
                !c.restrict_network_interfaces.is_empty(),
                "RestrictNetworkInterfaces",
            ),
            (!c.nft_set.is_empty(), "NFTSet"),
            (c.coredump_filter.is_some(), "CoredumpFilter"),
            (
                c.managed_oom_memory_pressure.is_some(),
                "ManagedOOMMemoryPressure",
            ),
            (
                c.managed_oom_memory_pressure_limit.is_some(),
                "ManagedOOMMemoryPressureLimit",
            ),
            (c.managed_oom_preference.is_some(), "ManagedOOMPreference"),
            (c.managed_oom_swap.is_some(), "ManagedOOMSwap"),
            (c.memory_pressure_watch.is_some(), "MemoryPressureWatch"),
        ]
        .into_iter()
        .find_map(|(configured, setting)| configured.then_some(setting))
    }

    fn normalized_cpu_max(info: &UnitFileInfo) -> Result<Option<String>, CgroupRealizationError> {
        const USEC_PER_SEC: u64 = 1_000_000;
        const MIN_PERIOD_USEC: u64 = 1_000;
        const DEFAULT_PERIOD_USEC: u64 = 100_000;
        const MAX_PERIOD_USEC: u64 = USEC_PER_SEC;

        let c = &info.cgroup;
        let cpu_configured = c.cpu_accounting == Some(true)
            || c.cpu_weight.is_some()
            || c.cpu_quota.is_some()
            || c.cpu_quota_period_usec.is_some();
        if !cpu_configured {
            return Ok(None);
        }

        let quota_per_sec = c
            .cpu_quota
            .as_deref()
            .map(|value| {
                systemd_basic_rs::percent_util::parse_permyriad_unbounded(value)
                    .map_err(|_| {
                        CgroupRealizationError::invalid(
                            "CPUQuota",
                            format!("invalid CPU quota {value:?}"),
                        )
                    })
                    .and_then(|permyriad| {
                        if permyriad <= 0 {
                            return Err(CgroupRealizationError::invalid(
                                "CPUQuota",
                                "CPU quota must be greater than zero",
                            ));
                        }
                        (permyriad as u64)
                            .checked_mul(USEC_PER_SEC / 10_000)
                            .ok_or_else(|| {
                                CgroupRealizationError::invalid(
                                    "CPUQuota",
                                    "CPU quota arithmetic overflow",
                                )
                            })
                    })
            })
            .transpose()?;

        let Some(quota_per_sec) = quota_per_sec else {
            // C deliberately ignores a configured custom period for an
            // unlimited quota and resets cpu.max to its canonical default.
            return Ok(Some(format!("max {DEFAULT_PERIOD_USEC}\n")));
        };

        let requested_period = match c.cpu_quota_period_usec {
            None | Some(u64::MAX) => DEFAULT_PERIOD_USEC,
            Some(period) => period,
        };
        let quota_resolution_period = MIN_PERIOD_USEC
            .checked_mul(USEC_PER_SEC)
            .and_then(|value| value.checked_div(quota_per_sec))
            .ok_or_else(|| {
                CgroupRealizationError::invalid("CPUQuota", "CPU quota arithmetic overflow")
            })?;
        let period = requested_period
            .max(MIN_PERIOD_USEC)
            .max(quota_resolution_period)
            .min(MAX_PERIOD_USEC);
        let quota = ((quota_per_sec as u128 * period as u128) / USEC_PER_SEC as u128)
            .max(MIN_PERIOD_USEC as u128);
        let quota = u64::try_from(quota).map_err(|_| {
            CgroupRealizationError::invalid("CPUQuota", "CPU quota arithmetic overflow")
        })?;
        Ok(Some(format!("{quota} {period}\n")))
    }

    fn normalized_cpuset(info: &UnitFileInfo) -> Result<Option<String>, CgroupRealizationError> {
        let Some(value) = info.cgroup.allowed_cpus.as_deref() else {
            return Ok(None);
        };
        let words = Self::assignment_words(value).ok_or_else(|| {
            CgroupRealizationError::invalid(
                "AllowedCPUs",
                format!("invalid quoted CPU-set assignment {value:?}"),
            )
        })?;
        let cpus = CpuSet::parse_full(&words.join(" "), true)
            .map_err(|error| CgroupRealizationError::invalid("AllowedCPUs", error.to_string()))?;
        if cpus.is_empty() {
            // The C configuration parser ignores invalid ranges and leaves an
            // all-invalid assignment unset rather than writing an empty mask.
            return Ok(None);
        }
        Ok(Some(format!("{}\n", cpus.to_range_string())))
    }

    fn assignment_words(value: &str) -> Option<Vec<String>> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut quote = None;
        let mut escaped = false;
        for character in value.chars() {
            if escaped {
                word.push(character);
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if let Some(delimiter) = quote {
                if character == delimiter {
                    quote = None;
                } else {
                    word.push(character);
                }
                continue;
            }
            if matches!(character, '\'' | '"') {
                quote = Some(character);
            } else if character.is_whitespace() {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            } else {
                word.push(character);
            }
        }
        if escaped || quote.is_some() {
            return None;
        }
        if !word.is_empty() {
            words.push(word);
        }
        Some(words)
    }

    fn linux_device_number(path: &str) -> Result<(u64, u64), CgroupRealizationError> {
        // This path names the configured I/O resource, not a cgroup hierarchy
        // node. Hierarchy traversal remains descriptor-confined. Following
        // /dev/disk/by-* symlinks matches lookup_block_device() in C.
        let metadata = std::fs::metadata(path).map_err(|source| {
            CgroupRealizationError::io(
                CgroupRealizationOperation::NormalizeControl,
                PathBuf::from(path),
                source,
            )
        })?;
        if metadata.file_type().is_char_device() {
            return Err(CgroupRealizationError::invalid(
                "IODevice",
                format!("{path:?} is a character device, not a block device"),
            ));
        }
        let device = if metadata.file_type().is_block_device() {
            metadata.rdev()
        } else {
            metadata.dev()
        };
        let major = ((device >> 8) & 0xfff) | ((device >> 32) & !0xfff);
        let minor = (device & 0xff) | ((device >> 12) & !0xff);
        if major == 0 {
            return Err(CgroupRealizationError::invalid(
                "IODevice",
                format!("{path:?} has no directly discoverable backing block-device number"),
            ));
        }
        Self::canonical_block_device((major, minor))
    }

    fn parse_sysfs_device_number(value: &str) -> Option<(u64, u64)> {
        let (major, minor) = value.trim().split_once(':')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    }

    fn whole_block_device(device: (u64, u64)) -> Option<(u64, u64)> {
        let path = PathBuf::from(format!("/sys/dev/block/{}:{}", device.0, device.1));
        if path.join("queue").exists() {
            return Some(device);
        }
        if !path.join("partition").exists() {
            return None;
        }
        std::fs::read_to_string(path.join("../dev"))
            .ok()
            .and_then(|value| Self::parse_sysfs_device_number(&value))
    }

    fn canonical_block_device(
        mut device: (u64, u64),
    ) -> Result<(u64, u64), CgroupRealizationError> {
        let configured_device = device;
        // Mirror block_get_originating(..., recursive=true): follow a single
        // backing-device chain, or multiple partitions only when they all
        // resolve to the same whole disk. The C caller deliberately ignores
        // failures from that best-effort lookup, then resolves the configured
        // device to a whole disk. Preserve that fallback for an ambiguous
        // fan-out, cycle, or unreasonable chain depth.
        for _ in 0..256 {
            let slaves = PathBuf::from(format!("/sys/dev/block/{}:{}/slaves", device.0, device.1));
            let entries = match std::fs::read_dir(slaves) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A device with no sysfs ancestry is ordinary, not a
                    // control-normalization failure. Resolve the current
                    // device exactly as the C code's subsequent
                    // block_get_whole_disk() does.
                    return Ok(Self::whole_block_device(device).unwrap_or(device));
                }
                Err(_) => {
                    // lookup_block_device() ignores a failed originating
                    // lookup and keeps its original device number.
                    return Ok(
                        Self::whole_block_device(configured_device).unwrap_or(configured_device)
                    );
                }
            };
            let mut first = None;
            let mut first_whole = None;
            let mut ambiguous = false;
            for entry in entries {
                let Ok(entry) = entry else {
                    ambiguous = true;
                    break;
                };
                let Ok(value) = std::fs::read_to_string(entry.path().join("dev")) else {
                    continue;
                };
                let Some(candidate) = Self::parse_sysfs_device_number(&value) else {
                    continue;
                };
                let Some(whole) = Self::whole_block_device(candidate) else {
                    continue;
                };
                if let Some(expected) = first_whole {
                    if expected != whole {
                        ambiguous = true;
                        break;
                    }
                } else {
                    first = Some(candidate);
                    first_whole = Some(whole);
                }
            }
            if ambiguous {
                return Ok(Self::whole_block_device(configured_device).unwrap_or(configured_device));
            }
            let Some(next) = first else {
                return Ok(Self::whole_block_device(device).unwrap_or(device));
            };
            if next == device {
                return Ok(Self::whole_block_device(configured_device).unwrap_or(configured_device));
            }
            device = next;
        }

        Ok(Self::whole_block_device(configured_device).unwrap_or(configured_device))
    }

    fn normalized_io_weight(
        info: &UnitFileInfo,
    ) -> Result<(Vec<String>, Vec<String>), CgroupRealizationError> {
        const WEIGHT_MIN: u64 = 1;
        const WEIGHT_MAX: u64 = 10_000;
        const WEIGHT_DEFAULT: u64 = 100;
        const BFQ_MIN: u64 = 1;
        const BFQ_MAX: u64 = 1_000;
        const BFQ_DEFAULT: u64 = 100;

        let validate = |weight: u64, setting: &str| {
            (WEIGHT_MIN..=WEIGHT_MAX)
                .contains(&weight)
                .then_some(weight)
                .ok_or_else(|| {
                    CgroupRealizationError::invalid(
                        setting,
                        format!("weight {weight} is outside {WEIGHT_MIN}..={WEIGHT_MAX}"),
                    )
                })
        };
        let bfq = |weight: u64| {
            if weight <= WEIGHT_DEFAULT {
                BFQ_DEFAULT
                    - (WEIGHT_DEFAULT - weight) * (BFQ_DEFAULT - BFQ_MIN)
                        / (WEIGHT_DEFAULT - WEIGHT_MIN)
            } else {
                BFQ_DEFAULT
                    + (weight - WEIGHT_DEFAULT) * (BFQ_MAX - BFQ_DEFAULT)
                        / (WEIGHT_MAX - WEIGHT_DEFAULT)
            }
        };

        let io_configured = info.cgroup.io_accounting == Some(true)
            || info.cgroup.io_weight.is_some()
            || !info.cgroup.io_device_weight.is_empty()
            || !info.cgroup.io_limits.is_empty();
        let mut io = Vec::new();
        let mut bfq_io = Vec::new();
        if io_configured {
            let weight = info.cgroup.io_weight.unwrap_or(WEIGHT_DEFAULT);
            let weight = validate(weight, "IOWeight")?;
            io.push(format!("default {weight}\n"));
            bfq_io.push(format!("{}\n", bfq(weight)));
        }
        for assignment in &info.cgroup.io_device_weight {
            let words = Self::assignment_words(assignment).ok_or_else(|| {
                CgroupRealizationError::invalid(
                    "IODeviceWeight",
                    format!("invalid quoted assignment {assignment:?}"),
                )
            })?;
            let [path, weight] = words.as_slice() else {
                return Err(CgroupRealizationError::invalid(
                    "IODeviceWeight",
                    format!("expected a device path and weight in {assignment:?}"),
                ));
            };
            let weight = weight
                .parse::<u64>()
                .ok()
                .and_then(|value| (WEIGHT_MIN..=WEIGHT_MAX).contains(&value).then_some(value));
            let weight = weight.ok_or_else(|| {
                CgroupRealizationError::invalid(
                    "IODeviceWeight",
                    format!("invalid device weight in {assignment:?}"),
                )
            })?;
            let (major, minor) = Self::linux_device_number(path)?;
            io.push(format!("{major}:{minor} {weight}\n"));
            bfq_io.push(format!("{major}:{minor} {}\n", bfq(weight)));
        }
        Ok((io, bfq_io))
    }

    fn normalized_io_limits(info: &UnitFileInfo) -> Result<Vec<String>, CgroupRealizationError> {
        let mut devices = BTreeMap::<(u64, u64), [Option<u64>; 4]>::new();
        for assignment in &info.cgroup.io_limits {
            let words = Self::assignment_words(&assignment.value).ok_or_else(|| {
                CgroupRealizationError::invalid(
                    "IOLimit",
                    format!("invalid quoted assignment {:?}", assignment.value),
                )
            })?;
            let [path, value] = words.as_slice() else {
                return Err(CgroupRealizationError::invalid(
                    "IOLimit",
                    format!("expected a device path and limit in {:?}", assignment.value),
                ));
            };
            let limit = if value == "infinity" {
                u64::MAX
            } else {
                let parsed =
                    systemd_basic_rs::parse_util::parse_size(value, 1000).map_err(|_| {
                        CgroupRealizationError::invalid(
                            "IOLimit",
                            format!("invalid I/O limit {value:?}"),
                        )
                    })?;
                if parsed == 0 {
                    return Err(CgroupRealizationError::invalid(
                        "IOLimit",
                        "I/O limits must be greater than zero",
                    ));
                }
                parsed
            };
            let index = match assignment.kind {
                CgroupIoLimitKind::ReadBandwidth => 0,
                CgroupIoLimitKind::WriteBandwidth => 1,
                CgroupIoLimitKind::ReadIops => 2,
                CgroupIoLimitKind::WriteIops => 3,
            };
            devices
                .entry(Self::linux_device_number(path)?)
                .or_insert([None; 4])[index] = Some(limit);
        }

        Ok(devices
            .into_iter()
            .map(|((major, minor), limits)| {
                let render = |value: Option<u64>| match value {
                    None | Some(u64::MAX) => "max".to_string(),
                    Some(value) => value.to_string(),
                };
                format!(
                    "{major}:{minor} rbps={} wbps={} riops={} wiops={}\n",
                    render(limits[0]),
                    render(limits[1]),
                    render(limits[2]),
                    render(limits[3])
                )
            })
            .collect())
    }

    fn scale_memory_limit(permyriad: u64, physical: u64, page_size: u64) -> Option<u64> {
        if permyriad == 0 {
            return Some(0);
        }
        let pages = physical / page_size;
        let scaled_pages = (pages as u128)
            .checked_mul(permyriad as u128)?
            .checked_div(10_000)?;
        u64::try_from(scaled_pages.checked_mul(page_size as u128)?).ok()
    }

    fn normalized_memory_limit(
        &self,
        setting: &'static str,
        value: Option<&str>,
        default: u64,
        allow_zero: bool,
    ) -> Result<u64, CgroupRealizationError> {
        let Some(value) = value else {
            return Ok(default);
        };
        let bytes = if value == "infinity" {
            u64::MAX
        } else if let Ok(permyriad) = systemd_basic_rs::percent_util::parse_permyriad(value) {
            let permyriad = u64::try_from(permyriad).map_err(|_| {
                CgroupRealizationError::invalid(setting, "memory percentage must not be negative")
            })?;
            let (physical, page_size) =
                self.cgroup_root.physical_memory_bytes().map_err(|source| {
                    CgroupRealizationError::io(
                        CgroupRealizationOperation::NormalizeControl,
                        PathBuf::from(setting),
                        source,
                    )
                })?;
            Self::scale_memory_limit(permyriad, physical, page_size).ok_or_else(|| {
                CgroupRealizationError::invalid(setting, "memory percentage overflow")
            })?
        } else {
            systemd_basic_rs::parse_util::parse_size(value, 1024).map_err(|_| {
                CgroupRealizationError::invalid(setting, format!("invalid memory limit {value:?}"))
            })?
        };
        if bytes == u64::MAX || (bytes == 0 && !allow_zero) {
            if bytes == u64::MAX && value == "infinity" {
                return Ok(bytes);
            }
            return Err(CgroupRealizationError::invalid(
                setting,
                format!("memory limit {value:?} is out of range"),
            ));
        }
        Ok(bytes)
    }

    fn render_limit(value: u64) -> String {
        if value == u64::MAX {
            "max\n".to_string()
        } else {
            format!("{value}\n")
        }
    }

    pub(super) fn write_cgroup_file(
        directory: &CgroupDirectory,
        diagnostic_path: &Path,
        file: &str,
        value: &str,
    ) -> Result<(), CgroupRealizationError> {
        let control_path = diagnostic_path.join(file);
        directory
            .write_control_file(file, value.as_bytes())
            .map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::ApplyControl,
                    control_path,
                    source,
                )
            })
    }

    pub(super) fn write_cgroup_list(
        directory: &CgroupDirectory,
        diagnostic_path: &Path,
        file: &str,
        values: &[String],
    ) -> Result<(), CgroupRealizationError> {
        if values.is_empty() {
            return Ok(());
        }
        // cgroupfs controls consume one command per write. A multi-line write
        // is not a portable substitute: some controllers apply only the first
        // command before returning. Keep each normalized command atomic.
        for value in values {
            Self::write_cgroup_file(directory, diagnostic_path, file, value)?;
        }
        Ok(())
    }

    pub(super) fn enable_subtree_controllers(
        &self,
        components: &[String],
        controllers: &BTreeSet<&'static str>,
    ) -> Result<(), CgroupRealizationError> {
        if controllers.is_empty() {
            return Ok(());
        }

        let rendered = format!(
            "{}\n",
            controllers
                .iter()
                .map(|controller| format!("+{controller}"))
                .collect::<Vec<_>>()
                .join(" ")
        );

        // Controllers must be enabled from the root toward the unit's parent
        // before their control files appear in the leaf. Never enable them in
        // the unit cgroup itself: doing so turns it into an internal node and
        // makes the initial clone3(CLONE_INTO_CGROUP) fail with EBUSY. A
        // delegated payload owns the choice to enable controllers below the
        // unit after it has moved processes into its own child cgroups.
        let final_depth = components.len().saturating_sub(1);
        for depth in 0..=final_depth {
            let mut path = self.cgroup_root.path().to_path_buf();
            path.extend(&components[..depth]);
            let directory = self
                .cgroup_root
                .ensure_directory(&components[..depth])
                .map_err(|source| {
                    CgroupRealizationError::io(
                        CgroupRealizationOperation::CreateDirectory,
                        path.clone(),
                        source,
                    )
                })?;
            directory
                .write_control_file("cgroup.subtree_control", rendered.as_bytes())
                .map_err(|source| {
                    CgroupRealizationError::io(
                        CgroupRealizationOperation::EnableControllers,
                        Self::cgroup_subtree_control_file(&path),
                        source,
                    )
                })?;
        }
        Ok(())
    }

    pub(super) fn apply_unit_cgroup_limits(
        &self,
        directory: &CgroupDirectory,
        diagnostic_path: &Path,
        info: &UnitFileInfo,
    ) -> Result<(), CgroupRealizationError> {
        let c = &info.cgroup;

        // These directives are implemented by upstream through BPF, oomd,
        // nftables, or per-exec setup. They are not cgroupfs attributes. The
        // previous port invented `systemd.*` files and could claim success on
        // a writable test filesystem. Reject only configured behavior before
        // applying any kernel control until its real subsystem adapter exists.
        if let Some(setting) = Self::unsupported_cgroup_setting(info) {
            return Err(CgroupRealizationError::unsupported(setting));
        }

        let cpu_configured = c.cpu_accounting == Some(true)
            || c.cpu_weight.is_some()
            || c.cpu_quota.is_some()
            || c.cpu_quota_period_usec.is_some();
        if cpu_configured {
            let weight = c.cpu_weight.unwrap_or(100);
            if !(1..=10_000).contains(&weight) {
                return Err(CgroupRealizationError::invalid(
                    "CPUWeight",
                    format!("weight {weight} is outside 1..=10000"),
                ));
            }
            Self::write_cgroup_file(
                directory,
                diagnostic_path,
                "cpu.weight",
                &format!("{weight}\n"),
            )?;
        }
        if let Some(cpu_max) = Self::normalized_cpu_max(info)? {
            Self::write_cgroup_file(directory, diagnostic_path, "cpu.max", &cpu_max)?;
        }
        if let Some(allowed) = Self::normalized_cpuset(info)? {
            Self::write_cgroup_file(directory, diagnostic_path, "cpuset.cpus", &allowed)?;
        }

        let (io_weight, bfq_weight) = Self::normalized_io_weight(info)?;
        for command in &bfq_weight {
            // The BFQ attribute is a compatibility fallback; io.weight remains
            // authoritative when BFQ is unavailable.
            let _ = Self::write_cgroup_file(directory, diagnostic_path, "io.bfq.weight", command);
        }
        Self::write_cgroup_list(directory, diagnostic_path, "io.weight", &io_weight)?;

        let io_limits = Self::normalized_io_limits(info)?;
        Self::write_cgroup_list(directory, diagnostic_path, "io.max", &io_limits)?;

        let memory_configured = c.memory_accounting == Some(true)
            || c.memory_min.is_some()
            || c.memory_low.is_some()
            || c.memory_high.is_some()
            || c.memory_max.is_some()
            || c.memory_swap_max.is_some()
            || c.memory_zswap_max.is_some();
        if memory_configured {
            let memory_min =
                self.normalized_memory_limit("MemoryMin", c.memory_min.as_deref(), 0, true)?;
            let memory_low =
                self.normalized_memory_limit("MemoryLow", c.memory_low.as_deref(), 0, true)?;
            let memory_high = self.normalized_memory_limit(
                "MemoryHigh",
                c.memory_high.as_deref(),
                u64::MAX,
                false,
            )?;
            let memory_max = self.normalized_memory_limit(
                "MemoryMax",
                c.memory_max.as_deref(),
                u64::MAX,
                false,
            )?;
            let memory_swap_max = self.normalized_memory_limit(
                "MemorySwapMax",
                c.memory_swap_max.as_deref(),
                u64::MAX,
                true,
            )?;
            let memory_zswap_max = self.normalized_memory_limit(
                "MemoryZSwapMax",
                c.memory_zswap_max.as_deref(),
                u64::MAX,
                true,
            )?;
            Self::write_cgroup_file(
                directory,
                diagnostic_path,
                "memory.min",
                &Self::render_limit(memory_min),
            )?;
            Self::write_cgroup_file(
                directory,
                diagnostic_path,
                "memory.low",
                &Self::render_limit(memory_low),
            )?;
            Self::write_cgroup_file(
                directory,
                diagnostic_path,
                "memory.high",
                &Self::render_limit(memory_high),
            )?;
            Self::write_cgroup_file(
                directory,
                diagnostic_path,
                "memory.max",
                &Self::render_limit(memory_max),
            )?;
            Self::write_cgroup_file(
                directory,
                diagnostic_path,
                "memory.swap.max",
                &Self::render_limit(memory_swap_max),
            )?;
            Self::write_cgroup_file(
                directory,
                diagnostic_path,
                "memory.zswap.max",
                &Self::render_limit(memory_zswap_max),
            )?;
        }

        if let Some(tasks_max) = c.tasks_max {
            Self::write_cgroup_file(
                directory,
                diagnostic_path,
                "pids.max",
                &format!("{tasks_max}\n"),
            )?;
        }

        Ok(())
    }

    #[cfg(test)]
    fn create_test_cgroup_interface(directory: &CgroupDirectory) -> io::Result<()> {
        // Ordinary files model only the kernel-provided controls needed by
        // unit tests. Production never creates or writes cgroup.events.
        directory.create_test_file("cgroup.procs", b"")?;
        directory.create_test_file("cgroup.subtree_control", b"")?;
        directory.create_test_file("cgroup.events", b"populated 0\nfrozen 0\n")?;
        Ok(())
    }

    pub(super) fn ensure_unit_cgroup(
        &mut self,
        unit_name: &str,
        info: &UnitFileInfo,
    ) -> Result<(), CgroupRealizationError> {
        if let Some(setting) = Self::unsupported_cgroup_setting(info) {
            return Err(CgroupRealizationError::unsupported(setting));
        }
        let delegated = info.cgroup.delegate == Some(true);
        let delegate_subgroup = if delegated {
            info.cgroup
                .delegate_subgroup
                .as_deref()
                .filter(|subgroup| !subgroup.is_empty())
                .map(|subgroup| {
                    if Self::cgroup_needs_escape(subgroup) {
                        Err(CgroupRealizationError::invalid(
                            "DelegateSubgroup",
                            format!("{subgroup:?} is not a literal safe cgroup component"),
                        ))
                    } else {
                        Ok(subgroup.to_string())
                    }
                })
                .transpose()?
        } else {
            None
        };
        let components = Self::unit_cgroup_components_for(unit_name, info);
        let path = self.unit_cgroup_path_for(unit_name, info);

        let already_realized = match self.unit_cgroups.get(unit_name) {
            Some(realized) => {
                if realized.path() != path
                    || realized.delegated != delegated
                    || realized.delegate_subgroup != delegate_subgroup
                    || self.unit_cgroup_paths.get(unit_name) != Some(&path)
                    || !self.unit_cgroup_populated.contains_key(unit_name)
                {
                    return Err(CgroupRealizationError::inconsistent(
                        unit_name,
                        "owned cgroup capability and compatibility indexes disagree",
                    ));
                }
                #[cfg(target_os = "linux")]
                {
                    let Some(wd) = self.cgroup_watch_by_unit.get(unit_name).copied() else {
                        return Err(CgroupRealizationError::inconsistent(
                            unit_name,
                            "realized cgroup has no event watch",
                        ));
                    };
                    if self.cgroup_inotify_fd.is_none()
                        || self.cgroup_watch_by_wd.get(&wd).map(String::as_str) != Some(unit_name)
                    {
                        return Err(CgroupRealizationError::inconsistent(
                            unit_name,
                            "cgroup event-watch indexes disagree",
                        ));
                    }
                }
                true
            }
            None => {
                let has_partial_index = self.unit_cgroup_paths.contains_key(unit_name)
                    || self.unit_cgroup_populated.contains_key(unit_name);
                #[cfg(target_os = "linux")]
                let has_partial_index =
                    has_partial_index || self.cgroup_watch_by_unit.contains_key(unit_name);
                if has_partial_index {
                    return Err(CgroupRealizationError::inconsistent(
                        unit_name,
                        "cgroup indexes exist without an owned capability",
                    ));
                }
                false
            }
        };

        let controllers = Self::collect_needed_cgroup_controllers(info);
        self.enable_subtree_controllers(&components, &controllers)?;
        let directory = self
            .cgroup_root
            .ensure_directory(&components)
            .map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::CreateDirectory,
                    path.clone(),
                    source,
                )
            })?;
        self.apply_unit_cgroup_limits(&directory, &path, info)?;

        // Reapply changed limits to an existing realization, but retain its
        // already-published capability and kernel watch as one coherent owner.
        if already_realized {
            return Ok(());
        }

        let payload = delegate_subgroup
            .as_deref()
            .map(|subgroup| {
                let subgroup_path = path.join(subgroup);
                directory
                    .ensure_child(std::ffi::OsStr::new(subgroup))
                    .map(|directory| (subgroup_path.clone(), directory))
                    .map_err(|source| {
                        CgroupRealizationError::io(
                            CgroupRealizationOperation::CreateDelegateSubgroup,
                            subgroup_path,
                            source,
                        )
                    })
            })
            .transpose()?;
        let control = if delegated {
            let control_path = path.join(".control");
            Some(
                directory
                    .ensure_child(std::ffi::OsStr::new(".control"))
                    .map(|directory| (control_path.clone(), directory))
                    .map_err(|source| {
                        CgroupRealizationError::io(
                            CgroupRealizationOperation::CreateDelegateSubgroup,
                            control_path,
                            source,
                        )
                    })?,
            )
        } else {
            None
        };

        #[cfg(test)]
        {
            Self::create_test_cgroup_interface(&directory).map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::CreateDirectory,
                    path.clone(),
                    source,
                )
            })?;
            if let Some((subgroup_path, subgroup)) = &payload {
                Self::create_test_cgroup_interface(subgroup).map_err(|source| {
                    CgroupRealizationError::io(
                        CgroupRealizationOperation::CreateDelegateSubgroup,
                        subgroup_path.clone(),
                        source,
                    )
                })?;
            }
            if let Some((control_path, control)) = &control {
                Self::create_test_cgroup_interface(control).map_err(|source| {
                    CgroupRealizationError::io(
                        CgroupRealizationOperation::CreateDelegateSubgroup,
                        control_path.clone(),
                        source,
                    )
                })?;
            }
        }

        let realized = RealizedUnitCgroup::open(
            path.clone(),
            directory,
            delegated,
            delegate_subgroup,
            payload,
            control,
        )?;
        let populated = realized.populated()?;
        let prepared_watch = self.prepare_unit_cgroup_watch(unit_name, &realized)?;

        // All fallible realization work, including installing the kernel
        // watch, completed before any indexes or manager-owned capabilities
        // become observable. Publication below is deliberately infallible, so
        // no successfully installed watch can be stranded by a later error.
        #[cfg(target_os = "linux")]
        {
            if let Some(inotify) = prepared_watch.new_inotify {
                self.cgroup_inotify_fd = Some(inotify);
            }
            self.cgroup_watch_by_wd
                .insert(prepared_watch.descriptor, unit_name.to_string());
            self.cgroup_watch_by_unit
                .insert(unit_name.to_string(), prepared_watch.descriptor);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = prepared_watch;
        self.unit_cgroup_paths.insert(unit_name.to_string(), path);
        self.unit_cgroups.insert(unit_name.to_string(), realized);
        self.unit_cgroup_populated
            .insert(unit_name.to_string(), populated);
        Ok(())
    }

    pub(super) fn unit_cgroup_spawn_fds(
        &self,
        unit_name: &str,
        command: ServiceExecCommand,
    ) -> Result<BorrowedCgroupSpawnFds<'_>, CgroupRealizationError> {
        self.unit_cgroups
            .get(unit_name)
            .ok_or_else(|| CgroupRealizationError::missing(unit_name))?
            .spawn_fds(command)
    }

    /// Clear controllers a previous delegated payload may have enabled on the
    /// unit root before the next service start.
    ///
    /// Keeping those controller bits would leave the root as an internal
    /// cgroup and make a new direct placement fail with EBUSY. Upstream treats
    /// these writes as best effort because the subsequent clone3/cgroup.procs
    /// placement remains the fail-closed authority.
    pub(super) fn prepare_delegated_cgroup_start(&self, unit_name: &str) {
        let Some(cgroup) = self
            .unit_cgroups
            .get(unit_name)
            .filter(|cgroup| cgroup.delegated)
        else {
            return;
        };
        for controller in ["cpu", "cpuset", "io", "memory", "pids"] {
            let _ = cgroup.base.directory.write_control_file(
                "cgroup.subtree_control",
                format!("-{controller}\n").as_bytes(),
            );
        }
    }

    /// Return a bounded, strictly parsed snapshot of the kernel's cgroup
    /// membership using the descriptor retained at realization time.  The
    /// caller must treat an error as an inability to prove membership, never
    /// as an empty cgroup.
    pub(super) fn read_unit_cgroup_pids(
        &self,
        unit_name: &str,
    ) -> Result<Vec<u32>, CgroupRealizationError> {
        self.unit_cgroups
            .get(unit_name)
            .ok_or_else(|| CgroupRealizationError::missing(unit_name))?
            .pids()
    }

    #[cfg(target_os = "linux")]
    fn prepare_unit_cgroup_watch(
        &self,
        unit_name: &str,
        cgroup: &RealizedUnitCgroup,
    ) -> Result<PreparedCgroupWatch, CgroupRealizationError> {
        if self.cgroup_watch_by_unit.contains_key(unit_name) {
            return Err(CgroupRealizationError::io(
                CgroupRealizationOperation::WatchEvents,
                cgroup.path().join("cgroup.events"),
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("unit {unit_name} already has a cgroup event watch"),
                ),
            ));
        }

        // Do not publish a newly created manager-wide inotify capability until
        // the unit watch itself has succeeded.
        let pending_inotify = if self.cgroup_inotify_fd.is_none() {
            Some(linux_cgroup::inotify_init_nonblocking().map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::WatchEvents,
                    cgroup.path().join("cgroup.events"),
                    source,
                )
            })?)
        } else {
            None
        };
        let inotify = pending_inotify
            .as_ref()
            .or(self.cgroup_inotify_fd.as_ref())
            .expect("an existing or newly created inotify descriptor");
        let events_identity = cgroup.events_identity().map_err(|source| {
            CgroupRealizationError::io(
                CgroupRealizationOperation::WatchEvents,
                cgroup.path().join("cgroup.events"),
                source,
            )
        })?;
        for (other_unit, other_cgroup) in &self.unit_cgroups {
            let other_identity = other_cgroup.events_identity().map_err(|source| {
                CgroupRealizationError::io(
                    CgroupRealizationOperation::WatchEvents,
                    other_cgroup.path().join("cgroup.events"),
                    source,
                )
            })?;
            if other_identity == events_identity {
                return Err(CgroupRealizationError::io(
                    CgroupRealizationOperation::WatchEvents,
                    cgroup.path().join("cgroup.events"),
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("cgroup.events capability is already owned by {other_unit}"),
                    ),
                ));
            }
        }
        let wd = linux_cgroup::inotify_add_watch_fd(
            inotify.as_fd(),
            cgroup.events_fd(),
            libc::IN_MODIFY | libc::IN_ATTRIB | libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO,
        )
        .map_err(|source| {
            CgroupRealizationError::io(
                CgroupRealizationOperation::WatchEvents,
                cgroup.path().join("cgroup.events"),
                source,
            )
        })?;

        if let Some(other_unit) = self.cgroup_watch_by_wd.get(&wd) {
            // Active watch descriptors are unique within an inotify instance,
            // and duplicate target inodes were rejected before add_watch.
            // Thus a collision proves that the old map entry is stale and this
            // newly installed watch must be removed before failing closed.
            let rollback = linux_cgroup::inotify_remove_watch(inotify.as_fd(), wd);
            let detail = match rollback {
                Ok(()) => format!("watch descriptor {wd} is still indexed for {other_unit}"),
                Err(error) => format!(
                    "watch descriptor {wd} is still indexed for {other_unit}; rollback failed: {error}"
                ),
            };
            return Err(CgroupRealizationError::io(
                CgroupRealizationOperation::WatchEvents,
                cgroup.path().join("cgroup.events"),
                io::Error::new(io::ErrorKind::AlreadyExists, detail),
            ));
        }

        Ok(PreparedCgroupWatch {
            descriptor: wd,
            new_inotify: pending_inotify,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn prepare_unit_cgroup_watch(
        &self,
        _unit_name: &str,
        _cgroup: &RealizedUnitCgroup,
    ) -> Result<PreparedCgroupWatch, CgroupRealizationError> {
        Ok(PreparedCgroupWatch)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn unwatch_unit_cgroup_events(&mut self, unit_name: &str) {
        let Some(wd) = self.cgroup_watch_by_unit.remove(unit_name) else {
            return;
        };
        self.cgroup_watch_by_wd.remove(&wd);
        if let Some(fd) = self.cgroup_inotify_fd.as_ref() {
            let _ = linux_cgroup::inotify_remove_watch(fd.as_fd(), wd);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn unwatch_unit_cgroup_events(&mut self, _unit_name: &str) {}

    pub(super) fn unit_has_tracked_processes(&self, unit_name: &str) -> bool {
        if self.unit_pid_map.contains_key(unit_name) {
            return true;
        }
        self.units.get(unit_name).is_some_and(|unit| {
            unit.main_pid.is_some() || unit.control_pid.is_some() || !unit.watched_pids.is_empty()
        })
    }

    pub(super) fn read_unit_cgroup_populated(&self, unit_name: &str) -> Option<bool> {
        self.unit_cgroups.get(unit_name)?.populated().ok()
    }

    pub(super) fn set_unit_cgroup_populated(&mut self, unit_name: &str, populated: bool) {
        #[cfg(test)]
        {
            let Some(cgroup) = self.unit_cgroups.get(unit_name) else {
                return;
            };
            let _ = cgroup.set_test_populated(populated);
            self.unit_cgroup_populated
                .insert(unit_name.to_string(), populated);
        }

        #[cfg(not(test))]
        {
            // Tracking is not cgroup state. Only the kernel-generated
            // cgroup.events descriptor may advance the production cache.
            let _ = populated;
            self.refresh_unit_cgroup_state(unit_name);
        }
    }

    pub(super) fn update_unit_cgroup_population_from_tracking(&mut self, unit_name: &str) {
        let populated = self.unit_has_tracked_processes(unit_name);
        self.set_unit_cgroup_populated(unit_name, populated);
    }

    pub(super) fn refresh_unit_cgroup_state(&mut self, unit_name: &str) {
        let Some(populated) = self.read_unit_cgroup_populated(unit_name) else {
            return;
        };

        self.unit_cgroup_populated
            .insert(unit_name.to_string(), populated);
        if !populated {
            self.maybe_handle_cgroup_empty(unit_name);
        }
    }

    pub(super) fn prune_unit_cgroup(&mut self, unit_name: &str) {
        if self.unit_has_tracked_processes(unit_name) {
            return;
        }

        let Some(info) = self.unit_files.get(unit_name) else {
            return;
        };
        let components = Self::unit_cgroup_components_for(unit_name, info);

        // `unit_prune_cgroup()` only releases C's cgroup runtime (including
        // its inotify watches) after `unit_maybe_release_cgroup()` confirmed
        // the cgroup is empty. Keep our ownership indexes and event watch
        // until deletion succeeds too: a failed deletion can leave a live
        // cgroup whose later empty event is needed to retry cleanup.
        if self.cgroup_root.remove_directory(&components).is_ok() {
            self.unwatch_unit_cgroup_events(unit_name);
            self.unit_cgroup_paths.remove(unit_name);
            self.unit_cgroups.remove(unit_name);
            self.unit_cgroup_populated.remove(unit_name);
        }
    }

    pub(super) fn maybe_handle_cgroup_empty(&mut self, unit_name: &str) {
        // An empty interval between two asynchronous Exec* commands is
        // expected.  Conversely, stale PID bookkeeping must not suppress a
        // kernel-authoritative empty notification. Only the canonical service
        // state machine may decide whether either case completes a stop/final
        // phase; it owns idempotence and state-specific handling.
        self.service_cgroup_empty_event(unit_name);

        let prune_allowed = self
            .units
            .get(unit_name)
            .is_some_and(|u| matches!(u.active_state, ActiveState::Inactive | ActiveState::Failed));
        if prune_allowed {
            self.prune_unit_cgroup(unit_name);
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn process_cgroup_events(&mut self) {
        let Some(fd) = self.cgroup_inotify_fd.as_ref() else {
            return;
        };

        let mut touched: BTreeSet<String> = BTreeSet::new();
        let mut buffer = [0u8; 4096];

        loop {
            let events = match linux_cgroup::read_inotify_events(fd.as_fd(), &mut buffer) {
                Ok(events) if events.is_empty() => break,
                Ok(events) => events,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };

            for event in events {
                if event.watch_descriptor >= 0
                    && (event.mask & libc::IN_IGNORED) == 0
                    && let Some(name) = self
                        .cgroup_watch_by_wd
                        .get(&event.watch_descriptor)
                        .cloned()
                {
                    touched.insert(name);
                }
            }
        }

        for unit_name in touched {
            self.refresh_unit_cgroup_state(&unit_name);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn process_cgroup_events(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::RealizedUnitCgroup;

    #[test]
    fn parses_strict_cgroup_process_membership() {
        assert_eq!(
            RealizedUnitCgroup::parse_pids("42\n31337\n"),
            Some(vec![42, 31337])
        );
        assert_eq!(RealizedUnitCgroup::parse_pids(""), Some(Vec::new()));
    }

    #[test]
    fn rejects_ambiguous_cgroup_process_membership() {
        for input in ["0\n", "42 \n", "42\n42\n", "-42\n", "99999999999\n"] {
            assert_eq!(RealizedUnitCgroup::parse_pids(input), None, "{input:?}");
        }
    }
}
