// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::{HashMap, HashSet};

use super::model::{SyscallFilterOperation, SyscallFilterSet};
use super::syscall_lists;

impl SyscallFilterSet {
    /// Total number of filter-set variants.
    pub const MAX: usize = 30;

    /// The `@`-prefixed name of this filter set.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "@default",
            Self::Aio => "@aio",
            Self::BasicIo => "@basic-io",
            Self::Chown => "@chown",
            Self::Clock => "@clock",
            Self::CpuEmulation => "@cpu-emulation",
            Self::Debug => "@debug",
            Self::FileSystem => "@file-system",
            Self::IoEvent => "@io-event",
            Self::Ipc => "@ipc",
            Self::Keyring => "@keyring",
            Self::Memlock => "@memlock",
            Self::Module => "@module",
            Self::Mount => "@mount",
            Self::NetworkIo => "@network-io",
            Self::Obsolete => "@obsolete",
            Self::Pkey => "@pkey",
            Self::Privileged => "@privileged",
            Self::Process => "@process",
            Self::RawIo => "@raw-io",
            Self::Reboot => "@reboot",
            Self::Resources => "@resources",
            Self::Sandbox => "@sandbox",
            Self::Setuid => "@setuid",
            Self::Signal => "@signal",
            Self::Swap => "@swap",
            Self::Sync => "@sync",
            Self::SystemService => "@system-service",
            Self::Timer => "@timer",
            Self::Known => "@known",
        }
    }

    /// Human-readable help string for this filter set.
    pub const fn help(self) -> &'static str {
        match self {
            Self::Default => "System calls that are always permitted",
            Self::Aio => "Asynchronous IO",
            Self::BasicIo => "Basic IO",
            Self::Chown => "Change ownership of files and directories",
            Self::Clock => "Change the system time",
            Self::CpuEmulation => "System calls for CPU emulation functionality",
            Self::Debug => "Debugging, performance monitoring and tracing functionality",
            Self::FileSystem => "File system operations",
            Self::IoEvent => "Event loop system calls",
            Self::Ipc => "SysV IPC, POSIX Message Queues or other IPC",
            Self::Keyring => "Kernel keyring access",
            Self::Memlock => "Memory locking control",
            Self::Module => "Loading and unloading of kernel modules",
            Self::Mount => "Mounting and unmounting of file systems",
            Self::NetworkIo => {
                "Network or Unix socket IO, should not be needed if not network facing"
            }
            Self::Obsolete => "Unusual, obsolete or unimplemented system calls",
            Self::Pkey => "System calls used for memory protection keys",
            Self::Privileged => "All system calls which need super-user capabilities",
            Self::Process => "Process control, execution, namespacing operations",
            Self::RawIo => "Raw I/O port access",
            Self::Reboot => "Reboot and reboot preparation/kexec",
            Self::Resources => "Alter resource settings",
            Self::Sandbox => "Sandbox functionality",
            Self::Setuid => "Operations for changing user/group credentials",
            Self::Signal => "Process signal handling",
            Self::Swap => "Enable/disable swap devices",
            Self::Sync => "Synchronize files and memory to storage",
            Self::SystemService => "General system service operations",
            Self::Timer => "Schedule operations by time",
            Self::Known => "All known syscalls declared in the kernel",
        }
    }

    /// Syscall names (and `@`-prefixed set references) belonging to this set.
    pub fn syscalls(self) -> &'static [&'static str] {
        syscall_lists::syscalls(self)
    }

    /// Iterator over all filter-set variants in canonical order
    /// (`Default` first, `Known` last, rest alphabetical).
    pub fn all() -> impl Iterator<Item = Self> {
        [
            SyscallFilterSet::Default,
            SyscallFilterSet::Aio,
            SyscallFilterSet::BasicIo,
            SyscallFilterSet::Chown,
            SyscallFilterSet::Clock,
            SyscallFilterSet::CpuEmulation,
            SyscallFilterSet::Debug,
            SyscallFilterSet::FileSystem,
            SyscallFilterSet::IoEvent,
            SyscallFilterSet::Ipc,
            SyscallFilterSet::Keyring,
            SyscallFilterSet::Memlock,
            SyscallFilterSet::Module,
            SyscallFilterSet::Mount,
            SyscallFilterSet::NetworkIo,
            SyscallFilterSet::Obsolete,
            SyscallFilterSet::Pkey,
            SyscallFilterSet::Privileged,
            SyscallFilterSet::Process,
            SyscallFilterSet::RawIo,
            SyscallFilterSet::Reboot,
            SyscallFilterSet::Resources,
            SyscallFilterSet::Sandbox,
            SyscallFilterSet::Setuid,
            SyscallFilterSet::Signal,
            SyscallFilterSet::Swap,
            SyscallFilterSet::Sync,
            SyscallFilterSet::SystemService,
            SyscallFilterSet::Timer,
            SyscallFilterSet::Known,
        ]
        .into_iter()
    }

    /// Number of syscall entries (including set references) in this set.
    pub fn len(self) -> usize {
        self.syscalls().len()
    }

    /// Whether this set contains any entries.
    pub fn is_empty(self) -> bool {
        self.syscalls().is_empty()
    }
}

// ── Filter Set Lookup ────────────────────────────────────────────────────

/// Look up a [`SyscallFilterSet`] by its `@`-prefixed name.
///
/// Returns `None` for empty strings, names not starting with `@`, or
/// unknown set names.
///
/// Corresponds to `syscall_filter_set_find()` in the C source.
pub fn syscall_filter_set_find(name: &str) -> Option<SyscallFilterSet> {
    if name.is_empty() || !name.starts_with('@') {
        return None;
    }
    SyscallFilterSet::all().find(|s| s.name() == name)
}

// ── Filter Set Expansion ─────────────────────────────────────────────────

/// Expand a filter set (resolving `@`-references) into a flat list of
/// individual syscall names, without duplicates.
pub fn expand_filter_set(set: SyscallFilterSet) -> Vec<&'static str> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    expand_filter_set_recursive(set, &mut seen, &mut result);
    result
}

fn expand_filter_set_recursive(
    set: SyscallFilterSet,
    seen: &mut HashSet<&'static str>,
    result: &mut Vec<&'static str>,
) {
    for &entry in set.syscalls() {
        if entry.starts_with('@') {
            if let Some(referenced) = syscall_filter_set_find(entry) {
                if seen.insert(entry) {
                    expand_filter_set_recursive(referenced, seen, result);
                }
            }
        } else if seen.insert(entry) {
            result.push(entry);
        }
    }
}

// ── Seccomp Filter Set Add (Logic) ──────────────────────────────────────

/// Build a filter set map from a `SyscallFilterSet`.
///
/// If `add` is `true`, syscalls are inserted; otherwise they are removed.
/// Returns exact syscall names mapped to the requested operation.
///
/// Corresponds to the pure-logic portion of `seccomp_filter_set_add()`.
pub fn filter_set_add_logic(
    set: SyscallFilterSet,
    add: bool,
) -> HashMap<String, SyscallFilterOperation> {
    let mut filter = HashMap::new();
    let syscalls = expand_filter_set(set);

    for name in &syscalls {
        let operation = if add {
            SyscallFilterOperation::Insert(-1)
        } else {
            SyscallFilterOperation::Remove
        };
        filter.insert((*name).to_string(), operation);
    }

    filter
}
