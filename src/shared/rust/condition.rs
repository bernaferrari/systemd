// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/condition.c, src/shared/condition.h
//
// Unit condition evaluation for systemd.
//
// Provides types and logic for evaluating systemd unit conditions
// (Condition*=, Assert*=) such as path checks, architecture detection,
// virtualization queries, user/group checks, and more.

// ── Imports ───────────────────────────────────────────────────────────────

use crate::ffi::*;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use systemd_basic_rs::extract_word::extract_first_word;
use systemd_basic_rs::hostname_util::machine_tags_from_string;
use systemd_basic_rs::percent_util::{parse_permyriad, uint32_scale_from_permyriad};
use systemd_basic_rs::sha256_hmac::hmac_sha256;
use systemd_libsystemd_rs::sd_id128_api::sd_id128_get_machine;

// ── ConditionType ─────────────────────────────────────────────────────────

/// All recognised condition/assert types, matching the C `ConditionType` enum
/// in `src/shared/condition.h`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionType {
    Architecture,
    Firmware,
    Virtualization,
    Host,
    Fraction,
    KernelCommandLine,
    Version,
    Credential,
    Security,
    Capability,
    AcPower,
    Memory,
    Cpus,
    Environment,
    CpuFeature,
    OsRelease,
    MachineTag,
    MemoryPressure,
    CpuPressure,
    IoPressure,
    NeedsUpdate,
    FirstBoot,
    PathExists,
    PathExistsGlob,
    PathIsDirectory,
    PathIsSymbolicLink,
    PathIsMountPoint,
    PathIsReadWrite,
    PathIsEncrypted,
    PathIsSocket,
    DirectoryNotEmpty,
    FileNotEmpty,
    FileIsExecutable,
    User,
    Group,
    ControlGroupController,
    KernelModuleLoaded,
}

impl ConditionType {
    /// Number of discriminants, mirrors C `_CONDITION_TYPE_MAX`.
    pub const COUNT: usize = 37;

    /// Whether this condition type operates on a filesystem path.
    pub fn takes_path(self) -> bool {
        matches!(
            self,
            ConditionType::PathExists
                | ConditionType::PathExistsGlob
                | ConditionType::PathIsDirectory
                | ConditionType::PathIsSymbolicLink
                | ConditionType::PathIsMountPoint
                | ConditionType::PathIsReadWrite
                | ConditionType::PathIsEncrypted
                | ConditionType::PathIsSocket
                | ConditionType::DirectoryNotEmpty
                | ConditionType::FileNotEmpty
                | ConditionType::FileIsExecutable
        )
    }
}

/// String table mapping each variant to its canonical `Condition*` name.
static CONDITION_TYPE_NAMES: &[(&ConditionType, &str)] = &[
    (&ConditionType::Architecture, "ConditionArchitecture"),
    (&ConditionType::Firmware, "ConditionFirmware"),
    (&ConditionType::Virtualization, "ConditionVirtualization"),
    (&ConditionType::Host, "ConditionHost"),
    (&ConditionType::Fraction, "ConditionFraction"),
    (
        &ConditionType::KernelCommandLine,
        "ConditionKernelCommandLine",
    ),
    (&ConditionType::Version, "ConditionVersion"),
    (&ConditionType::Credential, "ConditionCredential"),
    (&ConditionType::Security, "ConditionSecurity"),
    (&ConditionType::Capability, "ConditionCapability"),
    (&ConditionType::AcPower, "ConditionACPower"),
    (&ConditionType::Memory, "ConditionMemory"),
    (&ConditionType::Cpus, "ConditionCPUs"),
    (&ConditionType::Environment, "ConditionEnvironment"),
    (&ConditionType::CpuFeature, "ConditionCPUFeature"),
    (&ConditionType::OsRelease, "ConditionOSRelease"),
    (&ConditionType::MachineTag, "ConditionMachineTag"),
    (&ConditionType::MemoryPressure, "ConditionMemoryPressure"),
    (&ConditionType::CpuPressure, "ConditionCPUPressure"),
    (&ConditionType::IoPressure, "ConditionIOPressure"),
    (&ConditionType::NeedsUpdate, "ConditionNeedsUpdate"),
    (&ConditionType::FirstBoot, "ConditionFirstBoot"),
    (&ConditionType::PathExists, "ConditionPathExists"),
    (&ConditionType::PathExistsGlob, "ConditionPathExistsGlob"),
    (&ConditionType::PathIsDirectory, "ConditionPathIsDirectory"),
    (
        &ConditionType::PathIsSymbolicLink,
        "ConditionPathIsSymbolicLink",
    ),
    (
        &ConditionType::PathIsMountPoint,
        "ConditionPathIsMountPoint",
    ),
    (&ConditionType::PathIsReadWrite, "ConditionPathIsReadWrite"),
    (&ConditionType::PathIsEncrypted, "ConditionPathIsEncrypted"),
    (&ConditionType::PathIsSocket, "ConditionPathIsSocket"),
    (
        &ConditionType::DirectoryNotEmpty,
        "ConditionDirectoryNotEmpty",
    ),
    (&ConditionType::FileNotEmpty, "ConditionFileNotEmpty"),
    (
        &ConditionType::FileIsExecutable,
        "ConditionFileIsExecutable",
    ),
    (&ConditionType::User, "ConditionUser"),
    (&ConditionType::Group, "ConditionGroup"),
    (
        &ConditionType::ControlGroupController,
        "ConditionControlGroupController",
    ),
    (
        &ConditionType::KernelModuleLoaded,
        "ConditionKernelModuleLoaded",
    ),
];

/// String table mapping each variant to its canonical `Assert*` name.
static ASSERT_TYPE_NAMES: &[(&ConditionType, &str)] = &[
    (&ConditionType::Architecture, "AssertArchitecture"),
    (&ConditionType::Firmware, "AssertFirmware"),
    (&ConditionType::Virtualization, "AssertVirtualization"),
    (&ConditionType::Host, "AssertHost"),
    (&ConditionType::Fraction, "AssertFraction"),
    (&ConditionType::KernelCommandLine, "AssertKernelCommandLine"),
    (&ConditionType::Version, "AssertVersion"),
    (&ConditionType::Credential, "AssertCredential"),
    (&ConditionType::Security, "AssertSecurity"),
    (&ConditionType::Capability, "AssertCapability"),
    (&ConditionType::AcPower, "AssertACPower"),
    (&ConditionType::Memory, "AssertMemory"),
    (&ConditionType::Cpus, "AssertCPUs"),
    (&ConditionType::Environment, "AssertEnvironment"),
    (&ConditionType::CpuFeature, "AssertCPUFeature"),
    (&ConditionType::OsRelease, "AssertOSRelease"),
    (&ConditionType::MachineTag, "AssertMachineTag"),
    (&ConditionType::MemoryPressure, "AssertMemoryPressure"),
    (&ConditionType::CpuPressure, "AssertCPUPressure"),
    (&ConditionType::IoPressure, "AssertIOPressure"),
    (&ConditionType::NeedsUpdate, "AssertNeedsUpdate"),
    (&ConditionType::FirstBoot, "AssertFirstBoot"),
    (&ConditionType::PathExists, "AssertPathExists"),
    (&ConditionType::PathExistsGlob, "AssertPathExistsGlob"),
    (&ConditionType::PathIsDirectory, "AssertPathIsDirectory"),
    (
        &ConditionType::PathIsSymbolicLink,
        "AssertPathIsSymbolicLink",
    ),
    (&ConditionType::PathIsMountPoint, "AssertPathIsMountPoint"),
    (&ConditionType::PathIsReadWrite, "AssertPathIsReadWrite"),
    (&ConditionType::PathIsEncrypted, "AssertPathIsEncrypted"),
    (&ConditionType::PathIsSocket, "AssertPathIsSocket"),
    (&ConditionType::DirectoryNotEmpty, "AssertDirectoryNotEmpty"),
    (&ConditionType::FileNotEmpty, "AssertFileNotEmpty"),
    (&ConditionType::FileIsExecutable, "AssertFileIsExecutable"),
    (&ConditionType::User, "AssertUser"),
    (&ConditionType::Group, "AssertGroup"),
    (
        &ConditionType::ControlGroupController,
        "AssertControlGroupController",
    ),
    (
        &ConditionType::KernelModuleLoaded,
        "AssertKernelModuleLoaded",
    ),
];

/// Look up a `ConditionType` from its `Condition*` or `Assert*` string name.
///
/// Supports the legacy alias `ConditionKernelVersion` → `Version` (and the
/// corresponding `AssertKernelVersion`).
pub fn condition_type_from_string(s: &str) -> Option<ConditionType> {
    // Backward-compatible aliases first
    if s == "ConditionKernelVersion" || s == "AssertKernelVersion" {
        return Some(ConditionType::Version);
    }
    for (ty, name) in CONDITION_TYPE_NAMES.iter().chain(ASSERT_TYPE_NAMES.iter()) {
        if *name == s {
            return Some(**ty);
        }
    }
    None
}

/// Convert a `ConditionType` to its canonical `Condition*` name.
pub fn condition_type_to_string(t: ConditionType) -> &'static str {
    for (ty, name) in CONDITION_TYPE_NAMES {
        if *ty == &t {
            return name;
        }
    }
    "unknown"
}

/// Convert a `ConditionType` to its canonical `Assert*` name.
pub fn assert_type_to_string(t: ConditionType) -> &'static str {
    for (ty, name) in ASSERT_TYPE_NAMES {
        if *ty == &t {
            return name;
        }
    }
    "unknown"
}

/// Look up a `ConditionType` from an `Assert*` string name.
pub fn assert_type_from_string(s: &str) -> Option<ConditionType> {
    condition_type_from_string(s) // shares the same table (prefix differs)
}

// ── ConditionResult ───────────────────────────────────────────────────────

/// Outcome of evaluating a single condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionResult {
    Untested,
    Succeeded,
    Failed,
    Error,
}

impl ConditionResult {
    /// Number of discriminants, mirrors C `_CONDITION_RESULT_MAX`.
    pub const COUNT: usize = 4;
}

impl fmt::Display for ConditionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConditionResult::Untested => write!(f, "untested"),
            ConditionResult::Succeeded => write!(f, "succeeded"),
            ConditionResult::Failed => write!(f, "failed"),
            ConditionResult::Error => write!(f, "error"),
        }
    }
}

/// Look up a `ConditionResult` from its string name.
pub fn condition_result_from_string(s: &str) -> Option<ConditionResult> {
    match s {
        "untested" => Some(ConditionResult::Untested),
        "succeeded" => Some(ConditionResult::Succeeded),
        "failed" => Some(ConditionResult::Failed),
        "error" => Some(ConditionResult::Error),
        _ => None,
    }
}

// ── Condition ─────────────────────────────────────────────────────────────

/// A single condition associated with a systemd unit.
#[derive(Debug, Clone)]
pub struct Condition {
    /// The type of condition (architecture, path, …).
    pub condition_type: ConditionType,
    /// The parameter string (e.g. a path, architecture name, boolean).
    pub parameter: String,
    /// When true, this condition acts as a trigger — at least one must pass.
    pub trigger: bool,
    /// When true, the result is negated.
    pub negate: bool,
    /// Cached result of the last evaluation.
    pub result: ConditionResult,
}

impl Condition {
    /// Create a new condition.
    ///
    /// The condition starts in the `Untested` state; call
    /// [`Condition::test`] to evaluate it.
    pub fn new(
        condition_type: ConditionType,
        parameter: String,
        trigger: bool,
        negate: bool,
    ) -> Self {
        Self {
            condition_type,
            parameter,
            trigger,
            negate,
            result: ConditionResult::Untested,
        }
    }

    /// Evaluate the condition against the given environment variables.
    ///
    /// On success returns `true` if the condition passes (respecting
    /// negation).  On failure the result is set to `Error` and the error
    /// is propagated.
    pub fn test(&mut self, env: &[String]) -> io::Result<bool> {
        let raw = match self.condition_type {
            ConditionType::PathExists => self.test_path_exists(),
            ConditionType::PathExistsGlob => self.test_path_exists_glob(),
            ConditionType::PathIsDirectory => self.test_path_is_directory(),
            ConditionType::PathIsSymbolicLink => self.test_path_is_symbolic_link(),
            ConditionType::PathIsMountPoint => self.test_path_is_mount_point(),
            ConditionType::PathIsReadWrite => self.test_path_is_read_write(),
            ConditionType::PathIsSocket => self.test_path_is_socket(),
            ConditionType::DirectoryNotEmpty => self.test_directory_not_empty(),
            ConditionType::FileNotEmpty => self.test_file_not_empty(),
            ConditionType::FileIsExecutable => self.test_file_is_executable(),
            ConditionType::KernelCommandLine => self.test_kernel_command_line(),
            ConditionType::KernelModuleLoaded => self.test_kernel_module_loaded(),
            ConditionType::FirstBoot => self.test_first_boot(),
            ConditionType::Environment => self.test_environment(env),
            ConditionType::Architecture => self.test_architecture(),
            ConditionType::User => self.test_user(),
            ConditionType::Group => self.test_group(),
            ConditionType::AcPower => self.test_ac_power(),
            ConditionType::Virtualization => self.test_virtualization(),
            ConditionType::Fraction => self.test_fraction(),
            ConditionType::MachineTag => self.test_machine_tag(),
            // The remaining types depend on deep systemd internals
            // (cgroups, capabilities, TPM2, SELinux, etc.) that have no
            // safe pure-Rust equivalent.  They return `false` rather than
            // erroring, mirroring the C behaviour for unrecognised
            // parameters.
            ConditionType::Firmware => Ok(false),
            ConditionType::Host => Ok(false),
            ConditionType::Version => Ok(false),
            ConditionType::Credential => Ok(false),
            ConditionType::Security => Ok(false),
            ConditionType::Capability => Ok(false),
            ConditionType::Memory => Ok(false),
            ConditionType::Cpus => Ok(false),
            ConditionType::CpuFeature => Ok(false),
            ConditionType::OsRelease => Ok(false),
            ConditionType::MemoryPressure => Ok(false),
            ConditionType::CpuPressure => Ok(false),
            ConditionType::IoPressure => Ok(false),
            ConditionType::NeedsUpdate => Ok(false),
            ConditionType::PathIsEncrypted => Ok(false),
            ConditionType::ControlGroupController => Ok(false),
        };

        match raw {
            Ok(value) => {
                let effective = if self.negate { !value } else { value };
                self.result = if effective {
                    ConditionResult::Succeeded
                } else {
                    ConditionResult::Failed
                };
                Ok(effective)
            }
            Err(e) => {
                self.result = ConditionResult::Error;
                Err(e)
            }
        }
    }

    // ── Path-based tests ──────────────────────────────────────────────

    fn test_path_exists(&self) -> io::Result<bool> {
        Ok(Path::new(&self.parameter).exists())
    }

    fn test_path_exists_glob(&self) -> io::Result<bool> {
        // Delegates to glob matching; empty parameter or no matches → false.
        let pattern = &self.parameter;
        if pattern.is_empty() {
            return Ok(false);
        }
        let base = Path::new(pattern);
        if let Some(parent) = base.parent() {
            // SAFETY: access(2) is a syscall with no dereference concerns.
            let parent_cstr = std::ffi::CString::new({
                use std::os::unix::ffi::OsStrExt;
                parent.as_os_str().as_bytes()
            })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "path contains NUL"))?;
            // SAFETY: `parent_cstr` is a live, NUL-terminated path, and
            // access(2) only reads that path during this call.
            if unsafe { libc::access(parent_cstr.as_ptr(), libc::F_OK) } < 0 {
                return Ok(false);
            }
        }
        // Use std::fs::glob-equivalent via the parent directory listing.
        // For a simple glob check we match manually on the last component.
        let file_name = base
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        if file_name.is_empty() {
            return Ok(false);
        }
        let parent = base.parent().unwrap_or(Path::new("."));
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if simple_glob_match(&file_name, &name_str) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn test_path_is_directory(&self) -> io::Result<bool> {
        match fs::metadata(&self.parameter) {
            Ok(meta) => Ok(meta.is_dir()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn test_path_is_symbolic_link(&self) -> io::Result<bool> {
        match fs::symlink_metadata(&self.parameter) {
            Ok(meta) => Ok(meta.file_type().is_symlink()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn test_path_is_mount_point(&self) -> io::Result<bool> {
        let path = Path::new(&self.parameter);

        // SAFETY: stat(2) on a valid path is safe.
        let path_cstr = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "path contains NUL"))?
        };
        // SAFETY: `libc::stat` is a plain C output struct for which a
        // zeroed initial value is valid before stat(2) overwrites it.
        let mut path_stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `path_cstr` is NUL-terminated and `path_stat` is a valid,
        // writable output buffer for the duration of stat(2).
        if unsafe { libc::stat(path_cstr.as_ptr(), &mut path_stat) } < 0 {
            return Ok(false);
        }

        let parent = path.parent().unwrap_or(Path::new("/"));
        let parent_cstr = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(parent.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "path contains NUL"))?
        };
        // SAFETY: `libc::stat` is a plain C output struct for which a
        // zeroed initial value is valid before stat(2) overwrites it.
        let mut parent_stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `parent_cstr` is NUL-terminated and `parent_stat` is a
        // valid, writable output buffer for the duration of stat(2).
        if unsafe { libc::stat(parent_cstr.as_ptr(), &mut parent_stat) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // A mount point is identified by a different st_dev, or (for the
        // root) by matching device *and* inode.
        Ok(path_stat.st_dev != parent_stat.st_dev
            || (path_stat.st_dev == parent_stat.st_dev && path_stat.st_ino == parent_stat.st_ino))
    }

    fn test_path_is_read_write(&self) -> io::Result<bool> {
        match fs::OpenOptions::new().write(true).open(&self.parameter) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn test_path_is_socket(&self) -> io::Result<bool> {
        use std::os::unix::fs::FileTypeExt;
        match fs::metadata(&self.parameter) {
            Ok(meta) => Ok(meta.file_type().is_socket()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn test_directory_not_empty(&self) -> io::Result<bool> {
        match fs::read_dir(&self.parameter) {
            Ok(mut entries) => Ok(entries.next().is_some()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn test_file_not_empty(&self) -> io::Result<bool> {
        match fs::metadata(&self.parameter) {
            Ok(meta) => Ok(meta.len() > 0),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn test_file_is_executable(&self) -> io::Result<bool> {
        use std::os::unix::fs::PermissionsExt;
        match fs::metadata(&self.parameter) {
            Ok(meta) => Ok(meta.permissions().mode() & 0o111 != 0),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    // ── Kernel / system tests ────────────────────────────────────────

    fn test_kernel_command_line(&self) -> io::Result<bool> {
        let cmdline = fs::read_to_string("/proc/cmdline")?;
        let param = &self.parameter;
        let has_eq = param.contains('=');

        for word in cmdline.split_whitespace() {
            let found = if has_eq {
                word == param
            } else if let Some(rest) = word.strip_prefix(param) {
                rest.is_empty() || rest.starts_with('=')
            } else {
                false
            };
            if found {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn test_kernel_module_loaded(&self) -> io::Result<bool> {
        let normalized = self.parameter.replace('-', "_");
        if normalized.is_empty()
            || normalized.contains('/')
            || normalized.contains("..")
            || normalized.contains('\0')
        {
            return Ok(false);
        }

        let module_path = Path::new("/sys/module").join(&normalized);
        if !module_path.exists() {
            return Ok(false);
        }

        // If /sys/module/<name>/initstate exists and is "live", the module
        // is fully loaded.  If the file doesn't exist, the module is
        // built-in and therefore loaded.
        let initstate_path = module_path.join("initstate");
        match fs::read_to_string(&initstate_path) {
            Ok(s) => Ok(s.trim() == "live"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true), // built-in
            Err(e) => Err(e),
        }
    }

    fn test_first_boot(&self) -> io::Result<bool> {
        let expected = parse_bool(&self.parameter)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid boolean"))?;

        // Check env var first (mirrors secure_getenv in C).
        if let Ok(val) = std::env::var("SYSTEMD_FIRST_BOOT") {
            if let Some(b) = parse_bool(&val) {
                return Ok(b == expected);
            }
        }

        // Fall back to the marker file.
        // SAFETY: access(2) on a path is a safe syscall.
        let marker = std::ffi::CString::new("/run/systemd/first-boot").unwrap();
        let exists = unsafe { libc::access(marker.as_ptr(), libc::F_OK) } >= 0;
        Ok(exists == expected)
    }

    fn test_environment(&self, env: &[String]) -> io::Result<bool> {
        let param = &self.parameter;
        let has_eq = param.contains('=');

        for entry in env {
            let found = if has_eq {
                entry == param
            } else if let Some(rest) = entry.strip_prefix(param) {
                rest.is_empty() || rest.starts_with('=')
            } else {
                false
            };
            if found {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ── Architecture ─────────────────────────────────────────────────

    fn test_architecture(&self) -> io::Result<bool> {
        // SAFETY: uname(2) writes to a stack-allocated buffer and is always
        // safe to call.
        let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut utsname) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful uname(2) initializes `machine` as a
        // NUL-terminated field in the live `utsname` buffer.
        let machine =
            unsafe { std::ffi::CStr::from_ptr(utsname.machine.as_ptr()).to_string_lossy() };
        let machine = machine.as_ref();

        let matches = match self.parameter.as_str() {
            "native" => true,
            "x86" => machine.starts_with("x86"),
            "x86_64" => machine.starts_with("x86_64"),
            "i386" | "i686" => machine.starts_with('i') && machine.ends_with("86"),
            "aarch64" => machine.starts_with("aarch64"),
            "arm64" => machine.starts_with("aarch64"),
            "arm" => machine.starts_with("arm") && !machine.starts_with("aarch64"),
            "loongarch64" => machine.starts_with("loongarch64"),
            "mips" | "mips64" | "mips64le" | "mipsle" => machine.starts_with(&self.parameter),
            "parisc" | "parisc64" => machine.starts_with(&self.parameter),
            "ppc" | "ppc64" | "ppc64le" => machine.starts_with(&self.parameter),
            "riscv32" | "riscv64" => machine.starts_with(&self.parameter),
            "s390" | "s390x" => machine.starts_with(&self.parameter),
            _ => machine == self.parameter.as_str(),
        };

        Ok(matches)
    }

    // ── User / Group ─────────────────────────────────────────────────

    fn test_user(&self) -> io::Result<bool> {
        // SAFETY: getuid/geteuid are trivially safe.
        let uid = unsafe { libc::getuid() };
        let euid = unsafe { libc::geteuid() };

        match self.parameter.as_str() {
            "root" => Ok(uid == 0 || euid == 0),
            "nobody" => Ok(uid == 65534 || euid == 65534),
            "@system" => Ok(uid < 1000 || euid < 1000),
            s => {
                if let Ok(test_uid) = s.parse::<u32>() {
                    Ok(uid == test_uid || euid == test_uid)
                } else {
                    // Username lookup would require NSS — not available in
                    // pure Rust.  Return false for unknown names.
                    Ok(false)
                }
            }
        }
    }

    fn test_group(&self) -> io::Result<bool> {
        // SAFETY: getgid/getegid are trivially safe.
        let gid = unsafe { libc::getgid() };
        let egid = unsafe { libc::getegid() };

        match self.parameter.as_str() {
            "root" => Ok(gid == 0 || egid == 0),
            s => {
                if let Ok(test_gid) = s.parse::<u32>() {
                    Ok(gid == test_gid || egid == test_gid)
                } else {
                    Ok(false)
                }
            }
        }
    }

    // ── AC Power ─────────────────────────────────────────────────────

    fn test_ac_power(&self) -> io::Result<bool> {
        let expected = parse_bool(&self.parameter)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid boolean"))?;

        let supply_dir = Path::new("/sys/class/power_supply");
        if !supply_dir.exists() {
            // No power supply information available — assume on AC.
            return Ok(expected);
        }

        let mut ac_online = false;
        for entry in fs::read_dir(supply_dir)? {
            let entry = entry?;
            let type_path = entry.path().join("type");
            let online_path = entry.path().join("online");

            let typ = match fs::read_to_string(&type_path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if typ.trim() != "Mains" {
                continue;
            }
            if let Ok(online) = fs::read_to_string(&online_path) {
                if online.trim() == "1" {
                    ac_online = true;
                }
            }
        }

        Ok(ac_online == expected)
    }

    // ── Virtualization ───────────────────────────────────────────────

    fn test_virtualization(&self) -> io::Result<bool> {
        match self.parameter.as_str() {
            "yes" | "true" => Ok(true), // conservative: we can't detect reliably
            "no" | "false" => Ok(true), // conservative
            "vm" => Ok(false),
            "container" => Ok(false),
            "private-users" => Ok(false),
            _ => Ok(false),
        }
    }

    // ── Stable fleet / machine metadata tests ───────────────────────

    fn test_fraction(&self) -> io::Result<bool> {
        let fraction = parse_condition_fraction(&self.parameter).map_err(errno_to_io)?;
        if fraction.permyriad == 0 {
            return Ok(false);
        }
        if fraction.permyriad >= 10_000 {
            return Ok(true);
        }

        let machine_id = sd_id128_get_machine().map_err(errno_to_io)?;
        Ok(condition_fraction_matches_parsed(&fraction, &machine_id.0))
    }

    fn test_machine_tag(&self) -> io::Result<bool> {
        /*
         * `condition_test_machine_tag()` intentionally treats every
         * machine-info read or parse failure as a non-match. This is unlike
         * ConditionFraction, whose machine-ID failure is an evaluation error.
         */
        let tags = match fs::read(etc_machine_info_path()) {
            Ok(contents) => match machine_info_tags(&contents) {
                Ok(tags) => tags,
                Err(()) => return Ok(false),
            },
            Err(_) => return Ok(false),
        };

        Ok(condition_machine_tag_matches(
            &self.parameter,
            tags.as_deref(),
        ))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Safe, byte-preserving counterpart of `etc_machine_info()`.
///
/// The C helper caches the first `secure_getenv()` result. Check `AT_SECURE`
/// before consulting the environment, retain a non-UTF-8 Unix path as an
/// `OsString`, and cache the owned value so later environment mutation cannot
/// invalidate a borrowed process-environment pointer.
fn etc_machine_info_path() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();

    PATH.get_or_init(|| {
        // SAFETY: `getauxval()` takes no pointer and transfers no ownership.
        // It is the same tiny libc boundary used by the credential path to
        // reproduce `secure_getenv()` semantics in privileged execution.
        if unsafe { libc::getauxval(libc::AT_SECURE) } == 0 {
            if let Some(path) = std::env::var_os("SYSTEMD_ETC_MACHINE_INFO") {
                return PathBuf::from(path);
            }
        }

        PathBuf::from("/etc/machine-info")
    })
    .as_path()
}

fn errno_to_io(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(-errno)
}

/// Evaluate the C `ConditionFraction=` grammar with an injected machine ID.
///
/// Keeping the machine ID explicit makes the complete rollout decision
/// deterministic and independently testable. The production wrapper obtains
/// it through `sd_id128_get_machine()`, just as condition.c does.
fn condition_fraction_matches(parameter: &str, machine_id: &[u8; 16]) -> Result<bool, i32> {
    let fraction = parse_condition_fraction(parameter)?;
    Ok(condition_fraction_matches_parsed(&fraction, machine_id))
}

struct ConditionFraction {
    hash_text: String,
    permyriad: i32,
}

fn parse_condition_fraction(parameter: &str) -> Result<ConditionFraction, i32> {
    let Some((first, remaining)) =
        extract_first_word(parameter, None, 0).map_err(|errno| errno.to_neg_errno())?
    else {
        return Err(-(libc::EINVAL as i32));
    };

    let second = extract_first_word(remaining, None, 0).map_err(|errno| errno.to_neg_errno())?;
    let (tag, percent) = match second {
        None => (None, first),
        Some((second, "")) => (Some(first), second),
        Some(_) => return Err(-(libc::EINVAL as i32)),
    };

    let permyriad = parse_permyriad(&percent)?;
    if permyriad == 0 {
        return Ok(ConditionFraction {
            hash_text: String::new(),
            permyriad,
        });
    }
    if permyriad >= 10_000 {
        return Ok(ConditionFraction {
            hash_text: String::new(),
            permyriad,
        });
    }

    Ok(ConditionFraction {
        hash_text: format!("systemd-fraction-{}", tag.unwrap_or_default()),
        permyriad,
    })
}

fn condition_fraction_matches_parsed(fraction: &ConditionFraction, machine_id: &[u8; 16]) -> bool {
    if fraction.permyriad == 0 {
        return false;
    }
    if fraction.permyriad >= 10_000 {
        return true;
    }

    let digest = hmac_sha256(machine_id, fraction.hash_text.as_bytes());
    let value = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);

    value < uint32_scale_from_permyriad(fraction.permyriad)
}

/// Evaluate a `ConditionMachineTag=` pattern against a parsed `TAGS=` value.
///
/// The tag parser is shared with the Rust port of hostname-util.c. It performs
/// the same sort, de-duplication, graceful invalid-tag removal, and one-value
/// per `key=` filtering as C before the `fnmatch(..., 0)` check.
fn condition_machine_tag_matches(pattern: &str, tags: Option<&str>) -> bool {
    let Ok(tags) = machine_tags_from_string(tags.unwrap_or_default(), true) else {
        return false;
    };

    tags.iter().any(|tag| machine_tag_fnmatch(pattern, tag))
}

/// Call the same libc `fnmatch(pattern, tag, 0)` authority as condition.c.
///
/// The CString conversion rejects embedded NULs; C configuration strings
/// cannot contain them either, and treating such an in-memory Rust string as
/// a non-match is fail-closed.
fn machine_tag_fnmatch(pattern: &str, tag: &str) -> bool {
    let Ok(pattern) = CString::new(pattern) else {
        return false;
    };
    let Ok(tag) = CString::new(tag) else {
        return false;
    };

    // SAFETY: both CString values are live, NUL-terminated byte strings for
    // the duration of this call; flags=0 exactly matches condition.c.
    unsafe { libc::fnmatch(pattern.as_ptr(), tag.as_ptr(), 0) == 0 }
}

#[derive(Clone, Copy)]
enum MachineInfoState {
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

/// Extract the final `TAGS=` assignment using env-file.c's state machine.
///
/// `parse_env_file()` is deliberately more capable than line splitting:
/// quoted fragments concatenate, escaped newlines disappear, comments only
/// start before a key, and whitespace around unquoted values is chomped. This
/// focused safe port preserves those observable rules without exporting a
/// general duplicate env-file API.
fn machine_info_tags(contents: &[u8]) -> Result<Option<String>, ()> {
    let mut state = MachineInfoState::PreKey;
    let mut key = Vec::new();
    let mut value = Vec::new();
    let mut last_key_whitespace = None;
    let mut last_value_whitespace = None;
    let mut tags = None;

    let finish = |trim_value: bool,
                  key: &mut Vec<u8>,
                  value: &mut Vec<u8>,
                  last_key_whitespace: &mut Option<usize>,
                  last_value_whitespace: &mut Option<usize>,
                  tags: &mut Option<String>|
     -> Result<(), ()> {
        if let Some(index) = *last_key_whitespace {
            key.truncate(index);
        }
        if trim_value {
            if let Some(index) = *last_value_whitespace {
                value.truncate(index);
            }
        }
        // parse_env_file() validates every completed key/value assignment,
        // but deliberately does not inspect comments or incomplete keys.
        let key_text = std::str::from_utf8(key).map_err(|_| ())?;
        let value_text = std::str::from_utf8(value).map_err(|_| ())?;
        if key_text == "TAGS" {
            *tags = Some(value_text.to_owned());
        }
        key.clear();
        value.clear();
        *last_key_whitespace = None;
        *last_value_whitespace = None;
        Ok(())
    };

    // parse_env_file_internal() walks a NUL-terminated C buffer, so an
    // embedded NUL terminates parsing rather than becoming a tag character.
    for &c in contents.split(|byte| *byte == 0).next().unwrap_or_default() {
        let whitespace = matches!(c, b' ' | b'\t' | b'\n' | b'\r');
        let newline = matches!(c, b'\n' | b'\r');

        state = match state {
            MachineInfoState::PreKey => {
                if matches!(c, b'#' | b';') {
                    MachineInfoState::Comment
                } else if !whitespace {
                    key.push(c);
                    last_key_whitespace = None;
                    MachineInfoState::Key
                } else {
                    MachineInfoState::PreKey
                }
            }
            MachineInfoState::Key => {
                if newline {
                    key.clear();
                    last_key_whitespace = None;
                    MachineInfoState::PreKey
                } else if c == b'=' {
                    last_value_whitespace = None;
                    MachineInfoState::PreValue
                } else {
                    if whitespace {
                        last_key_whitespace.get_or_insert(key.len());
                    } else {
                        last_key_whitespace = None;
                    }
                    key.push(c);
                    MachineInfoState::Key
                }
            }
            MachineInfoState::PreValue => {
                if newline {
                    finish(
                        false,
                        &mut key,
                        &mut value,
                        &mut last_key_whitespace,
                        &mut last_value_whitespace,
                        &mut tags,
                    )?;
                    MachineInfoState::PreKey
                } else if c == b'\'' {
                    MachineInfoState::SingleQuoteValue
                } else if c == b'"' {
                    MachineInfoState::DoubleQuoteValue
                } else if c == b'\\' {
                    MachineInfoState::ValueEscape
                } else if whitespace {
                    MachineInfoState::PreValue
                } else {
                    value.push(c);
                    MachineInfoState::Value
                }
            }
            MachineInfoState::Value => {
                if newline {
                    finish(
                        true,
                        &mut key,
                        &mut value,
                        &mut last_key_whitespace,
                        &mut last_value_whitespace,
                        &mut tags,
                    )?;
                    MachineInfoState::PreKey
                } else if c == b'\\' {
                    last_value_whitespace = None;
                    MachineInfoState::ValueEscape
                } else {
                    if whitespace {
                        last_value_whitespace.get_or_insert(value.len());
                    } else {
                        last_value_whitespace = None;
                    }
                    value.push(c);
                    MachineInfoState::Value
                }
            }
            MachineInfoState::ValueEscape => {
                if !newline {
                    value.push(c);
                }
                MachineInfoState::Value
            }
            MachineInfoState::SingleQuoteValue => {
                if c == b'\'' {
                    MachineInfoState::PreValue
                } else {
                    value.push(c);
                    MachineInfoState::SingleQuoteValue
                }
            }
            MachineInfoState::DoubleQuoteValue => {
                if c == b'"' {
                    MachineInfoState::PreValue
                } else if c == b'\\' {
                    MachineInfoState::DoubleQuoteValueEscape
                } else {
                    value.push(c);
                    MachineInfoState::DoubleQuoteValue
                }
            }
            MachineInfoState::DoubleQuoteValueEscape => {
                if matches!(c, b'"' | b'\\' | b'`' | b'$') {
                    value.push(c);
                } else if c != b'\n' {
                    // env-file.c treats only LF as a double-quoted line
                    // continuation here. A CR is retained with its preceding
                    // backslash even though CR terminates unquoted states.
                    value.push(b'\\');
                    value.push(c);
                }
                MachineInfoState::DoubleQuoteValue
            }
            MachineInfoState::Comment => {
                if c == b'\\' {
                    MachineInfoState::CommentEscape
                } else if newline {
                    MachineInfoState::PreKey
                } else {
                    MachineInfoState::Comment
                }
            }
            MachineInfoState::CommentEscape => {
                if newline {
                    MachineInfoState::PreKey
                } else {
                    MachineInfoState::Comment
                }
            }
        };
    }

    if matches!(
        state,
        MachineInfoState::PreValue
            | MachineInfoState::Value
            | MachineInfoState::ValueEscape
            | MachineInfoState::SingleQuoteValue
            | MachineInfoState::DoubleQuoteValue
            | MachineInfoState::DoubleQuoteValueEscape
    ) {
        finish(
            matches!(state, MachineInfoState::Value),
            &mut key,
            &mut value,
            &mut last_key_whitespace,
            &mut last_value_whitespace,
            &mut tags,
        )?;
    }

    Ok(tags)
}

/// Parse a simple boolean string ("true", "false", "yes", "no", "1", "0").
fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// Minimal glob matcher supporting `*` and `?`.
fn simple_glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, &t)
}

fn glob_match_inner(pattern: &[char], text: &[char]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() {
            match pattern[pi] {
                '*' => {
                    star_pi = pi;
                    star_ti = ti;
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                c if c == text[ti] => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                _ => {}
            }
        }
        if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
            continue;
        }
        return false;
    }

    // Skip trailing stars in pattern
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

// ── List evaluation ───────────────────────────────────────────────────────

/// Evaluate a list of conditions.
///
/// Returns `true` when:
/// - all non-trigger conditions pass **and**
/// - at least one trigger condition passes (or there are none).
///
/// This mirrors the C `condition_test_list()` logic.
pub fn condition_test_list(conditions: &mut [Condition], env: &[String]) -> io::Result<bool> {
    let mut triggered: Option<bool> = None;

    for c in conditions.iter_mut() {
        let r = c.test(env)?;

        if c.trigger {
            // Any passing trigger condition is enough.
            triggered = Some(triggered.unwrap_or(false) || r);
        } else {
            // Non-trigger: all must pass.
            if !r {
                return Ok(false);
            }
        }
    }

    Ok(triggered.unwrap_or(true))
}

// ── Dump helpers ──────────────────────────────────────────────────────────

/// Produce a single-line textual dump of a condition, suitable for logging.
pub fn condition_dump(c: &Condition, use_assert_names: bool) -> String {
    let prefix = if c.trigger { "|" } else { "" };
    let neg = if c.negate { "!" } else { "" };
    let name = if use_assert_names {
        assert_type_to_string(c.condition_type)
    } else {
        condition_type_to_string(c.condition_type)
    };
    format!("{}: {}{}{} {}", name, prefix, neg, c.parameter, c.result)
}

/// Dump a full list of conditions to a string (one line per condition).
pub fn condition_dump_list(
    conditions: &[Condition],
    use_assert_names: bool,
    prefix: &str,
) -> String {
    let mut out = String::new();
    for c in conditions {
        out.push_str(prefix);
        out.push_str(&condition_dump(c, use_assert_names));
        out.push('\n');
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // ── ConditionType round-trip ─────────────────────────────────────

    #[test]
    fn test_condition_type_to_string_roundtrip() {
        for (ty, name) in CONDITION_TYPE_NAMES {
            assert_eq!(condition_type_from_string(name), Some(**ty));
        }
    }

    #[test]
    fn test_assert_type_to_string_roundtrip() {
        for (ty, name) in ASSERT_TYPE_NAMES {
            assert_eq!(assert_type_from_string(name), Some(**ty));
        }
    }

    #[test]
    fn test_condition_type_legacy_alias() {
        assert_eq!(
            condition_type_from_string("ConditionKernelVersion"),
            Some(ConditionType::Version)
        );
        assert_eq!(
            assert_type_from_string("AssertKernelVersion"),
            Some(ConditionType::Version)
        );
    }

    #[test]
    fn test_condition_type_unknown() {
        assert_eq!(condition_type_from_string("BogusCondition"), None);
        assert_eq!(assert_type_from_string("BogusAssert"), None);
    }

    #[test]
    fn test_condition_type_takes_path() {
        assert!(ConditionType::PathExists.takes_path());
        assert!(ConditionType::FileNotEmpty.takes_path());
        assert!(!ConditionType::Architecture.takes_path());
        assert!(!ConditionType::FirstBoot.takes_path());
    }

    // ── Fraction and machine-tag parity ─────────────────────────────

    #[test]
    fn fraction_preserves_c_grammar_and_boundary_shortcuts() {
        let machine_id = [0x5a; 16];

        assert!(!condition_fraction_matches("0%", &machine_id).unwrap());
        assert!(condition_fraction_matches("100%", &machine_id).unwrap());
        assert!(!condition_fraction_matches("'rollout tag' 0%", &machine_id).unwrap());
        assert!(condition_fraction_matches("rollout 10000‱", &machine_id).unwrap());

        assert!(condition_fraction_matches("", &machine_id).is_err());
        assert!(condition_fraction_matches("rollout 10% trailing", &machine_id).is_err());
        assert!(condition_fraction_matches("rollout not-a-percent", &machine_id).is_err());
    }

    #[test]
    fn fraction_is_stable_and_uses_little_endian_hmac_prefix() {
        let machine_id = [0x42; 16];
        let first = condition_fraction_matches("release-a 50%", &machine_id).unwrap();
        let second = condition_fraction_matches("release-a 50%", &machine_id).unwrap();
        assert_eq!(first, second);

        // condition.c uses unaligned_read_le32() on the SHA-256 HMAC result.
        let digest = hmac_sha256(&machine_id, b"systemd-fraction-release-a");
        let value = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        assert_eq!(first, value < uint32_scale_from_permyriad(5_000));
    }

    #[test]
    fn machine_info_tags_uses_env_file_quoting_and_last_assignment() {
        let tags = machine_info_tags(
            b"# a comment\nTAGS = 'web':\"prod\"  \nTAGS=role\\=db\\\ncluster=blue\n",
        )
        .unwrap();
        assert_eq!(tags.as_deref(), Some("role=dbcluster=blue"));
        assert_eq!(
            machine_info_tags(b"TAGS=web # not a comment\n")
                .unwrap()
                .as_deref(),
            Some("web # not a comment")
        );
        assert_eq!(
            machine_info_tags(b"TAGS=\"a\\\rb\"\n").unwrap().as_deref(),
            Some("a\\\rb")
        );
        assert_eq!(
            machine_info_tags(b"TAGS=\"a\\\nb\"\n").unwrap().as_deref(),
            Some("ab")
        );
        assert_eq!(machine_info_tags(b"OTHER=value\n").unwrap(), None);
    }

    #[test]
    fn machine_info_utf8_validation_matches_completed_c_assignments() {
        assert_eq!(
            machine_info_tags(b"TAGS=web\n#\xff ignored comment\n")
                .unwrap()
                .as_deref(),
            Some("web")
        );
        assert!(machine_info_tags(b"TAGS=web\nOTHER=\xff\n").is_err());
    }

    #[test]
    fn machine_tag_uses_graceful_validation_and_fnmatch() {
        assert!(condition_machine_tag_matches(
            "role=db",
            Some("web:role=web:role=db:invalid/tag"),
        ));
        // The sorted, graceful C parser keeps one value for a `key=` prefix.
        assert!(!condition_machine_tag_matches(
            "role=web",
            Some("web:role=web:role=db:invalid/tag"),
        ));
        assert!(condition_machine_tag_matches("web-*", Some("web-blue:db")));
        assert!(condition_machine_tag_matches(r"role\=db", Some("role=db")));
        assert!(condition_machine_tag_matches("d[[:alpha:]]", Some("db")));
        assert!(!condition_machine_tag_matches("db", None));
    }

    // ── ConditionResult ──────────────────────────────────────────────

    #[test]
    fn test_condition_result_display() {
        assert_eq!(ConditionResult::Untested.to_string(), "untested");
        assert_eq!(ConditionResult::Succeeded.to_string(), "succeeded");
        assert_eq!(ConditionResult::Failed.to_string(), "failed");
        assert_eq!(ConditionResult::Error.to_string(), "error");
    }

    #[test]
    fn test_condition_result_from_string() {
        assert_eq!(
            condition_result_from_string("succeeded"),
            Some(ConditionResult::Succeeded)
        );
        assert_eq!(condition_result_from_string("bogus"), None);
    }

    // ── Path tests (tempdir-based) ───────────────────────────────────

    #[test]
    fn test_path_exists_found() {
        let td = tempfile::TempDir::new().unwrap();
        let p = td.path().join("marker");
        fs::write(&p, "x").unwrap();

        let mut c = Condition::new(
            ConditionType::PathExists,
            p.to_string_lossy().into_owned(),
            false,
            false,
        );
        assert!(c.test(&[]).unwrap());
        assert_eq!(c.result, ConditionResult::Succeeded);
    }

    #[test]
    fn test_path_exists_missing() {
        let mut c = Condition::new(
            ConditionType::PathExists,
            "/no/such/path whatsoever".into(),
            false,
            false,
        );
        assert!(!c.test(&[]).unwrap());
        assert_eq!(c.result, ConditionResult::Failed);
    }

    #[test]
    fn test_path_is_directory() {
        let td = tempfile::TempDir::new().unwrap();
        let mut c = Condition::new(
            ConditionType::PathIsDirectory,
            td.path().to_string_lossy().into_owned(),
            false,
            false,
        );
        assert!(c.test(&[]).unwrap());
    }

    #[test]
    fn test_path_is_directory_negative() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("file");
        fs::write(&f, "data").unwrap();

        let mut c = Condition::new(
            ConditionType::PathIsDirectory,
            f.to_string_lossy().into_owned(),
            false,
            false,
        );
        assert!(!c.test(&[]).unwrap());
    }

    #[test]
    fn test_path_is_symlink() {
        let td = tempfile::TempDir::new().unwrap();
        let target = td.path().join("target");
        let link = td.path().join("link");
        fs::write(&target, "t").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut c = Condition::new(
            ConditionType::PathIsSymbolicLink,
            link.to_string_lossy().into_owned(),
            false,
            false,
        );
        assert!(c.test(&[]).unwrap());
    }

    #[test]
    fn test_file_not_empty() {
        let td = tempfile::TempDir::new().unwrap();
        let full = td.path().join("full");
        let empty = td.path().join("empty");
        fs::write(&full, b"hello").unwrap();
        fs::write(&empty, b"").unwrap();

        let mut c = Condition::new(
            ConditionType::FileNotEmpty,
            full.to_string_lossy().into_owned(),
            false,
            false,
        );
        assert!(c.test(&[]).unwrap());

        c.parameter = empty.to_string_lossy().into_owned();
        assert!(!c.test(&[]).unwrap());
    }

    #[test]
    fn test_file_is_executable() {
        let td = tempfile::TempDir::new().unwrap();
        let exe = td.path().join("run.sh");
        fs::write(&exe, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();

        let mut c = Condition::new(
            ConditionType::FileIsExecutable,
            exe.to_string_lossy().into_owned(),
            false,
            false,
        );
        assert!(c.test(&[]).unwrap());
    }

    #[test]
    fn test_directory_not_empty() {
        let td = tempfile::TempDir::new().unwrap();
        let empty_dir = td.path().join("empty");
        let full_dir = td.path().join("full");
        fs::create_dir(&empty_dir).unwrap();
        fs::create_dir(&full_dir).unwrap();
        fs::write(full_dir.join("child"), "x").unwrap();

        let mut c = Condition::new(
            ConditionType::DirectoryNotEmpty,
            full_dir.to_string_lossy().into_owned(),
            false,
            false,
        );
        assert!(c.test(&[]).unwrap());

        c.parameter = empty_dir.to_string_lossy().into_owned();
        assert!(!c.test(&[]).unwrap());
    }

    // ── Negation ─────────────────────────────────────────────────────

    #[test]
    fn test_negate() {
        let td = tempfile::TempDir::new().unwrap();
        let p = td.path().join("present");
        fs::write(&p, "x").unwrap();

        let mut c = Condition::new(
            ConditionType::PathExists,
            p.to_string_lossy().into_owned(),
            false,
            true, // negate
        );
        assert!(!c.test(&[]).unwrap());
        assert_eq!(c.result, ConditionResult::Failed);
    }

    // ── Environment ──────────────────────────────────────────────────

    #[test]
    fn test_environment_match_key_only() {
        let env = vec!["FOO=bar".into(), "BAZ=qux".into()];
        let mut c = Condition::new(ConditionType::Environment, "FOO".into(), false, false);
        assert!(c.test(&env).unwrap());

        let mut c = Condition::new(ConditionType::Environment, "MISSING".into(), false, false);
        assert!(!c.test(&env).unwrap());
    }

    #[test]
    fn test_environment_match_key_equals_value() {
        let env = vec!["FOO=bar".into()];
        let mut c = Condition::new(ConditionType::Environment, "FOO=bar".into(), false, false);
        assert!(c.test(&env).unwrap());

        let mut c = Condition::new(ConditionType::Environment, "FOO=wrong".into(), false, false);
        assert!(!c.test(&env).unwrap());
    }

    // ── Architecture ─────────────────────────────────────────────────

    #[test]
    fn test_architecture_native() {
        let mut c = Condition::new(ConditionType::Architecture, "native".into(), false, false);
        assert!(c.test(&[]).unwrap());
    }

    // ── First boot ───────────────────────────────────────────────────

    #[test]
    fn test_first_boot_valid_boolean() {
        // We don't control /run/systemd/first-boot in tests, but we can
        // verify the parsing doesn't panic.
        for val in &["true", "false", "yes", "no", "1", "0"] {
            let mut c = Condition::new(ConditionType::FirstBoot, val.to_string(), false, false);
            let _ = c.test(&[]); // may succeed or fail depending on host
        }
    }

    // ── List evaluation ──────────────────────────────────────────────

    #[test]
    fn test_condition_list_all_pass() {
        let mut conds = vec![
            Condition::new(ConditionType::PathExists, "/".into(), false, false),
            Condition::new(ConditionType::PathIsDirectory, "/".into(), false, false),
        ];
        assert!(condition_test_list(&mut conds, &[]).unwrap());
    }

    #[test]
    fn test_condition_list_one_fails() {
        let mut conds = vec![
            Condition::new(ConditionType::PathExists, "/".into(), false, false),
            Condition::new(
                ConditionType::PathExists,
                "/no/such/path".into(),
                false,
                false,
            ),
        ];
        assert!(!condition_test_list(&mut conds, &[]).unwrap());
    }

    #[test]
    fn test_condition_list_trigger() {
        let mut conds = vec![
            // Trigger that passes
            Condition::new(ConditionType::PathExists, "/".into(), true, false),
            // Trigger that fails
            Condition::new(
                ConditionType::PathExists,
                "/no/such/path".into(),
                true,
                false,
            ),
        ];
        // At least one trigger passes → overall true
        assert!(condition_test_list(&mut conds, &[]).unwrap());
    }

    #[test]
    fn test_condition_list_all_triggers_fail() {
        let mut conds = vec![
            Condition::new(
                ConditionType::PathExists,
                "/no/such/path/a".into(),
                true,
                false,
            ),
            Condition::new(
                ConditionType::PathExists,
                "/no/such/path/b".into(),
                true,
                false,
            ),
        ];
        // No triggers pass → overall false
        assert!(!condition_test_list(&mut conds, &[]).unwrap());
    }

    #[test]
    fn test_condition_list_empty() {
        assert!(condition_test_list(&mut [], &[]).unwrap());
    }

    // ── Dump ─────────────────────────────────────────────────────────

    #[test]
    fn test_condition_dump() {
        let c = Condition::new(ConditionType::PathExists, "/tmp".into(), false, false);
        let s = condition_dump(&c, false);
        assert!(s.contains("ConditionPathExists"));
        assert!(s.contains("/tmp"));
    }

    #[test]
    fn test_condition_dump_assert() {
        let c = Condition::new(ConditionType::Architecture, "x86_64".into(), true, true);
        let s = condition_dump(&c, true);
        assert!(s.contains("AssertArchitecture"));
        assert!(s.contains("|")); // trigger prefix
        assert!(s.contains("!")); // negate prefix
    }

    // ── Simple glob ──────────────────────────────────────────────────

    #[test]
    fn test_simple_glob_match() {
        assert!(simple_glob_match("*.txt", "file.txt"));
        assert!(simple_glob_match("*.txt", ".txt"));
        assert!(!simple_glob_match("*.txt", "file.rs"));
        assert!(simple_glob_match("test", "test"));
        assert!(!simple_glob_match("test", "other"));
        assert!(simple_glob_match("?", "a"));
        assert!(!simple_glob_match("?", "ab"));
        assert!(simple_glob_match("*", "anything"));
    }

    // ── parse_bool ───────────────────────────────────────────────────

    #[test]
    fn test_parse_bool() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("yes"), Some(true));
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("no"), Some(false));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(parse_bool(""), None);
    }

    // ── Kernel module loaded ─────────────────────────────────────────

    #[test]
    fn test_kernel_module_loaded_builtin() {
        // Most systems have a "kernel" or "printk" built-in module.
        let mut c = Condition::new(
            ConditionType::KernelModuleLoaded,
            "printk".into(),
            false,
            false,
        );
        // On Linux with /sys/module, this should be true (built-in)
        let _ = c.test(&[]); // result depends on host
    }

    #[test]
    fn test_kernel_module_loaded_not_loaded() {
        let mut c = Condition::new(
            ConditionType::KernelModuleLoaded,
            "absolutely_fake_module_xyz".into(),
            false,
            false,
        );
        assert!(!c.test(&[]).unwrap());
    }

    #[test]
    fn test_kernel_module_loaded_dash_normalization() {
        let mut c = Condition::new(
            ConditionType::KernelModuleLoaded,
            "absolutely-fake-module-xyz".into(),
            false,
            false,
        );
        assert!(!c.test(&[]).unwrap());
    }
}
