// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit-printf.c

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::Errno;
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::fs;
use std::mem::MaybeUninit;

pub type Result<T> = std::result::Result<T, UnitPrintfError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitPrintfError {
    pub errno: Errno,
    pub message: String,
}

impl UnitPrintfError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            errno: Errno::EINVAL,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecDirectory {
    Cache,
    Configuration,
    Logs,
    State,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerContext {
    pub cgroup_root: String,
    pub prefixes: HashMap<ExecDirectory, String>,
    pub shared_data_dir: String,
    pub user_name: String,
    pub group_name: String,
    pub user_id: u32,
    pub group_id: u32,
    pub user_home: String,
    pub user_shell: String,
    pub machine_id: String,
    pub boot_id: String,
    pub hostname: String,
    pub kernel_release: String,
    pub environment_dir: String,
    pub xdg_config_dirs: String,
}

impl Default for ManagerContext {
    fn default() -> Self {
        let user_id = {
            // SAFETY: libc getters are thread-safe and do not require preconditions.
            unsafe_ffi!(libc::geteuid() as u32)
        };
        let group_id = {
            // SAFETY: libc getters are thread-safe and do not require preconditions.
            unsafe_ffi!(libc::getegid() as u32)
        };

        let user_name = env::var("USER").unwrap_or_else(|_| "root".into());
        let group_name = env::var("GROUP").unwrap_or_else(|_| user_name.clone());
        let user_home = env::var("HOME").unwrap_or_else(|_| "/root".into());
        let user_shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());

        let machine_id = read_trimmed_file("/etc/machine-id")
            .or_else(|| read_trimmed_file("/var/lib/dbus/machine-id"))
            .map(normalize_id128)
            .unwrap_or_else(|| "00000000000000000000000000000000".into());
        let boot_id = read_trimmed_file("/proc/sys/kernel/random/boot_id")
            .map(normalize_id128)
            .unwrap_or_else(|| "00000000000000000000000000000000".into());
        let hostname = read_trimmed_file("/proc/sys/kernel/hostname")
            .or_else(|| env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "localhost".into());
        let kernel_release = kernel_release().unwrap_or_else(|| "unknown".into());

        Self {
            cgroup_root: "/sys/fs/cgroup".into(),
            prefixes: HashMap::from([
                (ExecDirectory::Cache, "/var/cache".into()),
                (ExecDirectory::Configuration, "/etc".into()),
                (ExecDirectory::Logs, "/var/log".into()),
                (ExecDirectory::State, "/var/lib".into()),
                (ExecDirectory::Runtime, "/run".into()),
            ]),
            shared_data_dir: "/usr/share".into(),
            user_name,
            group_name,
            user_id,
            group_id,
            user_home,
            user_shell,
            machine_id,
            boot_id,
            hostname,
            kernel_release,
            environment_dir: "/etc/environment.d".into(),
            xdg_config_dirs: env::var("XDG_CONFIG_DIRS").unwrap_or_else(|_| "/etc/xdg".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub id: String,
    pub instance: Option<String>,
    pub fragment_path: Option<String>,
    pub manager: ManagerContext,
    pub cgroup_path: Option<String>,
    pub slice_cgroup_path: Option<String>,
    pub warnings: Vec<char>,
}

impl Unit {
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        let instance = id
            .split_once('@')
            .and_then(|(_, right)| right.strip_suffix(unit_suffix(&id)).map(ToOwned::to_owned));
        Self {
            id,
            instance,
            fragment_path: None,
            manager: ManagerContext::default(),
            cgroup_path: None,
            slice_cgroup_path: None,
            warnings: Vec::new(),
        }
    }
}

fn read_trimmed_file(path: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_id128(value: String) -> String {
    value.replace('-', "")
}

fn kernel_release() -> Option<String> {
    let mut uts = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: `uts` points to writable memory for `uname`.
    let rc = unsafe_ffi!(libc::uname(uts.as_mut_ptr()));
    if rc < 0 {
        return None;
    }
    // SAFETY: `uname` initialized `uts` on success.
    let uts = unsafe_ffi!(uts.assume_init());
    // SAFETY: `release` from `utsname` is NUL-terminated on POSIX systems.
    let release = unsafe_ffi!(CStr::from_ptr(uts.release.as_ptr()))
        .to_string_lossy()
        .into_owned();
    Some(release)
}

fn unit_suffix(id: &str) -> &str {
    id.rsplit_once('.').map_or("", |(left, right)| {
        &id[left.len()..=left.len() + right.len()]
    })
}

fn prefix_and_suffix(id: &str) -> (&str, &str) {
    id.rsplit_once('.').unwrap_or((id, ""))
}

fn unit_name_to_prefix_and_instance(id: &str) -> String {
    let (body, _) = prefix_and_suffix(id);
    body.to_string()
}

fn unit_name_to_prefix(id: &str) -> String {
    let (body, _) = prefix_and_suffix(id);
    body.split_once('@')
        .map(|(prefix, _)| prefix.to_string())
        .unwrap_or_else(|| body.to_string())
}

fn unit_name_unescape(value: &str) -> String {
    value.replace('-', "/")
}

fn unit_name_path_unescape(value: &str) -> String {
    format!("/{}", unit_name_unescape(value).trim_start_matches('/'))
}

fn specifier_last_component(unit: &Unit) -> Result<String> {
    let prefix = unit_name_to_prefix(&unit.id);
    Ok(prefix.rsplit('-').next().unwrap_or(&prefix).to_string())
}

fn specifier_filename(unit: &Unit) -> String {
    unit.instance
        .as_deref()
        .map(unit_name_path_unescape)
        .unwrap_or_else(|| unit_name_path_unescape(&unit.id))
}

fn bad_specifier(unit: &mut Unit, specifier: char) {
    unit.warnings.push(specifier);
}

fn resolve_specifier(unit: &mut Unit, specifier: char) -> Result<String> {
    match specifier {
        '%' => Ok("%".into()),
        'i' => Ok(unit.instance.clone().unwrap_or_default()),
        'I' => Ok(unit_name_unescape(unit.instance.as_deref().unwrap_or(""))),
        'j' => specifier_last_component(unit),
        'J' => Ok(unit_name_unescape(&specifier_last_component(unit)?)),
        'n' => Ok(unit.id.clone()),
        'N' => Ok(unit_name_unescape(&unit_name_to_prefix_and_instance(
            &unit.id,
        ))),
        'p' => Ok(unit_name_to_prefix(&unit.id)),
        'P' => Ok(unit_name_unescape(&unit_name_to_prefix(&unit.id))),
        'f' => Ok(specifier_filename(unit)),
        'y' => Ok(unit.fragment_path.clone().unwrap_or_default()),
        'Y' => Ok(unit
            .fragment_path
            .as_deref()
            .and_then(|path| path.rsplit_once('/').map(|(dir, _)| dir.to_string()))
            .unwrap_or_default()),
        'c' => {
            bad_specifier(unit, specifier);
            Ok(unit
                .cgroup_path
                .clone()
                .unwrap_or_else(|| unit.manager.cgroup_root.clone()))
        }
        'r' => {
            bad_specifier(unit, specifier);
            Ok(unit
                .slice_cgroup_path
                .clone()
                .unwrap_or_else(|| unit.manager.cgroup_root.clone()))
        }
        'R' => {
            bad_specifier(unit, specifier);
            Ok(unit.manager.cgroup_root.clone())
        }
        'C' => Ok(unit
            .manager
            .prefixes
            .get(&ExecDirectory::Cache)
            .cloned()
            .unwrap_or_default()),
        'd' => Ok(format!(
            "{}/credentials/{}",
            unit.manager
                .prefixes
                .get(&ExecDirectory::Runtime)
                .cloned()
                .unwrap_or_default(),
            unit.id
        )),
        'D' => Ok(unit.manager.shared_data_dir.clone()),
        'E' => Ok(unit.manager.xdg_config_dirs.clone()),
        'e' => Ok(unit.manager.environment_dir.clone()),
        'L' => Ok(unit
            .manager
            .prefixes
            .get(&ExecDirectory::Logs)
            .cloned()
            .unwrap_or_default()),
        'S' => Ok(unit
            .manager
            .prefixes
            .get(&ExecDirectory::State)
            .cloned()
            .unwrap_or_default()),
        't' => Ok(unit
            .manager
            .prefixes
            .get(&ExecDirectory::Runtime)
            .cloned()
            .unwrap_or_default()),
        'T' => Ok("/tmp".into()),
        'V' => Ok("/var/tmp".into()),
        'u' => Ok(unit.manager.user_name.clone()),
        'g' => Ok(unit.manager.group_name.clone()),
        'U' => Ok(unit.manager.user_id.to_string()),
        'G' => Ok(unit.manager.group_id.to_string()),
        'h' => Ok(unit.manager.user_home.clone()),
        's' => Ok(unit.manager.user_shell.clone()),
        'm' => Ok(unit.manager.machine_id.clone()),
        'b' => Ok(unit.manager.boot_id.clone()),
        'H' => Ok(unit.manager.hostname.clone()),
        'v' => Ok(unit.manager.kernel_release.clone()),
        other => Err(UnitPrintfError::invalid(format!(
            "Unknown specifier %{other}"
        ))),
    }
}

fn specifier_printf(unit: &mut Unit, format: &str, max_length: usize) -> Result<String> {
    let mut chars = format.chars();
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
        } else {
            let Some(specifier) = chars.next() else {
                return Err(UnitPrintfError::invalid(
                    "Dangling % at end of format string",
                ));
            };
            out.push_str(&resolve_specifier(unit, specifier)?);
        }
        if out.len() > max_length {
            return Err(UnitPrintfError::invalid(
                "Expanded string exceeds maximum length",
            ));
        }
    }
    Ok(out)
}

pub fn unit_name_printf(unit: &mut Unit, format: &str) -> Result<String> {
    specifier_printf(unit, format, 255)
}

pub fn unit_full_printf_full(unit: &mut Unit, format: &str, max_length: usize) -> Result<String> {
    specifier_printf(unit, format, max_length)
}

pub fn unit_full_printf(unit: &mut Unit, text: &str) -> Result<String> {
    unit_full_printf_full(unit, text, 8192)
}

pub fn unit_path_printf(unit: &mut Unit, text: &str) -> Result<String> {
    unit_full_printf_full(unit, text, 4095)
}

pub fn unit_fd_printf(unit: &mut Unit, text: &str) -> Result<String> {
    unit_full_printf_full(unit, text, 255)
}

pub fn unit_cred_printf(unit: &mut Unit, text: &str) -> Result<String> {
    unit_full_printf_full(unit, text, 255)
}

pub fn unit_env_printf(unit: &mut Unit, text: &str) -> Result<String> {
    unit_full_printf_full(unit, text, 131072)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unit() -> Unit {
        let mut unit = Unit::new("foo-bar@baz.service");
        unit.fragment_path = Some("/etc/systemd/system/foo-bar@baz.service".into());
        unit.cgroup_path = Some("/sys/fs/cgroup/foo-bar@baz.service".into());
        unit.slice_cgroup_path = Some("/sys/fs/cgroup/system.slice".into());
        unit.manager.user_name = "alice".into();
        unit.manager.group_name = "staff".into();
        unit.manager.user_id = 1000;
        unit.manager.group_id = 100;
        unit.manager.user_home = "/home/alice".into();
        unit.manager.user_shell = "/bin/zsh".into();
        unit.manager.machine_id = "0123456789abcdef0123456789abcdef".into();
        unit.manager.boot_id = "fedcba9876543210fedcba9876543210".into();
        unit.manager.hostname = "demo-host".into();
        unit.manager.kernel_release = "6.12.0-test".into();
        unit.manager.environment_dir = "/etc/environment.d".into();
        unit.manager.xdg_config_dirs = "/etc/xdg:/usr/local/etc/xdg".into();
        unit
    }

    #[test]
    fn unit_name_printf_expands_safe_specifiers() {
        let mut unit = sample_unit();
        assert_eq!(
            unit_name_printf(&mut unit, "%n %p %i").unwrap(),
            "foo-bar@baz.service foo-bar baz"
        );
    }

    #[test]
    fn uppercase_n_expands_unescaped_name_without_suffix() {
        let mut unit = sample_unit();
        assert_eq!(unit_full_printf(&mut unit, "%N").unwrap(), "foo/bar@baz");
    }

    #[test]
    fn full_printf_expands_unescaped_variants() {
        let mut unit = sample_unit();
        assert_eq!(
            unit_full_printf(&mut unit, "%P %I %J").unwrap(),
            "foo/bar baz bar"
        );
    }

    #[test]
    fn filename_prefers_instance_path() {
        let mut unit = sample_unit();
        assert_eq!(unit_full_printf(&mut unit, "%f").unwrap(), "/baz");
    }

    #[test]
    fn fragment_specifiers_work() {
        let mut unit = sample_unit();
        assert!(
            unit_full_printf(&mut unit, "%y %Y")
                .unwrap()
                .contains("/etc/systemd/system")
        );
    }

    #[test]
    fn deprecated_specifiers_record_warning() {
        let mut unit = sample_unit();
        let rendered = unit_full_printf(&mut unit, "%c %r %R").unwrap();
        assert!(rendered.contains("/sys/fs/cgroup"));
        assert_eq!(unit.warnings, vec!['c', 'r', 'R']);
    }

    #[test]
    fn directory_specifiers_use_manager_prefixes() {
        let mut unit = sample_unit();
        let rendered = unit_full_printf(&mut unit, "%C %E %e %L %S %t %D").unwrap();
        assert!(rendered.contains("/var/cache"));
        assert!(rendered.contains("/etc/environment.d"));
        assert!(rendered.contains("/etc/xdg:/usr/local/etc/xdg"));
        assert!(rendered.contains("/usr/share"));
    }

    #[test]
    fn user_specifiers_use_manager_values() {
        let mut unit = sample_unit();
        assert_eq!(
            unit_full_printf(&mut unit, "%h %s").unwrap(),
            "/home/alice /bin/zsh"
        );
    }

    #[test]
    fn creds_and_system_specifiers_are_expanded() {
        let mut unit = sample_unit();
        assert_eq!(
            unit_full_printf(&mut unit, "%u %g %U %G %m %b %H %v").unwrap(),
            "alice staff 1000 100 0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210 demo-host 6.12.0-test"
        );
    }

    #[test]
    fn tmp_specifiers_are_expanded() {
        let mut unit = sample_unit();
        assert_eq!(
            unit_full_printf(&mut unit, "%T %V").unwrap(),
            "/tmp /var/tmp"
        );
    }

    #[test]
    fn credentials_dir_uses_runtime_prefix_and_id() {
        let mut unit = sample_unit();
        assert_eq!(
            unit_full_printf(&mut unit, "%d").unwrap(),
            "/run/credentials/foo-bar@baz.service"
        );
    }

    #[test]
    fn rejects_unknown_specifier() {
        let mut unit = sample_unit();
        assert!(unit_full_printf(&mut unit, "%z").is_err());
    }

    #[test]
    fn enforces_length_limit() {
        let mut unit = sample_unit();
        assert!(unit_full_printf_full(&mut unit, "%n", 3).is_err());
    }
}
