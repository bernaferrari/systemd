// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/exec-util.c
//! Execution utilities
//!
//! Functions for executing commands and scripts with various options.

use crate::ffi::*;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Exit code indicating remaining executables should be skipped.
pub const EXIT_SKIP_REMAINING: i32 = 77;

/// Flags for directory execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecDirFlags {
    pub parallel: bool,
    pub ignore_errors: bool,
    pub set_systemd_exec_pid: bool,
    pub skip_remaining: bool,
    pub warn_world_writable: bool,
}

impl Default for ExecDirFlags {
    fn default() -> Self {
        Self {
            parallel: false,
            ignore_errors: false,
            set_systemd_exec_pid: false,
            skip_remaining: false,
            warn_world_writable: false,
        }
    }
}

impl ExecDirFlags {
    pub fn parallel() -> Self {
        Self {
            parallel: true,
            ignore_errors: false,
            set_systemd_exec_pid: false,
            skip_remaining: false,
            warn_world_writable: false,
        }
    }
}

/// Result of command execution
#[derive(Debug)]
pub enum ExecResult {
    Success,
    Failed(i32),
    Signal(i32),
}

/// Execute a command with arguments
pub fn execute_command(
    program: &Path,
    args: &[&str],
    env: Option<&HashMap<String, String>>,
    timeout: Option<Duration>,
) -> std::io::Result<ExecResult> {
    let mut cmd = Command::new(program);
    cmd.args(args);

    if let Some(environment) = env {
        for (key, value) in environment {
            cmd.env(key, value);
        }
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    // Handle timeout if specified
    let result = if let Some(dur) = timeout {
        let deadline = Instant::now() + dur;
        loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }

            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(ExecResult::Failed(124)); // Standard timeout exit code
            }

            sleep(Duration::from_millis(10));
        }
    } else {
        child.wait()?
    };

    if result.success() {
        Ok(ExecResult::Success)
    } else if let Some(code) = result.code() {
        Ok(ExecResult::Failed(code))
    } else {
        // Process was terminated by signal
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = result.signal() {
                return Ok(ExecResult::Signal(sig));
            }
        }
        Ok(ExecResult::Failed(1))
    }
}

/// Execute all executables in a directory
pub fn execute_directories(
    name: &str,
    directories: &[&Path],
    timeout: Option<Duration>,
    flags: ExecDirFlags,
) -> std::io::Result<ExecResult> {
    let _ = name; // Used for logging in the C version
    let mut paths: Vec<PathBuf> = Vec::new();

    // Collect all executables from directories
    for dir in directories {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if is_executable(&path) {
                    paths.push(path);
                }
            }
        }
    }

    if paths.is_empty() {
        return Ok(ExecResult::Success);
    }

    // Sort for deterministic order
    paths.sort();

    if flags.parallel {
        execute_parallel(&paths, timeout, flags)
    } else {
        execute_serial(&paths, timeout, flags)
    }
}

/// Execute commands serially
fn execute_serial(
    paths: &[PathBuf],
    timeout: Option<Duration>,
    flags: ExecDirFlags,
) -> std::io::Result<ExecResult> {
    for path in paths {
        // Check if world-writable
        if flags.warn_world_writable && is_world_writable(path) {
            eprintln!("Warning: {} is world-writable", path.display());
        }

        let result = execute_command(path, &[], None, timeout)?;

        match result {
            ExecResult::Success => {}
            ExecResult::Failed(code) => {
                if code == EXIT_SKIP_REMAINING && flags.skip_remaining {
                    // Exit code 77 means skip remaining
                    break;
                }
                if !flags.ignore_errors {
                    return Ok(ExecResult::Failed(code));
                }
            }
            ExecResult::Signal(sig) => {
                if !flags.ignore_errors {
                    return Ok(ExecResult::Signal(sig));
                }
            }
        }
    }

    Ok(ExecResult::Success)
}

/// Execute commands in parallel
fn execute_parallel(
    paths: &[PathBuf],
    timeout: Option<Duration>,
    flags: ExecDirFlags,
) -> std::io::Result<ExecResult> {
    use std::sync::Arc;
    use std::thread;

    let paths = Arc::new(paths.to_vec());
    let mut handles = Vec::new();

    for i in 0..paths.len() {
        let paths = Arc::clone(&paths);
        let handle = thread::spawn(move || {
            let path = &paths[i];
            execute_command(path, &[], None, timeout)
        });
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.join().unwrap()?;
        match result {
            ExecResult::Success => {}
            ExecResult::Failed(code) => {
                if !flags.ignore_errors {
                    return Ok(ExecResult::Failed(code));
                }
            }
            ExecResult::Signal(sig) => {
                if !flags.ignore_errors {
                    return Ok(ExecResult::Signal(sig));
                }
            }
        }
    }

    Ok(ExecResult::Success)
}

/// Check if a file is executable
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(metadata) = std::fs::metadata(path) {
        let mode = metadata.permissions().mode();
        // Check if any execute bit is set
        return mode & 0o111 != 0;
    }
    false
}

/// Check if a file is world-writable
pub fn is_world_writable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(metadata) = std::fs::metadata(path) {
        let mode = metadata.permissions().mode();
        return mode & 0o002 != 0;
    }
    false
}

/// Check if path is null or empty
pub fn null_or_empty_path(path: Option<&str>) -> bool {
    path.is_none_or(|p| p.is_empty())
}

/// Check if path contains a slash
pub fn path_contains_slash(p: &str) -> bool {
    p.contains('/')
}

/// Find an executable in $PATH
pub fn find_executable_in_path(name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    if name.starts_with('/') {
        let p = PathBuf::from(name);
        return is_executable(&p).then_some(p);
    }

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Check if a path refers to an executable file using the access() syscall
pub fn executable_is_executable(path: &Path) -> bool {
    let c_path = match {
        use std::os::unix::ffi::OsStrExt;
        CString::new(path.as_os_str().as_bytes())
    } {
        Ok(p) => p,
        Err(_) => return false,
    };
    // SAFETY: c_path is a valid null-terminated C string. access() only
    // reads the filesystem and does not modify any state.
    unsafe { libc::access(c_path.as_ptr(), libc::X_OK) == 0 }
}

/// Flags for command execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecCommandFlags {
    pub ignore_failure: bool,
    pub fully_privileged: bool,
    pub no_setuid: bool,
    pub no_env_expand: bool,
    pub via_shell: bool,
}

impl Default for ExecCommandFlags {
    fn default() -> Self {
        Self {
            ignore_failure: false,
            fully_privileged: false,
            no_setuid: false,
            no_env_expand: false,
            via_shell: false,
        }
    }
}

/// Parse a single command flag from a string
pub fn exec_command_flags_from_string(s: &str) -> Option<ExecCommandFlags> {
    if s == "ambient" {
        return Some(ExecCommandFlags::default());
    }
    match s {
        "ignore-failure" => Some(ExecCommandFlags {
            ignore_failure: true,
            ..Default::default()
        }),
        "privileged" => Some(ExecCommandFlags {
            fully_privileged: true,
            ..Default::default()
        }),
        "no-setuid" => Some(ExecCommandFlags {
            no_setuid: true,
            ..Default::default()
        }),
        "no-env-expand" => Some(ExecCommandFlags {
            no_env_expand: true,
            ..Default::default()
        }),
        "via-shell" => Some(ExecCommandFlags {
            via_shell: true,
            ..Default::default()
        }),
        _ => None,
    }
}

/// Convert a single command flag to its string representation
pub fn exec_command_flags_to_string(flags: ExecCommandFlags) -> Option<&'static str> {
    match flags {
        ExecCommandFlags {
            ignore_failure: true,
            fully_privileged: false,
            no_setuid: false,
            no_env_expand: false,
            via_shell: false,
        } => Some("ignore-failure"),
        ExecCommandFlags {
            ignore_failure: false,
            fully_privileged: true,
            no_setuid: false,
            no_env_expand: false,
            via_shell: false,
        } => Some("privileged"),
        ExecCommandFlags {
            ignore_failure: false,
            fully_privileged: false,
            no_setuid: true,
            no_env_expand: false,
            via_shell: false,
        } => Some("no-setuid"),
        ExecCommandFlags {
            ignore_failure: false,
            fully_privileged: false,
            no_setuid: false,
            no_env_expand: true,
            via_shell: false,
        } => Some("no-env-expand"),
        ExecCommandFlags {
            ignore_failure: false,
            fully_privileged: false,
            no_setuid: false,
            no_env_expand: false,
            via_shell: true,
        } => Some("via-shell"),
        _ => None,
    }
}

/// Parse command flags from a slice of strings
pub fn exec_command_flags_from_strv(opts: &[&str]) -> Result<ExecCommandFlags, String> {
    let mut flags = ExecCommandFlags::default();
    for opt in opts {
        match exec_command_flags_from_string(opt) {
            Some(f) => flags = merge_flags(flags, f),
            None => return Err(format!("Unknown exec command flag: {}", opt)),
        }
    }
    Ok(flags)
}

/// Merge two ExecCommandFlags together (bitwise OR semantics)
fn merge_flags(a: ExecCommandFlags, b: ExecCommandFlags) -> ExecCommandFlags {
    ExecCommandFlags {
        ignore_failure: a.ignore_failure || b.ignore_failure,
        fully_privileged: a.fully_privileged || b.fully_privileged,
        no_setuid: a.no_setuid || b.no_setuid,
        no_env_expand: a.no_env_expand || b.no_env_expand,
        via_shell: a.via_shell || b.via_shell,
    }
}

/// Convert command flags to a vector of strings
pub fn exec_command_flags_to_strv(flags: ExecCommandFlags) -> Vec<&'static str> {
    let mut result = Vec::new();
    if flags.ignore_failure {
        result.push("ignore-failure");
    }
    if flags.fully_privileged {
        result.push("privileged");
    }
    if flags.no_setuid {
        result.push("no-setuid");
    }
    if flags.no_env_expand {
        result.push("no-env-expand");
    }
    if flags.via_shell {
        result.push("via-shell");
    }
    result
}

/// Check if we should fork an agent (has a controlling terminal)
pub fn shall_fork_agent() -> Result<bool, std::io::Error> {
    // SAFETY: ioctl(TIOCGPGRP) on fd 0 checks for a controlling terminal.
    // It only reads kernel state; no mutation occurs.
    let ret = unsafe { libc::ioctl(0, libc::TIOCGPGRP, std::ptr::null_mut::<libc::pid_t>()) };

    if ret == 0 {
        Ok(true)
    } else {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENXIO) {
            Ok(false)
        } else {
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_dir_flags_default() {
        let flags = ExecDirFlags::default();
        assert!(!flags.parallel);
        assert!(!flags.ignore_errors);
        assert!(!flags.set_systemd_exec_pid);
        assert!(!flags.skip_remaining);
        assert!(!flags.warn_world_writable);
    }

    #[test]
    fn test_exec_dir_flags_parallel() {
        let flags = ExecDirFlags::parallel();
        assert!(flags.parallel);
        assert!(!flags.ignore_errors);
    }

    #[test]
    fn test_exec_dir_flags_equality() {
        let a = ExecDirFlags::default();
        let b = ExecDirFlags::default();
        assert_eq!(a, b);
        assert_ne!(a, ExecDirFlags::parallel());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_exec_result_success() {
        let result = execute_command(Path::new("/bin/true"), &[], None, None);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ExecResult::Success));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_exec_result_failed() {
        let result = execute_command(Path::new("/bin/false"), &[], None, None);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ExecResult::Failed(1)));
    }

    #[test]
    fn test_exec_command_flags_default() {
        let flags = ExecCommandFlags::default();
        assert!(!flags.ignore_failure);
        assert!(!flags.fully_privileged);
        assert!(!flags.no_setuid);
        assert!(!flags.no_env_expand);
        assert!(!flags.via_shell);
    }

    #[test]
    fn test_exec_command_flags_from_string_valid() {
        assert!(
            exec_command_flags_from_string("ignore-failure")
                .unwrap()
                .ignore_failure
        );
        assert!(
            exec_command_flags_from_string("privileged")
                .unwrap()
                .fully_privileged
        );
        assert!(
            exec_command_flags_from_string("no-setuid")
                .unwrap()
                .no_setuid
        );
        assert!(
            exec_command_flags_from_string("no-env-expand")
                .unwrap()
                .no_env_expand
        );
        assert!(
            exec_command_flags_from_string("via-shell")
                .unwrap()
                .via_shell
        );
    }

    #[test]
    fn test_exec_command_flags_from_string_invalid() {
        assert_eq!(exec_command_flags_from_string("bogus"), None);
        assert_eq!(exec_command_flags_from_string(""), None);
    }

    #[test]
    fn test_exec_command_flags_from_string_ambient() {
        let ambient = exec_command_flags_from_string("ambient").unwrap();
        assert!(!ambient.ignore_failure);
        assert!(!ambient.fully_privileged);
    }

    #[test]
    fn test_exec_command_flags_to_string() {
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags {
                ignore_failure: true,
                ..Default::default()
            }),
            Some("ignore-failure")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags {
                via_shell: true,
                ..Default::default()
            }),
            Some("via-shell")
        );
        // Combined flags return None
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags {
                ignore_failure: true,
                via_shell: true,
                ..Default::default()
            }),
            None
        );
    }

    #[test]
    fn test_exec_command_flags_from_strv_valid() {
        let flags = exec_command_flags_from_strv(&["ignore-failure", "via-shell"]).unwrap();
        assert!(flags.ignore_failure);
        assert!(flags.via_shell);
        assert!(!flags.fully_privileged);
    }

    #[test]
    fn test_exec_command_flags_from_strv_empty() {
        let flags = exec_command_flags_from_strv(&[]).unwrap();
        assert!(!flags.ignore_failure);
        assert!(!flags.via_shell);
    }

    #[test]
    fn test_exec_command_flags_from_strv_invalid() {
        let result = exec_command_flags_from_strv(&["ignore-failure", "bogus"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bogus"));
    }

    #[test]
    fn test_exec_command_flags_to_strv_empty() {
        let v = exec_command_flags_to_strv(ExecCommandFlags::default());
        assert!(v.is_empty());
    }

    #[test]
    fn test_exec_command_flags_to_strv_multiple() {
        let flags = ExecCommandFlags {
            ignore_failure: true,
            no_setuid: true,
            via_shell: true,
            ..Default::default()
        };
        let v = exec_command_flags_to_strv(flags);
        assert!(v.contains(&"ignore-failure"));
        assert!(v.contains(&"no-setuid"));
        assert!(v.contains(&"via-shell"));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn test_is_executable_known() {
        assert!(is_executable(Path::new("/bin/sh")));
        assert!(is_executable(Path::new("/bin/ls")));
    }

    #[test]
    fn test_is_executable_nonexistent() {
        assert!(!is_executable(Path::new("/nonexistent_binary_12345")));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_is_executable_directory() {
        assert!(!is_executable(Path::new("/tmp")));
    }

    #[test]
    fn test_executable_is_executable_known() {
        assert!(executable_is_executable(Path::new("/bin/sh")));
        assert!(executable_is_executable(Path::new("/bin/ls")));
    }

    #[test]
    fn test_executable_is_executable_nonexistent() {
        assert!(!executable_is_executable(Path::new(
            "/nonexistent_binary_12345"
        )));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_executable_is_executable_directory() {
        assert!(!executable_is_executable(Path::new("/tmp")));
    }

    #[test]
    fn test_find_executable_in_path_sh() {
        let result = find_executable_in_path("sh");
        assert!(result.is_some());
        let p = result.unwrap();
        assert!(p.to_string_lossy().contains("sh"));
    }

    #[test]
    fn test_find_executable_in_path_nonexistent() {
        assert!(find_executable_in_path("nonexistent_binary_xyz_12345").is_none());
    }

    #[test]
    fn test_find_executable_in_path_empty() {
        assert!(find_executable_in_path("").is_none());
    }

    #[test]
    fn test_find_executable_in_path_absolute() {
        let result = find_executable_in_path("/bin/sh");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), PathBuf::from("/bin/sh"));
    }

    #[test]
    fn test_find_executable_in_path_absolute_nonexistent() {
        assert!(find_executable_in_path("/nonexistent_abc").is_none());
    }

    #[test]
    fn test_path_contains_slash() {
        assert!(path_contains_slash("/usr/bin/foo"));
        assert!(path_contains_slash("foo/bar"));
        assert!(!path_contains_slash("sh"));
        assert!(!path_contains_slash(""));
    }

    #[test]
    fn test_null_or_empty_path() {
        assert!(null_or_empty_path(None));
        assert!(null_or_empty_path(Some("")));
        assert!(!null_or_empty_path(Some("/usr/bin/true")));
    }

    #[test]
    fn test_execute_directories_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let result = execute_directories("test", &[tmp.path()], None, ExecDirFlags::default());
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ExecResult::Success));
    }

    #[test]
    fn test_execute_directories_nonexistent_dir() {
        let result = execute_directories(
            "test",
            &[Path::new("/nonexistent_dir_xyz")],
            None,
            ExecDirFlags::default(),
        );
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ExecResult::Success));
    }

    #[test]
    fn test_execute_directories_ignore_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("fail.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 1").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, PermissionsExt::from_mode(0o755)).unwrap();

        let result = execute_directories(
            "test",
            &[tmp.path()],
            None,
            ExecDirFlags {
                ignore_errors: true,
                ..Default::default()
            },
        );
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ExecResult::Success));
    }

    #[test]
    fn test_exit_skip_remaining_value() {
        assert_eq!(EXIT_SKIP_REMAINING, 77);
    }

    #[test]
    fn test_shall_fork_agent_returns() {
        // May return Ok(true/false) or Err depending on terminal state
        let _ = shall_fork_agent();
    }

    #[test]
    fn test_exec_command_flags_equality() {
        let a = ExecCommandFlags {
            ignore_failure: true,
            ..Default::default()
        };
        let b = ExecCommandFlags {
            ignore_failure: true,
            ..Default::default()
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_exec_command_flags_clone() {
        let flags = ExecCommandFlags {
            ignore_failure: true,
            via_shell: true,
            ..Default::default()
        };
        let cloned = flags.clone();
        assert_eq!(flags, cloned);
    }

    #[test]
    fn test_exec_dir_flags_clone() {
        let flags = ExecDirFlags::parallel();
        let cloned = flags.clone();
        assert_eq!(flags, cloned);
    }
}
