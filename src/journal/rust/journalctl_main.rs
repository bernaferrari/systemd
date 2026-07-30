// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

#[cfg(unix)]
use nix::unistd::{getegid, geteuid, getgid, getuid};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

fn append_if_present(out: &mut Vec<PathBuf>, path: Option<PathBuf>) {
    if let Some(path) = path {
        out.push(path);
    }
}

fn env_flag_enabled(name: &str) -> bool {
    env::var_os(name)
        .map(|raw| {
            let value = raw.to_string_lossy();
            let trimmed = value.trim();
            trimmed.eq_ignore_ascii_case("1")
                || trimmed.eq_ignore_ascii_case("true")
                || trimmed.eq_ignore_ascii_case("yes")
                || trimmed.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

#[cfg(unix)]
fn is_privileged_process() -> bool {
    let uid = getuid();
    let euid = geteuid();
    let gid = getgid();
    let egid = getegid();

    euid.is_root() || uid != euid || gid != egid
}

#[cfg(not(unix))]
fn is_privileged_process() -> bool {
    false
}

fn allow_path_search() -> bool {
    env_flag_enabled("SYSTEMD_JOURNALCTL_ALLOW_PATH") || !is_privileged_process()
}

fn backend_candidates(self_exe: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();

    append_if_present(
        &mut out,
        env::var_os("SYSTEMD_JOURNALCTL_BACKEND").map(PathBuf::from),
    );
    append_if_present(
        &mut out,
        self_exe.parent().map(|parent| parent.join("journalctl-c")),
    );
    append_if_present(
        &mut out,
        self_exe
            .parent()
            .and_then(|parent| parent.parent())
            .map(|parent| parent.join("lib").join("systemd").join("journalctl-c")),
    );
    out.push(PathBuf::from("/usr/lib/systemd/journalctl-c"));
    out.push(PathBuf::from("/usr/local/lib/systemd/journalctl-c"));

    if allow_path_search()
        && let Some(path_var) = env::var_os("PATH")
    {
        out.extend(env::split_paths(&path_var).map(|dir| dir.join("journalctl-c")));
    }

    out
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) if meta.is_file() => meta.permissions().mode() & 0o111 != 0,
        _ => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

fn is_same_path(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

fn resolve_backend(self_exe: &Path) -> Option<PathBuf> {
    backend_candidates(self_exe)
        .into_iter()
        .find(|candidate| is_executable_file(candidate) && !is_same_path(candidate, self_exe))
}

fn exec_backend(backend: &Path, args: &[OsString]) -> io::Error {
    let mut cmd = process::Command::new(backend);
    if let Some(argv0) = args.first() {
        cmd.arg0(argv0);
    }
    if args.len() > 1 {
        cmd.args(&args[1..]);
    }

    #[cfg(unix)]
    {
        cmd.exec()
    }

    #[cfg(not(unix))]
    {
        match cmd.status() {
            Ok(status) => {
                process::exit(status.code().unwrap_or(1));
            }
            Err(e) => e,
        }
    }
}

fn main() {
    let args: Vec<OsString> = env::args_os().collect();
    let self_exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("journalctl"));

    let backend = match resolve_backend(&self_exe) {
        Some(path) => path,
        None => {
            eprintln!(
                "journalctl (rust shim): could not find executable backend 'journalctl-c'. \
Set SYSTEMD_JOURNALCTL_BACKEND=/absolute/path/to/journalctl-c. \
PATH lookup is disabled for privileged execution unless SYSTEMD_JOURNALCTL_ALLOW_PATH=1."
            );
            process::exit(127);
        }
    };

    let err = exec_backend(&backend, &args);
    eprintln!(
        "journalctl (rust shim): failed to exec backend {}: {}",
        backend.display(),
        err
    );
    process::exit(127);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use systemd_shared_rs::tests::TestEnvironment;

    #[cfg(unix)]
    fn make_exec(path: &Path) {
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perm = fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        fs::set_permissions(path, perm).unwrap();
    }

    fn unique_tmp(prefix: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!("{prefix}-{ts}-{}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn resolve_prefers_explicit_env_backend() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        let dir = unique_tmp("journalctl-shim-env");
        let self_exe = dir.join("journalctl");
        let backend = dir.join("journalctl-c");
        make_exec(&self_exe);
        make_exec(&backend);
        environment.set("SYSTEMD_JOURNALCTL_BACKEND", &backend);

        let resolved = resolve_backend(&self_exe);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(resolved, Some(backend));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_uses_sibling_backend() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        let dir = unique_tmp("journalctl-shim-sibling");
        let self_exe = dir.join("journalctl");
        let sibling = dir.join("journalctl-c");
        make_exec(&self_exe);
        make_exec(&sibling);
        environment.remove("SYSTEMD_JOURNALCTL_BACKEND");

        let resolved = resolve_backend(&self_exe);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(resolved, Some(sibling));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_self_reference() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        let dir = unique_tmp("journalctl-shim-self");
        let self_exe = dir.join("journalctl");
        make_exec(&self_exe);
        environment.set("SYSTEMD_JOURNALCTL_BACKEND", &self_exe);

        let resolved = resolve_backend(&self_exe);
        fs::remove_dir_all(&dir).unwrap();

        assert!(resolved.is_none());
    }

    #[test]
    fn env_flag_enabled_accepts_common_truthy_values() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.set("SYSTEMD_JOURNALCTL_ALLOW_PATH", "1");
        assert!(env_flag_enabled("SYSTEMD_JOURNALCTL_ALLOW_PATH"));
        environment.set("SYSTEMD_JOURNALCTL_ALLOW_PATH", "true");
        assert!(env_flag_enabled("SYSTEMD_JOURNALCTL_ALLOW_PATH"));
        environment.set("SYSTEMD_JOURNALCTL_ALLOW_PATH", "yes");
        assert!(env_flag_enabled("SYSTEMD_JOURNALCTL_ALLOW_PATH"));
        environment.set("SYSTEMD_JOURNALCTL_ALLOW_PATH", "on");
        assert!(env_flag_enabled("SYSTEMD_JOURNALCTL_ALLOW_PATH"));
        environment.set("SYSTEMD_JOURNALCTL_ALLOW_PATH", "0");
        assert!(!env_flag_enabled("SYSTEMD_JOURNALCTL_ALLOW_PATH"));
    }

    #[cfg(unix)]
    #[test]
    fn backend_candidates_path_visibility_matches_policy() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        let dir = unique_tmp("journalctl-shim-path");
        let self_exe = dir.join("journalctl");
        let path_dir = dir.join("path-bin");
        make_exec(&self_exe);
        fs::create_dir_all(&path_dir).unwrap();

        environment.set("PATH", &path_dir);
        environment.remove("SYSTEMD_JOURNALCTL_ALLOW_PATH");
        let path_backend = path_dir.join("journalctl-c");

        let candidates_default = backend_candidates(&self_exe);
        let has_path_default = candidates_default.iter().any(|p| p == &path_backend);
        assert_eq!(has_path_default, !is_privileged_process());

        environment.set("SYSTEMD_JOURNALCTL_ALLOW_PATH", "1");
        let candidates_forced = backend_candidates(&self_exe);
        let has_path_forced = candidates_forced.iter().any(|p| p == &path_backend);
        assert!(has_path_forced);

        fs::remove_dir_all(&dir).unwrap();
    }
}
