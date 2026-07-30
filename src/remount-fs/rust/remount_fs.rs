// SPDX-License-Identifier: LGPL-2.1-or-later
//
// systemd-remount-fs-rs: conservative Rust shadow module for remount-fs.c
//
// Shadow port of src/remount-fs/remount-fs.c.
// Remounts API filesystems from /etc/fstab with correct options.

use std::collections::HashMap;

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub fn is_api_mount(path: &str) -> bool {
    matches!(
        path,
        "/proc" | "/sys" | "/dev" | "/run" | "/tmp" | "/var/tmp" | "/var/lock" | "/var/run"
    )
}

pub fn mount_option_needs_remount(path: &str) -> bool {
    path == "/" || is_api_mount(path) || path == "/usr"
}

pub fn build_remount_args(path: &str, force_rw: bool) -> Vec<String> {
    let options = if force_rw {
        String::from("remount,rw")
    } else {
        String::from("remount")
    };
    vec![
        String::from("mount"),
        path.to_string(),
        String::from("-o"),
        options,
    ]
}

pub fn track_pid(pids: &mut HashMap<u32, String>, path: &str, pid: u32) -> Result<()> {
    if pid == 0 {
        return Err(Errno(-libc::EINVAL));
    }
    pids.insert(pid, path.to_string());
    Ok(())
}

pub fn parse_remount_env(var: &str) -> Result<bool> {
    match var {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(Errno(-libc::EINVAL)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_mount_paths() {
        assert!(is_api_mount("/proc"));
        assert!(is_api_mount("/sys"));
        assert!(is_api_mount("/dev"));
        assert!(is_api_mount("/run"));
        assert!(!is_api_mount("/home"));
    }

    #[test]
    fn needs_remount() {
        assert!(mount_option_needs_remount("/"));
        assert!(mount_option_needs_remount("/proc"));
        assert!(mount_option_needs_remount("/usr"));
        assert!(!mount_option_needs_remount("/home"));
    }

    #[test]
    fn build_remount_args_ro() {
        let args = build_remount_args("/proc", false);
        assert_eq!(args[1], "/proc");
        assert_eq!(args[3], "remount");
    }

    #[test]
    fn build_remount_args_rw() {
        let args = build_remount_args("/", true);
        assert_eq!(args[3], "remount,rw");
    }

    #[test]
    fn track_pid_map() {
        let mut pids = HashMap::new();
        super::track_pid(&mut pids, "/proc", 1234).unwrap();
        assert_eq!(pids.get(&1234).unwrap(), "/proc");
    }

    #[test]
    fn track_pid_zero_rejects() {
        let mut pids = HashMap::new();
        assert!(super::track_pid(&mut pids, "/proc", 0).is_err());
    }

    #[test]
    fn remount_env_parsing() {
        assert!(super::parse_remount_env("1").unwrap());
        assert!(super::parse_remount_env("true").unwrap());
        assert!(!super::parse_remount_env("0").unwrap());
        assert!(super::parse_remount_env("bad").is_err());
    }
}
