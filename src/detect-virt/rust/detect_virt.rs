// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/detect-virt/detect-virt.c

pub const EINVAL: i32 = -22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Any,
    Vm,
    Container,
    Chroot,
    PrivateUsers,
    Cvm,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Virtualization {
    None,
    Kvm,
    Qemu,
    Vmware,
    Docker,
    Podman,
    SystemdNspawn,
    Chroot,
    PrivateUsers,
    Sev,
}

pub fn parse_args(args: &[&str]) -> Result<(bool, Mode), i32> {
    let mut quiet = false;
    let mut mode = Mode::Any;
    for a in args {
        match *a {
            "-q" | "--quiet" => quiet = true,
            "-v" | "--vm" => mode = Mode::Vm,
            "-c" | "--container" => mode = Mode::Container,
            "-r" | "--chroot" => mode = Mode::Chroot,
            "--private-users" => mode = Mode::PrivateUsers,
            "--cvm" => mode = Mode::Cvm,
            _ => return Err(EINVAL),
        }
    }
    Ok((quiet, mode))
}
pub fn name(v: Virtualization) -> &'static str {
    match v {
        Virtualization::None => "none",
        Virtualization::Kvm => "kvm",
        Virtualization::Qemu => "qemu",
        Virtualization::Vmware => "vmware",
        Virtualization::Docker => "docker",
        Virtualization::Podman => "podman",
        Virtualization::SystemdNspawn => "systemd-nspawn",
        Virtualization::Chroot => "chroot",
        Virtualization::PrivateUsers => "private-users",
        Virtualization::Sev => "sev",
    }
}
pub fn exit_code(v: Virtualization) -> i32 {
    if matches!(v, Virtualization::None) {
        1
    } else {
        0
    }
}
pub fn is_vm(v: Virtualization) -> bool {
    matches!(
        v,
        Virtualization::Kvm | Virtualization::Qemu | Virtualization::Vmware | Virtualization::Sev
    )
}
pub fn is_container(v: Virtualization) -> bool {
    matches!(
        v,
        Virtualization::Docker | Virtualization::Podman | Virtualization::SystemdNspawn
    )
}

#[cfg(target_os = "linux")]
fn read_file_first_line(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.to_string()))
}

#[cfg(target_os = "linux")]
fn detect_vm_cpuid() -> Option<Virtualization> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        if line.starts_with("flags") && line.contains("hypervisor") {
            return Some(Virtualization::Kvm);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_vm_dmi() -> Option<Virtualization> {
    for sysfs_path in &[
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
    ] {
        let val = read_file_first_line(sysfs_path)?;
        let v = match val.to_lowercase() {
            s if s.contains("vmware") => Virtualization::Vmware,
            s if s.contains("qemu") => Virtualization::Qemu,
            s if s.contains("kvm") => Virtualization::Kvm,
            _ => continue,
        };
        return Some(v);
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_container() -> Option<Virtualization> {
    if std::path::Path::new("/.dockerenv").exists() {
        return Some(Virtualization::Docker);
    }
    if std::path::Path::new("/run/.containerenv").exists() {
        return Some(Virtualization::Podman);
    }
    if let Ok(mountinfo) = std::fs::read_to_string("/proc/1/mountinfo") {
        for line in mountinfo.lines() {
            if line.contains("/docker/") || line.contains("/lxc/") {
                return Some(Virtualization::Docker);
            }
            if line.contains("/systemd/private") {
                return Some(Virtualization::SystemdNspawn);
            }
        }
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        for line in cgroup.lines() {
            if line.contains("/docker/") {
                return Some(Virtualization::Docker);
            }
            if line.contains("/libpod-") || line.contains("/podman/") {
                return Some(Virtualization::Podman);
            }
            if line.contains("/machine.slice/") || line.contains(".scope:") {
                return Some(Virtualization::SystemdNspawn);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_chroot() -> Option<Virtualization> {
    let my_root = std::fs::read_link("/proc/self/root").ok()?;
    let pid1_root = std::fs::read_link("/proc/1/root").ok()?;
    if my_root != pid1_root {
        return Some(Virtualization::Chroot);
    }
    None
}

#[cfg(target_os = "linux")]
pub fn detect() -> Virtualization {
    if let Some(v) = detect_vm_cpuid() {
        return v;
    }
    if let Some(v) = detect_vm_dmi() {
        return v;
    }
    if let Some(v) = detect_container() {
        return v;
    }
    if let Some(v) = detect_chroot() {
        return v;
    }
    Virtualization::None
}

#[cfg(not(target_os = "linux"))]
pub fn detect() -> Virtualization {
    Virtualization::None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quiet_flag_parses() {
        assert!(parse_args(&["--quiet"]).unwrap().0);
    }
    #[test]
    fn vm_mode_parses() {
        assert_eq!(parse_args(&["--vm"]).unwrap().1, Mode::Vm);
    }
    #[test]
    fn container_mode_parses() {
        assert_eq!(parse_args(&["--container"]).unwrap().1, Mode::Container);
    }
    #[test]
    fn cvm_mode_parses() {
        assert_eq!(parse_args(&["--cvm"]).unwrap().1, Mode::Cvm);
    }
    #[test]
    fn invalid_arg_fails() {
        assert!(parse_args(&["x"]).is_err());
    }
    #[test]
    fn names_are_stable() {
        assert_eq!(name(Virtualization::Docker), "docker");
    }
    #[test]
    fn none_exits_positive_failure() {
        assert_eq!(exit_code(Virtualization::None), 1);
    }
    #[test]
    fn vm_detection_helper() {
        assert!(is_vm(Virtualization::Kvm));
    }
    #[test]
    fn container_detection_helper() {
        assert!(is_container(Virtualization::Podman));
    }
    #[test]
    fn vm_is_not_container() {
        assert!(!is_container(Virtualization::Qemu));
    }
}
