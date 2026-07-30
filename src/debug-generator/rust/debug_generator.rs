// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/debug-generator/debug-generator.c

pub const PRE_UDEV: u32 = 1 << 0;
pub const PRE_BASIC: u32 = 1 << 1;
pub const PRE_SYSROOT_MOUNT: u32 = 1 << 2;
pub const PRE_SWITCH_ROOT: u32 = 1 << 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breakpoint {
    PreUdev,
    PreBasic,
    PreSysrootMount,
    PreSwitchRoot,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub default_unit: Option<String>,
    pub mask: Vec<String>,
    pub wants: Vec<String>,
    pub debug_shell: bool,
    pub debug_tty: Option<String>,
    pub default_debug_tty: Option<String>,
    pub breakpoints: u32,
}

pub fn bit(bp: Breakpoint) -> u32 {
    match bp {
        Breakpoint::PreUdev => PRE_UDEV,
        Breakpoint::PreBasic => PRE_BASIC,
        Breakpoint::PreSysrootMount => PRE_SYSROOT_MOUNT,
        Breakpoint::PreSwitchRoot => PRE_SWITCH_ROOT,
    }
}
pub fn unit(bp: Breakpoint) -> &'static str {
    match bp {
        Breakpoint::PreUdev => "breakpoint-pre-udev.service",
        Breakpoint::PreBasic => "breakpoint-pre-basic.service",
        Breakpoint::PreSysrootMount => "breakpoint-pre-mount.service",
        Breakpoint::PreSwitchRoot => "breakpoint-pre-switch-root.service",
    }
}
pub fn parse_breakpoints(s: &str, in_initrd: bool) -> u32 {
    if s.is_empty() {
        return if in_initrd { PRE_SWITCH_ROOT } else { 0 };
    }
    s.split(',').fold(0, |acc, p| {
        acc | match p {
            "pre-udev" => PRE_UDEV,
            "pre-basic" => PRE_BASIC,
            "pre-mount" if in_initrd => PRE_SYSROOT_MOUNT,
            "pre-switch-root" if in_initrd => PRE_SWITCH_ROOT,
            _ => 0,
        }
    })
}
pub fn parse_cmdline_item(cfg: &mut Config, key: &str, value: Option<&str>, in_initrd: bool) {
    match key {
        "systemd.mask" => {
            if let Some(v) = value {
                cfg.mask.push(v.into())
            }
        }
        "systemd.wants" => {
            if let Some(v) = value {
                cfg.wants.push(v.into())
            }
        }
        "systemd.debug_shell" => {
            cfg.debug_shell = value.unwrap_or("1") != "0";
            if value.is_some()
                && value != Some("1")
                && value != Some("yes")
                && value != Some("true")
            {
                cfg.debug_tty = value.map(|v| v.trim_start_matches("/dev/").into());
            }
        }
        "systemd.default_debug_tty" => {
            cfg.default_debug_tty = value.map(|v| v.trim_start_matches("/dev/").into())
        }
        "systemd.unit" => cfg.default_unit = value.map(str::to_string),
        "systemd.break" => cfg.breakpoints |= parse_breakpoints(value.unwrap_or(""), in_initrd),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bit_mapping() {
        assert_eq!(bit(Breakpoint::PreUdev), PRE_UDEV);
    }
    #[test]
    fn unit_mapping() {
        assert_eq!(
            unit(Breakpoint::PreSwitchRoot),
            "breakpoint-pre-switch-root.service"
        );
    }
    #[test]
    fn default_breakpoint_in_initrd() {
        assert_eq!(parse_breakpoints("", true), PRE_SWITCH_ROOT);
    }
    #[test]
    fn no_default_breakpoint_on_host() {
        assert_eq!(parse_breakpoints("", false), 0);
    }
    #[test]
    fn invalid_breakpoint_is_ignored() {
        assert_eq!(parse_breakpoints("bad", true), 0);
    }
    #[test]
    fn pre_mount_only_in_initrd() {
        assert_eq!(parse_breakpoints("pre-mount", false), 0);
    }
    #[test]
    fn mask_is_collected() {
        let mut c = Config::default();
        parse_cmdline_item(&mut c, "systemd.mask", Some("a.service"), false);
        assert_eq!(c.mask, vec!["a.service"]);
    }
    #[test]
    fn wants_is_collected() {
        let mut c = Config::default();
        parse_cmdline_item(&mut c, "systemd.wants", Some("b.service"), false);
        assert_eq!(c.wants, vec!["b.service"]);
    }
    #[test]
    fn debug_shell_boolean() {
        let mut c = Config::default();
        parse_cmdline_item(&mut c, "systemd.debug_shell", Some("1"), false);
        assert!(c.debug_shell);
    }
    #[test]
    fn debug_shell_tty_value() {
        let mut c = Config::default();
        parse_cmdline_item(&mut c, "systemd.debug_shell", Some("/dev/tty9"), false);
        assert_eq!(c.debug_tty.as_deref(), Some("tty9"));
    }
}
