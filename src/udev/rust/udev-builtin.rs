// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udev-builtin.c
//
// Builtin command registry and reload tracking.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BuiltinCommand {
    Blkid,
    Btrfs,
    DissectImage,
    FactoryReset,
    Hwdb,
    InputId,
    Keyboard,
    Kmod,
    NetDriver,
    NetId,
    NetSetupLink,
    PathId,
    Uaccess,
    UsbId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinDescriptor {
    pub name: &'static str,
    pub help: &'static str,
    pub run_once: bool,
}

pub fn builtins() -> &'static [BuiltinDescriptor] {
    &[
        BuiltinDescriptor { name: "blkid", help: "filesystem probe", run_once: false },
        BuiltinDescriptor { name: "btrfs", help: "btrfs metadata", run_once: false },
        BuiltinDescriptor { name: "dissect-image", help: "image metadata", run_once: false },
        BuiltinDescriptor { name: "factory-reset", help: "factory reset mode", run_once: true },
        BuiltinDescriptor { name: "hwdb", help: "hardware database", run_once: false },
        BuiltinDescriptor { name: "input_id", help: "input classification", run_once: false },
        BuiltinDescriptor { name: "keyboard", help: "keyboard setup", run_once: false },
        BuiltinDescriptor { name: "kmod", help: "module loading", run_once: false },
        BuiltinDescriptor { name: "net_driver", help: "driver metadata", run_once: false },
        BuiltinDescriptor { name: "net_id", help: "predictable names", run_once: false },
        BuiltinDescriptor { name: "net_setup_link", help: "link configuration", run_once: false },
        BuiltinDescriptor { name: "path_id", help: "physical path id", run_once: false },
        BuiltinDescriptor { name: "uaccess", help: "access tags", run_once: false },
        BuiltinDescriptor { name: "usb_id", help: "usb metadata", run_once: false },
    ]
}

pub fn builtin_by_name(name: &str) -> Option<&'static BuiltinDescriptor> {
    builtins().iter().find(|builtin| builtin.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn builtin_registry_contains_expected_entries() { assert!(builtin_by_name("net_id").is_some()); assert!(builtin_by_name("missing").is_none()); }
    #[test] fn factory_reset_is_run_once() { assert!(builtin_by_name("factory-reset").unwrap().run_once); }
}
