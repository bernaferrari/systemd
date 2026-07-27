// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-swap.c
//
use std::collections::BTreeMap;

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/dbus-swap.c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    Integer(i64),
    Unsigned(u64),
    Text(String),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyDescriptor {
    pub name: &'static str,
    pub signature: &'static str,
    pub emits_change: bool,
}

pub const BUS_SWAP_PROPERTIES: [PropertyDescriptor; 10] = [
    PropertyDescriptor {
        name: "What",
        signature: "s",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "Priority",
        signature: "i",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "Options",
        signature: "s",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "TimeoutUSec",
        signature: "t",
        emits_change: false,
    },
    PropertyDescriptor {
        name: "ControlPID",
        signature: "u",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "Result",
        signature: "s",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "UID",
        signature: "u",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "GID",
        signature: "u",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "ExecActivate",
        signature: "a(sasbttttuii)",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "ExecDeactivate",
        signature: "a(sasbttttuii)",
        emits_change: true,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CgroupContext {
    delegated: BTreeMap<String, PropertyValue>,
    pub realized: bool,
}

impl CgroupContext {
    pub fn set_property(&mut self, name: &str, value: PropertyValue) -> Result<bool, Errno> {
        if name.is_empty() {
            return Err(Errno::EINVAL);
        }

        if !is_cgroup_property(name) {
            return Ok(false);
        }

        self.delegated.insert(name.to_string(), value);
        Ok(true)
    }

    pub fn get(&self, name: &str) -> Option<&PropertyValue> {
        self.delegated.get(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Swap {
    pub what: Option<String>,
    pub priority: Option<i32>,
    pub options: Option<String>,
    pub timeout_usec: u64,
    pub cgroup_context: CgroupContext,
}

fn is_cgroup_property(name: &str) -> bool {
    matches!(
        name,
        "CPUWeight" | "StartupCPUWeight" | "MemoryMax" | "MemorySwapMax" | "TasksMax" | "IOWeight"
    )
}

pub fn bus_swap_set_property(
    unit: &mut Swap,
    name: &str,
    value: PropertyValue,
) -> Result<bool, Errno> {
    unit.cgroup_context.set_property(name, value)
}

pub fn bus_swap_commit_properties(unit: &mut Swap) -> Result<(), Errno> {
    unit.cgroup_context.realized = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_path_points_to_c_file() {
        assert_eq!(SOURCE_PATH, "src/core/dbus-swap.c");
    }

    #[test]
    fn vtable_shape_matches_c() {
        assert_eq!(BUS_SWAP_PROPERTIES.len(), 10);
        assert_eq!(BUS_SWAP_PROPERTIES[0].name, "What");
        assert_eq!(BUS_SWAP_PROPERTIES[8].name, "ExecActivate");
        assert_eq!(BUS_SWAP_PROPERTIES[9].name, "ExecDeactivate");
    }

    #[test]
    fn cgroup_property_is_delegated() {
        let mut swap = Swap::default();
        let handled =
            bus_swap_set_property(&mut swap, "CPUWeight", PropertyValue::Unsigned(100)).unwrap();

        assert!(handled);
        assert_eq!(
            swap.cgroup_context.get("CPUWeight"),
            Some(&PropertyValue::Unsigned(100))
        );
    }

    #[test]
    fn unknown_property_is_ignored() {
        let mut swap = Swap::default();
        let handled =
            bus_swap_set_property(&mut swap, "What", PropertyValue::Text("/dev/zram0".into()))
                .unwrap();

        assert!(!handled);
        assert!(swap.cgroup_context.get("What").is_none());
    }

    #[test]
    fn empty_property_name_is_invalid() {
        let mut swap = Swap::default();
        let err = bus_swap_set_property(&mut swap, "", PropertyValue::Bool(true)).unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn multiple_cgroup_properties_are_retained() {
        let mut swap = Swap::default();
        bus_swap_set_property(&mut swap, "MemoryMax", PropertyValue::Unsigned(4096)).unwrap();
        bus_swap_set_property(&mut swap, "TasksMax", PropertyValue::Unsigned(32)).unwrap();

        assert_eq!(
            swap.cgroup_context.get("MemoryMax"),
            Some(&PropertyValue::Unsigned(4096))
        );
        assert_eq!(
            swap.cgroup_context.get("TasksMax"),
            Some(&PropertyValue::Unsigned(32))
        );
    }

    #[test]
    fn commit_realizes_cgroup_state() {
        let mut swap = Swap::default();
        assert!(!swap.cgroup_context.realized);
        bus_swap_commit_properties(&mut swap).unwrap();
        assert!(swap.cgroup_context.realized);
    }

    #[test]
    fn commit_is_idempotent() {
        let mut swap = Swap::default();
        bus_swap_commit_properties(&mut swap).unwrap();
        bus_swap_commit_properties(&mut swap).unwrap();
        assert!(swap.cgroup_context.realized);
    }

    #[test]
    fn property_value_variants_are_preserved() {
        let mut context = CgroupContext::default();
        context
            .set_property("StartupCPUWeight", PropertyValue::Integer(7))
            .unwrap();
        context
            .set_property("IOWeight", PropertyValue::Text("low".into()))
            .unwrap();

        assert_eq!(
            context.get("StartupCPUWeight"),
            Some(&PropertyValue::Integer(7))
        );
        assert_eq!(
            context.get("IOWeight"),
            Some(&PropertyValue::Text("low".into()))
        );
    }
}
