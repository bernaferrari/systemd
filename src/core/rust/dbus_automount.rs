// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-automount.c
//
use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/dbus-automount.c";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Stub,
    Loaded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnitWriteFlags(u32);

impl UnitWriteFlags {
    pub const NONE: Self = Self(0);
    pub const PRIVATE: Self = Self(1 << 0);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    Path(String),
    Text(String),
    Usec(u64),
    Mode(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyDescriptor {
    pub name: &'static str,
    pub signature: &'static str,
    pub emits_change: bool,
}

pub const BUS_AUTOMOUNT_PROPERTIES: [PropertyDescriptor; 5] = [
    PropertyDescriptor {
        name: "Where",
        signature: "s",
        emits_change: false,
    },
    PropertyDescriptor {
        name: "ExtraOptions",
        signature: "s",
        emits_change: false,
    },
    PropertyDescriptor {
        name: "DirectoryMode",
        signature: "u",
        emits_change: false,
    },
    PropertyDescriptor {
        name: "Result",
        signature: "s",
        emits_change: true,
    },
    PropertyDescriptor {
        name: "TimeoutIdleUSec",
        signature: "t",
        emits_change: false,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Automount {
    pub where_path: Option<String>,
    pub extra_options: Option<String>,
    pub directory_mode: u32,
    pub timeout_idle_usec: u64,
    pub last_flags: UnitWriteFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AutomountUnit {
    pub transient: bool,
    pub load_state: LoadState,
    pub automount: Automount,
}

impl Default for LoadState {
    fn default() -> Self {
        Self::Stub
    }
}

fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/')
}

fn validate_mode(mode: u32) -> Result<u32, Errno> {
    if mode <= 0o7777 {
        Ok(mode)
    } else {
        Err(Errno::EINVAL)
    }
}

pub fn bus_automount_set_transient_property(
    automount: &mut Automount,
    name: &str,
    value: PropertyValue,
    flags: UnitWriteFlags,
) -> Result<bool, Errno> {
    let flags = flags.with(UnitWriteFlags::PRIVATE);
    automount.last_flags = flags;

    match (name, value) {
        ("Where", PropertyValue::Path(path)) => {
            if !is_absolute_path(&path) {
                return Err(Errno::EINVAL);
            }
            automount.where_path = Some(path);
            Ok(true)
        }
        ("ExtraOptions", PropertyValue::Text(text)) => {
            automount.extra_options = Some(text);
            Ok(true)
        }
        ("TimeoutIdleUSec", PropertyValue::Usec(value)) => {
            automount.timeout_idle_usec = value;
            Ok(true)
        }
        ("DirectoryMode", PropertyValue::Mode(mode)) => {
            automount.directory_mode = validate_mode(mode)?;
            Ok(true)
        }
        ("Where" | "ExtraOptions" | "TimeoutIdleUSec" | "DirectoryMode", _) => Err(Errno::EINVAL),
        _ => Ok(false),
    }
}

pub fn bus_automount_set_property(
    unit: &mut AutomountUnit,
    name: &str,
    value: PropertyValue,
    flags: UnitWriteFlags,
) -> Result<bool, Errno> {
    if unit.transient && unit.load_state == LoadState::Stub {
        return bus_automount_set_transient_property(&mut unit.automount, name, value, flags);
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vtable_shape_matches_c() {
        assert_eq!(BUS_AUTOMOUNT_PROPERTIES.len(), 5);
        assert_eq!(BUS_AUTOMOUNT_PROPERTIES[0].name, "Where");
        assert_eq!(BUS_AUTOMOUNT_PROPERTIES[4].signature, "t");
        assert!(BUS_AUTOMOUNT_PROPERTIES[3].emits_change);
    }

    #[test]
    fn source_path_points_to_c_file() {
        assert_eq!(SOURCE_PATH, "src/core/dbus-automount.c");
    }

    #[test]
    fn transient_where_accepts_absolute_path() {
        let mut automount = Automount::default();
        let handled = bus_automount_set_transient_property(
            &mut automount,
            "Where",
            PropertyValue::Path("/mnt/data".into()),
            UnitWriteFlags::NONE,
        )
        .unwrap();

        assert!(handled);
        assert_eq!(automount.where_path.as_deref(), Some("/mnt/data"));
        assert!(automount.last_flags.contains(UnitWriteFlags::PRIVATE));
    }

    #[test]
    fn transient_where_rejects_relative_path() {
        let mut automount = Automount::default();
        let err = bus_automount_set_transient_property(
            &mut automount,
            "Where",
            PropertyValue::Path("relative".into()),
            UnitWriteFlags::NONE,
        )
        .unwrap_err();

        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn transient_extra_options_updates_string() {
        let mut automount = Automount::default();
        let handled = bus_automount_set_transient_property(
            &mut automount,
            "ExtraOptions",
            PropertyValue::Text("x-systemd.idle-timeout=1min".into()),
            UnitWriteFlags::NONE,
        )
        .unwrap();

        assert!(handled);
        assert_eq!(
            automount.extra_options.as_deref(),
            Some("x-systemd.idle-timeout=1min")
        );
    }

    #[test]
    fn transient_timeout_updates_usec() {
        let mut automount = Automount::default();
        bus_automount_set_transient_property(
            &mut automount,
            "TimeoutIdleUSec",
            PropertyValue::Usec(5_000_000),
            UnitWriteFlags::NONE,
        )
        .unwrap();

        assert_eq!(automount.timeout_idle_usec, 5_000_000);
    }

    #[test]
    fn transient_directory_mode_validates_range() {
        let mut automount = Automount::default();
        bus_automount_set_transient_property(
            &mut automount,
            "DirectoryMode",
            PropertyValue::Mode(0o755),
            UnitWriteFlags::NONE,
        )
        .unwrap();

        assert_eq!(automount.directory_mode, 0o755);
        assert_eq!(
            bus_automount_set_transient_property(
                &mut automount,
                "DirectoryMode",
                PropertyValue::Mode(0o20_000),
                UnitWriteFlags::NONE,
            )
            .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn unit_property_delegates_for_transient_stub() {
        let mut unit = AutomountUnit {
            transient: true,
            load_state: LoadState::Stub,
            ..AutomountUnit::default()
        };

        let handled = bus_automount_set_property(
            &mut unit,
            "Where",
            PropertyValue::Path("/srv".into()),
            UnitWriteFlags::NONE,
        )
        .unwrap();

        assert!(handled);
        assert_eq!(unit.automount.where_path.as_deref(), Some("/srv"));
    }

    #[test]
    fn unit_property_ignores_non_transient_or_loaded_units() {
        let mut loaded = AutomountUnit {
            transient: true,
            load_state: LoadState::Loaded,
            ..AutomountUnit::default()
        };
        let mut non_transient = AutomountUnit {
            transient: false,
            load_state: LoadState::Stub,
            ..AutomountUnit::default()
        };

        assert!(
            !bus_automount_set_property(
                &mut loaded,
                "Where",
                PropertyValue::Path("/srv".into()),
                UnitWriteFlags::NONE,
            )
            .unwrap()
        );
        assert!(
            !bus_automount_set_property(
                &mut non_transient,
                "Where",
                PropertyValue::Path("/srv".into()),
                UnitWriteFlags::NONE,
            )
            .unwrap()
        );
    }
}
