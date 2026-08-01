// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/device-util.c
//

use std::collections::HashMap;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const NEG_ENOENT: i32 = -libc::ENOENT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
}

impl DeviceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Change => "change",
            Self::Move => "move",
            Self::Online => "online",
            Self::Offline => "offline",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    pub syspath: Option<String>,
    pub subsystem: Option<String>,
    pub devtype: Option<String>,
    pub driver: Option<String>,
    pub devpath: Option<String>,
    pub devname: Option<String>,
    pub sysname: Option<String>,
    pub sysnum: Option<String>,
    pub devnum: Option<u64>,
    pub ifindex: Option<i32>,
    pub action: Option<DeviceAction>,
    pub seqnum: Option<u64>,
    pub diskseq: Option<u64>,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    by_key: HashMap<(libc::mode_t, libc::dev_t), DeviceInfo>,
}

impl DeviceRegistry {
    pub fn insert(&mut self, mode: libc::mode_t, devnum: libc::dev_t, info: DeviceInfo) {
        self.by_key.insert((mode, devnum), info);
    }

    pub fn devname_from_devnum(&self, mode: libc::mode_t, devnum: libc::dev_t) -> Result<String> {
        if devnum == 0 {
            return Ok(device_path_make_inaccessible(mode));
        }
        self.by_key
            .get(&(mode, devnum))
            .and_then(|info| info.devname.clone())
            .ok_or(NEG_ENOENT)
    }

    pub fn device_open_from_devnum(
        &self,
        mode: libc::mode_t,
        devnum: libc::dev_t,
        flags: i32,
    ) -> Result<DeviceOpenResult> {
        let devname = self.devname_from_devnum(mode, devnum)?;
        Ok(DeviceOpenResult {
            fd: synthetic_fd(devnum, flags),
            devname,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceOpenResult {
    pub fd: i32,
    pub devname: String,
}

pub fn device_path_make_inaccessible(mode: libc::mode_t) -> String {
    let kind = match mode & libc::S_IFMT {
        libc::S_IFBLK => "blk",
        _ => "chr",
    };
    format!("/run/systemd/inaccessible/{kind}")
}

pub fn devname_from_stat_rdev(registry: &DeviceRegistry, st: &libc::stat) -> Result<String> {
    registry.devname_from_devnum(st.st_mode, st.st_rdev)
}

pub fn device_make_log_fields(device: &DeviceInfo) -> Vec<String> {
    let mut fields = Vec::new();
    push_string_field(&mut fields, "SYSPATH", device.syspath.as_deref());
    push_string_field(&mut fields, "SUBSYSTEM", device.subsystem.as_deref());
    push_string_field(&mut fields, "DEVTYPE", device.devtype.as_deref());
    push_string_field(&mut fields, "DRIVER", device.driver.as_deref());
    push_string_field(&mut fields, "DEVPATH", device.devpath.as_deref());
    push_string_field(&mut fields, "DEVNAME", device.devname.as_deref());
    push_string_field(&mut fields, "SYSNAME", device.sysname.as_deref());
    push_string_field(&mut fields, "SYSNUM", device.sysnum.as_deref());
    if let Some(devnum) = device.devnum {
        fields.push(format!("DEVNUM={devnum}"));
    }
    if let Some(ifindex) = device.ifindex {
        fields.push(format!("IFINDEX={ifindex}"));
    }
    if let Some(action) = device.action {
        fields.push(format!("ACTION={}", action.as_str()));
    }
    if let Some(seqnum) = device.seqnum {
        fields.push(format!("SEQNUM={seqnum}"));
    }
    if let Some(diskseq) = device.diskseq {
        fields.push(format!("DISKSEQ={diskseq}"));
    }
    fields
}

pub fn device_get_seat(device: &DeviceInfo) -> &str {
    match device.properties.get("ID_SEAT") {
        Some(seat) if !seat.is_empty() => seat,
        _ => "seat0",
    }
}

pub fn device_property_can_set(property: &str) -> bool {
    property.starts_with("SYNTH_ARG_").not()
        && !matches!(
            property,
            "ACTION"
                | "SEQNUM"
                | "SYNTH_UUID"
                | "DEVPATH"
                | "DEVPATH_OLD"
                | "SUBSYSTEM"
                | "DEVTYPE"
                | "DRIVER"
                | "MODALIAS"
                | "DEVNAME"
                | "DEVMODE"
                | "DEVUID"
                | "DEVGID"
                | "MAJOR"
                | "MINOR"
                | "DISKSEQ"
                | "PARTN"
                | "IFINDEX"
                | "INTERFACE"
                | "INTERFACE_OLD"
                | "DEVLINKS"
                | "TAGS"
                | "CURRENT_TAGS"
                | "USEC_INITIALIZED"
                | "UDEV_DATABASE_VERSION"
        )
}

pub fn device_sysname_startswith_strv<'a>(
    device: &'a DeviceInfo,
    prefixes: &[&str],
) -> Option<&'a str> {
    let sysname = device.sysname.as_deref()?;
    prefixes
        .iter()
        .find_map(|prefix| sysname.strip_prefix(prefix))
}

fn push_string_field(fields: &mut Vec<String>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        fields.push(format!("{name}={value}"));
    }
}

fn synthetic_fd(devnum: libc::dev_t, flags: i32) -> i32 {
    ((devnum as i32) & 0x7fff) | (flags & 0x1000)
}

trait BoolNot {
    fn not(self) -> bool;
}

impl BoolNot for bool {
    fn not(self) -> bool {
        !self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn returns_inaccessible_path_for_zero_devnum() {
        let registry = DeviceRegistry::default();
        assert_eq!(
            registry.devname_from_devnum(libc::S_IFCHR, 0).unwrap(),
            "/run/systemd/inaccessible/chr"
        );
    }

    #[test]
    fn looks_up_registered_devname() {
        let mut registry = DeviceRegistry::default();
        registry.insert(
            libc::S_IFBLK,
            7,
            DeviceInfo {
                devname: Some("/dev/loop7".into()),
                ..DeviceInfo::default()
            },
        );
        assert_eq!(
            registry.devname_from_devnum(libc::S_IFBLK, 7).unwrap(),
            "/dev/loop7"
        );
    }

    #[test]
    fn opens_registered_device() {
        let mut registry = DeviceRegistry::default();
        registry.insert(
            libc::S_IFCHR,
            5,
            DeviceInfo {
                devname: Some("/dev/tty5".into()),
                ..DeviceInfo::default()
            },
        );
        let opened = registry
            .device_open_from_devnum(libc::S_IFCHR, 5, 0)
            .unwrap();
        assert_eq!(opened.devname, "/dev/tty5");
        assert!(opened.fd >= 0);
    }

    #[test]
    fn builds_log_fields() {
        let info = DeviceInfo {
            subsystem: Some("block".into()),
            devname: Some("/dev/sda".into()),
            devnum: Some(2048),
            action: Some(DeviceAction::Add),
            ..DeviceInfo::default()
        };
        let fields = device_make_log_fields(&info);
        assert!(fields.contains(&"SUBSYSTEM=block".into()));
        assert!(fields.contains(&"DEVNAME=/dev/sda".into()));
        assert!(fields.contains(&"ACTION=add".into()));
    }

    #[test]
    fn defaults_seat_to_seat0() {
        assert_eq!(device_get_seat(&DeviceInfo::default()), "seat0");
    }

    #[test]
    fn respects_explicit_seat() {
        let mut info = DeviceInfo::default();
        info.properties.insert("ID_SEAT".into(), "seat-test".into());
        assert_eq!(device_get_seat(&info), "seat-test");
    }

    #[test]
    fn filters_immutable_properties() {
        assert!(!device_property_can_set("DEVNAME"));
        assert!(!device_property_can_set("SYNTH_ARG_FOO"));
        assert!(device_property_can_set("ID_MODEL"));
    }

    #[test]
    fn finds_sysname_prefix_suffix() {
        let info = DeviceInfo {
            sysname: Some("ttyS0".into()),
            ..DeviceInfo::default()
        };
        assert_eq!(
            device_sysname_startswith_strv(&info, &["tty", "loop"]),
            Some("S0")
        );
    }

    #[test]
    fn forwards_stat_rdev_lookup() {
        let mut registry = DeviceRegistry::default();
        registry.insert(
            libc::S_IFCHR,
            9,
            DeviceInfo {
                devname: Some("/dev/tty9".into()),
                ..DeviceInfo::default()
            },
        );
        // SAFETY: zeroed `libc::stat` is immediately initialized for the fields this test reads.
        let mut stat = unsafe_ffi!(MaybeUninit::<libc::stat>::zeroed().assume_init());
        stat.st_mode = libc::S_IFCHR;
        stat.st_rdev = 9;
        assert_eq!(
            devname_from_stat_rdev(&registry, &stat).unwrap(),
            "/dev/tty9"
        );
    }
}
