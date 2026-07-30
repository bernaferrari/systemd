// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-device/device-private.c, src/libsystemd/sd-device/device-private.h, src/systemd/sd-device.h

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;

#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceAction {
    Add = 0,
    Remove = 1,
    Change = 2,
    Move = 3,
    Online = 4,
    Offline = 5,
    Bind = 6,
    Unbind = 7,
    Max = 8,
    Invalid = NEG_EINVAL as i64,
    ForceS64Min = i64::MIN,
    ForceS64Max = i64::MAX,
}

impl DeviceAction {
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Add => Some("add"),
            Self::Remove => Some("remove"),
            Self::Change => Some("change"),
            Self::Move => Some("move"),
            Self::Online => Some("online"),
            Self::Offline => Some("offline"),
            Self::Bind => Some("bind"),
            Self::Unbind => Some("unbind"),
            Self::Max | Self::Invalid | Self::ForceS64Min | Self::ForceS64Max => None,
        }
    }
}

pub fn device_action_to_string(action: DeviceAction) -> Option<&'static str> {
    action.as_str()
}

pub fn device_action_from_string(s: &str) -> Result<DeviceAction> {
    match s {
        "add" => Ok(DeviceAction::Add),
        "remove" => Ok(DeviceAction::Remove),
        "change" => Ok(DeviceAction::Change),
        "move" => Ok(DeviceAction::Move),
        "online" => Ok(DeviceAction::Online),
        "offline" => Ok(DeviceAction::Offline),
        "bind" => Ok(DeviceAction::Bind),
        "unbind" => Ok(DeviceAction::Unbind),
        _ => Err(NEG_EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIONS: &[(DeviceAction, &str)] = &[
        (DeviceAction::Add, "add"),
        (DeviceAction::Remove, "remove"),
        (DeviceAction::Change, "change"),
        (DeviceAction::Move, "move"),
        (DeviceAction::Online, "online"),
        (DeviceAction::Offline, "offline"),
        (DeviceAction::Bind, "bind"),
        (DeviceAction::Unbind, "unbind"),
    ];

    #[test]
    fn converts_every_c_table_entry_in_both_directions() {
        for &(action, string) in ACTIONS {
            assert_eq!(device_action_to_string(action), Some(string));
            assert_eq!(device_action_from_string(string), Ok(action));
        }
    }

    #[test]
    fn preserves_c_enum_discriminants_and_invalid_lookup_result() {
        assert_eq!(DeviceAction::Add as i64, 0);
        assert_eq!(DeviceAction::Unbind as i64, 7);
        assert_eq!(DeviceAction::Max as i64, 8);
        assert_eq!(DeviceAction::Invalid as i64, NEG_EINVAL as i64);
        assert_eq!(DeviceAction::ForceS64Min as i64, i64::MIN);
        assert_eq!(DeviceAction::ForceS64Max as i64, i64::MAX);

        for action in [
            DeviceAction::Max,
            DeviceAction::Invalid,
            DeviceAction::ForceS64Min,
            DeviceAction::ForceS64Max,
        ] {
            assert_eq!(device_action_to_string(action), None);
        }
    }

    #[test]
    fn rejects_noncanonical_action_strings_with_c_errno() {
        for string in ["", "detach", "ADD", "add ", "unbound"] {
            assert_eq!(device_action_from_string(string), Err(NEG_EINVAL));
        }
    }
}
