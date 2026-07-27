// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-device/device-private.c, src/libsystemd/sd-device/device-private.h, src/systemd/sd-device.h

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);

#[repr(i32)]
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
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }
}

pub fn device_action_to_string(action: DeviceAction) -> &'static str {
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
    #[test]
    fn formats_add() {
        assert_eq!(device_action_to_string(DeviceAction::Add), "add");
    }
    #[test]
    fn formats_remove() {
        assert_eq!(device_action_to_string(DeviceAction::Remove), "remove");
    }
    #[test]
    fn parses_change() {
        assert_eq!(
            device_action_from_string("change"),
            Ok(DeviceAction::Change)
        );
    }
    #[test]
    fn parses_move() {
        assert_eq!(device_action_from_string("move"), Ok(DeviceAction::Move));
    }
    #[test]
    fn parses_online() {
        assert_eq!(
            device_action_from_string("online"),
            Ok(DeviceAction::Online)
        );
    }
    #[test]
    fn parses_offline() {
        assert_eq!(
            device_action_from_string("offline"),
            Ok(DeviceAction::Offline)
        );
    }
    #[test]
    fn parses_bind() {
        assert_eq!(device_action_from_string("bind"), Ok(DeviceAction::Bind));
    }
    #[test]
    fn rejects_invalid_action() {
        assert_eq!(device_action_from_string("detach"), Err(NEG_EINVAL));
    }
}
