// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-core.c

use crate::logind_action::HandleAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum InhibitWhat {
    Shutdown,
    Sleep,
    Idle,
    HandlePowerKey,
    HandleSuspendKey,
    HandleHibernateKey,
    HandleLidSwitch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionClass {
    User,
    Greeter,
    LockScreen,
    Background,
    Manager,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionType {
    Unspecified,
    Tty,
    X11,
    Wayland,
    Mir,
    Web,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KillWho {
    All,
    Leader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerConfig {
    pub n_autovts: u8,
    pub reserve_vt: u8,
    pub remove_ipc: bool,
    pub inhibit_delay_max_usec: u64,
    pub user_stop_delay_usec: u64,
    pub wall_messages: bool,
    pub handle_power_key: HandleAction,
    pub handle_reboot_key: HandleAction,
    pub handle_suspend_key: HandleAction,
    pub handle_hibernate_key: HandleAction,
    pub handle_lid_switch: HandleAction,
    pub idle_action: HandleAction,
    pub idle_action_usec: u64,
    pub runtime_dir_size: u64,
    pub runtime_dir_inodes: u64,
    pub sessions_max: u32,
    pub inhibitors_max: u32,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        let runtime_dir_size = 1024 * 1024 * 1024;
        Self {
            n_autovts: 6,
            reserve_vt: 6,
            remove_ipc: true,
            inhibit_delay_max_usec: 5_000_000,
            user_stop_delay_usec: 10_000_000,
            wall_messages: true,
            handle_power_key: HandleAction::PowerOff,
            handle_reboot_key: HandleAction::Reboot,
            handle_suspend_key: HandleAction::Suspend,
            handle_hibernate_key: HandleAction::Hibernate,
            handle_lid_switch: HandleAction::Suspend,
            idle_action: HandleAction::Ignore,
            idle_action_usec: 30 * 60 * 1_000_000,
            runtime_dir_size,
            runtime_dir_inodes: runtime_dir_size / 4096,
            sessions_max: 8192,
            inhibitors_max: 8192,
        }
    }
}

impl SessionType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Tty => "tty",
            Self::X11 => "x11",
            Self::Wayland => "wayland",
            Self::Mir => "mir",
            Self::Web => "web",
        }
    }

    pub fn from_str(value: &str) -> Result<Self, String> {
        match value {
            "unspecified" => Ok(Self::Unspecified),
            "tty" => Ok(Self::Tty),
            "x11" => Ok(Self::X11),
            "wayland" => Ok(Self::Wayland),
            "mir" => Ok(Self::Mir),
            "web" => Ok(Self::Web),
            _ => Err(format!("unknown session type: {value}")),
        }
    }
}

impl SessionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Greeter => "greeter",
            Self::LockScreen => "lock-screen",
            Self::Background => "background",
            Self::Manager => "manager",
        }
    }
}

impl KillWho {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Leader => "leader",
        }
    }
}

pub fn seat_name_is_valid(name: &str) -> bool {
    name == "seat0"
        || (!name.is_empty()
            && name.starts_with("seat")
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
}

pub fn session_id_valid(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_c_shape() {
        let cfg = ManagerConfig::default();
        assert_eq!(cfg.n_autovts, 6);
        assert_eq!(cfg.reserve_vt, 6);
        assert_eq!(cfg.handle_power_key, HandleAction::PowerOff);
    }

    #[test]
    fn validators_work() {
        assert!(seat_name_is_valid("seat0"));
        assert!(session_id_valid("c1"));
        assert!(!session_id_valid(""));
    }
}
