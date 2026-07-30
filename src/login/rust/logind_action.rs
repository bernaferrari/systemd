// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-action.c

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleAction {
    Ignore,
    PowerOff,
    Reboot,
    Halt,
    KExec,
    SoftReboot,
    Suspend,
    Hibernate,
    HybridSleep,
    SuspendThenHibernate,
    /// The C high-level HANDLE_SLEEP action. It is selected into a concrete
    /// sleep operation before execution.
    Sleep,
    SecureAttentionKey,
    Lock,
    FactoryReset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleActionData {
    pub action: HandleAction,
    pub name: &'static str,
    pub target: Option<&'static str>,
    pub polkit_action: Option<&'static str>,
    pub message: &'static str,
    pub verb: &'static str,
}

const HANDLE_ACTIONS: &[HandleActionData] = &[
    HandleActionData {
        action: HandleAction::Ignore,
        name: "ignore",
        target: None,
        polkit_action: None,
        message: "Action ignored",
        verb: "ignore",
    },
    HandleActionData {
        action: HandleAction::PowerOff,
        name: "poweroff",
        target: Some("poweroff.target"),
        polkit_action: Some("org.freedesktop.login1.power-off"),
        message: "System is powering down",
        verb: "power off",
    },
    HandleActionData {
        action: HandleAction::Reboot,
        name: "reboot",
        target: Some("reboot.target"),
        polkit_action: Some("org.freedesktop.login1.reboot"),
        message: "System is rebooting",
        verb: "reboot",
    },
    HandleActionData {
        action: HandleAction::Halt,
        name: "halt",
        target: Some("halt.target"),
        polkit_action: Some("org.freedesktop.login1.halt"),
        message: "System is halting",
        verb: "halt",
    },
    HandleActionData {
        action: HandleAction::KExec,
        name: "kexec",
        target: Some("kexec.target"),
        polkit_action: Some("org.freedesktop.login1.reboot"),
        message: "System is rebooting with kexec",
        verb: "reboot",
    },
    HandleActionData {
        action: HandleAction::SoftReboot,
        name: "soft-reboot",
        target: Some("soft-reboot.target"),
        polkit_action: Some("org.freedesktop.login1.reboot"),
        message: "Userspace is rebooting",
        verb: "soft reboot",
    },
    HandleActionData {
        action: HandleAction::Suspend,
        name: "suspend",
        target: Some("suspend.target"),
        polkit_action: Some("org.freedesktop.login1.suspend"),
        message: "System is suspending",
        verb: "suspend",
    },
    HandleActionData {
        action: HandleAction::Hibernate,
        name: "hibernate",
        target: Some("hibernate.target"),
        polkit_action: Some("org.freedesktop.login1.hibernate"),
        message: "System is hibernating",
        verb: "hibernate",
    },
    HandleActionData {
        action: HandleAction::HybridSleep,
        name: "hybrid-sleep",
        target: Some("hybrid-sleep.target"),
        polkit_action: Some("org.freedesktop.login1.hibernate"),
        message: "System is entering hybrid sleep",
        verb: "sleep",
    },
    HandleActionData {
        action: HandleAction::SuspendThenHibernate,
        name: "suspend-then-hibernate",
        target: Some("suspend-then-hibernate.target"),
        polkit_action: Some("org.freedesktop.login1.suspend"),
        message: "System is suspending, then hibernating",
        verb: "sleep",
    },
    // C's HANDLE_SLEEP has public string-table entries but no executable
    // action-data entry: logind resolves it to a concrete sleep action first.
    // Keep the safe model total for parsing, wall filtering, and metadata.
    HandleActionData {
        action: HandleAction::Sleep,
        name: "sleep",
        target: None,
        polkit_action: None,
        message: "System is sleeping",
        verb: "sleep",
    },
    HandleActionData {
        action: HandleAction::SecureAttentionKey,
        name: "secure-attention-key",
        target: None,
        polkit_action: None,
        message: "Secure attention key pressed",
        verb: "secure attention",
    },
    HandleActionData {
        action: HandleAction::Lock,
        name: "lock",
        target: None,
        polkit_action: None,
        message: "Session is locking",
        verb: "lock",
    },
    HandleActionData {
        action: HandleAction::FactoryReset,
        name: "factory-reset",
        target: Some("factory-reset.target"),
        polkit_action: Some("org.freedesktop.login1.set-reboot-parameter"),
        message: "System is performing a factory reset",
        verb: "factory reset",
    },
];

impl HandleAction {
    pub fn as_str(self) -> &'static str {
        self.data().name
    }

    pub fn data(self) -> &'static HandleActionData {
        HANDLE_ACTIONS
            .iter()
            .find(|entry| entry.action == self)
            .expect("every handle action has metadata")
    }

    pub fn is_sleep(self) -> bool {
        matches!(
            self,
            Self::Suspend
                | Self::Hibernate
                | Self::HybridSleep
                | Self::SuspendThenHibernate
                | Self::Sleep
        )
    }

    pub fn verb(self) -> &'static str {
        self.data().verb
    }

    pub fn message(self) -> &'static str {
        self.data().message
    }
}

impl std::str::FromStr for HandleAction {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        HANDLE_ACTIONS
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.action)
            .ok_or_else(|| format!("unknown handle action: {name}"))
    }
}

/// C-parity facade for `handle_action_from_string()`.
///
/// Keep parsing at the string-table boundary so Rust callers do not need to
/// rely on the inherent-method spelling that predates `FromStr`.
pub fn handle_action_from_string(name: &str) -> Result<HandleAction, String> {
    name.parse()
}

pub fn handle_action_lookup(action: HandleAction) -> &'static HandleActionData {
    action.data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn sleep_actions_are_detected() {
        assert!(HandleAction::Suspend.is_sleep());
        assert!(HandleAction::HybridSleep.is_sleep());
        assert!(HandleAction::Sleep.is_sleep());
        assert!(!HandleAction::Reboot.is_sleep());
    }

    #[test]
    fn strings_round_trip() {
        for action in [
            HandleAction::PowerOff,
            HandleAction::Reboot,
            HandleAction::Hibernate,
            HandleAction::Sleep,
        ] {
            assert_eq!(HandleAction::from_str(action.as_str()), Ok(action));
            assert_eq!(handle_action_from_string(action.as_str()), Ok(action));
        }

        assert_eq!(
            handle_action_from_string("invalid"),
            Err("unknown handle action: invalid".into())
        );
    }

    #[test]
    fn high_level_sleep_keeps_the_c_public_string_table_shape() {
        let sleep = handle_action_lookup(HandleAction::Sleep);
        assert_eq!(sleep.name, "sleep");
        assert_eq!(sleep.verb, "sleep");
        assert_eq!(sleep.target, None);
        assert_eq!(sleep.polkit_action, None);
    }
}
