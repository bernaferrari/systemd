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
    Lock,
    FactoryReset,
    SecureAttentionKey,
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
    HandleActionData {
        action: HandleAction::SecureAttentionKey,
        name: "secure-attention-key",
        target: None,
        polkit_action: None,
        message: "Secure attention key pressed",
        verb: "secure attention",
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
            Self::Suspend | Self::Hibernate | Self::HybridSleep | Self::SuspendThenHibernate
        )
    }

    pub fn verb(self) -> &'static str {
        self.data().verb
    }

    pub fn message(self) -> &'static str {
        self.data().message
    }

    pub fn from_str(name: &str) -> Result<Self, String> {
        HANDLE_ACTIONS
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.action)
            .ok_or_else(|| format!("unknown handle action: {name}"))
    }
}

pub fn handle_action_lookup(action: HandleAction) -> &'static HandleActionData {
    action.data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_actions_are_detected() {
        assert!(HandleAction::Suspend.is_sleep());
        assert!(HandleAction::HybridSleep.is_sleep());
        assert!(!HandleAction::Reboot.is_sleep());
    }

    #[test]
    fn strings_round_trip() {
        for action in [
            HandleAction::PowerOff,
            HandleAction::Reboot,
            HandleAction::Hibernate,
        ] {
            assert_eq!(HandleAction::from_str(action.as_str()), Ok(action));
        }
    }
}
