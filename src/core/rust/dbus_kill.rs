// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-kill.c
//
use std::fmt;

pub const UNIT_PRIVATE: u64 = 1 << 2;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillMode {
    ControlGroup = 0,
    Process = 1,
    Mixed = 2,
    None = 3,
}

impl KillMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlGroup => "control-group",
            Self::Process => "process",
            Self::Mixed => "mixed",
            Self::None => "none",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "control-group" => Some(Self::ControlGroup),
            "process" => Some(Self::Process),
            "mixed" => Some(Self::Mixed),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillContext {
    pub kill_mode: KillMode,
    pub kill_signal: i32,
    pub restart_kill_signal: i32,
    pub final_kill_signal: i32,
    pub send_sigkill: bool,
    pub send_sighup: bool,
    pub watchdog_signal: i32,
}

impl KillContext {
    pub fn restart_kill_signal(self) -> i32 {
        if self.restart_kill_signal != 0 {
            self.restart_kill_signal
        } else {
            self.kill_signal
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    String(String),
    Int(i32),
    Bool(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbusKillError {
    UnknownProperty,
    InvalidMode,
    WrongType,
}

impl fmt::Display for DbusKillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for DbusKillError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VTableEntry {
    pub property: &'static str,
    pub signature: &'static str,
}

pub const BUS_KILL_VTABLE: [VTableEntry; 7] = [
    VTableEntry {
        property: "KillMode",
        signature: "s",
    },
    VTableEntry {
        property: "KillSignal",
        signature: "i",
    },
    VTableEntry {
        property: "RestartKillSignal",
        signature: "i",
    },
    VTableEntry {
        property: "FinalKillSignal",
        signature: "i",
    },
    VTableEntry {
        property: "SendSIGKILL",
        signature: "b",
    },
    VTableEntry {
        property: "SendSIGHUP",
        signature: "b",
    },
    VTableEntry {
        property: "WatchdogSignal",
        signature: "i",
    },
];

pub fn property_get_kill_mode(context: &KillContext) -> Result<PropertyValue, DbusKillError> {
    Ok(PropertyValue::String(context.kill_mode.as_str().to_owned()))
}

pub fn property_get_restart_kill_signal(
    context: &KillContext,
) -> Result<PropertyValue, DbusKillError> {
    Ok(PropertyValue::Int(context.restart_kill_signal()))
}

pub fn property_get(context: &KillContext, name: &str) -> Result<PropertyValue, DbusKillError> {
    match name {
        "KillMode" => property_get_kill_mode(context),
        "KillSignal" => Ok(PropertyValue::Int(context.kill_signal)),
        "RestartKillSignal" => property_get_restart_kill_signal(context),
        "FinalKillSignal" => Ok(PropertyValue::Int(context.final_kill_signal)),
        "SendSIGKILL" => Ok(PropertyValue::Bool(context.send_sigkill)),
        "SendSIGHUP" => Ok(PropertyValue::Bool(context.send_sighup)),
        "WatchdogSignal" => Ok(PropertyValue::Int(context.watchdog_signal)),
        _ => Err(DbusKillError::UnknownProperty),
    }
}

pub fn bus_kill_context_set_transient_property(
    context: &mut KillContext,
    name: &str,
    value: PropertyValue,
    flags: u64,
) -> Result<bool, DbusKillError> {
    let _effective_flags = flags | UNIT_PRIVATE;

    match (name, value) {
        ("KillMode", PropertyValue::String(mode)) => {
            context.kill_mode = KillMode::parse(&mode).ok_or(DbusKillError::InvalidMode)?;
            Ok(true)
        }
        ("SendSIGHUP", PropertyValue::Bool(v)) => {
            context.send_sighup = v;
            Ok(true)
        }
        ("SendSIGKILL", PropertyValue::Bool(v)) => {
            context.send_sigkill = v;
            Ok(true)
        }
        ("KillSignal", PropertyValue::Int(v)) => {
            context.kill_signal = v;
            Ok(true)
        }
        ("RestartKillSignal", PropertyValue::Int(v)) => {
            context.restart_kill_signal = v;
            Ok(true)
        }
        ("FinalKillSignal", PropertyValue::Int(v)) => {
            context.final_kill_signal = v;
            Ok(true)
        }
        ("WatchdogSignal", PropertyValue::Int(v)) => {
            context.watchdog_signal = v;
            Ok(true)
        }
        ("KillMode", _)
        | ("KillSignal", _)
        | ("RestartKillSignal", _)
        | ("FinalKillSignal", _)
        | ("WatchdogSignal", _)
        | ("SendSIGHUP", _)
        | ("SendSIGKILL", _) => Err(DbusKillError::WrongType),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> KillContext {
        KillContext {
            kill_mode: KillMode::ControlGroup,
            kill_signal: 15,
            restart_kill_signal: 0,
            final_kill_signal: 9,
            send_sigkill: true,
            send_sighup: false,
            watchdog_signal: 6,
        }
    }

    #[test]
    fn kill_mode_property_serializes_to_string() {
        assert_eq!(
            property_get_kill_mode(&context()).unwrap(),
            PropertyValue::String("control-group".into())
        );
    }

    #[test]
    fn restart_kill_signal_falls_back_to_kill_signal() {
        assert_eq!(
            property_get_restart_kill_signal(&context()).unwrap(),
            PropertyValue::Int(15)
        );
    }

    #[test]
    fn vtable_lists_all_expected_properties() {
        assert_eq!(BUS_KILL_VTABLE.len(), 7);
        assert_eq!(BUS_KILL_VTABLE[0].property, "KillMode");
        assert_eq!(BUS_KILL_VTABLE[6].property, "WatchdogSignal");
    }

    #[test]
    fn transient_setter_updates_mode() {
        let mut context = context();
        bus_kill_context_set_transient_property(
            &mut context,
            "KillMode",
            PropertyValue::String("process".into()),
            0,
        )
        .unwrap();
        assert_eq!(context.kill_mode, KillMode::Process);
    }

    #[test]
    fn transient_setter_updates_bool() {
        let mut context = context();
        bus_kill_context_set_transient_property(
            &mut context,
            "SendSIGHUP",
            PropertyValue::Bool(true),
            0,
        )
        .unwrap();
        assert!(context.send_sighup);
    }

    #[test]
    fn transient_setter_updates_signal() {
        let mut context = context();
        bus_kill_context_set_transient_property(
            &mut context,
            "FinalKillSignal",
            PropertyValue::Int(11),
            0,
        )
        .unwrap();
        assert_eq!(context.final_kill_signal, 11);
    }

    #[test]
    fn transient_setter_rejects_invalid_mode() {
        let mut context = context();
        assert_eq!(
            bus_kill_context_set_transient_property(
                &mut context,
                "KillMode",
                PropertyValue::String("bogus".into()),
                0
            ),
            Err(DbusKillError::InvalidMode)
        );
    }

    #[test]
    fn transient_setter_rejects_wrong_type() {
        let mut context = context();
        assert_eq!(
            bus_kill_context_set_transient_property(
                &mut context,
                "KillSignal",
                PropertyValue::Bool(true),
                0
            ),
            Err(DbusKillError::WrongType)
        );
    }

    #[test]
    fn transient_setter_ignores_unknown_property() {
        let mut context = context();
        assert!(
            !bus_kill_context_set_transient_property(
                &mut context,
                "NoSuchProperty",
                PropertyValue::Int(1),
                0
            )
            .unwrap()
        );
    }

    #[test]
    fn property_get_reads_boolean_fields() {
        assert_eq!(
            property_get(&context(), "SendSIGKILL").unwrap(),
            PropertyValue::Bool(true)
        );
    }
}
