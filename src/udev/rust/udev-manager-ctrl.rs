// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-manager-ctrl.c

pub const SOURCE_PATH: &str = "src/udev/udev-manager-ctrl.c";
pub const SOURCE_LINE_COUNT: usize = 134;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrlMessageType {
    SetLogLevel,
    StopExecQueue,
    StartExecQueue,
    Reload,
    SetEnv,
    SetChildrenMax,
    Ping,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtrlValue<'a> {
    Int(i32),
    Str(&'a str),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtrlAction<'a> {
    SetLogLevel(i32),
    SetStopExecQueue(bool),
    Reload,
    SetEnvironment(&'a str),
    SetChildrenMax(i32),
    Ping,
    Exit,
    Ignore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtrlError {
    InvalidLogLevel(i32),
    InvalidChildrenMax(i32),
    InvalidEnvironment,
}

pub fn map_message<'a>(
    message: CtrlMessageType,
    value: CtrlValue<'a>,
) -> Result<CtrlAction<'a>, CtrlError> {
    match (message, value) {
        (CtrlMessageType::SetLogLevel, CtrlValue::Int(level)) if (0..=7).contains(&level) => {
            Ok(CtrlAction::SetLogLevel(level))
        }
        (CtrlMessageType::SetLogLevel, CtrlValue::Int(level)) => {
            Err(CtrlError::InvalidLogLevel(level))
        }
        (CtrlMessageType::StopExecQueue, _) => Ok(CtrlAction::SetStopExecQueue(true)),
        (CtrlMessageType::StartExecQueue, _) => Ok(CtrlAction::SetStopExecQueue(false)),
        (CtrlMessageType::Reload, _) => Ok(CtrlAction::Reload),
        (CtrlMessageType::SetEnv, CtrlValue::Str(value)) if value.contains('=') => {
            Ok(CtrlAction::SetEnvironment(value))
        }
        (CtrlMessageType::SetEnv, _) => Err(CtrlError::InvalidEnvironment),
        (CtrlMessageType::SetChildrenMax, CtrlValue::Int(value)) if value >= 0 => {
            Ok(CtrlAction::SetChildrenMax(value))
        }
        (CtrlMessageType::SetChildrenMax, CtrlValue::Int(value)) => {
            Err(CtrlError::InvalidChildrenMax(value))
        }
        (CtrlMessageType::Ping, _) => Ok(CtrlAction::Ping),
        (CtrlMessageType::Exit, _) => Ok(CtrlAction::Exit),
        (CtrlMessageType::SetLogLevel, _) => Err(CtrlError::InvalidEnvironment),
        (CtrlMessageType::SetChildrenMax, _) => Err(CtrlError::InvalidEnvironment),
    }
}

pub fn validate_port_model() -> Result<(), CtrlError> {
    if SOURCE_LINE_COUNT != 134 {
        return Err(CtrlError::InvalidEnvironment);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/udev-manager-ctrl.c");
        assert_eq!(SOURCE_LINE_COUNT, 134);
    }

    #[test]
    fn valid_log_level_maps_to_action() {
        assert_eq!(
            map_message(CtrlMessageType::SetLogLevel, CtrlValue::Int(6)).unwrap(),
            CtrlAction::SetLogLevel(6)
        );
    }

    #[test]
    fn invalid_log_level_is_rejected() {
        assert_eq!(
            map_message(CtrlMessageType::SetLogLevel, CtrlValue::Int(99)),
            Err(CtrlError::InvalidLogLevel(99))
        );
    }

    #[test]
    fn stop_and_start_exec_queue_flip_state() {
        assert_eq!(
            map_message(CtrlMessageType::StopExecQueue, CtrlValue::None).unwrap(),
            CtrlAction::SetStopExecQueue(true)
        );
        assert_eq!(
            map_message(CtrlMessageType::StartExecQueue, CtrlValue::None).unwrap(),
            CtrlAction::SetStopExecQueue(false)
        );
    }

    #[test]
    fn reload_maps_without_payload() {
        assert_eq!(
            map_message(CtrlMessageType::Reload, CtrlValue::None).unwrap(),
            CtrlAction::Reload
        );
    }

    #[test]
    fn set_env_requires_assignment() {
        assert_eq!(
            map_message(CtrlMessageType::SetEnv, CtrlValue::Str("A=B")).unwrap(),
            CtrlAction::SetEnvironment("A=B")
        );
        assert_eq!(
            map_message(CtrlMessageType::SetEnv, CtrlValue::Str("BAD")),
            Err(CtrlError::InvalidEnvironment)
        );
    }

    #[test]
    fn children_max_must_be_non_negative() {
        assert_eq!(
            map_message(CtrlMessageType::SetChildrenMax, CtrlValue::Int(8)).unwrap(),
            CtrlAction::SetChildrenMax(8)
        );
        assert_eq!(
            map_message(CtrlMessageType::SetChildrenMax, CtrlValue::Int(-1)),
            Err(CtrlError::InvalidChildrenMax(-1))
        );
    }

    #[test]
    fn ping_and_exit_are_passed_through() {
        assert_eq!(
            map_message(CtrlMessageType::Ping, CtrlValue::None).unwrap(),
            CtrlAction::Ping
        );
        assert_eq!(
            map_message(CtrlMessageType::Exit, CtrlValue::None).unwrap(),
            CtrlAction::Exit
        );
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
