// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-ctrl.c
//
// Pure-Rust control message encoder/decoder.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevCtrlMessageType {
    SetLogLevel,
    StopExecQueue,
    StartExecQueue,
    Reload,
    SetChildrenMax,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdevCtrlValue {
    Integer(i32),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdevCtrlMessage {
    pub message_type: UdevCtrlMessageType,
    pub value: UdevCtrlValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdevCtrlError {
    InvalidMessage,
    MissingPayload,
}
pub type Result<T> = std::result::Result<T, UdevCtrlError>;

pub fn encode_message(message: &UdevCtrlMessage) -> Vec<u8> {
    let type_byte = match message.message_type {
        UdevCtrlMessageType::SetLogLevel => 1,
        UdevCtrlMessageType::StopExecQueue => 2,
        UdevCtrlMessageType::StartExecQueue => 3,
        UdevCtrlMessageType::Reload => 4,
        UdevCtrlMessageType::SetChildrenMax => 5,
    };
    let mut out = vec![type_byte];
    match &message.value {
        UdevCtrlValue::Integer(value) => out.extend_from_slice(&value.to_le_bytes()),
        UdevCtrlValue::Text(text) => out.extend_from_slice(text.as_bytes()),
    }
    out
}

pub fn decode_message(bytes: &[u8]) -> Result<UdevCtrlMessage> {
    let (type_byte, rest) = bytes.split_first().ok_or(UdevCtrlError::InvalidMessage)?;
    let message_type = match *type_byte {
        1 => UdevCtrlMessageType::SetLogLevel,
        2 => UdevCtrlMessageType::StopExecQueue,
        3 => UdevCtrlMessageType::StartExecQueue,
        4 => UdevCtrlMessageType::Reload,
        5 => UdevCtrlMessageType::SetChildrenMax,
        _ => return Err(UdevCtrlError::InvalidMessage),
    };
    let value = match message_type {
        UdevCtrlMessageType::SetLogLevel | UdevCtrlMessageType::SetChildrenMax => {
            if rest.len() < 4 {
                return Err(UdevCtrlError::MissingPayload);
            }
            UdevCtrlValue::Integer(i32::from_le_bytes(rest[..4].try_into().unwrap()))
        }
        _ => UdevCtrlValue::Text(String::from_utf8_lossy(rest).into_owned()),
    };
    Ok(UdevCtrlMessage {
        message_type,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrips_integer_message() {
        let msg = UdevCtrlMessage {
            message_type: UdevCtrlMessageType::SetLogLevel,
            value: UdevCtrlValue::Integer(7),
        };
        assert_eq!(decode_message(&encode_message(&msg)).unwrap(), msg);
    }
    #[test]
    fn roundtrips_text_message() {
        let msg = UdevCtrlMessage {
            message_type: UdevCtrlMessageType::Reload,
            value: UdevCtrlValue::Text("now".into()),
        };
        assert_eq!(decode_message(&encode_message(&msg)).unwrap(), msg);
    }
    #[test]
    fn rejects_unknown_type() {
        assert_eq!(decode_message(&[99]), Err(UdevCtrlError::InvalidMessage));
    }
}
