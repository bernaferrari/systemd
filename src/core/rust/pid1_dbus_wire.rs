// SPDX-License-Identifier: LGPL-2.1-or-later

//! Checked D-Bus wire subset used by PID 1's direct private connection.
//!
//! This is not a general sd-bus replacement. It accepts complete method-call
//! frames with the standard scalar header fields and string/object-path
//! bodies needed by the deliberately small private-manager surface. It rejects
//! file descriptors, containers, malformed alignment, duplicate fields, and
//! messages beyond sd-bus' 128 MiB limit before allocating from declared
//! lengths. Every read is bounds checked and this module contains no `unsafe`.

use std::collections::BTreeMap;

const PRIMARY_HEADER_SIZE: usize = 16;
const MAX_MESSAGE_SIZE: usize = 128 * 1024 * 1024;
const PROTOCOL_VERSION: u8 = 1;
const MESSAGE_TYPE_METHOD_CALL: u8 = 1;
const MESSAGE_TYPE_METHOD_RETURN: u8 = 2;
const MESSAGE_TYPE_ERROR: u8 = 3;

const HEADER_PATH: u8 = 1;
const HEADER_INTERFACE: u8 = 2;
const HEADER_MEMBER: u8 = 3;
const HEADER_ERROR_NAME: u8 = 4;
const HEADER_REPLY_SERIAL: u8 = 5;
const HEADER_DESTINATION: u8 = 6;
const HEADER_SENDER: u8 = 7;
const HEADER_SIGNATURE: u8 = 8;
const HEADER_UNIX_FDS: u8 = 9;

const SYSTEMD_SENDER: &str = "org.freedesktop.systemd1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    fn marker(self) -> u8 {
        match self {
            Self::Little => b'l',
            Self::Big => b'B',
        }
    }

    fn read_u32(self, bytes: &[u8]) -> Result<u32, WireError> {
        let bytes: [u8; 4] = bytes.try_into().map_err(|_| WireError::Truncated)?;
        Ok(match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        })
    }

    fn push_u32(self, output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        });
    }
}

impl TryFrom<u8> for Endian {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            b'l' => Ok(Self::Little),
            b'B' => Ok(Self::Big),
            _ => Err(WireError::InvalidEndian),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    InvalidEndian,
    InvalidMessageType,
    InvalidProtocolVersion,
    InvalidSerial,
    InvalidHeader,
    DuplicateHeader(u8),
    MissingHeader(&'static str),
    UnsupportedHeaderType(u8),
    UnsupportedUnixFds,
    InvalidUtf8,
    InvalidSignature,
    InvalidBody,
    MessageTooLarge,
    Overflow,
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeaderValue {
    Text(String),
    U32(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodCall {
    pub endian: Endian,
    pub flags: u8,
    pub serial: u32,
    pub path: String,
    pub interface: Option<String>,
    pub member: String,
    pub destination: Option<String>,
    pub sender: Option<String>,
    pub signature: String,
    body: Vec<u8>,
}

impl MethodCall {
    pub const fn no_reply_expected(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn decode_no_args(&self) -> Result<(), WireError> {
        if !self.signature.is_empty() || !self.body.is_empty() {
            return Err(WireError::InvalidBody);
        }
        Ok(())
    }

    pub fn decode_one_string(&self) -> Result<String, WireError> {
        if self.signature != "s" {
            return Err(WireError::InvalidSignature);
        }
        let (value, consumed) = decode_string(self.endian, &self.body, 0)?;
        if consumed != self.body.len() {
            return Err(WireError::InvalidBody);
        }
        Ok(value)
    }

    pub fn decode_two_strings(&self) -> Result<(String, String), WireError> {
        if self.signature != "ss" {
            return Err(WireError::InvalidSignature);
        }
        let (first, offset) = decode_string(self.endian, &self.body, 0)?;
        let offset = align_to(offset, 4)?;
        let (second, consumed) = decode_string(self.endian, &self.body, offset)?;
        if consumed != self.body.len() {
            return Err(WireError::InvalidBody);
        }
        Ok((first, second))
    }
}

fn align_to(value: usize, alignment: usize) -> Result<usize, WireError> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(WireError::Overflow)
}

fn checked_range(
    offset: usize,
    length: usize,
    limit: usize,
) -> Result<std::ops::Range<usize>, WireError> {
    let end = offset.checked_add(length).ok_or(WireError::Overflow)?;
    if end > limit {
        return Err(WireError::Truncated);
    }
    Ok(offset..end)
}

fn read_u8(bytes: &[u8], offset: &mut usize, limit: usize) -> Result<u8, WireError> {
    let value = *bytes.get(*offset).ok_or(WireError::Truncated)?;
    *offset = offset.checked_add(1).ok_or(WireError::Overflow)?;
    if *offset > limit {
        return Err(WireError::Truncated);
    }
    Ok(value)
}

fn decode_marshaled_text(
    endian: Endian,
    bytes: &[u8],
    offset: &mut usize,
    limit: usize,
    signature: bool,
) -> Result<String, WireError> {
    let length = if signature {
        usize::from(read_u8(bytes, offset, limit)?)
    } else {
        *offset = align_to(*offset, 4)?;
        let range = checked_range(*offset, 4, limit)?;
        let length =
            usize::try_from(endian.read_u32(&bytes[range])?).map_err(|_| WireError::Overflow)?;
        *offset = offset.checked_add(4).ok_or(WireError::Overflow)?;
        length
    };

    let range = checked_range(*offset, length, limit)?;
    let text = std::str::from_utf8(&bytes[range])
        .map_err(|_| WireError::InvalidUtf8)?
        .to_string();
    *offset = offset.checked_add(length).ok_or(WireError::Overflow)?;
    if read_u8(bytes, offset, limit)? != 0 || text.as_bytes().contains(&0) {
        return Err(WireError::InvalidHeader);
    }
    Ok(text)
}

fn decode_string(endian: Endian, bytes: &[u8], start: usize) -> Result<(String, usize), WireError> {
    let mut offset = start;
    let value = decode_marshaled_text(endian, bytes, &mut offset, bytes.len(), false)?;
    Ok((value, offset))
}

fn decode_headers(
    endian: Endian,
    bytes: &[u8],
    header_length: usize,
) -> Result<BTreeMap<u8, HeaderValue>, WireError> {
    let start = PRIMARY_HEADER_SIZE;
    let limit = start
        .checked_add(header_length)
        .ok_or(WireError::Overflow)?;
    let mut offset = start;
    let mut fields = BTreeMap::new();

    while offset < limit {
        offset = align_to(offset, 8)?;
        if offset == limit {
            break;
        }
        if offset > limit {
            return Err(WireError::InvalidHeader);
        }

        let code = read_u8(bytes, &mut offset, limit)?;
        let signature_length = read_u8(bytes, &mut offset, limit)?;
        if signature_length != 1 {
            return Err(WireError::InvalidHeader);
        }
        let value_type = read_u8(bytes, &mut offset, limit)?;
        if read_u8(bytes, &mut offset, limit)? != 0 {
            return Err(WireError::InvalidHeader);
        }

        let value = match value_type {
            b's' | b'o' => HeaderValue::Text(decode_marshaled_text(
                endian,
                bytes,
                &mut offset,
                limit,
                false,
            )?),
            b'g' => HeaderValue::Text(decode_marshaled_text(
                endian,
                bytes,
                &mut offset,
                limit,
                true,
            )?),
            b'u' => {
                offset = align_to(offset, 4)?;
                let range = checked_range(offset, 4, limit)?;
                offset = offset.checked_add(4).ok_or(WireError::Overflow)?;
                HeaderValue::U32(endian.read_u32(&bytes[range])?)
            }
            other => return Err(WireError::UnsupportedHeaderType(other)),
        };

        if fields.insert(code, value).is_some() {
            return Err(WireError::DuplicateHeader(code));
        }
    }

    Ok(fields)
}

fn take_text(
    fields: &mut BTreeMap<u8, HeaderValue>,
    code: u8,
) -> Result<Option<String>, WireError> {
    match fields.remove(&code) {
        None => Ok(None),
        Some(HeaderValue::Text(value)) => Ok(Some(value)),
        Some(HeaderValue::U32(_)) => Err(WireError::InvalidHeader),
    }
}

fn take_u32(fields: &mut BTreeMap<u8, HeaderValue>, code: u8) -> Result<Option<u32>, WireError> {
    match fields.remove(&code) {
        None => Ok(None),
        Some(HeaderValue::U32(value)) => Ok(Some(value)),
        Some(HeaderValue::Text(_)) => Err(WireError::InvalidHeader),
    }
}

/// Decode one complete D-Bus method-call frame, retaining incomplete input.
pub fn decode_method_call(input: &[u8]) -> Result<Option<(MethodCall, usize)>, WireError> {
    if input.len() < PRIMARY_HEADER_SIZE {
        return Ok(None);
    }

    let endian = Endian::try_from(input[0])?;
    if input[1] != MESSAGE_TYPE_METHOD_CALL {
        return Err(WireError::InvalidMessageType);
    }
    if input[3] != PROTOCOL_VERSION {
        return Err(WireError::InvalidProtocolVersion);
    }

    let body_length =
        usize::try_from(endian.read_u32(&input[4..8])?).map_err(|_| WireError::Overflow)?;
    let serial = endian.read_u32(&input[8..12])?;
    if serial == 0 {
        return Err(WireError::InvalidSerial);
    }
    let header_length =
        usize::try_from(endian.read_u32(&input[12..16])?).map_err(|_| WireError::Overflow)?;
    let header_end = PRIMARY_HEADER_SIZE
        .checked_add(header_length)
        .ok_or(WireError::Overflow)?;
    let body_offset = align_to(header_end, 8)?;
    let message_length = body_offset
        .checked_add(body_length)
        .ok_or(WireError::Overflow)?;
    if message_length > MAX_MESSAGE_SIZE {
        return Err(WireError::MessageTooLarge);
    }
    if input.len() < message_length {
        return Ok(None);
    }

    let mut fields = decode_headers(endian, input, header_length)?;
    let path = take_text(&mut fields, HEADER_PATH)?.ok_or(WireError::MissingHeader("path"))?;
    let interface = take_text(&mut fields, HEADER_INTERFACE)?;
    let member =
        take_text(&mut fields, HEADER_MEMBER)?.ok_or(WireError::MissingHeader("member"))?;
    let destination = take_text(&mut fields, HEADER_DESTINATION)?;
    let sender = take_text(&mut fields, HEADER_SENDER)?;
    let signature = take_text(&mut fields, HEADER_SIGNATURE)?.unwrap_or_default();
    if take_u32(&mut fields, HEADER_UNIX_FDS)?.unwrap_or(0) != 0 {
        return Err(WireError::UnsupportedUnixFds);
    }
    // Method calls cannot carry reply/error metadata. Unknown standard or
    // extension fields are rejected because this subset cannot safely skip
    // arbitrary variant types.
    if fields.contains_key(&HEADER_ERROR_NAME)
        || fields.contains_key(&HEADER_REPLY_SERIAL)
        || !fields.is_empty()
    {
        return Err(WireError::InvalidHeader);
    }

    let body = input[body_offset..message_length].to_vec();
    if body.is_empty() != signature.is_empty() {
        return Err(WireError::InvalidSignature);
    }

    Ok(Some((
        MethodCall {
            endian,
            flags: input[2],
            serial,
            path,
            interface,
            member,
            destination,
            sender,
            signature,
            body,
        },
        message_length,
    )))
}

fn push_padding(output: &mut Vec<u8>, alignment: usize) -> Result<(), WireError> {
    let aligned = align_to(output.len(), alignment)?;
    output.resize(aligned, 0);
    Ok(())
}

fn push_marshaled_text(
    endian: Endian,
    output: &mut Vec<u8>,
    value: &str,
    signature: bool,
) -> Result<(), WireError> {
    if value.as_bytes().contains(&0) {
        return Err(WireError::InvalidUtf8);
    }
    if signature {
        let length = u8::try_from(value.len()).map_err(|_| WireError::MessageTooLarge)?;
        output.push(length);
    } else {
        push_padding(output, 4)?;
        let length = u32::try_from(value.len()).map_err(|_| WireError::MessageTooLarge)?;
        endian.push_u32(output, length);
    }
    output.extend_from_slice(value.as_bytes());
    output.push(0);
    Ok(())
}

fn push_header_text(
    endian: Endian,
    fields: &mut Vec<u8>,
    code: u8,
    value_type: u8,
    value: &str,
) -> Result<(), WireError> {
    push_padding(fields, 8)?;
    fields.extend_from_slice(&[code, 1, value_type, 0]);
    push_marshaled_text(endian, fields, value, value_type == b'g')
}

fn push_header_u32(
    endian: Endian,
    fields: &mut Vec<u8>,
    code: u8,
    value: u32,
) -> Result<(), WireError> {
    push_padding(fields, 8)?;
    fields.extend_from_slice(&[code, 1, b'u', 0]);
    push_padding(fields, 4)?;
    endian.push_u32(fields, value);
    Ok(())
}

fn encode_message(
    endian: Endian,
    message_type: u8,
    serial: u32,
    reply_serial: u32,
    error_name: Option<&str>,
    body_signature: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, WireError> {
    if serial == 0 || reply_serial == 0 {
        return Err(WireError::InvalidSerial);
    }

    let mut fields = Vec::new();
    if let Some(error_name) = error_name {
        push_header_text(endian, &mut fields, HEADER_ERROR_NAME, b's', error_name)?;
    }
    push_header_u32(endian, &mut fields, HEADER_REPLY_SERIAL, reply_serial)?;
    push_header_text(endian, &mut fields, HEADER_SENDER, b's', SYSTEMD_SENDER)?;
    if !body_signature.is_empty() {
        push_header_text(endian, &mut fields, HEADER_SIGNATURE, b'g', body_signature)?;
    }

    let body_length = u32::try_from(body.len()).map_err(|_| WireError::MessageTooLarge)?;
    let fields_length = u32::try_from(fields.len()).map_err(|_| WireError::MessageTooLarge)?;
    let mut output = Vec::with_capacity(
        PRIMARY_HEADER_SIZE
            .checked_add(fields.len())
            .and_then(|size| size.checked_add(7))
            .and_then(|size| size.checked_add(body.len()))
            .ok_or(WireError::Overflow)?,
    );
    output.extend_from_slice(&[endian.marker(), message_type, 0, PROTOCOL_VERSION]);
    endian.push_u32(&mut output, body_length);
    endian.push_u32(&mut output, serial);
    endian.push_u32(&mut output, fields_length);
    output.extend_from_slice(&fields);
    push_padding(&mut output, 8)?;
    output.extend_from_slice(&body);
    if output.len() > MAX_MESSAGE_SIZE {
        return Err(WireError::MessageTooLarge);
    }
    Ok(output)
}

pub fn encode_empty_reply(
    endian: Endian,
    serial: u32,
    reply_serial: u32,
) -> Result<Vec<u8>, WireError> {
    encode_message(
        endian,
        MESSAGE_TYPE_METHOD_RETURN,
        serial,
        reply_serial,
        None,
        "",
        Vec::new(),
    )
}

pub fn encode_text_reply(
    endian: Endian,
    serial: u32,
    reply_serial: u32,
    value_type: u8,
    value: &str,
) -> Result<Vec<u8>, WireError> {
    if !matches!(value_type, b's' | b'o') {
        return Err(WireError::InvalidSignature);
    }
    let mut body = Vec::new();
    push_marshaled_text(endian, &mut body, value, false)?;
    let signature = char::from(value_type).to_string();
    encode_message(
        endian,
        MESSAGE_TYPE_METHOD_RETURN,
        serial,
        reply_serial,
        None,
        &signature,
        body,
    )
}

pub fn encode_error_reply(
    endian: Endian,
    serial: u32,
    reply_serial: u32,
    error_name: &str,
    message: &str,
) -> Result<Vec<u8>, WireError> {
    let mut body = Vec::new();
    push_marshaled_text(endian, &mut body, message, false)?;
    encode_message(
        endian,
        MESSAGE_TYPE_ERROR,
        serial,
        reply_serial,
        Some(error_name),
        "s",
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_call(
        endian: Endian,
        serial: u32,
        path: &str,
        interface: &str,
        member: &str,
        signature: &str,
        body_values: &[&str],
    ) -> Vec<u8> {
        let mut fields = Vec::new();
        push_header_text(endian, &mut fields, HEADER_PATH, b'o', path).unwrap();
        push_header_text(endian, &mut fields, HEADER_INTERFACE, b's', interface).unwrap();
        push_header_text(endian, &mut fields, HEADER_MEMBER, b's', member).unwrap();
        if !signature.is_empty() {
            push_header_text(endian, &mut fields, HEADER_SIGNATURE, b'g', signature).unwrap();
        }
        let mut body = Vec::new();
        for value in body_values {
            push_padding(&mut body, 4).unwrap();
            push_marshaled_text(endian, &mut body, value, false).unwrap();
        }

        let mut output = vec![
            endian.marker(),
            MESSAGE_TYPE_METHOD_CALL,
            0,
            PROTOCOL_VERSION,
        ];
        endian.push_u32(&mut output, body.len() as u32);
        endian.push_u32(&mut output, serial);
        endian.push_u32(&mut output, fields.len() as u32);
        output.extend_from_slice(&fields);
        push_padding(&mut output, 8).unwrap();
        output.extend_from_slice(&body);
        output
    }

    #[test]
    fn decodes_little_and_big_endian_string_calls() {
        for endian in [Endian::Little, Endian::Big] {
            let bytes = encode_call(
                endian,
                7,
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "StartUnit",
                "ss",
                &["demo.service", "replace"],
            );
            let (call, consumed) = decode_method_call(&bytes).unwrap().unwrap();
            assert_eq!(consumed, bytes.len());
            assert_eq!(call.serial, 7);
            assert_eq!(call.member, "StartUnit");
            assert_eq!(
                call.decode_two_strings(),
                Ok(("demo.service".to_string(), "replace".to_string()))
            );
        }
    }

    #[test]
    fn incomplete_frames_are_retained_without_declared_length_allocation() {
        let bytes = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Peer",
            "Ping",
            "",
            &[],
        );
        for length in 0..bytes.len() {
            assert_eq!(decode_method_call(&bytes[..length]), Ok(None));
        }
    }

    #[test]
    fn rejects_oversized_declared_body_before_waiting_for_it() {
        let mut bytes = vec![b'l', MESSAGE_TYPE_METHOD_CALL, 0, PROTOCOL_VERSION];
        bytes.extend_from_slice(&(MAX_MESSAGE_SIZE as u32).to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode_method_call(&bytes), Err(WireError::MessageTooLarge));
    }

    #[test]
    fn rejects_nonzero_unix_fd_count() {
        let mut fields = Vec::new();
        push_header_text(
            Endian::Little,
            &mut fields,
            HEADER_PATH,
            b'o',
            "/org/freedesktop/systemd1",
        )
        .unwrap();
        push_header_text(Endian::Little, &mut fields, HEADER_MEMBER, b's', "Ping").unwrap();
        push_header_u32(Endian::Little, &mut fields, HEADER_UNIX_FDS, 1).unwrap();
        let mut bytes = vec![b'l', MESSAGE_TYPE_METHOD_CALL, 0, PROTOCOL_VERSION];
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&fields);
        push_padding(&mut bytes, 8).unwrap();
        assert_eq!(
            decode_method_call(&bytes),
            Err(WireError::UnsupportedUnixFds)
        );
    }

    #[test]
    fn encoded_replies_are_well_formed_and_bounded() {
        let empty = encode_empty_reply(Endian::Little, 1, 7).unwrap();
        assert_eq!(empty[1], MESSAGE_TYPE_METHOD_RETURN);
        let path = encode_text_reply(
            Endian::Little,
            2,
            8,
            b'o',
            "/org/freedesktop/systemd1/job/3",
        )
        .unwrap();
        assert_eq!(path[1], MESSAGE_TYPE_METHOD_RETURN);
        let error = encode_error_reply(
            Endian::Little,
            3,
            9,
            "org.freedesktop.DBus.Error.InvalidArgs",
            "bad arguments",
        )
        .unwrap();
        assert_eq!(error[1], MESSAGE_TYPE_ERROR);
    }
}
