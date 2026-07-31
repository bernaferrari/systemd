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
// These are the sd-bus/D-Bus protocol limits used by the C parser.
const MAX_OBJECT_PATH_LENGTH: usize = 64 * 1024;
const MAX_NAME_LENGTH: usize = 255;
const MAX_SIGNATURE_LENGTH: usize = 255;
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
        let (first, first_end) = decode_string(self.endian, &self.body, 0)?;
        let offset = align_to(first_end, 4)?;
        if offset > self.body.len() {
            return Err(WireError::Truncated);
        }
        if self.body[first_end..offset].iter().any(|byte| *byte != 0) {
            return Err(WireError::InvalidBody);
        }
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
    padding_error: WireError,
) -> Result<String, WireError> {
    let length = if signature {
        usize::from(read_u8(bytes, offset, limit)?)
    } else {
        let aligned = align_to(*offset, 4)?;
        validate_zero_padding(bytes, *offset, aligned, padding_error)?;
        *offset = aligned;
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
    let value = decode_marshaled_text(
        endian,
        bytes,
        &mut offset,
        bytes.len(),
        false,
        WireError::InvalidBody,
    )?;
    Ok((value, offset))
}

fn validate_zero_padding(
    bytes: &[u8],
    start: usize,
    end: usize,
    padding_error: WireError,
) -> Result<(), WireError> {
    let padding = checked_range(
        start,
        end.checked_sub(start).ok_or(WireError::Overflow)?,
        bytes.len(),
    )?;
    if bytes[padding].iter().any(|byte| *byte != 0) {
        return Err(padding_error);
    }
    Ok(())
}

fn is_ascii_alpha(byte: u8) -> bool {
    byte.is_ascii_alphabetic()
}

fn is_ascii_name_byte(byte: u8) -> bool {
    is_ascii_alpha(byte) || byte.is_ascii_digit() || byte == b'_'
}

fn object_path_is_valid(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() > MAX_OBJECT_PATH_LENGTH || bytes.first() != Some(&b'/') {
        return false;
    }
    if bytes == b"/" {
        return true;
    }

    let mut previous_was_slash = true;
    for byte in &bytes[1..] {
        if *byte == b'/' {
            if previous_was_slash {
                return false;
            }
            previous_was_slash = true;
        } else if is_ascii_name_byte(*byte) {
            previous_was_slash = false;
        } else {
            return false;
        }
    }
    !previous_was_slash
}

fn interface_name_is_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_LENGTH {
        return false;
    }

    let mut at_label_start = true;
    let mut found_dot = false;
    for byte in bytes {
        if *byte == b'.' {
            if at_label_start {
                return false;
            }
            found_dot = true;
            at_label_start = true;
        } else if is_ascii_alpha(*byte)
            || (!at_label_start && byte.is_ascii_digit())
            || *byte == b'_'
        {
            at_label_start = false;
        } else {
            return false;
        }
    }
    found_dot && !at_label_start
}

fn service_name_is_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_LENGTH {
        return false;
    }

    let unique = bytes[0] == b':';
    let mut at_label_start = true;
    let mut found_dot = false;
    for byte in &bytes[if unique { 1 } else { 0 }..] {
        if *byte == b'.' {
            if at_label_start {
                return false;
            }
            found_dot = true;
            at_label_start = true;
        } else if is_ascii_alpha(*byte)
            || ((!at_label_start || unique) && byte.is_ascii_digit())
            || matches!(*byte, b'_' | b'-')
        {
            at_label_start = false;
        } else {
            return false;
        }
    }
    found_dot && !at_label_start
}

fn member_name_is_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_NAME_LENGTH
        && bytes.iter().all(|byte| is_ascii_name_byte(*byte))
}

fn is_basic_signature_type(byte: u8) -> bool {
    matches!(
        byte,
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g' | b'h'
    )
}

fn signature_element_length(
    signature: &[u8],
    offset: usize,
    allow_dict_entry: bool,
    array_depth: usize,
    struct_depth: usize,
) -> Option<usize> {
    let current = *signature.get(offset)?;
    if is_basic_signature_type(current) || current == b'v' {
        return Some(1);
    }
    if current == b'a' {
        if array_depth >= 32 {
            return None;
        }
        return signature_element_length(
            signature,
            offset + 1,
            true,
            array_depth + 1,
            struct_depth,
        )
        .and_then(|length| length.checked_add(1));
    }
    if current == b'(' {
        if struct_depth >= 32 {
            return None;
        }
        let mut position = offset + 1;
        while *signature.get(position)? != b')' {
            position = position.checked_add(signature_element_length(
                signature,
                position,
                false,
                array_depth,
                struct_depth + 1,
            )?)?;
        }
        return (position > offset + 1).then_some(position - offset + 1);
    }
    if current == b'{' && allow_dict_entry {
        if struct_depth >= 32 {
            return None;
        }
        let mut position = offset + 1;
        let mut elements = 0usize;
        while *signature.get(position)? != b'}' {
            if elements == 0 && !is_basic_signature_type(*signature.get(position)?) {
                return None;
            }
            position = position.checked_add(signature_element_length(
                signature,
                position,
                false,
                array_depth,
                struct_depth + 1,
            )?)?;
            elements = elements.checked_add(1)?;
        }
        return (elements == 2).then_some(position - offset + 1);
    }
    None
}

fn signature_is_valid(signature: &str) -> bool {
    let bytes = signature.as_bytes();
    if bytes.len() > MAX_SIGNATURE_LENGTH {
        return false;
    }

    let mut offset = 0;
    while offset < bytes.len() {
        let Some(length) = signature_element_length(bytes, offset, true, 0, 0) else {
            return false;
        };
        let Some(next) = offset.checked_add(length) else {
            return false;
        };
        offset = next;
    }
    true
}

fn header_value_type_is_valid(code: u8, value_type: u8) -> bool {
    match code {
        HEADER_PATH => value_type == b'o',
        HEADER_INTERFACE | HEADER_MEMBER | HEADER_ERROR_NAME | HEADER_DESTINATION
        | HEADER_SENDER => value_type == b's',
        HEADER_REPLY_SERIAL | HEADER_UNIX_FDS => value_type == b'u',
        HEADER_SIGNATURE => value_type == b'g',
        _ => true,
    }
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
        let aligned = align_to(offset, 8)?;
        if aligned >= limit {
            return Err(WireError::InvalidHeader);
        }
        validate_zero_padding(bytes, offset, aligned, WireError::InvalidHeader)?;
        offset = aligned;

        let code = read_u8(bytes, &mut offset, limit)?;
        if code == 0 {
            return Err(WireError::InvalidHeader);
        }
        let signature_length = read_u8(bytes, &mut offset, limit)?;
        if signature_length != 1 {
            return Err(WireError::InvalidHeader);
        }
        let value_type = read_u8(bytes, &mut offset, limit)?;
        if read_u8(bytes, &mut offset, limit)? != 0 {
            return Err(WireError::InvalidHeader);
        }
        if !header_value_type_is_valid(code, value_type) {
            return Err(WireError::InvalidHeader);
        }

        let value = match value_type {
            b's' | b'o' => HeaderValue::Text(decode_marshaled_text(
                endian,
                bytes,
                &mut offset,
                limit,
                false,
                WireError::InvalidHeader,
            )?),
            b'g' => HeaderValue::Text(decode_marshaled_text(
                endian,
                bytes,
                &mut offset,
                limit,
                true,
                WireError::InvalidHeader,
            )?),
            b'u' => {
                let aligned = align_to(offset, 4)?;
                validate_zero_padding(bytes, offset, aligned, WireError::InvalidHeader)?;
                offset = aligned;
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
    // sd-bus accepts both currently defined protocol versions on input while
    // continuing to emit version 1 frames for this restricted server.
    if !matches!(input[3], 1 | 2) {
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

    if !object_path_is_valid(&path)
        || interface
            .as_deref()
            .is_some_and(|name| !interface_name_is_valid(name))
        || !member_name_is_valid(&member)
        || destination
            .as_deref()
            .is_some_and(|name| !service_name_is_valid(name))
        || sender
            .as_deref()
            .is_some_and(|name| !service_name_is_valid(name))
    {
        return Err(WireError::InvalidHeader);
    }
    if !signature_is_valid(&signature) {
        return Err(WireError::InvalidSignature);
    }
    // sd-bus reserves these names for its own local disconnect signaling;
    // external peers are never allowed to claim them.
    if path == "/org/freedesktop/DBus/Local"
        || interface.as_deref() == Some("org.freedesktop.DBus.Local")
        || sender.as_deref() == Some("org.freedesktop.DBus.Local")
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
    if value_type == b'o' && !object_path_is_valid(value) {
        return Err(WireError::InvalidBody);
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
    if !interface_name_is_valid(error_name) {
        return Err(WireError::InvalidHeader);
    }
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
    fn accepts_both_protocol_versions_sd_bus_accepts() {
        let mut version_two = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Peer",
            "Ping",
            "",
            &[],
        );
        version_two[3] = 2;
        assert!(decode_method_call(&version_two).unwrap().is_some());
        version_two[3] = 3;
        assert_eq!(
            decode_method_call(&version_two),
            Err(WireError::InvalidProtocolVersion)
        );
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
    fn accepts_the_same_header_name_and_signature_forms_as_sd_bus() {
        assert!(object_path_is_valid("/"));
        assert!(object_path_is_valid("/org/freedesktop/systemd1"));
        assert!(!object_path_is_valid("/org//systemd1"));
        assert!(!object_path_is_valid("/org/systemd1/"));
        assert!(!object_path_is_valid("/org/systemd-1"));

        assert!(interface_name_is_valid("org.freedesktop.systemd1"));
        assert!(!interface_name_is_valid("org..systemd1"));
        assert!(!interface_name_is_valid("1org.systemd"));
        assert!(!interface_name_is_valid("org.systemd-1"));
        assert!(service_name_is_valid("org.freedesktop.systemd1"));
        assert!(service_name_is_valid(":1.42"));
        assert!(!service_name_is_valid("org..systemd1"));
        assert!(!service_name_is_valid("1org.systemd"));
        assert!(member_name_is_valid("StartUnit"));
        assert!(!member_name_is_valid("Start-Unit"));

        assert!(signature_is_valid(""));
        assert!(signature_is_valid("a{sv}"));
        assert!(signature_is_valid("(ss)"));
        assert!(!signature_is_valid("a"));
        assert!(!signature_is_valid("()"));
        assert!(!signature_is_valid("{ss"));
        assert!(!signature_is_valid(&("a".repeat(33) + "s")));
    }

    #[test]
    fn rejects_invalid_header_values_before_dispatch() {
        let mut invalid_path = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "Ping",
            "",
            &[],
        );
        let path_start = invalid_path
            .windows(b"/org/freedesktop/systemd1".len())
            .position(|window| window == b"/org/freedesktop/systemd1")
            .unwrap();
        invalid_path[path_start + 1] = b'/';
        assert_eq!(
            decode_method_call(&invalid_path),
            Err(WireError::InvalidHeader)
        );

        let mut invalid_member = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "Ping",
            "",
            &[],
        );
        let member_start = invalid_member
            .windows(b"Ping".len())
            .position(|window| window == b"Ping")
            .unwrap();
        invalid_member[member_start + 2] = b'-';
        assert_eq!(
            decode_method_call(&invalid_member),
            Err(WireError::InvalidHeader)
        );

        let mut invalid_signature = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "Ping",
            "a",
            &[],
        );
        assert_eq!(
            decode_method_call(&invalid_signature),
            Err(WireError::InvalidSignature)
        );
        // The wire type for PATH is object path, not string. sd-bus rejects
        // the wrong variant even when the payload itself is a valid path.
        invalid_signature[16 + 2] = b's';
        assert_eq!(
            decode_method_call(&invalid_signature),
            Err(WireError::InvalidHeader)
        );
    }

    #[test]
    fn rejects_nonzero_header_and_body_alignment_padding() {
        let mut fields = Vec::new();
        push_header_text(
            Endian::Little,
            &mut fields,
            HEADER_PATH,
            b'o',
            "/org/freedesktop/systemd1",
        )
        .unwrap();
        let padding_start = fields.len();
        push_header_text(Endian::Little, &mut fields, HEADER_MEMBER, b's', "Ping").unwrap();
        assert!(fields.len() > padding_start);
        fields[padding_start] = 1;
        let mut bad_header_padding = vec![b'l', MESSAGE_TYPE_METHOD_CALL, 0, PROTOCOL_VERSION];
        bad_header_padding.extend_from_slice(&0u32.to_le_bytes());
        bad_header_padding.extend_from_slice(&1u32.to_le_bytes());
        bad_header_padding.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        bad_header_padding.extend_from_slice(&fields);
        push_padding(&mut bad_header_padding, 8).unwrap();
        assert_eq!(
            decode_method_call(&bad_header_padding),
            Err(WireError::InvalidHeader)
        );

        let bytes = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartUnit",
            "ss",
            &["x", "replace"],
        );
        let (call, _) = decode_method_call(&bytes).unwrap().unwrap();
        assert_eq!(
            call.decode_two_strings(),
            Ok(("x".into(), "replace".into()))
        );

        let mut bad_body_padding = bytes;
        let header_length =
            u32::from_le_bytes(bad_body_padding[12..16].try_into().unwrap()) as usize;
        let body_offset = align_to(PRIMARY_HEADER_SIZE + header_length, 8).unwrap();
        let first_value = body_offset + 4;
        assert_eq!(&bad_body_padding[first_value..first_value + 2], b"x\0");
        bad_body_padding[first_value + 2] = 1;
        let (call, _) = decode_method_call(&bad_body_padding).unwrap().unwrap();
        assert_eq!(call.decode_two_strings(), Err(WireError::InvalidBody));
    }

    #[test]
    fn rejects_local_reserved_names_and_invalid_outbound_names() {
        let local = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/DBus/Local",
            "org.freedesktop.systemd1.Manager",
            "Ping",
            "",
            &[],
        );
        assert_eq!(decode_method_call(&local), Err(WireError::InvalidHeader));
        assert_eq!(
            encode_text_reply(Endian::Little, 1, 1, b'o', "/bad-path"),
            Err(WireError::InvalidBody)
        );
        assert_eq!(
            encode_error_reply(Endian::Little, 1, 1, "invalid", "bad"),
            Err(WireError::InvalidHeader)
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
