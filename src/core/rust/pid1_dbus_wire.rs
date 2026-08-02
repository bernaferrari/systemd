// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (checked D-Bus wire scalar decoding).

//! Checked D-Bus wire subset used by PID 1's direct private connection.
//!
//! This is not a general sd-bus replacement. It accepts complete method-call
//! frames with the standard scalar header fields and string/object-path
//! bodies needed by the deliberately small private-manager surface. It rejects
//! received file descriptors at the live transport boundary, while exposing a
//! checked value decoder and an owned-descriptor handoff for a future recvmsg
//! transport. It rejects malformed alignment, duplicate fields, and messages
//! beyond sd-bus' 128 MiB limit before allocating from declared
//! lengths. [`PrivateBusWireAccumulator`] turns a nonblocking byte stream into
//! complete frames without discarding a partial or pipelined message. Its
//! caller obtains an exact read budget, so a disconnected private-bus
//! transport can apply backpressure before its per-connection memory cap is
//! reached. Every read is bounds checked and this module contains no `unsafe`.

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

const PRIMARY_HEADER_SIZE: usize = 16;
const MAX_MESSAGE_SIZE: usize = 128 * 1024 * 1024;
// These are the sd-bus/D-Bus protocol limits used by the C parser.
const MAX_OBJECT_PATH_LENGTH: usize = 64 * 1024;
const MAX_NAME_LENGTH: usize = 255;
const MAX_SIGNATURE_LENGTH: usize = 255;
const MAX_CONTAINER_ELEMENTS: usize = 64 * 1024;
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

    fn read_u16(self, bytes: &[u8]) -> Result<u16, WireError> {
        let bytes: [u8; 2] = bytes.try_into().map_err(|_| WireError::Truncated)?;
        Ok(match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        })
    }

    fn read_u64(self, bytes: &[u8]) -> Result<u64, WireError> {
        let bytes: [u8; 8] = bytes.try_into().map_err(|_| WireError::Truncated)?;
        Ok(match self {
            Self::Little => u64::from_le_bytes(bytes),
            Self::Big => u64::from_be_bytes(bytes),
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
    UnsupportedBodyType(u8),
    InvalidUnixFdIndex(u32),
    TooManyContainerElements,
    MessageTooLarge,
    Overflow,
    Truncated,
}

/// Failure while retaining a private-bus byte stream before method dispatch.
///
/// The accumulator never drops bytes after returning an error. A caller that
/// receives [`Self::FrameTooLarge`] or [`Self::BufferLimitExceeded`] should
/// close the untrusted peer instead of trying to consume more input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateBusWireAccumulatorError {
    /// The requested bound cannot hold a D-Bus primary header or exceeds the
    /// protocol-wide message maximum.
    InvalidCapacity { capacity: usize },
    /// Appending this read would exceed the configured per-connection bound.
    BufferLimitExceeded {
        buffered: usize,
        incoming: usize,
        capacity: usize,
    },
    /// The caller tried to read past the advertised per-frame read budget.
    ReadBudgetExceeded { incoming: usize, budget: usize },
    /// The allocator could not reserve space within the configured bound.
    AllocationFailed,
    /// The primary header declares a frame that cannot fit in this
    /// accumulator, even if it is otherwise a protocol-valid size.
    FrameTooLarge {
        frame_length: usize,
        capacity: usize,
    },
    /// The accumulated bytes fail D-Bus framing or method-call validation.
    Wire(WireError),
}

impl From<WireError> for PrivateBusWireAccumulatorError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// Bounded framing buffer for one authenticated private-bus stream.
///
/// Construct this with a cap appropriate for the transport's connection
/// limit, seed it with `AuthenticatedPrivateBusStream::buffered()` after the
/// D-Bus `BEGIN` handoff, and use [`Self::read_budget`] to limit every
/// nonblocking socket read. [`Self::take_next_method_call`] consumes exactly
/// one decoded frame; bytes belonging to a following frame remain buffered.
///
/// This deliberately performs no stream I/O or manager dispatch. Keeping it
/// separate lets the event source decide when a peer is readable while this
/// type enforces framing, backpressure, and bounded retained input.
#[derive(Debug)]
pub struct PrivateBusWireAccumulator {
    bytes: Vec<u8>,
    capacity: usize,
}

impl PrivateBusWireAccumulator {
    /// Create an empty accumulator with a strict per-connection byte cap.
    ///
    /// The cap includes complete frames awaiting dispatch and all partial or
    /// pipelined bytes. It must hold a primary header and is never permitted
    /// to exceed the D-Bus maximum message size.
    pub fn new(capacity: usize) -> Result<Self, PrivateBusWireAccumulatorError> {
        if !(PRIMARY_HEADER_SIZE..=MAX_MESSAGE_SIZE).contains(&capacity) {
            return Err(PrivateBusWireAccumulatorError::InvalidCapacity { capacity });
        }
        Ok(Self {
            bytes: Vec::new(),
            capacity,
        })
    }

    /// Create an accumulator while retaining bytes pipelined after D-Bus
    /// authentication completed.
    pub fn from_buffered(
        capacity: usize,
        buffered: &[u8],
    ) -> Result<Self, PrivateBusWireAccumulatorError> {
        let mut accumulator = Self::new(capacity)?;
        accumulator.append_within_capacity(buffered)?;
        Ok(accumulator)
    }

    /// Retained input, including an incomplete first frame and any following
    /// pipelined frames. The slice is never mutated by an unsuccessful call.
    pub fn buffered(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the accumulator and return every byte not yet dispatched.
    pub fn into_buffered(self) -> Vec<u8> {
        self.bytes
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn remaining_capacity(&self) -> usize {
        self.capacity - self.bytes.len()
    }

    /// Maximum number of bytes the transport may read without buffering past
    /// the current frame or the configured cap.
    ///
    /// A zero result is backpressure: a complete first frame must be consumed
    /// with [`Self::take_next_method_call`] before reading again. This method
    /// checks the primary header as soon as it is available, allowing a peer
    /// that declares a frame larger than the configured cap to be rejected
    /// without waiting for or allocating its body.
    pub fn read_budget(&self) -> Result<usize, PrivateBusWireAccumulatorError> {
        let Some(frame_length) = frame_length_from_primary(&self.bytes)? else {
            return Ok(self.remaining_capacity());
        };
        if frame_length > self.capacity {
            return Err(PrivateBusWireAccumulatorError::FrameTooLarge {
                frame_length,
                capacity: self.capacity,
            });
        }
        if self.bytes.len() >= frame_length {
            return Ok(0);
        }
        Ok((frame_length - self.bytes.len()).min(self.remaining_capacity()))
    }

    /// Retain bytes obtained from a single nonblocking stream read.
    ///
    /// Callers should pass at most [`Self::read_budget`] bytes. This method
    /// enforces that contract atomically, preserving all bytes already
    /// retained for later disconnect diagnostics or orderly teardown.
    pub fn receive(&mut self, input: &[u8]) -> Result<(), PrivateBusWireAccumulatorError> {
        let budget = self.read_budget()?;
        if input.len() > budget {
            return Err(PrivateBusWireAccumulatorError::ReadBudgetExceeded {
                incoming: input.len(),
                budget,
            });
        }
        self.append_within_capacity(input)
    }

    fn append_within_capacity(
        &mut self,
        input: &[u8],
    ) -> Result<(), PrivateBusWireAccumulatorError> {
        let buffered = self.bytes.len();
        let total = buffered.checked_add(input.len()).ok_or(
            PrivateBusWireAccumulatorError::BufferLimitExceeded {
                buffered,
                incoming: input.len(),
                capacity: self.capacity,
            },
        )?;
        if total > self.capacity {
            return Err(PrivateBusWireAccumulatorError::BufferLimitExceeded {
                buffered,
                incoming: input.len(),
                capacity: self.capacity,
            });
        }
        self.bytes
            .try_reserve_exact(input.len())
            .map_err(|_| PrivateBusWireAccumulatorError::AllocationFailed)?;
        self.bytes.extend_from_slice(input);
        Ok(())
    }

    /// Decode and remove one complete method-call frame, if available.
    ///
    /// Invalid or incomplete frames remain byte-for-byte available to the
    /// caller. Only a successfully decoded frame is removed.
    pub fn take_next_method_call(
        &mut self,
    ) -> Result<Option<MethodCall>, PrivateBusWireAccumulatorError> {
        let Some(frame_length) = frame_length_from_primary(&self.bytes)? else {
            return Ok(None);
        };
        if frame_length > self.capacity {
            return Err(PrivateBusWireAccumulatorError::FrameTooLarge {
                frame_length,
                capacity: self.capacity,
            });
        }
        if self.bytes.len() < frame_length {
            return Ok(None);
        }

        let (call, consumed) = decode_method_call(&self.bytes)?
            .ok_or(PrivateBusWireAccumulatorError::Wire(WireError::Truncated))?;
        debug_assert_eq!(consumed, frame_length);
        self.bytes.drain(..consumed);
        Ok(Some(call))
    }
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

/// One checked D-Bus value decoded from an already bounded method-call body.
///
/// This is intentionally an owned representation. It never retains a slice
/// into a socket buffer, so a caller cannot outlive a connection's input
/// ownership or accidentally retain unvalidated D-Bus padding.
#[derive(Debug, Clone, PartialEq)]
pub enum DbusValue {
    Byte(u8),
    Bool(bool),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    U32(u32),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    String(String),
    ObjectPath(String),
    Signature(String),
    /// Index into the SCM_RIGHTS attachment set for this one message. The
    /// current stream transport rejects attached FDs; a future recvmsg owner
    /// must resolve this through ReceivedUnixFds exactly once.
    UnixFdIndex(u32),
    Array(Vec<DbusValue>),
    Struct(Vec<DbusValue>),
    Variant {
        signature: String,
        value: Box<DbusValue>,
    },
}

/// Owns SCM_RIGHTS descriptors received for exactly one D-Bus message.
///
/// Construction consumes the descriptor vector, and Self::take removes one
/// descriptor permanently. Thus neither a repeated D-Bus h index nor a
/// disconnect path can create a second Rust owner for the same descriptor.
/// The current private stream does not construct this type yet: it continues
/// to reject Unix-FD negotiation until its recvmsg framing path can retain
/// ancillary data with the matching byte range.
#[derive(Debug, Default)]
pub struct ReceivedUnixFds {
    descriptors: Vec<Option<OwnedFd>>,
}

impl ReceivedUnixFds {
    pub fn new(descriptors: Vec<OwnedFd>) -> Self {
        Self {
            descriptors: descriptors.into_iter().map(Some).collect(),
        }
    }

    pub const fn len(&self) -> usize {
        self.descriptors.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    pub fn take(&mut self, index: u32) -> Result<OwnedFd, WireError> {
        let slot = self
            .descriptors
            .get_mut(usize::try_from(index).map_err(|_| WireError::Overflow)?)
            .ok_or(WireError::InvalidUnixFdIndex(index))?;
        slot.take().ok_or(WireError::InvalidUnixFdIndex(index))
    }
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

    /// Decode one D-Bus unsigned 32-bit scalar (`u`). The body of a scalar
    /// starts at an 8-byte aligned message offset, so its required 4-byte
    /// alignment is already satisfied by the checked frame decoder.
    pub fn decode_one_u32(&self) -> Result<u32, WireError> {
        if self.signature != "u" {
            return Err(WireError::InvalidSignature);
        }
        if self.body.len() != 4 {
            return Err(WireError::InvalidBody);
        }
        self.endian.read_u32(&self.body)
    }

    /// Decode one D-Bus byte array (`ay`). The D-Bus array payload starts
    /// with its four-byte byte length; because a byte has alignment one, its
    /// elements immediately follow that length without additional padding.
    ///
    /// This intentionally returns an owned vector only after proving the
    /// declared length consumes the complete, already bounded message body.
    /// Callers that require a fixed-size value (such as `sd_id128_t`) must
    /// validate that size at their semantic boundary.
    pub fn decode_one_byte_array(&self) -> Result<Vec<u8>, WireError> {
        if self.signature != "ay" {
            return Err(WireError::InvalidSignature);
        }
        let length_bytes: [u8; 4] = self
            .body
            .get(..4)
            .ok_or(WireError::Truncated)?
            .try_into()
            .map_err(|_| WireError::Truncated)?;
        let length = usize::try_from(self.endian.read_u32(&length_bytes)?)
            .map_err(|_| WireError::Overflow)?;
        let end = 4usize.checked_add(length).ok_or(WireError::Overflow)?;
        if end != self.body.len() {
            return Err(WireError::InvalidBody);
        }
        Ok(self.body[4..].to_vec())
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

    /// Decode every body value selected by this message's validated signature.
    ///
    /// The current manager adapter continues to accept only its small scalar
    /// subset. This helper is a bounded, transport-neutral foundation for
    /// later API rows: it validates every D-Bus basic body type, arrays,
    /// structs, variants, object paths, and Unix-FD indices before an adapter
    /// chooses whether that API is supported. It does not accept SCM_RIGHTS
    /// itself.
    pub fn decode_values(&self) -> Result<Vec<DbusValue>, WireError> {
        let signature = self.signature.as_bytes();
        let mut signature_offset = 0;
        let mut body_offset = 0;
        let mut values = Vec::new();
        while signature_offset < signature.len() {
            let element_length = signature_element_length(signature, signature_offset, true, 0, 0)
                .ok_or(WireError::InvalidSignature)?;
            let element_end = signature_offset
                .checked_add(element_length)
                .ok_or(WireError::Overflow)?;
            values.push(decode_body_value(
                self.endian,
                &self.body,
                &mut body_offset,
                &signature[signature_offset..element_end],
                0,
            )?);
            signature_offset = element_end;
        }
        if body_offset != self.body.len() {
            return Err(WireError::InvalidBody);
        }
        Ok(values)
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

fn body_alignment(signature: &[u8]) -> Result<usize, WireError> {
    match signature.first().copied() {
        Some(b'y' | b'g' | b'v') => Ok(1),
        Some(b'n' | b'q') => Ok(2),
        Some(b'i' | b'u' | b'b' | b'h' | b's' | b'o') => Ok(4),
        Some(b'x' | b't' | b'd' | b'(' | b'{') => Ok(8),
        Some(b'a') => Ok(4),
        Some(other) => Err(WireError::UnsupportedBodyType(other)),
        None => Err(WireError::InvalidSignature),
    }
}

fn align_body_offset(bytes: &[u8], offset: &mut usize, alignment: usize) -> Result<(), WireError> {
    let aligned = align_to(*offset, alignment)?;
    if aligned > bytes.len() {
        return Err(WireError::Truncated);
    }
    validate_zero_padding(bytes, *offset, aligned, WireError::InvalidBody)?;
    *offset = aligned;
    Ok(())
}

fn decode_body_u32(endian: Endian, bytes: &[u8], offset: &mut usize) -> Result<u32, WireError> {
    align_body_offset(bytes, offset, 4)?;
    let range = checked_range(*offset, 4, bytes.len())?;
    *offset = offset.checked_add(4).ok_or(WireError::Overflow)?;
    endian.read_u32(&bytes[range])
}

fn decode_body_u16(endian: Endian, bytes: &[u8], offset: &mut usize) -> Result<u16, WireError> {
    align_body_offset(bytes, offset, 2)?;
    let range = checked_range(*offset, 2, bytes.len())?;
    *offset = offset.checked_add(2).ok_or(WireError::Overflow)?;
    endian.read_u16(&bytes[range])
}

fn decode_body_u64(endian: Endian, bytes: &[u8], offset: &mut usize) -> Result<u64, WireError> {
    align_body_offset(bytes, offset, 8)?;
    let range = checked_range(*offset, 8, bytes.len())?;
    *offset = offset.checked_add(8).ok_or(WireError::Overflow)?;
    endian.read_u64(&bytes[range])
}

fn decode_body_value(
    endian: Endian,
    bytes: &[u8],
    offset: &mut usize,
    signature: &[u8],
    depth: usize,
) -> Result<DbusValue, WireError> {
    if depth >= 32 {
        return Err(WireError::InvalidSignature);
    }
    let tag = *signature.first().ok_or(WireError::InvalidSignature)?;
    match tag {
        b'y' => {
            align_body_offset(bytes, offset, 1)?;
            let value = *bytes.get(*offset).ok_or(WireError::Truncated)?;
            *offset = offset.checked_add(1).ok_or(WireError::Overflow)?;
            Ok(DbusValue::Byte(value))
        }
        b'b' => {
            let value = decode_body_u32(endian, bytes, offset)?;
            match value {
                0 => Ok(DbusValue::Bool(false)),
                1 => Ok(DbusValue::Bool(true)),
                _ => Err(WireError::InvalidBody),
            }
        }
        b'n' => Ok(DbusValue::Int16(i16::from_ne_bytes(
            decode_body_u16(endian, bytes, offset)?.to_ne_bytes(),
        ))),
        b'q' => Ok(DbusValue::Uint16(decode_body_u16(endian, bytes, offset)?)),
        b'i' => Ok(DbusValue::Int32(i32::from_ne_bytes(
            decode_body_u32(endian, bytes, offset)?.to_ne_bytes(),
        ))),
        b'u' => Ok(DbusValue::U32(decode_body_u32(endian, bytes, offset)?)),
        b'x' => Ok(DbusValue::Int64(i64::from_ne_bytes(
            decode_body_u64(endian, bytes, offset)?.to_ne_bytes(),
        ))),
        b't' => Ok(DbusValue::Uint64(decode_body_u64(endian, bytes, offset)?)),
        b'd' => Ok(DbusValue::Double(f64::from_bits(decode_body_u64(
            endian, bytes, offset,
        )?))),
        b'h' => Ok(DbusValue::UnixFdIndex(decode_body_u32(
            endian, bytes, offset,
        )?)),
        b's' => Ok(DbusValue::String(decode_body_text(
            endian, bytes, offset, false,
        )?)),
        b'o' => {
            let path = decode_body_text(endian, bytes, offset, false)?;
            if !object_path_is_valid(&path) {
                return Err(WireError::InvalidBody);
            }
            Ok(DbusValue::ObjectPath(path))
        }
        b'g' => {
            let value = decode_body_text(endian, bytes, offset, true)?;
            if !signature_is_valid(&value) {
                return Err(WireError::InvalidSignature);
            }
            Ok(DbusValue::Signature(value))
        }
        b'a' => decode_body_array(endian, bytes, offset, signature, depth + 1),
        b'(' | b'{' => decode_body_struct(endian, bytes, offset, signature, depth + 1),
        b'v' => decode_body_variant(endian, bytes, offset, depth + 1),
        other => Err(WireError::UnsupportedBodyType(other)),
    }
}

fn decode_body_text(
    endian: Endian,
    bytes: &[u8],
    offset: &mut usize,
    signature: bool,
) -> Result<String, WireError> {
    decode_marshaled_text(
        endian,
        bytes,
        offset,
        bytes.len(),
        signature,
        WireError::InvalidBody,
    )
}

fn decode_body_array(
    endian: Endian,
    bytes: &[u8],
    offset: &mut usize,
    signature: &[u8],
    depth: usize,
) -> Result<DbusValue, WireError> {
    let element = signature.get(1..).ok_or(WireError::InvalidSignature)?;
    if signature_element_length(element, 0, true, 0, 0) != Some(element.len()) {
        return Err(WireError::InvalidSignature);
    }
    let size = usize::try_from(decode_body_u32(endian, bytes, offset)?)
        .map_err(|_| WireError::Overflow)?;
    align_body_offset(bytes, offset, body_alignment(element)?)?;
    let end = offset.checked_add(size).ok_or(WireError::Overflow)?;
    if end > bytes.len() {
        return Err(WireError::Truncated);
    }
    let mut values = Vec::new();
    while *offset < end {
        if values.len() == MAX_CONTAINER_ELEMENTS {
            return Err(WireError::TooManyContainerElements);
        }
        let previous = *offset;
        values.push(decode_body_value(endian, bytes, offset, element, depth)?);
        if *offset <= previous || *offset > end {
            return Err(WireError::InvalidBody);
        }
    }
    if *offset != end {
        return Err(WireError::InvalidBody);
    }
    Ok(DbusValue::Array(values))
}

fn decode_body_struct(
    endian: Endian,
    bytes: &[u8],
    offset: &mut usize,
    signature: &[u8],
    depth: usize,
) -> Result<DbusValue, WireError> {
    let closing = match signature.first() {
        Some(b'(') => b')',
        Some(b'{') => b'}',
        _ => return Err(WireError::InvalidSignature),
    };
    if signature.last().copied() != Some(closing) {
        return Err(WireError::InvalidSignature);
    }
    align_body_offset(bytes, offset, 8)?;
    let inner = &signature[1..signature.len() - 1];
    let mut signature_offset = 0;
    let mut values = Vec::new();
    while signature_offset < inner.len() {
        if values.len() == MAX_CONTAINER_ELEMENTS {
            return Err(WireError::TooManyContainerElements);
        }
        let length = signature_element_length(inner, signature_offset, false, 0, 0)
            .ok_or(WireError::InvalidSignature)?;
        let end = signature_offset
            .checked_add(length)
            .ok_or(WireError::Overflow)?;
        values.push(decode_body_value(
            endian,
            bytes,
            offset,
            &inner[signature_offset..end],
            depth,
        )?);
        signature_offset = end;
    }
    Ok(DbusValue::Struct(values))
}

fn decode_body_variant(
    endian: Endian,
    bytes: &[u8],
    offset: &mut usize,
    depth: usize,
) -> Result<DbusValue, WireError> {
    let signature = decode_body_text(endian, bytes, offset, true)?;
    let signature_bytes = signature.as_bytes();
    if signature_element_length(signature_bytes, 0, true, 0, 0) != Some(signature_bytes.len()) {
        return Err(WireError::InvalidSignature);
    }
    let value = decode_body_value(endian, bytes, offset, signature_bytes, depth)?;
    Ok(DbusValue::Variant {
        signature,
        value: Box::new(value),
    })
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

/// Return the full frame length once a primary header is available.
///
/// This intentionally validates every primary-header field needed to safely
/// calculate the length, but it does not inspect the variable-sized header or
/// body. Stream accumulation uses it to impose a local cap before collecting
/// a peer-controlled body length.
fn frame_length_from_primary(input: &[u8]) -> Result<Option<usize>, WireError> {
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
    if endian.read_u32(&input[8..12])? == 0 {
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
    Ok(Some(message_length))
}

/// Decode one complete D-Bus method-call frame, retaining incomplete input.
pub fn decode_method_call(input: &[u8]) -> Result<Option<(MethodCall, usize)>, WireError> {
    let Some(message_length) = frame_length_from_primary(input)? else {
        return Ok(None);
    };
    let endian = Endian::try_from(input[0])?;
    let serial = endian.read_u32(&input[8..12])?;
    if input.len() < message_length {
        return Ok(None);
    }

    let header_length =
        usize::try_from(endian.read_u32(&input[12..16])?).map_err(|_| WireError::Overflow)?;
    let header_end = PRIMARY_HEADER_SIZE
        .checked_add(header_length)
        .ok_or(WireError::Overflow)?;
    let body_offset = align_to(header_end, 8)?;

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
    use std::fs::File;
    use std::os::fd::AsRawFd;

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

    fn call_with_body(endian: Endian, signature: &str, body: Vec<u8>) -> MethodCall {
        MethodCall {
            endian,
            flags: 0,
            serial: 1,
            path: "/org/freedesktop/systemd1".to_string(),
            interface: Some("org.freedesktop.systemd1.Manager".to_string()),
            member: "Test".to_string(),
            destination: None,
            sender: None,
            signature: signature.to_string(),
            body,
        }
    }

    fn push_body_u32(endian: Endian, output: &mut Vec<u8>, value: u32) {
        push_padding(output, 4).unwrap();
        endian.push_u32(output, value);
    }

    fn push_body_u16(endian: Endian, output: &mut Vec<u8>, value: u16) {
        push_padding(output, 2).unwrap();
        output.extend_from_slice(&match endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        });
    }

    fn push_body_u64(endian: Endian, output: &mut Vec<u8>, value: u64) {
        push_padding(output, 8).unwrap();
        output.extend_from_slice(&match endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        });
    }

    #[test]
    fn decodes_every_scalar_signature_with_its_wire_alignment() {
        for endian in [Endian::Little, Endian::Big] {
            let mut body = vec![7];
            push_body_u16(endian, &mut body, (-2_i16) as u16);
            push_body_u16(endian, &mut body, 5);
            push_body_u32(
                endian,
                &mut body,
                u32::from_ne_bytes((-3_i32).to_ne_bytes()),
            );
            push_body_u32(endian, &mut body, 9);
            push_body_u64(
                endian,
                &mut body,
                u64::from_ne_bytes((-4_i64).to_ne_bytes()),
            );
            push_body_u64(endian, &mut body, 11);
            push_body_u64(endian, &mut body, 3.5_f64.to_bits());
            push_body_u32(endian, &mut body, 0);

            let values = call_with_body(endian, "ynqiuxtdh", body)
                .decode_values()
                .unwrap();
            assert_eq!(
                values,
                vec![
                    DbusValue::Byte(7),
                    DbusValue::Int16(-2),
                    DbusValue::Uint16(5),
                    DbusValue::Int32(-3),
                    DbusValue::U32(9),
                    DbusValue::Int64(-4),
                    DbusValue::Uint64(11),
                    DbusValue::Double(3.5),
                    DbusValue::UnixFdIndex(0),
                ]
            );
        }
    }

    #[test]
    fn decodes_bounded_arrays_structs_variants_and_object_paths() {
        for endian in [Endian::Little, Endian::Big] {
            let mut body = Vec::new();

            push_body_u32(endian, &mut body, 3);
            body.extend_from_slice(&[1, 2, 3]);

            push_padding(&mut body, 8).unwrap();
            push_body_u32(endian, &mut body, 42);
            push_marshaled_text(endian, &mut body, "/org/example/Unit", false).unwrap();

            push_marshaled_text(endian, &mut body, "o", true).unwrap();
            push_padding(&mut body, 4).unwrap();
            push_marshaled_text(endian, &mut body, "/org/example/Variant", false).unwrap();

            let call = call_with_body(endian, "ay(uo)v", body);
            assert_eq!(
                call.decode_values(),
                Ok(vec![
                    DbusValue::Array(vec![
                        DbusValue::Byte(1),
                        DbusValue::Byte(2),
                        DbusValue::Byte(3),
                    ]),
                    DbusValue::Struct(vec![
                        DbusValue::U32(42),
                        DbusValue::ObjectPath("/org/example/Unit".to_string()),
                    ]),
                    DbusValue::Variant {
                        signature: "o".to_string(),
                        value: Box::new(DbusValue::ObjectPath("/org/example/Variant".to_string())),
                    },
                ])
            );
        }
    }

    #[test]
    fn generic_value_decoder_rejects_bad_padding_and_invalid_object_paths() {
        let mut bad_padding = Vec::new();
        push_body_u32(Endian::Little, &mut bad_padding, 0);
        bad_padding.extend_from_slice(&[7, 0, 0, 0]);
        let call = call_with_body(Endian::Little, "a(u)", bad_padding);
        assert_eq!(call.decode_values(), Err(WireError::InvalidBody));

        let mut bad_path = Vec::new();
        push_marshaled_text(Endian::Little, &mut bad_path, "invalid", false).unwrap();
        let call = call_with_body(Endian::Little, "o", bad_path);
        assert_eq!(call.decode_values(), Err(WireError::InvalidBody));

        let mut truncated_array = Vec::new();
        push_body_u32(Endian::Little, &mut truncated_array, 2);
        truncated_array.push(1);
        let call = call_with_body(Endian::Little, "ay", truncated_array);
        assert_eq!(call.decode_values(), Err(WireError::Truncated));

        let mut invalid_variant = Vec::new();
        push_marshaled_text(Endian::Little, &mut invalid_variant, "(", true).unwrap();
        let call = call_with_body(Endian::Little, "v", invalid_variant);
        assert_eq!(call.decode_values(), Err(WireError::InvalidSignature));
    }

    #[test]
    fn received_unix_fds_transfer_each_descriptor_at_most_once() {
        let descriptor: OwnedFd = File::open("/dev/null").unwrap().into();
        let expected = descriptor.as_raw_fd();
        let mut attachments = ReceivedUnixFds::new(vec![descriptor]);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments.take(0).unwrap().as_raw_fd(), expected);
        assert_eq!(attachments.take(0), Err(WireError::InvalidUnixFdIndex(0)));
        assert_eq!(attachments.take(1), Err(WireError::InvalidUnixFdIndex(1)));
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
    fn accumulator_assembles_partial_reads_and_only_consumes_complete_frames() {
        let bytes = encode_call(
            Endian::Little,
            17,
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartUnit",
            "ss",
            &["demo.service", "replace"],
        );
        let mut accumulator = PrivateBusWireAccumulator::new(bytes.len()).unwrap();

        for byte in &bytes[..bytes.len() - 1] {
            assert_eq!(
                accumulator.read_budget(),
                Ok(accumulator.remaining_capacity())
            );
            accumulator.receive(std::slice::from_ref(byte)).unwrap();
            assert_eq!(accumulator.take_next_method_call(), Ok(None));
        }
        assert_eq!(accumulator.read_budget(), Ok(1));
        accumulator.receive(&bytes[bytes.len() - 1..]).unwrap();
        assert_eq!(accumulator.read_budget(), Ok(0));

        let call = accumulator.take_next_method_call().unwrap().unwrap();
        assert_eq!(call.serial, 17);
        assert_eq!(
            call.decode_two_strings(),
            Ok(("demo.service".into(), "replace".into()))
        );
        assert!(accumulator.buffered().is_empty());
        assert_eq!(accumulator.read_budget(), Ok(bytes.len()));
    }

    #[test]
    fn accumulator_preserves_pipelined_and_auth_handoff_bytes() {
        let first = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Peer",
            "Ping",
            "",
            &[],
        );
        let second = encode_call(
            Endian::Little,
            2,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Peer",
            "Ping",
            "",
            &[],
        );
        let split = second.len() / 2;
        let mut handoff = first.clone();
        handoff.extend_from_slice(&second[..split]);
        let mut accumulator =
            PrivateBusWireAccumulator::from_buffered(first.len() + second.len(), &handoff).unwrap();

        assert_eq!(accumulator.read_budget(), Ok(0));
        assert_eq!(
            accumulator.take_next_method_call().unwrap().unwrap().serial,
            1
        );
        assert_eq!(accumulator.buffered(), &second[..split]);
        assert_eq!(accumulator.read_budget(), Ok(second.len() - split));

        accumulator.receive(&second[split..]).unwrap();
        assert_eq!(
            accumulator.take_next_method_call().unwrap().unwrap().serial,
            2
        );
        assert!(accumulator.buffered().is_empty());
    }

    #[test]
    fn accumulator_reports_backpressure_and_rejects_overflow_atomically() {
        let bytes = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Peer",
            "Ping",
            "",
            &[],
        );
        let mut accumulator = PrivateBusWireAccumulator::new(bytes.len()).unwrap();
        accumulator.receive(&bytes[..8]).unwrap();
        let retained = accumulator.buffered().to_vec();
        let mut overflowing = bytes[8..].to_vec();
        overflowing.push(0);
        assert_eq!(
            accumulator.receive(&overflowing),
            Err(PrivateBusWireAccumulatorError::ReadBudgetExceeded {
                incoming: bytes.len() - 7,
                budget: bytes.len() - 8,
            })
        );
        assert_eq!(accumulator.buffered(), retained);

        // Respecting the advertised budget fills the pending frame and stops
        // the next socket read until dispatch consumes it.
        let budget = accumulator.read_budget().unwrap();
        assert_eq!(budget, bytes.len() - 8);
        accumulator.receive(&bytes[8..8 + budget]).unwrap();
        assert_eq!(accumulator.read_budget(), Ok(0));
        assert_eq!(
            accumulator.receive(&[0]),
            Err(PrivateBusWireAccumulatorError::ReadBudgetExceeded {
                incoming: 1,
                budget: 0,
            })
        );
    }

    #[test]
    fn accumulator_rejects_declared_frame_larger_than_local_cap_without_loss() {
        let bytes = encode_call(
            Endian::Little,
            1,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Peer",
            "Ping",
            "",
            &[],
        );
        let capacity = PRIMARY_HEADER_SIZE;
        let mut accumulator = PrivateBusWireAccumulator::new(capacity).unwrap();
        accumulator.receive(&bytes[..PRIMARY_HEADER_SIZE]).unwrap();
        let expected = PrivateBusWireAccumulatorError::FrameTooLarge {
            frame_length: bytes.len(),
            capacity,
        };
        assert_eq!(accumulator.read_budget(), Err(expected.clone()));
        assert_eq!(accumulator.take_next_method_call(), Err(expected));
        assert_eq!(accumulator.buffered(), &bytes[..PRIMARY_HEADER_SIZE]);
    }

    #[test]
    fn accumulator_validates_its_capacity() {
        let too_small = PRIMARY_HEADER_SIZE - 1;
        assert!(matches!(
            PrivateBusWireAccumulator::new(too_small),
            Err(PrivateBusWireAccumulatorError::InvalidCapacity { capacity }) if capacity == too_small
        ));
        let too_large = MAX_MESSAGE_SIZE + 1;
        assert!(matches!(
            PrivateBusWireAccumulator::new(too_large),
            Err(PrivateBusWireAccumulatorError::InvalidCapacity { capacity }) if capacity == too_large
        ));
        assert!(matches!(
            PrivateBusWireAccumulator::from_buffered(PRIMARY_HEADER_SIZE, &[0; 17]),
            Err(PrivateBusWireAccumulatorError::BufferLimitExceeded {
                buffered: 0,
                incoming: 17,
                capacity: PRIMARY_HEADER_SIZE,
            })
        ));
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
