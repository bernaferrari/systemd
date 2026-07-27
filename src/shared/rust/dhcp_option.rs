// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-GAP: the historical DHCPv4 option source/header no longer exist in this
// checkout. Current DHCP message and DHCPv6 option APIs use different public
// contracts, so this facade intentionally has no C authority until re-reviewed.
//
// DHCP option handling: TLV parsing, construction, search, removal, and
// overload-based multi-buffer append. Ported from the C implementation with
// idiomatic safe Rust and full bounds checking.

// ── Constants ─────────────────────────────────────────────────────────────

/// DHCP magic cookie (RFC 2131 §4.1)
pub const DHCP_MAGIC_COOKIE: u32 = 0x6382_5363;

/// Overload flag: use the `file` field for extra options (RFC 2132 §9.3)
pub const DHCP_OVERLOAD_FILE: u8 = 1;

/// Overload flag: use the `sname` field for extra options (RFC 2132 §9.3)
pub const DHCP_OVERLOAD_SNAME: u8 = 2;

/// Size of the `file` field in a DHCP message header
pub const DHCP_FILE_SIZE: usize = 128;

/// Size of the `sname` field in a DHCP message header
pub const DHCP_SNAME_SIZE: usize = 64;

/// Well-known option code: Pad (single byte, no length)
pub const SD_DHCP_OPTION_PAD: u8 = 0;

/// Well-known option code: End (single byte, no length)
pub const SD_DHCP_OPTION_END: u8 = 255;

/// Well-known option code: DHCP Message Type
pub const SD_DHCP_OPTION_MESSAGE_TYPE: u8 = 53;

/// Well-known option code: Error Message
pub const SD_DHCP_OPTION_ERROR_MESSAGE: u8 = 56;

/// Well-known option code: Option Overload
pub const SD_DHCP_OPTION_OVERLOAD: u8 = 52;

/// Well-known option code: User Class (RFC 3004)
pub const SD_DHCP_OPTION_USER_CLASS: u8 = 77;

/// Well-known option code: SIP Server (RFC 3361)
pub const SD_DHCP_OPTION_SIP_SERVER: u8 = 120;

/// Well-known option code: Vendor Specific Information (RFC 2132)
pub const SD_DHCP_OPTION_VENDOR_SPECIFIC: u8 = 43;

/// Well-known option code: Relay Agent Information (RFC 3046)
pub const SD_DHCP_OPTION_RELAY_AGENT_INFORMATION: u8 = 82;

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors returned by DHCP option operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOptionError {
    /// Buffer too small for the requested operation.
    NoBufferSpace,
    /// Malformed data or invalid argument.
    InvalidData,
    /// Requested option was not found.
    NotFound,
    /// Parsed options did not contain a DHCP Message Type.
    NoMessageType,
    /// Invalid UTF-8 in a string option.
    InvalidUtf8,
    /// Invalid hostname.
    InvalidHostname,
    /// Unsafe (control) characters in string.
    UnsafeString,
}

impl std::fmt::Display for DhcpOptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBufferSpace => write!(f, "no buffer space"),
            Self::InvalidData => write!(f, "invalid data"),
            Self::NotFound => write!(f, "option not found"),
            Self::NoMessageType => write!(f, "no DHCP message type found"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8"),
            Self::InvalidHostname => write!(f, "invalid hostname"),
            Self::UnsafeString => write!(f, "unsafe string content"),
        }
    }
}

impl std::error::Error for DhcpOptionError {}

// ── Enums ─────────────────────────────────────────────────────────────────

/// DHCP message types (RFC 2132 §9.6, plus extensions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
    ForceRenew = 9,
    LeaseQuery = 10,
    LeaseUnassigned = 11,
    LeaseUnknown = 12,
    LeaseActive = 13,
    BulkLeaseQuery = 14,
    LeaseQueryDone = 15,
    ActiveLeaseQuery = 16,
    LeaseQueryStatus = 17,
    Tls = 18,
}

impl DhcpMessageType {
    /// Convert a raw byte to a known message type.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            9 => Some(Self::ForceRenew),
            10 => Some(Self::LeaseQuery),
            11 => Some(Self::LeaseUnassigned),
            12 => Some(Self::LeaseUnknown),
            13 => Some(Self::LeaseActive),
            14 => Some(Self::BulkLeaseQuery),
            15 => Some(Self::LeaseQueryDone),
            16 => Some(Self::ActiveLeaseQuery),
            17 => Some(Self::LeaseQueryStatus),
            18 => Some(Self::Tls),
            _ => None,
        }
    }
}

/// Well-known DHCP option codes.
///
/// Not every valid code is represented; use raw `u8` for unlisted codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOptionCode {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DomainNameServer = 6,
    HostName = 12,
    DomainName = 15,
    RequestedIpAddress = 50,
    IpAddressLeaseTime = 51,
    Overload = 52,
    DhcpMessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    ErrorMessage = 56,
    MaximumMessageSize = 57,
    RenewalTime = 58,
    RebindingTime = 59,
    VendorClassIdentifier = 60,
    ClientIdentifier = 61,
    UserClass = 77,
    RelayAgentInformation = 82,
    ClientSystem = 93,
    ClientNdi = 94,
    Ldap = 95,
    PosixTimezone = 100,
    TzdbTimezone = 101,
    SipServer = 120,
    ClasslessStaticRoute = 121,
    End = 255,
}

impl DhcpOptionCode {
    /// Convert a raw byte to a well-known option code.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Pad),
            1 => Some(Self::SubnetMask),
            3 => Some(Self::Router),
            6 => Some(Self::DomainNameServer),
            12 => Some(Self::HostName),
            15 => Some(Self::DomainName),
            50 => Some(Self::RequestedIpAddress),
            51 => Some(Self::IpAddressLeaseTime),
            52 => Some(Self::Overload),
            53 => Some(Self::DhcpMessageType),
            54 => Some(Self::ServerIdentifier),
            55 => Some(Self::ParameterRequestList),
            56 => Some(Self::ErrorMessage),
            57 => Some(Self::MaximumMessageSize),
            58 => Some(Self::RenewalTime),
            59 => Some(Self::RebindingTime),
            60 => Some(Self::VendorClassIdentifier),
            61 => Some(Self::ClientIdentifier),
            77 => Some(Self::UserClass),
            82 => Some(Self::RelayAgentInformation),
            93 => Some(Self::ClientSystem),
            94 => Some(Self::ClientNdi),
            95 => Some(Self::Ldap),
            100 => Some(Self::PosixTimezone),
            101 => Some(Self::TzdbTimezone),
            120 => Some(Self::SipServer),
            121 => Some(Self::ClasslessStaticRoute),
            255 => Some(Self::End),
            _ => None,
        }
    }
}

// ── DHCP Option value ─────────────────────────────────────────────────────

/// A single DHCP option: code + raw data bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOption {
    pub code: u8,
    pub data: Vec<u8>,
}

impl DhcpOption {
    /// Create a new DHCP option.
    pub fn new(code: u8, data: Vec<u8>) -> Self {
        Self { code, data }
    }

    /// Create a new DHCP option from a well-known code.
    pub fn from_known(code: DhcpOptionCode, data: Vec<u8>) -> Self {
        Self {
            code: code as u8,
            data,
        }
    }

    /// Get the well-known option code, if this is a known code.
    pub fn known_code(&self) -> Option<DhcpOptionCode> {
        DhcpOptionCode::from_u8(self.code)
    }

    /// Parse one option from a byte slice starting at `offset`.
    ///
    /// On success returns the parsed option and advances `offset`.
    /// Returns `None` at end-of-buffer or on malformed data.
    pub fn parse(data: &[u8], offset: &mut usize) -> Option<Self> {
        if *offset >= data.len() {
            return None;
        }

        let code = data[*offset];
        *offset += 1;

        // PAD and END are single-byte (no length field).
        if code == SD_DHCP_OPTION_PAD {
            return Some(Self::new(SD_DHCP_OPTION_PAD, vec![]));
        }
        if code == SD_DHCP_OPTION_END {
            return Some(Self::new(SD_DHCP_OPTION_END, vec![]));
        }

        if *offset >= data.len() {
            return None;
        }

        let len = data[*offset] as usize;
        *offset += 1;

        if *offset + len > data.len() {
            return None;
        }

        let opt_data = data[*offset..*offset + len].to_vec();
        *offset += len;

        Some(Self::new(code, opt_data))
    }

    /// Serialize this option to bytes (code + length + data for normal
    /// options; just code for PAD/END).
    ///
    /// Returns [`DhcpOptionError::InvalidData`] when a normal option's data
    /// cannot be represented by the one-byte DHCP length field.
    pub fn serialize(&self) -> Result<Vec<u8>, DhcpOptionError> {
        let length = if self.code == SD_DHCP_OPTION_PAD || self.code == SD_DHCP_OPTION_END {
            None
        } else {
            Some(u8::try_from(self.data.len()).map_err(|_| DhcpOptionError::InvalidData)?)
        };

        let mut buf = Vec::with_capacity(if length.is_some() {
            2 + self.data.len()
        } else {
            1
        });
        buf.push(self.code);

        if let Some(length) = length {
            buf.push(length);
            buf.extend_from_slice(&self.data);
        }

        Ok(buf)
    }

    /// Interpret the data as a UTF-8 string (allows one trailing NUL).
    pub fn as_string(&self) -> Option<String> {
        let bytes = if self.data.last() == Some(&0) {
            &self.data[..self.data.len() - 1]
        } else {
            &self.data
        };
        std::str::from_utf8(bytes).ok().map(|s| s.to_owned())
    }

    /// Interpret the data as a 4-byte IPv4 address.
    pub fn as_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if self.data.len() != 4 {
            return None;
        }
        Some(std::net::Ipv4Addr::new(
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ))
    }

    /// Interpret the data as a big-endian u32.
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() != 4 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ]))
    }
}

// ── Low-level TLV append ──────────────────────────────────────────────────

/// Append a standard Type-Length-Value entry to a buffer.
///
/// `offset` is advanced past the written bytes. Returns an error if
/// the buffer is too small.
pub fn option_append_tlv(
    buf: &mut [u8],
    offset: &mut usize,
    code: u8,
    optval: &[u8],
) -> Result<(), DhcpOptionError> {
    let optlen = optval.len();
    if *offset + 2 + optlen > buf.len() {
        return Err(DhcpOptionError::NoBufferSpace);
    }

    buf[*offset] = code;
    buf[*offset + 1] = optlen as u8;
    buf[*offset + 2..*offset + 2 + optlen].copy_from_slice(optval);
    *offset += 2 + optlen;
    Ok(())
}

// ── Option length calculation ─────────────────────────────────────────────

/// Return the total byte length of the option at `offset` (code + len + data).
///
/// PAD and END options are 1 byte. Returns an error if the buffer is too
/// short to read the full option.
pub fn option_length(buf: &[u8], offset: usize) -> Result<usize, DhcpOptionError> {
    if offset >= buf.len() {
        return Err(DhcpOptionError::InvalidData);
    }

    let code = buf[offset];
    if code == SD_DHCP_OPTION_PAD || code == SD_DHCP_OPTION_END {
        return Ok(1);
    }

    if offset + 2 > buf.len() {
        return Err(DhcpOptionError::NoBufferSpace);
    }

    let len = buf[offset + 1] as usize;
    if offset + 2 + len > buf.len() {
        return Err(DhcpOptionError::NoBufferSpace);
    }

    Ok(2 + len)
}

// ── Append single option to buffer ────────────────────────────────────────

/// Append a single DHCP option to `buf` at `offset`.
///
/// Handles special encoding for:
/// - PAD / END: single byte, no length field.
/// - SIP Server: prepends an extra encoding byte (0x01 = domain list).
/// - Everything else: standard TLV.
///
/// Reserves 1 byte at the end for the mandatory END option.
pub fn option_append(
    buf: &mut [u8],
    offset: &mut usize,
    code: u8,
    optval: &[u8],
) -> Result<(), DhcpOptionError> {
    // Reserve 1 byte for the trailing END.
    let usable = if code != SD_DHCP_OPTION_END {
        buf.len().saturating_sub(1)
    } else {
        buf.len()
    };

    match code {
        SD_DHCP_OPTION_PAD | SD_DHCP_OPTION_END => {
            if *offset + 1 > usable {
                return Err(DhcpOptionError::NoBufferSpace);
            }
            buf[*offset] = code;
            *offset += 1;
        }
        SD_DHCP_OPTION_SIP_SERVER => {
            // SIP Server option: encoding byte (1) + data
            let total = 3 + optval.len();
            if *offset + total > usable {
                return Err(DhcpOptionError::NoBufferSpace);
            }
            buf[*offset] = code;
            buf[*offset + 1] = (optval.len() + 1) as u8;
            buf[*offset + 2] = 1; // encoding: domain name list
            buf[*offset + 3..*offset + 3 + optval.len()].copy_from_slice(optval);
            *offset += total;
        }
        _ => {
            // Standard TLV
            option_append_tlv(buf, offset, code, optval)?;
        }
    }

    Ok(())
}

// ── Find option ───────────────────────────────────────────────────────────

/// Find the first occurrence of `code` in `buf`.
///
/// Returns `(offset, total_byte_length)` on success.
pub fn find_option(buf: &[u8], code: u8) -> Result<(usize, usize), DhcpOptionError> {
    let mut offset = 0;
    while offset < buf.len() {
        let len = option_length(buf, offset)?;
        if buf[offset] == code {
            return Ok((offset, len));
        }
        offset += len;
    }
    Err(DhcpOptionError::NotFound)
}

// ── Remove option ─────────────────────────────────────────────────────────

/// Remove the first occurrence of `code` from `buf` in place.
///
/// Returns the new length of the used portion of `buf`.
pub fn remove_option(buf: &mut [u8], used_len: usize, code: u8) -> Result<usize, DhcpOptionError> {
    let (offset, opt_len) = find_option(&buf[..used_len], code)?;
    buf.copy_within(offset + opt_len..used_len, offset);
    Ok(used_len - opt_len)
}

// ── Append with overload support ──────────────────────────────────────────

/// DHCP message buffer abstraction for overload-aware option appending.
///
/// Models the three option areas in a DHCP message: `options`, `file`, and
/// `sname`, matching the structure in RFC 2131.
pub struct DhcpMessageBuffers<'a> {
    pub options: &'a mut [u8],
    pub file: &'a mut [u8],
    pub sname: &'a mut [u8],
}

/// Append a DHCP option to a message, using overload fields as overflow.
///
/// Tries `options` first. If it doesn't fit and `overload` allows it,
/// overflows into `file`, then `sname`. Each completed section is
/// terminated with an END option before moving on.
pub fn dhcp_option_append(
    msg: &mut DhcpMessageBuffers<'_>,
    offset: &mut usize,
    overload: u8,
    code: u8,
    optval: &[u8],
) -> Result<(), DhcpOptionError> {
    let use_file = (overload & DHCP_OVERLOAD_FILE) != 0;
    let use_sname = (overload & DHCP_OVERLOAD_SNAME) != 0;

    let options_size = msg.options.len();

    // Phase 1: try the main options buffer
    if *offset < options_size {
        let mut opt_off = *offset;
        if option_append(msg.options, &mut opt_off, code, optval).is_ok() {
            *offset = opt_off;
            return Ok(());
        }

        // Didn't fit — close the options buffer with END if we have overflow
        if use_file || use_sname {
            let mut end_off = opt_off;
            option_append(msg.options, &mut end_off, SD_DHCP_OPTION_END, &[])?;
            *offset = options_size;
        } else {
            return Err(DhcpOptionError::NoBufferSpace);
        }
    }

    // Phase 2: try the file buffer
    if use_file {
        let mut file_offset = *offset - options_size;
        if file_offset < msg.file.len() {
            if option_append(msg.file, &mut file_offset, code, optval).is_ok() {
                *offset = options_size + file_offset;
                return Ok(());
            }

            if use_sname {
                let mut end_off = file_offset;
                option_append(msg.file, &mut end_off, SD_DHCP_OPTION_END, &[])?;
                *offset = options_size + msg.file.len();
            } else {
                return Err(DhcpOptionError::NoBufferSpace);
            }
        }
    }

    // Phase 3: try the sname buffer
    if use_sname {
        let sname_start = options_size + if use_file { msg.file.len() } else { 0 };
        let mut sname_offset = *offset - sname_start;
        if sname_offset < msg.sname.len() {
            if option_append(msg.sname, &mut sname_offset, code, optval).is_ok() {
                *offset = sname_start + sname_offset;
                return Ok(());
            }
        }
    }

    Err(DhcpOptionError::NoBufferSpace)
}

// ── Parse helpers ─────────────────────────────────────────────────────────

/// Result of parsing a complete DHCP message's options.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedDhcpOptions {
    /// The DHCP message type byte (0 if not found).
    pub message_type: u8,
    /// The overload byte (0 if not found).
    pub overload: u8,
    /// Error message string, if present.
    pub error_message: Option<String>,
    /// All non-special options found, in order.
    pub options: Vec<DhcpOption>,
}

/// Parse all options from a single buffer.
///
/// Extracts message_type, overload, and error_message specially;
/// all other options are collected into `options`.
fn parse_one_buffer(buf: &[u8], into: &mut ParsedDhcpOptions) -> Result<(), DhcpOptionError> {
    let mut offset = 0;

    while offset < buf.len() {
        let code = buf[offset];
        offset += 1;

        match code {
            SD_DHCP_OPTION_PAD => continue,
            SD_DHCP_OPTION_END => return Ok(()),
            _ => {}
        }

        if offset >= buf.len() {
            return Err(DhcpOptionError::NoBufferSpace);
        }

        let len = buf[offset] as usize;
        offset += 1;

        if offset + len > buf.len() {
            return Err(DhcpOptionError::InvalidData);
        }

        let opt_data = &buf[offset..offset + len];

        match code {
            SD_DHCP_OPTION_MESSAGE_TYPE => {
                if len != 1 {
                    return Err(DhcpOptionError::InvalidData);
                }
                into.message_type = opt_data[0];
            }
            SD_DHCP_OPTION_OVERLOAD => {
                if len != 1 {
                    return Err(DhcpOptionError::InvalidData);
                }
                into.overload = opt_data[0];
            }
            SD_DHCP_OPTION_ERROR_MESSAGE => {
                if len == 0 {
                    return Err(DhcpOptionError::InvalidData);
                }
                // Allow one trailing NUL
                let trimmed = if opt_data.last() == Some(&0) {
                    &opt_data[..opt_data.len() - 1]
                } else {
                    opt_data
                };
                match std::str::from_utf8(trimmed) {
                    Ok(s) if is_ascii_printable(s) => {
                        into.error_message = Some(s.to_owned());
                    }
                    Ok(_) => return Err(DhcpOptionError::UnsafeString),
                    Err(_) => return Err(DhcpOptionError::InvalidUtf8),
                }
            }
            _ => {
                into.options.push(DhcpOption::new(code, opt_data.to_vec()));
            }
        }

        offset += len;
    }

    Ok(())
}

/// Parse options from a full DHCP message, following overload pointers.
///
/// `options_buf` is the main options area, `file_buf` and `sname_buf` are
/// the overload fields. Returns the parsed result including the mandatory
/// message type.
pub fn dhcp_option_parse(
    options_buf: &[u8],
    file_buf: &[u8],
    sname_buf: &[u8],
) -> Result<ParsedDhcpOptions, DhcpOptionError> {
    let mut result = ParsedDhcpOptions::default();

    parse_one_buffer(options_buf, &mut result)?;

    if (result.overload & DHCP_OVERLOAD_FILE) != 0 {
        parse_one_buffer(file_buf, &mut result)?;
    }

    if (result.overload & DHCP_OVERLOAD_SNAME) != 0 {
        parse_one_buffer(sname_buf, &mut result)?;
    }

    if result.message_type == 0 {
        return Err(DhcpOptionError::NoMessageType);
    }

    Ok(result)
}

/// Parse multiple DHCP options from a single flat buffer (no overload).
///
/// Stops at END or end-of-buffer.
pub fn parse_options(buf: &[u8]) -> Vec<DhcpOption> {
    let mut options = vec![];
    let mut offset = 0;

    while offset < buf.len() {
        match DhcpOption::parse(buf, &mut offset) {
            Some(opt) => {
                let is_end = opt.code == SD_DHCP_OPTION_END;
                if is_end {
                    break;
                }
                options.push(opt);
            }
            None => break,
        }
    }

    options
}

/// Serialize multiple DHCP options to bytes, ensuring a trailing END.
///
/// Returns [`DhcpOptionError::InvalidData`] if any normal option has more
/// data than the one-byte DHCP length field permits.
pub fn serialize_options(options: &[DhcpOption]) -> Result<Vec<u8>, DhcpOptionError> {
    // Validate every input before building output, so an invalid later option
    // cannot leave a partially encoded result.
    if options.iter().any(|opt| {
        opt.code != SD_DHCP_OPTION_PAD
            && opt.code != SD_DHCP_OPTION_END
            && opt.data.len() > u8::MAX as usize
    }) {
        return Err(DhcpOptionError::InvalidData);
    }

    let mut buf = Vec::new();

    for opt in options {
        buf.extend_from_slice(&opt.serialize()?);
    }

    // Ensure buffer ends with END option
    if buf.last() != Some(&SD_DHCP_OPTION_END) {
        buf.push(SD_DHCP_OPTION_END);
    }

    Ok(buf)
}

// ── String / hostname parsing ─────────────────────────────────────────────

/// Parse a DHCP option value as a validated string.
///
/// Allows one trailing NUL byte. Rejects control characters and non-UTF-8.
pub fn parse_option_string(data: &[u8]) -> Result<Option<String>, DhcpOptionError> {
    if data.is_empty() {
        return Ok(None);
    }

    let trimmed = if data.last() == Some(&0) {
        &data[..data.len() - 1]
    } else {
        data
    };

    let s = std::str::from_utf8(trimmed).map_err(|_| DhcpOptionError::InvalidUtf8)?;

    if !is_safe_string(s) {
        return Err(DhcpOptionError::UnsafeString);
    }

    Ok(Some(s.to_owned()))
}

/// Parse a DHCP option value as a validated hostname.
///
/// Applies the same rules as `parse_option_string` plus hostname validity
/// checks: each label is 1–63 chars of alphanumeric/hyphen, no leading/trailing
/// hyphen, and the total is ≤ 253 characters.
pub fn parse_option_hostname(data: &[u8]) -> Result<Option<String>, DhcpOptionError> {
    let maybe_string = parse_option_string(data)?;
    let hostname = match maybe_string {
        Some(h) => h,
        None => return Ok(None),
    };

    if !is_valid_hostname(&hostname) {
        return Err(DhcpOptionError::InvalidHostname);
    }

    Ok(Some(hostname))
}

/// Check if all bytes are ASCII printable or common whitespace.
fn is_ascii_printable(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

/// Check if a string is "safe": valid UTF-8 with no C0/C1 control characters.
fn is_safe_string(s: &str) -> bool {
    s.chars().all(|c| !c.is_control() || c == '\t')
}

/// Validate a hostname per RFC 1123.
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Message type tests --

    #[test]
    fn test_message_type_roundtrip() {
        for v in 1u8..=18u8 {
            let mt = DhcpMessageType::from_u8(v).unwrap();
            assert_eq!(mt as u8, v);
        }
        assert_eq!(DhcpMessageType::from_u8(0), None);
        assert_eq!(DhcpMessageType::from_u8(19), None);
        assert_eq!(DhcpMessageType::from_u8(255), None);
    }

    // -- Option code tests --

    #[test]
    fn test_option_code_roundtrip() {
        let known = [
            0u8, 1, 3, 6, 12, 15, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 82, 93, 94,
            95, 100, 101, 120, 121, 255,
        ];
        for v in known {
            let code =
                DhcpOptionCode::from_u8(v).unwrap_or_else(|| panic!("code {v} should be known"));
            assert_eq!(code as u8, v);
        }
        assert_eq!(DhcpOptionCode::from_u8(2), None); // TimeOffset not in enum
    }

    // -- Option parse/serialize roundtrip --

    #[test]
    fn test_option_serialize_roundtrip() {
        let opt = DhcpOption::from_known(DhcpOptionCode::HostName, b"testhost".to_vec());
        let serialized = opt.serialize().unwrap();

        let mut offset = 0;
        let parsed = DhcpOption::parse(&serialized, &mut offset).unwrap();

        assert_eq!(parsed.code, DhcpOptionCode::HostName as u8);
        assert_eq!(parsed.data, b"testhost");
        assert_eq!(offset, serialized.len());
    }

    // -- Value accessors --

    #[test]
    fn test_option_as_string() {
        let opt = DhcpOption::from_known(DhcpOptionCode::HostName, b"myhost".to_vec());
        assert_eq!(opt.as_string().as_deref(), Some("myhost"));
    }

    #[test]
    fn test_option_as_string_trailing_nul() {
        let opt = DhcpOption::new(12, b"myhost\0".to_vec());
        assert_eq!(opt.as_string().as_deref(), Some("myhost"));
    }

    #[test]
    fn test_option_as_ipv4() {
        let opt = DhcpOption::from_known(DhcpOptionCode::SubnetMask, vec![255, 255, 255, 0]);
        assert_eq!(
            opt.as_ipv4(),
            Some(std::net::Ipv4Addr::new(255, 255, 255, 0))
        );

        // Wrong length
        let bad = DhcpOption::new(1, vec![255, 255]);
        assert_eq!(bad.as_ipv4(), None);
    }

    #[test]
    fn test_option_as_u32() {
        let opt = DhcpOption::from_known(
            DhcpOptionCode::IpAddressLeaseTime,
            3600u32.to_be_bytes().to_vec(),
        );
        assert_eq!(opt.as_u32(), Some(3600));

        let bad = DhcpOption::new(51, vec![0, 0]);
        assert_eq!(bad.as_u32(), None);
    }

    // -- PAD / END serialization --

    #[test]
    fn test_pad_and_end_serialization() {
        assert_eq!(
            DhcpOption::new(SD_DHCP_OPTION_PAD, vec![])
                .serialize()
                .unwrap(),
            vec![0]
        );
        assert_eq!(
            DhcpOption::new(SD_DHCP_OPTION_END, vec![])
                .serialize()
                .unwrap(),
            vec![255]
        );
    }

    #[test]
    fn test_option_serialize_rejects_oversize_tlv() {
        let opt = DhcpOption::new(12, vec![0; u8::MAX as usize + 1]);
        assert_eq!(opt.serialize(), Err(DhcpOptionError::InvalidData));
    }

    // -- TLV append --

    #[test]
    fn test_option_append_tlv() {
        let mut buf = [0u8; 16];
        let mut offset = 0;

        option_append_tlv(&mut buf, &mut offset, 6, &[1, 2, 3, 4]).unwrap();
        assert_eq!(offset, 6);
        assert_eq!(&buf[..6], &[6, 4, 1, 2, 3, 4]);
    }

    #[test]
    fn test_option_append_tlv_overflow() {
        let mut buf = [0u8; 4];
        let mut offset = 0;
        // Needs 2 + 3 = 5 bytes, only 4 available
        assert_eq!(
            option_append_tlv(&mut buf, &mut offset, 42, &[1, 2, 3]),
            Err(DhcpOptionError::NoBufferSpace)
        );
    }

    // -- Option length --

    #[test]
    fn test_option_length() {
        // PAD: 1 byte
        assert_eq!(option_length(&[0, 1, 2], 0), Ok(1));
        // END: 1 byte
        assert_eq!(option_length(&[255], 0), Ok(1));
        // Normal TLV: code=6, len=4 → 6 bytes total
        assert_eq!(option_length(&[6, 4, 1, 2, 3, 4], 0), Ok(6));
        // Truncated: not enough data for length
        assert_eq!(option_length(&[6], 0), Err(DhcpOptionError::NoBufferSpace));
    }

    // -- Find option --

    #[test]
    fn test_find_option() {
        let buf: Vec<u8> = [
            6, 4, 10, 0, 0, 1, // DNS server: code 6, len 4
            3, 4, 192, 168, 1, 1,   // Router: code 3, len 4
            255, // END
        ]
        .to_vec();

        let (off, len) = find_option(&buf, 3).unwrap();
        assert_eq!(off, 6);
        assert_eq!(len, 6);
        assert_eq!(&buf[off..off + len], &[3, 4, 192, 168, 1, 1]);

        assert_eq!(find_option(&buf, 99), Err(DhcpOptionError::NotFound));
    }

    // -- Remove option --

    #[test]
    fn test_remove_option() {
        let mut buf: Vec<u8> = [
            6, 4, 10, 0, 0, 1, // code 6
            3, 4, 192, 168, 1, 1, // code 3
            255,
        ]
        .to_vec();

        let buf_len = buf.len();
        let new_len = remove_option(&mut buf, buf_len, 3).unwrap();
        assert_eq!(new_len, 7);
        assert_eq!(&buf[..new_len], &[6u8, 4, 10, 0, 0, 1, 255]);
    }

    // -- parse_options / serialize_options --

    #[test]
    fn test_parse_and_serialize_options() {
        let raw: Vec<u8> = [
            6, 4, 8, 8, 8, 8, // DNS
            3, 4, 192, 168, 1, 1, // Router
            255,
        ]
        .to_vec();

        let opts = parse_options(&raw);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].code, 6);
        assert_eq!(opts[1].code, 3);

        let reserialized = serialize_options(&opts).unwrap();
        assert_eq!(reserialized, raw);
    }

    #[test]
    fn test_serialize_options_rejects_oversize_tlv() {
        let options = [
            DhcpOption::new(12, b"host".to_vec()),
            DhcpOption::new(43, vec![0; u8::MAX as usize + 1]),
        ];

        assert_eq!(
            serialize_options(&options),
            Err(DhcpOptionError::InvalidData)
        );
    }

    // -- Full option parse with overload --

    #[test]
    fn test_dhcp_option_parse_with_overload() {
        let options_buf: Vec<u8> = [
            53, 1, 5, // Message Type: ACK
            52, 1, 3,   // Overload: FILE | SNAME
            255, // END
        ]
        .to_vec();

        let file_buf: Vec<u8> = [
            6, 4, 8, 8, 8, 8, // DNS server in file field
            255,
        ]
        .to_vec();

        let sname_buf: Vec<u8> = [
            3, 4, 10, 0, 0, 1, // Router in sname field
            255,
        ]
        .to_vec();

        let result = dhcp_option_parse(&options_buf, &file_buf, &sname_buf).unwrap();

        assert_eq!(result.message_type, 5); // ACK
        assert_eq!(result.overload, 3);
        assert_eq!(result.options.len(), 2); // DNS + Router

        // Without overload, file/sname should be ignored
        let no_overload: Vec<u8> = [53u8, 1, 5, 255].to_vec();
        let result2 = dhcp_option_parse(&no_overload, &file_buf, &sname_buf).unwrap();
        assert_eq!(result2.options.len(), 0);
    }

    #[test]
    fn test_dhcp_option_parse_no_message_type() {
        let buf: Vec<u8> = [6u8, 4, 8, 8, 8, 8, 255].to_vec();
        assert_eq!(
            dhcp_option_parse(&buf, &[], &[]),
            Err(DhcpOptionError::NoMessageType)
        );
    }

    // -- String parsing --

    #[test]
    fn test_parse_option_string() {
        // Valid string
        let s = parse_option_string(b"hello world").unwrap();
        assert_eq!(s.as_deref(), Some("hello world"));

        // Trailing NUL
        let s = parse_option_string(b"hello\0").unwrap();
        assert_eq!(s.as_deref(), Some("hello"));

        // Empty
        let s = parse_option_string(b"").unwrap();
        assert!(s.is_none());

        // Invalid UTF-8
        let bad = parse_option_string(&[0xff, 0xfe]);
        assert_eq!(bad, Err(DhcpOptionError::InvalidUtf8));
    }

    // -- Hostname parsing --

    #[test]
    fn test_parse_option_hostname() {
        // Valid hostname
        let h = parse_option_hostname(b"example.com").unwrap();
        assert_eq!(h.as_deref(), Some("example.com"));

        // Empty → None
        assert!(parse_option_hostname(b"").unwrap().is_none());

        // Invalid: starts with hyphen
        assert_eq!(
            parse_option_hostname(b"-bad.com"),
            Err(DhcpOptionError::InvalidHostname)
        );

        // Invalid: label too long (>63)
        let long_label = "a".repeat(64);
        assert_eq!(
            parse_option_hostname(long_label.as_bytes()),
            Err(DhcpOptionError::InvalidHostname)
        );
    }

    // -- Overload-aware append --

    #[test]
    fn test_dhcp_option_append_overload() {
        let mut options_buf = [0u8; 8];
        let mut file_buf = [0u8; 16];
        let mut sname_buf = [0u8; 16];

        let mut msg = DhcpMessageBuffers {
            options: &mut options_buf,
            file: &mut file_buf,
            sname: &mut sname_buf,
        };

        let mut offset = 0;

        // First append fits in options
        dhcp_option_append(
            &mut msg,
            &mut offset,
            DHCP_OVERLOAD_FILE,
            53,
            &[5], // ACK
        )
        .unwrap();
        assert_eq!(offset, 3); // code + len + 1 byte

        // Fill options to capacity (5 bytes left, option needs 3 + 2 header)
        // Actually, option_append reserves 1 byte for END, so usable is 7.
        // offset=3, need 6 bytes (code+len+4data), 3+6=9 > 7, overflows to file.
        dhcp_option_append(
            &mut msg,
            &mut offset,
            DHCP_OVERLOAD_FILE | DHCP_OVERLOAD_SNAME,
            6,
            &[8, 8, 8, 8], // DNS
        )
        .unwrap();
        // Should have overflowed to file buffer
        // Options should end with END
        assert_eq!(options_buf[3], SD_DHCP_OPTION_END);
    }

    // -- option_append special cases --

    #[test]
    fn test_option_append_sip_server() {
        let mut buf = [0u8; 32];
        let mut offset = 0;

        option_append(
            &mut buf,
            &mut offset,
            SD_DHCP_OPTION_SIP_SERVER,
            b"example.com",
        )
        .unwrap();

        // code=120, len=12 (1+11), encoding=1, data=example.com
        assert_eq!(buf[0], SD_DHCP_OPTION_SIP_SERVER);
        assert_eq!(buf[1], 12);
        assert_eq!(buf[2], 1); // encoding: domain list
        assert_eq!(&buf[3..14], b"example.com");
    }

    #[test]
    fn test_option_append_pad_and_end() {
        let mut buf = [0u8; 8];
        let mut offset = 0;

        option_append(&mut buf, &mut offset, SD_DHCP_OPTION_PAD, &[]).unwrap();
        assert_eq!(offset, 1);
        assert_eq!(buf[0], 0);

        option_append(&mut buf, &mut offset, SD_DHCP_OPTION_END, &[]).unwrap();
        assert_eq!(offset, 2);
        assert_eq!(buf[1], 255);
    }

    // -- Error message parsing --

    #[test]
    fn test_error_message_extraction() {
        let buf: Vec<u8> = [
            53u8, 1, 6, // Message Type: NAK
            56, 10, b'i', b'n', b'v', b'a', b'l', b'i', b'd', b' ', b'i', b'p', 255,
        ]
        .to_vec();

        let result = dhcp_option_parse(&buf, &[], &[]).unwrap();
        assert_eq!(result.message_type, 6); // NAK
        assert_eq!(result.error_message.as_deref(), Some("invalid ip"));
    }

    // -- Hostname validation --

    #[test]
    fn test_hostname_validation() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("host"));
        assert!(is_valid_hostname("my-host.example.org"));
        assert!(is_valid_hostname("a.b.c"));

        // Invalid
        assert!(!is_valid_hostname("")); // empty
        assert!(!is_valid_hostname("-example.com")); // label starts with hyphen
        assert!(!is_valid_hostname("example-.com")); // label ends with hyphen
        assert!(!is_valid_hostname("exam ple.com")); // space in label
        assert!(!is_valid_hostname(&"a".repeat(254))); // too long overall
        assert!(!is_valid_hostname(&format!("{}.com", "a".repeat(64)))); // label too long
    }
}
