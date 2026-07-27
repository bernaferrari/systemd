// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-message.c
//
use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const NEG_ENODATA: i32 = -(libc::ENODATA as i32);
pub const NEG_EOPNOTSUPP: i32 = -(libc::EOPNOTSUPP as i32);

pub const SD_BUS_MAXIMUM_SIGNATURE_LENGTH: usize = 255;
pub const SD_BUS_MAXIMUM_NAME_LENGTH: usize = 255;
pub const BUS_MESSAGE_HEADER_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BusMessageType {
    Invalid = 0,
    MethodCall = 1,
    MethodReturn = 2,
    MethodError = 3,
    Signal = 4,
}

impl BusMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Invalid),
            1 => Some(Self::MethodCall),
            2 => Some(Self::MethodReturn),
            3 => Some(Self::MethodError),
            4 => Some(Self::Signal),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn is_valid(self) -> bool {
        !matches!(self, Self::Invalid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusMessageDumpFlags(u64);

impl BusMessageDumpFlags {
    pub const WITH_HEADER: Self = Self(1 << 0);
    pub const SUBTREE_ONLY: Self = Self(1 << 1);
}

impl std::ops::BitOr for BusMessageDumpFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for BusMessageDumpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for BusMessageDumpFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for BusMessageDumpFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BusMessageDumpFlags {
    pub const fn bits(&self) -> u64 {
        self.0
    }
    pub const fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BusMessageHeaderField {
    Path,
    Interface,
    Member,
    ErrorName,
    ReplySerial,
    Destination,
    Sender,
    Signature,
    UnixFds,
}

impl BusMessageHeaderField {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Path),
            2 => Some(Self::Interface),
            3 => Some(Self::Member),
            4 => Some(Self::ErrorName),
            5 => Some(Self::ReplySerial),
            6 => Some(Self::Destination),
            7 => Some(Self::Sender),
            8 => Some(Self::Signature),
            9 => Some(Self::UnixFds),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Path => 1,
            Self::Interface => 2,
            Self::Member => 3,
            Self::ErrorName => 4,
            Self::ReplySerial => 5,
            Self::Destination => 6,
            Self::Sender => 7,
            Self::Signature => 8,
            Self::UnixFds => 9,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BusMessageContainer {
    Array,
    Variant,
    Struct,
    DictEntry,
}

impl BusMessageContainer {
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'a' => Some(Self::Array),
            'v' => Some(Self::Variant),
            '(' | 'r' => Some(Self::Struct),
            '{' | 'e' => Some(Self::DictEntry),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusMessage {
    message_type: BusMessageType,
    cookie: u64,
    reply_cookie: u64,
    expect_reply: bool,
    auto_start: bool,
    allow_interactive_authorization: bool,
    sensitive: bool,
    path: Option<String>,
    interface: Option<String>,
    member: Option<String>,
    destination: Option<String>,
    sender: Option<String>,
    signature: Option<String>,
    error_name: Option<String>,
    error_message: Option<String>,
    monotonic_usec: Option<u64>,
    realtime_usec: Option<u64>,
    seqnum: Option<u64>,
    header_fields: BTreeMap<BusMessageHeaderField, String>,
}

impl BusMessage {
    pub fn new(message_type: BusMessageType) -> Result<Self> {
        if !message_type.is_valid() {
            return Err(NEG_EINVAL);
        }

        Ok(Self {
            message_type,
            cookie: 0,
            reply_cookie: 0,
            expect_reply: false,
            auto_start: false,
            allow_interactive_authorization: false,
            sensitive: false,
            path: None,
            interface: None,
            member: None,
            destination: None,
            sender: None,
            signature: None,
            error_name: None,
            error_message: None,
            monotonic_usec: None,
            realtime_usec: None,
            seqnum: None,
            header_fields: BTreeMap::new(),
        })
    }

    pub fn new_method_call(
        destination: Option<&str>,
        path: &str,
        interface: &str,
        member: &str,
    ) -> Result<Self> {
        let mut msg = Self::new(BusMessageType::MethodCall)?;
        msg.set_path(Some(path))?;
        msg.set_interface(Some(interface))?;
        msg.set_member(Some(member))?;
        msg.set_destination(destination)?;
        msg.expect_reply = true;
        Ok(msg)
    }

    pub fn new_signal(path: &str, interface: &str, member: &str) -> Result<Self> {
        let mut msg = Self::new(BusMessageType::Signal)?;
        msg.set_path(Some(path))?;
        msg.set_interface(Some(interface))?;
        msg.set_member(Some(member))?;
        Ok(msg)
    }

    pub fn new_method_return(reply_cookie: u64, destination: Option<&str>) -> Result<Self> {
        let mut msg = Self::new(BusMessageType::MethodReturn)?;
        msg.reply_cookie = reply_cookie;
        msg.set_destination(destination)?;
        Ok(msg)
    }

    pub fn new_method_error(reply_cookie: u64, name: &str, message: &str) -> Result<Self> {
        let mut msg = Self::new(BusMessageType::MethodError)?;
        msg.reply_cookie = reply_cookie;
        msg.set_error(name, message)?;
        Ok(msg)
    }

    pub fn message_type(&self) -> BusMessageType {
        self.message_type
    }

    pub fn cookie(&self) -> u64 {
        self.cookie
    }

    pub fn set_cookie(&mut self, cookie: u64) {
        self.cookie = cookie;
    }

    pub fn reply_cookie(&self) -> u64 {
        self.reply_cookie
    }

    pub fn expect_reply(&self) -> bool {
        self.expect_reply
    }

    pub fn set_expect_reply(&mut self, enabled: bool) {
        self.expect_reply = enabled;
    }

    pub fn auto_start(&self) -> bool {
        self.auto_start
    }

    pub fn set_auto_start(&mut self, enabled: bool) {
        self.auto_start = enabled;
    }

    pub fn allow_interactive_authorization(&self) -> bool {
        self.allow_interactive_authorization
    }

    pub fn set_allow_interactive_authorization(&mut self, enabled: bool) {
        self.allow_interactive_authorization = enabled;
    }

    pub fn sensitive(&self) -> bool {
        self.sensitive
    }

    pub fn set_sensitive(&mut self, enabled: bool) {
        self.sensitive = enabled;
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn set_path(&mut self, path: Option<&str>) -> Result<()> {
        let path = match path {
            Some(p) => {
                if object_path_is_valid(p) {
                    Some(p.to_string())
                } else {
                    return Err(NEG_EINVAL);
                }
            }
            None => None,
        };
        self.path = path.clone();
        self.sync_header_field(BusMessageHeaderField::Path, path);
        Ok(())
    }

    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    pub fn set_interface(&mut self, interface: Option<&str>) -> Result<()> {
        let value = validate_optional(interface, interface_name_is_valid)?;
        self.interface = value.clone();
        self.sync_header_field(BusMessageHeaderField::Interface, value);
        Ok(())
    }

    pub fn member(&self) -> Option<&str> {
        self.member.as_deref()
    }

    pub fn set_member(&mut self, member: Option<&str>) -> Result<()> {
        let value = validate_optional(member, member_name_is_valid)?;
        self.member = value.clone();
        self.sync_header_field(BusMessageHeaderField::Member, value);
        Ok(())
    }

    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }

    pub fn set_destination(&mut self, destination: Option<&str>) -> Result<()> {
        let value = validate_optional(destination, service_name_is_valid)?;
        self.destination = value.clone();
        self.sync_header_field(BusMessageHeaderField::Destination, value);
        Ok(())
    }

    pub fn sender(&self) -> Option<&str> {
        self.sender.as_deref()
    }

    pub fn set_sender(&mut self, sender: Option<&str>) -> Result<()> {
        let value = validate_optional(sender, service_name_is_valid)?;
        self.sender = value.clone();
        self.sync_header_field(BusMessageHeaderField::Sender, value);
        Ok(())
    }

    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    pub fn set_signature(&mut self, signature: Option<&str>) -> Result<()> {
        let value = validate_optional(signature, bus_message_is_signature_valid)?;
        self.signature = value.clone();
        self.sync_header_field(BusMessageHeaderField::Signature, value);
        Ok(())
    }

    pub fn error_name(&self) -> Option<&str> {
        self.error_name.as_deref()
    }

    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    pub fn set_error(&mut self, name: &str, message: &str) -> Result<()> {
        if !interface_name_is_valid(name) || message.is_empty() {
            return Err(NEG_EINVAL);
        }
        self.error_name = Some(name.to_string());
        self.error_message = Some(message.to_string());
        self.sync_header_field(BusMessageHeaderField::ErrorName, Some(name.to_string()));
        Ok(())
    }

    pub fn monotonic_usec(&self) -> Option<u64> {
        self.monotonic_usec
    }

    pub fn set_monotonic_usec(&mut self, value: Option<u64>) {
        self.monotonic_usec = value;
    }

    pub fn realtime_usec(&self) -> Option<u64> {
        self.realtime_usec
    }

    pub fn set_realtime_usec(&mut self, value: Option<u64>) {
        self.realtime_usec = value;
    }

    pub fn seqnum(&self) -> Option<u64> {
        self.seqnum
    }

    pub fn set_seqnum(&mut self, value: Option<u64>) {
        self.seqnum = value;
    }

    pub fn header_field(&self, field: BusMessageHeaderField) -> Option<&str> {
        self.header_fields.get(&field).map(String::as_str)
    }

    pub fn is_signal(&self, interface: Option<&str>, member: Option<&str>) -> bool {
        self.message_type == BusMessageType::Signal
            && option_matches(self.interface.as_deref(), interface)
            && option_matches(self.member.as_deref(), member)
    }

    pub fn is_method_call(&self, interface: Option<&str>, member: Option<&str>) -> bool {
        self.message_type == BusMessageType::MethodCall
            && option_matches(self.interface.as_deref(), interface)
            && option_matches(self.member.as_deref(), member)
    }

    pub fn is_method_error(&self, name: Option<&str>) -> bool {
        self.message_type == BusMessageType::MethodError
            && option_matches(self.error_name.as_deref(), name)
    }

    fn sync_header_field(&mut self, field: BusMessageHeaderField, value: Option<String>) {
        match value {
            Some(value) => {
                self.header_fields.insert(field, value);
            }
            None => {
                self.header_fields.remove(&field);
            }
        }
    }
}

pub fn bus_message_is_signature_valid(signature: &str) -> bool {
    if signature.len() > SD_BUS_MAXIMUM_SIGNATURE_LENGTH {
        return false;
    }

    let bytes = signature.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if parse_single_type(bytes, &mut index, 0, false).is_err() {
            return false;
        }
    }
    true
}

pub fn bus_message_type_is_container(c: char) -> bool {
    matches!(c, 'a' | 'v' | '(' | '{')
}

pub fn make_neg_errno(errno: i32) -> i32 {
    -(errno.abs())
}

pub fn object_path_is_valid(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }
    if path.ends_with('/') {
        return false;
    }
    path[1..].split('/').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

pub fn interface_name_is_valid(name: &str) -> bool {
    dotted_name_is_valid(name, false)
}

pub fn service_name_is_valid(name: &str) -> bool {
    dotted_name_is_valid(name, true)
}

pub fn member_name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= SD_BUS_MAXIMUM_NAME_LENGTH
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn dotted_name_is_valid(name: &str, allow_leading_colon: bool) -> bool {
    if name.is_empty() || name.len() > SD_BUS_MAXIMUM_NAME_LENGTH {
        return false;
    }

    let body = if allow_leading_colon && name.starts_with(':') {
        &name[1..]
    } else {
        name
    };

    let mut saw_dot = false;
    for segment in body.split('.') {
        if segment.is_empty() {
            return false;
        }
        let mut chars = segment.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !(first.is_ascii_alphabetic()
            || first == '_'
            || (allow_leading_colon && first.is_ascii_digit()))
        {
            return false;
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return false;
        }
        saw_dot = true;
    }

    saw_dot
}

fn validate_optional(value: Option<&str>, validate: fn(&str) -> bool) -> Result<Option<String>> {
    match value {
        Some(value) if validate(value) => Ok(Some(value.to_string())),
        Some(_) => Err(NEG_EINVAL),
        None => Ok(None),
    }
}

fn option_matches(actual: Option<&str>, expected: Option<&str>) -> bool {
    match expected {
        Some(expected) => actual == Some(expected),
        None => true,
    }
}

fn parse_single_type(
    bytes: &[u8],
    index: &mut usize,
    depth: usize,
    from_array: bool,
) -> Result<()> {
    if *index >= bytes.len() || depth > 64 {
        return Err(NEG_EINVAL);
    }

    match bytes[*index] {
        b'a' => {
            *index += 1;
            parse_single_type(bytes, index, depth + 1, true)
        }
        b'v' => {
            *index += 1;
            Ok(())
        }
        b'(' => {
            *index += 1;
            let start = *index;
            while *index < bytes.len() && bytes[*index] != b')' {
                parse_single_type(bytes, index, depth + 1, false)?;
            }
            if *index >= bytes.len() || *index == start {
                return Err(NEG_EINVAL);
            }
            *index += 1;
            Ok(())
        }
        b'{' => {
            if !from_array {
                return Err(NEG_EINVAL);
            }
            *index += 1;
            if *index >= bytes.len() || !is_basic_type(bytes[*index]) {
                return Err(NEG_EINVAL);
            }
            *index += 1;
            parse_single_type(bytes, index, depth + 1, false)?;
            if *index >= bytes.len() || bytes[*index] != b'}' {
                return Err(NEG_EINVAL);
            }
            *index += 1;
            Ok(())
        }
        c if is_type_char(c) => {
            *index += 1;
            Ok(())
        }
        _ => Err(NEG_EINVAL),
    }
}

fn is_basic_type(c: u8) -> bool {
    matches!(
        c,
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g' | b'h'
    )
}

fn is_type_char(c: u8) -> bool {
    is_basic_type(c) || c == b'v'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_roundtrips() {
        for value in 0u8..=4 {
            let parsed = BusMessageType::from_u8(value).unwrap();
            assert_eq!(parsed.as_u8(), value);
        }
        assert_eq!(BusMessageType::from_u8(9), None);
    }

    #[test]
    fn method_call_constructor_validates_fields() {
        let msg = BusMessage::new_method_call(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "Reload",
        )
        .unwrap();
        assert!(msg.expect_reply());
        assert_eq!(msg.destination(), Some("org.freedesktop.systemd1"));
    }

    #[test]
    fn method_call_rejects_invalid_path() {
        assert_eq!(
            BusMessage::new_method_call(None, "relative/path", "a.b", "Hello"),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn signal_predicate_matches_subset() {
        let msg = BusMessage::new_signal("/a", "a.b", "Ping").unwrap();
        assert!(msg.is_signal(Some("a.b"), None));
        assert!(!msg.is_signal(Some("x.y"), None));
    }

    #[test]
    fn signature_validation_accepts_nested_types() {
        assert!(bus_message_is_signature_valid("a{sv}"));
        assert!(bus_message_is_signature_valid("(ssu)"));
        assert!(bus_message_is_signature_valid("aa{si}"));
    }

    #[test]
    fn signature_validation_rejects_broken_types() {
        assert!(!bus_message_is_signature_valid("("));
        assert!(!bus_message_is_signature_valid("a{"));
        assert!(!bus_message_is_signature_valid("{ss}"));
    }

    #[test]
    fn setters_sync_header_fields() {
        let mut msg = BusMessage::new(BusMessageType::Signal).unwrap();
        msg.set_path(Some("/org/example")).unwrap();
        msg.set_signature(Some("s")).unwrap();
        assert_eq!(
            msg.header_field(BusMessageHeaderField::Path),
            Some("/org/example")
        );
        assert_eq!(
            msg.header_field(BusMessageHeaderField::Signature),
            Some("s")
        );
    }

    #[test]
    fn name_validators_match_common_dbus_rules() {
        assert!(object_path_is_valid("/org/freedesktop/systemd1"));
        assert!(interface_name_is_valid("org.freedesktop.systemd1.Manager"));
        assert!(service_name_is_valid(":1.42"));
        assert!(member_name_is_valid("Reload"));
        assert!(!member_name_is_valid("reload-now"));
    }

    #[test]
    fn header_fields_roundtrip() {
        for value in 1u8..=9 {
            let field = BusMessageHeaderField::from_u8(value).unwrap();
            assert_eq!(field.as_u8(), value);
        }
    }

    #[test]
    fn container_type_detection_matches_openers() {
        assert!(bus_message_type_is_container('a'));
        assert!(bus_message_type_is_container('v'));
        assert_eq!(
            BusMessageContainer::from_char('{'),
            Some(BusMessageContainer::DictEntry)
        );
        assert_eq!(BusMessageContainer::from_char('s'), None);
    }

    #[test]
    fn negative_errno_helper_is_stable() {
        assert_eq!(make_neg_errno(22), -22);
        assert_eq!(make_neg_errno(-22), -22);
    }
}
