// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-message.c
//

use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, MessageError>;

pub const NLM_F_DUMP: u16 = 0x0300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    MissingHeader,
    Sealed,
    InvalidAttribute,
    TypeMismatch,
    DumpNotSupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Route,
    Generic,
    Netfilter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NlaValue {
    String(String),
    U8(u8),
    U16(u16),
    U32(u32),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetlinkMessage {
    pub protocol: Protocol,
    pub msg_type: u16,
    pub flags: u16,
    pub sealed: bool,
    pub multicast_group: u32,
    attributes: BTreeMap<u16, NlaValue>,
}

impl NetlinkMessage {
    pub fn new_empty(protocol: Protocol) -> Self {
        Self {
            protocol,
            msg_type: 0,
            flags: 0,
            sealed: false,
            multicast_group: 0,
            attributes: BTreeMap::new(),
        }
    }

    pub fn new(protocol: Protocol, msg_type: u16, flags: u16) -> Self {
        Self {
            msg_type,
            flags,
            ..Self::new_empty(protocol)
        }
    }

    pub fn set_request_dump(&mut self, allowed: bool) -> Result<()> {
        if self.protocol != Protocol::Route {
            return Err(MessageError::DumpNotSupported);
        }
        if allowed {
            self.flags |= NLM_F_DUMP;
        } else {
            self.flags &= !NLM_F_DUMP;
        }
        Ok(())
    }

    pub fn set_flags(&mut self, flags: u16) -> Result<()> {
        self.flags = flags;
        Ok(())
    }

    pub fn append_string(&mut self, attr_type: u16, data: &str) -> Result<()> {
        self.ensure_mutable()?;
        self.attributes
            .insert(attr_type, NlaValue::String(data.to_string()));
        Ok(())
    }

    pub fn append_u32(&mut self, attr_type: u16, data: u32) -> Result<()> {
        self.ensure_mutable()?;
        self.attributes.insert(attr_type, NlaValue::U32(data));
        Ok(())
    }

    pub fn read_string(&self, attr_type: u16) -> Result<&str> {
        match self.attributes.get(&attr_type) {
            Some(NlaValue::String(value)) => Ok(value),
            Some(_) => Err(MessageError::TypeMismatch),
            None => Err(MessageError::InvalidAttribute),
        }
    }

    pub fn read_u32(&self, attr_type: u16) -> Result<u32> {
        match self.attributes.get(&attr_type) {
            Some(NlaValue::U32(value)) => Ok(*value),
            Some(_) => Err(MessageError::TypeMismatch),
            None => Err(MessageError::InvalidAttribute),
        }
    }

    pub fn seal(&mut self) {
        self.sealed = true;
    }

    pub fn is_broadcast(&self) -> bool {
        self.multicast_group != 0
    }

    fn ensure_mutable(&self) -> Result<()> {
        if self.sealed {
            return Err(MessageError::Sealed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_flag_only_allowed_for_route_protocol() {
        let mut route = NetlinkMessage::new(Protocol::Route, 1, 0);
        assert_eq!(route.set_request_dump(true), Ok(()));
        let mut generic = NetlinkMessage::new(Protocol::Generic, 1, 0);
        assert_eq!(
            generic.set_request_dump(true),
            Err(MessageError::DumpNotSupported)
        );
    }

    #[test]
    fn appends_and_reads_string_attributes() {
        let mut msg = NetlinkMessage::new(Protocol::Route, 1, 0);
        msg.append_string(7, "lo").unwrap();
        assert_eq!(msg.read_string(7).unwrap(), "lo");
    }

    #[test]
    fn type_mismatch_is_reported() {
        let mut msg = NetlinkMessage::new(Protocol::Route, 1, 0);
        msg.append_u32(9, 10).unwrap();
        assert_eq!(msg.read_string(9), Err(MessageError::TypeMismatch));
    }

    #[test]
    fn sealed_messages_reject_mutation() {
        let mut msg = NetlinkMessage::new(Protocol::Route, 1, 0);
        msg.seal();
        assert_eq!(msg.append_u32(1, 1), Err(MessageError::Sealed));
    }
}
