// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-message-nfnl.c
//

pub type Result<T> = std::result::Result<T, NfnlError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NfnlError {
    InvalidProto,
    InvalidMessageType,
    MixedSubsystems,
    EmptyBatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfProto {
    Unspec,
    Inet,
    Ipv4,
    Arp,
    Netdev,
    Bridge,
    Ipv6,
}

pub fn nfproto_is_valid(proto: NfProto) -> bool {
    matches!(
        proto,
        NfProto::Unspec
            | NfProto::Inet
            | NfProto::Ipv4
            | NfProto::Arp
            | NfProto::Netdev
            | NfProto::Bridge
            | NfProto::Ipv6
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfnlMessage {
    pub nfproto: NfProto,
    pub subsys: u16,
    pub msg_type: u16,
    pub flags: u16,
    pub res_id: u16,
    pub serial: u32,
}

impl NfnlMessage {
    pub fn new(nfproto: NfProto, subsys: u16, msg_type: u16, flags: u16) -> Result<Self> {
        if !nfproto_is_valid(nfproto) {
            return Err(NfnlError::InvalidProto);
        }
        if msg_type > 0x00ff {
            return Err(NfnlError::InvalidMessageType);
        }
        Ok(Self {
            nfproto,
            subsys,
            msg_type,
            flags,
            res_id: 0,
            serial: 0,
        })
    }

    pub fn set_res_id(&mut self, res_id: u16) {
        self.res_id = res_id;
    }
}

#[derive(Debug, Default)]
pub struct SerialAllocator {
    next: u32,
}

impl SerialAllocator {
    pub fn allocate(&mut self) -> u32 {
        self.next = self.next.saturating_add(1);
        self.next
    }
}

pub fn send_batch(messages: &mut [NfnlMessage], serials: &mut SerialAllocator) -> Result<Vec<u32>> {
    let Some(first) = messages.first() else {
        return Err(NfnlError::EmptyBatch);
    };
    let subsys = first.subsys;
    if messages.iter().any(|m| m.subsys != subsys) {
        return Err(NfnlError::MixedSubsystems);
    }

    let begin_serial = serials.allocate();
    let batch_res_id = (begin_serial & u16::MAX as u32) as u16;
    let mut out = vec![begin_serial];

    for message in messages {
        message.serial = serials.allocate();
        message.set_res_id(batch_res_id);
        out.push(message.serial);
    }

    out.push(serials.allocate());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_supported_protocols() {
        assert!(nfproto_is_valid(NfProto::Ipv6));
    }

    #[test]
    fn rejects_large_message_type() {
        assert_eq!(
            NfnlMessage::new(NfProto::Inet, 2, 0x0100, 0).unwrap_err(),
            NfnlError::InvalidMessageType
        );
    }

    #[test]
    fn batch_assigns_same_subsystem_cookie() {
        let mut alloc = SerialAllocator::default();
        let mut messages = vec![
            NfnlMessage::new(NfProto::Inet, 7, 1, 0).unwrap(),
            NfnlMessage::new(NfProto::Inet, 7, 2, 0).unwrap(),
        ];
        let serials = send_batch(&mut messages, &mut alloc).unwrap();
        assert_eq!(serials.len(), 4);
        assert_eq!(messages[0].res_id, messages[1].res_id);
    }

    #[test]
    fn batch_rejects_mixed_subsystems() {
        let mut alloc = SerialAllocator::default();
        let mut messages = vec![
            NfnlMessage::new(NfProto::Inet, 1, 1, 0).unwrap(),
            NfnlMessage::new(NfProto::Inet, 2, 1, 0).unwrap(),
        ];
        assert_eq!(
            send_batch(&mut messages, &mut alloc).unwrap_err(),
            NfnlError::MixedSubsystems
        );
    }
}
