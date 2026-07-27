// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/test-netlink.c
//

use crate::sd_netlink_message::{NetlinkMessage, Protocol};
use crate::sd_netlink_slot::{NetlinkSlot, SlotType};

pub type Result<T> = std::result::Result<T, String>;

pub fn build_bridge_cost_message(cost: u32) -> Result<NetlinkMessage> {
    let mut message = NetlinkMessage::new(Protocol::Route, 16, 0);
    message.append_u32(1, cost).map_err(|e| format!("{e:?}"))?;
    Ok(message)
}

pub fn async_slot_story(description: &str) -> NetlinkSlot {
    NetlinkSlot::new(
        false,
        SlotType::ReplyCallback {
            serial: 1,
            timeout_usec: Some(0),
        },
        Some("foo".into()),
        Some(description.into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_cost_roundtrip_works() {
        let message = build_bridge_cost_message(10).unwrap();
        assert_eq!(message.read_u32(1).unwrap(), 10);
    }

    #[test]
    fn async_slot_keeps_description() {
        let slot = async_slot_story("hogehoge");
        assert_eq!(slot.description.as_deref(), Some("hogehoge"));
    }

    #[test]
    fn async_slot_keeps_userdata() {
        let slot = async_slot_story("desc");
        assert_eq!(slot.userdata.as_deref(), Some("foo"));
    }

    #[test]
    fn bridge_cost_message_is_route_protocol() {
        let message = build_bridge_cost_message(7).unwrap();
        assert_eq!(message.protocol, Protocol::Route);
    }
}
