// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-slot.c
//

pub type Result<T> = std::result::Result<T, SlotError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotError {
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotType {
    ReplyCallback {
        serial: u32,
        timeout_usec: Option<u64>,
    },
    MatchCallback {
        groups: Vec<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetlinkSlot {
    pub floating: bool,
    pub connected: bool,
    pub slot_type: SlotType,
    pub userdata: Option<String>,
    pub description: Option<String>,
    pub destroy_callback_set: bool,
}

impl NetlinkSlot {
    pub fn new(
        floating: bool,
        slot_type: SlotType,
        userdata: Option<String>,
        description: Option<String>,
    ) -> Self {
        Self {
            floating,
            connected: true,
            slot_type,
            userdata,
            description,
            destroy_callback_set: false,
        }
    }

    pub fn disconnect(&mut self) {
        self.connected = false;
        if let SlotType::MatchCallback { groups } = &mut self.slot_type {
            groups.clear();
        }
    }

    pub fn set_userdata(&mut self, userdata: Option<String>) -> Option<String> {
        std::mem::replace(&mut self.userdata, userdata)
    }

    pub fn set_destroy_callback(&mut self, enabled: bool) {
        self.destroy_callback_set = enabled;
    }

    pub fn set_floating(&mut self, floating: bool) -> Result<bool> {
        if !self.connected {
            return Err(SlotError::Disconnected);
        }
        let changed = self.floating != floating;
        self.floating = floating;
        Ok(changed)
    }

    pub fn set_description(&mut self, description: Option<String>) {
        self.description = description;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userdata_roundtrip_matches_c_accessors() {
        let mut slot = NetlinkSlot::new(
            false,
            SlotType::ReplyCallback {
                serial: 7,
                timeout_usec: Some(10),
            },
            Some("foo".into()),
            None,
        );
        assert_eq!(slot.set_userdata(Some("bar".into())), Some("foo".into()));
        assert_eq!(slot.userdata.as_deref(), Some("bar"));
    }

    #[test]
    fn destroy_callback_flag_toggles() {
        let mut slot = NetlinkSlot::new(
            false,
            SlotType::ReplyCallback {
                serial: 1,
                timeout_usec: None,
            },
            None,
            None,
        );
        slot.set_destroy_callback(true);
        assert!(slot.destroy_callback_set);
    }

    #[test]
    fn floating_state_changes_only_when_connected() {
        let mut slot = NetlinkSlot::new(
            false,
            SlotType::ReplyCallback {
                serial: 1,
                timeout_usec: None,
            },
            None,
            None,
        );
        assert!(slot.set_floating(true).unwrap());
        slot.disconnect();
        assert_eq!(slot.set_floating(false), Err(SlotError::Disconnected));
    }

    #[test]
    fn disconnect_clears_match_groups() {
        let mut slot = NetlinkSlot::new(
            true,
            SlotType::MatchCallback { groups: vec![1, 2] },
            None,
            Some("hogehoge".into()),
        );
        slot.disconnect();
        match slot.slot_type {
            SlotType::MatchCallback { groups } => assert!(groups.is_empty()),
            _ => panic!("wrong slot type"),
        }
    }
}
