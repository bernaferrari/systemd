// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-slot.c

pub type Result<T> = std::result::Result<T, BusSlotError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusSlotError {
    InvalidSlot,
    Stale,
    NoDescription,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusSlotType {
    ReplyCallback,
    FilterCallback,
    MatchCallback,
    NodeCallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bus {
    pub id: u64,
    pub current_slot_id: Option<u64>,
    pub current_message: Option<String>,
    pub current_handler: Option<String>,
    pub current_userdata: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusSlot {
    id: u64,
    bus_id: Option<u64>,
    pub slot_type: BusSlotType,
    floating: bool,
    userdata: usize,
    description: Option<String>,
    match_string: Option<String>,
}

impl BusSlot {
    pub fn new(
        id: u64,
        bus: &Bus,
        floating: bool,
        slot_type: BusSlotType,
        userdata: usize,
    ) -> Self {
        Self {
            id,
            bus_id: Some(bus.id),
            slot_type,
            floating,
            userdata,
            description: None,
            match_string: None,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn get_bus<'a>(&self, bus: &'a Bus) -> Option<&'a Bus> {
        (self.bus_id == Some(bus.id)).then_some(bus)
    }

    pub fn get_userdata(&self) -> usize {
        self.userdata
    }

    pub fn set_userdata(&mut self, userdata: usize) -> usize {
        let old = self.userdata;
        self.userdata = userdata;
        old
    }

    pub fn get_floating(&self) -> bool {
        self.floating
    }

    pub fn set_floating(&mut self, floating: bool) -> Result<bool> {
        if self.floating == floating {
            return Ok(false);
        }
        if self.bus_id.is_none() {
            return Err(BusSlotError::Stale);
        }
        self.floating = floating;
        Ok(true)
    }

    pub fn disconnect(&mut self) {
        self.bus_id = None;
    }

    pub fn set_description(&mut self, description: Option<String>) {
        self.description = description;
    }

    pub fn set_match_string(&mut self, match_string: impl Into<String>) {
        self.match_string = Some(match_string.into());
    }

    pub fn get_description(&self) -> Result<&str> {
        self.description
            .as_deref()
            .or(self.match_string.as_deref())
            .ok_or(BusSlotError::NoDescription)
    }

    pub fn get_current_message<'a>(&self, bus: &'a Bus) -> Option<&'a str> {
        (self.bus_id == Some(bus.id) && bus.current_slot_id == Some(self.id))
            .then_some(bus.current_message.as_deref())
            .flatten()
    }

    pub fn get_current_handler<'a>(&self, bus: &'a Bus) -> Option<&'a str> {
        (self.bus_id == Some(bus.id) && bus.current_slot_id == Some(self.id))
            .then_some(bus.current_handler.as_deref())
            .flatten()
    }

    pub fn get_current_userdata(&self, bus: &Bus) -> Option<usize> {
        (self.bus_id == Some(bus.id) && bus.current_slot_id == Some(self.id))
            .then_some(bus.current_userdata)
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bus() -> Bus {
        Bus {
            id: 7,
            current_slot_id: None,
            current_message: None,
            current_handler: None,
            current_userdata: None,
        }
    }

    #[test]
    fn returns_matching_bus() {
        let bus = bus();
        let slot = BusSlot::new(1, &bus, false, BusSlotType::ReplyCallback, 11);
        assert_eq!(slot.get_bus(&bus).unwrap().id, 7);
    }

    #[test]
    fn userdata_roundtrips() {
        let bus = bus();
        let mut slot = BusSlot::new(1, &bus, false, BusSlotType::ReplyCallback, 11);
        assert_eq!(slot.set_userdata(22), 11);
        assert_eq!(slot.get_userdata(), 22);
    }

    #[test]
    fn floating_state_reports_change() {
        let bus = bus();
        let mut slot = BusSlot::new(1, &bus, false, BusSlotType::ReplyCallback, 0);
        assert_eq!(slot.set_floating(true).unwrap(), true);
        assert!(slot.get_floating());
    }

    #[test]
    fn floating_state_reports_no_change() {
        let bus = bus();
        let mut slot = BusSlot::new(1, &bus, false, BusSlotType::ReplyCallback, 0);
        assert_eq!(slot.set_floating(false).unwrap(), false);
    }

    #[test]
    fn disconnected_slot_becomes_stale() {
        let bus = bus();
        let mut slot = BusSlot::new(1, &bus, false, BusSlotType::ReplyCallback, 0);
        slot.disconnect();
        assert_eq!(slot.set_floating(true), Err(BusSlotError::Stale));
    }

    #[test]
    fn explicit_description_wins() {
        let bus = bus();
        let mut slot = BusSlot::new(1, &bus, false, BusSlotType::MatchCallback, 0);
        slot.set_match_string("type='signal'");
        slot.set_description(Some("custom".into()));
        assert_eq!(slot.get_description().unwrap(), "custom");
    }

    #[test]
    fn match_description_is_fallback() {
        let bus = bus();
        let mut slot = BusSlot::new(1, &bus, false, BusSlotType::MatchCallback, 0);
        slot.set_match_string("type='signal'");
        assert_eq!(slot.get_description().unwrap(), "type='signal'");
    }

    #[test]
    fn current_execution_state_is_exposed_only_for_active_slot() {
        let bus = Bus {
            id: 7,
            current_slot_id: Some(5),
            current_message: Some("hello".into()),
            current_handler: Some("handle".into()),
            current_userdata: Some(99),
        };
        let slot = BusSlot::new(5, &bus, false, BusSlotType::ReplyCallback, 0);
        assert_eq!(slot.get_current_message(&bus), Some("hello"));
        assert_eq!(slot.get_current_handler(&bus), Some("handle"));
        assert_eq!(slot.get_current_userdata(&bus), Some(99));
    }
}
