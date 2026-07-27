// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-track.c

use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, BusTrackError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusTrackError {
    InvalidName,
    InvalidMessage,
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusMessage {
    pub bus_id: u64,
    pub sender: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusTrack {
    pub bus_id: u64,
    names: BTreeMap<String, u32>,
    recursive: bool,
    userdata: usize,
    modified: bool,
    iteration_snapshot: Vec<String>,
    iteration_index: usize,
}

impl BusTrack {
    pub fn new(bus_id: u64, userdata: usize) -> Self {
        Self {
            bus_id,
            names: BTreeMap::new(),
            recursive: false,
            userdata,
            modified: false,
            iteration_snapshot: Vec::new(),
            iteration_index: 0,
        }
    }

    pub fn add_name(&mut self, name: &str) -> Result<bool> {
        if !service_name_is_valid(name) {
            return Err(BusTrackError::InvalidName);
        }
        match self.names.get_mut(name) {
            Some(count) if self.recursive => {
                *count += 1;
                self.modified = true;
                Ok(false)
            }
            Some(_) => Ok(false),
            None => {
                self.names.insert(name.to_string(), 1);
                self.modified = true;
                Ok(true)
            }
        }
    }

    pub fn remove_name(&mut self, name: &str) -> Result<bool> {
        if !service_name_is_valid(name) {
            return Err(BusTrackError::InvalidName);
        }
        let Some(count) = self.names.get_mut(name) else {
            return Ok(false);
        };
        if *count > 1 {
            *count -= 1;
        } else {
            self.names.remove(name);
        }
        self.modified = true;
        Ok(true)
    }

    pub fn count(&self) -> usize {
        self.names.len()
    }

    pub fn count_name(&self, name: &str) -> Result<u32> {
        if !service_name_is_valid(name) {
            return Err(BusTrackError::InvalidName);
        }
        Ok(self.names.get(name).copied().unwrap_or(0))
    }

    pub fn contains(&self, name: &str) -> Result<Option<&str>> {
        if !service_name_is_valid(name) {
            return Err(BusTrackError::InvalidName);
        }
        Ok(self.names.contains_key(name).then_some(name))
    }

    pub fn first(&mut self) -> Option<&str> {
        self.modified = false;
        self.iteration_snapshot = self.names.keys().cloned().collect();
        self.iteration_index = 0;
        self.next()
    }

    pub fn next(&mut self) -> Option<&str> {
        if self.modified || self.iteration_index >= self.iteration_snapshot.len() {
            return None;
        }
        let index = self.iteration_index;
        self.iteration_index += 1;
        self.iteration_snapshot.get(index).map(String::as_str)
    }

    pub fn add_sender(&mut self, message: &BusMessage) -> Result<bool> {
        if message.bus_id != self.bus_id {
            return Err(BusTrackError::InvalidMessage);
        }
        self.add_name(
            message
                .sender
                .as_deref()
                .ok_or(BusTrackError::InvalidMessage)?,
        )
    }

    pub fn remove_sender(&mut self, message: &BusMessage) -> Result<bool> {
        if message.bus_id != self.bus_id {
            return Err(BusTrackError::InvalidMessage);
        }
        self.remove_name(
            message
                .sender
                .as_deref()
                .ok_or(BusTrackError::InvalidMessage)?,
        )
    }

    pub fn count_sender(&self, message: &BusMessage) -> Result<u32> {
        if message.bus_id != self.bus_id {
            return Err(BusTrackError::InvalidMessage);
        }
        self.count_name(
            message
                .sender
                .as_deref()
                .ok_or(BusTrackError::InvalidMessage)?,
        )
    }

    pub fn set_recursive(&mut self, recursive: bool) -> Result<()> {
        if !self.names.is_empty() && self.recursive != recursive {
            return Err(BusTrackError::Busy);
        }
        self.recursive = recursive;
        Ok(())
    }

    pub fn recursive(&self) -> bool {
        self.recursive
    }

    pub fn get_userdata(&self) -> usize {
        self.userdata
    }

    pub fn set_userdata(&mut self, userdata: usize) -> usize {
        let old = self.userdata;
        self.userdata = userdata;
        old
    }

    pub fn close(&mut self) {
        self.names.clear();
        self.modified = true;
    }
}

fn service_name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_name_registers_unique_name() {
        let mut track = BusTrack::new(7, 1);
        assert_eq!(track.add_name("org.freedesktop.systemd1").unwrap(), true);
        assert_eq!(track.count(), 1);
    }

    #[test]
    fn duplicate_name_is_ignored_when_not_recursive() {
        let mut track = BusTrack::new(7, 1);
        track.add_name("org.freedesktop.systemd1").unwrap();
        assert_eq!(track.add_name("org.freedesktop.systemd1").unwrap(), false);
        assert_eq!(track.count_name("org.freedesktop.systemd1").unwrap(), 1);
    }

    #[test]
    fn recursive_mode_counts_duplicates() {
        let mut track = BusTrack::new(7, 1);
        track.set_recursive(true).unwrap();
        track.add_name("org.freedesktop.systemd1").unwrap();
        track.add_name("org.freedesktop.systemd1").unwrap();
        assert_eq!(track.count_name("org.freedesktop.systemd1").unwrap(), 2);
    }

    #[test]
    fn recursive_mode_cannot_change_when_busy() {
        let mut track = BusTrack::new(7, 1);
        track.add_name("org.freedesktop.systemd1").unwrap();
        assert_eq!(track.set_recursive(true), Err(BusTrackError::Busy));
    }

    #[test]
    fn contains_returns_original_name() {
        let mut track = BusTrack::new(7, 1);
        track.add_name("org.freedesktop.systemd1").unwrap();
        assert_eq!(
            track.contains("org.freedesktop.systemd1").unwrap(),
            Some("org.freedesktop.systemd1")
        );
    }

    #[test]
    fn iteration_stops_after_modification() {
        let mut track = BusTrack::new(7, 1);
        track.add_name("a.b").unwrap();
        track.add_name("c.d").unwrap();
        let _ = track.first();
        track.add_name("e.f").unwrap();
        assert_eq!(track.next(), None);
    }

    #[test]
    fn sender_operations_validate_bus() {
        let mut track = BusTrack::new(7, 1);
        let message = BusMessage {
            bus_id: 7,
            sender: Some("a.b".into()),
        };
        track.add_sender(&message).unwrap();
        assert_eq!(track.count_sender(&message).unwrap(), 1);
    }

    #[test]
    fn userdata_roundtrips() {
        let mut track = BusTrack::new(7, 5);
        assert_eq!(track.set_userdata(9), 5);
        assert_eq!(track.get_userdata(), 9);
    }
}
