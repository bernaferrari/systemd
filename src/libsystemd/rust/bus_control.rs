// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-control.c

use crate::id128_util::SdId128;
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const NEG_EALREADY: i32 = -(libc::EALREADY as i32);
pub const NEG_EEXIST: i32 = -(libc::EEXIST as i32);
pub const NEG_ENOTCONN: i32 = -(libc::ENOTCONN as i32);

pub const SD_BUS_NAME_ALLOW_REPLACEMENT: u64 = 1;
pub const SD_BUS_NAME_REPLACE_EXISTING: u64 = 2;
pub const SD_BUS_NAME_QUEUE: u64 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusCreds {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusConnection {
    pub unique_name: String,
    pub bus_client: bool,
    pub open: bool,
    pub machine_id: SdId128,
    pub owner_creds: BusCreds,
    owned_names: BTreeSet<String>,
    queued_names: BTreeSet<String>,
    foreign_names: BTreeMap<String, (BusCreds, SdId128)>,
    match_rules: BTreeMap<String, u64>,
}

impl BusConnection {
    pub fn new(unique_name: impl Into<String>, machine_id: SdId128, owner_creds: BusCreds) -> Self {
        Self {
            unique_name: unique_name.into(),
            bus_client: true,
            open: true,
            machine_id,
            owner_creds,
            owned_names: BTreeSet::new(),
            queued_names: BTreeSet::new(),
            foreign_names: BTreeMap::new(),
            match_rules: BTreeMap::new(),
        }
    }

    pub fn get_unique_name(&self) -> Result<&str> {
        self.validate_client()?;
        Ok(&self.unique_name)
    }

    pub fn request_name(&mut self, name: &str, flags: u64) -> Result<i32> {
        validate_request_name_parameters(self, name, flags)?;

        if self.owned_names.contains(name) {
            return Err(NEG_EALREADY);
        }
        if self.foreign_names.contains_key(name) {
            if flags & SD_BUS_NAME_REPLACE_EXISTING != 0 {
                self.foreign_names.remove(name);
                self.owned_names.insert(name.to_string());
                return Ok(1);
            }
            if flags & SD_BUS_NAME_QUEUE != 0 {
                self.queued_names.insert(name.to_string());
                return Ok(0);
            }
            return Err(NEG_EEXIST);
        }

        self.owned_names.insert(name.to_string());
        Ok(1)
    }

    pub fn release_name(&mut self, name: &str) -> Result<i32> {
        validate_release_name_parameters(self, name)?;

        if self.owned_names.remove(name) {
            return Ok(1);
        }
        if self.queued_names.remove(name) {
            return Ok(1);
        }
        if self.foreign_names.contains_key(name) {
            return Err(NEG_EEXIST);
        }
        Err(NEG_EALREADY)
    }

    pub fn list_names(&self) -> Result<(Vec<String>, Vec<String>)> {
        self.validate_client()?;

        let mut acquired = self.owned_names.iter().cloned().collect::<Vec<_>>();
        acquired.extend(self.foreign_names.keys().cloned());
        acquired.sort();

        let mut activatable = self.queued_names.iter().cloned().collect::<Vec<_>>();
        activatable.sort();
        Ok((acquired, activatable))
    }

    pub fn get_name_creds(&self, name: &str) -> Result<BusCreds> {
        self.validate_client()?;
        validate_service_name(name)?;

        if self.owned_names.contains(name) {
            return Ok(self.owner_creds.clone());
        }

        self.foreign_names
            .get(name)
            .map(|(creds, _)| creds.clone())
            .ok_or(NEG_EINVAL)
    }

    pub fn get_owner_creds(&self) -> Result<BusCreds> {
        self.validate_client()?;
        Ok(self.owner_creds.clone())
    }

    pub fn get_name_machine_id(&self, name: &str) -> Result<SdId128> {
        self.validate_client()?;
        validate_service_name(name)?;

        if self.owned_names.contains(name) {
            return Ok(self.machine_id);
        }

        self.foreign_names
            .get(name)
            .map(|(_, id)| *id)
            .ok_or(NEG_EINVAL)
    }

    pub fn add_match_internal(&mut self, rule: &str, timeout_usec: u64) -> Result<u64> {
        self.validate_client()?;
        if rule.is_empty() {
            return Err(NEG_EINVAL);
        }
        let counter = self.match_rules.len() as u64 + 1;
        self.match_rules
            .insert(rule.to_string(), timeout_usec.max(counter));
        Ok(counter)
    }

    pub fn remove_match_internal(&mut self, rule: &str) -> Result<()> {
        self.validate_client()?;
        if self.match_rules.remove(rule).is_some() {
            Ok(())
        } else {
            Err(NEG_EINVAL)
        }
    }

    pub fn register_foreign_name(
        &mut self,
        name: &str,
        creds: BusCreds,
        machine_id: SdId128,
    ) -> Result<()> {
        validate_service_name(name)?;
        if name == "org.freedesktop.DBus" || name == "org.freedesktop.DBus.Local" {
            return Err(NEG_EINVAL);
        }
        self.foreign_names
            .insert(name.to_string(), (creds, machine_id));
        Ok(())
    }

    fn validate_client(&self) -> Result<()> {
        if !self.bus_client {
            return Err(NEG_EINVAL);
        }
        if !self.open {
            return Err(NEG_ENOTCONN);
        }
        Ok(())
    }
}

fn validate_request_name_parameters(bus: &BusConnection, name: &str, flags: u64) -> Result<()> {
    if flags & !(SD_BUS_NAME_ALLOW_REPLACEMENT | SD_BUS_NAME_REPLACE_EXISTING | SD_BUS_NAME_QUEUE)
        != 0
    {
        return Err(NEG_EINVAL);
    }
    bus.validate_client()?;
    validate_service_name(name)?;
    if matches!(name, "org.freedesktop.DBus" | "org.freedesktop.DBus.Local") {
        return Err(NEG_EINVAL);
    }
    Ok(())
}

fn validate_release_name_parameters(bus: &BusConnection, name: &str) -> Result<()> {
    bus.validate_client()?;
    validate_service_name(name)?;
    if matches!(name, "org.freedesktop.DBus" | "org.freedesktop.DBus.Local") {
        return Err(NEG_EINVAL);
    }
    Ok(())
}

fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with(':')
        || !name.contains('.')
        || name.starts_with('.')
        || name.ends_with('.')
    {
        return Err(NEG_EINVAL);
    }
    if name.split('.').any(|p| p.is_empty()) {
        return Err(NEG_EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bus() -> BusConnection {
        BusConnection::new(
            ":1.7",
            SdId128([7; 16]),
            BusCreds {
                pid: 10,
                uid: 20,
                gid: 30,
            },
        )
    }

    #[test]
    fn returns_unique_name() {
        assert_eq!(sample_bus().get_unique_name().unwrap(), ":1.7");
    }

    #[test]
    fn rejects_invalid_request_flags() {
        assert_eq!(
            sample_bus().request_name("org.example.Service", 8),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn acquires_free_name() {
        assert_eq!(
            sample_bus()
                .clone()
                .request_name("org.example.Service", 0)
                .unwrap(),
            1
        );
    }

    #[test]
    fn rejects_already_owned_name() {
        let mut bus = sample_bus();
        bus.request_name("org.example.Service", 0).unwrap();
        assert_eq!(
            bus.request_name("org.example.Service", 0),
            Err(NEG_EALREADY)
        );
    }

    #[test]
    fn queues_name_when_requested() {
        let mut bus = sample_bus();
        bus.register_foreign_name(
            "org.example.Service",
            BusCreds {
                pid: 11,
                uid: 21,
                gid: 31,
            },
            SdId128([8; 16]),
        )
        .unwrap();
        assert_eq!(
            bus.request_name("org.example.Service", SD_BUS_NAME_QUEUE)
                .unwrap(),
            0
        );
    }

    #[test]
    fn replaces_existing_owner_when_allowed() {
        let mut bus = sample_bus();
        bus.register_foreign_name(
            "org.example.Service",
            BusCreds {
                pid: 11,
                uid: 21,
                gid: 31,
            },
            SdId128([8; 16]),
        )
        .unwrap();
        assert_eq!(
            bus.request_name("org.example.Service", SD_BUS_NAME_REPLACE_EXISTING)
                .unwrap(),
            1
        );
    }

    #[test]
    fn lists_acquired_and_activatable_names() {
        let mut bus = sample_bus();
        bus.request_name("org.example.Owned", 0).unwrap();
        bus.register_foreign_name(
            "org.example.Foreign",
            BusCreds {
                pid: 1,
                uid: 2,
                gid: 3,
            },
            SdId128([9; 16]),
        )
        .unwrap();
        bus.request_name("org.example.Foreign", SD_BUS_NAME_QUEUE)
            .unwrap();
        let (acquired, activatable) = bus.list_names().unwrap();
        assert!(acquired.contains(&"org.example.Owned".into()));
        assert!(acquired.contains(&"org.example.Foreign".into()));
        assert_eq!(activatable, vec!["org.example.Foreign"]);
    }

    #[test]
    fn returns_credentials_for_owner_and_foreign_name() {
        let mut bus = sample_bus();
        bus.request_name("org.example.Owned", 0).unwrap();
        assert_eq!(bus.get_name_creds("org.example.Owned").unwrap().uid, 20);
        bus.register_foreign_name(
            "org.example.Foreign",
            BusCreds {
                pid: 1,
                uid: 2,
                gid: 3,
            },
            SdId128([9; 16]),
        )
        .unwrap();
        assert_eq!(bus.get_name_creds("org.example.Foreign").unwrap().uid, 2);
    }

    #[test]
    fn exposes_machine_id_for_names() {
        let mut bus = sample_bus();
        bus.request_name("org.example.Owned", 0).unwrap();
        assert_eq!(
            bus.get_name_machine_id("org.example.Owned").unwrap(),
            SdId128([7; 16])
        );
    }

    #[test]
    fn tracks_match_rules() {
        let mut bus = sample_bus();
        let counter = bus.add_match_internal("type='signal'", 50).unwrap();
        assert_eq!(counter, 1);
        assert_eq!(bus.remove_match_internal("type='signal'"), Ok(()));
    }
}
