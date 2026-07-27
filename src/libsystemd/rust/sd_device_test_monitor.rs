// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/test-sd-device-monitor.c
//
// In-memory device monitor with filter semantics modeled after the C tests.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorDevice {
    pub syspath: String,
    pub subsystem: Option<String>,
    pub devtype: Option<String>,
    pub tags: BTreeSet<String>,
    pub sysattrs: BTreeMap<String, String>,
    pub parent_syspath: Option<String>,
    pub action: Option<String>,
    pub seqnum: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorError {
    NotRunning,
    InvalidDevice,
}

impl std::fmt::Display for MonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning => f.write_str("monitor is not running"),
            Self::InvalidDevice => f.write_str("device message is not consumable"),
        }
    }
}

impl std::error::Error for MonitorError {}

#[derive(Debug, Clone, Default)]
pub struct DeviceMonitor {
    running: bool,
    subsystem_filters: Vec<(String, Option<String>)>,
    tag_filters: BTreeSet<String>,
    sysattr_filters: Vec<(String, String, bool)>,
    parent_filter: Option<(String, bool)>,
    queue: VecDeque<MonitorDevice>,
}

impl DeviceMonitor {
    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn start(&mut self) -> Result<(), MonitorError> {
        self.running = true;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), MonitorError> {
        self.running = false;
        Ok(())
    }

    pub fn filter_add_match_subsystem_devtype(
        &mut self,
        subsystem: &str,
        devtype: Option<&str>,
    ) -> Result<(), MonitorError> {
        self.subsystem_filters
            .push((subsystem.into(), devtype.map(str::to_string)));
        Ok(())
    }

    pub fn filter_add_match_tag(&mut self, tag: &str) -> Result<(), MonitorError> {
        self.tag_filters.insert(tag.into());
        Ok(())
    }

    pub fn filter_add_match_sysattr(
        &mut self,
        name: &str,
        value: &str,
        match_mode: bool,
    ) -> Result<(), MonitorError> {
        self.sysattr_filters
            .push((name.into(), value.into(), match_mode));
        Ok(())
    }

    pub fn filter_add_match_parent(
        &mut self,
        parent_syspath: &str,
        match_mode: bool,
    ) -> Result<(), MonitorError> {
        self.parent_filter = Some((parent_syspath.into(), match_mode));
        Ok(())
    }

    pub fn filter_remove(&mut self) -> Result<(), MonitorError> {
        self.subsystem_filters.clear();
        self.tag_filters.clear();
        self.sysattr_filters.clear();
        self.parent_filter = None;
        Ok(())
    }

    fn matches_filters(&self, device: &MonitorDevice) -> bool {
        if !self.subsystem_filters.is_empty()
            && !self.subsystem_filters.iter().any(|(subsystem, devtype)| {
                device.subsystem.as_deref() == Some(subsystem.as_str())
                    && devtype
                        .as_deref()
                        .map_or(true, |d| device.devtype.as_deref() == Some(d))
            })
        {
            return false;
        }

        if !self.tag_filters.is_empty() && self.tag_filters.is_disjoint(&device.tags) {
            return false;
        }

        for (name, value, match_mode) in &self.sysattr_filters {
            let matched = device
                .sysattrs
                .get(name)
                .map(|v| v == value)
                .unwrap_or(false);
            if matched != *match_mode {
                return false;
            }
        }

        if let Some((parent_syspath, match_mode)) = &self.parent_filter {
            let matched = device.parent_syspath.as_deref() == Some(parent_syspath.as_str());
            if matched != *match_mode {
                return false;
            }
        }

        true
    }

    pub fn send(&mut self, device: MonitorDevice) -> Result<bool, MonitorError> {
        let valid_action = matches!(
            device.action.as_deref(),
            Some("add" | "remove" | "change" | "move" | "bind" | "unbind")
        );
        if !valid_action || device.seqnum.is_none() {
            return Ok(false);
        }
        if self.matches_filters(&device) {
            self.queue.push_back(device);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn receive(&mut self) -> Result<MonitorDevice, MonitorError> {
        if !self.running {
            return Err(MonitorError::NotRunning);
        }
        self.queue.pop_front().ok_or(MonitorError::InvalidDevice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> MonitorDevice {
        MonitorDevice {
            syspath: "/sys/class/net/lo".into(),
            subsystem: Some("net".into()),
            devtype: None,
            tags: BTreeSet::from(["TEST_SD_DEVICE_MONITOR".into()]),
            sysattrs: BTreeMap::from([("ifindex".into(), "1".into())]),
            parent_syspath: Some("/sys/class/net".into()),
            action: Some("add".into()),
            seqnum: Some(10),
        }
    }

    #[test]
    fn running_state_toggles() {
        let mut monitor = DeviceMonitor::default();
        assert!(!monitor.is_running());
        monitor.start().unwrap();
        assert!(monitor.is_running());
        monitor.stop().unwrap();
        assert!(!monitor.is_running());
    }

    #[test]
    fn send_receive_without_filters() {
        let mut monitor = DeviceMonitor::default();
        monitor.start().unwrap();
        assert!(monitor.send(loopback()).unwrap());
        assert_eq!(monitor.receive().unwrap().syspath, "/sys/class/net/lo");
    }

    #[test]
    fn subsystem_filter_matches() {
        let mut monitor = DeviceMonitor::default();
        monitor
            .filter_add_match_subsystem_devtype("net", None)
            .unwrap();
        monitor.start().unwrap();
        assert!(monitor.send(loopback()).unwrap());
    }

    #[test]
    fn subsystem_filter_rejects_other_devices() {
        let mut monitor = DeviceMonitor::default();
        monitor
            .filter_add_match_subsystem_devtype("block", None)
            .unwrap();
        assert!(!monitor.send(loopback()).unwrap());
    }

    #[test]
    fn tag_filter_matches() {
        let mut monitor = DeviceMonitor::default();
        monitor
            .filter_add_match_tag("TEST_SD_DEVICE_MONITOR")
            .unwrap();
        assert!(monitor.send(loopback()).unwrap());
    }

    #[test]
    fn sysattr_filter_matches() {
        let mut monitor = DeviceMonitor::default();
        monitor
            .filter_add_match_sysattr("ifindex", "1", true)
            .unwrap();
        assert!(monitor.send(loopback()).unwrap());
    }

    #[test]
    fn parent_filter_matches() {
        let mut monitor = DeviceMonitor::default();
        monitor
            .filter_add_match_parent("/sys/class/net", true)
            .unwrap();
        assert!(monitor.send(loopback()).unwrap());
    }

    #[test]
    fn filter_remove_restores_delivery() {
        let mut monitor = DeviceMonitor::default();
        monitor
            .filter_add_match_subsystem_devtype("block", None)
            .unwrap();
        assert!(!monitor.send(loopback()).unwrap());
        monitor.filter_remove().unwrap();
        assert!(monitor.send(loopback()).unwrap());
    }

    #[test]
    fn invalid_action_or_missing_seqnum_is_ignored() {
        let mut bad = loopback();
        bad.action = Some("hoge".into());
        let mut monitor = DeviceMonitor::default();
        assert!(!monitor.send(bad).unwrap());
    }
}
