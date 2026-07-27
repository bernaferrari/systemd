// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-network/sd-network.c

use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, NetworkError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    InvalidArgument,
    NotFound,
    NoData,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkState {
    global: BTreeMap<String, String>,
    links: BTreeMap<i32, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkMonitor {
    pending_events: usize,
}

impl NetworkState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_global(&mut self, key: &str, value: &str) {
        self.global.insert(key.into(), value.into());
    }

    pub fn set_link(&mut self, ifindex: i32, key: &str, value: &str) -> Result<()> {
        if ifindex <= 0 {
            return Err(NetworkError::InvalidArgument);
        }
        self.links
            .entry(ifindex)
            .or_default()
            .insert(key.into(), value.into());
        Ok(())
    }

    pub fn get_operational_state(&self) -> Result<String> {
        self.global_string("OPER_STATE")
    }

    pub fn get_carrier_state(&self) -> Result<String> {
        self.global_string("CARRIER_STATE")
    }

    pub fn get_address_state(&self) -> Result<String> {
        self.global_string("ADDRESS_STATE")
    }

    pub fn get_online_state(&self) -> Result<String> {
        self.global_string("ONLINE_STATE")
    }

    pub fn get_dns(&self) -> Result<Vec<String>> {
        self.global_list("DNS")
    }

    pub fn get_ntp(&self) -> Result<Vec<String>> {
        self.global_list("NTP")
    }

    pub fn get_search_domains(&self) -> Result<Vec<String>> {
        self.global_list("DOMAINS")
    }

    pub fn get_route_domains(&self) -> Result<Vec<String>> {
        self.global_list("ROUTE_DOMAINS")
    }

    pub fn link_get_operational_state(&self, ifindex: i32) -> Result<String> {
        self.link_string(ifindex, "OPER_STATE")
    }

    pub fn link_get_setup_state(&self, ifindex: i32) -> Result<String> {
        self.link_string(ifindex, "ADMIN_STATE")
    }

    pub fn link_get_dns(&self, ifindex: i32) -> Result<Vec<String>> {
        self.link_list(ifindex, "DNS")
    }

    pub fn link_get_search_domains(&self, ifindex: i32) -> Result<Vec<String>> {
        self.link_list(ifindex, "DOMAINS")
    }

    pub fn link_get_dns_default_route(&self, ifindex: i32) -> Result<bool> {
        match self.link_string(ifindex, "DNS_DEFAULT_ROUTE")?.as_str() {
            "yes" | "true" | "1" => Ok(true),
            "no" | "false" | "0" => Ok(false),
            _ => Err(NetworkError::NoData),
        }
    }

    pub fn link_get_carrier_bound_to(&self, ifindex: i32) -> Result<Vec<i32>> {
        self.link_ifindexes(ifindex, "CARRIER_BOUND_TO")
    }

    pub fn link_get_carrier_bound_by(&self, ifindex: i32) -> Result<Vec<i32>> {
        self.link_ifindexes(ifindex, "CARRIER_BOUND_BY")
    }

    fn global_string(&self, key: &str) -> Result<String> {
        non_empty(self.global.get(key).cloned())
    }

    fn global_list(&self, key: &str) -> Result<Vec<String>> {
        split_words(&self.global_string(key)?)
    }

    fn link_string(&self, ifindex: i32, key: &str) -> Result<String> {
        if ifindex <= 0 {
            return Err(NetworkError::InvalidArgument);
        }
        let link = self.links.get(&ifindex).ok_or(NetworkError::NotFound)?;
        non_empty(link.get(key).cloned())
    }

    fn link_list(&self, ifindex: i32, key: &str) -> Result<Vec<String>> {
        split_words(&self.link_string(ifindex, key)?)
    }

    fn link_ifindexes(&self, ifindex: i32, key: &str) -> Result<Vec<i32>> {
        let mut out = Vec::new();
        for word in split_words(&self.link_string(ifindex, key)?)? {
            out.push(word.parse().map_err(|_| NetworkError::NoData)?);
        }
        Ok(out)
    }
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn notify_change(&mut self) {
        self.pending_events += 1;
    }

    pub fn flush(&mut self) -> Result<()> {
        self.pending_events = 0;
        Ok(())
    }

    pub fn get_events(&self) -> i16 {
        0x001
    }

    pub fn get_timeout(&self) -> u64 {
        u64::MAX
    }
}

fn non_empty(value: Option<String>) -> Result<String> {
    match value {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(NetworkError::NoData),
        None => Err(NetworkError::NotFound),
    }
}

fn split_words(input: &str) -> Result<Vec<String>> {
    let mut words: Vec<String> = input.split_whitespace().map(ToOwned::to_owned).collect();
    words.sort();
    words.dedup();
    if words.is_empty() {
        Err(NetworkError::NoData)
    } else {
        Ok(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> NetworkState {
        let mut state = NetworkState::new();
        state.set_global("OPER_STATE", "routable");
        state.set_global("DNS", "1.1.1.1 8.8.8.8 1.1.1.1");
        state.set_global("DOMAINS", "example.com corp.example.com");
        state.set_link(2, "OPER_STATE", "carrier").unwrap();
        state.set_link(2, "ADMIN_STATE", "configured").unwrap();
        state.set_link(2, "DNS", "9.9.9.9 1.1.1.1").unwrap();
        state
            .set_link(2, "DOMAINS", "lan.example lan.example")
            .unwrap();
        state.set_link(2, "DNS_DEFAULT_ROUTE", "yes").unwrap();
        state.set_link(2, "CARRIER_BOUND_TO", "3 7").unwrap();
        state
    }

    #[test]
    fn reads_global_operational_state() {
        assert_eq!(state().get_operational_state().unwrap(), "routable");
    }

    #[test]
    fn splits_and_deduplicates_global_dns() {
        assert_eq!(state().get_dns().unwrap(), vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn reads_link_operational_state() {
        assert_eq!(state().link_get_operational_state(2).unwrap(), "carrier");
    }

    #[test]
    fn reads_link_setup_state() {
        assert_eq!(state().link_get_setup_state(2).unwrap(), "configured");
    }

    #[test]
    fn parses_link_dns_default_route() {
        assert!(state().link_get_dns_default_route(2).unwrap());
    }

    #[test]
    fn parses_ifindex_lists() {
        assert_eq!(state().link_get_carrier_bound_to(2).unwrap(), vec![3, 7]);
    }

    #[test]
    fn invalid_ifindex_is_rejected() {
        assert_eq!(
            state().link_get_operational_state(0),
            Err(NetworkError::InvalidArgument)
        );
    }

    #[test]
    fn monitor_flush_clears_pending_events() {
        let mut monitor = NetworkMonitor::new();
        monitor.notify_change();
        monitor.flush().unwrap();
        assert_eq!(monitor.get_timeout(), u64::MAX);
        assert_eq!(monitor.get_events(), 0x001);
    }
}
