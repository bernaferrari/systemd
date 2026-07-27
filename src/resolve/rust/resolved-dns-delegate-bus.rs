// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dns-delegate-bus.c
//
// D-Bus interface for DNS delegate objects: exposes DNS server lists,
// current DNS server, search domains, and default route status
// over the org.freedesktop.resolve1.DnsDelegate interface.

use std::collections::HashMap;
use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────

pub const DELEGATE_BUS_PATH_PREFIX: &str = "/org/freedesktop/resolve1/dns_delegate";
pub const DELEGATE_INTERFACE_NAME: &str = "org.freedesktop.resolve1.DnsDelegate";

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegateBusError {
    NotFound(String),
    PathEncodeFailed(String),
    PathDecodeFailed(String),
    NoMemory,
    InvalidPath(String),
}

impl fmt::Display for DelegateBusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelegateBusError::NotFound(id) => write!(f, "Delegate not found: {}", id),
            DelegateBusError::PathEncodeFailed(id) => {
                write!(f, "Failed to encode bus path for: {}", id)
            }
            DelegateBusError::PathDecodeFailed(path) => {
                write!(f, "Failed to decode bus path: {}", path)
            }
            DelegateBusError::NoMemory => write!(f, "Out of memory"),
            DelegateBusError::InvalidPath(path) => write!(f, "Invalid path: {}", path),
        }
    }
}

impl std::error::Error for DelegateBusError {}

// ── DNS server info ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerInfo {
    pub ifindex: i32,
    pub family: u8,
    pub address: Vec<u8>,
    pub port: u16,
    pub server_name: Option<String>,
}

// ── Search domain info ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDomainInfo {
    pub name: String,
    pub route_only: bool,
}

// ── Tri-state for default route ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriState {
    False,
    True,
    Unset,
}

impl TriState {
    pub fn is_true(&self) -> bool {
        matches!(self, TriState::True)
    }

    pub fn is_set(&self) -> bool {
        !matches!(self, TriState::Unset)
    }
}

// ── DnsDelegate ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsDelegate {
    pub id: String,
    pub dns_servers: Vec<DnsServerInfo>,
    pub current_dns_server: Option<DnsServerInfo>,
    pub search_domains: Vec<SearchDomainInfo>,
    pub default_route: TriState,
}

impl DnsDelegate {
    pub fn new(id: &str) -> Self {
        DnsDelegate {
            id: id.to_string(),
            dns_servers: Vec::new(),
            current_dns_server: None,
            search_domains: Vec::new(),
            default_route: TriState::Unset,
        }
    }

    pub fn add_server(&mut self, server: DnsServerInfo) {
        self.dns_servers.push(server);
    }

    pub fn add_domain(&mut self, name: &str, route_only: bool) {
        self.search_domains.push(SearchDomainInfo {
            name: name.to_string(),
            route_only,
        });
    }
}

// ── Bus path encoding/decoding ─────────────────────────────────────────────

pub fn dns_delegate_bus_path(delegate: &DnsDelegate) -> Result<String, DelegateBusError> {
    if delegate.id.is_empty() {
        return Err(DelegateBusError::PathEncodeFailed(delegate.id.clone()));
    }

    let encoded = bus_path_encode(&delegate.id);
    Ok(format!("{}/{}", DELEGATE_BUS_PATH_PREFIX, encoded))
}

pub fn dns_delegate_bus_path_decode(path: &str) -> Result<Option<String>, DelegateBusError> {
    let prefix = format!("{}/", DELEGATE_BUS_PATH_PREFIX);
    if let Some(encoded) = path.strip_prefix(&prefix) {
        let decoded = bus_path_decode(encoded);
        if decoded.is_empty() {
            return Ok(None);
        }
        return Ok(Some(decoded));
    }

    if path == DELEGATE_BUS_PATH_PREFIX {
        return Ok(None);
    }

    Err(DelegateBusError::InvalidPath(path.to_string()))
}

fn bus_path_encode(id: &str) -> String {
    let mut encoded = String::new();
    for ch in id.bytes() {
        match ch {
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'-' | b'.' => {
                encoded.push(ch as char);
            }
            _ => {
                encoded.push_str(&format!("_{:02x}", ch));
            }
        }
    }
    encoded
}

fn bus_path_decode(encoded: &str) -> String {
    let mut decoded = String::new();
    let mut chars = encoded.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '_' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                decoded.push(byte as char);
            }
        } else {
            decoded.push(ch);
        }
    }

    decoded
}

// ── Delegate manager ───────────────────────────────────────────────────────

pub struct DelegateManager {
    delegates: HashMap<String, DnsDelegate>,
}

impl DelegateManager {
    pub fn new() -> Self {
        DelegateManager {
            delegates: HashMap::new(),
        }
    }

    pub fn add(&mut self, delegate: DnsDelegate) {
        self.delegates.insert(delegate.id.clone(), delegate);
    }

    pub fn find(&self, id: &str) -> Option<&DnsDelegate> {
        self.delegates.get(id)
    }

    pub fn find_by_path(&self, path: &str) -> Result<Option<&DnsDelegate>, DelegateBusError> {
        match dns_delegate_bus_path_decode(path)? {
            Some(id) => Ok(self.find(&id)),
            None => Ok(None),
        }
    }

    pub fn enumerate_paths(&self) -> Result<Vec<String>, DelegateBusError> {
        let mut paths = Vec::new();
        for delegate in self.delegates.values() {
            paths.push(dns_delegate_bus_path(delegate)?);
        }
        Ok(paths)
    }

    pub fn count(&self) -> usize {
        self.delegates.len()
    }
}

impl Default for DelegateManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Property getters (serializable) ────────────────────────────────────────

pub fn property_get_dns(delegate: &DnsDelegate) -> Vec<&DnsServerInfo> {
    delegate.dns_servers.iter().collect()
}

pub fn property_get_current_dns_server(delegate: &DnsDelegate) -> Option<&DnsServerInfo> {
    delegate.current_dns_server.as_ref()
}

pub fn property_get_domains(delegate: &DnsDelegate) -> Vec<&SearchDomainInfo> {
    delegate.search_domains.iter().collect()
}

pub fn property_get_default_route(delegate: &DnsDelegate) -> TriState {
    delegate.default_route
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegate_new() {
        let d = DnsDelegate::new("vpn1");
        assert_eq!(d.id, "vpn1");
        assert!(d.dns_servers.is_empty());
        assert!(d.current_dns_server.is_none());
        assert!(d.search_domains.is_empty());
        assert_eq!(d.default_route, TriState::Unset);
    }

    #[test]
    fn test_delegate_add_server() {
        let mut d = DnsDelegate::new("test");
        d.add_server(DnsServerInfo {
            ifindex: 1,
            family: 2,
            address: vec![8, 8, 8, 8],
            port: 53,
            server_name: None,
        });
        assert_eq!(d.dns_servers.len(), 1);
    }

    #[test]
    fn test_delegate_add_domain() {
        let mut d = DnsDelegate::new("test");
        d.add_domain("example.com", false);
        d.add_domain("test.com", true);
        assert_eq!(d.search_domains.len(), 2);
        assert!(!d.search_domains[0].route_only);
        assert!(d.search_domains[1].route_only);
    }

    #[test]
    fn test_bus_path_encode_decode_simple() {
        let encoded = bus_path_encode("vpn1");
        let decoded = bus_path_decode(&encoded);
        assert_eq!(decoded, "vpn1");
    }

    #[test]
    fn test_bus_path_encode_decode_special_chars() {
        let encoded = bus_path_encode("vpn@example.com");
        let decoded = bus_path_decode(&encoded);
        assert_eq!(decoded, "vpn@example.com");
    }

    #[test]
    fn test_dns_delegate_bus_path() {
        let d = DnsDelegate::new("vpn1");
        let path = dns_delegate_bus_path(&d).unwrap();
        assert!(path.starts_with(DELEGATE_BUS_PATH_PREFIX));
    }

    #[test]
    fn test_dns_delegate_bus_path_decode() {
        let d = DnsDelegate::new("vpn1");
        let path = dns_delegate_bus_path(&d).unwrap();
        let decoded = dns_delegate_bus_path_decode(&path).unwrap();
        assert_eq!(decoded, Some("vpn1".to_string()));
    }

    #[test]
    fn test_dns_delegate_bus_path_decode_invalid() {
        let result = dns_delegate_bus_path_decode("/org/freedesktop/other/thing");
        assert!(result.is_err());
    }

    #[test]
    fn test_delegate_manager_add_find() {
        let mut mgr = DelegateManager::new();
        let mut d = DnsDelegate::new("vpn1");
        d.add_server(DnsServerInfo {
            ifindex: 1,
            family: 2,
            address: vec![10, 0, 0, 1],
            port: 53,
            server_name: None,
        });
        mgr.add(d);

        let found = mgr.find("vpn1").unwrap();
        assert_eq!(found.dns_servers.len(), 1);
        assert!(mgr.find("nonexistent").is_none());
    }

    #[test]
    fn test_delegate_manager_find_by_path() {
        let mut mgr = DelegateManager::new();
        mgr.add(DnsDelegate::new("vpn1"));

        let path = dns_delegate_bus_path(mgr.find("vpn1").unwrap()).unwrap();
        let found = mgr.find_by_path(&path).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "vpn1");
    }

    #[test]
    fn test_delegate_manager_enumerate_paths() {
        let mut mgr = DelegateManager::new();
        mgr.add(DnsDelegate::new("vpn1"));
        mgr.add(DnsDelegate::new("vpn2"));
        let paths = mgr.enumerate_paths().unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_property_get_dns() {
        let mut d = DnsDelegate::new("test");
        d.add_server(DnsServerInfo {
            ifindex: 1,
            family: 2,
            address: vec![8, 8, 8, 8],
            port: 53,
            server_name: None,
        });
        d.add_server(DnsServerInfo {
            ifindex: 2,
            family: 10,
            address: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 53,
            server_name: None,
        });
        assert_eq!(property_get_dns(&d).len(), 2);
    }

    #[test]
    fn test_property_get_current_dns_server() {
        let mut d = DnsDelegate::new("test");
        assert!(property_get_current_dns_server(&d).is_none());
        d.current_dns_server = Some(DnsServerInfo {
            ifindex: 1,
            family: 2,
            address: vec![8, 8, 8, 8],
            port: 53,
            server_name: None,
        });
        assert!(property_get_current_dns_server(&d).is_some());
    }

    #[test]
    fn test_property_get_domains() {
        let mut d = DnsDelegate::new("test");
        d.add_domain("example.com", false);
        d.add_domain("test.com", true);
        assert_eq!(property_get_domains(&d).len(), 2);
    }

    #[test]
    fn test_tristate() {
        assert!(TriState::True.is_true());
        assert!(!TriState::False.is_true());
        assert!(!TriState::Unset.is_true());
        assert!(TriState::True.is_set());
        assert!(TriState::False.is_set());
        assert!(!TriState::Unset.is_set());
    }
}
