// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-dnssd-bus.c
//
// DNS-SD D-Bus interface: handles registration and unregistration of
// mDNS services, manages service objects on the D-Bus, and dispatches
// goodbye announcements when services are removed.

use std::collections::HashMap;
use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────

pub const DNSSD_BUS_PATH_PREFIX: &str = "/org/freedesktop/resolve1/dnssd";
pub const DNSSD_INTERFACE_NAME: &str = "org.freedesktop.resolve1.DnssdService";

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssdBusError {
    NotFound(String),
    PathEncodeFailed,
    PathDecodeFailed(String),
    NoMemory,
    InvalidPath(String),
    PermissionDenied(String),
    PolkitPending,
}

impl fmt::Display for DnssdBusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnssdBusError::NotFound(id) => write!(f, "DNS-SD service not found: {}", id),
            DnssdBusError::PathEncodeFailed => write!(f, "Failed to encode D-Bus path"),
            DnssdBusError::PathDecodeFailed(path) => {
                write!(f, "Failed to decode D-Bus path: {}", path)
            }
            DnssdBusError::NoMemory => write!(f, "Out of memory"),
            DnssdBusError::InvalidPath(path) => write!(f, "Invalid D-Bus path: {}", path),
            DnssdBusError::PermissionDenied(action) => {
                write!(f, "Permission denied for: {}", action)
            }
            DnssdBusError::PolkitPending => write!(f, "Polkit authentication pending"),
        }
    }
}

impl std::error::Error for DnssdBusError {}

// ── DNS resource record ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

// ── TXT data item ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtDataItem {
    pub rr: DnsResourceRecord,
}

// ── Registered service ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnssdRegisteredService {
    pub id: String,
    pub name: String,
    pub type_name: String,
    pub domain: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub ptr_rr: Option<DnsResourceRecord>,
    pub sub_ptr_rr: Option<DnsResourceRecord>,
    pub srv_rr: Option<DnsResourceRecord>,
    pub txt_data_items: Vec<TxtDataItem>,
    pub originator: Option<u32>,
}

impl DnssdRegisteredService {
    pub fn new(id: &str, name: &str, type_name: &str, domain: &str) -> Self {
        DnssdRegisteredService {
            id: id.to_string(),
            name: name.to_string(),
            type_name: type_name.to_string(),
            domain: domain.to_string(),
            port: 0,
            priority: 0,
            weight: 0,
            ptr_rr: None,
            sub_ptr_rr: None,
            srv_rr: None,
            txt_data_items: Vec::new(),
            originator: None,
        }
    }
}

// ── DNS scope zone ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DnsZone {
    records: Vec<DnsResourceRecord>,
}

impl DnsZone {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rr(&mut self, rr: &DnsResourceRecord) {
        self.records.push(rr.clone());
    }

    pub fn remove_rr(&mut self, rr: Option<&DnsResourceRecord>) {
        if let Some(rr) = rr {
            self.records.retain(|r| r != rr);
        }
    }

    pub fn contains(&self, rr: &DnsResourceRecord) -> bool {
        self.records.contains(rr)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ── DNS scope ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsScope {
    pub zone: DnsZone,
    pub is_ipv4: bool,
}

impl DnsScope {
    pub fn new(is_ipv4: bool) -> Self {
        DnsScope {
            zone: DnsZone::new(),
            is_ipv4,
        }
    }

    pub fn announce(&self, _goodbye: bool) -> Result<(), DnssdBusError> {
        Ok(())
    }
}

// ── Link ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Link {
    pub ifindex: i32,
    pub mdns_ipv4_scope: Option<DnsScope>,
    pub mdns_ipv6_scope: Option<DnsScope>,
}

impl Link {
    pub fn new(ifindex: i32) -> Self {
        Link {
            ifindex,
            mdns_ipv4_scope: Some(DnsScope::new(true)),
            mdns_ipv6_scope: Some(DnsScope::new(false)),
        }
    }
}

// ── Manager ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct DnssdManager {
    pub registered_services: HashMap<String, DnssdRegisteredService>,
    pub links: HashMap<i32, Link>,
    pub polkit_registry: HashMap<String, bool>,
}

impl DnssdManager {
    pub fn new() -> Self {
        DnssdManager {
            registered_services: HashMap::new(),
            links: HashMap::new(),
            polkit_registry: HashMap::new(),
        }
    }

    pub fn add_link(&mut self, link: Link) {
        self.links.insert(link.ifindex, link);
    }

    pub fn register_service(&mut self, service: DnssdRegisteredService) {
        self.registered_services.insert(service.id.clone(), service);
    }

    pub fn refresh_rrs(&self) -> Result<(), DnssdBusError> {
        Ok(())
    }
}

impl Default for DnssdManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Bus path encoding/decoding ─────────────────────────────────────────────

pub fn dnssd_bus_path(service: &DnssdRegisteredService) -> Result<String, DnssdBusError> {
    if service.id.is_empty() {
        return Err(DnssdBusError::PathEncodeFailed);
    }

    let encoded = bus_path_encode(&service.id);
    Ok(format!("{}/{}", DNSSD_BUS_PATH_PREFIX, encoded))
}

pub fn dnssd_bus_path_decode(path: &str) -> Result<Option<String>, DnssdBusError> {
    let prefix = format!("{}/", DNSSD_BUS_PATH_PREFIX);
    if let Some(encoded) = path.strip_prefix(&prefix) {
        let decoded = bus_path_decode(encoded);
        if decoded.is_empty() {
            return Ok(None);
        }
        return Ok(Some(decoded));
    }

    if path == DNSSD_BUS_PATH_PREFIX {
        return Ok(None);
    }

    Err(DnssdBusError::InvalidPath(path.to_string()))
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

// ── Unregister method ──────────────────────────────────────────────────────

pub fn bus_dnssd_method_unregister(
    manager: &mut DnssdManager,
    service_id: &str,
    verify_polkit: bool,
) -> Result<(), DnssdBusError> {
    let service = manager
        .registered_services
        .get(service_id)
        .cloned()
        .ok_or_else(|| DnssdBusError::NotFound(service_id.to_string()))?;

    if verify_polkit {
        let uid = service.originator.unwrap_or(0xFFFF);
        if uid == 0xFFFF {
            return Err(DnssdBusError::PermissionDenied(
                "org.freedesktop.resolve1.unregister-service".to_string(),
            ));
        }
    }

    for link in manager.links.values_mut() {
        if let Some(ref scope) = link.mdns_ipv4_scope {
            let _ = scope.announce(true);
        }
        if let Some(ref scope) = link.mdns_ipv6_scope {
            let _ = scope.announce(true);
        }

        if let Some(ref mut scope) = link.mdns_ipv4_scope {
            scope.zone.remove_rr(service.ptr_rr.as_ref());
            scope.zone.remove_rr(service.sub_ptr_rr.as_ref());
            scope.zone.remove_rr(service.srv_rr.as_ref());
            for txt in &service.txt_data_items {
                scope.zone.remove_rr(Some(&txt.rr));
            }
        }

        if let Some(ref mut scope) = link.mdns_ipv6_scope {
            scope.zone.remove_rr(service.ptr_rr.as_ref());
            scope.zone.remove_rr(service.sub_ptr_rr.as_ref());
            scope.zone.remove_rr(service.srv_rr.as_ref());
            for txt in &service.txt_data_items {
                scope.zone.remove_rr(Some(&txt.rr));
            }
        }
    }

    manager
        .registered_services
        .remove(service_id)
        .ok_or_else(|| DnssdBusError::NotFound(service_id.to_string()))?;

    manager.refresh_rrs()?;

    Ok(())
}

// ── Object finder ──────────────────────────────────────────────────────────

pub fn dnssd_object_find(
    manager: &DnssdManager,
    path: &str,
) -> Result<Option<String>, DnssdBusError> {
    match dnssd_bus_path_decode(path)? {
        Some(name) => {
            if manager.registered_services.contains_key(&name) {
                Ok(Some(name))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

// ── Node enumerator ────────────────────────────────────────────────────────

pub fn dnssd_node_enumerate(manager: &DnssdManager) -> Result<Vec<String>, DnssdBusError> {
    let mut paths = Vec::new();
    for service in manager.registered_services.values() {
        paths.push(dnssd_bus_path(service)?);
    }
    Ok(paths)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service(id: &str) -> DnssdRegisteredService {
        DnssdRegisteredService::new(id, "MyService", "_http._tcp", "local")
    }

    #[test]
    fn test_service_new() {
        let s = make_service("svc1");
        assert_eq!(s.id, "svc1");
        assert_eq!(s.name, "MyService");
        assert_eq!(s.type_name, "_http._tcp");
        assert_eq!(s.domain, "local");
    }

    #[test]
    fn test_dns_zone_add_remove() {
        let mut zone = DnsZone::new();
        let rr = DnsResourceRecord {
            name: "test.local".to_string(),
            rr_type: 1,
            class: 1,
            ttl: 300,
            rdata: vec![127, 0, 0, 1],
        };
        zone.add_rr(&rr);
        assert_eq!(zone.len(), 1);
        assert!(zone.contains(&rr));
        zone.remove_rr(Some(&rr));
        assert_eq!(zone.len(), 0);
    }

    #[test]
    fn test_dns_zone_remove_none() {
        let mut zone = DnsZone::new();
        zone.remove_rr(None);
        assert_eq!(zone.len(), 0);
    }

    #[test]
    fn test_bus_path_encode_decode_roundtrip() {
        let encoded = bus_path_encode("my-service.local");
        let decoded = bus_path_decode(&encoded);
        assert_eq!(decoded, "my-service.local");
    }

    #[test]
    fn test_bus_path_encode_special_chars() {
        let encoded = bus_path_encode("svc@domain.com");
        assert!(encoded.contains("_40"));
        let decoded = bus_path_decode(&encoded);
        assert_eq!(decoded, "svc@domain.com");
    }

    #[test]
    fn test_dnssd_bus_path() {
        let s = make_service("svc1");
        let path = dnssd_bus_path(&s).unwrap();
        assert!(path.starts_with(DNSSD_BUS_PATH_PREFIX));
    }

    #[test]
    fn test_dnssd_bus_path_decode() {
        let s = make_service("svc1");
        let path = dnssd_bus_path(&s).unwrap();
        let decoded = dnssd_bus_path_decode(&path).unwrap();
        assert_eq!(decoded, Some("svc1".to_string()));
    }

    #[test]
    fn test_dnssd_bus_path_decode_invalid() {
        assert!(dnssd_bus_path_decode("/wrong/path").is_err());
    }

    #[test]
    fn test_manager_register_find() {
        let mut mgr = DnssdManager::new();
        mgr.register_service(make_service("svc1"));
        assert!(mgr.registered_services.contains_key("svc1"));
        assert!(!mgr.registered_services.contains_key("svc2"));
    }

    #[test]
    fn test_unregister_success() {
        let mut mgr = DnssdManager::new();
        mgr.add_link(Link::new(1));
        mgr.register_service(make_service("svc1"));
        bus_dnssd_method_unregister(&mut mgr, "svc1", false).unwrap();
        assert!(!mgr.registered_services.contains_key("svc1"));
    }

    #[test]
    fn test_unregister_not_found() {
        let mut mgr = DnssdManager::new();
        let result = bus_dnssd_method_unregister(&mut mgr, "nonexistent", false);
        assert!(matches!(result, Err(DnssdBusError::NotFound(_))));
    }

    #[test]
    fn test_unregister_polkit_denied() {
        let mut mgr = DnssdManager::new();
        let mut svc = make_service("svc1");
        svc.originator = None;
        mgr.register_service(svc);
        let result = bus_dnssd_method_unregister(&mut mgr, "svc1", true);
        assert!(matches!(result, Err(DnssdBusError::PermissionDenied(_))));
    }

    #[test]
    fn test_dnssd_object_find() {
        let mut mgr = DnssdManager::new();
        mgr.register_service(make_service("svc1"));
        let path = dnssd_bus_path(mgr.registered_services.get("svc1").unwrap()).unwrap();
        let found = dnssd_object_find(&mgr, &path).unwrap();
        assert_eq!(found, Some("svc1".to_string()));
    }

    #[test]
    fn test_dnssd_object_find_missing() {
        let mgr = DnssdManager::new();
        let found = dnssd_object_find(&mgr, &format!("{}/missing", DNSSD_BUS_PATH_PREFIX)).unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn test_dnssd_node_enumerate() {
        let mut mgr = DnssdManager::new();
        mgr.register_service(make_service("svc1"));
        mgr.register_service(make_service("svc2"));
        let paths = dnssd_node_enumerate(&mgr).unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_unregister_removes_from_zones() {
        let mut mgr = DnssdManager::new();
        let mut link = Link::new(1);
        let rr = DnsResourceRecord {
            name: "_http._tcp.local".to_string(),
            rr_type: 12,
            class: 1,
            ttl: 300,
            rdata: vec![],
        };
        link.mdns_ipv4_scope.as_mut().unwrap().zone.add_rr(&rr);
        mgr.add_link(link);

        let mut svc = make_service("svc1");
        svc.ptr_rr = Some(rr.clone());
        mgr.register_service(svc);

        assert_eq!(
            mgr.links
                .get(&1)
                .unwrap()
                .mdns_ipv4_scope
                .as_ref()
                .unwrap()
                .zone
                .len(),
            1
        );
        bus_dnssd_method_unregister(&mut mgr, "svc1", false).unwrap();
        assert_eq!(
            mgr.links
                .get(&1)
                .unwrap()
                .mdns_ipv4_scope
                .as_ref()
                .unwrap()
                .zone
                .len(),
            0
        );
    }
}
