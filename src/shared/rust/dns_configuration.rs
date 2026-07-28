// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dns-configuration.c, src/shared/dns-configuration.h

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

pub const fn family_address_size_safe(family: i32) -> usize {
    match family {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonValueKind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

impl fmt::Display for JsonValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "null",
            Self::Bool => "bool",
            Self::Number => "number",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn kind(&self) -> JsonValueKind {
        match self {
            Self::Null => JsonValueKind::Null,
            Self::Bool(_) => JsonValueKind::Bool,
            Self::Number(_) => JsonValueKind::Number,
            Self::String(_) => JsonValueKind::String,
            Self::Array(_) => JsonValueKind::Array,
            Self::Object(_) => JsonValueKind::Object,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(array) => Some(array),
            _ => None,
        }
    }
}

impl From<bool> for JsonValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for JsonValue {
    fn from(value: i64) -> Self {
        Self::Number(value)
    }
}

impl From<i32> for JsonValue {
    fn from(value: i32) -> Self {
        Self::Number(i64::from(value))
    }
}

impl From<u16> for JsonValue {
    fn from(value: u16) -> Self {
        Self::Number(i64::from(value))
    }
}

impl From<&str> for JsonValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsConfigurationError {
    MissingField(&'static str),
    UnexpectedType {
        field: Option<&'static str>,
        expected: JsonValueKind,
        actual: JsonValueKind,
    },
    IntegerOutOfRange {
        field: &'static str,
        value: i64,
    },
    InvalidAddressLength {
        family: i32,
        expected: usize,
        actual: usize,
    },
}

impl DnsConfigurationError {
    fn unexpected_type(
        field: Option<&'static str>,
        expected: JsonValueKind,
        actual: &JsonValue,
    ) -> Self {
        Self::UnexpectedType {
            field,
            expected,
            actual: actual.kind(),
        }
    }
}

impl fmt::Display for DnsConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing mandatory field '{field}'"),
            Self::UnexpectedType {
                field,
                expected,
                actual,
            } => match field {
                Some(field) => write!(
                    f,
                    "field '{field}' has wrong type: expected {expected}, got {actual}"
                ),
                None => write!(
                    f,
                    "JSON value has wrong type: expected {expected}, got {actual}"
                ),
            },
            Self::IntegerOutOfRange { field, value } => {
                write!(f, "field '{field}' is out of range: {value}")
            }
            Self::InvalidAddressLength {
                family,
                expected,
                actual,
            } => write!(
                f,
                "dispatched address size ({actual}) is incompatible with family {family} (expected {expected})"
            ),
        }
    }
}

impl std::error::Error for DnsConfigurationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServer {
    pub addr: Vec<u8>,
    pub family: i32,
    pub port: u16,
    pub ifindex: i32,
    pub server_name: Option<String>,
    pub accessible: bool,
    pub in_addr: Option<IpAddr>,
}

impl DnsServer {
    pub fn from_json(value: &JsonValue) -> Result<Self, DnsConfigurationError> {
        let object = required_object(value, None)?;
        let addr = required_byte_array(object, "address")?;
        let family = required_i32(object, "family")?;
        let expected = family_address_size_safe(family);
        if addr.len() != expected {
            return Err(DnsConfigurationError::InvalidAddressLength {
                family,
                expected,
                actual: addr.len(),
            });
        }

        Ok(Self {
            in_addr: parse_ip_addr(family, &addr),
            addr,
            family,
            port: optional_u16(object, "port")?.unwrap_or(0),
            ifindex: optional_i32(object, "ifindex")?.unwrap_or(0),
            server_name: optional_string(object, "name")?,
            accessible: required_bool(object, "accessible")?,
        })
    }

    pub fn formatted_address(&self) -> Option<String> {
        self.in_addr.as_ref().map(ToString::to_string)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDomain {
    pub name: String,
    pub route_only: bool,
    pub ifindex: i32,
}

impl SearchDomain {
    pub fn from_json(value: &JsonValue) -> Result<Self, DnsConfigurationError> {
        let object = required_object(value, None)?;
        Ok(Self {
            name: required_string(object, "name")?,
            route_only: required_bool(object, "routeOnly")?,
            ifindex: optional_i32(object, "ifindex")?.unwrap_or(0),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsScope {
    pub ifname: Option<String>,
    pub ifindex: i32,
    pub protocol: String,
    pub family: i32,
    pub dnssec_mode_str: Option<String>,
    pub dns_over_tls_mode_str: Option<String>,
}

impl DnsScope {
    pub fn from_json(value: &JsonValue) -> Result<Self, DnsConfigurationError> {
        let object = required_object(value, None)?;
        Ok(Self {
            ifname: optional_string(object, "ifname")?,
            ifindex: optional_i32(object, "ifindex")?.unwrap_or(0),
            protocol: required_string(object, "protocol")?,
            family: optional_i32(object, "family")?.unwrap_or(0),
            dnssec_mode_str: optional_string(object, "dnssec")?,
            dns_over_tls_mode_str: optional_string(object, "dnsOverTLS")?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfiguration {
    pub ifname: Option<String>,
    pub ifindex: i32,
    pub default_route: bool,
    pub current_dns_server: Option<DnsServer>,
    pub dns_servers: Vec<DnsServer>,
    pub search_domains: Vec<SearchDomain>,
    pub fallback_dns_servers: Vec<DnsServer>,
    pub dns_scopes: Vec<DnsScope>,
    pub dnssec_mode_str: Option<String>,
    pub dns_over_tls_mode_str: Option<String>,
    pub llmnr_mode_str: Option<String>,
    pub mdns_mode_str: Option<String>,
    pub negative_trust_anchors: Vec<String>,
    pub resolv_conf_mode_str: Option<String>,
    pub delegate: Option<String>,
    pub dnssec_supported: bool,
}

impl DnsConfiguration {
    pub fn from_json(value: &JsonValue) -> Result<Self, DnsConfigurationError> {
        let object = required_object(value, None)?;
        let mut negative_trust_anchors =
            optional_string_array(object, "negativeTrustAnchors")?.unwrap_or_default();
        negative_trust_anchors.sort();

        Ok(Self {
            ifname: optional_string(object, "ifname")?,
            ifindex: optional_i32(object, "ifindex")?.unwrap_or(0),
            default_route: optional_bool(object, "defaultRoute")?.unwrap_or(false),
            current_dns_server: optional_object(object, "currentServer")?
                .map(DnsServer::from_json)
                .transpose()?,
            dns_servers: optional_array(object, "servers")?
                .map(parse_dns_servers)
                .transpose()?
                .unwrap_or_default(),
            search_domains: optional_array(object, "searchDomains")?
                .map(parse_search_domains)
                .transpose()?
                .unwrap_or_default(),
            fallback_dns_servers: optional_array(object, "fallbackServers")?
                .map(parse_dns_servers)
                .transpose()?
                .unwrap_or_default(),
            dns_scopes: optional_array(object, "scopes")?
                .map(parse_dns_scopes)
                .transpose()?
                .unwrap_or_default(),
            dnssec_mode_str: optional_string(object, "dnssec")?,
            dns_over_tls_mode_str: optional_string(object, "dnsOverTLS")?,
            llmnr_mode_str: optional_string(object, "llmnr")?,
            mdns_mode_str: optional_string(object, "mDNS")?,
            negative_trust_anchors,
            resolv_conf_mode_str: optional_string(object, "resolvConfMode")?,
            delegate: optional_string(object, "delegate")?,
            dnssec_supported: optional_bool(object, "dnssecSupported")?.unwrap_or(false),
        })
    }

    pub fn is_accessible(&self) -> bool {
        self.current_dns_server
            .as_ref()
            .is_some_and(|server| server.accessible)
            || self.dns_servers.iter().any(|server| server.accessible)
    }

    pub fn contains_search_domain(&self, domain: &str) -> bool {
        self.search_domains
            .iter()
            .any(|search| search.name == domain)
    }
}

pub fn dns_configuration_from_json(
    value: &JsonValue,
) -> Result<DnsConfiguration, DnsConfigurationError> {
    DnsConfiguration::from_json(value)
}

pub fn dns_is_accessible(config: Option<&DnsConfiguration>) -> bool {
    config.is_some_and(DnsConfiguration::is_accessible)
}

pub fn dns_configuration_contains_search_domain(
    config: Option<&DnsConfiguration>,
    domain: &str,
) -> bool {
    config.is_some_and(|config| config.contains_search_domain(domain))
}

fn parse_ip_addr(family: i32, addr: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET if addr.len() == 4 => Some(IpAddr::V4(Ipv4Addr::from([
            addr[0], addr[1], addr[2], addr[3],
        ]))),
        AF_INET6 if addr.len() == 16 => {
            let octets: [u8; 16] = addr.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_dns_servers(values: &[JsonValue]) -> Result<Vec<DnsServer>, DnsConfigurationError> {
    values.iter().map(DnsServer::from_json).collect()
}

fn parse_search_domains(values: &[JsonValue]) -> Result<Vec<SearchDomain>, DnsConfigurationError> {
    values.iter().map(SearchDomain::from_json).collect()
}

fn parse_dns_scopes(values: &[JsonValue]) -> Result<Vec<DnsScope>, DnsConfigurationError> {
    values.iter().map(DnsScope::from_json).collect()
}

fn required_object<'a>(
    value: &'a JsonValue,
    field: Option<&'static str>,
) -> Result<&'a BTreeMap<String, JsonValue>, DnsConfigurationError> {
    value
        .as_object()
        .ok_or_else(|| DnsConfigurationError::unexpected_type(field, JsonValueKind::Object, value))
}

fn required_field<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<&'a JsonValue, DnsConfigurationError> {
    object
        .get(field)
        .ok_or(DnsConfigurationError::MissingField(field))
}

fn optional_field<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Option<&'a JsonValue> {
    object.get(field)
}

fn required_string(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<String, DnsConfigurationError> {
    match required_field(object, field)? {
        JsonValue::String(value) => Ok(value.clone()),
        value => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::String,
            value,
        )),
    }
}

fn optional_string(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<Option<String>, DnsConfigurationError> {
    match optional_field(object, field) {
        None => Ok(None),
        Some(JsonValue::String(value)) => Ok(Some(value.clone())),
        Some(value) => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::String,
            value,
        )),
    }
}

fn required_bool(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<bool, DnsConfigurationError> {
    match required_field(object, field)? {
        JsonValue::Bool(value) => Ok(*value),
        value => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::Bool,
            value,
        )),
    }
}

fn optional_bool(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<Option<bool>, DnsConfigurationError> {
    match optional_field(object, field) {
        None => Ok(None),
        Some(JsonValue::Bool(value)) => Ok(Some(*value)),
        Some(value) => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::Bool,
            value,
        )),
    }
}

fn required_i32(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<i32, DnsConfigurationError> {
    parse_i32(required_field(object, field)?, field)
}

fn optional_i32(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<Option<i32>, DnsConfigurationError> {
    optional_field(object, field)
        .map(|value| parse_i32(value, field))
        .transpose()
}

fn optional_u16(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<Option<u16>, DnsConfigurationError> {
    optional_field(object, field)
        .map(|value| parse_u16(value, field))
        .transpose()
}

fn optional_array<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<Option<&'a [JsonValue]>, DnsConfigurationError> {
    match optional_field(object, field) {
        None => Ok(None),
        Some(JsonValue::Array(value)) => Ok(Some(value)),
        Some(value) => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::Array,
            value,
        )),
    }
}

fn optional_object<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<Option<&'a JsonValue>, DnsConfigurationError> {
    match optional_field(object, field) {
        None => Ok(None),
        Some(value @ JsonValue::Object(_)) => Ok(Some(value)),
        Some(value) => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::Object,
            value,
        )),
    }
}

fn required_byte_array(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<Vec<u8>, DnsConfigurationError> {
    let value = required_field(object, field)?;
    let array = value.as_array().ok_or_else(|| {
        DnsConfigurationError::unexpected_type(Some(field), JsonValueKind::Array, value)
    })?;

    array
        .iter()
        .map(|entry| parse_u8(entry, field))
        .collect::<Result<Vec<_>, _>>()
}

fn optional_string_array(
    object: &BTreeMap<String, JsonValue>,
    field: &'static str,
) -> Result<Option<Vec<String>>, DnsConfigurationError> {
    let Some(array) = optional_array(object, field)? else {
        return Ok(None);
    };

    array
        .iter()
        .map(|entry| match entry {
            JsonValue::String(value) => Ok(value.clone()),
            value => Err(DnsConfigurationError::unexpected_type(
                Some(field),
                JsonValueKind::String,
                value,
            )),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn parse_i32(value: &JsonValue, field: &'static str) -> Result<i32, DnsConfigurationError> {
    match value {
        JsonValue::Number(number) => {
            i32::try_from(*number).map_err(|_| DnsConfigurationError::IntegerOutOfRange {
                field,
                value: *number,
            })
        }
        value => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::Number,
            value,
        )),
    }
}

fn parse_u16(value: &JsonValue, field: &'static str) -> Result<u16, DnsConfigurationError> {
    match value {
        JsonValue::Number(number) => {
            u16::try_from(*number).map_err(|_| DnsConfigurationError::IntegerOutOfRange {
                field,
                value: *number,
            })
        }
        value => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::Number,
            value,
        )),
    }
}

fn parse_u8(value: &JsonValue, field: &'static str) -> Result<u8, DnsConfigurationError> {
    match value {
        JsonValue::Number(number) => {
            u8::try_from(*number).map_err(|_| DnsConfigurationError::IntegerOutOfRange {
                field,
                value: *number,
            })
        }
        value => Err(DnsConfigurationError::unexpected_type(
            Some(field),
            JsonValueKind::Number,
            value,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(fields: &[(&str, JsonValue)]) -> JsonValue {
        JsonValue::Object(
            fields
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone()))
                .collect(),
        )
    }

    fn array(values: Vec<JsonValue>) -> JsonValue {
        JsonValue::Array(values)
    }

    fn ipv4_server_json(accessible: bool) -> JsonValue {
        object(&[
            (
                "address",
                array(vec![127.into(), 0.into(), 0.into(), 53.into()]),
            ),
            ("family", AF_INET.into()),
            ("port", 53u16.into()),
            ("ifindex", 7.into()),
            ("name", "resolver".into()),
            ("accessible", accessible.into()),
        ])
    }

    #[test]
    fn family_address_size_safe_matches_c_macro() {
        assert_eq!(family_address_size_safe(AF_INET), 4);
        assert_eq!(family_address_size_safe(AF_INET6), 16);
        assert_eq!(family_address_size_safe(999), 0);
    }

    #[test]
    fn dns_server_from_json_parses_ipv4() {
        let server = DnsServer::from_json(&ipv4_server_json(true)).unwrap();
        assert_eq!(server.family, AF_INET);
        assert_eq!(server.port, 53);
        assert_eq!(server.ifindex, 7);
        assert_eq!(server.server_name.as_deref(), Some("resolver"));
        assert!(server.accessible);
        assert_eq!(server.formatted_address().as_deref(), Some("127.0.0.53"));
    }

    #[test]
    fn dns_server_from_json_parses_ipv6() {
        let server = DnsServer::from_json(&object(&[
            (
                "address",
                array(vec![
                    0x20.into(),
                    0x01.into(),
                    0x0d.into(),
                    0xb8.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0x35.into(),
                ]),
            ),
            ("family", AF_INET6.into()),
            ("accessible", true.into()),
        ]))
        .unwrap();

        assert_eq!(server.formatted_address().as_deref(), Some("2001:db8::35"));
    }

    #[test]
    fn dns_server_from_json_allows_unknown_family_with_empty_address() {
        let server = DnsServer::from_json(&object(&[
            ("address", array(vec![])),
            ("family", 4711.into()),
            ("accessible", false.into()),
        ]))
        .unwrap();

        assert_eq!(server.family, 4711);
        assert!(server.addr.is_empty());
        assert!(server.in_addr.is_none());
        assert!(server.formatted_address().is_none());
    }

    #[test]
    fn dns_server_from_json_rejects_wrong_address_length() {
        let error = DnsServer::from_json(&object(&[
            ("address", array(vec![127.into(), 0.into(), 0.into()])),
            ("family", AF_INET.into()),
            ("accessible", true.into()),
        ]))
        .unwrap_err();

        assert_eq!(
            error,
            DnsConfigurationError::InvalidAddressLength {
                family: AF_INET,
                expected: 4,
                actual: 3,
            }
        );
    }

    #[test]
    fn dns_server_from_json_requires_accessible() {
        let error = DnsServer::from_json(&object(&[
            (
                "address",
                array(vec![127.into(), 0.into(), 0.into(), 53.into()]),
            ),
            ("family", AF_INET.into()),
        ]))
        .unwrap_err();

        assert_eq!(error, DnsConfigurationError::MissingField("accessible"));
    }

    #[test]
    fn dns_server_from_json_rejects_non_numeric_address_byte() {
        let error = DnsServer::from_json(&object(&[
            (
                "address",
                array(vec![
                    127.into(),
                    0.into(),
                    JsonValue::String("x".into()),
                    53.into(),
                ]),
            ),
            ("family", AF_INET.into()),
            ("accessible", true.into()),
        ]))
        .unwrap_err();

        assert_eq!(
            error,
            DnsConfigurationError::UnexpectedType {
                field: Some("address"),
                expected: JsonValueKind::Number,
                actual: JsonValueKind::String,
            }
        );
    }

    #[test]
    fn search_domain_from_json_parses_required_fields() {
        let domain = SearchDomain::from_json(&object(&[
            ("name", "example.com".into()),
            ("routeOnly", true.into()),
            ("ifindex", 12.into()),
        ]))
        .unwrap();

        assert_eq!(domain.name, "example.com");
        assert!(domain.route_only);
        assert_eq!(domain.ifindex, 12);
    }

    #[test]
    fn dns_scope_from_json_parses_optional_fields() {
        let scope = DnsScope::from_json(&object(&[
            ("protocol", "dns".into()),
            ("family", AF_INET6.into()),
            ("ifname", "eth0".into()),
            ("ifindex", 3.into()),
            ("dnssec", "allow-downgrade".into()),
            ("dnsOverTLS", "opportunistic".into()),
        ]))
        .unwrap();

        assert_eq!(scope.protocol, "dns");
        assert_eq!(scope.family, AF_INET6);
        assert_eq!(scope.ifname.as_deref(), Some("eth0"));
        assert_eq!(scope.ifindex, 3);
        assert_eq!(scope.dnssec_mode_str.as_deref(), Some("allow-downgrade"));
        assert_eq!(
            scope.dns_over_tls_mode_str.as_deref(),
            Some("opportunistic")
        );
    }

    #[test]
    fn dns_configuration_from_json_sorts_negative_trust_anchors() {
        let config = dns_configuration_from_json(&object(&[(
            "negativeTrustAnchors",
            array(vec![
                "z.example".into(),
                "a.example".into(),
                "m.example".into(),
            ]),
        )]))
        .unwrap();

        assert_eq!(
            config.negative_trust_anchors,
            vec!["a.example", "m.example", "z.example"]
        );
    }

    #[test]
    fn dns_configuration_from_json_parses_full_configuration() {
        let config = dns_configuration_from_json(&object(&[
            ("ifname", "eth0".into()),
            ("ifindex", 2.into()),
            ("defaultRoute", true.into()),
            ("currentServer", ipv4_server_json(true)),
            (
                "servers",
                array(vec![ipv4_server_json(false), ipv4_server_json(true)]),
            ),
            (
                "searchDomains",
                array(vec![object(&[
                    ("name", "example.com".into()),
                    ("routeOnly", false.into()),
                ])]),
            ),
            ("dnssecSupported", true.into()),
            ("dnssec", "yes".into()),
            ("dnsOverTLS", "opportunistic".into()),
            ("llmnr", "resolve".into()),
            ("mDNS", "no".into()),
            ("fallbackServers", array(vec![ipv4_server_json(true)])),
            (
                "negativeTrustAnchors",
                array(vec!["b.example".into(), "a.example".into()]),
            ),
            ("resolvConfMode", "uplink".into()),
            (
                "scopes",
                array(vec![object(&[
                    ("protocol", "dns".into()),
                    ("family", AF_INET.into()),
                ])]),
            ),
            ("delegate", "stub".into()),
        ]))
        .unwrap();

        assert_eq!(config.ifname.as_deref(), Some("eth0"));
        assert_eq!(config.ifindex, 2);
        assert!(config.default_route);
        assert_eq!(config.dns_servers.len(), 2);
        assert_eq!(config.search_domains.len(), 1);
        assert_eq!(config.fallback_dns_servers.len(), 1);
        assert_eq!(config.dns_scopes.len(), 1);
        assert!(config.dnssec_supported);
        assert_eq!(config.dnssec_mode_str.as_deref(), Some("yes"));
        assert_eq!(
            config.dns_over_tls_mode_str.as_deref(),
            Some("opportunistic")
        );
        assert_eq!(config.llmnr_mode_str.as_deref(), Some("resolve"));
        assert_eq!(config.mdns_mode_str.as_deref(), Some("no"));
        assert_eq!(config.resolv_conf_mode_str.as_deref(), Some("uplink"));
        assert_eq!(config.delegate.as_deref(), Some("stub"));
        assert_eq!(
            config.negative_trust_anchors,
            vec!["a.example", "b.example"]
        );
    }

    #[test]
    fn dns_configuration_is_accessible_checks_current_server_first() {
        let config = DnsConfiguration {
            current_dns_server: Some(DnsServer::from_json(&ipv4_server_json(true)).unwrap()),
            ..DnsConfiguration::default()
        };

        assert!(config.is_accessible());
        assert!(dns_is_accessible(Some(&config)));
    }

    #[test]
    fn dns_configuration_is_accessible_checks_servers_when_current_is_not_accessible() {
        let config = DnsConfiguration {
            current_dns_server: Some(DnsServer::from_json(&ipv4_server_json(false)).unwrap()),
            dns_servers: vec![DnsServer::from_json(&ipv4_server_json(true)).unwrap()],
            ..DnsConfiguration::default()
        };

        assert!(config.is_accessible());
    }

    #[test]
    fn dns_configuration_is_accessible_returns_false_for_none() {
        assert!(!dns_is_accessible(None));
    }

    #[test]
    fn dns_configuration_contains_search_domain_matches_exact_name() {
        let config = DnsConfiguration {
            search_domains: vec![SearchDomain {
                name: "example.com".into(),
                route_only: false,
                ifindex: 0,
            }],
            ..DnsConfiguration::default()
        };

        assert!(config.contains_search_domain("example.com"));
        assert!(dns_configuration_contains_search_domain(
            Some(&config),
            "example.com"
        ));
        assert!(!config.contains_search_domain("com"));
    }

    #[test]
    fn dns_configuration_contains_search_domain_returns_false_for_none() {
        assert!(!dns_configuration_contains_search_domain(
            None,
            "example.com"
        ));
    }

    #[test]
    fn dns_configuration_rejects_wrong_current_server_type() {
        let error =
            dns_configuration_from_json(&object(&[("currentServer", array(vec![]))])).unwrap_err();

        assert_eq!(
            error,
            DnsConfigurationError::UnexpectedType {
                field: Some("currentServer"),
                expected: JsonValueKind::Object,
                actual: JsonValueKind::Array,
            }
        );
    }

    #[test]
    fn dns_configuration_rejects_out_of_range_ifindex() {
        let error =
            dns_configuration_from_json(&object(&[("ifindex", JsonValue::Number(i64::MAX))]))
                .unwrap_err();

        assert_eq!(
            error,
            DnsConfigurationError::IntegerOutOfRange {
                field: "ifindex",
                value: i64::MAX,
            }
        );
    }

    #[test]
    fn dns_configuration_preserves_duplicate_servers() {
        let config = dns_configuration_from_json(&object(&[(
            "servers",
            array(vec![ipv4_server_json(true), ipv4_server_json(true)]),
        )]))
        .unwrap();

        assert_eq!(config.dns_servers.len(), 2);
    }
}
