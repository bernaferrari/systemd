// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/netif-naming-scheme.c, src/shared/netif-naming-scheme.h

use crate::ffi::*;
use std::env;
use std::fs;
use std::sync::OnceLock;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct NamingSchemeFlags: u64 {
        const NAMING_SR_IOV_V                  = 1 << 0;
        const NAMING_NPAR_ARI                  = 1 << 1;
        const NAMING_INFINIBAND                = 1 << 2;
        const NAMING_ZERO_ACPI_INDEX           = 1 << 3;
        const NAMING_ALLOW_RERENAMES           = 1 << 4;
        const NAMING_STABLE_VIRTUAL_MACS       = 1 << 5;
        const NAMING_NETDEVSIM                 = 1 << 6;
        const NAMING_LABEL_NOPREFIX            = 1 << 7;
        const NAMING_NSPAWN_LONG_HASH          = 1 << 8;
        const NAMING_BRIDGE_NO_SLOT            = 1 << 9;
        const NAMING_SLOT_FUNCTION_ID          = 1 << 10;
        const NAMING_16BIT_INDEX               = 1 << 11;
        const NAMING_REPLACE_STRICTLY          = 1 << 12;
        const NAMING_XEN_VIF                   = 1 << 13;
        const NAMING_BRIDGE_MULTIFUNCTION_SLOT = 1 << 14;
        const NAMING_DEVICETREE_ALIASES        = 1 << 15;
        const NAMING_USB_HOST                  = 1 << 16;
        const NAMING_SR_IOV_R                  = 1 << 17;
        const NAMING_FIRMWARE_NODE_SUN         = 1 << 18;
        const NAMING_DEVICETREE_PORT_ALIASES   = 1 << 19;
        const NAMING_USE_INTERFACE_PROPERTY    = 1 << 20;
        const NAMING_DEVICETREE_ALIASES_WLAN   = 1 << 21;
        const NAMING_MCTP                      = 1 << 22;
    }
}

impl NamingSchemeFlags {
    pub const NAMING_V238: Self = Self::empty();
    pub const NAMING_V239: Self = Self::NAMING_V238
        .union(Self::NAMING_SR_IOV_V)
        .union(Self::NAMING_NPAR_ARI);
    pub const NAMING_V240: Self = Self::NAMING_V239
        .union(Self::NAMING_INFINIBAND)
        .union(Self::NAMING_ZERO_ACPI_INDEX)
        .union(Self::NAMING_ALLOW_RERENAMES);
    pub const NAMING_V241: Self = Self::NAMING_V240.union(Self::NAMING_STABLE_VIRTUAL_MACS);
    pub const NAMING_V243: Self = Self::NAMING_V241
        .union(Self::NAMING_NETDEVSIM)
        .union(Self::NAMING_LABEL_NOPREFIX);
    pub const NAMING_V245: Self = Self::NAMING_V243.union(Self::NAMING_NSPAWN_LONG_HASH);
    pub const NAMING_V247: Self = Self::NAMING_V245.union(Self::NAMING_BRIDGE_NO_SLOT);
    pub const NAMING_V249: Self = Self::NAMING_V247
        .union(Self::NAMING_SLOT_FUNCTION_ID)
        .union(Self::NAMING_16BIT_INDEX)
        .union(Self::NAMING_REPLACE_STRICTLY);
    pub const NAMING_V250: Self = Self::NAMING_V249.union(Self::NAMING_XEN_VIF);
    pub const NAMING_V251: Self = Self::NAMING_V250.union(Self::NAMING_BRIDGE_MULTIFUNCTION_SLOT);
    pub const NAMING_V252: Self = Self::NAMING_V251.union(Self::NAMING_DEVICETREE_ALIASES);
    pub const NAMING_V253: Self = Self::NAMING_V252.union(Self::NAMING_USB_HOST);
    pub const NAMING_V254: Self = Self::NAMING_V253.union(Self::NAMING_SR_IOV_R);
    pub const NAMING_V255: Self = Self::from_bits_retain(
        Self::NAMING_V254.bits() & !Self::NAMING_BRIDGE_MULTIFUNCTION_SLOT.bits(),
    );
    pub const NAMING_V257: Self = Self::NAMING_V255
        .union(Self::NAMING_FIRMWARE_NODE_SUN)
        .union(Self::NAMING_DEVICETREE_PORT_ALIASES);
    pub const NAMING_V258: Self = Self::NAMING_V257.union(Self::NAMING_USE_INTERFACE_PROPERTY);
    pub const NAMING_V259: Self = Self::NAMING_V258.union(Self::NAMING_DEVICETREE_ALIASES_WLAN);
    pub const NAMING_V260: Self = Self::NAMING_V259.union(Self::NAMING_MCTP);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamingScheme {
    V238,
    V239,
    V240,
    V241,
    V243,
    V245,
    V247,
    V249,
    V250,
    V251,
    V252,
    V253,
    V254,
    V255,
    V257,
    V258,
    V259,
    V260,
}

impl NamingScheme {
    pub const ALL: [Self; 18] = [
        Self::V238,
        Self::V239,
        Self::V240,
        Self::V241,
        Self::V243,
        Self::V245,
        Self::V247,
        Self::V249,
        Self::V250,
        Self::V251,
        Self::V252,
        Self::V253,
        Self::V254,
        Self::V255,
        Self::V257,
        Self::V258,
        Self::V259,
        Self::V260,
    ];

    pub const fn latest() -> Self {
        Self::V260
    }

    pub const fn flags(self) -> NamingSchemeFlags {
        match self {
            Self::V238 => NamingSchemeFlags::NAMING_V238,
            Self::V239 => NamingSchemeFlags::NAMING_V239,
            Self::V240 => NamingSchemeFlags::NAMING_V240,
            Self::V241 => NamingSchemeFlags::NAMING_V241,
            Self::V243 => NamingSchemeFlags::NAMING_V243,
            Self::V245 => NamingSchemeFlags::NAMING_V245,
            Self::V247 => NamingSchemeFlags::NAMING_V247,
            Self::V249 => NamingSchemeFlags::NAMING_V249,
            Self::V250 => NamingSchemeFlags::NAMING_V250,
            Self::V251 => NamingSchemeFlags::NAMING_V251,
            Self::V252 => NamingSchemeFlags::NAMING_V252,
            Self::V253 => NamingSchemeFlags::NAMING_V253,
            Self::V254 => NamingSchemeFlags::NAMING_V254,
            Self::V255 => NamingSchemeFlags::NAMING_V255,
            Self::V257 => NamingSchemeFlags::NAMING_V257,
            Self::V258 => NamingSchemeFlags::NAMING_V258,
            Self::V259 => NamingSchemeFlags::NAMING_V259,
            Self::V260 => NamingSchemeFlags::NAMING_V260,
        }
    }

    pub const fn to_string(self) -> &'static str {
        match self {
            Self::V238 => "v238",
            Self::V239 => "v239",
            Self::V240 => "v240",
            Self::V241 => "v241",
            Self::V243 => "v243",
            Self::V245 => "v245",
            Self::V247 => "v247",
            Self::V249 => "v249",
            Self::V250 => "v250",
            Self::V251 => "v251",
            Self::V252 => "v252",
            Self::V253 => "v253",
            Self::V254 => "v254",
            Self::V255 => "v255",
            Self::V257 => "v257",
            Self::V258 => "v258",
            Self::V259 => "v259",
            Self::V260 => "v260",
        }
    }

    pub fn from_string(name: &str) -> Option<Self> {
        match name {
            "v238" => Some(Self::V238),
            "v239" => Some(Self::V239),
            "v240" => Some(Self::V240),
            "v241" => Some(Self::V241),
            "v243" => Some(Self::V243),
            "v245" => Some(Self::V245),
            "v247" => Some(Self::V247),
            "v249" => Some(Self::V249),
            "v250" => Some(Self::V250),
            "v251" => Some(Self::V251),
            "v252" => Some(Self::V252),
            "v253" => Some(Self::V253),
            "v254" => Some(Self::V254),
            "v255" => Some(Self::V255),
            "v257" => Some(Self::V257),
            "v258" => Some(Self::V258),
            "v259" => Some(Self::V259),
            "v260" => Some(Self::V260),
            "latest" => Some(Self::latest()),
            _ => None,
        }
    }
}

impl Default for NamingScheme {
    fn default() -> Self {
        naming_scheme()
    }
}

pub static DEFAULT_NET_NAMING_SCHEME: &str = match option_env!("SYSTEMD_DEFAULT_NET_NAMING_SCHEME")
{
    Some(v) => v,
    None => "latest",
};

pub fn naming_scheme_from_name(name: &str) -> Option<NamingScheme> {
    NamingScheme::from_string(name)
}

pub fn naming_scheme_has(flags: NamingSchemeFlags) -> bool {
    naming_scheme().flags().contains(flags)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamingSchemeSources<'a> {
    pub kernel_cmdline: Option<&'a str>,
    pub env_value: Option<&'a str>,
    pub default_scheme: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedNamingSchemeSources {
    pub kernel_cmdline: Option<String>,
    pub env_value: Option<String>,
    pub default_scheme: &'static str,
}

impl OwnedNamingSchemeSources {
    pub fn as_borrowed(&self) -> NamingSchemeSources<'_> {
        NamingSchemeSources {
            kernel_cmdline: self.kernel_cmdline.as_deref(),
            env_value: self.env_value.as_deref(),
            default_scheme: self.default_scheme,
        }
    }
}

impl Default for NamingSchemeSources<'static> {
    fn default() -> Self {
        Self {
            kernel_cmdline: None,
            env_value: None,
            default_scheme: DEFAULT_NET_NAMING_SCHEME,
        }
    }
}

pub fn naming_scheme() -> NamingScheme {
    static CACHE: OnceLock<NamingScheme> = OnceLock::new();

    *CACHE.get_or_init(detect_naming_scheme)
}

pub fn detect_naming_scheme() -> NamingScheme {
    resolve_naming_scheme(detect_naming_scheme_sources().as_borrowed())
}

pub fn detect_naming_scheme_sources() -> OwnedNamingSchemeSources {
    let kernel_cmdline = read_kernel_cmdline()
        .ok()
        .and_then(|cmdline| extract_cmdline_key(&cmdline, "net.naming_scheme").map(str::to_string));

    let env_value = env::var("NET_NAMING_SCHEME").ok();

    OwnedNamingSchemeSources {
        kernel_cmdline,
        env_value,
        default_scheme: DEFAULT_NET_NAMING_SCHEME,
    }
}

pub fn resolve_naming_scheme(sources: NamingSchemeSources<'_>) -> NamingScheme {
    let requested = match sources.env_value {
        Some(value) if value.starts_with(':') => {
            sources.kernel_cmdline.or_else(|| Some(&value[1..]))
        }
        Some(value) => Some(value),
        None => sources.kernel_cmdline,
    };

    requested
        .and_then(NamingScheme::from_string)
        .or_else(|| NamingScheme::from_string(sources.default_scheme))
        .unwrap_or_else(NamingScheme::latest)
}

pub fn read_kernel_cmdline() -> std::io::Result<String> {
    fs::read_to_string("/proc/cmdline")
}

pub fn extract_cmdline_key<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline.split_ascii_whitespace().find_map(|item| {
        item.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum NamePolicy {
    Kernel = 0,
    Keep = 1,
    Database = 2,
    Onboard = 3,
    Slot = 4,
    Path = 5,
    Mac = 6,
}

impl NamePolicy {
    pub fn from_string(value: &str) -> Option<Self> {
        match value {
            "kernel" => Some(Self::Kernel),
            "keep" => Some(Self::Keep),
            "database" => Some(Self::Database),
            "onboard" => Some(Self::Onboard),
            "slot" => Some(Self::Slot),
            "path" => Some(Self::Path),
            "mac" => Some(Self::Mac),
            _ => None,
        }
    }

    pub const fn to_string(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Keep => "keep",
            Self::Database => "database",
            Self::Onboard => "onboard",
            Self::Slot => "slot",
            Self::Path => "path",
            Self::Mac => "mac",
        }
    }

    pub fn from_alternative_names_policy_string(value: &str) -> Option<Self> {
        match value {
            "database" => Some(Self::Database),
            "onboard" => Some(Self::Onboard),
            "slot" => Some(Self::Slot),
            "path" => Some(Self::Path),
            "mac" => Some(Self::Mac),
            _ => None,
        }
    }

    pub const fn to_alternative_names_policy_string(self) -> Option<&'static str> {
        match self {
            Self::Kernel | Self::Keep => None,
            Self::Database => Some("database"),
            Self::Onboard => Some("onboard"),
            Self::Slot => Some("slot"),
            Self::Path => Some("path"),
            Self::Mac => Some("mac"),
        }
    }
}

pub fn name_policy_from_string(value: &str) -> Option<NamePolicy> {
    NamePolicy::from_string(value)
}

pub const fn name_policy_to_string(value: NamePolicy) -> &'static str {
    value.to_string()
}

pub fn alternative_names_policy_from_string(value: &str) -> Option<NamePolicy> {
    NamePolicy::from_alternative_names_policy_string(value)
}

pub const fn alternative_names_policy_to_string(value: NamePolicy) -> Option<&'static str> {
    value.to_alternative_names_policy_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysattrError {
    NotFound,
    Failed(String),
}

pub trait NetNamingDevice {
    fn property_bool(&self, property: &str) -> Result<bool, SysattrError>;
    fn sysattr_int(&self, sysattr: &str) -> Result<i32, SysattrError>;
    fn sysattr_unsigned(&self, sysattr: &str) -> Result<u32, SysattrError>;
    fn sysattr_bool(&self, sysattr: &str) -> Result<bool, SysattrError>;
    fn sysattr_value(&self, sysattr: &str) -> Result<String, SysattrError>;
}

pub fn naming_sysattr_allowed_by_default<D: NetNamingDevice>(
    dev: &D,
) -> Result<bool, SysattrError> {
    match dev.property_bool("ID_NET_NAME_ALLOW") {
        Ok(value) => Ok(value),
        Err(SysattrError::NotFound) => Ok(true),
        Err(err) => Err(err),
    }
}

pub fn naming_sysattr_allowed<D: NetNamingDevice>(
    dev: &D,
    sysattr: &str,
) -> Result<bool, SysattrError> {
    let property = format!("ID_NET_NAME_ALLOW_{}", sysattr).to_ascii_uppercase();

    match dev.property_bool(&property) {
        Ok(value) => Ok(value),
        Err(SysattrError::NotFound) => naming_sysattr_allowed_by_default(dev),
        Err(err) => Err(err),
    }
}

pub fn device_get_sysattr_int_filtered<D: NetNamingDevice>(
    device: &D,
    sysattr: &str,
) -> Result<i32, SysattrError> {
    if naming_sysattr_allowed(device, sysattr)? {
        device.sysattr_int(sysattr)
    } else {
        Err(SysattrError::NotFound)
    }
}

pub fn device_get_sysattr_unsigned_filtered<D: NetNamingDevice>(
    device: &D,
    sysattr: &str,
) -> Result<u32, SysattrError> {
    if naming_sysattr_allowed(device, sysattr)? {
        device.sysattr_unsigned(sysattr)
    } else {
        Err(SysattrError::NotFound)
    }
}

pub fn device_get_sysattr_bool_filtered<D: NetNamingDevice>(
    device: &D,
    sysattr: &str,
) -> Result<bool, SysattrError> {
    if naming_sysattr_allowed(device, sysattr)? {
        device.sysattr_bool(sysattr)
    } else {
        Err(SysattrError::NotFound)
    }
}

pub fn device_get_sysattr_value_filtered<D: NetNamingDevice>(
    device: &D,
    sysattr: &str,
) -> Result<String, SysattrError> {
    if naming_sysattr_allowed(device, sysattr)? {
        device.sysattr_value(sysattr)
    } else {
        Err(SysattrError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockDevice {
        properties: HashMap<String, Result<bool, SysattrError>>,
        int_sysattrs: HashMap<String, Result<i32, SysattrError>>,
        unsigned_sysattrs: HashMap<String, Result<u32, SysattrError>>,
        bool_sysattrs: HashMap<String, Result<bool, SysattrError>>,
        value_sysattrs: HashMap<String, Result<String, SysattrError>>,
    }

    impl MockDevice {
        fn with_property(mut self, key: &str, value: Result<bool, SysattrError>) -> Self {
            self.properties.insert(key.to_string(), value);
            self
        }

        fn with_int_sysattr(mut self, key: &str, value: Result<i32, SysattrError>) -> Self {
            self.int_sysattrs.insert(key.to_string(), value);
            self
        }

        fn with_unsigned_sysattr(mut self, key: &str, value: Result<u32, SysattrError>) -> Self {
            self.unsigned_sysattrs.insert(key.to_string(), value);
            self
        }

        fn with_bool_sysattr(mut self, key: &str, value: Result<bool, SysattrError>) -> Self {
            self.bool_sysattrs.insert(key.to_string(), value);
            self
        }

        fn with_value_sysattr(mut self, key: &str, value: Result<&str, SysattrError>) -> Self {
            self.value_sysattrs
                .insert(key.to_string(), value.map(str::to_string));
            self
        }
    }

    impl NetNamingDevice for MockDevice {
        fn property_bool(&self, property: &str) -> Result<bool, SysattrError> {
            self.properties
                .get(property)
                .cloned()
                .unwrap_or(Err(SysattrError::NotFound))
        }

        fn sysattr_int(&self, sysattr: &str) -> Result<i32, SysattrError> {
            self.int_sysattrs
                .get(sysattr)
                .cloned()
                .unwrap_or(Err(SysattrError::NotFound))
        }

        fn sysattr_unsigned(&self, sysattr: &str) -> Result<u32, SysattrError> {
            self.unsigned_sysattrs
                .get(sysattr)
                .cloned()
                .unwrap_or(Err(SysattrError::NotFound))
        }

        fn sysattr_bool(&self, sysattr: &str) -> Result<bool, SysattrError> {
            self.bool_sysattrs
                .get(sysattr)
                .cloned()
                .unwrap_or(Err(SysattrError::NotFound))
        }

        fn sysattr_value(&self, sysattr: &str) -> Result<String, SysattrError> {
            self.value_sysattrs
                .get(sysattr)
                .cloned()
                .unwrap_or(Err(SysattrError::NotFound))
        }
    }

    #[test]
    fn naming_scheme_from_name_handles_latest_and_unknown() {
        assert_eq!(naming_scheme_from_name("v255"), Some(NamingScheme::V255));
        assert_eq!(naming_scheme_from_name("latest"), Some(NamingScheme::V260));
        assert_eq!(naming_scheme_from_name("v999"), None);
    }

    #[test]
    fn naming_scheme_round_trips() {
        for scheme in NamingScheme::ALL {
            assert_eq!(NamingScheme::from_string(scheme.to_string()), Some(scheme));
        }
    }

    #[test]
    fn naming_scheme_flags_match_c_transitions() {
        assert!(
            NamingScheme::V239
                .flags()
                .contains(NamingSchemeFlags::NAMING_SR_IOV_V | NamingSchemeFlags::NAMING_NPAR_ARI)
        );
        assert!(
            NamingScheme::V254
                .flags()
                .contains(NamingSchemeFlags::NAMING_SR_IOV_R)
        );
        assert!(
            NamingScheme::V254
                .flags()
                .contains(NamingSchemeFlags::NAMING_BRIDGE_MULTIFUNCTION_SLOT)
        );
        assert!(
            !NamingScheme::V255
                .flags()
                .contains(NamingSchemeFlags::NAMING_BRIDGE_MULTIFUNCTION_SLOT)
        );
        assert!(
            NamingScheme::V260
                .flags()
                .contains(NamingSchemeFlags::NAMING_MCTP)
        );
    }

    #[test]
    fn resolve_naming_scheme_prefers_cmdline_when_env_is_colon_prefixed() {
        let scheme = resolve_naming_scheme(NamingSchemeSources {
            kernel_cmdline: Some("v249"),
            env_value: Some(":v255"),
            default_scheme: "v238",
        });

        assert_eq!(scheme, NamingScheme::V249);
    }

    #[test]
    fn resolve_naming_scheme_prefers_env_otherwise() {
        let scheme = resolve_naming_scheme(NamingSchemeSources {
            kernel_cmdline: Some("v249"),
            env_value: Some("v255"),
            default_scheme: "v238",
        });

        assert_eq!(scheme, NamingScheme::V255);
    }

    #[test]
    fn resolve_naming_scheme_falls_back_to_env_suffix_when_cmdline_missing() {
        let scheme = resolve_naming_scheme(NamingSchemeSources {
            kernel_cmdline: None,
            env_value: Some(":v255"),
            default_scheme: "v238",
        });

        assert_eq!(scheme, NamingScheme::V255);
    }

    #[test]
    fn resolve_naming_scheme_ignores_unknown_requested_scheme() {
        let scheme = resolve_naming_scheme(NamingSchemeSources {
            kernel_cmdline: Some("wat"),
            env_value: None,
            default_scheme: "v247",
        });

        assert_eq!(scheme, NamingScheme::V247);
    }

    #[test]
    fn extract_cmdline_key_reads_requested_value() {
        let cmdline = "root=1 quiet net.naming_scheme=v257 splash";
        assert_eq!(
            extract_cmdline_key(cmdline, "net.naming_scheme"),
            Some("v257")
        );
    }

    #[test]
    fn name_policy_round_trips() {
        for policy in [
            NamePolicy::Kernel,
            NamePolicy::Keep,
            NamePolicy::Database,
            NamePolicy::Onboard,
            NamePolicy::Slot,
            NamePolicy::Path,
            NamePolicy::Mac,
        ] {
            assert_eq!(
                name_policy_from_string(name_policy_to_string(policy)),
                Some(policy)
            );
        }
    }

    #[test]
    fn alternative_names_policy_matches_c_table() {
        assert_eq!(
            alternative_names_policy_from_string("database"),
            Some(NamePolicy::Database)
        );
        assert_eq!(
            alternative_names_policy_to_string(NamePolicy::Database),
            Some("database")
        );
        assert_eq!(alternative_names_policy_to_string(NamePolicy::Kernel), None);
        assert_eq!(alternative_names_policy_to_string(NamePolicy::Keep), None);
    }

    #[test]
    fn naming_sysattr_allowed_defaults_to_true() {
        let dev = MockDevice::default();
        assert_eq!(naming_sysattr_allowed_by_default(&dev), Ok(true));
        assert_eq!(naming_sysattr_allowed(&dev, "phys_port_name"), Ok(true));
    }

    #[test]
    fn naming_sysattr_allowed_uses_specific_property_override() {
        let dev = MockDevice::default()
            .with_property("ID_NET_NAME_ALLOW", Ok(false))
            .with_property("ID_NET_NAME_ALLOW_PHYS_PORT_NAME", Ok(true));

        assert_eq!(naming_sysattr_allowed(&dev, "phys_port_name"), Ok(true));
    }

    #[test]
    fn filtered_sysattr_access_returns_not_found_when_disallowed() {
        let dev = MockDevice::default()
            .with_property("ID_NET_NAME_ALLOW_PHYS_PORT_NAME", Ok(false))
            .with_int_sysattr("phys_port_name", Ok(7));

        assert_eq!(
            device_get_sysattr_int_filtered(&dev, "phys_port_name"),
            Err(SysattrError::NotFound)
        );
    }

    #[test]
    fn filtered_sysattr_access_forwards_successful_reads() {
        let dev = MockDevice::default()
            .with_int_sysattr("dev_port", Ok(11))
            .with_unsigned_sysattr("dev_id", Ok(12))
            .with_bool_sysattr("carrier", Ok(true))
            .with_value_sysattr("phys_port_name", Ok("p0"));

        assert_eq!(device_get_sysattr_int_filtered(&dev, "dev_port"), Ok(11));
        assert_eq!(device_get_sysattr_unsigned_filtered(&dev, "dev_id"), Ok(12));
        assert_eq!(device_get_sysattr_bool_filtered(&dev, "carrier"), Ok(true));
        assert_eq!(
            device_get_sysattr_value_filtered(&dev, "phys_port_name"),
            Ok("p0".to_string())
        );
    }
}
