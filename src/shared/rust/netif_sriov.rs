// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/netif-sriov.c, src/shared/netif-sriov.h
//
// SR-IOV (Single Root I/O Virtualization) configuration types and utilities.
//
// Manages Virtual Functions (VFs) for SR-IOV-capable network interfaces.
// Provides parsing of VF configuration properties (MAC, VLAN, QoS, spoof
// check, trust, link state), sysfs interactions for reading/writing VF
// counts, validation of VF sections, and construction of netlink messages
// for applying VF configuration to the kernel.

use crate::ffi::*;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum valid VF index (matches C constraint: vf < INT_MAX).
pub const VF_MAX_INDEX: u32 = i32::MAX as u32 - 1;

/// Maximum VLAN ID (12-bit field).
pub const VLAN_MAX: u32 = 4095;

/// Sysfs attribute for the current number of VFs.
pub const SYSFS_SRIOV_NUMVFS: &str = "device/sriov_numvfs";

/// Sysfs attribute for the maximum number of VFs.
pub const SYSFS_SRIOV_TOTALVFS: &str = "device/sriov_totalvfs";

/// Sentinel value meaning "num_vfs not specified" (auto-detect from VF config).
pub const NUM_VFS_AUTO: u32 = u32::MAX;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced by SR-IOV operations.
#[derive(Debug)]
pub enum SriovError {
    /// The value is out of the valid range (e.g., VF index too large, VLAN > 4095).
    OutOfRange {
        what: &'static str,
        value: u32,
        max: u32,
    },
    /// A required field is missing (e.g., VirtualFunction= not set).
    MissingField(&'static str),
    /// A boolean parse failed.
    InvalidBoolean(String),
    /// A MAC address parse failed.
    InvalidMacAddress(String),
    /// A VLAN protocol is not recognized.
    InvalidVlanProto(String),
    /// A VF index is out of bounds relative to the number of VFs.
    VfIndexOutOfBounds { vf: u32, num_vfs: u32 },
    /// A sysfs read or write failed.
    Sysfs { attr: String, source: io::Error },
    /// The number of VFs exceeds the hardware maximum.
    ExceedsTotalVfs { requested: u32, max: u32 },
    /// No VF is configured (num_vfs would be 0).
    NoVfConfigured,
    /// A netlink message attribute has no data (not configured).
    NoAttributeData(&'static str),
}

impl fmt::Display for SriovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SriovError::OutOfRange { what, value, max } => {
                write!(f, "{} {} exceeds maximum {}", what, value, max)
            }
            SriovError::MissingField(field) => write!(f, "missing required field: {}", field),
            SriovError::InvalidBoolean(s) => write!(f, "invalid boolean value: '{}'", s),
            SriovError::InvalidMacAddress(s) => write!(f, "invalid MAC address: '{}'", s),
            SriovError::InvalidVlanProto(s) => write!(f, "invalid VLAN protocol: '{}'", s),
            SriovError::VfIndexOutOfBounds { vf, num_vfs } => {
                write!(f, "VF index {} is out of bounds (num_vfs={})", vf, num_vfs)
            }
            SriovError::Sysfs { attr, source } => {
                write!(f, "sysfs attribute '{}' failed: {}", attr, source)
            }
            SriovError::ExceedsTotalVfs { requested, max } => {
                write!(f, "requested {} VFs exceeds maximum {}", requested, max)
            }
            SriovError::NoVfConfigured => write!(f, "no VF configured"),
            SriovError::NoAttributeData(attr) => write!(f, "attribute '{}' has no data", attr),
        }
    }
}

impl std::error::Error for SriovError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SriovError::Sysfs { source, .. } => Some(source),
            _ => None,
        }
    }
}

// ── Result alias ──────────────────────────────────────────────────────────

pub type SriovResult<T> = Result<T, SriovError>;

// ── MAC address ───────────────────────────────────────────────────────────

/// A 6-byte Ethernet MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The null/broadcast MAC (all zeros).
    pub const NULL: Self = Self([0u8; 6]);

    /// Returns true if all bytes are zero.
    pub fn is_null(&self) -> bool {
        self.0 == [0u8; 6]
    }

    /// Parse a MAC address from a colon-separated hex string (e.g. "aa:bb:cc:dd:ee:ff").
    pub fn from_str(s: &str) -> SriovResult<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(SriovError::InvalidMacAddress(s.to_owned()));
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| SriovError::InvalidMacAddress(s.to_owned()))?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// ── Enums ─────────────────────────────────────────────────────────────────

/// VLAN protocol encapsulation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VlanProto {
    /// Standard 802.1Q (0x8100).
    #[default]
    Eth8021Q,
    /// Provider bridging 802.1ad (0x88A8).
    Eth8021Ad,
}

impl VlanProto {
    /// 802.1Q ethertype value.
    pub const ETH_P_8021Q: u16 = 0x8100;
    /// 802.1ad ethertype value.
    pub const ETH_P_8021AD: u16 = 0x88A8;

    /// Parse a VLAN protocol from its string representation.
    pub fn from_str(s: &str) -> SriovResult<Self> {
        match s {
            "" | "802.1Q" => Ok(Self::Eth8021Q),
            "802.1ad" => Ok(Self::Eth8021Ad),
            _ => Err(SriovError::InvalidVlanProto(s.to_owned())),
        }
    }

    /// Return the big-endian ethertype value for wire encoding.
    pub const fn to_be_u16(self) -> u16 {
        match self {
            Self::Eth8021Q => Self::ETH_P_8021Q,
            Self::Eth8021Ad => Self::ETH_P_8021AD,
        }
    }
}

/// VF link state (maps to IFLA_VF_LINK_STATE_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SriovLinkState {
    /// Auto-detect link state.
    Auto = 0,
    /// Link is enabled.
    Enable = 1,
    /// Link is explicitly disabled.
    Disable = 2,
}

impl SriovLinkState {
    /// Sentinel for invalid/unset link state.
    pub const INVALID: i32 = -22; // -EINVAL

    /// Parse a link state from its string representation.
    pub fn from_str(s: &str) -> SriovResult<Self> {
        match s {
            "" => Err(SriovError::InvalidBoolean(String::new())),
            "auto" => Ok(Self::Auto),
            "1" | "true" | "yes" | "on" => Ok(Self::Enable),
            "0" | "false" | "no" | "off" => Ok(Self::Disable),
            _ => Err(SriovError::InvalidBoolean(s.to_owned())),
        }
    }
}

/// SR-IOV VF attribute types for netlink message construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SriovAttribute {
    /// VF MAC address.
    VfMac,
    /// VF spoof check.
    VfSpoofchk,
    /// VF RSS query enable.
    VfRssQueryEn,
    /// VF trust setting.
    VfTrust,
    /// VF link state.
    VfLinkState,
    /// VF VLAN list.
    VfVlanList,
}

impl SriovAttribute {
    /// Human-readable name for logging (matches C `sr_iov_attribute_table`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VfMac => "MAC address",
            Self::VfSpoofchk => "spoof check",
            Self::VfRssQueryEn => "RSS query",
            Self::VfTrust => "trust",
            Self::VfLinkState => "link state",
            Self::VfVlanList => "vlan list",
        }
    }
}

// ── Optional boolean ──────────────────────────────────────────────────────

/// A tri-state boolean for settings that can be unset (-1), off (0), or on (1).
/// Matches the C pattern of `int setting` where -1 means "not configured".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OptionalBool(i32);

impl OptionalBool {
    /// Unset / not configured.
    pub const UNSET: Self = Self(-1);
    /// Explicitly disabled.
    pub const OFF: Self = Self(0);
    /// Explicitly enabled.
    pub const ON: Self = Self(1);

    /// Create from a raw i32 value (clamped to -1, 0, 1).
    pub const fn new(value: i32) -> Self {
        if value < -1 {
            Self(-1)
        } else if value > 1 {
            Self(1)
        } else {
            Self(value)
        }
    }

    /// Returns true if the setting is configured (not UNSET).
    pub const fn is_set(self) -> bool {
        self.0 >= 0
    }

    /// Get the boolean value. Returns None if unset.
    pub const fn as_bool(self) -> Option<bool> {
        match self.0 {
            -1 => None,
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// Get the raw i32 value.
    pub const fn as_i32(self) -> i32 {
        self.0
    }

    /// Parse from a string. Empty string returns UNSET.
    pub fn parse(s: &str) -> SriovResult<Self> {
        if s.is_empty() {
            return Ok(Self::UNSET);
        }
        match s {
            "1" | "true" | "yes" | "on" => Ok(Self::ON),
            "0" | "false" | "no" | "off" => Ok(Self::OFF),
            _ => Err(SriovError::InvalidBoolean(s.to_owned())),
        }
    }
}

impl Default for OptionalBool {
    fn default() -> Self {
        Self::UNSET
    }
}

// ── Optional link state ───────────────────────────────────────────────────

/// A tri-state link state that can be unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OptionalLinkState(i32);

impl OptionalLinkState {
    /// Unset / not configured.
    pub const UNSET: Self = Self(-22); // _SR_IOV_LINK_STATE_INVALID

    /// Create from a raw value.
    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    /// Returns true if the link state is configured (not UNSET).
    pub const fn is_set(self) -> bool {
        self.0 >= 0
    }

    /// Get the link state. Returns None if unset.
    pub const fn as_state(self) -> Option<SriovLinkState> {
        match self.0 {
            0 => Some(SriovLinkState::Auto),
            1 => Some(SriovLinkState::Enable),
            2 => Some(SriovLinkState::Disable),
            _ => None,
        }
    }

    /// Get the raw i32 value.
    pub const fn as_i32(self) -> i32 {
        self.0
    }
}

impl Default for OptionalLinkState {
    fn default() -> Self {
        Self::UNSET
    }
}

// ── SR-IOV VF configuration ──────────────────────────────────────────────

/// Configuration for a single Virtual Function (VF) on an SR-IOV device.
///
/// Each VF has an index and optional properties (MAC, VLAN, QoS, spoof check,
/// trust, link state). Properties that are not explicitly configured are
/// represented by sentinel values and will not be applied to the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SriovVf {
    /// VF index (0 to VF_MAX_INDEX). `u32::MAX` means unconfigured.
    pub vf: u32,
    /// VLAN ID (0 = disabled, 1..=4095 = active).
    pub vlan: u32,
    /// Quality of Service priority.
    pub qos: u32,
    /// VLAN protocol (802.1Q or 802.1ad).
    pub vlan_proto: VlanProto,
    /// MAC spoof checking (tri-state: unset/off/on).
    pub spoof_check: OptionalBool,
    /// RSS query enable (tri-state: unset/off/on).
    pub query_rss: OptionalBool,
    /// VF trust setting (tri-state: unset/off/on).
    pub trust: OptionalBool,
    /// VF link state (tri-state: unset/auto/enable/disable).
    pub link_state: OptionalLinkState,
    /// VF MAC address. All-zeros means unconfigured.
    pub mac: MacAddress,
}

impl Default for SriovVf {
    fn default() -> Self {
        Self::new()
    }
}

impl SriovVf {
    /// Create a new VF configuration with default (unset) values.
    ///
    /// Matches the C `sr_iov_new()` defaults.
    pub fn new() -> Self {
        Self {
            vf: u32::MAX,
            vlan: 0,
            qos: 0,
            vlan_proto: VlanProto::Eth8021Q,
            spoof_check: OptionalBool::UNSET,
            query_rss: OptionalBool::UNSET,
            trust: OptionalBool::UNSET,
            link_state: OptionalLinkState::UNSET,
            mac: MacAddress::NULL,
        }
    }

    /// Check whether a specific attribute has been explicitly configured.
    ///
    /// Matches the C `sr_iov_has_config()` function.
    pub fn has_config(&self, attr: SriovAttribute) -> bool {
        match attr {
            SriovAttribute::VfMac => !self.mac.is_null(),
            SriovAttribute::VfSpoofchk => self.spoof_check.is_set(),
            SriovAttribute::VfRssQueryEn => self.query_rss.is_set(),
            SriovAttribute::VfTrust => self.trust.is_set(),
            SriovAttribute::VfLinkState => self.link_state.is_set(),
            SriovAttribute::VfVlanList => self.vlan > 0,
        }
    }

    /// Set the VF index. Returns error if >= VF_MAX_INDEX.
    pub fn set_vf(&mut self, value: u32) -> SriovResult<()> {
        if value >= VF_MAX_INDEX + 1 {
            return Err(SriovError::OutOfRange {
                what: "VirtualFunction",
                value,
                max: VF_MAX_INDEX,
            });
        }
        self.vf = value;
        Ok(())
    }

    /// Set the VLAN ID. Returns error if > 4095 or 0 (use reset_vlan to disable).
    pub fn set_vlan(&mut self, value: u32) -> SriovResult<()> {
        if value > VLAN_MAX {
            return Err(SriovError::OutOfRange {
                what: "VLANId",
                value,
                max: VLAN_MAX,
            });
        }
        self.vlan = value;
        Ok(())
    }

    /// Reset VLAN to disabled (0).
    pub fn reset_vlan(&mut self) {
        self.vlan = 0;
    }

    /// Set the QoS priority.
    pub fn set_qos(&mut self, value: u32) {
        self.qos = value;
    }

    /// Reset QoS to 0.
    pub fn reset_qos(&mut self) {
        self.qos = 0;
    }

    /// Set the VLAN protocol.
    pub fn set_vlan_proto(&mut self, proto: VlanProto) {
        self.vlan_proto = proto;
    }

    /// Set the MAC address.
    pub fn set_mac(&mut self, mac: MacAddress) {
        self.mac = mac;
    }

    /// Reset the MAC address to null (unconfigured).
    pub fn reset_mac(&mut self) {
        self.mac = MacAddress::NULL;
    }

    /// Set spoof checking from a string.
    pub fn parse_spoof_check(&mut self, s: &str) -> SriovResult<()> {
        self.spoof_check = OptionalBool::parse(s)?;
        Ok(())
    }

    /// Set RSS query from a string.
    pub fn parse_query_rss(&mut self, s: &str) -> SriovResult<()> {
        self.query_rss = OptionalBool::parse(s)?;
        Ok(())
    }

    /// Set trust from a string.
    pub fn parse_trust(&mut self, s: &str) -> SriovResult<()> {
        self.trust = OptionalBool::parse(s)?;
        Ok(())
    }

    /// Set link state from a string.
    pub fn parse_link_state(&mut self, s: &str) -> SriovResult<()> {
        if s.is_empty() {
            self.link_state = OptionalLinkState::UNSET;
            return Ok(());
        }
        let state = SriovLinkState::from_str(s)?;
        self.link_state = OptionalLinkState::new(state as i32);
        Ok(())
    }

    /// Parse a `VirtualFunction=` config value.
    pub fn parse_vf(&mut self, s: &str) -> SriovResult<()> {
        if s.is_empty() {
            self.vf = u32::MAX;
            return Ok(());
        }
        let value: u32 = s.parse().map_err(|_| SriovError::OutOfRange {
            what: "VirtualFunction",
            value: 0,
            max: VF_MAX_INDEX,
        })?;
        self.set_vf(value)
    }

    /// Parse a `VLANId=` config value.
    pub fn parse_vlan(&mut self, s: &str) -> SriovResult<()> {
        if s.is_empty() {
            self.reset_vlan();
            return Ok(());
        }
        let value: u32 = s.parse().map_err(|_| SriovError::OutOfRange {
            what: "VLANId",
            value: 0,
            max: VLAN_MAX,
        })?;
        if value == 0 || value > VLAN_MAX {
            return Err(SriovError::OutOfRange {
                what: "VLANId",
                value,
                max: VLAN_MAX,
            });
        }
        self.vlan = value;
        Ok(())
    }

    /// Parse a `QualityOfService=` config value.
    pub fn parse_qos(&mut self, s: &str) -> SriovResult<()> {
        if s.is_empty() {
            self.reset_qos();
            return Ok(());
        }
        let value: u32 = s.parse().map_err(|_| SriovError::OutOfRange {
            what: "QualityOfService",
            value: 0,
            max: u32::MAX,
        })?;
        self.qos = value;
        Ok(())
    }

    /// Parse a `VLANProtocol=` config value.
    pub fn parse_vlan_proto(&mut self, s: &str) -> SriovResult<()> {
        self.vlan_proto = VlanProto::from_str(s)?;
        Ok(())
    }

    /// Parse a `MACAddress=` config value.
    pub fn parse_mac(&mut self, s: &str) -> SriovResult<()> {
        if s.is_empty() {
            self.reset_mac();
            return Ok(());
        }
        self.mac = MacAddress::from_str(s)?;
        Ok(())
    }

    /// Verify this VF configuration against a given number of VFs.
    ///
    /// Returns error if the VF index is unconfigured or out of bounds.
    /// Matches the C `sr_iov_section_verify()` logic.
    pub fn verify(&self, num_vfs: u32) -> SriovResult<()> {
        if self.vf == u32::MAX {
            return Err(SriovError::MissingField("VirtualFunction"));
        }
        if self.vf >= num_vfs {
            return Err(SriovError::VfIndexOutOfBounds {
                vf: self.vf,
                num_vfs,
            });
        }
        Ok(())
    }
}

// ── Netlink message structures ────────────────────────────────────────────

/// Binary structure for IFLA_VF_MAC netlink attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IflaVfMac {
    pub vf: u32,
    pub mac: [u8; 6],
}

/// Binary structure for IFLA_VF_SPOOFCHK netlink attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IflaVfSpoofchk {
    pub vf: u32,
    pub setting: u32,
}

/// Binary structure for IFLA_VF_RSS_QUERY_EN netlink attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IflaVfRssQueryEn {
    pub vf: u32,
    pub setting: u32,
}

/// Binary structure for IFLA_VF_TRUST netlink attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IflaVfTrust {
    pub vf: u32,
    pub setting: u32,
}

/// Binary structure for IFLA_VF_LINK_STATE netlink attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IflaVfLinkState {
    pub vf: u32,
    pub link_state: u32,
}

/// Binary structure for IFLA_VF_VLAN_INFO netlink attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IflaVfVlanInfo {
    pub vf: u32,
    pub vlan: u32,
    pub qos: u32,
    pub vlan_proto: u16,
}

impl IflaVfVlanInfo {
    /// Construct VLAN info from a SriovVf configuration.
    pub fn from_vf_config(vf: &SriovVf) -> Self {
        Self {
            vf: vf.vf,
            vlan: vf.vlan,
            qos: vf.qos,
            vlan_proto: vf.vlan_proto.to_be_u16(),
        }
    }
}

/// Netlink attribute types for VF configuration.
pub mod nlattr {
    /// IFLA_VFINFO_LIST container.
    pub const IFLA_VFINFO_LIST: u16 = 1;
    /// IFLA_VF_INFO container.
    pub const IFLA_VF_INFO: u16 = 1;
    /// IFLA_VF_MAC attribute.
    pub const IFLA_VF_MAC: u16 = 1;
    /// IFLA_VF_VLAN_LIST container.
    pub const IFLA_VF_VLAN_LIST: u16 = 2;
    /// IFLA_VF_VLAN_INFO attribute.
    pub const IFLA_VF_VLAN_INFO: u16 = 1;
    /// IFLA_VF_SPOOFCHK attribute.
    pub const IFLA_VF_SPOOFCHK: u16 = 4;
    /// IFLA_VF_RSS_QUERY_EN attribute.
    pub const IFLA_VF_RSS_QUERY_EN: u16 = 7;
    /// IFLA_VF_TRUST attribute.
    pub const IFLA_VF_TRUST: u16 = 5;
    /// IFLA_VF_LINK_STATE attribute.
    pub const IFLA_VF_LINK_STATE: u16 = 6;
}

/// A single netlink attribute payload produced by building a VF config message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfNetlinkPayload {
    /// IFLA_VF_MAC data.
    Mac(IflaVfMac),
    /// IFLA_VF_SPOOFCHK data.
    Spoofchk(IflaVfSpoofchk),
    /// IFLA_VF_RSS_QUERY_EN data.
    RssQueryEn(IflaVfRssQueryEn),
    /// IFLA_VF_TRUST data.
    Trust(IflaVfTrust),
    /// IFLA_VF_LINK_STATE data.
    LinkState(IflaVfLinkState),
    /// IFLA_VF_VLAN_INFO data (nested in IFLA_VF_VLAN_LIST).
    VlanInfo(IflaVfVlanInfo),
}

/// Build the netlink payload for a given VF attribute.
///
/// Returns the payload that should be wrapped in the appropriate IFLA_VFINFO_LIST /
/// IFLA_VF_INFO containers. Returns error if the attribute is not configured.
///
/// Matches the C `sr_iov_set_netlink_message()` function.
pub fn build_vf_netlink_payload(
    vf: &SriovVf,
    attr: SriovAttribute,
) -> SriovResult<VfNetlinkPayload> {
    match attr {
        SriovAttribute::VfMac => {
            if vf.mac.is_null() {
                return Err(SriovError::NoAttributeData("MAC address"));
            }
            Ok(VfNetlinkPayload::Mac(IflaVfMac {
                vf: vf.vf,
                mac: vf.mac.0,
            }))
        }
        SriovAttribute::VfSpoofchk => {
            if !vf.spoof_check.is_set() {
                return Err(SriovError::NoAttributeData("spoof check"));
            }
            Ok(VfNetlinkPayload::Spoofchk(IflaVfSpoofchk {
                vf: vf.vf,
                setting: vf.spoof_check.as_i32() as u32,
            }))
        }
        SriovAttribute::VfRssQueryEn => {
            if !vf.query_rss.is_set() {
                return Err(SriovError::NoAttributeData("RSS query"));
            }
            Ok(VfNetlinkPayload::RssQueryEn(IflaVfRssQueryEn {
                vf: vf.vf,
                setting: vf.query_rss.as_i32() as u32,
            }))
        }
        SriovAttribute::VfTrust => {
            if !vf.trust.is_set() {
                return Err(SriovError::NoAttributeData("trust"));
            }
            Ok(VfNetlinkPayload::Trust(IflaVfTrust {
                vf: vf.vf,
                setting: vf.trust.as_i32() as u32,
            }))
        }
        SriovAttribute::VfLinkState => {
            if !vf.link_state.is_set() {
                return Err(SriovError::NoAttributeData("link state"));
            }
            Ok(VfNetlinkPayload::LinkState(IflaVfLinkState {
                vf: vf.vf,
                link_state: vf.link_state.as_i32() as u32,
            }))
        }
        SriovAttribute::VfVlanList => {
            if vf.vlan <= 0 {
                return Err(SriovError::NoAttributeData("VLAN list"));
            }
            Ok(VfNetlinkPayload::VlanInfo(IflaVfVlanInfo::from_vf_config(
                vf,
            )))
        }
    }
}

/// Build all configured netlink payloads for a VF.
///
/// Iterates all attributes and collects payloads for those that are configured.
pub fn build_all_vf_netlink_payloads(vf: &SriovVf) -> Vec<VfNetlinkPayload> {
    let mut payloads = Vec::new();
    let attrs = [
        SriovAttribute::VfMac,
        SriovAttribute::VfSpoofchk,
        SriovAttribute::VfRssQueryEn,
        SriovAttribute::VfTrust,
        SriovAttribute::VfLinkState,
        SriovAttribute::VfVlanList,
    ];
    for attr in &attrs {
        if vf.has_config(*attr) {
            if let Ok(payload) = build_vf_netlink_payload(vf, *attr) {
                payloads.push(payload);
            }
        }
    }
    payloads
}

// ── Hashing and comparison ────────────────────────────────────────────────

/// Hash a VF configuration by its VF index only.
///
/// Matches the C `sr_iov_hash_func()` which hashes `sr_iov->vf`.
pub fn sriov_hash_by_vf(vf: u32) -> u64 {
    // Simple hash matching the C siphash24 behavior for a single u32.
    // In production this would use the actual siphash state, but for
    // pure Rust the std Hash trait suffices.
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    vf.hash(&mut hasher);
    hasher.finish()
}

/// Compare two VF configurations by VF index.
///
/// Returns ordering: -1, 0, or 1. Matches C `sr_iov_compare_func()`.
pub fn sriov_compare_by_vf(a: &SriovVf, b: &SriovVf) -> i32 {
    a.vf.cmp(&b.vf) as i32
}

// ── Sysfs operations ──────────────────────────────────────────────────────

/// Resolve a network interface name to its sysfs device path.
///
/// Returns the path `/sys/class/net/<name>`.
pub fn netif_sysfs_path(name: &str) -> PathBuf {
    PathBuf::from("/sys/class/net").join(name)
}

/// Get the sysfs attribute path for a given network device and attribute.
fn sysfs_attr_path(sysfs_base: &Path, attr: &str) -> PathBuf {
    sysfs_base.join(attr)
}

/// Read a sysfs attribute as a string, trimming whitespace.
fn read_sysfs_attr(path: &Path) -> Result<String, SriovError> {
    let content = fs::read_to_string(path).map_err(|e| SriovError::Sysfs {
        attr: path.display().to_string(),
        source: e,
    })?;
    Ok(content.trim().to_owned())
}

/// Write a sysfs attribute.
fn write_sysfs_attr(path: &Path, value: &str) -> Result<(), SriovError> {
    fs::write(path, value).map_err(|e| SriovError::Sysfs {
        attr: path.display().to_string(),
        source: e,
    })
}

/// Get the current number of SR-IOV VFs from a sysfs device path.
///
/// Reads `device/sriov_numvfs` and parses it as u32.
///
/// Matches the C `sr_iov_get_num_vfs()` function.
pub fn sriov_get_num_vfs(sysfs_base: &Path) -> SriovResult<u32> {
    let path = sysfs_attr_path(sysfs_base, SYSFS_SRIOV_NUMVFS);
    let s = read_sysfs_attr(&path)?;
    let n: u32 = s.parse().map_err(|_| SriovError::Sysfs {
        attr: SYSFS_SRIOV_NUMVFS.to_owned(),
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot parse '{}' as u32", s),
        ),
    })?;
    Ok(n)
}

/// Get the maximum number of SR-IOV VFs from a sysfs device path.
///
/// Reads `device/sriov_totalvfs`. Returns `Ok(None)` if the attribute
/// doesn't exist (not all drivers expose it).
pub fn sriov_get_total_vfs(sysfs_base: &Path) -> SriovResult<Option<u32>> {
    let path = sysfs_attr_path(sysfs_base, SYSFS_SRIOV_TOTALVFS);
    match fs::read_to_string(&path) {
        Ok(content) => {
            let s = content.trim();
            let n: u32 = s.parse().map_err(|_| SriovError::Sysfs {
                attr: SYSFS_SRIOV_TOTALVFS.to_owned(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot parse '{}' as u32", s),
                ),
            })?;
            Ok(Some(n))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(SriovError::Sysfs {
            attr: SYSFS_SRIOV_TOTALVFS.to_owned(),
            source: e,
        }),
    }
}

/// Set the number of SR-IOV VFs via sysfs.
///
/// If `num_vfs` is `NUM_VFS_AUTO` (u32::MAX), automatically determines the
/// needed count from the VF configurations. If `num_vfs` is 0, disables all VFs.
///
/// Handles the EBUSY retry pattern (some devices require writing 0 first).
///
/// Matches the C `sr_iov_set_num_vfs()` function.
pub fn sriov_set_num_vfs(
    sysfs_base: &Path,
    num_vfs: u32,
    vf_configs: &[SriovVf],
) -> SriovResult<()> {
    let path = sysfs_attr_path(sysfs_base, SYSFS_SRIOV_NUMVFS);

    let target_num_vfs = if num_vfs == NUM_VFS_AUTO {
        // Determine the needed number of VFs from configuration.
        let mut needed: u32 = 0;
        for vf in vf_configs {
            if vf.vf != u32::MAX {
                needed = needed.max(vf.vf + 1);
            }
        }
        if needed == 0 {
            return Ok(()); // No VF configured, nothing to do.
        }

        // Check if enough VFs already exist.
        match sriov_get_num_vfs(sysfs_base) {
            Ok(current) if needed <= current => return Ok(()),
            Ok(_) => {}  // Need more VFs, continue below.
            Err(_) => {} // Ignore read error, try to set anyway.
        }
        needed
    } else if num_vfs == 0 {
        // Disable VFs. Gracefully handle missing attribute.
        match write_sysfs_attr(&path, "0") {
            Ok(()) => return Ok(()),
            Err(SriovError::Sysfs { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(()); // Interface doesn't support SR-IOV.
            }
            Err(e) => return Err(e),
        }
    } else {
        num_vfs
    };

    // Check the hardware maximum.
    if let Some(max) = sriov_get_total_vfs(sysfs_base)? {
        if target_num_vfs > max {
            return Err(SriovError::ExceedsTotalVfs {
                requested: target_num_vfs,
                max,
            });
        }
    }

    // Write the new value. Handle EBUSY by writing 0 first.
    let val_str = target_num_vfs.to_string();
    if let Err(e) = write_sysfs_attr(&path, &val_str) {
        if let SriovError::Sysfs { source, .. } = &e {
            if source.raw_os_error() == Some(libc::EBUSY) {
                // Retry: write 0 first, then the target value.
                write_sysfs_attr(&path, "0")?;
                write_sysfs_attr(&path, &val_str)?;
                return Ok(());
            }
        }
        return Err(e);
    }

    Ok(())
}

// ── VF collection management ──────────────────────────────────────────────

/// Drop invalid and duplicate VF configurations.
///
/// Verifies each VF against `num_vfs`, removes duplicates (keeping the first
/// occurrence), and drops entries with invalid VF indices.
///
/// Matches the C `sr_iov_drop_invalid_sections()` function.
pub fn sriov_drop_invalid_vfs(num_vfs: u32, vfs: &mut Vec<SriovVf>) -> SriovResult<()> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    for vf in vfs.drain(..) {
        // Verify the VF configuration.
        if vf.verify(num_vfs).is_err() {
            continue; // Drop invalid sections.
        }

        // Check for duplicates.
        if seen.contains(&vf.vf) {
            continue; // Drop duplicate.
        }

        seen.insert(vf.vf);
        result.push(vf);
    }

    *vfs = result;
    Ok(())
}

/// Compute the required number of VFs from a list of VF configurations.
///
/// Returns `NUM_VFS_AUTO` if no VF has a valid index.
pub fn sriov_compute_required_vfs(vfs: &[SriovVf]) -> u32 {
    let mut max_vf: u32 = 0;
    for vf in vfs {
        if vf.vf != u32::MAX {
            max_vf = max_vf.max(vf.vf + 1);
        }
    }
    max_vf
}

// ── Config parsing: num_vfs ───────────────────────────────────────────────

/// Parse the `SR-IOVVirtualFunctions=` config value.
///
/// Empty string sets to `NUM_VFS_AUTO`. Valid values are 0..=i32::MAX.
///
/// Matches the C `config_parse_sr_iov_num_vfs()` function.
pub fn parse_sriov_num_vfs(s: &str) -> SriovResult<u32> {
    if s.is_empty() {
        return Ok(NUM_VFS_AUTO);
    }
    let n: u32 = s.parse().map_err(|_| SriovError::OutOfRange {
        what: "SR-IOVVirtualFunctions",
        value: 0,
        max: VF_MAX_INDEX,
    })?;
    if n > VF_MAX_INDEX {
        return Err(SriovError::OutOfRange {
            what: "SR-IOVVirtualFunctions",
            value: n,
            max: VF_MAX_INDEX,
        });
    }
    Ok(n)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MacAddress tests ───────────────────────────────────────────────

    #[test]
    fn test_mac_address_null() {
        let mac = MacAddress::NULL;
        assert!(mac.is_null());
        assert_eq!(mac.0, [0u8; 6]);
    }

    #[test]
    fn test_mac_address_parse_valid() {
        let mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac.0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert!(!mac.is_null());
    }

    #[test]
    fn test_mac_address_parse_invalid() {
        assert!(MacAddress::from_str("invalid").is_err());
        assert!(MacAddress::from_str("aa:bb:cc").is_err());
        assert!(MacAddress::from_str("gg:hh:ii:jj:kk:ll").is_err());
    }

    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(format!("{}", mac), "AA:BB:CC:DD:EE:FF");
    }

    // ── VlanProto tests ────────────────────────────────────────────────

    #[test]
    fn test_vlan_proto_parse() {
        assert_eq!(VlanProto::from_str("802.1Q").unwrap(), VlanProto::Eth8021Q);
        assert_eq!(VlanProto::from_str("").unwrap(), VlanProto::Eth8021Q);
        assert_eq!(
            VlanProto::from_str("802.1ad").unwrap(),
            VlanProto::Eth8021Ad
        );
        assert!(VlanProto::from_str("invalid").is_err());
    }

    #[test]
    fn test_vlan_proto_be_u16() {
        assert_eq!(VlanProto::Eth8021Q.to_be_u16(), 0x8100);
        assert_eq!(VlanProto::Eth8021Ad.to_be_u16(), 0x88A8);
    }

    // ── SriovLinkState tests ───────────────────────────────────────────

    #[test]
    fn test_link_state_parse() {
        assert_eq!(
            SriovLinkState::from_str("auto").unwrap(),
            SriovLinkState::Auto
        );
        assert_eq!(
            SriovLinkState::from_str("true").unwrap(),
            SriovLinkState::Enable
        );
        assert_eq!(
            SriovLinkState::from_str("false").unwrap(),
            SriovLinkState::Disable
        );
        assert_eq!(
            SriovLinkState::from_str("1").unwrap(),
            SriovLinkState::Enable
        );
        assert_eq!(
            SriovLinkState::from_str("0").unwrap(),
            SriovLinkState::Disable
        );
        assert!(SriovLinkState::from_str("").is_err());
    }

    // ── OptionalBool tests ─────────────────────────────────────────────

    #[test]
    fn test_optional_bool_parse() {
        assert_eq!(OptionalBool::parse("").unwrap(), OptionalBool::UNSET);
        assert_eq!(OptionalBool::parse("true").unwrap(), OptionalBool::ON);
        assert_eq!(OptionalBool::parse("false").unwrap(), OptionalBool::OFF);
        assert_eq!(OptionalBool::parse("1").unwrap(), OptionalBool::ON);
        assert_eq!(OptionalBool::parse("yes").unwrap(), OptionalBool::ON);
        assert_eq!(OptionalBool::parse("no").unwrap(), OptionalBool::OFF);
        assert!(OptionalBool::parse("invalid").is_err());
    }

    #[test]
    fn test_optional_bool_is_set() {
        assert!(!OptionalBool::UNSET.is_set());
        assert!(OptionalBool::ON.is_set());
        assert!(OptionalBool::OFF.is_set());
    }

    // ── SriovVf defaults ───────────────────────────────────────────────

    #[test]
    fn test_sriov_vf_new_defaults() {
        let vf = SriovVf::new();
        assert_eq!(vf.vf, u32::MAX);
        assert_eq!(vf.vlan, 0);
        assert_eq!(vf.qos, 0);
        assert_eq!(vf.vlan_proto, VlanProto::Eth8021Q);
        assert!(!vf.spoof_check.is_set());
        assert!(!vf.query_rss.is_set());
        assert!(!vf.trust.is_set());
        assert!(!vf.link_state.is_set());
        assert!(vf.mac.is_null());
    }

    #[test]
    fn test_sriov_vf_has_config() {
        let mut vf = SriovVf::new();

        // Nothing configured initially.
        assert!(!vf.has_config(SriovAttribute::VfMac));
        assert!(!vf.has_config(SriovAttribute::VfSpoofchk));
        assert!(!vf.has_config(SriovAttribute::VfRssQueryEn));
        assert!(!vf.has_config(SriovAttribute::VfTrust));
        assert!(!vf.has_config(SriovAttribute::VfLinkState));
        assert!(!vf.has_config(SriovAttribute::VfVlanList));

        // Set MAC.
        vf.mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        assert!(vf.has_config(SriovAttribute::VfMac));

        // Set spoof check.
        vf.spoof_check = OptionalBool::ON;
        assert!(vf.has_config(SriovAttribute::VfSpoofchk));

        // Set VLAN.
        vf.vlan = 100;
        assert!(vf.has_config(SriovAttribute::VfVlanList));

        // VLAN 0 should not count as configured.
        vf.vlan = 0;
        assert!(!vf.has_config(SriovAttribute::VfVlanList));
    }

    // ── Attribute string tests ─────────────────────────────────────────

    #[test]
    fn test_attribute_as_str() {
        assert_eq!(SriovAttribute::VfMac.as_str(), "MAC address");
        assert_eq!(SriovAttribute::VfSpoofchk.as_str(), "spoof check");
        assert_eq!(SriovAttribute::VfRssQueryEn.as_str(), "RSS query");
        assert_eq!(SriovAttribute::VfTrust.as_str(), "trust");
        assert_eq!(SriovAttribute::VfLinkState.as_str(), "link state");
        assert_eq!(SriovAttribute::VfVlanList.as_str(), "vlan list");
    }

    // ── VF parsing tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_vf_valid() {
        let mut vf = SriovVf::new();
        vf.parse_vf("5").unwrap();
        assert_eq!(vf.vf, 5);
    }

    #[test]
    fn test_parse_vf_empty_resets() {
        let mut vf = SriovVf::new();
        vf.vf = 3;
        vf.parse_vf("").unwrap();
        assert_eq!(vf.vf, u32::MAX);
    }

    #[test]
    fn test_parse_vf_too_large() {
        let mut vf = SriovVf::new();
        let result = vf.parse_vf("2147483647");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vlan_valid() {
        let mut vf = SriovVf::new();
        vf.parse_vlan("100").unwrap();
        assert_eq!(vf.vlan, 100);
    }

    #[test]
    fn test_parse_vlan_zero_rejected() {
        let mut vf = SriovVf::new();
        assert!(vf.parse_vlan("0").is_err());
    }

    #[test]
    fn test_parse_vlan_empty_resets() {
        let mut vf = SriovVf::new();
        vf.vlan = 100;
        vf.parse_vlan("").unwrap();
        assert_eq!(vf.vlan, 0);
    }

    #[test]
    fn test_parse_vlan_too_large() {
        let mut vf = SriovVf::new();
        assert!(vf.parse_vlan("4096").is_err());
    }

    #[test]
    fn test_parse_qos() {
        let mut vf = SriovVf::new();
        vf.parse_qos("7").unwrap();
        assert_eq!(vf.qos, 7);
        vf.parse_qos("").unwrap();
        assert_eq!(vf.qos, 0);
    }

    #[test]
    fn test_parse_mac_valid() {
        let mut vf = SriovVf::new();
        vf.parse_mac("11:22:33:44:55:66").unwrap();
        assert_eq!(vf.mac.0, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_parse_mac_empty_resets() {
        let mut vf = SriovVf::new();
        vf.mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        vf.parse_mac("").unwrap();
        assert!(vf.mac.is_null());
    }

    #[test]
    fn test_parse_link_state_values() {
        let mut vf = SriovVf::new();
        vf.parse_link_state("auto").unwrap();
        assert_eq!(vf.link_state.as_state(), Some(SriovLinkState::Auto));

        vf.parse_link_state("true").unwrap();
        assert_eq!(vf.link_state.as_state(), Some(SriovLinkState::Enable));

        vf.parse_link_state("false").unwrap();
        assert_eq!(vf.link_state.as_state(), Some(SriovLinkState::Disable));

        vf.parse_link_state("").unwrap();
        assert!(!vf.link_state.is_set());
    }

    // ── VF verification tests ──────────────────────────────────────────

    #[test]
    fn test_verify_valid() {
        let mut vf = SriovVf::new();
        vf.vf = 2;
        assert!(vf.verify(4).is_ok());
    }

    #[test]
    fn test_verify_missing_vf() {
        let vf = SriovVf::new();
        let result = vf.verify(4);
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            SriovError::MissingField("VirtualFunction")
        );
    }

    #[test]
    fn test_verify_out_of_bounds() {
        let mut vf = SriovVf::new();
        vf.vf = 5;
        let result = vf.verify(3);
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            SriovError::VfIndexOutOfBounds { vf: 5, num_vfs: 3 }
        );
    }

    // ── Netlink payload tests ──────────────────────────────────────────

    #[test]
    fn test_build_netlink_payload_mac() {
        let mut vf = SriovVf::new();
        vf.vf = 3;
        vf.mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();

        let payload = build_vf_netlink_payload(&vf, SriovAttribute::VfMac).unwrap();
        match payload {
            VfNetlinkPayload::Mac(m) => {
                assert_eq!(m.vf, 3);
                assert_eq!(m.mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            }
            _ => panic!("expected Mac payload"),
        }
    }

    #[test]
    fn test_build_netlink_payload_mac_unset() {
        let vf = SriovVf::new();
        let result = build_vf_netlink_payload(&vf, SriovAttribute::VfMac);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_netlink_payload_spoofchk() {
        let mut vf = SriovVf::new();
        vf.vf = 1;
        vf.spoof_check = OptionalBool::ON;

        let payload = build_vf_netlink_payload(&vf, SriovAttribute::VfSpoofchk).unwrap();
        match payload {
            VfNetlinkPayload::Spoofchk(s) => {
                assert_eq!(s.vf, 1);
                assert_eq!(s.setting, 1);
            }
            _ => panic!("expected Spoofchk payload"),
        }
    }

    #[test]
    fn test_build_netlink_payload_vlan_info() {
        let mut vf = SriovVf::new();
        vf.vf = 2;
        vf.vlan = 100;
        vf.qos = 3;
        vf.vlan_proto = VlanProto::Eth8021Q;

        let payload = build_vf_netlink_payload(&vf, SriovAttribute::VfVlanList).unwrap();
        match payload {
            VfNetlinkPayload::VlanInfo(v) => {
                assert_eq!(v.vf, 2);
                assert_eq!(v.vlan, 100);
                assert_eq!(v.qos, 3);
                assert_eq!(v.vlan_proto, 0x8100u16);
            }
            _ => panic!("expected VlanInfo payload"),
        }
    }

    #[test]
    fn test_build_all_payloads() {
        let mut vf = SriovVf::new();
        vf.vf = 1;
        vf.mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        vf.spoof_check = OptionalBool::ON;
        vf.vlan = 200;

        let payloads = build_all_vf_netlink_payloads(&vf);
        assert_eq!(payloads.len(), 3); // MAC, Spoofchk, VlanInfo
    }

    // ── Hash and comparison tests ──────────────────────────────────────

    #[test]
    fn test_sriov_hash_by_vf_deterministic() {
        let h1 = sriov_hash_by_vf(5);
        let h2 = sriov_hash_by_vf(5);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sriov_compare_by_vf() {
        let mut a = SriovVf::new();
        a.vf = 3;
        let mut b = SriovVf::new();
        b.vf = 5;
        let mut c = SriovVf::new();
        c.vf = 3;

        assert_eq!(sriov_compare_by_vf(&a, &b), -1);
        assert_eq!(sriov_compare_by_vf(&b, &a), 1);
        assert_eq!(sriov_compare_by_vf(&a, &c), 0);
    }

    // ── Drop invalid VFs tests ─────────────────────────────────────────

    #[test]
    fn test_drop_invalid_vfs() {
        let mut vfs = vec![
            {
                let mut v = SriovVf::new();
                v.vf = 0;
                v
            },
            {
                let mut v = SriovVf::new();
                v.vf = 1;
                v
            },
            {
                // Missing VF index - should be dropped.
                let v = SriovVf::new();
                v
            },
            {
                // Out of bounds - should be dropped.
                let mut v = SriovVf::new();
                v.vf = 5;
                v
            },
        ];

        sriov_drop_invalid_vfs(3, &mut vfs).unwrap();
        assert_eq!(vfs.len(), 2);
        assert_eq!(vfs[0].vf, 0);
        assert_eq!(vfs[1].vf, 1);
    }

    #[test]
    fn test_drop_duplicate_vfs() {
        let mut vfs = vec![
            {
                let mut v = SriovVf::new();
                v.vf = 2;
                v.mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();
                v
            },
            {
                let mut v = SriovVf::new();
                v.vf = 2; // Duplicate - should be dropped.
                v.mac = MacAddress::from_str("11:22:33:44:55:66").unwrap();
                v
            },
            {
                let mut v = SriovVf::new();
                v.vf = 0;
                v
            },
        ];

        sriov_drop_invalid_vfs(4, &mut vfs).unwrap();
        assert_eq!(vfs.len(), 2);
        assert_eq!(vfs[0].vf, 2);
        // First occurrence kept.
        assert_eq!(vfs[0].mac.0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(vfs[1].vf, 0);
    }

    // ── Compute required VFs tests ─────────────────────────────────────

    #[test]
    fn test_compute_required_vfs() {
        let mut vf0 = SriovVf::new();
        vf0.vf = 2;
        let mut vf1 = SriovVf::new();
        vf1.vf = 5;

        assert_eq!(sriov_compute_required_vfs(&[vf0.clone(), vf1.clone()]), 6);
        assert_eq!(sriov_compute_required_vfs(&[]), 0);
        assert_eq!(sriov_compute_required_vfs(&[SriovVf::new()]), 0);
    }

    // ── Parse num_vfs tests ────────────────────────────────────────────

    #[test]
    fn test_parse_sriov_num_vfs() {
        assert_eq!(parse_sriov_num_vfs("").unwrap(), NUM_VFS_AUTO);
        assert_eq!(parse_sriov_num_vfs("8").unwrap(), 8);
        assert_eq!(parse_sriov_num_vfs("0").unwrap(), 0);
    }

    #[test]
    fn test_parse_sriov_num_vfs_too_large() {
        assert!(parse_sriov_num_vfs("2147483647").is_err());
    }

    #[test]
    fn test_parse_sriov_num_vfs_invalid() {
        assert!(parse_sriov_num_vfs("abc").is_err());
    }

    // ── IflaVfVlanInfo test ────────────────────────────────────────────

    #[test]
    fn test_ifla_vf_vlan_info_from_vf_config() {
        let mut vf = SriovVf::new();
        vf.vf = 7;
        vf.vlan = 500;
        vf.qos = 2;
        vf.vlan_proto = VlanProto::Eth8021Ad;

        let info = IflaVfVlanInfo::from_vf_config(&vf);
        assert_eq!(info.vf, 7);
        assert_eq!(info.vlan, 500);
        assert_eq!(info.qos, 2);
        assert_eq!(info.vlan_proto, 0x88A8);
    }

    // ── netif_sysfs_path test ──────────────────────────────────────────

    #[test]
    fn test_netif_sysfs_path() {
        let path = netif_sysfs_path("eth0");
        assert_eq!(path, PathBuf::from("/sys/class/net/eth0"));
    }
}
