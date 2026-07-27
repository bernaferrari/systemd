// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bond-util.c, src/shared/bond-util.h
//
// Bonding network device configuration string tables.
//
// This module provides string↔enum conversions for various bonding
// parameters including mode, xmit hash policy, LACP rate, AD select,
// fail over MAC, ARP validate, ARP all targets, and primary reselect.

use std::fmt;
use std::str::FromStr;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of ARP targets supported by kernel
pub const NETDEV_BOND_ARP_TARGETS_MAX: usize = 16;

// ── BondMode ──────────────────────────────────────────────────────────────

/// Bonding mode selection.
///
/// Determines how bonded interfaces distribute traffic and handle
/// link failures. Maps to the kernel's `BOND_MODE_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BondMode {
    /// Round-robin: packets are transmitted in sequential order.
    BalanceRr = 0,
    /// Active-backup: only one slave is active at a time.
    ActiveBackup = 1,
    /// XOR: selects slave based on hash of source/dest MAC.
    BalanceXor = 2,
    /// Broadcast: transmits on all slave interfaces.
    Broadcast = 3,
    /// IEEE 802.3ad Dynamic link aggregation (LACP).
    Ieee8023Ad = 4,
    /// Adaptive TLB: adaptive transmit load balancing.
    BalanceTlb = 5,
    /// Adaptive ALB: adaptive load balancing (includes TLB + receive balancing).
    BalanceAlb = 6,
}

impl BondMode {
    /// Total number of bond mode variants (used for table sizing).
    pub const COUNT: usize = 7;
}

impl fmt::Display for BondMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BondMode::BalanceRr => write!(f, "balance-rr"),
            BondMode::ActiveBackup => write!(f, "active-backup"),
            BondMode::BalanceXor => write!(f, "balance-xor"),
            BondMode::Broadcast => write!(f, "broadcast"),
            BondMode::Ieee8023Ad => write!(f, "802.3ad"),
            BondMode::BalanceTlb => write!(f, "balance-tlb"),
            BondMode::BalanceAlb => write!(f, "balance-alb"),
        }
    }
}

impl FromStr for BondMode {
    type Err = ParseBondError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "balance-rr" => Ok(BondMode::BalanceRr),
            "active-backup" => Ok(BondMode::ActiveBackup),
            "balance-xor" => Ok(BondMode::BalanceXor),
            "broadcast" => Ok(BondMode::Broadcast),
            "802.3ad" => Ok(BondMode::Ieee8023Ad),
            "balance-tlb" => Ok(BondMode::BalanceTlb),
            "balance-alb" => Ok(BondMode::BalanceAlb),
            _ => Err(ParseBondError::InvalidMode(s.to_owned())),
        }
    }
}

// ── BondXmitHashPolicy ────────────────────────────────────────────────────

/// Transmit hash policy for bond selection.
///
/// Determines how outgoing packets are distributed across slaves
/// when using XOR or 802.3ad modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BondXmitHashPolicy {
    /// Layer 2: hash based on MAC addresses only.
    Layer2 = 0,
    /// Layer 3+4: hash based on network + transport layer headers.
    Layer34 = 1,
    /// Layer 2+3: hash based on MAC + IP addresses.
    Layer23 = 2,
    /// Encapsulation layer 2+3: hash on encapsulated headers.
    Encap23 = 3,
    /// Encapsulation layer 3+4: hash on encapsulated network + transport.
    Encap34 = 4,
}

impl BondXmitHashPolicy {
    /// Total number of xmit hash policy variants.
    pub const COUNT: usize = 5;
}

impl fmt::Display for BondXmitHashPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BondXmitHashPolicy::Layer2 => write!(f, "layer2"),
            BondXmitHashPolicy::Layer34 => write!(f, "layer3+4"),
            BondXmitHashPolicy::Layer23 => write!(f, "layer2+3"),
            BondXmitHashPolicy::Encap23 => write!(f, "encap2+3"),
            BondXmitHashPolicy::Encap34 => write!(f, "encap3+4"),
        }
    }
}

impl FromStr for BondXmitHashPolicy {
    type Err = ParseBondError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "layer2" => Ok(BondXmitHashPolicy::Layer2),
            "layer3+4" => Ok(BondXmitHashPolicy::Layer34),
            "layer2+3" => Ok(BondXmitHashPolicy::Layer23),
            "encap2+3" => Ok(BondXmitHashPolicy::Encap23),
            "encap3+4" => Ok(BondXmitHashPolicy::Encap34),
            _ => Err(ParseBondError::InvalidXmitHashPolicy(s.to_owned())),
        }
    }
}

// ── BondLacpRate ──────────────────────────────────────────────────────────

/// LACP (Link Aggregation Control Protocol) transmission rate.
///
/// Defines how often LACP packets are sent to the partner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BondLacpRate {
    /// Slow: LACPDU sent every 30 seconds.
    Slow = 0,
    /// Fast: LACPDU sent every 1 second.
    Fast = 1,
}

impl BondLacpRate {
    /// Total number of LACP rate variants.
    pub const COUNT: usize = 2;
}

impl fmt::Display for BondLacpRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BondLacpRate::Slow => write!(f, "slow"),
            BondLacpRate::Fast => write!(f, "fast"),
        }
    }
}

impl FromStr for BondLacpRate {
    type Err = ParseBondError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "slow" => Ok(BondLacpRate::Slow),
            "fast" => Ok(BondLacpRate::Fast),
            _ => Err(ParseBondError::InvalidLacpRate(s.to_owned())),
        }
    }
}

// ── BondAdSelect ──────────────────────────────────────────────────────────

/// 802.3ad aggregator selection policy.
///
/// Determines how the active aggregator is selected in LACP mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BondAdSelect {
    /// Stable: active aggregator with highest bandwidth.
    Stable = 0,
    /// Bandwidth: select aggregator with highest total bandwidth.
    Bandwidth = 1,
    /// Count: select aggregator with most ports.
    Count = 2,
}

impl BondAdSelect {
    /// Total number of AD select variants.
    pub const COUNT: usize = 3;
}

impl fmt::Display for BondAdSelect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BondAdSelect::Stable => write!(f, "stable"),
            BondAdSelect::Bandwidth => write!(f, "bandwidth"),
            BondAdSelect::Count => write!(f, "count"),
        }
    }
}

impl FromStr for BondAdSelect {
    type Err = ParseBondError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stable" => Ok(BondAdSelect::Stable),
            "bandwidth" => Ok(BondAdSelect::Bandwidth),
            "count" => Ok(BondAdSelect::Count),
            _ => Err(ParseBondError::InvalidAdSelect(s.to_owned())),
        }
    }
}

// ── BondFailOverMac ───────────────────────────────────────────────────────

/// Fail-over MAC address policy.
///
/// Determines whether and how the MAC address is set on fail-over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BondFailOverMac {
    /// None: no MAC address change on fail-over.
    None = 0,
    /// Active: set MAC to the active slave's MAC.
    Active = 1,
    /// Follow: set MAC to the previously active slave's MAC.
    Follow = 2,
}

impl BondFailOverMac {
    /// Total number of fail-over MAC variants.
    pub const COUNT: usize = 3;
}

impl fmt::Display for BondFailOverMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BondFailOverMac::None => write!(f, "none"),
            BondFailOverMac::Active => write!(f, "active"),
            BondFailOverMac::Follow => write!(f, "follow"),
        }
    }
}

impl FromStr for BondFailOverMac {
    type Err = ParseBondError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(BondFailOverMac::None),
            "active" => Ok(BondFailOverMac::Active),
            "follow" => Ok(BondFailOverMac::Follow),
            _ => Err(ParseBondError::InvalidFailOverMac(s.to_owned())),
        }
    }
}

// ── BondArpValidate ───────────────────────────────────────────────────────

/// ARP validation targets.
///
/// Determines which slaves send and receive ARP probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BondArpValidate {
    /// No ARP validation.
    None = 0,
    /// Validate only the active slave.
    Active = 1,
    /// Validate only the backup slaves.
    Backup = 2,
    /// Validate all slaves.
    All = 3,
}

impl BondArpValidate {
    /// Total number of ARP validate variants.
    pub const COUNT: usize = 4;
}

impl fmt::Display for BondArpValidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BondArpValidate::None => write!(f, "none"),
            BondArpValidate::Active => write!(f, "active"),
            BondArpValidate::Backup => write!(f, "backup"),
            BondArpValidate::All => write!(f, "all"),
        }
    }
}

impl FromStr for BondArpValidate {
    type Err = ParseBondError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(BondArpValidate::None),
            "active" => Ok(BondArpValidate::Active),
            "backup" => Ok(BondArpValidate::Backup),
            "all" => Ok(BondArpValidate::All),
            _ => Err(ParseBondError::InvalidArpValidate(s.to_owned())),
        }
    }
}

// ── BondArpAllTargets ─────────────────────────────────────────────────────

/// ARP target response policy.
///
/// Determines how many ARP targets must respond before fail-over occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BondArpAllTargets {
    /// Any: fail-over if any target fails.
    Any = 0,
    /// All: fail-over only if all targets fail.
    All = 1,
}

impl BondArpAllTargets {
    /// Total number of ARP all targets variants.
    pub const COUNT: usize = 2;
}

impl fmt::Display for BondArpAllTargets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BondArpAllTargets::Any => write!(f, "any"),
            BondArpAllTargets::All => write!(f, "all"),
        }
    }
}

impl FromStr for BondArpAllTargets {
    type Err = ParseBondError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "any" => Ok(BondArpAllTargets::Any),
            "all" => Ok(BondArpAllTargets::All),
            _ => Err(ParseBondError::InvalidArpAllTargets(s.to_owned())),
        }
    }
}

// ── BondPrimaryReselect ───────────────────────────────────────────────────

/// Primary slave reselection policy.
///
/// Determines when the primary slave is re-selected after a fail-over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BondPrimaryReselect {
    /// Always: re-select primary as soon as it comes back up.
    Always = 0,
    /// Better: re-select primary only if it has better speed/duplex.
    Better = 1,
    /// Failure: re-select primary only when current active fails.
    Failure = 2,
}

impl BondPrimaryReselect {
    /// Total number of primary reselect variants.
    pub const COUNT: usize = 3;
}

impl fmt::Display for BondPrimaryReselect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BondPrimaryReselect::Always => write!(f, "always"),
            BondPrimaryReselect::Better => write!(f, "better"),
            BondPrimaryReselect::Failure => write!(f, "failure"),
        }
    }
}

impl FromStr for BondPrimaryReselect {
    type Err = ParseBondError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "always" => Ok(BondPrimaryReselect::Always),
            "better" => Ok(BondPrimaryReselect::Better),
            "failure" => Ok(BondPrimaryReselect::Failure),
            _ => Err(ParseBondError::InvalidPrimaryReselect(s.to_owned())),
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Error type for parsing bond configuration strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseBondError {
    InvalidMode(String),
    InvalidXmitHashPolicy(String),
    InvalidLacpRate(String),
    InvalidAdSelect(String),
    InvalidFailOverMac(String),
    InvalidArpValidate(String),
    InvalidArpAllTargets(String),
    InvalidPrimaryReselect(String),
}

impl fmt::Display for ParseBondError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseBondError::InvalidMode(s) => {
                write!(f, "invalid bond mode: '{s}'")
            }
            ParseBondError::InvalidXmitHashPolicy(s) => {
                write!(f, "invalid bond xmit hash policy: '{s}'")
            }
            ParseBondError::InvalidLacpRate(s) => {
                write!(f, "invalid bond LACP rate: '{s}'")
            }
            ParseBondError::InvalidAdSelect(s) => {
                write!(f, "invalid bond AD select: '{s}'")
            }
            ParseBondError::InvalidFailOverMac(s) => {
                write!(f, "invalid bond fail-over MAC: '{s}'")
            }
            ParseBondError::InvalidArpValidate(s) => {
                write!(f, "invalid bond ARP validate: '{s}'")
            }
            ParseBondError::InvalidArpAllTargets(s) => {
                write!(f, "invalid bond ARP all targets: '{s}'")
            }
            ParseBondError::InvalidPrimaryReselect(s) => {
                write!(f, "invalid bond primary reselect: '{s}'")
            }
        }
    }
}

impl std::error::Error for ParseBondError {}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BondMode tests ─────────────────────────────────────────────────

    #[test]
    fn bond_mode_roundtrip_all_variants() {
        let variants = [
            (BondMode::BalanceRr, "balance-rr"),
            (BondMode::ActiveBackup, "active-backup"),
            (BondMode::BalanceXor, "balance-xor"),
            (BondMode::Broadcast, "broadcast"),
            (BondMode::Ieee8023Ad, "802.3ad"),
            (BondMode::BalanceTlb, "balance-tlb"),
            (BondMode::BalanceAlb, "balance-alb"),
        ];
        for (mode, name) in variants {
            assert_eq!(mode.to_string(), name);
            assert_eq!(name.parse::<BondMode>().unwrap(), mode);
        }
    }

    #[test]
    fn bond_mode_from_str_invalid() {
        assert!("bogus".parse::<BondMode>().is_err());
        assert!("".parse::<BondMode>().is_err());
        assert!("BALANCE-RR".parse::<BondMode>().is_err());
    }

    #[test]
    fn bond_mode_count() {
        assert_eq!(BondMode::COUNT, 7);
    }

    // ── BondXmitHashPolicy tests ───────────────────────────────────────

    #[test]
    fn xmit_hash_policy_roundtrip_all_variants() {
        let variants = [
            (BondXmitHashPolicy::Layer2, "layer2"),
            (BondXmitHashPolicy::Layer34, "layer3+4"),
            (BondXmitHashPolicy::Layer23, "layer2+3"),
            (BondXmitHashPolicy::Encap23, "encap2+3"),
            (BondXmitHashPolicy::Encap34, "encap3+4"),
        ];
        for (policy, name) in variants {
            assert_eq!(policy.to_string(), name);
            assert_eq!(name.parse::<BondXmitHashPolicy>().unwrap(), policy);
        }
    }

    #[test]
    fn xmit_hash_policy_from_str_invalid() {
        assert!("layer5".parse::<BondXmitHashPolicy>().is_err());
        assert!("layer3+5".parse::<BondXmitHashPolicy>().is_err());
    }

    #[test]
    fn xmit_hash_policy_count() {
        assert_eq!(BondXmitHashPolicy::COUNT, 5);
    }

    // ── BondLacpRate tests ─────────────────────────────────────────────

    #[test]
    fn lacp_rate_roundtrip_all_variants() {
        assert_eq!(BondLacpRate::Slow.to_string(), "slow");
        assert_eq!(BondLacpRate::Fast.to_string(), "fast");
        assert_eq!("slow".parse::<BondLacpRate>().unwrap(), BondLacpRate::Slow);
        assert_eq!("fast".parse::<BondLacpRate>().unwrap(), BondLacpRate::Fast);
    }

    #[test]
    fn lacp_rate_from_str_invalid() {
        assert!("medium".parse::<BondLacpRate>().is_err());
        assert!("".parse::<BondLacpRate>().is_err());
    }

    #[test]
    fn lacp_rate_count() {
        assert_eq!(BondLacpRate::COUNT, 2);
    }

    // ── BondAdSelect tests ─────────────────────────────────────────────

    #[test]
    fn ad_select_roundtrip_all_variants() {
        let variants = [
            (BondAdSelect::Stable, "stable"),
            (BondAdSelect::Bandwidth, "bandwidth"),
            (BondAdSelect::Count, "count"),
        ];
        for (select, name) in variants {
            assert_eq!(select.to_string(), name);
            assert_eq!(name.parse::<BondAdSelect>().unwrap(), select);
        }
    }

    #[test]
    fn ad_select_from_str_invalid() {
        assert!("random".parse::<BondAdSelect>().is_err());
    }

    // ── BondFailOverMac tests ──────────────────────────────────────────

    #[test]
    fn fail_over_mac_roundtrip_all_variants() {
        let variants = [
            (BondFailOverMac::None, "none"),
            (BondFailOverMac::Active, "active"),
            (BondFailOverMac::Follow, "follow"),
        ];
        for (mac, name) in variants {
            assert_eq!(mac.to_string(), name);
            assert_eq!(name.parse::<BondFailOverMac>().unwrap(), mac);
        }
    }

    #[test]
    fn fail_over_mac_from_str_invalid() {
        assert!("other".parse::<BondFailOverMac>().is_err());
    }

    // ── BondArpValidate tests ──────────────────────────────────────────

    #[test]
    fn arp_validate_roundtrip_all_variants() {
        let variants = [
            (BondArpValidate::None, "none"),
            (BondArpValidate::Active, "active"),
            (BondArpValidate::Backup, "backup"),
            (BondArpValidate::All, "all"),
        ];
        for (validate, name) in variants {
            assert_eq!(validate.to_string(), name);
            assert_eq!(name.parse::<BondArpValidate>().unwrap(), validate);
        }
    }

    #[test]
    fn arp_validate_from_str_invalid() {
        assert!("both".parse::<BondArpValidate>().is_err());
    }

    // ── BondArpAllTargets tests ────────────────────────────────────────

    #[test]
    fn arp_all_targets_roundtrip_all_variants() {
        assert_eq!(BondArpAllTargets::Any.to_string(), "any");
        assert_eq!(BondArpAllTargets::All.to_string(), "all");
        assert_eq!(
            "any".parse::<BondArpAllTargets>().unwrap(),
            BondArpAllTargets::Any
        );
        assert_eq!(
            "all".parse::<BondArpAllTargets>().unwrap(),
            BondArpAllTargets::All
        );
    }

    #[test]
    fn arp_all_targets_from_str_invalid() {
        assert!("some".parse::<BondArpAllTargets>().is_err());
    }

    // ── BondPrimaryReselect tests ──────────────────────────────────────

    #[test]
    fn primary_reselect_roundtrip_all_variants() {
        let variants = [
            (BondPrimaryReselect::Always, "always"),
            (BondPrimaryReselect::Better, "better"),
            (BondPrimaryReselect::Failure, "failure"),
        ];
        for (reselect, name) in variants {
            assert_eq!(reselect.to_string(), name);
            assert_eq!(name.parse::<BondPrimaryReselect>().unwrap(), reselect);
        }
    }

    #[test]
    fn primary_reselect_from_str_invalid() {
        assert!("never".parse::<BondPrimaryReselect>().is_err());
    }

    // ── ParseBondError tests ───────────────────────────────────────────

    #[test]
    fn parse_error_display_mode() {
        let err = "bogus".parse::<BondMode>().unwrap_err();
        assert_eq!(err.to_string(), "invalid bond mode: 'bogus'");
    }

    #[test]
    fn parse_error_display_lacp_rate() {
        let err = "medium".parse::<BondLacpRate>().unwrap_err();
        assert_eq!(err.to_string(), "invalid bond LACP rate: 'medium'");
    }

    #[test]
    fn parse_error_display_xmit_hash_policy() {
        let err = "layer99".parse::<BondXmitHashPolicy>().unwrap_err();
        assert_eq!(err.to_string(), "invalid bond xmit hash policy: 'layer99'");
    }

    // ── Constant tests ─────────────────────────────────────────────────

    #[test]
    fn arp_targets_max() {
        assert_eq!(NETDEV_BOND_ARP_TARGETS_MAX, 16);
    }

    // ── Trait impl tests ───────────────────────────────────────────────

    #[test]
    fn bond_mode_debug() {
        assert!(format!("{:?}", BondMode::BalanceRr).contains("BalanceRr"));
    }

    #[test]
    fn bond_mode_equality() {
        assert_eq!(BondMode::BalanceRr, BondMode::BalanceRr);
        assert_ne!(BondMode::BalanceRr, BondMode::ActiveBackup);
    }

    #[test]
    fn bond_mode_repr_matches_discriminant() {
        assert_eq!(BondMode::BalanceRr as i32, 0);
        assert_eq!(BondMode::ActiveBackup as i32, 1);
        assert_eq!(BondMode::BalanceXor as i32, 2);
        assert_eq!(BondMode::Broadcast as i32, 3);
        assert_eq!(BondMode::Ieee8023Ad as i32, 4);
        assert_eq!(BondMode::BalanceTlb as i32, 5);
        assert_eq!(BondMode::BalanceAlb as i32, 6);
    }

    #[test]
    fn lacp_rate_repr_matches_discriminant() {
        assert_eq!(BondLacpRate::Slow as i32, 0);
        assert_eq!(BondLacpRate::Fast as i32, 1);
    }
}
