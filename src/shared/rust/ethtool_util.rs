// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/ethtool-util.c, src/shared/ethtool-util.h

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplex {
    Half,
    Full,
}

struct DuplexEntry {
    value: u32,
    name: &'static str,
}

const DUPLEX_TABLE: &[DuplexEntry] = &[
    DuplexEntry {
        value: 0,
        name: "half",
    },
    DuplexEntry {
        value: 1,
        name: "full",
    },
];

impl Duplex {
    pub const fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Half),
            1 => Some(Self::Full),
            _ => None,
        }
    }

    pub const fn to_raw(self) -> u32 {
        match self {
            Self::Half => 0,
            Self::Full => 1,
        }
    }

    pub fn to_name(self) -> &'static str {
        match self {
            Self::Half => "half",
            Self::Full => "full",
        }
    }
}

impl fmt::Display for Duplex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

impl FromStr for Duplex {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_ascii_lowercase();
        DUPLEX_TABLE
            .iter()
            .find(|e| e.name == lower)
            .map(|e| Self::from_raw(e.value).unwrap())
            .ok_or(ParseError::InvalidValue("duplex"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDevPort {
    TP = 0,
    AUI = 1,
    MII = 2,
    Fibre = 3,
    BNC = 4,
    DA = 5,
    None = 15,
    Other = 255,
}

struct PortEntry {
    value: u8,
    name: &'static str,
}

const PORT_TABLE: &[PortEntry] = &[
    PortEntry {
        value: 0,
        name: "tp",
    },
    PortEntry {
        value: 1,
        name: "aui",
    },
    PortEntry {
        value: 2,
        name: "mii",
    },
    PortEntry {
        value: 3,
        name: "fibre",
    },
    PortEntry {
        value: 4,
        name: "bnc",
    },
];

impl NetDevPort {
    pub const fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::TP,
            1 => Self::AUI,
            2 => Self::MII,
            3 => Self::Fibre,
            4 => Self::BNC,
            5 => Self::DA,
            15 => Self::None,
            _ => Self::Other,
        }
    }

    pub const fn to_raw(self) -> u8 {
        self as u8
    }

    pub fn to_name(self) -> &'static str {
        match self {
            Self::TP => "tp",
            Self::AUI => "aui",
            Self::MII => "mii",
            Self::Fibre => "fibre",
            Self::BNC => "bnc",
            Self::DA => "da",
            Self::None => "none",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for NetDevPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

impl FromStr for NetDevPort {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_ascii_lowercase();
        if lower == "fiber" {
            return Ok(Self::Fibre);
        }
        PORT_TABLE
            .iter()
            .find(|e| e.name == lower)
            .map(|e| Self::from_raw(e.value))
            .ok_or(ParseError::InvalidValue("port"))
    }
}

pub const MDI_INVALID: i32 = -1;
pub const MDI: i32 = 0;
pub const MDI_X: i32 = 1;
pub const MDI_AUTO: i32 = 2;

struct MdiEntry {
    value: i32,
    name: &'static str,
    aliases: &'static [&'static str],
}

const MDI_TABLE: &[MdiEntry] = &[
    MdiEntry {
        value: 0,
        name: "mdi",
        aliases: &["straight"],
    },
    MdiEntry {
        value: 1,
        name: "mdi-x",
        aliases: &["mdix", "crossover"],
    },
    MdiEntry {
        value: 2,
        name: "auto",
        aliases: &[],
    },
];

pub fn mdi_to_string(value: i32) -> Option<&'static str> {
    match value {
        MDI_INVALID => Some("unknown"),
        MDI => Some("mdi"),
        MDI_X => Some("mdi-x"),
        MDI_AUTO => Some("auto"),
        _ => None,
    }
}

pub fn parse_mdi(s: &str) -> Option<i32> {
    let lower = s.to_ascii_lowercase();
    for entry in MDI_TABLE {
        if entry.name == lower || entry.aliases.contains(&lower.as_str()) {
            return Some(entry.value);
        }
    }
    None
}

pub const WOL_PHY: u32 = 1 << 0;
pub const WOL_UCAST: u32 = 1 << 1;
pub const WOL_MCAST: u32 = 1 << 2;
pub const WOL_BCAST: u32 = 1 << 3;
pub const WOL_ARP: u32 = 1 << 4;
pub const WOL_MAGIC: u32 = 1 << 5;
pub const WOL_SECUREON: u32 = 1 << 6;

struct WolOptionEntry {
    flag: u32,
    name: &'static str,
}

const WOL_OPTION_TABLE: &[WolOptionEntry] = &[
    WolOptionEntry {
        flag: WOL_PHY,
        name: "phy",
    },
    WolOptionEntry {
        flag: WOL_UCAST,
        name: "unicast",
    },
    WolOptionEntry {
        flag: WOL_MCAST,
        name: "multicast",
    },
    WolOptionEntry {
        flag: WOL_BCAST,
        name: "broadcast",
    },
    WolOptionEntry {
        flag: WOL_ARP,
        name: "arp",
    },
    WolOptionEntry {
        flag: WOL_MAGIC,
        name: "magic",
    },
    WolOptionEntry {
        flag: WOL_SECUREON,
        name: "secureon",
    },
];

pub fn wol_options_to_string(opts: u32) -> Option<String> {
    if opts == u32::MAX {
        return None;
    }

    let parts: Vec<&str> = WOL_OPTION_TABLE
        .iter()
        .filter(|e| opts & e.flag != 0)
        .map(|e| e.name)
        .collect();

    if parts.is_empty() {
        Some("off".to_string())
    } else {
        Some(parts.join(","))
    }
}

pub fn parse_wol_options(s: &str) -> Option<u32> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Some(u32::MAX);
    }
    if trimmed == "off" {
        return Some(0);
    }

    let mut opts = 0u32;
    for word in trimmed.split_whitespace() {
        let entry = WOL_OPTION_TABLE.iter().find(|e| e.name == word)?;
        opts |= entry.flag;
    }
    Some(opts)
}

pub fn wol_option_from_name(name: &str) -> Option<u32> {
    WOL_OPTION_TABLE
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.flag)
}

struct FeatureEntry {
    index: usize,
    name: &'static str,
}

const NETDEV_FEATURE_TABLE: &[FeatureEntry] = &[
    FeatureEntry {
        index: 0,
        name: "tx-scatter-gather",
    },
    FeatureEntry {
        index: 1,
        name: "tx-checksum-ipv4",
    },
    FeatureEntry {
        index: 2,
        name: "tx-checksum-ip-generic",
    },
    FeatureEntry {
        index: 3,
        name: "tx-checksum-ipv6",
    },
    FeatureEntry {
        index: 4,
        name: "highdma",
    },
    FeatureEntry {
        index: 5,
        name: "tx-scatter-gather-fraglist",
    },
    FeatureEntry {
        index: 6,
        name: "tx-vlan-hw-insert",
    },
    FeatureEntry {
        index: 7,
        name: "rx-vlan-hw-parse",
    },
    FeatureEntry {
        index: 8,
        name: "rx-vlan-filter",
    },
    FeatureEntry {
        index: 9,
        name: "tx-vlan-stag-hw-insert",
    },
    FeatureEntry {
        index: 10,
        name: "rx-vlan-stag-hw-parse",
    },
    FeatureEntry {
        index: 11,
        name: "rx-vlan-stag-filter",
    },
    FeatureEntry {
        index: 12,
        name: "vlan-challenged",
    },
    FeatureEntry {
        index: 13,
        name: "tx-generic-segmentation",
    },
    FeatureEntry {
        index: 14,
        name: "tx-lockless",
    },
    FeatureEntry {
        index: 15,
        name: "netns-local",
    },
    FeatureEntry {
        index: 16,
        name: "rx-gro",
    },
    FeatureEntry {
        index: 17,
        name: "rx-gro-hw",
    },
    FeatureEntry {
        index: 18,
        name: "rx-lro",
    },
    FeatureEntry {
        index: 19,
        name: "tx-tcp-segmentation",
    },
    FeatureEntry {
        index: 20,
        name: "tx-gso-robust",
    },
    FeatureEntry {
        index: 21,
        name: "tx-tcp-ecn-segmentation",
    },
    FeatureEntry {
        index: 22,
        name: "tx-tcp-mangleid-segmentation",
    },
    FeatureEntry {
        index: 23,
        name: "tx-tcp6-segmentation",
    },
    FeatureEntry {
        index: 24,
        name: "tx-fcoe-segmentation",
    },
    FeatureEntry {
        index: 25,
        name: "tx-gre-segmentation",
    },
    FeatureEntry {
        index: 26,
        name: "tx-gre-csum-segmentation",
    },
    FeatureEntry {
        index: 27,
        name: "tx-ipxip4-segmentation",
    },
    FeatureEntry {
        index: 28,
        name: "tx-ipxip6-segmentation",
    },
    FeatureEntry {
        index: 29,
        name: "tx-udp_tnl-segmentation",
    },
    FeatureEntry {
        index: 30,
        name: "tx-udp_tnl-csum-segmentation",
    },
    FeatureEntry {
        index: 31,
        name: "tx-gso-partial",
    },
    FeatureEntry {
        index: 32,
        name: "tx-tunnel-remcsum-segmentation",
    },
    FeatureEntry {
        index: 33,
        name: "tx-sctp-segmentation",
    },
    FeatureEntry {
        index: 34,
        name: "tx-esp-segmentation",
    },
    FeatureEntry {
        index: 35,
        name: "tx-udp-segmentation",
    },
    FeatureEntry {
        index: 36,
        name: "tx-gso-list",
    },
    FeatureEntry {
        index: 37,
        name: "tx-checksum-fcoe-crc",
    },
    FeatureEntry {
        index: 38,
        name: "tx-checksum-sctp",
    },
    FeatureEntry {
        index: 39,
        name: "fcoe-mtu",
    },
    FeatureEntry {
        index: 40,
        name: "rx-ntuple-filter",
    },
    FeatureEntry {
        index: 41,
        name: "rx-hashing",
    },
    FeatureEntry {
        index: 42,
        name: "rx-checksum",
    },
    FeatureEntry {
        index: 43,
        name: "tx-nocache-copy",
    },
    FeatureEntry {
        index: 44,
        name: "loopback",
    },
    FeatureEntry {
        index: 45,
        name: "rx-fcs",
    },
    FeatureEntry {
        index: 46,
        name: "rx-all",
    },
    FeatureEntry {
        index: 47,
        name: "l2-fwd-offload",
    },
    FeatureEntry {
        index: 48,
        name: "hw-tc-offload",
    },
    FeatureEntry {
        index: 49,
        name: "esp-hw-offload",
    },
    FeatureEntry {
        index: 50,
        name: "esp-tx-csum-hw-offload",
    },
    FeatureEntry {
        index: 51,
        name: "rx-udp_tunnel-port-offload",
    },
    FeatureEntry {
        index: 52,
        name: "tls-hw-record",
    },
    FeatureEntry {
        index: 53,
        name: "tls-hw-tx-offload",
    },
    FeatureEntry {
        index: 54,
        name: "tls-hw-rx-offload",
    },
    FeatureEntry {
        index: 55,
        name: "rx-gro-list",
    },
    FeatureEntry {
        index: 56,
        name: "macsec-hw-offload",
    },
    FeatureEntry {
        index: 57,
        name: "rx-udp-gro-forwarding",
    },
    FeatureEntry {
        index: 58,
        name: "hsr-tag-ins-offload",
    },
    FeatureEntry {
        index: 59,
        name: "hsr-tag-rm-offload",
    },
    FeatureEntry {
        index: 60,
        name: "hsr-fwd-offload",
    },
    FeatureEntry {
        index: 61,
        name: "hsr-dup-offload",
    },
    FeatureEntry {
        index: 62,
        name: "tx-checksum-",
    },
];

pub const NET_DEV_FEAT_SIMPLE_MAX: usize = 62;
pub const NET_DEV_FEAT_MAX: usize = 63;
pub const N_ADVERTISE: usize = 4;

pub fn netdev_feature_name(index: usize) -> Option<&'static str> {
    NETDEV_FEATURE_TABLE.get(index).map(|e| e.name)
}

pub fn netdev_feature_by_name(name: &str) -> Option<usize> {
    NETDEV_FEATURE_TABLE
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.index)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct U32Opt {
    pub value: u32,
    pub set: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetdevRingParam {
    pub rx: U32Opt,
    pub rx_mini: U32Opt,
    pub rx_jumbo: U32Opt,
    pub tx: U32Opt,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetdevChannels {
    pub rx: U32Opt,
    pub tx: U32Opt,
    pub other: U32Opt,
    pub combined: U32Opt,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetdevCoalesceParam {
    pub rx_coalesce_usecs: U32Opt,
    pub rx_max_coalesced_frames: U32Opt,
    pub rx_coalesce_usecs_irq: U32Opt,
    pub rx_max_coalesced_frames_irq: U32Opt,
    pub tx_coalesce_usecs: U32Opt,
    pub tx_max_coalesced_frames: U32Opt,
    pub tx_coalesce_usecs_irq: U32Opt,
    pub tx_max_coalesced_frames_irq: U32Opt,
    pub stats_block_coalesce_usecs: U32Opt,
    pub use_adaptive_rx_coalesce: Option<bool>,
    pub use_adaptive_tx_coalesce: Option<bool>,
    pub pkt_rate_low: U32Opt,
    pub rx_coalesce_usecs_low: U32Opt,
    pub rx_max_coalesced_frames_low: U32Opt,
    pub tx_coalesce_usecs_low: U32Opt,
    pub tx_max_coalesced_frames_low: U32Opt,
    pub pkt_rate_high: U32Opt,
    pub rx_coalesce_usecs_high: U32Opt,
    pub rx_max_coalesced_frames_high: U32Opt,
    pub tx_coalesce_usecs_high: U32Opt,
    pub tx_max_coalesced_frames_high: U32Opt,
    pub rate_sample_interval: U32Opt,
}

#[derive(Debug, Clone, Default)]
pub struct LinkSettings {
    pub autonegotiation: Option<bool>,
    pub speed: Option<u64>,
    pub duplex: Option<Duplex>,
    pub port: Option<NetDevPort>,
    pub mdi: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    InvalidValue(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(kind) => write!(f, "invalid {kind} value"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn clamp_u32_with_max(value: u32, max: u32) -> u32 {
    if value == 0 || value > max {
        max
    } else {
        value
    }
}

pub fn ring_param_is_set(ring: &NetdevRingParam) -> bool {
    ring.rx.set || ring.rx_mini.set || ring.rx_jumbo.set || ring.tx.set
}

pub fn channels_is_set(channels: &NetdevChannels) -> bool {
    channels.rx.set || channels.tx.set || channels.other.set || channels.combined.set
}

pub fn coalesce_is_set(coalesce: &NetdevCoalesceParam) -> bool {
    coalesce.use_adaptive_rx_coalesce.is_some()
        || coalesce.use_adaptive_tx_coalesce.is_some()
        || coalesce.rx_coalesce_usecs.set
        || coalesce.rx_max_coalesced_frames.set
        || coalesce.rx_coalesce_usecs_irq.set
        || coalesce.rx_max_coalesced_frames_irq.set
        || coalesce.tx_coalesce_usecs.set
        || coalesce.tx_max_coalesced_frames.set
        || coalesce.tx_coalesce_usecs_irq.set
        || coalesce.tx_max_coalesced_frames_irq.set
        || coalesce.stats_block_coalesce_usecs.set
        || coalesce.pkt_rate_low.set
        || coalesce.rx_coalesce_usecs_low.set
        || coalesce.rx_max_coalesced_frames_low.set
        || coalesce.tx_coalesce_usecs_low.set
        || coalesce.tx_max_coalesced_frames_low.set
        || coalesce.pkt_rate_high.set
        || coalesce.rx_coalesce_usecs_high.set
        || coalesce.rx_max_coalesced_frames_high.set
        || coalesce.tx_coalesce_usecs_high.set
        || coalesce.tx_max_coalesced_frames_high.set
        || coalesce.rate_sample_interval.set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplex_round_trip() {
        for entry in DUPLEX_TABLE {
            let d = Duplex::from_raw(entry.value).unwrap();
            assert_eq!(d.to_name(), entry.name);
            let parsed: Duplex = entry.name.parse().unwrap();
            assert_eq!(parsed, d);
        }
    }

    #[test]
    fn duplex_from_raw_invalid() {
        assert!(Duplex::from_raw(99).is_none());
    }

    #[test]
    fn duplex_case_insensitive() {
        assert_eq!("FULL".parse::<Duplex>().unwrap(), Duplex::Full);
        assert_eq!("Half".parse::<Duplex>().unwrap(), Duplex::Half);
    }

    #[test]
    fn duplex_parse_invalid() {
        assert!("invalid".parse::<Duplex>().is_err());
    }

    #[test]
    fn duplex_display() {
        assert_eq!(format!("{}", Duplex::Full), "full");
        assert_eq!(format!("{}", Duplex::Half), "half");
    }

    #[test]
    fn port_round_trip() {
        for entry in PORT_TABLE {
            let p = NetDevPort::from_raw(entry.value);
            assert_eq!(p.to_name(), entry.name);
            let parsed: NetDevPort = entry.name.parse().unwrap();
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn port_fiber_alias() {
        assert_eq!("fiber".parse::<NetDevPort>().unwrap(), NetDevPort::Fibre);
        assert_eq!("fibre".parse::<NetDevPort>().unwrap(), NetDevPort::Fibre);
    }

    #[test]
    fn port_from_raw_unknown() {
        assert_eq!(NetDevPort::from_raw(99), NetDevPort::Other);
    }

    #[test]
    fn port_parse_invalid() {
        assert!("invalid".parse::<NetDevPort>().is_err());
    }

    #[test]
    fn mdi_to_string_all() {
        assert_eq!(mdi_to_string(MDI_INVALID), Some("unknown"));
        assert_eq!(mdi_to_string(MDI), Some("mdi"));
        assert_eq!(mdi_to_string(MDI_X), Some("mdi-x"));
        assert_eq!(mdi_to_string(MDI_AUTO), Some("auto"));
        assert_eq!(mdi_to_string(-99), None);
    }

    #[test]
    fn parse_mdi_names_and_aliases() {
        assert_eq!(parse_mdi("mdi"), Some(MDI));
        assert_eq!(parse_mdi("straight"), Some(MDI));
        assert_eq!(parse_mdi("mdi-x"), Some(MDI_X));
        assert_eq!(parse_mdi("mdix"), Some(MDI_X));
        assert_eq!(parse_mdi("crossover"), Some(MDI_X));
        assert_eq!(parse_mdi("auto"), Some(MDI_AUTO));
        assert_eq!(parse_mdi("invalid"), None);
    }

    #[test]
    fn wol_options_to_string_variants() {
        assert_eq!(wol_options_to_string(u32::MAX), None);
        assert_eq!(wol_options_to_string(0), Some("off".to_string()));
        let s = wol_options_to_string(WOL_MAGIC | WOL_PHY).unwrap();
        assert_eq!(s, "phy,magic");
    }

    #[test]
    fn parse_wol_options_variants() {
        assert_eq!(parse_wol_options(""), Some(u32::MAX));
        assert_eq!(parse_wol_options("off"), Some(0));
        assert_eq!(parse_wol_options("magic phy"), Some(WOL_MAGIC | WOL_PHY));
    }

    #[test]
    fn wol_option_from_name_all() {
        assert_eq!(wol_option_from_name("phy"), Some(WOL_PHY));
        assert_eq!(wol_option_from_name("unicast"), Some(WOL_UCAST));
        assert_eq!(wol_option_from_name("multicast"), Some(WOL_MCAST));
        assert_eq!(wol_option_from_name("broadcast"), Some(WOL_BCAST));
        assert_eq!(wol_option_from_name("arp"), Some(WOL_ARP));
        assert_eq!(wol_option_from_name("magic"), Some(WOL_MAGIC));
        assert_eq!(wol_option_from_name("secureon"), Some(WOL_SECUREON));
        assert_eq!(wol_option_from_name("unknown"), None);
    }

    #[test]
    fn netdev_feature_table_lookup() {
        assert_eq!(netdev_feature_name(0), Some("tx-scatter-gather"));
        assert_eq!(netdev_feature_name(41), Some("rx-hashing"));
        assert_eq!(netdev_feature_name(62), Some("tx-checksum-"));
        assert_eq!(netdev_feature_name(99), None);

        assert_eq!(netdev_feature_by_name("rx-gro"), Some(16));
        assert_eq!(netdev_feature_by_name("tx-tcp-segmentation"), Some(19));
        assert_eq!(netdev_feature_by_name("nonexistent"), None);
    }

    #[test]
    fn netdev_feature_round_trip() {
        for entry in NETDEV_FEATURE_TABLE {
            if entry.name.is_empty() || entry.name.ends_with('-') {
                continue;
            }
            let idx = netdev_feature_by_name(entry.name).unwrap();
            assert_eq!(idx, entry.index);
            let name = netdev_feature_name(entry.index).unwrap();
            assert_eq!(name, entry.name);
        }
    }

    #[test]
    fn u32_opt_default() {
        let opt = U32Opt::default();
        assert!(!opt.set);
        assert_eq!(opt.value, 0);
    }

    #[test]
    fn ring_param_is_set_all_variants() {
        let mut ring = NetdevRingParam::default();
        assert!(!ring_param_is_set(&ring));

        ring.rx.set = true;
        assert!(ring_param_is_set(&ring));
        ring.rx.set = false;

        ring.rx_mini.set = true;
        assert!(ring_param_is_set(&ring));
        ring.rx_mini.set = false;

        ring.rx_jumbo.set = true;
        assert!(ring_param_is_set(&ring));
        ring.rx_jumbo.set = false;

        ring.tx.set = true;
        assert!(ring_param_is_set(&ring));
    }

    #[test]
    fn channels_is_set_all_variants() {
        let mut ch = NetdevChannels::default();
        assert!(!channels_is_set(&ch));

        ch.rx.set = true;
        assert!(channels_is_set(&ch));
        ch.rx.set = false;

        ch.tx.set = true;
        assert!(channels_is_set(&ch));
        ch.tx.set = false;

        ch.other.set = true;
        assert!(channels_is_set(&ch));
        ch.other.set = false;

        ch.combined.set = true;
        assert!(channels_is_set(&ch));
    }

    #[test]
    fn coalesce_is_set_variants() {
        let mut co = NetdevCoalesceParam::default();
        assert!(!coalesce_is_set(&co));

        co.use_adaptive_rx_coalesce = Some(true);
        assert!(coalesce_is_set(&co));
        co.use_adaptive_rx_coalesce = None;

        co.rate_sample_interval.set = true;
        assert!(coalesce_is_set(&co));
        co.rate_sample_interval.set = false;

        co.tx_coalesce_usecs.set = true;
        assert!(coalesce_is_set(&co));
    }

    #[test]
    fn clamp_u32_with_max_logic() {
        assert_eq!(clamp_u32_with_max(0, 512), 512);
        assert_eq!(clamp_u32_with_max(100, 512), 100);
        assert_eq!(clamp_u32_with_max(1024, 512), 512);
        assert_eq!(clamp_u32_with_max(512, 512), 512);
    }

    #[test]
    fn feature_constants() {
        assert!(NET_DEV_FEAT_SIMPLE_MAX < NET_DEV_FEAT_MAX);
        assert_eq!(N_ADVERTISE, 4);
    }
}
