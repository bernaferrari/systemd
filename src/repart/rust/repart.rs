// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/repart/repart.c
//
// Grows and shrinks partitions, creates disk images with defined partition tables.
//
// Provides alignment helpers, partition type parsing, empty-mode classification,
// and configuration validation faithfully mirroring the C implementation's data
// types and constants.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default minimum partition size: 10 MiB.
/// Corresponds to `DEFAULT_MIN_SIZE` in repart.c.
pub const DEFAULT_MIN_SIZE: u64 = 10 * 1024 * 1024;

/// Hard lower limit for new partition sizes: 4096 bytes.
/// Corresponds to `HARD_MIN_SIZE` in repart.c.
pub const HARD_MIN_SIZE: u64 = 4096;

/// GPT metadata overhead: approximately 1 MiB.
/// Corresponds to `GPT_METADATA_SIZE` in repart.c.
pub const GPT_METADATA_SIZE: u64 = 1044 * 1024;

/// LUKS2 metadata overhead: 16 MiB.
/// Corresponds to `LUKS2_METADATA_SIZE` in repart.c.
pub const LUKS2_METADATA_SIZE: u64 = 16 * 1024 * 1024;

/// Default filesystem sector size: 4096 bytes.
/// Corresponds to `DEFAULT_FILESYSTEM_SECTOR_SIZE` in repart.c.
pub const DEFAULT_FILESYSTEM_SECTOR_SIZE: u64 = 4096;

/// Minimum ESP size for 512-byte sectors: 100 MiB.
pub const ESP_MIN_SIZE: u64 = 100 * 1024 * 1024;

/// Minimum ESP size for 4K sectors: 260 MiB.
pub const ESP_MIN_SIZE_4K: u64 = 260 * 1024 * 1024;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Empty disk mode.
/// Corresponds to `EmptyMode` in repart.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyMode {
    Unset,
    Refuse,
    Allow,
    Require,
    Force,
    Create,
}

/// Discard mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardMode {
    None,
    Offset,
    Pages,
}

/// Well-known GPT partition type GUIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptPartitionType {
    Esp,
    Xbootldr,
    RootX86_64,
    RootAarch64,
    UsrX86_64,
    UsrAarch64,
    Home,
    Swap,
    Linux,
    Unknown,
}

// ── Alignment helpers ─────────────────────────────────────────────────────

/// Round `value` up to the next multiple of `alignment`.
/// Corresponds to `ROUND_UP` / `round_up_size` logic.
///
/// # Panics
/// Panics if `alignment` is 0.
pub fn round_up(value: u64, alignment: u64) -> u64 {
    assert!(alignment > 0, "alignment must be non-zero");
    (value + alignment - 1) / alignment * alignment
}

/// Round `value` down to the previous multiple of `alignment`.
/// Corresponds to `round_down_size` logic.
///
/// # Panics
/// Panics if `alignment` is 0.
pub fn round_down(value: u64, alignment: u64) -> u64 {
    assert!(alignment > 0, "alignment must be non-zero");
    (value / alignment) * alignment
}

/// Determine the grain size for a given sector size.
/// Corresponds to the grain size logic in the C source (1 MiB aligned).
pub fn determine_grain_size(sector_size: u64) -> u64 {
    round_up(1024 * 1024, sector_size)
}

// ── GUID parsing ──────────────────────────────────────────────────────────

/// Parse a GPT partition type GUID string into a `GptPartitionType`.
/// Corresponds to the GUID table used throughout repart.c.
pub fn parse_partition_type_guid(guid: &str) -> Result<GptPartitionType> {
    match guid.to_ascii_lowercase().as_str() {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => Ok(GptPartitionType::Esp),
        "bc13c2ff-59e6-4262-a352-b275fd6f7172" => Ok(GptPartitionType::Xbootldr),
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" => Ok(GptPartitionType::RootX86_64),
        "b921b045-1df0-41c3-af44-4c6f280d3fae" => Ok(GptPartitionType::RootAarch64),
        "8484680c-9521-48c6-9c11-0714cc5610d1" => Ok(GptPartitionType::UsrX86_64),
        "75250d76-8cc6-458e-be48-bf4093e9599a" => Ok(GptPartitionType::UsrAarch64),
        "933ac7e1-2eb4-4f13-b844-0e14e2aef915" => Ok(GptPartitionType::Home),
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => Ok(GptPartitionType::Swap),
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => Ok(GptPartitionType::Linux),
        _ => Err(Errno(-95)), // -EOPNOTSUPP
    }
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Repart tool configuration, mirroring the static args in repart.c.
#[derive(Debug, Clone)]
pub struct RepartConfig {
    pub empty: EmptyMode,
    pub dry_run: bool,
    pub discard: DiscardMode,
    pub sector_size: Option<u64>,
    pub size: Option<u64>,
    pub seed: Option<u64>,
    pub split: bool,
    pub json_format: bool,
}

impl Default for RepartConfig {
    fn default() -> Self {
        Self {
            empty: EmptyMode::Unset,
            dry_run: true,
            discard: DiscardMode::None,
            sector_size: None,
            size: None,
            seed: None,
            split: false,
            json_format: false,
        }
    }
}

impl RepartConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate sector size: must be a non-zero multiple of 512.
    pub fn validate(&self) -> Result<()> {
        if let Some(ss) = self.sector_size {
            if ss == 0 || ss % 512 != 0 {
                return Err(Errno(-22)); // -EINVAL
            }
        }
        Ok(())
    }

    /// Check whether we are in an empty-disk mode.
    pub fn is_empty_mode(&self) -> bool {
        !matches!(self.empty, EmptyMode::Unset | EmptyMode::Refuse)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_up_basic() {
        assert_eq!(round_up(0, 512), 0);
        assert_eq!(round_up(1, 512), 512);
        assert_eq!(round_up(512, 512), 512);
        assert_eq!(round_up(513, 512), 1024);
        assert_eq!(round_up(1023, 512), 1024);
        assert_eq!(round_up(1024, 512), 1024);
    }

    #[test]
    fn round_up_large_alignment() {
        assert_eq!(round_up(1, 4096), 4096);
        assert_eq!(round_up(4096, 4096), 4096);
        assert_eq!(round_up(4097, 4096), 8192);
    }

    #[test]
    fn round_down_basic() {
        assert_eq!(round_down(0, 512), 0);
        assert_eq!(round_down(511, 512), 0);
        assert_eq!(round_down(512, 512), 512);
        assert_eq!(round_down(1023, 512), 512);
        assert_eq!(round_down(1024, 512), 1024);
        assert_eq!(round_down(1025, 512), 1024);
    }

    #[test]
    fn grain_size() {
        assert_eq!(determine_grain_size(512), 1024 * 1024);
        assert_eq!(determine_grain_size(4096), 1024 * 1024);
    }

    #[test]
    fn parse_partition_type_esp() {
        assert_eq!(
            parse_partition_type_guid("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").unwrap(),
            GptPartitionType::Esp
        );
    }

    #[test]
    fn parse_partition_type_case_insensitive() {
        assert_eq!(
            parse_partition_type_guid("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").unwrap(),
            GptPartitionType::Esp
        );
    }

    #[test]
    fn parse_partition_type_xbootldr() {
        assert_eq!(
            parse_partition_type_guid("bc13c2ff-59e6-4262-a352-b275fd6f7172").unwrap(),
            GptPartitionType::Xbootldr
        );
    }

    #[test]
    fn parse_partition_type_root_x86_64() {
        assert_eq!(
            parse_partition_type_guid("4f68bce3-e8cd-4db1-96e7-fbcaf984b709").unwrap(),
            GptPartitionType::RootX86_64
        );
    }

    #[test]
    fn parse_partition_type_unknown() {
        assert!(parse_partition_type_guid("deadbeef-dead-dead-dead-deaddeafbeef").is_err());
    }

    #[test]
    fn config_validate_ok() {
        let cfg = RepartConfig::new();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_sector_size_zero() {
        let cfg = RepartConfig {
            sector_size: Some(0),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_sector_size_misaligned() {
        let cfg = RepartConfig {
            sector_size: Some(1000),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_sector_size_valid() {
        let cfg = RepartConfig {
            sector_size: Some(512),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn empty_mode_detection() {
        assert!(!RepartConfig::new().is_empty_mode());
        assert!(
            !RepartConfig {
                empty: EmptyMode::Refuse,
                ..Default::default()
            }
            .is_empty_mode()
        );
        assert!(
            RepartConfig {
                empty: EmptyMode::Force,
                ..Default::default()
            }
            .is_empty_mode()
        );
        assert!(
            RepartConfig {
                empty: EmptyMode::Create,
                ..Default::default()
            }
            .is_empty_mode()
        );
        assert!(
            RepartConfig {
                empty: EmptyMode::Allow,
                ..Default::default()
            }
            .is_empty_mode()
        );
    }

    #[test]
    fn constants_sanity() {
        assert_eq!(HARD_MIN_SIZE, 4096);
        assert!(GPT_METADATA_SIZE < 2 * 1024 * 1024);
        assert_eq!(LUKS2_METADATA_SIZE, 16 * 1024 * 1024);
        assert_eq!(DEFAULT_FILESYSTEM_SECTOR_SIZE, 4096);
        assert!(ESP_MIN_SIZE < ESP_MIN_SIZE_4K);
    }
}
