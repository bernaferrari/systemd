// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/repart/repart.c
pub const DEFAULT_MIN_SIZE: u64 = 10 * 1024 * 1024;
pub const HARD_MIN_SIZE: u64 = 4096;
pub const VERITY_SIG_SIZE: u64 = HARD_MIN_SIZE * 4;
pub const GPT_METADATA_SIZE: u64 = 1_044 * 1024;
pub const LUKS2_METADATA_SIZE: u64 = 16 * 1024 * 1024;
pub const LUKS2_METADATA_KEEP_FREE: u64 = LUKS2_METADATA_SIZE * 2;
pub const VOLUME_KEY_SIZE: u64 = 512 / 8;
pub const DEFAULT_FILESYSTEM_SECTOR_SIZE: u64 = 4096;
pub const ESP_MIN_SIZE: u64 = 100 * 1024 * 1024;
pub const ESP_MIN_SIZE_4K: u64 = 260 * 1024 * 1024;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidSectorSize(u64),
    SizeTooSmall(u64),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSectorSize(size) => write!(f, "invalid sector size {size}"),
            Self::SizeTooSmall(size) => write!(f, "size {size} smaller than hard minimum"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyMode {
    Unset,
    Refuse,
    Allow,
    Require,
    Force,
    Create,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterPartitionsType {
    None,
    Exclude,
    Include,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendMode {
    No,
    Auto,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepartConfig {
    pub empty: EmptyMode,
    pub dry_run: bool,
    pub discard: bool,
    pub size: Option<u64>,
    pub sector_size: u64,
    pub split: bool,
    pub append_fstab: AppendMode,
}

impl Default for RepartConfig {
    fn default() -> Self {
        Self {
            empty: EmptyMode::Unset,
            dry_run: true,
            discard: true,
            size: None,
            sector_size: DEFAULT_FILESYSTEM_SECTOR_SIZE,
            split: false,
            append_fstab: AppendMode::No,
        }
    }
}

impl RepartConfig {
    pub fn validate(&self) -> Result<()> {
        validate_sector_size(self.sector_size)?;
        if let Some(size) = self.size {
            if size < HARD_MIN_SIZE {
                return Err(Error::SizeTooSmall(size));
            }
        }
        Ok(())
    }
}

pub fn round_up_size(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        value
    } else {
        value.div_ceil(alignment) * alignment
    }
}

pub fn round_down_size(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        value
    } else {
        value / alignment * alignment
    }
}

pub fn validate_sector_size(sector_size: u64) -> Result<()> {
    if sector_size == 0 || sector_size % 512 != 0 {
        Err(Error::InvalidSectorSize(sector_size))
    } else {
        Ok(())
    }
}

pub fn determine_grain_size(sector_size: u64) -> Result<u64> {
    validate_sector_size(sector_size)?;
    Ok(round_up_size(1024 * 1024, sector_size))
}

pub fn esp_min_size_for_sector_size(sector_size: u64) -> Result<u64> {
    validate_sector_size(sector_size)?;
    Ok(if sector_size >= 4096 {
        ESP_MIN_SIZE_4K
    } else {
        ESP_MIN_SIZE
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_c_file() {
        assert_eq!(DEFAULT_MIN_SIZE, 10 * 1024 * 1024);
        assert_eq!(HARD_MIN_SIZE, 4096);
        assert_eq!(VERITY_SIG_SIZE, 16_384);
    }

    #[test]
    fn round_up_size_aligns_to_next_boundary() {
        assert_eq!(round_up_size(4097, 4096), 8192);
    }

    #[test]
    fn round_down_size_aligns_to_previous_boundary() {
        assert_eq!(round_down_size(8191, 4096), 4096);
    }

    #[test]
    fn sector_size_must_be_multiple_of_512() {
        assert_eq!(
            validate_sector_size(1000),
            Err(Error::InvalidSectorSize(1000))
        );
    }

    #[test]
    fn grain_size_rounds_up_mebibyte() {
        assert_eq!(determine_grain_size(4096).unwrap(), 1_048_576);
    }

    #[test]
    fn esp_min_size_uses_4k_threshold() {
        assert_eq!(esp_min_size_for_sector_size(512).unwrap(), ESP_MIN_SIZE);
        assert_eq!(esp_min_size_for_sector_size(4096).unwrap(), ESP_MIN_SIZE_4K);
    }

    #[test]
    fn config_defaults_match_c_behavior() {
        let config = RepartConfig::default();
        assert_eq!(config.empty, EmptyMode::Unset);
        assert!(config.dry_run);
        assert!(config.discard);
    }

    #[test]
    fn config_validation_rejects_too_small_size() {
        let mut config = RepartConfig::default();
        config.size = Some(1);
        assert_eq!(config.validate(), Err(Error::SizeTooSmall(1)));
    }

    #[test]
    fn config_validation_accepts_sane_values() {
        let config = RepartConfig {
            size: Some(DEFAULT_MIN_SIZE),
            ..RepartConfig::default()
        };
        assert_eq!(config.validate(), Ok(()));
    }
}
