// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udev-config.c
//
// Safe manager configuration model.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerConfig {
    pub children_max: u32,
    pub log_level: i32,
    pub trace: bool,
    pub worker_timeout_usec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError { InvalidChildrenMax, InvalidWorkerTimeout }
pub type Result<T> = std::result::Result<T, ConfigError>;

pub const USEC_PER_SEC: u64 = 1_000_000;
pub const DEFAULT_WORKER_TIMEOUT_USEC: u64 = 180 * USEC_PER_SEC;
pub const MIN_WORKER_TIMEOUT_USEC: u64 = 5 * USEC_PER_SEC;
pub const WORKER_NUM_MAX: u32 = 2048;

pub fn default_config() -> ManagerConfig {
    ManagerConfig { children_max: 8, log_level: 6, trace: false, worker_timeout_usec: DEFAULT_WORKER_TIMEOUT_USEC }
}

pub fn validate_config(config: &ManagerConfig) -> Result<()> {
    if config.children_max == 0 || config.children_max > WORKER_NUM_MAX { return Err(ConfigError::InvalidChildrenMax); }
    if config.worker_timeout_usec < MIN_WORKER_TIMEOUT_USEC { return Err(ConfigError::InvalidWorkerTimeout); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn default_configuration_is_valid() { validate_config(&default_config()).unwrap(); }
    #[test] fn rejects_zero_children_max() { let mut cfg = default_config(); cfg.children_max = 0; assert_eq!(validate_config(&cfg), Err(ConfigError::InvalidChildrenMax)); }
    #[test] fn rejects_short_worker_timeout() { let mut cfg = default_config(); cfg.worker_timeout_usec = 1; assert_eq!(validate_config(&cfg), Err(ConfigError::InvalidWorkerTimeout)); }
}
