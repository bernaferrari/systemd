// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/random-seed/random-seed-tool.c
//
// Loads and saves the random seed from /var/lib/systemd/random-seed.
//
// Provides seed action parsing, entropy credit logic, and seed size validation
// faithfully mirroring the C implementation's core data types and constants.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default path to the random seed file.
/// Corresponds to `RANDOM_SEED` defined via `RANDOM_SEED_DIR "/" RANDOM_SEED_FILE`.
pub const RANDOM_SEED_PATH: &str = "/var/lib/systemd/random-seed";

/// Minimum seed file size in bytes.
/// Mirrors the kernel's expected minimum entropy pool size.
pub const MIN_SEED_SIZE: usize = 512;

/// Maximum seed file size.
/// Corresponds to `RANDOM_POOL_SIZE_MAX` from random-util.h.
pub const RANDOM_POOL_SIZE_MAX: usize = 512;

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

/// Actions the random-seed tool can perform.
/// Corresponds to `SeedAction` in the C source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedAction {
    Load,
    Save,
}

/// Entropy credit mode.
/// Corresponds to `CreditEntropy` in the C source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditEntropy {
    /// Do not credit entropy.
    NoWay,
    /// Credit entropy if the seed file is marked as creditable.
    YesPlease,
    /// Credit entropy unconditionally (forced via `SYSTEMD_RANDOM_SEED_CREDIT=force`).
    YesForced,
}

// ── Action parsing ────────────────────────────────────────────────────────

/// Parse a seed action from its string representation.
/// Corresponds to `seed_action_from_string()` via the string table.
pub fn seed_action_from_string(s: &str) -> Result<SeedAction> {
    match s {
        "load" => Ok(SeedAction::Load),
        "save" => Ok(SeedAction::Save),
        _ => Err(Errno(-22)), // -EINVAL
    }
}

/// Convert a seed action back to its string representation.
pub fn seed_action_to_string(action: SeedAction) -> &'static str {
    match action {
        SeedAction::Load => "load",
        SeedAction::Save => "save",
    }
}

// ── Credit entropy parsing ────────────────────────────────────────────────

/// Parse the `SYSTEMD_RANDOM_SEED_CREDIT` environment variable value.
/// Corresponds to `may_credit()` logic in the C source.
pub fn parse_credit_env(value: &str) -> CreditEntropy {
    if value == "force" {
        CreditEntropy::YesForced
    } else {
        match parse_boolean(value) {
            Some(true) => CreditEntropy::YesPlease,
            _ => CreditEntropy::NoWay,
        }
    }
}

/// Parse a simple boolean string ("1", "yes", "true", "on" → true;
/// "0", "no", "false", "off" → false).
/// Mirrors `parse_boolean()` from the C source.
pub fn parse_boolean(s: &str) -> Option<bool> {
    match s {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

// ── Seed size validation ──────────────────────────────────────────────────

/// Validate a seed file size.
/// A size of 0 means "uninitialized" and is allowed; any positive size below
/// `MIN_SEED_SIZE` is rejected. Corresponds to the `CLAMP` logic in
/// `random_seed_size()` and subsequent checks.
pub fn validate_seed_size(size: usize) -> Result<()> {
    if size > 0 && size < MIN_SEED_SIZE {
        return Err(Errno(-22)); // -EINVAL
    }
    Ok(())
}

/// Clamp a raw file size to the valid seed size range.
/// Corresponds to `CLAMP(st.st_size, random_pool_size(), RANDOM_POOL_SIZE_MAX)`.
pub fn clamp_seed_size(file_size: u64, pool_size: u64) -> u64 {
    pool_size.max(file_size.min(RANDOM_POOL_SIZE_MAX as u64))
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the random-seed tool, mirroring the static args.
#[derive(Debug, Clone)]
pub struct RandomSeedConfig {
    pub action: SeedAction,
}

impl Default for RandomSeedConfig {
    fn default() -> Self {
        Self {
            action: SeedAction::Load,
        }
    }
}

impl RandomSeedConfig {
    pub fn new(action: SeedAction) -> Self {
        Self { action }
    }

    /// Whether we need to read the seed file.
    /// Corresponds to `read_seed_file = true` in the `ACTION_LOAD` branch.
    pub fn should_read(&self) -> bool {
        self.action == SeedAction::Load
    }

    /// Whether we need to write the seed file.
    /// Always true (both load and save write a new seed back).
    pub fn should_write(&self) -> bool {
        true
    }

    /// Whether to use synchronous mode (barrier for random pool init).
    /// Corresponds to `synchronous = true` for `ACTION_LOAD`.
    pub fn is_synchronous(&self) -> bool {
        self.action == SeedAction::Load
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_action_roundtrip() {
        assert_eq!(seed_action_from_string("load").unwrap(), SeedAction::Load);
        assert_eq!(seed_action_from_string("save").unwrap(), SeedAction::Save);
        assert!(seed_action_from_string("bad").is_err());
    }

    #[test]
    fn seed_action_strings() {
        assert_eq!(seed_action_to_string(SeedAction::Load), "load");
        assert_eq!(seed_action_to_string(SeedAction::Save), "save");
    }

    #[test]
    fn parse_boolean_true() {
        for v in &["1", "yes", "true", "on"] {
            assert_eq!(parse_boolean(v), Some(true));
        }
    }

    #[test]
    fn parse_boolean_false() {
        for v in &["0", "no", "false", "off"] {
            assert_eq!(parse_boolean(v), Some(false));
        }
    }

    #[test]
    fn parse_boolean_invalid() {
        assert_eq!(parse_boolean("maybe"), None);
        assert_eq!(parse_boolean(""), None);
    }

    #[test]
    fn parse_credit_env_force() {
        assert_eq!(parse_credit_env("force"), CreditEntropy::YesForced);
    }

    #[test]
    fn parse_credit_env_yes() {
        assert_eq!(parse_credit_env("1"), CreditEntropy::YesPlease);
        assert_eq!(parse_credit_env("yes"), CreditEntropy::YesPlease);
    }

    #[test]
    fn parse_credit_env_no() {
        assert_eq!(parse_credit_env("0"), CreditEntropy::NoWay);
        assert_eq!(parse_credit_env("no"), CreditEntropy::NoWay);
        assert_eq!(parse_credit_env("invalid"), CreditEntropy::NoWay);
    }

    #[test]
    fn validate_seed_size_zero_ok() {
        assert!(validate_seed_size(0).is_ok());
    }

    #[test]
    fn validate_seed_size_minimum_ok() {
        assert!(validate_seed_size(MIN_SEED_SIZE).is_ok());
    }

    #[test]
    fn validate_seed_size_large_ok() {
        assert!(validate_seed_size(1024).is_ok());
    }

    #[test]
    fn validate_seed_size_too_small() {
        assert!(validate_seed_size(100).is_err());
        assert!(validate_seed_size(1).is_err());
        assert!(validate_seed_size(511).is_err());
    }

    #[test]
    fn clamp_seed_size_basic() {
        assert_eq!(clamp_seed_size(256, 512), 512);
        assert_eq!(clamp_seed_size(1024, 512), 512);
        assert_eq!(clamp_seed_size(512, 512), 512);
    }

    #[test]
    fn clamp_seed_size_caps_at_max() {
        assert_eq!(
            clamp_seed_size(RANDOM_POOL_SIZE_MAX as u64 + 100, 512),
            RANDOM_POOL_SIZE_MAX as u64
        );
    }

    #[test]
    fn config_load_mode() {
        let cfg = RandomSeedConfig::new(SeedAction::Load);
        assert!(cfg.should_read());
        assert!(cfg.should_write());
        assert!(cfg.is_synchronous());
    }

    #[test]
    fn config_save_mode() {
        let cfg = RandomSeedConfig::new(SeedAction::Save);
        assert!(!cfg.should_read());
        assert!(cfg.should_write());
        assert!(!cfg.is_synchronous());
    }

    #[test]
    fn default_seed_path() {
        assert_eq!(RANDOM_SEED_PATH, "/var/lib/systemd/random-seed");
    }
}
