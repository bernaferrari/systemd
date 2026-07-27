// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/random-seed/random-seed-tool.c
pub const RANDOM_SEED: &str = "/var/lib/systemd/random-seed";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidBoolean(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBoolean(value) => write!(f, "invalid boolean value {value:?}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedAction {
    Load,
    Save,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditEntropy {
    NoWay,
    YesPlease,
    YesForced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditContext<'a> {
    pub env_value: Option<&'a str>,
    pub seed_marked_creditable: bool,
    pub first_boot: bool,
}

pub fn parse_boolean(value: &str) -> Result<bool> {
    match value {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        other => Err(Error::InvalidBoolean(other.to_string())),
    }
}

pub fn may_credit(context: CreditContext<'_>) -> Result<CreditEntropy> {
    let Some(value) = context.env_value else {
        return Ok(CreditEntropy::NoWay);
    };

    if value == "force" {
        return Ok(CreditEntropy::YesForced);
    }

    if !parse_boolean(value)? || !context.seed_marked_creditable || context.first_boot {
        Ok(CreditEntropy::NoWay)
    } else {
        Ok(CreditEntropy::YesPlease)
    }
}

pub fn random_seed_size(file_size: u64, pool_size: usize, pool_size_max: usize) -> usize {
    let lower_bounded = file_size.max(pool_size as u64);
    lower_bounded.min(pool_size_max as u64) as usize
}

pub fn seed_file_path(root: Option<&str>) -> String {
    match root.filter(|value| !value.is_empty()) {
        Some(root) => format!("{}{RANDOM_SEED}", root.trim_end_matches('/')),
        None => RANDOM_SEED.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_boolean_accepts_true_values() {
        assert_eq!(parse_boolean("yes").unwrap(), true);
        assert_eq!(parse_boolean("1").unwrap(), true);
    }

    #[test]
    fn parse_boolean_accepts_false_values() {
        assert_eq!(parse_boolean("no").unwrap(), false);
        assert_eq!(parse_boolean("0").unwrap(), false);
    }

    #[test]
    fn parse_boolean_rejects_invalid_value() {
        assert_eq!(
            parse_boolean("maybe"),
            Err(Error::InvalidBoolean("maybe".to_string()))
        );
    }

    #[test]
    fn may_credit_returns_no_way_without_env() {
        assert_eq!(
            may_credit(CreditContext {
                env_value: None,
                seed_marked_creditable: true,
                first_boot: false,
            })
            .unwrap(),
            CreditEntropy::NoWay
        );
    }

    #[test]
    fn may_credit_honors_force() {
        assert_eq!(
            may_credit(CreditContext {
                env_value: Some("force"),
                seed_marked_creditable: false,
                first_boot: true,
            })
            .unwrap(),
            CreditEntropy::YesForced
        );
    }

    #[test]
    fn may_credit_requires_creditable_seed_and_not_first_boot() {
        assert_eq!(
            may_credit(CreditContext {
                env_value: Some("1"),
                seed_marked_creditable: true,
                first_boot: false,
            })
            .unwrap(),
            CreditEntropy::YesPlease
        );
    }

    #[test]
    fn may_credit_suppresses_entropy_on_first_boot() {
        assert_eq!(
            may_credit(CreditContext {
                env_value: Some("1"),
                seed_marked_creditable: true,
                first_boot: true,
            })
            .unwrap(),
            CreditEntropy::NoWay
        );
    }

    #[test]
    fn random_seed_size_clamps_to_pool_limits() {
        assert_eq!(random_seed_size(100, 512, 4096), 512);
        assert_eq!(random_seed_size(8192, 512, 4096), 4096);
    }

    #[test]
    fn seed_file_path_respects_optional_root() {
        assert_eq!(seed_file_path(None), "/var/lib/systemd/random-seed");
        assert_eq!(
            seed_file_path(Some("/sysroot/")),
            "/sysroot/var/lib/systemd/random-seed"
        );
    }
}
