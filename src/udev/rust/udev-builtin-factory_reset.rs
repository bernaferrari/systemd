// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-factory_reset.c
//
// Factory reset mode parsing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryResetMode {
    Off,
    Requested,
    Forced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactoryResetError {
    InvalidMode,
}
pub type Result<T> = std::result::Result<T, FactoryResetError>;

pub fn parse_factory_reset_mode(value: &str) -> Result<FactoryResetMode> {
    match value.trim() {
        "0" | "off" => Ok(FactoryResetMode::Off),
        "1" | "requested" => Ok(FactoryResetMode::Requested),
        "force" | "forced" => Ok(FactoryResetMode::Forced),
        _ => Err(FactoryResetError::InvalidMode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_known_modes() {
        assert_eq!(
            parse_factory_reset_mode("off").unwrap(),
            FactoryResetMode::Off
        );
        assert_eq!(
            parse_factory_reset_mode("force").unwrap(),
            FactoryResetMode::Forced
        );
    }
    #[test]
    fn rejects_unknown_mode() {
        assert_eq!(
            parse_factory_reset_mode("nope"),
            Err(FactoryResetError::InvalidMode)
        );
    }
}
