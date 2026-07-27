// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.FactoryReset.c
//
// Rust shadow of the io.systemd.FactoryReset varlink interface.
//
// Types for querying and requesting factory-reset status via the
// factory-reset.target unit mechanism.

// ── Constants ─────────────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.FactoryReset";

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryResetMode {
    Unsupported,
    Unspecified,
    Off,
    On,
    Complete,
    Pending,
}

impl FactoryResetMode {
    pub fn from_varlink(s: &str) -> Result<FactoryResetMode, FactoryResetError> {
        match s {
            "unsupported" => Ok(FactoryResetMode::Unsupported),
            "unspecified" => Ok(FactoryResetMode::Unspecified),
            "off" => Ok(FactoryResetMode::Off),
            "on" => Ok(FactoryResetMode::On),
            "complete" => Ok(FactoryResetMode::Complete),
            "pending" => Ok(FactoryResetMode::Pending),
            _ => Err(FactoryResetError::InvalidMode(s.to_owned())),
        }
    }

    pub fn to_varlink(self) -> &'static str {
        match self {
            FactoryResetMode::Unsupported => "unsupported",
            FactoryResetMode::Unspecified => "unspecified",
            FactoryResetMode::Off => "off",
            FactoryResetMode::On => "on",
            FactoryResetMode::Complete => "complete",
            FactoryResetMode::Pending => "pending",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, FactoryResetMode::On | FactoryResetMode::Pending)
    }

    pub fn is_supported(self) -> bool {
        !matches!(self, FactoryResetMode::Unsupported)
    }

    pub fn all() -> &'static [FactoryResetMode] {
        &[
            FactoryResetMode::Unsupported,
            FactoryResetMode::Unspecified,
            FactoryResetMode::Off,
            FactoryResetMode::On,
            FactoryResetMode::Complete,
            FactoryResetMode::Pending,
        ]
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct GetFactoryResetModeOutput {
    pub mode: FactoryResetMode,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CanRequestFactoryResetOutput {
    pub supported: bool,
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum FactoryResetError {
    NotSupported,
    InvalidMode(String),
}

impl std::fmt::Display for FactoryResetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FactoryResetError::NotSupported => write!(f, "NotSupported"),
            FactoryResetError::InvalidMode(s) => write!(f, "InvalidMode: {}", s),
        }
    }
}

impl std::error::Error for FactoryResetError {}

// ── Methods ───────────────────────────────────────────────────────────────

pub fn get_factory_reset_mode(
    current: FactoryResetMode,
) -> Result<GetFactoryResetModeOutput, FactoryResetError> {
    if matches!(current, FactoryResetMode::Unsupported) {
        return Err(FactoryResetError::NotSupported);
    }
    Ok(GetFactoryResetModeOutput { mode: current })
}

pub fn can_request_factory_reset(supported: bool) -> CanRequestFactoryResetOutput {
    CanRequestFactoryResetOutput { supported }
}

pub fn request_factory_reset(supported: bool) -> Result<FactoryResetMode, FactoryResetError> {
    if !supported {
        return Err(FactoryResetError::NotSupported);
    }
    Ok(FactoryResetMode::Pending)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_reset_mode_roundtrip() {
        for mode in FactoryResetMode::all() {
            assert_eq!(
                FactoryResetMode::from_varlink(mode.to_varlink()).unwrap(),
                *mode
            );
        }
    }

    #[test]
    fn factory_reset_mode_all_count() {
        assert_eq!(FactoryResetMode::all().len(), 6);
    }

    #[test]
    fn factory_reset_mode_from_varlink_invalid() {
        assert!(FactoryResetMode::from_varlink("bogus").is_err());
        assert!(FactoryResetMode::from_varlink("").is_err());
    }

    #[test]
    fn factory_reset_mode_is_active() {
        assert!(FactoryResetMode::On.is_active());
        assert!(FactoryResetMode::Pending.is_active());
        assert!(!FactoryResetMode::Off.is_active());
        assert!(!FactoryResetMode::Unsupported.is_active());
        assert!(!FactoryResetMode::Complete.is_active());
        assert!(!FactoryResetMode::Unspecified.is_active());
    }

    #[test]
    fn factory_reset_mode_is_supported() {
        assert!(FactoryResetMode::Off.is_supported());
        assert!(FactoryResetMode::On.is_supported());
        assert!(!FactoryResetMode::Unsupported.is_supported());
    }

    #[test]
    fn get_mode_supported_returns_mode() {
        let result = get_factory_reset_mode(FactoryResetMode::Off);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mode, FactoryResetMode::Off);
    }

    #[test]
    fn get_mode_unsupported_returns_error() {
        assert_eq!(
            get_factory_reset_mode(FactoryResetMode::Unsupported).unwrap_err(),
            FactoryResetError::NotSupported
        );
    }

    #[test]
    fn get_mode_pending() {
        let result = get_factory_reset_mode(FactoryResetMode::Pending);
        assert_eq!(result.unwrap().mode, FactoryResetMode::Pending);
    }

    #[test]
    fn get_mode_complete() {
        let result = get_factory_reset_mode(FactoryResetMode::Complete);
        assert_eq!(result.unwrap().mode, FactoryResetMode::Complete);
    }

    #[test]
    fn can_request_true() {
        let out = can_request_factory_reset(true);
        assert!(out.supported);
    }

    #[test]
    fn can_request_false() {
        let out = can_request_factory_reset(false);
        assert!(!out.supported);
    }

    #[test]
    fn request_factory_reset_supported() {
        let result = request_factory_reset(true);
        assert_eq!(result.unwrap(), FactoryResetMode::Pending);
    }

    #[test]
    fn request_factory_reset_unsupported() {
        assert_eq!(
            request_factory_reset(false).unwrap_err(),
            FactoryResetError::NotSupported
        );
    }

    #[test]
    fn error_display() {
        assert_eq!(
            format!("{}", FactoryResetError::NotSupported),
            "NotSupported"
        );
        assert_eq!(
            format!("{}", FactoryResetError::InvalidMode("bad".to_owned())),
            "InvalidMode: bad"
        );
    }

    #[test]
    fn interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.FactoryReset");
    }
}
