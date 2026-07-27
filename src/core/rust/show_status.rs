// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/show-status.c
//

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowStatusError {
    InvalidValue,
}

pub type Result<T> = std::result::Result<T, ShowStatusError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowStatus {
    No,
    Error,
    Auto,
    Temporary,
    Yes,
}

impl ShowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Error => "error",
            Self::Auto => "auto",
            Self::Temporary => "temporary",
            Self::Yes => "yes",
        }
    }

    pub fn from_str(value: &str) -> Result<Self> {
        if is_boolean_false(value) {
            return Ok(Self::No);
        }
        if is_boolean_true(value) {
            return Ok(Self::Yes);
        }

        match value {
            "no" => Ok(Self::No),
            "error" => Ok(Self::Error),
            "auto" => Ok(Self::Auto),
            "temporary" => Ok(Self::Temporary),
            "yes" => Ok(Self::Yes),
            _ => Err(ShowStatusError::InvalidValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusUnitFormat {
    Name,
    Description,
    Combined,
}

impl StatusUnitFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Description => "description",
            Self::Combined => "combined",
        }
    }

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "name" => Ok(Self::Name),
            "description" => Ok(Self::Description),
            "combined" => Ok(Self::Combined),
            _ => Err(ShowStatusError::InvalidValue),
        }
    }
}

pub fn parse_show_status(value: &str) -> Result<ShowStatus> {
    let status = ShowStatus::from_str(value)?;
    if status == ShowStatus::Temporary {
        return Err(ShowStatusError::InvalidValue);
    }

    Ok(status)
}

fn is_boolean_true(value: &str) -> bool {
    matches!(value, "1" | "y" | "Y" | "t" | "T")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("on")
}

fn is_boolean_false(value: &str) -> bool {
    matches!(value, "0" | "n" | "N" | "f" | "F")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("off")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_status_roundtrips_named_values() {
        for status in [
            ShowStatus::No,
            ShowStatus::Error,
            ShowStatus::Auto,
            ShowStatus::Temporary,
            ShowStatus::Yes,
        ] {
            assert_eq!(ShowStatus::from_str(status.as_str()), Ok(status));
        }
    }

    #[test]
    fn show_status_accepts_true_aliases() {
        for alias in ["1", "y", "Y", "t", "T", "yes", "true", "on"] {
            assert_eq!(ShowStatus::from_str(alias), Ok(ShowStatus::Yes));
        }
    }

    #[test]
    fn show_status_accepts_false_aliases() {
        for alias in ["0", "n", "N", "f", "F", "no", "false", "off"] {
            assert_eq!(ShowStatus::from_str(alias), Ok(ShowStatus::No));
        }
    }

    #[test]
    fn show_status_rejects_unknown_values() {
        assert_eq!(
            ShowStatus::from_str("sometimes"),
            Err(ShowStatusError::InvalidValue)
        );
    }

    #[test]
    fn parse_show_status_rejects_temporary() {
        assert_eq!(
            parse_show_status("temporary"),
            Err(ShowStatusError::InvalidValue)
        );
    }

    #[test]
    fn parse_show_status_accepts_yes_and_no() {
        assert_eq!(parse_show_status("yes"), Ok(ShowStatus::Yes));
        assert_eq!(parse_show_status("off"), Ok(ShowStatus::No));
    }

    #[test]
    fn status_unit_format_roundtrips() {
        for format in [
            StatusUnitFormat::Name,
            StatusUnitFormat::Description,
            StatusUnitFormat::Combined,
        ] {
            assert_eq!(StatusUnitFormat::from_str(format.as_str()), Ok(format));
        }
    }

    #[test]
    fn status_unit_format_rejects_unknown_values() {
        assert_eq!(
            StatusUnitFormat::from_str("path"),
            Err(ShowStatusError::InvalidValue)
        );
    }
}
