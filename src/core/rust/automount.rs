// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/automount.c
//
use std::path::{Component, Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Automount {
    pub unit_id: String,
    pub where_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomountSetWhereOutcome {
    Unchanged,
    Updated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomountSetWhereError {
    InvalidSuffix,
    EmptyStem,
    InvalidEscape,
    InvalidHexEscape,
    NonUtf8Path,
}

pub fn automount_set_where(
    automount: &mut Automount,
) -> Result<AutomountSetWhereOutcome, AutomountSetWhereError> {
    if automount.where_path.is_some() {
        return Ok(AutomountSetWhereOutcome::Unchanged);
    }

    let decoded = unit_name_to_path(&automount.unit_id)?;
    automount.where_path = Some(path_simplify(&decoded));
    Ok(AutomountSetWhereOutcome::Updated)
}

fn unit_name_to_path(unit_id: &str) -> Result<String, AutomountSetWhereError> {
    let stem = unit_id
        .strip_suffix(".automount")
        .ok_or(AutomountSetWhereError::InvalidSuffix)?;

    if stem.is_empty() {
        return Err(AutomountSetWhereError::EmptyStem);
    }

    if stem == "-" {
        return Ok("/".to_string());
    }

    let mut bytes = Vec::with_capacity(stem.len() + 1);
    bytes.push(b'/');

    let raw = stem.as_bytes();
    let mut i = 0usize;
    while i < raw.len() {
        match raw[i] {
            b'-' => {
                bytes.push(b'/');
                i += 1;
            }
            b'\\' => {
                if i + 3 >= raw.len() || raw[i + 1] != b'x' {
                    return Err(AutomountSetWhereError::InvalidEscape);
                }

                let hi = hex_value(raw[i + 2]).ok_or(AutomountSetWhereError::InvalidHexEscape)?;
                let lo = hex_value(raw[i + 3]).ok_or(AutomountSetWhereError::InvalidHexEscape)?;
                bytes.push((hi << 4) | lo);
                i += 4;
            }
            byte => {
                bytes.push(byte);
                i += 1;
            }
        }
    }

    String::from_utf8(bytes).map_err(|_| AutomountSetWhereError::NonUtf8Path)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn path_simplify(path: &str) -> String {
    let source = Path::new(path);
    let mut pieces = Vec::new();

    for component in source.components() {
        match component {
            Component::RootDir => pieces.clear(),
            Component::CurDir => {}
            Component::ParentDir => {
                pieces.pop();
            }
            Component::Normal(part) => pieces.push(part.to_string_lossy().into_owned()),
            Component::Prefix(_) => {}
        }
    }

    if pieces.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", pieces.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_existing_where() {
        let mut automount = Automount {
            unit_id: "tmp.automount".into(),
            where_path: Some("/already/set".into()),
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Ok(AutomountSetWhereOutcome::Unchanged)
        );
        assert_eq!(automount.where_path.as_deref(), Some("/already/set"));
    }

    #[test]
    fn derives_basic_path_from_unit_name() {
        let mut automount = Automount {
            unit_id: "var-lib.automount".into(),
            where_path: None,
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Ok(AutomountSetWhereOutcome::Updated)
        );
        assert_eq!(automount.where_path.as_deref(), Some("/var/lib"));
    }

    #[test]
    fn root_unit_maps_to_root_path() {
        let mut automount = Automount {
            unit_id: "-.automount".into(),
            where_path: None,
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Ok(AutomountSetWhereOutcome::Updated)
        );
        assert_eq!(automount.where_path.as_deref(), Some("/"));
    }

    #[test]
    fn hex_escape_is_decoded_before_simplification() {
        let mut automount = Automount {
            unit_id: r"srv-foo\x2dbar.automount".into(),
            where_path: None,
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Ok(AutomountSetWhereOutcome::Updated)
        );
        assert_eq!(automount.where_path.as_deref(), Some("/srv/foo-bar"));
    }

    #[test]
    fn dotdot_components_are_simplified() {
        let mut automount = Automount {
            unit_id: "var-lib-..-tmp.automount".into(),
            where_path: None,
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Ok(AutomountSetWhereOutcome::Updated)
        );
        assert_eq!(automount.where_path.as_deref(), Some("/var/tmp"));
    }

    #[test]
    fn missing_suffix_is_rejected() {
        let mut automount = Automount {
            unit_id: "var-lib.mount".into(),
            where_path: None,
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Err(AutomountSetWhereError::InvalidSuffix)
        );
    }

    #[test]
    fn malformed_escape_is_rejected() {
        let mut automount = Automount {
            unit_id: r"var-\q1.automount".into(),
            where_path: None,
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Err(AutomountSetWhereError::InvalidEscape)
        );
    }

    #[test]
    fn invalid_hex_escape_is_rejected() {
        let mut automount = Automount {
            unit_id: r"var-\xGG.automount".into(),
            where_path: None,
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Err(AutomountSetWhereError::InvalidHexEscape)
        );
    }

    #[test]
    fn empty_stem_is_rejected() {
        let mut automount = Automount {
            unit_id: ".automount".into(),
            where_path: None,
        };
        assert_eq!(
            automount_set_where(&mut automount),
            Err(AutomountSetWhereError::EmptyStem)
        );
    }
}
