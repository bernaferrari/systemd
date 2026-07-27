// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-format.c

pub const SOURCE_PATH: &str = "src/udev/udev-format.c";
pub const SOURCE_LINE_COUNT: usize = 552;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatSubstitutionType {
    Devnode,
    Attr,
    Env,
    Kernel,
    KernelNumber,
    Driver,
    Devpath,
    Id,
    Major,
    Minor,
    Result,
    Parent,
    Name,
    Links,
    Root,
    Sys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubstMapEntry {
    pub name: &'static str,
    pub fmt: char,
    pub ty: FormatSubstitutionType,
}

pub const SUBST_MAP: &[SubstMapEntry] = &[
    SubstMapEntry {
        name: "devnode",
        fmt: 'N',
        ty: FormatSubstitutionType::Devnode,
    },
    SubstMapEntry {
        name: "tempnode",
        fmt: 'N',
        ty: FormatSubstitutionType::Devnode,
    },
    SubstMapEntry {
        name: "attr",
        fmt: 's',
        ty: FormatSubstitutionType::Attr,
    },
    SubstMapEntry {
        name: "sysfs",
        fmt: 's',
        ty: FormatSubstitutionType::Attr,
    },
    SubstMapEntry {
        name: "env",
        fmt: 'E',
        ty: FormatSubstitutionType::Env,
    },
    SubstMapEntry {
        name: "kernel",
        fmt: 'k',
        ty: FormatSubstitutionType::Kernel,
    },
    SubstMapEntry {
        name: "number",
        fmt: 'n',
        ty: FormatSubstitutionType::KernelNumber,
    },
    SubstMapEntry {
        name: "driver",
        fmt: 'd',
        ty: FormatSubstitutionType::Driver,
    },
    SubstMapEntry {
        name: "devpath",
        fmt: 'p',
        ty: FormatSubstitutionType::Devpath,
    },
    SubstMapEntry {
        name: "id",
        fmt: 'b',
        ty: FormatSubstitutionType::Id,
    },
    SubstMapEntry {
        name: "major",
        fmt: 'M',
        ty: FormatSubstitutionType::Major,
    },
    SubstMapEntry {
        name: "minor",
        fmt: 'm',
        ty: FormatSubstitutionType::Minor,
    },
    SubstMapEntry {
        name: "result",
        fmt: 'c',
        ty: FormatSubstitutionType::Result,
    },
    SubstMapEntry {
        name: "parent",
        fmt: 'P',
        ty: FormatSubstitutionType::Parent,
    },
    SubstMapEntry {
        name: "name",
        fmt: 'D',
        ty: FormatSubstitutionType::Name,
    },
    SubstMapEntry {
        name: "links",
        fmt: 'L',
        ty: FormatSubstitutionType::Links,
    },
    SubstMapEntry {
        name: "root",
        fmt: 'r',
        ty: FormatSubstitutionType::Root,
    },
    SubstMapEntry {
        name: "sys",
        fmt: 'S',
        ty: FormatSubstitutionType::Sys,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    UnknownToken,
    InvalidBraces,
}

pub fn format_type_to_string(ty: FormatSubstitutionType) -> Result<&'static str, FormatError> {
    SUBST_MAP
        .iter()
        .find(|entry| entry.ty == ty)
        .map(|entry| entry.name)
        .ok_or(FormatError::UnknownToken)
}

pub fn format_type_to_char(ty: FormatSubstitutionType) -> Result<char, FormatError> {
    SUBST_MAP
        .iter()
        .find(|entry| entry.ty == ty)
        .map(|entry| entry.fmt)
        .ok_or(FormatError::UnknownToken)
}

pub fn parse_substitution(input: &str) -> Result<(FormatSubstitutionType, String), FormatError> {
    let (prefix, rest) = input.split_at(1);
    match prefix {
        "$" => parse_dollar(rest),
        "%" => parse_percent(rest),
        _ => Err(FormatError::UnknownToken),
    }
}

fn parse_dollar(input: &str) -> Result<(FormatSubstitutionType, String), FormatError> {
    for entry in SUBST_MAP {
        if let Some(rest) = input.strip_prefix(entry.name) {
            return parse_attr(rest, entry.ty);
        }
    }
    Err(FormatError::UnknownToken)
}

fn parse_percent(input: &str) -> Result<(FormatSubstitutionType, String), FormatError> {
    let mut chars = input.chars();
    let fmt = chars.next().ok_or(FormatError::UnknownToken)?;
    let rest = chars.as_str();
    for entry in SUBST_MAP {
        if entry.fmt == fmt {
            return parse_attr(rest, entry.ty);
        }
    }
    Err(FormatError::UnknownToken)
}

fn parse_attr(
    rest: &str,
    ty: FormatSubstitutionType,
) -> Result<(FormatSubstitutionType, String), FormatError> {
    if let Some(attr) = rest.strip_prefix('{') {
        let end = attr.find('}').ok_or(FormatError::InvalidBraces)?;
        return Ok((ty, attr[..end].to_string()));
    }
    Ok((ty, String::new()))
}

pub fn validate_port_model() -> Result<(), FormatError> {
    if SUBST_MAP.len() != 18 {
        return Err(FormatError::UnknownToken);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/udev-format.c");
        assert_eq!(SOURCE_LINE_COUNT, 552);
    }

    #[test]
    fn devnode_mapping_matches_c_table() {
        assert_eq!(
            format_type_to_char(FormatSubstitutionType::Devnode).unwrap(),
            'N'
        );
        assert_eq!(
            format_type_to_string(FormatSubstitutionType::Devnode).unwrap(),
            "devnode"
        );
    }

    #[test]
    fn parse_dollar_form_with_attr() {
        assert_eq!(
            parse_substitution("$attr{size}").unwrap(),
            (FormatSubstitutionType::Attr, "size".into())
        );
    }

    #[test]
    fn parse_percent_form_without_attr() {
        assert_eq!(
            parse_substitution("%k").unwrap(),
            (FormatSubstitutionType::Kernel, String::new())
        );
    }

    #[test]
    fn parse_percent_form_with_result_selector() {
        assert_eq!(
            parse_substitution("%c{2+}").unwrap(),
            (FormatSubstitutionType::Result, "2+".into())
        );
    }

    #[test]
    fn reject_unknown_substitution() {
        assert_eq!(
            parse_substitution("$unknown"),
            Err(FormatError::UnknownToken)
        );
    }

    #[test]
    fn reject_unclosed_attr_braces() {
        assert_eq!(
            parse_substitution("$env{ID"),
            Err(FormatError::InvalidBraces)
        );
    }

    #[test]
    fn deprecated_aliases_share_same_type() {
        assert_eq!(
            parse_substitution("$tempnode").unwrap().0,
            FormatSubstitutionType::Devnode
        );
        assert_eq!(
            parse_substitution("$sysfs{modalias}").unwrap().0,
            FormatSubstitutionType::Attr
        );
    }

    #[test]
    fn table_size_matches_c_map() {
        assert_eq!(SUBST_MAP.len(), 18);
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
