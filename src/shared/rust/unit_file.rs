// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/unit-file.c

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::sync::LazyLock;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitFileState {
    Enabled = 0,
    EnabledRuntime = 1,
    Linked = 2,
    LinkedRuntime = 3,
    Alias = 4,
    Masked = 5,
    MaskedRuntime = 6,
    Static = 7,
    Disabled = 8,
    Indirect = 9,
    Generated = 10,
    Transient = 11,
    Bad = 12,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitNameKind {
    Plain,
    Template,
    Instance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitFileError {
    InvalidUnitName,
    NotATemplate,
}

impl fmt::Display for UnitFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUnitName => f.write_str("invalid unit name"),
            Self::NotATemplate => f.write_str("unit name is not a template-capable name"),
        }
    }
}

impl std::error::Error for UnitFileError {}

fn split_unit_name(name: &str) -> Result<(&str, &str), UnitFileError> {
    let dot = name.rfind('.').ok_or(UnitFileError::InvalidUnitName)?;
    let (stem, suffix) = name.split_at(dot);

    if stem.is_empty() || suffix.len() <= 1 {
        return Err(UnitFileError::InvalidUnitName);
    }

    Ok((stem, &suffix[1..]))
}

pub fn classify_unit_name(name: &str) -> Result<UnitNameKind, UnitFileError> {
    let (stem, suffix) = split_unit_name(name)?;
    if suffix.contains('@') || suffix.is_empty() {
        return Err(UnitFileError::InvalidUnitName);
    }

    match stem.split_once('@') {
        None => Ok(UnitNameKind::Plain),
        Some((prefix, instance)) if prefix.is_empty() => Err(UnitFileError::InvalidUnitName),
        Some((_, "")) => Ok(UnitNameKind::Template),
        Some((_, instance)) if instance.contains('@') => Err(UnitFileError::InvalidUnitName),
        Some((_, _)) => Ok(UnitNameKind::Instance),
    }
}

pub fn unit_name_template(name: &str) -> Result<String, UnitFileError> {
    let (stem, suffix) = split_unit_name(name)?;
    let (prefix, _) = stem.split_once('@').ok_or(UnitFileError::NotATemplate)?;

    if prefix.is_empty() {
        return Err(UnitFileError::InvalidUnitName);
    }

    Ok(format!("{prefix}@.{suffix}"))
}

pub fn unit_symlink_name_compatible(
    symlink: &str,
    target: &str,
    instance_propagation: bool,
) -> bool {
    let symlink_kind = match classify_unit_name(symlink) {
        Ok(kind) => kind,
        Err(_) => return false,
    };

    if symlink == target && matches!(symlink_kind, UnitNameKind::Plain | UnitNameKind::Instance) {
        return true;
    }

    let template = match unit_name_template(symlink) {
        Ok(template) => template,
        Err(UnitFileError::NotATemplate) => return false,
        Err(UnitFileError::InvalidUnitName) => return false,
    };

    let target_kind = match classify_unit_name(target) {
        Ok(kind) => kind,
        Err(_) => return false,
    };

    if symlink_kind == UnitNameKind::Instance
        && target_kind == UnitNameKind::Template
        && template == target
    {
        return true;
    }

    instance_propagation
        && symlink_kind == UnitNameKind::Template
        && target_kind == UnitNameKind::Template
        && template == target
}

pub const SPECIAL_EMERGENCY_TARGET: &str = "emergency.target";
pub const SPECIAL_RESCUE_TARGET: &str = "rescue.target";
pub const SPECIAL_MULTI_USER_TARGET: &str = "multi-user.target";
pub const SPECIAL_GRAPHICAL_TARGET: &str = "graphical.target";

const RUNLEVEL_MAP: &[(&str, &str)] = &[
    ("emergency", SPECIAL_EMERGENCY_TARGET),
    ("-b", SPECIAL_EMERGENCY_TARGET),
    ("rescue", SPECIAL_RESCUE_TARGET),
    ("single", SPECIAL_RESCUE_TARGET),
    ("-s", SPECIAL_RESCUE_TARGET),
    ("s", SPECIAL_RESCUE_TARGET),
    ("S", SPECIAL_RESCUE_TARGET),
    ("1", SPECIAL_RESCUE_TARGET),
    ("2", SPECIAL_MULTI_USER_TARGET),
    ("3", SPECIAL_MULTI_USER_TARGET),
    ("4", SPECIAL_MULTI_USER_TARGET),
    ("5", SPECIAL_GRAPHICAL_TARGET),
];

const RUNLEVEL_MAP_INITRD: &[(&str, &str)] = &[
    ("emergency", SPECIAL_EMERGENCY_TARGET),
    ("rescue", SPECIAL_RESCUE_TARGET),
];

pub const UNIT_FILE_MAX_LINE_LENGTH: usize = 1024 * 1024;
const COMMENT_CHARS: &[char] = &['#', ';'];
const UTF8_BOM: char = '\u{FEFF}';
const SYSTEMD_LOAD_FRAGMENT_GPERF_TEMPLATE: &str =
    include_str!("../../core/load-fragment-gperf.gperf.in");

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitDirectiveSchema {
    by_section: BTreeMap<String, BTreeSet<String>>,
}

impl UnitDirectiveSchema {
    fn insert_pair(&mut self, section: String, key: String) {
        self.by_section.entry(section).or_default().insert(key);
    }

    pub fn section_count(&self) -> usize {
        self.by_section.len()
    }

    pub fn directive_count(&self) -> usize {
        self.by_section.values().map(BTreeSet::len).sum()
    }

    pub fn has_section(&self, section: &str) -> bool {
        self.by_section.contains_key(section)
    }

    pub fn has_directive(&self, section: &str, key: &str) -> bool {
        self.by_section
            .get(section)
            .is_some_and(|keys| keys.contains(key))
    }

    fn parse_macro_name(line: &str) -> Option<String> {
        let trimmed = line.trim();
        if !(trimmed.starts_with("{%- macro ") || trimmed.starts_with("{% macro ")) {
            return None;
        }

        let (_, rest) = trimmed.split_once("macro ")?;
        let (name, _) = rest.split_once('(')?;
        let name = name.trim();
        if name.is_empty() {
            return None;
        }

        Some(name.to_string())
    }

    fn parse_macro_invocation(line: &str) -> Option<(String, String)> {
        let trimmed = line.trim();
        if !(trimmed.starts_with("{{") && trimmed.ends_with("}}")) {
            return None;
        }

        let mut inner = &trimmed[2..trimmed.len().saturating_sub(2)];
        inner = inner.trim();
        if let Some(stripped) = inner.strip_prefix('-') {
            inner = stripped.trim_start();
        }
        if let Some(stripped) = inner.strip_suffix('-') {
            inner = stripped.trim_end();
        }
        let (name, args) = inner.split_once('(')?;
        let macro_name = name.trim();
        let arg = args.split_once(')')?.0.trim();

        let section = arg.trim_matches('"').trim_matches('\'').trim().to_string();
        if macro_name.is_empty() || section.is_empty() {
            return None;
        }

        Some((macro_name.to_string(), section))
    }

    fn parse_directive_pair(line: &str, macro_section: Option<&str>) -> Option<(String, String)> {
        let trimmed = line.trim();
        if let Some(section) = macro_section {
            let (lhs, _) = trimmed.split_once(',')?;
            let lhs = lhs.trim();
            if let Some(rest) = lhs.strip_prefix("{{type}}.") {
                return Some((section.to_string(), rest.trim().to_string()));
            }
        }

        if trimmed.is_empty() || trimmed.starts_with('{') || trimmed.starts_with('%') {
            return None;
        }

        let (lhs, _) = trimmed.split_once(',')?;
        let lhs = lhs.trim();

        let (section, key) = lhs.split_once('.')?;
        let section = section.trim();
        let key = key.trim();
        if section.is_empty() || key.is_empty() {
            return None;
        }

        if !section
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }

        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }

        Some((section.to_string(), key.to_string()))
    }

    fn from_gperf_template(template: &str) -> Self {
        let mut schema = Self::default();
        let mut macros: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut current_macro: Option<String> = None;

        for line in template.lines() {
            let trimmed = line.trim();
            if let Some(name) = Self::parse_macro_name(trimmed) {
                current_macro = Some(name.clone());
                macros.entry(name).or_default();
                continue;
            }

            if trimmed.starts_with("{%- endmacro") || trimmed.starts_with("{% endmacro") {
                current_macro = None;
                continue;
            }

            if let Some(name) = &current_macro {
                if let Some(lines) = macros.get_mut(name) {
                    lines.push(line.to_string());
                }
                continue;
            }

            if let Some((macro_name, section)) = Self::parse_macro_invocation(trimmed) {
                if let Some(body) = macros.get(&macro_name) {
                    for macro_line in body {
                        if let Some((sec, key)) =
                            Self::parse_directive_pair(macro_line, Some(&section))
                        {
                            schema.insert_pair(sec, key);
                        }
                    }
                }
                continue;
            }

            if let Some((section, key)) = Self::parse_directive_pair(trimmed, None) {
                schema.insert_pair(section, key);
            }
        }

        schema
    }
}

static SYSTEMD_DIRECTIVE_SCHEMA: LazyLock<UnitDirectiveSchema> = LazyLock::new(|| {
    UnitDirectiveSchema::from_gperf_template(SYSTEMD_LOAD_FRAGMENT_GPERF_TEMPLATE)
});

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitValidationReport {
    pub unknown_sections: Vec<(String, usize)>,
    pub unknown_directives: Vec<(String, String, usize)>,
}

impl UnitValidationReport {
    pub fn is_clean(&self) -> bool {
        self.unknown_sections.is_empty() && self.unknown_directives.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitFile {
    pub sections: Vec<UnitFileSection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitFileSection {
    pub name: String,
    pub line_number: usize,
    pub directives: Vec<UnitFileDirective>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitFileDirective {
    pub key: String,
    pub value: String,
    pub line_number: usize,
}

pub type Section = UnitFileSection;
pub type Directive = UnitFileDirective;

#[derive(Debug)]
pub enum UnitFileParseError {
    Io(io::Error),
    LineTooLong {
        line: usize,
    },
    InvalidSectionHeader {
        line: usize,
        header: String,
    },
    InvalidSectionName {
        line: usize,
        section: String,
    },
    UnknownSection {
        line: usize,
        section: String,
    },
    UnknownDirective {
        line: usize,
        section: String,
        key: String,
    },
    InvalidDirectiveValue {
        line: usize,
        section: String,
        key: String,
        value: String,
    },
}

impl fmt::Display for UnitFileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error while parsing unit file: {err}"),
            Self::LineTooLong { line } => write!(
                f,
                "line {line} exceeds maximum length of {UNIT_FILE_MAX_LINE_LENGTH} bytes"
            ),
            Self::InvalidSectionHeader { line, header } => {
                write!(f, "invalid section header at line {line}: '{header}'")
            }
            Self::InvalidSectionName { line, section } => {
                write!(f, "invalid section name at line {line}: '{section}'")
            }
            Self::UnknownSection { line, section } => {
                write!(f, "unknown section at line {line}: '{section}'")
            }
            Self::UnknownDirective { line, section, key } => {
                write!(f, "unknown directive at line {line}: '{section}.{key}'")
            }
            Self::InvalidDirectiveValue {
                line,
                section,
                key,
                value,
            } => write!(
                f,
                "invalid value '{value}' for directive at line {line}: '{section}.{key}'"
            ),
        }
    }
}

impl std::error::Error for UnitFileParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for UnitFileParseError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn unit_section_name_is_safe(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    !name
        .bytes()
        .any(|c| (c > 0 && c < b' ') || c == b'\'' || c == b'"' || c == b'\\' || c == 0x7f)
}

fn has_unescaped_trailing_backslash(line: &str) -> bool {
    let mut escaped = false;
    for byte in line.bytes() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        }
    }
    escaped
}

fn is_comment_line(line: &str) -> bool {
    line.trim_start().starts_with(COMMENT_CHARS)
}

impl UnitFileSection {
    pub fn values_for(&self, key: &str) -> Vec<&str> {
        let mut values = Vec::new();
        for directive in self.directives.iter().filter(|d| d.key == key) {
            if directive.value.is_empty() {
                values.clear();
            } else {
                values.push(directive.value.as_str());
            }
        }
        values
    }

    pub fn effective_values(&self) -> BTreeMap<String, Vec<String>> {
        let mut effective = BTreeMap::new();
        for directive in &self.directives {
            let values = effective
                .entry(directive.key.clone())
                .or_insert_with(Vec::new);
            if directive.value.is_empty() {
                values.clear();
            } else {
                values.push(directive.value.clone());
            }
        }
        effective
    }
}

impl UnitFile {
    pub fn systemd_directive_schema() -> &'static UnitDirectiveSchema {
        &SYSTEMD_DIRECTIVE_SCHEMA
    }

    pub fn parse_str(input: &str) -> Result<Self, UnitFileParseError> {
        Self::parse_reader(input.as_bytes())
    }

    pub fn parse_strict_systemd(input: &str) -> Result<Self, UnitFileParseError> {
        Self::parse_reader_strict_systemd(input.as_bytes())
    }

    pub fn parse_reader_strict_systemd<R: Read>(reader: R) -> Result<Self, UnitFileParseError> {
        let parsed = Self::parse_reader(reader)?;
        let report = parsed.validate_systemd_schema();

        if let Some((section, line)) = report.unknown_sections.first() {
            return Err(UnitFileParseError::UnknownSection {
                line: *line,
                section: section.clone(),
            });
        }

        if let Some((section, key, line)) = report.unknown_directives.first() {
            return Err(UnitFileParseError::UnknownDirective {
                line: *line,
                section: section.clone(),
                key: key.clone(),
            });
        }

        Ok(parsed)
    }

    pub fn parse_reader<R: Read>(reader: R) -> Result<Self, UnitFileParseError> {
        let mut parser = UnitFile::default();
        let mut current_section: Option<usize> = None;
        let mut continuation: Option<String> = None;
        let mut reader = BufReader::new(reader);
        let mut line_number = 0usize;
        let mut bom_seen = false;

        loop {
            let mut raw = String::new();
            let read = reader.read_line(&mut raw)?;
            if read == 0 {
                break;
            }

            line_number += 1;

            if raw.ends_with('\n') {
                raw.pop();
                if raw.ends_with('\r') {
                    raw.pop();
                }
            }

            if is_comment_line(&raw) {
                continue;
            }

            if !bom_seen {
                if raw.starts_with(UTF8_BOM) {
                    raw = raw.trim_start_matches(UTF8_BOM).to_string();
                }
                bom_seen = true;
            }

            let total_len = continuation.as_ref().map_or(0, |c| c.len()) + raw.len();
            if total_len > UNIT_FILE_MAX_LINE_LENGTH {
                return Err(UnitFileParseError::LineTooLong { line: line_number });
            }

            let mut logical = if let Some(mut previous) = continuation.take() {
                previous.push_str(&raw);
                previous
            } else {
                raw
            };

            if has_unescaped_trailing_backslash(&logical) {
                logical.pop();
                logical.push(' ');
                continuation = Some(logical);
                continue;
            }

            parser.parse_logical_line(&mut current_section, &logical, line_number)?;
        }

        if let Some(logical) = continuation {
            parser.parse_logical_line(&mut current_section, &logical, line_number + 1)?;
        }

        Ok(parser)
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        for (idx, section) in self.sections.iter().enumerate() {
            if idx > 0 {
                output.push('\n');
            }

            output.push('[');
            output.push_str(&section.name);
            output.push_str("]\n");

            for directive in &section.directives {
                output.push_str(&directive.key);
                output.push('=');
                output.push_str(&directive.value);
                output.push('\n');
            }
        }
        output
    }

    pub fn section(&self, name: &str) -> Option<&UnitFileSection> {
        self.sections.iter().rfind(|section| section.name == name)
    }

    pub fn validate_systemd_schema(&self) -> UnitValidationReport {
        let schema = Self::systemd_directive_schema();
        let mut report = UnitValidationReport::default();

        for section in &self.sections {
            if !schema.has_section(&section.name) && !section.name.starts_with("X-") {
                report
                    .unknown_sections
                    .push((section.name.clone(), section.line_number));
                continue;
            }

            if section.name.starts_with("X-") {
                continue;
            }

            for directive in &section.directives {
                if directive.key.starts_with("X-") {
                    continue;
                }

                if !schema.has_directive(&section.name, &directive.key) {
                    report.unknown_directives.push((
                        section.name.clone(),
                        directive.key.clone(),
                        directive.line_number,
                    ));
                }
            }
        }

        report
    }

    fn parse_logical_line(
        &mut self,
        current_section: &mut Option<usize>,
        line: &str,
        line_number: usize,
    ) -> Result<(), UnitFileParseError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        }

        if let Some(rest) = line.strip_prefix('[') {
            if !rest.ends_with(']') {
                return Err(UnitFileParseError::InvalidSectionHeader {
                    line: line_number,
                    header: line.to_string(),
                });
            }

            let section_name = rest[..rest.len() - 1].trim();
            if !unit_section_name_is_safe(section_name) {
                return Err(UnitFileParseError::InvalidSectionName {
                    line: line_number,
                    section: section_name.to_string(),
                });
            }

            self.sections.push(UnitFileSection {
                name: section_name.to_string(),
                line_number,
                directives: Vec::new(),
            });
            *current_section = Some(self.sections.len() - 1);
            return Ok(());
        }

        let Some(section_idx) = *current_section else {
            return Ok(());
        };

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            return Ok(());
        };

        let key = raw_key.trim();
        if key.is_empty() {
            return Ok(());
        }

        self.sections[section_idx]
            .directives
            .push(UnitFileDirective {
                key: key.to_string(),
                value: raw_value.trim().to_string(),
                line_number,
            });

        Ok(())
    }
}

fn in_initrd() -> bool {
    Path::new("/run/initramfs").exists()
}

pub fn runlevel_to_target(word: &str) -> Option<&'static str> {
    runlevel_to_target_with_initrd(word, in_initrd())
}

pub fn runlevel_to_target_with_initrd(word: &str, in_initrd: bool) -> Option<&'static str> {
    let (lookup, map) = if in_initrd {
        (word.strip_prefix("rd.")?, RUNLEVEL_MAP_INITRD)
    } else {
        (word, RUNLEVEL_MAP)
    };

    map.iter()
        .find_map(|(runlevel, target)| (*runlevel == lookup).then_some(*target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};

    #[test]
    fn classify_plain_unit_name() {
        assert_eq!(classify_unit_name("dbus.service"), Ok(UnitNameKind::Plain));
    }

    #[test]
    fn classify_template_unit_name() {
        assert_eq!(
            classify_unit_name("serial-getty@.service"),
            Ok(UnitNameKind::Template)
        );
    }

    #[test]
    fn classify_instance_unit_name() {
        assert_eq!(
            classify_unit_name("serial-getty@ttyS0.service"),
            Ok(UnitNameKind::Instance)
        );
    }

    #[test]
    fn reject_invalid_unit_name_without_suffix() {
        assert_eq!(
            classify_unit_name("broken"),
            Err(UnitFileError::InvalidUnitName)
        );
    }

    #[test]
    fn derive_template_name_from_instance() {
        assert_eq!(
            unit_name_template("serial-getty@ttyS0.service"),
            Ok("serial-getty@.service".to_string())
        );
    }

    #[test]
    fn derive_template_name_from_template() {
        assert_eq!(
            unit_name_template("serial-getty@.service"),
            Ok("serial-getty@.service".to_string())
        );
    }

    #[test]
    fn plain_name_matches_itself() {
        assert!(unit_symlink_name_compatible(
            "dbus.service",
            "dbus.service",
            false,
        ));
    }

    #[test]
    fn instance_name_matches_itself() {
        assert!(unit_symlink_name_compatible(
            "serial-getty@ttyS0.service",
            "serial-getty@ttyS0.service",
            false,
        ));
    }

    #[test]
    fn template_name_does_not_match_itself_without_instance() {
        assert!(!unit_symlink_name_compatible(
            "serial-getty@.service",
            "serial-getty@.service",
            false,
        ));
    }

    #[test]
    fn instance_can_point_to_template() {
        assert!(unit_symlink_name_compatible(
            "serial-getty@ttyS0.service",
            "serial-getty@.service",
            false,
        ));
    }

    #[test]
    fn template_can_propagate_instance_only_when_enabled() {
        assert!(unit_symlink_name_compatible(
            "serial-getty@.service",
            "serial-getty@.service",
            true,
        ));
        assert!(!unit_symlink_name_compatible(
            "serial-getty@.service",
            "serial-getty@.service",
            false,
        ));
    }

    #[test]
    fn incompatible_names_are_rejected() {
        assert!(!unit_symlink_name_compatible(
            "dbus.service",
            "systemd-journald.service",
            false,
        ));
    }

    #[test]
    fn invalid_symlink_name_is_rejected() {
        assert!(!unit_symlink_name_compatible(
            "not-a-unit",
            "dbus.service",
            false,
        ));
    }

    #[test]
    fn invalid_target_name_is_rejected() {
        assert!(!unit_symlink_name_compatible(
            "dbus.service",
            "not-a-unit",
            false,
        ));
    }

    #[test]
    fn normal_runlevel_maps_to_graphical_target() {
        assert_eq!(
            runlevel_to_target_with_initrd("5", false),
            Some(SPECIAL_GRAPHICAL_TARGET)
        );
    }

    #[test]
    fn rescue_alias_maps_to_rescue_target() {
        assert_eq!(
            runlevel_to_target_with_initrd("single", false),
            Some(SPECIAL_RESCUE_TARGET)
        );
    }

    #[test]
    fn initrd_requires_rd_prefix() {
        assert_eq!(runlevel_to_target_with_initrd("rescue", true), None);
        assert_eq!(
            runlevel_to_target_with_initrd("rd.rescue", true),
            Some(SPECIAL_RESCUE_TARGET)
        );
    }

    #[test]
    fn initrd_rejects_non_initrd_runlevels() {
        assert_eq!(runlevel_to_target_with_initrd("rd.5", true), None);
    }

    #[test]
    fn unknown_runlevel_returns_none() {
        assert_eq!(runlevel_to_target_with_initrd("unknown", false), None);
    }

    #[test]
    fn parse_unit_file_builds_ast() {
        let input = r#"
[Unit]
Description=Test service
After=network-online.target

[Service]
ExecStart=/usr/bin/sleep 1
"#;

        let parsed = UnitFile::parse_str(input).unwrap();
        assert_eq!(parsed.sections.len(), 2);
        assert_eq!(parsed.sections[0].name, "Unit");
        assert_eq!(parsed.sections[1].name, "Service");
        assert_eq!(parsed.sections[1].directives.len(), 1);
        assert_eq!(parsed.sections[1].directives[0].key, "ExecStart");
    }

    #[test]
    fn parse_unit_file_handles_multiline_and_comments() {
        let input = concat!(
            "[Service]\n",
            "ExecStart=/bin/echo one\\\n",
            "# this line is ignored while continuation is active\n",
            "two\\\n",
            "; another comment line\n",
            "three\n"
        );

        let parsed = UnitFile::parse_reader(Cursor::new(input)).unwrap();
        let service = parsed.section("Service").unwrap();
        assert_eq!(service.directives.len(), 1);
        assert_eq!(service.directives[0].key, "ExecStart");
        assert_eq!(service.directives[0].value, "/bin/echo one two three");
    }

    #[test]
    fn parse_unit_file_empty_value_clears_previous_values() {
        let input = concat!(
            "[Service]\n",
            "ExecStart=/bin/a\n",
            "ExecStart=/bin/b\n",
            "ExecStart=\n",
            "ExecStart=/bin/c\n"
        );

        let parsed = UnitFile::parse_str(input).unwrap();
        let service = parsed.section("Service").unwrap();
        assert_eq!(service.values_for("ExecStart"), vec!["/bin/c"]);
        assert_eq!(
            service.effective_values().get("ExecStart"),
            Some(&vec!["/bin/c".to_string()])
        );
    }

    #[test]
    fn parse_unit_file_ignores_assignments_before_section() {
        let input = concat!("Description=ignored\n", "[Unit]\n", "Description=kept\n");

        let parsed = UnitFile::parse_str(input).unwrap();
        assert_eq!(parsed.sections.len(), 1);
        let unit = parsed.section("Unit").unwrap();
        assert_eq!(unit.directives.len(), 1);
        assert_eq!(unit.directives[0].value, "kept");
    }

    #[test]
    fn parse_unit_file_rejects_invalid_section_header() {
        let input = "[Unit\nDescription=broken\n";
        let error = UnitFile::parse_str(input).unwrap_err();
        assert!(matches!(
            error,
            UnitFileParseError::InvalidSectionHeader { line: 1, .. }
        ));
    }

    #[test]
    fn parse_unit_file_rejects_unsafe_section_name_characters() {
        for bad in ["[Un\"it]\n", "[Un'it]\n", "[Un\\it]\n", "[Un\x7fit]\n"] {
            let err = UnitFile::parse_str(bad).unwrap_err();
            assert!(matches!(err, UnitFileParseError::InvalidSectionName { .. }));
        }
    }

    #[test]
    fn systemd_directive_schema_is_populated() {
        let schema = UnitFile::systemd_directive_schema();
        assert!(schema.section_count() >= 10);
        assert!(schema.directive_count() >= 200);
        assert!(schema.has_directive("Unit", "Description"));
        assert!(schema.has_directive("Service", "ExecStart"));
        assert!(schema.has_directive("Socket", "ListenStream"));
    }

    #[test]
    fn strict_parser_rejects_unknown_sections_and_keys() {
        let unknown_section = "[NotASection]\nDescription=hi\n";
        let section_error = UnitFile::parse_strict_systemd(unknown_section).unwrap_err();
        assert!(matches!(
            section_error,
            UnitFileParseError::UnknownSection { line: 1, .. }
        ));

        let unknown_key = "[Service]\nTotallyUnknownKey=value\n";
        let key_error = UnitFile::parse_strict_systemd(unknown_key).unwrap_err();
        assert!(matches!(
            key_error,
            UnitFileParseError::UnknownDirective { line: 2, .. }
        ));
    }

    #[test]
    fn strict_parser_accepts_extensions_and_known_keys() {
        let input = "\
[X-Custom]
X-OwnDirective=value
Description=extension section should not be validated against core schema

[Unit]
Description=Known

[Service]
ExecStart=/usr/bin/true
X-DebugOption=1
";
        let parsed = UnitFile::parse_strict_systemd(input).unwrap();
        let report = parsed.validate_systemd_schema();
        assert!(report.is_clean());
    }

    #[test]
    fn schema_parser_handles_jinja_whitespace_control_invocations() {
        let template = "\
{%- macro SAMPLE(type) -%}
{{type}}.Environment, config_parse_environ, 0, 0
{%- endmacro -%}
{{- SAMPLE('Service') -}}
";
        let schema = UnitDirectiveSchema::from_gperf_template(template);
        assert!(schema.has_directive("Service", "Environment"));
    }

    #[test]
    fn strict_parser_accepts_template_style_values() {
        let input = "\
[Unit]
Description=Template Base
Wants=templ-%i.target
After=template-only-%i.target

[Service]
ExecStart=/usr/bin/template %i
Environment=ROLE=%i
";
        UnitFile::parse_strict_systemd(input).unwrap();
    }

    #[test]
    fn unit_file_round_trip_via_serializer() {
        let input = "\
[Unit]
Description=Round Trip
Wants=network.target

[Service]
ExecStart=/usr/bin/echo hello
ExecStart=
ExecStart=/usr/bin/echo world
";

        let parsed = UnitFile::parse_str(input).unwrap();
        let serialized = parsed.to_text();
        let reparsed = UnitFile::parse_str(&serialized).unwrap();
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn generated_unit_files_round_trip() {
        fn without_line_numbers(mut unit: UnitFile) -> UnitFile {
            for section in &mut unit.sections {
                section.line_number = 0;
                for directive in &mut section.directives {
                    directive.line_number = 0;
                }
            }
            unit
        }

        fn sample(seed: u64) -> UnitFile {
            let mut state = seed;
            let mut next = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                state
            };

            let section_count = 1 + (next() % 4) as usize;
            let mut sections = Vec::new();
            for section_idx in 0..section_count {
                let directive_count = 1 + (next() % 6) as usize;
                let mut directives = Vec::new();
                for directive_idx in 0..directive_count {
                    directives.push(UnitFileDirective {
                        key: format!("Key{}_{}", section_idx, directive_idx),
                        value: format!("value-{}", next() % 10_000),
                        line_number: directive_idx + 1,
                    });
                }
                sections.push(UnitFileSection {
                    name: format!("Section{}", section_idx),
                    line_number: section_idx + 1,
                    directives,
                });
            }

            UnitFile { sections }
        }

        for seed in 0..64_u64 {
            let generated = sample(seed);
            let serialized = generated.to_text();
            let reparsed = UnitFile::parse_str(&serialized).unwrap();
            assert_eq!(
                without_line_numbers(reparsed),
                without_line_numbers(generated),
                "round-trip mismatch for seed {seed}"
            );
        }
    }

    #[test]
    fn parser_tolerates_arbitrary_bytes_without_panicking() {
        let mut state = 0x5A17_2C39_941B_DA2Eu64;
        for _ in 0..256 {
            state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            let len = (state % 4096) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(2862933555777941757)
                    .wrapping_add(3037000493);
                bytes.push((state & 0xFF) as u8);
            }

            let _ = UnitFile::parse_reader(Cursor::new(bytes));
        }
    }

    fn has_unit_suffix(path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        [
            ".service",
            ".socket",
            ".target",
            ".timer",
            ".path",
            ".mount",
            ".swap",
            ".automount",
            ".scope",
            ".slice",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    }

    #[test]
    fn system_unit_files_round_trip_when_available() {
        let roots = [
            PathBuf::from("/lib/systemd/system"),
            PathBuf::from("/usr/lib/systemd/system"),
        ];
        let mut files = Vec::new();

        for root in roots {
            let Ok(entries) = std::fs::read_dir(&root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && has_unit_suffix(&path) {
                    files.push(path);
                }
            }
        }

        if files.is_empty() {
            return;
        }

        for path in files {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read failed for {}: {e}", path.display()));
            let parsed = UnitFile::parse_str(&content)
                .unwrap_or_else(|e| panic!("parse failed for {}: {e}", path.display()));
            let serialized = parsed.to_text();
            let reparsed = UnitFile::parse_str(&serialized)
                .unwrap_or_else(|e| panic!("reparse failed for {}: {e}", path.display()));
            assert_eq!(
                reparsed,
                parsed,
                "round-trip mismatch for {}",
                path.display()
            );
        }
    }

    #[test]
    fn system_unit_files_validate_against_schema_when_available() {
        let roots = [
            PathBuf::from("/lib/systemd/system"),
            PathBuf::from("/usr/lib/systemd/system"),
        ];
        let mut files = Vec::new();

        for root in roots {
            let Ok(entries) = std::fs::read_dir(&root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && has_unit_suffix(&path) {
                    files.push(path);
                }
            }
        }

        if files.is_empty() {
            return;
        }

        for path in files {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read failed for {}: {e}", path.display()));
            UnitFile::parse_strict_systemd(&content)
                .unwrap_or_else(|e| panic!("strict parse failed for {}: {e}", path.display()));
        }
    }
}
