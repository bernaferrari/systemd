// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-rules.c

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const SOURCE_PATH: &str = "src/udev/udev-rules.c";
pub const SOURCE_LINE_COUNT: usize = 3347;
pub const RULES_DIRS: [&str; 2] = ["/usr/lib/udev/rules.d", "/etc/udev/rules.d"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevRuleOperatorType {
    Match,
    NoMatch,
    Add,
    Remove,
    Assign,
    AssignFinal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevRuleMatchType {
    Empty,
    Plain,
    PlainWithEmpty,
    Glob,
    GlobWithEmpty,
    Subsystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevRuleSubstituteType {
    Plain,
    Format,
    Subsys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevRuleTokenClass {
    Match,
    Assign,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    Io(i32),
    UnknownOperator(String),
    UnknownToken(String),
    MissingOperator(String),
    MissingValue(String),
    MalformedKey(String),
    UnterminatedQuote(String),
    InvalidTokenClass {
        key: String,
        operator: UdevRuleOperatorType,
    },
}

impl From<io::Error> for RuleError {
    fn from(value: io::Error) -> Self {
        RuleError::Io(-value.raw_os_error().unwrap_or(libc::EIO))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleKey {
    Action,
    Devpath,
    Kernel,
    Name,
    Symlink,
    Subsystem,
    Driver,
    Attr(String),
    Sysctl(String),
    Env(String),
    Tag,
    Program,
    Result,
    Import(Option<String>),
    Test(Option<String>),
    Owner,
    Group,
    Mode,
    Run(Option<String>),
    Label,
    Goto,
    Options,
}

impl RuleKey {
    fn display_name(&self) -> &'static str {
        match self {
            RuleKey::Action => "ACTION",
            RuleKey::Devpath => "DEVPATH",
            RuleKey::Kernel => "KERNEL",
            RuleKey::Name => "NAME",
            RuleKey::Symlink => "SYMLINK",
            RuleKey::Subsystem => "SUBSYSTEM",
            RuleKey::Driver => "DRIVER",
            RuleKey::Attr(_) => "ATTR",
            RuleKey::Sysctl(_) => "SYSCTL",
            RuleKey::Env(_) => "ENV",
            RuleKey::Tag => "TAG",
            RuleKey::Program => "PROGRAM",
            RuleKey::Result => "RESULT",
            RuleKey::Import(_) => "IMPORT",
            RuleKey::Test(_) => "TEST",
            RuleKey::Owner => "OWNER",
            RuleKey::Group => "GROUP",
            RuleKey::Mode => "MODE",
            RuleKey::Run(_) => "RUN",
            RuleKey::Label => "LABEL",
            RuleKey::Goto => "GOTO",
            RuleKey::Options => "OPTIONS",
        }
    }

    fn supports_match(&self) -> bool {
        matches!(
            self,
            RuleKey::Action
                | RuleKey::Devpath
                | RuleKey::Kernel
                | RuleKey::Name
                | RuleKey::Symlink
                | RuleKey::Subsystem
                | RuleKey::Driver
                | RuleKey::Attr(_)
                | RuleKey::Sysctl(_)
                | RuleKey::Env(_)
                | RuleKey::Tag
                | RuleKey::Program
                | RuleKey::Result
                | RuleKey::Import(_)
                | RuleKey::Test(_)
        )
    }

    fn supports_assign(&self) -> bool {
        matches!(
            self,
            RuleKey::Name
                | RuleKey::Symlink
                | RuleKey::Owner
                | RuleKey::Group
                | RuleKey::Mode
                | RuleKey::Attr(_)
                | RuleKey::Sysctl(_)
                | RuleKey::Env(_)
                | RuleKey::Tag
                | RuleKey::Run(_)
                | RuleKey::Label
                | RuleKey::Goto
                | RuleKey::Import(_)
                | RuleKey::Options
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleToken {
    pub key: RuleKey,
    pub operator: UdevRuleOperatorType,
    pub value: String,
}

pub fn parse_operator(input: &str) -> Result<UdevRuleOperatorType, RuleError> {
    match input {
        "==" => Ok(UdevRuleOperatorType::Match),
        "!=" => Ok(UdevRuleOperatorType::NoMatch),
        "+=" => Ok(UdevRuleOperatorType::Add),
        "-=" => Ok(UdevRuleOperatorType::Remove),
        "=" => Ok(UdevRuleOperatorType::Assign),
        ":=" => Ok(UdevRuleOperatorType::AssignFinal),
        other => Err(RuleError::UnknownOperator(other.to_string())),
    }
}

pub fn token_class(name: &str) -> Result<UdevRuleTokenClass, RuleError> {
    match name {
        "ACTION" | "DEVPATH" | "KERNEL" | "SUBSYSTEM" | "DRIVER" | "ENV" | "ATTR" | "SYSCTL"
        | "TAG" | "PROGRAM" | "RESULT" | "TEST" => Ok(UdevRuleTokenClass::Match),
        "NAME" | "SYMLINK" | "OWNER" | "GROUP" | "MODE" | "RUN" | "LABEL" | "GOTO" | "IMPORT"
        | "OPTIONS" => Ok(UdevRuleTokenClass::Assign),
        other => Err(RuleError::UnknownToken(other.to_string())),
    }
}

pub fn infer_match_type(pattern: &str) -> Result<UdevRuleMatchType, RuleError> {
    if pattern.is_empty() {
        return Ok(UdevRuleMatchType::Empty);
    }
    if pattern.contains('|') && !pattern.contains(['*', '?', '[']) {
        return Ok(UdevRuleMatchType::PlainWithEmpty);
    }
    if pattern.contains(['*', '?', '[']) && pattern.contains('|') {
        return Ok(UdevRuleMatchType::GlobWithEmpty);
    }
    if pattern.contains(['*', '?', '[']) {
        return Ok(UdevRuleMatchType::Glob);
    }
    Ok(UdevRuleMatchType::Plain)
}

pub fn validate_port_model() -> Result<(), RuleError> {
    if SOURCE_LINE_COUNT < 3000 || SOURCE_PATH != "src/udev/udev-rules.c" {
        return Err(RuleError::UnknownToken("rules".into()));
    }
    Ok(())
}

pub fn parse_rules_line(line: &str) -> Result<Vec<RuleToken>, RuleError> {
    let line = strip_inline_comment(line);
    if line.trim().is_empty() {
        return Ok(Vec::new());
    }

    split_rule_clauses(line)
        .iter()
        .map(|clause| parse_rule_clause(clause))
        .collect()
}

pub fn parse_rules_text(input: &str) -> Result<Vec<Vec<RuleToken>>, RuleError> {
    let mut logical_lines = Vec::new();
    let mut current = String::new();

    for line in input.lines() {
        let mut part = line.trim_end().to_string();
        let continuation = part.ends_with('\\');
        if continuation {
            part.pop();
        }

        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&part);

        if continuation {
            continue;
        }

        logical_lines.push(std::mem::take(&mut current));
    }

    if !current.is_empty() {
        logical_lines.push(current);
    }

    let mut out = Vec::new();
    for line in logical_lines {
        let parsed = parse_rules_line(&line)?;
        if !parsed.is_empty() {
            out.push(parsed);
        }
    }

    Ok(out)
}

pub fn parse_rules_from_paths(paths: &[PathBuf]) -> Result<Vec<Vec<RuleToken>>, RuleError> {
    let mut aggregated = Vec::new();

    for path in paths {
        let text = fs::read_to_string(path)?;
        aggregated.extend(parse_rules_text(&text)?);
    }

    Ok(aggregated)
}

pub fn parse_rules_from_dirs(directories: &[&Path]) -> Result<Vec<Vec<RuleToken>>, RuleError> {
    let mut files = Vec::new();
    for dir in directories {
        if !dir.exists() {
            continue;
        }

        let mut dir_files: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("rules"))
            })
            .collect();

        dir_files.sort();
        files.extend(dir_files);
    }

    parse_rules_from_paths(&files)
}

fn parse_rule_clause(clause: &str) -> Result<RuleToken, RuleError> {
    let (key_raw, op_raw, value_raw) = split_key_operator_value(clause)?;
    let operator = parse_operator(op_raw)?;
    let key = parse_key(key_raw)?;
    validate_token_operator(&key, operator)?;
    let value = parse_value(value_raw)?;

    Ok(RuleToken {
        key,
        operator,
        value,
    })
}

fn split_key_operator_value(clause: &str) -> Result<(&str, &str, &str), RuleError> {
    let mut in_quote = false;
    let mut escaped = false;
    let bytes = clause.as_bytes();

    for i in 0..bytes.len() {
        let c = bytes[i] as char;
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            continue;
        }

        for op in ["==", "!=", ":=", "+=", "-=", "="] {
            if clause[i..].starts_with(op) {
                let key = clause[..i].trim();
                let value = clause[i + op.len()..].trim();

                if key.is_empty() {
                    return Err(RuleError::MalformedKey(clause.trim().to_string()));
                }
                if value.is_empty() {
                    return Err(RuleError::MissingValue(clause.trim().to_string()));
                }

                return Ok((key, op, value));
            }
        }
    }

    Err(RuleError::MissingOperator(clause.trim().to_string()))
}

fn parse_key(raw: &str) -> Result<RuleKey, RuleError> {
    let (base, scope) = parse_scoped_key(raw)?;

    match (base, scope) {
        ("ACTION", None) => Ok(RuleKey::Action),
        ("DEVPATH", None) => Ok(RuleKey::Devpath),
        ("KERNEL", None) => Ok(RuleKey::Kernel),
        ("NAME", None) => Ok(RuleKey::Name),
        ("SYMLINK", None) => Ok(RuleKey::Symlink),
        ("SUBSYSTEM", None) => Ok(RuleKey::Subsystem),
        ("DRIVER", None) => Ok(RuleKey::Driver),
        ("ATTR", Some(attr)) => Ok(RuleKey::Attr(attr.to_string())),
        ("SYSCTL", Some(key)) => Ok(RuleKey::Sysctl(key.to_string())),
        ("ENV", Some(key)) => Ok(RuleKey::Env(key.to_string())),
        ("TAG", None) => Ok(RuleKey::Tag),
        ("PROGRAM", None) => Ok(RuleKey::Program),
        ("RESULT", None) => Ok(RuleKey::Result),
        ("IMPORT", scope) => Ok(RuleKey::Import(scope.map(str::to_string))),
        ("TEST", scope) => Ok(RuleKey::Test(scope.map(str::to_string))),
        ("OWNER", None) => Ok(RuleKey::Owner),
        ("GROUP", None) => Ok(RuleKey::Group),
        ("MODE", None) => Ok(RuleKey::Mode),
        ("RUN", scope) => Ok(RuleKey::Run(scope.map(str::to_string))),
        ("LABEL", None) => Ok(RuleKey::Label),
        ("GOTO", None) => Ok(RuleKey::Goto),
        ("OPTIONS", None) => Ok(RuleKey::Options),
        (name, _) => Err(RuleError::UnknownToken(name.to_string())),
    }
}

fn parse_scoped_key(raw: &str) -> Result<(&str, Option<&str>), RuleError> {
    let key = raw.trim();
    if let Some(open) = key.find('{') {
        if !key.ends_with('}') || open == 0 || open + 2 > key.len() {
            return Err(RuleError::MalformedKey(key.to_string()));
        }

        let base = &key[..open];
        let scope = &key[open + 1..key.len() - 1];
        if scope.is_empty() {
            return Err(RuleError::MalformedKey(key.to_string()));
        }

        return Ok((base, Some(scope)));
    }

    Ok((key, None))
}

fn validate_token_operator(key: &RuleKey, operator: UdevRuleOperatorType) -> Result<(), RuleError> {
    let is_match_op = matches!(
        operator,
        UdevRuleOperatorType::Match | UdevRuleOperatorType::NoMatch
    );
    let is_assign_op = matches!(
        operator,
        UdevRuleOperatorType::Assign
            | UdevRuleOperatorType::AssignFinal
            | UdevRuleOperatorType::Add
            | UdevRuleOperatorType::Remove
    );

    if (is_match_op && key.supports_match()) || (is_assign_op && key.supports_assign()) {
        return Ok(());
    }

    Err(RuleError::InvalidTokenClass {
        key: key.display_name().to_string(),
        operator,
    })
}

fn parse_value(raw: &str) -> Result<String, RuleError> {
    let value = raw.trim();

    let mut idx = 0;
    let mut seen_i = false;
    let mut seen_e = false;
    let bytes = value.as_bytes();

    while idx < bytes.len() {
        match bytes[idx] as char {
            'i' if !seen_i => {
                seen_i = true;
                idx += 1;
            }
            'e' if !seen_e => {
                seen_e = true;
                idx += 1;
            }
            _ => break,
        }
    }

    if idx < bytes.len() && bytes[idx] == b'"' {
        let mut out = String::new();
        let mut escaped = false;
        idx += 1;

        while idx < bytes.len() {
            let c = bytes[idx] as char;
            idx += 1;

            if escaped {
                out.push(c);
                escaped = false;
                continue;
            }

            if c == '\\' {
                escaped = true;
                continue;
            }

            if c == '"' {
                let trailing = value[idx..].trim();
                if trailing.is_empty() {
                    return Ok(out);
                }
                return Err(RuleError::UnterminatedQuote(value.to_string()));
            }

            out.push(c);
        }

        return Err(RuleError::UnterminatedQuote(value.to_string()));
    }

    Ok(value.to_string())
}

fn split_rule_clauses(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut escaped = false;

    for c in line.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }

        if c == '\\' {
            current.push(c);
            escaped = true;
            continue;
        }

        if c == '"' {
            in_quote = !in_quote;
            current.push(c);
            continue;
        }

        if c == ',' && !in_quote {
            let clause = current.trim();
            if !clause.is_empty() {
                out.push(clause.to_string());
            }
            current.clear();
            continue;
        }

        current.push(c);
    }

    let clause = current.trim();
    if !clause.is_empty() {
        out.push(clause.to_string());
    }

    out
}

fn strip_inline_comment(line: &str) -> &str {
    let mut in_quote = false;
    let mut escaped = false;

    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match c {
            '\\' if in_quote => {
                escaped = true;
            }
            '"' => {
                in_quote = !in_quote;
            }
            '#' if !in_quote => {
                return &line[..i];
            }
            _ => {}
        }
    }

    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/udev-rules.c");
        assert_eq!(SOURCE_LINE_COUNT, 3347);
        assert_eq!(RULES_DIRS[0], "/usr/lib/udev/rules.d");
        assert_eq!(RULES_DIRS[1], "/etc/udev/rules.d");
    }

    #[test]
    fn operator_parsing_matches_c_enum() {
        assert_eq!(parse_operator("==").unwrap(), UdevRuleOperatorType::Match);
        assert_eq!(
            parse_operator(":=").unwrap(),
            UdevRuleOperatorType::AssignFinal
        );
        assert_eq!(parse_operator("-=").unwrap(), UdevRuleOperatorType::Remove);
    }

    #[test]
    fn unknown_operator_is_rejected() {
        assert_eq!(
            parse_operator("?="),
            Err(RuleError::UnknownOperator("?=".into()))
        );
    }

    #[test]
    fn token_classifies_core_keys() {
        assert_eq!(token_class("ACTION").unwrap(), UdevRuleTokenClass::Match);
        assert_eq!(token_class("PROGRAM").unwrap(), UdevRuleTokenClass::Match);
        assert_eq!(token_class("RUN").unwrap(), UdevRuleTokenClass::Assign);
        assert_eq!(token_class("LABEL").unwrap(), UdevRuleTokenClass::Assign);
    }

    #[test]
    fn unknown_token_is_rejected() {
        assert_eq!(
            token_class("BROKEN"),
            Err(RuleError::UnknownToken("BROKEN".into()))
        );
    }

    #[test]
    fn infer_empty_and_plain_match_types() {
        assert_eq!(infer_match_type("").unwrap(), UdevRuleMatchType::Empty);
        assert_eq!(infer_match_type("usb").unwrap(), UdevRuleMatchType::Plain);
    }

    #[test]
    fn infer_glob_match_types() {
        assert_eq!(infer_match_type("sd*").unwrap(), UdevRuleMatchType::Glob);
        assert_eq!(
            infer_match_type("|sd*").unwrap(),
            UdevRuleMatchType::GlobWithEmpty
        );
    }

    #[test]
    fn infer_plain_with_empty_match_type() {
        assert_eq!(
            infer_match_type("|foo").unwrap(),
            UdevRuleMatchType::PlainWithEmpty
        );
    }

    #[test]
    fn parse_line_supports_scoped_keys_and_operators() {
        let tokens = parse_rules_line(
            r#"ACTION==\"add\", ENV{ID_VENDOR}==\"Acme\", ATTR{queue/rotational}=\"0\", TAG+=\"systemd\", RUN{builtin}+=\"builtin:net_id\""#,
        )
        .unwrap();

        assert_eq!(tokens.len(), 5);
        assert_eq!(tokens[0].key, RuleKey::Action);
        assert_eq!(tokens[1].key, RuleKey::Env("ID_VENDOR".to_string()));
        assert_eq!(tokens[2].key, RuleKey::Attr("queue/rotational".to_string()));
        assert_eq!(tokens[3].operator, UdevRuleOperatorType::Add);
        assert_eq!(tokens[4].key, RuleKey::Run(Some("builtin".to_string())));
    }

    #[test]
    fn parse_line_handles_import_test_and_directives() {
        let tokens = parse_rules_line(
            r#"TEST{mode}==\"0400\", IMPORT{program}=\"/usr/bin/helper\", LABEL=\"rule_end\", GOTO=\"rule_end\", OPTIONS+=\"string_escape=replace\""#,
        )
        .unwrap();

        assert_eq!(tokens[0].key, RuleKey::Test(Some("mode".to_string())));
        assert_eq!(tokens[1].key, RuleKey::Import(Some("program".to_string())));
        assert_eq!(tokens[2].key, RuleKey::Label);
        assert_eq!(tokens[3].key, RuleKey::Goto);
        assert_eq!(tokens[4].key, RuleKey::Options);
    }

    #[test]
    fn parse_text_handles_comments_blank_lines_and_continuations() {
        let text = r#"
# comment only
ACTION==\"add\", DEVPATH==\"/devices/*\", \
    SUBSYSTEM==\"block\"

KERNEL==\"sd*\", MODE:=\"0644\" # trailing comment
"#;

        let parsed = parse_rules_text(text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].len(), 3);
        assert_eq!(parsed[1].len(), 2);
        assert_eq!(parsed[1][1].operator, UdevRuleOperatorType::AssignFinal);
    }

    #[test]
    fn parse_value_supports_prefix_and_quotes() {
        let token = parse_rules_line(r#"ENV{X}==i"Value With Space""#).unwrap();
        assert_eq!(token[0].value, "Value With Space");

        let token = parse_rules_line(r#"PROGRAM==ei"/usr/bin/probe --fast""#).unwrap();
        assert_eq!(token[0].value, "/usr/bin/probe --fast");

        let token = parse_rules_line(r#"RESULT=="""#).unwrap();
        assert_eq!(token[0].value, "");
    }

    #[test]
    fn parse_rejects_invalid_key_form() {
        let err = parse_rules_line(r#"ATTR{}==\"x\""#).unwrap_err();
        assert!(matches!(err, RuleError::MalformedKey(_)));
    }

    #[test]
    fn parse_rejects_invalid_operator_for_key_class() {
        let err = parse_rules_line(r#"PROGRAM=\"/bin/true\""#).unwrap_err();
        assert!(matches!(err, RuleError::InvalidTokenClass { .. }));

        let err = parse_rules_line(r#"OWNER==\"root\""#).unwrap_err();
        assert!(matches!(err, RuleError::InvalidTokenClass { .. }));
    }

    #[test]
    fn parse_rejects_unterminated_quote() {
        let err = parse_rules_line(r#"ENV{A}=="broken"#).unwrap_err();
        assert!(matches!(err, RuleError::UnterminatedQuote(_)));
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
