// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/fuzz-udev-rules.c
//
// Safe Rust harness for udev rule parsing smoke coverage.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLine {
    pub key: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleParseError {
    InvalidUtf8,
    MissingOperator,
    MissingKey,
    MissingValue,
}

pub type Result<T> = std::result::Result<T, RuleParseError>;

pub fn parse_rule_line(data: &[u8]) -> Result<RuleLine> {
    let line = std::str::from_utf8(data)
        .map_err(|_| RuleParseError::InvalidUtf8)?
        .trim();
    let operators = ["==", "!=", "=", "+=", ":="];
    let (operator, index) = operators
        .iter()
        .find_map(|op| line.find(op).map(|idx| (*op, idx)))
        .ok_or(RuleParseError::MissingOperator)?;

    let key = line[..index].trim();
    let value_raw = line[index + operator.len()..].trim().replace("\\\"", "\"");
    let value = value_raw.trim_matches('"');
    if key.is_empty() {
        return Err(RuleParseError::MissingKey);
    }
    if value.is_empty() {
        return Err(RuleParseError::MissingValue);
    }
    Ok(RuleLine {
        key: key.to_string(),
        operator: operator.to_string(),
        value: value.to_string(),
    })
}

pub fn fuzz_rules(data: &[u8]) -> Result<RuleLine> {
    parse_rule_line(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_match_rule() {
        let line = parse_rule_line(br#"ACTION==\"add\""#).unwrap();
        assert_eq!(line.key, "ACTION");
        assert_eq!(line.value, "add");
    }
    #[test]
    fn parses_assignment_rule() {
        let line = parse_rule_line(br#"ENV{ID}=\"1\""#).unwrap();
        assert_eq!(line.operator, "=");
    }
    #[test]
    fn rejects_missing_operator() {
        assert_eq!(
            parse_rule_line(b"ACTION"),
            Err(RuleParseError::MissingOperator)
        );
    }
    #[test]
    fn rejects_missing_value() {
        assert_eq!(
            parse_rule_line(b"ACTION=="),
            Err(RuleParseError::MissingValue)
        );
    }
}
