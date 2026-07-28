// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/fuzz-udev-rule-parse-value.c
//
// Safe Rust harness for udev rule value parsing invariants.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedValue<'a> {
    pub value: &'a str,
    pub end_offset: usize,
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseValueError {
    Empty,
    MissingBody,
    UnterminatedQuote,
}

pub type Result<T> = core::result::Result<T, ParseValueError>;

pub fn parse_rule_value(input: &str) -> Result<ParsedValue<'_>> {
    if input.is_empty() {
        return Err(ParseValueError::Empty);
    }

    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return Err(ParseValueError::MissingBody);
    }

    let first = trimmed.as_bytes()[0];
    let (value, case_sensitive, consumed) = if first == b'"' || first == b'\'' {
        let quote = first as char;
        let body = &trimmed[1..];
        match body.find(quote) {
            Some(end) => (&body[..end], true, end + 2),
            None => return Err(ParseValueError::UnterminatedQuote),
        }
    } else {
        let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
        (&trimmed[..end], !trimmed.starts_with('i'), end)
    };

    if value.is_empty() {
        return Err(ParseValueError::MissingBody);
    }

    Ok(ParsedValue {
        value,
        end_offset: input.len() - trimmed.len() + consumed,
        case_sensitive,
    })
}

pub fn fuzz_one_input(data: &[u8]) -> Result<ParsedValue<'_>> {
    let text = core::str::from_utf8(data).unwrap_or("");
    parse_rule_value(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_token() {
        let parsed = parse_rule_value("value next").unwrap();
        assert_eq!(parsed.value, "value");
        assert_eq!(parsed.end_offset, 5);
    }
    #[test]
    fn parses_quoted_token() {
        let parsed = parse_rule_value("\"value\" next").unwrap();
        assert_eq!(parsed.value, "value");
        assert!(parsed.case_sensitive);
    }
    #[test]
    fn rejects_empty() {
        assert_eq!(parse_rule_value(""), Err(ParseValueError::Empty));
    }
    #[test]
    fn rejects_unterminated_quote() {
        assert_eq!(
            parse_rule_value("\"value"),
            Err(ParseValueError::UnterminatedQuote)
        );
    }
}
