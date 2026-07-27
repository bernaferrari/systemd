// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of fuzz-network-parser.c
//
// Safe Rust parser harness for .network snippets.

pub const MAX_FUZZ_INPUT_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAssignment {
    pub section: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MissingSectionHeader,
    MalformedSection,
    MissingKeyValueSeparator,
    EmptyKey,
}

pub fn parse_network_config(input: &str) -> Result<Vec<NetworkAssignment>, ParseError> {
    let mut section: Option<String> = None;
    let mut assignments = Vec::new();

    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') {
            if !line.ends_with(']') || line.len() <= 2 {
                return Err(ParseError::MalformedSection);
            }
            section = Some(line[1..line.len() - 1].trim().to_string());
            continue;
        }

        let current_section = section.as_ref().ok_or(ParseError::MissingSectionHeader)?;
        let (key, value) = line
            .split_once('=')
            .ok_or(ParseError::MissingKeyValueSeparator)?;
        let key = key.trim();
        if key.is_empty() {
            return Err(ParseError::EmptyKey);
        }

        assignments.push(NetworkAssignment {
            section: current_section.clone(),
            key: key.to_string(),
            value: value.trim().to_string(),
        });
    }

    Ok(assignments)
}

pub fn fuzz_network_parser(data: &[u8]) -> Result<Vec<NetworkAssignment>, ParseError> {
    if data.len() > MAX_FUZZ_INPUT_SIZE {
        return Ok(Vec::new());
    }

    let text = String::from_utf8_lossy(data);
    parse_network_config(text.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_network_snippet() {
        let parsed = parse_network_config(
            r#"
[Match]
Name=en*

[Network]
DHCP=yes
"#,
        )
        .expect("must parse");

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].section, "Match");
        assert_eq!(parsed[1].section, "Network");
        assert_eq!(parsed[1].key, "DHCP");
        assert_eq!(parsed[1].value, "yes");
    }

    #[test]
    fn rejects_assignment_without_section() {
        assert_eq!(
            parse_network_config("DHCP=yes"),
            Err(ParseError::MissingSectionHeader)
        );
    }

    #[test]
    fn rejects_malformed_section() {
        assert_eq!(
            parse_network_config("[Network\nDHCP=yes"),
            Err(ParseError::MalformedSection)
        );
    }

    #[test]
    fn fuzz_skips_oversized_input() {
        let input = vec![b'a'; MAX_FUZZ_INPUT_SIZE + 1];
        let parsed = fuzz_network_parser(&input).expect("oversize is skipped");
        assert!(parsed.is_empty());
    }
}
