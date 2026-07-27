// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of fuzz-netdev-parser.c
//
// Safe Rust parser harness for .netdev snippets.

pub const MAX_FUZZ_INPUT_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetDevAssignment {
    pub section: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MissingSectionHeader,
    MissingKeyValueSeparator,
    EmptyKey,
    MissingNetDevSection,
}

pub fn parse_netdev_config(input: &str) -> Result<Vec<NetDevAssignment>, ParseError> {
    let mut section: Option<String> = None;
    let mut assignments = Vec::new();
    let mut has_netdev_section = false;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') && line.len() > 2 {
            let next = line[1..line.len() - 1].trim().to_string();
            if next == "NetDev" {
                has_netdev_section = true;
            }
            section = Some(next);
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

        assignments.push(NetDevAssignment {
            section: current_section.clone(),
            key: key.to_string(),
            value: value.trim().to_string(),
        });
    }

    if !has_netdev_section {
        return Err(ParseError::MissingNetDevSection);
    }

    Ok(assignments)
}

pub fn fuzz_netdev_parser(data: &[u8]) -> Result<Vec<NetDevAssignment>, ParseError> {
    if data.len() > MAX_FUZZ_INPUT_SIZE {
        return Ok(Vec::new());
    }

    let text = String::from_utf8_lossy(data);
    parse_netdev_config(text.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_netdev_snippet() {
        let parsed = parse_netdev_config(
            r#"
[NetDev]
Name=vlan10
Kind=vlan
"#,
        )
        .expect("must parse");

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].section, "NetDev");
        assert_eq!(parsed[0].key, "Name");
        assert_eq!(parsed[1].value, "vlan");
    }

    #[test]
    fn rejects_without_netdev_section() {
        assert_eq!(
            parse_netdev_config("[Match]\nName=eth0"),
            Err(ParseError::MissingNetDevSection)
        );
    }

    #[test]
    fn rejects_assignment_without_section() {
        assert_eq!(
            parse_netdev_config("Kind=bridge"),
            Err(ParseError::MissingSectionHeader)
        );
    }

    #[test]
    fn fuzz_skips_oversized_input() {
        let input = vec![b'a'; MAX_FUZZ_INPUT_SIZE + 1];
        let parsed = fuzz_netdev_parser(&input).expect("oversize is skipped");
        assert!(parsed.is_empty());
    }
}
