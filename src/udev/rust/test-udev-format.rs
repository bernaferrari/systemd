// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/test-udev-format.c
//
// Rust-side formatter checks mirroring the C tests.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    MissingClosingBrace,
    UnknownPlaceholder,
}
pub type Result<T> = std::result::Result<T, FormatError>;

pub fn format_template(template: &str, lookup: &dyn Fn(&str) -> Option<&str>) -> Result<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or(FormatError::MissingClosingBrace)?;
        let key = &after[..end];
        let value = lookup(key).ok_or(FormatError::UnknownPlaceholder)?;
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn env(key: &str) -> Option<&str> {
        match key {
            "devnode" => Some("/dev/sda"),
            "id" => Some("disk0"),
            _ => None,
        }
    }
    #[test]
    fn expands_single_value() {
        assert_eq!(format_template("${devnode}", &env).unwrap(), "/dev/sda");
    }
    #[test]
    fn expands_multiple_values() {
        assert_eq!(
            format_template("${id}:${devnode}", &env).unwrap(),
            "disk0:/dev/sda"
        );
    }
    #[test]
    fn leaves_plain_text() {
        assert_eq!(format_template("plain", &env).unwrap(), "plain");
    }
    #[test]
    fn rejects_unknown_placeholder() {
        assert_eq!(
            format_template("${missing}", &env),
            Err(FormatError::UnknownPlaceholder)
        );
    }
}
