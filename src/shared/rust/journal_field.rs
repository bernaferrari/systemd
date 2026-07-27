// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c

/// Validate a journal field name using the canonical journal-file rules.
///
/// Field names contain one to 64 ASCII `A-Z`, `0-9`, or `_` bytes, may not
/// begin with a digit, and protected names beginning with `_` are accepted
/// only when the caller opts in.
pub fn journal_field_valid(field: &[u8], allow_protected: bool) -> bool {
    if field.is_empty() || field.len() > 64 {
        return false;
    }

    let first = field[0];
    if first.is_ascii_digit() || (first == b'_' && !allow_protected) {
        return false;
    }

    field
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::journal_field_valid;

    #[test]
    fn accepts_canonical_public_and_protected_names() {
        assert!(journal_field_valid(b"MESSAGE", false));
        assert!(journal_field_valid(b"FIELD_123", false));
        assert!(journal_field_valid(b"_SYSTEMD_UNIT", true));
    }

    #[test]
    fn rejects_protected_names_without_permission() {
        assert!(!journal_field_valid(b"_PID", false));
    }

    #[test]
    fn rejects_invalid_length_and_alphabet() {
        assert!(!journal_field_valid(b"", true));
        assert!(!journal_field_valid(&[b'A'; 65], true));
        assert!(!journal_field_valid(b"1FIELD", true));
        assert!(!journal_field_valid(b"lowercase", true));
        assert!(!journal_field_valid(b"FIELD-NAME", true));
    }
}
