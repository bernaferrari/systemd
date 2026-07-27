// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/replace-var.c
//
// Generic infrastructure for replacing @FOO@ style variables in strings.

// ── Error type ──────────────────────────────────────────────────────────

/// Errors from variable replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaceVarError {
    /// The lookup callback returned None for a variable.
    LookupFailed(String),
}

impl std::fmt::Display for ReplaceVarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplaceVarError::LookupFailed(var) => write!(f, "lookup failed for variable @{var}@"),
        }
    }
}

impl std::error::Error for ReplaceVarError {}

// ── Internal helpers ────────────────────────────────────────────────────

/// Check if `s` starting at position `pos` has an @VARIABLE@ pattern.
/// Returns Some(variable_name) if found, None otherwise.
fn get_variable(s: &str, pos: usize) -> Option<&str> {
    let bytes = s.as_bytes();
    if pos >= bytes.len() || bytes[pos] != b'@' {
        return None;
    }

    let mut end = pos + 1;
    while end < bytes.len() {
        let c = bytes[end];
        if c.is_ascii_alphabetic() || c == b'_' {
            end += 1;
        } else {
            break;
        }
    }

    if end == pos + 1 || end >= bytes.len() || bytes[end] != b'@' {
        return None;
    }

    Some(&s[pos + 1..end])
}

// ── Public API ──────────────────────────────────────────────────────────

/// Replace @FOO@ style variables in `text` using the `lookup` callback.
///
/// For each `@UPPERCASE_AND_UNDERSCORES@` pattern found in `text`, the
/// `lookup` function is called with the variable name (without the `@`
/// delimiters). If `lookup` returns `Some(replacement)`, the variable is
/// replaced. If it returns `None`, the function returns an error.
pub fn replace_var<F>(text: &str, lookup: F) -> Result<String, ReplaceVarError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut result = String::with_capacity(text.len());
    let mut pos = 0;
    let bytes = text.as_bytes();

    while pos < bytes.len() {
        let at_at = bytes[pos] == b'@'
            && pos + 1 < bytes.len()
            && bytes[pos + 1] == b'@'
            && (pos == 0 || bytes[pos - 1] != b'@')
            && (pos + 2 >= bytes.len() || bytes[pos + 2] != b'@');
        if at_at {
            return Err(ReplaceVarError::LookupFailed(String::new()));
        }

        if let Some(var_name) = get_variable(text, pos) {
            let skip = var_name.len() + 2;

            match lookup(var_name) {
                Some(replacement) => {
                    result.push_str(&replacement);
                    pos += skip;
                }
                None => {
                    return Err(ReplaceVarError::LookupFailed(var_name.to_string()));
                }
            }
        } else {
            result.push(bytes[pos] as char);
            pos += 1;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_lookup(name: &str) -> Option<String> {
        match name {
            "HOME" => Some("/home/user".to_string()),
            "USER" => Some("testuser".to_string()),
            "PATH" => Some("/usr/bin".to_string()),
            "EMPTY" => Some(String::new()),
            "HOST" => Some("localhost".to_string()),
            _ => None,
        }
    }

    fn echo_lookup(name: &str) -> Option<String> {
        Some(name.to_string())
    }

    #[test]
    fn test_no_variables() {
        assert_eq!(
            replace_var("hello world", simple_lookup).unwrap(),
            "hello world"
        );
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(replace_var("", simple_lookup).unwrap(), "");
    }

    #[test]
    fn test_single_variable() {
        assert_eq!(replace_var("@HOME@", simple_lookup).unwrap(), "/home/user");
    }

    #[test]
    fn test_multiple_variables() {
        assert_eq!(
            replace_var("@USER@:@HOME@", simple_lookup).unwrap(),
            "testuser:/home/user"
        );
    }

    #[test]
    fn test_mixed_text_and_variables() {
        assert_eq!(
            replace_var("user=@USER@ home=@HOME@", simple_lookup).unwrap(),
            "user=testuser home=/home/user"
        );
    }

    #[test]
    fn test_unknown_variable_returns_error() {
        let result = replace_var("@UNKNOWN@", simple_lookup);
        assert!(result.is_err());
    }

    #[test]
    fn test_lowercase_not_matched() {
        let result = replace_var("@home@", simple_lookup);
        assert!(result.is_err());
    }

    #[test]
    fn test_unclosed_variable() {
        assert_eq!(replace_var("@HOME", simple_lookup).unwrap(), "@HOME");
    }

    #[test]
    fn test_empty_variable_name() {
        let result = replace_var("@@", simple_lookup);
        assert!(result.is_err());
    }

    #[test]
    fn test_variable_with_underscore() {
        assert_eq!(replace_var("@HOST@", simple_lookup).unwrap(), "localhost");
    }

    #[test]
    fn test_empty_replacement() {
        assert_eq!(
            replace_var("prefix=@EMPTY@=suffix", simple_lookup).unwrap(),
            "prefix==suffix"
        );
    }

    #[test]
    fn test_repeated_variable() {
        assert_eq!(
            replace_var("@USER@ @USER@ @USER@", simple_lookup).unwrap(),
            "testuser testuser testuser"
        );
    }

    #[test]
    fn test_at_signs_only() {
        // No valid @VAR@ patterns (all empty names), so all '@' are literal
        assert_eq!(replace_var("@@@@", simple_lookup).unwrap(), "@@@@");
    }

    #[test]
    fn test_echo_callback() {
        assert_eq!(replace_var("@FOO@ @BAR@", echo_lookup).unwrap(), "FOO BAR");
    }

    #[test]
    fn test_longer_replacement() {
        assert_eq!(replace_var("@PATH@", simple_lookup).unwrap(), "/usr/bin");
    }

    #[test]
    fn test_adjacent_variables() {
        assert_eq!(
            replace_var("@USER@@HOME@", simple_lookup).unwrap(),
            "testuser/home/user"
        );
    }
}
