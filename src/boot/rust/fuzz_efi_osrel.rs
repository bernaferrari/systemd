// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/fuzz-efi-osrel.c
//
// OS-release file parser fuzzer logic.
//
// Ports the input validation and `line_get_key_value` iteration from the C
// fuzzer.  The separator handling and key-value extraction are fully
// testable without libFuzzer.

// ── Constants ─────────────────────────────────────────────────────────────

/// Length of the separator field embedded at the start of the fuzz input.
pub const SEP_LEN: usize = 4;

/// Maximum input size for the fuzzer (64 KiB).
pub const FUZZ_MAX_SIZE: usize = 64 * 1024;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from the OS-release fuzzer input validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsrelFuzzError {
    /// Input size is outside the accepted range.
    SizeOutOfRange,
    /// The separator is not NUL-terminated at the expected position.
    BadSeparator,
}

impl std::fmt::Display for OsrelFuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsrelFuzzError::SizeOutOfRange => {
                write!(
                    f,
                    "Input size out of range [{}, {}]",
                    SEP_LEN + 1,
                    FUZZ_MAX_SIZE
                )
            }
            OsrelFuzzError::BadSeparator => write!(f, "Separator not NUL-terminated"),
        }
    }
}

impl std::error::Error for OsrelFuzzError {}

// ── Input validation ─────────────────────────────────────────────────────

/// Validate the fuzzer input.
///
/// Mirrors the checks in `LLVMFuzzerTestOneInput`:
///   - Size must be in `[SEP_LEN+1, 64*1024]`
///   - `data[SEP_LEN]` must be `0` (NUL-terminated separator)
pub fn validate_input(data: &[u8]) -> Result<(), OsrelFuzzError> {
    if data.len() < SEP_LEN + 1 || data.len() > FUZZ_MAX_SIZE {
        return Err(OsrelFuzzError::SizeOutOfRange);
    }
    if data[SEP_LEN] != 0 {
        return Err(OsrelFuzzError::BadSeparator);
    }
    Ok(())
}

/// Extract the separator bytes from the input (first `SEP_LEN` bytes).
pub fn extract_separator(data: &[u8]) -> Option<&[u8]> {
    if data.len() < SEP_LEN + 1 {
        return None;
    }
    Some(&data[..SEP_LEN])
}

/// Extract the content after the separator (from byte `SEP_LEN + 1` onward).
pub fn extract_content(data: &[u8]) -> Option<&[u8]> {
    if data.len() < SEP_LEN + 1 {
        return None;
    }
    Some(&data[SEP_LEN + 1..])
}

// ── Key-value parsing ────────────────────────────────────────────────────

/// A parsed key-value pair from an os-release-like file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

/// Parse all key-value pairs from a NUL-terminated content buffer using
/// the given separator characters.
///
/// Mirrors the loop in `LLVMFuzzerTestOneInput` that repeatedly calls
/// `line_get_key_value`.  This is a simplified but faithful port: it
/// splits lines, trims whitespace, skips comments and empty lines, and
/// splits on the first separator character.
pub fn parse_key_values(content: &[u8], sep: &[u8]) -> Vec<KeyValue> {
    let mut results = Vec::new();
    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return results,
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Find separator
        let sep_pos = trimmed.chars().position(|c| sep.contains(&(c as u8)));

        let (key, value) = match sep_pos {
            Some(pos) => {
                let key = trimmed[..pos].trim();
                let mut value = &trimmed[pos + 1..];
                // Skip additional separator chars
                while !value.is_empty() && sep.contains(&(value.as_bytes()[0])) {
                    value = &value[1..];
                }
                (key, value)
            }
            None => continue,
        };

        if key.is_empty() || value.is_empty() {
            continue;
        }

        // Unquote
        let value = unquote(value);

        results.push(KeyValue {
            key: key.to_string(),
            value,
        });
    }

    results
}

/// Remove surrounding quotes from a value string.
fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        if (first == b'\'' || first == b'"') && bytes[bytes.len() - 1] == first {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

/// Full fuzzer entry-point logic.
///
/// Mirrors `LLVMFuzzerTestOneInput`: validates input, parses key-value
/// pairs.  Returns the parsed pairs, or an error if input is invalid.
pub fn fuzz_efi_osrel(data: &[u8]) -> Result<Vec<KeyValue>, OsrelFuzzError> {
    validate_input(data)?;
    let sep = extract_separator(data).unwrap();
    let content = extract_content(data).unwrap();
    Ok(parse_key_values(content, sep))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_input_valid() {
        let mut data = vec![b'=', b' ', b'=', b' ', 0]; // separator "= =" + NUL
        data.extend_from_slice(b"KEY=value\n");
        assert!(validate_input(&data).is_ok());
    }

    #[test]
    fn test_validate_input_too_small() {
        assert_eq!(validate_input(&[0; 4]), Err(OsrelFuzzError::SizeOutOfRange));
        assert_eq!(validate_input(&[0; 3]), Err(OsrelFuzzError::SizeOutOfRange));
    }

    #[test]
    fn test_validate_input_too_large() {
        let data = vec![0u8; FUZZ_MAX_SIZE + 1];
        assert_eq!(validate_input(&data), Err(OsrelFuzzError::SizeOutOfRange));
    }

    #[test]
    fn test_validate_input_bad_separator() {
        let data = vec![b'=', b' ', b'=', b'X', b'Z', b'K', b'=', b'v'];
        assert_eq!(validate_input(&data), Err(OsrelFuzzError::BadSeparator));
    }

    #[test]
    fn test_extract_separator() {
        let data: Vec<u8> = vec![b'=', b' ', b':', b'\t', 0, b'x'];
        let sep = extract_separator(&data).unwrap();
        assert_eq!(sep, b"= :\t");
    }

    #[test]
    fn test_extract_content() {
        let data: Vec<u8> = vec![b'=', 0, 0, 0, 0, b'K', b'=', b'V'];
        let content = extract_content(&data).unwrap();
        assert_eq!(content, b"K=V");
    }

    #[test]
    fn test_parse_key_values_basic() {
        let content = b"NAME=TestOS\nVERSION=1.0\n";
        let pairs = parse_key_values(content, b"=");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].key, "NAME");
        assert_eq!(pairs[0].value, "TestOS");
        assert_eq!(pairs[1].key, "VERSION");
        assert_eq!(pairs[1].value, "1.0");
    }

    #[test]
    fn test_parse_key_values_quoted() {
        let content = b"NAME=\"Test OS\"\n";
        let pairs = parse_key_values(content, b"=");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].value, "Test OS");
    }

    #[test]
    fn test_parse_key_values_comment() {
        let content = b"# comment\nKEY=val\n";
        let pairs = parse_key_values(content, b"=");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].key, "KEY");
    }

    #[test]
    fn test_fuzz_efi_osrel_full() {
        let mut data = vec![b'=', 0, 0, 0, 0]; // 4-byte sep + NUL
        data.extend_from_slice(b"ID=test\nVERSION=2.0\n");
        let pairs = fuzz_efi_osrel(&data).unwrap();
        assert_eq!(pairs.len(), 2);
    }
}
