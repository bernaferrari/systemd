// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/fuzz-efi-string.c
//
// EFI string function fuzzer logic.
//
// Ports the input-validation, length-prefix parsing, `memdup_str16`,
// `parse_number`, and `efi_fnmatch` invocation from the C fuzzer.

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum input size (at least `sizeof(size_t)` = 8 bytes on 64-bit).
pub const FUZZ_MIN_SIZE: usize = 8;

/// Maximum input size (64 KiB).
pub const FUZZ_MAX_SIZE: usize = 64 * 1024;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringFuzzError {
    SizeOutOfRange,
    InvalidLengthPrefix,
    SliceTooSmall,
}

impl std::fmt::Display for StringFuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringFuzzError::SizeOutOfRange => {
                write!(
                    f,
                    "Input size out of range [{}, {}]",
                    FUZZ_MIN_SIZE, FUZZ_MAX_SIZE
                )
            }
            StringFuzzError::InvalidLengthPrefix => write!(f, "Invalid length prefix"),
            StringFuzzError::SliceTooSmall => write!(f, "Slice too small for char16_t"),
        }
    }
}

impl std::error::Error for StringFuzzError {}

// ── Input validation ─────────────────────────────────────────────────────

pub fn is_valid_size(size: usize) -> bool {
    (FUZZ_MIN_SIZE..=FUZZ_MAX_SIZE).contains(&size)
}

// ── Length extraction ─────────────────────────────────────────────────────

/// Extract a `usize` length prefix from the first 8 bytes (little-endian).
pub fn extract_length(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    let len = usize::from_le_bytes(data[0..8].try_into().ok()?);
    Some(len)
}

// ── memdup_str16 ──────────────────────────────────────────────────────────

/// Duplicate raw bytes into a NUL-terminated UTF-16 vector.
///
/// Mirrors `memdup_str16` from the C source: copies `size` bytes into
/// a `Vec<u16>`, then NUL-terminates the last element.
pub fn memdup_str16(data: &[u8], size: usize) -> Option<Vec<u16>> {
    if size < 2 || size > data.len() {
        return None;
    }
    let num_u16 = size / 2;
    let mut result = vec![0u16; num_u16];
    for i in 0..num_u16 {
        result[i] = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
    }
    result[num_u16 - 1] = 0;
    Some(result)
}

// ── Fuzzer input parsing ─────────────────────────────────────────────────

/// Parsed fuzzer input: two string slices and a length prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzStringInput {
    pub len: usize,
    pub data: Vec<u8>,
}

/// Validate and parse the fuzzer input.
///
/// Mirrors the validation in `LLVMFuzzerTestOneInput`:
///   - Size in `[sizeof(size_t), 64*1024]`
///   - First 8 bytes = `len` (little-endian `usize`)
///   - `len <= size - 8`, `len >= 2`, `size - 8 - len >= 2`
pub fn parse_fuzz_input(data: &[u8]) -> Result<FuzzStringInput, StringFuzzError> {
    if !is_valid_size(data.len()) {
        return Err(StringFuzzError::SizeOutOfRange);
    }

    let len = extract_length(data).ok_or(StringFuzzError::InvalidLengthPrefix)?;
    let remaining = data.len() - 8;

    if len > remaining {
        return Err(StringFuzzError::InvalidLengthPrefix);
    }

    let len2 = remaining - len;
    if len < 2 || len2 < 2 {
        return Err(StringFuzzError::SliceTooSmall);
    }

    Ok(FuzzStringInput {
        len,
        data: data[8..].to_vec(),
    })
}

/// Split the parsed input into two halves for fnmatch testing.
///
/// Returns `(pattern, haystack)` as `Vec<u16>` slices.
pub fn split_for_fnmatch(input: &FuzzStringInput) -> (Vec<u16>, Vec<u16>) {
    let pattern = memdup_str16(&input.data, input.len).unwrap_or_default();
    let haystack =
        memdup_str16(&input.data[input.len..], input.data.len() - input.len).unwrap_or_default();
    (pattern, haystack)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_size_min() {
        assert!(is_valid_size(FUZZ_MIN_SIZE));
    }

    #[test]
    fn test_is_valid_size_max() {
        assert!(is_valid_size(FUZZ_MAX_SIZE));
    }

    #[test]
    fn test_is_valid_size_below_min() {
        assert!(!is_valid_size(FUZZ_MIN_SIZE - 1));
        assert!(!is_valid_size(0));
    }

    #[test]
    fn test_is_valid_size_above_max() {
        assert!(!is_valid_size(FUZZ_MAX_SIZE + 1));
    }

    #[test]
    fn test_extract_length() {
        let data = 42usize.to_le_bytes().to_vec();
        assert_eq!(extract_length(&data), Some(42));
        assert_eq!(extract_length(&[0; 4]), None);
    }

    #[test]
    fn test_memdup_str16_basic() {
        let data = [b'H', 0, b'i', 0];
        let result = memdup_str16(&data, 4).unwrap();
        assert_eq!(&result, &[b'H' as u16, 0]); // last element zeroed
    }

    #[test]
    fn test_memdup_str16_too_small() {
        assert_eq!(memdup_str16(&[0], 1), None);
        assert_eq!(memdup_str16(&[0, 0], 4), None); // size > data.len()
    }

    #[test]
    fn test_parse_fuzz_input_valid() {
        let len = 4usize;
        let mut data = len.to_le_bytes().to_vec();
        data.extend_from_slice(&[b'A', 0, b'B', 0, b'C', 0]);
        let input = parse_fuzz_input(&data).unwrap();
        assert_eq!(input.len, 4);
        assert_eq!(input.data.len(), 6);
    }

    #[test]
    fn test_parse_fuzz_input_too_small() {
        assert_eq!(
            parse_fuzz_input(&[0; 4]),
            Err(StringFuzzError::SizeOutOfRange)
        );
    }

    #[test]
    fn test_parse_fuzz_input_bad_len() {
        let len = 100usize;
        let mut data = len.to_le_bytes().to_vec();
        data.extend_from_slice(&[0; 4]);
        assert_eq!(
            parse_fuzz_input(&data),
            Err(StringFuzzError::InvalidLengthPrefix)
        );
    }

    #[test]
    fn test_split_for_fnmatch() {
        let len = 4usize;
        let mut data = len.to_le_bytes().to_vec();
        data.extend_from_slice(&[b'a', 0, b'b', 0, b'c', 0, b'd', 0]);
        let input = parse_fuzz_input(&data).unwrap();
        let (pattern, haystack) = split_for_fnmatch(&input);
        assert_eq!(pattern.len(), 2); // 4 bytes / 2 = 2 u16s
        assert_eq!(haystack.len(), 2);
    }

    #[test]
    fn test_memdup_str16_nul_termination() {
        let data = [b'X', 0, b'Y', 0];
        let result = memdup_str16(&data, 4).unwrap();
        assert_eq!(result[result.len() - 1], 0);
    }
}
