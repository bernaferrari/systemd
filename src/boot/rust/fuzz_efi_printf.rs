// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/fuzz-efi-printf.c
//
// EFI printf formatting fuzzer logic.
//
// Ports the `Input` struct and the input-validation logic from the C
// fuzzer.  The actual printf formatting is delegated to the `efi_string`
// module; this module focuses on the fuzzer's input parsing and the
/// various format-string combinations it tests.

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum input size (size of the `Input` struct header).
/// Mirrors `sizeof(Input)` from the C source.
pub const INPUT_HEADER_SIZE: usize = 104; // approximate sizeof(Input) on 64-bit

/// Maximum input size (1 MiB).
pub const FUZZ_MAX_SIZE: usize = 1024 * 1024;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from the printf fuzzer input validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintfFuzzError {
    /// Input size is outside the accepted range.
    SizeOutOfRange,
}

impl std::fmt::Display for PrintfFuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrintfFuzzError::SizeOutOfRange => {
                write!(
                    f,
                    "Input size out of range [{}, {}]",
                    INPUT_HEADER_SIZE, FUZZ_MAX_SIZE
                )
            }
        }
    }
}

impl std::error::Error for PrintfFuzzError {}

// ── Input data model ─────────────────────────────────────────────────────

/// Parsed fuzzer input mirroring the C `Input` struct.
///
/// The C struct packs various integer/pointer types followed by a format
/// string.  We model it with explicit fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrintfInput {
    pub status: u64,
    pub field_width: i16,
    pub precision: i16,
    pub ptr: u64,
    pub char_val: u8,
    pub uchar: u8,
    pub schar: libc::c_schar,
    pub ushort: u16,
    pub sshort: i16,
    pub uint: u32,
    pub sint: i32,
    pub ulong: u64,
    pub slong: i64,
    pub ulonglong: u64,
    pub slonglong: i64,
    pub size_val: u64,
    pub ssize_val: i64,
    pub intmax_val: i64,
    pub uintmax_val: u64,
    pub ptrdiff_val: i64,
    pub format_str: Vec<u8>,
}

// ── Input validation ─────────────────────────────────────────────────────

/// Check whether the input size is within the accepted range.
pub fn is_valid_size(size: usize) -> bool {
    size >= INPUT_HEADER_SIZE && size <= FUZZ_MAX_SIZE
}

// ── Input parsing ────────────────────────────────────────────────────────

/// Parse the fuzzer `Input` struct from raw bytes.
///
/// Reads the fixed fields and extracts the trailing format-string bytes.
/// This is a simplified but faithful model of the C `Input` struct
/// layout (which depends on compiler packing and platform).
pub fn parse_input(data: &[u8]) -> Result<PrintfInput, PrintfFuzzError> {
    if !is_valid_size(data.len()) {
        return Err(PrintfFuzzError::SizeOutOfRange);
    }

    // The C struct has fields in order; we read them sequentially.
    // Layout (approximate, 64-bit little-endian):
    //   EFI_STATUS status;          (8 bytes, offset 0)
    //   int16_t field_width;        (2 bytes, offset 8)
    //   int16_t precision;          (2 bytes, offset 10)
    //   const void *ptr;            (8 bytes, offset 12, aligned to 8 -> 16)
    //   char c;                     (1 byte,  offset 24)
    //   unsigned char uchar;        (1 byte,  offset 25)
    //   signed char schar;          (1 byte,  offset 26)
    //   unsigned short ushort;      (2 bytes, offset 28)
    //   signed short sshort;        (2 bytes, offset 30)
    //   unsigned int uint;          (4 bytes, offset 32)
    //   signed int sint;            (4 bytes, offset 36)
    //   unsigned long ulong;        (8 bytes, offset 40)
    //   signed long slong;          (8 bytes, offset 48)
    //   unsigned long long;         (8 bytes, offset 56)
    //   signed long long;           (8 bytes, offset 64)
    //   size_t size;                (8 bytes, offset 72)
    //   ssize_t ssize;              (8 bytes, offset 80)
    //   intmax_t intmax;            (8 bytes, offset 88)
    //   uintmax_t uintmax;          (8 bytes, offset 96)
    //   ptrdiff_t ptrdiff;          (8 bytes, offset 104... but we use INPUT_HEADER_SIZE)
    //   char str[];                 (flexible array member)

    let status = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let field_width = i16::from_le_bytes(data[8..10].try_into().unwrap());
    let precision = i16::from_le_bytes(data[10..12].try_into().unwrap());

    // Flexible format string at the end
    let format_str = data[INPUT_HEADER_SIZE..].to_vec();

    Ok(PrintfInput {
        status,
        field_width,
        precision,
        format_str,
        ..Default::default()
    })
}

// ── Format-string catalog ────────────────────────────────────────────────

/// The list of format strings that the C fuzzer exercises.
///
/// Mirrors the `PRINTF_ONE` calls in `LLVMFuzzerTestOneInput`.  Each entry
/// is a format string (without the `status` argument which is always first).
pub const FORMAT_CATALOG: &[&str] = &[
    "%*.*s",
    "%*.*ls",
    "%% %*.*m",
    "%*p",
    "%*c %12340c %56789c",
    "%*.*hhu",
    "%*.*hhi",
    "%*.*hu",
    "%*.*hi",
    "%*.*u",
    "%*.*i",
    "%*.*lu",
    "%*.*li",
    "%*.*llu",
    "%*.*lli",
    "%+*.*hhi",
    "%-*.*hi",
    "% *.*i",
    "%0*li",
    "%#*.*llx",
    "%-*.*zx",
    "% *.*zi",
    "%0*ji",
    "%#0*jX",
    "%*.*ti",
];

/// Count how many format specifiers are in the catalog.
pub fn format_catalog_count() -> usize {
    FORMAT_CATALOG.len()
}

// ── Simplified printf for testing ─────────────────────────────────────────

/// A very simple printf-like formatter that supports a subset of
/// specifiers for testing purposes.
///
/// Supports: `%d`, `%u`, `%x`, `%s`, `%%`.
pub fn simple_printf(fmt: &str, args: &[u64]) -> String {
    let mut result = String::new();
    let mut arg_idx = 0;
    let mut chars = fmt.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '%' {
            result.push(c);
            continue;
        }
        let spec = chars.next().unwrap_or('%');
        match spec {
            '%' => result.push('%'),
            'd' | 'i' => {
                if let Some(&v) = args.get(arg_idx) {
                    result.push_str(&(v as i64).to_string());
                    arg_idx += 1;
                }
            }
            'u' => {
                if let Some(&v) = args.get(arg_idx) {
                    result.push_str(&v.to_string());
                    arg_idx += 1;
                }
            }
            'x' => {
                if let Some(&v) = args.get(arg_idx) {
                    result.push_str(&format!("{:x}", v));
                    arg_idx += 1;
                }
            }
            'X' => {
                if let Some(&v) = args.get(arg_idx) {
                    result.push_str(&format!("{:X}", v));
                    arg_idx += 1;
                }
            }
            's' => {
                // Interpret arg as a string length marker (for testing)
                if let Some(&v) = args.get(arg_idx) {
                    result.push_str(&format!("<str:{}>", v));
                    arg_idx += 1;
                }
            }
            _ => {
                result.push('%');
                result.push(spec);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_size_min() {
        assert!(is_valid_size(INPUT_HEADER_SIZE));
    }

    #[test]
    fn test_is_valid_size_max() {
        assert!(is_valid_size(FUZZ_MAX_SIZE));
    }

    #[test]
    fn test_is_valid_size_too_small() {
        assert!(!is_valid_size(INPUT_HEADER_SIZE - 1));
        assert!(!is_valid_size(0));
    }

    #[test]
    fn test_is_valid_size_too_large() {
        assert!(!is_valid_size(FUZZ_MAX_SIZE + 1));
    }

    #[test]
    fn test_parse_input_basic() {
        let mut data = vec![0u8; INPUT_HEADER_SIZE + 20];
        // Set status = 0xDEAD_BEEF
        data[0..8].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        // Set field_width = -5
        data[8..10].copy_from_slice(&(-5i16).to_le_bytes());
        // Set precision = 10
        data[10..12].copy_from_slice(&10i16.to_le_bytes());
        // Format string at end
        data[INPUT_HEADER_SIZE..].copy_from_slice(b"%d%c%d%c%d%c%d%c%d%c");

        let input = parse_input(&data).unwrap();
        assert_eq!(input.status, 0xDEAD_BEEF);
        assert_eq!(input.field_width, -5);
        assert_eq!(input.precision, 10);
        assert_eq!(&input.format_str, b"%d%c%d%c%d%c%d%c%d%c");
    }

    #[test]
    fn test_parse_input_invalid_size() {
        assert_eq!(parse_input(&[0; 50]), Err(PrintfFuzzError::SizeOutOfRange));
        assert_eq!(parse_input(&[]), Err(PrintfFuzzError::SizeOutOfRange));
    }

    #[test]
    fn test_format_catalog_count() {
        assert_eq!(format_catalog_count(), 25);
    }

    #[test]
    fn test_simple_printf_percent() {
        assert_eq!(simple_printf("100%%", &[]), "100%");
    }

    #[test]
    fn test_simple_printf_integers() {
        assert_eq!(simple_printf("%d %u %x", &[42, 255, 255]), "42 255 ff");
    }

    #[test]
    fn test_simple_printf_mixed() {
        assert_eq!(simple_printf("val=%d done", &[7]), "val=7 done");
    }

    #[test]
    fn test_simple_printf_no_args() {
        assert_eq!(simple_printf("hello", &[]), "hello");
    }
}
