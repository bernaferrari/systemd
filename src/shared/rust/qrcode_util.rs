// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/qrcode-util.c, src/shared/qrcode-util.h
//
// QR code generation and terminal rendering utilities.
//
// Provides dynamic loading of libqrencode via dlopen, QR code encoding
// from strings, and Unicode-based terminal rendering using half-block
// characters for compact display. The module gracefully degrades when
// libqrencode is not available.

use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by QR code operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrCodeError {
    /// libqrencode is not available on this system.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// The input string could not be encoded (e.g. too long for QR capacity).
    EncodeFailed(String),
    /// Not a UTF-8 locale, QR code printing not possible.
    NotUtf8Locale,
    /// ANSI colors are disabled, QR code printing not possible.
    ColorsDisabled,
    /// Terminal too small for QR code rendering.
    TerminalTooSmall,
}

impl fmt::Display for QrCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(
                f,
                "QR code support is not compiled in or libqrencode not available"
            ),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libqrencode: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libqrencode symbol not found: {}", sym)
            }
            Self::EncodeFailed(msg) => write!(f, "Failed to encode QR code: {}", msg),
            Self::NotUtf8Locale => write!(f, "Not a UTF-8 system, cannot print QR code"),
            Self::ColorsDisabled => write!(f, "Colors are disabled, cannot print QR code"),
            Self::TerminalTooSmall => write!(f, "Terminal too small for QR code rendering"),
        }
    }
}

impl std::error::Error for QrCodeError {}

impl From<QrCodeError> for i32 {
    fn from(e: QrCodeError) -> i32 {
        match e {
            QrCodeError::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            QrCodeError::DlopenFailed(_) => Errno::ENOENT.to_neg_errno(),
            QrCodeError::SymbolNotFound(_) => Errno::ENOENT.to_neg_errno(),
            QrCodeError::EncodeFailed(_) => Errno::ENOMEM.to_neg_errno(),
            QrCodeError::NotUtf8Locale => Errno::EOPNOTSUPP.to_neg_errno(),
            QrCodeError::ColorsDisabled => Errno::EOPNOTSUPP.to_neg_errno(),
            QrCodeError::TerminalTooSmall => Errno::EOPNOTSUPP.to_neg_errno(),
        }
    }
}

// ── Library name constants ──────────────────────────────────────────────────

/// Shared library names to try, in preference order.
const LIBQRENCODE_CANDIDATES: &[&str] = &["libqrencode.so.4", "libqrencode.so.3"];

/// Human-readable description for the ELF NOTE metadata.
const QRENCODE_FEATURE_DESCRIPTION: &str = "Support for generating QR codes";

// ── Required symbol names ───────────────────────────────────────────────────

const SYMBOL_QRCODE_ENCODE_STRING: &str = "QRcode_encodeString";
const SYMBOL_QRCODE_FREE: &str = "QRcode_free";

// ── QRcode structure (mirrors libqrencode's QRcode) ─────────────────────────

/// Mirrors the `QRcode` struct from `<qrencode.h>`.
///
/// Only the fields we actually read are included.
#[repr(C)]
struct QRcode {
    version: i32,
    width: i32,
    data: *mut u8,
}

// ── QR encoding constants (from qrencode.h) ────────────────────────────────

/// Error correction level: Low (~7% recovery).
const QR_ECLEVEL_L: i32 = 0;

/// Encoding mode: 8-bit byte data.
const QR_MODE_8: i32 = 3;

// ── ANSI / Unicode constants ────────────────────────────────────────────────

/// ANSI escape sequence: white text on black background, bold.
const ANSI_WHITE_ON_BLACK: &str = "\x1b[40;37;1m";

/// ANSI escape sequence: reset all attributes.
const ANSI_NORMAL: &str = "\x1b[0m";

/// Unicode full block character.
const UNICODE_FULL_BLOCK: &str = "\u{2588}";

/// Unicode lower half block character.
const UNICODE_LOWER_HALF_BLOCK: &str = "\u{2584}";

/// Unicode upper half block character.
const UNICODE_UPPER_HALF_BLOCK: &str = "\u{2580}";

/// Border padding width (in character cells) on each side.
const BORDER_WIDTH: usize = 4;

/// Sentinel value for "no position specified" (matches C's UINT_MAX).
const NO_POSITION: u32 = u32::MAX;

// ── Dlopen state ────────────────────────────────────────────────────────────

/// Global flag: has `dlopen_qrencode()` been called and completed?
static QRENCODE_LOADED: AtomicBool = AtomicBool::new(false);

// ── QR code data wrapper ────────────────────────────────────────────────────

/// A decoded QR code matrix.
///
/// Owns the pixel data as a 2D grid of booleans. The data is extracted
/// from the libqrencode `QRcode` structure and converted to safe Rust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrCodeMatrix {
    /// Width of the QR code (number of modules per side).
    pub width: usize,
    /// Pixel data: `true` = black module, `false` = white module.
    /// Row-major, `data[y * width + x]`.
    pub data: Vec<bool>,
}

impl QrCodeMatrix {
    /// Get the module value at (x, y). Returns `false` for out-of-bounds.
    pub fn get(&self, x: usize, y: usize) -> bool {
        if x < self.width && y < self.width {
            self.data[y * self.width + x]
        } else {
            false
        }
    }

    /// Returns the total number of modules.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the QR code has zero dimensions.
    pub fn is_empty(&self) -> bool {
        self.width == 0
    }
}

// ── Dynamic loading ─────────────────────────────────────────────────────────

/// Dynamically load libqrencode and resolve required symbols.
///
/// This function is idempotent: after the first successful call it returns
/// `Ok(())` immediately. If the library cannot be found the error is
/// cached so subsequent calls return `Err` without retrying.
pub fn dlopen_qrencode() -> Result<(), QrCodeError> {
    if QRENCODE_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let mut last_err = String::new();

    for lib in LIBQRENCODE_CANDIDATES.iter() {
        match try_load_qrencode(lib) {
            Ok(()) => {
                QRENCODE_LOADED.store(true, Ordering::Release);
                return Ok(());
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }

    Err(QrCodeError::DlopenFailed(last_err))
}

/// Try to open a single libqrencode candidate and resolve all required symbols.
fn try_load_qrencode(lib_name: &str) -> Result<(), QrCodeError> {
    let handle = unsafe { dlopen_wrapper(lib_name) }?;

    let symbols_to_check = [
        (SYMBOL_QRCODE_ENCODE_STRING, "QRcode_encodeString"),
        (SYMBOL_QRCODE_FREE, "QRcode_free"),
    ];

    for (sym_name, sym_display) in &symbols_to_check {
        let c_sym = CString::new(*sym_name).unwrap_or_default();
        let ptr = unsafe { dlsym_wrapper(handle, &c_sym) };
        if ptr.is_null() {
            return Err(QrCodeError::SymbolNotFound((*sym_display).to_string()));
        }
    }

    // Intentionally keep handle open for the process lifetime.
    let _ = handle;

    Ok(())
}

/// Open a shared library, returning the handle on success.
///
/// Wraps `dlopen()` with `RTLD_LAZY | RTLD_LOCAL`.
unsafe fn dlopen_wrapper(lib_name: &str) -> Result<*mut c_void, QrCodeError> {
    let c_name = CString::new(lib_name)
        .map_err(|e| QrCodeError::DlopenFailed(format!("Invalid library name: {}", e)))?;
    // SAFETY: c_name is NUL-terminated and remains live for the call.
    let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let detail = dlerror_string();
        Err(QrCodeError::DlopenFailed(format!(
            "{}: {}",
            lib_name, detail
        )))
    } else {
        Ok(handle)
    }
}

/// Look up a symbol in an already-opened library handle.
///
/// # Safety
/// `handle` must be a valid handle returned by `dlopen`.
unsafe fn dlsym_wrapper(handle: *mut c_void, symbol: &CStr) -> *mut c_void {
    // SAFETY: the caller supplies a live dlopen handle and symbol is NUL-terminated.
    unsafe { libc::dlsym(handle, symbol.as_ptr()) }
}

/// Retrieve the last `dlerror()` message as a Rust `String`.
fn dlerror_string() -> String {
    unsafe {
        let ptr = libc::dlerror();
        if ptr.is_null() {
            return "unknown error".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

/// Returns `true` if `dlopen_qrencode()` has been called successfully.
pub fn qrencode_is_loaded() -> bool {
    QRENCODE_LOADED.load(Ordering::Acquire)
}

/// Reset the loaded state. Useful for tests.
#[cfg(test)]
pub fn reset_qrencode_loaded() {
    QRENCODE_LOADED.store(false, Ordering::Release);
}

// ── QR code encoding ────────────────────────────────────────────────────────

/// Encode a string into a QR code matrix using libqrencode.
///
/// This function dynamically loads libqrencode (if not already loaded),
/// encodes the string at error correction level L with 8-bit byte mode,
/// and returns the resulting QR code data as a safe Rust structure.
pub fn qr_code_from_string(string: &str) -> Result<QrCodeMatrix, QrCodeError> {
    dlopen_qrencode()?;

    let c_string = CString::new(string)
        .map_err(|e| QrCodeError::EncodeFailed(format!("Invalid input string: {}", e)))?;

    // Load the symbol for QRcode_encodeString
    let c_sym = CString::new(SYMBOL_QRCODE_ENCODE_STRING).unwrap();
    let handle = find_loaded_handle();
    let encode_fn = unsafe {
        let ptr = dlsym_wrapper(handle, &c_sym);
        if ptr.is_null() {
            return Err(QrCodeError::SymbolNotFound(
                SYMBOL_QRCODE_ENCODE_STRING.to_string(),
            ));
        }
        std::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(*const libc::c_char, i32, i32, i32, i32) -> *mut QRcode,
        >(ptr)
    };

    let c_free_sym = CString::new(SYMBOL_QRCODE_FREE).unwrap();
    let free_fn = unsafe {
        let ptr = dlsym_wrapper(handle, &c_free_sym);
        if ptr.is_null() {
            return Err(QrCodeError::SymbolNotFound(SYMBOL_QRCODE_FREE.to_string()));
        }
        std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut QRcode)>(ptr)
    };

    // QRcode_encodeString(string, version, ecLevel, mode, case_sensitive)
    let qr = unsafe {
        encode_fn(
            c_string.as_ptr(),
            0,            // version: auto
            QR_ECLEVEL_L, // error correction level L
            QR_MODE_8,    // 8-bit byte mode
            1,            // case sensitive
        )
    };

    if qr.is_null() {
        return Err(QrCodeError::EncodeFailed(
            "QRcode_encodeString returned NULL".to_string(),
        ));
    }

    let width = unsafe { (*qr).width } as usize;
    let data_ptr = unsafe { (*qr).data };

    // Extract pixel data into a safe Vec<bool>
    let mut data = Vec::with_capacity(width * width);
    for i in 0..(width * width) {
        let byte = unsafe { *data_ptr.add(i) };
        data.push((byte & 1) != 0);
    }

    // Free the QRcode via libqrencode's free function
    unsafe {
        free_fn(qr);
    }

    Ok(QrCodeMatrix { width, data })
}

/// Find a previously loaded libqrencode handle by re-opening with the same flags.
///
/// This is necessary because we don't store the handle globally. Instead, we
/// re-dlopen (which returns the same handle if already loaded).
fn find_loaded_handle() -> *mut c_void {
    for lib in LIBQRENCODE_CANDIDATES {
        let c_name = match CString::new(*lib) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // SAFETY: c_name is NUL-terminated and remains live for the call.
        let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
        if !handle.is_null() {
            return handle;
        }
    }
    std::ptr::null_mut()
}

// ── Terminal rendering ──────────────────────────────────────────────────────

/// Render a QR code border line (4 rows using Unicode full blocks).
fn render_border<W: Write>(out: &mut W, qr_width: usize) -> io::Result<()> {
    let total_width = BORDER_WIDTH + qr_width + BORDER_WIDTH;
    for _ in 0..2 {
        write!(out, "{}", ANSI_WHITE_ON_BLACK)?;
        for _ in 0..total_width {
            write!(out, "{}", UNICODE_FULL_BLOCK)?;
        }
        writeln!(out, "{}", ANSI_NORMAL)?;
    }
    Ok(())
}

/// Render a single pair of QR code rows using Unicode half-block characters.
///
/// Each terminal character cell is roughly twice as tall as it is wide,
/// so we render two QR code rows per terminal row: the upper half-block
/// shows the top row's modules, and the lower half shows the bottom row's.
fn render_qr_row<W: Write>(out: &mut W, matrix: &QrCodeMatrix, y: usize) -> io::Result<()> {
    write!(out, "{}", ANSI_WHITE_ON_BLACK)?;

    // Left border
    for _ in 0..BORDER_WIDTH {
        write!(out, "{}", UNICODE_FULL_BLOCK)?;
    }

    // QR code pixels for this pair of rows
    for x in 0..matrix.width {
        let a = matrix.get(x, y);
        let b = matrix.get(x, y + 1);

        match (a, b) {
            (true, true) => write!(out, " ")?, // both black → space (transparent)
            (true, false) => write!(out, "{}", UNICODE_LOWER_HALF_BLOCK)?,
            (false, true) => write!(out, "{}", UNICODE_UPPER_HALF_BLOCK)?,
            (false, false) => write!(out, "{}", UNICODE_FULL_BLOCK)?,
        }
    }

    // Right border
    for _ in 0..BORDER_WIDTH {
        write!(out, "{}", UNICODE_FULL_BLOCK)?;
    }

    writeln!(out, "{}", ANSI_NORMAL)?;
    Ok(())
}

/// Write a QR code to the given output stream.
///
/// Renders the QR code matrix using Unicode half-block characters with
/// ANSI-colored borders, producing a compact visual representation
/// suitable for terminal display.
pub fn write_qrcode<W: Write>(out: &mut W, matrix: &QrCodeMatrix) -> io::Result<()> {
    render_border(out, matrix.width)?;

    for y in (0..matrix.width).step_by(2) {
        render_qr_row(out, matrix, y)?;
    }

    render_border(out, matrix.width)?;
    out.flush()?;
    Ok(())
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Print a QR code encoding `string` to `out`.
///
/// This is the Rust equivalent of `print_qrcode()` from the C API.
/// It encodes the string, then renders the QR code with a header if provided.
///
/// # Errors
///
/// Returns an error if:
/// - libqrencode cannot be loaded
/// - The string cannot be encoded
/// - An I/O error occurs during writing
pub fn print_qrcode<W: Write>(
    out: &mut W,
    header: Option<&str>,
    string: &str,
) -> Result<(), QrCodeError> {
    print_qrcode_full(
        out,
        header,
        string,
        NO_POSITION,
        NO_POSITION,
        NO_POSITION,
        NO_POSITION,
        false,
    )
}

/// Print a QR code with full positioning control.
///
/// This is the Rust equivalent of `print_qrcode_full()` from the C API.
/// When `row` and `column` are `NO_POSITION`, the QR code is printed at
/// the current cursor position. Otherwise, it is positioned at the
/// specified terminal coordinates.
///
/// # Errors
///
/// Returns an error if:
/// - libqrencode cannot be loaded
/// - The string cannot be encoded
/// - An I/O error occurs during writing
pub fn print_qrcode_full<W: Write>(
    out: &mut W,
    header: Option<&str>,
    string: &str,
    row: u32,
    column: u32,
    tty_width: u32,
    tty_height: u32,
    check_tty: bool,
) -> Result<(), QrCodeError> {
    let matrix = qr_code_from_string(string)?;

    // Validate terminal size when check_tty is requested
    if check_tty {
        let required_width = (matrix.width + 2 * BORDER_WIDTH) as u32;
        let required_height = (matrix.width + 2 * BORDER_WIDTH) as u32;
        if tty_width != NO_POSITION && tty_width < required_width {
            return Err(QrCodeError::TerminalTooSmall);
        }
        if tty_height != NO_POSITION && tty_height < required_height / 2 {
            return Err(QrCodeError::TerminalTooSmall);
        }
    }

    // Print header
    if let Some(hdr) = header {
        if row != NO_POSITION && column != NO_POSITION {
            writeln!(out, "{}:\n", hdr)
                .map_err(|e| QrCodeError::EncodeFailed(format!("Failed to write header: {}", e)))?;
        } else {
            writeln!(out, "\n{}:\n", hdr)
                .map_err(|e| QrCodeError::EncodeFailed(format!("Failed to write header: {}", e)))?;
        }
    }

    write_qrcode(out, &matrix)
        .map_err(|e| QrCodeError::EncodeFailed(format!("Failed to write QR code: {}", e)))?;

    write!(out, "\n").map_err(|e| {
        QrCodeError::EncodeFailed(format!("Failed to write trailing newline: {}", e))
    })?;

    Ok(())
}

// ── Query helpers ───────────────────────────────────────────────────────────

/// Returns the human-readable description of the QR code feature.
pub fn qrencode_feature_description() -> &'static str {
    QRENCODE_FEATURE_DESCRIPTION
}

/// Returns the list of candidate library names tried during loading.
pub fn qrencode_library_candidates() -> &'static [&'static str] {
    LIBQRENCODE_CANDIDATES
}

/// Compute the rendered width (in terminal columns) for a QR code matrix.
pub fn qr_rendered_width(matrix: &QrCodeMatrix) -> usize {
    matrix.width + 2 * BORDER_WIDTH
}

/// Compute the rendered height (in terminal rows) for a QR code matrix.
///
/// Each pair of QR rows maps to one terminal row, plus 4 border rows
/// (2 top + 2 bottom).
pub fn qr_rendered_height(matrix: &QrCodeMatrix) -> usize {
    let data_rows = (matrix.width + 1) / 2;
    data_rows + 4 // 2 top border + 2 bottom border
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_code_error_display_unsupported() {
        let e = QrCodeError::Unsupported;
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn test_qr_code_error_display_dlopen_failed() {
        let e = QrCodeError::DlopenFailed("lib missing".to_string());
        assert!(e.to_string().contains("lib missing"));
    }

    #[test]
    fn test_qr_code_error_display_symbol_not_found() {
        let e = QrCodeError::SymbolNotFound("QRcode_encodeString".to_string());
        assert!(e.to_string().contains("QRcode_encodeString"));
    }

    #[test]
    fn test_qr_code_error_display_encode_failed() {
        let e = QrCodeError::EncodeFailed("input too long".to_string());
        assert!(e.to_string().contains("input too long"));
    }

    #[test]
    fn test_qr_code_error_display_not_utf8() {
        let e = QrCodeError::NotUtf8Locale;
        assert!(e.to_string().contains("UTF-8"));
    }

    #[test]
    fn test_qr_code_error_display_colors_disabled() {
        let e = QrCodeError::ColorsDisabled;
        assert!(e.to_string().contains("Colors are disabled"));
    }

    #[test]
    fn test_qr_code_error_display_terminal_too_small() {
        let e = QrCodeError::TerminalTooSmall;
        assert!(e.to_string().contains("Terminal too small"));
    }

    #[test]
    fn test_qr_code_error_into_c_int() {
        let val: i32 = QrCodeError::Unsupported.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());

        let val: i32 = QrCodeError::EncodeFailed("x".into()).into();
        assert_eq!(val, Errno::ENOMEM.to_neg_errno());

        let val: i32 = QrCodeError::NotUtf8Locale.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());

        let val: i32 = QrCodeError::TerminalTooSmall.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_qr_code_error_equality() {
        assert_eq!(QrCodeError::Unsupported, QrCodeError::Unsupported);
        assert_eq!(
            QrCodeError::DlopenFailed("a".into()),
            QrCodeError::DlopenFailed("a".into())
        );
        assert_ne!(
            QrCodeError::DlopenFailed("a".into()),
            QrCodeError::DlopenFailed("b".into())
        );
        assert_ne!(QrCodeError::Unsupported, QrCodeError::ColorsDisabled);
    }

    #[test]
    fn test_qr_code_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(QrCodeError::Unsupported);
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn test_qr_matrix_get_within_bounds() {
        let matrix = QrCodeMatrix {
            width: 3,
            data: vec![true, false, true, false, true, false, true, false, true],
        };
        assert!(matrix.get(0, 0));
        assert!(!matrix.get(1, 0));
        assert!(matrix.get(2, 0));
        assert!(!matrix.get(0, 1));
        assert!(matrix.get(1, 1));
        assert!(!matrix.get(2, 1));
    }

    #[test]
    fn test_qr_matrix_get_out_of_bounds() {
        let matrix = QrCodeMatrix {
            width: 2,
            data: vec![true, false, false, true],
        };
        assert!(!matrix.get(2, 0)); // x out of bounds
        assert!(!matrix.get(0, 2)); // y out of bounds
        assert!(!matrix.get(5, 5)); // both out of bounds
    }

    #[test]
    fn test_qr_matrix_len_and_empty() {
        let empty = QrCodeMatrix {
            width: 0,
            data: vec![],
        };
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let matrix = QrCodeMatrix {
            width: 5,
            data: vec![false; 25],
        };
        assert!(!matrix.is_empty());
        assert_eq!(matrix.len(), 25);
    }

    #[test]
    fn test_qr_rendered_dimensions() {
        let matrix = QrCodeMatrix {
            width: 21,
            data: vec![false; 21 * 21],
        };
        assert_eq!(qr_rendered_width(&matrix), 21 + 8);
        // 21 rows → 11 terminal rows + 4 border rows = 15
        assert_eq!(qr_rendered_height(&matrix), (21 + 1) / 2 + 4);
    }

    #[test]
    fn test_qr_rendered_dimensions_small() {
        let matrix = QrCodeMatrix {
            width: 1,
            data: vec![true],
        };
        assert_eq!(qr_rendered_width(&matrix), 1 + 8);
        // 1 row → 1 terminal row + 4 border rows = 5
        assert_eq!(qr_rendered_height(&matrix), (1 + 1) / 2 + 4);
    }

    #[test]
    fn test_qrencode_feature_description() {
        let desc = qrencode_feature_description();
        assert!(!desc.is_empty());
        assert!(desc.contains("QR"));
    }

    #[test]
    fn test_qrencode_library_candidates() {
        let candidates = qrencode_library_candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], "libqrencode.so.4");
        assert_eq!(candidates[1], "libqrencode.so.3");
    }

    #[test]
    fn test_qrencode_is_loaded_initial() {
        reset_qrencode_loaded();
        assert!(!qrencode_is_loaded());
    }

    #[test]
    fn test_write_qrcode_small_matrix() {
        let matrix = QrCodeMatrix {
            width: 3,
            data: vec![true, false, true, false, true, false, true, false, true],
        };
        let mut output = Vec::new();
        write_qrcode(&mut output, &matrix).unwrap();

        let text = String::from_utf8(output).unwrap();
        // Should contain ANSI escapes and Unicode block characters
        assert!(text.contains(ANSI_WHITE_ON_BLACK));
        assert!(text.contains(UNICODE_FULL_BLOCK));
        assert!(text.contains(UNICODE_LOWER_HALF_BLOCK));
        assert!(text.contains(UNICODE_UPPER_HALF_BLOCK));
    }

    #[test]
    fn test_write_qrcode_single_row_matrix() {
        let matrix = QrCodeMatrix {
            width: 1,
            data: vec![true],
        };
        let mut output = Vec::new();
        write_qrcode(&mut output, &matrix).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(UNICODE_LOWER_HALF_BLOCK));
        assert!(text.contains(UNICODE_FULL_BLOCK));
    }

    #[test]
    fn test_render_border_output() {
        let mut output = Vec::new();
        render_border(&mut output, 5).unwrap();
        let text = String::from_utf8(output).unwrap();

        // Each border line: 4 + 5 + 4 = 13 full blocks + ANSI + newline
        assert!(text.contains(ANSI_WHITE_ON_BLACK));
        assert!(text.contains(ANSI_NORMAL));
    }

    #[test]
    fn test_constants_are_valid() {
        // Ensure ANSI sequences are well-formed
        assert!(ANSI_WHITE_ON_BLACK.starts_with("\x1b["));
        assert!(ANSI_NORMAL.starts_with("\x1b["));

        // Ensure Unicode characters are the expected ones
        assert_eq!(UNICODE_FULL_BLOCK, "\u{2588}");
        assert_eq!(UNICODE_LOWER_HALF_BLOCK, "\u{2584}");
        assert_eq!(UNICODE_UPPER_HALF_BLOCK, "\u{2580}");

        // Border width
        assert_eq!(BORDER_WIDTH, 4);

        // No position sentinel
        assert_eq!(NO_POSITION, u32::MAX);

        // QR encoding constants
        assert_eq!(QR_ECLEVEL_L, 0);
        assert_eq!(QR_MODE_8, 3);
    }

    #[test]
    fn test_dlerror_string_returns_string() {
        // Just ensure it doesn't panic and returns something
        let s = dlerror_string();
        assert!(!s.is_empty());
    }
}
