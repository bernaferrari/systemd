// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/qrcode-util.c, src/shared/qrcode-util.h
//
// QR code generation and terminal rendering utilities.
//
// PORT-GAP: C's `HAVE_QRENCODE` configuration gate and its `FILE*` terminal
// cursor/locale/color integration are not yet represented by this generic
// `Write` API. The C implementation remains authoritative for those paths.
// This module keeps the optional-library boundary aligned with C and exposes
// only owned QR matrices to safe Rust.

use std::ffi::{CString, c_char};
use std::fmt;
use std::io::{self, Write};
use std::ptr::NonNull;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::ffi::Errno;
use systemd_basic_rs::dlfcn_util::{PublishedDlopenHandle, UnpublishedDlopenHandle};

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
            // `dlopen_many_sym_or_warn()` normalizes an unavailable optional
            // dependency to EOPNOTSUPP and a missing required ABI to ELIBBAD.
            QrCodeError::DlopenFailed(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            QrCodeError::SymbolNotFound(_) => Errno::ELIBBAD.to_neg_errno(),
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

/// C's static loader cache is success-only. Serialize Rust's equivalent
/// check/open/publish sequence so concurrent callers cannot retain multiple
/// permanent references while racing through the initial load.
static QRENCODE_LOAD_LOCK: Mutex<Option<QrencodeApi>> = Mutex::new(None);

/// libqrencode's largest standard QR matrix is version 40 (177 × 177).
/// Refusing a wider foreign result avoids creating an unchecked slice from
/// malformed or ABI-incompatible library data.
const MAX_QR_WIDTH: usize = 177;

type QrCodeEncodeString = unsafe extern "C" fn(*const c_char, i32, i32, i32, i32) -> *mut QRcode;
type QrCodeFree = unsafe extern "C" fn(*mut QRcode);

/// Fully validated libqrencode entry points plus their process-lifetime
/// loader reference. Function pointers are copied only after `dlsym()` has
/// verified the exact symbol names from `qrcode-util.c`.
#[derive(Clone, Copy)]
struct QrencodeApi {
    _library: PublishedDlopenHandle,
    encode_string: QrCodeEncodeString,
    free: QrCodeFree,
}

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
/// This function is idempotent after the first success. Failures are retried,
/// matching C's success-only `qrcode_dl` cache: an optional library that
/// becomes available later may still be loaded.
pub fn dlopen_qrencode() -> Result<(), QrCodeError> {
    if QRENCODE_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let mut api = QRENCODE_LOAD_LOCK
        .lock()
        // A prior panic cannot invalidate a published process-lifetime
        // loader reference, so recover the guard instead of pinning an
        // unrelated historical panic to future load attempts.
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if api.is_some() {
        QRENCODE_LOADED.store(true, Ordering::Release);
        return Ok(());
    }

    // C returns the outcome of the final candidate. Preserve that distinction:
    // an absent .3 is optional-dependency failure, while an ABI-incomplete .3
    // is ELIBBAD even if an earlier candidate failed differently.
    let mut last_error = QrCodeError::Unsupported;

    for lib in LIBQRENCODE_CANDIDATES {
        match QrencodeApi::load(lib) {
            Ok(loaded) => {
                *api = Some(loaded);
                QRENCODE_LOADED.store(true, Ordering::Release);
                return Ok(());
            }
            Err(e) => {
                last_error = e;
            }
        }
    }

    Err(last_error)
}

impl QrencodeApi {
    /// Load one C-authoritative candidate and resolve its complete ABI.
    fn load(lib_name: &str) -> Result<Self, QrCodeError> {
        // `dlopen_qrencode()` uses `dlopen_many_sym_or_warn()`, hence the
        // shared `dlopen_safe()` policy (static builds, block_dlopen(),
        // RTLD_NOW, and RTLD_NODELETE) is part of its contract. Do not use a
        // local RTLD_LAZY | RTLD_LOCAL implementation here.
        let handle = UnpublishedDlopenHandle::open(lib_name)
            .map_err(|error| QrCodeError::DlopenFailed(error.to_string()))?;
        let encode_string = handle
            .resolve_required(SYMBOL_QRCODE_ENCODE_STRING)
            .map_err(|error| QrCodeError::SymbolNotFound(error.to_string()))?;
        let free = handle
            .resolve_required(SYMBOL_QRCODE_FREE)
            .map_err(|error| QrCodeError::SymbolNotFound(error.to_string()))?;

        // SAFETY: `qrcode-util.c` declares these exact libqrencode symbols
        // with the signatures below. `resolve_required()` obtained each from
        // the validated live handle, which is retained for process lifetime.
        let encode_string = unsafe {
            std::mem::transmute::<*mut std::ffi::c_void, QrCodeEncodeString>(encode_string.as_ptr())
        };
        // SAFETY: as above, `QRcode_free`'s ABI is declared by qrencode.h and
        // the live handle is retained by the returned API object.
        let free =
            unsafe { std::mem::transmute::<*mut std::ffi::c_void, QrCodeFree>(free.as_ptr()) };

        Ok(Self {
            _library: handle.publish(),
            encode_string,
            free,
        })
    }
}

/// Returns `true` if `dlopen_qrencode()` has been called successfully.
pub fn qrencode_is_loaded() -> bool {
    QRENCODE_LOADED.load(Ordering::Acquire)
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

    let api = QRENCODE_LOAD_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .copied()
        .ok_or_else(|| {
            QrCodeError::DlopenFailed(
                "loader completed without publishing a libqrencode API".to_string(),
            )
        })?;

    // QRcode_encodeString(string, version, ecLevel, mode, case_sensitive)
    // SAFETY: `api.encode_string` was resolved from qrencode.h's exact ABI;
    // `c_string` is NUL-terminated and stays live for this call.
    let qr = unsafe {
        (api.encode_string)(
            c_string.as_ptr(),
            0,            // version: auto
            QR_ECLEVEL_L, // error correction level L
            QR_MODE_8,    // 8-bit byte mode
            1,            // case sensitive
        )
    };

    let qr = QrCodeAllocation::new(qr, api.free).ok_or_else(|| {
        QrCodeError::EncodeFailed("QRcode_encodeString returned NULL".to_string())
    })?;
    qr.copy_matrix()
}

/// Owns a non-null `QRcode*` until its matching libqrencode destructor runs.
struct QrCodeAllocation {
    pointer: NonNull<QRcode>,
    free: QrCodeFree,
}

impl QrCodeAllocation {
    fn new(pointer: *mut QRcode, free: QrCodeFree) -> Option<Self> {
        NonNull::new(pointer).map(|pointer| Self { pointer, free })
    }

    /// Copy the foreign matrix after validating its documented QR bounds.
    fn copy_matrix(&self) -> Result<QrCodeMatrix, QrCodeError> {
        // SAFETY: `pointer` is non-null and is owned by this allocation until
        // Drop invokes libqrencode's matching `QRcode_free` function.
        let qr = unsafe { self.pointer.as_ref() };
        let width = usize::try_from(qr.width).map_err(|_| {
            QrCodeError::EncodeFailed("libqrencode returned a negative matrix width".to_string())
        })?;
        if !(1..=MAX_QR_WIDTH).contains(&width) {
            return Err(QrCodeError::EncodeFailed(format!(
                "libqrencode returned unsupported matrix width {width}"
            )));
        }
        let len = width.checked_mul(width).ok_or_else(|| {
            QrCodeError::EncodeFailed("QR matrix dimensions overflowed".to_string())
        })?;
        let data = NonNull::new(qr.data).ok_or_else(|| {
            QrCodeError::EncodeFailed("libqrencode returned a null matrix".to_string())
        })?;

        // qrencode.h specifies `width * width` matrix bytes for a successful
        // `QRcode_encodeString` result. The positive standard-QR width bound
        // above prevents overflow; this allocation stays owned by `self`.
        // SAFETY: the documented matrix remains valid until `self` is dropped.
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr(), len) };
        Ok(QrCodeMatrix {
            width,
            data: bytes.iter().map(|byte| byte & 1 != 0).collect(),
        })
    }
}

impl Drop for QrCodeAllocation {
    fn drop(&mut self) {
        // SAFETY: this allocation owns one successful `QRcode_encodeString`
        // result, and `free` was resolved from the same retained libqrencode
        // ABI. It is called exactly once when the wrapper is dropped.
        unsafe { (self.free)(self.pointer.as_ptr()) };
    }
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

        let val: i32 = QrCodeError::DlopenFailed("x".into()).into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());

        let val: i32 = QrCodeError::SymbolNotFound("x".into()).into();
        assert_eq!(val, Errno::ELIBBAD.to_neg_errno());

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
}
