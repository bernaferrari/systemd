// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pam-util.c, src/shared/pam-util.h
//
// PAM (Pluggable Authentication Modules) utility functions.
//
// Provides error conversion, format-string substitution, item/data batch
// access helpers, cleanup callbacks, conversation prompting, and bus-cache
// management for PAM modules.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::c_void;

// ── PAM Error ───────────────────────────────────────────────────────────

/// PAM result/error codes corresponding to `<security/pam_modules.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamError {
    Success,
    OpenErr,
    SymbolErr,
    ServiceErr,
    SystemErr,
    BufErr,
    ConvErr,
    PermDenied,
    MaxTries,
    AuthErr,
    CredInsufficient,
    AuthinfoUnavail,
    UserUnknown,
    AuthtokErr,
    AuthtokRecoveryErr,
    AuthtokLockBusy,
    AuthtokDisableAging,
    NoModuleData,
    Ignore,
    Abort,
    TryAgain,
    ModuleUnknown,
    BadItem,
    /// Unrecognised PAM status code.
    Unknown(i32),
}

impl PamError {
    /// Integer PAM status code for each variant.
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::OpenErr => 1,
            Self::SymbolErr => 2,
            Self::ServiceErr => 3,
            Self::SystemErr => 4,
            Self::BufErr => 5,
            Self::ConvErr => 6,
            Self::PermDenied => 7,
            Self::MaxTries => 8,
            Self::AuthErr => 9,
            Self::CredInsufficient => 10,
            Self::AuthinfoUnavail => 11,
            Self::UserUnknown => 12,
            Self::AuthtokErr => 13,
            Self::AuthtokRecoveryErr => 14,
            Self::AuthtokLockBusy => 15,
            Self::AuthtokDisableAging => 16,
            Self::NoModuleData => 17,
            Self::Ignore => 25,
            Self::Abort => 26,
            Self::TryAgain => 27,
            Self::ModuleUnknown => 28,
            Self::BadItem => 29,
            Self::Unknown(c) => c,
        }
    }

    /// Parse an integer PAM status code.
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::OpenErr,
            2 => Self::SymbolErr,
            3 => Self::ServiceErr,
            4 => Self::SystemErr,
            5 => Self::BufErr,
            6 => Self::ConvErr,
            7 => Self::PermDenied,
            8 => Self::MaxTries,
            9 => Self::AuthErr,
            10 => Self::CredInsufficient,
            11 => Self::AuthinfoUnavail,
            12 => Self::UserUnknown,
            13 => Self::AuthtokErr,
            14 => Self::AuthtokRecoveryErr,
            15 => Self::AuthtokLockBusy,
            16 => Self::AuthtokDisableAging,
            17 => Self::NoModuleData,
            25 => Self::Ignore,
            26 => Self::Abort,
            27 => Self::TryAgain,
            28 => Self::ModuleUnknown,
            29 => Self::BadItem,
            c => Self::Unknown(c),
        }
    }

    /// `true` for transient errors that may succeed on retry.
    pub const fn is_transient(self) -> bool {
        matches!(
            self,
            Self::AuthErr
                | Self::AuthtokErr
                | Self::AuthtokRecoveryErr
                | Self::AuthtokLockBusy
                | Self::MaxTries
                | Self::TryAgain
                | Self::BufErr
        )
    }

    /// `true` if this is [`Success`].
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

impl From<i32> for PamError {
    fn from(code: i32) -> Self {
        Self::from_code(code)
    }
}

impl From<PamError> for i32 {
    fn from(err: PamError) -> Self {
        err.code()
    }
}

impl std::fmt::Display for PamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::OpenErr => write!(f, "Failed to load module"),
            Self::SymbolErr => write!(f, "Symbol not found"),
            Self::ServiceErr => write!(f, "Error in service module"),
            Self::SystemErr => write!(f, "System error"),
            Self::BufErr => write!(f, "Memory buffer error"),
            Self::ConvErr => write!(f, "Conversation error"),
            Self::PermDenied => write!(f, "Permission denied"),
            Self::MaxTries => write!(f, "Maximum tries exceeded"),
            Self::AuthErr => write!(f, "Authentication error"),
            Self::CredInsufficient => write!(f, "Insufficient credentials"),
            Self::AuthinfoUnavail => write!(f, "Authentication info unavailable"),
            Self::UserUnknown => write!(f, "Unknown user"),
            Self::AuthtokErr => write!(f, "Authentication token error"),
            Self::AuthtokRecoveryErr => write!(f, "Authentication token recovery error"),
            Self::AuthtokLockBusy => write!(f, "Authentication token lock busy"),
            Self::AuthtokDisableAging => write!(f, "Authentication token aging disabled"),
            Self::NoModuleData => write!(f, "No module data"),
            Self::Ignore => write!(f, "Ignore"),
            Self::Abort => write!(f, "Abort"),
            Self::TryAgain => write!(f, "Try again"),
            Self::ModuleUnknown => write!(f, "Unknown module"),
            Self::BadItem => write!(f, "Bad item"),
            Self::Unknown(c) => write!(f, "Unknown PAM error ({c})"),
        }
    }
}

impl std::error::Error for PamError {}

/// Convenience alias for results carrying a [`PamError`].
pub type PamResult<T> = Result<T, PamError>;

// ── PAM Item Types ──────────────────────────────────────────────────────

/// PAM item types for `pam_get_item` / `pam_set_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamItemType {
    Service,     // PAM_SERVICE  = 1
    User,        // PAM_USER     = 2
    Tty,         // PAM_TTY      = 3
    Rhost,       // PAM_RHOST    = 4
    Conv,        // PAM_CONV     = 5
    Authtok,     // PAM_AUTHTOK  = 6
    OldAuthtok,  // PAM_OLDAUTHTOK = 7
    Ruser,       // PAM_RUSER    = 8
    UserPrompt,  // PAM_USER_PROMPT = 9
    FailDelay,   // PAM_FAIL_DELAY = 10
    XDisplay,    // PAM_XDISPLAY = 11
    XAuthData,   // PAM_XAUTHDATA = 12
    AuthtokType, // PAM_AUTHTOK_TYPE = 13
    Other(i32),
}

impl PamItemType {
    pub const fn code(self) -> i32 {
        match self {
            Self::Service => 1,
            Self::User => 2,
            Self::Tty => 3,
            Self::Rhost => 4,
            Self::Conv => 5,
            Self::Authtok => 6,
            Self::OldAuthtok => 7,
            Self::Ruser => 8,
            Self::UserPrompt => 9,
            Self::FailDelay => 10,
            Self::XDisplay => 11,
            Self::XAuthData => 12,
            Self::AuthtokType => 13,
            Self::Other(c) => c,
        }
    }

    pub fn from_code(code: i32) -> Self {
        match code {
            1 => Self::Service,
            2 => Self::User,
            3 => Self::Tty,
            4 => Self::Rhost,
            5 => Self::Conv,
            6 => Self::Authtok,
            7 => Self::OldAuthtok,
            8 => Self::Ruser,
            9 => Self::UserPrompt,
            10 => Self::FailDelay,
            11 => Self::XDisplay,
            12 => Self::XAuthData,
            13 => Self::AuthtokType,
            c => Self::Other(c),
        }
    }
}

// ── PAM Prompt Styles ───────────────────────────────────────────────────

/// PAM conversation message styles (`pam_message.msg_style`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamPromptStyle {
    EchoOff,  // PAM_PROMPT_ECHO_OFF = 1
    EchoOn,   // PAM_PROMPT_ECHO_ON  = 2
    ErrorMsg, // PAM_ERROR_MSG        = 3
    TextInfo, // PAM_TEXT_INFO        = 4
    Other(i32),
}

impl PamPromptStyle {
    pub const fn code(self) -> i32 {
        match self {
            Self::EchoOff => 1,
            Self::EchoOn => 2,
            Self::ErrorMsg => 3,
            Self::TextInfo => 4,
            Self::Other(c) => c,
        }
    }

    pub fn from_code(code: i32) -> Self {
        match code {
            1 => Self::EchoOff,
            2 => Self::EchoOn,
            3 => Self::ErrorMsg,
            4 => Self::TextInfo,
            c => Self::Other(c),
        }
    }
}

// ── PAM Data Flags ──────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags passed to PAM data cleanup callbacks.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PamDataFlags: u32 {
        /// Indicates cleanup is running in a forked child (`PAM_DATA_SILENT`).
        const SILENT = 0x4000_0000;
    }
}

// ── errno → PAM Error Conversion ────────────────────────────────────────

/// Linux `ENOMEM` errno value.
const ENOMEM: i32 = 12;

/// Convert an errno value to a [`PamError`].
///
/// Follows the systemd convention where negative return values encode
/// `-errno`.  `ENOMEM` maps to [`BufErr`](PamError::BufErr); everything
/// else maps to [`ServiceErr`](PamError::ServiceErr).
///
/// Mirrors `errno_to_pam_error()` in *pam-util.c*.
pub fn errno_to_pam_error(errno: i32) -> PamError {
    if errno == ENOMEM || errno == -ENOMEM {
        PamError::BufErr
    } else {
        PamError::ServiceErr
    }
}

// ── @PAMERR@ Substitution ───────────────────────────────────────────────

/// Replace a trailing `@PAMERR@` in `format_str` with `pam_error_desc`.
///
/// If `pam_error_desc` contains `%` characters it is replaced with `"n/a"`
/// to prevent format-string injection when the result is later passed to a
/// `printf`-style function.
///
/// Returns a new [`String`].  If no `@PAMERR@` suffix is present the
/// original string is returned unchanged (cloned).
///
/// Mirrors the substitution logic inside `pam_syslog_pam_error()`.
pub fn pam_substitute_err(format_str: &str, pam_error_desc: &str) -> String {
    if let Some(prefix) = format_str.strip_suffix("@PAMERR@") {
        let safe = if pam_error_desc.contains('%') {
            "n/a"
        } else {
            pam_error_desc
        };
        format!("{prefix}{safe}")
    } else {
        format_str.to_owned()
    }
}

// ── Item / Data Batch Requests ──────────────────────────────────────────

/// Descriptor for a single PAM item to retrieve in batch.
///
/// Used with [`pam_get_item_many`] to collect multiple items in one pass.
/// Mirrors the variadic `pam_get_item_many_internal()` in C.
#[derive(Debug, Clone)]
pub struct PamItemRequest {
    /// The PAM item type to query.
    pub item_type: PamItemType,
    /// Set to `true` when the item was found in the PAM handle.
    pub found: bool,
    /// Opaque value pointer returned by PAM (valid only when `found` is true).
    pub value: Option<usize>,
}

impl PamItemRequest {
    /// Create a new item request for the given type.
    pub const fn new(item_type: PamItemType) -> Self {
        Self {
            item_type,
            found: false,
            value: None,
        }
    }
}

/// Descriptor for a single named PAM data entry to retrieve in batch.
///
/// Used with [`pam_get_data_many`] to collect multiple data entries in one
/// pass.  Mirrors the variadic `pam_get_data_many_internal()` in C.
#[derive(Debug, Clone)]
pub struct PamDataRequest<'a> {
    /// The PAM data key name.
    pub name: &'a str,
    /// Set to `true` when the entry was found in the PAM handle.
    pub found: bool,
    /// Opaque value pointer returned by PAM (valid only when `found` is true).
    pub value: Option<usize>,
}

impl<'a> PamDataRequest<'a> {
    /// Create a new data request for the given key.
    pub const fn new(name: &'a str) -> Self {
        Self {
            name,
            found: false,
            value: None,
        }
    }
}

/// Retrieve multiple PAM items in one pass.
///
/// Each entry in `requests` is updated with `found` / `value` if PAM returns
/// [`Success`](PamError::Success) or [`BadItem`](PamError::BadItem) (missing)
/// for that item.  The first non-recoverable error terminates iteration and
/// is returned.
///
/// The `get_item` closure encapsulates the underlying `pam_get_item()` FFI
/// call so this function itself remains safe.
pub fn pam_get_item_many<F>(requests: &mut [PamItemRequest], get_item: F) -> PamResult<()>
where
    F: Fn(PamItemType) -> PamResult<Option<usize>>,
{
    for req in requests.iter_mut() {
        match get_item(req.item_type) {
            Ok(Some(v)) => {
                req.found = true;
                req.value = Some(v);
            }
            Ok(None) => {
                // Item not set — equivalent to PAM_BAD_ITEM
                req.found = false;
                req.value = None;
            }
            Err(PamError::BadItem) => {
                req.found = false;
                req.value = None;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Retrieve multiple named PAM data entries in one pass.
///
/// Each entry in `requests` is updated with `found` / `value` if PAM returns
/// [`Success`](PamError::Success) or [`NoModuleData`](PamError::NoModuleData)
/// (missing).  The first non-recoverable error terminates iteration and is
/// returned.
///
/// The `get_data` closure encapsulates the underlying `pam_get_data()` FFI
/// call so this function itself remains safe.
pub fn pam_get_data_many<'a, F>(requests: &mut [PamDataRequest<'a>], get_data: F) -> PamResult<()>
where
    F: Fn(&str) -> PamResult<Option<usize>>,
{
    for req in requests.iter_mut() {
        match get_data(req.name) {
            Ok(Some(v)) => {
                req.found = true;
                req.value = Some(v);
            }
            Ok(None) => {
                req.found = false;
                req.value = None;
            }
            Err(PamError::NoModuleData) => {
                req.found = false;
                req.value = None;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ── Cleanup Callbacks ───────────────────────────────────────────────────

/// Free heap memory pointed to by `data`.
///
/// Intended as a destructor for `pam_set_data()`.  Null `data` is a no-op.
///
/// Mirrors `pam_cleanup_free()` in *pam-util.c*.
///
/// # Safety
/// `data` must be null or exclusively own a live allocation created by libc
/// `malloc`/`calloc`/`realloc`. It must not be a Rust allocation, an interior
/// pointer, or be freed by another owner after this callback is registered.
pub unsafe fn cleanup_free(data: *mut c_void) {
    if !data.is_null() {
        // SAFETY: the caller guarantees data was allocated by the libc allocator.
        unsafe_ffi!(libc::free(data));
    }
}

/// Close a file descriptor encoded with the C `FD_TO_PTR()` convention in
/// `data` (the stored pointer value is `fd + 1`, so null represents `-1`).
///
/// If `flags` contains [`SILENT`](PamDataFlags::SILENT) the call is a no-op
/// (we are in a forked child where the fd is likely already closed).
/// Null `data` is also a no-op.
///
/// Mirrors `pam_cleanup_close()` in *pam-util.c*.
///
/// # Safety
/// `data` must be null or a value encoded from a non-negative descriptor with
/// `FD_TO_PTR()`. The callback consumes that descriptor; no other owner may
/// close it after it is registered with PAM.
pub unsafe fn cleanup_close(data: *mut c_void, flags: PamDataFlags) {
    if flags.contains(PamDataFlags::SILENT) {
        return;
    }
    if !data.is_null() {
        let fd = (data as usize)
            .checked_sub(1)
            .and_then(|encoded| i32::try_from(encoded).ok());
        if let Some(fd) = fd.filter(|fd| *fd >= 0) {
            // SAFETY: the caller guarantees data encodes the descriptor owned by this cleanup.
            unsafe_ffi!(libc::close(fd));
        }
    }
}

// ── Conversation Prompt ─────────────────────────────────────────────────

/// Perform a PAM conversation prompt without noisy automatic logging.
///
/// The `converse` closure receives the prompt style and formatted message,
/// and returns the user's response (or a PAM error).  This encapsulates the
/// PAM conversation function so the public API remains safe.
///
/// Mirrors `pam_prompt_graceful()` in *pam-util.c*.
pub fn pam_prompt_graceful<F>(
    style: PamPromptStyle,
    message: &str,
    converse: F,
) -> PamResult<Option<String>>
where
    F: FnOnce(PamPromptStyle, &str) -> PamResult<Option<String>>,
{
    converse(style, message)
}

// ── Bus Cache ID ────────────────────────────────────────────────────────

/// Validate a PAM module name for use as a bus cache key.
///
/// Rejects names containing NUL, which cannot be represented by the C string
/// passed to `pam_make_bus_cache_id()`.
pub fn validate_module_name(name: &str) -> PamResult<&str> {
    if name.contains('\0') {
        return Err(PamError::SystemErr);
    }
    Ok(name)
}

/// Generate a PAM bus data cache identifier.
///
/// Format: `"system-bus-{module_name}-{pid}"`.  Including the PID prevents
/// reuse across forked child processes; the module name prevents clashes
/// between different PAM modules loaded in the same namespace.
///
/// Mirrors `pam_make_bus_cache_id()` in *pam-util.c*.
pub fn make_bus_cache_id(module_name: &str) -> PamResult<String> {
    let name = validate_module_name(module_name)?;
    Ok(format!("system-bus-{name}-{}", std::process::id()))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PamError ─────────────────────────────────────────────────────

    #[test]
    fn test_pam_error_code_roundtrip() {
        let variants = [
            PamError::Success,
            PamError::BufErr,
            PamError::ServiceErr,
            PamError::SystemErr,
            PamError::AuthErr,
            PamError::NoModuleData,
            PamError::BadItem,
            PamError::Ignore,
            PamError::Abort,
            PamError::TryAgain,
            PamError::ModuleUnknown,
        ];
        for v in variants {
            assert_eq!(PamError::from_code(v.code()), v);
        }
    }

    #[test]
    fn test_pam_error_unknown_roundtrip() {
        let code = 999;
        let err = PamError::from_code(code);
        assert_eq!(err, PamError::Unknown(999));
        assert_eq!(err.code(), 999);
    }

    #[test]
    fn test_pam_error_from_i32() {
        let err: PamError = 5.into();
        assert_eq!(err, PamError::BufErr);
    }

    #[test]
    fn test_pam_error_into_i32() {
        let code: i32 = PamError::AuthErr.into();
        assert_eq!(code, 9);
    }

    #[test]
    fn test_pam_error_display() {
        assert_eq!(PamError::Success.to_string(), "Success");
        assert_eq!(PamError::BufErr.to_string(), "Memory buffer error");
        assert_eq!(PamError::Unknown(42).to_string(), "Unknown PAM error (42)");
    }

    #[test]
    fn test_pam_error_is_success() {
        assert!(PamError::Success.is_success());
        assert!(!PamError::BufErr.is_success());
        assert!(!PamError::Unknown(0).is_success());
    }

    #[test]
    fn test_pam_error_is_transient() {
        assert!(PamError::AuthErr.is_transient());
        assert!(PamError::BufErr.is_transient());
        assert!(PamError::TryAgain.is_transient());
        assert!(PamError::AuthtokLockBusy.is_transient());
        assert!(!PamError::Success.is_transient());
        assert!(!PamError::PermDenied.is_transient());
        assert!(!PamError::SystemErr.is_transient());
    }

    // ── errno → PAM Error ────────────────────────────────────────────

    #[test]
    fn test_errno_to_pam_error_enomem() {
        assert_eq!(errno_to_pam_error(ENOMEM), PamError::BufErr);
        assert_eq!(errno_to_pam_error(-ENOMEM), PamError::BufErr);
    }

    #[test]
    fn test_errno_to_pam_error_other() {
        assert_eq!(errno_to_pam_error(1), PamError::ServiceErr);
        assert_eq!(errno_to_pam_error(-1), PamError::ServiceErr);
        assert_eq!(errno_to_pam_error(22), PamError::ServiceErr);
        assert_eq!(errno_to_pam_error(-22), PamError::ServiceErr);
        assert_eq!(errno_to_pam_error(0), PamError::ServiceErr);
        assert_eq!(errno_to_pam_error(i32::MIN), PamError::ServiceErr);
    }

    // ── @PAMERR@ Substitution ────────────────────────────────────────

    #[test]
    fn test_pam_substitute_err_with_suffix() {
        let result = pam_substitute_err("Failed to do thing: @PAMERR@", "Authentication error");
        assert_eq!(result, "Failed to do thing: Authentication error");
    }

    #[test]
    fn test_pam_substitute_err_without_suffix() {
        let result = pam_substitute_err("Plain message", "some error");
        assert_eq!(result, "Plain message");
    }

    #[test]
    fn test_pam_substitute_err_percent_in_desc() {
        // pam_strerror may return strings with % — must be sanitised.
        let result = pam_substitute_err("Failed: @PAMERR@", "100% done");
        assert_eq!(result, "Failed: n/a");
    }

    #[test]
    fn test_pam_substitute_err_empty_format() {
        assert_eq!(pam_substitute_err("", "err"), "");
    }

    #[test]
    fn test_pam_substitute_err_only_marker() {
        assert_eq!(pam_substitute_err("@PAMERR@", "ok"), "ok");
    }

    // ── Item Types ───────────────────────────────────────────────────

    #[test]
    fn test_pam_item_type_roundtrip() {
        let items = [
            PamItemType::Service,
            PamItemType::User,
            PamItemType::Tty,
            PamItemType::Rhost,
            PamItemType::Conv,
            PamItemType::Authtok,
            PamItemType::OldAuthtok,
            PamItemType::Ruser,
            PamItemType::UserPrompt,
            PamItemType::FailDelay,
            PamItemType::XDisplay,
            PamItemType::XAuthData,
            PamItemType::AuthtokType,
        ];
        for item in items {
            assert_eq!(PamItemType::from_code(item.code()), item);
        }
    }

    #[test]
    fn test_pam_item_type_other() {
        let other = PamItemType::Other(99);
        assert_eq!(other.code(), 99);
        assert_eq!(PamItemType::from_code(99), PamItemType::Other(99));
    }

    // ── Prompt Styles ────────────────────────────────────────────────

    #[test]
    fn test_pam_prompt_style_roundtrip() {
        let styles = [
            PamPromptStyle::EchoOff,
            PamPromptStyle::EchoOn,
            PamPromptStyle::ErrorMsg,
            PamPromptStyle::TextInfo,
        ];
        for s in styles {
            assert_eq!(PamPromptStyle::from_code(s.code()), s);
        }
    }

    // ── Data Flags ───────────────────────────────────────────────────

    #[test]
    fn test_pam_data_flags_silent() {
        let flags = PamDataFlags::SILENT;
        assert!(flags.contains(PamDataFlags::SILENT));
        assert_eq!(flags.bits(), 0x4000_0000);
    }

    #[test]
    fn test_pam_data_flags_empty() {
        let flags = PamDataFlags::empty();
        assert!(!flags.contains(PamDataFlags::SILENT));
    }

    // ── Batch Requests ───────────────────────────────────────────────

    #[test]
    fn test_pam_get_item_many_success() {
        let mut reqs = [
            PamItemRequest::new(PamItemType::User),
            PamItemRequest::new(PamItemType::Tty),
        ];

        // Mock: User found with ptr 0xDEAD, Tty missing
        let get_item = |item: PamItemType| -> PamResult<Option<usize>> {
            match item {
                PamItemType::User => Ok(Some(0xDEAD)),
                PamItemType::Tty => Ok(None),
                _ => Err(PamError::BadItem),
            }
        };

        pam_get_item_many(&mut reqs, get_item).unwrap();
        assert!(reqs[0].found);
        assert_eq!(reqs[0].value, Some(0xDEAD));
        assert!(!reqs[1].found);
        assert_eq!(reqs[1].value, None);
    }

    #[test]
    fn test_pam_get_item_many_bad_item_is_ok() {
        let mut reqs = [PamItemRequest::new(PamItemType::Service)];

        let get_item = |_item: PamItemType| -> PamResult<Option<usize>> { Err(PamError::BadItem) };

        pam_get_item_many(&mut reqs, get_item).unwrap();
        assert!(!reqs[0].found);
    }

    #[test]
    fn test_pam_get_item_many_propagates_error() {
        let mut reqs = [PamItemRequest::new(PamItemType::Service)];

        let get_item =
            |_item: PamItemType| -> PamResult<Option<usize>> { Err(PamError::SystemErr) };

        let err = pam_get_item_many(&mut reqs, get_item).unwrap_err();
        assert_eq!(err, PamError::SystemErr);
    }

    #[test]
    fn test_pam_get_data_many_success() {
        let mut reqs = [
            PamDataRequest::new("systemd-home"),
            PamDataRequest::new("nonexistent"),
        ];

        let get_data = |name: &str| -> PamResult<Option<usize>> {
            match name {
                "systemd-home" => Ok(Some(0xBEEF)),
                _ => Err(PamError::NoModuleData),
            }
        };

        pam_get_data_many(&mut reqs, get_data).unwrap();
        assert!(reqs[0].found);
        assert_eq!(reqs[0].value, Some(0xBEEF));
        assert!(!reqs[1].found);
    }

    #[test]
    fn test_pam_get_data_many_propagates_error() {
        let mut reqs = [PamDataRequest::new("key")];

        let get_data = |_name: &str| -> PamResult<Option<usize>> { Err(PamError::ServiceErr) };

        let err = pam_get_data_many(&mut reqs, get_data).unwrap_err();
        assert_eq!(err, PamError::ServiceErr);
    }

    // ── Cleanup ──────────────────────────────────────────────────────

    #[test]
    fn test_cleanup_free_null() {
        // Must not panic on null.
        // SAFETY: a null pointer satisfies cleanup_free's ownership contract.
        unsafe_ffi!(cleanup_free(std::ptr::null_mut()));
    }

    #[test]
    fn test_cleanup_close_null() {
        // Must not panic on null, regardless of flags.
        // SAFETY: a null pointer is the encoded no-descriptor sentinel.
        unsafe_ffi!(cleanup_close(std::ptr::null_mut(), PamDataFlags::empty()));
    }

    #[test]
    fn test_cleanup_close_silent_flag() {
        // SILENT suppresses the close of a descriptor encoded with FD_TO_PTR().
        // SAFETY: the silent path does not consume the encoded descriptor.
        unsafe_ffi!(cleanup_close(43 as *mut c_void, PamDataFlags::SILENT));
    }

    // ── Conversation ─────────────────────────────────────────────────

    #[test]
    fn test_pam_prompt_graceful_success() {
        let result = pam_prompt_graceful(PamPromptStyle::EchoOff, "Password: ", |_style, _msg| {
            Ok(Some("secret".to_owned()))
        });
        assert_eq!(result.unwrap(), Some("secret".to_owned()));
    }

    #[test]
    fn test_pam_prompt_graceful_none_response() {
        let result =
            pam_prompt_graceful(PamPromptStyle::TextInfo, "Welcome", |_style, _msg| Ok(None));
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_pam_prompt_graceful_error() {
        let result = pam_prompt_graceful(PamPromptStyle::EchoOff, "Password: ", |_style, _msg| {
            Err(PamError::ConvErr)
        });
        assert_eq!(result.unwrap_err(), PamError::ConvErr);
    }

    #[test]
    fn test_pam_prompt_graceful_empty_message_is_forwarded() {
        let result = pam_prompt_graceful(PamPromptStyle::EchoOff, "", |_style, _msg| {
            Ok(Some("x".to_owned()))
        });
        assert_eq!(result.unwrap(), Some("x".to_owned()));
    }

    // ── Bus Cache ID ─────────────────────────────────────────────────

    #[test]
    fn test_make_bus_cache_id() {
        let id = make_bus_cache_id("pam_systemd_home").unwrap();
        assert!(id.starts_with("system-bus-pam_systemd_home-"));
        assert!(id.ends_with(&std::process::id().to_string()));
    }

    #[test]
    fn test_make_bus_cache_id_empty_module_name() {
        let id = make_bus_cache_id("").unwrap();
        assert!(id.starts_with("system-bus--"));
    }

    #[test]
    fn test_make_bus_cache_id_null_rejected() {
        assert_eq!(make_bus_cache_id("bad\0name"), Err(PamError::SystemErr));
    }

    #[test]
    fn test_make_bus_cache_id_slash_module_name() {
        let id = make_bus_cache_id("bad/name").unwrap();
        assert!(id.starts_with("system-bus-bad/name-"));
    }

    // ── Request constructors ─────────────────────────────────────────

    #[test]
    fn test_pam_item_request_new() {
        let req = PamItemRequest::new(PamItemType::User);
        assert_eq!(req.item_type, PamItemType::User);
        assert!(!req.found);
        assert!(req.value.is_none());
    }

    #[test]
    fn test_pam_data_request_new() {
        let req = PamDataRequest::new("my-key");
        assert_eq!(req.name, "my-key");
        assert!(!req.found);
        assert!(req.value.is_none());
    }
}
