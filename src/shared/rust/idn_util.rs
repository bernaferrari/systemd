// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/idn-util.c, src/shared/idn-util.h

use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::sync::OnceLock;

use crate::ffi::Errno;

const LIBIDN2_CANDIDATES: &[&str] = &["libidn2.so.0"];

const IDN2_OK: i32 = 0;
const IDN2_NFC_INPUT: i32 = 1;
const IDN2_TRANSITIONAL: i32 = 4;
const IDN2_NONTRANSITIONAL: i32 = 8;

const IDN2_TOO_BIG_DOMAIN: i32 = -205;
const IDN2_TOO_BIG_LABEL: i32 = -206;
const IDN2_2HYPHEN: i32 = -301;
const IDN2_DISALLOWED: i32 = -304;

const IDN2008_LOOKUP_FLAGS: i32 = IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL;
const IDN2003_LOOKUP_FLAGS: i32 = IDN2_NFC_INPUT | IDN2_TRANSITIONAL;

// SAFETY: These function-pointer types exactly mirror libidn2's public C
// declarations; calls remain confined to validated wrapper functions below.
type Idn2LookupU8Fn = unsafe extern "C" fn(*const u8, *mut *mut u8, i32) -> i32;
type Idn2StrerrorFn = unsafe extern "C" fn(i32) -> *const libc::c_char;
type Idn2ToUnicode8z8zFn =
    unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char, i32) -> i32;
type Idn2FreeFn = unsafe extern "C" fn(*mut c_void);

const _: () = {
    let _: Option<unsafe extern "C" fn(*const u8, *mut *mut u8, i32) -> i32> =
        None::<Idn2LookupU8Fn>;
    let _: Option<unsafe extern "C" fn(i32) -> *const libc::c_char> = None::<Idn2StrerrorFn>;
    let _: Option<unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char, i32) -> i32> =
        None::<Idn2ToUnicode8z8zFn>;
    let _: Option<unsafe extern "C" fn(*mut c_void)> = None::<Idn2FreeFn>;
};

#[derive(Debug)]
struct LibIdn2 {
    _handle: *mut c_void,
    lookup_u8: Idn2LookupU8Fn,
    strerror: Idn2StrerrorFn,
    to_unicode_8z8z: Idn2ToUnicode8z8zFn,
    free: Idn2FreeFn,
}

unsafe impl Send for LibIdn2 {}
unsafe impl Sync for LibIdn2 {}

static LIBIDN2: OnceLock<Result<LibIdn2, IdnError>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdnError {
    Unsupported,
    DlopenFailed(String),
    SymbolNotFound(String),
    InvalidInput(&'static str),
    LookupFailed {
        input: String,
        code: i32,
        message: String,
    },
    DecodeFailed {
        input: String,
        code: i32,
        message: String,
    },
    RoundtripMismatch {
        input: String,
        ascii: String,
        unicode: String,
    },
    InvalidUtf8Output,
}

impl fmt::Display for IdnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "libidn2 support is unavailable"),
            Self::DlopenFailed(detail) => write!(f, "failed to open libidn2: {detail}"),
            Self::SymbolNotFound(symbol) => {
                write!(f, "required libidn2 symbol not found: {symbol}")
            }
            Self::InvalidInput(message) => write!(f, "invalid IDN input: {message}"),
            Self::LookupFailed {
                input,
                code,
                message,
            } => write!(
                f,
                "failed to encode domain name '{input}' with libidn2 ({code}): {message}"
            ),
            Self::DecodeFailed {
                input,
                code,
                message,
            } => write!(
                f,
                "failed to decode domain name '{input}' with libidn2 ({code}): {message}"
            ),
            Self::RoundtripMismatch {
                input,
                ascii,
                unicode,
            } => write!(
                f,
                "IDNA roundtrip mismatch: '{input}' -> '{ascii}' -> '{unicode}'"
            ),
            Self::InvalidUtf8Output => write!(f, "libidn2 returned non-UTF-8 output"),
        }
    }
}

impl std::error::Error for IdnError {}

impl From<IdnError> for i32 {
    fn from(error: IdnError) -> Self {
        match error {
            IdnError::Unsupported | IdnError::DlopenFailed(_) | IdnError::SymbolNotFound(_) => {
                Errno::EOPNOTSUPP.to_neg_errno()
            }
            IdnError::InvalidInput(_)
            | IdnError::RoundtripMismatch { .. }
            | IdnError::InvalidUtf8Output => Errno::EINVAL.to_neg_errno(),
            IdnError::LookupFailed { code, .. } | IdnError::DecodeFailed { code, .. } => {
                if matches!(code, IDN2_TOO_BIG_DOMAIN | IDN2_TOO_BIG_LABEL) {
                    Errno::ENOSPC.to_neg_errno()
                } else {
                    Errno::EINVAL.to_neg_errno()
                }
            }
        }
    }
}

pub fn dlopen_idn() -> Result<(), IdnError> {
    libidn2().map(|_| ())
}

pub fn have_libidn2() -> bool {
    dlopen_idn().is_ok()
}

pub fn idn_name_to_ascii(name: &str) -> Result<String, IdnError> {
    validate_domain_input(name)?;

    let api = libidn2()?;
    let ascii = match call_lookup(api, name, IDN2008_LOOKUP_FLAGS) {
        Ok(ascii) => ascii,
        Err(IdnError::LookupFailed { code, .. }) if code == IDN2_DISALLOWED => {
            call_lookup(api, name, IDN2003_LOOKUP_FLAGS)?
        }
        Err(error) => return Err(error),
    };

    if has_punycode_label(name) {
        return Ok(ascii);
    }

    let unicode = call_to_unicode(api, &ascii)?;
    if unicode != name {
        return Err(IdnError::RoundtripMismatch {
            input: name.to_owned(),
            ascii,
            unicode,
        });
    }

    Ok(ascii)
}

pub fn idn_name_from_ascii(name: &str) -> Result<String, IdnError> {
    validate_domain_input(name)?;
    call_to_unicode(libidn2()?, name)
}

fn validate_domain_input(name: &str) -> Result<(), IdnError> {
    if name.is_empty() {
        return Err(IdnError::InvalidInput("domain name must not be empty"));
    }

    if name.as_bytes().contains(&0) {
        return Err(IdnError::InvalidInput(
            "domain name must not contain interior NUL bytes",
        ));
    }

    Ok(())
}

fn has_punycode_label(name: &str) -> bool {
    name.split('.')
        .any(|label| label.len() >= 4 && label.as_bytes()[..4].eq_ignore_ascii_case(b"xn--"))
}

fn libidn2() -> Result<&'static LibIdn2, IdnError> {
    LIBIDN2
        .get_or_init(load_libidn2)
        .as_ref()
        .map_err(Clone::clone)
}

fn load_libidn2() -> Result<LibIdn2, IdnError> {
    let mut saw_dlopen_failure = false;

    for candidate in LIBIDN2_CANDIDATES {
        match try_load_libidn2(candidate) {
            Ok(api) => return Ok(api),
            Err(IdnError::DlopenFailed(_)) => saw_dlopen_failure = true,
            Err(error) => return Err(error),
        }
    }

    if saw_dlopen_failure {
        Err(IdnError::Unsupported)
    } else {
        Err(IdnError::DlopenFailed(
            "no libidn2 candidates configured".into(),
        ))
    }
}

fn try_load_libidn2(lib_name: &str) -> Result<LibIdn2, IdnError> {
    let handle = unsafe { dlopen_wrapper(lib_name) }?;

    let lookup_u8 = unsafe { resolve_symbol(handle, "idn2_lookup_u8") }?;
    let strerror = unsafe { resolve_symbol(handle, "idn2_strerror") }?;
    let to_unicode_8z8z = unsafe { resolve_symbol(handle, "idn2_to_unicode_8z8z") }?;
    let free = unsafe { resolve_symbol(handle, "idn2_free") }?;

    Ok(LibIdn2 {
        _handle: handle,
        lookup_u8,
        strerror,
        to_unicode_8z8z,
        free,
    })
}

fn call_lookup(api: &LibIdn2, name: &str, flags: i32) -> Result<String, IdnError> {
    let input =
        CString::new(name).map_err(|_| IdnError::InvalidInput("domain name contains NUL"))?;
    let mut output = std::ptr::null_mut();

    let rc = unsafe { (api.lookup_u8)(input.as_ptr().cast(), &mut output, flags) };
    if rc != IDN2_OK {
        return Err(IdnError::LookupFailed {
            input: name.to_owned(),
            code: rc,
            message: idn2_error_message(api, rc),
        });
    }

    take_owned_output(api, output.cast())
}

fn call_to_unicode(api: &LibIdn2, name: &str) -> Result<String, IdnError> {
    let input =
        CString::new(name).map_err(|_| IdnError::InvalidInput("domain name contains NUL"))?;
    let mut output = std::ptr::null_mut();

    let rc = unsafe { (api.to_unicode_8z8z)(input.as_ptr(), &mut output, 0) };
    if rc != IDN2_OK {
        return Err(IdnError::DecodeFailed {
            input: name.to_owned(),
            code: rc,
            message: idn2_error_message(api, rc),
        });
    }

    take_owned_output(api, output)
}

fn take_owned_output(api: &LibIdn2, output: *mut libc::c_char) -> Result<String, IdnError> {
    if output.is_null() {
        return Err(IdnError::InvalidUtf8Output);
    }

    let bytes = unsafe { CStr::from_ptr(output).to_bytes().to_vec() };
    unsafe { (api.free)(output.cast()) };

    String::from_utf8(bytes).map_err(|_| IdnError::InvalidUtf8Output)
}

fn idn2_error_message(api: &LibIdn2, code: i32) -> String {
    let message = unsafe { (api.strerror)(code) };
    if message.is_null() {
        return format!("libidn2 error {code}");
    }

    unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

unsafe fn dlopen_wrapper(lib_name: &str) -> Result<*mut c_void, IdnError> {
    let c_name = CString::new(lib_name)
        .map_err(|e| IdnError::DlopenFailed(format!("invalid library name: {e}")))?;

    // SAFETY: c_name is NUL-terminated and remains live for the call.
    let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let detail = dlerror_string();
        Err(IdnError::DlopenFailed(format!("{lib_name}: {detail}")))
    } else {
        Ok(handle)
    }
}

unsafe fn resolve_symbol<T: Copy>(handle: *mut c_void, symbol: &str) -> Result<T, IdnError> {
    let c_symbol = CString::new(symbol)
        .map_err(|e| IdnError::SymbolNotFound(format!("{symbol}: invalid symbol name: {e}")))?;

    // SAFETY: the caller supplies a live dlopen handle and c_symbol is NUL-terminated.
    let ptr = unsafe { libc::dlsym(handle, c_symbol.as_ptr()) };
    if ptr.is_null() {
        return Err(IdnError::SymbolNotFound(symbol.to_owned()));
    }

    // SAFETY: the caller chooses T to match the resolved C symbol's function signature.
    Ok(unsafe { std::mem::transmute_copy(&ptr) })
}

fn dlerror_string() -> String {
    unsafe {
        let ptr = libc::dlerror();
        if ptr.is_null() {
            "unknown error".to_owned()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_input_empty_is_rejected() {
        assert_eq!(
            validate_domain_input(""),
            Err(IdnError::InvalidInput("domain name must not be empty"))
        );
    }

    #[test]
    fn invalid_input_nul_is_rejected() {
        assert_eq!(
            validate_domain_input("bad\0name"),
            Err(IdnError::InvalidInput(
                "domain name must not contain interior NUL bytes",
            ))
        );
    }

    #[test]
    fn unicode_input_is_accepted() {
        assert_eq!(validate_domain_input("bücher.example"), Ok(()));
    }

    #[test]
    fn punycode_detection_handles_single_label() {
        assert!(has_punycode_label("xn--bcher-kva.example"));
    }

    #[test]
    fn punycode_detection_handles_non_leading_label() {
        assert!(has_punycode_label("www.xn--bcher-kva.example"));
    }

    #[test]
    fn punycode_detection_is_case_insensitive() {
        assert!(has_punycode_label("XN--BCHER-KVA.example"));
    }

    #[test]
    fn punycode_detection_ignores_plain_ascii() {
        assert!(!has_punycode_label("example.com"));
    }

    #[test]
    fn unsupported_maps_to_eopnotsupp() {
        assert_eq!(
            i32::from(IdnError::Unsupported),
            Errno::EOPNOTSUPP.to_neg_errno()
        );
    }

    #[test]
    fn dlopen_failure_maps_to_eopnotsupp() {
        assert_eq!(
            i32::from(IdnError::DlopenFailed("missing".into())),
            Errno::EOPNOTSUPP.to_neg_errno()
        );
    }

    #[test]
    fn symbol_failure_maps_to_eopnotsupp() {
        assert_eq!(
            i32::from(IdnError::SymbolNotFound("idn2_lookup_u8".into())),
            Errno::EOPNOTSUPP.to_neg_errno()
        );
    }

    #[test]
    fn invalid_input_maps_to_einval() {
        assert_eq!(
            i32::from(IdnError::InvalidInput("bad input")),
            Errno::EINVAL.to_neg_errno()
        );
    }

    #[test]
    fn lookup_too_big_domain_maps_to_enospc() {
        assert_eq!(
            i32::from(IdnError::LookupFailed {
                input: "example".into(),
                code: IDN2_TOO_BIG_DOMAIN,
                message: "too big".into(),
            }),
            Errno::ENOSPC.to_neg_errno()
        );
    }

    #[test]
    fn lookup_too_big_label_maps_to_enospc() {
        assert_eq!(
            i32::from(IdnError::LookupFailed {
                input: "example".into(),
                code: IDN2_TOO_BIG_LABEL,
                message: "too big".into(),
            }),
            Errno::ENOSPC.to_neg_errno()
        );
    }

    #[test]
    fn lookup_other_error_maps_to_einval() {
        assert_eq!(
            i32::from(IdnError::LookupFailed {
                input: "example".into(),
                code: IDN2_2HYPHEN,
                message: "two hyphens".into(),
            }),
            Errno::EINVAL.to_neg_errno()
        );
    }

    #[test]
    fn roundtrip_mismatch_maps_to_einval() {
        assert_eq!(
            i32::from(IdnError::RoundtripMismatch {
                input: "bücher.example".into(),
                ascii: "xn--bcher-kva.example".into(),
                unicode: "bucher.example".into(),
            }),
            Errno::EINVAL.to_neg_errno()
        );
    }

    #[test]
    fn invalid_utf8_output_maps_to_einval() {
        assert_eq!(
            i32::from(IdnError::InvalidUtf8Output),
            Errno::EINVAL.to_neg_errno()
        );
    }

    #[test]
    fn dlopen_result_matches_availability_probe() {
        assert_eq!(have_libidn2(), dlopen_idn().is_ok());
    }

    #[test]
    fn ascii_passthrough_roundtrip_when_library_is_available() {
        if !have_libidn2() {
            return;
        }

        let ascii = idn_name_to_ascii("example.com").unwrap();
        assert_eq!(ascii, "example.com");
        assert_eq!(idn_name_from_ascii(&ascii).unwrap(), "example.com");
    }

    #[test]
    fn unicode_name_encodes_when_library_is_available() {
        if !have_libidn2() {
            return;
        }

        assert_eq!(
            idn_name_to_ascii("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn punycode_name_decodes_when_library_is_available() {
        if !have_libidn2() {
            return;
        }

        assert_eq!(
            idn_name_from_ascii("xn--bcher-kva.example").unwrap(),
            "bücher.example"
        );
    }
}
