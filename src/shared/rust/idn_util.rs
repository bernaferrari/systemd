// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/idn-util.c, src/shared/idn-util.h

use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::ptr::NonNull;
use std::sync::OnceLock;

use crate::ffi::Errno;
use systemd_basic_rs::dlfcn_util::UnpublishedDlopenHandle;

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

#[derive(Debug)]
struct LibIdn2 {
    lookup_u8: Idn2LookupU8Fn,
    strerror: Idn2StrerrorFn,
    to_unicode_8z8z: Idn2ToUnicode8z8zFn,
}

struct OwnedIdn2String {
    ptr: NonNull<libc::c_char>,
}

impl OwnedIdn2String {
    fn from_raw(ptr: *mut libc::c_char) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Self { ptr })
    }

    fn into_string(self) -> Result<String, IdnError> {
        // SAFETY: libidn2 returned this as a successful, NUL-terminated string,
        // and self keeps the allocation alive for the duration of the copy.
        unsafe { CStr::from_ptr(self.ptr.as_ptr()) }
            .to_str()
            .map(str::to_owned)
            .map_err(|_| IdnError::InvalidUtf8Output)
    }
}

impl Drop for OwnedIdn2String {
    fn drop(&mut self) {
        // SAFETY: ptr is the unique allocation returned by libidn2. Its public
        // ABI requires the caller to free output buffers, as the C path does.
        unsafe {
            libc::free(self.ptr.as_ptr().cast());
        }
    }
}

static LIBIDN2: OnceLock<LibIdn2> = OnceLock::new();

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
            Self::InvalidUtf8Output => write!(f, "libidn2 returned non-UTF-8 output"),
        }
    }
}

impl std::error::Error for IdnError {}

impl From<IdnError> for i32 {
    fn from(error: IdnError) -> Self {
        match error {
            IdnError::Unsupported | IdnError::DlopenFailed(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            IdnError::SymbolNotFound(_) => Errno::ELIBBAD.to_neg_errno(),
            IdnError::InvalidInput(_) => Errno::EINVAL.to_neg_errno(),
            IdnError::DecodeFailed { .. } | IdnError::InvalidUtf8Output => {
                Errno::EUCLEAN.to_neg_errno()
            }
            IdnError::LookupFailed { code, .. } => {
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

/// Apply IDNA lookup conversion with the same tri-state contract as
/// `dns_name_apply_idna()`:
///
/// * `Ok(Some(name))` means conversion succeeded;
/// * `Ok(None)` means IDNA is unavailable or the input should be used unchanged;
/// * `Err(error)` reports a hard failure.
pub fn idn_name_to_ascii(name: &str) -> Result<Option<String>, IdnError> {
    validate_domain_input(name)?;

    let api = match libidn2() {
        Ok(api) => api,
        Err(IdnError::Unsupported | IdnError::DlopenFailed(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let ascii = match call_lookup(api, name, IDN2008_LOOKUP_FLAGS) {
        Ok(ascii) => ascii,
        Err(IdnError::LookupFailed { code, .. }) if code == IDN2_DISALLOWED => {
            match call_lookup(api, name, IDN2003_LOOKUP_FLAGS) {
                Ok(ascii) => ascii,
                Err(IdnError::LookupFailed { code, .. }) if code == IDN2_2HYPHEN => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        Err(IdnError::LookupFailed { code, .. }) if code == IDN2_2HYPHEN => return Ok(None),
        Err(error) => return Err(error),
    };

    if skips_roundtrip_check(name) {
        return Ok(Some(ascii));
    }

    let unicode = match call_to_unicode(api, &ascii) {
        Ok(unicode) => unicode,
        Err(IdnError::DecodeFailed { .. }) => return Ok(None),
        Err(error) => return Err(error),
    };
    if unicode != name {
        return Ok(None);
    }

    Ok(Some(ascii))
}

pub fn idn_name_from_ascii(name: &str) -> Result<String, IdnError> {
    validate_domain_input(name)?;
    call_to_unicode(libidn2()?, name)
}

fn validate_domain_input(name: &str) -> Result<(), IdnError> {
    if name.as_bytes().contains(&0) {
        return Err(IdnError::InvalidInput(
            "domain name must not contain interior NUL bytes",
        ));
    }

    Ok(())
}

fn skips_roundtrip_check(name: &str) -> bool {
    /* Match dns_name_apply_idna() exactly: only a lower-case ACE prefix at the
     * beginning of the complete name suppresses the roundtrip check. */
    name.starts_with("xn--")
}

fn libidn2() -> Result<&'static LibIdn2, IdnError> {
    if let Some(api) = LIBIDN2.get() {
        return Ok(api);
    }

    let (api, handle) = load_libidn2()?;
    match LIBIDN2.set(api) {
        // Match dlopen_many_sym_or_warn(): a fully resolved library remains
        // loaded for the process lifetime.
        Ok(()) => handle.publish(),
        Err(_) => {
            /* Another thread installed an API first. Dropping our handle is safe
             * because its function pointers were never published. */
        }
    }

    Ok(LIBIDN2
        .get()
        .expect("the libidn2 API was installed by this or another thread"))
}

fn load_libidn2() -> Result<(LibIdn2, UnpublishedDlopenHandle), IdnError> {
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

fn try_load_libidn2(lib_name: &str) -> Result<(LibIdn2, UnpublishedDlopenHandle), IdnError> {
    let handle = dlopen_wrapper(lib_name)?;

    let lookup_u8 = resolve_symbol(&handle, "idn2_lookup_u8")?;
    let strerror = resolve_symbol(&handle, "idn2_strerror")?;
    let to_unicode_8z8z = resolve_symbol(&handle, "idn2_to_unicode_8z8z")?;

    // SAFETY: Each symbol was resolved by its exact public libidn2 ABI name,
    // and the compile-time assertions above spell out the corresponding type.
    let api = unsafe {
        LibIdn2 {
            lookup_u8: std::mem::transmute::<*mut c_void, Idn2LookupU8Fn>(lookup_u8.as_ptr()),
            strerror: std::mem::transmute::<*mut c_void, Idn2StrerrorFn>(strerror.as_ptr()),
            to_unicode_8z8z: std::mem::transmute::<*mut c_void, Idn2ToUnicode8z8zFn>(
                to_unicode_8z8z.as_ptr(),
            ),
        }
    };

    Ok((api, handle))
}

fn call_lookup(api: &LibIdn2, name: &str, flags: i32) -> Result<String, IdnError> {
    let input =
        CString::new(name).map_err(|_| IdnError::InvalidInput("domain name contains NUL"))?;
    let mut output = std::ptr::null_mut();

    // SAFETY: input is a live NUL-terminated UTF-8 string, output is writable,
    // and lookup_u8 has the verified idn2_lookup_u8 ABI.
    let rc = unsafe { (api.lookup_u8)(input.as_ptr().cast(), &mut output, flags) };
    if rc != IDN2_OK {
        return Err(IdnError::LookupFailed {
            input: name.to_owned(),
            code: rc,
            message: idn2_error_message(api, rc),
        });
    }

    take_owned_output(output.cast())
}

fn call_to_unicode(api: &LibIdn2, name: &str) -> Result<String, IdnError> {
    let input =
        CString::new(name).map_err(|_| IdnError::InvalidInput("domain name contains NUL"))?;
    let mut output = std::ptr::null_mut();

    // SAFETY: input is a live NUL-terminated UTF-8 string, output is writable,
    // and to_unicode_8z8z has the verified idn2_to_unicode_8z8z ABI.
    let rc = unsafe { (api.to_unicode_8z8z)(input.as_ptr(), &mut output, 0) };
    if rc != IDN2_OK {
        return Err(IdnError::DecodeFailed {
            input: name.to_owned(),
            code: rc,
            message: idn2_error_message(api, rc),
        });
    }

    take_owned_output(output)
}

fn take_owned_output(output: *mut libc::c_char) -> Result<String, IdnError> {
    OwnedIdn2String::from_raw(output)
        .ok_or(IdnError::InvalidUtf8Output)?
        .into_string()
}

fn idn2_error_message(api: &LibIdn2, code: i32) -> String {
    // SAFETY: strerror has the verified idn2_strerror ABI and accepts every
    // libidn2 status code.
    let message = unsafe { (api.strerror)(code) };
    if message.is_null() {
        return format!("libidn2 error {code}");
    }

    // SAFETY: idn2_strerror returns a borrowed, NUL-terminated static string.
    unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

fn dlopen_wrapper(lib_name: &str) -> Result<UnpublishedDlopenHandle, IdnError> {
    // `dlopen_safe()` deliberately omits RTLD_GLOBAL, so it retains the
    // platform default RTLD_LOCAL visibility while also enforcing systemd's
    // static-build and block_dlopen() policy. Keep that C authority instead
    // of reproducing loader policy with a direct libc::dlopen() call.
    UnpublishedDlopenHandle::open(lib_name)
        .map_err(|error| IdnError::DlopenFailed(error.to_string()))
}

fn resolve_symbol(
    handle: &UnpublishedDlopenHandle,
    symbol: &str,
) -> Result<NonNull<c_void>, IdnError> {
    handle
        .resolve_required(symbol)
        .map_err(|error| IdnError::SymbolNotFound(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_passed_to_libidn2_like_the_c_path() {
        assert_eq!(validate_domain_input(""), Ok(()));
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
    fn leading_lowercase_punycode_prefix_skips_roundtrip() {
        assert!(skips_roundtrip_check("xn--bcher-kva.example"));
    }

    #[test]
    fn non_leading_punycode_label_does_not_skip_roundtrip() {
        assert!(!skips_roundtrip_check("www.xn--bcher-kva.example"));
    }

    #[test]
    fn uppercase_punycode_prefix_does_not_skip_roundtrip() {
        assert!(!skips_roundtrip_check("XN--BCHER-KVA.example"));
    }

    #[test]
    fn plain_ascii_does_not_skip_roundtrip() {
        assert!(!skips_roundtrip_check("example.com"));
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
    fn symbol_failure_maps_to_elibbad() {
        assert_eq!(
            i32::from(IdnError::SymbolNotFound("idn2_lookup_u8".into())),
            Errno::ELIBBAD.to_neg_errno()
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
    fn decode_failure_maps_to_euclean() {
        assert_eq!(
            i32::from(IdnError::DecodeFailed {
                input: "xn--invalid".into(),
                code: IDN2_DISALLOWED,
                message: "disallowed".into(),
            }),
            Errno::EUCLEAN.to_neg_errno()
        );
    }

    #[test]
    fn invalid_utf8_output_maps_to_euclean() {
        assert_eq!(
            i32::from(IdnError::InvalidUtf8Output),
            Errno::EUCLEAN.to_neg_errno()
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

        let ascii = idn_name_to_ascii("example.com").unwrap().unwrap();
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
            Some("xn--bcher-kva.example".into())
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
