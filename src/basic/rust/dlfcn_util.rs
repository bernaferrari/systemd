// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/dlfcn-util.c, src/basic/dlfcn-util.h
//
// Safe ownership and diagnostic facade over systemd's authoritative C dynamic
// loader policy. This module deliberately does not reproduce that policy:
// `dlopen_safe()` remains responsible for static-build handling,
// `block_dlopen()`, and the security-required RTLD_NOW | RTLD_NODELETE flags.

use std::ffi::{CStr, CString, c_char, c_void};
use std::fmt;
use std::ptr::{self, NonNull};

// SAFETY: the safe wrappers below provide live C strings, writable output
// storage, and handles returned by the same dynamic-loader implementation.
unsafe extern "C" {
    #[link_name = "dlopen_safe"]
    fn c_dlopen_safe(
        filename: *const c_char,
        ret: *mut *mut c_void,
        reterr_dlerror: *mut *const c_char,
    ) -> libc::c_int;

    #[link_name = "safe_dlclose"]
    fn c_safe_dlclose(handle: *mut c_void) -> *mut c_void;
}

/// Failure to open a library through systemd's dynamic-loader policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlopenError {
    library: String,
    errno: i32,
    detail: Option<String>,
}

impl DlopenError {
    /// Positive errno reported by the loader boundary.
    pub fn errno(&self) -> i32 {
        self.errno
    }

    fn invalid_name(library: &str) -> Self {
        Self {
            library: library.into(),
            errno: libc::EINVAL,
            detail: Some("library name contains an interior NUL byte".into()),
        }
    }

    fn null_handle(library: &str) -> Self {
        Self {
            library: library.into(),
            errno: libc::EIO,
            detail: Some("loader returned success with a null handle".into()),
        }
    }
}

impl fmt::Display for DlopenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.library)?;
        if let Some(detail) = &self.detail {
            f.write_str(detail)
        } else {
            write!(f, "{}", std::io::Error::from_raw_os_error(self.errno))
        }
    }
}

impl std::error::Error for DlopenError {}

/// Failure to resolve a required symbol from a live library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlsymError {
    symbol: String,
    detail: Option<String>,
}

impl DlsymError {
    fn invalid_name(symbol: &str) -> Self {
        Self {
            symbol: symbol.into(),
            detail: Some("symbol name contains an interior NUL byte".into()),
        }
    }
}

impl fmt::Display for DlsymError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.symbol)?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DlsymError {}

/// An owned, unpublished dynamic-loader reference.
///
/// Dropping this value releases an incomplete load. Once all required symbols
/// have been validated, [`publish`](Self::publish) deliberately retains the
/// reference for process lifetime, matching `dlopen_many_sym_or_warn()`.
#[derive(Debug)]
pub struct UnpublishedDlopenHandle(NonNull<c_void>);

/// A fully validated dynamic-loader reference retained for process lifetime.
///
/// This deliberately has no `Drop` implementation.  systemd's
/// `dlopen_many_sym_or_warn()` treats successfully resolved optional
/// libraries as regular dependencies and keeps their references for the
/// remainder of the process.  Keeping the live handle also permits later
/// symbol lookups without bypassing the shared loader policy.
#[derive(Debug, Clone, Copy)]
pub struct PublishedDlopenHandle(NonNull<c_void>);

// SAFETY: POSIX dynamic-loader handles may be shared between threads and this
// wrapper never unloads or mutates the referenced object. Its only operation,
// dlsym(), uses the platform's thread-safe loader interface.
unsafe impl Send for PublishedDlopenHandle {}

// SAFETY: as for Send, concurrent immutable references only perform
// thread-safe loader symbol lookups and cannot create Rust aliasing.
unsafe impl Sync for PublishedDlopenHandle {}

fn resolve_required_symbol(
    handle: NonNull<c_void>,
    symbol: &str,
) -> Result<NonNull<c_void>, DlsymError> {
    let name = CString::new(symbol).map_err(|_| DlsymError::invalid_name(symbol))?;

    // POSIX requires clearing the thread-local diagnostic before dlsym():
    // a null symbol value alone does not distinguish an error.
    // SAFETY: `dlerror()` takes no arguments.
    unsafe { libc::dlerror() };
    // SAFETY: `handle` is a live reference returned by `dlopen_safe()` and
    // `name` remains a live NUL-terminated string throughout the lookup.
    let pointer = unsafe { libc::dlsym(handle.as_ptr(), name.as_ptr()) };
    // SAFETY: `dlerror()` takes no arguments and returns thread-local loader
    // state.
    let loader_error = unsafe { libc::dlerror() };

    if !loader_error.is_null() {
        // SAFETY: checked non-null above; copy the borrowed diagnostic before
        // any subsequent loader operation invalidates it.
        let detail = unsafe { CStr::from_ptr(loader_error) }
            .to_string_lossy()
            .into_owned();
        return Err(DlsymError {
            symbol: symbol.into(),
            detail: Some(detail),
        });
    }

    NonNull::new(pointer).ok_or_else(|| DlsymError {
        symbol: symbol.into(),
        detail: None,
    })
}

impl UnpublishedDlopenHandle {
    /// Open `library` using C's process-wide loader policy.
    pub fn open(library: &str) -> Result<Self, DlopenError> {
        let name = CString::new(library).map_err(|_| DlopenError::invalid_name(library))?;
        let mut handle = ptr::null_mut();
        let mut loader_error = ptr::null();

        // SAFETY: `name` is a live NUL-terminated string and both out-pointers
        // refer to writable local storage for the duration of the call.
        let result = unsafe { c_dlopen_safe(name.as_ptr(), &mut handle, &mut loader_error) };
        if result < 0 {
            let detail = if loader_error.is_null() {
                None
            } else {
                Some(
                    // SAFETY: `dlopen_safe()` returned this borrowed,
                    // NUL-terminated diagnostic. Copy it before another
                    // loader operation can replace the thread-local buffer.
                    unsafe { CStr::from_ptr(loader_error) }
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            return Err(DlopenError {
                library: library.into(),
                errno: result.checked_neg().unwrap_or(libc::EIO),
                detail,
            });
        }

        NonNull::new(handle)
            .map(Self)
            .ok_or_else(|| DlopenError::null_handle(library))
    }

    /// Resolve a required symbol, preserving the loader's diagnostic.
    pub fn resolve_required(&self, symbol: &str) -> Result<NonNull<c_void>, DlsymError> {
        resolve_required_symbol(self.0, symbol)
    }

    /// Retain a fully validated library reference for process lifetime.
    pub fn publish(self) -> PublishedDlopenHandle {
        let handle = self.0;
        std::mem::forget(self);
        PublishedDlopenHandle(handle)
    }
}

impl PublishedDlopenHandle {
    /// Resolve a required symbol from this process-lifetime library handle.
    pub fn resolve_required(&self, symbol: &str) -> Result<NonNull<c_void>, DlsymError> {
        resolve_required_symbol(self.0, symbol)
    }
}

impl Drop for UnpublishedDlopenHandle {
    fn drop(&mut self) {
        // SAFETY: this value owns exactly one unpublished reference returned
        // by `dlopen_safe()`. `safe_dlclose()` consumes that reference.
        unsafe { c_safe_dlclose(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_interior_nul_without_calling_c() {
        let error = UnpublishedDlopenHandle::open("libbad\0name.so").unwrap_err();
        assert_eq!(error.errno(), libc::EINVAL);
        assert!(error.to_string().contains("interior NUL"));
    }

    #[test]
    fn symbol_error_display_preserves_context() {
        let error = DlsymError {
            symbol: "required_symbol".into(),
            detail: Some("missing".into()),
        };
        assert_eq!(error.to_string(), "required_symbol: missing");
    }
}
