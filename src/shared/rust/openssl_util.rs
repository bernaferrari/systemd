// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/crypto-util.c, src/shared/crypto-util.h
//
// Digest helpers backed by C's OpenSSL capability boundary. C owns the
// configured HAVE_OPENSSL decision, lazy loading, provider lookup, and OpenSSL
// ABI; Rust owns only validated inputs and returned-allocation lifetime.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::{CString, c_char, c_void};
use std::ptr::NonNull;
use std::sync::Mutex;

use crate::ffi::Errno;

// SAFETY: Exact crypto-util.h declarations for the stable, always-linked
// digest bridges. The calls retain no Rust pointers or allocation ownership;
// C returns a `malloc(3)` allocation only through `ret_digest` on success.
unsafe extern "C" {
    #[link_name = "openssl_digest_size_for_rust"]
    fn c_openssl_digest_size(digest_alg: *const c_char, ret_digest_size: *mut usize)
    -> libc::c_int;

    #[link_name = "openssl_digest_many_for_rust"]
    fn c_openssl_digest_many(
        digest_alg: *const c_char,
        data: *const libc::iovec,
        n_data: usize,
        ret_digest: *mut *mut c_void,
        ret_digest_size: *mut usize,
    ) -> libc::c_int;
}

/// Errors returned by the C-authoritative OpenSSL digest helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSslError {
    pub code: i32,
}

impl OpenSslError {
    fn from_neg_errno(code: i32) -> Self {
        Self { code }
    }

    fn invalid_argument() -> Self {
        Self {
            code: Errno::EINVAL.to_neg_errno(),
        }
    }

    fn io_error() -> Self {
        Self {
            code: Errno::EIO.to_neg_errno(),
        }
    }
}

impl std::fmt::Display for OpenSslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenSSL digest error (errno {})", self.code)
    }
}

impl std::error::Error for OpenSslError {}

pub type Result<T> = std::result::Result<T, OpenSslError>;

/// Serializes Rust entry into C's lazy libcrypto loader and published symbol
/// table. Once loaded, C/OpenSSL own all process-wide cryptographic state.
static OPENSSL_DIGEST_LOCK: Mutex<()> = Mutex::new(());

/// A digest buffer allocated by C with `malloc(3)`.
///
/// The guard is created immediately after a successful C call so every later
/// Rust validation and copy path releases the C allocation exactly once.
struct CAllocatedDigest {
    ptr: NonNull<u8>,
    len: usize,
}

impl CAllocatedDigest {
    fn new(ptr: *mut c_void, len: usize) -> Result<Self> {
        let ptr = NonNull::new(ptr.cast()).ok_or_else(OpenSslError::io_error)?;
        Ok(Self { ptr, len })
    }

    fn to_vec(&self) -> Vec<u8> {
        // SAFETY: C's successful `openssl_digest_many()` result is a live
        // malloc allocation of exactly `len` digest bytes, owned by this guard.
        unsafe_ffi!(std::slice::from_raw_parts(self.ptr.as_ptr(), self.len)).to_vec()
    }
}

impl Drop for CAllocatedDigest {
    fn drop(&mut self) {
        // SAFETY: `ptr` is the single malloc allocation transferred by C to
        // this guard. `libc::free` is allocator-compatible and runs once.
        unsafe_ffi!(libc::free(self.ptr.as_ptr().cast()));
    }
}

fn digest_algorithm(algorithm: &str) -> Result<CString> {
    CString::new(algorithm).map_err(|_| OpenSslError::invalid_argument())
}

/// Return the size of C/OpenSSL's fixed-size digest algorithm.
///
/// Provider names and availability are intentionally determined by C at call
/// time, rather than by a Rust table that can disagree with the configured
/// OpenSSL build.
pub fn digest_size(digest_alg: &str) -> Result<usize> {
    let digest_alg = digest_algorithm(digest_alg)?;
    let _lock = OPENSSL_DIGEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut size = 0;

    // SAFETY: `digest_alg` is NUL-terminated and live for the call; `size` is
    // a writable output slot. C retains neither pointer.
    let result = unsafe_ffi!(c_openssl_digest_size(digest_alg.as_ptr(), &mut size));
    if result < 0 {
        return Err(OpenSslError::from_neg_errno(result));
    }
    if size == 0 {
        return Err(OpenSslError::io_error());
    }

    Ok(size)
}

/// Encode bytes using C's lowercase hexadecimal spelling.
pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(data.len().saturating_mul(2));
    for byte in data {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

/// Hash one byte slice through C's `openssl_digest_many()` implementation.
///
/// A zero-length slice is represented by a live one-byte sentinel with length
/// zero. This preserves the C iovec contract without turning Rust's dangling
/// empty-slice pointer into a foreign pointer argument.
pub fn compute_hash(data: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    let digest_alg = digest_algorithm(algorithm)?;
    let empty_sentinel = 0_u8;
    let base = if data.is_empty() {
        &empty_sentinel as *const u8
    } else {
        data.as_ptr()
    };
    let iovec = libc::iovec {
        iov_base: base.cast_mut().cast(),
        iov_len: data.len(),
    };
    let _lock = OPENSSL_DIGEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut digest = std::ptr::null_mut();
    let mut digest_size = 0;

    // SAFETY: the one-element iovec, its input bytes (or live zero-length
    // sentinel), and both output slots live for the call. C copies no input
    // pointers and transfers only the malloc allocation in `digest` on success.
    let result = unsafe {
        c_openssl_digest_many(
            digest_alg.as_ptr(),
            &iovec,
            1,
            &mut digest,
            &mut digest_size,
        )
    };
    if result < 0 {
        return Err(OpenSslError::from_neg_errno(result));
    }

    let digest = CAllocatedDigest::new(digest, digest_size)?;
    if digest.len == 0 {
        return Err(OpenSslError::io_error());
    }
    Ok(digest.to_vec())
}

/// Hash exactly `len` UTF-8 bytes from `s` and return lowercase hexadecimal.
///
/// C accepts an arbitrary pointer/length pair. The safe Rust API rejects an
/// out-of-bounds length rather than reading past `s`, while preserving C's
/// zero-length behavior (hash the empty byte sequence).
pub fn string_hashsum(s: &str, len: usize, md_algorithm: &str) -> Result<String> {
    let bytes = s.as_bytes();
    if len > bytes.len() {
        return Err(OpenSslError::invalid_argument());
    }

    Ok(hex_encode(&compute_hash(&bytes[..len], md_algorithm)?))
}

/// Hash all UTF-8 bytes of `s` and return lowercase hexadecimal.
pub fn string_hashsum_full(s: &str, md_algorithm: &str) -> Result<String> {
    string_hashsum(s, s.len(), md_algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_uses_c_lowercase_spelling() {
        assert_eq!(hex_encode(&[0x01, 0x23, 0xff]), "0123ff");
    }

    #[test]
    fn string_hashsum_rejects_out_of_bounds_byte_lengths() {
        assert_eq!(
            string_hashsum("abc", 4, "SHA256").unwrap_err().code,
            Errno::EINVAL.to_neg_errno()
        );
    }
}
