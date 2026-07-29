// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pkcs7-util.c, src/shared/pkcs7-util.h
//
// PKCS#7 signature utilities — C-authoritative signer extraction from
// DER-encoded PKCS#7 signatures.
//
// Signer extraction delegates to C so OpenSSL loading, parsing, and error
// behavior remain shared. The returned C allocation is copied into Rust-owned
// values and released with signer_free_many(), its authoritative destructor.

use crate::ffi::Errno;
use std::ptr::NonNull;

#[repr(C)]
struct CSigner {
    issuer: libc::iovec,
    serial: libc::iovec,
}

// SAFETY: These declarations exactly match pkcs7-util.h. The safe extraction
// wrapper below supplies initialized output slots and releases every successful
// signer array through the paired C destructor.
unsafe extern "C" {
    #[link_name = "pkcs7_extract_signers"]
    fn c_pkcs7_extract_signers(
        signature: *const libc::iovec,
        ret_signers: *mut *mut CSigner,
        ret_n_signers: *mut usize,
    ) -> libc::c_int;

    #[link_name = "signer_free_many"]
    fn c_signer_free_many(signers: *mut CSigner, n_signers: usize);
}

struct CSignerArray {
    signers: NonNull<CSigner>,
    len: usize,
}

impl CSignerArray {
    fn as_slice(&self) -> &[CSigner] {
        // The guard exists only after C returns exactly `len` initialized
        // elements and retains their ownership for this slice's lifetime.
        // SAFETY: `signers` is non-null and valid for `len` CSigner elements.
        unsafe { std::slice::from_raw_parts(self.signers.as_ptr(), self.len) }
    }
}

impl Drop for CSignerArray {
    fn drop(&mut self) {
        // SAFETY: `signers` and `len` are the unchanged allocation and count
        // returned by pkcs7_extract_signers(), and this guard is their sole
        // owner. signer_free_many() releases both nested iovecs and the array.
        unsafe { c_signer_free_many(self.signers.as_ptr(), self.len) }
    }
}

fn copy_signer_iovec(iovec: &libc::iovec, encoded_signature_len: usize) -> Result<Vec<u8>> {
    if iovec.iov_base.is_null()
        || iovec.iov_len == 0
        || iovec.iov_len > encoded_signature_len
        || iovec.iov_len > isize::MAX as usize
    {
        return Err(Pkcs7Error::not_recoverable());
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(iovec.iov_len)
        .map_err(|_| Pkcs7Error::out_of_memory())?;

    // C owns this allocation until CSignerArray drops; Rust retains no borrow.
    // SAFETY: the checked non-null pointer is live for the checked, bounded
    // iov_len according to the successful extractor's output contract.
    let source = unsafe { std::slice::from_raw_parts(iovec.iov_base.cast::<u8>(), iovec.iov_len) };
    bytes.extend_from_slice(source);
    Ok(bytes)
}

// ── Constants ───────────────────────────────────────────────────────────────

/// Maximum number of signers we will accept from a single PKCS#7 signature.
/// This is a safety net against maliciously complex signatures.
pub const SIGNERS_MAX: usize = 32;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors produced by PKCS#7 operations.
///
/// Wraps a negative errno value, matching the systemd C convention where
/// functions return `-EINVAL`, `-EBADMSG`, etc. on failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs7Error {
    code: i32,
}

impl Pkcs7Error {
    /// Construct from a raw negative errno value.
    pub fn from_neg_errno(neg: i32) -> Self {
        Self { code: neg }
    }

    /// Operation not supported (e.g. OpenSSL not compiled in).
    pub fn not_supported() -> Self {
        Self {
            code: Errno::EOPNOTSUPP.to_neg_errno(),
        }
    }

    /// Bad / malformed message.
    pub fn bad_message() -> Self {
        Self {
            code: Errno::EBADMSG.to_neg_errno(),
        }
    }

    /// No data available (e.g. no signer info in PKCS#7).
    pub fn no_data() -> Self {
        Self {
            code: Errno::ENODATA.to_neg_errno(),
        }
    }

    /// Out of memory.
    pub fn out_of_memory() -> Self {
        Self {
            code: Errno::ENOMEM.to_neg_errno(),
        }
    }

    /// Recoverable error (transient failure).
    pub fn not_recoverable() -> Self {
        Self {
            code: Errno::ENOTRECOVERABLE.to_neg_errno(),
        }
    }

    /// Returns the raw negative errno code.
    pub fn as_neg_errno(&self) -> i32 {
        self.code
    }

    /// Returns `true` if this is `-EOPNOTSUPP`.
    pub fn is_not_supported(&self) -> bool {
        self.code == Errno::EOPNOTSUPP.to_neg_errno()
    }

    /// Returns `true` if this is `-EBADMSG`.
    pub fn is_bad_message(&self) -> bool {
        self.code == Errno::EBADMSG.to_neg_errno()
    }

    /// Returns `true` if this is `-ENODATA`.
    pub fn is_no_data(&self) -> bool {
        self.code == Errno::ENODATA.to_neg_errno()
    }
}

impl std::fmt::Display for Pkcs7Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PKCS#7 error (errno {})", self.code)
    }
}

impl std::error::Error for Pkcs7Error {}

/// Module-local Result alias.
pub type Result<T> = std::result::Result<T, Pkcs7Error>;

// ── Signer type ─────────────────────────────────────────────────────────────

/// Information about a single signer extracted from a PKCS#7 signature.
///
/// Each signer is identified by the DER-encoded issuer X.509 name and the
/// serial number, both stored as owned byte vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// DER-encoded X.509 Name of the certificate issuer.
    pub issuer: Vec<u8>,
    /// DER-encoded ASN.1 INTEGER serial number.
    pub serial: Vec<u8>,
}

impl Signer {
    /// Create a new signer with the given issuer and serial DER data.
    pub fn new(issuer: Vec<u8>, serial: Vec<u8>) -> Self {
        Self { issuer, serial }
    }

    /// Returns `true` if both issuer and serial are non-empty.
    pub fn is_valid(&self) -> bool {
        !self.issuer.is_empty() && !self.serial.is_empty()
    }
}

// ── PKCS#7 extraction ───────────────────────────────────────────────────────

/// Extract signer information from a DER-encoded PKCS#7 signature.
///
/// Parsing remains C-authoritative: this passes the DER bytes to
/// `pkcs7_extract_signers()`, copies its bounded results into Rust-owned
/// vectors, and releases all C allocations through `signer_free_many()`.
///
/// # Errors
///
/// - `Pkcs7Error::bad_message()` — the DER data is not valid PKCS#7 or
///   there are too many signers (see [`SIGNERS_MAX`]).
/// - `Pkcs7Error::no_data()` — the PKCS#7 structure contains no signer
///   information.
/// - `Pkcs7Error::not_supported()` — OpenSSL is not available at runtime.
/// - `Pkcs7Error::not_recoverable()` — C returned an inconsistent signer
///   allocation or an invalid encoded signer field.
/// - `Pkcs7Error::out_of_memory()` — a Rust-owned result could not be
///   allocated.
pub fn pkcs7_extract_signers(der: &[u8]) -> Result<Vec<Signer>> {
    if der.is_empty() || der.len() > libc::c_long::MAX as usize {
        return Err(Pkcs7Error::bad_message());
    }

    let signature = libc::iovec {
        iov_base: der.as_ptr().cast_mut().cast(),
        iov_len: der.len(),
    };
    let mut c_signers = std::ptr::null_mut();
    let mut n_signers = 0;

    // C only reads `signature` and transfers successful outputs to its caller.
    // SAFETY: the iovec borrows live `der` bytes, and both outputs are valid,
    // uniquely borrowed, initialized slots.
    let result = unsafe { c_pkcs7_extract_signers(&signature, &mut c_signers, &mut n_signers) };
    if result < 0 {
        return Err(Pkcs7Error::from_neg_errno(result));
    }

    let count = result as usize;
    let Some(c_signers) = NonNull::new(c_signers) else {
        return Err(Pkcs7Error::not_recoverable());
    };

    // C returns its local signer count both as the positive result and through
    // ret_n_signers. Use the return value for ownership because it is also the
    // exact number of initialized array elements. Take ownership before
    // validating the redundant count and limit so inconsistent successful
    // outputs are still released through the C destructor.
    let c_signers = CSignerArray {
        signers: c_signers,
        len: count,
    };
    if count == 0 || count > SIGNERS_MAX || n_signers != count {
        return Err(Pkcs7Error::not_recoverable());
    }

    let mut signers = Vec::new();
    signers
        .try_reserve_exact(count)
        .map_err(|_| Pkcs7Error::out_of_memory())?;
    for signer in c_signers.as_slice() {
        signers.push(Signer {
            issuer: copy_signer_iovec(&signer.issuer, der.len())?,
            serial: copy_signer_iovec(&signer.serial, der.len())?,
        });
    }

    Ok(signers)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Error type tests ─────────────────────────────────────────────────

    #[test]
    fn test_pkcs7_error_not_supported() {
        let err = Pkcs7Error::not_supported();
        assert_eq!(err.as_neg_errno(), Errno::EOPNOTSUPP.to_neg_errno());
        assert!(err.is_not_supported());
        assert!(!err.is_bad_message());
        assert!(!err.is_no_data());
    }

    #[test]
    fn test_pkcs7_error_bad_message() {
        let err = Pkcs7Error::bad_message();
        assert_eq!(err.as_neg_errno(), Errno::EBADMSG.to_neg_errno());
        assert!(err.is_bad_message());
        assert!(!err.is_not_supported());
    }

    #[test]
    fn test_pkcs7_error_no_data() {
        let err = Pkcs7Error::no_data();
        assert_eq!(err.as_neg_errno(), Errno::ENODATA.to_neg_errno());
        assert!(err.is_no_data());
    }

    #[test]
    fn test_pkcs7_error_out_of_memory() {
        let err = Pkcs7Error::out_of_memory();
        assert_eq!(err.as_neg_errno(), Errno::ENOMEM.to_neg_errno());
    }

    #[test]
    fn test_pkcs7_error_not_recoverable() {
        let err = Pkcs7Error::not_recoverable();
        assert_eq!(err.as_neg_errno(), Errno::ENOTRECOVERABLE.to_neg_errno());
    }

    #[test]
    fn test_pkcs7_error_from_neg_errno() {
        let err = Pkcs7Error::from_neg_errno(-74); // -EBADMSG
        assert_eq!(err.as_neg_errno(), -74);
        assert!(err.is_bad_message());
    }

    #[test]
    fn test_pkcs7_error_display() {
        let err = Pkcs7Error::bad_message();
        let msg = format!("{err}");
        assert!(msg.contains("PKCS#7"));
        assert!(msg.contains("-74"));
    }

    #[test]
    fn test_pkcs7_error_equality() {
        assert_eq!(Pkcs7Error::bad_message(), Pkcs7Error::bad_message());
        assert_ne!(Pkcs7Error::bad_message(), Pkcs7Error::no_data());
    }

    // ── Signer tests ─────────────────────────────────────────────────────

    #[test]
    fn test_signer_new() {
        let issuer = vec![0x30, 0x06, 0x03, 0x01, 0x00, 0x04, 0x01];
        let serial = vec![0x02, 0x01, 0x05];
        let signer = Signer::new(issuer.clone(), serial.clone());
        assert_eq!(signer.issuer, issuer);
        assert_eq!(signer.serial, serial);
    }

    #[test]
    fn test_signer_is_valid() {
        let valid = Signer::new(vec![1, 2, 3], vec![4, 5]);
        assert!(valid.is_valid());

        let no_issuer = Signer::new(vec![], vec![4, 5]);
        assert!(!no_issuer.is_valid());

        let no_serial = Signer::new(vec![1, 2, 3], vec![]);
        assert!(!no_serial.is_valid());

        let empty = Signer::new(vec![], vec![]);
        assert!(!empty.is_valid());
    }

    #[test]
    fn test_signer_equality() {
        let a = Signer::new(vec![1], vec![2]);
        let b = Signer::new(vec![1], vec![2]);
        let c = Signer::new(vec![1], vec![3]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── Extraction tests ─────────────────────────────────────────────────

    #[test]
    fn test_pkcs7_extract_signers_empty_input() {
        let result = pkcs7_extract_signers(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_bad_message());
    }

    #[test]
    fn test_pkcs7_extract_signers_malformed_or_not_supported() {
        // With OpenSSL this is malformed DER; without OpenSSL the authoritative
        // C implementation reports that extraction is unsupported.
        let result = pkcs7_extract_signers(&[0x30, 0x82]);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.is_bad_message() || error.is_not_supported());
    }

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn test_signers_max() {
        assert_eq!(SIGNERS_MAX, 32);
    }
}
