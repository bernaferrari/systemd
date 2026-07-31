// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.iovec-util; authority=src/basic/iovec-util.c,src/basic/iovec-util.h,src/fundamental/iovec-util.h
//
// iovec utility functions: allocation, erasure, total_size, inc_many,
// make_string, memcmp, memdup, replace-with-copy, is_set, is_valid, done,
// done_many_and_free.

// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter documents and validates the raw-pointer,
        // ownership, and lifetime contract before evaluating this expression.
        unsafe { $expression }
    }};
}
use std::ffi::{CStr, c_void};
use std::sync::atomic::{Ordering, compiler_fence};
use std::{cmp, ptr, slice};

use libc::c_char;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoVec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

/// `malloc(3)` has no pointer or lifetime preconditions; allocation ownership
/// is transferred to the caller of the C ABI wrapper that receives its result.
fn c_malloc(size: usize) -> *mut c_void {
    // SAFETY: malloc accepts every usize byte count.
    unsafe_ffi!(libc::malloc(size))
}

/// A Rust-owned byte vector with safe iovec-style operations.
///
/// This type deliberately does not expose a freely copyable raw `IoVec`:
/// borrowed pointers must not outlive the owner. C-allocator ownership stays
/// confined to the `rs_iovec_*` ABI shims below.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnedIoVec {
    bytes: Vec<u8>,
}

impl OwnedIoVec {
    /// Allocate a zero-initialized payload of exactly `len` bytes.
    pub fn allocate(len: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len)?;
        bytes.resize(len, 0);
        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::collections::TryReserveError> {
        let mut copy = Vec::new();
        copy.try_reserve_exact(bytes.len())?;
        copy.extend_from_slice(bytes);
        Ok(Self { bytes: copy })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Erase the payload with volatile stores so the writes cannot be
    /// optimized away.
    pub fn erase(&mut self) {
        erase_bytes(&mut self.bytes);
    }

    /// Replace this payload with a fallibly allocated copy.
    ///
    /// Returns `false` without allocating when the byte content is unchanged.
    /// Allocation failure leaves the original payload untouched.
    pub fn replace_with_copy(
        &mut self,
        source: &[u8],
    ) -> Result<bool, std::collections::TryReserveError> {
        if self.bytes == source {
            return Ok(false);
        }

        let replacement = Self::from_bytes(source)?;
        *self = replacement;
        Ok(true)
    }
}

fn erase_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a unique, valid pointer to one initialized byte.
        // Volatile stores are used specifically to make secret erasure
        // observable to the abstract machine and hence non-elidable.
        unsafe_ffi!(ptr::write_volatile(byte, 0));
    }
    compiler_fence(Ordering::SeqCst);
}

fn total_size(iovecs: &[IoVec]) -> usize {
    iovecs
        .iter()
        .fold(0, |sum, iov| sum.saturating_add(iov.iov_len))
}

/// Advance safe iovec descriptors after their raw array has been validated by
/// the C ABI adapter. Returns true when no payload remains.
fn increment_many(iovecs: &mut [IoVec], mut remaining: usize) -> bool {
    let mut have_payload = false;
    for entry in iovecs {
        if entry.iov_len == 0 {
            continue;
        }
        if remaining == 0 {
            return false;
        }

        let consumed = cmp::min(entry.iov_len, remaining);
        entry.iov_len -= consumed;
        // The ABI adapter's contract guarantees this pointer remains within
        // the payload allocation. No dereference is performed here.
        entry.iov_base = entry.iov_base.wrapping_byte_add(consumed);
        remaining -= consumed;
        have_payload |= entry.iov_len > 0 && !entry.iov_base.is_null();
    }
    assert_eq!(remaining, 0);
    !have_payload
}

/// Borrow the payload of a validated iovec as a Rust byte slice.
///
/// A null base is accepted only for the canonical empty iovec. Keeping this
/// conversion here lets comparison and copy cores operate entirely on slices.
fn iovec_bytes(iovec: &IoVec) -> Option<&[u8]> {
    if iovec.iov_len == 0 {
        return Some(&[]);
    }
    if iovec.iov_base.is_null() {
        return None;
    }
    // SAFETY: callers have validated the iovec payload's readable extent.
    Some(unsafe_ffi!(slice::from_raw_parts(
        iovec.iov_base.cast::<u8>(),
        iovec.iov_len
    )))
}

fn memcmp_bytes(a: &[u8], b: &[u8]) -> i32 {
    for (left, right) in a.iter().zip(b) {
        if left != right {
            return (*left as i32) - (*right as i32);
        }
    }
    match a.len().cmp(&b.len()) {
        cmp::Ordering::Less => -1,
        cmp::Ordering::Equal => 0,
        cmp::Ordering::Greater => 1,
    }
}

/// Free the owned C allocation described by an iovec and clear the descriptor.
///
/// This module-private core is called only after its C ABI adapters establish
/// that any non-null payload is uniquely C-allocator-owned. It releases that
/// payload exactly once and always restores the canonical empty descriptor.
fn free_iov_base(iovec: &mut IoVec) {
    if !iovec.iov_base.is_null() {
        // SAFETY: callers are the reviewed C ABI ownership adapters; their
        // contract guarantees malloc/calloc/strdup-style provenance here.
        unsafe_ffi!(libc::free(iovec.iov_base));
    }
    iovec.iov_base = ptr::null_mut();
    iovec.iov_len = 0;
}

/// Allocate a C-allocator-owned iovec payload.
///
/// Zero-length allocations still receive a non-null, one-byte allocation,
/// matching `iovec_alloc()` and preserving `free(3)` provenance.
///
/// # Safety
/// `ret` must point to writable, properly aligned `IoVec` storage. The caller
/// becomes responsible for releasing a successful result with
/// `rs_iovec_done`.
#[unsafe(export_name = "rs_iovec_alloc")]
pub unsafe extern "C" fn rs_iovec_alloc(n: usize, ret: *mut IoVec) -> i32 {
    if ret.is_null() {
        return -libc::EINVAL;
    }

    // Allocating one byte for an empty payload preserves the non-null C API
    // contract.
    let allocation = c_malloc(n.max(1));
    if allocation.is_null() {
        return -libc::ENOMEM;
    }

    // SAFETY: required by this C ABI entry point's contract.
    unsafe {
        ret.write(IoVec {
            iov_base: allocation,
            iov_len: n,
        })
    };
    0
}

/// Erase, but do not release, an iovec payload.
///
/// # Safety
/// `iovec` must point to one readable, properly aligned `IoVec`; its non-empty
/// payload must be writable for `iov_len` bytes.
#[unsafe(export_name = "rs_iovec_erase")]
pub unsafe extern "C" fn rs_iovec_erase(iovec: *mut IoVec) {
    // SAFETY: required by this C ABI entry point's contract.
    let Some(iovec) = (unsafe_ffi!(iovec.as_mut())) else {
        return;
    };
    if iovec.iov_len == 0 {
        return;
    }
    if iovec.iov_base.is_null() {
        return;
    }

    // SAFETY: required by this C ABI entry point's contract.
    let bytes = unsafe_ffi!(slice::from_raw_parts_mut(
        iovec.iov_base.cast::<u8>(),
        iovec.iov_len
    ));
    erase_bytes(bytes);
}

/// Report whether a C iovec has a non-empty payload.
///
/// # Safety
/// If non-null, `iovec` must point to one readable, properly aligned C
/// `struct rs_IoVec`.
#[unsafe(export_name = "rs_iovec_is_set")]
pub unsafe extern "C" fn rs_iovec_is_set(iovec: *const IoVec) -> bool {
    // SAFETY: required by this C ABI entry point's contract.
    !iovec.is_null() && unsafe_ffi!((*iovec).iov_len > 0 && !(*iovec).iov_base.is_null())
}

/// Report whether a C iovec satisfies the fundamental iovec invariant.
///
/// # Safety
/// If non-null, `iovec` must point to one readable, properly aligned C
/// `struct rs_IoVec`.
#[unsafe(export_name = "rs_iovec_is_valid")]
pub unsafe extern "C" fn rs_iovec_is_valid(iovec: *const IoVec) -> bool {
    // SAFETY: required by this C ABI entry point's contract.
    iovec.is_null() || unsafe_ffi!(!(*iovec).iov_base.is_null() || (*iovec).iov_len == 0)
}

/// Release the payload of one owned C iovec and clear it.
///
/// # Safety
/// If non-null, `iovec` must be writable, properly aligned, and its payload
/// must be either null or releasable by the C allocator.
#[unsafe(export_name = "rs_iovec_done")]
pub unsafe extern "C" fn rs_iovec_done(iovec: *mut IoVec) {
    // SAFETY: required by this C ABI entry point's contract.
    if let Some(iovec) = unsafe_ffi!(iovec.as_mut()) {
        free_iov_base(iovec);
    }
}

/// Release an owned C iovec array and all of its payloads.
///
/// # Safety
/// If non-null, `iovec` must designate `n` writable, properly aligned entries
/// in a C-allocator-owned array. Each non-null payload must be releasable by
/// the C allocator.
#[unsafe(export_name = "rs_iovec_done_many_and_free")]
pub unsafe extern "C" fn rs_iovec_done_many_and_free(iovec: *mut IoVec, n: usize) {
    if iovec.is_null() {
        return;
    }

    // SAFETY: required by this C ABI entry point's contract.
    for entry in unsafe_ffi!(slice::from_raw_parts_mut(iovec, n)) {
        free_iov_base(entry);
    }

    // SAFETY: the public C API takes ownership of an array allocated by the C
    // allocator. `free(NULL)` was handled above and `free` does not need `n`.
    unsafe_ffi!(libc::free(iovec.cast::<c_void>()));
}

/// Return the saturating byte count of a C iovec array.
///
/// # Safety
/// If `n` is non-zero, `iovec` must designate `n` readable, properly aligned
/// C `struct rs_IoVec` entries.
#[unsafe(export_name = "rs_iovec_total_size")]
pub unsafe extern "C" fn rs_iovec_total_size(iovec: *const IoVec, n: usize) -> usize {
    if n == 0 {
        return 0;
    }

    // SAFETY: required by this C ABI entry point's contract.
    total_size(unsafe_ffi!(slice::from_raw_parts(iovec, n)))
}

/// Advance through a mutable C iovec array by exactly `k` bytes.
///
/// # Safety
/// If non-null, `iovec` must designate `n` writable, properly aligned C
/// `struct rs_IoVec` entries. `k` must not exceed their total byte count, and
/// advancing each non-empty payload must remain within its allocation.
///
/// Returns true only when no payload remains after the increment, matching
/// `iovec_inc_many()` rather than merely reporting that `k` was consumed.
#[unsafe(export_name = "rs_iovec_inc_many")]
pub unsafe extern "C" fn rs_iovec_inc_many(iovec: *mut IoVec, n: usize, k: usize) -> bool {
    assert!(!iovec.is_null() || n == 0);
    if n == 0 {
        assert_eq!(k, 0);
        return true;
    }

    // SAFETY: required by this C ABI entry point's contract.
    increment_many(unsafe_ffi!(slice::from_raw_parts_mut(iovec, n)), k)
}

/// Point a C iovec at a borrowed NUL-terminated C string.
///
/// # Safety
/// `iovec` must point to writable, properly aligned storage. If non-null,
/// `s` must point to a readable NUL-terminated C string for the duration of
/// the call and the resulting iovec's use.
#[unsafe(export_name = "rs_iovec_make_string")]
pub unsafe extern "C" fn rs_iovec_make_string(iovec: *mut IoVec, s: *const c_char) -> *mut IoVec {
    // SAFETY: required by this C ABI entry point's contract.
    let Some(iovec) = (unsafe_ffi!(iovec.as_mut())) else {
        return ptr::null_mut();
    };

    let len = if s.is_null() {
        0
    } else {
        // SAFETY: required by this C ABI entry point's contract.
        unsafe_ffi!(CStr::from_ptr(s)).to_bytes().len()
    };

    iovec.iov_base = s.cast_mut().cast::<c_void>();
    iovec.iov_len = len;
    iovec
}

/// Compare the payloads described by two C iovecs.
///
/// # Safety
/// Each non-null argument must point to a readable, properly aligned C iovec.
/// Each non-empty payload must be readable for its declared length.
#[unsafe(export_name = "rs_iovec_memcmp")]
pub unsafe extern "C" fn rs_iovec_memcmp(a: *const IoVec, b: *const IoVec) -> i32 {
    if a == b {
        return 0;
    }

    // SAFETY: required by this C ABI entry point's contract.
    // SAFETY: required by this C ABI entry point's contract.
    let a = unsafe_ffi!(a.as_ref());
    // SAFETY: required by this C ABI entry point's contract.
    let b = unsafe_ffi!(b.as_ref());
    let a_bytes = a.and_then(iovec_bytes);
    let b_bytes = b.and_then(iovec_bytes);
    match (a_bytes, b_bytes) {
        (Some(a), Some(b)) => memcmp_bytes(a, b),
        // Preserve `memcmp_nn()`'s defensive result for malformed non-empty
        // iovecs whose payload pointer is null.
        _ => 0,
    }
}

/// Duplicate one C iovec's payload into C-allocator-owned storage.
///
/// # Safety
/// `ret` must point to writable, properly aligned C iovec storage. If
/// non-null, `source` must point to a readable C iovec whose non-empty payload
/// is readable for its declared length. `source` may equal `ret`.
#[unsafe(export_name = "rs_iovec_memdup")]
pub unsafe extern "C" fn rs_iovec_memdup(source: *const IoVec, ret: *mut IoVec) -> *mut IoVec {
    if ret.is_null() {
        return ptr::null_mut();
    }

    // Capture the descriptor before borrowing the output. This preserves the
    // C API's `source == ret` behavior while allowing the final publication to
    // use an ordinary mutable Rust reference.
    let source = if source.is_null() {
        None
    } else {
        // SAFETY: required by this C ABI entry point's contract.
        Some(unsafe_ffi!(*source))
    };
    // SAFETY: `ret` was checked non-null above and remains writable under the
    // entry-point contract after all aliased source reads have completed.
    let output = unsafe_ffi!(&mut *ret);
    let Some(source) = source.filter(|source| source.iov_len > 0 && !source.iov_base.is_null())
    else {
        *output = IoVec::default();
        return ret;
    };

    // The non-zero byte count is supplied directly to the C allocator so the
    // returned buffer can be released by either Rust or C callers.
    let copy = c_malloc(source.iov_len).cast::<u8>();
    if copy.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the source and destination ranges are valid and non-overlapping
    // by this C ABI entry point's contract and the fresh allocation above.
    unsafe_ffi!(ptr::copy_nonoverlapping(
        source.iov_base.cast::<u8>(),
        copy,
        source.iov_len
    ));
    *output = IoVec {
        iov_base: copy.cast::<c_void>(),
        iov_len: source.iov_len,
    };
    ret
}

/// Replace an owned C iovec with a copy of `source`.
///
/// Returns 0 when the byte content is unchanged, 1 after replacement, and
/// `-ENOMEM` if the copy cannot be allocated. Allocation failure leaves the
/// original iovec untouched.
///
/// # Safety
/// `iovec` must point to writable, properly aligned storage whose payload is
/// null or C-allocator-owned. If non-null, `source` and its non-empty payload
/// must be readable for the duration of the call.
#[unsafe(export_name = "rs_iovec_done_and_memdup")]
pub unsafe extern "C" fn rs_iovec_done_and_memdup(iovec: *mut IoVec, source: *const IoVec) -> i32 {
    if iovec.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: both pointers meet the contracts of `rs_iovec_memcmp`.
    if unsafe_ffi!(rs_iovec_memcmp(iovec, source)) == 0 {
        return 0;
    }

    let mut copy = IoVec::default();
    // SAFETY: `copy` is writable local storage and `source` satisfies this
    // function's source contract.
    if unsafe_ffi!(rs_iovec_memdup(source, &mut copy)).is_null() {
        return -libc::ENOMEM;
    }

    // SAFETY: required by this C ABI entry point's ownership contract; the
    // earlier helper calls have finished reading `source` before this mutable
    // destination borrow.
    let iovec = unsafe_ffi!(iovec.as_mut().unwrap_unchecked());
    free_iov_base(iovec);
    *iovec = copy;
    1
}

#[cfg(test)]
mod tests {
    // Keep the test-only FFI boundary explicit while allowing assertions to stay in safe Rust.
    macro_rules! test_ffi {
        ($expression:expr) => {{
            // SAFETY: test inputs are constructed in this module and satisfy the
            // documented C ABI preconditions of the exercised facade.
            unsafe { $expression }
        }};
    }
    use super::*;
    use std::ffi::CString;

    fn alloc_test_bytes(bytes: &[u8]) -> *mut c_void {
        let ptr = c_malloc(bytes.len().max(1)).cast::<u8>();
        assert!(!ptr.is_null());
        // SAFETY: ptr owns at least bytes.len() bytes and the source slice is disjoint.
        test_ffi!(ptr.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()));
        ptr.cast::<c_void>()
    }

    fn alloc_iovec_array(entries: &[IoVec]) -> *mut IoVec {
        let bytes = entries
            .len()
            .max(1)
            .checked_mul(std::mem::size_of::<IoVec>())
            .unwrap();
        let ptr = c_malloc(bytes).cast::<IoVec>();
        assert!(!ptr.is_null());
        // SAFETY: ptr owns storage for entries.len() IoVec values and the source is disjoint.
        test_ffi!(ptr.copy_from_nonoverlapping(entries.as_ptr(), entries.len()));
        ptr
    }

    #[test]
    fn owned_iovec_is_safe_for_empty_and_nonempty_allocations() {
        let empty = OwnedIoVec::allocate(0).unwrap();
        assert!(empty.as_bytes().is_empty());

        let mut payload = OwnedIoVec::allocate(4).unwrap();
        assert_eq!(payload.as_bytes(), &[0, 0, 0, 0]);
        payload.as_mut_bytes().copy_from_slice(b"test");
        assert_eq!(payload.as_bytes(), b"test");
    }

    #[test]
    fn owned_iovec_replace_reports_changed_and_preserves_content() {
        let mut payload = OwnedIoVec::from_bytes(b"old").unwrap();
        assert!(!payload.replace_with_copy(b"old").unwrap());
        assert_eq!(payload.as_bytes(), b"old");
        assert!(payload.replace_with_copy(b"new").unwrap());
        assert_eq!(payload.as_bytes(), b"new");
    }

    #[test]
    fn owned_iovec_erase_zeros_every_byte() {
        let mut payload = OwnedIoVec::from_bytes(b"secret").unwrap();
        payload.erase();
        assert_eq!(payload.as_bytes(), &[0; 6]);
    }

    #[test]
    fn c_allocation_preserves_zero_length_and_malloc_provenance() {
        let mut empty = IoVec::default();
        // SAFETY: `empty` is writable and the successful allocation is
        // released through the matching C-allocator shim.
        unsafe {
            assert_eq!(rs_iovec_alloc(0, &mut empty), 0);
            assert!(!empty.iov_base.is_null());
            assert_eq!(empty.iov_len, 0);
            rs_iovec_done(&mut empty);
        }
        assert_eq!(empty, IoVec::default());
    }

    #[test]
    fn c_erase_zeros_borrowed_stack_storage_without_freeing_it() {
        let mut bytes = *b"secret";
        let mut iovec = IoVec {
            iov_base: bytes.as_mut_ptr().cast::<c_void>(),
            iov_len: bytes.len(),
        };
        // SAFETY: the iovec designates the writable stack array for exactly
        // its length. `rs_iovec_erase` does not take ownership.
        test_ffi!(rs_iovec_erase(&mut iovec));
        assert_eq!(bytes, [0; 6]);
        assert_eq!(iovec.iov_len, 6);
    }

    #[test]
    fn done_and_memdup_matches_changed_and_unchanged_results() {
        // SAFETY: both payloads use the C allocator and are released through
        // `rs_iovec_done`.
        unsafe {
            let mut destination = IoVec {
                iov_base: alloc_test_bytes(b"old"),
                iov_len: 3,
            };
            let same = IoVec {
                iov_base: b"old".as_ptr().cast_mut().cast::<c_void>(),
                iov_len: 3,
            };
            assert_eq!(rs_iovec_done_and_memdup(&mut destination, &same), 0);

            let replacement = IoVec {
                iov_base: b"new".as_ptr().cast_mut().cast::<c_void>(),
                iov_len: 3,
            };
            let old_allocation = destination.iov_base;
            assert_eq!(rs_iovec_done_and_memdup(&mut destination, &replacement), 1);
            assert_ne!(destination.iov_base, old_allocation);
            assert_eq!(
                slice::from_raw_parts(destination.iov_base.cast::<u8>(), destination.iov_len),
                b"new"
            );
            rs_iovec_done(&mut destination);
        }
    }

    #[test]
    fn iovec_is_set_matches_c_rules() {
        let bytes = [1u8, 2, 3];
        let set = IoVec {
            iov_base: bytes.as_ptr() as *mut c_void,
            iov_len: 3,
        };
        let zero = IoVec {
            iov_base: bytes.as_ptr() as *mut c_void,
            iov_len: 0,
        };
        let null = IoVec {
            iov_base: ptr::null_mut(),
            iov_len: 3,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert!(rs_iovec_is_set(&set));
            assert!(!rs_iovec_is_set(&zero));
            assert!(!rs_iovec_is_set(&null));
            assert!(!rs_iovec_is_set(ptr::null()));
        }
    }

    #[test]
    fn iovec_is_valid_matches_c_rules() {
        let bytes = [1u8, 2, 3];
        let set = IoVec {
            iov_base: bytes.as_ptr() as *mut c_void,
            iov_len: 3,
        };
        let zero = IoVec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        };
        let invalid = IoVec {
            iov_base: ptr::null_mut(),
            iov_len: 3,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert!(rs_iovec_is_valid(&set));
            assert!(rs_iovec_is_valid(&zero));
            assert!(rs_iovec_is_valid(ptr::null()));
            assert!(!rs_iovec_is_valid(&invalid));
        }
    }

    #[test]
    fn total_size_sums_lengths() {
        let a = [1u8; 5];
        let b = [2u8; 1];
        let iovecs = [
            IoVec {
                iov_base: a.as_ptr() as *mut c_void,
                iov_len: 5,
            },
            IoVec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            },
            IoVec {
                iov_base: b.as_ptr() as *mut c_void,
                iov_len: 1,
            },
        ];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe {
            assert_eq!(rs_iovec_total_size(ptr::null(), 0), 0);
            assert_eq!(rs_iovec_total_size(iovecs.as_ptr(), 3), 6);
        }
    }

    #[test]
    fn total_size_saturates_on_overflow() {
        let iovecs = [
            IoVec {
                iov_base: ptr::null_mut(),
                iov_len: usize::MAX,
            },
            IoVec {
                iov_base: ptr::null_mut(),
                iov_len: 1,
            },
        ];

        // SAFETY: total-size only reads the two valid IoVec values and does
        // not dereference their payload pointers.
        assert_eq!(
            test_ffi!(rs_iovec_total_size(iovecs.as_ptr(), iovecs.len())),
            usize::MAX
        );
    }

    #[test]
    fn increment_consumes_across_boundaries() {
        let mut buf = *b"hello world";
        let mut iovecs = [
            IoVec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: 5,
            },
            IoVec {
                // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
                iov_base: test_ffi!(buf.as_mut_ptr().add(6)) as *mut c_void,
                iov_len: 5,
            },
        ];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe {
            assert!(!rs_iovec_inc_many(iovecs.as_mut_ptr(), 2, 7));
        }
        assert_eq!(iovecs[0].iov_len, 0);
        assert_eq!(iovecs[1].iov_len, 3);
    }

    #[test]
    fn increment_zero_bytes_returns_false_with_remaining_data() {
        let mut buf = *b"hello";
        let mut iovec = IoVec {
            iov_base: buf.as_mut_ptr() as *mut c_void,
            iov_len: 5,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert!(!rs_iovec_inc_many(&mut iovec, 1, 0));
        }
        assert_eq!(iovec.iov_len, 5);
    }

    #[test]
    fn make_string_tracks_pointer_and_length() {
        let s = CString::new("hello").unwrap();
        let mut iovec = IoVec::default();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe {
            assert!(!rs_iovec_make_string(&mut iovec, s.as_ptr()).is_null());
            assert_eq!(iovec.iov_base, s.as_ptr() as *mut c_void);
            assert_eq!(iovec.iov_len, 5);
            rs_iovec_make_string(&mut iovec, ptr::null());
            assert_eq!(iovec.iov_len, 0);
        }
    }

    #[test]
    fn memcmp_matches_lexicographic_c_behavior() {
        let a = IoVec {
            iov_base: b"abc".as_ptr() as *mut c_void,
            iov_len: 3,
        };
        let b = IoVec {
            iov_base: b"abd".as_ptr() as *mut c_void,
            iov_len: 3,
        };
        let c = IoVec {
            iov_base: b"ab".as_ptr() as *mut c_void,
            iov_len: 2,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_iovec_memcmp(&a, &a), 0);
            assert!(rs_iovec_memcmp(&a, &b) < 0);
            assert!(rs_iovec_memcmp(&b, &a) > 0);
            assert!(rs_iovec_memcmp(&c, &a) < 0);
            assert_eq!(rs_iovec_memcmp(ptr::null(), ptr::null()), 0);
        }
    }

    #[test]
    fn memdup_copies_set_iovecs() {
        let mut out = IoVec::default();
        let src = IoVec {
            iov_base: b"hello world".as_ptr() as *mut c_void,
            iov_len: 11,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert!(!rs_iovec_memdup(&src, &mut out).is_null());
            assert_eq!(out.iov_len, 11);
            assert_ne!(out.iov_base, src.iov_base);
            let bytes = slice::from_raw_parts(out.iov_base.cast::<u8>(), out.iov_len);
            assert_eq!(bytes, b"hello world");
            rs_iovec_done(&mut out);
        }
    }

    #[test]
    fn memdup_returns_empty_for_unset_sources() {
        let src = IoVec::default();
        let mut out = IoVec {
            iov_base: ptr::dangling_mut(),
            iov_len: 1,
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert!(!rs_iovec_memdup(&src, &mut out).is_null());
        }
        assert_eq!(out, IoVec::default());
    }

    #[test]
    fn memdup_allows_source_to_alias_result() {
        let mut iovec = IoVec {
            iov_base: b"hello world".as_ptr() as *mut c_void,
            iov_len: 11,
        };
        let iovec_ptr = &mut iovec as *mut IoVec;
        // SAFETY: the raw pointer is valid for both source and result. The C
        // API permits this aliasing and the implementation copies before it
        // writes the result back through the pointer.
        unsafe {
            assert_eq!(rs_iovec_memdup(iovec_ptr, iovec_ptr), iovec_ptr);
            assert_ne!(iovec.iov_base, b"hello world".as_ptr() as *mut c_void);
            assert_eq!(
                slice::from_raw_parts(iovec.iov_base.cast::<u8>(), iovec.iov_len),
                b"hello world"
            );
            rs_iovec_done(iovec_ptr);
        }
    }

    #[test]
    fn done_many_and_free_clears_allocated_entries() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let entries = [
                IoVec {
                    iov_base: alloc_test_bytes(b"ab"),
                    iov_len: 2,
                },
                IoVec {
                    iov_base: alloc_test_bytes(b"cd"),
                    iov_len: 2,
                },
            ];
            let ptr = alloc_iovec_array(&entries);
            rs_iovec_done_many_and_free(ptr, 2);
        }
    }
}
