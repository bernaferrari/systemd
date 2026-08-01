// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/iovec-util.h
//
// I/O vector utilities.

/// A single I/O vector entry.
/// PORT-SYNC: mirrors struct iovec from POSIX / EFI mode.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Iovec {
    pub iov_base: *mut u8,
    pub iov_len: usize,
}

impl Iovec {
    /// Create a new Iovec from a pointer and length.
    #[inline]
    pub const fn new(base: *mut u8, len: usize) -> Self {
        Self {
            iov_base: base,
            iov_len: len,
        }
    }

    /// Create a new Iovec from a const pointer.
    #[inline]
    pub const fn from_const(base: *const u8, len: usize) -> Self {
        Self {
            iov_base: base as *mut u8,
            iov_len: len,
        }
    }

    /// Create a new Iovec from a slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            iov_base: slice.as_ptr() as *mut u8,
            iov_len: slice.len(),
        }
    }

    /// Check if the iovec points to a non-empty chunk of memory.
    /// PORT-SYNC: mirrors iovec_is_set()
    #[inline]
    pub fn is_set(&self) -> bool {
        !self.iov_base.is_null() && self.iov_len > 0
    }

    /// Check if the iovec is valid (either NULL, empty, or points to valid memory).
    /// PORT-SYNC: mirrors iovec_is_valid()
    #[inline]
    pub fn is_valid(&self) -> bool {
        if self.iov_base.is_null() {
            self.iov_len == 0
        } else {
            true
        }
    }

    /// Reset the iovec to empty.
    /// PORT-SYNC: mirrors iovec_done()
    #[inline]
    pub fn done(&mut self) {
        self.iov_base = core::ptr::null_mut();
        self.iov_len = 0;
    }

    /// Return the configured region as a shared byte slice.
    ///
    /// # Safety
    ///
    /// For a set vector, `iov_base` must be non-null, aligned for `u8`, and
    /// readable for `iov_len` bytes. The memory must remain alive and must not
    /// be mutated for the returned lifetime except through `UnsafeCell`.
    #[inline]
    pub unsafe fn as_slice(&self) -> Option<&[u8]> {
        if self.is_set() {
            // SAFETY: the caller upholds the allocation, lifetime, and aliasing
            // requirements for this exact region.
            Some(unsafe_ffi!(core::slice::from_raw_parts(
                self.iov_base,
                self.iov_len
            )))
        } else {
            None
        }
    }

    /// Return as a mutable byte slice.
    ///
    /// # Safety
    ///
    /// For a set vector, `iov_base` must be non-null, aligned for `u8`, and
    /// exclusively writable for `iov_len` bytes. The memory must remain alive
    /// for the returned lifetime.
    #[inline]
    pub unsafe fn as_slice_mut(&mut self) -> Option<&mut [u8]> {
        if self.is_set() {
            // SAFETY: the caller upholds the allocation, lifetime, and
            // exclusive-access requirements for this exact region.
            Some(unsafe_ffi!(core::slice::from_raw_parts_mut(
                self.iov_base,
                self.iov_len
            )))
        } else {
            None
        }
    }
}

/// Free an array of iovecs and their bases.
/// PORT-SYNC: mirrors iovec_done_many_and_free()
///
/// # Safety
///
/// For nonzero `n`, `iovecs` must be a uniquely owned allocation of exactly
/// `n` contiguous `Iovec` values made with Rust's global allocator. Every
/// non-null `iov_base` must likewise be uniquely owned, allocated by the
/// global allocator with size `iov_len` and alignment 1, and appear at most
/// once in the array.
#[cfg(feature = "alloc")]
pub unsafe fn iovec_done_many_and_free(iovecs: *mut Iovec, n: usize) {
    if n > 0 && !iovecs.is_null() {
        for i in 0..n {
            // SAFETY: the caller guarantees an exclusive `n`-element array.
            let iov = unsafe_ffi!(&mut *iovecs.add(i));
            if !iov.iov_base.is_null() {
                // SAFETY: the caller guarantees this exact global-allocation
                // provenance and layout, and every base appears only once.
                unsafe_ffi!({
                    alloc::alloc::dealloc(
                        iov.iov_base,
                        alloc::alloc::Layout::from_size_align_unchecked(iov.iov_len, 1),
                    );
                })
            }
            iov.iov_base = core::ptr::null_mut();
            iov.iov_len = 0;
        }
        // SAFETY: the caller guarantees `iovecs` came from the global
        // allocator with the exact `n`-element array layout.
        unsafe_ffi!({
            alloc::alloc::dealloc(
                iovecs.cast::<u8>(),
                alloc::alloc::Layout::array::<Iovec>(n).unwrap(),
            );
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iovec_new() {
        let mut buf = [1u8, 2, 3];
        let iov = Iovec::new(buf.as_mut_ptr(), 3);
        assert_eq!(iov.iov_len, 3);
    }

    #[test]
    fn test_iovec_from_slice() {
        let buf = [1u8, 2, 3, 4];
        let iov = Iovec::from_slice(&buf);
        assert_eq!(iov.iov_len, 4);
    }

    #[test]
    fn test_iovec_is_set() {
        let mut buf = [0u8; 4];
        let iov = Iovec::new(buf.as_mut_ptr(), 4);
        assert!(iov.is_set());

        let empty = Iovec::new(core::ptr::null_mut(), 0);
        assert!(!empty.is_set());
    }

    #[test]
    fn test_iovec_is_valid() {
        let null_iov = Iovec::new(core::ptr::null_mut(), 0);
        assert!(null_iov.is_valid());

        let mut buf = [0u8; 4];
        let iov = Iovec::new(buf.as_mut_ptr(), 4);
        assert!(iov.is_valid());
    }

    #[test]
    fn test_iovec_done() {
        let mut buf = [0u8; 4];
        let mut iov = Iovec::new(buf.as_mut_ptr(), 4);
        assert!(iov.is_set());
        iov.done();
        assert!(!iov.is_set());
        assert_eq!(iov.iov_len, 0);
    }
}
