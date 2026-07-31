// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.iovec-wrapper; authority=src/basic/alloc-util.c,src/basic/alloc-util.h,src/basic/iovec-util.c,src/basic/iovec-util.h,src/basic/iovec-wrapper.c,src/basic/iovec-wrapper.h

use crate::ffi::Errno;
use libc::{c_int, c_void, iovec};
use std::ptr;

const IOV_MAX: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoVec {
    pub iov_base: usize,
    pub iov_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoVecBuffer {
    bytes: Box<[u8]>,
    view_base: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IoVecWrapper {
    buffers: Vec<IoVecBuffer>,
}

/// Exact C-layout shadow of `struct iovec_wrapper`.
///
/// This is intentionally separate from [`IoVecWrapper`]: C's type stores
/// borrowed raw buffers in a libc-allocated iovec array, while the safe Rust
/// model owns its buffers.
#[repr(C)]
pub struct RsIoVecWrapper {
    pub iovec: *mut iovec,
    pub count: usize,
}

impl RsIoVecWrapper {
    // The exported C ABI functions validate the wrapper representation before
    // entering this private core, which can work with safe iovec slices.
    fn entries(&self) -> Option<&[iovec]> {
        if self.count == 0 {
            return Some(&[]);
        }
        if self.iovec.is_null() {
            return None;
        }
        // SAFETY: the C ABI wrapper contract provides `count` live entries.
        Some(unsafe { std::slice::from_raw_parts(self.iovec, self.count) })
    }

    fn entries_mut(&mut self) -> Option<&mut [iovec]> {
        if self.count == 0 {
            return Some(&mut []);
        }
        if self.iovec.is_null() {
            return None;
        }
        // SAFETY: the C ABI wrapper contract provides exclusive access to
        // `count` live entries.
        Some(unsafe { std::slice::from_raw_parts_mut(self.iovec, self.count) })
    }

    fn done(&mut self, free_buffers: bool) {
        if free_buffers {
            if let Some(entries) = self.entries_mut() {
                for entry in entries {
                    // SAFETY: the caller's C ownership contract makes every
                    // non-null base a libc allocation when requested.
                    unsafe { libc::free(entry.iov_base) };
                    entry.iov_base = ptr::null_mut();
                    entry.iov_len = 0;
                }
            }
        }

        // SAFETY: NULL is accepted and a non-NULL iovec array is libc-owned.
        unsafe { libc::free(self.iovec.cast()) };
        self.iovec = ptr::null_mut();
        self.count = 0;
    }

    fn put(&mut self, data: *mut c_void, len: usize) -> Result<(), c_int> {
        if self.count >= IOV_MAX {
            return Err(-libc::E2BIG);
        }
        let new_count = self.count + 1;
        let Some(bytes) = new_count.checked_mul(std::mem::size_of::<iovec>()) else {
            return Err(-libc::E2BIG);
        };
        // SAFETY: NULL is accepted; otherwise the existing iovec array is
        // libc-owned. A failing realloc preserves the current allocation.
        let allocation = unsafe { libc::realloc(self.iovec.cast(), bytes) }.cast::<iovec>();
        if allocation.is_null() {
            return Err(-libc::ENOMEM);
        }

        self.iovec = allocation;
        self.count = new_count;
        self.entries_mut()
            .expect("new iovec allocation is non-null")[new_count - 1] = iovec {
            iov_base: data,
            iov_len: len,
        };
        Ok(())
    }

    fn rebase(&mut self, old: *mut c_void, new: *mut c_void) {
        let old = old as usize;
        let new = new as usize;
        let Some(entries) = self.entries_mut() else {
            return;
        };
        for entry in entries {
            if entry.iov_base.is_null() {
                continue;
            }
            let Some(offset) = (entry.iov_base as usize).checked_sub(old) else {
                continue;
            };
            let Some(rebased) = new.checked_add(offset) else {
                continue;
            };
            entry.iov_base = rebased as *mut c_void;
        }
    }

    fn size(&self) -> Option<usize> {
        self.entries()?
            .iter()
            .try_fold(0_usize, |total, entry| total.checked_add(entry.iov_len))
    }
}

impl IoVecBuffer {
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        let bytes = bytes.into();
        let view_base = bytes.as_ptr() as usize;
        Self { bytes, view_base }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_iovec(&self) -> IoVec {
        IoVec {
            iov_base: self.view_base,
            iov_len: self.bytes.len(),
        }
    }
}

impl IoVecWrapper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn done(self) -> Vec<Box<[u8]>> {
        self.buffers
            .into_iter()
            .map(|buffer| buffer.bytes)
            .collect()
    }

    pub fn done_free(self) {}

    pub fn free(self) -> Vec<Box<[u8]>> {
        self.done()
    }

    pub fn free_free(self) {}

    pub fn put(&mut self, buffer: IoVecBuffer) -> Result<(), Errno> {
        if buffer.is_empty() {
            return Ok(());
        }

        if self.buffers.len() >= IOV_MAX {
            return Err(Errno::E2BIG);
        }

        self.buffers.push(buffer);
        Ok(())
    }

    pub fn rebase(&mut self, old: usize, new: usize) {
        for buffer in &mut self.buffers {
            buffer.view_base = buffer.view_base.wrapping_sub(old).wrapping_add(new);
        }
    }

    pub fn size(&self) -> usize {
        self.buffers.iter().map(IoVecBuffer::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    pub fn count(&self) -> usize {
        self.buffers.len()
    }

    pub fn iovecs(&self) -> Vec<IoVec> {
        self.buffers.iter().map(IoVecBuffer::as_iovec).collect()
    }

    pub fn append(&mut self, source: &Self) -> Result<(), Errno> {
        if source.is_empty() {
            return Ok(());
        }

        if self.count().saturating_add(source.count()) > IOV_MAX {
            return Err(Errno::E2BIG);
        }

        self.buffers.extend(source.buffers.iter().cloned());
        Ok(())
    }
}

// ── C ABI shadow facade ──────────────────────────────────────────────────

/// Release the iovec array and optionally each entry's libc-owned buffer.
///
/// # Safety
///
/// `iovw` must point to a live, initialized, exclusively accessible
/// `RsIoVecWrapper`. Its iovec array must have been allocated by libc. When
/// `free_buffers` is true, every non-NULL base must also be libc-owned.
fn ffi_done(iovw: *mut RsIoVecWrapper, free_buffers: bool) {
    // SAFETY: callers are the audited C ABI adapters below.
    let wrapper = unsafe { &mut *iovw };
    wrapper.done(free_buffers);
}

/// Release only the libc-allocated iovec array.
///
/// # Safety
///
/// `iovw` must point to a live, initialized, exclusively accessible
/// `RsIoVecWrapper` whose array was allocated by libc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_iovw_done(iovw: *mut RsIoVecWrapper) {
    if iovw.is_null() {
        return;
    }

    ffi_done(iovw, false);
}

/// Release every libc-owned buffer and then the iovec array.
///
/// # Safety
///
/// `iovw` must satisfy [`rs_iovw_done`]'s requirements, and every non-NULL
/// iovec base must be owned by libc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_iovw_done_free(iovw: *mut RsIoVecWrapper) {
    if iovw.is_null() {
        return;
    }

    ffi_done(iovw, true);
}

/// Release the iovec array and its libc-owned wrapper, returning NULL.
///
/// # Safety
///
/// A non-NULL `iovw` must be a libc-owned `RsIoVecWrapper` satisfying
/// [`rs_iovw_done`]'s requirements.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_iovw_free(iovw: *mut RsIoVecWrapper) -> *mut RsIoVecWrapper {
    if iovw.is_null() {
        return ptr::null_mut();
    }

    ffi_done(iovw, false);
    // SAFETY: the wrapper itself is libc-owned by contract.
    unsafe { libc::free(iovw.cast()) };
    ptr::null_mut()
}

/// Release every owned buffer, the iovec array, and the wrapper, returning
/// NULL.
///
/// # Safety
///
/// A non-NULL `iovw` must be a libc-owned `RsIoVecWrapper` satisfying
/// [`rs_iovw_done_free`]'s requirements.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_iovw_free_free(iovw: *mut RsIoVecWrapper) -> *mut RsIoVecWrapper {
    if iovw.is_null() {
        return ptr::null_mut();
    }

    ffi_done(iovw, true);
    // SAFETY: the wrapper itself is libc-owned by contract.
    unsafe { libc::free(iovw.cast()) };
    ptr::null_mut()
}

/// Append a borrowed buffer to the iovec array.
///
/// Returns `1` when appended, `0` for a zero-length no-op, or a negative errno.
///
/// # Safety
///
/// `iovw` must point to a live, initialized, exclusively accessible
/// `RsIoVecWrapper` whose array is NULL or libc-owned. `data` must be non-NULL
/// when `len` is nonzero and remain valid for the wrapper's use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_iovw_put(
    iovw: *mut RsIoVecWrapper,
    data: *mut c_void,
    len: usize,
) -> c_int {
    if iovw.is_null() || (len > 0 && data.is_null()) {
        return -libc::EINVAL;
    }
    if len == 0 {
        return 0;
    }

    // SAFETY: required by this entry point's exclusive wrapper contract.
    let wrapper = unsafe { &mut *iovw };
    match wrapper.put(data, len) {
        Ok(()) => 1,
        Err(error) => error,
    }
}

/// Rebase every borrowed iovec from `old` to the corresponding offset at
/// `new`.
///
/// # Safety
///
/// `iovw` must point to a live, initialized, exclusively accessible wrapper.
/// Every base and `old` must belong to the same allocation with base at or
/// after `old`; each corresponding offset from `new` must remain within the
/// allocation rooted at `new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_iovw_rebase(
    iovw: *mut RsIoVecWrapper,
    old: *mut c_void,
    new: *mut c_void,
) {
    if iovw.is_null() || old.is_null() || new.is_null() {
        return;
    }

    // SAFETY: required by this entry point's exclusive wrapper contract.
    unsafe { (&mut *iovw).rebase(old, new) };
}

/// Return the sum of the iovec lengths, or `SIZE_MAX` on overflow.
///
/// # Safety
///
/// A non-NULL `iovw` must point to a live initialized wrapper, and a nonzero
/// count requires a live array of that many iovecs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_iovw_size(iovw: *const RsIoVecWrapper) -> usize {
    if iovw.is_null() {
        return 0;
    }

    // SAFETY: required by this entry point's wrapper contract.
    unsafe { (&*iovw).size().unwrap_or(usize::MAX) }
}

/// Return whether a wrapper is NULL or has no entries.
///
/// # Safety
///
/// A non-NULL `iovw` must point to a live initialized wrapper.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_iovw_isempty(iovw: *const RsIoVecWrapper) -> bool {
    if iovw.is_null() {
        return true;
    }

    // SAFETY: required by this entry point's wrapper contract.
    unsafe { (&*iovw).count == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer(bytes: &[u8]) -> IoVecBuffer {
        IoVecBuffer::new(bytes.to_vec().into_boxed_slice())
    }

    #[test]
    fn new_wrapper_is_empty() {
        let wrapper = IoVecWrapper::new();
        assert!(wrapper.is_empty());
        assert_eq!(wrapper.count(), 0);
        assert_eq!(wrapper.size(), 0);
    }

    #[test]
    fn put_adds_non_empty_buffer() {
        let mut wrapper = IoVecWrapper::new();
        wrapper.put(buffer(b"abc")).unwrap();
        assert_eq!(wrapper.count(), 1);
        assert_eq!(wrapper.size(), 3);
    }

    #[test]
    fn put_ignores_empty_buffer() {
        let mut wrapper = IoVecWrapper::new();
        wrapper.put(buffer(b"")).unwrap();
        assert!(wrapper.is_empty());
    }

    #[test]
    fn put_enforces_iov_max() {
        let mut wrapper = IoVecWrapper::new();
        for _ in 0..IOV_MAX {
            wrapper.put(buffer(b"x")).unwrap();
        }
        assert_eq!(wrapper.put(buffer(b"overflow")), Err(Errno::E2BIG));
    }

    #[test]
    fn rebase_adjusts_all_view_bases() {
        let mut wrapper = IoVecWrapper::new();
        wrapper.put(buffer(b"abc")).unwrap();
        wrapper.put(buffer(b"de")).unwrap();

        let before = wrapper.iovecs();
        wrapper.rebase(before[0].iov_base - 4, 1000);
        let after = wrapper.iovecs();

        assert_eq!(after[0].iov_base, 1004);
        assert_eq!(
            after[1].iov_base,
            before[1]
                .iov_base
                .wrapping_sub(before[0].iov_base - 4)
                .wrapping_add(1000)
        );
    }

    #[test]
    fn done_returns_owned_buffers_without_freeing_them() {
        let mut wrapper = IoVecWrapper::new();
        wrapper.put(buffer(b"hello")).unwrap();
        wrapper.put(buffer(b"world")).unwrap();

        let buffers = wrapper.done();
        assert_eq!(buffers.len(), 2);
        assert_eq!(&*buffers[0], b"hello");
        assert_eq!(&*buffers[1], b"world");
    }

    #[test]
    fn append_duplicates_source_buffers() {
        let mut target = IoVecWrapper::new();
        let mut source = IoVecWrapper::new();
        target.put(buffer(b"a")).unwrap();
        source.put(buffer(b"bc")).unwrap();
        source.put(buffer(b"def")).unwrap();

        target.append(&source).unwrap();

        assert_eq!(target.size(), 6);
        assert_eq!(source.size(), 5);
        assert_eq!(target.count(), 3);
    }

    #[test]
    fn append_rejects_overflow() {
        let mut target = IoVecWrapper::new();
        let mut source = IoVecWrapper::new();

        for _ in 0..IOV_MAX {
            target.put(buffer(b"x")).unwrap();
        }
        source.put(buffer(b"y")).unwrap();

        assert_eq!(target.append(&source), Err(Errno::E2BIG));
    }

    #[test]
    fn free_matches_done_semantics() {
        let mut wrapper = IoVecWrapper::new();
        wrapper.put(buffer(b"xyz")).unwrap();

        let buffers = wrapper.free();
        assert_eq!(buffers.len(), 1);
        assert_eq!(&*buffers[0], b"xyz");
    }

    #[test]
    fn iovecs_reflect_current_layout() {
        let mut wrapper = IoVecWrapper::new();
        wrapper.put(buffer(b"12")).unwrap();
        wrapper.put(buffer(b"345")).unwrap();

        let iovecs = wrapper.iovecs();
        assert_eq!(iovecs.len(), 2);
        assert_eq!(iovecs[0].iov_len, 2);
        assert_eq!(iovecs[1].iov_len, 3);
    }
}
