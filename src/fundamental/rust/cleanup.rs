// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/cleanup-util.h
//
// RAII cleanup patterns for Rust. In Rust, Drop traits replace
// __attribute__((__cleanup__(x))) from C.

/// Cleanup guard that runs a closure when dropped.
/// PORT-SYNC: mirrors CLEANUP_ERASE / DEFINE_TRIVIAL_CLEANUP_FUNC patterns.
// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
pub struct CleanupGuard<F: FnOnce()> {
    f: core::mem::ManuallyDrop<Option<F>>,
}

impl<F: FnOnce()> CleanupGuard<F> {
    #[inline]
    pub fn new(f: F) -> Self {
        Self {
            f: core::mem::ManuallyDrop::new(Some(f)),
        }
    }

    /// Disarm the guard so the closure won't run on drop.
    #[inline]
    pub fn disarm(self) {
        // SAFETY: moving `self` into `ManuallyDrop` suppresses `Drop`, so the closure is intentionally not run.
        let _ = core::mem::ManuallyDrop::new(self);
    }
}

impl<F: FnOnce()> Drop for CleanupGuard<F> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: `self.f` is stored in `ManuallyDrop`; `ptr::read` moves it out exactly once without double-drop.
        if let Some(f) = unsafe_ffi!(core::ptr::read(&self.f as *const _ as *mut Option<F>)) {
            f();
        }
    }
}

/// Array cleanup helper — mirrors CLEANUP_ARRAY from C.
/// PORT-SYNC: ArrayCleanup struct + array_cleanup() from cleanup-util.h
pub struct ArrayCleanup<T, F: FnOnce(*mut T, usize)> {
    ptr: *mut T,
    len: usize,
    func: core::mem::ManuallyDrop<Option<F>>,
}

impl<T, F: FnOnce(*mut T, usize)> ArrayCleanup<T, F> {
    #[inline]
    pub fn new(ptr: *mut T, len: usize, func: F) -> Self {
        Self {
            ptr,
            len,
            func: core::mem::ManuallyDrop::new(Some(func)),
        }
    }

    /// Disarm — prevents cleanup on drop.
    #[inline]
    pub fn disarm(&mut self) {
        self.ptr = core::ptr::null_mut();
        self.len = 0;
    }
}

impl<T, F: FnOnce(*mut T, usize)> Drop for ArrayCleanup<T, F> {
    #[inline]
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `self.func` is stored in `ManuallyDrop`; `ptr::read` moves it out exactly once.
            if let Some(f) = unsafe_ffi!(core::ptr::read(&self.func as *const _ as *mut Option<F>))
            {
                f(self.ptr, self.len);
            }
        }
    }
}

/// TAKE_PTR equivalent — takes ownership of a value behind a mutable pointer,
/// leaving a default value in its place.
/// PORT-SYNC: mirrors TAKE_PTR / TAKE_STRUCT from macro.h
#[inline]
pub fn take_ptr<T: Default>(ptr: &mut *mut T) -> *mut T {
    core::mem::replace(ptr, core::ptr::null_mut())
}

/// TAKE_STRUCT equivalent — takes ownership of a value, leaving default.
#[inline]
pub fn take_struct<T: Default>(val: &mut T) -> T {
    core::mem::take(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    #[test]
    fn test_cleanup_guard_runs_on_drop() {
        let flag = core::cell::Cell::new(false);
        {
            let _guard = CleanupGuard::new(|| flag.set(true));
            assert!(!flag.get());
        }
        assert!(flag.get());
    }

    #[test]
    fn test_array_cleanup() {
        let freed = core::cell::Cell::new(false);
        let ptr = Box::into_raw(Box::new([1u8, 2, 3]));
        {
            let _cleanup = ArrayCleanup::new(ptr, 3, |p, _len| {
                freed.set(true);
                // SAFETY: the raw pointer was allocated for this exact type
                // and is reclaimed exactly once here.
                drop(unsafe_ffi!(Box::from_raw(p)));
            });
            assert!(!freed.get());
        }
        assert!(freed.get());
    }

    #[test]
    fn test_take_ptr() {
        let mut ptr: *mut u8 = Box::into_raw(Box::new(42));
        let taken = take_ptr(&mut ptr);
        assert!(!taken.is_null());
        assert!(ptr.is_null());
        // SAFETY: the raw pointer was allocated for this exact type and is reclaimed exactly once here.
        unsafe_ffi!(drop(Box::from_raw(taken)));
    }

    #[test]
    fn test_take_struct() {
        let mut val = Some(42);
        let taken = take_struct(&mut val);
        assert_eq!(taken, Some(42));
        assert_eq!(val, None);
    }
}
