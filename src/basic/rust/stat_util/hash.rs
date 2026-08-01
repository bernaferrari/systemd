// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h,src/basic/siphash24.h
//
// inode_hash_func and inode_unmodified_hash_func via canonical SipHash.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::marker::PhantomData;
use std::ptr::NonNull;

use super::inode::inode_type;
use super::{S_IFBLK, S_IFCHR, S_IFREG};

/// Opaque canonical C `struct siphash`.
///
/// Rust never constructs or dereferences this state. The canonical C
/// compressor owns its layout and mutation semantics.
#[repr(C)]
pub struct SipHashState {
    _private: [u8; 0],
}

// SAFETY: this is the exact declaration from siphash24.h; callers below pass
// readable native objects and a live opaque canonical state.
unsafe extern "C" {
    fn siphash24_compress(
        input: *const libc::c_void,
        input_length: usize,
        state: *mut SipHashState,
    );
}

struct SipHashCompressor<'a> {
    state: NonNull<SipHashState>,
    _borrow: PhantomData<&'a mut SipHashState>,
}

impl<'a> SipHashCompressor<'a> {
    // SAFETY: state must identify a uniquely borrowed live C struct siphash.
    unsafe fn from_raw(state: *mut SipHashState) -> Option<Self> {
        NonNull::new(state).map(|state| Self {
            state,
            _borrow: PhantomData,
        })
    }

    fn compress<T>(&mut self, value: &T) {
        // SAFETY: `value` is readable for its exact native size and `state`
        // is the unique live canonical C state captured at the ABI boundary.
        unsafe_ffi!({
            siphash24_compress(
                (value as *const T).cast::<libc::c_void>(),
                std::mem::size_of::<T>(),
                self.state.as_ptr(),
            )
        });
    }
}

fn inode_hash(stat: &libc::stat, state: &mut SipHashCompressor<'_>) {
    state.compress(&stat.st_dev);
    state.compress(&stat.st_ino);

    // Keep this as mode_t, matching C's local variable and typesafe macro.
    let file_type: libc::mode_t = inode_type(stat.st_mode);
    state.compress(&file_type);
}

fn inode_unmodified_hash(stat: &libc::stat, state: &mut SipHashCompressor<'_>) {
    inode_hash(stat, state);
    state.compress(&stat.st_mtime);
    state.compress(&stat.st_mtime_nsec);

    if inode_type(stat.st_mode) == S_IFREG as libc::mode_t {
        state.compress(&stat.st_size);
    } else {
        let invalid = u64::MAX;
        state.compress(&invalid);
    }

    if matches!(
        inode_type(stat.st_mode),
        value if value == S_IFCHR as libc::mode_t || value == S_IFBLK as libc::mode_t
    ) {
        state.compress(&stat.st_rdev);
    } else {
        let invalid: libc::dev_t = !0;
        state.compress(&invalid);
    }
}

/// C ABI mirror of `inode_hash_func()`.
///
/// # Safety
///
/// `stat` must point to a live native `struct stat`, and `state` must point to
/// a uniquely borrowed, initialized canonical C `struct siphash`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_inode_hash_func(stat: *const libc::stat, state: *mut SipHashState) {
    // SAFETY: both conversions are covered by the entry-point contract.
    let (Some(stat), Some(mut state)) = (unsafe_ffi!(stat.as_ref()), unsafe {
        SipHashCompressor::from_raw(state)
    }) else {
        return;
    };
    inode_hash(stat, &mut state);
}

/// C ABI mirror of `inode_unmodified_hash_func()`.
///
/// # Safety
///
/// `stat` and `state` have the same contracts as `rs_inode_hash_func`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_inode_unmodified_hash_func(
    stat: *const libc::stat,
    state: *mut SipHashState,
) {
    // SAFETY: both conversions are covered by the entry-point contract.
    let (Some(stat), Some(mut state)) = (unsafe_ffi!(stat.as_ref()), unsafe {
        SipHashCompressor::from_raw(state)
    }) else {
        return;
    };
    inode_unmodified_hash(stat, &mut state);
}
