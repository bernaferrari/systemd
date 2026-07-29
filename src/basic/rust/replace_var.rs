// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.replace-var; authority=src/basic/replace-var.c,src/basic/replace-var.h
//
// Generic infrastructure for replacing @FOO@ style variables in byte strings.

use libc::{c_char, c_void};
use std::ffi::CStr;
use std::ptr;

pub type ReplaceVarLookup = unsafe extern "C" fn(*const c_char, *mut c_void) -> *mut c_char;

/// Unique ownership of one allocation returned by the process C allocator.
///
/// This guard is used for the result buffer, temporary variable names, and
/// callback results. Keeping all three under the same guard makes every early
/// OOM and lookup-failure path release exactly the allocations it owns.
struct CAllocation {
    pointer: *mut c_char,
}

impl CAllocation {
    fn allocate(size: usize) -> Option<Self> {
        let pointer = crate::ffi::malloc(size).cast::<c_char>();
        (!pointer.is_null()).then_some(Self { pointer })
    }

    fn copy_c_string(bytes: &[u8]) -> Option<Self> {
        let allocation_size = bytes.len().checked_add(1)?;
        let allocation = Self::allocate(allocation_size)?;

        // SAFETY: `allocation` owns `bytes.len() + 1` writable bytes and the
        // source slice is live and non-overlapping. The last byte is in bounds.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr().cast::<c_char>(),
                allocation.pointer,
                bytes.len(),
            );
            *allocation.pointer.add(bytes.len()) = 0;
        }
        Some(allocation)
    }

    /// Adopt the allocation returned by `lookup`.
    ///
    /// # Safety
    /// `pointer` must be the unique base pointer of a live C-allocator
    /// allocation, and that allocation must contain a NUL-terminated string.
    unsafe fn from_callback(pointer: *mut c_char) -> Option<Self> {
        (!pointer.is_null()).then_some(Self { pointer })
    }

    fn as_ptr(&self) -> *const c_char {
        self.pointer
    }

    /// Borrow the non-NUL bytes of this allocation as a C string.
    ///
    /// # Safety
    /// The allocation must contain a NUL-terminated string.
    unsafe fn to_bytes(&self) -> &[u8] {
        // SAFETY: upheld by the method's contract, and the returned borrow
        // cannot outlive `self`.
        unsafe { CStr::from_ptr(self.pointer) }.to_bytes()
    }

    fn realloc(&mut self, size: usize) -> bool {
        // SAFETY: `self.pointer` is the unique live base pointer of this
        // C-allocator allocation. On failure realloc leaves it untouched.
        let replacement = unsafe { crate::ffi::realloc(self.pointer.cast(), size) }.cast();
        if replacement.is_null() {
            return false;
        }

        self.pointer = replacement;
        true
    }

    fn into_raw(mut self) -> *mut c_char {
        let pointer = self.pointer;
        self.pointer = ptr::null_mut();
        pointer
    }
}

impl Drop for CAllocation {
    fn drop(&mut self) {
        // SAFETY: a non-null `pointer` is uniquely owned by this guard and was
        // allocated by the process C allocator. `free(NULL)` is also valid.
        unsafe { crate::ffi::free(self.pointer.cast()) };
    }
}

fn variable_length(input: &[u8], offset: usize) -> Option<usize> {
    if input.get(offset) != Some(&b'@') {
        return None;
    }

    let start = offset + 1;
    let mut end = start;
    while input
        .get(end)
        .is_some_and(|byte| byte.is_ascii_uppercase() || *byte == b'_')
    {
        end += 1;
    }

    (end > start && input.get(end) == Some(&b'@')).then_some(end - start)
}

/// C ABI twin of `replace_var()`.
///
/// The implementation intentionally operates on C-string bytes rather than
/// UTF-8. Each callback result is adopted immediately and freed after it is
/// copied, including when a later operation fails. A successful result uses
/// the process C allocator and is owned by the caller.
///
/// # Safety
/// `text` must be a non-null live NUL-terminated string. `lookup` must be
/// non-null, matching the two `assert()` preconditions of the C function.
/// During each call, the variable argument is borrowed and valid only until
/// the callback returns. A non-null callback result must be a unique live
/// C-allocator allocation containing a NUL-terminated string; its ownership
/// transfers to this function and it must not be retained or freed elsewhere.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_replace_var(
    text: *const c_char,
    lookup: Option<ReplaceVarLookup>,
    userdata: *mut c_void,
) -> *mut c_char {
    if text.is_null() {
        std::process::abort();
    }
    let lookup = match lookup {
        Some(lookup) => lookup,
        None => std::process::abort(),
    };

    // SAFETY: `text` satisfies the live NUL-terminated-string contract above.
    let input = unsafe { CStr::from_ptr(text) }.to_bytes();
    let Some(initial_size) = input.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let Some(mut output) = CAllocation::allocate(initial_size) else {
        return ptr::null_mut();
    };

    let mut input_offset = 0;
    let mut output_offset = 0;
    let mut output_length = input.len();

    while input_offset < input.len() {
        let Some(name_length) = variable_length(input, input_offset) else {
            // SAFETY: the output allocation has `output_length + 1` bytes and
            // the untranslated suffix guarantees `output_offset < output_length`.
            unsafe {
                *output.pointer.add(output_offset) = input[input_offset] as c_char;
            }
            input_offset += 1;
            output_offset += 1;
            continue;
        };

        let name_start = input_offset + 1;
        let Some(variable) =
            CAllocation::copy_c_string(&input[name_start..name_start + name_length])
        else {
            return ptr::null_mut();
        };

        // SAFETY: `variable` is a live NUL-terminated temporary. The callback
        // and userdata obey the caller-provided FFI contract.
        let replacement_pointer = unsafe { lookup(variable.as_ptr(), userdata) };
        // SAFETY: a non-null callback result transfers the allocation contract
        // documented on `rs_replace_var`; null denotes lookup failure.
        let Some(replacement) = (unsafe { CAllocation::from_callback(replacement_pointer) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the adopted callback result is required to be NUL-terminated.
        let replacement_bytes = unsafe { replacement.to_bytes() };

        let skip = name_length + 2;
        let Some(new_length) = output_length
            .checked_sub(skip)
            .and_then(|length| length.checked_add(replacement_bytes.len()))
        else {
            return ptr::null_mut();
        };
        let Some(new_size) = new_length.checked_add(1) else {
            return ptr::null_mut();
        };
        if !output.realloc(new_size) {
            return ptr::null_mut();
        }
        output_length = new_length;

        // SAFETY: realloc produced `output_length + 1` writable bytes. The C
        // length calculation guarantees the replacement fits at
        // `output_offset`; the source callback allocation is distinct and live.
        unsafe {
            ptr::copy_nonoverlapping(
                replacement_bytes.as_ptr().cast::<c_char>(),
                output.pointer.add(output_offset),
                replacement_bytes.len(),
            );
        }
        output_offset += replacement_bytes.len();
        input_offset += skip;
    }

    // SAFETY: the replacement accounting mirrors the C loop, so the cursor is
    // exactly the final content length and the allocation has its suffix byte.
    unsafe {
        *output.pointer.add(output_offset) = 0;
    }
    output.into_raw()
}
