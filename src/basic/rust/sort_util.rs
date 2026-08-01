// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.sort-util; authority=src/basic/sort-util.c,src/basic/sort-util.h

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::cmp::Ordering;
use std::ffi::c_void;

use libc::c_int;

fn ordering_to_c_value(ordering: Ordering) -> i32 {
    match ordering {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

pub fn cmp_int(a: i32, b: i32) -> i32 {
    ordering_to_c_value(a.cmp(&b))
}

pub fn cmp_uint16(a: u16, b: u16) -> i32 {
    ordering_to_c_value(a.cmp(&b))
}

pub fn qsort_safe<T, F>(data: &mut [T], mut compar: F)
where
    F: FnMut(&T, &T) -> Ordering,
{
    if data.len() <= 1 {
        return;
    }

    data.sort_unstable_by(|left, right| compar(left, right));
}

pub fn qsort_r_safe<T, U, F>(data: &mut [T], userdata: &mut U, mut compar: F)
where
    F: FnMut(&T, &T, &mut U) -> Ordering,
{
    if data.len() <= 1 {
        return;
    }

    for i in 1..data.len() {
        let mut j = i;
        while j > 0 {
            let should_swap = {
                let left = &data[j - 1];
                let right = &data[j];
                compar(left, right, userdata) == Ordering::Greater
            };

            if !should_swap {
                break;
            }

            data.swap(j - 1, j);
            j -= 1;
        }
    }
}

pub fn bsearch_safe<T, F>(key: &T, data: &[T], mut compar: F) -> Option<usize>
where
    F: FnMut(&T, &T) -> Ordering,
{
    if data.is_empty() {
        return None;
    }

    data.binary_search_by(|probe| compar(probe, key)).ok()
}

pub fn xbsearch_r<T, U, F>(key: &T, data: &[T], userdata: &U, mut compar: F) -> Option<usize>
where
    F: FnMut(&T, &T, &U) -> Ordering,
{
    let mut lower = 0;
    let mut upper = data.len();

    while lower < upper {
        let index = (lower + upper) / 2;
        match compar(key, &data[index], userdata) {
            Ordering::Less => upper = index,
            Ordering::Greater => lower = index + 1,
            Ordering::Equal => return Some(index),
        }
    }

    None
}

// ── Raw C ABI facades ────────────────────────────────────────────────────

/// Exact C callback types. Callback arguments deliberately stay raw: callers
/// decide the element layout through the `size` argument, just as in C.
pub type ComparisonFn = Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>;
pub type ComparisonUserdataFn =
    Option<unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int>;

/// # Safety
///
/// `base` must start a live `nmemb * size` byte array, and `index < nmemb`.
/// The multiplication has been checked by the caller.
unsafe fn element_at(base: *const u8, index: usize, size: usize) -> *const c_void {
    // SAFETY: upheld by this helper's contract; the offset is checked before
    // the caller enters the search or sort loop.
    unsafe_ffi!(base.add(index * size).cast())
}

/// Binary-search raw C elements using the exact lower/upper-bound algorithm
/// from C `xbsearch_r()`.
///
/// # Safety
///
/// When `nmemb > 0`, `key` and `base` must be live and `base` must name
/// `nmemb * size` readable bytes. `compar` must be a live C callback that does
/// not retain its borrowed pointers; `arg` follows that callback's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_xbsearch_r(
    key: *const c_void,
    base: *const c_void,
    nmemb: usize,
    size: usize,
    compar: ComparisonUserdataFn,
    arg: *mut c_void,
) -> *mut c_void {
    if nmemb == 0 {
        return std::ptr::null_mut();
    }
    let Some(compar) = compar else {
        return std::ptr::null_mut();
    };
    if size == 0 || nmemb.checked_mul(size).is_none() || key.is_null() || base.is_null() {
        return std::ptr::null_mut();
    }

    let mut lower = 0usize;
    let mut upper = nmemb;
    let base = base.cast::<u8>();
    while lower < upper {
        let index = (lower + upper) / 2;
        // SAFETY: checked total byte size and index bounds make this an
        // in-allocation element pointer for the synchronous callback.
        let element = unsafe_ffi!(element_at(base, index, size));
        // SAFETY: caller supplies a valid C comparator and its userdata.
        let comparison = unsafe_ffi!(compar(key, element, arg));
        if comparison < 0 {
            upper = index;
        } else if comparison > 0 {
            lower = index + 1;
        } else {
            return element.cast_mut();
        }
    }
    std::ptr::null_mut()
}

/// Sort raw fixed-width C elements without interpreting their layout.
///
/// # Safety
///
/// For `nmemb > 1`, `base` must name a unique, writable `nmemb * size` byte
/// array, `size` must be nonzero, and `compar` must be a live strict-weak C
/// comparator that neither retains nor mutates its borrowed element pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_qsort_safe(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: ComparisonFn,
) {
    if nmemb <= 1 {
        return;
    }
    let Some(compar) = compar else {
        return;
    };
    if base.is_null() || size == 0 || nmemb.checked_mul(size).is_none() {
        return;
    }

    let base = base.cast::<u8>();
    for index in 1..nmemb {
        let mut cursor = index;
        while cursor > 0 {
            // SAFETY: the checked array extent and loop bounds produce two
            // distinct, in-allocation elements for the callback and swap.
            let (left, right) = unsafe_ffi!({
                (
                    element_at(base.cast_const(), cursor - 1, size),
                    element_at(base.cast_const(), cursor, size),
                )
            });
            // SAFETY: the comparator contract covers these borrowed elements.
            if unsafe_ffi!(compar(left, right)) <= 0 {
                break;
            }
            // SAFETY: left/right denote distinct `size`-byte elements in the
            // uniquely writable array; swapping preserves opaque bytes.
            unsafe_ffi!({
                std::ptr::swap_nonoverlapping(
                    base.add((cursor - 1) * size),
                    base.add(cursor * size),
                    size,
                )
            });
            cursor -= 1;
        }
    }
}

/// Raw-byte userdata sort equivalent to C `qsort_r_safe()`.
///
/// # Safety
///
/// This has the same array requirements as [`rs_qsort_safe`]. `compar` and
/// `userdata` must additionally satisfy `comparison_userdata_fn_t` and must
/// not retain, free, or re-enter the array during comparison.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_qsort_r_safe(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: ComparisonUserdataFn,
    userdata: *mut c_void,
) {
    if nmemb <= 1 {
        return;
    }
    let Some(compar) = compar else {
        return;
    };
    if base.is_null() || size == 0 || nmemb.checked_mul(size).is_none() {
        return;
    }

    let base = base.cast::<u8>();
    for index in 1..nmemb {
        let mut cursor = index;
        while cursor > 0 {
            // SAFETY: the checked extent and loop bounds keep both elements
            // within the array and distinct.
            let (left, right) = unsafe_ffi!({
                (
                    element_at(base.cast_const(), cursor - 1, size),
                    element_at(base.cast_const(), cursor, size),
                )
            });
            // SAFETY: caller upholds the callback and userdata contract.
            if unsafe_ffi!(compar(left, right, userdata)) <= 0 {
                break;
            }
            // SAFETY: distinct fixed-width elements of a unique byte array.
            unsafe_ffi!({
                std::ptr::swap_nonoverlapping(
                    base.add((cursor - 1) * size),
                    base.add(cursor * size),
                    size,
                )
            });
            cursor -= 1;
        }
    }
}

/// Search raw C elements. The returned pointer aliases `base` and is never
/// allocated or transferred.
///
/// # Safety
///
/// When `nmemb > 0`, `key` and `base` must be live and `base` must name
/// `nmemb * size` readable bytes. `compar` must be a live synchronous C
/// comparator for the supplied opaque elements.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bsearch_safe_internal(
    key: *const c_void,
    base: *const c_void,
    nmemb: usize,
    size: usize,
    compar: ComparisonFn,
) -> *mut c_void {
    if nmemb == 0 {
        return std::ptr::null_mut();
    }
    let Some(compar) = compar else {
        return std::ptr::null_mut();
    };
    if size == 0 || nmemb.checked_mul(size).is_none() || key.is_null() || base.is_null() {
        return std::ptr::null_mut();
    }

    let mut lower = 0usize;
    let mut upper = nmemb;
    let base = base.cast::<u8>();
    while lower < upper {
        let index = (lower + upper) / 2;
        // SAFETY: checked total byte size and index bounds identify the raw element.
        let element = unsafe_ffi!(element_at(base, index, size));
        // SAFETY: caller supplies a valid comparator for this key/element pair.
        let comparison = unsafe_ffi!(compar(key, element));
        if comparison < 0 {
            upper = index;
        } else if comparison > 0 {
            lower = index + 1;
        } else {
            return element.cast_mut();
        }
    }
    std::ptr::null_mut()
}

/// Compare two native C `int` values without subtraction overflow.
///
/// # Safety
///
/// `a` and `b` must be aligned, initialized, live `int` objects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cmp_int(a: *const c_int, b: *const c_int) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }
    // SAFETY: upheld by this export's operand contract.
    let (a, b) = unsafe_ffi!((*a, *b));
    ordering_to_c_value(a.cmp(&b))
}

/// Compare two native C `uint16_t` values without subtraction overflow.
///
/// # Safety
///
/// `a` and `b` must be aligned, initialized, live `uint16_t` objects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cmp_uint16(a: *const u16, b: *const u16) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }
    // SAFETY: upheld by this export's operand contract.
    let (a, b) = unsafe_ffi!((*a, *b));
    ordering_to_c_value(a.cmp(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_int_matches_c_cmp_macro() {
        assert_eq!(cmp_int(1, 2), -1);
        assert_eq!(cmp_int(2, 2), 0);
        assert_eq!(cmp_int(3, 2), 1);
    }

    #[test]
    fn cmp_uint16_matches_c_cmp_macro() {
        assert_eq!(cmp_uint16(0, 1), -1);
        assert_eq!(cmp_uint16(7, 7), 0);
        assert_eq!(cmp_uint16(9, 7), 1);
    }

    #[test]
    fn qsort_safe_is_noop_for_trivial_inputs() {
        let mut empty: [i32; 0] = [];
        qsort_safe(&mut empty, |a, b| a.cmp(b));
        assert_eq!(empty, []);

        let mut one = [5];
        qsort_safe(&mut one, |a, b| a.cmp(b));
        assert_eq!(one, [5]);
    }

    #[test]
    fn qsort_safe_sorts_using_callback() {
        let mut values = [3, 1, 4, 1, 5, 9];
        qsort_safe(&mut values, |a, b| a.cmp(b));
        assert_eq!(values, [1, 1, 3, 4, 5, 9]);
    }

    #[test]
    fn qsort_safe_supports_reverse_order() {
        let mut values = [1, 2, 3, 4];
        qsort_safe(&mut values, |a, b| b.cmp(a));
        assert_eq!(values, [4, 3, 2, 1]);
    }

    #[test]
    fn qsort_r_safe_threads_userdata_through_comparator() {
        let mut values = [1, 4, 2, 3];
        let mut descending = true;
        qsort_r_safe(&mut values, &mut descending, |a, b, descending| {
            if *descending { b.cmp(a) } else { a.cmp(b) }
        });
        assert_eq!(values, [4, 3, 2, 1]);
    }

    #[test]
    fn bsearch_safe_finds_existing_elements() {
        let values = [1, 3, 5, 7, 9];
        assert_eq!(bsearch_safe(&1, &values, |a, b| a.cmp(b)), Some(0));
        assert_eq!(bsearch_safe(&5, &values, |a, b| a.cmp(b)), Some(2));
        assert_eq!(bsearch_safe(&9, &values, |a, b| a.cmp(b)), Some(4));
    }

    #[test]
    fn bsearch_safe_returns_none_for_missing_or_empty_inputs() {
        let values = [1, 3, 5, 7, 9];
        assert_eq!(bsearch_safe(&4, &values, |a, b| a.cmp(b)), None);
        assert_eq!(bsearch_safe(&4, &[], |a: &i32, b: &i32| a.cmp(b)), None);
    }

    #[test]
    fn xbsearch_r_matches_manual_binary_search_semantics() {
        let values = [10, 20, 30, 40, 50];
        let offset = 10;
        assert_eq!(
            xbsearch_r(&40, &values, &offset, |key, probe, offset| (key - offset)
                .cmp(&(probe - offset))),
            Some(3)
        );
        assert_eq!(
            xbsearch_r(&25, &values, &offset, |key, probe, offset| (key - offset)
                .cmp(&(probe - offset))),
            None
        );
    }
}
