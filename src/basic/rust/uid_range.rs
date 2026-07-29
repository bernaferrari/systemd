// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.uid-range; authority=src/basic/uid-range.c,src/basic/uid-range.h,src/basic/user-util.c,src/basic/user-util.h

use std::ffi::c_char;
use std::ffi::c_void;
use std::ptr;

use crate::ffi::Errno;

pub const UID_INVALID: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UIDRangeEntry {
    pub start: u32,
    pub nr: u32,
}

/// C ABI representation of `UIDRange`.
///
/// This intentionally remains separate from the native [`UIDRange`] below:
/// C owns its `entries` allocation and represents it as a pointer plus length,
/// whereas the Rust-native API uses a `Vec`.
#[repr(C)]
pub struct CUIDRange {
    entries: *mut UIDRangeEntry,
    n_entries: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UIDRange {
    entries: Vec<UIDRangeEntry>,
}

fn parse_u32_component(text: &str) -> Result<u32, i32> {
    text.parse::<u32>()
        .map_err(|_| Errno::EINVAL.to_neg_errno())
}

fn parse_uid_range(s: &str) -> Result<(u32, u32), i32> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    if let Some((a, b)) = s.split_once('-') {
        let start = parse_u32_component(a.trim())?;
        let end = parse_u32_component(b.trim())?;
        if end < start {
            return Err(Errno::EINVAL.to_neg_errno());
        }
        Ok((start, end))
    } else {
        let uid = parse_u32_component(s)?;
        Ok((uid, uid))
    }
}

fn entry_intersects(a: UIDRangeEntry, b: UIDRangeEntry) -> bool {
    a.start <= b.start.saturating_add(b.nr) && a.start.saturating_add(a.nr) >= b.start
}

impl UIDRange {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[UIDRangeEntry] {
        &self.entries
    }

    pub fn n_entries(&self) -> usize {
        self.entries.len()
    }

    pub fn get_entry(&self, index: usize) -> Option<UIDRangeEntry> {
        self.entries.get(index).copied()
    }

    pub fn add_internal(&mut self, start: u32, nr: u32, coalesce: bool) -> Result<(), i32> {
        if nr == 0 {
            return Ok(());
        }

        if start > u32::MAX - nr {
            return Err(Errno::ERANGE.to_neg_errno());
        }

        self.entries.push(UIDRangeEntry { start, nr });

        if coalesce {
            self.coalesce();
        }

        Ok(())
    }

    pub fn add_str_full(&mut self, s: &str, coalesce: bool) -> Result<(), i32> {
        let (start, end) = parse_uid_range(s)?;
        self.add_internal(start, end - start + 1, coalesce)
    }

    pub fn next_lower(&self, uid: u32) -> Result<u32, i32> {
        if uid == 0 {
            return Err(-libc::EBUSY);
        }

        let candidate = uid - 1;
        let mut closest = UID_INVALID;

        for entry in &self.entries {
            if entry.nr == 0 {
                continue;
            }

            let begin = entry.start;
            let end = entry.start + entry.nr - 1;

            if candidate >= begin && candidate <= end {
                return Ok(candidate);
            }

            if end < candidate {
                closest = end;
            }
        }

        if closest == UID_INVALID {
            Err(-libc::EBUSY)
        } else {
            Ok(closest)
        }
    }

    pub fn covers(&self, start: u32, nr: u32) -> bool {
        if nr == 0 {
            return true;
        }

        if start > u32::MAX - nr {
            return false;
        }

        self.entries
            .iter()
            .any(|entry| start >= entry.start && start + nr <= entry.start.saturating_add(entry.nr))
    }

    pub fn contains(&self, uid: u32) -> bool {
        self.covers(uid, 1)
    }

    pub fn overlaps(&self, start: u32, nr: u32) -> bool {
        let nr = if start > u32::MAX - nr {
            u32::MAX - start
        } else {
            nr
        };

        if nr == 0 {
            return false;
        }

        let end = start + nr;
        self.entries
            .iter()
            .any(|entry| start < entry.start.saturating_add(entry.nr) && end >= entry.start)
    }

    pub fn size(&self) -> u32 {
        self.entries
            .iter()
            .fold(0u32, |acc, entry| acc.wrapping_add(entry.nr))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|entry| entry.nr == 0)
    }

    pub fn base(&self) -> u32 {
        self.entries
            .iter()
            .find(|entry| entry.nr > 0)
            .map(|entry| entry.start)
            .unwrap_or(UID_INVALID)
    }

    fn coalesce(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        self.entries.sort_by_key(|entry| (entry.start, entry.nr));

        let mut merged: Vec<UIDRangeEntry> = Vec::with_capacity(self.entries.len());
        for entry in self.entries.iter().copied() {
            match merged.last_mut() {
                Some(current) if entry_intersects(*current, entry) => {
                    let begin = current.start.min(entry.start);
                    let end = current
                        .start
                        .saturating_add(current.nr)
                        .max(entry.start.saturating_add(entry.nr));
                    current.start = begin;
                    current.nr = end - begin;
                }
                _ => merged.push(entry),
            }
        }

        self.entries = merged;
    }
}

/// Borrow the entries of a valid C `UIDRange`.
///
/// # Safety
/// `range` must be non-null and point to a live C `UIDRange`. When its
/// `n_entries` is non-zero, `entries` must point to that many readable,
/// properly aligned `UIDRangeEntry` values.
unsafe fn c_range_entries<'a>(range: *const CUIDRange) -> &'a [UIDRangeEntry] {
    // SAFETY: upheld by this helper's representation contract.
    let n_entries = unsafe { (*range).n_entries };
    if n_entries == 0 {
        return &[];
    }
    // SAFETY: upheld by this helper's representation contract.
    unsafe { std::slice::from_raw_parts((*range).entries, n_entries) }
}

/// Borrow the entries of a valid mutable C `UIDRange`.
///
/// # Safety
/// `range` must be uniquely borrowed for the duration of the returned slice
/// and otherwise meet [`c_range_entries`]' representation contract.
unsafe fn c_range_entries_mut<'a>(range: *mut CUIDRange) -> &'a mut [UIDRangeEntry] {
    // SAFETY: upheld by this helper's representation contract.
    let n_entries = unsafe { (*range).n_entries };
    if n_entries == 0 {
        return &mut [];
    }
    // SAFETY: upheld by this helper's representation contract.
    unsafe { std::slice::from_raw_parts_mut((*range).entries, n_entries) }
}

/// Return the entry count with C's null-as-empty convention.
///
/// # Safety
/// A non-null `range` must point to a readable C `UIDRange`.
unsafe fn c_range_len(range: *const CUIDRange) -> usize {
    if range.is_null() {
        0
    } else {
        // SAFETY: required by this helper's contract.
        unsafe { (*range).n_entries }
    }
}

/// Grow a C range entry allocation to precisely `new_len` elements.
///
/// # Safety
/// `range` must be a uniquely borrowed, libc-owned C `UIDRange`; its current
/// entry allocation must be null or a live libc allocation.
unsafe fn c_range_resize_entries(range: *mut CUIDRange, new_len: usize) -> Result<(), i32> {
    let Some(bytes) = new_len.checked_mul(std::mem::size_of::<UIDRangeEntry>()) else {
        return Err(Errno::ENOMEM.to_neg_errno());
    };
    // SAFETY: required by this helper's libc-allocation contract.
    let entries = unsafe { crate::ffi::realloc((*range).entries.cast::<c_void>(), bytes) }
        .cast::<UIDRangeEntry>();
    if entries.is_null() {
        return Err(Errno::ENOMEM.to_neg_errno());
    }
    // SAFETY: `realloc` returned the current allocation for this C range.
    unsafe { (*range).entries = entries };
    Ok(())
}

/// Coalesce overlapping or adjacent C range entries exactly as `uid-range.c`.
///
/// # Safety
/// `range` must be a uniquely borrowed valid C range. Each populated entry
/// must satisfy the C range invariant `start + nr <= UINT32_MAX`.
unsafe fn c_range_coalesce(range: *mut CUIDRange) {
    // SAFETY: required by this helper's C representation contract.
    let n_entries = unsafe { (*range).n_entries };
    if n_entries == 0 {
        return;
    }

    // SAFETY: required by this helper's C representation contract.
    unsafe { c_range_entries_mut(range) }.sort_by_key(|entry| (entry.start, entry.nr));

    let mut n_entries = n_entries;
    let mut i = 0;
    while i < n_entries {
        let mut j = i + 1;
        while j < n_entries {
            // SAFETY: `j < n_entries <= original n_entries` indexes the live allocation.
            let (x, y) = unsafe {
                let entries = (*range).entries;
                (*entries.add(i), *entries.add(j))
            };
            if !(x.start <= y.start + y.nr && x.start + x.nr >= y.start) {
                break;
            }

            let begin = x.start.min(y.start);
            let end = (x.start + x.nr).max(y.start + y.nr);
            // SAFETY: `i` indexes the live entry allocation.
            unsafe {
                (*range).entries.add(i).write(UIDRangeEntry {
                    start: begin,
                    nr: end - begin,
                });
            }

            let tail = n_entries - j - 1;
            if tail > 0 {
                // SAFETY: the source and destination are within one live C
                // allocation, and `copy` has memmove semantics for overlap.
                unsafe {
                    ptr::copy((*range).entries.add(j + 1), (*range).entries.add(j), tail);
                }
            }
            n_entries -= 1;
            // Do not advance `j`: the entry shifted into its place must be
            // checked against the newly widened entry, as in the C loop.
        }
        i += 1;
    }
    // SAFETY: only logical length changes; allocation ownership is unchanged.
    unsafe { (*range).n_entries = n_entries };
}

/// Add an entry to a C range using C allocator ownership and C layout.
///
/// # Safety
/// `range` must point to writable `UIDRange *` storage. A non-null `*range`
/// must be a valid libc-owned C range with a writable entry allocation.
unsafe fn c_range_add_internal(
    range: *mut *mut CUIDRange,
    start: u32,
    nr: u32,
    coalesce: bool,
) -> i32 {
    if nr == 0 {
        return 0;
    }
    if start > u32::MAX - nr {
        return Errno::ERANGE.to_neg_errno();
    }

    // SAFETY: required by this helper's writable-output contract.
    let mut current = unsafe { *range };
    let newly_allocated = current.is_null();
    if newly_allocated {
        // SAFETY: libc provides correctly aligned, zeroed C storage.
        current = unsafe { libc::calloc(1, std::mem::size_of::<CUIDRange>()) }.cast();
        if current.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
    }

    // SAFETY: `current` is either the caller's valid C range or this fresh allocation.
    let old_len = unsafe { (*current).n_entries };
    let Some(new_len) = old_len.checked_add(1) else {
        if newly_allocated {
            // SAFETY: the local allocation has not escaped.
            unsafe { libc::free(current.cast::<c_void>()) };
        }
        return Errno::ENOMEM.to_neg_errno();
    };
    // SAFETY: `current` has the required unique libc allocation ownership.
    if let Err(errno) = unsafe { c_range_resize_entries(current, new_len) } {
        if newly_allocated {
            // SAFETY: `realloc` left the old allocation live on failure.
            unsafe {
                libc::free((*current).entries.cast::<c_void>());
                libc::free(current.cast::<c_void>());
            }
        }
        return errno;
    }

    // SAFETY: the resized allocation has a slot at `old_len`.
    unsafe {
        (*current)
            .entries
            .add(old_len)
            .write(UIDRangeEntry { start, nr });
        (*current).n_entries = new_len;
        if coalesce {
            c_range_coalesce(current);
        }
        *range = current;
    }
    0
}

/// Exact C ABI shadow of `uid_range_free()`.
///
/// # Safety
/// A non-null `range` must be a valid libc-owned C `UIDRange`, and its entries
/// allocation must be null or uniquely owned by that range. Neither may be
/// accessed again after this call.
#[unsafe(export_name = "rs_uid_range_free")]
pub unsafe extern "C" fn rs_uid_range_free(range: *mut CUIDRange) -> *mut CUIDRange {
    if !range.is_null() {
        // SAFETY: required by this FFI boundary's libc ownership contract.
        unsafe {
            libc::free((*range).entries.cast::<c_void>());
            libc::free(range.cast::<c_void>());
        }
    }
    ptr::null_mut()
}

/// Exact C ABI shadow of `uid_range_add_internal()`.
///
/// # Safety
/// `range` must point to writable `UIDRange *` storage; a non-null `*range`
/// must meet [`c_range_add_internal`]' C allocation and representation contract.
#[unsafe(export_name = "rs_uid_range_add_internal")]
pub unsafe extern "C" fn rs_uid_range_add_internal(
    range: *mut *mut CUIDRange,
    start: u32,
    nr: u32,
    coalesce: bool,
) -> i32 {
    if range.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by this FFI boundary's writable-output contract.
    unsafe { c_range_add_internal(range, start, nr, coalesce) }
}

/// Exact C ABI shadow of `uid_range_covers()`.
///
/// # Safety
/// A non-null `range` must be a readable valid C range and its entries must be
/// readable for the recorded length. The function only borrows input storage.
#[unsafe(export_name = "rs_uid_range_covers")]
pub unsafe extern "C" fn rs_uid_range_covers(range: *const CUIDRange, start: u32, nr: u32) -> bool {
    if nr == 0 {
        return true;
    }
    if start > u32::MAX - nr || range.is_null() {
        return false;
    }
    // SAFETY: required by this FFI boundary's C range representation contract.
    unsafe {
        c_range_entries(range)
            .iter()
            .any(|entry| start >= entry.start && start + nr <= entry.start + entry.nr)
    }
}

/// Exact C ABI shadow of `uid_range_contains()`.
///
/// # Safety
/// A non-null `range` must satisfy [`rs_uid_range_covers`]' C representation
/// contract.
#[unsafe(export_name = "rs_uid_range_contains")]
pub unsafe extern "C" fn rs_uid_range_contains(range: *const CUIDRange, uid: u32) -> bool {
    // SAFETY: delegated to `rs_uid_range_covers` with the same preconditions.
    unsafe { rs_uid_range_covers(range, uid, 1) }
}

/// Exact C ABI shadow of `uid_range_overlaps()`.
///
/// # Safety
/// A non-null `range` must be a readable valid C range and its entries must be
/// readable for the recorded length. The function only borrows input storage.
#[unsafe(export_name = "rs_uid_range_overlaps")]
pub unsafe extern "C" fn rs_uid_range_overlaps(
    range: *const CUIDRange,
    start: u32,
    nr: u32,
) -> bool {
    if range.is_null() {
        return false;
    }
    let nr = if start > u32::MAX - nr {
        u32::MAX - start
    } else {
        nr
    };
    if nr == 0 {
        return false;
    }
    let end = start + nr;
    // SAFETY: required by this FFI boundary's C range representation contract.
    unsafe {
        c_range_entries(range)
            .iter()
            .any(|entry| start < entry.start + entry.nr && end >= entry.start)
    }
}

/// Exact C ABI shadow of `uid_range_size()`.
///
/// # Safety
/// A non-null `range` must be a readable valid C range and its entries must be
/// readable for the recorded length. The function only borrows input storage.
#[unsafe(export_name = "rs_uid_range_size")]
pub unsafe extern "C" fn rs_uid_range_size(range: *const CUIDRange) -> u32 {
    if range.is_null() {
        return 0;
    }
    // SAFETY: required by this FFI boundary's C range representation contract.
    unsafe {
        c_range_entries(range)
            .iter()
            .fold(0_u32, |size, entry| size.wrapping_add(entry.nr))
    }
}

/// Exact C ABI shadow of `uid_range_is_empty()`.
///
/// # Safety
/// A non-null `range` must be a readable valid C range and its entries must be
/// readable for the recorded length. The function only borrows input storage.
#[unsafe(export_name = "rs_uid_range_is_empty")]
pub unsafe extern "C" fn rs_uid_range_is_empty(range: *const CUIDRange) -> bool {
    if range.is_null() {
        return true;
    }
    // SAFETY: required by this FFI boundary's C range representation contract.
    unsafe { c_range_entries(range).iter().all(|entry| entry.nr == 0) }
}

/// Exact C ABI shadow of `uid_range_equal()`.
///
/// # Safety
/// Each non-null input must be a readable valid C range whose entries are
/// readable for its recorded length. The function only borrows input storage.
#[unsafe(export_name = "rs_uid_range_equal")]
pub unsafe extern "C" fn rs_uid_range_equal(a: *const CUIDRange, b: *const CUIDRange) -> bool {
    if a == b {
        return true;
    }
    if a.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: required by this FFI boundary's C range representation contract.
    unsafe { c_range_entries(a) == c_range_entries(b) }
}

/// Exact C ABI shadow of `uid_range_base()`.
///
/// # Safety
/// A non-null `range` must be a readable valid C range and its entries must be
/// readable for the recorded length. The function only borrows input storage.
#[unsafe(export_name = "rs_uid_range_base")]
pub unsafe extern "C" fn rs_uid_range_base(range: *const CUIDRange) -> u32 {
    if range.is_null() {
        return UID_INVALID;
    }
    // SAFETY: required by this FFI boundary's C range representation contract.
    unsafe {
        c_range_entries(range)
            .iter()
            .find(|entry| entry.nr > 0)
            .map_or(UID_INVALID, |entry| entry.start)
    }
}

/// Exact C ABI shadow of `uid_range_next_lower()`.
///
/// # Safety
/// `range` must be a valid readable C range and `uid` must point to writable,
/// properly aligned `uid_t` storage. The function borrows `range` only.
#[unsafe(export_name = "rs_uid_range_next_lower")]
pub unsafe extern "C" fn rs_uid_range_next_lower(range: *const CUIDRange, uid: *mut u32) -> i32 {
    if range.is_null() || uid.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by this FFI boundary's writable-output contract.
    let candidate = unsafe { *uid };
    if candidate == 0 {
        return -libc::EBUSY;
    }
    let candidate = candidate - 1;
    let mut closest = UID_INVALID;
    // SAFETY: required by this FFI boundary's C range representation contract.
    for entry in unsafe { c_range_entries(range) } {
        let end = entry.start + entry.nr - 1;
        if candidate >= entry.start && candidate <= end {
            // SAFETY: required by this FFI boundary's writable-output contract.
            unsafe { uid.write(candidate) };
            return 1;
        }
        if end < candidate {
            closest = end;
        }
    }
    if closest == UID_INVALID {
        -libc::EBUSY
    } else {
        // SAFETY: required by this FFI boundary's writable-output contract.
        unsafe { uid.write(closest) };
        1
    }
}

/// Exact C ABI shadow of `uid_range_clip()`.
///
/// # Safety
/// `range` must be a uniquely borrowed valid C range with writable entries for
/// its recorded length.
#[unsafe(export_name = "rs_uid_range_clip")]
pub unsafe extern "C" fn rs_uid_range_clip(range: *mut CUIDRange, min: u32, max: u32) -> i32 {
    if range.is_null() || min > max {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by this FFI boundary's mutable C range contract.
    let n_entries = unsafe { (*range).n_entries };
    let mut kept = 0;
    for index in 0..n_entries {
        // SAFETY: index is within the valid entry allocation.
        let entry = unsafe { *(*range).entries.add(index) };
        let entry_end = entry.start + entry.nr;
        if entry_end <= min || entry.start > max {
            continue;
        }
        let new_start = entry.start.max(min);
        let new_end = if entry_end <= max { entry_end } else { max + 1 };
        // SAFETY: `kept <= index < n_entries`, so the output slot is writable.
        unsafe {
            (*range).entries.add(kept).write(UIDRangeEntry {
                start: new_start,
                nr: new_end - new_start,
            });
        }
        kept += 1;
    }
    // SAFETY: only logical length changes; allocation ownership is unchanged.
    unsafe { (*range).n_entries = kept };
    0
}

/// Exact C ABI shadow of `uid_range_copy()`.
///
/// # Safety
/// `ret` must point to writable `UIDRange *` storage. A non-null `range` must
/// be a readable valid C range whose entries are readable for its recorded
/// length. On success, the returned range is libc-owned.
#[unsafe(export_name = "rs_uid_range_copy")]
pub unsafe extern "C" fn rs_uid_range_copy(
    range: *const CUIDRange,
    ret: *mut *mut CUIDRange,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if range.is_null() {
        // SAFETY: required by this FFI boundary's writable-output contract.
        unsafe { ret.write(ptr::null_mut()) };
        return 0;
    }
    // SAFETY: libc allocates correctly aligned, zeroed C range storage.
    let copy = unsafe { libc::calloc(1, std::mem::size_of::<CUIDRange>()) }.cast::<CUIDRange>();
    if copy.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: required by this FFI boundary's C range representation contract.
    let n_entries = unsafe { (*range).n_entries };
    if n_entries > 0 {
        let Some(bytes) = n_entries.checked_mul(std::mem::size_of::<UIDRangeEntry>()) else {
            // SAFETY: the local allocation has not escaped.
            unsafe { libc::free(copy.cast::<c_void>()) };
            return Errno::ENOMEM.to_neg_errno();
        };
        // SAFETY: libc allocates the checked C entry-array byte length.
        let entries = unsafe { libc::malloc(bytes) }.cast::<UIDRangeEntry>();
        if entries.is_null() {
            // SAFETY: the local allocation has not escaped.
            unsafe { libc::free(copy.cast::<c_void>()) };
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: both entry arrays are valid for `n_entries` values.
        unsafe {
            ptr::copy_nonoverlapping((*range).entries, entries, n_entries);
            (*copy).entries = entries;
            (*copy).n_entries = n_entries;
        }
    }
    // SAFETY: required by this FFI boundary's writable-output contract.
    unsafe { ret.write(copy) };
    0
}

/// Exact C ABI shadow of `uid_range_remove()`.
///
/// # Safety
/// `range` must be a uniquely borrowed valid C range with a libc-owned,
/// writable entry allocation. Its entries must satisfy the C range invariant.
#[unsafe(export_name = "rs_uid_range_remove")]
pub unsafe extern "C" fn rs_uid_range_remove(range: *mut CUIDRange, start: u32, size: u32) -> i32 {
    if range.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if size == 0 {
        return 0;
    }
    // C intentionally permits unsigned wrapping for this calculation.
    let end = start.wrapping_add(size);
    let mut index = 0;
    // SAFETY: required by this FFI boundary's mutable C range contract.
    while index < unsafe { (*range).n_entries } {
        // SAFETY: index is within the live entry allocation.
        let entry = unsafe { *(*range).entries.add(index) };
        let entry_end = entry.start + entry.nr;
        if entry_end <= start || entry.start >= end {
            index += 1;
            continue;
        }
        if entry.start < start && entry_end > end {
            // SAFETY: required by this FFI boundary's mutable C range contract.
            let Some(new_len) = (unsafe { (*range).n_entries }).checked_add(1) else {
                return Errno::ENOMEM.to_neg_errno();
            };
            // SAFETY: the C range is uniquely owned by this operation.
            if let Err(errno) = unsafe { c_range_resize_entries(range, new_len) } {
                return errno;
            }
            // SAFETY: realloc may move storage; refetch all raw pointers afterwards.
            unsafe {
                let n_entries = (*range).n_entries;
                let entries = (*range).entries;
                ptr::copy(
                    entries.add(index + 1),
                    entries.add(index + 2),
                    n_entries - index - 1,
                );
                (*range).n_entries = n_entries + 1;
                entries.add(index).write(UIDRangeEntry {
                    start: entry.start,
                    nr: start - entry.start,
                });
                entries.add(index + 1).write(UIDRangeEntry {
                    start: end,
                    nr: entry_end - end,
                });
            }
            index += 2;
            continue;
        }
        if start <= entry.start && end >= entry_end {
            // SAFETY: source and destination are within one live C allocation.
            unsafe {
                let n_entries = (*range).n_entries;
                let entries = (*range).entries;
                ptr::copy(
                    entries.add(index + 1),
                    entries.add(index),
                    n_entries - index - 1,
                );
                (*range).n_entries = n_entries - 1;
            }
            continue;
        }
        if start <= entry.start && end > entry.start {
            // SAFETY: index is within the live entry allocation.
            unsafe {
                (*range).entries.add(index).write(UIDRangeEntry {
                    start: end,
                    nr: entry_end - end,
                });
            }
            index += 1;
            continue;
        }
        if start < entry_end && end >= entry_end {
            // SAFETY: index is within the live entry allocation.
            unsafe {
                (*range).entries.add(index).write(UIDRangeEntry {
                    start: entry.start,
                    nr: start - entry.start,
                });
            }
        }
        index += 1;
    }
    0
}

/// Exact C ABI shadow of `uid_range_partition()`.
///
/// # Safety
/// `range` must be a uniquely borrowed valid C range with a libc-owned,
/// writable entry allocation. Its entries must satisfy the C range invariant.
#[unsafe(export_name = "rs_uid_range_partition")]
pub unsafe extern "C" fn rs_uid_range_partition(range: *mut CUIDRange, size: u32) -> i32 {
    if range.is_null() || size == 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by this FFI boundary's mutable C range contract.
    let n_entries = unsafe { (*range).n_entries };
    let mut n_new_entries = 0_usize;
    for entry in unsafe { c_range_entries(range) } {
        let parts = (entry.nr / size) as usize;
        let Some(total) = n_new_entries.checked_add(parts) else {
            return Errno::ENOMEM.to_neg_errno();
        };
        n_new_entries = total;
    }
    if n_new_entries == 0 {
        // SAFETY: only logical length changes; C keeps its allocation too.
        unsafe { (*range).n_entries = 0 };
        return 0;
    }
    if n_new_entries > n_entries {
        // SAFETY: required by this FFI boundary's mutable C range contract.
        if let Err(errno) = unsafe { c_range_resize_entries(range, n_new_entries) } {
            return errno;
        }
    }

    // Compact first, exactly as the C forward pass does.
    let mut n_src = 0;
    for index in 0..n_entries {
        // SAFETY: index is in the original live allocation.
        let entry = unsafe { *(*range).entries.add(index) };
        if entry.nr >= size {
            // SAFETY: `n_src <= index`, so the destination is a live slot.
            unsafe { (*range).entries.add(n_src).write(entry) };
            n_src += 1;
        }
    }
    let mut target = n_new_entries;
    for index in (0..n_src).rev() {
        // SAFETY: the pre-compacted source slot remains live and readable.
        let entry = unsafe { *(*range).entries.add(index) };
        let parts = entry.nr / size;
        for part in (0..parts).rev() {
            target -= 1;
            // SAFETY: target is within the resized allocation.
            unsafe {
                (*range).entries.add(target).write(UIDRangeEntry {
                    start: entry.start + part * size,
                    nr: size,
                });
            }
        }
    }
    // SAFETY: only logical length changes; allocation ownership is unchanged.
    unsafe { (*range).n_entries = n_new_entries };
    0
}

/// Exact C ABI shadow of `uid_range_translate()`.
///
/// # Safety
/// Each non-null range must be a readable valid C range. `ret` must point to
/// writable, properly aligned `uid_t` storage. Both input arrays must have the
/// same entry count and matching per-entry lengths, as required by C.
#[unsafe(export_name = "rs_uid_range_translate")]
pub unsafe extern "C" fn rs_uid_range_translate(
    outside: *const CUIDRange,
    inside: *const CUIDRange,
    uid: u32,
    ret: *mut u32,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by this FFI boundary's C range representation contract.
    let (outside_len, inside_len) = unsafe { (c_range_len(outside), c_range_len(inside)) };
    if outside_len != inside_len {
        return Errno::EINVAL.to_neg_errno();
    }
    if outside_len == 0 {
        return Errno::ESRCH.to_neg_errno();
    }
    // SAFETY: non-zero matching lengths imply both pointers are non-null and
    // valid according to this FFI boundary's representation contract.
    let (outside_entries, inside_entries) =
        unsafe { (c_range_entries(outside), c_range_entries(inside)) };
    if outside_entries
        .iter()
        .zip(inside_entries)
        .any(|(outer, inner)| outer.nr != inner.nr)
    {
        return Errno::EINVAL.to_neg_errno();
    }
    for (outer, inner) in outside_entries.iter().zip(inside_entries) {
        if uid >= outer.start && uid < outer.start + outer.nr {
            // SAFETY: required by this FFI boundary's writable-output contract.
            unsafe { ret.write(inner.start + uid - outer.start) };
            return 0;
        }
    }
    Errno::ESRCH.to_neg_errno()
}

/// Exact C ABI shadow of `uid_range_add_str_full()`.
///
/// # Safety
/// `range` must point to writable `UIDRange *` storage; a non-null `*range`
/// must be a valid libc-owned C range. `s` must be a readable NUL-terminated
/// string for the call.
#[unsafe(export_name = "rs_uid_range_add_str_full")]
pub unsafe extern "C" fn rs_uid_range_add_str_full(
    range: *mut *mut CUIDRange,
    s: *const c_char,
    coalesce: bool,
) -> i32 {
    if range.is_null() || s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    let (mut start, mut end) = (0, 0);
    // SAFETY: `s` and both local outputs satisfy the parser's C ABI contract.
    let result = unsafe { crate::user_util::rs_parse_uid_range(s, &mut start, &mut end) };
    if result < 0 {
        return result;
    }
    // A successful parser call guarantees `end >= start` and excludes
    // `UID_INVALID`, so this inclusive count cannot overflow.
    let nr = end - start + 1;
    // SAFETY: delegated with the same C range output contract.
    unsafe { c_range_add_internal(range, start, nr, coalesce) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_zero_range_is_noop() {
        let mut range = UIDRange::new();
        range.add_internal(100, 0, false).unwrap();
        assert!(range.entries().is_empty());
    }

    #[test]
    fn add_rejects_overflow() {
        let mut range = UIDRange::new();
        assert_eq!(
            range.add_internal(u32::MAX, 1, false),
            Err(Errno::ERANGE.to_neg_errno())
        );
    }

    #[test]
    fn add_str_single_uid() {
        let mut range = UIDRange::new();
        range.add_str_full("42", false).unwrap();
        assert_eq!(range.get_entry(0), Some(UIDRangeEntry { start: 42, nr: 1 }));
    }

    #[test]
    fn add_str_interval() {
        let mut range = UIDRange::new();
        range.add_str_full("10-12", false).unwrap();
        assert_eq!(range.get_entry(0), Some(UIDRangeEntry { start: 10, nr: 3 }));
    }

    #[test]
    fn coalesce_merges_overlapping_and_adjacent_ranges() {
        let mut range = UIDRange::new();
        range.add_internal(20, 3, false).unwrap();
        range.add_internal(10, 5, false).unwrap();
        range.add_internal(15, 5, true).unwrap();
        assert_eq!(range.entries(), &[UIDRangeEntry { start: 10, nr: 13 }]);
    }

    #[test]
    fn covers_and_contains_match_c_logic() {
        let mut range = UIDRange::new();
        range.add_internal(100, 10, true).unwrap();
        assert!(range.covers(100, 10));
        assert!(range.covers(103, 4));
        assert!(range.contains(109));
        assert!(!range.covers(95, 20));
        assert!(!range.contains(110));
    }

    #[test]
    fn overlaps_clamps_overflowing_query() {
        let mut range = UIDRange::new();
        range.add_internal(u32::MAX - 4, 4, true).unwrap();
        assert!(range.overlaps(u32::MAX - 5, 10));
    }

    #[test]
    fn next_lower_returns_previous_uid_inside_same_entry() {
        let mut range = UIDRange::new();
        range.add_internal(100, 10, true).unwrap();
        assert_eq!(range.next_lower(105), Ok(104));
    }

    #[test]
    fn next_lower_returns_closest_lower_entry_end() {
        let mut range = UIDRange::new();
        range.add_internal(10, 3, false).unwrap();
        range.add_internal(30, 5, false).unwrap();
        assert_eq!(range.next_lower(25), Ok(12));
    }

    #[test]
    fn next_lower_fails_at_zero() {
        let range = UIDRange::new();
        assert_eq!(range.next_lower(0), Err(-libc::EBUSY));
    }

    #[test]
    fn size_is_wrapping_sum_like_c() {
        let mut range = UIDRange::new();
        range.add_internal(0, u32::MAX, false).unwrap();
        range.add_internal(0, 10, false).unwrap();
        assert_eq!(range.size(), 9);
    }

    #[test]
    fn base_returns_first_non_empty_entry() {
        let mut range = UIDRange::new();
        range.add_internal(500, 0, false).unwrap();
        range.add_internal(123, 4, false).unwrap();
        assert_eq!(range.base(), 123);
    }
}
