// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=sd-bus.bus-kernel; authority=src/libsystemd/sd-bus/bus-kernel.c,src/libsystemd/sd-bus/bus-kernel.h,src/libsystemd/sd-bus/bus-internal.h,src/fundamental/memory-util.h
//
// Checked, non-I/O shadow of the memfd-cache cleanup helpers.

use std::ffi::{c_int, c_void};

pub const MEMFD_CACHE_MAX: usize = 32;
pub const MEMFD_CACHE_ITEM_SIZE_MAX: usize = 128 * 1024;
pub const MEMFD_MIN_SIZE: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    InvalidPageSize,
    AlignmentOverflow,
    InvalidMappingAddress,
    CacheCapacityExceeded,
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPageSize => f.write_str("page size must be a non-zero power of two"),
            Self::AlignmentOverflow => f.write_str("page alignment overflow"),
            Self::InvalidMappingAddress => {
                f.write_str("a non-empty mapping must have a non-null address")
            }
            Self::CacheCapacityExceeded => f.write_str("memfd cache capacity exceeded"),
        }
    }
}

impl std::error::Error for KernelError {}

pub fn page_align(size: usize, page_size: usize) -> Result<usize, KernelError> {
    // ALIGN_TO(), which backs C's PAGE_ALIGN(), requires a power-of-two
    // alignment. Make that assertion boundary recoverable in the Rust shadow.
    if !page_size.is_power_of_two() {
        return Err(KernelError::InvalidPageSize);
    }
    let remainder = size % page_size;
    if remainder == 0 {
        Ok(size)
    } else {
        size.checked_add(page_size - remainder)
            .ok_or(KernelError::AlignmentOverflow)
    }
}

/// Layout mirror of C's private `struct memfd_cache`.
///
/// `address` is an opaque C address here: this module never dereferences it or
/// performs `munmap(2)`. Constructing this value does not establish that the
/// address denotes a live mapping. Any future syscall/FFI consumer must
/// separately uphold the mapping lifetime and extent contract.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CMemfdCacheEntry {
    pub fd: c_int,
    pub address: *mut c_void,
    pub mapped: usize,
    pub allocated: usize,
}

// Linux systemd targets have an int followed by three pointer-sized fields.
// Keep these assertions next to the mirror so layout drift fails compilation.
const _: () = assert!(std::mem::offset_of!(CMemfdCacheEntry, fd) == 0);
const _: () =
    assert!(std::mem::offset_of!(CMemfdCacheEntry, address) == std::mem::size_of::<usize>());
const _: () =
    assert!(std::mem::offset_of!(CMemfdCacheEntry, mapped) == 2 * std::mem::size_of::<usize>());
const _: () =
    assert!(std::mem::offset_of!(CMemfdCacheEntry, allocated) == 3 * std::mem::size_of::<usize>());
const _: () = assert!(std::mem::size_of::<CMemfdCacheEntry>() == 4 * std::mem::size_of::<usize>());

/// Observable state used to test cleanup decisions without issuing syscalls.
///
/// This is deliberately not a C-ABI type; [`CMemfdCacheEntry`] is the layout
/// mirror. `address` remains an opaque integer and is never dereferenced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemfdCacheEntry {
    pub fd: i32,
    pub address: usize,
    pub mapped: usize,
    pub unmapped_len: Option<usize>,
    pub closed: bool,
}

impl MemfdCacheEntry {
    pub fn new(fd: i32, address: usize, mapped: usize) -> Self {
        Self {
            fd,
            address,
            mapped,
            unmapped_len: None,
            closed: false,
        }
    }
}

pub fn close_and_munmap(entry: &mut MemfdCacheEntry, page_size: usize) -> Result<(), KernelError> {
    if entry.mapped > 0 {
        if entry.address == 0 {
            return Err(KernelError::InvalidMappingAddress);
        }
        entry.unmapped_len = Some(page_align(entry.mapped, page_size)?);
    }
    entry.closed = true;
    entry.fd = -1;
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BusMemfdCache {
    pub entries: Vec<MemfdCacheEntry>,
}

impl BusMemfdCache {
    pub fn bus_flush_memfd(&mut self, page_size: usize) -> Result<usize, KernelError> {
        let count = self.entries.len();

        if count > MEMFD_CACHE_MAX {
            return Err(KernelError::CacheCapacityExceeded);
        }

        // Validate the whole fixed-capacity cache before mutating the
        // observational state. Unlike the infallible C cleanup path, this
        // shadow reports invalid internal state; an Err must not describe a
        // cache that was only partly cleaned.
        for entry in &self.entries {
            if entry.mapped > 0 {
                if entry.address == 0 {
                    return Err(KernelError::InvalidMappingAddress);
                }
                page_align(entry.mapped, page_size)?;
            }
        }

        for entry in &mut self.entries {
            close_and_munmap(entry, page_size)?;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_align_keeps_aligned_value() {
        assert_eq!(page_align(8192, 4096).unwrap(), 8192);
    }

    #[test]
    fn page_align_rounds_up() {
        assert_eq!(page_align(4097, 4096).unwrap(), 8192);
    }

    #[test]
    fn page_align_rejects_zero_page_size() {
        assert_eq!(page_align(1, 0).unwrap_err(), KernelError::InvalidPageSize);
    }

    #[test]
    fn page_align_rejects_non_power_of_two_page_size() {
        assert_eq!(page_align(1, 3).unwrap_err(), KernelError::InvalidPageSize);
    }

    #[test]
    fn close_and_munmap_marks_entry_closed() {
        let mut entry = MemfdCacheEntry::new(10, 123, 0);
        close_and_munmap(&mut entry, 4096).unwrap();
        assert!(entry.closed);
        assert_eq!(entry.fd, -1);
    }

    #[test]
    fn close_and_munmap_aligns_mapping_like_c_code() {
        let mut entry = MemfdCacheEntry::new(10, 123, 5000);
        close_and_munmap(&mut entry, 4096).unwrap();
        assert_eq!(entry.unmapped_len, Some(8192));
    }

    #[test]
    fn close_and_munmap_rejects_null_nonempty_mapping_without_closing() {
        let mut entry = MemfdCacheEntry::new(10, 0, 1);
        assert_eq!(
            close_and_munmap(&mut entry, 4096).unwrap_err(),
            KernelError::InvalidMappingAddress
        );
        assert!(!entry.closed);
        assert_eq!(entry.fd, 10);
    }

    #[test]
    fn flush_processes_all_entries() {
        let mut cache = BusMemfdCache {
            entries: vec![
                MemfdCacheEntry::new(1, 10, 1),
                MemfdCacheEntry::new(2, 20, 0),
            ],
        };
        assert_eq!(cache.bus_flush_memfd(4096).unwrap(), 2);
        assert!(cache.entries.iter().all(|e| e.closed));
    }

    #[test]
    fn flush_keeps_zero_sized_mapping_without_unmap_len() {
        let mut cache = BusMemfdCache {
            entries: vec![MemfdCacheEntry::new(1, 10, 0)],
        };
        cache.bus_flush_memfd(4096).unwrap();
        assert_eq!(cache.entries[0].unmapped_len, None);
    }

    #[test]
    fn flush_rejects_more_entries_than_the_c_cache_without_partial_cleanup() {
        let mut cache = BusMemfdCache {
            entries: (0..=MEMFD_CACHE_MAX)
                .map(|fd| MemfdCacheEntry::new(fd as i32, 1, 1))
                .collect(),
        };
        assert_eq!(
            cache.bus_flush_memfd(4096).unwrap_err(),
            KernelError::CacheCapacityExceeded
        );
        assert!(cache.entries.iter().all(|entry| !entry.closed));
    }

    #[test]
    fn flush_validation_error_does_not_partially_mutate_cache() {
        let mut cache = BusMemfdCache {
            entries: vec![MemfdCacheEntry::new(1, 1, 1), MemfdCacheEntry::new(2, 0, 1)],
        };
        assert_eq!(
            cache.bus_flush_memfd(4096).unwrap_err(),
            KernelError::InvalidMappingAddress
        );
        assert!(cache.entries.iter().all(|entry| !entry.closed));
        assert_eq!(cache.entries[0].fd, 1);
    }

    #[test]
    fn alignment_overflow_is_reported() {
        assert_eq!(
            page_align(usize::MAX, 4096).unwrap_err(),
            KernelError::AlignmentOverflow
        );
    }

    #[test]
    fn c_memfd_cache_entry_layout_matches_the_header() {
        assert_eq!(
            std::mem::offset_of!(CMemfdCacheEntry, address),
            std::mem::size_of::<usize>()
        );
        assert_eq!(
            std::mem::size_of::<CMemfdCacheEntry>(),
            4 * std::mem::size_of::<usize>()
        );
    }

    #[test]
    fn header_constants_match_c_authority() {
        assert_eq!(MEMFD_CACHE_MAX, 32);
        assert_eq!(MEMFD_CACHE_ITEM_SIZE_MAX, 128 * 1024);
        assert_eq!(MEMFD_MIN_SIZE, 512 * 1024);
    }
}
