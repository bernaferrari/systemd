// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-kernel.c
//
// Safe close-and-unmap helpers for memfd cache entries.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    InvalidPageSize,
    AlignmentOverflow,
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPageSize => f.write_str("page size must be non-zero"),
            Self::AlignmentOverflow => f.write_str("page alignment overflow"),
        }
    }
}

impl std::error::Error for KernelError {}

pub fn page_align(size: usize, page_size: usize) -> Result<usize, KernelError> {
    if page_size == 0 {
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
    fn alignment_overflow_is_reported() {
        assert_eq!(
            page_align(usize::MAX, 4096).unwrap_err(),
            KernelError::AlignmentOverflow
        );
    }
}
