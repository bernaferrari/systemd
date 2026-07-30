// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-mmap-cache.c

use std::collections::HashMap;

pub const WINDOW_SIZE: u64 = 8 * 1024 * 1024;
pub const PROT_READ: i32 = 0x1;

pub type Result<T> = std::result::Result<T, CacheError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    InvalidFd,
    InvalidCategory,
    ProtectionMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Any = 0,
    Data = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub offset: u64,
    pub size: u64,
    pub base: usize,
}

impl Window {
    pub fn contains(&self, offset: u64, size: u64) -> bool {
        size > 0 && offset >= self.offset && offset + size <= self.offset + self.size
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub category_cache_hit: u32,
    pub window_list_hit: u32,
    pub missed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptor {
    fd: i32,
    prot: i32,
    windows: Vec<Window>,
    category_cache: HashMap<Category, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmapCache {
    fds: Vec<FileDescriptor>,
    next_base: usize,
    pub stats: CacheStats,
}

impl Default for MmapCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MmapCache {
    pub fn new() -> Self {
        Self {
            fds: Vec::new(),
            next_base: 0x1000_0000,
            stats: CacheStats::default(),
        }
    }

    pub fn add_fd(&mut self, fd: i32, prot: i32) -> Result<usize> {
        if let Some((index, existing)) = self.fds.iter().enumerate().find(|(_, item)| item.fd == fd)
        {
            if existing.prot != prot {
                return Err(CacheError::ProtectionMismatch);
            }
            return Ok(index);
        }

        self.fds.push(FileDescriptor {
            fd,
            prot,
            windows: Vec::new(),
            category_cache: HashMap::new(),
        });
        Ok(self.fds.len() - 1)
    }

    pub fn fd_get(
        &mut self,
        fd_index: usize,
        category: Category,
        offset: u64,
        size: u64,
    ) -> Result<usize> {
        let descriptor = self.fds.get(fd_index).ok_or(CacheError::InvalidFd)?;

        if let Some(pointer) = descriptor
            .category_cache
            .get(&category)
            .and_then(|index| descriptor.windows.get(*index))
            .filter(|window| window.contains(offset, size))
            .map(|window| window.base + (offset - window.offset) as usize)
        {
            self.stats.category_cache_hit += 1;
            return Ok(pointer);
        }

        if let Some((index, pointer)) = descriptor
            .windows
            .iter()
            .enumerate()
            .find(|(_, window)| window.contains(offset, size))
            .map(|(index, window)| (index, window.base + (offset - window.offset) as usize))
        {
            self.stats.window_list_hit += 1;
            self.fds
                .get_mut(fd_index)
                .expect("validated fd index must stay valid")
                .category_cache
                .insert(category, index);
            return Ok(pointer);
        }

        self.stats.missed += 1;
        let window = self.allocate_window(offset, size.max(1));
        let descriptor = self
            .fds
            .get_mut(fd_index)
            .expect("validated fd index must stay valid");
        descriptor.windows.push(window);
        let index = descriptor.windows.len() - 1;
        descriptor.category_cache.insert(category, index);
        Ok(window.base + (offset - window.offset) as usize)
    }

    pub fn free_fd(&mut self, fd_index: usize) -> Result<()> {
        if fd_index >= self.fds.len() {
            return Err(CacheError::InvalidFd);
        }
        self.fds.remove(fd_index);
        Ok(())
    }

    fn allocate_window(&mut self, offset: u64, size: u64) -> Window {
        let aligned_offset = offset & !4095;
        let page_tail = offset - aligned_offset;
        let aligned_size = (size + page_tail).div_ceil(4096) * 4096;
        let final_size = aligned_size.max(WINDOW_SIZE);
        let base = self.next_base;
        self.next_base += final_size as usize + 0x1000;
        Window {
            offset: aligned_offset,
            size: final_size,
            base,
        }
    }
}

pub fn pointer_delta(first: usize, second: usize) -> usize {
    second - first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_fd_registers_descriptor() {
        let mut cache = MmapCache::new();
        assert_eq!(cache.add_fd(3, PROT_READ).unwrap(), 0);
    }

    #[test]
    fn add_fd_reuses_same_descriptor() {
        let mut cache = MmapCache::new();
        let a = cache.add_fd(3, PROT_READ).unwrap();
        let b = cache.add_fd(3, PROT_READ).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn add_fd_rejects_protection_mismatch() {
        let mut cache = MmapCache::new();
        cache.add_fd(3, PROT_READ).unwrap();
        assert_eq!(cache.add_fd(3, 2), Err(CacheError::ProtectionMismatch));
    }

    #[test]
    fn two_reads_in_same_window_are_contiguous() {
        let mut cache = MmapCache::new();
        let fd = cache.add_fd(3, PROT_READ).unwrap();
        let p = cache.fd_get(fd, Category::Any, 1, 2).unwrap();
        let q = cache.fd_get(fd, Category::Any, 2, 2).unwrap();
        assert_eq!(pointer_delta(p, q), 1);
    }

    #[test]
    fn second_category_can_share_window() {
        let mut cache = MmapCache::new();
        let fd = cache.add_fd(3, PROT_READ).unwrap();
        let p = cache.fd_get(fd, Category::Any, 1, 2).unwrap();
        let q = cache.fd_get(fd, Category::Data, 3, 2).unwrap();
        assert_eq!(pointer_delta(p, q), 2);
    }

    #[test]
    fn high_offset_reads_remain_contiguous() {
        let mut cache = MmapCache::new();
        let fd = cache.add_fd(3, PROT_READ).unwrap();
        let p = cache
            .fd_get(fd, Category::Any, 16 * 1024 * 1024, 2)
            .unwrap();
        let q = cache
            .fd_get(fd, Category::Data, 16 * 1024 * 1024 + 1, 2)
            .unwrap();
        assert_eq!(pointer_delta(p, q), 1);
    }

    #[test]
    fn repeated_category_hits_update_stats() {
        let mut cache = MmapCache::new();
        let fd = cache.add_fd(3, PROT_READ).unwrap();
        let _ = cache.fd_get(fd, Category::Any, 1, 2).unwrap();
        let _ = cache.fd_get(fd, Category::Any, 2, 2).unwrap();
        assert_eq!(cache.stats.category_cache_hit, 1);
    }

    #[test]
    fn freeing_invalid_fd_fails() {
        let mut cache = MmapCache::new();
        assert_eq!(cache.free_fd(0), Err(CacheError::InvalidFd));
    }
}
