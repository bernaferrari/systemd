// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/mmap-cache.c
//

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EADDRNOTAVAIL: i32 = -(libc::EADDRNOTAVAIL as i32);
pub const NEG_EEXIST: i32 = -(libc::EEXIST as i32);
pub const WINDOWS_MIN: usize = 64;
pub const UNUSED_MIN: usize = 4;
pub const WINDOW_SIZE: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MMapCacheCategory {
    Any = 0,
    Data = 1,
    Field = 2,
    Entry = 3,
    DataHashTable = 4,
    FieldHashTable = 5,
    EntryArray = 6,
    Tag = 7,
    Header = 8,
    Pin = 9,
}

impl MMapCacheCategory {
    const COUNT: usize = 10;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    pub fd_index: usize,
    pub offset: u64,
    pub size: usize,
    pub categories: [bool; MMapCacheCategory::COUNT],
    pub keep_always: bool,
    pub invalidated: bool,
    pub in_unused: bool,
}

impl Window {
    pub fn matches(&self, fd_index: usize, offset: u64, size: usize) -> bool {
        self.fd_index == fd_index
            && offset >= self.offset
            && offset.saturating_add(size as u64) <= self.offset.saturating_add(self.size as u64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MMapFileDescriptor {
    pub fd: i32,
    pub prot: i32,
    pub sigbus: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MMapCache {
    pub n_ref: u32,
    pub n_category_cache_hit: u32,
    pub n_window_list_hit: u32,
    pub n_missed: u32,
    pub fds: Vec<MMapFileDescriptor>,
    pub windows: Vec<Window>,
    pub unused: Vec<usize>,
    pub windows_by_category: [Option<usize>; MMapCacheCategory::COUNT],
}

impl Default for MMapCache {
    fn default() -> Self {
        Self {
            n_ref: 1,
            n_category_cache_hit: 0,
            n_window_list_hit: 0,
            n_missed: 0,
            fds: Vec::new(),
            windows: Vec::new(),
            unused: Vec::new(),
            windows_by_category: [None; MMapCacheCategory::COUNT],
        }
    }
}

impl MMapCache {
    pub fn add_fd(&mut self, fd: i32, prot: i32) -> Result<usize> {
        if let Some((index, existing)) = self
            .fds
            .iter()
            .enumerate()
            .find(|(_, existing)| existing.fd == fd)
        {
            return if existing.prot == prot {
                Ok(index)
            } else {
                Err(NEG_EEXIST)
            };
        }

        self.fds.push(MMapFileDescriptor {
            fd,
            prot,
            sigbus: false,
        });
        Ok(self.fds.len() - 1)
    }

    pub fn add_window(&mut self, fd_index: usize, offset: u64, size: usize) -> Result<usize> {
        if fd_index >= self.fds.len() || size == 0 {
            return Err(NEG_EADDRNOTAVAIL);
        }

        let window = Window {
            fd_index,
            offset,
            size: size.max(WINDOW_SIZE.min(size)),
            categories: [false; MMapCacheCategory::COUNT],
            keep_always: false,
            invalidated: false,
            in_unused: false,
        };
        self.windows.push(window);
        Ok(self.windows.len() - 1)
    }

    pub fn category_attach_window(&mut self, category: MMapCacheCategory, index: usize) {
        self.category_detach_window(category);
        self.windows[index].categories[category as usize] = true;
        self.windows[index].in_unused = false;
        self.windows_by_category[category as usize] = Some(index);
    }

    pub fn category_detach_window(&mut self, category: MMapCacheCategory) {
        if let Some(index) = self.windows_by_category[category as usize].take() {
            self.windows[index].categories[category as usize] = false;
            if !self.windows[index].categories.iter().any(|used| *used)
                && !self.windows[index].keep_always
            {
                self.windows[index].in_unused = true;
                self.unused.push(index);
            }
        }
    }

    pub fn find_window(&mut self, fd_index: usize, offset: u64, size: usize) -> Option<usize> {
        let found = self
            .windows
            .iter()
            .position(|window| window.matches(fd_index, offset, size));
        if found.is_some() {
            self.n_window_list_hit += 1;
        } else {
            self.n_missed += 1;
        }
        found
    }

    pub fn invalidate_window(&mut self, index: usize) {
        self.windows[index].invalidated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_new_fd() {
        let mut cache = MMapCache::default();
        assert_eq!(cache.add_fd(3, libc::PROT_READ), Ok(0));
    }

    #[test]
    fn reuses_fd_with_same_protection() {
        let mut cache = MMapCache::default();
        cache.add_fd(3, libc::PROT_READ).unwrap();
        assert_eq!(cache.add_fd(3, libc::PROT_READ), Ok(0));
    }

    #[test]
    fn rejects_fd_with_different_protection() {
        let mut cache = MMapCache::default();
        cache.add_fd(3, libc::PROT_READ).unwrap();
        assert_eq!(cache.add_fd(3, libc::PROT_WRITE), Err(NEG_EEXIST));
    }

    #[test]
    fn adds_window() {
        let mut cache = MMapCache::default();
        let fd = cache.add_fd(3, libc::PROT_READ).unwrap();
        assert_eq!(cache.add_window(fd, 128, 4096), Ok(0));
    }

    #[test]
    fn window_matches_range_inside_mapping() {
        let window = Window {
            fd_index: 0,
            offset: 100,
            size: 1000,
            categories: [false; MMapCacheCategory::COUNT],
            keep_always: false,
            invalidated: false,
            in_unused: false,
        };
        assert!(window.matches(0, 200, 100));
    }

    #[test]
    fn attaches_and_detaches_category() {
        let mut cache = MMapCache::default();
        let fd = cache.add_fd(3, libc::PROT_READ).unwrap();
        let window = cache.add_window(fd, 0, 4096).unwrap();
        cache.category_attach_window(MMapCacheCategory::Header, window);
        assert_eq!(
            cache.windows_by_category[MMapCacheCategory::Header as usize],
            Some(window)
        );
        cache.category_detach_window(MMapCacheCategory::Header);
        assert_eq!(
            cache.windows_by_category[MMapCacheCategory::Header as usize],
            None
        );
    }

    #[test]
    fn find_window_tracks_hits() {
        let mut cache = MMapCache::default();
        let fd = cache.add_fd(3, libc::PROT_READ).unwrap();
        cache.add_window(fd, 0, 4096).unwrap();
        assert_eq!(cache.find_window(fd, 0, 1024), Some(0));
        assert_eq!(cache.n_window_list_hit, 1);
    }

    #[test]
    fn find_window_tracks_misses() {
        let mut cache = MMapCache::default();
        let fd = cache.add_fd(3, libc::PROT_READ).unwrap();
        assert_eq!(cache.find_window(fd, 0, 1024), None);
        assert_eq!(cache.n_missed, 1);
    }

    #[test]
    fn invalidate_window_marks_window() {
        let mut cache = MMapCache::default();
        let fd = cache.add_fd(3, libc::PROT_READ).unwrap();
        let index = cache.add_window(fd, 0, 4096).unwrap();
        cache.invalidate_window(index);
        assert!(cache.windows[index].invalidated);
    }
}
