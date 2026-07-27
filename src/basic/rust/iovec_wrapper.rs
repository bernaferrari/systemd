// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/iovec-wrapper.c, src/basic/iovec-wrapper.h

use crate::ffi::Errno;

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
