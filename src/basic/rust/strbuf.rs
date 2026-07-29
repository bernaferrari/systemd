// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.strbuf; authority=src/basic/strbuf.c,src/basic/strbuf.h
//
// strbuf: trie-based string buffer with deduplication.

// ── Internal types ──────────────────────────────────────────────────────────

struct StrbufNode {
    value_off: usize,
    value_len: usize,
    children: Vec<StrbufChildEntry>,
}

struct StrbufChildEntry {
    c: u8,
    child_idx: usize,
}

enum SearchOutcome {
    Found { offset: usize },
    NotFound { parent_idx: usize, child_char: u8 },
}

// ── Public type ─────────────────────────────────────────────────────────────

pub struct Strbuf {
    buf: Vec<u8>,
    nodes: Vec<StrbufNode>,
    root_idx: Option<usize>,
    pub nodes_count: usize,
    pub in_count: usize,
    pub in_len: usize,
    pub dedup_len: usize,
    pub dedup_count: usize,
}

/// Opaque ABI handle. Its storage contains a Rust [`Strbuf`], but C only ever
/// receives this incomplete pointer type and must return it to
/// `rs_strbuf_free()` rather than calling `free(3)` directly.
#[repr(C)]
pub struct RsStrbuf {
    _opaque: [u8; 0],
}

impl Strbuf {
    /// Create a new empty strbuf.
    /// Equivalent to C strbuf_new().
    pub fn new() -> Result<Self, i32> {
        let nodes = vec![StrbufNode {
            value_off: 0,
            value_len: 0,
            children: Vec::new(),
        }];
        let mut buf = Vec::with_capacity(64);
        buf.push(0);
        Ok(Strbuf {
            buf,
            nodes,
            root_idx: Some(0),
            nodes_count: 1,
            in_count: 0,
            in_len: 0,
            dedup_len: 0,
            dedup_count: 0,
        })
    }

    /// Get the string at the given buffer offset.
    pub fn get(&self, offset: usize) -> Option<&[u8]> {
        if offset >= self.buf.len() {
            return None;
        }
        let end = self.buf[offset..].iter().position(|&b| b == 0)?;
        Some(&self.buf[offset..offset + end])
    }

    /// Add a string to the buffer. If `len == usize::MAX`, auto-detect from `s`.
    /// Returns the offset into the buffer, or a negative errno on failure.
    /// Equivalent to C strbuf_add_string_full().
    pub fn add_string_full(&mut self, s: &[u8], len: usize) -> Result<usize, i32> {
        let effective_len = if len == usize::MAX { s.len() } else { len };

        if self.root_idx.is_none() {
            return Err(-22); // -EINVAL
        }

        self.in_count += 1;
        if effective_len == 0 {
            self.dedup_count += 1;
            return Ok(0);
        }
        self.in_len += effective_len;

        // Phase 1: search (read-only)
        let outcome = self.search(effective_len, s);

        match outcome {
            SearchOutcome::Found { offset } => {
                self.dedup_len += effective_len;
                self.dedup_count += 1;
                Ok(offset)
            }
            SearchOutcome::NotFound {
                parent_idx,
                child_char,
            } => {
                // Phase 2: insert
                self.insert_new(s, effective_len, parent_idx, child_char)
            }
        }
    }

    /// Convenience wrapper: add a string with auto-detected length.
    pub fn add_string(&mut self, s: &[u8]) -> Result<usize, i32> {
        self.add_string_full(s, usize::MAX)
    }

    /// Clean up trie data, leaving only the string buffer.
    /// Equivalent to C strbuf_complete().
    pub fn complete(&mut self) {
        self.root_idx = None;
        self.nodes.clear();
        // C frees the trie but retains this cumulative diagnostic counter.
    }

    fn search(&self, len: usize, s: &[u8]) -> SearchOutcome {
        let mut node_idx = self.root_idx.unwrap();
        for depth in 0..=len {
            let node = &self.nodes[node_idx];
            let off = (node.value_off + node.value_len) as isize - len as isize;
            if off >= 0 {
                let off_u = off as usize;
                if off_u + len <= self.buf.len()
                    && (depth == len
                        || (node.value_len >= len && self.buf[off_u..off_u + len] == s[..len]))
                {
                    return SearchOutcome::Found { offset: off_u };
                }
            }
            if depth == len {
                break;
            }
            let c = s[len - 1 - depth];
            match find_child_index(&node.children, c) {
                Some(child_idx) => node_idx = child_idx,
                None => {
                    return SearchOutcome::NotFound {
                        parent_idx: node_idx,
                        child_char: c,
                    };
                }
            }
        }
        SearchOutcome::NotFound {
            parent_idx: node_idx,
            child_char: 0,
        }
    }

    fn insert_new(
        &mut self,
        s: &[u8],
        len: usize,
        parent_idx: usize,
        child_char: u8,
    ) -> Result<usize, i32> {
        let off = self.buf.len();
        self.buf.extend_from_slice(&s[..len]);
        self.buf.push(0);

        let new_node_idx = self.nodes.len();
        self.nodes.push(StrbufNode {
            value_off: off,
            value_len: len,
            children: Vec::new(),
        });

        {
            let parent = &mut self.nodes[parent_idx];
            let entry = StrbufChildEntry {
                c: child_char,
                child_idx: new_node_idx,
            };
            match parent.children.binary_search_by(|e| e.c.cmp(&child_char)) {
                Ok(_) => {}
                Err(pos) => parent.children.insert(pos, entry),
            }
        }

        self.nodes_count += 1;
        Ok(off)
    }
}

fn find_child_index(children: &[StrbufChildEntry], c: u8) -> Option<usize> {
    match children.binary_search_by(|e| e.c.cmp(&c)) {
        Ok(idx) => Some(children[idx].child_idx),
        Err(_) => None,
    }
}

// ── C ABI facades ────────────────────────────────────────────────────────

/// Allocate an opaque strbuf handle.
///
/// The exposed handle itself uses malloc(3), so it follows the same allocator
/// family as C's `strbuf_new()`. Its Rust-owned internals are released only by
/// `rs_strbuf_free()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_strbuf_new() -> *mut RsStrbuf {
    // SAFETY: malloc accepts this nonzero layout size and returns storage from
    // the C allocator used for the opaque handle's final release.
    let storage = unsafe { libc::malloc(std::mem::size_of::<Strbuf>()) }.cast::<Strbuf>();
    if storage.is_null() {
        return std::ptr::null_mut();
    }

    let value = match Strbuf::new() {
        Ok(value) => value,
        Err(_) => {
            // SAFETY: `storage` was allocated above and has not been initialized.
            unsafe { libc::free(storage.cast()) };
            return std::ptr::null_mut();
        }
    };
    // SAFETY: malloc returned storage sized and aligned for Strbuf; it is
    // uninitialized and uniquely owned at this point.
    unsafe { std::ptr::write(storage, value) };
    storage.cast::<RsStrbuf>()
}

/// Append `len` opaque bytes and return their strbuf offset, or a negative
/// errno. `usize::MAX` has C's SIZE_MAX meaning: derive the length from the
/// NUL-terminated input.
///
/// # Safety
///
/// `str` must be a live handle returned by `rs_strbuf_new()`.  For explicit
/// nonzero `len`, `s` must reference at least `len` readable bytes; those bytes
/// need not be valid UTF-8 or NUL-terminated. For `SIZE_MAX`, `s` must be a
/// live NUL-terminated C string. The handle must not be concurrently accessed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strbuf_add_string_full(
    str: *mut RsStrbuf,
    s: *const libc::c_char,
    len: usize,
) -> isize {
    if str.is_null() || (s.is_null() && len != 0) {
        return -(libc::EINVAL as isize);
    }

    let bytes: &[u8] = if len == usize::MAX {
        if s.is_null() {
            return -(libc::EINVAL as isize);
        }
        // SAFETY: required by the SIZE_MAX branch of this export's contract.
        unsafe { std::ffi::CStr::from_ptr(s) }.to_bytes()
    } else if len == 0 {
        &[]
    } else {
        // SAFETY: required by the explicit-length branch of this export's contract.
        unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len) }
    };

    // SAFETY: the opaque handle's allocation was initialized by rs_strbuf_new.
    let buffer = unsafe { &mut *str.cast::<Strbuf>() };
    match buffer.add_string_full(bytes, len) {
        Ok(offset) if offset <= isize::MAX as usize => offset as isize,
        Ok(_) => -(libc::EOVERFLOW as isize),
        Err(error) => error as isize,
    }
}

/// Discard the trie while retaining string storage. A null handle is a no-op,
/// exactly as C `strbuf_complete()`.
///
/// # Safety
///
/// A non-null `str` must be a live, exclusive handle returned by
/// `rs_strbuf_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strbuf_complete(str: *mut RsStrbuf) {
    if str.is_null() {
        return;
    }
    // SAFETY: upheld by this export's opaque-handle contract.
    unsafe { (&mut *str.cast::<Strbuf>()).complete() };
}

/// Destroy an opaque handle and return null, matching the C cleanup helper.
///
/// # Safety
///
/// A non-null `str` must be the unique, still-live pointer returned by
/// `rs_strbuf_new()`. It must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strbuf_free(str: *mut RsStrbuf) -> *mut RsStrbuf {
    if str.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the handle was initialized in malloc(3) storage by
    // rs_strbuf_new. Dropping releases Rust-owned Vec allocations before the
    // C-allocator storage for the opaque handle itself is returned to libc.
    unsafe {
        std::ptr::drop_in_place(str.cast::<Strbuf>());
        libc::free(str.cast());
    }
    std::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strbuf_new() {
        let buf = Strbuf::new().unwrap();
        assert_eq!(buf.buf.len(), 1);
        assert_eq!(buf.nodes_count, 1);
        assert_eq!(buf.in_count, 0);
        assert_eq!(buf.dedup_count, 0);
        assert!(buf.root_idx.is_some());
    }

    #[test]
    fn test_strbuf_add_empty_string() {
        let mut buf = Strbuf::new().unwrap();
        let ret = buf.add_string_full(b"", 0).unwrap();
        assert_eq!(ret, 0);
        assert_eq!(buf.dedup_count, 1);
        assert_eq!(buf.in_count, 1);
    }

    #[test]
    fn test_strbuf_add_single() {
        let mut buf = Strbuf::new().unwrap();
        let ret = buf.add_string_full(b"hello", 5).unwrap();
        assert!(ret > 0);
        assert_eq!(buf.in_count, 1);
        assert_eq!(buf.dedup_count, 0);
        assert_eq!(buf.get(ret), Some(&b"hello"[..]));
    }

    #[test]
    fn test_strbuf_add_duplicate() {
        let mut buf = Strbuf::new().unwrap();
        let r1 = buf.add_string_full(b"hello", 5).unwrap();
        let r2 = buf.add_string_full(b"hello", 5).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(buf.in_count, 2);
        assert_eq!(buf.dedup_count, 1);
        assert_eq!(buf.dedup_len, 5);
    }

    #[test]
    fn test_strbuf_add_multiple_different() {
        let mut buf = Strbuf::new().unwrap();
        let r1 = buf.add_string_full(b"hello", 5).unwrap();
        let r2 = buf.add_string_full(b"world", 5).unwrap();
        let r3 = buf.add_string_full(b"foo", 3).unwrap();
        assert!(r1 != r2);
        assert!(r2 != r3);
        assert!(r1 != r3);
        assert_eq!(buf.in_count, 3);
        assert_eq!(buf.dedup_count, 0);
    }

    #[test]
    fn test_strbuf_add_single_char() {
        let mut buf = Strbuf::new().unwrap();
        let r1 = buf.add_string_full(b"a", 1).unwrap();
        let r2 = buf.add_string_full(b"a", 1).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(buf.dedup_count, 1);
    }

    #[test]
    fn test_strbuf_add_auto_len() {
        let mut buf = Strbuf::new().unwrap();
        let ret = buf.add_string(b"hello").unwrap();
        assert!(ret > 0);
        assert_eq!(buf.in_count, 1);
        assert_eq!(buf.get(ret), Some(&b"hello"[..]));
    }

    #[test]
    fn test_strbuf_complete() {
        let mut buf = Strbuf::new().unwrap();
        buf.add_string_full(b"test", 4).unwrap();
        buf.complete();
        assert!(buf.root_idx.is_none());
        assert!(buf.nodes.is_empty());
        // Buffer content should still be accessible
        assert!(!buf.buf.is_empty());
    }

    #[test]
    fn test_strbuf_complete_then_get() {
        let mut buf = Strbuf::new().unwrap();
        let off = buf.add_string_full(b"test", 4).unwrap();
        buf.complete();
        assert_eq!(buf.get(off), Some(&b"test"[..]));
    }

    #[test]
    fn test_strbuf_prefix_overlap() {
        let mut buf = Strbuf::new().unwrap();
        let r1 = buf.add_string_full(b"abc", 3).unwrap();
        let r2 = buf.add_string_full(b"abcd", 4).unwrap();
        let r3 = buf.add_string_full(b"abc", 3).unwrap();
        assert_eq!(r1, r3);
        assert!(r1 != r2);
        assert_eq!(buf.dedup_count, 1);
    }

    #[test]
    fn test_strbuf_suffix_dedup() {
        let mut buf = Strbuf::new().unwrap();
        let r1 = buf.add_string_full(b"hello", 5).unwrap();
        let r2 = buf.add_string_full(b"lo", 2).unwrap();
        assert_ne!(r1, r2);
        assert_eq!(buf.dedup_count, 1);
        assert_eq!(buf.dedup_len, 2);
    }

    #[test]
    fn test_strbuf_many_strings() {
        let mut buf = Strbuf::new().unwrap();
        let strings: Vec<Vec<u8>> = (0..100).map(|i| format!("str{}", i).into_bytes()).collect();
        let mut offsets = Vec::new();
        for s in &strings {
            let ret = buf.add_string(s).unwrap();
            assert!(ret > 0);
            offsets.push(ret);
        }
        assert_eq!(buf.in_count, 100);
        for s in &strings {
            buf.add_string(s).unwrap();
        }
        assert_eq!(buf.dedup_count, 100);
        // Verify content
        for (i, s) in strings.iter().enumerate() {
            assert_eq!(buf.get(offsets[i]), Some(s.as_slice()));
        }
    }

    #[test]
    fn test_strbuf_get_out_of_bounds() {
        let buf = Strbuf::new().unwrap();
        assert_eq!(buf.get(999), None);
    }
}
