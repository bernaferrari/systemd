// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/memory-util.c, src/basic/memory-util.h
//
// Memory utility functions.

use std::cmp::Ordering;
use std::sync::OnceLock;

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    InvalidLength,
    SystemPageSizeUnavailable,
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid slice length"),
            Self::SystemPageSizeUnavailable => write!(f, "system page size unavailable"),
        }
    }
}

impl std::error::Error for MemoryError {}

// ── page_size ─────────────────────────────────────────────────────────────

static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

pub fn page_size() -> Result<usize, MemoryError> {
    PAGE_SIZE.get_or_init(|| {
        // SAFETY: arguments satisfy the libc `sysconf` contract and any passed pointers remain valid for the call.
        let r = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if r <= 0 {
            4096_usize // fallback
        } else {
            r as usize
        }
    });
    Ok(*PAGE_SIZE.get().unwrap())
}

// ── Basic operations ──────────────────────────────────────────────────────

pub fn memdup_reverse(data: &[u8]) -> Result<Vec<u8>, MemoryError> {
    if data.is_empty() {
        return Err(MemoryError::InvalidLength);
    }

    let mut out = data.to_vec();
    out.reverse();
    Ok(out)
}

pub fn memcpy_safe(dst: &mut [u8], src: &[u8], n: usize) -> Result<(), MemoryError> {
    if n == 0 {
        return Ok(());
    }
    if dst.len() < n || src.len() < n {
        return Err(MemoryError::InvalidLength);
    }

    dst[..n].copy_from_slice(&src[..n]);
    Ok(())
}

pub fn mempcpy_safe(dst: &mut [u8], src: &[u8], n: usize) -> Result<usize, MemoryError> {
    memcpy_safe(dst, src, n)?;
    Ok(n)
}

pub fn memcmp_safe(s1: &[u8], s2: &[u8], n: usize) -> Result<i32, MemoryError> {
    if n == 0 {
        return Ok(0);
    }
    if s1.len() < n || s2.len() < n {
        return Err(MemoryError::InvalidLength);
    }

    for (a, b) in s1[..n].iter().zip(&s2[..n]) {
        if a != b {
            return Ok(i32::from(*a) - i32::from(*b));
        }
    }

    Ok(0)
}

pub fn memcmp_nn(s1: &[u8], s2: &[u8]) -> i32 {
    let common = s1.len().min(s2.len());
    let cmp = memcmp_safe(s1, s2, common).expect("common prefix length is valid");
    if cmp != 0 {
        return cmp;
    }

    match s1.len().cmp(&s2.len()) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

pub fn mempset(buf: &mut [u8], byte: u8, n: usize) -> Result<usize, MemoryError> {
    if buf.len() < n {
        return Err(MemoryError::InvalidLength);
    }

    buf[..n].fill(byte);
    Ok(n)
}

pub fn memmem_safe(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }

    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn mempmem_safe(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memmem_safe(haystack, needle).map(|i| i + needle.len())
}

pub fn memeqbyte(byte: u8, data: &[u8]) -> bool {
    data.iter().all(|b| *b == byte)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_is_cached_and_positive() {
        let a = page_size().unwrap();
        let b = page_size().unwrap();
        assert!(a > 0);
        assert_eq!(a, b);
    }

    #[test]
    fn memdup_reverse_reverses_bytes() {
        assert_eq!(memdup_reverse(&[1, 2, 3, 4]).unwrap(), vec![4, 3, 2, 1]);
    }

    #[test]
    fn memdup_reverse_rejects_empty() {
        assert_eq!(memdup_reverse(&[]), Err(MemoryError::InvalidLength));
    }

    #[test]
    fn memcpy_safe_copies_prefix() {
        let mut dst = [0u8; 4];
        memcpy_safe(&mut dst, &[9, 8, 7, 6], 3).unwrap();
        assert_eq!(dst, [9, 8, 7, 0]);
    }

    #[test]
    fn mempcpy_safe_returns_end_offset() {
        let mut dst = [0u8; 3];
        assert_eq!(mempcpy_safe(&mut dst, &[1, 2, 3], 3).unwrap(), 3);
        assert_eq!(dst, [1, 2, 3]);
    }

    #[test]
    fn memcmp_safe_matches_c_ordering() {
        assert_eq!(memcmp_safe(b"abc", b"abc", 3).unwrap(), 0);
        assert!(memcmp_safe(b"abc", b"abd", 3).unwrap() < 0);
        assert!(memcmp_safe(b"abd", b"abc", 3).unwrap() > 0);
    }

    #[test]
    fn memcmp_nn_uses_length_when_prefix_matches() {
        assert_eq!(memcmp_nn(b"abc", b"abc"), 0);
        assert!(memcmp_nn(b"abc", b"abcd") < 0);
        assert!(memcmp_nn(b"abcd", b"abc") > 0);
    }

    #[test]
    fn mempset_sets_bytes_and_returns_past_end() {
        let mut buf = [0u8; 5];
        assert_eq!(mempset(&mut buf, 0x7f, 4).unwrap(), 4);
        assert_eq!(buf, [0x7f, 0x7f, 0x7f, 0x7f, 0]);
    }

    #[test]
    fn memmem_safe_handles_empty_and_miss() {
        assert_eq!(memmem_safe(b"abcdef", b""), Some(0));
        assert_eq!(memmem_safe(b"abcdef", b"cd"), Some(2));
        assert_eq!(memmem_safe(b"abcdef", b"xy"), None);
    }

    #[test]
    fn mempmem_safe_returns_end_of_match() {
        assert_eq!(mempmem_safe(b"abcdef", b"cd"), Some(4));
        assert_eq!(mempmem_safe(b"abcdef", b"xy"), None);
    }

    #[test]
    fn memeqbyte_checks_uniform_buffers() {
        assert!(memeqbyte(0x42, &[0x42; 32]));
        assert!(!memeqbyte(0x42, &[0x42, 0x42, 0x41]));
        assert!(memeqbyte(0, &[]));
    }
}
