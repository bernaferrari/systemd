// SPDX-License-Identifier: CC0-1.0
//
// PORT-SYNC: scope=basic.siphash24; authority=src/basic/siphash24.c,src/basic/siphash24.h
//
// SipHash-2-4 cryptographic hash (pure Rust implementation).

use libc::{c_char, c_void};
use std::{ffi::CStr, ptr, slice};

// ── Struct ────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SipHash {
    pub v0: u64,
    pub v1: u64,
    pub v2: u64,
    pub v3: u64,
    pub padding: u64,
    pub inlen: usize,
}

// The exported C ABI deliberately uses the C structure spelling. Keeping the
// alias local to this facade lets the safe implementation retain Rust naming.
#[allow(non_camel_case_types)]
pub type siphash = SipHash;

impl Default for SipHash {
    fn default() -> Self {
        SipHash {
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            padding: 0,
            inlen: 0,
        }
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────

#[inline(always)]
fn rotate_left(x: u64, b: u8) -> u64 {
    let b = b & 63;
    (x << b) | (x >> (64 - b))
}

fn sipround(state: &mut SipHash) {
    state.v0 = state.v0.wrapping_add(state.v1);
    state.v1 = rotate_left(state.v1, 13);
    state.v1 ^= state.v0;
    state.v0 = rotate_left(state.v0, 32);
    state.v2 = state.v2.wrapping_add(state.v3);
    state.v3 = rotate_left(state.v3, 16);
    state.v3 ^= state.v2;
    state.v0 = state.v0.wrapping_add(state.v3);
    state.v3 = rotate_left(state.v3, 21);
    state.v3 ^= state.v0;
    state.v2 = state.v2.wrapping_add(state.v1);
    state.v1 = rotate_left(state.v1, 17);
    state.v1 ^= state.v2;
    state.v2 = rotate_left(state.v2, 32);
}

fn read_le64(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let len = data.len().min(8);
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(bytes)
}

// ── siphash24_init ────────────────────────────────────────────────────────

pub fn siphash24_init(k: &[u8; 16]) -> SipHash {
    let k0 = u64::from_le_bytes(k[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(k[8..16].try_into().unwrap());

    SipHash {
        v0: 0x736f6d6570736575 ^ k0,
        v1: 0x646f72616e646f6d ^ k1,
        v2: 0x6c7967656e657261 ^ k0,
        v3: 0x7465646279746573 ^ k1,
        padding: 0,
        inlen: 0,
    }
}

// ── siphash24_compress ────────────────────────────────────────────────────

pub fn siphash24_compress(data: &[u8], state: &mut SipHash) {
    if data.is_empty() {
        return;
    }

    let mut pos = 0;
    let mut left = state.inlen & 7;

    state.inlen = state.inlen.wrapping_add(data.len());

    // Fill existing padding
    if left > 0 {
        while pos < data.len() && left < 8 {
            state.padding |= (data[pos] as u64) << (left * 8);
            pos += 1;
            left += 1;
        }

        if pos == data.len() && left < 8 {
            return;
        }

        state.v3 ^= state.padding;
        sipround(state);
        sipround(state);
        state.v0 ^= state.padding;
        state.padding = 0;
    }

    // Process 8-byte blocks
    let end_full = data.len() - (state.inlen % 8);
    while pos + 8 <= end_full {
        let m = read_le64(&data[pos..pos + 8]);
        state.v3 ^= m;
        sipround(state);
        sipround(state);
        state.v0 ^= m;
        pos += 8;
    }

    // Collect remaining bytes into padding
    left = state.inlen & 7;
    for i in 0..left {
        if pos + i < data.len() {
            state.padding |= (data[pos + i] as u64) << (i * 8);
        }
    }
}

// ── siphash24_compress_byte ───────────────────────────────────────────────

pub fn siphash24_compress_byte(byte: u8, state: &mut SipHash) {
    siphash24_compress(&[byte], state);
}

// ── siphash24_compress_string ─────────────────────────────────────────────

pub fn siphash24_compress_string(s: &str, state: &mut SipHash) {
    if !s.is_empty() {
        siphash24_compress(s.as_bytes(), state);
    }
}

// ── siphash24_finalize ────────────────────────────────────────────────────

pub fn siphash24_finalize(state: &mut SipHash) -> u64 {
    let b = state.padding | ((state.inlen as u64) << 56);

    state.v3 ^= b;
    sipround(state);
    sipround(state);
    state.v0 ^= b;

    state.v2 ^= 0xff;

    sipround(state);
    sipround(state);
    sipround(state);
    sipround(state);

    state.v0 ^ state.v1 ^ state.v2 ^ state.v3
}

// ── siphash24 ─────────────────────────────────────────────────────────────

pub fn siphash24(data: &[u8], k: &[u8; 16]) -> u64 {
    let mut state = siphash24_init(k);
    siphash24_compress(data, &mut state);
    siphash24_finalize(&mut state)
}

// ── siphash24_string ──────────────────────────────────────────────────────

/// Hash a NUL-terminated string (includes the NUL byte in the hash).
/// Equivalent to C `siphash24_string(s, k)`.
pub fn siphash24_string(s: &str, k: &[u8; 16]) -> u64 {
    let mut state = siphash24_init(k);
    siphash24_compress(s.as_bytes(), &mut state);
    siphash24_compress_byte(0, &mut state);
    siphash24_finalize(&mut state)
}

// ── C ABI shadow facade ──────────────────────────────────────────────────

/// Initialize a C-layout SipHash state.
///
/// # Safety
///
/// `state` must point to writable, properly aligned storage for one
/// `SipHash`, and `k` must designate 16 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_siphash24_init(state: *mut siphash, k: *const u8) {
    if state.is_null() || k.is_null() {
        return;
    }

    // SAFETY: the caller guarantees a readable 16-byte key.
    let key = unsafe { &*k.cast::<[u8; 16]>() };
    // SAFETY: the caller guarantees writable aligned state storage.
    unsafe { ptr::write(state, siphash24_init(key)) };
}

/// Compress bytes into a C-layout SipHash state.
///
/// # Safety
///
/// `state` must point to an initialized, exclusively accessible `SipHash`.
/// `input` must be non-NULL and designate `inlen` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_siphash24_compress(
    input: *const c_void,
    inlen: usize,
    state: *mut siphash,
) {
    if state.is_null() || input.is_null() {
        return;
    }

    let data = if inlen == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees a readable `inlen`-byte region.
        unsafe { slice::from_raw_parts(input.cast::<u8>(), inlen) }
    };
    // SAFETY: the caller guarantees live, initialized, exclusive state.
    siphash24_compress(data, unsafe { &mut *state });
}

/// Compress the bytes preceding the NUL terminator of `input`.
///
/// C's `siphash24_compress_string(NULL, state)` is a no-op.
///
/// # Safety
///
/// `state` must point to an initialized, exclusively accessible `SipHash`.
/// `input`, when non-NULL, must point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_siphash24_compress_string(input: *const c_char, state: *mut siphash) {
    if state.is_null() || input.is_null() {
        return;
    }

    // SAFETY: required by this entry point's C-string contract.
    let data = unsafe { CStr::from_ptr(input) }.to_bytes();
    // SAFETY: the caller guarantees live, initialized, exclusive state.
    siphash24_compress(data, unsafe { &mut *state });
}

/// Finalize a C-layout SipHash state.
///
/// # Safety
///
/// `state` must point to an initialized, exclusively accessible `SipHash`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_siphash24_finalize(state: *mut siphash) -> u64 {
    if state.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees live, initialized, exclusive state.
    siphash24_finalize(unsafe { &mut *state })
}

/// One-shot SipHash-2-4 C facade.
///
/// # Safety
///
/// `input` must designate `inlen` readable bytes (including for zero-length
/// input, matching C's non-NULL precondition), and `k` must designate 16
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_siphash24(input: *const c_void, inlen: usize, k: *const u8) -> u64 {
    if input.is_null() || k.is_null() {
        return 0;
    }

    let data = if inlen == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees a readable `inlen`-byte region.
        unsafe { slice::from_raw_parts(input.cast::<u8>(), inlen) }
    };
    // SAFETY: the caller guarantees a readable 16-byte key.
    let key = unsafe { &*k.cast::<[u8; 16]>() };
    siphash24(data, key)
}

/// Hash a NUL-terminated string including its terminating NUL byte.
///
/// # Safety
///
/// `s` must point to a live NUL-terminated C string and `k` must designate 16
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_siphash24_string(s: *const c_char, k: *const u8) -> u64 {
    if s.is_null() || k.is_null() {
        return 0;
    }

    // SAFETY: required by this entry point's C-string contract.
    let bytes_with_nul = unsafe { CStr::from_ptr(s) }.to_bytes_with_nul();
    // SAFETY: the caller guarantees a readable 16-byte key.
    let key = unsafe { &*k.cast::<[u8; 16]>() };
    siphash24(bytes_with_nul, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siphash24_init_zero_key() {
        let key = [0u8; 16];
        let state = siphash24_init(&key);
        assert_eq!(state.v0, 0x736f6d6570736575);
        assert_eq!(state.v1, 0x646f72616e646f6d);
        assert_eq!(state.v2, 0x6c7967656e657261);
        assert_eq!(state.v3, 0x7465646279746573);
        assert_eq!(state.padding, 0);
        assert_eq!(state.inlen, 0);
    }

    #[test]
    fn test_siphash24_init_nonzero_key() {
        let key: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let state = siphash24_init(&key);
        assert_ne!(state.v0, 0);
        assert_ne!(state.v1, 0);
        assert_ne!(state.v2, 0);
        assert_ne!(state.v3, 0);
    }

    #[test]
    fn test_siphash24_deterministic() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let data = [0u8; 15];
        let r1 = siphash24(&data, &key);
        let r2 = siphash24(&data, &key);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_siphash24_different_keys() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let data = [0u8; 8];
        let r1 = siphash24(&data, &key1);
        let r2 = siphash24(&data, &key2);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_siphash24_different_data() {
        let key = [0u8; 16];
        let d1 = [0u8; 8];
        let d2 = [1u8; 8];
        let r1 = siphash24(&d1, &key);
        let r2 = siphash24(&d2, &key);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_siphash24_empty_input() {
        let key = [0u8; 16];
        let result = siphash24(&[], &key);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_siphash24_single_byte() {
        let key = [0u8; 16];
        let data = [0x00u8];
        let r1 = siphash24(&data, &key);
        let r2 = siphash24(&data, &key);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_siphash24_various_lengths() {
        let key = [0x42u8; 16];
        let mut hashes = Vec::new();
        for len in 0..16usize {
            let data = vec![0u8; len];
            hashes.push(siphash24(&data, &key));
        }
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "hashes for len {} and {} should differ",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_siphash24_multi_compress() {
        let key = [0u8; 16];

        let mut state = siphash24_init(&key);
        siphash24_compress(b"hello", &mut state);
        siphash24_compress(b" world", &mut state);
        let result = siphash24_finalize(&mut state);

        let combined = b"hello world";
        let expected = siphash24(combined, &key);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_siphash24_compress_string_empty() {
        let key = [0u8; 16];
        let mut state = siphash24_init(&key);
        siphash24_compress_string("", &mut state);
        assert_eq!(state.inlen, 0);
    }

    #[test]
    fn test_siphash24_compress_string_nonempty() {
        let key = [0u8; 16];
        let mut state = siphash24_init(&key);
        siphash24_compress_string("hello", &mut state);
        assert_eq!(state.inlen, 5);
    }

    #[test]
    fn test_siphash24_string_deterministic() {
        let key = [0x42u8; 16];
        let r1 = siphash24_string("test", &key);
        let r2 = siphash24_string("test", &key);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_siphash24_string_different_strings() {
        let key = [0x42u8; 16];
        let r1 = siphash24_string("hello", &key);
        let r2 = siphash24_string("world", &key);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_siphash24_large_input() {
        let key = [0u8; 16];
        let data = vec![0xABu8; 1024];
        let result = siphash24(&data, &key);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_siphash24_all_lengths_0_to_63() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        for len in 0..=63usize {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let hash = siphash24(&data, &key);
            assert_ne!(hash, 0);
        }
    }

    #[test]
    fn test_siphash24_compress_byte() {
        let key = [0u8; 16];
        let mut state = siphash24_init(&key);
        siphash24_compress_byte(0x42, &mut state);
        assert_eq!(state.inlen, 1);
    }

    #[test]
    fn test_siphash24_default_state() {
        let state = SipHash::default();
        assert_eq!(state.v0, 0);
        assert_eq!(state.inlen, 0);
    }
}
