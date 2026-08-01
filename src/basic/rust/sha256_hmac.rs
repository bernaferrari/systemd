// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.sha256-hmac; authority=src/basic/hmac.c,src/basic/hmac.h,src/basic/sha256.c,src/basic/sha256.h,src/fundamental/sha256.c,src/fundamental/sha256.h
//
// SHA-256 hash, validation/parsing, and HMAC-SHA-256 computation.
// Pure Rust implementation; no dependency on C sha256-fundamental.

use libc::{c_char, c_int, c_void};
use std::{
    ffi::CStr,
    ptr, slice,
    sync::atomic::{Ordering, compiler_fence},
};

// ── Constants ──────────────────────────────────────────────────────────────

const SHA256_DIGEST_SIZE: usize = 32;
const HMAC_BLOCK_SIZE: usize = 64;
const INNER_PADDING_BYTE: u8 = 0x36;
const OUTER_PADDING_BYTE: u8 = 0x5c;

// SHA-256 initial hash values: first 32 bits of fractional parts of square roots of first 8 primes.
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// SHA-256 round constants: first 32 bits of fractional parts of cube roots of first 64 primes.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ── Internal SHA-256 implementation ─────────────────────────────────────────

fn right_rotate32(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

struct Sha256Ctx {
    h: [u32; 8],
    total: u64,
    buf: [u8; 64],
    buflen: usize,
}

fn erase_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: every `byte` is a unique live byte in the supplied slice.
        // Volatile writes prevent removal of this key-material cleanup.
        unsafe_ffi!(ptr::write_volatile(byte, 0));
    }
    compiler_fence(Ordering::SeqCst);
}

fn erase_sha256_ctx(ctx: &mut Sha256Ctx) {
    let size = std::mem::size_of::<Sha256Ctx>();
    let bytes = ptr::from_mut(ctx).cast::<u8>();
    for offset in 0..size {
        // SAFETY: offsets below the object size remain within `ctx`; byte
        // writes are valid for every part of an object's representation.
        unsafe_ffi!(ptr::write_volatile(bytes.add(offset), 0));
    }
    compiler_fence(Ordering::SeqCst);
}

fn sha256_init_ctx() -> Sha256Ctx {
    Sha256Ctx {
        h: H_INIT,
        total: 0,
        buf: [0; 64],
        buflen: 0,
    }
}

fn sha256_process_block(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = right_rotate32(w[i - 15], 7) ^ right_rotate32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = right_rotate32(w[i - 2], 17) ^ right_rotate32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;

    for i in 0..64 {
        let s1 = right_rotate32(e, 6) ^ right_rotate32(e, 11) ^ right_rotate32(e, 25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = right_rotate32(a, 2) ^ right_rotate32(a, 13) ^ right_rotate32(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

fn sha256_process_bytes(ctx: &mut Sha256Ctx, data: &[u8]) {
    let mut offset = 0;
    let mut remaining = data.len();

    if ctx.buflen > 0 {
        let space = 64 - ctx.buflen;
        let copy = remaining.min(space);
        ctx.buf[ctx.buflen..ctx.buflen + copy].copy_from_slice(&data[..copy]);
        ctx.buflen += copy;
        offset += copy;
        remaining -= copy;

        if ctx.buflen == 64 {
            sha256_process_block(&mut ctx.h, &ctx.buf);
            ctx.buflen = 0;
        }
    }

    while remaining >= 64 {
        let mut block = [0u8; 64];
        block.copy_from_slice(&data[offset..offset + 64]);
        sha256_process_block(&mut ctx.h, &block);
        offset += 64;
        remaining -= 64;
    }

    if remaining > 0 {
        ctx.buf[..remaining].copy_from_slice(&data[offset..offset + remaining]);
        ctx.buflen = remaining;
    }

    ctx.total = ctx.total.wrapping_add(data.len() as u64);
}

fn sha256_finish_ctx(ctx: &mut Sha256Ctx) -> [u8; 32] {
    let total_bits = ctx.total.wrapping_mul(8);

    ctx.buf[ctx.buflen] = 0x80;
    ctx.buflen += 1;

    if ctx.buflen > 56 {
        ctx.buf[ctx.buflen..].fill(0);
        sha256_process_block(&mut ctx.h, &ctx.buf);
        ctx.buf.fill(0);
    } else {
        ctx.buf[ctx.buflen..].fill(0);
    }

    ctx.buf[56..64].copy_from_slice(&total_bits.to_be_bytes());
    sha256_process_block(&mut ctx.h, &ctx.buf);

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..i * 4 + 4].copy_from_slice(&ctx.h[i].to_be_bytes());
    }
    result
}

/// Compute SHA-256 hash of arbitrary data.
fn sha256_direct(data: &[u8]) -> [u8; 32] {
    let mut ctx = sha256_init_ctx();
    sha256_process_bytes(&mut ctx, data);
    sha256_finish_ctx(&mut ctx)
}

// ── Hex helpers ─────────────────────────────────────────────────────────────

fn unhexchar(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn is_hexdigit(c: u8) -> bool {
    unhexchar(c).is_some()
}

fn parse_sha256_bytes(bytes: &[u8]) -> Option<[u8; SHA256_DIGEST_SIZE]> {
    if bytes.len() != SHA256_DIGEST_SIZE * 2 {
        return None;
    }
    let mut result = [0u8; SHA256_DIGEST_SIZE];
    for (output, pair) in result.iter_mut().zip(bytes.chunks_exact(2)) {
        let hi = unhexchar(pair[0])?;
        let lo = unhexchar(pair[1])?;
        *output = (hi << 4) | lo;
    }
    Some(result)
}

fn sha256_bytes_is_valid(bytes: &[u8]) -> bool {
    bytes.len() == SHA256_DIGEST_SIZE * 2 && bytes.iter().all(|&c| is_hexdigit(c))
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Check if a string is a valid SHA-256 hex string (exactly 64 hex chars).
/// Equivalent to C sha256_is_valid().
pub fn sha256_is_valid(s: &str) -> bool {
    sha256_bytes_is_valid(s.as_bytes())
}

/// Parse a SHA-256 hex string into 32 bytes.
/// Equivalent to C parse_sha256(). Returns Err(-22) on failure.
pub fn parse_sha256(s: &str) -> Result<[u8; 32], i32> {
    parse_sha256_bytes(s.as_bytes()).ok_or(-libc::EINVAL)
}

/// Compute HMAC-SHA-256 per FIPS 198.
/// Equivalent to C hmac_sha256().
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut ctx = sha256_init_ctx();
    sha256_process_bytes(&mut ctx, data);
    sha256_finish_ctx(&mut ctx)
}

pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut replacement_key = [0u8; SHA256_DIGEST_SIZE];
    let actual_key = if key.len() > HMAC_BLOCK_SIZE {
        replacement_key = sha256_direct(key);
        replacement_key.as_slice()
    } else {
        key
    };
    let mut inner_padding = [0u8; HMAC_BLOCK_SIZE];
    let mut outer_padding = [0u8; HMAC_BLOCK_SIZE];

    inner_padding[..actual_key.len()].copy_from_slice(&actual_key);
    outer_padding[..actual_key.len()].copy_from_slice(&actual_key);

    for i in 0..HMAC_BLOCK_SIZE {
        inner_padding[i] ^= INNER_PADDING_BYTE;
        outer_padding[i] ^= OUTER_PADDING_BYTE;
    }

    // First pass: hash inner padding + input
    let mut ctx = sha256_init_ctx();
    sha256_process_bytes(&mut ctx, &inner_padding);
    sha256_process_bytes(&mut ctx, input);
    let mut res = sha256_finish_ctx(&mut ctx);
    erase_sha256_ctx(&mut ctx);

    // Second pass: hash outer padding + first result
    let mut ctx2 = sha256_init_ctx();
    sha256_process_bytes(&mut ctx2, &outer_padding);
    sha256_process_bytes(&mut ctx2, &res);
    let result = sha256_finish_ctx(&mut ctx2);
    erase_sha256_ctx(&mut ctx2);

    erase_bytes(&mut replacement_key);
    erase_bytes(&mut inner_padding);
    erase_bytes(&mut outer_padding);
    erase_bytes(&mut res);
    result
}

// ── C ABI shadow facade ──────────────────────────────────────────────────

/// Byte-oriented C facade for `sha256_is_valid()`.
///
/// # Safety
///
/// `s`, when non-NULL, must point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sha256_is_valid(s: *const c_char) -> bool {
    if s.is_null() {
        return false;
    }

    // SAFETY: required by this entry point's C-string contract.
    sha256_bytes_is_valid(unsafe_ffi!(CStr::from_ptr(s)).to_bytes())
}

/// Byte-oriented C facade for `parse_sha256()`.
///
/// On failure `ret` is left untouched, matching C.
///
/// # Safety
///
/// `s`, when non-NULL, must point to a live NUL-terminated C string. `ret`
/// must designate at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_sha256(s: *const c_char, ret: *mut u8) -> c_int {
    if s.is_null() || ret.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: required by this entry point's C-string contract.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let Some(digest) = parse_sha256_bytes(bytes) else {
        return -libc::EINVAL;
    };

    // SAFETY: the caller guarantees a writable 32-byte result region. `copy`
    // permits the result to overlap the input string, as C's final memcpy can.
    unsafe_ffi!(ptr::copy(digest.as_ptr(), ret, SHA256_DIGEST_SIZE));
    0
}

/// C facade for `hmac_sha256()`.
///
/// # Safety
///
/// `key` must designate `key_size > 0` readable bytes, `input` must be non-NULL
/// and designate `input_size` readable bytes, and `res` must designate 32
/// writable bytes. Invalid pointers are rejected by leaving `res` untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hmac_sha256(
    key: *const c_void,
    key_size: usize,
    input: *const c_void,
    input_size: usize,
    res: *mut u8,
) {
    if key.is_null() || key_size == 0 || input.is_null() || res.is_null() {
        return;
    }

    // SAFETY: the caller guarantees a readable key region.
    let key = unsafe_ffi!(slice::from_raw_parts(key.cast::<u8>(), key_size));
    let input = if input_size == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees a readable input region.
        unsafe_ffi!(slice::from_raw_parts(input.cast::<u8>(), input_size))
    };
    let digest = hmac_sha256(key, input);
    // SAFETY: the caller guarantees a writable 32-byte result region. `copy`
    // permits result/input overlap after the digest has been fully computed.
    unsafe_ffi!(ptr::copy(digest.as_ptr(), res, SHA256_DIGEST_SIZE));
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SHA-256 known-answer tests ───────────────────────────────────────

    #[test]
    fn test_sha256_empty_string() {
        let hash = sha256_direct(b"");
        let expected = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex.as_bytes(), expected);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256_direct(b"abc");
        let expected = b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex.as_bytes(), expected);
    }

    #[test]
    fn test_sha256_longer() {
        let hash = sha256_direct(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected = b"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex.as_bytes(), expected);
    }

    #[test]
    fn test_sha256_single_byte() {
        let hash = sha256_direct(b"a");
        assert_ne!(hash, [0u8; 32]);
    }

    // ── sha256_is_valid tests ────────────────────────────────────────────

    #[test]
    fn test_sha256_is_valid_valid_lowercase() {
        assert!(sha256_is_valid(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn test_sha256_is_valid_valid_uppercase() {
        assert!(sha256_is_valid(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ));
    }

    #[test]
    fn test_sha256_is_valid_mixed_case() {
        assert!(sha256_is_valid(
            "e3B0c44298Fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn test_sha256_is_valid_empty() {
        assert!(!sha256_is_valid(""));
    }

    #[test]
    fn test_sha256_is_valid_too_short() {
        assert!(!sha256_is_valid("e3b0c44298fc1c149afbf4c8996fb924"));
    }

    #[test]
    fn test_sha256_is_valid_too_long() {
        assert!(!sha256_is_valid(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550"
        ));
    }

    #[test]
    fn test_sha256_is_valid_invalid_char() {
        assert!(!sha256_is_valid(
            "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    // ── parse_sha256 tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_sha256_valid() {
        let result =
            parse_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(result[0], 0xe3);
        assert_eq!(result[1], 0xb0);
        assert_eq!(result[2], 0xc4);
        assert_eq!(result[3], 0x42);
    }

    #[test]
    fn test_parse_sha256_invalid_string() {
        assert!(parse_sha256("invalid").is_err());
    }

    #[test]
    fn test_parse_sha256_wrong_length() {
        assert!(parse_sha256("e3b0c442").is_err());
    }

    #[test]
    fn test_parse_sha256_all_zeros() {
        let result =
            parse_sha256("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_parse_sha256_all_ffs() {
        let result =
            parse_sha256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert_eq!(result, [0xffu8; 32]);
    }

    #[test]
    fn test_parse_sha256_uppercase() {
        let result =
            parse_sha256("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
                .unwrap();
        assert_eq!(result[0], 0xe3);
        assert_eq!(result[1], 0xb0);
    }

    // ── HMAC-SHA-256 tests ───────────────────────────────────────────────

    #[test]
    fn test_hmac_sha256_empty_input() {
        let key = [0x0bu8; 20];
        let res = hmac_sha256(&key, b"Hi There");
        assert!(!res.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_hmac_sha256_basic() {
        let res = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        assert!(!res.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let res1 = hmac_sha256(b"testkey", b"testdata");
        let res2 = hmac_sha256(b"testkey", b"testdata");
        assert_eq!(res1, res2);
    }

    #[test]
    fn test_hmac_sha256_different_keys() {
        let res1 = hmac_sha256(b"key1", b"same input");
        let res2 = hmac_sha256(b"key2", b"same input");
        assert_ne!(res1, res2);
    }

    #[test]
    fn test_hmac_sha256_different_inputs() {
        let res1 = hmac_sha256(b"same key", b"input1");
        let res2 = hmac_sha256(b"same key", b"input2");
        assert_ne!(res1, res2);
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        let key = [0xaau8; 100];
        let res = hmac_sha256(&key, b"test input");
        assert!(!res.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_hmac_sha256_empty_key() {
        let res = hmac_sha256(b"", b"test");
        // Empty key still produces a valid hash
        assert!(!res.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_hmac_sha256_rfc4231_test_case_2() {
        let res = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let expected: String = res.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            expected,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
