// SPDX-License-Identifier: LicenseRef-alg-sha1-public-domain
//
// PORT-SYNC: scope=fundamental.sha1; authority=src/fundamental/sha1.c,src/fundamental/sha1.h
//
// SHA-1 hash implementation, faithful to the public domain SHA-1 by Steve Reid.
// The algorithm is safe Rust; unsafe code is confined to the documented C ABI facade.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use libc::c_void;
use std::{ptr, slice};

// ── Constants ─────────────────────────────────────────────────────────────

pub const SHA1_DIGEST_SIZE: usize = 20;

// ── Context ───────────────────────────────────────────────────────────────

/// SHA-1 computation state, mirrors `struct sha1_ctx` from sha1.h.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Sha1Ctx {
    pub state: [u32; 5],
    pub count: [u32; 2],
    pub buffer: [u8; 64],
}

impl Default for Sha1Ctx {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1Ctx {
    /// Create an initialized SHA-1 context.
    ///
    /// Faithful to `sha1_init_ctx()` — sets the five initialization constants
    /// from RFC 3174 §6.1 and zeroes the counter/buffer.
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            count: [0, 0],
            buffer: [0u8; 64],
        }
    }

    /// Feed data into the SHA-1 computation.
    ///
    /// Faithful to `sha1_process_bytes(const void *buffer, size_t size, struct sha1_ctx *ctx)`.
    /// Manages the 64-byte block buffer and byte-count tracking identically to the C code.
    pub fn update(&mut self, data: &[u8]) {
        let size = data.len();
        let mut j = ((self.count[0] >> 3) & 63) as usize;

        let size_bits = (size as u32) << 3;
        if self.count[0].wrapping_add(size_bits) < size_bits {
            self.count[1] = self.count[1].wrapping_add(1);
        }
        self.count[0] = self.count[0].wrapping_add(size_bits);
        self.count[1] = self.count[1].wrapping_add((size >> 29) as u32);

        let mut i: usize = 0;
        if j + size > 63 {
            let to_copy = 64 - j;
            self.buffer[j..64].copy_from_slice(&data[..to_copy]);
            sha1_do_transform(&mut self.state, &self.buffer);
            i = to_copy;
            while i + 63 < size {
                let block: [u8; 64] = data[i..i + 64].try_into().unwrap();
                sha1_do_transform(&mut self.state, &block);
                i += 64;
            }
            j = 0;
        }

        let remaining = size - i;
        self.buffer[j..j + remaining].copy_from_slice(&data[i..i + remaining]);
    }

    /// Finalize the hash and return the 20-byte digest.
    ///
    /// Faithful to `sha1_finish_ctx()` — pads the message, appends the bit-length,
    /// extracts the digest, and wipes internal state.
    pub fn finish(&mut self) -> [u8; SHA1_DIGEST_SIZE] {
        let mut finalcount = [0u8; 8];
        for (i, byte) in finalcount.iter_mut().enumerate() {
            let idx = if i >= 4 { 0 } else { 1 };
            let shift = (3 - (i & 3)) * 8;
            *byte = ((self.count[idx] >> shift) & 0xFF) as u8;
        }

        self.update(&[0x80]);
        while (self.count[0] & 504) != 448 {
            self.update(&[0x00]);
        }
        self.update(&finalcount);

        let mut result = [0u8; SHA1_DIGEST_SIZE];
        for (i, byte) in result.iter_mut().enumerate() {
            let shift = (3 - (i & 3)) * 8;
            *byte = ((self.state[i >> 2] >> shift) & 0xFF) as u8;
        }

        // Wipe context and temp
        self.state.fill(0);
        self.count.fill(0);
        self.buffer.fill(0);
        finalcount.fill(0);

        result
    }
}

// ── Core transform ────────────────────────────────────────────────────────

const fn rol(value: u32, bits: u32) -> u32 {
    value.rotate_left(bits)
}

/// SHA-1 block transform for a single 512-bit (64-byte) block.
///
/// Faithful to `sha1_do_transform()` in sha1.c.
/// Implements the four rounds (R0/R1, R2, R3, R4) with the same constants
/// and message schedule expansion.
fn sha1_do_transform(state: &mut [u32; 5], buffer: &[u8; 64]) {
    let mut w = [0u32; 16];
    for (i, word) in w.iter_mut().enumerate() {
        let off = i * 4;
        *word = u32::from_be_bytes([
            buffer[off],
            buffer[off + 1],
            buffer[off + 2],
            buffer[off + 3],
        ]);
    }

    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);

    // Rounds 0-15: R0 — z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999
    for word in &w {
        let temp = e
            .wrapping_add((b & (c ^ d)) ^ d)
            .wrapping_add(*word)
            .wrapping_add(0x5A827999)
            .wrapping_add(rol(a, 5));
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    // Rounds 16-19: R1 — same function, with message expansion
    for i in 16..20 {
        let v = rol(
            w[(i - 3) & 15] ^ w[(i - 8) & 15] ^ w[(i - 14) & 15] ^ w[i & 15],
            1,
        );
        w[i & 15] = v;
        let temp = e
            .wrapping_add((b & (c ^ d)) ^ d)
            .wrapping_add(v)
            .wrapping_add(0x5A827999)
            .wrapping_add(rol(a, 5));
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    // Rounds 20-39: R2 — z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1
    for i in 20..40 {
        let v = rol(
            w[(i - 3) & 15] ^ w[(i - 8) & 15] ^ w[(i - 14) & 15] ^ w[i & 15],
            1,
        );
        w[i & 15] = v;
        let temp = e
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(v)
            .wrapping_add(0x6ED9EBA1)
            .wrapping_add(rol(a, 5));
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    // Rounds 40-59: R3 — z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC
    for i in 40..60 {
        let v = rol(
            w[(i - 3) & 15] ^ w[(i - 8) & 15] ^ w[(i - 14) & 15] ^ w[i & 15],
            1,
        );
        w[i & 15] = v;
        let temp = e
            .wrapping_add(((b | c) & d) | (b & c))
            .wrapping_add(v)
            .wrapping_add(0x8F1BBCDC)
            .wrapping_add(rol(a, 5));
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    // Rounds 60-79: R4 — z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6
    for i in 60..80 {
        let v = rol(
            w[(i - 3) & 15] ^ w[(i - 8) & 15] ^ w[(i - 14) & 15] ^ w[i & 15],
            1,
        );
        w[i & 15] = v;
        let temp = e
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(v)
            .wrapping_add(0xCA62C1D6)
            .wrapping_add(rol(a, 5));
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// Convenience: compute SHA-1 of an arbitrary byte slice in one call.
pub fn sha1(data: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let mut ctx = Sha1Ctx::new();
    ctx.update(data);
    ctx.finish()
}

// ── C ABI shadow facade ──────────────────────────────────────────────────

/// Initialize a C-layout SHA-1 context.
///
/// # Safety
///
/// `ctx` must point to writable, properly aligned storage for one `Sha1Ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sha1_init_ctx(ctx: *mut Sha1Ctx) {
    if ctx.is_null() {
        return;
    }

    // SAFETY: required by this entry point's contract. `ptr::write` also
    // permits the caller-provided storage to be uninitialized.
    unsafe_ffi!(ptr::write(ctx, Sha1Ctx::new()));
}

/// Process `size` bytes into a C-layout SHA-1 context.
///
/// # Safety
///
/// `ctx` must point to a context initialized by `rs_sha1_init_ctx`. When
/// called, `buffer` must be non-NULL and designate at least `size` readable
/// bytes that do not overlap `ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sha1_process_bytes(
    buffer: *const c_void,
    size: usize,
    ctx: *mut Sha1Ctx,
) {
    if ctx.is_null() || buffer.is_null() {
        return;
    }

    let data = if size == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees a live region of `size` bytes.
        unsafe_ffi!(slice::from_raw_parts(buffer.cast::<u8>(), size))
    };
    // SAFETY: the caller guarantees that `ctx` is live, aligned, initialized,
    // and exclusively accessible for the duration of this call.
    unsafe_ffi!(&mut *ctx).update(data);
}

/// Finalize a C-layout SHA-1 context and return `result`.
///
/// As in C, finalization erases the context.
///
/// # Safety
///
/// `ctx` must point to a context initialized by `rs_sha1_init_ctx`, and
/// `result` must designate at least `SHA1_DIGEST_SIZE` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sha1_finish_ctx(ctx: *mut Sha1Ctx, result: *mut u8) -> *mut c_void {
    if ctx.is_null() || result.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the caller guarantees a live, initialized, exclusive context.
    // Moving the plain-data context local also avoids creating an exclusive
    // Rust reference that could conflict if `result` points inside `ctx`.
    let mut local = unsafe_ffi!(ptr::read(ctx));
    let digest = local.finish();
    // SAFETY: the caller provides a writable 20-byte result region. `copy`
    // deliberately tolerates overlap with the context storage.
    unsafe_ffi!(ptr::copy(digest.as_ptr(), result, SHA1_DIGEST_SIZE));
    // SAFETY: `ctx` remains valid writable storage. Writing the erased context
    // after the digest preserves C's ordering when the two regions overlap.
    unsafe_ffi!(ptr::write(ctx, local));
    result.cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_constants() {
        let ctx = Sha1Ctx::new();
        assert_eq!(ctx.state[0], 0x67452301);
        assert_eq!(ctx.state[1], 0xEFCDAB89);
        assert_eq!(ctx.state[2], 0x98BADCFE);
        assert_eq!(ctx.state[3], 0x10325476);
        assert_eq!(ctx.state[4], 0xC3D2E1F0);
        assert_eq!(ctx.count, [0, 0]);
    }

    #[test]
    fn test_default_trait() {
        let ctx = Sha1Ctx::default();
        assert_eq!(ctx.state[0], 0x67452301);
        let ctx2 = Sha1Ctx::new();
        assert_eq!(ctx.state, ctx2.state);
    }

    #[test]
    fn test_empty_string() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let digest = sha1(b"");
        assert_eq!(
            digest,
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn test_abc() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let digest = sha1(b"abc");
        assert_eq!(
            digest,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn test_two_blocks() {
        // SHA-1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 84983e441c3bd26ebaae4aa1f95129e5e54670f1
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha1(input);
        assert_eq!(
            digest,
            [
                0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
                0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
            ]
        );
    }

    #[test]
    fn test_single_byte() {
        // SHA-1("a") = 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8
        let digest = sha1(b"a");
        assert_eq!(
            digest,
            [
                0x86, 0xf7, 0xe4, 0x37, 0xfa, 0xa5, 0xa7, 0xfc, 0xe1, 0x5d, 0x1d, 0xdc, 0xb9, 0xea,
                0xea, 0xea, 0x37, 0x76, 0x67, 0xb8
            ]
        );
    }

    #[test]
    fn test_incremental_update() {
        let mut ctx = Sha1Ctx::new();
        ctx.update(b"abc");
        let digest = ctx.finish();
        assert_eq!(
            digest,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn test_chunked_update() {
        let mut ctx = Sha1Ctx::new();
        ctx.update(b"a");
        ctx.update(b"b");
        ctx.update(b"c");
        let digest = ctx.finish();
        assert_eq!(
            digest,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn test_wipe_on_finish() {
        let mut ctx = Sha1Ctx::new();
        ctx.update(b"test data");
        let _ = ctx.finish();
        assert_eq!(ctx.state, [0, 0, 0, 0, 0]);
        assert_eq!(ctx.count, [0, 0]);
    }

    #[test]
    fn test_exactly_64_bytes() {
        let data = [0xAAu8; 64];
        let digest = sha1(&data);
        // Verify it produces a valid 20-byte digest (not all zeros)
        assert_ne!(digest, [0u8; 20]);
    }

    #[test]
    fn test_exactly_128_bytes() {
        let data = [0x55u8; 128];
        let digest = sha1(&data);
        assert_ne!(digest, [0u8; 20]);
    }

    #[test]
    fn test_large_input_consistency() {
        let data = [0x61u8; 1000];
        let digest1 = sha1(&data);
        let digest2 = sha1(&data);
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_clone_independent() {
        let mut ctx1 = Sha1Ctx::new();
        ctx1.update(b"hello");
        let ctx2 = ctx1.clone();
        ctx1.update(b" world");
        let digest1 = ctx1.finish();
        // ctx2 should only have "hello"
        let digest2 = sha1(b"hello");
        assert_ne!(digest1, digest2);
        // Verify cloned context produces same as sha1("hello")
        let mut ctx2 = ctx2;
        let digest2 = ctx2.finish();
        assert_eq!(digest2, sha1(b"hello"));
    }
}
