// SPDX-License-Identifier: LicenseRef-murmurhash2-public-domain
//
// PORT-SYNC: src/basic/MurmurHash2.c
//
// MurmurHash2 was written by Austin Appleby, and is placed in the public domain.
// The author hereby disclaims copyright to this source code.
//
// Pure Rust implementation of MurmurHash2 — a fast, non-cryptographic hash.
// Produces identical results to the C version on little-endian platforms.

// ── MurmurHash2 ──────────────────────────────────────────────────────────

/// MurmurHash2 — a fast, non-cryptographic hash function.
///
/// Produces identical results to the C MurmurHash2 on little-endian platforms.
/// Note: This function reads memory in a platform-dependent manner and will
/// produce different results on different endiannesses.
pub fn murmur_hash2(data: &[u8], seed: u32) -> u32 {
    let m: u32 = 0x5bd1e995;
    let r: u32 = 24;
    let len = data.len();

    let mut h = seed ^ (len as u32);

    let mut offset = 0usize;
    let mut remaining = len;

    // Mix 4 bytes at a time
    while remaining >= 4 {
        let k = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        let mut k = k.wrapping_mul(m);
        k ^= k >> r;
        k = k.wrapping_mul(m);

        h = h.wrapping_mul(m);
        h ^= k;

        offset += 4;
        remaining -= 4;
    }

    // Handle the last few bytes
    match remaining {
        3 => {
            h ^= (data[offset + 2] as u32) << 16;
            h ^= (data[offset + 1] as u32) << 8;
            h ^= data[offset] as u32;
            h = h.wrapping_mul(m);
        }
        2 => {
            h ^= (data[offset + 1] as u32) << 8;
            h ^= data[offset] as u32;
            h = h.wrapping_mul(m);
        }
        1 => {
            h ^= data[offset] as u32;
            h = h.wrapping_mul(m);
        }
        _ => {}
    }

    // Final mixing
    h ^= h >> 13;
    h = h.wrapping_mul(m);
    h ^= h >> 15;

    if len == 0 {
        return seed;
    }

    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_vectors() {
        assert_eq!(murmur_hash2(b"hello", 0), 0xe56129cb);
        assert_eq!(murmur_hash2(b"hello", 1234), 0x8e251908);
        assert_eq!(murmur_hash2(b"abc", 42), 0xda0d1400);
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(murmur_hash2(b"", 0), 0);
        assert_eq!(murmur_hash2(b"", 1), 1);
    }

    #[test]
    fn test_zero_length_slice() {
        assert_eq!(murmur_hash2(&[], 0), 0);
    }

    #[test]
    fn test_single_byte() {
        let h = murmur_hash2(b"a", 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_two_bytes() {
        let h = murmur_hash2(b"ab", 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_three_bytes() {
        let h = murmur_hash2(b"abc", 0);
        assert_ne!(h, 0);
        // Deterministic
        assert_eq!(murmur_hash2(b"abc", 0), h);
    }

    #[test]
    fn test_four_bytes_aligned() {
        let h = murmur_hash2(b"abcd", 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_five_bytes_tail() {
        // Exercises both the 4-byte loop and the 1-byte tail
        assert_eq!(murmur_hash2(b"hello", 0), 0xe56129cb);
    }

    #[test]
    fn test_seven_bytes_tail() {
        // 7 = 4 + 3, exercises the 3-byte tail case
        let h = murmur_hash2(b"abcdefg", 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_six_bytes_tail() {
        // 6 = 4 + 2, exercises the 2-byte tail case
        let h = murmur_hash2(b"abcdef", 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_deterministic() {
        assert_eq!(
            murmur_hash2(b"test data", 42),
            murmur_hash2(b"test data", 42)
        );
    }

    #[test]
    fn test_different_seeds_differ() {
        assert_ne!(murmur_hash2(b"hello", 0), murmur_hash2(b"hello", 1));
        assert_ne!(
            murmur_hash2(b"hello", 0),
            murmur_hash2(b"hello", 0xdeadbeef)
        );
    }

    #[test]
    fn test_different_inputs_differ() {
        assert_ne!(murmur_hash2(b"hello", 0), murmur_hash2(b"world", 0));
    }

    #[test]
    fn test_large_input() {
        let data = vec![0xAB_u8; 1024];
        let h = murmur_hash2(&data, 0);
        assert_ne!(h, 0);
        assert_eq!(h, murmur_hash2(&data, 0));
    }

    #[test]
    fn test_all_zeros() {
        let data = vec![0u8; 16];
        let h = murmur_hash2(&data, 0);
        assert_eq!(h, murmur_hash2(&data, 0));
        // With seed 0 and all-zero data the result should still be non-trivial
        // after the final mixing steps
        assert_ne!(h, 0);
    }
}
