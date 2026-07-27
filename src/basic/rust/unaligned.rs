// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/unaligned.h (unaligned_read/write_be/le16/32/64)
//
// Unaligned memory access with byte-order conversion.
//
// Provides safe byte-slice based read/write for big-endian and
// little-endian 16/32/64-bit values. Mirrors the C unaligned.h
// inline functions using pure Rust byte manipulation.

use libc::c_void;

// ── Big-endian read ───────────────────────────────────────────────────────

/// Read a big-endian u16 from a byte slice (2 bytes).
///
/// Panics if slice is shorter than 2 bytes.
pub fn read_be16(bytes: &[u8]) -> u16 {
    let b0 = bytes[0] as u16;
    let b1 = bytes[1] as u16;
    (b0 << 8) | b1
}

/// Read a big-endian u32 from a byte slice (4 bytes).
///
/// Panics if slice is shorter than 4 bytes.
pub fn read_be32(bytes: &[u8]) -> u32 {
    let b0 = bytes[0] as u32;
    let b1 = bytes[1] as u32;
    let b2 = bytes[2] as u32;
    let b3 = bytes[3] as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

/// Read a big-endian u64 from a byte slice (8 bytes).
///
/// Panics if slice is shorter than 8 bytes.
pub fn read_be64(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for i in 0..8 {
        v = (v << 8) | (bytes[i] as u64);
    }
    v
}

// ── Big-endian write ──────────────────────────────────────────────────────

/// Write a big-endian u16 into a byte slice (2 bytes).
///
/// Panics if slice is shorter than 2 bytes.
pub fn write_be16(bytes: &mut [u8], val: u16) {
    bytes[0] = (val >> 8) as u8;
    bytes[1] = val as u8;
}

/// Write a big-endian u32 into a byte slice (4 bytes).
///
/// Panics if slice is shorter than 4 bytes.
pub fn write_be32(bytes: &mut [u8], val: u32) {
    bytes[0] = (val >> 24) as u8;
    bytes[1] = (val >> 16) as u8;
    bytes[2] = (val >> 8) as u8;
    bytes[3] = val as u8;
}

/// Write a big-endian u64 into a byte slice (8 bytes).
///
/// Panics if slice is shorter than 8 bytes.
pub fn write_be64(bytes: &mut [u8], val: u64) {
    bytes[0] = (val >> 56) as u8;
    bytes[1] = (val >> 48) as u8;
    bytes[2] = (val >> 40) as u8;
    bytes[3] = (val >> 32) as u8;
    bytes[4] = (val >> 24) as u8;
    bytes[5] = (val >> 16) as u8;
    bytes[6] = (val >> 8) as u8;
    bytes[7] = val as u8;
}

// ── Little-endian read ────────────────────────────────────────────────────

/// Read a little-endian u16 from a byte slice (2 bytes).
///
/// Panics if slice is shorter than 2 bytes.
pub fn read_le16(bytes: &[u8]) -> u16 {
    let b0 = bytes[0] as u16;
    let b1 = bytes[1] as u16;
    b0 | (b1 << 8)
}

/// Read a little-endian u32 from a byte slice (4 bytes).
///
/// Panics if slice is shorter than 4 bytes.
pub fn read_le32(bytes: &[u8]) -> u32 {
    let b0 = bytes[0] as u32;
    let b1 = bytes[1] as u32;
    let b2 = bytes[2] as u32;
    let b3 = bytes[3] as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

/// Read a little-endian u64 from a byte slice (8 bytes).
///
/// Panics if slice is shorter than 8 bytes.
pub fn read_le64(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for i in 0..8 {
        v |= (bytes[i] as u64) << (i * 8);
    }
    v
}

// ── Little-endian write ───────────────────────────────────────────────────

/// Write a little-endian u16 into a byte slice (2 bytes).
///
/// Panics if slice is shorter than 2 bytes.
pub fn write_le16(bytes: &mut [u8], val: u16) {
    bytes[0] = val as u8;
    bytes[1] = (val >> 8) as u8;
}

/// Write a little-endian u32 into a byte slice (4 bytes).
///
/// Panics if slice is shorter than 4 bytes.
pub fn write_le32(bytes: &mut [u8], val: u32) {
    bytes[0] = val as u8;
    bytes[1] = (val >> 8) as u8;
    bytes[2] = (val >> 16) as u8;
    bytes[3] = (val >> 24) as u8;
}

/// Write a little-endian u64 into a byte slice (8 bytes).
///
/// Panics if slice is shorter than 8 bytes.
pub fn write_le64(bytes: &mut [u8], val: u64) {
    bytes[0] = val as u8;
    bytes[1] = (val >> 8) as u8;
    bytes[2] = (val >> 16) as u8;
    bytes[3] = (val >> 24) as u8;
    bytes[4] = (val >> 32) as u8;
    bytes[5] = (val >> 40) as u8;
    bytes[6] = (val >> 48) as u8;
    bytes[7] = (val >> 56) as u8;
}

// ── C ABI ────────────────────────────────────────────────────────────────

/// Copy exactly `N` bytes from a C pointer without imposing an alignment
/// requirement.
///
/// # Safety
/// `p` must be non-null and point to `N` initialized, readable bytes for the
/// duration of the call. The pointed-to region may be unaligned because the
/// copied array has byte alignment.
#[inline]
unsafe fn read_c_bytes<const N: usize>(p: *const c_void) -> [u8; N] {
    // SAFETY: guaranteed by this helper's contract; `[u8; N]` has alignment 1.
    unsafe { std::ptr::read(p.cast::<[u8; N]>()) }
}

/// Copy exactly `N` bytes to a C pointer without imposing an alignment
/// requirement.
///
/// # Safety
/// `p` must be non-null and point to `N` writable bytes for the duration of
/// the call. The caller must also provide the usual C-side synchronization for
/// concurrent access. The pointed-to region may be unaligned because the
/// copied array has byte alignment.
#[inline]
unsafe fn write_c_bytes<const N: usize>(p: *mut c_void, bytes: [u8; N]) {
    // SAFETY: guaranteed by this helper's contract; `[u8; N]` has alignment 1.
    unsafe { std::ptr::write(p.cast::<[u8; N]>(), bytes) };
}

/// Read a big-endian 16-bit integer from an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to two initialized, readable bytes. No
/// alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_read_be16(p: *const c_void) -> u16 {
    // SAFETY: required by this C ABI entry point's contract.
    read_be16(&unsafe { read_c_bytes::<2>(p) })
}

/// Read a big-endian 32-bit integer from an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to four initialized, readable bytes. No
/// alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_read_be32(p: *const c_void) -> u32 {
    // SAFETY: required by this C ABI entry point's contract.
    read_be32(&unsafe { read_c_bytes::<4>(p) })
}

/// Read a big-endian 64-bit integer from an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to eight initialized, readable bytes. No
/// alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_read_be64(p: *const c_void) -> u64 {
    // SAFETY: required by this C ABI entry point's contract.
    read_be64(&unsafe { read_c_bytes::<8>(p) })
}

/// Write a big-endian 16-bit integer to an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to two writable bytes. The caller must
/// synchronize concurrent access. No alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_write_be16(p: *mut c_void, value: u16) {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { write_c_bytes(p, value.to_be_bytes()) };
}

/// Write a big-endian 32-bit integer to an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to four writable bytes. The caller must
/// synchronize concurrent access. No alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_write_be32(p: *mut c_void, value: u32) {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { write_c_bytes(p, value.to_be_bytes()) };
}

/// Write a big-endian 64-bit integer to an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to eight writable bytes. The caller must
/// synchronize concurrent access. No alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_write_be64(p: *mut c_void, value: u64) {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { write_c_bytes(p, value.to_be_bytes()) };
}

/// Read a little-endian 16-bit integer from an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to two initialized, readable bytes. No
/// alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_read_le16(p: *const c_void) -> u16 {
    // SAFETY: required by this C ABI entry point's contract.
    read_le16(&unsafe { read_c_bytes::<2>(p) })
}

/// Read a little-endian 32-bit integer from an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to four initialized, readable bytes. No
/// alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_read_le32(p: *const c_void) -> u32 {
    // SAFETY: required by this C ABI entry point's contract.
    read_le32(&unsafe { read_c_bytes::<4>(p) })
}

/// Read a little-endian 64-bit integer from an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to eight initialized, readable bytes. No
/// alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_read_le64(p: *const c_void) -> u64 {
    // SAFETY: required by this C ABI entry point's contract.
    read_le64(&unsafe { read_c_bytes::<8>(p) })
}

/// Write a little-endian 16-bit integer to an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to two writable bytes. The caller must
/// synchronize concurrent access. No alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_write_le16(p: *mut c_void, value: u16) {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { write_c_bytes(p, value.to_le_bytes()) };
}

/// Write a little-endian 32-bit integer to an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to four writable bytes. The caller must
/// synchronize concurrent access. No alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_write_le32(p: *mut c_void, value: u32) {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { write_c_bytes(p, value.to_le_bytes()) };
}

/// Write a little-endian 64-bit integer to an unaligned C byte buffer.
///
/// # Safety
/// `p` must be non-null and point to eight writable bytes. The caller must
/// synchronize concurrent access. No alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unaligned_write_le64(p: *mut c_void, value: u64) {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { write_c_bytes(p, value.to_le_bytes()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_be16_basic() {
        assert_eq!(read_be16(&[0x12, 0x34]), 0x1234);
    }

    #[test]
    fn test_read_be16_zero() {
        assert_eq!(read_be16(&[0, 0]), 0);
    }

    #[test]
    fn test_read_be16_max() {
        assert_eq!(read_be16(&[0xFF, 0xFF]), 0xFFFF);
    }

    #[test]
    fn test_read_be32_basic() {
        assert_eq!(read_be32(&[0x12, 0x34, 0x56, 0x78]), 0x12345678);
    }

    #[test]
    fn test_read_be32_zero() {
        assert_eq!(read_be32(&[0, 0, 0, 0]), 0);
    }

    #[test]
    fn test_read_be32_max() {
        assert_eq!(read_be32(&[0xFF; 4]), 0xFFFFFFFF);
    }

    #[test]
    fn test_read_be64_basic() {
        assert_eq!(
            read_be64(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
            0x0123456789ABCDEF
        );
    }

    #[test]
    fn test_read_be64_zero() {
        assert_eq!(read_be64(&[0; 8]), 0);
    }

    #[test]
    fn test_read_be64_max() {
        assert_eq!(read_be64(&[0xFF; 8]), u64::MAX);
    }

    #[test]
    fn test_write_be16_roundtrip() {
        let mut buf = [0u8; 2];
        write_be16(&mut buf, 0x1234);
        assert_eq!(read_be16(&buf), 0x1234);
    }

    #[test]
    fn test_write_be16_zero() {
        let mut buf = [0xFFu8; 2];
        write_be16(&mut buf, 0);
        assert_eq!(buf, [0, 0]);
    }

    #[test]
    fn test_write_be16_max() {
        let mut buf = [0u8; 2];
        write_be16(&mut buf, 0xFFFF);
        assert_eq!(buf, [0xFF, 0xFF]);
    }

    #[test]
    fn test_write_be32_roundtrip() {
        let mut buf = [0u8; 4];
        write_be32(&mut buf, 0x12345678);
        assert_eq!(read_be32(&buf), 0x12345678);
    }

    #[test]
    fn test_write_be32_bytes() {
        let mut buf = [0u8; 4];
        write_be32(&mut buf, 0x12345678);
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_write_be64_roundtrip() {
        let mut buf = [0u8; 8];
        write_be64(&mut buf, 0x0123456789ABCDEF);
        assert_eq!(read_be64(&buf), 0x0123456789ABCDEF);
    }

    #[test]
    fn test_read_le16_basic() {
        assert_eq!(read_le16(&[0x34, 0x12]), 0x1234);
    }

    #[test]
    fn test_read_le16_zero() {
        assert_eq!(read_le16(&[0, 0]), 0);
    }

    #[test]
    fn test_read_le16_max() {
        assert_eq!(read_le16(&[0xFF, 0xFF]), 0xFFFF);
    }

    #[test]
    fn test_read_le32_basic() {
        assert_eq!(read_le32(&[0x78, 0x56, 0x34, 0x12]), 0x12345678);
    }

    #[test]
    fn test_read_le64_basic() {
        assert_eq!(
            read_le64(&[0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]),
            0x0123456789ABCDEF
        );
    }

    #[test]
    fn test_read_le64_zero() {
        assert_eq!(read_le64(&[0; 8]), 0);
    }

    #[test]
    fn test_write_le16_roundtrip() {
        let mut buf = [0u8; 2];
        write_le16(&mut buf, 0x1234);
        assert_eq!(read_le16(&buf), 0x1234);
    }

    #[test]
    fn test_write_le32_roundtrip() {
        let mut buf = [0u8; 4];
        write_le32(&mut buf, 0x12345678);
        assert_eq!(read_le32(&buf), 0x12345678);
    }

    #[test]
    fn test_write_le64_roundtrip() {
        let mut buf = [0u8; 8];
        write_le64(&mut buf, 0x0123456789ABCDEF);
        assert_eq!(read_le64(&buf), 0x0123456789ABCDEF);
    }

    #[test]
    fn test_write_le32_bytes() {
        let mut buf = [0u8; 4];
        write_le32(&mut buf, 0x12345678);
        assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_misaligned_access_be32() {
        let buf: [u8; 10] = [0xAA, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xBB];
        assert_eq!(read_be32(&buf[1..5]), 0x01234567);
    }

    #[test]
    fn test_misaligned_access_le32() {
        let buf: [u8; 10] = [0xAA, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xBB];
        assert_eq!(read_le32(&buf[1..5]), 0x67452301);
    }
}
