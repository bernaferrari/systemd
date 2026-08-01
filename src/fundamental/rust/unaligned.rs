// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter documents and validates the raw-pointer,
        // ownership, and lifetime contract before evaluating this expression.
        unsafe { $expression }
    }};
}
// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/unaligned.h
//
// Unaligned native-endian memory access.
// In Rust, reading/writing through packed structs is UB-free when done
// via ptr::read_unaligned / ptr::write_unaligned.

// ── Native-endian (host byte order) ─────────────────────────────────────

/// Read an unaligned native-endian `u16`.
///
/// # Safety
///
/// `p` must be valid and readable for two consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_ne16(p: *const u8) -> u16 {
    // SAFETY: the caller guarantees a readable two-byte region; unaligned
    // access deliberately imposes no alignment requirement.
    unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u16>()))
}

/// Read an unaligned native-endian `u32`.
///
/// # Safety
///
/// `p` must be valid and readable for four consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_ne32(p: *const u8) -> u32 {
    // SAFETY: the caller guarantees a readable four-byte region.
    unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u32>()))
}

/// Read an unaligned native-endian `u64`.
///
/// # Safety
///
/// `p` must be valid and readable for eight consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_ne64(p: *const u8) -> u64 {
    // SAFETY: the caller guarantees a readable eight-byte region.
    unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u64>()))
}

/// Write an unaligned native-endian `u16`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for two consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_ne16(p: *mut u8, val: u16) {
    // SAFETY: the caller guarantees an exclusively writable two-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u16>(), val);
    })
}

/// Write an unaligned native-endian `u32`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for four consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_ne32(p: *mut u8, val: u32) {
    // SAFETY: the caller guarantees an exclusively writable four-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u32>(), val);
    })
}

/// Write an unaligned native-endian `u64`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for eight consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_ne64(p: *mut u8, val: u64) {
    // SAFETY: the caller guarantees an exclusively writable eight-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u64>(), val);
    })
}

// ── Big-endian ──────────────────────────────────────────────────────────

/// Read an unaligned big-endian `u16`.
///
/// # Safety
///
/// `p` must be valid and readable for two consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_be16(p: *const u8) -> u16 {
    // SAFETY: the caller guarantees a readable two-byte region.
    u16::from_be(unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u16>())))
}

/// Read an unaligned big-endian `u32`.
///
/// # Safety
///
/// `p` must be valid and readable for four consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_be32(p: *const u8) -> u32 {
    // SAFETY: the caller guarantees a readable four-byte region.
    u32::from_be(unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u32>())))
}

/// Read an unaligned big-endian `u64`.
///
/// # Safety
///
/// `p` must be valid and readable for eight consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_be64(p: *const u8) -> u64 {
    // SAFETY: the caller guarantees a readable eight-byte region.
    u64::from_be(unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u64>())))
}

/// Write an unaligned big-endian `u16`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for two consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_be16(p: *mut u8, val: u16) {
    // SAFETY: the caller guarantees an exclusively writable two-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u16>(), val.to_be());
    })
}

/// Write an unaligned big-endian `u32`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for four consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_be32(p: *mut u8, val: u32) {
    // SAFETY: the caller guarantees an exclusively writable four-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u32>(), val.to_be());
    })
}

/// Write an unaligned big-endian `u64`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for eight consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_be64(p: *mut u8, val: u64) {
    // SAFETY: the caller guarantees an exclusively writable eight-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u64>(), val.to_be());
    })
}

// ── Little-endian ───────────────────────────────────────────────────────

/// Read an unaligned little-endian `u16`.
///
/// # Safety
///
/// `p` must be valid and readable for two consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_le16(p: *const u8) -> u16 {
    // SAFETY: the caller guarantees a readable two-byte region.
    u16::from_le(unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u16>())))
}

/// Read an unaligned little-endian `u32`.
///
/// # Safety
///
/// `p` must be valid and readable for four consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_le32(p: *const u8) -> u32 {
    // SAFETY: the caller guarantees a readable four-byte region.
    u32::from_le(unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u32>())))
}

/// Read an unaligned little-endian `u64`.
///
/// # Safety
///
/// `p` must be valid and readable for eight consecutive bytes.
#[inline]
pub unsafe fn unaligned_read_le64(p: *const u8) -> u64 {
    // SAFETY: the caller guarantees a readable eight-byte region.
    u64::from_le(unsafe_ffi!(core::ptr::read_unaligned(p.cast::<u64>())))
}

/// Write an unaligned little-endian `u16`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for two consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_le16(p: *mut u8, val: u16) {
    // SAFETY: the caller guarantees an exclusively writable two-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u16>(), val.to_le());
    })
}

/// Write an unaligned little-endian `u32`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for four consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_le32(p: *mut u8, val: u32) {
    // SAFETY: the caller guarantees an exclusively writable four-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u32>(), val.to_le());
    })
}

/// Write an unaligned little-endian `u64`.
///
/// # Safety
///
/// `p` must be valid and exclusively writable for eight consecutive bytes.
#[inline]
pub unsafe fn unaligned_write_le64(p: *mut u8, val: u64) {
    // SAFETY: the caller guarantees an exclusively writable eight-byte region.
    unsafe_ffi!({
        core::ptr::write_unaligned(p.cast::<u64>(), val.to_le());
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unaligned_read_ne16() {
        let buf: [u8; 4] = [0x34, 0x12, 0x78, 0x56];
        // SAFETY: `buf` is a live byte array and these helpers read/write only within its bounds using unaligned access.
        unsafe_ffi!({
            assert_eq!(unaligned_read_ne16(buf.as_ptr()), 0x1234);
            assert_eq!(unaligned_read_ne16(buf.as_ptr().add(2)), 0x5678);
        })
    }

    #[test]
    fn test_unaligned_read_ne32() {
        let buf: [u8; 8] = [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x89];
        // SAFETY: `buf` is a live byte array and these helpers read/write only within its bounds using unaligned access.
        unsafe_ffi!({
            assert_eq!(unaligned_read_ne32(buf.as_ptr()), 0x12345678);
        })
    }

    #[test]
    fn test_unaligned_write_ne16_roundtrip() {
        let mut buf = [0u8; 2];
        // SAFETY: `buf` is a live byte array and these helpers read/write only within its bounds using unaligned access.
        unsafe_ffi!({
            unaligned_write_ne16(buf.as_mut_ptr(), 0x1234);
            assert_eq!(unaligned_read_ne16(buf.as_ptr()), 0x1234);
        })
    }

    #[test]
    fn test_unaligned_be16() {
        let buf: [u8; 2] = [0x12, 0x34];
        // SAFETY: `buf` is a live byte array and these helpers read/write only within its bounds using unaligned access.
        unsafe_ffi!({
            assert_eq!(unaligned_read_be16(buf.as_ptr()), 0x1234);
        })
    }

    #[test]
    fn test_unaligned_be32_roundtrip() {
        let mut buf = [0u8; 4];
        // SAFETY: `buf` is a live byte array and these helpers read/write only within its bounds using unaligned access.
        unsafe_ffi!({
            unaligned_write_be32(buf.as_mut_ptr(), 0x12345678);
            assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
            assert_eq!(unaligned_read_be32(buf.as_ptr()), 0x12345678);
        })
    }

    #[test]
    fn test_unaligned_le16() {
        let buf: [u8; 2] = [0x34, 0x12];
        // SAFETY: `buf` is a live byte array and these helpers read/write only within its bounds using unaligned access.
        unsafe_ffi!({
            assert_eq!(unaligned_read_le16(buf.as_ptr()), 0x1234);
        })
    }

    #[test]
    fn test_unaligned_le32_roundtrip() {
        let mut buf = [0u8; 4];
        // SAFETY: `buf` is a live byte array and these helpers read/write only within its bounds using unaligned access.
        unsafe_ffi!({
            unaligned_write_le32(buf.as_mut_ptr(), 0x12345678);
            assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);
            assert_eq!(unaligned_read_le32(buf.as_ptr()), 0x12345678);
        })
    }

    #[test]
    fn test_unaligned_misaligned() {
        let buf: [u8; 10] = [0xAA, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xBB];
        // SAFETY: `buf` is a live byte array and these helpers read/write only within its bounds using unaligned access.
        unsafe_ffi!({
            let p = buf.as_ptr().add(1);
            assert_eq!(unaligned_read_be32(p), 0x01234567);
            assert_eq!(unaligned_read_le32(p), 0x67452301);
        })
    }
}
