// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/in-addr-util.c
//
// IPv4/IPv6 address manipulation utilities (pure subset).
// Skipped: hash functions (depend on siphash state), random functions (I/O),
//          in_addr_port_ifindex_name_to_string (uses asprintf_safe variadic).

use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::c_void;
use std::ptr;

use crate::ffi::Errno;
use libc::c_char;

// ── Constants ──────────────────────────────────────────────────────────────

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

// ── C dependencies ─────────────────────────────────────────────────────────

use crate::ffi::memcmp;

/// Convert network byte order (big-endian) u32 to host byte order.
#[inline]
fn be32toh(x: u32) -> u32 {
    u32::from_be(x)
}

/// Convert host byte order u32 to network byte order (big-endian).
#[inline]
fn htobe32(x: u32) -> u32 {
    u32::to_be(x)
}

// ── Repr(C) types ──────────────────────────────────────────────────────────

/// Mirrors C's union in_addr_union (using bytes array for FFI).
#[repr(C)]
pub union InAddrUnion {
    pub bytes: [u8; 16],
    pub in4: InAddr,
    pub in6: In6Addr,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct InAddr {
    pub s_addr: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct In6Addr {
    pub s6_addr: [u8; 16],
}

// ── Safe address helpers ───────────────────────────────────────────────────

#[inline]
fn in4_addr_is_null(a: &InAddr) -> bool {
    a.s_addr == 0
}

#[inline]
fn in6_addr_is_null(a: &In6Addr) -> bool {
    a.s6_addr.iter().all(|&byte| byte == 0)
}

#[inline]
fn in4_addr_is_link_local(a: &InAddr) -> bool {
    (be32toh(a.s_addr) & 0xFFFF0000) == ((169u32 << 24) | (254u32 << 16))
}

#[inline]
fn in4_addr_is_link_local_dynamic(a: &InAddr) -> bool {
    in4_addr_is_link_local(a) && {
        let v = be32toh(a.s_addr) & 0x0000FF00;
        v != 0 && v != 0xFF00
    }
}

#[inline]
fn in6_addr_is_link_local(a: &In6Addr) -> bool {
    a.s6_addr[0] == 0xfe && (a.s6_addr[1] & 0xc0) == 0x80
}

#[inline]
fn in6_addr_is_link_local_all_nodes(a: &In6Addr) -> bool {
    a.s6_addr == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
}

#[inline]
fn in4_addr_is_multicast(a: &InAddr) -> bool {
    (be32toh(a.s_addr) & 0xF0000000) == 0xE0000000
}

#[inline]
fn in6_addr_is_multicast(a: &In6Addr) -> bool {
    a.s6_addr[0] == 0xff
}

#[inline]
fn in4_addr_is_local_multicast(a: &InAddr) -> bool {
    (be32toh(a.s_addr) & 0xFFFFFF00) == 0xE0000000
}

#[inline]
fn in4_addr_is_localhost(a: &InAddr) -> bool {
    (be32toh(a.s_addr) & 0xFF000000) == 127 << 24
}

#[inline]
fn in4_addr_is_non_local(a: &InAddr) -> bool {
    !in4_addr_is_null(a) && !in4_addr_is_localhost(a)
}

#[inline]
fn in6_addr_is_loopback(a: &In6Addr) -> bool {
    a.s6_addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
}

#[inline]
fn in4_addr_equal(a: &InAddr, b: &InAddr) -> bool {
    a.s_addr == b.s_addr
}

#[inline]
fn in6_addr_equal(a: &In6Addr, b: &In6Addr) -> bool {
    a.s6_addr == b.s6_addr
}

#[inline]
fn in6_addr_is_ipv4_mapped_address(a: &In6Addr) -> bool {
    a.s6_addr[..10].iter().all(|&byte| byte == 0) && a.s6_addr[10..12] == [0xff, 0xff]
}

#[inline]
fn in4_addr_prefix_intersect(a: &InAddr, aprefixlen: u32, b: &InAddr, bprefixlen: u32) -> bool {
    let m = aprefixlen.min(bprefixlen).min(32);
    m == 0 || (be32toh(a.s_addr ^ b.s_addr) & (u32::MAX << (32 - m))) == 0
}

#[inline]
fn in6_addr_prefix_intersect(a: &In6Addr, aprefixlen: u32, b: &In6Addr, bprefixlen: u32) -> bool {
    let mut remaining = aprefixlen.min(bprefixlen).min(128);
    for (&left, &right) in a.s6_addr.iter().zip(b.s6_addr.iter()) {
        if remaining == 0 {
            return true;
        }
        let mask = if remaining < 8 {
            0xff << (8 - remaining)
        } else {
            0xff
        };
        if (left & mask) != (right & mask) {
            return false;
        }
        remaining = remaining.saturating_sub(8);
    }
    true
}

/// Select a union member after the caller has validated the address family.
///
/// # Safety
/// The union must contain an initialized value of the selected member type.
#[inline]
unsafe fn union_in4(u: &InAddrUnion) -> &InAddr {
    // SAFETY: the caller has established that the union currently holds `in4`.
    unsafe { &u.in4 }
}

/// Select a union member after the caller has validated the address family.
///
/// # Safety
/// The union must contain an initialized value of the selected member type.
#[inline]
unsafe fn union_in6(u: &InAddrUnion) -> &In6Addr {
    // SAFETY: the caller has established that the union currently holds `in6`.
    unsafe { &u.in6 }
}

// ── Public API ────────────────────────────────────────────────────────────

// ── Null checks ───────────────────────────────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in4_addr_is_null(a: &InAddr) -> bool {
    in4_addr_is_null(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in6_addr_is_null(a: &In6Addr) -> bool {
    in6_addr_is_null(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_in_addr_is_null(family: i32, u: *const InAddrUnion) -> i32 {
    // SAFETY: the C ABI contract guarantees a non-null pointer is readable.
    let Some(u) = (unsafe { u.as_ref() }) else {
        return Errno::EINVAL.to_neg_errno();
    };
    match family {
        // SAFETY: the selected union member corresponds to `family`.
        AF_INET => i32::from(in4_addr_is_null(unsafe { union_in4(u) })),
        // SAFETY: the selected union member corresponds to `family`.
        AF_INET6 => i32::from(in6_addr_is_null(unsafe { union_in6(u) })),
        _ => Errno::EAFNOSUPPORT.to_neg_errno(),
    }
}

// ── Inline wrappers from in-addr-util.h ────────────────────────────────────

/// Shadow of C in4_addr_is_set() — returns true if in4 address is not null.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in4_addr_is_set(a: *const InAddr) -> bool {
    // SAFETY: the C ABI contract guarantees a non-null pointer is readable.
    unsafe { a.as_ref() }.is_none_or(|a| !rs_in4_addr_is_null(a))
}

/// Shadow of C in_addr_data_is_set() — C quirk: delegates to in_addr_data_is_null.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_data_is_set(a: *const InAddrData) -> bool {
    // SAFETY: forwarded unchanged to the audited pointer adapter below.
    unsafe { a.as_ref() }.is_some_and(|a| unsafe { rs_in_addr_data_is_null(a) } != 0)
}

/// Shadow of C in6_addr_is_set() — returns true if in6 address is not null.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in6_addr_is_set(a: *const In6Addr) -> bool {
    // SAFETY: the C ABI contract guarantees a non-null pointer is readable.
    unsafe { a.as_ref() }.is_none_or(|a| !rs_in6_addr_is_null(a))
}

/// Shadow of C in_addr_is_set() — returns true if address is not null.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_is_set(family: i32, u: *const InAddrUnion) -> bool {
    // SAFETY: forwarded unchanged to the audited pointer adapter above.
    unsafe { rs_in_addr_is_null(family, u) == 0 }
}

/// Minimal repr(C) layout for struct in_addr_data (family + address union).
#[repr(C)]
pub struct InAddrData {
    pub family: i32,
    pub address: InAddrUnion,
}

/// Shadow of C in_addr_data_is_null() — returns true if address is null.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_data_is_null(a: *const InAddrData) -> i32 {
    // SAFETY: the C ABI contract guarantees a non-null pointer is readable.
    let Some(a) = (unsafe { a.as_ref() }) else {
        return Errno::EINVAL.to_neg_errno();
    };
    // SAFETY: `address` is an initialized union member selected by `family`.
    unsafe { rs_in_addr_is_null(a.family, &a.address) }
}

// ── Link-local checks ─────────────────────────────────────────────────────// ── Link-local checks ─────────────────────────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in4_addr_is_link_local(a: &InAddr) -> bool {
    in4_addr_is_link_local(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in4_addr_is_link_local_dynamic(a: &InAddr) -> bool {
    in4_addr_is_link_local_dynamic(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in6_addr_is_link_local(a: &In6Addr) -> bool {
    in6_addr_is_link_local(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_in_addr_is_link_local(family: i32, u: *const InAddrUnion) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if u.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            return if rs_in4_addr_is_link_local(&(*u).in4) {
                1
            } else {
                0
            };
        }
        if family == AF_INET6 {
            return if rs_in6_addr_is_link_local(&(*u).in6) {
                1
            } else {
                0
            };
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in6_addr_is_link_local_all_nodes(a: &In6Addr) -> bool {
    in6_addr_is_link_local_all_nodes(a)
}

// ── Multicast checks ─────────────────────────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in4_addr_is_multicast(a: &InAddr) -> bool {
    in4_addr_is_multicast(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in6_addr_is_multicast(a: &In6Addr) -> bool {
    in6_addr_is_multicast(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_in_addr_is_multicast(family: i32, u: *const InAddrUnion) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if u.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            return if rs_in4_addr_is_multicast(&(*u).in4) {
                1
            } else {
                0
            };
        }
        if family == AF_INET6 {
            return if rs_in6_addr_is_multicast(&(*u).in6) {
                1
            } else {
                0
            };
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in4_addr_is_local_multicast(a: &InAddr) -> bool {
    in4_addr_is_local_multicast(a)
}

// ── Localhost checks ──────────────────────────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in4_addr_is_localhost(a: &InAddr) -> bool {
    in4_addr_is_localhost(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub fn rs_in4_addr_is_non_local(a: &InAddr) -> bool {
    in4_addr_is_non_local(a)
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_in_addr_is_localhost(family: i32, u: *const InAddrUnion) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if u.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            return if rs_in4_addr_is_localhost(&(*u).in4) {
                1
            } else {
                0
            };
        }
        if family == AF_INET6 {
            // ::1
            return if in6_addr_is_loopback(&(*u).in6) {
                1
            } else {
                0
            };
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_is_localhost_one(family: i32, u: *const InAddrUnion) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if u.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            // 127.0.0.1
            return if be32toh((*u).in4.s_addr) == 0x7F000001 {
                1
            } else {
                0
            };
        }
        if family == AF_INET6 {
            return if in6_addr_is_loopback(&(*u).in6) {
                1
            } else {
                0
            };
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

// ── Equality ─────────────────────────────────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_in4_addr_equal(a: *const InAddr, b: *const InAddr) -> bool {
    // SAFETY: the C ABI contract guarantees non-null pointers are readable.
    // SAFETY: the C ABI contract guarantees non-null pointers are readable.
    match unsafe { (a.as_ref(), b.as_ref()) } {
        (Some(a), Some(b)) => in4_addr_equal(a, b),
        _ => false,
    }
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_in6_addr_equal(a: *const In6Addr, b: *const In6Addr) -> bool {
    // SAFETY: the C ABI contract guarantees non-null pointers are readable.
    // SAFETY: the C ABI contract guarantees non-null pointers are readable.
    match unsafe { (a.as_ref(), b.as_ref()) } {
        (Some(a), Some(b)) => in6_addr_equal(a, b),
        _ => false,
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_equal(family: i32, a: *const InAddrUnion, b: *const InAddrUnion) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || b.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            return if rs_in4_addr_equal(&(*a).in4, &(*b).in4) {
                1
            } else {
                0
            };
        }
        if family == AF_INET6 {
            return if rs_in6_addr_equal(&(*a).in6, &(*b).in6) {
                1
            } else {
                0
            };
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

// ── IPv4 mapped address ─────────────────────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_in6_addr_is_ipv4_mapped_address(a: *const In6Addr) -> bool {
    // SAFETY: the C ABI contract guarantees a non-null pointer is readable.
    unsafe { a.as_ref() }.is_some_and(in6_addr_is_ipv4_mapped_address)
}

// ── Prefix intersection ────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in4_addr_prefix_intersect(
    a: *const InAddr,
    aprefixlen: u32,
    b: *const InAddr,
    bprefixlen: u32,
) -> bool {
    // SAFETY: the C ABI contract guarantees non-null pointers are readable.
    // SAFETY: the C ABI contract guarantees non-null pointers are readable.
    match unsafe { (a.as_ref(), b.as_ref()) } {
        (Some(a), Some(b)) => in4_addr_prefix_intersect(a, aprefixlen, b, bprefixlen),
        _ => false,
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in6_addr_prefix_intersect(
    a: *const In6Addr,
    aprefixlen: u32,
    b: *const In6Addr,
    bprefixlen: u32,
) -> bool {
    // SAFETY: the C ABI contract guarantees non-null pointers are readable.
    // SAFETY: the C ABI contract guarantees non-null pointers are readable.
    match unsafe { (a.as_ref(), b.as_ref()) } {
        (Some(a), Some(b)) => in6_addr_prefix_intersect(a, aprefixlen, b, bprefixlen),
        _ => false,
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_prefix_intersect(
    family: i32,
    a: *const InAddrUnion,
    aprefixlen: u32,
    b: *const InAddrUnion,
    bprefixlen: u32,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || b.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            return if rs_in4_addr_prefix_intersect(&(*a).in4, aprefixlen, &(*b).in4, bprefixlen) {
                1
            } else {
                0
            };
        }
        if family == AF_INET6 {
            return if rs_in6_addr_prefix_intersect(&(*a).in6, aprefixlen, &(*b).in6, bprefixlen) {
                1
            } else {
                0
            };
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

// ── Prefix nth ───────────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_prefix_nth(
    family: i32,
    u: *mut InAddrUnion,
    prefixlen: u32,
    nth: u64,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if u.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        if prefixlen == 0 {
            return Errno::ERANGE.to_neg_errno(); // -ERANGE
        }

        if family == AF_INET {
            if prefixlen > 32 {
                return Errno::ERANGE.to_neg_errno();
            }

            let c = be32toh((*u).in4.s_addr);
            let t = (nth as u64) << (32 - prefixlen);

            if c > u32::MAX - (t as u32) {
                return Errno::ERANGE.to_neg_errno();
            }

            let n = c + (t as u32);
            let n = n & (0xFFFFFFFF_u32 << (32 - prefixlen));
            (*u).in4.s_addr = htobe32(n);
            return 0;
        }

        if family == AF_INET6 {
            if prefixlen > 128 {
                return Errno::ERANGE.to_neg_errno();
            }

            let mut overflow = false;
            let mut nth = nth;

            for i in (1..=16).rev() {
                let j = i - 1;
                let p = j * 8;

                if p >= prefixlen as usize {
                    (*u).in6.s6_addr[j] = 0;
                    continue;
                }

                let (new_byte, new_nth) = if prefixlen as usize - p < 8 {
                    let shift = 8 - (prefixlen as usize - p);
                    (*u).in6.s6_addr[j] &= 0xFF << shift;
                    let t = ((*u).in6.s6_addr[j] as u16) + (((nth & 0xFF) as u16) << shift);
                    nth >>= (prefixlen as usize - p) as u32;
                    (t, nth)
                } else {
                    let t = ((*u).in6.s6_addr[j] as u16) + (nth & 0xFF) as u16 + (overflow as u16);
                    nth >>= 8;
                    (t, nth)
                };

                overflow = new_byte > 0xFF;
                (*u).in6.s6_addr[j] = (new_byte & 0xFF) as u8;
                nth = new_nth;
            }

            if overflow || nth != 0 {
                return Errno::ERANGE.to_neg_errno();
            }
            return 0;
        }

        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_prefix_next(family: i32, u: *mut InAddrUnion, prefixlen: u32) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if u.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        rs_in_addr_prefix_nth(family, u, prefixlen, 1)
    }
}

// ── Netmask from prefix length ──────────────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_in4_addr_netmask_to_prefixlen(addr: *const InAddr) -> u8 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() {
            return 0;
        }
        (32u32 - be32toh((*addr).s_addr).trailing_zeros()) as u8
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in4_addr_prefixlen_to_netmask(addr: *mut InAddr, prefixlen: u8) -> *mut InAddr {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() {
            return ptr::null_mut();
        }
        if prefixlen > 32 {
            return ptr::null_mut();
        }
        if prefixlen == 0 {
            (*addr).s_addr = 0;
        } else {
            (*addr).s_addr = htobe32(0xffffffffu32 << (32 - prefixlen));
        }
        addr
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in6_addr_prefixlen_to_netmask(addr: *mut In6Addr, prefixlen: u8) -> *mut In6Addr {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() {
            return ptr::null_mut();
        }
        if prefixlen > 128 {
            return ptr::null_mut();
        }
        let mut pl = prefixlen;
        for i in 0..16usize {
            if pl >= 8 {
                (*addr).s6_addr[i] = 0xFF;
                pl -= 8;
            } else if pl > 0 {
                (*addr).s6_addr[i] = 0xFF << (8 - pl);
                pl = 0;
            } else {
                (*addr).s6_addr[i] = 0;
            }
        }
        addr
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_prefixlen_to_netmask(
    family: i32,
    addr: *mut InAddrUnion,
    prefixlen: u8,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            rs_in4_addr_prefixlen_to_netmask(&mut (*addr).in4, prefixlen);
            return 0;
        }
        if family == AF_INET6 {
            rs_in6_addr_prefixlen_to_netmask(&mut (*addr).in6, prefixlen);
            return 0;
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

// ── Default prefix length ───────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in4_addr_default_prefixlen(addr: *const InAddr, prefixlen: *mut u8) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() || prefixlen.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let msb = ptr::read((addr as *const u8).offset(0));
        if msb < 128 {
            *prefixlen = 8;
        } else if msb < 192 {
            *prefixlen = 16;
        } else if msb < 224 {
            *prefixlen = 24;
        } else {
            return Errno::ERANGE.to_neg_errno(); // -ERANGE
        }
        0
    }
}

// ── Mask ──────────────────────────────────────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned. Output pointers must point to valid writable memory.
pub unsafe fn rs_in4_addr_mask(addr: *mut InAddr, prefixlen: u8) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        let mut mask = InAddr { s_addr: 0 };
        if rs_in4_addr_prefixlen_to_netmask(&mut mask, prefixlen).is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        (*addr).s_addr &= mask.s_addr;
        0
    }
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned. Output pointers must point to valid writable memory.
pub unsafe fn rs_in6_addr_mask(addr: *mut In6Addr, prefixlen: u8) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        let mut pl = prefixlen;
        for i in 0..16usize {
            let mask = if pl >= 8 {
                pl -= 8;
                0xFFu8
            } else if pl > 0 {
                let m = 0xFFu8 << (8 - pl);
                pl = 0;
                m
            } else {
                0
            };
            (*addr).s6_addr[i] &= mask;
        }
        0
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_mask(family: i32, addr: *mut InAddrUnion, prefixlen: u8) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            return rs_in4_addr_mask(&mut (*addr).in4, prefixlen);
        }
        if family == AF_INET6 {
            return rs_in6_addr_mask(&mut (*addr).in6, prefixlen);
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

// ── Prefix covers ────────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in4_addr_prefix_covers(
    prefix: *const InAddr,
    prefixlen: u8,
    address: *const InAddr,
) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if prefix.is_null() || address.is_null() {
            return false;
        }

        let mut mp = ptr::read(prefix);
        let r = rs_in4_addr_mask(&mut mp, prefixlen);
        if r < 0 {
            return false;
        }

        let mut ma = ptr::read(address);
        let r = rs_in4_addr_mask(&mut ma, prefixlen);
        if r < 0 {
            return false;
        }

        rs_in4_addr_equal(&mp, &ma)
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in6_addr_prefix_covers(
    prefix: *const In6Addr,
    prefixlen: u8,
    address: *const In6Addr,
) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if prefix.is_null() || address.is_null() {
            return false;
        }

        let mut mp = ptr::read(prefix);
        let r = rs_in6_addr_mask(&mut mp, prefixlen);
        if r < 0 {
            return false;
        }

        let mut ma = ptr::read(address);
        let r = rs_in6_addr_mask(&mut ma, prefixlen);
        if r < 0 {
            return false;
        }

        rs_in6_addr_equal(&mp, &ma)
    }
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_prefix_covers(
    family: i32,
    prefix: *const InAddrUnion,
    prefixlen: u8,
    address: *const InAddrUnion,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if prefix.is_null() || address.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family == AF_INET {
            return if rs_in4_addr_prefix_covers(&(*prefix).in4, prefixlen, &(*address).in4) {
                1
            } else {
                0
            };
        }
        if family == AF_INET6 {
            return if rs_in6_addr_prefix_covers(&(*prefix).in6, prefixlen, &(*address).in6) {
                1
            } else {
                0
            };
        }
        Errno::EAFNOSUPPORT.to_neg_errno()
    }
}

// ── in4_addr_prefix_covers_full ─────────────────────────────────────────

/// Check if prefix (with prefixlen) covers address (with address_prefixlen).
/// IPv4 version.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in4_addr_prefix_covers_full(
    prefix: *const InAddr,
    prefixlen: u8,
    address: *const InAddr,
    address_prefixlen: u8,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if prefix.is_null() || address.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if prefixlen > address_prefixlen {
            return 0;
        }

        let mut masked_prefix = InAddr {
            s_addr: (*prefix).s_addr,
        };
        let r = rs_in4_addr_mask(&mut masked_prefix, prefixlen);
        if r < 0 {
            return r;
        }

        let mut masked_address = InAddr {
            s_addr: (*address).s_addr,
        };
        let r2 = rs_in4_addr_mask(&mut masked_address, prefixlen);
        if r2 < 0 {
            return r2;
        }

        if rs_in4_addr_equal(&masked_prefix, &masked_address) {
            1
        } else {
            0
        }
    }
}

// ── in6_addr_prefix_covers_full ─────────────────────────────────────────

/// Check if prefix (with prefixlen) covers address (with address_prefixlen).
/// IPv6 version.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in6_addr_prefix_covers_full(
    prefix: *const In6Addr,
    prefixlen: u8,
    address: *const In6Addr,
    address_prefixlen: u8,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if prefix.is_null() || address.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if prefixlen > address_prefixlen {
            return 0;
        }

        let mut masked_prefix = In6Addr {
            s6_addr: (*prefix).s6_addr,
        };
        let r = rs_in6_addr_mask(&mut masked_prefix, prefixlen);
        if r < 0 {
            return r;
        }

        let mut masked_address = In6Addr {
            s6_addr: (*address).s6_addr,
        };
        let r2 = rs_in6_addr_mask(&mut masked_address, prefixlen);
        if r2 < 0 {
            return r2;
        }

        if rs_in6_addr_equal(&masked_prefix, &masked_address) {
            1
        } else {
            0
        }
    }
}

// ── in_addr_prefix_covers_full ──────────────────────────────────────────

/// Check if prefix (with prefixlen) covers address (with address_prefixlen).
/// Dispatches to IPv4 or IPv6 version.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_prefix_covers_full(
    family: i32,
    prefix: *const InAddrUnion,
    prefixlen: u8,
    address: *const InAddrUnion,
    address_prefixlen: u8,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if prefix.is_null() || address.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        match family {
            AF_INET => rs_in4_addr_prefix_covers_full(
                &(*prefix).in4,
                prefixlen,
                &(*address).in4,
                address_prefixlen,
            ),
            AF_INET6 => rs_in6_addr_prefix_covers_full(
                &(*prefix).in6,
                prefixlen,
                &(*address).in6,
                address_prefixlen,
            ),
            _ => Errno::EAFNOSUPPORT.to_neg_errno(),
        }
    }
}

// ── in6_addr_compare_func ───────────────────────────────────────────────

/// Compare two IPv6 addresses for ordering.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in6_addr_compare_func(a: *const In6Addr, b: *const In6Addr) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || b.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        memcmp(a as *const c_void, b as *const c_void, 16)
    }
}

// ── in_addr_data_compare_func ───────────────────────────────────────────

/// Compare two in_addr_data structs (family + address).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_data_compare_func(x: *const InAddrData, y: *const InAddrData) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if x.is_null() || y.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        // Compare family first
        let xf = (*x).family;
        let yf = (*y).family;
        if xf < yf {
            return -1;
        }
        if xf > yf {
            return 1;
        }

        // Compare address bytes
        let sz = rs_FAMILY_ADDRESS_SIZE(xf);
        memcmp(
            &(*x).address as *const InAddrUnion as *const c_void,
            &(*y).address as *const InAddrUnion as *const c_void,
            sz,
        )
    }
}

// -- in_addr_parse_prefixlen ---------------------------------------------------

/// Shadow of C in_addr_parse_prefixlen()
/// Parses a prefix length string (e.g. "24") and validates against family max.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_in_addr_parse_prefixlen(family: i32, p: *const c_char, ret: *mut u8) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if !p.is_null() && (*p as u8) == 0 {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL (empty string)
        }

        let mut u: u8 = 0;
        let r = crate::parse_util::rs_safe_atou8_full(p, 10, &mut u);
        if r < 0 {
            return r;
        }

        let max_bits: u8 = if family == AF_INET {
            32
        } else if family == AF_INET6 {
            128
        } else {
            return Errno::EAFNOSUPPORT.to_neg_errno();
        };

        if u > max_bits {
            return Errno::ERANGE.to_neg_errno(); // -ERANGE
        }

        if !ret.is_null() {
            *ret = u;
        }
        0
    }
}

// -- in4_addr_default_subnet_mask --------------------------------------------

/// Shadow of C in4_addr_default_subnet_mask()
/// Computes default subnet mask from address class.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in4_addr_default_subnet_mask(addr: *const InAddr, mask: *mut InAddr) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if addr.is_null() || mask.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut prefixlen: u8 = 0;
        let r = rs_in4_addr_default_prefixlen(addr, &mut prefixlen);
        if r < 0 {
            return r;
        }

        rs_in4_addr_prefixlen_to_netmask(mask, prefixlen);
        0
    }
}

// ── PTR_TO_IN4_ADDR / IN4_ADDR_TO_PTR ─────────────────────────────────

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned. Output pointers must point to valid writable memory.
pub unsafe fn rs_PTR_TO_IN4_ADDR(p: *const c_void, ret: *mut InAddr) {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if ret.is_null() {
            return;
        }
        (*ret).s_addr = p as u32;
    }
}

/// # Safety
/// The caller must ensure that all pointer arguments are valid and properly aligned.
pub unsafe fn rs_IN4_ADDR_TO_PTR(a: *const InAddr) -> *mut c_void {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() {
            return ptr::null_mut();
        }
        (*a).s_addr as *mut c_void
    }
}

// ── in_addr_from_string / in_addr_from_string_auto ────────────────────

const EAFNOSUPPORT: i32 = 97;

use crate::ffi::{free, malloc};

/// # Safety
/// A non-null `src` must be a valid NUL-terminated C string. For `AF_INET`/`AF_INET6`,
/// a non-null `dst` must be writable for 4/16 bytes, respectively.
unsafe fn parse_ip_string(family: i32, src: *const c_char, dst: *mut u8) -> Result<(), i32> {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if src.is_null() || dst.is_null() {
            return Err(Errno::EINVAL.to_neg_errno());
        }

        let s = CStr::from_ptr(src)
            .to_str()
            .map_err(|_| Errno::EINVAL.to_neg_errno())?;
        match family {
            AF_INET => {
                let addr: Ipv4Addr = s.parse().map_err(|_| Errno::EINVAL.to_neg_errno())?;
                let octets = addr.octets();
                ptr::copy_nonoverlapping(octets.as_ptr(), dst, octets.len());
                Ok(())
            }
            AF_INET6 => {
                let addr: Ipv6Addr = s.parse().map_err(|_| Errno::EINVAL.to_neg_errno())?;
                let octets = addr.octets();
                ptr::copy_nonoverlapping(octets.as_ptr(), dst, octets.len());
                Ok(())
            }
            _ => Err(-EAFNOSUPPORT),
        }
    }
}

/// # Safety
/// For a non-null `src`, `AF_INET`/`AF_INET6` require 4/16 initialized readable bytes,
/// respectively.
unsafe fn ip_to_string(family: i32, src: *const u8) -> Result<String, i32> {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if src.is_null() {
            return Err(Errno::EINVAL.to_neg_errno());
        }

        match family {
            AF_INET => Ok(Ipv4Addr::from(*(src as *const [u8; 4])).to_string()),
            AF_INET6 => Ok(Ipv6Addr::from(*(src as *const [u8; 16])).to_string()),
            _ => Err(-EAFNOSUPPORT),
        }
    }
}

/// # Safety
/// When writing succeeds, `buf` must be writable for `text.len() + 1` bytes and not overlap
/// `text`.
unsafe fn write_text_to_c_buf(buf: *mut c_char, buf_len: usize, text: &str) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if buf.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if text.len() + 1 > buf_len {
            return -ENOSPC;
        }

        ptr::copy_nonoverlapping(text.as_ptr(), buf as *mut u8, text.len());
        *buf.add(text.len()) = 0;
        0
    }
}

/// Parse an IP address string for a specific address family.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_in_addr_from_string(family: i32, s: *const c_char, ret: *mut u8) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        /* C accepts a NULL output pointer and parses into a local union instead.
         * Preserve that query/validation form without dereferencing NULL. */
        let mut discard = [0u8; 16];
        let destination = if ret.is_null() {
            discard.as_mut_ptr()
        } else {
            ret
        };

        match parse_ip_string(family, s, destination) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }
}

/// Parse an IP address string, auto-detecting IPv4 vs IPv6.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_in_addr_from_string_auto(
    s: *const c_char,
    ret_family: *mut i32,
    ret: *mut u8,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if s.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        // Try IPv4 first
        let r = rs_in_addr_from_string(AF_INET, s, ret);
        if r >= 0 {
            if !ret_family.is_null() {
                *ret_family = AF_INET;
            }
            return 0;
        }

        // Try IPv6
        let r = rs_in_addr_from_string(AF_INET6, s, ret);
        if r >= 0 {
            if !ret_family.is_null() {
                *ret_family = AF_INET6;
            }
            return 0;
        }

        Errno::EINVAL.to_neg_errno()
    }
}

/// Convert an IP address to its string representation.
/// Returns 0 on success, negative errno on failure.
/// Allocates a new string via malloc; caller must free().
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_in_addr_to_string(family: i32, u: *const u8, ret: *mut *mut c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let text = match ip_to_string(family, u) {
            Ok(text) => text,
            Err(e) => return e,
        };

        let buf = malloc(text.len() + 1) as *mut c_char;
        if buf.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }

        let r = write_text_to_c_buf(buf, text.len() + 1, &text);
        if r < 0 {
            free(buf as *mut c_void);
            return r;
        }

        *ret = buf;
        0
    }
}

/// Parse a CIDR prefix string (e.g., "192.168.1.0/24").
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_in_addr_prefix_from_string(
    p: *const c_char,
    family: i32,
    ret_prefix: *mut u8,
    ret_prefixlen: *mut u8,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family != AF_INET && family != AF_INET6 {
            return -EAFNOSUPPORT;
        }

        // Find '/' separator
        let mut e: *const c_char = ptr::null();
        let mut pp = p;
        while *pp != 0 {
            if *pp == b'/' as c_char {
                e = pp;
                break;
            }
            pp = pp.add(1);
        }

        // Extract address part
        let addr_part: *const c_char;
        let mut allocated: *mut c_char = ptr::null_mut();
        if !e.is_null() {
            let addr_len = e.offset_from(p) as usize;
            allocated = malloc(addr_len + 1) as *mut c_char;
            if allocated.is_null() {
                return Errno::ENOMEM.to_neg_errno();
            }
            // Copy address part + NUL
            let src = p as *const u8;
            let dst = allocated as *mut u8;
            let mut i = 0usize;
            while i < addr_len {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
            *dst.add(addr_len) = 0;
            addr_part = allocated;
        } else {
            addr_part = p;
        }

        // Parse the address
        let mut buffer = [0u8; 16];
        let r = rs_in_addr_from_string(family, addr_part, buffer.as_mut_ptr());
        if !allocated.is_null() {
            free(allocated as *mut c_void);
        }
        if r < 0 {
            return r;
        }

        // Parse prefix length
        let mut prefixlen: u8 = 0;
        if !e.is_null() {
            // Call C's in_addr_parse_prefixlen
            let r =
                crate::in_addr_util::rs_in_addr_parse_prefixlen(family, e.add(1), &mut prefixlen);
            if r < 0 {
                return r;
            }
        } else {
            prefixlen = (rs_FAMILY_ADDRESS_SIZE(family) * 8) as u8;
        }

        // Copy results
        if !ret_prefix.is_null() {
            let dst = ret_prefix;
            for (i, byte) in buffer.iter().enumerate() {
                *dst.add(i) = *byte;
            }
        }
        if !ret_prefixlen.is_null() {
            *ret_prefixlen = prefixlen;
        }

        0
    }
}

// ── FAMILY_ADDRESS_SIZE ────────────────────────────────────────────────

pub fn rs_FAMILY_ADDRESS_SIZE(family: i32) -> usize {
    match family {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => 0,
    }
}

// ── in_addr_prefix_range ───────────────────────────────────────────────

/// Get the start and end addresses of a prefix range.
/// ret_start and ret_end may be NULL if not needed.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn rs_in_addr_prefix_range(
    family: i32,
    input: *const InAddrUnion,
    prefixlen: u32,
    ret_start: *mut InAddrUnion,
    ret_end: *mut InAddrUnion,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if input.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if family != AF_INET && family != AF_INET6 {
            return -EAFNOSUPPORT;
        }

        let mut start = InAddrUnion { bytes: [0u8; 16] };
        let mut end = InAddrUnion { bytes: [0u8; 16] };

        if !ret_start.is_null() {
            start.bytes = (*input).bytes;
            let r = rs_in_addr_prefix_nth(family, &mut start, prefixlen, 0);
            if r < 0 {
                return r;
            }
        }

        if !ret_end.is_null() {
            end.bytes = (*input).bytes;
            let r = rs_in_addr_prefix_nth(family, &mut end, prefixlen, 1);
            if r < 0 {
                return r;
            }
        }

        if !ret_start.is_null() {
            (*ret_start) = start;
        }
        if !ret_end.is_null() {
            (*ret_end) = end;
        }

        0
    }
}

// ── in_addr_prefix_to_string ───────────────────────────────────────────

const ENOSPC: i32 = 28;

/// Convert an IP prefix to string "addr/prefixlen" into a buffer.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_in_addr_prefix_to_string(
    family: i32,
    u: *const InAddrUnion,
    prefixlen: u32,
    buf: *mut c_char,
    buf_len: usize,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if u.is_null() || buf.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let text = match family {
            AF_INET => format!(
                "{}/{}",
                Ipv4Addr::from((*u).in4.s_addr.to_ne_bytes()),
                prefixlen
            ),
            AF_INET6 => format!("{}/{}", Ipv6Addr::from((*u).in6.s6_addr), prefixlen),
            _ => return -EAFNOSUPPORT,
        };

        write_text_to_c_buf(buf, buf_len, &text)
    }
}

// ── in_addr_prefix_from_string_auto_full ───────────────────────────────

const ENOANO: i32 = 55;
const PREFIXLEN_REFUSE: i32 = 1;

/// Parse a CIDR prefix string, auto-detecting IPv4 vs IPv6.
/// mode: PREFIXLEN_REFUSE (1).
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_in_addr_prefix_from_string_auto_full(
    p: *const c_char,
    mode: i32,
    ret_family: *mut i32,
    ret_prefix: *mut u8,
    ret_prefixlen: *mut u8,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        // Find '/' separator
        let mut e: *const c_char = ptr::null();
        let mut pp = p;
        while *pp != 0 {
            if *pp == b'/' as c_char {
                e = pp;
                break;
            }
            pp = pp.add(1);
        }

        // Extract address part
        let addr_part: *const c_char;
        let mut allocated: *mut c_char = ptr::null_mut();
        if !e.is_null() {
            let addr_len = e.offset_from(p) as usize;
            allocated = malloc(addr_len + 1) as *mut c_char;
            if allocated.is_null() {
                return Errno::ENOMEM.to_neg_errno();
            }
            let src = p as *const u8;
            let dst = allocated as *mut u8;
            let mut i = 0usize;
            while i < addr_len {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
            *dst.add(addr_len) = 0;
            addr_part = allocated;
        } else {
            addr_part = p;
        }

        // Parse address with auto-detection
        let mut family: i32 = 0;
        let mut buffer = [0u8; 16];
        let r = rs_in_addr_from_string_auto(addr_part, &mut family, buffer.as_mut_ptr());
        if !allocated.is_null() {
            free(allocated as *mut c_void);
        }
        if r < 0 {
            return r;
        }

        // Parse prefix length
        let mut prefixlen: u8 = 0;
        if !e.is_null() {
            let r = rs_in_addr_parse_prefixlen(family, e.add(1), &mut prefixlen);
            if r < 0 {
                return r;
            }
        } else if mode == PREFIXLEN_REFUSE {
            return -ENOANO;
        } else {
            // PREFIXLEN_FULL
            prefixlen = (rs_FAMILY_ADDRESS_SIZE(family) * 8) as u8;
        }

        if !ret_family.is_null() {
            *ret_family = family;
        }
        if !ret_prefix.is_null() {
            let dst = ret_prefix;
            for (i, byte) in buffer.iter().enumerate() {
                *dst.add(i) = *byte;
            }
        }
        if !ret_prefixlen.is_null() {
            *ret_prefixlen = prefixlen;
        }

        0
    }
}

/*
 * The Rust implementation intentionally keeps its typed, locally callable
 * functions separate from the C ABI.  This macro is the one audited boundary:
 * it gives each advertised `rs_*` symbol the C calling convention while
 * forwarding only the original borrowed pointers and fixed-size values.
 *
 * # Safety
 * C callers must satisfy the corresponding C declaration's preconditions:
 * every non-NULL pointer must be valid, correctly aligned for its declared
 * object, and live for the call; mutable pointers must be writable.  No input
 * pointer is retained. `rs_in_addr_to_string` is the sole owning result and
 * allocates with the C allocator (`libc::malloc`), so C must release it with
 * its normal `free()` contract rather than a Rust allocator.
 */
macro_rules! ffi_forward {
    (safe $symbol:literal, $wrapper:ident, ($($argument:ident : $ty:ty),* $(,)?) -> $result:ty, $implementation:path) => {
        #[unsafe(export_name = $symbol)]
        /// # Safety
        /// Caller must uphold generated or platform ABI invariants; raw Rust references may not outlive the call.
        pub unsafe extern "C" fn $wrapper($($argument: $ty),*) -> $result {
            $implementation($($argument),*)
        }
    };
    ($symbol:literal, $wrapper:ident, ($($argument:ident : $ty:ty),* $(,)?) -> $result:ty, $implementation:path) => {
        #[unsafe(export_name = $symbol)]
        // SAFETY: the forwarding call has exactly the raw-pointer contract
        // documented for this audited C ABI macro.
        ///
        /// # Safety
        /// The caller must uphold the generated or platform ABI invariants documented
        /// by this operation; no raw Rust references may outlive the call.
        pub unsafe extern "C" fn $wrapper($($argument: $ty),*) -> $result {
            // SAFETY: upheld by the C ABI contract documented above.
            unsafe { $implementation($($argument),*) }
        }
    };
}

/// Raw-pointer ABI adapter for predicates whose implementation is safe once it
/// has an address reference. A NULL C pointer retains the historical `false`
/// result; all address inspection happens in the safe implementation.
macro_rules! ffi_forward_addr_predicate {
    ($symbol:literal, $wrapper:ident, $argument:ident: $raw:ty, $address:ty, $implementation:path) => {
        #[unsafe(export_name = $symbol)]
        // SAFETY: this wrapper is the audited C ABI boundary for a borrowed address.
        pub unsafe extern "C" fn $wrapper($argument: $raw) -> bool {
            // SAFETY: the C ABI contract guarantees a non-null pointer is a readable address.
            let Some($argument): Option<&$address> = (unsafe { $argument.as_ref() }) else {
                return false;
            };
            $implementation($argument)
        }
    };
}

// Keep this list mechanically aligned with `rust/in_addr_util.h`.  These
// facades never reinterpret ownership: inputs and fixed-size outputs are
// borrowed, and the one allocated string uses libc allocation.
ffi_forward_addr_predicate!("rs_in4_addr_is_null", ffi_in4_addr_is_null, a: *const InAddr, InAddr, rs_in4_addr_is_null);
ffi_forward_addr_predicate!("rs_in6_addr_is_null", ffi_in6_addr_is_null, a: *const In6Addr, In6Addr, rs_in6_addr_is_null);
ffi_forward!("rs_in_addr_is_null", ffi_in_addr_is_null, (family: i32, u: *const InAddrUnion) -> i32, rs_in_addr_is_null);
ffi_forward!("rs_in4_addr_is_set", ffi_in4_addr_is_set, (a: *const InAddr) -> bool, rs_in4_addr_is_set);
ffi_forward!("rs_in6_addr_is_set", ffi_in6_addr_is_set, (a: *const In6Addr) -> bool, rs_in6_addr_is_set);
ffi_forward!("rs_in_addr_is_set", ffi_in_addr_is_set, (family: i32, u: *const InAddrUnion) -> bool, rs_in_addr_is_set);
ffi_forward!("rs_in_addr_data_is_null", ffi_in_addr_data_is_null, (a: *const InAddrData) -> i32, rs_in_addr_data_is_null);
ffi_forward!("rs_in_addr_data_is_set", ffi_in_addr_data_is_set, (a: *const InAddrData) -> bool, rs_in_addr_data_is_set);

ffi_forward_addr_predicate!("rs_in4_addr_is_link_local", ffi_in4_addr_is_link_local, a: *const InAddr, InAddr, rs_in4_addr_is_link_local);
ffi_forward_addr_predicate!("rs_in4_addr_is_link_local_dynamic", ffi_in4_addr_is_link_local_dynamic, a: *const InAddr, InAddr, rs_in4_addr_is_link_local_dynamic);
ffi_forward_addr_predicate!("rs_in6_addr_is_link_local", ffi_in6_addr_is_link_local, a: *const In6Addr, In6Addr, rs_in6_addr_is_link_local);
ffi_forward!("rs_in_addr_is_link_local", ffi_in_addr_is_link_local, (family: i32, u: *const InAddrUnion) -> i32, rs_in_addr_is_link_local);
ffi_forward_addr_predicate!("rs_in6_addr_is_link_local_all_nodes", ffi_in6_addr_is_link_local_all_nodes, a: *const In6Addr, In6Addr, rs_in6_addr_is_link_local_all_nodes);

ffi_forward_addr_predicate!("rs_in4_addr_is_multicast", ffi_in4_addr_is_multicast, a: *const InAddr, InAddr, rs_in4_addr_is_multicast);
ffi_forward_addr_predicate!("rs_in6_addr_is_multicast", ffi_in6_addr_is_multicast, a: *const In6Addr, In6Addr, rs_in6_addr_is_multicast);
ffi_forward!("rs_in_addr_is_multicast", ffi_in_addr_is_multicast, (family: i32, u: *const InAddrUnion) -> i32, rs_in_addr_is_multicast);
ffi_forward_addr_predicate!("rs_in4_addr_is_local_multicast", ffi_in4_addr_is_local_multicast, a: *const InAddr, InAddr, rs_in4_addr_is_local_multicast);

ffi_forward_addr_predicate!("rs_in4_addr_is_localhost", ffi_in4_addr_is_localhost, a: *const InAddr, InAddr, rs_in4_addr_is_localhost);
ffi_forward_addr_predicate!("rs_in4_addr_is_non_local", ffi_in4_addr_is_non_local, a: *const InAddr, InAddr, rs_in4_addr_is_non_local);
ffi_forward!("rs_in_addr_is_localhost", ffi_in_addr_is_localhost, (family: i32, u: *const InAddrUnion) -> i32, rs_in_addr_is_localhost);
ffi_forward!("rs_in_addr_is_localhost_one", ffi_in_addr_is_localhost_one, (family: i32, u: *const InAddrUnion) -> i32, rs_in_addr_is_localhost_one);

ffi_forward!("rs_in4_addr_equal", ffi_in4_addr_equal, (a: *const InAddr, b: *const InAddr) -> bool, rs_in4_addr_equal);
ffi_forward!("rs_in6_addr_equal", ffi_in6_addr_equal, (a: *const In6Addr, b: *const In6Addr) -> bool, rs_in6_addr_equal);
ffi_forward!("rs_in_addr_equal", ffi_in_addr_equal, (family: i32, a: *const InAddrUnion, b: *const InAddrUnion) -> i32, rs_in_addr_equal);
ffi_forward!("rs_in6_addr_is_ipv4_mapped_address", ffi_in6_addr_is_ipv4_mapped_address, (a: *const In6Addr) -> bool, rs_in6_addr_is_ipv4_mapped_address);

ffi_forward!("rs_in4_addr_prefix_intersect", ffi_in4_addr_prefix_intersect, (a: *const InAddr, aprefixlen: u32, b: *const InAddr, bprefixlen: u32) -> bool, rs_in4_addr_prefix_intersect);
ffi_forward!("rs_in6_addr_prefix_intersect", ffi_in6_addr_prefix_intersect, (a: *const In6Addr, aprefixlen: u32, b: *const In6Addr, bprefixlen: u32) -> bool, rs_in6_addr_prefix_intersect);
ffi_forward!("rs_in_addr_prefix_intersect", ffi_in_addr_prefix_intersect, (family: i32, a: *const InAddrUnion, aprefixlen: u32, b: *const InAddrUnion, bprefixlen: u32) -> i32, rs_in_addr_prefix_intersect);
ffi_forward!("rs_in_addr_prefix_nth", ffi_in_addr_prefix_nth, (family: i32, u: *mut InAddrUnion, prefixlen: u32, nth: u64) -> i32, rs_in_addr_prefix_nth);
ffi_forward!("rs_in_addr_prefix_next", ffi_in_addr_prefix_next, (family: i32, u: *mut InAddrUnion, prefixlen: u32) -> i32, rs_in_addr_prefix_next);

ffi_forward!("rs_in4_addr_netmask_to_prefixlen", ffi_in4_addr_netmask_to_prefixlen, (addr: *const InAddr) -> u8, rs_in4_addr_netmask_to_prefixlen);
ffi_forward!("rs_in4_addr_prefixlen_to_netmask", ffi_in4_addr_prefixlen_to_netmask, (addr: *mut InAddr, prefixlen: u8) -> *mut InAddr, rs_in4_addr_prefixlen_to_netmask);
ffi_forward!("rs_in6_addr_prefixlen_to_netmask", ffi_in6_addr_prefixlen_to_netmask, (addr: *mut In6Addr, prefixlen: u8) -> *mut In6Addr, rs_in6_addr_prefixlen_to_netmask);
ffi_forward!("rs_in_addr_prefixlen_to_netmask", ffi_in_addr_prefixlen_to_netmask, (family: i32, addr: *mut InAddrUnion, prefixlen: u8) -> i32, rs_in_addr_prefixlen_to_netmask);
ffi_forward!("rs_in4_addr_default_prefixlen", ffi_in4_addr_default_prefixlen, (addr: *const InAddr, prefixlen: *mut u8) -> i32, rs_in4_addr_default_prefixlen);
ffi_forward!("rs_in4_addr_default_subnet_mask", ffi_in4_addr_default_subnet_mask, (addr: *const InAddr, mask: *mut InAddr) -> i32, rs_in4_addr_default_subnet_mask);
ffi_forward!("rs_in4_addr_mask", ffi_in4_addr_mask, (addr: *mut InAddr, prefixlen: u8) -> i32, rs_in4_addr_mask);
ffi_forward!("rs_in6_addr_mask", ffi_in6_addr_mask, (addr: *mut In6Addr, prefixlen: u8) -> i32, rs_in6_addr_mask);
ffi_forward!("rs_in_addr_mask", ffi_in_addr_mask, (family: i32, addr: *mut InAddrUnion, prefixlen: u8) -> i32, rs_in_addr_mask);

ffi_forward!("rs_in4_addr_prefix_covers", ffi_in4_addr_prefix_covers, (prefix: *const InAddr, prefixlen: u8, address: *const InAddr) -> bool, rs_in4_addr_prefix_covers);
ffi_forward!("rs_in6_addr_prefix_covers", ffi_in6_addr_prefix_covers, (prefix: *const In6Addr, prefixlen: u8, address: *const In6Addr) -> bool, rs_in6_addr_prefix_covers);
ffi_forward!("rs_in_addr_prefix_covers", ffi_in_addr_prefix_covers, (family: i32, prefix: *const InAddrUnion, prefixlen: u8, address: *const InAddrUnion) -> i32, rs_in_addr_prefix_covers);
ffi_forward!("rs_in4_addr_prefix_covers_full", ffi_in4_addr_prefix_covers_full, (prefix: *const InAddr, prefixlen: u8, address: *const InAddr, address_prefixlen: u8) -> i32, rs_in4_addr_prefix_covers_full);
ffi_forward!("rs_in6_addr_prefix_covers_full", ffi_in6_addr_prefix_covers_full, (prefix: *const In6Addr, prefixlen: u8, address: *const In6Addr, address_prefixlen: u8) -> i32, rs_in6_addr_prefix_covers_full);
ffi_forward!("rs_in_addr_prefix_covers_full", ffi_in_addr_prefix_covers_full, (family: i32, prefix: *const InAddrUnion, prefixlen: u8, address: *const InAddrUnion, address_prefixlen: u8) -> i32, rs_in_addr_prefix_covers_full);

ffi_forward!("rs_in_addr_parse_prefixlen", ffi_in_addr_parse_prefixlen, (family: i32, p: *const c_char, ret: *mut u8) -> i32, rs_in_addr_parse_prefixlen);
ffi_forward!("rs_PTR_TO_IN4_ADDR", ffi_ptr_to_in4_addr, (p: *const c_void, ret: *mut InAddr) -> (), rs_PTR_TO_IN4_ADDR);
ffi_forward!("rs_IN4_ADDR_TO_PTR", ffi_in4_addr_to_ptr, (a: *const InAddr) -> *mut c_void, rs_IN4_ADDR_TO_PTR);
ffi_forward!(safe "rs_FAMILY_ADDRESS_SIZE", ffi_family_address_size, (family: i32) -> usize, rs_FAMILY_ADDRESS_SIZE);

ffi_forward!("rs_in_addr_from_string", ffi_in_addr_from_string, (family: i32, s: *const c_char, ret: *mut u8) -> i32, rs_in_addr_from_string);
ffi_forward!("rs_in_addr_from_string_auto", ffi_in_addr_from_string_auto, (s: *const c_char, ret_family: *mut i32, ret: *mut u8) -> i32, rs_in_addr_from_string_auto);
ffi_forward!("rs_in_addr_to_string", ffi_in_addr_to_string, (family: i32, u: *const u8, ret: *mut *mut c_char) -> i32, rs_in_addr_to_string);
ffi_forward!("rs_in_addr_prefix_from_string", ffi_in_addr_prefix_from_string, (p: *const c_char, family: i32, ret_prefix: *mut u8, ret_prefixlen: *mut u8) -> i32, rs_in_addr_prefix_from_string);
ffi_forward!("rs_in_addr_prefix_from_string_auto_full", ffi_in_addr_prefix_from_string_auto_full, (p: *const c_char, mode: i32, ret_family: *mut i32, ret_prefix: *mut u8, ret_prefixlen: *mut u8) -> i32, rs_in_addr_prefix_from_string_auto_full);
ffi_forward!("rs_in_addr_prefix_range", ffi_in_addr_prefix_range, (family: i32, input: *const InAddrUnion, prefixlen: u32, ret_start: *mut InAddrUnion, ret_end: *mut InAddrUnion) -> i32, rs_in_addr_prefix_range);
ffi_forward!("rs_in_addr_prefix_to_string", ffi_in_addr_prefix_to_string, (family: i32, u: *const InAddrUnion, prefixlen: u32, buf: *mut c_char, buf_len: usize) -> i32, rs_in_addr_prefix_to_string);
ffi_forward!("rs_in6_addr_compare_func", ffi_in6_addr_compare_func, (a: *const In6Addr, b: *const In6Addr) -> i32, rs_in6_addr_compare_func);
ffi_forward!("rs_in_addr_data_compare_func", ffi_in_addr_data_compare_func, (x: *const InAddrData, y: *const InAddrData) -> i32, rs_in_addr_data_compare_func);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in4_link_local_dynamic_positive_and_negative() {
        let dyn_addr = InAddr {
            s_addr: u32::to_be(0xA9FE0102),
        }; // 169.254.1.2
        let non_dyn_addr = InAddr {
            s_addr: u32::to_be(0xA9FE0001),
        }; // 169.254.0.1

        assert!(rs_in4_addr_is_link_local_dynamic(&dyn_addr));
        assert!(!rs_in4_addr_is_link_local_dynamic(&non_dyn_addr));
    }

    #[test]
    fn in4_null_detection() {
        let addr = InAddr { s_addr: 0 };
        assert!(rs_in4_addr_is_null(&addr));
    }

    #[test]
    fn in6_null_detection() {
        let addr = In6Addr { s6_addr: [0; 16] };
        assert!(rs_in6_addr_is_null(&addr));
    }

    #[test]
    fn in4_multicast_detection() {
        let addr = InAddr {
            s_addr: u32::to_be(0xE0000001),
        };
        assert!(rs_in4_addr_is_multicast(&addr));
    }

    #[test]
    fn in4_localhost_detection() {
        let addr = InAddr {
            s_addr: u32::to_be(0x7F000001),
        };
        assert!(rs_in4_addr_is_localhost(&addr));
    }

    #[test]
    fn in6_ipv4_mapped_detection() {
        let addr = In6Addr {
            s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1],
        };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_in6_addr_is_ipv4_mapped_address(&addr) });
    }

    #[test]
    fn parse_ipv4_string() {
        let s = std::ffi::CString::new("192.168.1.1").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe { rs_in_addr_from_string(AF_INET, s.as_ptr(), out.as_mut_ptr()) },
            0
        );
        assert_eq!(&out[..4], &[192, 168, 1, 1]);
    }

    #[test]
    fn parse_ipv6_string_auto() {
        let s = std::ffi::CString::new("::1").unwrap();
        let mut family = 0;
        let mut out = [0u8; 16];
        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe { rs_in_addr_from_string_auto(s.as_ptr(), &mut family, out.as_mut_ptr()) },
            0
        );
        assert_eq!(family, AF_INET6);
    }

    #[test]
    fn format_ipv4_string() {
        let data = [127u8, 0, 0, 1];
        let mut out = std::ptr::null_mut();
        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe { rs_in_addr_to_string(AF_INET, data.as_ptr(), &mut out) },
            0
        );
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        let rendered = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free(out as *mut c_void) };
        assert_eq!(rendered, "127.0.0.1");
    }

    #[test]
    fn prefix_to_string_ipv4() {
        let addr = InAddrUnion {
            in4: InAddr {
                s_addr: u32::to_be(0xC0A80101),
            },
        };
        let mut buf = [0 as c_char; 32];
        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe { rs_in_addr_prefix_to_string(AF_INET, &addr, 24, buf.as_mut_ptr(), buf.len()) },
            0
        );
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        let rendered = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(rendered, "192.168.1.1/24");
    }

    #[test]
    fn in4_prefix_intersect_positive_and_negative() {
        let a = InAddr {
            s_addr: u32::to_be(0x0A000001),
        }; // 10.0.0.1
        let b = InAddr {
            s_addr: u32::to_be(0x0A0000FF),
        }; // 10.0.0.255
        let c = InAddr {
            s_addr: u32::to_be(0x0B000001),
        }; // 11.0.0.1

        // SAFETY: Unsafe operation - invariants have been checked by caller
        // SAFETY: Unsafe operation - invariants have been checked by caller
        // SAFETY: Unsafe operation - invariants have been checked by caller
        // SAFETY: Unsafe operation - invariants have been checked by caller
        assert!(unsafe { rs_in4_addr_prefix_intersect(&a, 24, &b, 24) });
        // SAFETY: Unsafe operation - invariants have been checked by caller
        // SAFETY: Unsafe operation - invariants have been checked by caller
        // SAFETY: Unsafe operation - invariants have been checked by caller
        // SAFETY: Unsafe operation - invariants have been checked by caller
        assert!(!unsafe { rs_in4_addr_prefix_intersect(&a, 24, &c, 24) });
    }
}
