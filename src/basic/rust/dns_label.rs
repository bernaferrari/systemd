// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.dns-label; authority=src/shared/dns-domain.c,src/shared/dns-domain.h,src/basic/parse-util.c,src/basic/parse-util.h
//
// DNS label parsing and DNS name utility functions.
// These are pure functions with no I/O or global state.

use libc::{c_char, c_void};

use crate::ffi::Errno;
use std::ptr;

const DNS_LABEL_MAX: usize = 63;
const DNS_N_LABELS_MAX: usize = 127;

// DNS label flags
const DNS_LABEL_LDH: u32 = 1 << 0;
const DNS_LABEL_NO_ESCAPES: u32 = 1 << 1;
const DNS_LABEL_LEAVE_TRAILING_DOT: u32 = 1 << 2;

// ── dns_label_unescape ──────────────────────────────────────────────────

/// Shadow of C dns_label_unescape()
/// Parses one DNS label from *name, writes unescaped form to dest.
/// Advances *name past the label and separator dot.
/// Returns number of characters in label, 0 if no more labels, or negative errno.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_label_unescape(
    name: *mut *const c_char,
    dest: *mut c_char,
    mut sz: usize,
    flags: u32,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut n = *name;

        // `isempty(*name)` in the C implementation also accepts a null string.
        if n.is_null() || *n == 0 {
            if !dest.is_null() && sz >= 1 {
                *dest = 0;
            }
            return 0;
        }

        let mut d = dest;
        let mut r: i32 = 0;
        let mut last_char: c_char = 0;
        let flags = flags as u32;

        loop {
            let c = *n;

            if c == 0 || c == b'.' as c_char {
                // Trailing dash check for LDH mode
                if (flags & DNS_LABEL_LDH) != 0 && last_char == b'-' as c_char {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL
                }

                // Skip the dot separator (unless leaving trailing dot)
                if c == b'.' as c_char {
                    let next = *n.add(1);
                    if next != 0 || (flags & DNS_LABEL_LEAVE_TRAILING_DOT) == 0 {
                        n = n.add(1);
                    }
                }
                break;
            }

            if r as usize >= DNS_LABEL_MAX {
                return Errno::EINVAL.to_neg_errno(); // -EINVAL
            }

            if sz == 0 {
                return Errno::ENOBUFS.to_neg_errno(); // -ENOBUFS
            }

            if c == b'\\' as c_char {
                // Escaped character
                if (flags & DNS_LABEL_NO_ESCAPES) != 0 {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL
                }

                n = n.add(1);
                let ec = *n;

                if ec == 0 {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL (backslash at end)
                } else if ec == b'\\' as c_char || ec == b'.' as c_char {
                    // Escaped backslash or dot
                    if (flags & DNS_LABEL_LDH) != 0 {
                        return Errno::EINVAL.to_neg_errno(); // -EINVAL
                    }

                    last_char = ec;
                    if !d.is_null() {
                        *d = ec;
                        d = d.add(1);
                    }
                    sz -= 1;
                    r += 1;
                    n = n.add(1);
                } else {
                    let eb = ec as u8;
                    if eb >= b'0' && eb <= b'9' {
                        // \DDD decimal escape
                        let b1 = *n.add(1) as u8;
                        if !b1.is_ascii_digit() {
                            return Errno::EINVAL.to_neg_errno();
                        }
                        let b2 = *n.add(2) as u8;
                        if !b2.is_ascii_digit() {
                            return Errno::EINVAL.to_neg_errno(); // -EINVAL
                        }

                        let k = ((eb - b'0') as u32 * 100)
                            + ((b1 - b'0') as u32 * 10)
                            + ((b2 - b'0') as u32);

                        if k > 255 {
                            return Errno::EINVAL.to_neg_errno(); // -EINVAL
                        }

                        if (flags & DNS_LABEL_LDH) != 0
                            && !crate::hostname_util::rs_valid_ldh_char(k as c_char)
                        {
                            return Errno::EINVAL.to_neg_errno(); // -EINVAL
                        }

                        last_char = k as c_char;
                        if !d.is_null() {
                            *d = k as c_char;
                            d = d.add(1);
                        }
                        sz -= 1;
                        r += 1;
                        n = n.add(3);
                    } else {
                        return Errno::EINVAL.to_neg_errno(); // -EINVAL
                    }
                }
            } else {
                let cu = c as u8;
                if cu >= 0x20 && cu != 0x7F {
                    // Normal character
                    if (flags & DNS_LABEL_LDH) != 0 {
                        if !crate::hostname_util::rs_valid_ldh_char(c) {
                            return Errno::EINVAL.to_neg_errno(); // -EINVAL
                        }
                        if r == 0 && c == b'-' as c_char {
                            return Errno::EINVAL.to_neg_errno(); // -EINVAL (leading dash)
                        }
                    }

                    last_char = c;
                    if !d.is_null() {
                        *d = c;
                        d = d.add(1);
                    }
                    sz -= 1;
                    r += 1;
                    n = n.add(1);
                } else {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL (control character)
                }
            }
        }

        // Empty label that is not at the end?
        if r == 0 && *n != 0 {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }

        // More than one trailing dot?
        if *n == b'.' as c_char && (flags & DNS_LABEL_LEAVE_TRAILING_DOT) == 0 {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }

        if sz >= 1 && !d.is_null() {
            *d = 0;
        }

        *name = n;
        r
    }
}

// ── dns_name_skip ────────────────────────────────────────────────────

/// Shadow of C dns_name_skip()
/// Skips n_labels labels from *a, returns remaining pointer via ret.
/// Returns 1 if labels skipped, 0 if exhausted before n_labels, negative on error.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_skip(
    a: *const c_char,
    n_labels: u32,
    ret: *mut *const c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut p = a;
        let mut remaining = n_labels;

        while remaining > 0 {
            let r = rs_dns_name_parent(&mut p);
            if r < 0 {
                return r;
            }
            if r == 0 {
                *ret = c"".as_ptr();
                return 0;
            }
            remaining -= 1;
        }

        *ret = p;
        1
    }
}

// ── dns_name_suffix ──────────────────────────────────────────────────

/// Shadow of C dns_name_suffix()
/// Returns a pointer to the suffix of name consisting of n_labels labels.
/// Returns remaining label count or negative errno.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_suffix(
    name: *const c_char,
    n_labels: u32,
    ret: *mut *const c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut table: [*const c_char; DNS_N_LABELS_MAX + 1] =
            [std::ptr::null(); DNS_N_LABELS_MAX + 1];
        let mut p = name;
        let mut n: usize = 0;

        loop {
            if n > DNS_N_LABELS_MAX {
                return Errno::EINVAL.to_neg_errno(); // -EINVAL
            }

            table[n] = p;
            let r = rs_dns_name_parent(&mut p);
            if r < 0 {
                return r;
            }
            if r == 0 {
                break;
            }

            n += 1;
        }

        let n = n as i32;
        if n_labels as i32 > n {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }

        *ret = table[n as usize - n_labels as usize];
        n - n_labels as i32
    }
}

// ── dns_name_equal_skip ─────────────────────────────────────────────

/// Shadow of C dns_name_equal_skip()
/// Skip n_labels from a, then compare the remainder with b.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_equal_skip(
    a: *const c_char,
    n_labels: u32,
    b: *const c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || b.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut p = a;
        let r = rs_dns_name_skip(p, n_labels, &mut p);
        if r <= 0 {
            return r;
        }

        rs_dns_name_equal(p, b)
    }
}

// ── dns_name_common_suffix ──────────────────────────────────────────

/// Shadow of C dns_name_common_suffix()
/// Determines the common suffix of domain names a and b.
/// Returns 0 and sets *ret to the common suffix.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_common_suffix(
    a: *const c_char,
    b: *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || b.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut a_labels: [*const c_char; DNS_N_LABELS_MAX + 1] =
            [std::ptr::null(); DNS_N_LABELS_MAX + 1];
        let mut b_labels: [*const c_char; DNS_N_LABELS_MAX + 1] =
            [std::ptr::null(); DNS_N_LABELS_MAX + 1];

        // Build suffix table for a
        let mut p = a;
        let mut n: i32 = 0;
        loop {
            if n as usize > DNS_N_LABELS_MAX {
                return Errno::EINVAL.to_neg_errno();
            }
            a_labels[n as usize] = p;
            let r = rs_dns_name_parent(&mut p);
            if r < 0 {
                return r;
            }
            if r == 0 {
                break;
            }
            n += 1;
        }

        // Build suffix table for b
        p = b;
        let mut m: i32 = 0;
        loop {
            if m as usize > DNS_N_LABELS_MAX {
                return Errno::EINVAL.to_neg_errno();
            }
            b_labels[m as usize] = p;
            let r = rs_dns_name_parent(&mut p);
            if r < 0 {
                return r;
            }
            if r == 0 {
                break;
            }
            m += 1;
        }

        let mut k: i32 = 0;
        loop {
            if k >= n || k >= m {
                *ret = a_labels[(n - k) as usize];
                return 0;
            }

            let mut la: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
            let mut lb: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

            let mut x = a_labels[(n - 1 - k) as usize];
            let r = rs_dns_label_unescape(&mut x, la.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if r < 0 {
                return r;
            }

            let mut y = b_labels[(m - 1 - k) as usize];
            let q = rs_dns_label_unescape(&mut y, lb.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if q < 0 {
                return q;
            }

            if r != q
                || crate::string_util::rs_ascii_strcasecmp_n(la.as_ptr(), lb.as_ptr(), r as usize)
                    != 0
            {
                *ret = a_labels[(n - k) as usize];
                return 0;
            }

            k += 1;
        }
    }
}

// ── dns_name_to_wire_format ─────────────────────────────────────────

const DNS_HOSTNAME_MAX: usize = 253;

/// Shadow of C dns_name_to_wire_format()
/// Encodes a domain name according to RFC 1035 Section 3.1, without compression.
/// Returns number of bytes written, or negative errno.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_to_wire_format(
    domain: *const c_char,
    buffer: *mut u8,
    mut len: usize,
    canonical: bool,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if domain.is_null() || buffer.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut d = domain;
        let mut out = buffer;
        let start = buffer;

        loop {
            // Reserve a byte for label length
            if len == 0 {
                return Errno::ENOBUFS.to_neg_errno(); // -ENOBUFS
            }
            len -= 1;
            let label_length = out;
            out = out.add(1);

            // dns_label_unescape returns 0 at end of domain name
            let r = rs_dns_label_unescape(&mut d, out as *mut c_char, len, 0);
            if r < 0 {
                return r;
            }

            // Optionally output in DNSSEC canonical format (lowercase)
            if canonical {
                for i in 0..r as usize {
                    let c = *out.add(i) as u8;
                    if c >= b'A' && c <= b'Z' {
                        *out.add(i) = c.wrapping_add(32); // to lowercase
                    }
                }
            }

            // Fill label length, move forward
            *label_length = r as u8;
            out = out.add(r as usize);
            len -= r as usize;

            if r == 0 {
                break;
            }
        }

        // Verify maximum size: DNS_HOSTNAME_MAX + 2 = 255
        let written = (out as isize - start as isize) as usize;
        if written > DNS_HOSTNAME_MAX + 2 {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }

        written as i32
    }
}

// ── dns_label_escape ────────────────────────────────────────────────────

/// Shadow of C dns_label_escape()
/// Escapes a DNS label, writing to dest. Returns bytes written or negative errno.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_label_escape(
    p: *const c_char,
    l: usize,
    dest: *mut c_char,
    sz: usize,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if l == 0 || l > DNS_LABEL_MAX {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }
        if sz < 1 {
            return Errno::ENOBUFS.to_neg_errno(); // -ENOBUFS
        }
        if p.is_null() || dest.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut q = dest;
        let mut src = p;
        let mut remaining = l;
        let mut space = sz;

        while remaining > 0 {
            let c = *src as u8;

            if c == b'.' || c == b'\\' {
                if space < 3 {
                    return Errno::ENOBUFS.to_neg_errno(); // -ENOBUFS
                }
                *q = b'\\' as c_char;
                q = q.add(1);
                *q = c as c_char;
                q = q.add(1);
                space -= 2;
            } else if c == b'_' || c == b'-' || c.is_ascii_digit() || c.is_ascii_alphabetic() {
                if space < 2 {
                    return Errno::ENOBUFS.to_neg_errno(); // -ENOBUFS
                }
                *q = c as c_char;
                q = q.add(1);
                space -= 1;
            } else {
                if space < 5 {
                    return Errno::ENOBUFS.to_neg_errno(); // -ENOBUFS
                }
                *q = b'\\' as c_char;
                q = q.add(1);
                *q = b'0' as c_char + (c / 100) as c_char;
                q = q.add(1);
                *q = b'0' as c_char + ((c / 10) % 10) as c_char;
                q = q.add(1);
                *q = b'0' as c_char + (c % 10) as c_char;
                q = q.add(1);
                space -= 4;
            }

            src = src.add(1);
            remaining -= 1;
        }

        *q = 0;
        (q as isize - dest as isize) as i32
    }
}

// ── dns_name_parent ─────────────────────────────────────────────────────

/// Shadow of C dns_name_parent()
/// Advances *name past one label. Returns label length, 0 if root, or negative errno.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_parent(name: *mut *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_dns_label_unescape(name, std::ptr::null_mut(), DNS_LABEL_MAX, 0) }
}

// ── dns_name_is_root ────────────────────────────────────────────────────

/// Shadow of C dns_name_is_root()
/// Returns true if name is "" or "." (root domain).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_is_root(name: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() {
            return false;
        }
        let c0 = *name;
        if c0 == 0 {
            return true;
        }
        if c0 == b'.' as c_char && *name.add(1) == 0 {
            return true;
        }
        false
    }
}

// ── dns_name_equal ──────────────────────────────────────────────────────

/// Shadow of C dns_name_equal()
/// Case-insensitive DNS name equality check.
/// Returns 1 if equal, 0 if not, negative on error.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_equal(x: *const c_char, y: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if x.is_null() || y.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut px = x;
        let mut py = y;

        loop {
            let mut la: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
            let mut lb: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

            let r = rs_dns_label_unescape(&mut px, la.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if r < 0 {
                return r;
            }

            let q = rs_dns_label_unescape(&mut py, lb.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if q < 0 {
                return q;
            }

            if r == 0 && q == 0 {
                return 1; // both exhausted
            }

            if r != q {
                return 0;
            }

            let cmp =
                crate::string_util::rs_ascii_strcasecmp_n(la.as_ptr(), lb.as_ptr(), r as usize);
            if cmp != 0 {
                return 0;
            }
        }
    }
}

// ── dns_name_endswith ───────────────────────────────────────────────────

/// Shadow of C dns_name_endswith()
/// Checks if name ends with suffix (case-insensitive).
/// Returns 1 if true, 0 if false, negative on error.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_endswith(name: *const c_char, suffix: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() || suffix.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut n = name;
        let mut s = suffix;
        let mut saved_n: *const c_char = std::ptr::null();

        loop {
            let mut ln: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
            let mut ls: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

            let r = rs_dns_label_unescape(&mut n, ln.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if r < 0 {
                return r;
            }

            if saved_n.is_null() {
                saved_n = n;
            }

            let q = rs_dns_label_unescape(&mut s, ls.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if q < 0 {
                return q;
            }

            if r == 0 && q == 0 {
                return 1;
            }
            if r == 0 && saved_n == n {
                return 0;
            }

            if r != q
                || crate::string_util::rs_ascii_strcasecmp_n(ln.as_ptr(), ls.as_ptr(), r as usize)
                    != 0
            {
                // Not the same, jump back and try with the next label again
                s = suffix;
                n = saved_n;
                saved_n = std::ptr::null();
            }
        }
    }
}

// ── dns_name_startswith ─────────────────────────────────────────────────

/// Shadow of C dns_name_startswith()
/// Checks if name starts with prefix (case-insensitive).
/// Returns 1 if true, 0 if false, negative on error.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_startswith(name: *const c_char, prefix: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() || prefix.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut n = name;
        let mut p = prefix;

        loop {
            let mut ln: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
            let mut lp: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

            let r = rs_dns_label_unescape(&mut p, lp.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if r < 0 {
                return r;
            }
            if r == 0 {
                return 1; // prefix exhausted → match
            }

            let q = rs_dns_label_unescape(&mut n, ln.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if q < 0 {
                return q;
            }

            if r != q {
                return 0;
            }

            let cmp =
                crate::string_util::rs_ascii_strcasecmp_n(ln.as_ptr(), lp.as_ptr(), r as usize);
            if cmp != 0 {
                return 0;
            }
        }
    }
}

// ── dns_name_count_labels ───────────────────────────────────────────────

/// Shadow of C dns_name_count_labels()
/// Counts the number of labels in a DNS name.
/// Returns label count or negative errno.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_count_labels(name: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut n = name;
        let mut count: u32 = 0;

        loop {
            let r = rs_dns_name_parent(&mut n);
            if r < 0 {
                return r;
            }
            if r == 0 {
                break;
            }
            if count as usize >= DNS_N_LABELS_MAX {
                return Errno::EINVAL.to_neg_errno(); // -EINVAL
            }
            count += 1;
        }

        count as i32
    }
}

// ── dns_srv_type_is_valid ───────────────────────────────────────────────

/// Helper: validates a single service type label.
/// RFC 6335 Section 5.1: first char '_', second char letter, rest alphanumeric or hyphen.
///
/// # Safety
/// `label` must reference at least `n` readable bytes for the duration of the
/// call.
unsafe fn srv_type_label_is_valid(label: *const c_char, n: usize) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if n < 2 {
            return false;
        }
        if *label != b'_' as c_char {
            return false;
        }
        let second = *label.add(1) as u8;
        if !second.is_ascii_alphabetic() {
            return false;
        }
        for i in 2..n {
            let c = *label.add(i) as u8;
            if !c.is_ascii_alphabetic() && !c.is_ascii_digit() && c != b'-' {
                return false;
            }
        }
        true
    }
}

/// Shadow of C dns_srv_type_is_valid()
/// Validates DNS SRV type name (e.g. "_http._tcp").
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_dns_srv_type_is_valid(name: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() {
            return false;
        }

        let mut n = name;
        let mut c: u32 = 0;

        loop {
            let mut label: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

            let r = rs_dns_label_unescape(&mut n, label.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if r < 0 {
                return false;
            }
            if r == 0 {
                break;
            }

            if c >= 2 {
                return false;
            }

            if !srv_type_label_is_valid(label.as_ptr(), r as usize) {
                return false;
            }

            c += 1;
        }

        c == 2
    }
}

/// Shadow of C dnssd_srv_type_is_valid()
/// Like dns_srv_type_is_valid but requires _tcp or _udp suffix.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_dnssd_srv_type_is_valid(name: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if !rs_dns_srv_type_is_valid(name) {
            return false;
        }

        let n = name;
        rs_dns_name_endswith(n, c"_tcp".as_ptr()) > 0
            || rs_dns_name_endswith(n, c"_udp".as_ptr()) > 0
    }
}

// ── dns_name_is_single_label ────────────────────────────────────────────

/// Shadow of C dns_name_is_single_label()
/// Returns true if name consists of exactly one label (e.g. "www" but not "www.example").
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_is_single_label(name: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() {
            return false;
        }

        let mut n = name;
        let r = rs_dns_name_parent(&mut n);
        if r <= 0 {
            return false;
        }

        rs_dns_name_is_root(n)
    }
}

/// Shadow of C dns_name_dont_resolve()
/// Never respond to some of the domains listed in RFC6303, RFC6761, RFC9476.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_dont_resolve(name: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if rs_dns_name_endswith(name, c"0.in-addr.arpa".as_ptr()) > 0 {
            return true;
        }
        if rs_dns_name_equal(name, c"255.255.255.255.in-addr.arpa".as_ptr()) > 0 {
            return true;
        }
        if rs_dns_name_equal(
            name,
            c"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa".as_ptr(),
        ) > 0
        {
            return true;
        }
        if rs_dns_name_endswith(name, c"invalid".as_ptr()) > 0 {
            return true;
        }
        if rs_dns_name_endswith(name, c"alt".as_ptr()) > 0 {
            return true;
        }
        false
    }
}

/// Shadow of C dns_name_dot_suffixed()
/// Returns >0 if name ends with a dot, 0 if not, negative on error.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_dot_suffixed(name: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }
        let mut p = name;
        loop {
            if *p == b'.' as c_char && *(p.add(1)) == 0 {
                return 1;
            }
            let r = rs_dns_label_unescape(
                &mut p,
                std::ptr::null_mut(),
                DNS_LABEL_MAX,
                DNS_LABEL_LEAVE_TRAILING_DOT,
            );
            if r < 0 {
                return r;
            }
            if r == 0 {
                return 0;
            }
        }
    }
}

// ── dns_name_reverse ──────────────────────────────────────────────────

use crate::ffi::{free, malloc, strlen};

fn rs_hexchar(x: i32) -> c_char {
    match x {
        0..=9 => (b'0' + x as u8) as c_char,
        10..=15 => (b'a' + (x as u8 - 10)) as c_char,
        _ => 0,
    }
}

fn rs_unhexchar(c: c_char) -> i32 {
    match c as u8 {
        b'0'..=b'9' => (c as u8 - b'0') as i32,
        b'a'..=b'f' => (c as u8 - b'a' + 10) as i32,
        b'A'..=b'F' => (c as u8 - b'A' + 10) as i32,
        _ => -1,
    }
}

/// Compare two C strings as unsigned bytes.
///
/// # Safety
/// `s1` and `s2` must each reference a live NUL-terminated string.
unsafe fn strcmp(s1: *const c_char, s2: *const c_char) -> i32 {
    let mut i = 0usize;
    loop {
        // SAFETY: the caller supplies readable NUL-terminated strings; this
        // loop advances both pointers in lockstep until either terminator.
        let (a, b) = unsafe { (*s1.add(i) as u8, *s2.add(i) as u8) };
        if a != b || a == 0 || b == 0 {
            return (a as i32) - (b as i32);
        }
        i += 1;
    }
}

/// Helper: allocate a NUL-terminated C string from a Rust string.
fn alloc_c_string(s: &str) -> *mut c_char {
    let bytes = s.as_bytes();
    let ptr = malloc(bytes.len() + 1) as *mut c_char;
    if ptr.is_null() {
        return ptr;
    }
    // SAFETY: `ptr` owns `bytes.len() + 1` writable C-allocation bytes and
    // `bytes` is a valid source slice of exactly `bytes.len()` bytes.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), ptr, bytes.len());
        *ptr.add(bytes.len()) = 0;
    }
    ptr
}

/// Shadow of C dns_name_reverse()
/// Converts an IP address to its reverse DNS name.
/// For IPv4: a.b.c.d → d.c.b.a.in-addr.arpa
/// For IPv6: nibble-reversed hex.ip6.arpa
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_reverse(
    family: i32,
    a: *const c_void,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let p = a.cast::<u8>();

        if family == 2 {
            // AF_INET
            let b0 = *p;
            let b1 = *p.add(1);
            let b2 = *p.add(2);
            let b3 = *p.add(3);
            let s = std::fmt::format(format_args!("{}.{}.{}.{}.in-addr.arpa", b3, b2, b1, b0));
            let ptr = alloc_c_string(&s);
            if ptr.is_null() {
                return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
            }
            *ret = ptr;
            0
        } else if family == 10 {
            // AF_INET6
            let mut s = String::with_capacity(128);
            for i in (0..16).rev() {
                let byte = *p.add(i);
                let lo = rs_hexchar((byte & 0x0F) as i32) as u8;
                let hi = rs_hexchar((byte >> 4) as i32) as u8;
                if !s.is_empty() {
                    s.push('.');
                }
                s.push(lo as char);
                s.push('.');
                s.push(hi as char);
            }
            s.push_str(".ip6.arpa");
            let ptr = alloc_c_string(&s);
            if ptr.is_null() {
                return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
            }
            *ret = ptr;
            0
        } else {
            Errno::EAFNOSUPPORT.to_neg_errno() // -EAFNOSUPPORT
        }
    }
}

// ── dns_name_address ──────────────────────────────────────────────────

/// Shadow of C dns_name_address()
/// Parses a reverse DNS name back into an IP address.
/// Returns 1 if address found, 0 if not a reverse name, negative on error.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_address(
    p: *const c_char,
    ret_family: *mut i32,
    ret: *mut c_void,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() || ret_family.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let ret = ret.cast::<u8>();
        let mut name = p;

        // Check in-addr.arpa suffix
        let r = rs_dns_name_endswith(name, c"in-addr.arpa".as_ptr());
        if r < 0 {
            return r;
        }
        if r > 0 {
            let mut octets: [u8; 4] = [0; 4];
            for octet in &mut octets {
                let mut label: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
                let lr = rs_dns_label_unescape(&mut name, label.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
                if lr < 0 {
                    return lr;
                }
                if lr == 0 {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL
                }
                if lr > 3 {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL
                }
                let mut value = 0;
                let parsed = crate::parse_util::rs_safe_atou8(label.as_ptr(), &mut value);
                if parsed < 0 {
                    return parsed;
                }
                *octet = value;
            }

            // Verify remaining name equals "in-addr.arpa"
            let eq = rs_dns_name_equal(name, c"in-addr.arpa".as_ptr());
            if eq <= 0 {
                return eq;
            }

            *ret_family = 2; // AF_INET
            // Write as big-endian: octets[3].octets[2].octets[1].octets[0]
            *ret = octets[3];
            *ret.add(1) = octets[2];
            *ret.add(2) = octets[1];
            *ret.add(3) = octets[0];
            return 1;
        }

        // Check ip6.arpa suffix
        let r = rs_dns_name_endswith(name, c"ip6.arpa".as_ptr());
        if r < 0 {
            return r;
        }
        if r > 0 {
            let mut addr: [u8; 16] = [0; 16];
            for i in 0..16 {
                let mut label: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

                let lr = rs_dns_label_unescape(&mut name, label.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
                if lr <= 0 {
                    return lr;
                }
                if lr != 1 {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL
                }
                let x = rs_unhexchar(label[0]);
                if x < 0 {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL
                }

                let lr2 =
                    rs_dns_label_unescape(&mut name, label.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
                if lr2 <= 0 {
                    return lr2;
                }
                if lr2 != 1 {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL
                }
                let y = rs_unhexchar(label[0]);
                if y < 0 {
                    return Errno::EINVAL.to_neg_errno(); // -EINVAL
                }

                addr[15 - i] = ((y as u8) << 4) | (x as u8);
            }

            let eq = rs_dns_name_equal(name, c"ip6.arpa".as_ptr());
            if eq <= 0 {
                return eq;
            }

            *ret_family = 10; // AF_INET6
            ptr::copy_nonoverlapping(addr.as_ptr(), ret, 16);
            return 1;
        }

        // Not a reverse name
        *ret_family = 0; // AF_UNSPEC
        for i in 0..16 {
            *ret.add(i) = 0;
        }
        0
    }
}

// ── dns_name_from_wire_format ─────────────────────────────────────────

const DNS_LABEL_ESCAPED_MAX: usize = DNS_LABEL_MAX * 4 + 1;

/// Shadow of C dns_name_from_wire_format()
/// Decodes a DNS name from wire format (RFC 1035 § 3.1) into dotted string.
/// Accepts partial names (no terminating zero-length label) per RFC 4704.
/// Returns length of decoded name, or negative errno.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_from_wire_format(
    data: *mut *const u8,
    len: *mut usize,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if data.is_null() || len.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut optval = *data;
        let mut optlen = *len;
        let original_len = *len;
        let mut domain: Vec<c_char> = Vec::new();
        let mut n: usize = 0;

        loop {
            // RFC 4704: partial names may omit the terminating zero-length label
            if optlen == 0 {
                break;
            }

            // RFC 1035: total length limited to 255 octets
            if original_len - optlen > 255 {
                return Errno::EMSGSIZE.to_neg_errno(); // -EMSGSIZE
            }

            let c = *optval;
            optval = optval.add(1);
            optlen -= 1;

            if c == 0 {
                // End label
                break;
            }
            if c > DNS_LABEL_MAX as u8 {
                return Errno::EBADMSG.to_neg_errno();
            }
            if c as usize > optlen {
                return Errno::EMSGSIZE.to_neg_errno(); // -EMSGSIZE
            }

            // Literal label — escape it
            let label_ptr = optval as *const c_char;
            optval = optval.add(c as usize);
            optlen -= c as usize;

            // Grow domain buffer
            let needed = n + (if n != 0 { 1 } else { 0 }) + DNS_LABEL_ESCAPED_MAX;
            if domain.len() < needed {
                domain.resize(needed, 0);
            }

            if n != 0 {
                domain[n] = b'.' as c_char;
                n += 1;
            }

            let escaped = rs_dns_label_escape(
                label_ptr,
                c as usize,
                domain.as_mut_ptr().add(n),
                DNS_LABEL_ESCAPED_MAX,
            );
            if escaped < 0 {
                return escaped;
            }
            n += escaped as usize;
        }

        // NUL-terminate
        if domain.len() <= n {
            domain.resize(n + 1, 0);
        }
        domain[n] = 0;

        let ptr = malloc(n + 1) as *mut c_char;
        if ptr.is_null() {
            return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
        }
        ptr::copy_nonoverlapping(domain.as_ptr(), ptr, n + 1);
        *ret = ptr;
        *data = optval;
        *len = optlen;
        n as i32
    }
}

// ── dns_label_unescape_suffix ────────────────────────────────────────

/// Helper: like PTR_SUB1(p, base) — returns p-1 if p > base, else NULL.
///
/// # Safety
/// Non-null pointers must belong to the same live allocation, with `p` at or
/// after `base`.
unsafe fn ptr_sub1(p: *const c_char, base: *const c_char) -> *const c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if !p.is_null() && p > base {
            p.sub(1)
        } else {
            ptr::null()
        }
    }
}

/// Shadow of C dns_label_unescape_suffix()
/// Unescapes labels from right to left (suffix-first order).
/// *label_terminal tracks position; initially set to past-end of name.
/// Returns label length, 0 if done, negative on error.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_label_unescape_suffix(
    mut name: *const c_char,
    label_terminal: *mut *const c_char,
    dest: *mut c_char,
    sz: usize,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() || label_terminal.is_null() || dest.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        // No more labels
        if (*label_terminal).is_null() {
            if sz >= 1 {
                *dest = 0;
            }
            return 0;
        }

        let mut terminal = *label_terminal;
        if *terminal != 0 && *terminal != b'.' as c_char {
            return Errno::EINVAL.to_neg_errno();
        }

        // Skip current terminal character (and accept domain names ending with ".")
        if *terminal == 0 {
            terminal = ptr_sub1(terminal, name);
        }
        if !terminal.is_null() && terminal >= name && *terminal == b'.' as c_char {
            terminal = ptr_sub1(terminal, name);
        }

        // Find the start of the last label, and set terminal to the preceding separator
        while !terminal.is_null() {
            if *terminal == b'.' as c_char {
                let mut y = ptr_sub1(terminal, name);
                let mut slashes: u32 = 0;

                while !y.is_null() && *y == b'\\' as c_char {
                    slashes += 1;
                    y = ptr_sub1(y, name);
                }

                if slashes.is_multiple_of(2) {
                    // The '.' was not escaped
                    name = terminal.add(1);
                    break;
                } else {
                    terminal = y;
                    continue;
                }
            }

            terminal = ptr_sub1(terminal, name);
        }

        let r = rs_dns_label_unescape(&mut name, dest, sz, 0);
        if r < 0 {
            return r;
        }

        *label_terminal = terminal;
        r
    }
}

// ── dns_name_compare_func ────────────────────────────────────────────

/// Shadow of C dns_name_compare_func()
/// Compares DNS names in canonical (right-to-left) order.
/// Returns negative if a < b, 0 if equal, positive if a > b.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_compare_func(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || b.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut x = a.add(strlen(a));
        let mut y = b.add(strlen(b));

        loop {
            let mut la: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
            let mut lb: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

            if x.is_null() && y.is_null() {
                return 0;
            }

            let r = rs_dns_label_unescape_suffix(a, &mut x, la.as_mut_ptr(), DNS_LABEL_MAX + 1);
            let q = rs_dns_label_unescape_suffix(b, &mut y, lb.as_mut_ptr(), DNS_LABEL_MAX + 1);

            if r < 0 || q < 0 {
                // If not valid DNS labels, compare as raw strings
                return strcmp(a, b);
            }

            let cmp = crate::string_util::rs_ascii_strcasecmp_nn(
                la.as_ptr(),
                r as usize,
                lb.as_ptr(),
                q as usize,
            );
            if cmp != 0 {
                return cmp;
            }
        }
    }
}

// ── dns_name_between ─────────────────────────────────────────────────

/// Shadow of C dns_name_between()
/// Returns true if b is strictly between a and c in circular DNS name order.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_between(
    a: *const c_char,
    b: *const c_char,
    c: *const c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if a.is_null() || b.is_null() || c.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        if rs_dns_name_compare_func(a, c) < 0 {
            // a and c are properly ordered: a <---b--->c
            return if rs_dns_name_compare_func(a, b) < 0 && rs_dns_name_compare_func(b, c) < 0 {
                1
            } else {
                0
            };
        } else {
            // a and c are equal or 'reversed': <--b--c a-----> or <----c a--b-->
            return if rs_dns_name_compare_func(b, c) < 0 || rs_dns_name_compare_func(a, b) < 0 {
                1
            } else {
                0
            };
        }
    }
}

// ── dns_label_escape_new ─────────────────────────────────────────────

/// Shadow of C dns_label_escape_new()
/// Allocates and escapes a DNS label into a new string.
/// Returns label length or negative errno.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_label_escape_new(
    p: *const c_char,
    l: usize,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        if l == 0 || l > DNS_LABEL_MAX {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }

        let buf = malloc(DNS_LABEL_ESCAPED_MAX) as *mut c_char;
        if buf.is_null() {
            return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
        }

        let r = rs_dns_label_escape(p, l, buf, DNS_LABEL_ESCAPED_MAX);
        if r < 0 {
            free(buf.cast());
            return r;
        }

        *ret = buf;
        r
    }
}

// ── dns_name_concat ───────────────────────────────────────────────────

/// Shadow of C dns_name_concat()
/// Concatenates two DNS names, escaping labels.
/// a or b may be NULL. If ret is NULL, only validates.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_concat(
    a: *const c_char,
    b: *const c_char,
    flags: u32,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let mut result: Vec<c_char> = Vec::new();
        let mut n_result: usize = 0;
        let mut n_unescaped: usize = 0;
        let mut first = true;
        let mut p: *const c_char;
        let mut second: *const c_char;

        if !a.is_null() {
            p = a;
            second = b;
        } else if !b.is_null() {
            p = b;
            second = ptr::null();
        } else {
            p = ptr::null();
            second = ptr::null();
        }

        let should_alloc = !ret.is_null();

        if !p.is_null() {
            loop {
                let mut label: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

                let r = rs_dns_label_unescape(&mut p, label.as_mut_ptr(), DNS_LABEL_MAX + 1, flags);
                if r < 0 {
                    return r;
                }
                if r == 0 {
                    if *p != 0 {
                        return Errno::EINVAL.to_neg_errno(); // -EINVAL
                    }
                    if !second.is_null() {
                        p = second;
                        second = ptr::null();
                        continue;
                    }
                    break;
                }

                n_unescaped += r as usize + if first { 0 } else { 1 };

                if should_alloc {
                    let needed = n_result + if first { 0 } else { 1 } + DNS_LABEL_ESCAPED_MAX;
                    if result.len() < needed {
                        result.resize(needed, 0);
                    }

                    if !first {
                        result[n_result] = b'.' as c_char;
                    }

                    let escaped = rs_dns_label_escape(
                        label.as_ptr(),
                        r as usize,
                        result
                            .as_mut_ptr()
                            .add(n_result + if first { 0 } else { 1 }),
                        DNS_LABEL_ESCAPED_MAX,
                    );
                    if escaped < 0 {
                        return escaped;
                    }
                    n_result += escaped as usize + if first { 0 } else { 1 };
                } else {
                    let mut escaped: [c_char; DNS_LABEL_ESCAPED_MAX] = [0; DNS_LABEL_ESCAPED_MAX];
                    let r2 = rs_dns_label_escape(
                        label.as_ptr(),
                        r as usize,
                        escaped.as_mut_ptr(),
                        DNS_LABEL_ESCAPED_MAX,
                    );
                    if r2 < 0 {
                        return r2;
                    }
                }

                first = false;
            }
        }

        // Nothing appended? Generate at least a dot for root domain
        if n_unescaped == 0 {
            if should_alloc {
                if result.len() < 2 {
                    result.resize(2, 0);
                }
                result[n_result] = b'.' as c_char;
                n_result += 1;
            }
            n_unescaped += 1;
        }

        // Enforce max length check on unescaped length
        if n_unescaped > DNS_HOSTNAME_MAX {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }

        if should_alloc {
            if result.len() <= n_result {
                result.resize(n_result + 1, 0);
            }
            result[n_result] = 0;

            let ptr = malloc(n_result + 1) as *mut c_char;
            if ptr.is_null() {
                return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
            }
            ptr::copy_nonoverlapping(result.as_ptr(), ptr, n_result + 1);
            *ret = ptr;
        }

        0
    }
}

// ── dns_name_change_suffix ───────────────────────────────────────────

/// Helper: like strempty() — returns "" for NULL.
/// Uses a static to ensure the pointer is valid for the program lifetime.
fn strempty(s: *const c_char) -> *const c_char {
    if s.is_null() {
        static EMPTY: [c_char; 1] = [0];
        EMPTY.as_ptr()
    } else {
        s
    }
}

/// Shadow of C dns_name_change_suffix()
/// Replaces old_suffix in name with new_suffix.
/// Returns 1 if suffix found and changed, 0 if no match, negative on error.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_change_suffix(
    name: *const c_char,
    old_suffix: *const c_char,
    new_suffix: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if name.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut n = name;
        let mut s = strempty(old_suffix);
        let mut saved_before: *const c_char = ptr::null();
        let mut saved_after: *const c_char = ptr::null();

        loop {
            let mut ln: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
            let mut ls: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

            if saved_before.is_null() {
                saved_before = n;
            }

            let r = rs_dns_label_unescape(&mut n, ln.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if r < 0 {
                return r;
            }

            if saved_after.is_null() {
                saved_after = n;
            }

            let q = rs_dns_label_unescape(&mut s, ls.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if q < 0 {
                return q;
            }

            if r == 0 && q == 0 {
                break;
            }
            if r == 0 && saved_after == n {
                *ret = ptr::null_mut(); // doesn't match
                return 0;
            }

            if r != q
                || crate::string_util::rs_ascii_strcasecmp_n(ln.as_ptr(), ls.as_ptr(), r as usize)
                    != 0
            {
                // Not the same, jump back and try with the next label again
                s = strempty(old_suffix);
                n = saved_after;
                saved_after = ptr::null();
                saved_before = ptr::null();
            }
        }

        // Found it! Build prefix string (NUL-terminated copy)
        let prefix_len = (saved_before as isize - name as isize) as usize;
        let mut prefix_buf: Vec<c_char> = vec![0; prefix_len + 1];
        ptr::copy_nonoverlapping(name as *const c_char, prefix_buf.as_mut_ptr(), prefix_len);

        // Concatenate prefix + new_suffix
        let r = rs_dns_name_concat(prefix_buf.as_ptr(), new_suffix, 0, ret);
        if r < 0 {
            return r;
        }

        1
    }
}

// ── dns_name_normalize ──────────────────────────────────────────────────

/// Shadow of C dns_name_normalize()
/// dns_name_concat() normalizes as a side-effect.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_normalize(
    s: *const c_char,
    flags: u32,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_dns_name_concat(s, ptr::null(), flags, ret) }
}

// ── dns_name_is_valid ───────────────────────────────────────────────────

/// Shadow of C dns_name_is_valid()
/// dns_name_concat() verifies as a side effect.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_is_valid(s: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let r = rs_dns_name_concat(s, ptr::null(), 0, ptr::null_mut());
        if r == Errno::EINVAL.to_neg_errno() {
            // -EINVAL
            return 0;
        }
        if r < 0 {
            return r;
        }
        1
    }
}

// ── dns_name_is_valid_ldh ───────────────────────────────────────────────

/// Shadow of C dns_name_is_valid_ldh()
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_name_is_valid_ldh(s: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let r = rs_dns_name_concat(
            s,
            ptr::null(),
            DNS_LABEL_LDH | DNS_LABEL_NO_ESCAPES,
            ptr::null_mut(),
        );
        if r == Errno::EINVAL.to_neg_errno() {
            // -EINVAL
            return 0;
        }
        if r < 0 {
            return r;
        }
        1
    }
}

// ── dns_service_join ────────────────────────────────────────────────────

/// Helper: join two C strings with a separator, allocating the result.
///
/// # Safety
/// `a` and `b` must each reference a live NUL-terminated string. The returned
/// allocation, when non-null, belongs to the caller and must be released with
/// the C allocator.
unsafe fn alloc_strjoin(a: *const c_char, b: *const c_char) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let la = strlen(a);
        let lb = strlen(b);
        let total = la + 1 + lb + 1; // a + "." + b + NUL
        let ptr = malloc(total) as *mut c_char;
        if ptr.is_null() {
            return ptr;
        }
        ptr::copy_nonoverlapping(a, ptr, la);
        *ptr.add(la) = b'.' as c_char;
        ptr::copy_nonoverlapping(b, ptr.add(la + 1), lb + 1); // include NUL
        ptr
    }
}

/// Helper: duplicate n bytes from a C string, NUL-terminated.
///
/// # Safety
/// `s` must reference at least `n` readable bytes. The returned allocation,
/// when non-null, belongs to the caller and must be released with the C
/// allocator.
unsafe fn alloc_strndup(s: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let ptr = malloc(n + 1) as *mut c_char;
        if ptr.is_null() {
            return ptr;
        }
        ptr::copy_nonoverlapping(s, ptr, n);
        *ptr.add(n) = 0;
        ptr
    }
}

/// Shadow of C dns_service_join()
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_service_join(
    name: *const c_char,
    type_: *const c_char,
    domain: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if type_.is_null() || domain.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        if !rs_dns_srv_type_is_valid(type_) {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }

        if name.is_null() {
            return rs_dns_name_concat(type_, domain, 0, ret);
        }

        // Check if name is valid — call dns_service_name_is_valid from dns_domain_validators
        if !crate::dns_domain_validators::rs_dns_service_name_is_valid(name) {
            return Errno::EINVAL.to_neg_errno(); // -EINVAL
        }

        // Escape the name label
        let mut escaped: [c_char; DNS_LABEL_ESCAPED_MAX] = [0; DNS_LABEL_ESCAPED_MAX];
        let r = rs_dns_label_escape(
            name,
            strlen(name),
            escaped.as_mut_ptr(),
            DNS_LABEL_ESCAPED_MAX,
        );
        if r < 0 {
            return r;
        }

        // Concatenate type.domain
        let mut n: *mut c_char = ptr::null_mut();
        let r = rs_dns_name_concat(type_, domain, 0, &mut n);
        if r < 0 {
            return r;
        }

        // Concatenate escaped + n
        let r = rs_dns_name_concat(escaped.as_ptr(), n, 0, ret);
        // Free intermediate n (it was allocated by dns_name_concat via malloc)
        free(n as *mut std::ffi::c_void);
        r
    }
}

// ── dns_service_split ───────────────────────────────────────────────────

/// Shadow of C dns_service_split()
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_service_split(
    joined: *const c_char,
    ret_name: *mut *mut c_char,
    ret_type: *mut *mut c_char,
    ret_domain: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if joined.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut name: *mut c_char = ptr::null_mut();
        let mut type_: *mut c_char = ptr::null_mut();
        let mut domain: *mut c_char = ptr::null_mut();

        let mut p = joined;
        let mut q: *const c_char = ptr::null();
        let mut d = joined;

        let mut a: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
        let mut b: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];
        let mut c: [c_char; DNS_LABEL_MAX + 1] = [0; DNS_LABEL_MAX + 1];

        let an = rs_dns_label_unescape(&mut p, a.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
        if an < 0 {
            return an;
        }

        let mut x: u32 = 0;
        let mut do_finish = false;

        if an > 0 {
            x += 1;

            let bn = rs_dns_label_unescape(&mut p, b.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
            if bn < 0 {
                return bn;
            }

            if bn > 0 {
                if !srv_type_label_is_valid(b.as_ptr(), bn as usize) {
                    do_finish = true;
                } else {
                    x += 1;

                    q = p;
                    let cn = rs_dns_label_unescape(&mut p, c.as_mut_ptr(), DNS_LABEL_MAX + 1, 0);
                    if cn < 0 {
                        return cn;
                    }

                    if cn > 0 && srv_type_label_is_valid(c.as_ptr(), cn as usize) {
                        x += 1;
                    }
                }
            }
        }

        if !do_finish {
            match x {
                2 => {
                    if !srv_type_label_is_valid(a.as_ptr(), an as usize) {
                        // fall through to finish
                    } else {
                        // OK, got <type> . <type2> . <domain>
                        name = ptr::null_mut();

                        type_ = alloc_strjoin(a.as_ptr(), b.as_ptr());
                        if type_.is_null() {
                            return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
                        }

                        d = q;
                    }
                }
                3 => {
                    // Check dns_service_name_label_is_valid
                    let has_nul = (0..an as usize).any(|i| *a.as_ptr().add(i) == 0);
                    if !has_nul
                        && crate::dns_domain_validators::rs_dns_service_name_is_valid(a.as_ptr())
                    {
                        // OK, got <name> . <type> . <type2> . <domain>
                        name = alloc_strndup(a.as_ptr(), an as usize);
                        if name.is_null() {
                            return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
                        }

                        type_ = alloc_strjoin(b.as_ptr(), c.as_ptr());
                        if type_.is_null() {
                            free(name as *mut std::ffi::c_void);
                            return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
                        }

                        d = p;
                    }
                }
                _ => {}
            }
        }

        // finish: normalize domain
        let r = rs_dns_name_normalize(d, 0, &mut domain);
        if r < 0 {
            if !name.is_null() {
                free(name as *mut std::ffi::c_void);
            }
            if !type_.is_null() {
                free(type_ as *mut std::ffi::c_void);
            }
            return r;
        }

        if !ret_domain.is_null() {
            *ret_domain = domain;
        } else if !domain.is_null() {
            free(domain.cast());
        }
        if !ret_type.is_null() {
            *ret_type = type_;
        } else if !type_.is_null() {
            free(type_.cast());
        }
        if !ret_name.is_null() {
            *ret_name = name;
        } else if !name.is_null() {
            free(name.cast());
        }

        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::Errno;
    use std::ffi::{CStr, CString};

    #[test]
    fn dns_label_unescape_plain_label() {
        let input = CString::new("host.example").unwrap();
        let mut p = input.as_ptr();
        let mut out = [0 as c_char; DNS_LABEL_MAX + 1];

        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        let r = unsafe { rs_dns_label_unescape(&mut p, out.as_mut_ptr(), out.len(), 0) };
        assert_eq!(r, 4);
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        assert_eq!(unsafe { CStr::from_ptr(out.as_ptr()) }.to_bytes(), b"host");
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        assert_eq!(unsafe { CStr::from_ptr(p) }.to_bytes(), b"example");
    }

    #[test]
    fn dns_label_unescape_rejects_double_trailing_dot() {
        let input = CString::new("foo..").unwrap();
        let mut p = input.as_ptr();

        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let r = unsafe { rs_dns_label_unescape(&mut p, std::ptr::null_mut(), DNS_LABEL_MAX, 0) };
        assert_eq!(r, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn dns_name_equal_is_case_insensitive() {
        let a = CString::new("Foo.Example").unwrap();
        let b = CString::new("foo.example").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(unsafe { rs_dns_name_equal(a.as_ptr(), b.as_ptr()) }, 1);
    }

    #[test]
    fn dns_name_endswith_matches_suffix() {
        let name = CString::new("www.example.com").unwrap();
        let suffix = CString::new("example.com").unwrap();
        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe { rs_dns_name_endswith(name.as_ptr(), suffix.as_ptr()) },
            1
        );
    }

    #[test]
    fn dns_name_count_labels_counts_non_root_labels() {
        let name = CString::new("www.example.com").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(unsafe { rs_dns_name_count_labels(name.as_ptr()) }, 3);
    }

    #[test]
    fn dns_srv_type_validation_tracks_c_rules() {
        let ok = CString::new("_http._tcp").unwrap();
        let bad = CString::new("http._tcp").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert!(unsafe { rs_dns_srv_type_is_valid(ok.as_ptr()) });
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert!(!unsafe { rs_dns_srv_type_is_valid(bad.as_ptr()) });
    }

    #[test]
    fn dns_name_dot_suffixed_detects_trailing_dot() {
        let dotted = CString::new("example.com.").unwrap();
        let plain = CString::new("example.com").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(unsafe { rs_dns_name_dot_suffixed(dotted.as_ptr()) }, 1);
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        assert_eq!(unsafe { rs_dns_name_dot_suffixed(plain.as_ptr()) }, 0);
    }

    #[test]
    fn dns_name_reverse_ipv4_roundtrip() {
        let addr = [1u8, 2, 3, 4];
        let mut name = std::ptr::null_mut();
        let mut family = 0;
        let mut out = [0u8; 16];

        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe { rs_dns_name_reverse(2, addr.as_ptr().cast(), &mut name) },
            0
        );
        assert_eq!(
            // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
            unsafe { CStr::from_ptr(name) }.to_bytes(),
            b"4.3.2.1.in-addr.arpa"
        );
        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe { rs_dns_name_address(name, &mut family, out.as_mut_ptr().cast()) },
            1
        );
        assert_eq!(family, 2);
        assert_eq!(&out[..4], &addr);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free(name.cast()) };
    }

    #[test]
    fn dns_service_join_and_split_preserve_components() {
        let instance = CString::new("Printer").unwrap();
        let ty = CString::new("_ipp._tcp").unwrap();
        let domain = CString::new("example.com").unwrap();
        let mut joined = std::ptr::null_mut();
        let mut out_name = std::ptr::null_mut();
        let mut out_type = std::ptr::null_mut();
        let mut out_domain = std::ptr::null_mut();

        assert_eq!(
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe {
                rs_dns_service_join(instance.as_ptr(), ty.as_ptr(), domain.as_ptr(), &mut joined)
            },
            0
        );
        assert_eq!(
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            unsafe { rs_dns_service_split(joined, &mut out_name, &mut out_type, &mut out_domain) },
            0
        );
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        assert_eq!(unsafe { CStr::from_ptr(out_name) }.to_bytes(), b"Printer");
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        assert_eq!(unsafe { CStr::from_ptr(out_type) }.to_bytes(), b"_ipp._tcp");
        assert_eq!(
            // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
            unsafe { CStr::from_ptr(out_domain) }.to_bytes(),
            b"example.com"
        );

        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            free(joined.cast());
            free(out_name.cast());
            free(out_type.cast());
            free(out_domain.cast());
        }
    }

    #[test]
    fn dns_label_unescape_accepts_escaped_dot() {
        let input = CString::new("foo\\.bar.rest").unwrap();
        let mut p = input.as_ptr();
        let mut out = [0 as c_char; DNS_LABEL_MAX + 1];

        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let r = unsafe { rs_dns_label_unescape(&mut p, out.as_mut_ptr(), out.len(), 0) };
        assert_eq!(r, 7);
        assert_eq!(
            // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
            unsafe { CStr::from_ptr(out.as_ptr()) }.to_bytes(),
            b"foo.bar"
        );
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        assert_eq!(unsafe { CStr::from_ptr(p) }.to_bytes(), b"rest");
    }

    #[test]
    fn dns_label_unescape_rejects_invalid_ldh() {
        let input = CString::new("-bad").unwrap();
        let mut p = input.as_ptr();
        let mut out = [0 as c_char; DNS_LABEL_MAX + 1];

        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let r = unsafe {
            rs_dns_label_unescape(&mut p, out.as_mut_ptr(), out.len(), DNS_LABEL_LDH as u32)
        };
        assert_eq!(r, Errno::EINVAL.to_neg_errno());
    }
}
