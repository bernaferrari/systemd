// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/securebits-util.c,src/shared/securebits-util.h,
//           src/shared/ioprio-util.h,src/shared/vlan-util.c,src/shared/vlan-util.h,
//           src/shared/condition.h,src/shared/kbd-util.c,src/shared/kbd-util.h
//
// Shared policy validators and parsers.

use libc::{c_char, c_void};
use std::ffi::CStr;
use std::fmt;
use std::ptr;

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validators2Error {
    InvalidArgument,
    UnterminatedQuote,
}

impl fmt::Display for Validators2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::UnterminatedQuote => write!(f, "unterminated quote"),
        }
    }
}

impl std::error::Error for Validators2Error {}

// ── Securebits ────────────────────────────────────────────────────────────

pub const SECURE_NOROOT: i32 = 0;
pub const SECURE_NOROOT_LOCKED: i32 = 1;
pub const SECURE_NO_SETUID_FIXUP: i32 = 2;
pub const SECURE_NO_SETUID_FIXUP_LOCKED: i32 = 3;
pub const SECURE_KEEP_CAPS: i32 = 4;
pub const SECURE_KEEP_CAPS_LOCKED: i32 = 5;

pub fn secure_bits_is_valid(bits: i32) -> bool {
    const SECURE_ALL_BITS: i32 = 0x555;
    const SECURE_ALL_LOCKS: i32 = 0xaaa;
    ((SECURE_ALL_BITS | SECURE_ALL_LOCKS) & bits) == bits
}

fn secure_bit_to_name(bit: i32) -> Option<&'static str> {
    match bit {
        SECURE_KEEP_CAPS => Some("keep-caps"),
        SECURE_KEEP_CAPS_LOCKED => Some("keep-caps-locked"),
        SECURE_NO_SETUID_FIXUP => Some("no-setuid-fixup"),
        SECURE_NO_SETUID_FIXUP_LOCKED => Some("no-setuid-fixup-locked"),
        SECURE_NOROOT => Some("noroot"),
        SECURE_NOROOT_LOCKED => Some("noroot-locked"),
        _ => None,
    }
}

const SECURE_BITS_IN_C_ORDER: [(i32, &[u8]); 6] = [
    (SECURE_KEEP_CAPS, b"keep-caps"),
    (SECURE_KEEP_CAPS_LOCKED, b"keep-caps-locked"),
    (SECURE_NO_SETUID_FIXUP, b"no-setuid-fixup"),
    (SECURE_NO_SETUID_FIXUP_LOCKED, b"no-setuid-fixup-locked"),
    (SECURE_NOROOT, b"noroot"),
    (SECURE_NOROOT_LOCKED, b"noroot-locked"),
];

fn parse_words_unquote(input: &str) -> Result<Vec<String>, Validators2Error> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let mut word = String::new();
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            if bytes[i] == b'"' || bytes[i] == b'\'' {
                let quote = bytes[i];
                i += 1;

                while i < bytes.len() && bytes[i] != quote {
                    word.push(bytes[i] as char);
                    i += 1;
                }

                if i >= bytes.len() {
                    return Err(Validators2Error::UnterminatedQuote);
                }

                i += 1;
            } else {
                word.push(bytes[i] as char);
                i += 1;
            }
        }

        out.push(word);
    }

    Ok(out)
}

pub fn secure_bits_from_string(s: &str) -> i32 {
    let words = match parse_words_unquote(s) {
        Ok(words) => words,
        Err(Validators2Error::UnterminatedQuote) => {
            let truncated = s
                .split_once('"')
                .map_or(s, |(prefix, _)| prefix)
                .split_once('\'')
                .map_or(
                    s.split_once('"').map_or(s, |(prefix, _)| prefix),
                    |(prefix, _)| prefix,
                );
            parse_words_unquote(truncated).unwrap_or_default()
        }
        Err(_) => Vec::new(),
    };

    let mut bits = 0;
    for word in words {
        match word.as_str() {
            "keep-caps" => bits |= 1 << SECURE_KEEP_CAPS,
            "keep-caps-locked" => bits |= 1 << SECURE_KEEP_CAPS_LOCKED,
            "no-setuid-fixup" => bits |= 1 << SECURE_NO_SETUID_FIXUP,
            "no-setuid-fixup-locked" => bits |= 1 << SECURE_NO_SETUID_FIXUP_LOCKED,
            "noroot" => bits |= 1 << SECURE_NOROOT,
            "noroot-locked" => bits |= 1 << SECURE_NOROOT_LOCKED,
            _ => {}
        }
    }
    bits
}

pub fn secure_bits_to_strv(bits: i32) -> Result<Vec<String>, Validators2Error> {
    const ORDER: [i32; 6] = [
        SECURE_KEEP_CAPS,
        SECURE_KEEP_CAPS_LOCKED,
        SECURE_NO_SETUID_FIXUP,
        SECURE_NO_SETUID_FIXUP_LOCKED,
        SECURE_NOROOT,
        SECURE_NOROOT_LOCKED,
    ];

    let mut out = Vec::new();
    for bit in ORDER {
        if bits & (1 << bit) != 0 {
            out.push(secure_bit_to_name(bit).unwrap().to_string());
        }
    }
    Ok(out)
}

pub fn secure_bits_to_string_alloc(bits: i32) -> Result<String, Validators2Error> {
    Ok(secure_bits_to_strv(bits)?.join(" "))
}

/// Parse the secure-bit names accepted by `secure_bits_from_string()`.
///
/// # Safety
/// `s` must point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_secure_bits_from_string(s: *const c_char) -> i32 {
    if s.is_null() {
        return -libc::EINVAL;
    }

    let mut bits = 0;
    let mut cursor = s;
    loop {
        let mut word = ptr::null_mut();
        // SAFETY: cursor refers into the caller's live C string and word is a
        // writable local receiving ownership from the C allocator.
        let r = unsafe {
            crate::extract_word::rs_extract_first_word(
                &mut cursor,
                &mut word,
                ptr::null(),
                crate::extract_word::EXTRACT_UNQUOTE,
            )
        };
        if r == -libc::ENOMEM {
            return r;
        }
        if r <= 0 {
            return bits;
        }

        // SAFETY: a successful extraction publishes a live C string.
        let bytes = unsafe { CStr::from_ptr(word) }.to_bytes();
        for (bit, name) in SECURE_BITS_IN_C_ORDER {
            if bytes == name {
                bits |= 1 << bit;
                break;
            }
        }
        // SAFETY: rs_extract_first_word returned C-allocator ownership.
        unsafe { crate::ffi::free(word.cast::<c_void>()) };
    }
}

/// Allocate the canonical space-separated secure-bit list with `malloc()`.
///
/// # Safety
/// `ret` must be non-null, properly aligned, and writable. On success it
/// receives a C-owned string that the caller must release with `free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_secure_bits_to_string_alloc(bits: i32, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() {
        return -libc::EINVAL;
    }

    let selected = SECURE_BITS_IN_C_ORDER
        .iter()
        .filter(|(bit, _)| bits & (1 << bit) != 0);
    let count = selected.clone().count();
    let names_len = selected
        .clone()
        .try_fold(0usize, |total, (_, name)| total.checked_add(name.len()));
    let Some(names_len) = names_len else {
        return -libc::ENOMEM;
    };
    let Some(total_len) = names_len
        .checked_add(count.saturating_sub(1))
        .and_then(|n| n.checked_add(1))
    else {
        return -libc::ENOMEM;
    };

    // SAFETY: malloc accepts any size; total_len is at least one.
    let allocated = unsafe { libc::malloc(total_len) }.cast::<u8>();
    if allocated.is_null() {
        return -libc::ENOMEM;
    }

    let mut offset = 0usize;
    for (index, (_, name)) in selected.enumerate() {
        if index > 0 {
            // SAFETY: total_len includes one separator for every later item.
            unsafe { *allocated.add(offset) = b' ' };
            offset += 1;
        }
        // SAFETY: checked sizing above reserves name.len() bytes here and the
        // static source slice cannot overlap the malloc allocation.
        unsafe {
            ptr::copy_nonoverlapping(name.as_ptr(), allocated.add(offset), name.len());
        }
        offset += name.len();
    }
    // SAFETY: total_len includes the trailing NUL byte.
    unsafe {
        *allocated.add(offset) = 0;
        *ret = allocated.cast::<c_char>();
    }
    0
}

// SAFETY: callers pass the calloc allocation and the exact initialized prefix
// owned exclusively by rs_secure_bits_to_strv.
unsafe fn free_c_string_vector(vector: *mut *mut c_char, initialized: usize) {
    for index in 0..initialized {
        // SAFETY: the caller passes the allocation and initialized prefix
        // created by rs_secure_bits_to_strv.
        unsafe { libc::free((*vector.add(index)).cast::<c_void>()) };
    }
    // SAFETY: vector itself came from calloc.
    unsafe { libc::free(vector.cast::<c_void>()) };
}

/// Allocate the canonical null-terminated secure-bit string vector.
///
/// # Safety
/// `ret` must be non-null, properly aligned, and writable. On success it
/// receives either NULL for an empty vector or a C-owned strv suitable for
/// `strv_free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_secure_bits_to_strv(bits: i32, ret: *mut *mut *mut c_char) -> i32 {
    if ret.is_null() {
        return -libc::EINVAL;
    }

    let count = SECURE_BITS_IN_C_ORDER
        .iter()
        .filter(|(bit, _)| bits & (1 << bit) != 0)
        .count();
    if count == 0 {
        // SAFETY: ret is non-null and writable by contract.
        unsafe { *ret = ptr::null_mut() };
        return 0;
    }

    let Some(slots) = count.checked_add(1) else {
        return -libc::ENOMEM;
    };
    // SAFETY: calloc receives a checked element count and size.
    let vector =
        unsafe { libc::calloc(slots, std::mem::size_of::<*mut c_char>()) }.cast::<*mut c_char>();
    if vector.is_null() {
        return -libc::ENOMEM;
    }

    let mut initialized = 0usize;
    for (_, name) in SECURE_BITS_IN_C_ORDER
        .iter()
        .filter(|(bit, _)| bits & (1 << bit) != 0)
    {
        let Some(size) = name.len().checked_add(1) else {
            // SAFETY: vector and its initialized prefix are ours.
            unsafe { free_c_string_vector(vector, initialized) };
            return -libc::ENOMEM;
        };
        // SAFETY: malloc accepts this checked non-zero size.
        let string = unsafe { libc::malloc(size) }.cast::<u8>();
        if string.is_null() {
            // SAFETY: vector and its initialized prefix are ours.
            unsafe { free_c_string_vector(vector, initialized) };
            return -libc::ENOMEM;
        }
        // SAFETY: string has name.len()+1 bytes and cannot overlap static data.
        unsafe {
            ptr::copy_nonoverlapping(name.as_ptr(), string, name.len());
            *string.add(name.len()) = 0;
            *vector.add(initialized) = string.cast::<c_char>();
        }
        initialized += 1;
    }

    // SAFETY: ret is writable and vector is a complete null-terminated strv
    // because calloc zeroed its final slot.
    unsafe { *ret = vector };
    0
}

// ── IOPriority ────────────────────────────────────────────────────────────

pub fn ioprio_class_is_valid(i: i32) -> bool {
    matches!(i, 0..=3)
}

pub fn ioprio_priority_is_valid(i: i32) -> bool {
    (0..8).contains(&i)
}

pub fn ioprio_parse_priority(s: &str) -> Result<i32, Validators2Error> {
    let v: i32 = s.parse().map_err(|_| Validators2Error::InvalidArgument)?;
    if !ioprio_priority_is_valid(v) {
        return Err(Validators2Error::InvalidArgument);
    }
    Ok(v)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ioprio_class_is_valid(i: i32) -> bool {
    ioprio_class_is_valid(i)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ioprio_priority_is_valid(i: i32) -> bool {
    ioprio_priority_is_valid(i)
}

/// Parse an I/O priority while preserving `safe_atoi()` error semantics.
///
/// # Safety
/// `s` must be a live NUL-terminated C string and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ioprio_parse_priority(s: *const c_char, ret: *mut i32) -> i32 {
    if s.is_null() || ret.is_null() {
        return -libc::EINVAL;
    }

    let mut parsed = 0;
    // SAFETY: s and the local output satisfy rs_safe_atoi's contract.
    let r = unsafe { crate::parse_util::rs_safe_atoi(s, &mut parsed) };
    if r < 0 {
        return r;
    }
    if !ioprio_priority_is_valid(parsed) {
        return -libc::EINVAL;
    }

    // SAFETY: ret is non-null and writable by contract.
    unsafe { *ret = parsed };
    0
}

// ── VLAN ──────────────────────────────────────────────────────────────────

pub fn vlanid_is_valid(id: u16) -> bool {
    id <= 4094
}

pub fn parse_vid_range(s: &str) -> Result<(u16, u16), Validators2Error> {
    let (lower, upper) = match s.split_once('-') {
        Some((a, b)) => (
            a.parse::<u16>()
                .map_err(|_| Validators2Error::InvalidArgument)?,
            b.parse::<u16>()
                .map_err(|_| Validators2Error::InvalidArgument)?,
        ),
        None => {
            let v = s
                .parse::<u16>()
                .map_err(|_| Validators2Error::InvalidArgument)?;
            (v, v)
        }
    };

    if !vlanid_is_valid(lower) || !vlanid_is_valid(upper) || lower > upper {
        return Err(Validators2Error::InvalidArgument);
    }

    Ok((lower, upper))
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_vlanid_is_valid(id: u16) -> bool {
    vlanid_is_valid(id)
}

/// Parse a VLAN range while publishing outputs only after full validation.
///
/// # Safety
/// `p` must be a live NUL-terminated C string and both output pointers must be
/// non-null, properly aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_vid_range(
    p: *const c_char,
    vid: *mut u16,
    vid_end: *mut u16,
) -> i32 {
    if p.is_null() || vid.is_null() || vid_end.is_null() {
        return -libc::EINVAL;
    }

    let mut lower = 0u32;
    let mut upper = 0u32;
    // SAFETY: p is a live C string and both locals are writable.
    let r = unsafe { crate::parse_util::rs_parse_range(p, &mut lower, &mut upper) };
    if r < 0 {
        return r;
    }
    if lower > 4094 || upper > 4094 || lower > upper {
        return -libc::EINVAL;
    }

    // SAFETY: the checked values fit u16 and both outputs are writable.
    unsafe {
        *vid = lower as u16;
        *vid_end = upper as u16;
    }
    0
}

// ── Conditions and keymaps ────────────────────────────────────────────────

// Keep these discriminants synchronized with ConditionType in
// src/shared/condition.h. The C helper accepts the enum by value, so the Rust
// ABI entry point intentionally uses its underlying `int` representation.
const CONDITION_NEEDS_UPDATE: i32 = 20;
const CONDITION_PATH_EXISTS: i32 = 22;
const CONDITION_FILE_IS_EXECUTABLE: i32 = 32;

pub fn condition_takes_path(t: i32) -> bool {
    t == CONDITION_NEEDS_UPDATE
        || (CONDITION_PATH_EXISTS..=CONDITION_FILE_IS_EXECUTABLE).contains(&t)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_condition_takes_path(t: i32) -> bool {
    condition_takes_path(t)
}

fn filename_is_valid(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

fn string_is_safe(s: &str) -> bool {
    s.bytes().all(|b| {
        !(b > 0 && b < 0x20)
            && b != b'"'
            && b != b'\''
            && b != b'\\'
            && b != b'?'
            && b != b'*'
            && b != b'['
            && b != 0x7f
    })
}

pub fn keymap_is_valid(name: &str) -> bool {
    !name.is_empty() && name.len() < 128 && filename_is_valid(name) && string_is_safe(name)
}

/// Validate a keymap name with the current `STRING_FILENAME` rules.
///
/// # Safety
/// `name` must point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_keymap_is_valid(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }

    // SAFETY: name is a live C string by contract.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    if bytes.is_empty()
        || bytes.len() >= 128
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || std::str::from_utf8(bytes).is_err()
    {
        return false;
    }

    bytes.iter().copied().all(|b| {
        !(b > 0 && b < 0x20)
            && b != b'"'
            && b != b'\''
            && b != b'\\'
            && b != b'?'
            && b != b'*'
            && b != b'['
            && b != 0x7f
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_bits_single_roundtrip() {
        let bits = secure_bits_from_string("keep-caps");
        assert_eq!(bits, 1 << SECURE_KEEP_CAPS);
        assert_eq!(secure_bits_to_string_alloc(bits).unwrap(), "keep-caps");
    }

    #[test]
    fn secure_bits_all_roundtrip_in_c_order() {
        let joined = "keep-caps keep-caps-locked no-setuid-fixup no-setuid-fixup-locked noroot noroot-locked";
        let bits = secure_bits_from_string(joined);
        assert!(secure_bits_is_valid(bits));
        assert_eq!(secure_bits_to_string_alloc(bits).unwrap(), joined);
    }

    #[test]
    fn secure_bits_ignore_unknown_words() {
        assert_eq!(
            secure_bits_from_string("noroot foo bar keep-caps"),
            (1 << SECURE_NOROOT) | (1 << SECURE_KEEP_CAPS)
        );
    }

    #[test]
    fn secure_bits_stop_usefully_on_unterminated_quotes() {
        assert_eq!(
            secure_bits_from_string("noroot \"foo\" \"bar keep-caps"),
            1 << SECURE_NOROOT
        );
    }

    #[test]
    fn ioprio_validation_matches_header_rules() {
        assert!(ioprio_class_is_valid(0));
        assert!(ioprio_class_is_valid(3));
        assert!(!ioprio_class_is_valid(4));
        assert!(ioprio_priority_is_valid(7));
        assert!(!ioprio_priority_is_valid(8));
    }

    #[test]
    fn ioprio_parse_priority_rejects_bad_values() {
        assert_eq!(ioprio_parse_priority("4").unwrap(), 4);
        assert_eq!(
            ioprio_parse_priority("8"),
            Err(Validators2Error::InvalidArgument)
        );
        assert_eq!(
            ioprio_parse_priority("x"),
            Err(Validators2Error::InvalidArgument)
        );
    }

    #[test]
    fn vlan_range_parser_matches_c_contract() {
        assert_eq!(parse_vid_range("5").unwrap(), (5, 5));
        assert_eq!(parse_vid_range("5-7").unwrap(), (5, 7));
        assert_eq!(
            parse_vid_range("4095"),
            Err(Validators2Error::InvalidArgument)
        );
        assert_eq!(
            parse_vid_range("9-2"),
            Err(Validators2Error::InvalidArgument)
        );
    }

    #[test]
    fn condition_takes_path_matches_condition_header() {
        assert!(condition_takes_path(20));
        assert!(condition_takes_path(22));
        assert!(condition_takes_path(32));
        assert!(!condition_takes_path(18));
        assert!(!condition_takes_path(21));
        assert!(!condition_takes_path(33));
        assert!(!condition_takes_path(19));
    }

    #[test]
    fn keymap_validation_matches_c_checks() {
        assert!(keymap_is_valid("uk"));
        assert!(keymap_is_valid("ANSI-dvorak"));
        assert!(!keymap_is_valid(""));
        assert!(!keymap_is_valid("/usr/bin/foo"));
        assert!(!keymap_is_valid("bad\"name"));
    }
}
