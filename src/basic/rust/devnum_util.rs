// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.devnum-util; authority=src/basic/devnum-util.c,src/basic/devnum-util.h
//
// Device number parsing and formatting utilities.

use std::ffi::CStr;
use std::ptr;

use libc::c_char;

use crate::ffi::Errno;

const DEVNUM_MAJOR_MAX: u32 = (1u32 << 12) - 1;
const DEVNUM_MINOR_MAX: u32 = (1u32 << 20) - 1;
/* C's DECIMAL_STR_MAX(dev_t) includes the trailing-NUL slot and is 21 for
 * Linux's 64-bit unsigned dev_t. parse_devnum() compares the digit count to
 * that macro directly, so a 21-digit, leading-zero major remains accepted. */
const DECIMAL_STR_MAX_DEV_T: usize = 21;
const NAME_MAX_VAL: usize = 255;
const U32_DECIMAL_MAX: usize = 10;
const DEVNUM_FORMAT_MAX: usize = U32_DECIMAL_MAX + 1 + U32_DECIMAL_MAX;
const S_IFMT: u32 = 0o170000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;

/// A C ABI output pointer whose writable-storage contract is established by
/// the exporting function. Keeping stores here leaves parsing and formatting
/// cores entirely in Rust values.
#[derive(Clone, Copy)]
struct COut<T>(*mut T);

impl<T> COut<T> {
    fn from_contract(ptr: *mut T) -> Self {
        Self(ptr)
    }

    fn store(self, value: T) {
        if !self.0.is_null() {
            // SAFETY: a non-null output pointer is writable under the enclosing ABI contract.
            unsafe_ffi!(*self.0 = value);
        }
    }
}

/// Caller-contract-validated writable C buffer used by the stack formatter.
struct CCharBuffer(*mut c_char);

impl CCharBuffer {
    fn from_contract(ptr: *mut c_char) -> Self {
        Self(ptr)
    }

    fn is_present(&self) -> bool {
        !self.0.is_null()
    }

    fn write_nul_terminated(&self, bytes: &[u8]) {
        // SAFETY: the C ABI contract guarantees space for `bytes` plus NUL;
        // `bytes` is a live Rust slice and therefore cannot overlap this output.
        unsafe_ffi!({
            ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), self.0, bytes.len());
            *self.0.add(bytes.len()) = 0;
        })
    }
}

#[inline]
const fn makedev(major: u32, minor: u32) -> u64 {
    (minor as u64 & 0x0000_00ff)
        | (((major as u64) & 0x0000_0fff) << 8)
        | (((minor as u64) & 0xffff_ff00) << 12)
        | (((major as u64) & 0xffff_f000) << 32)
}

#[inline]
const fn dev_major(dev: u64) -> u32 {
    (((dev & 0x0000_0000_000f_ff00) >> 8) | ((dev & 0xffff_f000_0000_0000) >> 32)) as u32
}

#[inline]
const fn dev_minor(dev: u64) -> u32 {
    ((dev & 0x0000_0000_0000_00ff) | ((dev & 0x0000_0fff_fff0_0000) >> 12)) as u32
}

/// Encode Linux `dev_t` bits from a major/minor pair.
///
/// This is the same layout as glibc's `makedev(3)` macro and systemd's C
/// `devnum-util`; keeping it here prevents consumers from inventing their own
/// incompatible `major << 32 | minor` representation.
#[inline]
pub const fn devnum_from_major_minor(major: u32, minor: u32) -> u64 {
    makedev(major, minor)
}

/// Decode the major component of Linux `dev_t` bits.
#[inline]
pub const fn devnum_major(dev: u64) -> u32 {
    dev_major(dev)
}

/// Decode the minor component of Linux `dev_t` bits.
#[inline]
pub const fn devnum_minor(dev: u64) -> u32 {
    dev_minor(dev)
}

fn parse_u32_base0(text: &[u8]) -> Result<u32, Errno> {
    let mut cursor = text
        .iter()
        .position(|byte| !matches!(*byte, b' ' | b'\t' | b'\n' | b'\r'))
        .unwrap_or(text.len());
    if cursor == text.len() {
        return Err(Errno::EINVAL);
    }

    /* safe_atou() first recognizes Python's unsigned 0b/0o prefixes, then
     * delegates to strtoul(base=0), which accepts a sign and C's 0/0x
     * prefixes. Keep that order: +0b1 is invalid while +010 is valid. */
    let mut base = if text[cursor..].starts_with(b"0b") || text[cursor..].starts_with(b"0B") {
        cursor += 2;
        2_u64
    } else if text[cursor..].starts_with(b"0o") || text[cursor..].starts_with(b"0O") {
        cursor += 2;
        8_u64
    } else {
        0
    };

    /* strtoul() itself skips the full C-locale whitespace set and accepts a
     * sign after mangle_base() has selected a Python base. */
    while cursor < text.len() && matches!(text[cursor], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
    {
        cursor += 1;
    }
    if cursor == text.len() {
        return Err(Errno::EINVAL);
    }

    let negative = text[cursor] == b'-';
    if matches!(text[cursor], b'+' | b'-') {
        cursor += 1;
        if cursor == text.len() {
            return Err(Errno::EINVAL);
        }
    }

    if base == 0 {
        base = if text[cursor..].starts_with(b"0x") || text[cursor..].starts_with(b"0X") {
            cursor += 2;
            16
        } else if text[cursor] == b'0' {
            8
        } else {
            10
        };
    }

    let digits_begin = cursor;
    let mut value = 0_u64;
    while cursor < text.len() {
        let digit = match text[cursor] {
            b'0'..=b'9' => (text[cursor] - b'0') as u64,
            b'a'..=b'f' => (text[cursor] - b'a' + 10) as u64,
            b'A'..=b'F' => (text[cursor] - b'A' + 10) as u64,
            _ => break,
        };
        if digit >= base {
            break;
        }
        value = value
            .checked_mul(base)
            .and_then(|current| current.checked_add(digit))
            .ok_or(Errno::ERANGE)?;
        if value > libc::c_ulong::MAX as u64 {
            return Err(Errno::ERANGE);
        }
        cursor += 1;
    }

    if cursor == digits_begin || cursor != text.len() {
        return Err(Errno::EINVAL);
    }
    if (negative && value != 0) || value > u32::MAX as u64 {
        return Err(Errno::ERANGE);
    }
    Ok(value as u32)
}

fn parse_devnum_bytes(text: &[u8]) -> Result<u64, Errno> {
    let digit_prefix = text.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if digit_prefix == 0 || digit_prefix > DECIMAL_STR_MAX_DEV_T {
        return Err(Errno::EINVAL);
    }
    if text.get(digit_prefix) != Some(&b':') {
        return Err(Errno::EINVAL);
    }

    let major = parse_u32_base0(&text[..digit_prefix])?;
    let minor = parse_u32_base0(&text[digit_prefix + 1..])?;
    if major > DEVNUM_MAJOR_MAX || minor > DEVNUM_MINOR_MAX {
        return Err(Errno::ERANGE);
    }

    Ok(makedev(major, minor))
}

/// Allocate and NUL-terminate concatenated byte slices using the C allocator.
/// This is the common ownership-transfer boundary for device paths.
fn allocate_c_string_parts(parts: &[&[u8]]) -> Result<*mut c_char, Errno> {
    let content_len = parts.iter().try_fold(0usize, |len, part| {
        len.checked_add(part.len()).ok_or(Errno::ENOMEM)
    })?;
    let size = content_len.checked_add(1).ok_or(Errno::ENOMEM)?;
    let allocation = crate::ffi::malloc(size).cast::<u8>();
    if allocation.is_null() {
        return Err(Errno::ENOMEM);
    }

    // SAFETY: `allocation` owns `size` bytes from the C allocator. Each input
    // is a live Rust slice; cursor advancement is bounded by `content_len`.
    unsafe_ffi!({
        let mut cursor = allocation;
        for part in parts {
            ptr::copy_nonoverlapping(part.as_ptr(), cursor, part.len());
            cursor = cursor.add(part.len());
        }
        *cursor = 0;
    });
    Ok(allocation.cast::<c_char>())
}

fn allocate_c_string(text: &str) -> Result<*mut c_char, Errno> {
    allocate_c_string_parts(&[text.as_bytes()])
}

fn write_u32_decimal(mut value: u32, output: &mut [u8]) -> Result<usize, Errno> {
    let mut reversed = [0_u8; 10];
    let mut n = 0;

    loop {
        reversed[n] = b'0' + (value % 10) as u8;
        n += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    if n > output.len() {
        return Err(Errno::ERANGE);
    }

    for (destination, source) in output[..n].iter_mut().zip(reversed[..n].iter().rev()) {
        *destination = *source;
    }
    Ok(n)
}

fn format_devnum_bytes(devnum: u64) -> Result<([u8; DEVNUM_FORMAT_MAX], usize), Errno> {
    let mut output = [0_u8; DEVNUM_FORMAT_MAX];
    let major_length = write_u32_decimal(dev_major(devnum), &mut output)?;
    output[major_length] = b':';
    let minor_length = write_u32_decimal(dev_minor(devnum), &mut output[major_length + 1..])?;
    Ok((output, major_length + 1 + minor_length))
}

fn device_path_prefix(mode: u32) -> Result<&'static [u8], Errno> {
    match mode & S_IFMT {
        S_IFCHR => Ok(b"/dev/char/"),
        S_IFBLK => Ok(b"/dev/block/"),
        _ => Err(Errno::ENODEV),
    }
}

fn next_path_component<'a>(path: &'a [u8], cursor: &mut usize) -> Result<Option<&'a [u8]>, Errno> {
    while *cursor < path.len() {
        if path[*cursor] == b'/' {
            *cursor += 1;
            continue;
        }
        if path[*cursor..].starts_with(b"./") {
            *cursor += 2;
            continue;
        }
        break;
    }

    if *cursor == path.len() || (*cursor + 1 == path.len() && path[*cursor] == b'.') {
        *cursor = path.len();
        return Ok(None);
    }

    let begin = *cursor;
    while *cursor < path.len() && path[*cursor] != b'/' {
        *cursor += 1;
    }
    if *cursor - begin > NAME_MAX_VAL {
        return Err(Errno::EINVAL);
    }
    Ok(Some(&path[begin..*cursor]))
}

fn path_equal_components(left: &[u8], right: &[u8]) -> bool {
    if left.starts_with(b"/") != right.starts_with(b"/") {
        return false;
    }

    let (mut left_cursor, mut right_cursor) = (0, 0);
    loop {
        match (
            next_path_component(left, &mut left_cursor),
            next_path_component(right, &mut right_cursor),
        ) {
            (Ok(Some(a)), Ok(Some(b))) if a == b => {}
            (Ok(None), Ok(None)) => return true,
            _ => return false,
        }
    }
}

fn path_startswith_components<'a>(path: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if path.starts_with(b"/") != prefix.starts_with(b"/") {
        return None;
    }

    let (mut path_cursor, mut prefix_cursor) = (0, 0);
    loop {
        let path_component = next_path_component(path, &mut path_cursor).ok()?;
        match next_path_component(prefix, &mut prefix_cursor).ok()? {
            Some(prefix_component) => {
                if path_component? != prefix_component {
                    return None;
                }
            }
            None => {
                return Some(match path_component {
                    Some(component) => &path[path_cursor - component.len()..],
                    None => &path[path.len()..],
                });
            }
        }
    }
}

fn parse_device_path(path: &[u8]) -> Result<(u32, u64), Errno> {
    if path_equal_components(path, b"/run/systemd/inaccessible/chr") {
        return Ok((S_IFCHR, makedev(0, 0)));
    }
    if path_equal_components(path, b"/run/systemd/inaccessible/blk") {
        return Ok((S_IFBLK, makedev(0, 0)));
    }

    if let Some(rest) = path_startswith_components(path, b"/dev/block/") {
        return parse_devnum_bytes(rest).map(|dev| (S_IFBLK, dev));
    }
    if let Some(rest) = path_startswith_components(path, b"/dev/char/") {
        return parse_devnum_bytes(rest).map(|dev| (S_IFCHR, dev));
    }

    Err(Errno::ENODEV)
}

/// Parse a NUL-terminated `major:minor` C string into `dev_t`.
///
/// # Safety
/// `s` must point to a readable NUL-terminated C string and `ret` must point
/// to writable, properly aligned `dev_t` storage for the duration of the call.
#[unsafe(export_name = "rs_parse_devnum")]
pub unsafe extern "C" fn rs_parse_devnum(s: *const c_char, ret: *mut u64) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `s` is a readable NUL-terminated string by this C ABI contract.
    let result = parse_devnum_bytes(unsafe_ffi!(CStr::from_ptr(s)).to_bytes());

    match result {
        Ok(dev) => {
            COut::from_contract(ret).store(dev);
            0
        }
        Err(errno) => errno.to_neg_errno(),
    }
}

/// Format a C `dev_t` into its `major:minor` representation.
///
/// # Safety
/// If non-null, `buf` must designate writable storage large enough for the
/// formatted value and its trailing NUL byte.
#[unsafe(export_name = "rs_format_devnum")]
pub unsafe extern "C" fn rs_format_devnum(d: u64, buf: *mut c_char) -> *mut c_char {
    let output = CCharBuffer::from_contract(buf);
    if !output.is_present() {
        return ptr::null_mut();
    }

    let Ok((text, text_length)) = format_devnum_bytes(d) else {
        return ptr::null_mut();
    };
    output.write_nul_terminated(&text[..text_length]);
    buf
}

#[unsafe(export_name = "rs_devnum_is_zero")]
pub extern "C" fn rs_devnum_is_zero(d: u64) -> bool {
    dev_major(d) == 0 && dev_minor(d) == 0
}

#[unsafe(export_name = "rs_devnum_set_and_equal")]
pub extern "C" fn rs_devnum_set_and_equal(a: u64, b: u64) -> bool {
    a == b && a != 0
}

/// Parse a C device path and optionally return its mode and device number.
///
/// # Safety
/// `path` must point to a readable NUL-terminated C string. Each non-null
/// output pointer must point to writable, properly aligned storage for its C
/// type for the duration of the call.
#[unsafe(export_name = "rs_device_path_parse_major_minor")]
pub unsafe extern "C" fn rs_device_path_parse_major_minor(
    path: *const c_char,
    ret_mode: *mut u32,
    ret_devnum: *mut u64,
) -> i32 {
    if path.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `path` is a readable NUL-terminated string by this C ABI contract.
    match parse_device_path(unsafe_ffi!(CStr::from_ptr(path)).to_bytes()) {
        Ok((mode, devnum)) => {
            COut::from_contract(ret_mode).store(mode);
            COut::from_contract(ret_devnum).store(devnum);
            0
        }
        Err(errno) => errno.to_neg_errno(),
    }
}

/// Allocate the canonical C device path for `mode` and `devnum`.
///
/// # Safety
/// `ret` must point to writable, properly aligned `char *` storage. On
/// success it receives a NUL-terminated allocation that the C allocator can
/// release.
#[unsafe(export_name = "rs_device_path_make_major_minor")]
pub unsafe extern "C" fn rs_device_path_make_major_minor(
    mode: u32,
    devnum: u64,
    ret: *mut *mut c_char,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let prefix = match device_path_prefix(mode) {
        Ok(prefix) => prefix,
        Err(errno) => return errno.to_neg_errno(),
    };
    let (formatted_devnum, formatted_devnum_length) = match format_devnum_bytes(devnum) {
        Ok(formatted) => formatted,
        Err(errno) => return errno.to_neg_errno(),
    };
    let Some(size) = prefix
        .len()
        .checked_add(formatted_devnum_length)
        .and_then(|length| length.checked_add(1))
    else {
        return Errno::ENOMEM.to_neg_errno();
    };

    // SAFETY: `size` includes the NUL terminator. This single C allocator
    // boundary preserves the ownership expected by the exported C ABI.
    let path = unsafe_ffi!(libc::malloc(size)).cast::<u8>();
    if path.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: `path` owns exactly `size` writable bytes and both source ranges
    // are live Rust slices whose combined length is `size - 1`.
    unsafe_ffi!({
        ptr::copy_nonoverlapping(prefix.as_ptr(), path, prefix.len());
        ptr::copy_nonoverlapping(
            formatted_devnum.as_ptr(),
            path.add(prefix.len()),
            formatted_devnum_length,
        );
        *path.add(size - 1) = 0;
    });
    COut::from_contract(ret).store(path.cast::<c_char>());
    0
}

/// Allocate the inaccessible-device path for a C file-type mode.
///
/// # Safety
/// `ret` must point to writable, properly aligned `char *` storage. On
/// success it receives a NUL-terminated allocation that the C allocator can
/// release.
#[unsafe(export_name = "rs_device_path_make_inaccessible")]
pub unsafe extern "C" fn rs_device_path_make_inaccessible(mode: u32, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let path = match mode & S_IFMT {
        S_IFCHR => "/run/systemd/inaccessible/chr",
        S_IFBLK => "/run/systemd/inaccessible/blk",
        _ => return Errno::ENODEV.to_neg_errno(),
    };

    match allocate_c_string(path) {
        Ok(p) => {
            COut::from_contract(ret).store(p);
            0
        }
        Err(errno) => errno.to_neg_errno(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn parse_devnum_accepts_basic_values() {
        let mut dev = 0;
        let input = CString::new("8:2").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            assert_eq!(rs_parse_devnum(input.as_ptr(), &mut dev), 0);
        });
        assert_eq!(dev_major(dev), 8);
        assert_eq!(dev_minor(dev), 2);
    }

    #[test]
    fn parse_devnum_accepts_maximum_values() {
        let mut dev = 0;
        let input = CString::new("4095:1048575").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            assert_eq!(rs_parse_devnum(input.as_ptr(), &mut dev), 0);
        });
        assert_eq!(dev_major(dev), 4095);
        assert_eq!(dev_minor(dev), 1_048_575);
    }

    #[test]
    fn parse_devnum_matches_safe_atou_base_zero_rules() {
        for (input, expected_major, expected_minor) in [
            (b"010:010".as_slice(), 8, 8),
            (b"8:0x10".as_slice(), 8, 16),
            (b"8:0b10".as_slice(), 8, 2),
            (b"8:0o10".as_slice(), 8, 8),
            (b"8:0b 10".as_slice(), 8, 2),
            (b"8:0b+10".as_slice(), 8, 2),
            (b"8:0o\x0b10".as_slice(), 8, 8),
            (b"8:0b-0".as_slice(), 8, 0),
            (b"8: 2".as_slice(), 8, 2),
            (b"000000000000000000001:0".as_slice(), 1, 0),
        ] {
            let dev = parse_devnum_bytes(input).unwrap();
            assert_eq!(dev_major(dev), expected_major);
            assert_eq!(dev_minor(dev), expected_minor);
        }
        assert_eq!(parse_devnum_bytes(b"08:02"), Err(Errno::EINVAL));
        assert_eq!(parse_devnum_bytes(b"8:0b-1"), Err(Errno::ERANGE));
    }

    #[test]
    fn parse_devnum_rejects_missing_colon() {
        let mut dev = 0;
        let input = CString::new("8").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            assert_eq!(
                rs_parse_devnum(input.as_ptr(), &mut dev),
                Errno::EINVAL.to_neg_errno()
            );
        })
    }

    #[test]
    fn parse_devnum_rejects_invalid_text() {
        let mut dev = 0;
        let input = CString::new("abc").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            assert_eq!(
                rs_parse_devnum(input.as_ptr(), &mut dev),
                Errno::EINVAL.to_neg_errno()
            );
        })
    }

    #[test]
    fn parse_devnum_rejects_major_overflow() {
        let mut dev = 0;
        let input = CString::new("4096:0").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            assert_eq!(
                rs_parse_devnum(input.as_ptr(), &mut dev),
                Errno::ERANGE.to_neg_errno()
            );
        })
    }

    #[test]
    fn parse_devnum_rejects_minor_overflow() {
        let mut dev = 0;
        let input = CString::new("0:1048576").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            assert_eq!(
                rs_parse_devnum(input.as_ptr(), &mut dev),
                Errno::ERANGE.to_neg_errno()
            );
        })
    }

    #[test]
    fn format_devnum_matches_c_format() {
        let mut buf = [0 as c_char; 32];
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            let out = rs_format_devnum(makedev(7, 255), buf.as_mut_ptr());
            assert_eq!(out, buf.as_mut_ptr());
            assert_eq!(CStr::from_ptr(out).to_str().unwrap(), "7:255");
        })
    }

    #[test]
    fn format_devnum_handles_full_encoded_dev_t_bits() {
        let mut buf = [0 as c_char; DEVNUM_FORMAT_MAX + 1];
        // SAFETY: the fixed buffer has room for two maximum-width u32 values,
        // their separator, and the trailing NUL byte.
        unsafe_ffi!({
            let out = rs_format_devnum(u64::MAX, buf.as_mut_ptr());
            assert_eq!(out, buf.as_mut_ptr());
            assert_eq!(
                CStr::from_ptr(out).to_str().unwrap(),
                "4294967295:4294967295"
            );
        })
    }

    #[test]
    fn devnum_zero_helpers_match_header_logic() {
        assert!(rs_devnum_is_zero(makedev(0, 0)));
        assert!(!rs_devnum_is_zero(makedev(1, 0)));
        assert!(rs_devnum_set_and_equal(makedev(1, 2), makedev(1, 2)));
        assert!(!rs_devnum_set_and_equal(0, 0));
    }

    #[test]
    fn device_path_parse_handles_block_char_and_inaccessible() {
        let mut mode = 0;
        let mut dev = 0;

        for (path, expected_mode, expected_dev) in [
            ("/dev/block/8:2", S_IFBLK, makedev(8, 2)),
            ("/dev/char/8:2", S_IFCHR, makedev(8, 2)),
            ("/run/systemd/inaccessible/blk", S_IFBLK, makedev(0, 0)),
            ("/run/systemd/inaccessible/chr", S_IFCHR, makedev(0, 0)),
        ] {
            let c = CString::new(path).unwrap();
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            unsafe_ffi!({
                assert_eq!(
                    rs_device_path_parse_major_minor(c.as_ptr(), &mut mode, &mut dev),
                    0
                );
            });
            assert_eq!(mode, expected_mode);
            assert_eq!(dev, expected_dev);
        }
    }

    #[test]
    fn device_path_parse_normalizes_components_without_allocating() {
        for (path, expected_mode, expected_dev) in [
            (b"/dev//block/8:2".as_slice(), S_IFBLK, makedev(8, 2)),
            (b"/dev/./block/8:2".as_slice(), S_IFBLK, makedev(8, 2)),
            (b"/dev/block/./8:2".as_slice(), S_IFBLK, makedev(8, 2)),
            (
                b"/run//systemd/./inaccessible/chr/".as_slice(),
                S_IFCHR,
                makedev(0, 0),
            ),
        ] {
            assert_eq!(
                parse_device_path(path),
                Ok((expected_mode, expected_dev)),
                "{path:?}"
            );
        }
        assert_eq!(parse_device_path(b"/home/\xff"), Err(Errno::ENODEV));
    }

    #[test]
    fn device_path_parse_rejects_non_device_paths() {
        let input = CString::new("/home/user/file").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe_ffi!({
            assert_eq!(
                rs_device_path_parse_major_minor(input.as_ptr(), ptr::null_mut(), ptr::null_mut()),
                Errno::ENODEV.to_neg_errno()
            );
        })
    }

    #[test]
    fn device_path_make_major_minor_builds_expected_paths() {
        let mut out = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe_ffi!({
            assert_eq!(
                rs_device_path_make_major_minor(S_IFBLK, makedev(8, 2), &mut out),
                0
            );
            assert_eq!(CStr::from_ptr(out).to_str().unwrap(), "/dev/block/8:2");
        })
    }

    #[test]
    fn device_path_make_inaccessible_builds_expected_paths() {
        let mut out = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe_ffi!({
            assert_eq!(rs_device_path_make_inaccessible(S_IFCHR, &mut out), 0);
            assert_eq!(
                CStr::from_ptr(out).to_str().unwrap(),
                "/run/systemd/inaccessible/chr"
            );
        })
    }
}
