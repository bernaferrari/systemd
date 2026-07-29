// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.sysctl-util; authority=src/basic/sysctl-util.c,src/basic/sysctl-util.h
//
// Sysctl path normalization utility.

use std::ffi::{CStr, c_char};

// ── Internal helpers ────────────────────────────────────────────────────

/// Simplify a path: collapse duplicate slashes, remove trailing slashes.
fn path_simplify(s: &str) -> String {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len == 0 {
        return String::new();
    }

    let absolute = bytes[0] == b'/';
    let mut result = Vec::with_capacity(len);
    if absolute {
        result.push(b'/');
    }

    let mut i = if absolute { 1 } else { 0 };
    let mut add_slash = false;

    while i < len {
        // Skip slashes
        while i < len && bytes[i] == b'/' {
            i += 1;
        }
        if i >= len {
            break;
        }

        // Find end of component
        let start = i;
        while i < len && bytes[i] != b'/' {
            i += 1;
        }
        let component = &bytes[start..i];

        // Skip "." components
        if component == b"." {
            add_slash = true;
            continue;
        }

        // Skip ".." at beginning of absolute path
        if component == b".." && absolute && result.len() == 1 {
            add_slash = true;
            continue;
        }

        if add_slash {
            result.push(b'/');
        }

        result.extend_from_slice(component);
        add_slash = true;
    }

    if result.is_empty() {
        result.push(b'.');
    }

    String::from_utf8(result).unwrap_or_else(|_| ".".to_string())
}

// ── Public API ──────────────────────────────────────────────────────────

/// Return the first byte after a run of `/` and `./` path separators.
///
/// This is the byte-for-byte rule used by `path_find_first_component()` for
/// the `path_simplify()` call in `sysctl_normalize()`.
fn skip_slash_or_dot(bytes: &[u8], mut cursor: usize, end: usize) -> usize {
    while cursor < end {
        if bytes[cursor] == b'/' {
            cursor += 1;
        } else if bytes[cursor] == b'.' && cursor + 1 < end && bytes[cursor + 1] == b'/' {
            cursor += 1;
        } else {
            break;
        }
    }
    cursor
}

/// In-place `path_simplify(path)` for a single NUL-terminated byte buffer.
///
/// The broader path facade has its own public ABI, but sysctl normalization
/// needs this exact C helper behavior locally: in particular, a component
/// longer than `NAME_MAX` copies the remaining original bytes unchanged, and
/// only a complete leading `..` component is discarded from an absolute path.
fn simplify_path_in_place(bytes: &mut [u8]) {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .expect("C-string boundary includes a terminator");
    if end == 0 {
        return;
    }

    let absolute = bytes[0] == b'/';
    let mut write = usize::from(absolute);
    let mut cursor = write;
    let mut add_slash = false;
    let mut beginning = true;

    loop {
        let first = skip_slash_or_dot(bytes, cursor, end);
        if first == end {
            break;
        }
        if first + 1 == end && bytes[first] == b'.' {
            break;
        }

        let mut component_end = first;
        while component_end < end && bytes[component_end] != b'/' {
            component_end += 1;
        }
        let component_len = component_end - first;

        // This is C's path_find_first_component() error path. It copies from
        // the pre-skip cursor, retaining any original separators and dots.
        if component_len > libc::NAME_MAX as usize {
            if add_slash {
                bytes[write] = b'/';
                write += 1;
            }
            bytes.copy_within(cursor..=end, write);
            return;
        }

        let next = skip_slash_or_dot(bytes, component_end, end);
        cursor = if next < end && next + 1 == end && bytes[next] == b'.' {
            next + 1
        } else {
            next
        };

        // `path_startswith(e, "..")` in C compares complete components, not
        // the `..` prefix of an ordinary component such as `...`.
        if absolute && beginning && component_len == 2 && &bytes[first..component_end] == b".." {
            continue;
        }

        beginning = false;
        if add_slash {
            bytes[write] = b'/';
            write += 1;
        }
        bytes.copy_within(first..component_end, write);
        write += component_len;
        add_slash = true;
    }

    if write == 0 {
        bytes[write] = b'.';
        write += 1;
    }
    bytes[write] = 0;
}

/// C ABI mirror of `sysctl_normalize()`.
///
/// # Safety
/// `s` must be a non-null, writable, NUL-terminated C byte string whose full
/// current extent remains writable. The function modifies that storage in
/// place, preserves opaque non-UTF-8 bytes, and returns the original pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sysctl_normalize(s: *mut c_char) -> *mut c_char {
    // `sysctl_normalize()` has the same assert(s) precondition. Keeping this
    // assertion makes a violated C contract terminate rather than inventing a
    // nullable success case at the ABI boundary.
    assert!(!s.is_null());

    // SAFETY: the entry contract guarantees a live NUL-terminated C string.
    let length = unsafe { CStr::from_ptr(s).to_bytes().len() };
    // SAFETY: the entry contract makes the entire current C-string extent
    // writable, including its terminating NUL byte.
    let bytes = unsafe { std::slice::from_raw_parts_mut(s.cast::<u8>(), length + 1) };
    let swap_separators = bytes[..length]
        .iter()
        .find(|&&byte| matches!(byte, b'/' | b'.'))
        == Some(&b'.');

    if swap_separators {
        for byte in &mut bytes[..length] {
            *byte = match *byte {
                b'.' => b'/',
                b'/' => b'.',
                _ => *byte,
            };
        }
    }

    simplify_path_in_place(bytes);

    // C uses memmove(s, s + 1, strlen(s)) so the copied range includes the
    // terminating NUL while retaining the original allocation and pointer.
    let simplified_length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .expect("path simplification preserves the C-string terminator");
    if bytes[0] == b'/' && simplified_length > 1 {
        bytes.copy_within(1..=simplified_length, 0);
    }

    s
}

/// Normalize a sysctl path string.
///
/// If the first separator found is a dot (`.`), swaps all dots and slashes.
/// Then simplifies the path (collapsing duplicate slashes, removing trailing
/// slashes) and removes a leading slash if present.
///
/// Returns the normalized path.
pub fn sysctl_normalize(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }

    // Find first occurrence of '/' or '.'
    let mut first_sep: Option<u8> = None;
    for &b in s.as_bytes() {
        if b == b'/' || b == b'.' {
            first_sep = Some(b);
            break;
        }
    }

    let mut chars: Vec<u8> = s.bytes().collect();

    // If first separator is a dot, swap dots and slashes throughout
    if let Some(sep) = first_sep {
        if sep == b'.' {
            for b in &mut chars {
                if *b == b'.' {
                    *b = b'/';
                } else if *b == b'/' {
                    *b = b'.';
                }
            }
        }
    }

    let swapped = String::from_utf8(chars).unwrap_or_default();
    let mut simplified = path_simplify(&swapped);

    // Remove leading slash if present (and not the only character)
    let sbytes = simplified.as_bytes();
    if sbytes.len() > 1 && sbytes[0] == b'/' {
        simplified.remove(0);
    }

    simplified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_already_normalized() {
        assert_eq!(sysctl_normalize("kernel/hostname"), "kernel/hostname");
    }

    #[test]
    fn test_dot_separators() {
        assert_eq!(sysctl_normalize("kernel.hostname"), "kernel/hostname");
    }

    #[test]
    fn test_mixed_separators() {
        assert_eq!(
            sysctl_normalize("net.ipv4.conf.all.forwarding"),
            "net/ipv4/conf/all/forwarding"
        );
    }

    #[test]
    fn test_empty() {
        assert_eq!(sysctl_normalize(""), "");
    }

    #[test]
    fn test_single_component() {
        assert_eq!(sysctl_normalize("kernel"), "kernel");
    }

    #[test]
    fn test_leading_slash() {
        assert_eq!(sysctl_normalize("/kernel/hostname"), "kernel/hostname");
    }

    #[test]
    fn test_double_slash() {
        assert_eq!(sysctl_normalize("kernel//hostname"), "kernel/hostname");
    }

    #[test]
    fn test_slash_first_no_swap() {
        // First separator is '/', so no swap happens
        assert_eq!(sysctl_normalize("net/ipv4.conf.all"), "net/ipv4.conf.all");
    }

    #[test]
    fn test_trailing_slash() {
        assert_eq!(sysctl_normalize("kernel.hostname."), "kernel/hostname");
    }

    #[test]
    fn test_only_slash() {
        assert_eq!(sysctl_normalize("/"), "/");
    }

    #[test]
    fn test_only_dots() {
        assert_eq!(sysctl_normalize("..."), "/");
    }

    #[test]
    fn test_deep_path() {
        assert_eq!(
            sysctl_normalize("net.ipv4.conf.eth0.forwarding"),
            "net/ipv4/conf/eth0/forwarding"
        );
    }

    #[test]
    fn test_dot_swap_with_embedded_slash() {
        // First sep is '.', so dots→slashes and slashes→dots
        assert_eq!(sysctl_normalize("a.b/c"), "a/b.c");
    }
}
