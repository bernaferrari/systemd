// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/util.c
//
// Boot utility functions: path separator conversion, command-line
// sanitisation, insertion sort, URL path replacement, ASCII checks,
// whitespace classification, and boot-count stripping.

// ── Whitespace classification ────────────────────────────────────────────

/// Returns true for control characters and DEL.
/// Mirrors `shall_be_whitespace()` in util.c: c ≤ 0x20 || c == 0x7F.
pub fn shall_be_whitespace(c: u16) -> bool {
    c <= 0x20 || c == 0x7F
}

// ── ASCII check ─────────────────────────────────────────────────────────

/// Returns true when every u16 code-point is ≤ 127.
/// Mirrors `is_ascii()` in util.c.
pub fn is_ascii(s: &[u16]) -> bool {
    s.iter().all(|&c| c <= 127)
}

// ── EFI path conversion ─────────────────────────────────────────────────

/// Convert forward-slashes to backslashes and collapse consecutive
/// backslashes in a UTF-16 path buffer.
/// Mirrors `convert_efi_path()` in util.c.
pub fn convert_efi_path(path: &mut Vec<u16>) {
    let src = path.clone();
    let mut fixed = 0usize;
    for &ch in &src {
        path[fixed] = if ch == b'/' as u16 { '\\' as u16 } else { ch };

        if fixed > 0 && path[fixed - 1] == '\\' as u16 && path[fixed] == '\\' as u16 {
            continue; // collapse double backslash
        }

        if ch == 0 {
            path.truncate(fixed + 1);
            return;
        }
        fixed += 1;
    }
    path.truncate(fixed);
}

// ── Command-line sanitisation ────────────────────────────────────────────

/// Strip leading/trailing whitespace and collapse internal runs of
/// whitespace to single ASCII space characters.
/// Mirrors `mangle_stub_cmdline()` in util.c.
pub fn mangle_stub_cmdline(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut last_non_ws = 0usize;
    let mut prev_was_ws = false;

    let mut chars = input.chars().peekable();
    while chars.peek().is_some_and(|c| shall_be_whitespace(*c as u16)) {
        chars.next();
    }

    for ch in chars {
        if shall_be_whitespace(ch as u16) {
            if !prev_was_ws {
                result.push(' ');
                prev_was_ws = true;
            }
        } else {
            result.push(ch);
            last_non_ws = result.len();
            prev_was_ws = false;
        }
    }

    result.truncate(last_non_ws);
    result
}

// ── Insertion sort ───────────────────────────────────────────────────────

/// Stable insertion sort using a C-style comparator returning <0, 0, >0.
/// Mirrors `sort_pointer_array()` in util.c.
pub fn sort_pointer_array<T, F>(array: &mut [T], mut compare: F)
where
    F: FnMut(&T, &T) -> i32,
{
    if array.len() <= 1 {
        return;
    }
    for i in 1..array.len() {
        let mut j = i;
        while j > 0 && compare(&array[j - 1], &array[j]) > 0 {
            array.swap(j - 1, j);
            j -= 1;
        }
    }
}

// ── URL last-component replacement ───────────────────────────────────────

/// Replace the last path component of *url* with *filename*.
/// Mirrors `url_replace_last_component()` in util.c.
///
/// Returns `None` when the URL cannot be parsed or has no replaceable
/// component.
pub fn url_replace_last_component(url: &str, filename: &str) -> Option<String> {
    let bytes = url.as_bytes();

    let colon_pos = url.find(':')?;
    if colon_pos == 0 {
        return None;
    }
    let mut idx = colon_pos + 1;

    while idx < bytes.len() && bytes[idx] == b'/' {
        idx += 1;
    }

    let host_start = idx;
    while idx < bytes.len() && bytes[idx] != b'/' && bytes[idx] != b'?' && bytes[idx] != b'#' {
        idx += 1;
    }
    if idx - host_start == 0 {
        return None;
    }

    let path_start = idx;

    let mut path_end = path_start;
    while path_end < bytes.len() && bytes[path_end] != b'?' && bytes[path_end] != b'#' {
        path_end += 1;
    }

    let mut last_slash = None;
    for (i, byte) in bytes.iter().enumerate().take(path_end).skip(path_start) {
        if *byte == b'/' {
            last_slash = Some(i);
        }
    }

    let cut = match last_slash {
        Some(i) => i + 1,
        None => path_start,
    };

    Some(format!("{}{}", &url[..cut], filename))
}

// ── Boot-count removal ───────────────────────────────────────────────────

/// Parse a decimal number at the start of *s*, returning its byte length.
fn parse_number_len(s: &str) -> Option<usize> {
    let len = s.chars().take_while(|c| c.is_ascii_digit()).count();
    if len == 0 { None } else { Some(len) }
}

/// Remove a boot-count suffix such as `+3` or `+3-1` from a path.
/// The suffix must be followed by end-of-string or `.` to be removed.
/// Mirrors `remove_boot_count()` in util.c.
pub fn remove_boot_count(path: &mut String) {
    let plus_pos = match path.find('+') {
        Some(p) => p,
        None => return,
    };

    let after_plus = &path[plus_pos + 1..];
    let num1_len = match parse_number_len(after_plus) {
        Some(l) => l,
        None => return,
    };

    let mut end_of_match = plus_pos + 1 + num1_len;
    let rest = &path[end_of_match..];

    // Optional `-N` suffix
    if let Some(after_dash) = rest.strip_prefix('-') {
        match parse_number_len(after_dash) {
            Some(l) => end_of_match += 1 + l,
            None => return,
        }
    }

    let rest = &path[end_of_match..];
    if !rest.is_empty() && !rest.starts_with('.') {
        return;
    }

    path.replace_range(plus_pos..end_of_match, "");
}

// ── xstr8-to-path (simplified) ───────────────────────────────────────────

/// Convert a Rust string to an EFI-style path (backslash separators,
/// no consecutive backslashes).
/// Mirrors `xstr8_to_path()` + `convert_efi_path()` in util.c.
pub fn xstr8_to_path(input: &str) -> Vec<u16> {
    let mut path: Vec<u16> = input.encode_utf16().collect();
    path.push(0); // null terminator
    convert_efi_path(&mut path);
    path
}

// ── String-vector free (no-op in Rust) ───────────────────────────────────

/// In C, `strv_free()` iterates and frees every string. In Rust the
/// `Drop` impl handles this automatically; the function is kept as a
/// named API for callers that need explicit cleanup signalling.
pub fn strv_free(_v: Vec<String>) {
    // Vec<String> drops all contents automatically.
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shall_be_whitespace() {
        assert!(shall_be_whitespace(0x00)); // NUL
        assert!(shall_be_whitespace(0x09)); // TAB
        assert!(shall_be_whitespace(0x0A)); // LF
        assert!(shall_be_whitespace(0x20)); // SPACE
        assert!(shall_be_whitespace(0x7F)); // DEL
        assert!(!shall_be_whitespace(0x21)); // '!'
        assert!(!shall_be_whitespace(0x41)); // 'A'
        assert!(!shall_be_whitespace(0x80));
    }

    #[test]
    fn test_is_ascii() {
        assert!(is_ascii(&[65, 66, 0])); // "AB\0"
        assert!(is_ascii(&[]));
        assert!(!is_ascii(&[65, 200, 0]));
        assert!(is_ascii(&[0x7F]));
        assert!(!is_ascii(&[0x80]));
    }

    #[test]
    fn test_convert_efi_path() {
        let mut p: Vec<u16> = "a/b/c".encode_utf16().chain(std::iter::once(0)).collect();
        convert_efi_path(&mut p);
        let s: String = p.iter().map(|&c| c as u8 as char).collect();
        assert_eq!(s, "a\\b\\c\0");

        // Collapse double backslash
        let mut p2: Vec<u16> = "a//b".encode_utf16().chain(std::iter::once(0)).collect();
        convert_efi_path(&mut p2);
        let s2: String = p2.iter().map(|&c| c as u8 as char).collect();
        assert_eq!(s2, "a\\b\0");

        // Already backslash stays
        let mut p3: Vec<u16> = "a\\b".encode_utf16().chain(std::iter::once(0)).collect();
        convert_efi_path(&mut p3);
        let s3: String = p3.iter().map(|&c| c as u8 as char).collect();
        assert_eq!(s3, "a\\b\0");
    }

    #[test]
    fn test_mangle_stub_cmdline() {
        assert_eq!(mangle_stub_cmdline("  hello  world  "), "hello world");
        assert_eq!(mangle_stub_cmdline("single"), "single");
        assert_eq!(mangle_stub_cmdline("   "), "");
        assert_eq!(mangle_stub_cmdline(""), "");
        assert_eq!(mangle_stub_cmdline("a\tb\nc"), "a b c");
    }

    #[test]
    fn test_sort_pointer_array() {
        let mut v = vec![3, 1, 4, 1, 5, 9, 2, 6];
        sort_pointer_array(&mut v, |a, b| a.cmp(b) as i32);
        assert_eq!(v, vec![1, 1, 2, 3, 4, 5, 6, 9]);

        let mut v2: Vec<i32> = vec![];
        sort_pointer_array(&mut v2, |a, b| a.cmp(b) as i32);
        assert!(v2.is_empty());

        let mut v3 = vec![42];
        sort_pointer_array(&mut v3, |a, b| a.cmp(b) as i32);
        assert_eq!(v3, vec![42]);
    }

    #[test]
    fn test_url_replace_last_component() {
        assert_eq!(
            url_replace_last_component("file:///path/to/old.txt", "new.txt"),
            Some("file:///path/to/new.txt".into())
        );
        assert_eq!(
            url_replace_last_component("http://host/dir/file", "other"),
            Some("http://host/dir/other".into())
        );
        assert_eq!(
            url_replace_last_component("http://host/dir/file?q=1", "other"),
            Some("http://host/dir/other".into())
        );
        assert_eq!(url_replace_last_component("noscheme", "x"), None);
        assert_eq!(url_replace_last_component(":nocolonprefix", "x"), None);
    }

    #[test]
    fn test_url_replace_last_component_trailing_slash() {
        assert_eq!(
            url_replace_last_component("http://host/dir/sub/", "file"),
            Some("http://host/dir/sub/file".into())
        );
    }

    #[test]
    fn test_remove_boot_count() {
        let mut s = String::from("kernel+1.efi");
        remove_boot_count(&mut s);
        assert_eq!(s, "kernel.efi");

        let mut s2 = String::from("kernel+3-2.efi");
        remove_boot_count(&mut s2);
        assert_eq!(s2, "kernel.efi");

        let mut s3 = String::from("kernel.efi");
        remove_boot_count(&mut s3);
        assert_eq!(s3, "kernel.efi"); // no +, unchanged

        let mut s4 = String::from("kernel+abc.efi");
        remove_boot_count(&mut s4);
        assert_eq!(s4, "kernel+abc.efi"); // not a number after +
    }

    #[test]
    fn test_remove_boot_count_trailing_text() {
        let mut s = String::from("kernel+1x.efi");
        remove_boot_count(&mut s);
        assert_eq!(s, "kernel+1x.efi"); // 'x' is not '.' or end
    }

    #[test]
    fn test_xstr8_to_path() {
        let path = xstr8_to_path("a/b/c");
        let decoded: String = path[..path.len().saturating_sub(1)]
            .iter()
            .map(|&c| {
                if c == 0 {
                    '\0'
                } else {
                    char::from_u32(c as u32).unwrap_or('?')
                }
            })
            .collect();
        assert_eq!(decoded, "a\\b\\c");
    }

    #[test]
    fn test_strv_free_noop() {
        let v = vec!["a".into(), "b".into()];
        strv_free(v); // must not panic
    }
}
