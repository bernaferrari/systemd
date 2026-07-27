// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/nulstr-util.c, src/basic/nulstr-util.h
//
// NUL-terminated string list utilities.
// Pure Rust — no FFI.

// ── nulstr_get ────────────────────────────────────────────────────────────

/// Search a NUL-terminated string list for `needle`.
///
/// Faithful to `const char* nulstr_get(const char *nulstr, const char *needle)` in nulstr-util.c.
/// The input `nulstr` is a sequence of NUL-terminated strings, ending with an empty string
/// (i.e., two consecutive NUL bytes). Returns `Some(index)` of the matching string's byte offset,
/// or `None` if not found.
pub fn nulstr_get(nulstr: &[u8], needle: &[u8]) -> Option<usize> {
    if nulstr.is_empty() {
        return None;
    }

    let mut pos = 0;
    while pos < nulstr.len() {
        let end = memchr(nulstr, 0, pos);
        if end == pos {
            break;
        }
        if end <= nulstr.len() {
            let entry = &nulstr[pos..end];
            if entry == needle {
                return Some(pos);
            }
        }
        pos = end + 1;
    }

    None
}

// ── nulstr_contains ───────────────────────────────────────────────────────

/// Check if a NUL-terminated string list contains `needle`.
///
/// Faithful to `static inline bool nulstr_contains(const char *nulstr, const char *needle)`
/// in nulstr-util.h: `return nulstr_get(nulstr, needle);`
pub fn nulstr_contains(nulstr: &[u8], needle: &[u8]) -> bool {
    nulstr_get(nulstr, needle).is_some()
}

// ── strv_parse_nulstr_full ────────────────────────────────────────────────

/// Parse a NUL-separated byte buffer into a vector of byte slices.
///
/// Faithful to `char** strv_parse_nulstr_full(const char *s, size_t l, bool drop_trailing_nuls)`
/// in nulstr-util.c. Returns a vector of byte slices (each string without its NUL terminator).
/// Unlike a traditional nulstr, this parser accepts embedded empty strings.
///
/// # Arguments
/// * `s` - The byte buffer to parse
/// * `drop_trailing_nuls` - If true, trailing NUL bytes are stripped before parsing
///
/// # Returns
/// A vector of byte slices borrowed from the input
pub fn strv_parse_nulstr_full(s: &[u8], drop_trailing_nuls: bool) -> Vec<&[u8]> {
    let mut len = s.len();

    if drop_trailing_nuls && len > 0 {
        while len > 0 && s[len - 1] == 0 {
            len -= 1;
        }
    }

    if len == 0 {
        return Vec::new();
    }

    let slice = &s[..len];

    let mut count = 0usize;
    for &b in slice {
        if b == 0 {
            count += 1;
        }
    }
    if slice[len - 1] != 0 {
        count += 1;
    }

    let mut result = Vec::with_capacity(count);
    let mut p = 0;
    while p < len {
        let e = memchr(slice, 0, p);
        let elem_end = if e <= len { e } else { len };
        result.push(&slice[p..elem_end]);
        if e > len {
            break;
        }
        p = e + 1;
    }

    result
}

/// Convenience wrapper for `strv_parse_nulstr_full` without dropping trailing NULs.
///
/// Faithful to `static inline char** strv_parse_nulstr(const char *s, size_t l)`.
pub fn strv_parse_nulstr(s: &[u8]) -> Vec<&[u8]> {
    strv_parse_nulstr_full(s, false)
}

// ── strv_split_nulstr ─────────────────────────────────────────────────────

/// Split a NUL-terminated string list into a vector of byte slices.
///
/// Faithful to `char** strv_split_nulstr(const char *s)` in nulstr-util.c.
/// Unlike `strv_parse_nulstr`, this stops at an empty string (which is the
/// traditional NULSTR_FOREACH end marker). Cannot parse embedded empty strings.
pub fn strv_split_nulstr(s: &[u8]) -> Vec<&[u8]> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < s.len() {
        let end = memchr(s, 0, pos);
        if end == pos {
            break;
        }
        if end > s.len() {
            break;
        }
        result.push(&s[pos..end]);
        pos = end + 1;
    }

    result
}

// ── strv_make_nulstr ──────────────────────────────────────────────────────

/// Build a NUL-terminated string list from a slice of byte slices.
///
/// Faithful to `int strv_make_nulstr(char * const *l, char **ret, size_t *ret_size)`
/// in nulstr-util.c. Returns the nulstr buffer and its size (excluding the trailing NUL).
/// An extra NUL byte is appended but not counted in the size.
pub fn strv_make_nulstr(strings: &[&[u8]]) -> (Vec<u8>, usize) {
    let mut buf = Vec::new();

    for s in strings {
        buf.extend_from_slice(s);
        buf.push(0);
    }

    let size = buf.len();

    // Append extra NUL as end marker (not counted in size)
    if !buf.is_empty() {
        buf.push(0);
    } else {
        // Return buffer with two trailing NULs for consistency with C behavior
        buf = vec![0, 0];
    }

    (buf, size)
}

/// Find the index of byte `c` in `data` starting from position `start`.
/// Returns `data.len() + 1` if not found (mimicking C pointer arithmetic where
/// memchr returns NULL and the caller checks against end boundary).
fn memchr(data: &[u8], c: u8, start: usize) -> usize {
    let mut i = start;
    while i < data.len() {
        if data[i] == c {
            return i;
        }
        i += 1;
    }
    data.len() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nulstr_get_empty_nulstr() {
        assert!(nulstr_get(b"", b"foo").is_none());
    }

    #[test]
    fn test_nulstr_get_terminator_only() {
        assert!(nulstr_get(b"\0", b"foo").is_none());
    }

    #[test]
    fn test_nulstr_get_found_first() {
        let nulstr = b"foo\0bar\0baz\0";
        let result = nulstr_get(nulstr, b"foo");
        assert_eq!(result, Some(0));
        assert_eq!(&nulstr[result.unwrap()..result.unwrap() + 3], b"foo");
    }

    #[test]
    fn test_nulstr_get_found_middle() {
        let nulstr = b"foo\0bar\0baz\0";
        let result = nulstr_get(nulstr, b"bar");
        assert!(result.is_some());
        let pos = result.unwrap();
        assert_eq!(&nulstr[pos..pos + 3], b"bar");
    }

    #[test]
    fn test_nulstr_get_found_last() {
        let nulstr = b"foo\0bar\0baz\0";
        let result = nulstr_get(nulstr, b"baz");
        assert!(result.is_some());
        let pos = result.unwrap();
        assert_eq!(&nulstr[pos..pos + 3], b"baz");
    }

    #[test]
    fn test_nulstr_get_not_found() {
        assert!(nulstr_get(b"foo\0bar\0baz\0", b"qux").is_none());
    }

    #[test]
    fn test_nulstr_get_single_entry() {
        let result = nulstr_get(b"only\0", b"only");
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_nulstr_get_partial_match_not_found() {
        assert!(nulstr_get(b"foo\0foobar\0", b"fo").is_none());
    }

    #[test]
    fn test_nulstr_contains() {
        assert!(nulstr_contains(b"foo\0bar\0\0", b"foo"));
        assert!(nulstr_contains(b"foo\0bar\0\0", b"bar"));
        assert!(!nulstr_contains(b"foo\0bar\0\0", b"baz"));
        assert!(!nulstr_contains(b"\0", b""));
    }

    #[test]
    fn test_strv_parse_nulstr_full_empty() {
        let result = strv_parse_nulstr_full(b"", false);
        assert!(result.is_empty());
    }

    #[test]
    fn test_strv_parse_nulstr_full_single_string() {
        let result = strv_parse_nulstr_full(b"hello", false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"hello");
    }

    #[test]
    fn test_strv_parse_nulstr_full_multiple_strings() {
        let nulstr = b"foo\0bar\0baz";
        let result = strv_parse_nulstr_full(nulstr, false);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
        assert_eq!(result[2], b"baz");
    }

    #[test]
    fn test_strv_parse_nulstr_full_drop_trailing_nuls() {
        let nulstr = b"foo\0bar\0\0";
        let result = strv_parse_nulstr_full(nulstr, true);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
    }

    #[test]
    fn test_strv_parse_nulstr_full_keep_trailing_nuls() {
        let nulstr = b"foo\0";
        let result = strv_parse_nulstr_full(nulstr, false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"foo");
    }

    #[test]
    fn test_strv_parse_nulstr_full_empty_strings() {
        let nulstr = b"\0\0";
        let result = strv_parse_nulstr_full(nulstr, false);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"");
        assert_eq!(result[1], b"");
    }

    #[test]
    fn test_strv_parse_nulstr_full_no_trailing_nul() {
        let nulstr = b"foo\0bar";
        let result = strv_parse_nulstr_full(nulstr, false);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
    }

    #[test]
    fn test_strv_parse_nulstr_full_drop_all_trailing() {
        let nulstr = b"\0\0";
        let result = strv_parse_nulstr_full(nulstr, true);
        assert!(result.is_empty());
    }

    #[test]
    fn test_strv_parse_nulstr_convenience() {
        let result = strv_parse_nulstr(b"foo\0bar");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
    }

    #[test]
    fn test_strv_split_nulstr_basic() {
        let nulstr = b"foo\0bar\0baz\0";
        let result = strv_split_nulstr(nulstr);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
        assert_eq!(result[2], b"baz");
    }

    #[test]
    fn test_strv_split_nulstr_stops_at_empty() {
        let nulstr = b"foo\0\0bar\0";
        let result = strv_split_nulstr(nulstr);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"foo");
    }

    #[test]
    fn test_strv_split_nulstr_empty_input() {
        let result = strv_split_nulstr(b"");
        assert!(result.is_empty());
    }

    #[test]
    fn test_strv_make_nulstr_basic() {
        let strings: &[&[u8]] = &[b"foo", b"bar", b"baz"];
        let (buf, size) = strv_make_nulstr(strings);
        assert_eq!(size, 12); // 3+1 + 3+1 + 3+1 = 12
        assert_eq!(&buf[..size], b"foo\0bar\0baz\0");
        // Extra trailing NUL
        assert_eq!(buf[size], 0);
    }

    #[test]
    fn test_strv_make_nulstr_empty_input() {
        let strings: &[&[u8]] = &[];
        let (buf, size) = strv_make_nulstr(strings);
        assert_eq!(size, 0);
        // Two trailing NULs for consistency
        assert_eq!(buf, vec![0, 0]);
    }

    #[test]
    fn test_strv_make_nulstr_roundtrip() {
        let original: &[&[u8]] = &[b"hello", b"world"];
        let (buf, _size) = strv_make_nulstr(original);
        // Parse back (without trailing NUL handling)
        let result = strv_parse_nulstr_full(&buf, false);
        // Should get our strings back plus empty entries from trailing NULs
        assert_eq!(result[0], b"hello");
        assert_eq!(result[1], b"world");
    }
}
