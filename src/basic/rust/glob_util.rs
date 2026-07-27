// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/glob-util.c (string_is_glob, glob_non_glob_prefix)
//
// Glob pattern utility functions — pure string operations.

use crate::ffi::Errno;

const GLOB_CHARS: &[u8] = b"*?[";

/// Check if a string contains any glob pattern characters (*, ?, [).
/// Mirrors C `string_is_glob()`.
pub fn string_is_glob(s: &str) -> bool {
    s.bytes().any(|c| GLOB_CHARS.contains(&c))
}

/// Return the path prefix up to (but not including) the first glob character.
/// Walks back to the previous '/' if the glob char is in the middle of a component.
/// If no glob chars are found, returns the entire path.
/// Mirrors C `glob_non_glob_prefix()`.
pub fn glob_non_glob_prefix(path: &str) -> Result<String, Errno> {
    let bytes = path.as_bytes();

    let mut n = 0;
    for (i, &c) in bytes.iter().enumerate() {
        if c == 0 {
            break;
        }
        if GLOB_CHARS.contains(&c) {
            n = i;
            break;
        }
        n = i + 1;
    }

    if n < bytes.len() && GLOB_CHARS.contains(&bytes[n]) {
        while n > 0 && bytes[n - 1] != b'/' {
            n -= 1;
        }
    }

    if n == 0 {
        return Err(Errno::ENOENT);
    }

    Ok(path[..n].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_is_glob_star() {
        assert!(string_is_glob("*.txt"));
    }

    #[test]
    fn test_string_is_glob_question() {
        assert!(string_is_glob("file?.txt"));
    }

    #[test]
    fn test_string_is_glob_bracket() {
        assert!(string_is_glob("file[0-9].txt"));
    }

    #[test]
    fn test_string_is_glob_no_glob() {
        assert!(!string_is_glob("hello.txt"));
    }

    #[test]
    fn test_string_is_glob_empty() {
        assert!(!string_is_glob(""));
    }

    #[test]
    fn test_string_is_glob_plain() {
        assert!(!string_is_glob("filename"));
    }

    #[test]
    fn test_string_is_glob_star_only() {
        assert!(string_is_glob("*"));
    }

    #[test]
    fn test_string_is_glob_glob_at_end() {
        assert!(string_is_glob("/path/to/*"));
    }

    #[test]
    fn test_string_is_glob_glob_at_start() {
        assert!(string_is_glob("*/file.txt"));
    }

    #[test]
    fn test_string_is_glob_multiple_globs() {
        assert!(string_is_glob("foo*bar?baz[0]"));
    }

    #[test]
    fn test_glob_non_glob_prefix_no_glob() {
        let result = glob_non_glob_prefix("/path/to/file.txt").unwrap();
        assert_eq!(result, "/path/to/file.txt");
    }

    #[test]
    fn test_glob_non_glob_prefix_with_star() {
        let result = glob_non_glob_prefix("/path/to/*.txt").unwrap();
        assert_eq!(result, "/path/to/");
    }

    #[test]
    fn test_glob_non_glob_prefix_with_question() {
        let result = glob_non_glob_prefix("/path/file?.txt").unwrap();
        assert_eq!(result, "/path/");
    }

    #[test]
    fn test_glob_non_glob_prefix_with_bracket() {
        let result = glob_non_glob_prefix("/path/file[0-9].txt").unwrap();
        assert_eq!(result, "/path/");
    }

    #[test]
    fn test_glob_non_glob_prefix_star_at_start() {
        assert_eq!(glob_non_glob_prefix("*.txt"), Err(Errno::ENOENT));
    }

    #[test]
    fn test_glob_non_glob_prefix_empty_string() {
        assert_eq!(glob_non_glob_prefix(""), Err(Errno::ENOENT));
    }

    #[test]
    fn test_glob_non_glob_prefix_glob_in_middle_of_component() {
        let result = glob_non_glob_prefix("/path/ab*cd/file.txt").unwrap();
        assert_eq!(result, "/path/");
    }

    #[test]
    fn test_glob_non_glob_prefix_single_slash() {
        let result = glob_non_glob_prefix("/*").unwrap();
        assert_eq!(result, "/");
    }

    #[test]
    fn test_glob_non_glob_prefix_filename_with_star() {
        assert_eq!(glob_non_glob_prefix("file*"), Err(Errno::ENOENT));
    }

    #[test]
    fn test_glob_non_glob_prefix_deep_path() {
        let result = glob_non_glob_prefix("/a/b/c/d/e/*.conf").unwrap();
        assert_eq!(result, "/a/b/c/d/e/");
    }
}
