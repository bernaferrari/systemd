// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/sysctl-util.c (sysctl_normalize)
//
// Sysctl path normalization utility.

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
