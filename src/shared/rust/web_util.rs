// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/web-util.c
//
// URL validation utilities for HTTP, file, and documentation URLs.

pub fn http_etag_is_valid(etag: &str) -> bool {
    if etag.is_empty() || !etag.ends_with('"') {
        return false;
    }
    etag.starts_with('"') || etag.starts_with("W/\"")
}

pub fn http_url_is_valid(url: &str) -> bool {
    let rest = match url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    {
        Some(r) => r,
        None => return false,
    };
    !rest.is_empty() && rest.is_ascii() && !rest.contains('\0')
}

pub fn file_url_is_valid(url: &str) -> bool {
    let rest = match url.strip_prefix("file:/") {
        Some(r) => r,
        None => return false,
    };
    !rest.is_empty() && rest.is_ascii()
}

pub fn documentation_url_is_valid(url: &str) -> bool {
    if http_url_is_valid(url) || file_url_is_valid(url) {
        return true;
    }
    let rest = match url
        .strip_prefix("info:")
        .or_else(|| url.strip_prefix("man:"))
    {
        Some(r) => r,
        None => return false,
    };
    !rest.is_empty() && rest.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_etag_is_valid() {
        assert!(http_etag_is_valid("\"abc123\""));
        assert!(http_etag_is_valid("W/\"abc123\""));
        assert!(!http_etag_is_valid(""));
        assert!(!http_etag_is_valid("abc123"));
        assert!(!http_etag_is_valid("\"abc123"));
        assert!(!http_etag_is_valid("abc123\""));
    }

    #[test]
    fn test_http_url_is_valid() {
        assert!(http_url_is_valid("http://example.com"));
        assert!(http_url_is_valid("https://example.com/path"));
        assert!(!http_url_is_valid(""));
        assert!(!http_url_is_valid("ftp://example.com"));
        assert!(!http_url_is_valid("http://"));
        assert!(!http_url_is_valid("just-text"));
        assert!(!http_url_is_valid("http://example.com/\0"));
    }

    #[test]
    fn test_http_url_non_ascii_rejected() {
        assert!(!http_url_is_valid(
            "http://example.com/\u{65e5}\u{672c}\u{8a9e}"
        ));
    }

    #[test]
    fn test_file_url_is_valid() {
        assert!(file_url_is_valid("file:///etc/fstab"));
        assert!(file_url_is_valid("file:/etc/fstab"));
        assert!(!file_url_is_valid(""));
        assert!(!file_url_is_valid("http://example.com"));
        assert!(!file_url_is_valid("file:/"));
    }

    #[test]
    fn test_documentation_url_is_valid() {
        assert!(documentation_url_is_valid("https://example.com/docs"));
        assert!(documentation_url_is_valid("file:///etc/fstab"));
        assert!(documentation_url_is_valid("info:systemd"));
        assert!(documentation_url_is_valid("man:systemd(1)"));
        assert!(!documentation_url_is_valid(""));
        assert!(!documentation_url_is_valid("ftp://example.com"));
        assert!(!documentation_url_is_valid("info:"));
        assert!(!documentation_url_is_valid("man:"));
    }
}
