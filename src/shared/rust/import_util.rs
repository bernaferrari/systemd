// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/import-util.c, src/shared/import-util.h
//
// Image import utilities for systemd.
//
// Provides types and functions for handling disk image imports including
// type/verify enums with string conversion, URL path manipulation for
// image pull sources, and archive suffix stripping.
//
// NOTE: import_assign_pool_quota_and_warn() and import_set_nocow_and_log()
// require btrfs/ioctl FFI and are intentionally omitted from this safe-Rust
// module. They remain implemented in C.

use std::fmt;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Import format type for disk images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportType {
    /// Raw disk image format.
    Raw,
    /// Tar archive format.
    Tar,
    /// OCI (Open Container Initiative) image format.
    Oci,
}

impl ImportType {
    /// All valid import type variants, in canonical order.
    pub const ALL: &[ImportType] = &[ImportType::Raw, ImportType::Tar, ImportType::Oci];
    /// Total number of valid variants.
    pub const COUNT: usize = 3;
}

impl fmt::Display for ImportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportType::Raw => write!(f, "raw"),
            ImportType::Tar => write!(f, "tar"),
            ImportType::Oci => write!(f, "oci"),
        }
    }
}

impl std::str::FromStr for ImportType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raw" => Ok(ImportType::Raw),
            "tar" => Ok(ImportType::Tar),
            "oci" => Ok(ImportType::Oci),
            _ => Err(()),
        }
    }
}

/// Import verification mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportVerify {
    /// No verification.
    No,
    /// Verify via checksum.
    Checksum,
    /// Verify via cryptographic signature.
    Signature,
}

impl ImportVerify {
    /// All valid import verify variants, in canonical order.
    pub const ALL: &[ImportVerify] = &[
        ImportVerify::No,
        ImportVerify::Checksum,
        ImportVerify::Signature,
    ];
    /// Total number of valid variants.
    pub const COUNT: usize = 3;
}

impl fmt::Display for ImportVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportVerify::No => write!(f, "no"),
            ImportVerify::Checksum => write!(f, "checksum"),
            ImportVerify::Signature => write!(f, "signature"),
        }
    }
}

impl std::str::FromStr for ImportVerify {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "no" => Ok(ImportVerify::No),
            "checksum" => Ok(ImportVerify::Checksum),
            "signature" => Ok(ImportVerify::Signature),
            _ => Err(()),
        }
    }
}

// ── URL Utilities ─────────────────────────────────────────────────────────

/// A very lenient implementation of RFC 3986 Section 3.2.
///
/// Skips past the protocol scheme and authority (hostname) portion of a URL,
/// returning the byte offset where the path component begins (i.e. the position
/// of the first `/`, `?`, or `#` after the host).  Returns `None` if the URL
/// lacks a recognizable `scheme:` prefix or has an empty host.
fn skip_protocol_and_hostname(url: &str) -> Option<usize> {
    let colon = url.find(':')?;
    if colon == 0 {
        return None;
    }

    // Advance past the colon, then skip '/' characters (e.g. "://").
    let rest = &url[colon + 1..];
    let slash_len = rest.len() - rest.trim_start_matches('/').len();
    let after_slashes = colon + 1 + slash_len;

    // Scan for the first path / query / fragment delimiter.
    let remaining = &url[after_slashes..];
    let delimiter = remaining.find(|c| c == '/' || c == '?' || c == '#');
    let host_end = match delimiter {
        Some(p) => after_slashes + p,
        None => url.len(),
    };

    if host_end <= after_slashes {
        return None;
    }

    Some(host_end)
}

/// Extracts the last path component of a URL, per RFC 3986.
///
/// Returns the last non-empty substring between `/` characters in the path
/// portion of *url*, ignoring any Query (`?…`) or Fragment (`#…`) suffixes.
///
/// Returns `None` when the URL has no recognizable scheme/host or the path
/// contains no non-empty component.
pub fn import_url_last_component(url: &str) -> Option<&str> {
    let path_start = skip_protocol_and_hostname(url)?;
    let path = &url[path_start..];

    // Strip Query and Fragment.
    let path_end = path.find(|c| c == '?' || c == '#').unwrap_or(path.len());
    let trimmed = path[..path_end].trim_end_matches('/');

    if trimmed.is_empty() {
        return None;
    }

    match trimmed.rfind('/') {
        Some(slash) => {
            let component = &trimmed[slash + 1..];
            if component.is_empty() {
                None
            } else {
                Some(component)
            }
        }
        None => Some(trimmed),
    }
}

/// Drops `n_drop` trailing path components from *url*, then appends *suffix*
/// (separated by `/`).
///
/// Query and Fragment portions are stripped and **not** re-added.
/// When `n_drop` is zero the suffix is simply appended; when `suffix` is
/// `None` nothing is appended (only components are dropped).  If more
/// components are requested than exist, all are silently dropped and the
/// suffix is appended to the scheme+authority.
///
/// Returns `None` when *url* has no recognizable scheme/host.
pub fn import_url_change_suffix(url: &str, n_drop: usize, suffix: Option<&str>) -> Option<String> {
    let path_start = skip_protocol_and_hostname(url)?;
    let base = &url[..path_start];
    let path = &url[path_start..];

    // Strip Query and Fragment, then trailing slashes.
    let path_end = path.find(|c| c == '?' || c == '#').unwrap_or(path.len());
    let trimmed = path[..path_end].trim_end_matches('/');
    let bytes = trimmed.as_bytes();

    // Walk backward, dropping `n_drop` components.
    let mut pos = bytes.len();
    for _ in 0..n_drop {
        // Eat the last word (non-'/' characters).
        while pos > 0 && bytes[pos - 1] != b'/' {
            pos -= 1;
        }
        // Eat the slashes preceding the word.
        while pos > 0 && bytes[pos - 1] == b'/' {
            pos -= 1;
        }
    }

    let kept = &trimmed[..pos];
    let suffix_str = suffix.unwrap_or("");
    Some(format!("{base}{kept}/{suffix_str}"))
}

/// Convenience wrapper: drops exactly one trailing path component and appends
/// *suffix*.
pub fn import_url_change_last_component(url: &str, suffix: &str) -> Option<String> {
    import_url_change_suffix(url, 1, Some(suffix))
}

/// Convenience wrapper: appends *suffix* as a new path component (drops zero).
pub fn import_url_append_component(url: &str, suffix: &str) -> Option<String> {
    import_url_change_suffix(url, 0, Some(suffix))
}

// ── Suffix Stripping ──────────────────────────────────────────────────────

/// Strips recognized **tar** archive suffixes from *name*.
///
/// Recognized suffixes (checked in priority order):
/// `.tar.xz`, `.tar.gz`, `.tar.bz2`, `.tar.zst`, `.tar`, `.tgz`.
///
/// Returns the portion of *name* before the first recognized suffix, or the
/// full *name* when no suffix matches.  Returns `None` for an empty input.
pub fn tar_strip_suffixes(name: &str) -> Option<&str> {
    if name.is_empty() {
        return None;
    }

    const SUFFIXES: &[&str] = &[".tar.xz", ".tar.gz", ".tar.bz2", ".tar.zst", ".tar", ".tgz"];

    for suffix in SUFFIXES {
        if let Some(stripped) = name.strip_suffix(suffix) {
            if !stripped.is_empty() {
                return Some(stripped);
            }
        }
    }

    Some(name)
}

/// Iteratively strips recognized **raw disk image** suffixes from *name*.
///
/// The following suffixes are stripped repeatedly until none remain:
/// `.xz`, `.gz`, `.bz2`, `.zst`, `.sysext.raw`, `.confext.raw`,
/// `.raw`, `.qcow2`, `.img`, `.bin`.
///
/// Longer suffixes (`.sysext.raw`, `.confext.raw`) are checked first within
/// each pass to avoid partial stripping.
pub fn raw_strip_suffixes(name: &str) -> String {
    const SUFFIXES: &[&str] = &[
        ".sysext.raw",
        ".confext.raw",
        ".xz",
        ".gz",
        ".bz2",
        ".zst",
        ".raw",
        ".qcow2",
        ".img",
        ".bin",
    ];

    let mut result = name.to_string();

    loop {
        let mut changed = false;
        for suffix in SUFFIXES {
            if result.ends_with(suffix) {
                let new_len = result.len() - suffix.len();
                result.truncate(new_len);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    result
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- ImportType --

    #[test]
    fn import_type_from_string_valid() {
        assert_eq!("raw".parse::<ImportType>(), Ok(ImportType::Raw));
        assert_eq!("tar".parse::<ImportType>(), Ok(ImportType::Tar));
        assert_eq!("oci".parse::<ImportType>(), Ok(ImportType::Oci));
    }

    #[test]
    fn import_type_from_string_invalid() {
        assert!("bogus".parse::<ImportType>().is_err());
        assert!("".parse::<ImportType>().is_err());
        assert!("RAW".parse::<ImportType>().is_err());
    }

    #[test]
    fn import_type_display_roundtrip() {
        for v in ImportType::ALL {
            assert_eq!(v.to_string().parse::<ImportType>(), Ok(*v));
        }
    }

    // -- ImportVerify --

    #[test]
    fn import_verify_from_string_valid() {
        assert_eq!("no".parse::<ImportVerify>(), Ok(ImportVerify::No));
        assert_eq!(
            "checksum".parse::<ImportVerify>(),
            Ok(ImportVerify::Checksum)
        );
        assert_eq!(
            "signature".parse::<ImportVerify>(),
            Ok(ImportVerify::Signature)
        );
    }

    #[test]
    fn import_verify_from_string_invalid() {
        assert!("maybe".parse::<ImportVerify>().is_err());
        assert!("".parse::<ImportVerify>().is_err());
        assert!("No".parse::<ImportVerify>().is_err());
    }

    #[test]
    fn import_verify_display_roundtrip() {
        for v in ImportVerify::ALL {
            assert_eq!(v.to_string().parse::<ImportVerify>(), Ok(*v));
        }
    }

    // -- URL last component --

    #[test]
    fn url_last_component_basic() {
        assert_eq!(
            import_url_last_component("https://example.com/path/to/image.raw"),
            Some("image.raw")
        );
    }

    #[test]
    fn url_last_component_trailing_slash() {
        assert_eq!(
            import_url_last_component("https://example.com/path/to/"),
            Some("to")
        );
    }

    #[test]
    fn url_last_component_with_query() {
        assert_eq!(
            import_url_last_component("https://example.com/path/img.raw?token=abc"),
            Some("img.raw")
        );
    }

    #[test]
    fn url_last_component_with_fragment() {
        assert_eq!(
            import_url_last_component("https://example.com/a/b.tar.gz#section"),
            Some("b.tar.gz")
        );
    }

    #[test]
    fn url_last_component_no_protocol() {
        assert!(import_url_last_component("not-a-url").is_none());
        assert!(import_url_last_component(":missing-host").is_none());
    }

    #[test]
    fn url_last_component_root_only() {
        assert!(import_url_last_component("https://example.com").is_none());
        assert!(import_url_last_component("https://example.com/").is_none());
    }

    // -- URL change suffix --

    #[test]
    fn url_change_suffix_drop_one() {
        assert_eq!(
            import_url_change_suffix("https://example.com/a/b/c", 1, Some("d")),
            Some("https://example.com/a/b/d".into())
        );
    }

    #[test]
    fn url_change_suffix_drop_zero() {
        assert_eq!(
            import_url_change_suffix("https://example.com/a/b", 0, Some("c")),
            Some("https://example.com/a/b/c".into())
        );
    }

    #[test]
    fn url_change_suffix_drop_multiple() {
        assert_eq!(
            import_url_change_suffix("https://example.com/a/b/c/d", 2, Some("e")),
            Some("https://example.com/a/b/e".into())
        );
    }

    #[test]
    fn url_change_suffix_no_suffix() {
        assert_eq!(
            import_url_change_suffix("https://example.com/a/b", 1, None),
            Some("https://example.com/a/".into())
        );
    }

    #[test]
    fn url_change_suffix_strips_query_and_fragment() {
        assert_eq!(
            import_url_change_suffix("https://example.com/a/b?q=1#x", 1, Some("c")),
            Some("https://example.com/a/c".into())
        );
    }

    #[test]
    fn url_change_suffix_drop_more_than_available() {
        assert_eq!(
            import_url_change_suffix("https://example.com/a", 5, Some("z")),
            Some("https://example.com/z".into())
        );
    }

    #[test]
    fn url_change_suffix_empty_path_drop() {
        assert_eq!(
            import_url_change_suffix("https://example.com/", 1, Some("new")),
            Some("https://example.com/new".into())
        );
    }

    #[test]
    fn url_change_last_component_convenience() {
        assert_eq!(
            import_url_change_last_component("https://example.com/old", "new"),
            Some("https://example.com/new".into())
        );
    }

    #[test]
    fn url_append_component_convenience() {
        assert_eq!(
            import_url_append_component("https://example.com/a", "b"),
            Some("https://example.com/a/b".into())
        );
    }

    // -- tar_strip_suffixes --

    #[test]
    fn tar_strip_suffixes_plain_tar() {
        assert_eq!(tar_strip_suffixes("image.tar"), Some("image"));
    }

    #[test]
    fn tar_strip_suffixes_compressed_variants() {
        assert_eq!(tar_strip_suffixes("image.tar.gz"), Some("image"));
        assert_eq!(tar_strip_suffixes("image.tar.xz"), Some("image"));
        assert_eq!(tar_strip_suffixes("image.tar.bz2"), Some("image"));
        assert_eq!(tar_strip_suffixes("image.tar.zst"), Some("image"));
    }

    #[test]
    fn tar_strip_suffixes_tgz() {
        assert_eq!(tar_strip_suffixes("image.tgz"), Some("image"));
    }

    #[test]
    fn tar_strip_suffixes_no_match() {
        assert_eq!(tar_strip_suffixes("image.raw"), Some("image.raw"));
        assert_eq!(tar_strip_suffixes("image"), Some("image"));
    }

    #[test]
    fn tar_strip_suffixes_empty() {
        assert!(tar_strip_suffixes("").is_none());
    }

    // -- raw_strip_suffixes --

    #[test]
    fn raw_strip_suffixes_basic() {
        assert_eq!(raw_strip_suffixes("image.raw"), "image");
    }

    #[test]
    fn raw_strip_suffixes_compressed() {
        assert_eq!(raw_strip_suffixes("image.raw.xz"), "image");
        assert_eq!(raw_strip_suffixes("image.raw.gz"), "image");
    }

    #[test]
    fn raw_strip_suffixes_sysext_confext() {
        assert_eq!(raw_strip_suffixes("foo.sysext.raw"), "foo");
        assert_eq!(raw_strip_suffixes("bar.confext.raw"), "bar");
    }

    #[test]
    fn raw_strip_suffixes_iterative() {
        assert_eq!(raw_strip_suffixes("image.raw.xz.gz"), "image");
    }

    #[test]
    fn raw_strip_suffixes_no_match() {
        assert_eq!(raw_strip_suffixes("image"), "image");
    }

    #[test]
    fn raw_strip_suffixes_qcow2_img_bin() {
        assert_eq!(raw_strip_suffixes("disk.qcow2"), "disk");
        assert_eq!(raw_strip_suffixes("disk.img"), "disk");
        assert_eq!(raw_strip_suffixes("firmware.bin"), "firmware");
    }
}
