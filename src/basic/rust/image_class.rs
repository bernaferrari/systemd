// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/os-util.c (image_class string table, os_release_pretty_name)
//
// Image class string table lookups and OS release pretty name resolution.

use crate::ffi::Errno;
use libc::c_char;

// ── ImageClass enum ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageClass {
    Machine = 0,
    Portable = 1,
    Sysext = 2,
    Confext = 3,
}

impl ImageClass {
    pub fn from_raw(val: i32) -> Option<Self> {
        match val {
            0 => Some(Self::Machine),
            1 => Some(Self::Portable),
            2 => Some(Self::Sysext),
            3 => Some(Self::Confext),
            _ => None,
        }
    }

    pub fn to_raw(self) -> i32 {
        self as i32
    }
}

// ── Image class string table ─────────────────────────────────────────────

static IMAGE_CLASS_TABLE: &[(ImageClass, &str)] = &[
    (ImageClass::Machine, "machine"),
    (ImageClass::Portable, "portable"),
    (ImageClass::Sysext, "sysext"),
    (ImageClass::Confext, "confext"),
];

// ── image_class_to_string ────────────────────────────────────────────────

/// Convert an ImageClass to its string representation.
/// Returns None for invalid values.
pub fn image_class_to_string(c: ImageClass) -> &'static str {
    IMAGE_CLASS_TABLE
        .iter()
        .find(|&&(class, _)| class == c)
        .map(|&(_, name)| name)
        .unwrap()
}

/// Convert a raw i32 to image class string.
pub fn image_class_to_string_from_raw(val: i32) -> Option<&'static str> {
    ImageClass::from_raw(val).map(image_class_to_string)
}

// ── image_class_from_string ──────────────────────────────────────────────

/// Convert a string to an ImageClass.
/// Case-sensitive. Returns Err(-EINVAL) on failure or empty input.
pub fn image_class_from_string(s: &str) -> Result<ImageClass, i32> {
    if s.is_empty() {
        return Err(Errno::EINVAL.to_neg_errno());
    }
    for &(class, name) in IMAGE_CLASS_TABLE {
        if name == s {
            return Ok(class);
        }
    }
    Err(Errno::EINVAL.to_neg_errno())
}

// ── os_release_pretty_name ───────────────────────────────────────────────

/// Resolve the display name from os-release data.
/// Returns pretty_name if non-empty, else name if non-empty, else "Linux".
/// Faithful to C os_release_pretty_name().
pub fn os_release_pretty_name<'a>(pretty_name: Option<&'a str>, name: Option<&'a str>) -> &'a str {
    let pn = pretty_name.filter(|s| !s.is_empty());
    if let Some(s) = pn {
        return s;
    }

    let n = name.filter(|s| !s.is_empty());
    if let Some(s) = n {
        return s;
    }

    "Linux"
}

/// Return the same borrowed string selected by C's `os_release_pretty_name()`.
///
/// No allocation or ownership transfer takes place: a non-empty input pointer
/// is returned verbatim, otherwise the result points at immutable static
/// storage containing `"Linux"`.
///
/// # Safety
///
/// Each non-NULL argument must point to a readable, NUL-terminated C string
/// for the duration of this call. The returned pointer is borrowed and must
/// not be freed by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_os_release_pretty_name(
    pretty_name: *const c_char,
    name: *const c_char,
) -> *const c_char {
    // SAFETY: the entry point contract guarantees that each non-NULL input is
    // readable through its first byte. C's empty_to_null() has exactly this
    // first-byte test and deliberately does not validate or copy the string.
    if !pretty_name.is_null() && unsafe { *pretty_name } != 0 {
        return pretty_name;
    }
    // SAFETY: the same entry point contract covers the independent fallback
    // input after its explicit NULL check.
    if !name.is_null() && unsafe { *name } != 0 {
        return name;
    }

    c"Linux".as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_class_to_string_all() {
        assert_eq!(image_class_to_string(ImageClass::Machine), "machine");
        assert_eq!(image_class_to_string(ImageClass::Portable), "portable");
        assert_eq!(image_class_to_string(ImageClass::Sysext), "sysext");
        assert_eq!(image_class_to_string(ImageClass::Confext), "confext");
    }

    #[test]
    fn test_image_class_to_string_from_raw_valid() {
        assert_eq!(image_class_to_string_from_raw(0), Some("machine"));
        assert_eq!(image_class_to_string_from_raw(1), Some("portable"));
        assert_eq!(image_class_to_string_from_raw(2), Some("sysext"));
        assert_eq!(image_class_to_string_from_raw(3), Some("confext"));
    }

    #[test]
    fn test_image_class_to_string_from_raw_invalid() {
        assert!(image_class_to_string_from_raw(-1).is_none());
        assert!(image_class_to_string_from_raw(4).is_none());
        assert!(image_class_to_string_from_raw(100).is_none());
        assert!(image_class_to_string_from_raw(i32::MAX).is_none());
    }

    #[test]
    fn test_image_class_from_string_all() {
        assert_eq!(image_class_from_string("machine"), Ok(ImageClass::Machine));
        assert_eq!(
            image_class_from_string("portable"),
            Ok(ImageClass::Portable)
        );
        assert_eq!(image_class_from_string("sysext"), Ok(ImageClass::Sysext));
        assert_eq!(image_class_from_string("confext"), Ok(ImageClass::Confext));
    }

    #[test]
    fn test_image_class_from_string_invalid() {
        assert_eq!(
            image_class_from_string("unknown"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            image_class_from_string(""),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            image_class_from_string("Machine"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            image_class_from_string("SYSEXT"),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }

    #[test]
    fn test_image_class_roundtrip() {
        for i in 0..=3 {
            let class = ImageClass::from_raw(i).unwrap();
            let name = image_class_to_string(class);
            let result = image_class_from_string(name).unwrap();
            assert_eq!(result, class);
        }
    }

    #[test]
    fn test_os_release_pretty_name_both_non_empty() {
        assert_eq!(os_release_pretty_name(Some("My OS"), Some("myos")), "My OS");
    }

    #[test]
    fn test_os_release_pretty_name_pretty_null() {
        assert_eq!(os_release_pretty_name(None, Some("myos")), "myos");
    }

    #[test]
    fn test_os_release_pretty_name_pretty_empty() {
        assert_eq!(os_release_pretty_name(Some(""), Some("myos")), "myos");
    }

    #[test]
    fn test_os_release_pretty_name_both_null() {
        assert_eq!(os_release_pretty_name(None, None), "Linux");
    }

    #[test]
    fn test_os_release_pretty_name_both_empty() {
        assert_eq!(os_release_pretty_name(Some(""), Some("")), "Linux");
    }

    #[test]
    fn test_os_release_pretty_name_name_null() {
        assert_eq!(os_release_pretty_name(Some("Pretty"), None), "Pretty");
    }

    #[test]
    fn test_os_release_pretty_name_name_empty_pretty_null() {
        assert_eq!(os_release_pretty_name(None, Some("")), "Linux");
    }
}
