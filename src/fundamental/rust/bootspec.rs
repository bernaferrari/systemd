// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/bootspec.h, src/fundamental/bootspec.c
//
// Bootspec name/version/sort-key picking logic.

/// Pick the best human-readable name, version string, and sort key for a boot entry.
///
/// Returns false if no name could be determined.
///
/// Priority for name:
///   1. os_pretty_name
///   2. os_image_id
///   3. os_name
///   4. os_id
///
/// Priority for version:
///   1. os_image_version
///   2. os_version
///   3. os_version_id
///   4. os_build_id
///
/// Sort key:
///   1. os_image_id
///   2. os_id
pub fn bootspec_pick_name_version_sort_key<'a>(
    os_pretty_name: Option<&'a str>,
    os_image_id: Option<&'a str>,
    os_name: Option<&'a str>,
    os_id: Option<&'a str>,
    os_image_version: Option<&'a str>,
    os_version: Option<&'a str>,
    os_version_id: Option<&'a str>,
    os_build_id: Option<&'a str>,
) -> Option<(&'a str, Option<&'a str>, Option<&'a str>)> {
    let good_name = os_pretty_name.or(os_image_id).or(os_name).or(os_id)?;

    let good_version = os_image_version
        .or(os_version)
        .or(os_version_id)
        .or(os_build_id);

    let good_sort_key = os_image_id.or(os_id);

    Some((good_name, good_version, good_sort_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pick_pretty_name() {
        let result = bootspec_pick_name_version_sort_key(
            Some("Fedora Linux 38"),
            Some("fedora"),
            Some("Fedora Linux"),
            Some("fedora"),
            Some("38"),
            Some("38"),
            Some("38"),
            None,
        );
        assert_eq!(
            result,
            Some(("Fedora Linux 38", Some("38"), Some("fedora")))
        );
    }

    #[test]
    fn test_pick_image_id_fallback() {
        let result = bootspec_pick_name_version_sort_key(
            None,
            Some("my-image"),
            None,
            Some("my-os"),
            Some("1.0"),
            None,
            None,
            None,
        );
        assert_eq!(result, Some(("my-image", Some("1.0"), Some("my-image"))));
    }

    #[test]
    fn test_pick_no_name() {
        let result =
            bootspec_pick_name_version_sort_key(None, None, None, None, None, None, None, None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_pick_os_id_fallback() {
        let result = bootspec_pick_name_version_sort_key(
            None,
            None,
            None,
            Some("debian"),
            None,
            None,
            Some("12"),
            Some("bookworm"),
        );
        assert_eq!(result, Some(("debian", Some("12"), Some("debian"))));
    }
}
