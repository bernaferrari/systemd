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
#[derive(Debug, Clone, Copy, Default)]
pub struct BootspecMetadata<'a> {
    pub os_pretty_name: Option<&'a str>,
    pub os_image_id: Option<&'a str>,
    pub os_name: Option<&'a str>,
    pub os_id: Option<&'a str>,
    pub os_image_version: Option<&'a str>,
    pub os_version: Option<&'a str>,
    pub os_version_id: Option<&'a str>,
    pub os_build_id: Option<&'a str>,
}

pub fn bootspec_pick_name_version_sort_key(
    metadata: BootspecMetadata<'_>,
) -> Option<(&str, Option<&str>, Option<&str>)> {
    let good_name = metadata
        .os_pretty_name
        .or(metadata.os_image_id)
        .or(metadata.os_name)
        .or(metadata.os_id)?;

    let good_version = metadata
        .os_image_version
        .or(metadata.os_version)
        .or(metadata.os_version_id)
        .or(metadata.os_build_id);

    let good_sort_key = metadata.os_image_id.or(metadata.os_id);

    Some((good_name, good_version, good_sort_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pick_pretty_name() {
        let result = bootspec_pick_name_version_sort_key(BootspecMetadata {
            os_pretty_name: Some("Fedora Linux 38"),
            os_image_id: Some("fedora"),
            os_name: Some("Fedora Linux"),
            os_id: Some("fedora"),
            os_image_version: Some("38"),
            os_version: Some("38"),
            os_version_id: Some("38"),
            os_build_id: None,
        });
        assert_eq!(
            result,
            Some(("Fedora Linux 38", Some("38"), Some("fedora")))
        );
    }

    #[test]
    fn test_pick_image_id_fallback() {
        let result = bootspec_pick_name_version_sort_key(BootspecMetadata {
            os_image_id: Some("my-image"),
            os_id: Some("my-os"),
            os_image_version: Some("1.0"),
            ..Default::default()
        });
        assert_eq!(result, Some(("my-image", Some("1.0"), Some("my-image"))));
    }

    #[test]
    fn test_pick_no_name() {
        let result = bootspec_pick_name_version_sort_key(BootspecMetadata::default());
        assert_eq!(result, None);
    }

    #[test]
    fn test_pick_os_id_fallback() {
        let result = bootspec_pick_name_version_sort_key(BootspecMetadata {
            os_id: Some("debian"),
            os_version_id: Some("12"),
            os_build_id: Some("bookworm"),
            ..Default::default()
        });
        assert_eq!(result, Some(("debian", Some("12"), Some("debian"))));
    }
}
