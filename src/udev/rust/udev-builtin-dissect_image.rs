// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-dissect_image.c
//
// Image metadata extraction helpers.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageMetadata {
    pub format: String,
    pub architecture: Option<String>,
    pub partitions: usize,
    pub bootable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    EmptyFormat,
}
pub type Result<T> = std::result::Result<T, ImageError>;

pub fn dissect_image(metadata: ImageMetadata) -> Result<BTreeMap<String, String>> {
    if metadata.format.trim().is_empty() {
        return Err(ImageError::EmptyFormat);
    }
    let mut map = BTreeMap::from([
        ("ID_DISSECT_IMAGE_FORMAT".into(), metadata.format),
        (
            "ID_DISSECT_IMAGE_PARTITIONS".into(),
            metadata.partitions.to_string(),
        ),
        (
            "ID_DISSECT_IMAGE_BOOTABLE".into(),
            if metadata.bootable { "1" } else { "0" }.into(),
        ),
    ]);
    if let Some(arch) = metadata.architecture {
        map.insert("ID_DISSECT_IMAGE_ARCHITECTURE".into(), arch);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exports_image_metadata() {
        let props = dissect_image(ImageMetadata {
            format: "gpt".into(),
            architecture: Some("x86-64".into()),
            partitions: 3,
            bootable: true,
        })
        .unwrap();
        assert_eq!(props["ID_DISSECT_IMAGE_FORMAT"], "gpt");
        assert_eq!(props["ID_DISSECT_IMAGE_BOOTABLE"], "1");
    }
    #[test]
    fn rejects_empty_format() {
        assert_eq!(
            dissect_image(ImageMetadata {
                format: "".into(),
                architecture: None,
                partitions: 0,
                bootable: false
            }),
            Err(ImageError::EmptyFormat)
        );
    }
}
