// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-path_id.c
//
// Path-based device identifier construction.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSegment {
    pub bus: String,
    pub slot: String,
    pub function: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathIdError { EmptyBus, EmptySlot }
pub type Result<T> = std::result::Result<T, PathIdError>;

pub fn build_path_id(segments: &[PathSegment]) -> Result<String> {
    let mut out = Vec::new();
    for segment in segments {
        if segment.bus.trim().is_empty() { return Err(PathIdError::EmptyBus); }
        if segment.slot.trim().is_empty() { return Err(PathIdError::EmptySlot); }
        let mut item = format!("{}-{}", segment.bus.trim(), segment.slot.trim());
        if let Some(function) = &segment.function { item.push_str(&format!(".{}", function.trim())); }
        out.push(item);
    }
    Ok(out.join("-"))
}

pub fn build_tag(path_id: &str) -> String {
    path_id.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn builds_compound_path_id() { let id = build_path_id(&[PathSegment { bus: "pci".into(), slot: "0000:00:1f".into(), function: Some("6".into()) }, PathSegment { bus: "usb".into(), slot: "1-2".into(), function: None }]).unwrap(); assert_eq!(id, "pci-0000:00:1f.6-usb-1-2"); }
    #[test] fn builds_sanitized_tag() { assert_eq!(build_tag("pci-0000:00:1f.6"), "pci_0000_00_1f_6"); }
    #[test] fn rejects_empty_bus() { assert_eq!(build_path_id(&[PathSegment { bus: "".into(), slot: "1".into(), function: None }]), Err(PathIdError::EmptyBus)); }
}
