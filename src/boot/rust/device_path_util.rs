// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/device-path-util.c
//
// EFI device path utility functions.
//
// Provides manipulation, comparison, and string conversion for EFI device
// paths. Device paths are the EFI standard way to identify devices and
// files in the boot environment.

// ── Constants ─────────────────────────────────────────────────────────────

/// End of device path type.
pub const END_DEVICE_PATH_TYPE: u8 = 0x7F;

/// End of entire device path subtype.
pub const END_ENTIRE_DEVICE_PATH_SUBTYPE: u8 = 0xFF;

/// End of this device path instance subtype.
pub const END_INSTANCE_DEVICE_PATH_SUBTYPE: u8 = 0x01;

/// Media device path type.
pub const MEDIA_DEVICE_PATH: u8 = 0x04;

/// Media file path subtype.
pub const MEDIA_FILEPATH_DP: u8 = 0x04;

/// Messaging device path type.
pub const MESSAGING_DEVICE_PATH: u8 = 0x03;

/// URI device path subtype.
pub const MSG_URI_DP: u8 = 0x24;

/// Size of an EFI_DEVICE_PATH header (type + subtype + length).
pub const DEVICE_PATH_HEADER_SIZE: usize = 4;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePathError {
    InvalidParameter,
    OutOfResources,
    DeviceError,
    NotFound,
    Unsupported,
    ProtocolError,
}

impl std::fmt::Display for DevicePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DevicePathError::InvalidParameter => write!(f, "invalid parameter"),
            DevicePathError::OutOfResources => write!(f, "out of resources"),
            DevicePathError::DeviceError => write!(f, "device error"),
            DevicePathError::NotFound => write!(f, "not found"),
            DevicePathError::Unsupported => write!(f, "unsupported"),
            DevicePathError::ProtocolError => write!(f, "protocol error"),
        }
    }
}

impl std::error::Error for DevicePathError {}

// ── Data structures ───────────────────────────────────────────────────────

/// A parsed EFI device path node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePathNode {
    pub type_: u8,
    pub subtype: u8,
    pub data: Vec<u8>,
}

impl DevicePathNode {
    pub fn new(type_: u8, subtype: u8, data: Vec<u8>) -> Self {
        Self {
            type_,
            subtype,
            data,
        }
    }

    pub fn length(&self) -> u16 {
        (DEVICE_PATH_HEADER_SIZE + self.data.len()) as u16
    }

    pub fn is_end(&self) -> bool {
        self.type_ == END_DEVICE_PATH_TYPE
            && (self.subtype == END_ENTIRE_DEVICE_PATH_SUBTYPE
                || self.subtype == END_INSTANCE_DEVICE_PATH_SUBTYPE)
    }

    pub fn is_end_entire(&self) -> bool {
        self.type_ == END_DEVICE_PATH_TYPE && self.subtype == END_ENTIRE_DEVICE_PATH_SUBTYPE
    }

    pub fn is_filepath(&self) -> bool {
        self.type_ == MEDIA_DEVICE_PATH && self.subtype == MEDIA_FILEPATH_DP
    }

    pub fn is_uri(&self) -> bool {
        self.type_ == MESSAGING_DEVICE_PATH && self.subtype == MSG_URI_DP
    }
}

/// An end-of-path sentinel node.
pub fn end_node() -> DevicePathNode {
    DevicePathNode::new(END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, vec![])
}

// ── Parsing ───────────────────────────────────────────────────────────────

/// Parse a raw byte buffer into a list of device path nodes.
pub fn parse_device_path(data: &[u8]) -> Result<Vec<DevicePathNode>, DevicePathError> {
    let mut nodes = Vec::new();
    let mut offset = 0;

    loop {
        if offset + DEVICE_PATH_HEADER_SIZE > data.len() {
            return Err(DevicePathError::InvalidParameter);
        }

        let type_ = data[offset];
        let subtype = data[offset + 1];
        let length = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if length < DEVICE_PATH_HEADER_SIZE {
            return Err(DevicePathError::InvalidParameter);
        }
        if offset + length > data.len() {
            return Err(DevicePathError::InvalidParameter);
        }

        let node_data = data[offset + DEVICE_PATH_HEADER_SIZE..offset + length].to_vec();
        let node = DevicePathNode::new(type_, subtype, node_data);

        let is_end = node.is_end_entire();
        nodes.push(node);

        if is_end {
            break;
        }

        offset += length;
    }

    Ok(nodes)
}

// ── Core functions ────────────────────────────────────────────────────────

/// Find the end node in a device path.
pub fn device_path_find_end_node(nodes: &[DevicePathNode]) -> Option<&DevicePathNode> {
    nodes.iter().find(|n| n.is_end_entire())
}

/// Calculate the total size in bytes of a serialized device path.
pub fn device_path_size(nodes: &[DevicePathNode]) -> usize {
    nodes.iter().map(|n| n.length() as usize).sum()
}

/// Check if one device path starts with another (prefix match).
pub fn device_path_startswith(path: &[DevicePathNode], prefix: &[DevicePathNode]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if path.len() < prefix.len() {
        return false;
    }

    for (p, s) in path.iter().zip(prefix.iter()) {
        if s.is_end_entire() {
            return true;
        }
        if p.is_end_entire() {
            return false;
        }
        if p.length() != s.length() {
            return false;
        }
        if p.type_ != s.type_ || p.subtype != s.subtype || p.data != s.data {
            return false;
        }
    }

    prefix.last().is_some_and(|n| n.is_end_entire())
}

/// Replace a node in a device path with a new node.
pub fn device_path_replace_node(
    path: &[DevicePathNode],
    node_index: usize,
    new_node: Option<&DevicePathNode>,
) -> Vec<DevicePathNode> {
    let mut result: Vec<DevicePathNode> = path[..node_index.min(path.len())].to_vec();

    if let Some(replacement) = new_node {
        result.push(replacement.clone());
    }

    result.push(end_node());
    result
}

/// Duplicate a device path.
pub fn device_path_dup(nodes: &[DevicePathNode]) -> Vec<DevicePathNode> {
    nodes.to_vec()
}

/// Convert a device path to a human-readable string.
pub fn device_path_to_str(nodes: &[DevicePathNode]) -> String {
    let mut parts: Vec<String> = Vec::new();

    for node in nodes {
        if node.is_end() {
            if node.subtype == END_INSTANCE_DEVICE_PATH_SUBTYPE {
                parts.push(",".to_string());
            }
            continue;
        }

        if node.is_filepath() {
            let path_str = String::from_utf16_lossy(
                &node
                    .data
                    .chunks(2)
                    .map(|c| {
                        u16::from_le_bytes(if c.len() == 2 {
                            [c[0], c[1]]
                        } else {
                            [c[0], 0]
                        })
                    })
                    .collect::<Vec<u16>>(),
            );
            let sep = if parts.is_empty() { "" } else { "\\" };
            parts.push(format!("{sep}{path_str}"));
        } else {
            let hex: String = node.data.iter().map(|b| format!("{b:02x}")).collect();
            let sep = if node.data.is_empty() { "" } else { "," };
            let prefix = if parts.is_empty() { "" } else { "/" };
            parts.push(format!(
                "{prefix}Path({},{},{}{hex})",
                node.type_, node.subtype, sep
            ));
        }
    }

    parts.join("")
}

/// Build a file device path from a device path prefix and a filename.
pub fn make_file_device_path(base_nodes: &[DevicePathNode], filename: &str) -> Vec<DevicePathNode> {
    let mut result = base_nodes.to_vec();

    if result.last().is_none_or(|n| n.is_end_entire()) {
        result.pop();
    }

    let filename_utf16: Vec<u8> = filename
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    result.push(DevicePathNode::new(
        MEDIA_DEVICE_PATH,
        MEDIA_FILEPATH_DP,
        filename_utf16,
    ));
    result.push(end_node());

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(type_: u8, subtype: u8) -> DevicePathNode {
        DevicePathNode::new(type_, subtype, vec![])
    }

    #[test]
    fn test_end_node() {
        let node = end_node();
        assert!(node.is_end());
        assert!(node.is_end_entire());
        assert!(!node.is_filepath());
    }

    #[test]
    fn test_node_is_filepath() {
        let node = DevicePathNode::new(MEDIA_DEVICE_PATH, MEDIA_FILEPATH_DP, vec![]);
        assert!(node.is_filepath());
        assert!(!node.is_end());
    }

    #[test]
    fn test_parse_device_path_end_only() {
        let data = [END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, 4, 0];
        let nodes = parse_device_path(&data).unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(nodes[0].is_end_entire());
    }

    #[test]
    fn test_parse_device_path_invalid() {
        assert!(parse_device_path(&[]).is_err());
        assert!(parse_device_path(&[0x01]).is_err());
    }

    #[test]
    fn test_device_path_size() {
        let nodes = vec![make_node(1, 1), end_node()];
        assert_eq!(device_path_size(&nodes), 8);
    }

    #[test]
    fn test_device_path_startswith_empty_prefix() {
        let path = vec![make_node(1, 1), end_node()];
        assert!(device_path_startswith(&path, &[]));
    }

    #[test]
    fn test_device_path_startswith_match() {
        let prefix = vec![make_node(1, 1), end_node()];
        let path = vec![make_node(1, 1), end_node()];
        assert!(device_path_startswith(&path, &prefix));
    }

    #[test]
    fn test_device_path_startswith_no_match() {
        let prefix = vec![make_node(1, 1), end_node()];
        let path = vec![make_node(2, 2), end_node()];
        assert!(!device_path_startswith(&path, &prefix));
    }

    #[test]
    fn test_device_path_replace_node() {
        let path = vec![make_node(1, 1), make_node(2, 2), end_node()];
        let new = make_node(3, 3);
        let result = device_path_replace_node(&path, 1, Some(&new));
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].type_, 1);
        assert_eq!(result[1].type_, 3);
        assert!(result[2].is_end_entire());
    }

    #[test]
    fn test_device_path_dup() {
        let path = vec![make_node(1, 1), end_node()];
        let dup = device_path_dup(&path);
        assert_eq!(path, dup);
    }

    #[test]
    fn test_device_path_to_str_empty() {
        let nodes = vec![end_node()];
        let s = device_path_to_str(&nodes);
        assert!(s.is_empty());
    }

    #[test]
    fn test_make_file_device_path() {
        let base = vec![make_node(1, 1), end_node()];
        let result = make_file_device_path(&base, "\\test.efi");
        assert!(result.iter().any(|n| n.is_filepath()));
        assert!(result.last().unwrap().is_end_entire());
    }

    #[test]
    fn test_error_display() {
        assert!(!DevicePathError::InvalidParameter.to_string().is_empty());
    }
}
