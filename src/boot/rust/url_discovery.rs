// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/url-discovery.c
//
// URL discovery from EFI device paths.
//
// Scans the device path of an EFI handle for URI device path nodes
// and extracts the URI as a string.

// ── Constants ─────────────────────────────────────────────────────────────

/// MESSAGING_DEVICE_PATH type value.
pub const MESSAGING_DEVICE_PATH: u8 = 3;

/// MSG_URI_DP subtype value.
pub const MSG_URI_DP: u8 = 24;

// ── Types ─────────────────────────────────────────────────────────────────

/// A single device path node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePathNode {
    pub type_: u8,
    pub sub_type: u8,
    pub data: Vec<u8>,
}

/// A complete device path (list of nodes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePath {
    pub nodes: Vec<DevicePathNode>,
}

/// Error for URL discovery operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlDiscoveryError {
    /// No handle provided.
    NoHandle,
    /// Failed to get device path protocol.
    ProtocolNotFound,
    /// No URI node found in device path.
    NoUriNode,
    /// URI data is not valid UTF-8.
    InvalidUtf8,
}

impl std::fmt::Display for UrlDiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlDiscoveryError::NoHandle => write!(f, "no handle provided"),
            UrlDiscoveryError::ProtocolNotFound => write!(f, "device path protocol not found"),
            UrlDiscoveryError::NoUriNode => write!(f, "no URI node in device path"),
            UrlDiscoveryError::InvalidUtf8 => write!(f, "invalid UTF-8 in URI"),
        }
    }
}

impl std::error::Error for UrlDiscoveryError {}

// ── Device path parsing ───────────────────────────────────────────────────

/// Check if a device path node is the end-of-path marker.
pub fn device_path_is_end(node: &DevicePathNode) -> bool {
    node.type_ == 0x7F && node.sub_type == 0xFF
}

/// Parse a raw device path into a list of nodes.
///
/// Each node starts with type (u8), subtype (u8), length (u16 LE).
pub fn parse_device_path(data: &[u8]) -> Result<DevicePath, UrlDiscoveryError> {
    let mut nodes = Vec::new();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let type_ = data[pos];
        let sub_type = data[pos + 1];
        let length = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if length < 4 || pos + length > data.len() {
            break;
        }

        let node = DevicePathNode {
            type_,
            sub_type,
            data: data[pos + 4..pos + length].to_vec(),
        };

        if device_path_is_end(&node) {
            break;
        }

        nodes.push(node);
        pos += length;
    }

    Ok(DevicePath { nodes })
}

// ── URL extraction ────────────────────────────────────────────────────────

/// Extract a URL from a device path by finding URI nodes.
///
/// Mirrors `disk_get_url()` in C, which iterates through device path
/// nodes looking for MESSAGING_DEVICE_PATH / MSG_URI_DP.
pub fn disk_get_url(path: &DevicePath) -> Result<String, UrlDiscoveryError> {
    for node in &path.nodes {
        if node.type_ == MESSAGING_DEVICE_PATH && node.sub_type == MSG_URI_DP {
            let uri =
                String::from_utf8(node.data.clone()).map_err(|_| UrlDiscoveryError::InvalidUtf8)?;
            let trimmed = uri.split('\0').next().unwrap_or("").to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
    }
    Err(UrlDiscoveryError::NoUriNode)
}

/// Check if a device path contains a URI node.
pub fn has_uri_node(path: &DevicePath) -> bool {
    path.nodes
        .iter()
        .any(|n| n.type_ == MESSAGING_DEVICE_PATH && n.sub_type == MSG_URI_DP)
}

/// Extract all URIs from a device path.
pub fn get_all_urls(path: &DevicePath) -> Vec<String> {
    path.nodes
        .iter()
        .filter(|n| n.type_ == MESSAGING_DEVICE_PATH && n.sub_type == MSG_URI_DP)
        .filter_map(|n| {
            String::from_utf8(n.data.clone())
                .ok()
                .map(|s| s.trim_end_matches('\0').to_string())
                .filter(|s| !s.is_empty())
        })
        .collect()
}

/// Build a URI device path node from a URL string.
pub fn make_uri_node(uri: &str) -> DevicePathNode {
    let mut data = uri.as_bytes().to_vec();
    data.push(0); // NUL terminate
    DevicePathNode {
        type_: MESSAGING_DEVICE_PATH,
        sub_type: MSG_URI_DP,
        data,
    }
}

/// Serialize a device path node to bytes.
pub fn serialize_node(node: &DevicePathNode) -> Vec<u8> {
    let length = (4 + node.data.len()) as u16;
    let mut result = Vec::with_capacity(length as usize);
    result.push(node.type_);
    result.push(node.sub_type);
    result.extend_from_slice(&length.to_le_bytes());
    result.extend_from_slice(&node.data);
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uri_path(uri: &str) -> DevicePath {
        DevicePath {
            nodes: vec![
                DevicePathNode {
                    type_: 1, // hardware
                    sub_type: 1,
                    data: vec![0; 8],
                },
                DevicePathNode {
                    type_: MESSAGING_DEVICE_PATH,
                    sub_type: MSG_URI_DP,
                    data: uri.as_bytes().to_vec(),
                },
            ],
        }
    }

    #[test]
    fn test_device_path_is_end() {
        let end = DevicePathNode {
            type_: 0x7F,
            sub_type: 0xFF,
            data: vec![],
        };
        assert!(device_path_is_end(&end));

        let not_end = DevicePathNode {
            type_: 1,
            sub_type: 1,
            data: vec![],
        };
        assert!(!device_path_is_end(&not_end));
    }

    #[test]
    fn test_parse_device_path() {
        let mut data = Vec::new();
        // Node 1: type=1, subtype=1, length=8 (4 header + 4 data)
        data.push(1u8);
        data.push(1u8);
        data.extend_from_slice(&8u16.to_le_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // End node
        data.push(0x7F);
        data.push(0xFF);
        data.extend_from_slice(&4u16.to_le_bytes());

        let path = parse_device_path(&data).unwrap();
        assert_eq!(path.nodes.len(), 1);
        assert_eq!(path.nodes[0].type_, 1);
        assert_eq!(path.nodes[0].data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_disk_get_url_found() {
        let path = make_uri_path("http://example.com/boot");
        let url = disk_get_url(&path).unwrap();
        assert_eq!(url, "http://example.com/boot");
    }

    #[test]
    fn test_disk_get_url_not_found() {
        let path = DevicePath {
            nodes: vec![DevicePathNode {
                type_: 1,
                sub_type: 1,
                data: vec![0; 4],
            }],
        };
        assert!(disk_get_url(&path).is_err());
    }

    #[test]
    fn test_has_uri_node() {
        let path = make_uri_path("http://example.com");
        assert!(has_uri_node(&path));

        let path_no_uri = DevicePath {
            nodes: vec![DevicePathNode {
                type_: 1,
                sub_type: 1,
                data: vec![],
            }],
        };
        assert!(!has_uri_node(&path_no_uri));
    }

    #[test]
    fn test_get_all_urls_multiple() {
        let path = DevicePath {
            nodes: vec![
                DevicePathNode {
                    type_: MESSAGING_DEVICE_PATH,
                    sub_type: MSG_URI_DP,
                    data: b"http://first".to_vec(),
                },
                DevicePathNode {
                    type_: MESSAGING_DEVICE_PATH,
                    sub_type: MSG_URI_DP,
                    data: b"http://second".to_vec(),
                },
            ],
        };
        let urls = get_all_urls(&path);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "http://first");
        assert_eq!(urls[1], "http://second");
    }

    #[test]
    fn test_make_uri_node() {
        let node = make_uri_node("http://example.com");
        assert_eq!(node.type_, MESSAGING_DEVICE_PATH);
        assert_eq!(node.sub_type, MSG_URI_DP);
        assert_eq!(&node.data[..node.data.len() - 1], b"http://example.com");
    }

    #[test]
    fn test_serialize_roundtrip() {
        let node = make_uri_node("http://test.local");
        let bytes = serialize_node(&node);
        let path = parse_device_path(&bytes).unwrap();
        assert_eq!(path.nodes.len(), 1);
        let url = disk_get_url(&path).unwrap();
        assert_eq!(url, "http://test.local");
    }

    #[test]
    fn test_disk_get_url_null_terminated() {
        let data = b"http://example.com\0extra".to_vec();
        let path = DevicePath {
            nodes: vec![DevicePathNode {
                type_: MESSAGING_DEVICE_PATH,
                sub_type: MSG_URI_DP,
                data: data.clone(),
            }],
        };
        let url = disk_get_url(&path).unwrap();
        assert_eq!(url, "http://example.com");
    }
}
