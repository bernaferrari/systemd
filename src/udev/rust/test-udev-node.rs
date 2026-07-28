// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/test-udev-node.c
//
// Device-node naming checks.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    EmptyName,
    RelativePath,
}
pub type Result<T> = std::result::Result<T, NodeError>;

pub fn validate_node(path: &str) -> Result<&str> {
    if path.is_empty() {
        return Err(NodeError::EmptyName);
    }
    if !path.starts_with("/dev/") {
        return Err(NodeError::RelativePath);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_devnode() {
        assert_eq!(validate_node("/dev/sda").unwrap(), "/dev/sda");
    }
    #[test]
    fn rejects_empty() {
        assert_eq!(validate_node(""), Err(NodeError::EmptyName));
    }
    #[test]
    fn rejects_relative_path() {
        assert_eq!(validate_node("sda"), Err(NodeError::RelativePath));
    }
}
