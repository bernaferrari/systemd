// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/oci-util.c
//
// Minimal safe helpers for OCI reference handling plus source sync checks.

use crate::import_common::{
    PortError, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};
use std::io;

pub const SOURCE_PATH: &str = "src/import/oci-util.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "oci_digest_string",
    "oci_image_is_valid",
    "oci_make_blob_url",
    "oci_make_manifest_url",
    "oci_ref_normalize",
    "oci_ref_parse",
    "oci_registry_is_valid",
    "oci_tag_is_valid",
    "urlescape",
];

#[derive(Debug)]
pub enum OciError {
    InvalidReference(String),
    ParseFailed(String),
    Io(io::Error),
}

impl From<io::Error> for OciError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for OciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidReference(msg) => write!(f, "{msg}"),
            Self::ParseFailed(msg) => write!(f, "{msg}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for OciError {}

pub fn oci_digest_from_string(s: &str) -> Result<(&str, &str), OciError> {
    let parts: Vec<_> = s.splitn(2, ':').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(OciError::ParseFailed(format!("invalid digest: {s}")));
    }
    Ok((parts[0], parts[1]))
}

pub fn oci_normalize_reference(reference: &str) -> Result<String, OciError> {
    if reference.is_empty() {
        return Err(OciError::InvalidReference("empty reference".into()));
    }
    let mut parts = reference.splitn(2, ':');
    let image = parts.next().unwrap();
    let tag = parts.next().unwrap_or("latest");
    if image.is_empty() {
        return Err(OciError::InvalidReference(reference.into()));
    }
    Ok(format!("{image}:{tag}"))
}

pub fn oci_ref_parse_host(reference: &str) -> Option<&str> {
    reference.find('/').map(|idx| &reference[..idx])
}

pub fn metadata() -> Result<PortMetadata, PortError> {
    Ok(PortMetadata {
        module_name: module_path!(),
        source_path: SOURCE_PATH,
        source_lines: count_port_source_lines(SOURCE_PATH)?,
        extracted_functions: EXTRACTED_FUNCTIONS,
    })
}

pub fn read_source() -> Result<String, PortError> {
    read_port_source(SOURCE_PATH)
}

pub fn source_lines() -> Result<usize, PortError> {
    count_port_source_lines(SOURCE_PATH)
}

pub fn verify_port_sync() -> Result<(), PortError> {
    verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_parser_splits_algorithm_and_value() {
        assert_eq!(
            oci_digest_from_string("sha256:abc").unwrap(),
            ("sha256", "abc")
        );
    }

    #[test]
    fn digest_parser_rejects_invalid_input() {
        assert!(oci_digest_from_string("broken").is_err());
    }

    #[test]
    fn normalize_adds_latest_tag() {
        assert_eq!(oci_normalize_reference("alpine").unwrap(), "alpine:latest");
    }

    #[test]
    fn host_parser_only_returns_registry_like_prefix() {
        assert_eq!(
            oci_ref_parse_host("docker.io/library/alpine"),
            Some("docker.io")
        );
    }

    #[test]
    fn oci_source_sync_is_valid() {
        verify_port_sync().unwrap();
    }
}
