// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-blob.c, src/home/homework-blob.h

use std::collections::HashMap;

use crate::home_util::suitable_blob_filename;

pub type BlobManifest = HashMap<String, Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobError {
    InvalidFilename(String),
    InvalidHex(String),
    HashMismatch(String),
    MissingBlob(String),
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFilename(name) => write!(f, "invalid blob filename: {name}"),
            Self::InvalidHex(value) => write!(f, "invalid blob digest: {value}"),
            Self::HashMismatch(name) => write!(f, "hash mismatch for blob: {name}"),
            Self::MissingBlob(name) => write!(f, "missing blob: {name}"),
        }
    }
}

impl std::error::Error for BlobError {}

pub fn read_blob_manifest(data: &str) -> Result<BlobManifest, BlobError> {
    let mut manifest = BlobManifest::new();
    for line in data.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (digest, name) = line
            .split_once(' ')
            .ok_or_else(|| BlobError::InvalidHex(line.to_string()))?;
        if !suitable_blob_filename(name) {
            return Err(BlobError::InvalidFilename(name.to_string()));
        }
        let digest = hex_decode(digest).ok_or_else(|| BlobError::InvalidHex(digest.to_string()))?;
        manifest.insert(name.to_string(), digest);
    }
    Ok(manifest)
}

pub fn verify_blob_manifest(
    manifest: &BlobManifest,
    blobs: &HashMap<String, Vec<u8>>,
) -> Result<(), BlobError> {
    for (name, expected) in manifest {
        let Some(actual) = blobs.get(name) else {
            return Err(BlobError::MissingBlob(name.clone()));
        };
        if simple_digest(actual) != *expected {
            return Err(BlobError::HashMismatch(name.clone()));
        }
    }
    Ok(())
}

pub fn install_blobs(
    manifest: &BlobManifest,
    blobs: &HashMap<String, Vec<u8>>,
) -> Result<usize, BlobError> {
    verify_blob_manifest(manifest, blobs)?;
    Ok(blobs
        .iter()
        .filter(|(name, _)| manifest.contains_key(*name))
        .map(|(_, data)| data.len())
        .sum())
}

fn simple_digest(data: &[u8]) -> Vec<u8> {
    let sum = data.iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte));
    vec![sum]
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[index..index + 2], 16).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_handles_even_hex() {
        assert_eq!(hex_decode("00ff"), Some(vec![0, 255]));
    }

    #[test]
    fn hex_decode_rejects_odd_hex() {
        assert_eq!(hex_decode("abc"), None);
    }

    #[test]
    fn read_manifest_accepts_valid_entry() {
        let manifest = read_blob_manifest("06 avatar\n").unwrap();
        assert_eq!(manifest.get("avatar"), Some(&vec![6]));
    }

    #[test]
    fn read_manifest_rejects_bad_filename() {
        assert_eq!(
            read_blob_manifest("06 ../avatar\n"),
            Err(BlobError::InvalidFilename("../avatar".into()))
        );
    }

    #[test]
    fn read_manifest_rejects_bad_hex() {
        assert_eq!(
            read_blob_manifest("zz avatar\n"),
            Err(BlobError::InvalidHex("zz".into()))
        );
    }

    #[test]
    fn verify_manifest_rejects_missing_blob() {
        let manifest = read_blob_manifest("06 avatar\n").unwrap();
        assert_eq!(
            verify_blob_manifest(&manifest, &HashMap::new()),
            Err(BlobError::MissingBlob("avatar".into()))
        );
    }

    #[test]
    fn verify_manifest_rejects_hash_mismatch() {
        let manifest = read_blob_manifest("06 avatar\n").unwrap();
        let blobs = HashMap::from([("avatar".into(), vec![1, 2])]);
        assert_eq!(
            verify_blob_manifest(&manifest, &blobs),
            Err(BlobError::HashMismatch("avatar".into()))
        );
    }

    #[test]
    fn verify_manifest_accepts_matching_digest() {
        let manifest = read_blob_manifest("03 avatar\n").unwrap();
        let blobs = HashMap::from([("avatar".into(), vec![1, 2])]);
        assert!(verify_blob_manifest(&manifest, &blobs).is_ok());
    }

    #[test]
    fn install_blobs_returns_total_size() {
        let manifest = read_blob_manifest("03 avatar\n").unwrap();
        let blobs = HashMap::from([("avatar".into(), vec![1, 2])]);
        assert_eq!(install_blobs(&manifest, &blobs).unwrap(), 2);
    }
}
