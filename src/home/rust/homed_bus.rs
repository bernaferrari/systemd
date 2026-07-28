// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homed-bus.c, src/home/homed-bus.h

use std::collections::HashMap;

use crate::home_util::{BlobFdMap, suitable_blob_filename};
use crate::user_record_util::UserRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusError {
    InvalidJson,
    InvalidBlobFilename(String),
    InvalidBlobFd(String),
}

impl std::fmt::Display for BusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson => write!(f, "invalid JSON data"),
            Self::InvalidBlobFilename(name) => write!(f, "invalid blob directory filename: {name}"),
            Self::InvalidBlobFd(name) => write!(f, "fd for '{name}' is not a regular file"),
        }
    }
}

impl std::error::Error for BusError {}

pub fn bus_message_read_secret(json: &str) -> Result<UserRecord, BusError> {
    let user_name = extract_json_string(json, "userName").ok_or(BusError::InvalidJson)?;
    let mut record = UserRecord::new();
    record.user_name = user_name;
    Ok(record)
}

pub fn bus_message_read_home_record(json: &str) -> Result<UserRecord, BusError> {
    let user_name = extract_json_string(json, "userName").ok_or(BusError::InvalidJson)?;
    let mut record = UserRecord::new();
    record.user_name = user_name;
    record.home_directory = extract_json_string(json, "homeDirectory");
    Ok(record)
}

pub fn bus_message_read_blobs(entries: &[(String, i32)]) -> Result<BlobFdMap, BusError> {
    let mut blobs: HashMap<String, i32> = HashMap::new();
    for (name, fd) in entries {
        if !suitable_blob_filename(name) {
            return Err(BusError::InvalidBlobFilename(name.clone()));
        }
        if *fd < 0 {
            return Err(BusError::InvalidBlobFd(name.clone()));
        }
        blobs.insert(name.clone(), *fd);
    }
    Ok(blobs)
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)?;
    let rest = &json[start + needle.len()..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_secret_requires_username() {
        assert_eq!(bus_message_read_secret("{}"), Err(BusError::InvalidJson));
    }

    #[test]
    fn read_secret_extracts_username() {
        let record = bus_message_read_secret("{\"userName\":\"alice\"}").unwrap();
        assert_eq!(record.user_name, "alice");
    }

    #[test]
    fn read_home_record_extracts_home_directory() {
        let record = bus_message_read_home_record(
            "{\"userName\":\"alice\",\"homeDirectory\":\"/home/alice\"}",
        )
        .unwrap();
        assert_eq!(record.home_directory.as_deref(), Some("/home/alice"));
    }

    #[test]
    fn read_home_record_requires_username() {
        assert_eq!(
            bus_message_read_home_record("{\"homeDirectory\":\"/tmp\"}"),
            Err(BusError::InvalidJson)
        );
    }

    #[test]
    fn read_blobs_accepts_empty_map() {
        assert!(bus_message_read_blobs(&[]).unwrap().is_empty());
    }

    #[test]
    fn read_blobs_accepts_valid_entries() {
        let blobs = bus_message_read_blobs(&[("avatar".into(), 3), ("ssh-key".into(), 4)]).unwrap();
        assert_eq!(blobs.len(), 2);
    }

    #[test]
    fn read_blobs_rejects_bad_filename() {
        let err = bus_message_read_blobs(&[("../passwd".into(), 3)]).unwrap_err();
        assert_eq!(err, BusError::InvalidBlobFilename("../passwd".into()));
    }

    #[test]
    fn read_blobs_rejects_negative_fd() {
        let err = bus_message_read_blobs(&[("avatar".into(), -1)]).unwrap_err();
        assert_eq!(err, BusError::InvalidBlobFd("avatar".into()));
    }

    #[test]
    fn helper_returns_none_for_missing_key() {
        assert_eq!(extract_json_string("{}", "userName"), None);
    }
}
