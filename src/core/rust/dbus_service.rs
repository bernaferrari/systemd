// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-service.c

use std::collections::BTreeSet;
use std::fmt;

pub const SOURCE_PATH: &str = "src/core/dbus-service.c";

pub type Result<T> = std::result::Result<T, DbusServiceError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbusServiceError {
    FileDescriptorStoreDisabled,
    InvalidPath(String),
    InvalidStatusCode(i32),
    InvalidSignal(i32),
    MountsUnsupported,
}

impl fmt::Display for DbusServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileDescriptorStoreDisabled => write!(f, "file descriptor store disabled"),
            Self::InvalidPath(path) => write!(f, "invalid path: {path}"),
            Self::InvalidStatusCode(code) => write!(f, "invalid status code: {code}"),
            Self::InvalidSignal(signal) => write!(f, "invalid signal: {signal}"),
            Self::MountsUnsupported => {
                write!(f, "runtime mounts supported only for system manager")
            }
        }
    }
}

impl std::error::Error for DbusServiceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFileEntry {
    pub path: String,
    pub fdname: String,
    pub flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatusSet {
    pub status: BTreeSet<i32>,
    pub signal: BTreeSet<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptorStoreEntry {
    pub fdname: String,
    pub mode: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub path: Option<String>,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRequest {
    pub source: String,
    pub destination: String,
    pub read_only: bool,
    pub make_file_or_directory: bool,
    pub is_image: bool,
    pub options: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedMountRequest {
    pub source: String,
    pub destination: String,
    pub read_only: bool,
    pub make_file_or_directory: bool,
    pub is_image: bool,
    pub options: Vec<(String, String)>,
}

pub fn property_get_open_files(entries: &[OpenFileEntry]) -> Vec<(String, String, u64)> {
    entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.fdname.clone(), entry.flags))
        .collect()
}

pub fn property_get_extra_file_descriptors(names: &[String]) -> Vec<String> {
    names.to_vec()
}

pub fn property_get_refresh_on_reload(flags: &[String]) -> Vec<String> {
    flags.to_vec()
}

pub fn property_get_exit_status_set(set: &ExitStatusSet) -> (Vec<i32>, Vec<i32>) {
    (
        set.status.iter().copied().collect(),
        set.signal.iter().copied().collect(),
    )
}

pub fn property_get_size_as_uint32(value: usize) -> u32 {
    value.min(u32::MAX as usize) as u32
}

pub fn bus_service_method_mount(
    request: MountRequest,
    system_manager: bool,
) -> Result<NormalizedMountRequest> {
    if !system_manager {
        return Err(DbusServiceError::MountsUnsupported);
    }

    validate_absolute_normalized_path(&request.source)?;

    let destination = if !request.is_image && request.destination.is_empty() {
        request.source.clone()
    } else {
        validate_absolute_normalized_path(&request.destination)?;
        request.destination.clone()
    };

    Ok(NormalizedMountRequest {
        source: request.source,
        destination,
        read_only: request.read_only,
        make_file_or_directory: request.make_file_or_directory,
        is_image: request.is_image,
        options: request.options,
    })
}

pub fn bus_service_method_dump_file_descriptor_store(
    enabled: bool,
    entries: &[FileDescriptorStoreEntry],
) -> Result<Vec<FileDescriptorStoreEntry>> {
    if !enabled && entries.is_empty() {
        return Err(DbusServiceError::FileDescriptorStoreDisabled);
    }

    Ok(entries.to_vec())
}

pub fn bus_set_transient_exit_status(
    _name: &str,
    statuses: &[i32],
    signals: &[i32],
    noop: bool,
    set: &mut ExitStatusSet,
) -> Result<bool> {
    if statuses.is_empty() && signals.is_empty() && !noop {
        set.status.clear();
        set.signal.clear();
        return Ok(true);
    }

    for status in statuses {
        if !(0..=255).contains(status) {
            return Err(DbusServiceError::InvalidStatusCode(*status));
        }
        if !noop {
            set.status.insert(*status);
        }
    }

    for signal in signals {
        if *signal <= 0 || *signal > 64 {
            return Err(DbusServiceError::InvalidSignal(*signal));
        }
        if !noop {
            set.signal.insert(*signal);
        }
    }

    Ok(true)
}

fn validate_absolute_normalized_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.contains("//")
        || path.contains("/../")
        || path.ends_with("/..")
    {
        return Err(DbusServiceError::InvalidPath(path.into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_files_are_marshaled_as_triplets() {
        let entries = vec![OpenFileEntry {
            path: "/tmp/a".into(),
            fdname: "cache".into(),
            flags: 5,
        }];
        assert_eq!(
            property_get_open_files(&entries),
            vec![("/tmp/a".into(), "cache".into(), 5)]
        );
    }

    #[test]
    fn extra_fd_names_and_refresh_flags_roundtrip() {
        let names = vec!["stdin".into(), "stdout".into()];
        assert_eq!(property_get_extra_file_descriptors(&names), names);
        assert_eq!(
            property_get_refresh_on_reload(&["exec".into()]),
            vec!["exec"]
        );
    }

    #[test]
    fn exit_status_sets_are_split_into_statuses_and_signals() {
        let set = ExitStatusSet {
            status: BTreeSet::from([1, 2]),
            signal: BTreeSet::from([9]),
        };
        assert_eq!(property_get_exit_status_set(&set), (vec![1, 2], vec![9]));
    }

    #[test]
    fn size_is_saturated_to_uint32() {
        assert_eq!(property_get_size_as_uint32(7), 7);
        assert_eq!(property_get_size_as_uint32(usize::MAX), u32::MAX);
    }

    #[test]
    fn bind_mount_defaults_destination_to_source() {
        let request = MountRequest {
            source: "/src".into(),
            destination: String::new(),
            read_only: true,
            make_file_or_directory: false,
            is_image: false,
            options: Vec::new(),
        };
        let normalized = bus_service_method_mount(request, true).unwrap();
        assert_eq!(normalized.destination, "/src");
    }

    #[test]
    fn mount_rejects_non_system_manager_and_bad_paths() {
        let request = MountRequest {
            source: "relative".into(),
            destination: "/dest".into(),
            read_only: false,
            make_file_or_directory: false,
            is_image: false,
            options: Vec::new(),
        };
        assert!(matches!(
            bus_service_method_mount(request.clone(), false),
            Err(DbusServiceError::MountsUnsupported)
        ));
        assert!(matches!(
            bus_service_method_mount(request, true),
            Err(DbusServiceError::InvalidPath(_))
        ));
    }

    #[test]
    fn dump_fd_store_requires_feature_or_entries() {
        assert!(matches!(
            bus_service_method_dump_file_descriptor_store(false, &[]),
            Err(DbusServiceError::FileDescriptorStoreDisabled)
        ));
    }

    #[test]
    fn transient_exit_status_accepts_valid_values() {
        let mut set = ExitStatusSet {
            status: BTreeSet::new(),
            signal: BTreeSet::new(),
        };
        bus_set_transient_exit_status("SuccessExitStatus", &[0, 1], &[15], false, &mut set)
            .unwrap();
        assert!(set.status.contains(&1));
        assert!(set.signal.contains(&15));
    }

    #[test]
    fn transient_exit_status_rejects_invalid_values() {
        let mut set = ExitStatusSet {
            status: BTreeSet::new(),
            signal: BTreeSet::new(),
        };
        assert!(matches!(
            bus_set_transient_exit_status("X", &[256], &[], false, &mut set),
            Err(DbusServiceError::InvalidStatusCode(256))
        ));
        assert!(matches!(
            bus_set_transient_exit_status("X", &[], &[0], false, &mut set),
            Err(DbusServiceError::InvalidSignal(0))
        ));
    }
}
