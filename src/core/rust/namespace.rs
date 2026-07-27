// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/namespace.c, src/core/namespace.h
//

use std::collections::BTreeMap;

use crate::ffi::Errno;

pub const SOURCE_PATHS: &[&str] = &["src/core/namespace.c", "src/core/namespace.h"];
pub const RUN_SYSTEMD_EMPTY: &str = "/run/systemd/empty";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PinnedResource {
    pub directory_fd: Option<i32>,
    pub directory: Option<String>,
    pub image_fd: Option<i32>,
    pub image: Option<String>,
    pub mstack_loaded: bool,
    pub mstack: Option<String>,
}

impl PinnedResource {
    pub fn done(&mut self) {
        *self = Self::default();
    }

    pub fn is_set(&self) -> bool {
        self.directory_fd.is_some()
            || self.directory.is_some()
            || self.image_fd.is_some()
            || self.image.is_some()
            || self.mstack_loaded
            || self.mstack.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: String,
    pub destination: String,
    pub read_only: bool,
    pub nodev: bool,
    pub nosuid: bool,
    pub noexec: bool,
    pub recursive: bool,
    pub ignore_enoent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountImageType {
    Discrete,
    Extension,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountOptions {
    pub by_partition: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountImage {
    pub source: String,
    pub destination: Option<String>,
    pub mount_options: Option<MountOptions>,
    pub ignore_enoent: bool,
    pub image_type: MountImageType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporaryFileSystem {
    pub path: String,
    pub options: Option<String>,
}

pub fn bind_mount_add(items: &mut Vec<BindMount>, item: &BindMount) -> Result<(), Errno> {
    if item.source.is_empty() || item.destination.is_empty() {
        return Err(Errno::EINVAL);
    }
    items.push(item.clone());
    Ok(())
}

pub fn mount_image_add(items: &mut Vec<MountImage>, item: &MountImage) -> Result<(), Errno> {
    if item.source.is_empty() {
        return Err(Errno::EINVAL);
    }
    if matches!(item.image_type, MountImageType::Discrete) && item.destination.is_none() {
        return Err(Errno::EINVAL);
    }
    items.push(item.clone());
    Ok(())
}

pub fn temporary_filesystem_add(
    items: &mut Vec<TemporaryFileSystem>,
    path: &str,
    options: Option<&str>,
) -> Result<(), Errno> {
    if path.is_empty() {
        return Err(Errno::EINVAL);
    }

    items.push(TemporaryFileSystem {
        path: path.into(),
        options: options.filter(|s| !s.is_empty()).map(str::to_string),
    });
    Ok(())
}

pub fn namespace_cleanup_tmpdir(path: Option<String>) -> Option<String> {
    let _ = path;
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmpDirMode {
    ReadWrite,
    ReadOnlyFallback,
}

pub fn setup_tmp_dir_one(
    id: &str,
    prefix: &str,
    boot_id: &str,
    mode: TmpDirMode,
) -> Result<String, Errno> {
    if id.is_empty() || prefix.is_empty() || boot_id.is_empty() {
        return Err(Errno::EINVAL);
    }

    if mode == TmpDirMode::ReadOnlyFallback {
        return Ok(RUN_SYSTEMD_EMPTY.into());
    }

    Ok(format!("{prefix}/systemd-private-{boot_id}-{id}-XXXXXX"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareableNamespaceResult {
    JoinedExisting,
    CreatedNew,
    OpenedExistingPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShareableNamespaceStore {
    stored_path: Option<String>,
}

impl ShareableNamespaceStore {
    pub fn setup_shareable_ns(
        &mut self,
        namespace_name: &str,
    ) -> Result<ShareableNamespaceResult, Errno> {
        if namespace_name.is_empty() {
            return Err(Errno::EINVAL);
        }

        if self.stored_path.is_some() {
            return Ok(ShareableNamespaceResult::JoinedExisting);
        }

        self.stored_path = Some(format!("/proc/self/ns/{namespace_name}"));
        Ok(ShareableNamespaceResult::CreatedNew)
    }

    pub fn open_shareable_ns_path(
        &mut self,
        path: &str,
    ) -> Result<ShareableNamespaceResult, Errno> {
        if path.is_empty() || !path.starts_with('/') {
            return Err(Errno::EINVAL);
        }

        if self.stored_path.is_some() {
            return Ok(ShareableNamespaceResult::JoinedExisting);
        }

        self.stored_path = Some(path.into());
        Ok(ShareableNamespaceResult::OpenedExistingPath)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRequest {
    pub target_is_separate_mount_namespace: bool,
    pub hierarchy_env: String,
    pub private_namespace_dir: String,
    pub extension_images: Vec<String>,
    pub extension_directories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshPlan {
    pub overlay_prefix: String,
    pub extension_dir: String,
    pub hierarchies: Vec<String>,
}

pub fn refresh_extensions_in_namespace(request: &RefreshRequest) -> Result<RefreshPlan, Errno> {
    if !request.target_is_separate_mount_namespace {
        return Err(Errno::EINVAL);
    }
    if request.hierarchy_env.trim().is_empty() || request.private_namespace_dir.is_empty() {
        return Err(Errno::EINVAL);
    }

    let hierarchies = request
        .hierarchy_env
        .split(':')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();

    Ok(RefreshPlan {
        overlay_prefix: "/run/systemd/mount-rootfs".into(),
        extension_dir: format!("{}/unit-extensions", request.private_namespace_dir),
        hierarchies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_mount_add_clones_item() {
        let item = BindMount {
            source: "/src".into(),
            destination: "/dst".into(),
            read_only: true,
            nodev: false,
            nosuid: false,
            noexec: false,
            recursive: true,
            ignore_enoent: false,
        };

        let mut items = Vec::new();
        bind_mount_add(&mut items, &item).unwrap();
        assert_eq!(items, vec![item]);
    }

    #[test]
    fn mount_image_add_requires_destination_for_discrete_images() {
        let item = MountImage {
            source: "root.img".into(),
            destination: None,
            mount_options: None,
            ignore_enoent: false,
            image_type: MountImageType::Discrete,
        };

        assert_eq!(mount_image_add(&mut Vec::new(), &item), Err(Errno::EINVAL));
    }

    #[test]
    fn temporary_filesystem_omits_empty_options() {
        let mut items = Vec::new();
        temporary_filesystem_add(&mut items, "/tmp", Some("")).unwrap();
        assert_eq!(items[0].options, None);
    }

    #[test]
    fn cleanup_tmpdir_matches_c_freeing_contract() {
        assert_eq!(namespace_cleanup_tmpdir(Some("/tmp/x".into())), None);
        assert_eq!(namespace_cleanup_tmpdir(None), None);
    }

    #[test]
    fn setup_tmp_dir_one_uses_boot_id_shape() {
        let path = setup_tmp_dir_one("svc", "/tmp", "bootid", TmpDirMode::ReadWrite).unwrap();
        assert_eq!(path, "/tmp/systemd-private-bootid-svc-XXXXXX");
    }

    #[test]
    fn setup_tmp_dir_one_falls_back_to_empty_dir() {
        let path =
            setup_tmp_dir_one("svc", "/tmp", "bootid", TmpDirMode::ReadOnlyFallback).unwrap();
        assert_eq!(path, RUN_SYSTEMD_EMPTY);
    }

    #[test]
    fn shareable_namespace_store_prefers_existing_entry() {
        let mut store = ShareableNamespaceStore::default();
        assert_eq!(
            store.open_shareable_ns_path("/proc/1/ns/net").unwrap(),
            ShareableNamespaceResult::OpenedExistingPath
        );
        assert_eq!(
            store.setup_shareable_ns("net").unwrap(),
            ShareableNamespaceResult::JoinedExisting
        );
    }

    #[test]
    fn pinned_resource_is_set_tracks_any_field() {
        let mut resource = PinnedResource::default();
        assert!(!resource.is_set());
        resource.image = Some("disk.raw".into());
        assert!(resource.is_set());
        resource.done();
        assert!(!resource.is_set());
    }

    #[test]
    fn refresh_extensions_parses_hierarchy_env() {
        let plan = refresh_extensions_in_namespace(&RefreshRequest {
            target_is_separate_mount_namespace: true,
            hierarchy_env: "sysext:confext".into(),
            private_namespace_dir: "/run/ns".into(),
            extension_images: Vec::new(),
            extension_directories: Vec::new(),
        })
        .unwrap();

        assert_eq!(plan.extension_dir, "/run/ns/unit-extensions");
        assert_eq!(plan.hierarchies, vec!["sysext", "confext"]);
    }
}
