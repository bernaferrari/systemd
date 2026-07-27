// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/user-runtime-dir.c

use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeDirectoryProperties {
    pub size: u64,
    pub inodes: u64,
}

impl Default for RuntimeDirectoryProperties {
    fn default() -> Self {
        let size = 1024 * 1024 * 1024;
        Self {
            size,
            inodes: size / 4096,
        }
    }
}

pub fn user_runtime_dir(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}"))
}

pub fn acquire_runtime_dir_properties() -> Result<RuntimeDirectoryProperties, String> {
    Ok(RuntimeDirectoryProperties::default())
}

pub fn user_mkdir_runtime_path(uid: u32) -> Result<PathBuf, String> {
    let path = user_runtime_dir(uid);
    fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn user_remove_runtime_path(uid: u32) -> Result<(), String> {
    let path = user_runtime_dir(uid);
    if path.exists() {
        fs::remove_dir_all(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}
