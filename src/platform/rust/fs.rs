// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::io;
use std::path::Path;

/// Recursively create a directory and all parent components, like `mkdir -p`.
pub fn mkdir_p(path: &str, mode: u32) -> io::Result<()> {
    let p = Path::new(path);
    if p.exists() {
        return Ok(());
    }
    fs::create_dir_all(p)?;
    // Set the final mode via chmod (permissions may be affected by umask).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Recursively remove a directory tree, like `rm -rf`.
pub fn rm_rf(path: &str) -> io::Result<()> {
    let p = Path::new(path);
    if !p.exists() {
        return Ok(());
    }
    if p.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

/// Read the target of a symbolic link, allocating as needed.
pub fn readlink_malloc(path: &str) -> io::Result<String> {
    let target = fs::read_link(path)?;
    target
        .into_os_string()
        .into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "path is not valid UTF-8"))
}
