// SPDX-License-Identifier: LGPL-2.1-or-later

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn setup_fake_runtime_dir() -> io::Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = PathBuf::from(format!("/tmp/fake-xdg-runtime-{nonce}"));
    fs::create_dir_all(&dir)?;
    unsafe { env::set_var("XDG_RUNTIME_DIR", &dir) };
    Ok(dir)
}

pub fn slow_tests_enabled() -> bool {
    env::var("SYSTEMD_SLOW_TESTS")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "yes" | "true"))
        .unwrap_or(false)
}

pub fn write_tmpfile(pattern: &str, contents: &str) -> io::Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = PathBuf::from(pattern.replace("XXXXXX", &nonce.to_string()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    file.write_all(contents.as_bytes())?;
    Ok(path)
}

pub fn can_memlock(size: usize) -> bool {
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_SHARED,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return false;
        }
        let ok = libc::mlock(ptr, size) == 0;
        if ok {
            let _ = libc::munlock(ptr, size);
        }
        let _ = libc::munmap(ptr, size);
        ok
    }
}
