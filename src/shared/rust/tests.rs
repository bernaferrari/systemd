// SPDX-License-Identifier: LGPL-2.1-or-later

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::cell::RefCell;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

static TEST_ENVIRONMENT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// A scoped, process-wide environment mutation for tests.
pub struct TestEnvironment {
    _lock: MutexGuard<'static, ()>,
    previous_values: RefCell<Vec<(OsString, Option<OsString>)>>,
}

impl TestEnvironment {
    /// Serializes test environment mutations and restores them when dropped.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no other thread reads or mutates the process
    /// environment until the returned guard is dropped. The lock serializes
    /// cooperating tests, but cannot synchronize arbitrary environment readers.
    pub unsafe fn lock() -> Self {
        Self {
            _lock: TEST_ENVIRONMENT_LOCK
                .lock()
                .expect("test environment lock poisoned"),
            previous_values: RefCell::new(Vec::new()),
        }
    }

    fn remember(&self, key: &OsStr) {
        let mut previous_values = self.previous_values.borrow_mut();
        if previous_values
            .iter()
            .any(|(saved_key, _)| saved_key.as_os_str() == key)
        {
            return;
        }

        previous_values.push((key.to_os_string(), env::var_os(key)));
    }

    pub fn set<K: AsRef<OsStr>, V: AsRef<OsStr>>(&self, key: K, value: V) {
        let key = key.as_ref();
        self.remember(key);
        // SAFETY: this guard serializes every test environment mutation through
        // one process-wide lock. Test targets use it only while no thread that
        // accesses the process environment is running.
        unsafe_ffi!(env::set_var(key, value));
    }

    pub fn remove<K: AsRef<OsStr>>(&self, key: K) {
        let key = key.as_ref();
        self.remember(key);
        // SAFETY: this guard serializes every test environment mutation through
        // one process-wide lock. Test targets use it only while no thread that
        // accesses the process environment is running.
        unsafe_ffi!(env::remove_var(key));
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        for (key, value) in self.previous_values.get_mut().drain(..).rev() {
            // SAFETY: `self` still owns the process-wide test environment lock,
            // so restoration has the same synchronization as mutation.
            unsafe {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }
}

pub fn setup_fake_runtime_dir(environment: &TestEnvironment) -> io::Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = PathBuf::from(format!("/tmp/fake-xdg-runtime-{nonce}"));
    fs::create_dir_all(&dir)?;
    environment.set("XDG_RUNTIME_DIR", &dir);
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
    // SAFETY: the mmap result is checked against MAP_FAILED before use, and any
    // successful mapping is released with munmap after the optional mlock call.
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
