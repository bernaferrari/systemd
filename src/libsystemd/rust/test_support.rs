// SPDX-License-Identifier: LGPL-2.1-or-later

use std::cell::RefCell;
use std::env;
use std::ffi::{OsStr, OsString};
use std::sync::{LazyLock, Mutex, MutexGuard};

static TEST_ENVIRONMENT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub(crate) struct TestEnvironment {
    _lock: MutexGuard<'static, ()>,
    previous_values: RefCell<Vec<(OsString, Option<OsString>)>>,
}

impl TestEnvironment {
    /// # Safety
    ///
    /// The caller must ensure that no other thread reads or mutates the process
    /// environment until the returned guard is dropped. The lock serializes
    /// cooperating tests, but cannot synchronize arbitrary environment readers.
    pub(crate) unsafe fn lock() -> Self {
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

    pub(crate) fn set<K: AsRef<OsStr>, V: AsRef<OsStr>>(&self, key: K, value: V) {
        let key = key.as_ref();
        self.remember(key);
        // SAFETY: callers acquire this guard only in a test target that runs
        // without concurrent process-environment access.
        unsafe_ffi!(env::set_var(key, value));
    }

    pub(crate) fn remove<K: AsRef<OsStr>>(&self, key: K) {
        let key = key.as_ref();
        self.remember(key);
        // SAFETY: callers acquire this guard only in a test target that runs
        // without concurrent process-environment access.
        unsafe_ffi!(env::remove_var(key));
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        for (key, value) in self.previous_values.get_mut().drain(..).rev() {
            // SAFETY: the caller's no-concurrent-access invariant remains in
            // force while this guard owns the environment lock.
            unsafe_ffi!({
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            })
        }
    }
}
