// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/test-sd-device-thread.c
//
// Thread-safe mock sd-device references.

use std::sync::Arc;

#[derive(Debug)]
struct DeviceInner {
    syspath: String,
    properties: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct ThreadSafeDevice {
    inner: Arc<DeviceInner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadDeviceError {
    JoinFailed,
}

impl std::fmt::Display for ThreadDeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JoinFailed => f.write_str("thread join failed"),
        }
    }
}

impl std::error::Error for ThreadDeviceError {}

impl ThreadSafeDevice {
    pub fn new(syspath: &str, properties: Vec<(&str, &str)>) -> Self {
        Self {
            inner: Arc::new(DeviceInner {
                syspath: syspath.into(),
                properties: properties
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            }),
        }
    }

    pub fn syspath(&self) -> &str {
        &self.inner.syspath
    }

    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    pub fn foreach_property(&self, mut f: impl FnMut(&str, &str)) {
        for (key, value) in &self.inner.properties {
            f(key, value);
        }
    }

    pub fn unref_in_thread(self) -> Result<(), ThreadDeviceError> {
        std::thread::spawn(move || drop(self))
            .join()
            .map_err(|_| ThreadDeviceError::JoinFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> ThreadSafeDevice {
        ThreadSafeDevice::new(
            "/sys/class/net/lo",
            vec![("ACTION", "add"), ("SEQNUM", "10")],
        )
    }

    #[test]
    fn keeps_syspath() {
        assert_eq!(loopback().syspath(), "/sys/class/net/lo");
    }

    #[test]
    fn iterates_properties() {
        let mut seen = Vec::new();
        loopback().foreach_property(|k, v| seen.push((k.to_string(), v.to_string())));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn clone_increments_reference_count() {
        let device = loopback();
        let clone = device.clone();
        assert_eq!(device.strong_count(), 2);
        drop(clone);
        assert_eq!(device.strong_count(), 1);
    }

    #[test]
    fn dropping_in_thread_releases_clone() {
        let device = loopback();
        let worker_ref = device.clone();
        assert_eq!(device.strong_count(), 2);
        worker_ref.unref_in_thread().unwrap();
        assert_eq!(device.strong_count(), 1);
    }

    #[test]
    fn multiple_threaded_unref_operations_are_safe() {
        let device = loopback();
        let a = device.clone();
        let b = device.clone();
        assert_eq!(device.strong_count(), 3);
        a.unref_in_thread().unwrap();
        b.unref_in_thread().unwrap();
        assert_eq!(device.strong_count(), 1);
    }

    #[test]
    fn property_iteration_is_read_only() {
        let device = loopback();
        let before = device.strong_count();
        device.foreach_property(|_, _| {});
        assert_eq!(device.strong_count(), before);
    }

    #[test]
    fn empty_property_list_is_supported() {
        let device = ThreadSafeDevice::new("/sys/class/net/lo", vec![]);
        let mut count = 0;
        device.foreach_property(|_, _| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn thread_unref_consumes_only_the_clone() {
        let device = loopback();
        let clone = device.clone();
        clone.unref_in_thread().unwrap();
        assert_eq!(device.syspath(), "/sys/class/net/lo");
    }
}
