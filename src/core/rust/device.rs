// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/device.c, src/core/device.h

use crate::ffi::Errno;

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceFound(u8);

impl DeviceFound {
    pub const NOT_FOUND: Self = Self(0);
    pub const UDEV: Self = Self(1 << 0);
    pub const MOUNT: Self = Self(1 << 1);
    pub const SWAP: Self = Self(1 << 2);
    pub const MASK: Self = Self(Self::UDEV.0 | Self::MOUNT.0 | Self::SWAP.0);

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl std::ops::BitOr for DeviceFound {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceNodeOutcome {
    UdevUnavailable,
    NothingToDo,
    UpdatedOnly,
    UpdatedWithNewUnit { opened_device: Option<String> },
    IgnoredBadDeviceNode,
}

pub trait DeviceRegistry {
    fn udev_available(&self) -> bool;
    fn open_device(&mut self, node: &str) -> Result<Option<String>>;
    fn setup_unit(&mut self, node: &str, device: Option<&str>) -> Result<()>;
    fn update_found_by_name(&mut self, node: &str, found: DeviceFound, mask: DeviceFound);
}

pub fn device_found_node<R: DeviceRegistry>(
    registry: &mut R,
    node: &str,
    found: DeviceFound,
    mask: DeviceFound,
) -> Result<DeviceNodeOutcome> {
    if node.is_empty() {
        return Err(Errno::EINVAL);
    }

    if mask.contains(DeviceFound::UDEV) {
        return Err(Errno::EINVAL);
    }

    if !registry.udev_available() {
        return Ok(DeviceNodeOutcome::UdevUnavailable);
    }

    if mask.is_empty() {
        return Ok(DeviceNodeOutcome::NothingToDo);
    }

    if !found.intersect(mask).is_empty() {
        let opened_device = match registry.open_device(node) {
            Ok(device) => device,
            Err(Errno::ENODEV | Errno::EINVAL) => {
                return Ok(DeviceNodeOutcome::IgnoredBadDeviceNode)
            }
            Err(error) => return Err(error),
        };

        registry.setup_unit(node, opened_device.as_deref())?;
        registry.update_found_by_name(node, found, mask);
        return Ok(DeviceNodeOutcome::UpdatedWithNewUnit { opened_device });
    }

    registry.update_found_by_name(node, found, mask);
    Ok(DeviceNodeOutcome::UpdatedOnly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeRegistry {
        available: bool,
        open_result: Option<Result<Option<String>>>,
        updates: Vec<(String, u8, u8)>,
        setups: Vec<(String, Option<String>)>,
    }

    impl DeviceRegistry for FakeRegistry {
        fn udev_available(&self) -> bool {
            self.available
        }

        fn open_device(&mut self, _node: &str) -> Result<Option<String>> {
            self.open_result.take().unwrap_or(Ok(None))
        }

        fn setup_unit(&mut self, node: &str, device: Option<&str>) -> Result<()> {
            self.setups
                .push((node.to_string(), device.map(ToOwned::to_owned)));
            Ok(())
        }

        fn update_found_by_name(&mut self, node: &str, found: DeviceFound, mask: DeviceFound) {
            self.updates
                .push((node.to_string(), found.bits(), mask.bits()));
        }
    }

    #[test]
    fn returns_early_when_udev_is_unavailable() {
        let mut registry = FakeRegistry {
            available: false,
            ..FakeRegistry::default()
        };

        let outcome = device_found_node(
            &mut registry,
            "/dev/sda",
            DeviceFound::MOUNT,
            DeviceFound::MOUNT,
        )
        .unwrap();
        assert_eq!(outcome, DeviceNodeOutcome::UdevUnavailable);
        assert!(registry.updates.is_empty());
    }

    #[test]
    fn sets_up_unit_before_updating_state() {
        let mut registry = FakeRegistry {
            available: true,
            open_result: Some(Ok(Some("sysfs:/devices/mock0".into()))),
            ..FakeRegistry::default()
        };

        let outcome = device_found_node(
            &mut registry,
            "/dev/sda",
            DeviceFound::MOUNT,
            DeviceFound::MOUNT,
        )
        .unwrap();
        assert_eq!(
            outcome,
            DeviceNodeOutcome::UpdatedWithNewUnit {
                opened_device: Some("sysfs:/devices/mock0".into()),
            }
        );
        assert_eq!(registry.setups.len(), 1);
        assert_eq!(registry.updates.len(), 1);
    }

    #[test]
    fn ignores_invalid_device_nodes_without_updating() {
        let mut registry = FakeRegistry {
            available: true,
            open_result: Some(Err(Errno::EINVAL)),
            ..FakeRegistry::default()
        };

        let outcome = device_found_node(
            &mut registry,
            "/dev/not-a-device",
            DeviceFound::SWAP,
            DeviceFound::SWAP,
        )
        .unwrap();
        assert_eq!(outcome, DeviceNodeOutcome::IgnoredBadDeviceNode);
        assert!(registry.setups.is_empty());
        assert!(registry.updates.is_empty());
    }

    #[test]
    fn rejects_masks_that_touch_udev_bit() {
        let mut registry = FakeRegistry {
            available: true,
            ..FakeRegistry::default()
        };

        let error = device_found_node(
            &mut registry,
            "/dev/sda",
            DeviceFound::UDEV,
            DeviceFound::UDEV,
        )
        .unwrap_err();
        assert_eq!(error, Errno::EINVAL);
    }
}
