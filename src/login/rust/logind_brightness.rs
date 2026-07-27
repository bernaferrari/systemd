// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-brightness.c

use std::collections::VecDeque;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrightnessDevice {
    pub sysfs_path: PathBuf,
    pub max_brightness: u32,
    pub current_brightness: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrightnessWriter {
    pub device: BrightnessDevice,
    pending: VecDeque<u32>,
    pub in_flight: Option<u32>,
}

impl BrightnessWriter {
    pub fn new(device: BrightnessDevice) -> Self {
        Self {
            device,
            pending: VecDeque::new(),
            in_flight: None,
        }
    }

    pub fn request(&mut self, brightness: u32) {
        let brightness = brightness.min(self.device.max_brightness);
        if self.in_flight.is_none() {
            self.in_flight = Some(brightness);
        } else {
            self.pending.clear();
            self.pending.push_back(brightness);
        }
    }

    pub fn complete_current(&mut self) -> Option<u32> {
        if let Some(done) = self.in_flight.take() {
            self.device.current_brightness = done;
        }
        self.in_flight = self.pending.pop_front();
        self.in_flight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_requests_replace_pending_write() {
        let device = BrightnessDevice {
            sysfs_path: PathBuf::from("/sys/class/backlight/intel_backlight"),
            max_brightness: 100,
            current_brightness: 10,
        };
        let mut writer = BrightnessWriter::new(device);
        writer.request(30);
        writer.request(40);
        writer.request(50);
        assert_eq!(writer.complete_current(), Some(50));
    }
}
