// SPDX-License-Identifier: LGPL-2.1-or-later

#[cfg(target_os = "linux")]
pub use systemd_platform_rs::signal::SignalFd;

#[cfg(target_os = "linux")]
pub use crate::source::SignalEvent;
