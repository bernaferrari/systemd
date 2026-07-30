// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
// Rust port of systemd/src/login/

pub mod inhibit;
pub mod loginctl;
pub mod logind;
pub mod logind_action;
pub mod logind_brightness;
pub mod logind_button;
pub mod logind_core;
pub mod logind_dbus;
pub mod logind_device;
pub mod logind_inhibit;
pub mod logind_polkit;
pub mod logind_seat;
pub mod logind_seat_dbus;
pub mod logind_session;
pub mod logind_session_dbus;
pub mod logind_session_device;
pub mod logind_user;
pub mod logind_user_dbus;
pub mod logind_utmp;
pub mod logind_varlink;
pub mod logind_wall;
pub mod pam_systemd;
pub mod pam_systemd_loadkey;
pub mod sysfs_show;
// These mirror C test executables and are intentionally absent from the
// production library. Keeping the module boundary here (rather than only
// gating individual test bodies) also prevents their test-only imports and
// source fixtures from becoming production API.
#[cfg(test)]
mod test_inhibit;
#[cfg(test)]
mod test_login_shared;
#[cfg(test)]
mod test_login_tables;
#[cfg(test)]
mod test_session_properties;
pub mod user_runtime_dir;
