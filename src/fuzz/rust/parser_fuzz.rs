// SPDX-License-Identifier: LGPL-2.1-or-later

// These deterministic parser fuzz targets do not require systemd's C-linked
// Rust libraries. Keep them in a small Cargo package so CI does not attempt
// to link those libraries without Meson's C objects.
// The imported modules also expose fuzz entry points that these unit tests do
// not call directly, so dead-code detection is not meaningful in this harness.
#![allow(dead_code)]

#[path = "../../shared/rust/calendarspec.rs"]
mod calendarspec;
#[path = "../../shared/rust/fuzz_calendarspec.rs"]
mod fuzz_calendarspec;
#[path = "../../resolve/rust/fuzz-dns-packet.rs"]
mod fuzz_dns_packet;
#[path = "../../journal/rust/fuzz_journald_native.rs"]
mod fuzz_journald_native;
#[path = "../../journal/rust/fuzz_journald_native_fd.rs"]
mod fuzz_journald_native_fd;
#[path = "../../network/rust/fuzz_netdev_parser.rs"]
mod fuzz_netdev_parser;
#[path = "../../network/rust/fuzz_network_parser.rs"]
mod fuzz_network_parser;
#[path = "../../udev/rust/fuzz-udev-rules.rs"]
mod fuzz_udev_rules;
#[path = "../../core/rust/fuzz_unit_file.rs"]
mod fuzz_unit_file;
