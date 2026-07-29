// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Rust FFI wrappers for systemd/src/journal.
//

pub struct Errno(pub i32);

pub mod port_sync;

#[path = "bsod.rs"]
pub mod bsod;

#[path = "cat.rs"]
pub mod cat;

#[path = "fuzz_journald_audit.rs"]
pub mod fuzz_journald_audit;

#[path = "fuzz_journald_kmsg.rs"]
pub mod fuzz_journald_kmsg;

#[path = "fuzz_journald_native_fd.rs"]
pub mod fuzz_journald_native_fd;

#[path = "fuzz_journald_native.rs"]
pub mod fuzz_journald_native;

#[path = "fuzz_journald_stream.rs"]
pub mod fuzz_journald_stream;

#[path = "fuzz_journald_syslog.rs"]
pub mod fuzz_journald_syslog;

#[path = "journalctl_filter.rs"]
pub mod journalctl_filter;

#[path = "journalctl.rs"]
pub mod journalctl;

#[path = "journald_runtime.rs"]
pub mod journald_runtime;
