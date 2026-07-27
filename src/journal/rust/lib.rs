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

#[path = "fuzz_journald_util.rs"]
pub mod fuzz_journald_util;

#[path = "journalctl_authenticate.rs"]
pub mod journalctl_authenticate;

#[path = "journalctl_catalog.rs"]
pub mod journalctl_catalog;

#[path = "journalctl_filter.rs"]
pub mod journalctl_filter;

#[path = "journalctl_misc.rs"]
pub mod journalctl_misc;

#[path = "journalctl_show.rs"]
pub mod journalctl_show;

#[path = "journalctl_util.rs"]
pub mod journalctl_util;

#[path = "journalctl_varlink_server.rs"]
pub mod journalctl_varlink_server;

#[path = "journalctl_varlink.rs"]
pub mod journalctl_varlink;

#[path = "journalctl.rs"]
pub mod journalctl;

#[path = "journald_audit.rs"]
pub mod journald_audit;

#[path = "journald_client.rs"]
pub mod journald_client;

#[path = "journald_config.rs"]
pub mod journald_config;

#[path = "journald_console.rs"]
pub mod journald_console;

#[path = "journald_context.rs"]
pub mod journald_context;

#[path = "journald_kmsg.rs"]
pub mod journald_kmsg;

#[path = "journald_manager.rs"]
pub mod journald_manager;

#[path = "journald_native.rs"]
pub mod journald_native;

#[path = "journald_runtime.rs"]
pub mod journald_runtime;

#[path = "journald_rate_limit.rs"]
pub mod journald_rate_limit;

#[path = "journald_socket.rs"]
pub mod journald_socket;

#[path = "journald_stream.rs"]
pub mod journald_stream;

#[path = "journald_sync.rs"]
pub mod journald_sync;

#[path = "journald_syslog.rs"]
pub mod journald_syslog;

#[path = "journald_varlink.rs"]
pub mod journald_varlink;

#[path = "journald_wall.rs"]
pub mod journald_wall;

#[path = "journald.rs"]
pub mod journald;

#[path = "test_journald_config.rs"]
pub mod test_journald_config;

#[path = "test_journald_rate_limit.rs"]
pub mod test_journald_rate_limit;

#[path = "test_journald_syslog.rs"]
pub mod test_journald_syslog;

#[path = "test_journald_tables.rs"]
pub mod test_journald_tables;
