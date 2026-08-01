// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[macro_use]
pub mod spawn;
pub mod cgroup;
#[cfg(target_os = "linux")]
pub mod epoll;
pub mod fs;
pub mod io;
pub mod mount;
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod process;
#[cfg(target_os = "linux")]
pub mod signal;
pub mod time;
