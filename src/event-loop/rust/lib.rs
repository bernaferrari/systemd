// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod loop_;
pub mod source;
pub mod timerfd;

#[cfg(target_os = "linux")]
pub mod signalfd;

use nix::errno::Errno;

pub type Result<T> = std::result::Result<T, Errno>;
