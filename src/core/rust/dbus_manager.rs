// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-manager.c
//

mod authorization;
mod model;
mod protocol;

pub use authorization::{
    ManagerMethodContext, authorize_manager_method_request, handle_authorized_manager_method_call,
};
pub use model::*;
pub use protocol::*;

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/dbus-manager.c";
pub type Result<T> = std::result::Result<T, Errno>;

#[cfg(test)]
mod tests;
