// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/loop-util.c, src/shared/loop-util.h
//
// Stable loop-device facade. Implementation ownership is split into an
// acyclic stack: model -> Linux adapter -> lifecycle -> allocation/discovery.

mod allocate;
mod device;
mod linux;
mod model;

pub use allocate::{
    loop_device_make, loop_device_make_by_path, loop_device_make_by_path_at,
    loop_device_make_by_path_memory,
};
pub use device::{LoopDevice, loop_device_open_from_fd, loop_device_open_from_path};
pub use model::{
    AUTO_SECTOR_SIZE, DEFAULT_SECTOR_SIZE, LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO,
    LO_FLAGS_PARTSCAN, LO_FLAGS_READ_ONLY, LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN, LockOp,
    LoopDeviceMakeOptions, LoopError, LoopFlags, NO_CHANGE, O_RDONLY, O_RDWR,
};

#[cfg(test)]
#[path = "loop_util/tests.rs"]
mod tests;
