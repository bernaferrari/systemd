// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::c_int;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    EINTR = 4,
    EIO = 5,
    ENOMEM = 12,
    EACCES = 13,
    EBUSY = 16,
    EEXIST = 17,
    ENODEV = 19,
    EINVAL = 22,
    ENOSYS = 38,
}

impl Errno {
    #[inline]
    pub const fn to_neg_errno(self) -> c_int {
        -(self as c_int)
    }
}
