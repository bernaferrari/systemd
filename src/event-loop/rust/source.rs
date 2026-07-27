// SPDX-License-Identifier: LGPL-2.1-or-later

use std::os::unix::io::RawFd;

pub struct IoEvent {
    pub fd: RawFd,
    pub events: u32,
    pub data: u64,
}

pub struct TimerEvent {
    pub id: usize,
}

pub struct SignalEvent {
    pub signo: i32,
    pub pid: u32,
    pub uid: u32,
}
