// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dm-util.c, src/shared/dm-util.h
//
// Device mapper utilities (deferred remove cancel, name validation).

use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

// ── Constants ─────────────────────────────────────────────────────────────

const DM_CONTROL_PATH: &str = "/dev/mapper/control";
const DM_DEFERRED_REMOVE_MSG: &str = "@cancel_deferred_remove";
const DM_DEFERRED_REMOVE_MSG_LEN: usize = DM_DEFERRED_REMOVE_MSG.len() + 1;
const DM_IOCTL: u32 = 0xfd;
const DM_TARGET_MSG_CMD: u32 = 14;
const DM_VERSION_MAJOR: u32 = 4;
const DM_VERSION_MINOR: u32 = 47;
const DM_VERSION_PATCHLEVEL: u32 = 0;
const DM_NAME_LEN: usize = 128;

// ── Name validation ───────────────────────────────────────────────────────

pub fn dm_name_is_valid(name: &str) -> bool {
    !name.is_empty() && name.len() < DM_NAME_LEN && name.bytes().all(|b| b != 0)
}

// ── DM ioctl structures ───────────────────────────────────────────────────

/// Matches kernel `struct dm_ioctl` — fields must match kernel ABI layout exactly.
#[repr(C)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding1: u32,
    dev: u64,
    name: [u8; DM_NAME_LEN],
    uuid: [u8; 129],
    data: [u8; 7],
}

#[repr(C)]
struct DmTargetMsg {
    sector: u64,
}

/// Complete in/out buffer for `DM_TARGET_MSG`.
///
/// The kernel locates `dm_target_msg` through `dm_ioctl.data_start` and then
/// reads the NUL-terminated text immediately after it, so all three fields must
/// be part of the same allocation.
#[repr(C)]
struct DmTargetMessage {
    dm_ioctl: DmIoctl,
    dm_target_msg: DmTargetMsg,
    text: [u8; DM_DEFERRED_REMOVE_MSG_LEN],
}

const _: [(); 312] = [(); std::mem::size_of::<DmIoctl>()];
const _: [(); 344] = [(); std::mem::size_of::<DmTargetMessage>()];
const _: [(); 312] = [(); std::mem::offset_of!(DmTargetMessage, dm_target_msg)];
const _: [(); 320] = [(); std::mem::offset_of!(DmTargetMessage, text)];

// ── Deferred remove cancel ────────────────────────────────────────────────

pub fn dm_deferred_remove_cancel(name: &str) -> Result<(), i32> {
    if name.len() >= DM_NAME_LEN {
        return Err(crate::ffi::Errno::ENODEV.to_neg_errno());
    }

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(DM_CONTROL_PATH)
        .map_err(|e| {
            if let Some(errno) = e.raw_os_error() {
                -errno
            } else {
                crate::ffi::Errno::EIO.to_neg_errno()
            }
        })?;

    let name_bytes = name.as_bytes();
    let msg_bytes = DM_DEFERRED_REMOVE_MSG.as_bytes();

    let mut message = DmTargetMessage {
        dm_ioctl: DmIoctl {
            version: [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCHLEVEL],
            data_size: std::mem::size_of::<DmTargetMessage>() as u32,
            data_start: std::mem::size_of::<DmIoctl>() as u32,
            target_count: 0,
            open_count: 0,
            flags: 0,
            event_nr: 0,
            padding1: 0,
            dev: 0,
            name: [0u8; DM_NAME_LEN],
            uuid: [0u8; 129],
            data: [0u8; 7],
        },
        dm_target_msg: DmTargetMsg { sector: 0 },
        text: [0u8; DM_DEFERRED_REMOVE_MSG_LEN],
    };

    message.dm_ioctl.name[..name_bytes.len()].copy_from_slice(name_bytes);
    message.text[..msg_bytes.len()].copy_from_slice(msg_bytes);

    #[cfg(target_os = "linux")]
    {
        // SAFETY: `fd` stays alive for the call, the request code describes
        // `DmIoctl`, and `message` is a writable, ABI-checked contiguous buffer
        // whose `data_size` covers the target header and NUL-terminated text.
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                libc::_IOWR::<DmIoctl>(DM_IOCTL, DM_TARGET_MSG_CMD),
                &mut message as *mut DmTargetMessage,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .map_or(crate::ffi::Errno::EIO.to_neg_errno(), |errno| -errno));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dm_name_is_valid_simple() {
        assert!(dm_name_is_valid("test-dev"));
    }

    #[test]
    fn test_dm_name_is_valid_empty() {
        assert!(!dm_name_is_valid(""));
    }

    #[test]
    fn test_dm_name_is_valid_single_char() {
        assert!(dm_name_is_valid("a"));
    }

    #[test]
    fn test_dm_name_is_valid_max_length() {
        assert!(dm_name_is_valid(&"a".repeat(127)));
    }

    #[test]
    fn test_dm_name_is_valid_too_long() {
        assert!(!dm_name_is_valid(&"a".repeat(128)));
    }

    #[test]
    fn test_dm_name_is_valid_with_hyphens() {
        assert!(dm_name_is_valid("vg-lvol0"));
        assert!(dm_name_is_valid("my--device--name"));
    }

    #[test]
    fn test_dm_name_is_valid_with_underscores() {
        assert!(dm_name_is_valid("my_device_name"));
    }

    #[test]
    fn test_dm_name_is_valid_with_dots() {
        assert!(dm_name_is_valid("dm-0"));
    }

    #[test]
    fn test_dm_deferred_remove_cancel_long_name() {
        let long_name = "a".repeat(128);
        let result = dm_deferred_remove_cancel(&long_name);
        assert_eq!(result, Err(crate::ffi::Errno::ENODEV.to_neg_errno()));
    }

    #[test]
    fn test_dm_deferred_remove_cancel_very_long_name() {
        let long_name = "x".repeat(1024);
        let result = dm_deferred_remove_cancel(&long_name);
        assert_eq!(result, Err(crate::ffi::Errno::ENODEV.to_neg_errno()));
    }

    #[test]
    fn test_dm_deferred_remove_cancel_empty_name() {
        let result = dm_deferred_remove_cancel("");
        let _ = result;
    }

    #[test]
    fn test_dm_deferred_remove_cancel_typical_name() {
        let result = dm_deferred_remove_cancel("vg0-lvol0");
        let _ = result;
    }

    #[test]
    fn test_dm_deferred_remove_msg_content() {
        assert_eq!(DM_DEFERRED_REMOVE_MSG, "@cancel_deferred_remove");
    }

    #[test]
    fn test_dm_control_path() {
        assert_eq!(DM_CONTROL_PATH, "/dev/mapper/control");
    }

    #[test]
    fn test_dm_version_constants() {
        assert_eq!(DM_VERSION_MAJOR, 4);
        assert_eq!(DM_VERSION_MINOR, 47);
        assert_eq!(DM_VERSION_PATCHLEVEL, 0);
    }

    #[test]
    fn test_dm_name_len() {
        assert_eq!(DM_NAME_LEN, 128);
    }
}
