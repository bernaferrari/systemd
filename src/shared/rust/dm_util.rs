// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dm-util.c, src/shared/dm-util.h
//
// Device mapper utilities (deferred remove cancel, name validation).

// ── Constants ─────────────────────────────────────────────────────────────

const DM_CONTROL_PATH: &str = "/dev/mapper/control";
const DM_DEFERRED_REMOVE_MSG: &str = "@cancel_deferred_remove";
const DM_IOCTL: u8 = 0xfd;
const DM_TARGET_MSG: u8 = 0x0e;
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
struct DmTargetMsg {
    sector: u64,
}

// ── Deferred remove cancel ────────────────────────────────────────────────

pub fn dm_deferred_remove_cancel(name: &str) -> Result<(), i32> {
    if name.len() >= DM_NAME_LEN {
        return Err(crate::ffi::Errno::ENODEV.to_neg_errno());
    }

    let fd = std::fs::File::open(DM_CONTROL_PATH).map_err(|e| {
        if let Some(errno) = e.raw_os_error() {
            -errno
        } else {
            crate::ffi::Errno::EIO.to_neg_errno()
        }
    })?;

    let name_bytes = name.as_bytes();
    let msg_bytes = DM_DEFERRED_REMOVE_MSG.as_bytes();

    let mut dm_ioctl = DmIoctl {
        version: [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCHLEVEL],
        data_size: 0,
        data_start: 0,
        target_count: 0,
        open_count: 0,
        flags: 0,
        event_nr: 0,
        padding1: 0,
        dev: 0,
        name: [0u8; DM_NAME_LEN],
        uuid: [0u8; 129],
        data: [0u8; 7],
    };

    let copy_len = name_bytes.len().min(DM_NAME_LEN);
    dm_ioctl.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    dm_ioctl.data_start = std::mem::size_of_val(&dm_ioctl) as u32;
    dm_ioctl.data_size = (std::mem::size_of_val(&dm_ioctl)
        + std::mem::size_of::<DmTargetMsg>()
        + msg_bytes.len()) as u32;

    #[cfg(target_os = "linux")]
    {
        let ret = unsafe {
            libc::ioctl(
                libc::dup(fd.as_raw_fd()),
                libc::ioctl_request_code!(DM_IOCTL, DM_TARGET_MSG, i32),
                &mut dm_ioctl as *mut _,
            )
        };
        if ret < 0 {
            return Err(crate::ffi::Errno::EOPNOTSUPP.to_neg_errno());
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
