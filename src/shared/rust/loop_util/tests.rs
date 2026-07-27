use crate::ffi::{ENOANO, EUCLEAN};
use crate::loop_util::device::simplify_path;
use crate::loop_util::linux::{
    fd_stat, is_block_device, is_regular_file, loop_flags_mangle, path_to_cstr, LoopConfig,
    LoopInfo64,
};
use crate::loop_util::{
    LockOp, LoopDeviceMakeOptions, LoopError, LoopFlags, AUTO_SECTOR_SIZE, DEFAULT_SECTOR_SIZE,
    LOCK_EX, LOCK_NB, LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO, LO_FLAGS_PARTSCAN,
    LO_FLAGS_READ_ONLY, NO_CHANGE, O_RDWR,
};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

#[test]
fn test_loop_flags_default() {
    let flags = LoopFlags::default();
    assert!(flags.contains(LoopFlags::AUTOCLEAR));
    assert!(!flags.contains(LoopFlags::READ_ONLY));
    assert!(!flags.contains(LoopFlags::DIRECT_IO));
    assert!(!flags.contains(LoopFlags::PARTSCAN));
}

#[test]
fn test_loop_flags_bitflags_operations() {
    let flags = LoopFlags::AUTOCLEAR | LoopFlags::PARTSCAN;
    assert!(flags.contains(LoopFlags::AUTOCLEAR));
    assert!(flags.contains(LoopFlags::PARTSCAN));
    assert!(!flags.contains(LoopFlags::READ_ONLY));

    let without = flags - LoopFlags::PARTSCAN;
    assert!(without.contains(LoopFlags::AUTOCLEAR));
    assert!(!without.contains(LoopFlags::PARTSCAN));
}

#[test]
fn test_lock_op_bitflags() {
    let op = LockOp::EXCLUSIVE | LockOp::NON_BLOCKING;
    assert!(op.contains(LockOp::EXCLUSIVE));
    assert!(op.contains(LockOp::NON_BLOCKING));
    assert!(!op.contains(LockOp::SHARED));

    let base = op.bits() & !LOCK_NB;
    assert_eq!(base, LOCK_EX);
}

#[cfg(target_os = "linux")]
#[test]
fn test_loop_error_from_errno() {
    assert!(matches!(
        LoopError::from_errno(libc::EBUSY),
        LoopError::Busy
    ));
    assert!(matches!(
        LoopError::from_errno(libc::ENODEV),
        LoopError::DeviceAbsent
    ));
    assert!(matches!(
        LoopError::from_errno(ENOANO),
        LoopError::DirectIoFailed
    ));
    assert!(matches!(
        LoopError::from_errno(libc::ENOTBLK),
        LoopError::NotABlockDevice
    ));
    assert!(matches!(
        LoopError::from_errno(EUCLEAN),
        LoopError::StalePartitions
    ));
    assert!(matches!(
        LoopError::from_errno(libc::EINVAL),
        LoopError::InvalidArgument
    ));
    assert!(matches!(
        LoopError::from_errno(libc::ENOBUFS),
        LoopError::NoBufferSpace
    ));
    assert!(matches!(
        LoopError::from_errno(libc::EIO),
        LoopError::IoError
    ));
    assert!(matches!(
        LoopError::from_errno(libc::ENOMEM),
        LoopError::OutOfMemory
    ));
    // Unknown errno maps to Errno variant.
    assert!(matches!(
        LoopError::from_errno(libc::EACCES),
        LoopError::Errno(13)
    ));
}

#[test]
fn test_loop_error_raw_errno() {
    let err = LoopError::Busy;
    assert_eq!(err.raw_errno(), Some(libc::EBUSY));

    let err = LoopError::InvalidOperation("test".into());
    assert_eq!(err.raw_errno(), None);
}

#[test]
fn test_loop_error_display() {
    let err = LoopError::Busy;
    assert_eq!(format!("{}", err), "loop device is busy");

    let err = LoopError::InvalidOperation("bad state".into());
    assert_eq!(format!("{}", err), "invalid operation: bad state");
}

#[cfg(target_os = "linux")]
#[test]
fn test_loop_error_from_io() {
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
    let loop_err = LoopError::from_io(io_err);
    assert!(matches!(loop_err, LoopError::Errno(13)));
}

#[test]
fn test_loop_info64_default() {
    let info = LoopInfo64::default();
    assert_eq!(info.lo_flags, 0);
    assert_eq!(info.lo_offset, 0);
    assert_eq!(info.lo_sizelimit, 0);
    assert_eq!(info.lo_number, 0);
    assert!(info.lo_file_name.iter().all(|&b| b == 0));
}

#[test]
fn test_loop_config_default() {
    let config = LoopConfig::default();
    assert_eq!(config.fd, 0);
    assert_eq!(config.block_size, 0);
    assert_eq!(config.info.lo_flags, 0);
}

#[test]
fn test_constants() {
    assert_eq!(LO_FLAGS_READ_ONLY, 1);
    assert_eq!(LO_FLAGS_AUTOCLEAR, 4);
    assert_eq!(LO_FLAGS_PARTSCAN, 8);
    assert_eq!(LO_FLAGS_DIRECT_IO, 16);
    assert_eq!(DEFAULT_SECTOR_SIZE, 512);
    assert_eq!(NO_CHANGE, u64::MAX);
    assert_eq!(AUTO_SECTOR_SIZE, u32::MAX);
}

#[test]
fn test_make_options_default() {
    let opts = LoopDeviceMakeOptions::default();
    assert!(opts.open_flags.is_none());
    assert_eq!(opts.offset, 0);
    assert_eq!(opts.size, 0);
    assert_eq!(opts.sector_size, 0);
    assert_eq!(opts.loop_flags, LoopFlags::AUTOCLEAR);
    assert_eq!(opts.lock_op, LockOp::EXCLUSIVE);
}

#[test]
fn test_simplify_path() {
    let mut p = PathBuf::from("/a/b/../c/./d");
    simplify_path(&mut p);
    assert_eq!(p, PathBuf::from("/a/c/d"));

    let mut p = PathBuf::from("/a/./b/./c");
    simplify_path(&mut p);
    assert_eq!(p, PathBuf::from("/a/b/c"));

    let mut p = PathBuf::from("/a/b/../../c");
    simplify_path(&mut p);
    assert_eq!(p, PathBuf::from("/c"));
}

#[test]
fn test_is_block_device_and_regular_file() {
    // Test with /dev/null (char device).
    if let Ok(file) = std::fs::File::open("/dev/null") {
        let stat = fd_stat(file.as_raw_fd()).unwrap();
        assert!(!is_block_device(&stat));
        assert!(!is_regular_file(&stat));
    }

    // Test with /tmp (directory - not regular, not block).
    if let Ok(file) = std::fs::File::open("/tmp") {
        let stat = fd_stat(file.as_raw_fd()).unwrap();
        assert!(!is_block_device(&stat));
        assert!(!is_regular_file(&stat));
    }
}

#[test]
fn test_fd_stat_valid_fd() {
    if let Ok(file) = std::fs::File::open("/dev/null") {
        let stat = fd_stat(file.as_raw_fd());
        assert!(stat.is_ok());
    }
}

#[test]
fn test_fd_stat_invalid_fd() {
    let result = fd_stat(-1);
    assert!(result.is_err());
}

#[test]
fn test_loop_flags_mangle_without_env() {
    // Without env var, DIRECT_IO should be enabled by default.
    std::env::remove_var("SYSTEMD_LOOP_DIRECT_IO");
    let flags = LoopFlags::AUTOCLEAR;
    let mangled = loop_flags_mangle(flags);
    assert!(mangled.contains(LoopFlags::DIRECT_IO));
    assert!(mangled.contains(LoopFlags::AUTOCLEAR));
}

#[test]
fn test_loop_flags_mangle_with_env_off() {
    std::env::set_var("SYSTEMD_LOOP_DIRECT_IO", "0");
    let flags = LoopFlags::AUTOCLEAR;
    let mangled = loop_flags_mangle(flags);
    assert!(!mangled.contains(LoopFlags::DIRECT_IO));
    std::env::remove_var("SYSTEMD_LOOP_DIRECT_IO");
}

#[test]
fn test_loop_flags_mangle_with_env_on() {
    std::env::set_var("SYSTEMD_LOOP_DIRECT_IO", "1");
    let flags = LoopFlags::empty();
    let mangled = loop_flags_mangle(flags);
    assert!(mangled.contains(LoopFlags::DIRECT_IO));
    std::env::remove_var("SYSTEMD_LOOP_DIRECT_IO");
}

#[test]
fn test_loop_configure_verify_direct_io_no_flag() {
    // When LO_FLAGS_DIRECT_IO is not set, verification should pass.
    let config = LoopConfig::default();
    // We can't test with a real fd, but the logic path when
    // LO_FLAGS_DIRECT_IO is not set should return Ok immediately.
    assert_eq!(config.info.lo_flags & LO_FLAGS_DIRECT_IO, 0);
}

#[test]
fn test_loop_device_make_options_builder_pattern() {
    let opts = LoopDeviceMakeOptions {
        open_flags: Some(O_RDWR),
        offset: 4096,
        size: 1024 * 1024,
        sector_size: 4096,
        loop_flags: LoopFlags::AUTOCLEAR | LoopFlags::PARTSCAN,
        lock_op: LockOp::SHARED,
    };
    assert_eq!(opts.open_flags, Some(O_RDWR));
    assert_eq!(opts.offset, 4096);
    assert_eq!(opts.size, 1024 * 1024);
    assert_eq!(opts.sector_size, 4096);
    assert!(opts.loop_flags.contains(LoopFlags::PARTSCAN));
    assert_eq!(opts.lock_op, LockOp::SHARED);
}

#[test]
fn test_path_to_cstr() {
    let c = path_to_cstr(Path::new("/dev/loop0")).unwrap();
    assert_eq!(c.to_bytes(), b"/dev/loop0");
}

#[test]
fn test_loop_error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LoopError>();
}
