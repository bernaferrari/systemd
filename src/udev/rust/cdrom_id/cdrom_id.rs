// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/cdrom_id/cdrom_id.c

pub const SOURCE_PATH: &str = "src/udev/cdrom_id/cdrom_id.c";
pub const SOURCE_TEXT: &str = include_str!("../../cdrom_id/cdrom_id.c");

#[repr(C)]
pub struct Context {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn context_clear(c: *mut Context);
    fn drive_has_feature(c: *const Context, f: i32) -> bool;
    fn set_drive_feature(c: *mut Context, f: i32) -> i32;
    fn media_lock(fd: i32, lock: bool) -> i32;
    fn media_eject(fd: i32) -> i32;
    fn cd_media_compat(c: *mut Context) -> i32;
    fn cd_inquiry(c: *mut Context) -> i32;
    fn cd_profiles(c: *mut Context) -> i32;
    fn cd_media_info(c: *mut Context) -> i32;
    fn cd_media_toc(c: *mut Context) -> i32;
    fn open_drive(c: *mut Context) -> i32;
    fn help() -> i32;
    fn parse_argv(argc: i32, argv: *mut *mut libc::c_char) -> i32;
    fn run(argc: i32, argv: *mut *mut libc::c_char) -> i32;
}

#[no_mangle]
/// # Safety
/// `c` must be null or point to a live C `Context` accepted by `context_clear`.
pub unsafe extern "C" fn rs_cdrom_id_context_clear(c: *mut Context) {
    // SAFETY: the caller supplies a Context pointer satisfying context_clear()'s contract.
    unsafe { context_clear(c) }
}

#[no_mangle]
/// # Safety
/// `c` must point to a live C `Context`.
pub unsafe extern "C" fn rs_cdrom_id_drive_has_feature(c: *const Context, f: i32) -> bool {
    // SAFETY: the caller supplies a readable Context pointer.
    unsafe { drive_has_feature(c, f) }
}

#[no_mangle]
/// # Safety
/// `c` must point to a live, uniquely borrowed C `Context`.
pub unsafe extern "C" fn rs_cdrom_id_set_drive_feature(c: *mut Context, f: i32) -> i32 {
    // SAFETY: the caller supplies a writable Context pointer.
    unsafe { set_drive_feature(c, f) }
}

#[no_mangle]
pub extern "C" fn rs_cdrom_id_media_lock(fd: i32, lock: bool) -> i32 {
    // SAFETY: media_lock() only consumes value arguments and reports invalid descriptors as errno.
    unsafe { media_lock(fd, lock) }
}

#[no_mangle]
pub extern "C" fn rs_cdrom_id_media_eject(fd: i32) -> i32 {
    // SAFETY: media_eject() only consumes a descriptor value and reports invalid descriptors as errno.
    unsafe { media_eject(fd) }
}

#[no_mangle]
/// # Safety
/// `c` must point to a live, uniquely borrowed C `Context`.
pub unsafe extern "C" fn rs_cdrom_id_cd_media_compat(c: *mut Context) -> i32 {
    // SAFETY: the caller supplies the Context pointer required by cd_media_compat().
    unsafe { cd_media_compat(c) }
}

#[no_mangle]
/// # Safety
/// `c` must point to a live, uniquely borrowed C `Context`.
pub unsafe extern "C" fn rs_cdrom_id_cd_inquiry(c: *mut Context) -> i32 {
    // SAFETY: the caller supplies the Context pointer required by cd_inquiry().
    unsafe { cd_inquiry(c) }
}

#[no_mangle]
/// # Safety
/// `c` must point to a live, uniquely borrowed C `Context`.
pub unsafe extern "C" fn rs_cdrom_id_cd_profiles(c: *mut Context) -> i32 {
    // SAFETY: the caller supplies the Context pointer required by cd_profiles().
    unsafe { cd_profiles(c) }
}

#[no_mangle]
/// # Safety
/// `c` must point to a live, uniquely borrowed C `Context`.
pub unsafe extern "C" fn rs_cdrom_id_cd_media_info(c: *mut Context) -> i32 {
    // SAFETY: the caller supplies the Context pointer required by cd_media_info().
    unsafe { cd_media_info(c) }
}

#[no_mangle]
/// # Safety
/// `c` must point to a live, uniquely borrowed C `Context`.
pub unsafe extern "C" fn rs_cdrom_id_cd_media_toc(c: *mut Context) -> i32 {
    // SAFETY: the caller supplies the Context pointer required by cd_media_toc().
    unsafe { cd_media_toc(c) }
}

#[no_mangle]
/// # Safety
/// `c` must point to a live, uniquely borrowed C `Context`.
pub unsafe extern "C" fn rs_cdrom_id_open_drive(c: *mut Context) -> i32 {
    // SAFETY: the caller supplies the Context pointer required by open_drive().
    unsafe { open_drive(c) }
}

#[no_mangle]
pub extern "C" fn rs_cdrom_id_help() -> i32 {
    // SAFETY: help() takes no arguments and has no Rust-visible memory preconditions.
    unsafe { help() }
}

#[no_mangle]
/// # Safety
/// `argv` must reference an array of `argc` valid C-string pointers.
pub unsafe extern "C" fn rs_cdrom_id_parse_argv(argc: i32, argv: *mut *mut libc::c_char) -> i32 {
    // SAFETY: the caller supplies the conventional argc/argv representation expected by C.
    unsafe { parse_argv(argc, argv) }
}

#[no_mangle]
/// # Safety
/// `argv` must reference an array of `argc` valid C-string pointers.
pub unsafe extern "C" fn rs_cdrom_id_run(argc: i32, argv: *mut *mut libc::c_char) -> i32 {
    // SAFETY: the caller supplies the conventional argc/argv representation expected by C.
    unsafe { run(argc, argv) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert!(!super::SOURCE_TEXT.is_empty());
        assert!(super::SOURCE_PATH.ends_with(".c"));
    }
}
