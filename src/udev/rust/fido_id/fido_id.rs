// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/fido_id/fido_id.c

pub const SOURCE_PATH: &str = "src/udev/fido_id/fido_id.c";
pub const SOURCE_TEXT: &str = include_str!("../../fido_id/fido_id.c");

unsafe extern "C" {
    fn parse_argv(argc: i32, argv: *mut *mut libc::c_char) -> i32;
    fn run(argc: i32, argv: *mut *mut libc::c_char) -> i32;
}

#[no_mangle]
/// # Safety
/// `argv` must reference an array of `argc` valid C-string pointers.
pub unsafe extern "C" fn rs_fido_id_parse_argv(argc: i32, argv: *mut *mut libc::c_char) -> i32 {
    // SAFETY: the caller supplies the conventional argc/argv representation expected by C.
    unsafe { parse_argv(argc, argv) }
}

#[no_mangle]
/// # Safety
/// `argv` must reference an array of `argc` valid C-string pointers.
pub unsafe extern "C" fn rs_fido_id_run(argc: i32, argv: *mut *mut libc::c_char) -> i32 {
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
