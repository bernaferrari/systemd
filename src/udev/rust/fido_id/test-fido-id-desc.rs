// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/fido_id/test-fido-id-desc.c
pub const SOURCE_PATH: &str = "src/udev/fido_id/test-fido-id-desc.c";
pub const SOURCE_TEXT: &str = include_str!("../../fido_id/test-fido-id-desc.c");

unsafe extern "C" {
    fn is_fido_security_token_desc(desc: *const u8, size: usize) -> i32;
}

#[no_mangle]
/// # Safety
/// `desc` must be readable for `size` bytes.
pub unsafe extern "C" fn rs_fido_id_test_is_fido_security_token_desc(
    desc: *const u8,
    size: usize,
) -> i32 {
    // SAFETY: the caller supplies the readable descriptor range required by the C parser.
    unsafe { is_fido_security_token_desc(desc, size) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert!(!super::SOURCE_TEXT.is_empty());
        assert!(super::SOURCE_PATH.ends_with(".c"));
    }
}
