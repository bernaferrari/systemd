// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/fido_id/fuzz-fido-id-desc.c
pub const SOURCE_PATH: &str = "src/udev/fido_id/fuzz-fido-id-desc.c";
pub const SOURCE_TEXT: &str = include_str!("../../fido_id/fuzz-fido-id-desc.c");

unsafe extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;
}

#[no_mangle]
/// # Safety
/// `data` must be readable for `size` bytes.
pub unsafe extern "C" fn rs_fido_id_fuzz_fido_id_desc(data: *const u8, size: usize) -> i32 {
    // SAFETY: the caller supplies the readable byte range required by the fuzz target.
    unsafe { LLVMFuzzerTestOneInput(data, size) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        assert!(!SOURCE_TEXT.is_empty());
        assert!(SOURCE_PATH.ends_with(".c"));
    }
}
