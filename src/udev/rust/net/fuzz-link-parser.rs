// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/net/fuzz-link-parser.c
pub const SOURCE_PATH: &str = "src/udev/net/fuzz-link-parser.c";
pub const SOURCE_TEXT: &str = include_str!("../../net/fuzz-link-parser.c");

unsafe extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;
}

#[no_mangle]
/// # Safety
/// `data` must be readable for `size` bytes.
pub unsafe extern "C" fn rs_net_fuzz_link_parser(data: *const u8, size: usize) -> i32 {
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
