// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/ata_id/ata_id.c

pub const SOURCE_PATH: &str = "src/udev/ata_id/ata_id.c";
pub const SOURCE_TEXT: &str = include_str!("../../ata_id/ata_id.c");

unsafe extern "C" {
    fn disk_scsi_inquiry_command(fd: i32, buf: *mut u8, bufsize: usize) -> i32;
    fn disk_identify_command(fd: i32, buf: *mut u8, bufsize: usize) -> i32;
    fn disk_identify_packet_device_command(fd: i32, buf: *mut u8, bufsize: usize) -> i32;
    fn disk_identify_get_string(
        identify: *const u8,
        offset_words: i32,
        dest: *mut libc::c_char,
        dest_len: usize,
    );
    fn disk_identify_fixup_string(identify: *mut u8, offset_words: i32);
    fn disk_identify_fixup_uint16(identify: *mut u8, offset_words: i32);
    fn disk_identify(fd: i32, identify: *mut u8, msn: bool, is_packet_device: *mut bool) -> i32;
    fn parse_argv(argc: i32, argv: *mut *mut libc::c_char) -> i32;
    fn run(argc: i32, argv: *mut *mut libc::c_char) -> i32;
}

#[unsafe(no_mangle)]
/// # Safety
/// `buf` must be writable for `bufsize` bytes for the duration of the C call.
pub unsafe extern "C" fn rs_ata_id_disk_scsi_inquiry_command(
    fd: i32,
    buf: *mut u8,
    bufsize: usize,
) -> i32 {
    // SAFETY: the caller supplies the writable buffer required by disk_scsi_inquiry_command().
    unsafe { disk_scsi_inquiry_command(fd, buf, bufsize) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `buf` must be writable for `bufsize` bytes for the duration of the C call.
pub unsafe extern "C" fn rs_ata_id_disk_identify_command(
    fd: i32,
    buf: *mut u8,
    bufsize: usize,
) -> i32 {
    // SAFETY: the caller supplies the writable buffer required by disk_identify_command().
    unsafe { disk_identify_command(fd, buf, bufsize) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `buf` must be writable for `bufsize` bytes for the duration of the C call.
pub unsafe extern "C" fn rs_ata_id_disk_identify_packet_device_command(
    fd: i32,
    buf: *mut u8,
    bufsize: usize,
) -> i32 {
    // SAFETY: the caller supplies the writable buffer required by
    // disk_identify_packet_device_command().
    unsafe { disk_identify_packet_device_command(fd, buf, bufsize) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `identify` must reference the ATA identify data read by the C implementation,
/// and `dest` must be writable for `dest_len` bytes.
pub unsafe extern "C" fn rs_ata_id_disk_identify_get_string(
    identify: *const u8,
    offset_words: i32,
    dest: *mut libc::c_char,
    dest_len: usize,
) {
    // SAFETY: the caller supplies the source and destination ranges required by the C helper.
    unsafe { disk_identify_get_string(identify, offset_words, dest, dest_len) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `identify` must reference writable ATA identify data large enough for `offset_words`.
pub unsafe extern "C" fn rs_ata_id_disk_identify_fixup_string(
    identify: *mut u8,
    offset_words: i32,
) {
    // SAFETY: the caller supplies the writable identify buffer required by the C helper.
    unsafe { disk_identify_fixup_string(identify, offset_words) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `identify` must reference writable ATA identify data large enough for `offset_words`.
pub unsafe extern "C" fn rs_ata_id_disk_identify_fixup_uint16(
    identify: *mut u8,
    offset_words: i32,
) {
    // SAFETY: the caller supplies the writable identify buffer required by the C helper.
    unsafe { disk_identify_fixup_uint16(identify, offset_words) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `identify` must reference a writable ATA identify buffer and
/// `is_packet_device` must be a valid writable `bool`.
pub unsafe extern "C" fn rs_ata_id_disk_identify(
    fd: i32,
    identify: *mut u8,
    msn: bool,
    is_packet_device: *mut bool,
) -> i32 {
    // SAFETY: the caller supplies both writable out-parameters required by disk_identify().
    unsafe { disk_identify(fd, identify, msn, is_packet_device) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `argv` must reference an array of `argc` valid C-string pointers.
pub unsafe extern "C" fn rs_ata_id_parse_argv(argc: i32, argv: *mut *mut libc::c_char) -> i32 {
    // SAFETY: the caller supplies the conventional argc/argv representation expected by C.
    unsafe { parse_argv(argc, argv) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `argv` must reference an array of `argc` valid C-string pointers.
pub unsafe extern "C" fn rs_ata_id_run(argc: i32, argv: *mut *mut libc::c_char) -> i32 {
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
