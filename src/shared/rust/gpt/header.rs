// SPDX-License-Identifier: LGPL-2.1-or-later

/// Maximum GPT partition label length in UTF-16 code units.
pub const GPT_LABEL_MAX: usize = 36;

/// Returns whether the UTF-16 encoding fits in a GPT partition label.
pub fn gpt_partition_label_valid(label: &str) -> bool {
    label.encode_utf16().count() <= GPT_LABEL_MAX
}

/// GPT 1.0 header signature.
pub const GPT_HEADER_SIGNATURE: &[u8; 8] = b"EFI PART";

/// The only GPT revision currently defined by the specification.
pub const GPT_HEADER_REVISION: u32 = 0x0001_0000;

/// Packed size of C's `GptHeader`.
pub const GPT_HEADER_BASE_SIZE: usize = 92;

/// Validates the fields checked by C's `gpt_header_has_signature()`.
pub fn gpt_header_has_signature(data: &[u8]) -> bool {
    if data.len() < GPT_HEADER_BASE_SIZE || &data[..8] != GPT_HEADER_SIGNATURE {
        return false;
    }

    let revision = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if revision != GPT_HEADER_REVISION {
        return false;
    }

    let header_size = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
    if !(GPT_HEADER_BASE_SIZE..=4096).contains(&header_size) {
        return false;
    }

    u64::from_le_bytes(data[24..32].try_into().unwrap()) == 1
}
