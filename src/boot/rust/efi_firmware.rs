// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/efi-firmware.c
//
// EFI firmware header validation and firmware-ID matching.
//
// Validates the structure of firmware blobs (magic, sizes, NUL termination)
// and matches them by firmware ID string.

// ── Constants ─────────────────────────────────────────────────────────────

/// Magic value that identifies a valid firmware header.
pub const FW_HEADER_MAGIC: u64 = 0x5346534f4d454du64; // "MEMOSFS"

/// Alignment requirement for firmware headers.
pub const FW_HEADER_ALIGN: usize = 8;

/// Minimum header size: offset of `payload` field in `EfiFwHeader`.
/// In the C struct this is `offsetof(EfiFwHeader, payload)`.
pub const FW_HEADER_BASE_SIZE: usize = 20; // magic(8) + header_len(4) + fwid_len(4) + payload_len(4)

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from firmware header validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareError {
    /// The blob pointer is not properly aligned.
    Misaligned,
    /// The blob is too small for the base header.
    BlobTooSmall,
    /// The magic value does not match.
    InvalidMagic,
    /// The `header_len` is smaller than the base size.
    MalformedHeaderLen,
    /// Overflow in computed total size (header + fwid + payload).
    SizeOverflow,
    /// The blob is smaller than the total computed size.
    Truncated,
    /// The fwid is not NUL-terminated correctly.
    InvalidFwid,
    /// The blob pointer is null.
    NullBlob,
    /// The fwid pointer is null.
    NullFwid,
    /// The firmware ID does not match.
    FwidMismatch,
}

impl std::fmt::Display for FirmwareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirmwareError::Misaligned => write!(f, "Misaligned firmware blob"),
            FirmwareError::BlobTooSmall => write!(f, "Blob too small for header"),
            FirmwareError::InvalidMagic => write!(f, "Invalid firmware magic"),
            FirmwareError::MalformedHeaderLen => write!(f, "Malformed header_len"),
            FirmwareError::SizeOverflow => write!(f, "Size overflow in header fields"),
            FirmwareError::Truncated => write!(f, "Truncated firmware blob"),
            FirmwareError::InvalidFwid => write!(f, "Invalid (non-NUL-terminated) fwid"),
            FirmwareError::NullBlob => write!(f, "Null blob pointer"),
            FirmwareError::NullFwid => write!(f, "Null fwid pointer"),
            FirmwareError::FwidMismatch => write!(f, "Firmware ID mismatch"),
        }
    }
}

impl std::error::Error for FirmwareError {}

// ── Data structures ──────────────────────────────────────────────────────

/// Parsed firmware header fields.
///
/// Mirrors the fields read from the `EfiFwHeader` C struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareHeader {
    /// Magic value identifying a valid firmware blob.
    pub magic: u64,
    /// Total length of the header itself.
    pub header_len: u32,
    /// Length of the firmware ID string (including NUL).
    pub fwid_len: u32,
    /// Length of the payload following the fwid.
    pub payload_len: u32,
}

// ── Safe overflow-checking arithmetic ────────────────────────────────────

/// Add two `usize` values, returning `None` on overflow.
///
/// Mirrors the `ADD_SAFE` macro used in the C source.
pub fn add_safe(a: usize, b: usize) -> Option<usize> {
    a.checked_add(b)
}

// ── Parsing / validation ─────────────────────────────────────────────────

/// Parse a firmware header from a raw byte slice.
///
/// Reads the four fixed fields at the start of the blob.
fn parse_header(blob: &[u8]) -> Option<FirmwareHeader> {
    if blob.len() < FW_HEADER_BASE_SIZE {
        return None;
    }
    let magic = u64::from_le_bytes(blob[0..8].try_into().ok()?);
    let header_len = u32::from_le_bytes(blob[8..12].try_into().ok()?);
    let fwid_len = u32::from_le_bytes(blob[12..16].try_into().ok()?);
    let payload_len = u32::from_le_bytes(blob[16..20].try_into().ok()?);
    Some(FirmwareHeader {
        magic,
        header_len,
        fwid_len,
        payload_len,
    })
}

/// Validate a firmware header blob and extract the fwid / payload pointers.
///
/// Faithfully replicates the checks in `efifw_validate_header` from the C
/// source:
///   1. Alignment check
///   2. Base-size minimum
///   3. Magic check
///   4. `header_len` ≥ base size
///   5. Overflow-safe total size computation
///   6. Blob length ≥ total size
///   7. fwid NUL termination
///
/// Returns `(fwid_str, payload_offset)` on success.
pub fn validate_header(blob: &[u8]) -> Result<(&str, usize), FirmwareError> {
    if blob.is_empty() {
        return Err(FirmwareError::NullBlob);
    }

    // 1. Alignment check (simulated: in C this checks pointer alignment)
    if !(blob.as_ptr() as usize).is_multiple_of(FW_HEADER_ALIGN) {
        return Err(FirmwareError::Misaligned);
    }

    // 2. At least the base size must be present
    if blob.len() < FW_HEADER_BASE_SIZE {
        return Err(FirmwareError::BlobTooSmall);
    }

    let hdr = parse_header(blob).ok_or(FirmwareError::BlobTooSmall)?;

    // 3. Magic check
    if hdr.magic != FW_HEADER_MAGIC {
        return Err(FirmwareError::InvalidMagic);
    }

    // 4. header_len must be at least base_sz
    if (hdr.header_len as usize) < FW_HEADER_BASE_SIZE {
        return Err(FirmwareError::MalformedHeaderLen);
    }

    // 5. Overflow-safe total size: header_len + fwid_len + payload_len
    let total = add_safe(hdr.header_len as usize, hdr.fwid_len as usize)
        .and_then(|s| add_safe(s, hdr.payload_len as usize))
        .ok_or(FirmwareError::SizeOverflow)?;

    // 6. Blob must be large enough
    if blob.len() < total {
        return Err(FirmwareError::Truncated);
    }

    // 7. fwid starts at offset header_len, must be NUL-terminated at fwid_len - 1
    let fwid_start = hdr.header_len as usize;
    let fwid_end = fwid_start + hdr.fwid_len as usize;

    if fwid_len_is_zero_or_not_nul_terminated(blob, fwid_start, hdr.fwid_len as usize) {
        return Err(FirmwareError::InvalidFwid);
    }

    let fwid_bytes = &blob[fwid_start..fwid_end - 1]; // exclude NUL
    let fwid_str = std::str::from_utf8(fwid_bytes).map_err(|_| FirmwareError::InvalidFwid)?;

    let payload_offset = fwid_end;

    Ok((fwid_str, payload_offset))
}

/// Check that fwid at `[start, start+len)` is properly NUL-terminated.
fn fwid_len_is_zero_or_not_nul_terminated(blob: &[u8], start: usize, len: usize) -> bool {
    if len == 0 {
        return true; // zero-length fwid is invalid
    }
    // Last byte of the fwid region must be NUL
    blob.get(start + len - 1) != Some(&0)
}

/// Match a firmware blob by firmware ID string.
///
/// Mirrors `efi_firmware_match_by_fwid` in the C source: validates the
/// header and compares the embedded fwid with the provided string.
pub fn match_by_fwid(blob: &[u8], expected_fwid: &str) -> Result<(), FirmwareError> {
    if blob.is_empty() {
        return Err(FirmwareError::NullBlob);
    }
    if expected_fwid.is_empty() {
        return Err(FirmwareError::NullFwid);
    }

    let (fwid, _) = validate_header(blob)?;
    if fwid == expected_fwid {
        Ok(())
    } else {
        Err(FirmwareError::FwidMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a firmware blob with the given fwid string and optional payload.
    fn make_blob(fwid: &str, payload: &[u8]) -> Vec<u8> {
        let header_len = FW_HEADER_BASE_SIZE as u32;
        let fwid_bytes_with_nul = [fwid.as_bytes(), &[0u8]].concat();
        let fwid_len = fwid_bytes_with_nul.len() as u32;
        let payload_len = payload.len() as u32;

        let mut blob = Vec::new();
        blob.extend_from_slice(&FW_HEADER_MAGIC.to_le_bytes());
        blob.extend_from_slice(&header_len.to_le_bytes());
        blob.extend_from_slice(&fwid_len.to_le_bytes());
        blob.extend_from_slice(&payload_len.to_le_bytes());
        // Pad header to header_len if needed (it's exactly base size here)
        blob.extend_from_slice(&fwid_bytes_with_nul);
        blob.extend_from_slice(payload);
        blob
    }

    #[test]
    fn test_validate_header_valid() {
        let blob = make_blob("test-fw-v1", &[0xAA, 0xBB]);
        let (fwid, payload_off) = validate_header(&blob).unwrap();
        assert_eq!(fwid, "test-fw-v1");
        assert_eq!(payload_off, FW_HEADER_BASE_SIZE + "test-fw-v1".len() + 1);
    }

    #[test]
    fn test_validate_header_empty_blob() {
        assert_eq!(validate_header(&[]), Err(FirmwareError::NullBlob));
    }

    #[test]
    fn test_validate_header_too_small() {
        let blob = vec![0u8; 10];
        assert_eq!(validate_header(&blob), Err(FirmwareError::BlobTooSmall));
    }

    #[test]
    fn test_validate_header_wrong_magic() {
        let mut blob = make_blob("fwid", &[]);
        // Corrupt magic
        blob[0] = 0xFF;
        assert_eq!(validate_header(&blob), Err(FirmwareError::InvalidMagic));
    }

    #[test]
    fn test_validate_header_malformed_header_len() {
        let mut blob = make_blob("fwid", &[]);
        // Set header_len to less than base size
        let bad_len = (FW_HEADER_BASE_SIZE - 1) as u32;
        blob[8..12].copy_from_slice(&bad_len.to_le_bytes());
        assert_eq!(
            validate_header(&blob),
            Err(FirmwareError::MalformedHeaderLen)
        );
    }

    #[test]
    fn test_validate_header_truncated() {
        let mut blob = make_blob("abc", &[1, 2, 3]);
        blob.truncate(blob.len() - 2); // remove payload bytes
        assert_eq!(validate_header(&blob), Err(FirmwareError::Truncated));
    }

    #[test]
    fn test_validate_header_invalid_fwid_no_nul() {
        let header_len = FW_HEADER_BASE_SIZE as u32;
        let fwid_len = 4u32;
        let payload_len = 0u32;
        let mut blob = Vec::new();
        blob.extend_from_slice(&FW_HEADER_MAGIC.to_le_bytes());
        blob.extend_from_slice(&header_len.to_le_bytes());
        blob.extend_from_slice(&fwid_len.to_le_bytes());
        blob.extend_from_slice(&payload_len.to_le_bytes());
        // Put 4 non-NUL bytes as "fwid"
        blob.extend_from_slice(b"ABCD");
        assert_eq!(validate_header(&blob), Err(FirmwareError::InvalidFwid));
    }

    #[test]
    fn test_match_by_fwid_success() {
        let blob = make_blob("my-fw", &[]);
        assert!(match_by_fwid(&blob, "my-fw").is_ok());
    }

    #[test]
    fn test_match_by_fwid_mismatch() {
        let blob = make_blob("my-fw", &[]);
        assert_eq!(
            match_by_fwid(&blob, "other-fw"),
            Err(FirmwareError::FwidMismatch)
        );
    }

    #[test]
    fn test_match_by_fwid_empty_blob() {
        assert_eq!(match_by_fwid(&[], "fwid"), Err(FirmwareError::NullBlob));
    }

    #[test]
    fn test_add_safe() {
        assert_eq!(add_safe(1, 2), Some(3));
        assert_eq!(add_safe(usize::MAX, 1), None);
        assert_eq!(add_safe(0, 0), Some(0));
    }

    #[test]
    fn test_validate_header_with_empty_fwid() {
        // fwid_len == 0 should fail
        let header_len = FW_HEADER_BASE_SIZE as u32;
        let fwid_len = 0u32;
        let payload_len = 0u32;
        let mut blob = Vec::new();
        blob.extend_from_slice(&FW_HEADER_MAGIC.to_le_bytes());
        blob.extend_from_slice(&header_len.to_le_bytes());
        blob.extend_from_slice(&fwid_len.to_le_bytes());
        blob.extend_from_slice(&payload_len.to_le_bytes());
        assert_eq!(validate_header(&blob), Err(FirmwareError::InvalidFwid));
    }
}
