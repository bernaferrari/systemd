// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/pcrextend/pcrextend.c
//
// Extends TPM2 Platform Configuration Registers (PCRs).
//
// Provides PCR mask manipulation, event type parsing, and data escaping
// utilities for the systemd-pcrextend tool.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of PCR indices (0–23).
pub const PCR_MAX: u32 = 24;

/// PCR index used for kernel boot measurements.
pub const TPM2_PCR_KERNEL_BOOT: u32 = 11;

/// PCR index used for system identity measurements.
pub const TPM2_PCR_SYSTEM_IDENTITY: u32 = 15;

/// Safe limit for display strings (from `EXTENSION_STRING_SAFE_LIMIT`).
pub const EXTENSION_STRING_SAFE_LIMIT: usize = 1024;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Enums ─────────────────────────────────────────────────────────────────

/// TPM2 userspace event types, mirroring `Tpm2UserspaceEventType` in the C source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2UserspaceEventType {
    Ima,
    ImaNg,
    Phase,
    Filesystem,
    MachineId,
    ProductId,
}

/// TPM2 PCR bank algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrBank {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

// ── PCR mask utilities ────────────────────────────────────────────────────

/// Convert a single PCR index to a bit mask.
/// Corresponds to the `INDEX_TO_MASK` macro.
pub fn pcr_index_to_mask(index: u32) -> u32 {
    assert!(index < PCR_MAX, "PCR index out of range");
    1u32 << index
}

/// Extract individual PCR indices from a bitmask.
/// Mirrors the `BIT_FOREACH` expansion in `extend_pcr_now()`.
pub fn pcr_mask_to_indices(mask: u32) -> Vec<u32> {
    let mut indices = Vec::new();
    for i in 0..PCR_MAX {
        if mask & (1 << i) != 0 {
            indices.push(i);
        }
    }
    indices
}

/// Build a bitmask from a slice of PCR indices.
pub fn indices_to_pcr_mask(indices: &[u32]) -> u32 {
    let mut mask = 0u32;
    for &i in indices {
        if i < PCR_MAX {
            mask |= 1 << i;
        }
    }
    mask
}

/// Check whether a PCR index is valid (0–23).
/// Corresponds to `TPM2_PCR_INDEX_VALID` in the C source.
pub fn pcr_index_valid(index: u32) -> bool {
    index < PCR_MAX
}

// ── PCR extend request ────────────────────────────────────────────────────

/// A request to extend a PCR with data.
#[derive(Debug, Clone)]
pub struct PcrExtendRequest {
    pub pcr_mask: u32,
    pub bank: PcrBank,
    pub data: Vec<u8>,
    pub event_type: Tpm2UserspaceEventType,
}

impl PcrExtendRequest {
    pub fn new(pcr_mask: u32, bank: PcrBank, data: Vec<u8>) -> Self {
        Self {
            pcr_mask,
            bank,
            data,
            event_type: Tpm2UserspaceEventType::Phase,
        }
    }

    /// Validate the request: non-empty data, at least one PCR bit set, all bits in range.
    pub fn validate(&self) -> Result<()> {
        if self.pcr_mask == 0 {
            return Err(Errno(-22)); // -EINVAL
        }
        // All set bits must be within PCR range
        let valid_mask = (1u32 << PCR_MAX) - 1;
        if self.pcr_mask & !valid_mask != 0 {
            return Err(Errno(-22));
        }
        if self.data.is_empty() {
            return Err(Errno(-22));
        }
        Ok(())
    }

    /// Format data as hexadecimal string.
    pub fn data_hex(&self) -> String {
        self.data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ── Event type parsing ────────────────────────────────────────────────────

/// Parse a `Tpm2UserspaceEventType` from its string representation.
/// Corresponds to `tpm2_userspace_event_type_from_string()`.
pub fn tpm2_userspace_event_type_from_string(s: &str) -> Result<Tpm2UserspaceEventType> {
    match s {
        "ima" => Ok(Tpm2UserspaceEventType::Ima),
        "ima-ng" => Ok(Tpm2UserspaceEventType::ImaNg),
        "phase" => Ok(Tpm2UserspaceEventType::Phase),
        "filesystem" => Ok(Tpm2UserspaceEventType::Filesystem),
        "machine-id" => Ok(Tpm2UserspaceEventType::MachineId),
        "product-id" => Ok(Tpm2UserspaceEventType::ProductId),
        _ => Err(Errno(-22)),
    }
}

/// Convert an event type back to its string representation.
pub fn tpm2_userspace_event_type_to_string(et: Tpm2UserspaceEventType) -> &'static str {
    match et {
        Tpm2UserspaceEventType::Ima => "ima",
        Tpm2UserspaceEventType::ImaNg => "ima-ng",
        Tpm2UserspaceEventType::Phase => "phase",
        Tpm2UserspaceEventType::Filesystem => "filesystem",
        Tpm2UserspaceEventType::MachineId => "machine-id",
        Tpm2UserspaceEventType::ProductId => "product-id",
    }
}

// ── Data escaping ─────────────────────────────────────────────────────────

/// Escape binary data for safe display, truncating at `max_len`.
/// Corresponds to `escape_and_truncate_data()` in the C source.
pub fn escape_and_truncate_data(data: &[u8], max_len: usize) -> String {
    let truncated = if data.len() > max_len {
        &data[..max_len]
    } else {
        data
    };
    let mut s: String = truncated
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    if data.len() > max_len {
        s.push_str("...");
    }
    s
}

/// C-escape binary data (replace non-printable with octal escapes).
/// Corresponds to `cescape_length()` used in `escape_and_truncate_data()`.
pub fn cescape(data: &[u8]) -> String {
    let mut out = String::new();
    for &b in data {
        match b {
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{:02x}", b)),
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_mask_roundtrip() {
        let indices = vec![0, 7, 11, 23];
        let mask = indices_to_pcr_mask(&indices);
        let back = pcr_mask_to_indices(mask);
        assert_eq!(back, indices);
    }

    #[test]
    fn pcr_index_to_mask_basic() {
        assert_eq!(pcr_index_to_mask(0), 1);
        assert_eq!(pcr_index_to_mask(1), 2);
        assert_eq!(pcr_index_to_mask(23), 1 << 23);
    }

    #[test]
    fn pcr_index_valid_checks() {
        assert!(pcr_index_valid(0));
        assert!(pcr_index_valid(23));
        assert!(!pcr_index_valid(24));
        assert!(!pcr_index_valid(100));
    }

    #[test]
    fn extend_request_validate_ok() {
        let req = PcrExtendRequest::new(1 << 11, PcrBank::Sha256, vec![1, 2, 3]);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn extend_request_validate_zero_mask() {
        let req = PcrExtendRequest::new(0, PcrBank::Sha256, vec![1]);
        assert!(req.validate().is_err());
    }

    #[test]
    fn extend_request_validate_empty_data() {
        let req = PcrExtendRequest::new(1 << 11, PcrBank::Sha256, vec![]);
        assert!(req.validate().is_err());
    }

    #[test]
    fn extend_request_validate_out_of_range() {
        let req = PcrExtendRequest::new(1 << 24, PcrBank::Sha256, vec![1]);
        assert!(req.validate().is_err());
    }

    #[test]
    fn data_hex_formatting() {
        let req = PcrExtendRequest::new(1, PcrBank::Sha256, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(req.data_hex(), "deadbeef");
    }

    #[test]
    fn event_type_roundtrip() {
        for et in [
            Tpm2UserspaceEventType::Ima,
            Tpm2UserspaceEventType::ImaNg,
            Tpm2UserspaceEventType::Phase,
            Tpm2UserspaceEventType::Filesystem,
            Tpm2UserspaceEventType::MachineId,
            Tpm2UserspaceEventType::ProductId,
        ] {
            let s = tpm2_userspace_event_type_to_string(et);
            assert_eq!(tpm2_userspace_event_type_from_string(s).unwrap(), et);
        }
    }

    #[test]
    fn event_type_unknown_fails() {
        assert!(tpm2_userspace_event_type_from_string("bad").is_err());
        assert!(tpm2_userspace_event_type_from_string("").is_err());
    }

    #[test]
    fn escape_and_truncate_no_truncation() {
        let data = b"hello world";
        let escaped = escape_and_truncate_data(data, 100);
        assert_eq!(escaped, "hello world");
    }

    #[test]
    fn escape_and_truncate_with_truncation() {
        let data = b"hello\x00world";
        let escaped = escape_and_truncate_data(data, 5);
        assert_eq!(escaped, "hello...");
    }

    #[test]
    fn escape_and_truncate_non_printable() {
        let data = b"abc\x01\x02def";
        let escaped = escape_and_truncate_data(data, 100);
        assert_eq!(escaped, "abc..def");
    }

    #[test]
    fn cescape_basic() {
        assert_eq!(cescape(b"hello"), "hello");
        assert_eq!(cescape(b"line\nbreak"), "line\\nbreak");
        assert_eq!(cescape(b"tab\there"), "tab\\there");
        assert_eq!(cescape(b"back\\slash"), "back\\\\slash");
    }

    #[test]
    fn cescape_non_printable() {
        let result = cescape(&[0x00, 0x01, 0xff]);
        assert!(result.contains("\\x00"));
        assert!(result.contains("\\x01"));
        assert!(result.contains("\\xff"));
    }

    #[test]
    fn pcr_mask_to_indices_empty() {
        assert!(pcr_mask_to_indices(0).is_empty());
    }

    #[test]
    fn pcr_constants() {
        assert_eq!(TPM2_PCR_KERNEL_BOOT, 11);
        assert_eq!(TPM2_PCR_SYSTEM_IDENTITY, 15);
    }
}
