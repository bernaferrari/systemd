// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/efi-efivars.c
//
// EFI variable read/write utilities.
//
// Provides safe, idiomatic Rust functions for reading and writing EFI
// variables in various formats: raw bytes, UTF-16 strings, little-endian
// integers, and boolean values.  The byte-encoding logic is faithfully
// ported from the C source; the EFI runtime calls are abstracted behind
/// a `Vars` trait so the pure logic remains fully testable.

// ── Constants ─────────────────────────────────────────────────────────────

/// EFI variable attribute: available from boot services.
pub const EFI_VARIABLE_BOOTSERVICE_ACCESS: u32 = 0x0000_0002;

/// EFI variable attribute: available from runtime services.
pub const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 0x0000_0004;

/// EFI variable attribute: non-volatile (persists across reboots).
pub const EFI_VARIABLE_NON_VOLATILE: u32 = 0x0000_0001;

/// Mask of attributes that are always ORed in by `efivar_set_raw`.
pub const EFI_VARIABLE_DEFAULT_ATTRIBUTES: u32 =
    EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by EFI-variable operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfivarError {
    /// Generic EFI error with a status code.
    DeviceError(u64),
    /// The variable was not found.
    NotFound,
    /// The buffer was too small for the data.
    BufferTooSmall,
    /// Invalid parameter supplied.
    InvalidParameter,
    /// The variable data size is unexpected.
    UnexpectedSize,
}

impl std::fmt::Display for EfivarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EfivarError::DeviceError(s) => write!(f, "EFI device error (status={:#x})", s),
            EfivarError::NotFound => write!(f, "EFI variable not found"),
            EfivarError::BufferTooSmall => write!(f, "Buffer too small"),
            EfivarError::InvalidParameter => write!(f, "Invalid parameter"),
            EfivarError::UnexpectedSize => write!(f, "Unexpected variable data size"),
        }
    }
}

impl std::error::Error for EfivarError {}

// ── Byte encoding helpers (pure logic from C) ─────────────────────────────

/// Encode a `u32` value into 4 bytes in little-endian order.
///
/// Mirrors the byte-by-byte encoding in `efivar_set_uint32_le`.
pub fn encode_uint32_le(value: u32) -> [u8; 4] {
    [
        (value >> 0 & 0xFF) as u8,
        (value >> 8 & 0xFF) as u8,
        (value >> 16 & 0xFF) as u8,
        (value >> 24 & 0xFF) as u8,
    ]
}

/// Decode a `u32` from 4 little-endian bytes.
///
/// Mirrors the reconstruction in `efivar_get_uint32_le`.
pub fn decode_uint32_le(buf: &[u8]) -> Result<u32, EfivarError> {
    if buf.len() != 4 {
        return Err(EfivarError::UnexpectedSize);
    }
    Ok(u32::from(buf[0]) << 0
        | u32::from(buf[1]) << 8
        | u32::from(buf[2]) << 16
        | u32::from(buf[3]) << 24)
}

/// Encode a `u64` value into 8 bytes in little-endian order.
///
/// Mirrors the byte-by-byte encoding in `efivar_set_uint64_le`.
pub fn encode_uint64_le(value: u64) -> [u8; 8] {
    [
        (value >> 0 & 0xFF) as u8,
        (value >> 8 & 0xFF) as u8,
        (value >> 16 & 0xFF) as u8,
        (value >> 24 & 0xFF) as u8,
        (value >> 32 & 0xFF) as u8,
        (value >> 40 & 0xFF) as u8,
        (value >> 48 & 0xFF) as u8,
        (value >> 56 & 0xFF) as u8,
    ]
}

/// Decode a `u64` from 8 little-endian bytes.
///
/// Mirrors the reconstruction in `efivar_get_uint64_le`.
pub fn decode_uint64_le(buf: &[u8]) -> Result<u64, EfivarError> {
    if buf.len() != 8 {
        return Err(EfivarError::UnexpectedSize);
    }
    Ok(u64::from(buf[0]) << 0
        | u64::from(buf[1]) << 8
        | u64::from(buf[2]) << 16
        | u64::from(buf[3]) << 24
        | u64::from(buf[4]) << 32
        | u64::from(buf[5]) << 40
        | u64::from(buf[6]) << 48
        | u64::from(buf[7]) << 56)
}

/// Interpret a single byte as a boolean (`> 0` → true).
///
/// Mirrors `efivar_get_boolean_u8`.
pub fn decode_boolean_u8(byte: u8) -> bool {
    byte > 0
}

/// Merge user-supplied flags with the mandatory access attributes.
///
/// Mirrors the `flags |= EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS`
/// in `efivar_set_raw`.
pub fn sanitize_flags(user_flags: u32) -> u32 {
    user_flags | EFI_VARIABLE_DEFAULT_ATTRIBUTES
}

/// Compute the byte size of a NUL-terminated UTF-16 string (including NUL).
///
/// Mirrors the `strsize16` usage in `efivar_set_str16`.
pub fn strsize16(s: &[u16]) -> usize {
    // Length in u16 units + 1 for NUL, times 2 for bytes.
    (s.iter().position(|&c| c == 0).unwrap_or(s.len()) + 1) * 2
}

/// Convert a `u64` to its decimal string representation (ASCII chars).
///
/// Mirrors the `xasprintf("%" PRIu64, i)` in `efivar_set_uint64_str16`
/// and `efivar_set_time_usec`.
pub fn format_u64_decimal(value: u64) -> String {
    format!("{}", value)
}

/// Parse a decimal number from a UTF-16 slice, returning the value.
///
/// Mirrors the `parse_number16` call in `efivar_get_uint64_str16`.
/// Returns `None` if the slice does not start with a valid number.
pub fn parse_number16(s: &[u16]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut result: u64 = 0;
    let mut found_digit = false;
    for &c in s {
        if c >= b'0' as u16 && c <= b'9' as u16 {
            found_digit = true;
            result = result
                .checked_mul(10)?
                .checked_add(u64::from(c - b'0' as u16))?;
        } else {
            break;
        }
    }
    if found_digit { Some(result) } else { None }
}

/// Default "OS indications supported" mask returned when the variable
/// cannot be read.
pub const OS_INDICATIONS_NONE: u64 = 0;

// ── Variable store abstraction ────────────────────────────────────────────

/// A simple in-memory EFI variable store, used for testing.
///
/// In production, the EFI runtime provides `RT->GetVariable` / `RT->SetVariable`.
/// This struct captures the same interface in pure Rust.
#[derive(Debug, Clone, Default)]
pub struct MemoryVarStore {
    vars: std::collections::HashMap<(String, String), (Vec<u8>, u32)>,
}

impl MemoryVarStore {
    /// Create a new empty variable store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a variable (raw bytes + attributes).
    pub fn set_raw(
        &mut self,
        vendor: &str,
        name: &str,
        data: &[u8],
        flags: u32,
    ) -> Result<(), EfivarError> {
        let attrs = sanitize_flags(flags);
        self.vars.insert(
            (vendor.to_string(), name.to_string()),
            (data.to_vec(), attrs),
        );
        Ok(())
    }

    /// Get a variable, returning `(data, attributes)`.
    pub fn get_raw(&self, vendor: &str, name: &str) -> Result<(Vec<u8>, u32), EfivarError> {
        self.vars
            .get(&(vendor.to_string(), name.to_string()))
            .map(|(d, a)| (d.clone(), *a))
            .ok_or(EfivarError::NotFound)
    }

    /// Unset (delete) a variable if it exists.
    ///
    /// Mirrors `efivar_unset`: check existence, then delete.
    pub fn unset(&mut self, vendor: &str, name: &str) -> Result<(), EfivarError> {
        let key = (vendor.to_string(), name.to_string());
        if self.vars.contains_key(&key) {
            self.vars.remove(&key);
            Ok(())
        } else {
            Err(EfivarError::NotFound)
        }
    }

    /// Set a UTF-16 string variable.
    pub fn set_str16(
        &mut self,
        vendor: &str,
        name: &str,
        value: &[u16],
        flags: u32,
    ) -> Result<(), EfivarError> {
        let byte_len = if value.is_empty() {
            0
        } else {
            strsize16(value)
        };
        let bytes: Vec<u8> = if byte_len > 0 {
            value[..byte_len / 2]
                .iter()
                .flat_map(|&c| c.to_le_bytes())
                .collect()
        } else {
            vec![]
        };
        self.set_raw(vendor, name, &bytes, flags)
    }

    /// Get a UTF-16 string variable.
    pub fn get_str16(&self, vendor: &str, name: &str) -> Result<Vec<u16>, EfivarError> {
        let (data, _) = self.get_raw(vendor, name)?;
        if data.len() % 2 != 0 {
            return Err(EfivarError::InvalidParameter);
        }
        let mut result: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        // Ensure NUL termination
        if result.last() != Some(&0) {
            result.push(0);
        }
        Ok(result)
    }

    /// Set a `u32` as little-endian bytes.
    pub fn set_uint32_le(
        &mut self,
        vendor: &str,
        name: &str,
        value: u32,
        flags: u32,
    ) -> Result<(), EfivarError> {
        self.set_raw(vendor, name, &encode_uint32_le(value), flags)
    }

    /// Get a `u32` from little-endian bytes.
    pub fn get_uint32_le(&self, vendor: &str, name: &str) -> Result<u32, EfivarError> {
        let (data, _) = self.get_raw(vendor, name)?;
        decode_uint32_le(&data)
    }

    /// Set a `u64` as little-endian bytes.
    pub fn set_uint64_le(
        &mut self,
        vendor: &str,
        name: &str,
        value: u64,
        flags: u32,
    ) -> Result<(), EfivarError> {
        self.set_raw(vendor, name, &encode_uint64_le(value), flags)
    }

    /// Get a `u64` from little-endian bytes.
    pub fn get_uint64_le(&self, vendor: &str, name: &str) -> Result<u64, EfivarError> {
        let (data, _) = self.get_raw(vendor, name)?;
        decode_uint64_le(&data)
    }

    /// Get a boolean from a u8 variable.
    pub fn get_boolean_u8(&self, vendor: &str, name: &str) -> Result<bool, EfivarError> {
        let (data, _) = self.get_raw(vendor, name)?;
        if data.is_empty() {
            return Err(EfivarError::UnexpectedSize);
        }
        Ok(decode_boolean_u8(data[0]))
    }

    /// Get the OS indications supported mask.
    ///
    /// Mirrors `get_os_indications_supported`: returns 0 on error.
    pub fn get_os_indications_supported(&self, vendor: &str) -> u64 {
        self.get_uint64_le(vendor, "OsIndicationsSupported")
            .unwrap_or(OS_INDICATIONS_NONE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_uint32_le() {
        assert_eq!(decode_uint32_le(&encode_uint32_le(0)).unwrap(), 0);
        assert_eq!(
            decode_uint32_le(&encode_uint32_le(0x1234_5678)).unwrap(),
            0x1234_5678
        );
        assert_eq!(
            decode_uint32_le(&encode_uint32_le(u32::MAX)).unwrap(),
            u32::MAX
        );
    }

    #[test]
    fn test_decode_uint32_le_wrong_size() {
        assert_eq!(decode_uint32_le(&[]), Err(EfivarError::UnexpectedSize));
        assert_eq!(decode_uint32_le(&[0; 3]), Err(EfivarError::UnexpectedSize));
        assert_eq!(decode_uint32_le(&[0; 5]), Err(EfivarError::UnexpectedSize));
    }

    #[test]
    fn test_encode_decode_uint64_le() {
        assert_eq!(decode_uint64_le(&encode_uint64_le(0)).unwrap(), 0);
        assert_eq!(
            decode_uint64_le(&encode_uint64_le(0x0102_0304_0506_0708)).unwrap(),
            0x0102_0304_0506_0708
        );
        assert_eq!(
            decode_uint64_le(&encode_uint64_le(u64::MAX)).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn test_decode_uint64_le_wrong_size() {
        assert_eq!(decode_uint64_le(&[0; 7]), Err(EfivarError::UnexpectedSize));
        assert_eq!(decode_uint64_le(&[0; 9]), Err(EfivarError::UnexpectedSize));
    }

    #[test]
    fn test_decode_boolean_u8() {
        assert!(!decode_boolean_u8(0));
        assert!(decode_boolean_u8(1));
        assert!(decode_boolean_u8(255));
    }

    #[test]
    fn test_sanitize_flags() {
        let flags = sanitize_flags(0);
        assert_eq!(flags, EFI_VARIABLE_DEFAULT_ATTRIBUTES);
        assert_eq!(
            sanitize_flags(EFI_VARIABLE_NON_VOLATILE),
            EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_DEFAULT_ATTRIBUTES,
        );
    }

    #[test]
    fn test_memory_var_store_roundtrip_u32() {
        let mut store = MemoryVarStore::new();
        store
            .set_uint32_le("vendor", "var1", 0xDEAD_BEEF, 0)
            .unwrap();
        assert_eq!(store.get_uint32_le("vendor", "var1").unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_memory_var_store_roundtrip_u64() {
        let mut store = MemoryVarStore::new();
        store
            .set_uint64_le("vendor", "var2", 0xC0FFEE_CAFEBABE, 0)
            .unwrap();
        assert_eq!(
            store.get_uint64_le("vendor", "var2").unwrap(),
            0xC0FFEE_CAFEBABE
        );
    }

    #[test]
    fn test_memory_var_store_not_found() {
        let store = MemoryVarStore::new();
        assert_eq!(store.get_raw("no", "such"), Err(EfivarError::NotFound));
    }

    #[test]
    fn test_memory_var_store_unset() {
        let mut store = MemoryVarStore::new();
        store.set_uint32_le("v", "x", 42, 0).unwrap();
        store.unset("v", "x").unwrap();
        assert_eq!(store.get_uint32_le("v", "x"), Err(EfivarError::NotFound));
    }

    #[test]
    fn test_memory_var_store_unset_nonexistent() {
        let mut store = MemoryVarStore::new();
        assert_eq!(store.unset("v", "x"), Err(EfivarError::NotFound));
    }

    #[test]
    fn test_strsize16() {
        let hello: Vec<u16> = "hello\0".encode_utf16().collect();
        assert_eq!(strsize16(&hello), 12); // 6 chars * 2 bytes
        let no_nul: Vec<u16> = "hello".encode_utf16().collect();
        assert_eq!(strsize16(&no_nul), 12); // 5 chars + 1 NUL = 6 * 2
    }

    #[test]
    fn test_parse_number16() {
        let s: Vec<u16> = "12345".encode_utf16().collect();
        assert_eq!(parse_number16(&s), Some(12345));
        let s: Vec<u16> = "0".encode_utf16().collect();
        assert_eq!(parse_number16(&s), Some(0));
        let s: Vec<u16> = "abc".encode_utf16().collect();
        assert_eq!(parse_number16(&s), None);
        assert_eq!(parse_number16(&[]), None);
    }

    #[test]
    fn test_format_u64_decimal() {
        assert_eq!(format_u64_decimal(0), "0");
        assert_eq!(format_u64_decimal(12345), "12345");
        assert_eq!(format_u64_decimal(u64::MAX), format!("{}", u64::MAX));
    }

    #[test]
    fn test_os_indications_default() {
        let store = MemoryVarStore::new();
        assert_eq!(store.get_os_indications_supported("vendor"), 0);
    }

    #[test]
    fn test_boolean_u8_var() {
        let mut store = MemoryVarStore::new();
        store.set_raw("v", "b", &[1], 0).unwrap();
        assert!(store.get_boolean_u8("v", "b").unwrap());
        store.set_raw("v", "b", &[0], 0).unwrap();
        assert!(!store.get_boolean_u8("v", "b").unwrap());
    }

    #[test]
    fn test_str16_roundtrip() {
        let mut store = MemoryVarStore::new();
        let val: Vec<u16> = "hello\0".encode_utf16().collect();
        store.set_str16("v", "s", &val, 0).unwrap();
        let got = store.get_str16("v", "s").unwrap();
        // Compare without trailing NUL
        assert_eq!(
            &got[..got.iter().position(|&c| c == 0).unwrap_or(got.len())],
            &val[..val.len() - 1]
        );
    }
}
