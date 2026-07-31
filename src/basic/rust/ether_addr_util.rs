// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.ether-addr-util; authority=src/basic/ether-addr-util.c,src/basic/ether-addr-util.h

// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter documents and validates the raw-pointer,
        // ownership, and lifetime contract before evaluating this expression.
        unsafe { $expression }
    }};
}
use libc::c_char;
use std::cmp::Ordering;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::ffi::Errno;

pub const HW_ADDR_MAX_SIZE: usize = 32;
pub const ETH_ALEN: usize = 6;
pub const INFINIBAND_ALEN: usize = 20;
const HW_ADDR_TO_STRING_MAX: usize = 3 * HW_ADDR_MAX_SIZE;
const ETHER_ADDR_TO_STRING_MAX: usize = 3 * ETH_ALEN;

/// C ABI mirror of `struct hw_addr_data` used solely by the Rust shadow ABI.
#[repr(C)]
pub struct RsHwAddrData {
    pub length: usize,
    pub bytes: [u8; HW_ADDR_MAX_SIZE],
}

/// C ABI mirror of `struct ether_addr` used solely by the Rust shadow ABI.
#[repr(C)]
pub struct RsEtherAddr {
    pub octet: [u8; ETH_ALEN],
}

// The exported ABI contracts validate these pointers. Keep the raw conversion
// here so address parsing, comparison, and formatting operate only on Rust
// values and fixed slices.
fn with_hw_addr<T>(ptr: *const RsHwAddrData, operation: impl FnOnce(&RsHwAddrData) -> T) -> T {
    // SAFETY: the enclosing ABI contract guarantees a live readable RsHwAddrData.
    operation(unsafe_ffi!(&*ptr))
}

fn with_hw_addrs<T>(
    left: *const RsHwAddrData,
    right: *const RsHwAddrData,
    operation: impl FnOnce(&RsHwAddrData, &RsHwAddrData) -> T,
) -> T {
    // SAFETY: the enclosing ABI contract guarantees both live readable values.
    unsafe_ffi!(operation(&*left, &*right))
}

fn with_mut_hw_addr<T>(
    ptr: *mut RsHwAddrData,
    operation: impl FnOnce(&mut RsHwAddrData) -> T,
) -> T {
    // SAFETY: the enclosing ABI contract guarantees a live writable RsHwAddrData.
    operation(unsafe_ffi!(&mut *ptr))
}

fn with_ether_addr<T>(ptr: *const RsEtherAddr, operation: impl FnOnce(&RsEtherAddr) -> T) -> T {
    // SAFETY: the enclosing ABI contract guarantees a live readable RsEtherAddr.
    operation(unsafe_ffi!(&*ptr))
}

fn with_ether_addrs<T>(
    left: *const RsEtherAddr,
    right: *const RsEtherAddr,
    operation: impl FnOnce(&RsEtherAddr, &RsEtherAddr) -> T,
) -> T {
    // SAFETY: the enclosing ABI contract guarantees both live readable values.
    unsafe_ffi!(operation(&*left, &*right))
}

fn with_mut_ether_addr<T>(
    ptr: *mut RsEtherAddr,
    operation: impl FnOnce(&mut RsEtherAddr) -> T,
) -> T {
    // SAFETY: the enclosing ABI contract guarantees a live writable RsEtherAddr.
    operation(unsafe_ffi!(&mut *ptr))
}

fn with_c_buffer<const N: usize, T>(
    ptr: *mut c_char,
    operation: impl FnOnce(&mut [c_char; N]) -> T,
) -> T {
    // SAFETY: the enclosing ABI contract guarantees N writable C-char slots.
    operation(unsafe { &mut *ptr.cast::<[c_char; N]>() })
}

impl RsHwAddrData {
    fn bytes(&self) -> Option<&[u8]> {
        self.bytes.get(..self.length)
    }

    fn set_bytes(&mut self, bytes: &[u8]) {
        self.length = bytes.len();
        self.bytes[..bytes.len()].copy_from_slice(bytes);
    }

    fn compare(&self, other: &Self) -> Option<i32> {
        let left = self.bytes()?;
        let right = other.bytes()?;
        Some(compare_bytes(left, right))
    }

    fn is_null(&self) -> bool {
        self.bytes()
            .is_some_and(|bytes| bytes.is_empty() || bytes.iter().all(|byte| *byte == 0))
    }
}

impl RsEtherAddr {
    fn as_ether_addr(&self) -> EtherAddr {
        EtherAddr(self.octet)
    }

    fn set_ether_addr(&mut self, addr: EtherAddr) {
        self.octet = addr.0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Invalid,
    TooLong,
}

impl AddressError {
    pub const fn errno(self) -> Errno {
        match self {
            Self::Invalid => Errno::EINVAL,
            Self::TooLong => Errno::EINVAL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwAddress(Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtherAddr(pub [u8; ETH_ALEN]);

impl HwAddress {
    pub fn new(bytes: &[u8]) -> Result<Self, AddressError> {
        if bytes.len() > HW_ADDR_MAX_SIZE {
            return Err(AddressError::TooLong);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_null(&self) -> bool {
        self.0.is_empty() || self.0.iter().all(|byte| *byte == 0)
    }

    pub fn to_colon_string(&self) -> String {
        self.0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn to_string_no_colon(&self) -> String {
        self.0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }
}

impl Ord for HwAddress {
    fn cmp(&self, other: &Self) -> Ordering {
        self.len()
            .cmp(&other.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for HwAddress {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl EtherAddr {
    pub const NULL: Self = Self([0; ETH_ALEN]);

    pub fn to_colon_string(self) -> String {
        HwAddress(self.0.to_vec()).to_colon_string()
    }

    pub fn is_broadcast(self) -> bool {
        self.0.iter().all(|byte| *byte == 0xff)
    }

    pub fn is_null(self) -> bool {
        self == Self::NULL
    }

    pub fn is_multicast(self) -> bool {
        (self.0[0] & 0x01) != 0
    }

    pub fn is_unicast(self) -> bool {
        !self.is_multicast()
    }

    pub fn is_local(self) -> bool {
        (self.0[0] & 0x02) != 0
    }

    pub fn is_global(self) -> bool {
        !self.is_local()
    }

    pub fn mark_random(&mut self) {
        self.0[0] &= 0xfe;
        self.0[0] |= 0x02;
    }
}

fn is_hex_digit(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn compare_bytes(left: &[u8], right: &[u8]) -> i32 {
    // This preserves the ordering contract of the C `libc::memcmp` calls
    // without handing byte-array access to a foreign function.
    match left.cmp(right) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

fn write_hex_bytes(bytes: &[u8], separator: Option<u8>, buffer: &mut [c_char]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut cursor = 0;
    for (index, byte) in bytes.iter().enumerate() {
        buffer[cursor] = HEX[(byte >> 4) as usize] as c_char;
        cursor += 1;
        buffer[cursor] = HEX[(byte & 0x0f) as usize] as c_char;
        cursor += 1;
        if separator.is_some() && index + 1 < bytes.len() {
            buffer[cursor] = separator.unwrap() as c_char;
            cursor += 1;
        }
    }
    buffer[cursor] = 0;
}

fn hw_addr_to_string_bytes(bytes: &[u8], flags: u32, buffer: &mut [c_char; HW_ADDR_TO_STRING_MAX]) {
    write_hex_bytes(
        bytes,
        (flags & 1 == 0).then_some(b':'),
        buffer.as_mut_slice(),
    );
}

fn ether_addr_to_string_bytes(
    bytes: &[u8; ETH_ALEN],
    buffer: &mut [c_char; ETHER_ADDR_TO_STRING_MAX],
) {
    write_hex_bytes(bytes, Some(b':'), buffer.as_mut_slice());
}

fn parse_field(field: &str, field_size: usize) -> Result<Vec<u8>, AddressError> {
    if field.is_empty()
        || field.len() > field_size * 2
        || !field.as_bytes().iter().all(|ch| is_hex_digit(*ch))
    {
        return Err(AddressError::Invalid);
    }

    let mut value: u16 = 0;
    for ch in field.bytes() {
        value = (value << 4) | u16::from(hex_value(ch).ok_or(AddressError::Invalid)?);
    }

    Ok(match field_size {
        1 => vec![value as u8],
        2 => vec![(value >> 8) as u8, value as u8],
        _ => return Err(AddressError::Invalid),
    })
}

fn parse_hw_addr_text(s: &str, expected_len: usize) -> Result<HwAddress, AddressError> {
    let hex_prefix_len = s.bytes().take_while(|byte| is_hex_digit(*byte)).count();
    let sep = s
        .as_bytes()
        .get(hex_prefix_len)
        .copied()
        .ok_or(AddressError::Invalid)?;
    let field_size = match sep {
        b'.' => 2,
        b':' | b'-' => 1,
        _ => return Err(AddressError::Invalid),
    };

    let max_len = if expected_len == 0 {
        INFINIBAND_ALEN
    } else if expected_len == usize::MAX {
        HW_ADDR_MAX_SIZE
    } else {
        expected_len
    };

    if max_len % field_size != 0 {
        return Err(AddressError::Invalid);
    }

    let parts: Vec<&str> = s.split(sep as char).collect();
    if parts.iter().any(|part| part.is_empty()) || parts.len() > max_len / field_size {
        return Err(AddressError::Invalid);
    }

    let mut bytes = Vec::with_capacity(parts.len() * field_size);
    for part in parts {
        bytes.extend(parse_field(part, field_size)?);
    }

    if bytes.is_empty() {
        return Err(AddressError::Invalid);
    }

    if expected_len == 0 {
        if !matches!(bytes.len(), 4 | 16 | ETH_ALEN | INFINIBAND_ALEN) {
            return Err(AddressError::Invalid);
        }
    } else if expected_len != usize::MAX && bytes.len() != expected_len {
        return Err(AddressError::Invalid);
    }

    HwAddress::new(&bytes)
}

fn parse_ip_addr(s: &str, expected_len: usize) -> Option<HwAddress> {
    if !matches!(expected_len, 0 | 4 | 16) {
        return None;
    }

    match (expected_len, s.parse::<IpAddr>().ok()?) {
        (0, IpAddr::V4(addr)) | (4, IpAddr::V4(addr)) => HwAddress::new(&addr.octets()).ok(),
        (0, IpAddr::V6(addr)) | (16, IpAddr::V6(addr)) => HwAddress::new(&addr.octets()).ok(),
        _ => None,
    }
}

pub fn hw_addr_set(bytes: &[u8]) -> Result<HwAddress, AddressError> {
    HwAddress::new(bytes)
}

pub fn hw_addr_compare(a: &HwAddress, b: &HwAddress) -> Ordering {
    a.cmp(b)
}

pub fn parse_hw_addr_full(s: &str, expected_len: usize) -> Result<HwAddress, AddressError> {
    if expected_len > HW_ADDR_MAX_SIZE && expected_len != usize::MAX {
        return Err(AddressError::Invalid);
    }

    if let Some(ip) = parse_ip_addr(s, expected_len) {
        return Ok(ip);
    }

    parse_hw_addr_text(s, expected_len)
}

pub fn parse_ether_addr(s: &str) -> Result<EtherAddr, AddressError> {
    let parsed = parse_hw_addr_full(s, ETH_ALEN)?;
    let mut bytes = [0u8; ETH_ALEN];
    bytes.copy_from_slice(parsed.as_bytes());
    Ok(EtherAddr(bytes))
}

pub fn parse_ipv4_bytes(s: &str) -> Option<[u8; 4]> {
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V4(addr) => Some(Ipv4Addr::octets(&addr)),
        IpAddr::V6(_) => None,
    }
}

pub fn parse_ipv6_bytes(s: &str) -> Option<[u8; 16]> {
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V6(addr) => Some(Ipv6Addr::octets(&addr)),
        IpAddr::V4(_) => None,
    }
}

/// # Safety
///
/// `addr` must point to a live `RsHwAddrData` whose `length` does not exceed
/// `HW_ADDR_MAX_SIZE`; `buffer` must point to at least 96 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hw_addr_to_string_full(
    addr: *const RsHwAddrData,
    flags: u32,
    buffer: *mut c_char,
) -> *mut c_char {
    with_hw_addr(addr, |addr| {
        let Some(bytes) = addr.bytes() else {
            return ptr::null_mut();
        };
        with_c_buffer(buffer, |buffer| {
            hw_addr_to_string_bytes(bytes, flags, buffer);
            buffer.as_mut_ptr()
        })
    })
}

/// # Safety
///
/// `addr` must be writable. When `length` is nonzero, `bytes` must designate
/// at least `length` readable bytes; `length` must not exceed
/// `HW_ADDR_MAX_SIZE`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hw_addr_set(
    addr: *mut RsHwAddrData,
    bytes: *const u8,
    length: usize,
) -> *mut RsHwAddrData {
    if length > HW_ADDR_MAX_SIZE || addr.is_null() || (length > 0 && bytes.is_null()) {
        return ptr::null_mut();
    }
    // SAFETY: the public ABI contract guarantees `length` readable bytes.
    let bytes = unsafe_ffi!(std::slice::from_raw_parts(bytes, length));
    with_mut_hw_addr(addr, |addr| {
        addr.set_bytes(bytes);
        addr as *mut RsHwAddrData
    })
}

/// # Safety
///
/// Both pointers must designate live `RsHwAddrData` values with lengths no
/// larger than `HW_ADDR_MAX_SIZE`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hw_addr_compare(a: *const RsHwAddrData, b: *const RsHwAddrData) -> i32 {
    with_hw_addrs(a, b, |a, b| a.compare(b).unwrap_or(0))
}

/// # Safety
///
/// `addr` must designate a live `RsHwAddrData` with a length no larger than
/// `HW_ADDR_MAX_SIZE`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hw_addr_is_null(addr: *const RsHwAddrData) -> bool {
    with_hw_addr(addr, RsHwAddrData::is_null)
}

/// # Safety
///
/// `addr` must point to a live `RsEtherAddr`; `buffer` must point to at least
/// 18 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_to_string(
    addr: *const RsEtherAddr,
    buffer: *mut c_char,
) -> *mut c_char {
    with_ether_addr(addr, |addr| {
        with_c_buffer(buffer, |buffer| {
            ether_addr_to_string_bytes(&addr.octet, buffer);
            buffer.as_mut_ptr()
        })
    })
}

/// # Safety
///
/// Both pointers must designate live `RsEtherAddr` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_compare(
    a: *const RsEtherAddr,
    b: *const RsEtherAddr,
) -> i32 {
    with_ether_addrs(a, b, |a, b| compare_bytes(&a.octet, &b.octet))
}

/// # Safety
///
/// `addr` must designate a live `RsEtherAddr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_is_broadcast(addr: *const RsEtherAddr) -> bool {
    with_ether_addr(addr, |addr| addr.as_ether_addr().is_broadcast())
}

/// # Safety
///
/// Both pointers must designate live `RsEtherAddr` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_equal(a: *const RsEtherAddr, b: *const RsEtherAddr) -> bool {
    with_ether_addrs(a, b, |a, b| a.as_ether_addr() == b.as_ether_addr())
}

/// # Safety
///
/// `addr` must designate a live `RsEtherAddr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_is_null(addr: *const RsEtherAddr) -> bool {
    with_ether_addr(addr, |addr| addr.as_ether_addr().is_null())
}

/// # Safety
///
/// `addr` must designate a live `RsEtherAddr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_is_multicast(addr: *const RsEtherAddr) -> bool {
    with_ether_addr(addr, |addr| addr.as_ether_addr().is_multicast())
}

/// # Safety
///
/// `addr` must designate a live `RsEtherAddr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_is_unicast(addr: *const RsEtherAddr) -> bool {
    with_ether_addr(addr, |addr| addr.as_ether_addr().is_unicast())
}

/// # Safety
///
/// `addr` must designate a live `RsEtherAddr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_is_local(addr: *const RsEtherAddr) -> bool {
    with_ether_addr(addr, |addr| addr.as_ether_addr().is_local())
}

/// # Safety
///
/// `addr` must designate a live `RsEtherAddr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_is_global(addr: *const RsEtherAddr) -> bool {
    with_ether_addr(addr, |addr| addr.as_ether_addr().is_global())
}

/// # Safety
///
/// `addr` must designate a writable `RsEtherAddr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ether_addr_mark_random(addr: *mut RsEtherAddr) {
    with_mut_ether_addr(addr, |addr| {
        let mut ether = addr.as_ether_addr();
        ether.mark_random();
        addr.set_ether_addr(ether);
    });
}

/// # Safety
///
/// `s` must designate a live NUL-terminated C string and `ret` must designate
/// writable `RsHwAddrData` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_hw_addr_full(
    s: *const c_char,
    expected_len: usize,
    ret: *mut RsHwAddrData,
) -> i32 {
    // SAFETY: the documented ABI contract guarantees a readable C string.
    let Ok(text) = unsafe_ffi!(CStr::from_ptr(s)).to_str() else {
        return Errno::EINVAL.to_neg_errno();
    };
    let Ok(parsed) = parse_hw_addr_full(text, expected_len) else {
        return Errno::EINVAL.to_neg_errno();
    };
    with_mut_hw_addr(ret, |ret| {
        ret.bytes.fill(0);
        ret.set_bytes(parsed.as_bytes());
    });
    0
}

/// # Safety
///
/// `s` must designate a live NUL-terminated C string and `ret` must designate
/// writable `RsEtherAddr` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_ether_addr(s: *const c_char, ret: *mut RsEtherAddr) -> i32 {
    // SAFETY: the documented ABI contract guarantees a readable C string.
    let Ok(text) = unsafe_ffi!(CStr::from_ptr(s)).to_str() else {
        return Errno::EINVAL.to_neg_errno();
    };
    let Ok(parsed) = parse_ether_addr(text) else {
        return Errno::EINVAL.to_neg_errno();
    };
    with_mut_ether_addr(ret, |ret| ret.set_ether_addr(parsed));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hw_address_formatting_matches_c() {
        let hw = hw_addr_set(&[0x12, 0x34, 0xab, 0xcd]).unwrap();
        assert_eq!(hw.to_colon_string(), "12:34:ab:cd");
        assert_eq!(hw.to_string_no_colon(), "1234abcd");
    }

    #[test]
    fn hw_address_ordering_matches_c() {
        let shorter = hw_addr_set(&[1, 2]).unwrap();
        let longer = hw_addr_set(&[1, 2, 3]).unwrap();
        let same_len_a = hw_addr_set(&[1, 2, 3]).unwrap();
        let same_len_b = hw_addr_set(&[1, 2, 4]).unwrap();
        assert_eq!(hw_addr_compare(&shorter, &longer), Ordering::Less);
        assert_eq!(hw_addr_compare(&same_len_a, &same_len_b), Ordering::Less);
    }

    #[test]
    fn hw_address_null_detection_matches_c() {
        assert!(hw_addr_set(&[]).unwrap().is_null());
        assert!(hw_addr_set(&[0, 0, 0]).unwrap().is_null());
        assert!(!hw_addr_set(&[0, 1, 0]).unwrap().is_null());
    }

    #[test]
    fn ether_helpers_match_c() {
        let mut addr = EtherAddr([0x01, 0x23, 0x34, 0x56, 0x78, 0x9a]);
        assert_eq!(addr.to_colon_string(), "01:23:34:56:78:9a");
        assert!(addr.is_multicast());
        assert!(!addr.is_unicast());
        assert!(!addr.is_local());
        assert!(addr.is_global());
        addr.mark_random();
        assert!(!addr.is_multicast());
        assert!(addr.is_local());
    }

    #[test]
    fn ether_broadcast_and_null_match_c() {
        assert!(EtherAddr([0xff; ETH_ALEN]).is_broadcast());
        assert!(EtherAddr::NULL.is_null());
        assert!(!EtherAddr([0xff; ETH_ALEN]).is_null());
    }

    #[test]
    fn parser_accepts_ipv4_when_allowed() {
        let parsed = parse_hw_addr_full("10.0.0.1", 0).unwrap();
        assert_eq!(parsed.as_bytes(), &[10, 0, 0, 1]);
        let parsed = parse_hw_addr_full("192.168.0.1", 4).unwrap();
        assert_eq!(parsed.to_colon_string(), "c0:a8:00:01");
    }

    #[test]
    fn parser_accepts_ipv6_when_allowed() {
        let parsed = parse_hw_addr_full("::1", 0).unwrap();
        assert_eq!(parsed.len(), 16);
        assert_eq!(
            parsed.to_colon_string(),
            "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01"
        );
        let parsed = parse_hw_addr_full("1234::", 16).unwrap();
        assert_eq!(parsed.as_bytes()[0..2], [0x12, 0x34]);
    }

    #[test]
    fn parser_accepts_dot_colon_and_hyphen_formats() {
        assert_eq!(
            parse_hw_addr_full("aabb.ccdd.eeff", 6)
                .unwrap()
                .to_colon_string(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            parse_hw_addr_full("12:34:56:78:90:ab", 6)
                .unwrap()
                .to_colon_string(),
            "12:34:56:78:90:ab"
        );
        assert_eq!(
            parse_hw_addr_full("12-34-56-78-90-AB-CD-EF", 8)
                .unwrap()
                .to_colon_string(),
            "12:34:56:78:90:ab:cd:ef"
        );
    }

    #[test]
    fn parser_rejects_invalid_inputs_like_c() {
        assert_eq!(
            parse_hw_addr_full("", usize::MAX),
            Err(AddressError::Invalid)
        );
        assert_eq!(
            parse_hw_addr_full("12", usize::MAX),
            Err(AddressError::Invalid)
        );
        assert_eq!(
            parse_hw_addr_full("12:34:", usize::MAX),
            Err(AddressError::Invalid)
        );
        assert_eq!(
            parse_hw_addr_full("aa:bb-cc", usize::MAX),
            Err(AddressError::Invalid)
        );
        assert_eq!(
            parse_hw_addr_full("::1", usize::MAX),
            Err(AddressError::Invalid)
        );
    }

    #[test]
    fn parser_enforces_expected_lengths_like_c() {
        assert_eq!(parse_hw_addr_full("12:34", 0), Err(AddressError::Invalid));
        assert_eq!(
            parse_hw_addr_full("12:34", 2).unwrap().to_colon_string(),
            "12:34"
        );
        assert_eq!(
            parse_hw_addr_full("12.34.56.78", 8)
                .unwrap()
                .to_colon_string(),
            "00:12:00:34:00:56:00:78"
        );
        assert_eq!(
            parse_hw_addr_full("12.34.56.78.90", 0),
            Err(AddressError::Invalid)
        );
    }

    #[test]
    fn parse_ether_addr_matches_c() {
        assert_eq!(
            parse_ether_addr("12:34:56:78:90:ab").unwrap(),
            EtherAddr([0x12, 0x34, 0x56, 0x78, 0x90, 0xab])
        );
        assert_eq!(parse_ether_addr("12:34").err(), Some(AddressError::Invalid));
    }
}
