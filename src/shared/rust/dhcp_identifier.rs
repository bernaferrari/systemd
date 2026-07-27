// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd-network/sd-dhcp-duid.c, src/libsystemd-network/sd-dhcp-client-id.c
//            src/libsystemd-network/dhcp-duid-internal.h, src/libsystemd-network/dhcp-client-id-internal.h
//
// DHCP DUID (DHCP Unique Identifier) and Client Identifier types and operations.
//
// Implements RFC 8415 DUID types (LLT, EN, LL, UUID) and RFC 2132 DHCP client
// identifiers with IAID generation via SipHash-2-4.

// ── Constants ─────────────────────────────────────────────────────────────

/// systemd Private Enterprise Number (IANA-assigned)
pub const SYSTEMD_PEN: u32 = 43793;

/// DUID size limits per RFC 8415 §11.1
pub const MIN_DUID_DATA_LEN: usize = 1;
pub const MAX_DUID_DATA_LEN: usize = 128;
pub const MIN_DUID_LEN: usize = 2 + MIN_DUID_DATA_LEN;
pub const MAX_DUID_LEN: usize = 2 + MAX_DUID_DATA_LEN;

/// DHCP client ID size limits per RFC 2132 §9.14
pub const MIN_CLIENT_ID_LEN: usize = 2;
pub const MAX_CLIENT_ID_LEN: usize = 255;
pub const MIN_CLIENT_ID_DATA_LEN: usize = MIN_CLIENT_ID_LEN - 1;
pub const MAX_CLIENT_ID_DATA_LEN: usize = MAX_CLIENT_ID_LEN - 1;

/// ARP hardware types
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_INFINIBAND: u16 = 32;

/// Hardware address lengths
pub const ETH_ALEN: usize = 6;
pub const INFINIBAND_ALEN: usize = 20;
pub const HW_ADDR_MAX_SIZE: usize = INFINIBAND_ALEN;

/// Microseconds since 2000-01-01 00:00:00 UTC
const USEC_2000: u64 = 946684800_000_000;

/// SipHash-2-4 key for IAID and DUID-EN generation
const HASH_KEY: [u8; 16] = [
    0x80, 0x11, 0x8c, 0xc2, 0xfe, 0x4a, 0x03, 0xee, 0x3e, 0xd6, 0x0c, 0x6f, 0x36, 0x39, 0x14, 0x09,
];

// ── Error type ────────────────────────────────────────────────────────────

/// Errors for DHCP identifier operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpIdentifierError {
    /// Invalid input parameter (null pointer or bad argument)
    InvalidInput,
    /// Data size out of valid range
    InvalidSize,
    /// Operation not supported for the given hardware/identifier type
    NotSupported,
    /// DUID or Client ID has not been set
    NotSet,
}

impl std::fmt::Display for DhcpIdentifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "Invalid input parameter"),
            Self::InvalidSize => write!(f, "Data size out of valid range"),
            Self::NotSupported => write!(f, "Operation not supported"),
            Self::NotSet => write!(f, "Identifier not set"),
        }
    }
}

impl std::error::Error for DhcpIdentifierError {}

// ── DuidType enum ─────────────────────────────────────────────────────────

/// DUID types per RFC 8415
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DuidType {
    /// Link-layer address plus time — RFC 8415 §11.2
    Llt = 1,
    /// Vendor-assigned unique ID based on enterprise number — RFC 8415 §11.3
    En = 2,
    /// Link-layer address — RFC 8415 §11.4
    Ll = 3,
    /// UUID-based — RFC 8415 §11.5
    Uuid = 4,
}

impl DuidType {
    /// Try to convert a u16 to a known DuidType.
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(Self::Llt),
            2 => Some(Self::En),
            3 => Some(Self::Ll),
            4 => Some(Self::Uuid),
            _ => None,
        }
    }

    /// Human-readable type name for known types, e.g. `"DUID-LLT"`.
    pub fn to_type_name(self) -> Option<&'static str> {
        match self {
            Self::Llt => Some("DUID-LLT"),
            Self::En => Some("DUID-EN/Vendor"),
            Self::Ll => Some("DUID-LL"),
            Self::Uuid => Some("UUID"),
        }
    }
}

// ── Byte helpers ──────────────────────────────────────────────────────────

#[inline]
fn write_be16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset] = (val >> 8) as u8;
    buf[offset + 1] = val as u8;
}

#[inline]
fn write_be32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset] = (val >> 24) as u8;
    buf[offset + 1] = (val >> 16) as u8;
    buf[offset + 2] = (val >> 8) as u8;
    buf[offset + 3] = val as u8;
}

#[inline]
fn read_be16(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

#[inline]
fn read_be32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

#[inline]
fn write_le64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// Hex-encode bytes with `:` separators, matching the C `hexmem` output.
fn hexmem(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

// ── Duid struct ───────────────────────────────────────────────────────────

/// DHCP Unique Identifier (DUID).
///
/// Wire format: 2-byte big-endian type code followed by 1..=128 data bytes.
/// Total length: 3..=130 bytes.
#[derive(Clone)]
pub struct Duid {
    raw: [u8; MAX_DUID_LEN],
    size: usize,
}

impl Default for Duid {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Duid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Duid")
            .field("size", &self.size)
            .field("data", &&self.raw[..self.size])
            .finish()
    }
}

impl PartialEq for Duid {
    fn eq(&self, other: &Self) -> bool {
        self.raw[..self.size] == other.raw[..other.size]
    }
}

impl Eq for Duid {}

impl std::hash::Hash for Duid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.raw[..self.size].hash(state);
    }
}

impl Duid {
    /// Create an empty (unset) DUID.
    pub fn new() -> Self {
        Self {
            raw: [0u8; MAX_DUID_LEN],
            size: 0,
        }
    }

    /// Reset the DUID to an unset state.
    pub fn clear(&mut self) {
        self.raw = [0u8; MAX_DUID_LEN];
        self.size = 0;
    }

    /// Returns `true` if the DUID has a valid size.
    pub fn is_set(&self) -> bool {
        duid_size_is_valid(self.size)
    }

    /// Extract the typed DUID type and the data portion (excluding the 2-byte type header).
    ///
    /// Returns `(duid_type, data_slice)`.
    pub fn get(&self) -> Result<(DuidType, &[u8]), DhcpIdentifierError> {
        if !self.is_set() {
            return Err(DhcpIdentifierError::NotSet);
        }
        let type_val = read_be16(&self.raw, 0);
        let duid_type = DuidType::from_u16(type_val).ok_or(DhcpIdentifierError::InvalidInput)?;
        let data = &self.raw[2..self.size];
        Ok((duid_type, data))
    }

    /// Return the raw DUID bytes (including the 2-byte type header).
    pub fn get_raw(&self) -> Result<&[u8], DhcpIdentifierError> {
        if !self.is_set() {
            return Err(DhcpIdentifierError::NotSet);
        }
        Ok(&self.raw[..self.size])
    }

    /// Set DUID from a type code and data bytes.
    ///
    /// `data` is the portion *after* the 2-byte type header (1..=128 bytes).
    pub fn set(&mut self, duid_type: DuidType, data: &[u8]) -> Result<(), DhcpIdentifierError> {
        if !duid_data_size_is_valid(data.len()) {
            return Err(DhcpIdentifierError::InvalidSize);
        }
        write_be16(&mut self.raw, 0, duid_type as u16);
        self.raw[2..2 + data.len()].copy_from_slice(data);
        self.size = 2 + data.len();
        Ok(())
    }

    /// Set DUID from raw wire bytes (including the 2-byte type header).
    pub fn set_raw(&mut self, data: &[u8]) -> Result<(), DhcpIdentifierError> {
        if !duid_size_is_valid(data.len()) {
            return Err(DhcpIdentifierError::InvalidSize);
        }
        self.raw[..data.len()].copy_from_slice(data);
        self.size = data.len();
        Ok(())
    }

    /// Build a DUID-LLT (Link-Layer Time).
    ///
    /// `hw_addr` must be 6 bytes (Ethernet) or 20 bytes (InfiniBand).
    /// `usec` is a microsecond timestamp (e.g. from `clock_gettime`).
    pub fn set_llt(
        &mut self,
        hw_addr: &[u8],
        arp_type: u16,
        usec: u64,
    ) -> Result<(), DhcpIdentifierError> {
        validate_hw_addr(hw_addr, arp_type)?;

        let time_from_2000 = ((usec.saturating_sub(USEC_2000) / 1_000_000) & 0xffffffff) as u32;

        write_be16(&mut self.raw, 0, DuidType::Llt as u16);
        // LLT layout: [type:2][htype:2][time:4][haddr:..]
        write_be16(&mut self.raw, 2, arp_type);
        write_be32(&mut self.raw, 4, time_from_2000);
        self.raw[8..8 + hw_addr.len()].copy_from_slice(hw_addr);
        self.size = 8 + hw_addr.len();
        Ok(())
    }

    /// Build a DUID-LL (Link-Layer).
    ///
    /// `hw_addr` must be 6 bytes (Ethernet) or 20 bytes (InfiniBand).
    pub fn set_ll(&mut self, hw_addr: &[u8], arp_type: u16) -> Result<(), DhcpIdentifierError> {
        validate_hw_addr(hw_addr, arp_type)?;

        write_be16(&mut self.raw, 0, DuidType::Ll as u16);
        // LL layout: [type:2][htype:2][haddr:..]
        write_be16(&mut self.raw, 2, arp_type);
        self.raw[4..4 + hw_addr.len()].copy_from_slice(hw_addr);
        self.size = 4 + hw_addr.len();
        Ok(())
    }

    /// Build a DUID-EN (Enterprise Number) from a 128-bit machine ID.
    ///
    /// The machine ID is hashed with SipHash-2-4 using the systemd hash key
    /// to avoid exposing the raw machine-id.
    pub fn set_en(&mut self, machine_id: &[u8; 16]) -> Result<(), DhcpIdentifierError> {
        write_be16(&mut self.raw, 0, DuidType::En as u16);
        // EN layout: [type:2][pen:4][id:8]
        write_be32(&mut self.raw, 2, SYSTEMD_PEN);
        let hash = siphash24(machine_id, &HASH_KEY);
        write_le64(&mut self.raw, 6, hash.to_le());
        self.size = 6 + 8;
        Ok(())
    }

    /// Build a DUID-UUID from a raw 128-bit UUID.
    pub fn set_uuid(&mut self, uuid: &[u8; 16]) -> Result<(), DhcpIdentifierError> {
        write_be16(&mut self.raw, 0, DuidType::Uuid as u16);
        // UUID layout: [type:2][uuid:16]
        self.raw[2..18].copy_from_slice(uuid);
        self.size = 18;
        Ok(())
    }

    /// Format the DUID as a human-readable string.
    ///
    /// Known types produce `"DUID-LLT:xx:xx:..."` etc.
    /// Unknown types produce `"XXXX:xx:xx:..."` where XXXX is the hex type code.
    pub fn to_string(&self) -> Result<String, DhcpIdentifierError> {
        if !self.is_set() {
            return Err(DhcpIdentifierError::NotSet);
        }
        let type_val = read_be16(&self.raw, 0);
        let data = &self.raw[2..self.size];

        if !duid_data_size_is_valid(data.len()) {
            return Err(DhcpIdentifierError::InvalidSize);
        }

        let hex = hexmem(data);

        if let Some(known) = DuidType::from_u16(type_val) {
            if let Some(name) = known.to_type_name() {
                return Ok(format!("{}:{}", name, hex));
            }
        }

        Ok(format!("{:04x}:{}", type_val, hex))
    }

    /// Compare two DUIDs by raw bytes (ordering).
    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        self.raw[..self.size].cmp(&other.raw[..other.size])
    }
}

// ── ClientId struct ───────────────────────────────────────────────────────

/// DHCP Client Identifier.
///
/// Wire format: 1-byte type code followed by 1..=254 data bytes.
/// Total length: 2..=255 bytes.
#[derive(Clone)]
pub struct ClientId {
    raw: [u8; MAX_CLIENT_ID_LEN],
    size: usize,
}

impl Default for ClientId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientId")
            .field("size", &self.size)
            .field("data", &&self.raw[..self.size])
            .finish()
    }
}

impl PartialEq for ClientId {
    fn eq(&self, other: &Self) -> bool {
        self.raw[..self.size] == other.raw[..other.size]
    }
}

impl Eq for ClientId {}

impl std::hash::Hash for ClientId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.raw[..self.size].hash(state);
    }
}

impl ClientId {
    /// Create an empty (unset) client ID.
    pub fn new() -> Self {
        Self {
            raw: [0u8; MAX_CLIENT_ID_LEN],
            size: 0,
        }
    }

    /// Reset the client ID to an unset state.
    pub fn clear(&mut self) {
        self.raw = [0u8; MAX_CLIENT_ID_LEN];
        self.size = 0;
    }

    /// Returns `true` if the client ID has a valid size.
    pub fn is_set(&self) -> bool {
        client_id_size_is_valid(self.size)
    }

    /// Extract the type byte and the data portion (excluding the 1-byte type).
    pub fn get(&self) -> Result<(u8, &[u8]), DhcpIdentifierError> {
        if !self.is_set() {
            return Err(DhcpIdentifierError::NotSet);
        }
        let id_type = self.raw[0];
        let data = &self.raw[1..self.size];
        Ok((id_type, data))
    }

    /// Return the raw client ID bytes (including the 1-byte type).
    pub fn get_raw(&self) -> Result<&[u8], DhcpIdentifierError> {
        if !self.is_set() {
            return Err(DhcpIdentifierError::NotSet);
        }
        Ok(&self.raw[..self.size])
    }

    /// Set client ID from a type byte and data bytes.
    ///
    /// `data` is the portion *after* the 1-byte type (1..=254 bytes).
    pub fn set(&mut self, id_type: u8, data: &[u8]) -> Result<(), DhcpIdentifierError> {
        if !client_id_data_size_is_valid(data.len()) {
            return Err(DhcpIdentifierError::InvalidSize);
        }
        self.raw[0] = id_type;
        self.raw[1..1 + data.len()].copy_from_slice(data);
        self.size = 1 + data.len();
        Ok(())
    }

    /// Set client ID from raw wire bytes (including the 1-byte type).
    pub fn set_raw(&mut self, data: &[u8]) -> Result<(), DhcpIdentifierError> {
        if !client_id_size_is_valid(data.len()) {
            return Err(DhcpIdentifierError::InvalidSize);
        }
        self.raw[..data.len()].copy_from_slice(data);
        self.size = data.len();
        Ok(())
    }

    /// Build a client ID of type 255 (Node-specific, RFC 4361) from an IAID and DUID.
    ///
    /// Wire layout: `[0xFF][IAID:4][DUID:...]`
    pub fn set_iaid_duid(&mut self, iaid: u32, duid: &Duid) -> Result<(), DhcpIdentifierError> {
        if !duid.is_set() {
            return Err(DhcpIdentifierError::NotSet);
        }
        let duid_raw = duid.get_raw()?;

        // 1 (type) + 4 (iaid) + duid_len
        let total = 1 + 4 + duid_raw.len();
        if total > MAX_CLIENT_ID_LEN {
            return Err(DhcpIdentifierError::InvalidSize);
        }

        self.raw[0] = 255;
        write_be32(&mut self.raw, 1, iaid);
        self.raw[5..5 + duid_raw.len()].copy_from_slice(duid_raw);
        self.size = total;
        Ok(())
    }

    /// Format the client ID as a human-readable string.
    ///
    /// Type 0: printable text or `"DATA"`.
    /// Type 1: Ethernet MAC `"xx:xx:xx:xx:xx:xx"` or `"ETHER"`.
    /// Type 2..=254: `"ARP/LL"`.
    /// Type 255: `"IAID:0xXXXXX/DUID"` or `"IAID/DUID"`.
    pub fn to_string(&self) -> Result<String, DhcpIdentifierError> {
        if !self.is_set() {
            return Err(DhcpIdentifierError::NotSet);
        }

        let id_type = self.raw[0];
        let data_len = self.size - 1;
        let data = &self.raw[1..self.size];

        match id_type {
            0 => {
                if is_printable(data) {
                    Ok(String::from_utf8_lossy(data).into_owned())
                } else {
                    Ok("DATA".to_string())
                }
            }
            1 => {
                if data_len == ETH_ALEN {
                    Ok(format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        data[0], data[1], data[2], data[3], data[4], data[5]
                    ))
                } else {
                    Ok("ETHER".to_string())
                }
            }
            2..=254 => Ok("ARP/LL".to_string()),
            255 => {
                if data_len >= 4 {
                    let iaid = read_be32(data, 0);
                    Ok(format!("IAID:0x{:x}/DUID", iaid))
                } else {
                    Ok("IAID/DUID".to_string())
                }
            }
        }
    }

    /// Convenience: format raw bytes as a client ID string without constructing a `ClientId`.
    pub fn to_string_from_raw(raw: &[u8]) -> Result<String, DhcpIdentifierError> {
        let mut cid = ClientId::new();
        cid.set_raw(raw)?;
        cid.to_string()
    }

    /// Compare two client IDs by raw bytes (ordering).
    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        self.raw[..self.size].cmp(&other.raw[..other.size])
    }
}

// ── Size validation helpers ───────────────────────────────────────────────

#[inline]
fn duid_size_is_valid(size: usize) -> bool {
    (MIN_DUID_LEN..=MAX_DUID_LEN).contains(&size)
}

#[inline]
fn duid_data_size_is_valid(size: usize) -> bool {
    (MIN_DUID_DATA_LEN..=MAX_DUID_DATA_LEN).contains(&size)
}

#[inline]
fn client_id_size_is_valid(size: usize) -> bool {
    (MIN_CLIENT_ID_LEN..=MAX_CLIENT_ID_LEN).contains(&size)
}

#[inline]
fn client_id_data_size_is_valid(size: usize) -> bool {
    (MIN_CLIENT_ID_DATA_LEN..=MAX_CLIENT_ID_DATA_LEN).contains(&size)
}

// ── Hardware address validation ───────────────────────────────────────────

fn validate_hw_addr(hw_addr: &[u8], arp_type: u16) -> Result<(), DhcpIdentifierError> {
    match arp_type {
        ARPHRD_ETHER if hw_addr.len() == ETH_ALEN => Ok(()),
        ARPHRD_INFINIBAND if hw_addr.len() == INFINIBAND_ALEN => Ok(()),
        ARPHRD_ETHER | ARPHRD_INFINIBAND => Err(DhcpIdentifierError::InvalidSize),
        _ => Err(DhcpIdentifierError::NotSupported),
    }
}

// ── IAID generation ───────────────────────────────────────────────────────

/// Generate an IAID (Identity Association Identifier) from an interface name
/// or hardware address.
///
/// Matches the C `dhcp_identifier_set_iaid` logic:
/// 1. If `interface_name` is `Some`, hash it with SipHash-2-4.
/// 2. Otherwise hash `hw_addr` with SipHash-2-4.
/// 3. Fold the 64-bit hash into 32 bits.
/// 4. Adjust byte order (stable BE, or legacy native on LE).
///
/// `legacy_unstable_byteorder = true` preserves the old buggy byte-swap behaviour.
pub fn set_iaid(
    interface_name: Option<&str>,
    hw_addr: &[u8],
    legacy_unstable_byteorder: bool,
) -> u32 {
    let id: u64 = match interface_name {
        Some(name) => siphash24(name.as_bytes(), &HASH_KEY),
        None => siphash24(hw_addr, &HASH_KEY),
    };

    let mut id32 = ((id & 0xffffffff) ^ (id >> 32)) as u32;

    if legacy_unstable_byteorder {
        // Preserve historical endianness-dependent behaviour
        id32 = id32.swap_bytes();
    } else {
        // Stable big-endian result (matches legacy on little-endian hosts)
        id32 = u32::from_be(id32);
    }

    id32
}

// ── SipHash-2-4 ───────────────────────────────────────────────────────────

/// Compute SipHash-2-4 with a 16-byte key, returning a 64-bit hash.
///
/// This is a straightforward implementation of the algorithm described in
/// <https://131002.net/siphash/> — the same variant used by the C code
/// (`siphash24` in `src/basic/siphash24.{c,h}`).
pub fn siphash24(data: &[u8], key: &[u8; 16]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let mut iter = data.chunks_exact(8);
    for chunk in &mut iter {
        let mi = u64::from_le_bytes(chunk.try_into().unwrap());
        v3 ^= mi;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= mi;
    }

    // Last block: remaining bytes + length byte (padded with zeros)
    let remainder = iter.remainder();
    let last = {
        let mut buf = [0u8; 8];
        buf[..remainder.len()].copy_from_slice(remainder);
        buf[7] = data.len() as u8;
        u64::from_le_bytes(buf)
    };

    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    // Finalization
    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

// ── Printable check ───────────────────────────────────────────────────────

fn is_printable(data: &[u8]) -> bool {
    data.iter().all(|&b| b >= 0x20 && b < 0x7f)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DUID tests ──

    #[test]
    fn test_duid_new_is_unset() {
        let d = Duid::new();
        assert!(!d.is_set());
        assert!(d.get().is_err());
        assert!(d.get_raw().is_err());
    }

    #[test]
    fn test_duid_clear() {
        let mut d = Duid::new();
        d.set_ll(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], ARPHRD_ETHER)
            .unwrap();
        assert!(d.is_set());
        d.clear();
        assert!(!d.is_set());
    }

    #[test]
    fn test_duid_set_and_get() {
        let mut d = Duid::new();
        let payload = &[0x10, 0x20, 0x30];
        d.set(DuidType::En, payload).unwrap();
        assert!(d.is_set());

        let (dtype, data) = d.get().unwrap();
        assert_eq!(dtype, DuidType::En);
        assert_eq!(data, payload);

        let raw = d.get_raw().unwrap();
        assert_eq!(raw.len(), 2 + payload.len());
        assert_eq!(raw[0], 0x00);
        assert_eq!(raw[1], 0x02);
    }

    #[test]
    fn test_duid_set_raw_roundtrip() {
        let wire: &[u8] = &[
            0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10,
        ];
        let mut d = Duid::new();
        d.set_raw(wire).unwrap();
        assert_eq!(d.get_raw().unwrap(), wire);
    }

    #[test]
    fn test_duid_set_llt() {
        let mut d = Duid::new();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let usec = USEC_2000 + 1_000_000 * 12345; // 12345 seconds after 2000-01-01
        d.set_llt(&mac, ARPHRD_ETHER, usec).unwrap();
        assert!(d.is_set());

        let raw = d.get_raw().unwrap();
        // type = 0x0001, htype = 0x0001, time = BE(12345), then MAC
        assert_eq!(raw[0], 0x00);
        assert_eq!(raw[1], 0x01);
        assert_eq!(raw[2], 0x00);
        assert_eq!(raw[3], 0x01);
        assert_eq!(&raw[8..14], &mac);
        assert_eq!(raw.len(), 14);
    }

    #[test]
    fn test_duid_set_ll() {
        let mut d = Duid::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        d.set_ll(&mac, ARPHRD_ETHER).unwrap();

        let raw = d.get_raw().unwrap();
        assert_eq!(raw[0], 0x00);
        assert_eq!(raw[1], 0x03);
        assert_eq!(raw[2], 0x00);
        assert_eq!(raw[3], 0x01);
        assert_eq!(&raw[4..10], &mac);
        assert_eq!(raw.len(), 10);
    }

    #[test]
    fn test_duid_set_en_test_vector() {
        // Matches the C test_mode assertion in sd_dhcp_duid_set_en:
        // machine_id = [01..10], expected = 00:02:00:00:ab:11:61:77:40:de:13:42:c3:a2
        let machine_id: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mut d = Duid::new();
        d.set_en(&machine_id).unwrap();

        let expected: &[u8] = &[
            0x00, 0x02, 0x00, 0x00, 0xab, 0x11, 0x61, 0x77, 0x40, 0xde, 0x13, 0x42, 0xc3, 0xa2,
        ];
        assert_eq!(d.get_raw().unwrap(), expected);
    }

    #[test]
    fn test_duid_set_uuid() {
        let mut d = Duid::new();
        let uuid: [u8; 16] = [0x01; 16];
        d.set_uuid(&uuid).unwrap();

        let raw = d.get_raw().unwrap();
        assert_eq!(raw.len(), 18);
        assert_eq!(raw[0], 0x00);
        assert_eq!(raw[1], 0x04);
        assert_eq!(&raw[2..18], &[0x01u8; 16]);
    }

    #[test]
    fn test_duid_to_string() {
        let mut d = Duid::new();
        d.set_ll(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], ARPHRD_ETHER)
            .unwrap();
        let s = d.to_string().unwrap();
        assert!(s.starts_with("DUID-LL:"));
        assert!(s.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_duid_to_string_unknown_type() {
        let wire: &[u8] = &[0x00, 0x99, 0xde, 0xad]; // unknown type 0x0099
        let mut d = Duid::new();
        d.set_raw(wire).unwrap();
        let s = d.to_string().unwrap();
        assert!(s.starts_with("0099:"));
    }

    #[test]
    fn test_duid_invalid_sizes() {
        let mut d = Duid::new();
        // Data too small (0 bytes)
        assert!(d.set(DuidType::Ll, &[]).is_err());
        // Data too large (129 bytes)
        let big = [0u8; 129];
        assert!(d.set(DuidType::Ll, &big).is_err());
        // Raw too small (2 bytes)
        assert!(d.set_raw(&[0x00, 0x01]).is_err());
        // Raw too large (131 bytes)
        let raw_big = [0u8; 131];
        assert!(d.set_raw(&raw_big).is_err());
    }

    #[test]
    fn test_duid_llt_unsupported_arp() {
        let mut d = Duid::new();
        // Unsupported ARP type
        assert!(d.set_llt(&[0u8; 6], 999, 0).is_err());
    }

    #[test]
    fn test_duid_ll_wrong_mac_len() {
        let mut d = Duid::new();
        // Ethernet but wrong MAC length
        assert!(d.set_ll(&[0xaa; 4], ARPHRD_ETHER).is_err());
    }

    // ── ClientId tests ──

    #[test]
    fn test_client_id_new_is_unset() {
        let c = ClientId::new();
        assert!(!c.is_set());
        assert!(c.get().is_err());
        assert!(c.get_raw().is_err());
    }

    #[test]
    fn test_client_id_set_and_get() {
        let mut c = ClientId::new();
        let data = &[0x10, 0x20, 0x30];
        c.set(42, data).unwrap();
        assert!(c.is_set());

        let (id_type, cdata) = c.get().unwrap();
        assert_eq!(id_type, 42);
        assert_eq!(cdata, data);
    }

    #[test]
    fn test_client_id_set_raw_roundtrip() {
        let wire: &[u8] = &[0xFF, 0x00, 0x00, 0xAB, 0x11, 0x00, 0x02, 0x01, 0x02, 0x03];
        let mut c = ClientId::new();
        c.set_raw(wire).unwrap();
        assert_eq!(c.get_raw().unwrap(), wire);
    }

    #[test]
    fn test_client_id_set_iaid_duid() {
        let mut duid = Duid::new();
        duid.set_ll(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], ARPHRD_ETHER)
            .unwrap();

        let mut c = ClientId::new();
        c.set_iaid_duid(0x12345678, &duid).unwrap();

        let (id_type, data) = c.get().unwrap();
        assert_eq!(id_type, 255);
        // First 4 bytes of data = big-endian IAID
        assert_eq!(data[0], 0x12);
        assert_eq!(data[1], 0x34);
        assert_eq!(data[2], 0x56);
        assert_eq!(data[3], 0x78);
    }

    #[test]
    fn test_client_id_set_iaid_duid_unset() {
        let duid = Duid::new(); // not set
        let mut c = ClientId::new();
        assert!(c.set_iaid_duid(1, &duid).is_err());
    }

    #[test]
    fn test_client_id_to_string_type0_printable() {
        let mut c = ClientId::new();
        c.set(0, b"hello").unwrap();
        assert_eq!(c.to_string().unwrap(), "hello");
    }

    #[test]
    fn test_client_id_to_string_type0_nonprintable() {
        let mut c = ClientId::new();
        c.set(0, &[0x01, 0x02]).unwrap();
        assert_eq!(c.to_string().unwrap(), "DATA");
    }

    #[test]
    fn test_client_id_to_string_type1_mac() {
        let mut c = ClientId::new();
        c.set(1, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).unwrap();
        assert_eq!(c.to_string().unwrap(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_client_id_to_string_type1_wrong_len() {
        let mut c = ClientId::new();
        c.set(1, &[0xaa, 0xbb]).unwrap();
        assert_eq!(c.to_string().unwrap(), "ETHER");
    }

    #[test]
    fn test_client_id_to_string_type_arp() {
        let mut c = ClientId::new();
        c.set(5, &[0x01, 0x02]).unwrap();
        assert_eq!(c.to_string().unwrap(), "ARP/LL");
    }

    #[test]
    fn test_client_id_to_string_type255_iaid() {
        let mut c = ClientId::new();
        c.set(255, &[0x12, 0x34, 0x56, 0x78, 0x00]).unwrap();
        let s = c.to_string().unwrap();
        assert_eq!(s, "IAID:0x12345678/DUID");
    }

    #[test]
    fn test_client_id_to_string_type255_short() {
        let mut c = ClientId::new();
        c.set(255, &[0x01, 0x02]).unwrap(); // < 4 bytes of data
        assert_eq!(c.to_string().unwrap(), "IAID/DUID");
    }

    #[test]
    fn test_client_id_to_string_from_raw() {
        let wire: &[u8] = &[1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let s = ClientId::to_string_from_raw(wire).unwrap();
        assert_eq!(s, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_client_id_invalid_sizes() {
        let mut c = ClientId::new();
        // Data empty (0 bytes after type)
        assert!(c.set(0, &[]).is_err());
        // Data too large (255 bytes after type = 256 total > 255)
        let big = [0u8; 255];
        assert!(c.set(0, &big).is_err());
        // Raw too small (1 byte)
        assert!(c.set_raw(&[0x00]).is_err());
        // Raw too large (256 bytes)
        let raw_big = [0u8; 256];
        assert!(c.set_raw(&raw_big).is_err());
    }

    // ── Comparison / equality tests ──

    #[test]
    fn test_duid_equality() {
        let mut a = Duid::new();
        let mut b = Duid::new();
        a.set_ll(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06], ARPHRD_ETHER)
            .unwrap();
        b.set_ll(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06], ARPHRD_ETHER)
            .unwrap();
        assert_eq!(a, b);

        b.set_ll(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x07], ARPHRD_ETHER)
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_client_id_equality() {
        let mut a = ClientId::new();
        let mut b = ClientId::new();
        a.set(1, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).unwrap();
        b.set(1, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).unwrap();
        assert_eq!(a, b);

        b.set(1, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xfe]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_duid_compare_ordering() {
        let mut a = Duid::new();
        let mut b = Duid::new();
        a.set(DuidType::En, &[0x01]).unwrap();
        b.set(DuidType::Ll, &[0x01]).unwrap();
        // En (0x0002) > Ll (0x0003)? Actually 0x0002 < 0x0003
        assert_eq!(a.compare(&b), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_client_id_compare_ordering() {
        let mut a = ClientId::new();
        let mut b = ClientId::new();
        a.set(1, &[0x00]).unwrap();
        b.set(2, &[0x00]).unwrap();
        assert_eq!(a.compare(&b), std::cmp::Ordering::Less);
    }

    // ── IAID tests ──

    #[test]
    fn test_iaid_from_interface_name_deterministic() {
        let a = set_iaid(Some("eth0"), &[0u8; 6], false);
        let b = set_iaid(Some("eth0"), &[0u8; 6], false);
        assert_eq!(a, b);
    }

    #[test]
    fn test_iaid_different_names_differ() {
        let a = set_iaid(Some("eth0"), &[0u8; 6], false);
        let b = set_iaid(Some("eth1"), &[0u8; 6], false);
        assert_ne!(a, b);
    }

    #[test]
    fn test_iaid_from_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let id = set_iaid(None, &mac, false);
        assert_ne!(id, 0);
    }

    #[test]
    fn test_iaid_legacy_vs_stable() {
        let id_legacy = set_iaid(Some("eth0"), &[0u8; 6], true);
        let id_stable = set_iaid(Some("eth0"), &[0u8; 6], false);
        // On little-endian hosts the legacy byte-swap and the stable
        // big-endian conversion produce the same result.  Just verify
        // both return a valid, deterministic IAID.
        assert_ne!(id_legacy, 0);
        assert_ne!(id_stable, 0);
        // Stable result must be reproducible.
        let id_stable2 = set_iaid(Some("eth0"), &[0u8; 6], false);
        assert_eq!(id_stable, id_stable2);
    }

    // ── SipHash-2-4 tests ──

    #[test]
    fn test_siphash24_empty() {
        let key = [0u8; 16];
        let h = siphash24(&[], &key);
        // Known reference value for SipHash-2-4 with zero key and empty message
        assert_eq!(h, 0x1e924b9d_737700d7);
    }

    #[test]
    fn test_siphash24_known_vector() {
        // Reference: SipHash-2-4 test vector from the paper
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let msg: [u8; 15] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e,
        ];
        let h = siphash24(&msg, &key);
        assert_eq!(h, 0xa129ca61_49be45e5);
    }

    #[test]
    fn test_siphash24_duid_en_vector() {
        // Verify the hash used by set_en with the test machine ID matches C expectations.
        let machine_id: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let hash = siphash24(&machine_id, &HASH_KEY);
        // The C code stores htole64(hash) as the EN id.
        // Expected bytes: 61 77 40 de 13 42 c3 a2
        let expected_le_bytes: [u8; 8] = [0x61, 0x77, 0x40, 0xde, 0x13, 0x42, 0xc3, 0xa2];
        let expected = u64::from_le_bytes(expected_le_bytes);
        assert_eq!(hash.to_le(), expected);
    }

    // ── DuidType tests ──

    #[test]
    fn test_duid_type_from_u16() {
        assert_eq!(DuidType::from_u16(1), Some(DuidType::Llt));
        assert_eq!(DuidType::from_u16(2), Some(DuidType::En));
        assert_eq!(DuidType::from_u16(3), Some(DuidType::Ll));
        assert_eq!(DuidType::from_u16(4), Some(DuidType::Uuid));
        assert_eq!(DuidType::from_u16(0), None);
        assert_eq!(DuidType::from_u16(5), None);
    }

    #[test]
    fn test_duid_type_to_type_name() {
        assert_eq!(DuidType::Llt.to_type_name(), Some("DUID-LLT"));
        assert_eq!(DuidType::En.to_type_name(), Some("DUID-EN/Vendor"));
        assert_eq!(DuidType::Ll.to_type_name(), Some("DUID-LL"));
        assert_eq!(DuidType::Uuid.to_type_name(), Some("UUID"));
    }

    // ── Constant validation tests ──

    #[test]
    fn test_constants_match_c() {
        assert_eq!(SYSTEMD_PEN, 43793);
        assert_eq!(MIN_DUID_DATA_LEN, 1);
        assert_eq!(MAX_DUID_DATA_LEN, 128);
        assert_eq!(MIN_DUID_LEN, 3);
        assert_eq!(MAX_DUID_LEN, 130);
        assert_eq!(MIN_CLIENT_ID_LEN, 2);
        assert_eq!(MAX_CLIENT_ID_LEN, 255);
        assert_eq!(ARPHRD_ETHER, 1);
        assert_eq!(ARPHRD_INFINIBAND, 32);
        assert_eq!(ETH_ALEN, 6);
        assert_eq!(INFINIBAND_ALEN, 20);
    }
}
