// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pcrextend-util.c, src/shared/pcrextend-util.h

use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────

pub const PCREXTEND_PATH: &str = "/usr/bin/pcrextend";
pub const PCREXTEND_VARLINK_ADDRESS: &str = "/run/systemd/io.systemd.PCRExtend";
const IMDS_USERDATA_TRUNCATED_MAX: usize = 256;

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum PcrExtendMode {
    Replace = 0,
    Extend = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
        }
    }

    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcrEvent {
    KernelConfig,
    Verity,
    ImdsUserdata,
}

impl PcrEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            PcrEvent::KernelConfig => "kernel_config",
            PcrEvent::Verity => "dm_verity",
            PcrEvent::ImdsUserdata => "imds_userdata",
        }
    }
}

/// PCR index assignments matching systemd's TPM2_PCR_* constants.
pub mod pcr_index {
    pub const KERNEL_CONFIG: u32 = 12;
    pub const KERNEL_BOOT: u32 = 12;
}

// ── Parsing ───────────────────────────────────────────────────────────────

pub fn pcrextend_parse_hash_alg(s: &str) -> Option<HashAlgorithm> {
    match s.to_lowercase().as_str() {
        "sha1" => Some(HashAlgorithm::Sha1),
        "sha256" => Some(HashAlgorithm::Sha256),
        "sha384" => Some(HashAlgorithm::Sha384),
        "sha512" => Some(HashAlgorithm::Sha512),
        _ => None,
    }
}

pub fn pcrextend_parse_mode(s: &str) -> Option<PcrExtendMode> {
    match s.to_lowercase().as_str() {
        "replace" => Some(PcrExtendMode::Replace),
        "extend" => Some(PcrExtendMode::Extend),
        _ => None,
    }
}

// ── Word Generation ───────────────────────────────────────────────────────

/// Escape colons in a string to avoid ambiguity in word format.
fn escape_colons(s: &str) -> String {
    s.replace('\\', "\\\\").replace(':', "\\x3a")
}

/// Build a "file-system:" word from components.
/// Format: `file-system:<path>:<type>:<uuid>:<label>:<part_uuid>:<part_type>:<part_name>`
/// Always produces 8 colon-separated components (prefix + 7 fields).
pub fn build_file_system_word(
    path: &str,
    fs_type: Option<&str>,
    uuid: Option<&str>,
    label: Option<&str>,
    part_uuid: Option<&str>,
    part_type: Option<&str>,
    part_name: Option<&str>,
) -> String {
    let escaped_path = escape_colons(path);
    let prefix = format!("file-system:{escaped_path}");
    let fields = [
        fs_type.unwrap_or(""),
        uuid.unwrap_or(""),
        label.unwrap_or(""),
        part_uuid.unwrap_or(""),
        part_type.unwrap_or(""),
        part_name.unwrap_or(""),
    ];
    let escaped: Vec<String> = fields.iter().map(|f| escape_colons(f)).collect();
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        prefix, escaped[0], escaped[1], escaped[2], escaped[3], escaped[4], escaped[5]
    )
}

/// Build a "machine-id:" word from a 128-bit ID.
/// Format: `machine-id:<hex-string>`
pub fn build_machine_id_word(id_bytes: &[u8; 16]) -> String {
    let hex: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("machine-id:{hex}")
}

/// Build a "product-id:" word from a 128-bit product UUID.
pub fn build_product_id_word(id_bytes: Option<&[u8; 16]>) -> String {
    match id_bytes {
        Some(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            format!("product-id:{hex}")
        }
        None => "product-id:missing".to_string(),
    }
}

/// Build a "verity:" word from a name, root hash, and optional signature data.
/// Format: `verity:<name>:<root-hash-hex>:<sig1-serial/base64-issuer>,<sig2-...>`
pub fn build_verity_word(name: &str, root_hash: &[u8], sig_data: Option<&str>) -> String {
    let name_escaped = escape_colons(name);
    let hash_hex: String = root_hash.iter().map(|b| format!("{b:02x}")).collect();
    let sigs = sig_data.unwrap_or("");
    format!("verity:{name_escaped}:{hash_hex}:{sigs}")
}

/// Build an "imds-userdata:" word from userdata bytes.
/// Format: `imds-userdata:<sha256-hex>:<truncated-base64>`
pub fn build_imds_userdata_word(data: &[u8], sha256_hex: &str) -> String {
    use std::io::Write;
    let truncated: Vec<u8> = data
        .iter()
        .copied()
        .take(IMDS_USERDATA_TRUNCATED_MAX)
        .collect();
    let encoded = base64_encode(&truncated);
    format!("imds-userdata:{sha256_hex}:{encoded}")
}

/// Minimal base64 encoding without external dependencies.
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push(TABLE[(n & 0x3F) as usize] as char);
        i += 3;
    }
    if data.len() % 3 == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if data.len() % 3 == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

/// Compute SHA-256 of input data (minimal implementation for word generation).
/// Returns 32 bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // Minimal SHA-256 implementation
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn rotr(x: u32, n: u32) -> u32 {
        (x >> n) | (x << (32 - n))
    }
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    fn big_sigma0(x: u32) -> u32 {
        rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
    }
    fn big_sigma1(x: u32) -> u32 {
        rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
    }
    fn small_sigma0(x: u32) -> u32 {
        rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
    }
    fn small_sigma1(x: u32) -> u32 {
        rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
    }

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;

        for i in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut result = [0u8; 32];
    for (i, &s) in state.iter().enumerate() {
        let bytes = s.to_be_bytes();
        result[i * 4] = bytes[0];
        result[i * 4 + 1] = bytes[1];
        result[i * 4 + 2] = bytes[2];
        result[i * 4 + 3] = bytes[3];
    }
    result
}

/// Convenience: compute hex SHA-256 of data.
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash_alg_valid() {
        assert_eq!(pcrextend_parse_hash_alg("sha1"), Some(HashAlgorithm::Sha1));
        assert_eq!(pcrextend_parse_hash_alg("SHA1"), Some(HashAlgorithm::Sha1));
        assert_eq!(
            pcrextend_parse_hash_alg("sha256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            pcrextend_parse_hash_alg("SHA256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            pcrextend_parse_hash_alg("sha384"),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            pcrextend_parse_hash_alg("sha512"),
            Some(HashAlgorithm::Sha512)
        );
    }

    #[test]
    fn test_parse_hash_alg_invalid() {
        assert_eq!(pcrextend_parse_hash_alg("md5"), None);
        assert_eq!(pcrextend_parse_hash_alg("invalid"), None);
        assert_eq!(pcrextend_parse_hash_alg(""), None);
    }

    #[test]
    fn test_hash_alg_digest_sizes() {
        assert_eq!(HashAlgorithm::Sha1.digest_size(), 20);
        assert_eq!(HashAlgorithm::Sha256.digest_size(), 32);
        assert_eq!(HashAlgorithm::Sha384.digest_size(), 48);
        assert_eq!(HashAlgorithm::Sha512.digest_size(), 64);
    }

    #[test]
    fn test_hash_alg_display() {
        assert_eq!(format!("{}", HashAlgorithm::Sha256), "sha256");
        assert_eq!(format!("{}", HashAlgorithm::Sha1), "sha1");
    }

    #[test]
    fn test_parse_mode() {
        assert_eq!(
            pcrextend_parse_mode("replace"),
            Some(PcrExtendMode::Replace)
        );
        assert_eq!(pcrextend_parse_mode("EXTEND"), Some(PcrExtendMode::Extend));
        assert_eq!(pcrextend_parse_mode("Extend"), Some(PcrExtendMode::Extend));
        assert_eq!(pcrextend_parse_mode("invalid"), None);
    }

    #[test]
    fn test_mode_values() {
        assert_eq!(PcrExtendMode::Replace as i32, 0);
        assert_eq!(PcrExtendMode::Extend as i32, 1);
    }

    #[test]
    fn test_escape_colons() {
        assert_eq!(escape_colons("hello"), "hello");
        assert_eq!(escape_colons("a:b:c"), "a\\x3ab\\x3ac");
        assert_eq!(escape_colons(""), "");
    }

    #[test]
    fn test_build_file_system_word_full() {
        let word = build_file_system_word(
            "/",
            Some("ext4"),
            Some("abc-123"),
            Some("root"),
            Some("part-uuid"),
            Some("part-type"),
            Some("part-name"),
        );
        assert!(word.starts_with("file-system:"));
        // Should contain escaped path and all 6 field values
        assert!(word.contains("ext4"));
        assert!(word.contains("abc-123"));
    }

    #[test]
    fn test_build_file_system_word_fallback() {
        let word = build_file_system_word("/mnt/data", None, None, None, None, None, None);
        // 8 components: prefix + 7 empty fields
        let parts: Vec<&str> = word.split(':').collect();
        assert!(parts.len() >= 7);
    }

    #[test]
    fn test_build_machine_id_word() {
        let id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let word = build_machine_id_word(&id);
        assert!(word.starts_with("machine-id:"));
        assert!(word.contains("0123456789abcdeffedcba9876543210"));
    }

    #[test]
    fn test_build_product_id_word_present() {
        let id = [
            0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xff, 0xee,
        ];
        let word = build_product_id_word(Some(&id));
        assert!(word.starts_with("product-id:"));
        assert!(word.contains("aabbccdd"));
    }

    #[test]
    fn test_build_product_id_word_missing() {
        assert_eq!(build_product_id_word(None), "product-id:missing");
    }

    #[test]
    fn test_build_verity_word_no_sig() {
        let hash = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let word = build_verity_word("myimage", &hash, None);
        assert!(word.starts_with("verity:"));
        assert!(word.contains("myimage"));
        assert!(word.contains("deadbeef"));
        assert!(word.ends_with(':')); // empty sig
    }

    #[test]
    fn test_build_verity_word_with_sig() {
        let hash = vec![0x01, 0x02];
        let word = build_verity_word("test", &hash, Some("sig1,sig2"));
        assert!(word.contains("0102"));
        assert!(word.contains("sig1,sig2"));
    }

    #[test]
    fn test_build_imds_userdata_word() {
        let data = b"cloud-config: test";
        let hash_hex = "a".repeat(64); // fake sha256 hex
        let word = build_imds_userdata_word(data, &hash_hex);
        assert!(word.starts_with("imds-userdata:"));
        assert!(word.contains(&hash_hex));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(&[]);
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_hex_convenience() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_pcr_event_strings() {
        assert_eq!(PcrEvent::KernelConfig.as_str(), "kernel_config");
        assert_eq!(PcrEvent::Verity.as_str(), "dm_verity");
        assert_eq!(PcrEvent::ImdsUserdata.as_str(), "imds_userdata");
    }

    #[test]
    fn test_constants() {
        assert_eq!(PCREXTEND_PATH, "/usr/bin/pcrextend");
        assert_eq!(pcr_index::KERNEL_CONFIG, 12);
    }
}
