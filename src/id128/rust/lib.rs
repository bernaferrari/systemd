// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/id128/id128.c
//
// Generate and print 128-bit identifiers.
//
// This module deliberately delegates the security-sensitive parts to the Rust
// implementation of the public sd-id128 API.  Keeping one implementation of
// the machine/boot source parsing, CSPRNG, and HMAC construction prevents the
// command-line utility from drifting from the library API.

// ── Error type ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

// ── 128-bit ID type ───────────────────────────────────────────────────────

pub type Id128 = [u8; 16];

pub const NULL_ID: Id128 = [0u8; 16];

pub fn is_null(id: &Id128) -> bool {
    id == &NULL_ID
}

pub fn from_string(s: &str) -> Result<Id128> {
    systemd_libsystemd_rs::sd_id128_strings::sd_id128_from_string(s)
        .map(|id| id.0)
        .map_err(Errno)
}

pub fn to_string(id: &Id128) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn to_uuid_string(id: &Id128) -> String {
    let h = to_string(id);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

// ── Pretty-print modes ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrettyPrintMode {
    Id128,
    Uuid,
    Pretty,
}

impl Default for PrettyPrintMode {
    fn default() -> Self {
        Self::Id128
    }
}

pub fn format_id(id: &Id128, mode: PrettyPrintMode) -> String {
    match mode {
        PrettyPrintMode::Id128 => to_string(id),
        PrettyPrintMode::Uuid => to_uuid_string(id),
        PrettyPrintMode::Pretty => pretty_sample("XYZ", id),
    }
}

// ── Verb ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Id128Verb {
    New,
    MachineId,
    BootId,
    InvocationId,
    VarPartitionUuid,
    Show,
}

pub fn parse_verb(s: &str) -> Result<Id128Verb> {
    match s {
        "new" => Ok(Id128Verb::New),
        "machine-id" => Ok(Id128Verb::MachineId),
        "boot-id" => Ok(Id128Verb::BootId),
        "invocation-id" => Ok(Id128Verb::InvocationId),
        "var-partition-uuid" => Ok(Id128Verb::VarPartitionUuid),
        "show" => Ok(Id128Verb::Show),
        _ => Err(Errno(-libc::EINVAL)),
    }
}

// ── App-specific derivation ───────────────────────────────────────────────

/// Derive an application-specific ID exactly like `sd_id128_get_app_specific()`.
///
/// The base ID is the HMAC-SHA256 key and the app ID is the input. The first
/// 16 digest bytes are then marked as an RFC 4122 version-4 UUID. A null app
/// ID is rejected with `-ENXIO`, as in the C API.
pub fn derive_app_specific(base: &Id128, app: &Id128) -> Result<Id128> {
    systemd_libsystemd_rs::sd_id128_api::sd_id128_get_app_specific(
        systemd_libsystemd_rs::id128_util::SdId128(*base),
        systemd_libsystemd_rs::id128_util::SdId128(*app),
    )
    .map(|id| id.0)
    .map_err(Errno)
}

/// Generate a cryptographically random UUIDv4 using the OS random source.
pub fn random_id() -> Result<Id128> {
    systemd_libsystemd_rs::sd_id128_api::sd_id128_randomize()
        .map(|id| id.0)
        .map_err(Errno)
}

/// Read the canonical machine ID from `/etc/machine-id`.
pub fn machine_id() -> Result<Id128> {
    systemd_libsystemd_rs::sd_id128_api::sd_id128_get_machine()
        .map(|id| id.0)
        .map_err(Errno)
}

/// Read the canonical boot ID from `/proc/sys/kernel/random/boot_id`.
pub fn boot_id() -> Result<Id128> {
    systemd_libsystemd_rs::sd_id128_api::sd_id128_get_boot()
        .map(|id| id.0)
        .map_err(Errno)
}

/// Read the invocation ID from the currently supported service-manager source.
///
/// The underlying Rust API validates `INVOCATION_ID` and fails rather than
/// inventing an ID. The C implementation's trusted kernel-keyring fallback is
/// still a tracked parity requirement.
pub fn invocation_id() -> Result<Id128> {
    systemd_libsystemd_rs::sd_id128_api::sd_id128_get_invocation()
        .map(|id| id.0)
        .map_err(Errno)
}

/// Render the non-terminal form of `id128_pretty_print_sample()`.
///
/// The C helper adds ANSI and OSC-8 sequences only when stdout is a terminal.
/// This pure formatter is intentionally deterministic; the binary owns the
/// terminal policy and writes this text unchanged for non-terminal output.
pub fn pretty_sample(name: &str, id: &Id128) -> String {
    let plain = to_string(id);
    let uuid = to_uuid_string(id);
    let bytes = id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "As string:\n{plain}\n\nAs UUID:\n{uuid}\n\nAs systemd-id128(1) macro:\n#define {name} SD_ID128_MAKE({bytes})\n\nAs Python constant:\n>>> import uuid\n>>> {name} = uuid.UUID('{plain}')\n"
    )
}

// ── Parsing utilities ─────────────────────────────────────────────────────

pub fn is_valid_app_id(s: &str) -> bool {
    parse_id128_or_error(s).is_ok()
}

pub fn parse_id128_or_error(s: &str) -> Result<Id128> {
    let id = from_string(s)?;
    if is_null(&id) {
        return Err(Errno(-libc::ENXIO));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_32hex() {
        let id = from_string("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(id[0], 0x01);
        assert_eq!(id[15], 0xef);
    }

    #[test]
    fn from_string_uuid_format() {
        let id = from_string("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(id[0], 0x01);
        assert_eq!(id[15], 0xef);
    }

    #[test]
    fn from_string_invalid() {
        assert!(from_string("abc").is_err());
        assert!(from_string("gggggggggggggggggggggggggggggggg").is_err());
        assert!(from_string("01234567-89abcdef0123456789abcdef").is_err());
    }

    #[test]
    fn to_string_format() {
        let id: Id128 = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(to_string(&id), "0123456789abcdeffedcba9876543210");
    }

    #[test]
    fn to_uuid_format() {
        let id: Id128 = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(to_uuid_string(&id), "01234567-89ab-cdef-fedc-ba9876543210");
    }

    #[test]
    fn null_detection() {
        assert!(is_null(&NULL_ID));
        assert!(!is_null(&[1u8; 16]));
    }

    #[test]
    fn roundtrip() {
        let original = from_string("f47ac10b58cc4582ae851e7396c8051d").unwrap();
        let s = to_string(&original);
        let parsed = from_string(&s).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn verb_parsing() {
        assert_eq!(parse_verb("new").unwrap(), Id128Verb::New);
        assert_eq!(parse_verb("machine-id").unwrap(), Id128Verb::MachineId);
        assert_eq!(parse_verb("show").unwrap(), Id128Verb::Show);
        assert!(parse_verb("unknown").is_err());
    }

    #[test]
    fn pretty_print_modes() {
        let id: Id128 = [0x01; 16];
        let id128 = format_id(&id, PrettyPrintMode::Id128);
        assert!(!id128.contains('-'));
        let uuid = format_id(&id, PrettyPrintMode::Uuid);
        assert!(uuid.contains('-'));
        let pretty = format_id(&id, PrettyPrintMode::Pretty);
        assert!(pretty.starts_with("As string:\n"));
    }

    #[test]
    fn derive_app_specific_matches_sd_id128_vector() {
        let base: Id128 = [
            0x51, 0xdf, 0x0b, 0x4b, 0xc3, 0xb0, 0x4c, 0x97, 0x80, 0xe2, 0x99, 0xb9, 0x8c, 0xa3,
            0x73, 0xb8,
        ];
        let app: Id128 = [
            0xf0, 0x3d, 0xaa, 0xeb, 0x1c, 0x33, 0x4b, 0x43, 0xa7, 0x32, 0x17, 0x29, 0x44, 0xbf,
            0x77, 0x2e,
        ];
        assert_eq!(
            derive_app_specific(&base, &app).unwrap(),
            [
                0x1d, 0xee, 0x59, 0x54, 0xe7, 0x5c, 0x4d, 0x6f, 0xb9, 0x6c, 0xc6, 0xc0, 0x4c, 0xa1,
                0x8a, 0x86,
            ]
        );
    }

    #[test]
    fn derive_app_specific_rejects_null_app_id() {
        assert_eq!(
            derive_app_specific(&[1; 16], &NULL_ID),
            Err(Errno(-libc::ENXIO))
        );
    }

    #[test]
    fn random_id_is_uuid_v4() {
        let id = random_id().unwrap();
        assert_eq!(id[6] >> 4, 4);
        assert_eq!(id[8] >> 6, 2);
    }

    #[test]
    fn parse_id128_rejects_null() {
        assert!(parse_id128_or_error("00000000000000000000000000000000").is_err());
    }
}
