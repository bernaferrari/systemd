// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/measure/measure-tool.c
//
// Pre-calculate and sign expected TPM PCR values for unified kernel images.
//
// Supports verbs: status, calculate, sign, policy-digest.
// Measures UKI PE sections into PCR 11 using SHA1/SHA256/SHA384/SHA512.

pub mod measure;

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

// ── PCR constants ─────────────────────────────────────────────────────────

/// PCR index for kernel boot measurements.
pub const TPM2_PCR_KERNEL_BOOT: u32 = 11;

// ── Boot phase ────────────────────────────────────────────────────────────

/// Boot phase identifiers, measured into PCR 11 by sd-stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPhase {
    EnterInitrd,
    LeaveInitrd,
    Sysinit,
    Ready,
    EnterFirmware,
    LeaveFirmware,
    Shutdown,
}

pub fn normalize_phase(s: &str) -> Result<BootPhase> {
    match s.to_ascii_lowercase().as_str() {
        "enter-initrd" => Ok(BootPhase::EnterInitrd),
        "leave-initrd" => Ok(BootPhase::LeaveInitrd),
        "sysinit" => Ok(BootPhase::Sysinit),
        "ready" => Ok(BootPhase::Ready),
        "enter-firmware" => Ok(BootPhase::EnterFirmware),
        "leave-firmware" => Ok(BootPhase::LeaveFirmware),
        "shutdown" => Ok(BootPhase::Shutdown),
        _ => Err(Errno(-libc::EINVAL)),
    }
}

pub fn phase_to_string(phase: BootPhase) -> &'static str {
    match phase {
        BootPhase::EnterInitrd => "enter-initrd",
        BootPhase::LeaveInitrd => "leave-initrd",
        BootPhase::Sysinit => "sysinit",
        BootPhase::Ready => "ready",
        BootPhase::EnterFirmware => "enter-firmware",
        BootPhase::LeaveFirmware => "leave-firmware",
        BootPhase::Shutdown => "shutdown",
    }
}

/// Normalize a phase expression: split on colons, remove empty parts, rejoin.
pub fn normalize_phase_expression(s: &str) -> String {
    s.split(':')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(":")
}

// ── PCR bank ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrBank {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl PcrBank {
    pub fn digest_size(&self) -> usize {
        match self {
            PcrBank::Sha1 => 20,
            PcrBank::Sha256 => 32,
            PcrBank::Sha384 => 48,
            PcrBank::Sha512 => 64,
        }
    }

    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_uppercase().as_str() {
            "SHA1" => Ok(PcrBank::Sha1),
            "SHA256" => Ok(PcrBank::Sha256),
            "SHA384" => Ok(PcrBank::Sha384),
            "SHA512" => Ok(PcrBank::Sha512),
            _ => Err(Errno(-libc::EINVAL)),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            PcrBank::Sha1 => "sha1",
            PcrBank::Sha256 => "sha256",
            PcrBank::Sha384 => "sha384",
            PcrBank::Sha512 => "sha512",
        }
    }
}

/// Default banks used when none are specified.
pub fn default_banks() -> Vec<PcrBank> {
    vec![
        PcrBank::Sha1,
        PcrBank::Sha256,
        PcrBank::Sha384,
        PcrBank::Sha512,
    ]
}

// ── UKI sections ──────────────────────────────────────────────────────────

/// UKI PE section identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedSection {
    Linux,
    OsRel,
    Cmdline,
    Initrd,
    UCode,
    Splash,
    Dtb,
    DtbAuto,
    Uname,
    Sbat,
    PcrPkey,
    Profile,
    Hwids,
}

pub fn section_name(section: UnifiedSection) -> &'static str {
    match section {
        UnifiedSection::Linux => ".linux",
        UnifiedSection::OsRel => ".osrel",
        UnifiedSection::Cmdline => ".cmdline",
        UnifiedSection::Initrd => ".initrd",
        UnifiedSection::UCode => ".ucode",
        UnifiedSection::Splash => ".splash",
        UnifiedSection::Dtb => ".dtb",
        UnifiedSection::DtbAuto => ".dtbauto",
        UnifiedSection::Uname => ".uname",
        UnifiedSection::Sbat => ".sbat",
        UnifiedSection::PcrPkey => ".pcrpkey",
        UnifiedSection::Profile => ".profile",
        UnifiedSection::Hwids => ".hwids",
    }
}

/// Default boot phases for measurement.
pub fn default_phases() -> Vec<String> {
    vec![
        "enter-initrd".to_string(),
        "enter-initrd:leave-initrd".to_string(),
        "enter-initrd:leave-initrd:sysinit".to_string(),
        "enter-initrd:leave-initrd:sysinit:ready".to_string(),
    ]
}

// ── Verb ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasureVerb {
    Status,
    Calculate,
    Sign,
    PolicyDigest,
}

pub fn parse_verb(s: &str) -> Result<MeasureVerb> {
    match s {
        "status" => Ok(MeasureVerb::Status),
        "calculate" => Ok(MeasureVerb::Calculate),
        "sign" => Ok(MeasureVerb::Sign),
        "policy-digest" => Ok(MeasureVerb::PolicyDigest),
        _ => Err(Errno(-libc::EINVAL)),
    }
}

// ── PCR value ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrValue {
    pub bank: PcrBank,
    pub pcr_index: u32,
    pub digest: Vec<u8>,
}

// ── Hex helpers ───────────────────────────────────────────────────────────

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Errno(-libc::EINVAL));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| Errno(-libc::EINVAL)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_roundtrip() {
        for phase in [
            BootPhase::EnterInitrd,
            BootPhase::LeaveInitrd,
            BootPhase::Sysinit,
            BootPhase::Ready,
            BootPhase::Shutdown,
        ] {
            assert_eq!(normalize_phase(phase_to_string(phase)).unwrap(), phase);
        }
    }

    #[test]
    fn phase_case_insensitive() {
        assert_eq!(
            normalize_phase("ENTER-INITRD").unwrap(),
            BootPhase::EnterInitrd
        );
        assert_eq!(normalize_phase("Ready").unwrap(), BootPhase::Ready);
    }

    #[test]
    fn phase_invalid() {
        assert!(normalize_phase("bogus").is_err());
    }

    #[test]
    fn phase_expression_normalization() {
        assert_eq!(normalize_phase_expression("::a::b::"), "a:b");
        assert_eq!(normalize_phase_expression("enter-initrd"), "enter-initrd");
        assert_eq!(normalize_phase_expression("::"), "");
    }

    #[test]
    fn pcr_bank_from_name() {
        assert_eq!(PcrBank::from_name("SHA256").unwrap(), PcrBank::Sha256);
        assert_eq!(PcrBank::from_name("sha1").unwrap(), PcrBank::Sha1);
        assert!(PcrBank::from_name("md5").is_err());
    }

    #[test]
    fn pcr_bank_digest_sizes() {
        assert_eq!(PcrBank::Sha1.digest_size(), 20);
        assert_eq!(PcrBank::Sha256.digest_size(), 32);
        assert_eq!(PcrBank::Sha384.digest_size(), 48);
        assert_eq!(PcrBank::Sha512.digest_size(), 64);
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "deadbeef");
        assert_eq!(hex_to_bytes(&hex).unwrap(), bytes);
    }

    #[test]
    fn hex_invalid() {
        assert!(hex_to_bytes("xyz").is_err());
        assert!(hex_to_bytes("a").is_err());
    }

    #[test]
    fn verb_parsing() {
        assert_eq!(parse_verb("status").unwrap(), MeasureVerb::Status);
        assert_eq!(parse_verb("sign").unwrap(), MeasureVerb::Sign);
        assert!(parse_verb("unknown").is_err());
    }

    #[test]
    fn section_names() {
        assert_eq!(section_name(UnifiedSection::Linux), ".linux");
        assert_eq!(section_name(UnifiedSection::Initrd), ".initrd");
        assert_eq!(section_name(UnifiedSection::PcrPkey), ".pcrpkey");
    }

    #[test]
    fn default_banks_all_present() {
        let banks = default_banks();
        assert_eq!(banks.len(), 4);
        assert!(banks.contains(&PcrBank::Sha256));
    }
}
