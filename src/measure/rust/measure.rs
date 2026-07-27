// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/measure/measure-tool.c
//
// TPM2 PCR measurement computation and phase handling.
//
// Provides types and utilities for pre-calculating expected TPM PCR values
// for unified kernel images.  Supports multiple PCR banks (SHA-256/384/512)
// and the standard boot phase strings used by sd-stub.

// ── Error type ────────────────────────────────────────────────────────────

use systemd_shared_rs::openssl_util::compute_hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Constants ─────────────────────────────────────────────────────────────

/// PCR index used for kernel boot measurements (PCR 11).
pub const TPM2_PCR_KERNEL_BOOT: u32 = 11;

/// Default phases used when none are specified.
///
/// Corresponds to the default `arg_phase` initialisation in `parse_argv()`.
pub const DEFAULT_PHASES: &[&str] = &[
    "enter-initrd",
    "enter-initrd:leave-initrd",
    "enter-initrd:leave-initrd:sysinit",
    "enter-initrd:leave-initrd:sysinit:ready",
];

/// Unified kernel image PE section names.
///
/// Mirrors `unified_sections[]` from the C code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedSection {
    Linux,
    OsRel,
    Cmdline,
    Initrd,
    Ucode,
    Splash,
    Dtb,
    DtbAuto,
    Uname,
    Sbat,
    PcrPKey,
    Profile,
    Hwids,
}

impl UnifiedSection {
    /// Return the section name as used in the PE binary.
    pub fn section_name(&self) -> &'static str {
        match self {
            UnifiedSection::Linux => ".linux",
            UnifiedSection::OsRel => ".osrel",
            UnifiedSection::Cmdline => ".cmdline",
            UnifiedSection::Initrd => ".initrd",
            UnifiedSection::Ucode => ".ucode",
            UnifiedSection::Splash => ".splash",
            UnifiedSection::Dtb => ".dtb",
            UnifiedSection::DtbAuto => ".dtbauto",
            UnifiedSection::Uname => ".uname",
            UnifiedSection::Sbat => ".sbat",
            UnifiedSection::PcrPKey => ".pcrpkey",
            UnifiedSection::Profile => ".profile",
            UnifiedSection::Hwids => ".hwids",
        }
    }
}

// ── Enums ─────────────────────────────────────────────────────────────────

/// Boot phases that sd-stub can measure into PCR 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPhase {
    EnterInitrd,
    LeaveInitrd,
    EnterFirmware,
    LeaveFirmware,
    Sysinit,
    Ready,
    Shutdown,
}

/// PCR hash bank identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrBank {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl PcrBank {
    /// Digest size in bytes for the given bank.
    pub fn digest_size(&self) -> usize {
        match self {
            PcrBank::Sha1 => 20,
            PcrBank::Sha256 => 32,
            PcrBank::Sha384 => 48,
            PcrBank::Sha512 => 64,
        }
    }

    /// The OpenSSL-style name used on the command line.
    pub fn bank_name(&self) -> &'static str {
        match self {
            PcrBank::Sha1 => "SHA1",
            PcrBank::Sha256 => "SHA256",
            PcrBank::Sha384 => "SHA384",
            PcrBank::Sha512 => "SHA512",
        }
    }
}

// ── Phase parsing ─────────────────────────────────────────────────────────

/// Parse a boot phase string into a `BootPhase` value.
///
/// Accepts case-insensitive input, matching the `normalize_phase()` usage in C.
pub fn normalize_phase(s: &str) -> Result<BootPhase> {
    match s.to_ascii_lowercase().as_str() {
        "enter-initrd" => Ok(BootPhase::EnterInitrd),
        "leave-initrd" => Ok(BootPhase::LeaveInitrd),
        "enter-firmware" => Ok(BootPhase::EnterFirmware),
        "leave-firmware" => Ok(BootPhase::LeaveFirmware),
        "sysinit" => Ok(BootPhase::Sysinit),
        "ready" => Ok(BootPhase::Ready),
        "shutdown" => Ok(BootPhase::Shutdown),
        _ => Err(Errno(-22)), // -EINVAL
    }
}

/// Convert a `BootPhase` to its canonical string representation.
pub fn phase_to_string(phase: BootPhase) -> &'static str {
    match phase {
        BootPhase::EnterInitrd => "enter-initrd",
        BootPhase::LeaveInitrd => "leave-initrd",
        BootPhase::EnterFirmware => "enter-firmware",
        BootPhase::LeaveFirmware => "leave-firmware",
        BootPhase::Sysinit => "sysinit",
        BootPhase::Ready => "ready",
        BootPhase::Shutdown => "shutdown",
    }
}

/// Normalise a colon-separated phase expression.
///
/// Splits on `:`, removes empty components, and re-joins.
/// Mirrors the C `normalize_phase()` which does `strv_split` → `strv_remove("")` → `strv_join`.
pub fn normalize_phase_expression(expr: &str) -> String {
    expr.split(':')
        .filter(|w| !w.is_empty())
        .collect::<Vec<&str>>()
        .join(":")
}

/// Parse a colon-separated phase expression into individual phase strings.
///
/// Returns the non-empty components in order.
pub fn split_phases(expr: &str) -> Vec<&str> {
    expr.split(':').filter(|w| !w.is_empty()).collect()
}

// ── Measure state ─────────────────────────────────────────────────────────

/// A single measured PCR value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrValue {
    pub bank: PcrBank,
    pub pcr_index: u32,
    pub digest: Vec<u8>,
}

/// Accumulator for PCR extend operations.
#[derive(Debug, Clone)]
pub struct MeasureState {
    pub pcr_values: Vec<PcrValue>,
    pub phases: Vec<String>,
    pub current: bool,
}

impl Default for MeasureState {
    fn default() -> Self {
        Self {
            pcr_values: Vec::new(),
            phases: Vec::new(),
            current: false,
        }
    }
}

impl MeasureState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Extend a PCR by hashing the old value concatenated with the new data.
    pub fn extend(&mut self, bank: PcrBank, pcr_index: u32, data: &[u8]) -> Result<()> {
        let size = bank.digest_size();
        let existing = self
            .pcr_values
            .iter()
            .position(|value| value.bank == bank && value.pcr_index == pcr_index);
        let old = existing
            .map(|index| self.pcr_values[index].digest.as_slice())
            .unwrap_or(&[]);
        if !old.is_empty() && old.len() != size {
            return Err(Errno(-libc::EINVAL));
        }

        let input_size = size
            .checked_add(data.len())
            .ok_or(Errno(-libc::EOVERFLOW))?;
        let mut input = Vec::new();
        input
            .try_reserve_exact(input_size)
            .map_err(|_| Errno(-libc::ENOMEM))?;
        if old.is_empty() {
            input.resize(size, 0);
        } else {
            input.extend_from_slice(old);
        }
        input.extend_from_slice(data);

        let digest = compute_hash(&input, bank.bank_name()).map_err(|error| Errno(error.code))?;
        if digest.len() != size {
            return Err(Errno(-libc::EIO));
        }

        if let Some(index) = existing {
            self.pcr_values[index].digest = digest;
        } else {
            self.pcr_values.push(PcrValue {
                bank,
                pcr_index,
                digest,
            });
        }
        Ok(())
    }

    /// Reset all accumulated PCR values.
    pub fn reset(&mut self) {
        self.pcr_values.clear();
    }
}

// ── Bank helpers ──────────────────────────────────────────────────────────

/// Parse a bank name string (case-insensitive).
pub fn parse_bank(name: &str) -> Result<PcrBank> {
    match name.to_ascii_uppercase().as_str() {
        "SHA1" | "SHA-1" => Ok(PcrBank::Sha1),
        "SHA256" | "SHA-256" => Ok(PcrBank::Sha256),
        "SHA384" | "SHA-384" => Ok(PcrBank::Sha384),
        "SHA512" | "SHA-512" => Ok(PcrBank::Sha512),
        _ => Err(Errno(-22)), // -EINVAL
    }
}

/// Default set of PCR banks used when none are specified.
///
/// Mirrors the C code: `arg_banks = strv_new("SHA1", "SHA256", "SHA384", "SHA512")`.
pub fn default_banks() -> Vec<PcrBank> {
    vec![
        PcrBank::Sha1,
        PcrBank::Sha256,
        PcrBank::Sha384,
        PcrBank::Sha512,
    ]
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_phase_valid() {
        assert_eq!(
            normalize_phase("enter-initrd").unwrap(),
            BootPhase::EnterInitrd
        );
        assert_eq!(
            normalize_phase("leave-initrd").unwrap(),
            BootPhase::LeaveInitrd
        );
        assert_eq!(normalize_phase("sysinit").unwrap(), BootPhase::Sysinit);
        assert_eq!(normalize_phase("ready").unwrap(), BootPhase::Ready);
        assert_eq!(normalize_phase("shutdown").unwrap(), BootPhase::Shutdown);
    }

    #[test]
    fn normalize_phase_case_insensitive() {
        assert_eq!(normalize_phase("READY").unwrap(), BootPhase::Ready);
        assert_eq!(normalize_phase("ShutDown").unwrap(), BootPhase::Shutdown);
    }

    #[test]
    fn normalize_phase_invalid() {
        assert!(normalize_phase("bogus").is_err());
        assert!(normalize_phase("").is_err());
    }

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
    fn normalize_phase_expression_strips_empty() {
        assert_eq!(
            normalize_phase_expression(":enter-initrd::leave-initrd:"),
            "enter-initrd:leave-initrd"
        );
        assert_eq!(normalize_phase_expression("enter-initrd"), "enter-initrd");
        assert_eq!(normalize_phase_expression(":::"), "");
    }

    #[test]
    fn split_phases_basic() {
        let phases = split_phases("enter-initrd:leave-initrd:sysinit");
        assert_eq!(phases, vec!["enter-initrd", "leave-initrd", "sysinit"]);
    }

    #[test]
    fn split_phases_removes_empty() {
        let phases = split_phases("enter-initrd::leave-initrd:");
        assert_eq!(phases, vec!["enter-initrd", "leave-initrd"]);
    }

    #[test]
    fn default_state() {
        let state = MeasureState::new();
        assert!(state.pcr_values.is_empty());
        assert!(state.phases.is_empty());
        assert!(!state.current);
    }

    #[test]
    fn extend_pcr() {
        let mut state = MeasureState::new();
        state.extend(PcrBank::Sha256, 11, b"test data").unwrap();
        assert_eq!(state.pcr_values.len(), 1);
        assert_eq!(state.pcr_values[0].pcr_index, 11);
        assert_eq!(state.pcr_values[0].bank, PcrBank::Sha256);
        assert_eq!(state.pcr_values[0].digest.len(), 32);
    }

    #[test]
    fn extend_multiple_banks() {
        let mut state = MeasureState::new();
        state.extend(PcrBank::Sha256, 11, b"test").unwrap();
        state.extend(PcrBank::Sha384, 11, b"test").unwrap();
        assert_eq!(state.pcr_values.len(), 2);
        assert_eq!(state.pcr_values[0].digest.len(), 32);
        assert_eq!(state.pcr_values[1].digest.len(), 48);
    }

    #[test]
    fn extending_the_same_pcr_updates_its_chained_value() {
        let mut state = MeasureState::new();
        state.extend(PcrBank::Sha256, 11, b"first").unwrap();
        let first = state.pcr_values[0].digest.clone();
        state.extend(PcrBank::Sha256, 11, b"second").unwrap();

        assert_eq!(state.pcr_values.len(), 1);
        assert_ne!(state.pcr_values[0].digest, first);
    }

    #[test]
    fn parse_bank_valid() {
        assert_eq!(parse_bank("sha1").unwrap(), PcrBank::Sha1);
        assert_eq!(parse_bank("SHA256").unwrap(), PcrBank::Sha256);
        assert_eq!(parse_bank("sha384").unwrap(), PcrBank::Sha384);
        assert_eq!(parse_bank("SHA-512").unwrap(), PcrBank::Sha512);
    }

    #[test]
    fn parse_bank_invalid() {
        assert!(parse_bank("MD5").is_err());
        assert!(parse_bank("unknown").is_err());
    }

    #[test]
    fn bank_digest_sizes() {
        assert_eq!(PcrBank::Sha1.digest_size(), 20);
        assert_eq!(PcrBank::Sha256.digest_size(), 32);
        assert_eq!(PcrBank::Sha384.digest_size(), 48);
        assert_eq!(PcrBank::Sha512.digest_size(), 64);
    }

    #[test]
    fn unified_section_names() {
        assert_eq!(UnifiedSection::Linux.section_name(), ".linux");
        assert_eq!(UnifiedSection::Initrd.section_name(), ".initrd");
        assert_eq!(UnifiedSection::Cmdline.section_name(), ".cmdline");
    }

    #[test]
    fn default_banks_count() {
        assert_eq!(
            default_banks(),
            vec![
                PcrBank::Sha1,
                PcrBank::Sha256,
                PcrBank::Sha384,
                PcrBank::Sha512
            ]
        );
    }

    #[test]
    fn reset_clears_values() {
        let mut state = MeasureState::new();
        state.extend(PcrBank::Sha256, 11, b"test").unwrap();
        assert!(!state.pcr_values.is_empty());
        state.reset();
        assert!(state.pcr_values.is_empty());
    }
}
