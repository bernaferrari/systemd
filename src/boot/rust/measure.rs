// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/measure.c
//
// TPM2 and CC (Confidential Computing) measurement operations.
//
// Provides functions for measuring boot events into TPM2 PCR banks
// and CC measurement registers. Handles both TCG2 and CC protocols,
// measuring into both when available (CVE-2021-42299 mitigation).

// ── Constants ─────────────────────────────────────────────────────────────

/// PCR index for disabled measurements
pub const PCR_DISABLED: u32 = u32::MAX;
/// TPM2 PCR for kernel config / load options
pub const TPM2_PCR_KERNEL_CONFIG: u32 = 11;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasureError {
    NotReady,
    ProtocolError(u32),
}

impl std::fmt::Display for MeasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasureError::NotReady => write!(f, "TPM not ready"),
            MeasureError::ProtocolError(code) => write!(f, "protocol error: {}", code),
        }
    }
}

impl std::error::Error for MeasureError {}

/// Represents a TCG2 protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcg2Version {
    pub major: u8,
    pub minor: u8,
}

impl Tcg2Version {
    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Check if version supports GetActivePcrBanks (>= 1.1)
    pub fn supports_active_pcr_banks(&self) -> bool {
        self.major > 1 || (self.major == 1 && self.minor >= 1)
    }
}

/// Simulated TCG2 protocol state for testing
#[derive(Debug, Clone)]
pub struct Tcg2State {
    pub present: bool,
    pub version: Tcg2Version,
    pub active_pcr_banks: u32,
    pub logged_events: Vec<MeasuredEvent>,
}

impl Default for Tcg2State {
    fn default() -> Self {
        Self {
            present: true,
            version: Tcg2Version::new(1, 1),
            active_pcr_banks: 0x00000001,
            logged_events: Vec::new(),
        }
    }
}

/// Simulated CC measurement protocol state
#[derive(Debug, Clone)]
pub struct CcState {
    pub available: bool,
    pub logged_events: Vec<MeasuredEvent>,
}

impl Default for CcState {
    fn default() -> Self {
        Self {
            available: true,
            logged_events: Vec::new(),
        }
    }
}

/// A measured event record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredEvent {
    pub pcr_index: u32,
    pub event_type: EventType,
    pub event_id: u32,
    pub description: Vec<u16>,
}

/// Type of measurement event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Ipl,
    Tagged,
}

/// Combined measurement system state
#[derive(Debug, Clone, Default)]
pub struct MeasureSystem {
    pub tcg2: Tcg2State,
    pub cc: CcState,
}

impl MeasureSystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tpm_present(mut self, present: bool) -> Self {
        self.tcg2.present = present;
        self
    }

    pub fn with_cc_available(mut self, available: bool) -> Self {
        self.cc.available = available;
        self
    }

    pub fn with_tcg2_version(mut self, major: u8, minor: u8) -> Self {
        self.tcg2.version = Tcg2Version::new(major, minor);
        self
    }
}

// ── TPM present check ─────────────────────────────────────────────────────

/// Check if TPM2 is present (matches C `tpm_present`)
pub fn tpm_present(state: &MeasureSystem) -> bool {
    state.tcg2.present
}

// ── Active PCR banks ──────────────────────────────────────────────────────

/// Get active PCR banks (matches C `tpm_get_active_pcr_banks`)
pub fn tpm_get_active_pcr_banks(state: &MeasureSystem) -> u32 {
    if !state.tcg2.present {
        return 0;
    }

    if !state.tcg2.version.supports_active_pcr_banks() {
        return u32::MAX;
    }

    state.tcg2.active_pcr_banks
}

// ── Log IPL event ─────────────────────────────────────────────────────────

/// Log an IPL event to both CC and TPM (matches C `tpm_log_ipl_event`)
pub fn tpm_log_ipl_event(
    state: &mut MeasureSystem,
    pcr_index: u32,
    description: &[u16],
) -> Result<bool, MeasureError> {
    if pcr_index == PCR_DISABLED {
        return Ok(false);
    }

    let mut measured = false;

    if state.cc.available {
        state.cc.logged_events.push(MeasuredEvent {
            pcr_index,
            event_type: EventType::Ipl,
            event_id: 0,
            description: description.to_vec(),
        });
        measured = true;
    }

    if state.tcg2.present {
        state.tcg2.logged_events.push(MeasuredEvent {
            pcr_index,
            event_type: EventType::Ipl,
            event_id: 0,
            description: description.to_vec(),
        });
        measured = true;
    }

    Ok(measured)
}

// ── Log tagged event ──────────────────────────────────────────────────────

/// Log a tagged event to both CC and TPM (matches C `tpm_log_tagged_event`)
pub fn tpm_log_tagged_event(
    state: &mut MeasureSystem,
    pcr_index: u32,
    event_id: u32,
    description: &[u16],
) -> Result<bool, MeasureError> {
    if pcr_index == PCR_DISABLED {
        return Ok(false);
    }

    assert!(event_id > 0, "event_id must be > 0");

    let mut measured = false;

    if state.cc.available {
        state.cc.logged_events.push(MeasuredEvent {
            pcr_index,
            event_type: EventType::Tagged,
            event_id,
            description: description.to_vec(),
        });
        measured = true;
    }

    if state.tcg2.present {
        state.tcg2.logged_events.push(MeasuredEvent {
            pcr_index,
            event_type: EventType::Tagged,
            event_id,
            description: description.to_vec(),
        });
        measured = true;
    }

    Ok(measured)
}

// ── Log load options ──────────────────────────────────────────────────────

/// Measure load options string (matches C `tpm_log_load_options`)
pub fn tpm_log_load_options(
    state: &mut MeasureSystem,
    load_options: &[u16],
) -> Result<bool, MeasureError> {
    tpm_log_ipl_event(state, TPM2_PCR_KERNEL_CONFIG, load_options)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_present_true() {
        let state = MeasureSystem::new();
        assert!(tpm_present(&state));
    }

    #[test]
    fn test_tpm_present_false() {
        let state = MeasureSystem::new().with_tpm_present(false);
        assert!(!tpm_present(&state));
    }

    #[test]
    fn test_tcg2_version_supports_active_pcr_banks() {
        assert!(Tcg2Version::new(1, 1).supports_active_pcr_banks());
        assert!(Tcg2Version::new(2, 0).supports_active_pcr_banks());
        assert!(!Tcg2Version::new(1, 0).supports_active_pcr_banks());
        assert!(!Tcg2Version::new(0, 9).supports_active_pcr_banks());
    }

    #[test]
    fn test_get_active_pcr_banks_present() {
        let state = MeasureSystem::new();
        assert_eq!(tpm_get_active_pcr_banks(&state), 1);
    }

    #[test]
    fn test_get_active_pcr_banks_old_version() {
        let state = MeasureSystem::new().with_tcg2_version(1, 0);
        assert_eq!(tpm_get_active_pcr_banks(&state), u32::MAX);
    }

    #[test]
    fn test_get_active_pcr_banks_not_present() {
        let state = MeasureSystem::new().with_tpm_present(false);
        assert_eq!(tpm_get_active_pcr_banks(&state), 0);
    }

    #[test]
    fn test_log_ipl_event_both_protocols() {
        let mut state = MeasureSystem::new();
        let desc: Vec<u16> = "test".encode_utf16().collect();
        let measured = tpm_log_ipl_event(&mut state, 4, &desc).unwrap();
        assert!(measured);
        assert_eq!(state.tcg2.logged_events.len(), 1);
        assert_eq!(state.cc.logged_events.len(), 1);
    }

    #[test]
    fn test_log_ipl_event_disabled_pcr() {
        let mut state = MeasureSystem::new();
        let desc: Vec<u16> = "test".encode_utf16().collect();
        let measured = tpm_log_ipl_event(&mut state, PCR_DISABLED, &desc).unwrap();
        assert!(!measured);
    }

    #[test]
    fn test_log_ipl_event_no_protocols() {
        let mut state = MeasureSystem::new()
            .with_tpm_present(false)
            .with_cc_available(false);
        let desc: Vec<u16> = "test".encode_utf16().collect();
        let measured = tpm_log_ipl_event(&mut state, 4, &desc).unwrap();
        assert!(!measured);
    }

    #[test]
    fn test_log_tagged_event() {
        let mut state = MeasureSystem::new();
        let desc: Vec<u16> = "tagged".encode_utf16().collect();
        let measured = tpm_log_tagged_event(&mut state, 4, 42, &desc).unwrap();
        assert!(measured);
        assert_eq!(state.tcg2.logged_events[0].event_type, EventType::Tagged);
        assert_eq!(state.tcg2.logged_events[0].event_id, 42);
    }

    #[test]
    fn test_log_load_options() {
        let mut state = MeasureSystem::new();
        let opts: Vec<u16> = "root=/dev/sda1".encode_utf16().collect();
        let measured = tpm_log_load_options(&mut state, &opts).unwrap();
        assert!(measured);
        assert_eq!(
            state.tcg2.logged_events[0].pcr_index,
            TPM2_PCR_KERNEL_CONFIG
        );
    }

    #[test]
    fn test_tagged_event_disabled_pcr() {
        let mut state = MeasureSystem::new();
        let desc: Vec<u16> = "test".encode_utf16().collect();
        let measured = tpm_log_tagged_event(&mut state, PCR_DISABLED, 1, &desc).unwrap();
        assert!(!measured);
    }

    #[test]
    fn test_log_ipl_event_tpm_only() {
        let mut state = MeasureSystem::new().with_cc_available(false);
        let desc: Vec<u16> = "test".encode_utf16().collect();
        let measured = tpm_log_ipl_event(&mut state, 4, &desc).unwrap();
        assert!(measured);
        assert_eq!(state.tcg2.logged_events.len(), 1);
        assert_eq!(state.cc.logged_events.len(), 0);
    }

    #[test]
    fn test_log_ipl_event_cc_only() {
        let mut state = MeasureSystem::new().with_tpm_present(false);
        let desc: Vec<u16> = "test".encode_utf16().collect();
        let measured = tpm_log_ipl_event(&mut state, 4, &desc).unwrap();
        assert!(measured);
        assert_eq!(state.tcg2.logged_events.len(), 0);
        assert_eq!(state.cc.logged_events.len(), 1);
    }
}
