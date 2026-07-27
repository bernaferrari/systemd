// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/ticks.c
//
// High-resolution tick reading and frequency detection.
//
// Provides tick counters for x86 (TSC), aarch64 (cntvct_el0), and fallback
// implementations. Computes tick frequency via CPUID or calibration delay.

// ── Constants ─────────────────────────────────────────────────────────────

/// Calibration delay in microseconds for fallback frequency detection.
pub const CALIBRATION_DELAY_USEC: u64 = 1000;

/// Scale factor from microseconds to seconds.
pub const USEC_PER_SEC: u64 = 1_000_000;

// ── Types ─────────────────────────────────────────────────────────────────

/// Cached tick frequency state.
#[derive(Debug, Clone)]
pub struct TickState {
    freq_cache: u64,
}

impl Default for TickState {
    fn default() -> Self {
        Self::new()
    }
}

impl TickState {
    pub fn new() -> Self {
        TickState { freq_cache: 0 }
    }

    /// Get the cached frequency, computing it if needed.
    pub fn freq(&mut self, arch_freq: u64, arch_ticks_start: u64, arch_ticks_end: u64) -> u64 {
        if self.freq_cache != 0 {
            return self.freq_cache;
        }

        self.freq_cache = arch_freq;
        if self.freq_cache != 0 {
            return self.freq_cache;
        }

        if arch_ticks_end < arch_ticks_start {
            return 0;
        }

        let delta = arch_ticks_end - arch_ticks_start;
        self.freq_cache = delta * 1000;
        self.freq_cache
    }

    /// Get the currently cached frequency (0 if not computed).
    pub fn cached_freq(&self) -> u64 {
        self.freq_cache
    }
}

// ── Core tick functions ───────────────────────────────────────────────────

/// Convert ticks to microseconds.
///
/// Mirrors `time_usec()` in C.
pub fn time_usec(ticks: u64, freq: u64) -> u64 {
    if ticks == 0 || freq == 0 {
        return 0;
    }
    USEC_PER_SEC * ticks / freq
}

/// Compute tick frequency from a calibration measurement.
///
/// Given ticks sampled `delay_usec` apart, compute ticks/second.
pub fn calibrate_freq(ticks_start: u64, ticks_end: u64, delay_usec: u64) -> u64 {
    if ticks_end < ticks_start || delay_usec == 0 {
        return 0;
    }
    let delta = ticks_end - ticks_start;
    delta * (USEC_PER_SEC / delay_usec)
}

/// Check if the tick counter overflowed between two readings.
pub fn ticks_overflowed(start: u64, end: u64) -> bool {
    end < start
}

/// Compute frequency from CPUID crystal Hz, denominator, and numerator.
///
/// Mirrors the Intel CPUID leaf 0x15 logic in C.
pub fn cpuid_freq(crystal_hz: u64, denominator: u32, numerator: u32) -> u64 {
    if denominator == 0 || numerator == 0 {
        return 0;
    }
    crystal_hz * numerator as u64 / denominator as u64
}

/// Deduce crystal Hz from core MHz when CPUID doesn't provide it.
///
/// Mirrors the fallback in `ticks_freq_arch()` for Intel CPUs.
pub fn deduce_crystal_hz(core_mhz: u32, denominator: u32, numerator: u32) -> u64 {
    if denominator == 0 || numerator == 0 {
        return 0;
    }
    (core_mhz as u64) * 1_000_000 * denominator as u64 / numerator as u64
}

/// Full frequency calculation from CPUID parameters.
///
/// If crystal_hz is 0, deduces it from core_mhz.
pub fn compute_tick_freq(
    crystal_hz: u64,
    denominator: u32,
    numerator: u32,
    core_mhz: Option<u32>,
) -> u64 {
    let freq = if crystal_hz != 0 {
        crystal_hz
    } else {
        match core_mhz {
            Some(mhz) => deduce_crystal_hz(mhz, denominator, numerator),
            None => return 0,
        }
    };
    cpuid_freq(freq, denominator, numerator)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_usec_basic() {
        // 1 MHz freq, 1000 ticks = 1ms = 1000us
        assert_eq!(time_usec(1000, 1_000_000), 1000);
    }

    #[test]
    fn test_time_usec_zero_ticks() {
        assert_eq!(time_usec(0, 1_000_000), 0);
    }

    #[test]
    fn test_time_usec_zero_freq() {
        assert_eq!(time_usec(1000, 0), 0);
    }

    #[test]
    fn test_time_usec_1ghz() {
        // 1 GHz freq, 1e9 ticks = 1 second = 1e6 us
        assert_eq!(time_usec(1_000_000_000, 1_000_000_000), 1_000_000);
    }

    #[test]
    fn test_calibrate_freq() {
        // 1000 ticks in 1000us = 1MHz
        assert_eq!(calibrate_freq(0, 1000, 1000), 1_000_000);
    }

    #[test]
    fn test_calibrate_freq_overflow() {
        assert_eq!(calibrate_freq(1000, 0, 1000), 0);
    }

    #[test]
    fn test_calibrate_freq_zero_delay() {
        assert_eq!(calibrate_freq(0, 1000, 0), 0);
    }

    #[test]
    fn test_ticks_overflowed() {
        assert!(ticks_overflowed(100, 50));
        assert!(!ticks_overflowed(50, 100));
        assert!(!ticks_overflowed(100, 100));
    }

    #[test]
    fn test_cpuid_freq() {
        // crystal=24MHz, denom=2, num=1 => 24e6*1/2 = 12MHz
        assert_eq!(cpuid_freq(24_000_000, 2, 1), 12_000_000);
    }

    #[test]
    fn test_cpuid_freq_zero_denom() {
        assert_eq!(cpuid_freq(24_000_000, 0, 1), 0);
    }

    #[test]
    fn test_cpuid_freq_zero_numer() {
        assert_eq!(cpuid_freq(24_000_000, 1, 0), 0);
    }

    #[test]
    fn test_deduce_crystal_hz() {
        // core=2400MHz, denom=2, num=1 => 2400e6*2/1 = 4800MHz
        let result = deduce_crystal_hz(2400, 2, 1);
        assert_eq!(result, 4_800_000_000);
    }

    #[test]
    fn test_deduce_crystal_hz_zero_denom() {
        assert_eq!(deduce_crystal_hz(2400, 0, 1), 0);
    }

    #[test]
    fn test_compute_tick_freq_with_crystal() {
        let freq = compute_tick_freq(24_000_000, 2, 1, None);
        assert_eq!(freq, 12_000_000);
    }

    #[test]
    fn test_compute_tick_freq_with_core_mhz() {
        let freq = compute_tick_freq(0, 2, 1, Some(2400));
        // crystal deduced = 2400*1e6*2/1 = 4800MHz
        // freq = 4800e6*1/2 = 2400MHz
        assert_eq!(freq, 2_400_000_000);
    }

    #[test]
    fn test_compute_tick_freq_no_data() {
        assert_eq!(compute_tick_freq(0, 2, 1, None), 0);
    }

    #[test]
    fn test_tick_state_caching() {
        let mut state = TickState::new();
        // First call: use arch_freq
        assert_eq!(state.freq(1_000_000, 0, 0), 1_000_000);
        // Second call: cached
        assert_eq!(state.freq(0, 0, 0), 1_000_000);
        assert_eq!(state.cached_freq(), 1_000_000);
    }

    #[test]
    fn test_tick_state_calibration() {
        let mut state = TickState::new();
        // arch_freq=0, use calibration: 1000 ticks in 1ms
        let freq = state.freq(0, 100, 1100);
        assert_eq!(freq, 1_000_000);
    }

    #[test]
    fn test_tick_state_overflow() {
        let mut state = TickState::new();
        // ticks_end < ticks_start => overflow => 0
        assert_eq!(state.freq(0, 1100, 100), 0);
    }
}
