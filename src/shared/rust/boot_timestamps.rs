// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/boot-timestamps.c, src/shared/boot-timestamps.h
//
// Boot timestamp calculation using ACPI FPDT or EFI loader data.
// Converts raw firmware/loader microsecond values into dual (realtime +
// monotonic) timestamps relative to a reference "now" point.

// ── Types ──────────────────────────────────────────────────────────────────

/// Microsecond-precision timestamp type.
pub type Usec = u64;

/// A pair of realtime and monotonic timestamps in microseconds.
///
/// Port of the C `dual_timestamp` struct. The `realtime` field is
/// wall-clock time; `monotonic` is measured from kernel init.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DualTimestamp {
    pub realtime: Usec,
    pub monotonic: Usec,
}

impl DualTimestamp {
    /// Create a new timestamp pair.
    pub const fn new(realtime: Usec, monotonic: Usec) -> Self {
        Self {
            realtime,
            monotonic,
        }
    }
}

/// Boot timestamp data for firmware and loader phases.
///
/// `firmware` covers the entire firmware phase up to the point the boot
/// loader was finished. `loader` covers just the time the boot loader
/// itself spent executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootTimestamps {
    pub firmware: DualTimestamp,
    pub loader: DualTimestamp,
}

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors returned by [`boot_timestamps`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootTimestampError {
    /// No boot timing data available from any source (ACPI or EFI).
    NoData,
}

impl std::fmt::Display for BootTimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoData => write!(f, "no boot timing data available"),
        }
    }
}

impl std::error::Error for BootTimestampError {}

// ── Core calculation ───────────────────────────────────────────────────────

/// Pure calculation that converts raw firmware/loader microsecond values
/// into dual timestamps relative to a reference point `now`.
///
/// * `now`           – the reference timestamp (typically the current time).
/// * `loader_start`  – microseconds (monotonic) when the boot loader started.
/// * `loader_exit`   – microseconds (monotonic) when the boot loader finished.
///
/// The algorithm mirrors the C implementation:
///
/// ```text
/// firmware.monotonic = loader_exit
/// loader.monotonic   = loader_exit - loader_start
/// firmware.realtime  = now.realtime - (now.monotonic + loader_exit)   [clamped to 0]
/// loader.realtime    = now.realtime - (now.monotonic + loader.monotonic) [clamped to 0]
/// ```
///
/// Because `Usec` is unsigned the realtime values are saturated at zero
/// rather than wrapping.
pub fn calculate_boot_timestamps(
    now: DualTimestamp,
    loader_start: Usec,
    loader_exit: Usec,
) -> BootTimestamps {
    let firmware_monotonic = loader_exit;
    let loader_monotonic = loader_exit.saturating_sub(loader_start);

    let fw_offset = now.monotonic.saturating_add(firmware_monotonic);
    let firmware_realtime = now.realtime.saturating_sub(fw_offset);

    let ld_offset = now.monotonic.saturating_add(loader_monotonic);
    let loader_realtime = now.realtime.saturating_sub(ld_offset);

    BootTimestamps {
        firmware: DualTimestamp::new(firmware_realtime, firmware_monotonic),
        loader: DualTimestamp::new(loader_realtime, loader_monotonic),
    }
}

// ── High-level API ─────────────────────────────────────────────────────────

/// Trait abstracting a source of raw boot timing data (ACPI FPDT, EFI, …).
///
/// Implementors return `(loader_start_usec, loader_exit_usec)` on success.
pub trait BootTimingSource {
    /// Read raw boot timing from this source.
    ///
    /// Returns `(loader_start_usec, loader_exit_usec)` on success.
    fn get_boot_usec(&self) -> Result<(Usec, Usec), BootTimestampError>;
}

/// Compute firmware and loader dual timestamps.
///
/// If `now` is `None` a zero-initialized timestamp is used (callers that
/// need the actual current time should supply it explicitly).
///
/// The function queries `source` for raw timing data. A typical caller
/// chains an ACPI source with an EFI fallback:
///
/// ```ignore
/// let chain = ChainSource::new(acpi_source, efi_source);
/// let result = boot_timestamps(now, &chain)?;
/// ```
pub fn boot_timestamps<S: BootTimingSource + ?Sized>(
    now: Option<DualTimestamp>,
    source: &S,
) -> Result<BootTimestamps, BootTimestampError> {
    let now = now.unwrap_or_default();
    let (loader_start, loader_exit) = source.get_boot_usec()?;
    Ok(calculate_boot_timestamps(now, loader_start, loader_exit))
}

// ── Source utilities ───────────────────────────────────────────────────────

/// A boot timing source that tries a primary source first, falling back
/// to a secondary one on failure.
#[derive(Debug, Clone, Copy)]
pub struct ChainSource<A, B> {
    primary: A,
    fallback: B,
}

impl<A, B> ChainSource<A, B> {
    pub const fn new(primary: A, fallback: B) -> Self {
        Self { primary, fallback }
    }
}

impl<A: BootTimingSource, B: BootTimingSource> BootTimingSource for ChainSource<A, B> {
    fn get_boot_usec(&self) -> Result<(Usec, Usec), BootTimestampError> {
        self.primary
            .get_boot_usec()
            .or_else(|_| self.fallback.get_boot_usec())
    }
}

/// A simple in-memory source for testing / fuzzing.
#[derive(Debug, Clone, Copy)]
pub struct StaticSource {
    pub loader_start: Usec,
    pub loader_exit: Usec,
}

impl BootTimingSource for StaticSource {
    fn get_boot_usec(&self) -> Result<(Usec, Usec), BootTimestampError> {
        Ok((self.loader_start, self.loader_exit))
    }
}

/// A source that always returns [`BootTimestampError::NoData`].
#[derive(Debug, Clone, Copy)]
pub struct NoDataSource;

impl BootTimingSource for NoDataSource {
    fn get_boot_usec(&self) -> Result<(Usec, Usec), BootTimestampError> {
        Err(BootTimestampError::NoData)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_timestamp_default() {
        let ts = DualTimestamp::default();
        assert_eq!(ts.realtime, 0);
        assert_eq!(ts.monotonic, 0);
    }

    #[test]
    fn test_dual_timestamp_new() {
        let ts = DualTimestamp::new(100, 200);
        assert_eq!(ts.realtime, 100);
        assert_eq!(ts.monotonic, 200);
    }

    #[test]
    fn test_dual_timestamp_equality() {
        let a = DualTimestamp::new(10, 20);
        let b = DualTimestamp::new(10, 20);
        let c = DualTimestamp::new(30, 40);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_dual_timestamp_copy() {
        let a = DualTimestamp::new(1, 2);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_calculate_basic() {
        let now = DualTimestamp::new(10_000_000, 5_000_000);
        let result = calculate_boot_timestamps(now, 1_000_000, 2_000_000);

        assert_eq!(result.firmware.monotonic, 2_000_000);
        assert_eq!(result.loader.monotonic, 1_000_000);
        assert_eq!(result.firmware.realtime, 3_000_000);
        assert_eq!(result.loader.realtime, 4_000_000);
    }

    #[test]
    fn test_calculate_zero_timing() {
        let now = DualTimestamp::new(100, 50);
        let result = calculate_boot_timestamps(now, 0, 0);

        assert_eq!(result.firmware.monotonic, 0);
        assert_eq!(result.loader.monotonic, 0);
        assert_eq!(result.firmware.realtime, 50);
        assert_eq!(result.loader.realtime, 50);
    }

    #[test]
    fn test_calculate_realtime_clamps_to_zero() {
        let now = DualTimestamp::new(100, 50);
        let result = calculate_boot_timestamps(now, 10, 200);

        assert_eq!(result.firmware.realtime, 0);
        assert_eq!(result.loader.realtime, 0);
    }

    #[test]
    fn test_calculate_loader_start_exceeds_exit() {
        let now = DualTimestamp::new(5000, 1000);
        let result = calculate_boot_timestamps(now, 500, 100);

        assert_eq!(result.firmware.monotonic, 100);
        assert_eq!(result.loader.monotonic, 0);
    }

    #[test]
    fn test_calculate_large_values_no_panic() {
        let now = DualTimestamp::new(u64::MAX, u64::MAX / 2);
        let result = calculate_boot_timestamps(now, 1_000_000, 2_000_000);

        assert_eq!(result.firmware.monotonic, 2_000_000);
        assert_eq!(result.loader.monotonic, 1_000_000);
        assert!(result.firmware.realtime < u64::MAX);
        assert!(result.loader.realtime < u64::MAX);
    }

    #[test]
    fn test_boot_timestamps_with_static_source() {
        let src = StaticSource {
            loader_start: 500,
            loader_exit: 1500,
        };
        let now = DualTimestamp::new(100_000, 50_000);
        let result = boot_timestamps(Some(now), &src).unwrap();

        assert_eq!(result.firmware.monotonic, 1500);
        assert_eq!(result.loader.monotonic, 1000);
    }

    #[test]
    fn test_boot_timestamps_default_now() {
        let src = StaticSource {
            loader_start: 0,
            loader_exit: 0,
        };
        let result = boot_timestamps(None, &src).unwrap();

        assert_eq!(result.firmware.monotonic, 0);
        assert_eq!(result.loader.monotonic, 0);
        assert_eq!(result.firmware.realtime, 0);
        assert_eq!(result.loader.realtime, 0);
    }

    #[test]
    fn test_boot_timestamps_no_data() {
        let result = boot_timestamps(None, &NoDataSource);
        assert_eq!(result.unwrap_err(), BootTimestampError::NoData);
    }

    #[test]
    fn test_chain_source_primary_succeeds() {
        let primary = StaticSource {
            loader_start: 100,
            loader_exit: 200,
        };
        let fallback = NoDataSource;
        let chain = ChainSource::new(primary, fallback);

        let (x, y) = chain.get_boot_usec().unwrap();
        assert_eq!(x, 100);
        assert_eq!(y, 200);
    }

    #[test]
    fn test_chain_source_falls_back() {
        let primary = NoDataSource;
        let fallback = StaticSource {
            loader_start: 300,
            loader_exit: 400,
        };
        let chain = ChainSource::new(primary, fallback);

        let (x, y) = chain.get_boot_usec().unwrap();
        assert_eq!(x, 300);
        assert_eq!(y, 400);
    }

    #[test]
    fn test_chain_source_both_fail() {
        let chain = ChainSource::new(NoDataSource, NoDataSource);
        assert_eq!(
            chain.get_boot_usec().unwrap_err(),
            BootTimestampError::NoData
        );
    }

    #[test]
    fn test_error_display() {
        let msg = format!("{}", BootTimestampError::NoData);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_calculate_matches_c_logic() {
        let now = DualTimestamp::new(30_000_000, 20_000_000);
        let result = calculate_boot_timestamps(now, 3_000_000, 8_000_000);

        assert_eq!(result.firmware.monotonic, 8_000_000);
        assert_eq!(result.loader.monotonic, 5_000_000);

        let expected_fw_realtime = 30_000_000u64.saturating_sub(20_000_000 + 8_000_000);
        let expected_ld_realtime = 30_000_000u64.saturating_sub(20_000_000 + 5_000_000);
        assert_eq!(result.firmware.realtime, expected_fw_realtime);
        assert_eq!(result.loader.realtime, expected_ld_realtime);
    }
}
