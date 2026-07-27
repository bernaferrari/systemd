// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/battery-util.c, src/shared/battery-util.h
//
// Battery and power supply utilities for detecting AC power status
// and battery charge levels. Reads from /sys/class/power_supply to
// enumerate power sources, determine discharge state, and check
// whether the battery is critically low.
//
// Public API:
//   - `on_ac_power()` — is the system running on AC power?
//   - `battery_enumerator_new()` — collect paths to present system batteries
//   - `battery_read_capacity_percentage()` — read capacity from a battery syspath
//   - `battery_is_discharging_and_low()` — low-battery + not-on-AC check

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::ffi::Errno;

// ── Constants ─────────────────────────────────────────────────────────────

/// Battery capacity percentage considered "low".
const BATTERY_LOW_CAPACITY_LEVEL: u8 = 5;

/// Base sysfs path for power supply devices.
const POWER_SUPPLY_BASE: &str = "/sys/class/power_supply";

/// Kernel power supply type strings.
const PS_TYPE_BATTERY: &str = "Battery";
const PS_TYPE_USB: &str = "USB";

/// USB-C power-role markers (bracket-delimited in sysfs).
const POWER_ROLE_SOURCE: &str = "[source]";
const POWER_ROLE_SINK: &str = "[sink]";

/// Battery status strings.
const BATTERY_STATUS_DISCHARGING: &str = "Discharging";

/// Battery scope string (device-scope batteries are not system batteries).
const BATTERY_SCOPE_DEVICE: &str = "Device";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by battery utility operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatteryError {
    /// Underlying OS error (wrapped errno).
    Errno(Errno),
    /// An I/O error from reading sysfs.
    Io(String),
    /// Capacity value out of the 0–100 range.
    CapacityOutOfRange(i32),
    /// Invalid (non-integer) content in a sysfs attribute file.
    InvalidSysfsValue(String),
}

impl BatteryError {
    /// Convert a `std::io::Error` into a `BatteryError`.
    pub fn from_io(err: io::Error) -> Self {
        let raw = err.raw_os_error().unwrap_or(libc::EIO);
        match Errno_from_raw(raw) {
            Some(e) => BatteryError::Errno(e),
            None => BatteryError::Errno(Errno::EIO),
        }
    }

    /// Return the underlying errno value, if any.
    pub fn errno(&self) -> Option<Errno> {
        match self {
            BatteryError::Errno(e) => Some(*e),
            _ => None,
        }
    }
}

impl std::fmt::Display for BatteryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatteryError::Errno(e) => write!(f, "battery error: errno {:?}", e),
            BatteryError::Io(msg) => write!(f, "battery I/O error: {}", msg),
            BatteryError::CapacityOutOfRange(v) => {
                write!(f, "battery capacity out of range: {}", v)
            }
            BatteryError::InvalidSysfsValue(v) => {
                write!(f, "invalid sysfs value: {}", v)
            }
        }
    }
}

impl std::error::Error for BatteryError {}

impl From<io::Error> for BatteryError {
    fn from(err: io::Error) -> Self {
        BatteryError::from_io(err)
    }
}

impl From<Errno> for BatteryError {
    fn from(e: Errno) -> Self {
        BatteryError::Errno(e)
    }
}

/// Try to map a raw errno integer to the `Errno` enum.
fn Errno_from_raw(raw: i32) -> Option<Errno> {
    match raw {
        2 => Some(Errno::ENOENT),
        5 => Some(Errno::EIO),
        22 => Some(Errno::EINVAL),
        34 => Some(Errno::ERANGE),
        _ => None,
    }
}

// ── Result alias ──────────────────────────────────────────────────────────

/// Result type for battery utility operations.
pub type BatteryResult<T> = Result<T, BatteryError>;

// ── Sysfs helpers ─────────────────────────────────────────────────────────

/// Read a single-line sysfs attribute and return the trimmed string.
fn read_sysfs_attr(path: &Path) -> BatteryResult<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s.trim_end().to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(BatteryError::from_io(e)),
    }
}

/// Read a sysfs attribute that contains an integer.
fn read_sysfs_int(path: &Path) -> BatteryResult<Option<i32>> {
    let s = match read_sysfs_attr(path)? {
        Some(s) => s,
        None => return Ok(None),
    };
    match s.trim().parse::<i32>() {
        Ok(v) => Ok(Some(v)),
        Err(_) => Err(BatteryError::InvalidSysfsValue(s)),
    }
}

/// Read a sysfs attribute that contains an unsigned integer.
fn read_sysfs_unsigned(path: &Path) -> BatteryResult<Option<u32>> {
    let s = match read_sysfs_attr(path)? {
        Some(s) => s,
        None => return Ok(None),
    };
    match s.trim().parse::<u32>() {
        Ok(v) => Ok(Some(v)),
        Err(_) => Err(BatteryError::InvalidSysfsValue(s)),
    }
}

// ── Power-role detection (USB-C) ─────────────────────────────────────────

/// Result of checking USB-C power role for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSinkResult {
    /// The device is in sink mode (drawing power).
    Sink,
    /// The device is in source mode (providing power).
    Source,
}

/// Determine whether a USB-C power supply device is operating as a power sink.
///
/// Iterates over sibling typec ports under the device's parent directory,
/// inspecting each port's `power_role` sysfs attribute. If any port reports
/// `[sink]`, the device is considered a sink. If no ports are found at all,
/// the device is conservatively assumed to be a sink.
fn device_is_power_sink(device_path: &Path) -> BatteryResult<PowerSinkResult> {
    let parent = device_path
        .parent()
        .ok_or_else(|| BatteryError::Errno(Errno::EINVAL))?;

    let typec_path = parent.join("typec");
    if !typec_path.is_dir() {
        // No typec subsystem — conservatively assume sink.
        return Ok(PowerSinkResult::Sink);
    }

    let mut found_source = false;
    let mut found_sink = false;

    let entries = fs::read_dir(&typec_path)?;
    for entry in entries.flatten() {
        let port_path = entry.path();
        if !port_path.is_dir() {
            continue;
        }

        let power_role_path = port_path.join("power_role");
        if let Some(role) = read_sysfs_attr(&power_role_path)? {
            if role.contains(POWER_ROLE_SOURCE) {
                found_source = true;
            } else if role.contains(POWER_ROLE_SINK) {
                found_sink = true;
            }
        }
    }

    if found_sink {
        Ok(PowerSinkResult::Sink)
    } else if !found_source {
        // No ports explicitly in source mode → assume sink.
        Ok(PowerSinkResult::Sink)
    } else {
        Ok(PowerSinkResult::Source)
    }
}

// ── Battery discharge detection ──────────────────────────────────────────

/// Check whether a battery device (given by its sysfs path) is currently discharging.
///
/// A battery is considered discharging when:
/// - Its `scope` is not "Device" (device-scope batteries are peripherals).
/// - Its `present` attribute indicates it is physically present.
/// - Its `status` attribute reads "Discharging".
///
/// If any attribute cannot be read, the function follows systemd's conservative
/// defaults: missing `scope` or `present` is ignored (assumed present & system-scope),
/// missing `status` is treated as discharging.
fn battery_is_discharging(device_path: &Path) -> bool {
    // Check scope — ignore device-scope batteries.
    if let Ok(Some(scope)) = read_sysfs_attr(&device_path.join("scope")) {
        if scope == BATTERY_SCOPE_DEVICE {
            return false;
        }
    }

    // Check present.
    if let Ok(Some(present)) = read_sysfs_attr(&device_path.join("present")) {
        if present != "1" {
            return false;
        }
    }

    // Check status. Missing → assume discharging (C default).
    match read_sysfs_attr(&device_path.join("status")) {
        Ok(Some(status)) => status == BATTERY_STATUS_DISCHARGING,
        Ok(None) | Err(_) => true,
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Result of the AC-power check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcPowerResult {
    /// The system is running on AC power.
    OnAc,
    /// The system is running from battery.
    OnBattery,
}

/// Check whether the system is currently running on AC power.
///
/// Scans all power_supply devices in `/sys/class/power_supply`:
/// - **USB** type devices are checked for power-role (sink vs source).
/// - **Battery** type devices are checked for discharge state.
/// - All other types are checked for an `online` attribute.
///
/// Returns `OnAc` if any non-battery supply reports online, `OnBattery` if
/// any battery is discharging and no supply is online, or `OnAc` as the
/// conservative default when nothing definitive is found.
pub fn on_ac_power() -> BatteryResult<AcPowerResult> {
    let base = Path::new(POWER_SUPPLY_BASE);
    if !base.is_dir() {
        return Ok(AcPowerResult::OnAc);
    }

    let mut found_ac_online = false;
    let mut found_discharging_battery = false;

    let entries = fs::read_dir(base)?;
    for entry in entries.flatten() {
        let device_path = entry.path();

        let ptype = match read_sysfs_attr(&device_path.join("type"))? {
            Some(t) => t,
            None => continue,
        };

        // USB power supply — check power role.
        if ptype == PS_TYPE_USB {
            match device_is_power_sink(&device_path) {
                Ok(PowerSinkResult::Source) => continue,
                Ok(PowerSinkResult::Sink) => { /* treat as power consumer */ }
                Err(_) => continue,
            }
        }

        // Battery — check discharge state.
        if ptype == PS_TYPE_BATTERY {
            if battery_is_discharging(&device_path) {
                found_discharging_battery = true;
            }
            continue;
        }

        // Non-battery supply — check online attribute.
        if let Some(online) = read_sysfs_unsigned(&device_path.join("online"))? {
            if online > 0 {
                found_ac_online = true;
            }
        }
    }

    if found_ac_online {
        Ok(AcPowerResult::OnAc)
    } else if found_discharging_battery {
        Ok(AcPowerResult::OnBattery)
    } else {
        // No definitive information — assume AC (C default).
        Ok(AcPowerResult::OnAc)
    }
}

/// Collect paths to all present system batteries.
///
/// Enumerates power_supply devices matching:
/// - `type` == "Battery"
/// - `present` == "1"
/// - `scope` != "Device"
///
/// Returns the list of sysfs directory paths for matching batteries.
pub fn battery_enumerator_new() -> BatteryResult<Vec<PathBuf>> {
    let base = Path::new(POWER_SUPPLY_BASE);
    if !base.is_dir() {
        return Ok(Vec::new());
    }

    let mut batteries = Vec::new();
    let entries = fs::read_dir(base)?;

    for entry in entries.flatten() {
        let device_path = entry.path();

        // type == Battery
        match read_sysfs_attr(&device_path.join("type"))? {
            Some(ref t) if t == PS_TYPE_BATTERY => {}
            _ => continue,
        }

        // present == 1
        match read_sysfs_attr(&device_path.join("present"))? {
            Some(ref p) if p == "1" => {}
            _ => continue,
        }

        // scope != Device
        match read_sysfs_attr(&device_path.join("scope")) {
            Ok(Some(ref s)) if s == BATTERY_SCOPE_DEVICE => continue,
            _ => {}
        }

        batteries.push(device_path);
    }

    Ok(batteries)
}

/// Read the capacity percentage of a battery from its sysfs `capacity` attribute.
///
/// The value must be in the range 0–100 inclusive.
pub fn battery_read_capacity_percentage(device_path: &Path) -> BatteryResult<u8> {
    let capacity_path = device_path.join("capacity");
    let raw = read_sysfs_int(&capacity_path)?
        .ok_or_else(|| BatteryError::Io("capacity attribute not found".into()))?;

    if raw < 0 || raw > 100 {
        return Err(BatteryError::CapacityOutOfRange(raw));
    }

    Ok(raw as u8)
}

/// Check whether any battery is both discharging and below the low-capacity threshold,
/// while the system is not on AC power.
///
/// This is the main entry point used by systemd-sleep to decide whether to
/// trigger a low-battery action (suspend → hibernate).
///
/// Returns `false` if:
/// - The system is on AC power.
/// - Any battery has capacity above the low threshold (5%).
/// - Battery state could not be reliably determined (conservative).
pub fn battery_is_discharging_and_low() -> BatteryResult<bool> {
    // Check AC power first. If on AC, no low-battery concern.
    match on_ac_power() {
        Ok(AcPowerResult::OnAc) => return Ok(false),
        Err(_) => { /* couldn't determine — continue checking */ }
        Ok(AcPowerResult::OnBattery) => { /* proceed */ }
    }

    let batteries = battery_enumerator_new()?;

    let mut unsure = false;
    let mut found_low = false;

    for dev in &batteries {
        match battery_read_capacity_percentage(dev) {
            Ok(capacity) => {
                if capacity > BATTERY_LOW_CAPACITY_LEVEL {
                    // Found a sufficiently charged battery.
                    return Ok(false);
                }
                found_low = true;
            }
            Err(_) => {
                unsure = true;
                continue;
            }
        }
    }

    // If any battery state was unreadable, don't assume low.
    if unsure {
        return Ok(false);
    }

    Ok(found_low)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: create a temporary directory tree mimicking /sys/class/power_supply.
    /// Returns (TempDir, power_supply_path).
    fn setup_power_supply() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let ps = tmp.path().join("power_supply");
        fs::create_dir_all(&ps).unwrap();
        (tmp, ps)
    }

    /// Helper: create a power supply device directory with attributes.
    fn create_device(base: &Path, name: &str, attrs: &[(&str, &str)]) -> PathBuf {
        let dev = base.join(name);
        fs::create_dir_all(&dev).unwrap();
        for (attr, val) in attrs {
            fs::write(dev.join(attr), val).unwrap();
        }
        dev
    }

    #[test]
    fn test_battery_low_capacity_level() {
        assert_eq!(BATTERY_LOW_CAPACITY_LEVEL, 5);
    }

    #[test]
    fn test_battery_is_discharging_status_discharging() {
        let (tmp, ps) = setup_power_supply();
        create_device(
            &ps,
            "BAT0",
            &[
                ("scope", "System"),
                ("present", "1"),
                ("status", "Discharging"),
            ],
        );
        assert!(battery_is_discharging(&ps.join("BAT0")));
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_status_charging() {
        let (tmp, ps) = setup_power_supply();
        create_device(
            &ps,
            "BAT0",
            &[
                ("scope", "System"),
                ("present", "1"),
                ("status", "Charging"),
            ],
        );
        assert!(!battery_is_discharging(&ps.join("BAT0")));
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_device_scope() {
        let (tmp, ps) = setup_power_supply();
        create_device(
            &ps,
            "BAT0",
            &[
                ("scope", "Device"),
                ("present", "1"),
                ("status", "Discharging"),
            ],
        );
        assert!(!battery_is_discharging(&ps.join("BAT0")));
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_not_present() {
        let (tmp, ps) = setup_power_supply();
        create_device(
            &ps,
            "BAT0",
            &[
                ("scope", "System"),
                ("present", "0"),
                ("status", "Discharging"),
            ],
        );
        assert!(!battery_is_discharging(&ps.join("BAT0")));
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_missing_status() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "BAT0", &[("scope", "System"), ("present", "1")]);
        // Missing status → assume discharging.
        assert!(battery_is_discharging(&ps.join("BAT0")));
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_nonexistent_path() {
        assert!(!battery_is_discharging(Path::new("/nonexistent/path/BAT0")));
    }

    #[test]
    fn test_battery_read_capacity_percentage_valid() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "BAT0", &[("capacity", "42")]);
        let result = battery_read_capacity_percentage(&ps.join("BAT0"));
        assert_eq!(result.unwrap(), 42);
        drop(tmp);
    }

    #[test]
    fn test_battery_read_capacity_percentage_out_of_range() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "BAT0", &[("capacity", "150")]);
        let result = battery_read_capacity_percentage(&ps.join("BAT0"));
        assert!(matches!(result, Err(BatteryError::CapacityOutOfRange(150))));
        drop(tmp);
    }

    #[test]
    fn test_battery_read_capacity_percentage_negative() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "BAT0", &[("capacity", "-1")]);
        let result = battery_read_capacity_percentage(&ps.join("BAT0"));
        assert!(matches!(result, Err(BatteryError::CapacityOutOfRange(-1))));
        drop(tmp);
    }

    #[test]
    fn test_battery_read_capacity_percentage_missing() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "BAT0", &[]);
        let result = battery_read_capacity_percentage(&ps.join("BAT0"));
        assert!(result.is_err());
        drop(tmp);
    }

    #[test]
    fn test_battery_read_capacity_percentage_boundaries() {
        let (tmp, ps) = setup_power_supply();

        create_device(&ps, "BAT0", &[("capacity", "0")]);
        assert_eq!(
            battery_read_capacity_percentage(&ps.join("BAT0")).unwrap(),
            0
        );

        create_device(&ps, "BAT1", &[("capacity", "100")]);
        assert_eq!(
            battery_read_capacity_percentage(&ps.join("BAT1")).unwrap(),
            100
        );

        drop(tmp);
    }

    #[test]
    fn test_battery_enumerator_new_filters() {
        let (tmp, ps) = setup_power_supply();

        // Valid system battery.
        create_device(
            &ps,
            "BAT0",
            &[
                ("type", "Battery"),
                ("present", "1"),
                ("scope", "System"),
                ("capacity", "80"),
            ],
        );

        // Device-scope battery (should be filtered out).
        create_device(
            &ps,
            "BAT1",
            &[("type", "Battery"), ("present", "1"), ("scope", "Device")],
        );

        // Not-present battery (should be filtered out).
        create_device(
            &ps,
            "BAT2",
            &[("type", "Battery"), ("present", "0"), ("scope", "System")],
        );

        // Non-battery device.
        create_device(&ps, "AC0", &[("type", "Mains"), ("online", "1")]);

        let batteries = battery_enumerator_new().unwrap();
        assert_eq!(batteries.len(), 1);
        assert!(batteries[0].file_name().unwrap() == "BAT0");

        drop(tmp);
    }

    #[test]
    fn test_battery_enumerator_new_empty() {
        let (tmp, _ps) = setup_power_supply();
        let batteries = battery_enumerator_new().unwrap();
        assert!(batteries.is_empty());
        drop(tmp);
    }

    #[test]
    fn test_device_is_power_sink_no_typec() {
        let (tmp, ps) = setup_power_supply();
        let dev = create_device(&ps, "usb0", &[("type", "USB")]);
        // No typec directory → assume sink.
        assert_eq!(device_is_power_sink(&dev).unwrap(), PowerSinkResult::Sink);
        drop(tmp);
    }

    #[test]
    fn test_device_is_power_sink_with_source_ports() {
        let (tmp, ps) = setup_power_supply();
        let dev = create_device(&ps, "usb0", &[("type", "USB")]);

        // Create typec ports all in source mode.
        let typec = dev.parent().unwrap().join("typec");
        fs::create_dir_all(&typec).unwrap();
        let port = typec.join("port0");
        fs::create_dir_all(&port).unwrap();
        fs::write(port.join("power_role"), "[source]\n").unwrap();

        assert_eq!(device_is_power_sink(&dev).unwrap(), PowerSinkResult::Source);
        drop(tmp);
    }

    #[test]
    fn test_device_is_power_sink_with_sink_ports() {
        let (tmp, ps) = setup_power_supply();
        let dev = create_device(&ps, "usb0", &[("type", "USB")]);

        let typec = dev.parent().unwrap().join("typec");
        fs::create_dir_all(&typec).unwrap();
        let port = typec.join("port0");
        fs::create_dir_all(&port).unwrap();
        fs::write(port.join("power_role"), "[sink]\n").unwrap();

        assert_eq!(device_is_power_sink(&dev).unwrap(), PowerSinkResult::Sink);
        drop(tmp);
    }

    #[test]
    fn test_on_ac_power_with_mains_online() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "AC0", &[("type", "Mains"), ("online", "1")]);
        create_device(
            &ps,
            "BAT0",
            &[
                ("type", "Battery"),
                ("present", "1"),
                ("scope", "System"),
                ("status", "Discharging"),
            ],
        );
        // AC online → OnAc even with discharging battery.
        assert_eq!(on_ac_power().unwrap(), AcPowerResult::OnAc);
        drop(tmp);
    }

    #[test]
    fn test_on_ac_power_battery_only() {
        let (tmp, ps) = setup_power_supply();
        create_device(
            &ps,
            "BAT0",
            &[
                ("type", "Battery"),
                ("present", "1"),
                ("scope", "System"),
                ("status", "Discharging"),
            ],
        );
        assert_eq!(on_ac_power().unwrap(), AcPowerResult::OnBattery);
        drop(tmp);
    }

    #[test]
    fn test_on_ac_power_no_devices() {
        let (tmp, _ps) = setup_power_supply();
        // No devices at all → assume AC.
        assert_eq!(on_ac_power().unwrap(), AcPowerResult::OnAc);
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_and_low_true() {
        let (tmp, ps) = setup_power_supply();
        // Mains offline.
        create_device(&ps, "AC0", &[("type", "Mains"), ("online", "0")]);
        // Battery at 3% (below threshold of 5).
        create_device(
            &ps,
            "BAT0",
            &[
                ("type", "Battery"),
                ("present", "1"),
                ("scope", "System"),
                ("status", "Discharging"),
                ("capacity", "3"),
            ],
        );
        assert!(battery_is_discharging_and_low().unwrap());
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_and_low_false_on_ac() {
        let (tmp, ps) = setup_power_supply();
        // Mains online.
        create_device(&ps, "AC0", &[("type", "Mains"), ("online", "1")]);
        // Battery at 2% but on AC.
        create_device(
            &ps,
            "BAT0",
            &[
                ("type", "Battery"),
                ("present", "1"),
                ("scope", "System"),
                ("status", "Discharging"),
                ("capacity", "2"),
            ],
        );
        assert!(!battery_is_discharging_and_low().unwrap());
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_and_low_false_charged() {
        let (tmp, ps) = setup_power_supply();
        // No AC power.
        create_device(&ps, "AC0", &[("type", "Mains"), ("online", "0")]);
        // Battery at 50% (above threshold).
        create_device(
            &ps,
            "BAT0",
            &[
                ("type", "Battery"),
                ("present", "1"),
                ("scope", "System"),
                ("status", "Discharging"),
                ("capacity", "50"),
            ],
        );
        assert!(!battery_is_discharging_and_low().unwrap());
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_and_low_false_unsure() {
        let (tmp, ps) = setup_power_supply();
        // No AC power.
        create_device(&ps, "AC0", &[("type", "Mains"), ("online", "0")]);
        // Battery present but capacity file missing → unsure.
        create_device(
            &ps,
            "BAT0",
            &[
                ("type", "Battery"),
                ("present", "1"),
                ("scope", "System"),
                ("status", "Discharging"),
            ],
        );
        // Should return false when unsure.
        assert!(!battery_is_discharging_and_low().unwrap());
        drop(tmp);
    }

    #[test]
    fn test_battery_is_discharging_and_low_no_batteries() {
        let (tmp, ps) = setup_power_supply();
        // No batteries at all → false.
        assert!(!battery_is_discharging_and_low().unwrap());
        drop(tmp);
    }

    #[test]
    fn test_read_sysfs_int_valid() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "DEV0", &[("attr", "42")]);
        assert_eq!(
            read_sysfs_int(&ps.join("DEV0").join("attr")).unwrap(),
            Some(42)
        );
        drop(tmp);
    }

    #[test]
    fn test_read_sysfs_int_missing() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "DEV0", &[]);
        assert_eq!(
            read_sysfs_int(&ps.join("DEV0").join("nonexistent")).unwrap(),
            None
        );
        drop(tmp);
    }

    #[test]
    fn test_read_sysfs_int_invalid() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "DEV0", &[("attr", "not-a-number")]);
        assert!(read_sysfs_int(&ps.join("DEV0").join("attr")).is_err());
        drop(tmp);
    }

    #[test]
    fn test_read_sysfs_attr_trims_newline() {
        let (tmp, ps) = setup_power_supply();
        create_device(&ps, "DEV0", &[("val", "hello\n")]);
        assert_eq!(
            read_sysfs_attr(&ps.join("DEV0").join("val")).unwrap(),
            Some("hello".to_string())
        );
        drop(tmp);
    }

    #[test]
    fn test_battery_error_display() {
        let e = BatteryError::CapacityOutOfRange(150);
        assert!(e.to_string().contains("150"));

        let e = BatteryError::Errno(Errno::EIO);
        assert!(e.to_string().contains("EIO"));
    }
}
