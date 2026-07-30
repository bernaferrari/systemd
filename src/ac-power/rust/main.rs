// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-ac-power

use systemd_ac_power_rs::{AcPowerAction, parse_ac_power_args, run_ac_power, run_low_battery};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-ac-power [OPTIONS...]");
    println!("Report whether system is on AC power.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
    println!("  -v --verbose           Show result as text");
    println!("     --low               Check for low battery instead");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    let ac_args = match parse_ac_power_args(&refs) {
        Ok(a) => a,
        Err(0) => {
            if refs.contains(&"--help") || refs.contains(&"-h") {
                print_help();
            } else {
                println!("systemd-ac-power {}", VERSION);
            }
            return;
        }
        Err(_) => {
            eprintln!("Usage: systemd-ac-power. Try --help.");
            std::process::exit(1);
        }
    };

    let exit_code = match ac_args.action {
        AcPowerAction::AcPower => {
            let result = run_ac_power(&ac_args, detect_on_ac_power);
            result.unwrap_or(1)
        }
        AcPowerAction::Low => {
            let result = run_low_battery(&ac_args, detect_low_battery);
            result.unwrap_or(0)
        }
    };
    std::process::exit(exit_code);
}

#[cfg(target_os = "linux")]
fn detect_on_ac_power() -> Result<bool, i32> {
    let ps_dir = std::path::Path::new("/sys/class/power_supply");
    if !ps_dir.exists() {
        return Ok(true); // no power supply info → assume AC (matches C behavior)
    }

    let entries = std::fs::read_dir(ps_dir).map_err(|_| -libc::EIO)?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let type_str = std::fs::read_to_string(path.join("type")).unwrap_or_default();
        let type_str = type_str.trim();

        if type_str == "Mains" {
            let online = std::fs::read_to_string(path.join("online")).unwrap_or_default();
            if online.trim() == "1" {
                return Ok(true);
            }
        } else if type_str == "Battery" {
            let status = std::fs::read_to_string(path.join("status")).unwrap_or_default();
            let status = status.trim();
            if status == "Charging" || status == "Full" {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn detect_on_ac_power() -> Result<bool, i32> {
    Ok(true)
}

/// Detect whether the system is on AC power by reading /sys/class/power_supply/.
#[cfg(target_os = "linux")]
fn detect_low_battery() -> Result<bool, i32> {
    let ps_dir = std::path::Path::new("/sys/class/power_supply");
    if !ps_dir.exists() {
        return Ok(false);
    }

    let entries = std::fs::read_dir(ps_dir).map_err(|_| -libc::EIO)?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let type_str = std::fs::read_to_string(path.join("type")).unwrap_or_default();
        if type_str.trim() != "Battery" {
            continue;
        }

        let status = std::fs::read_to_string(path.join("status")).unwrap_or_default();
        if status.trim() != "Discharging" {
            continue;
        }

        // Check capacity if available
        if let Ok(cap_str) = std::fs::read_to_string(path.join("capacity"))
            && let Ok(cap) = cap_str.trim().parse::<u32>()
            && cap < 10
        {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn detect_low_battery() -> Result<bool, i32> {
    Ok(false)
}
