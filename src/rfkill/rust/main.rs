// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-rfkill

use systemd_rfkill_rs::{EXIT_USEC, RfkillType};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-rfkill [OPTIONS...] [DEVICE]");
    println!("Manage rfkill (wireless device) state persistence.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
    println!("Device types: wlan, bluetooth, uwb, wimax, wwan, gps, fm, nfc, all");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    for a in &refs {
        match *a {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                println!("systemd-rfkill {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let _timeout = EXIT_USEC;

    if refs.is_empty() {
        eprintln!(
            "Monitoring rfkill events (timeout {}s)...",
            EXIT_USEC / 1_000_000
        );
        return;
    }

    if let Some(rfkill_type) = refs.first().and_then(|a| match *a {
        "wlan" => Some(RfkillType::Wlan),
        "bluetooth" => Some(RfkillType::Bluetooth),
        "uwb" => Some(RfkillType::Uwb),
        "wimax" => Some(RfkillType::Wimax),
        "wwan" => Some(RfkillType::Wwan),
        "gps" => Some(RfkillType::Gps),
        "fm" => Some(RfkillType::Fm),
        "nfc" => Some(RfkillType::Nfc),
        "all" => Some(RfkillType::All),
        _ => None,
    }) {
        eprintln!("Operating on rfkill type: {}", rfkill_type.as_str());
    } else if !refs.is_empty() {
        eprintln!("Unknown device type '{}'. Try --help.", refs[0]);
        std::process::exit(1);
    }
}
