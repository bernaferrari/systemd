// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-battery-check

use systemd_battery_check_rs::{
    parse_battery_check_args, run_battery_check, BatteryCheckResult, BATTERY_LOW_MESSAGE,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-battery-check [OPTIONS...]");
    println!("Check battery level before proceeding.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    let check_args = match parse_battery_check_args(&refs) {
        Ok(a) => a,
        Err(0) => {
            if refs.contains(&"--help") || refs.contains(&"-h") {
                print_help();
            } else {
                println!("systemd-battery-check {}", VERSION);
            }
            return;
        }
        Err(_) => {
            eprintln!("Usage: systemd-battery-check. Try --help.");
            std::process::exit(1);
        }
    };

    let _ = BATTERY_LOW_MESSAGE;
    let exit_code = run_battery_check(
        BatteryCheckResult::Ok,
        BatteryCheckResult::Ok,
        check_args.doit,
    );
    std::process::exit(exit_code);
}
