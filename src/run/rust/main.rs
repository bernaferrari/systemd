// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-run

use systemd_run_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-run [OPTIONS...] {{COMMAND}} [ARGS...]");
    println!();
    println!("Run command in transient scope or service.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --scope          Run as scope instead of service");
    println!("     --unit=NAME      Override unit name");
    println!("     --property=PROP  Set unit property");
    println!("     --setenv=VAR     Set environment variable");
    println!("     --pty            Allocate pseudo-TTY");
    println!("     --pipe           Connect stdin/stdout/stderr");
    println!("     --wait           Wait for service to exit");
    println!("     --quiet          Suppress output");
    println!("  -M --machine=NAME   Run in container");
    println!("     --user           Run in user session");
}

fn print_version() {
    println!("systemd-run {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    for arg in &args[1..] {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            _ => {}
        }
    }

    let scope = args[1..].iter().any(|a| a == "--scope");
    if let Err(e) = lib::validate_trigger_compatibility(false, false, false) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    eprintln!("{}: scope={}, job_mode=fail", env!("CARGO_PKG_NAME"), scope);
}
