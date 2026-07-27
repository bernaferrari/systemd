// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-vpick

use systemd_vpick_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-vpick [OPTIONS...] [PATH]");
    println!();
    println!("Pick entries from versioned directories.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --print=MODE     Output mode (path|filename|version|type|arch|tries|all)");
    println!("     --resolve=MODE   Resolve symlinks");
}

fn print_version() {
    println!("systemd-vpick {}", VERSION);
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

    eprintln!(
        "{}: VC_MAX={}, print_modes: path, filename, version, type, arch, tries, all",
        env!("CARGO_PKG_NAME"),
        lib::VC_MAX
    );
}
