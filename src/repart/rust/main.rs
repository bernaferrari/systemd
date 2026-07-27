// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-repart

use systemd_repart_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-repart [OPTIONS...] [DEVICE|IMAGE]");
    println!();
    println!("Grow and shrink partitions, create disk images.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --dry-run        Show changes without applying");
    println!("     --empty=MODE     How to handle empty drives");
    println!("     --size=BYTES     Set partition size");
    println!("     --definitions=DIR Read .partition definitions");
    println!("     --sector-size=N  Sector size in bytes");
}

fn print_version() {
    println!("systemd-repart {}", VERSION);
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

    let config = lib::RepartConfig::default();
    if let Err(e) = config.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    let name = env!("CARGO_PKG_NAME");
    eprintln!(
        "{}: default_min_size={}, hard_min_size={}, sector_size={}",
        name,
        lib::DEFAULT_MIN_SIZE,
        lib::HARD_MIN_SIZE,
        config.sector_size
    );
}
