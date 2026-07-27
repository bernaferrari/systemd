// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-sysext

use systemd_sysext_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-sysext [OPTIONS...] {{COMMAND}}");
    println!();
    println!("Manage system extension images.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --mutable=MODE   Mutable mode (no|yes|auto|import|ephemeral)");
    println!("     --force          Force operation");
    println!("     --no-pager       Do not pipe output into pager");
    println!();
    println!("Commands:");
    println!("  list                List extensions");
    println!("  merge               Merge extensions");
    println!("  unmerge             Unmerge extensions");
    println!("  refresh             Refresh merged extensions");
}

fn print_version() {
    println!("systemd-sysext {}", VERSION);
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
        "{}: base_dir={}, mount_opts={}",
        env!("CARGO_PKG_NAME"),
        lib::MUTABLE_EXTENSIONS_BASE_DIR,
        lib::MUTABLE_EXTENSIONS_MOUNT_OPTIONS
    );
}
