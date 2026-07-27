// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-dissect

use systemd_dissect_rs::dissect as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-dissect [OPTIONS...] {{COMMAND}} [IMAGE]");
    println!();
    println!("Dissect, mount, and inspect disk images.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --mount          Mount image");
    println!("     --umount         Unmount image");
    println!("     --list           List partitions");
    println!("     --copy-from PATH Copy file from image");
    println!("     --copy-to PATH   Copy file to image");
    println!("     --discover       Discover images");
    println!("     --validate       Validate image");
}

fn print_version() {
    println!("systemd-dissect {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut action: Option<lib::Action> = None;
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
            s if s.starts_with('-') => {
                if let Some(a) = lib::parse_action(s) {
                    action = Some(a);
                }
            }
            _ => {}
        }
    }

    if let Some(a) = action {
        println!("action: {:?}", a);
    } else {
        eprintln!(
            "{}: no action specified, use --help for usage",
            env!("CARGO_PKG_NAME")
        );
    }
}
