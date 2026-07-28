// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-mute-console

use systemd_mute_console_rs::{MuteContext, format_startup_notify, format_stopping_notify};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-mute-console [OPTIONS...]");
    println!("Temporarily mute PID 1 and kernel console status output.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
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
                println!("systemd-mute-console {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let ctx = MuteContext::default();
    if !ctx.needs_mute() {
        return;
    }

    eprintln!("{}", format_startup_notify());
    let _ = ctx.pid1_mute_value();
    eprintln!("{}", format_stopping_notify());
}
