// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-creds

use systemd_creds_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-creds [OPTIONS...] {{COMMAND}} [NAME [DATA]]");
    println!();
    println!("Display and process credentials.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --system         Operate on system credentials");
    println!("     --transcode=MODE Transcode mode (off|base64|unbase64|hex|unhex)");
    println!("     --name=NAME      Credential name");
    println!("     --pretty         Pretty-print output");
    println!("     --quiet          Suppress output");
    println!();
    println!("Commands:");
    println!("  encrypt NAME [DATA] Encrypt a credential");
    println!("  decrypt             Decrypt a credential");
    println!("  list                List credentials");
    println!("  has NAME            Check if credential exists");
}

fn print_version() {
    println!("systemd-creds {}", VERSION);
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
        "{}: transcode modes: off, base64, unbase64, hex, unhex",
        env!("CARGO_PKG_NAME")
    );
}
