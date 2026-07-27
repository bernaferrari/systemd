// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-ask-password

use systemd_ask_password_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-ask-password [OPTIONS...] [MESSAGE]");
    println!();
    println!("Query the user for a passphrase.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --icon=ICON      Icon name for dialog");
    println!("     --timeout=SEC    Timeout in seconds");
    println!("  -e --echo[=MODE]    Control echo (on/off/masked)");
    println!("     --id=ID          Ask-password identifier");
    println!("     --keyname=KEY    Kernel keyring name");
    println!("     --credential=N   Credential name");
    println!("     --no-output      Do not print to stdout");
    println!("     --multiple       List multiple passwords");
    println!("  -n                  No trailing newline");
}

fn print_version() {
    println!("systemd-ask-password {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();

    match lib::parse_ask_password_args(&refs) {
        Ok(parsed) => {
            if let Some(ref msg) = parsed.message {
                println!("{}", msg);
            }
            let cred = lib::default_credential_name(&parsed);
            eprintln!(
                "{}: credential='{}', timeout={}us, flags={:?}",
                env!("CARGO_PKG_NAME"),
                cred,
                parsed.timeout_usec,
                parsed.flags
            );
        }
        Err(0) => {
            print_help();
        }
        Err(code) => {
            eprintln!("Failed to parse arguments (errno {}).", -code);
            std::process::exit(1);
        }
    }
}
