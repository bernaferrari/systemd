// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-keyutil

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-keyutil [OPTIONS...] {{COMMAND}}");
    println!();
    println!("Operations on private keys and certificates.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --private-key=PATH  Private key path");
    println!("     --certificate=PATH  Certificate path");
    println!("     --source=TYPE     Key source (file|provider|engine)");
}

fn print_version() {
    println!("systemd-keyutil {}", VERSION);
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
        "{}: key_sources: file, provider, engine",
        env!("CARGO_PKG_NAME")
    );
}
