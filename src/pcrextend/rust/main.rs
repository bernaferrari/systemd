// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-pcrextend

use systemd_pcrextend_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-pcrextend [OPTIONS...] {{PCR}} {{DATA}}");
    println!();
    println!("Extend TPM2 Platform Configuration Registers.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --bank=HASH      PCR bank (sha1|sha256|sha384|sha512)");
    println!("     --pcr=INDEX      PCR index (0-23)");
    println!("     --file-system=FS Extend with filesystem data");
    println!("     --machine-id     Extend with machine ID");
    println!("     --product-id     Extend with product ID");
}

fn print_version() {
    println!("systemd-pcrextend {}", VERSION);
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

    if let Some(bank_arg) = args[1..].iter().find(|a| a.starts_with("--bank=")) {
        let val = bank_arg.split_once('=').map(|(_, v)| v).unwrap_or("");
        match lib::normalize_bank(val) {
            Ok(bank) => println!("bank: {}", bank),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    eprintln!(
        "{}: string_safe_limit={}",
        env!("CARGO_PKG_NAME"),
        lib::EXTENSION_STRING_SAFE_LIMIT
    );
}
