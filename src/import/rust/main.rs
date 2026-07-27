// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-importd
//
// PORT-SYNC: src/import/importd.c

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-importd [OPTIONS...]");
    println!();
    println!("  -h --help             Show this help");
    println!("     --version          Show package version");
    println!();
    println!("The Rust daemon runtime is not implemented.");
}

fn print_version() {
    println!("systemd-importd {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_, flag] if matches!(flag.as_str(), "-h" | "--help") => print_help(),
        [_, flag] if flag == "--version" => print_version(),
        _ => {
            /*
             * importd must expose the import1 D-Bus object model and the Import
             * Varlink methods before it may advertise service readiness. The Rust
             * executable has not implemented that lifecycle or transfer ownership,
             * so binding the public socket and accepting requests would be a
             * false-success daemon. Refuse before touching the socket or notify
             * protocol instead.
             */
            eprintln!("systemd-importd: Rust daemon runtime is not implemented; refusing to start");
            std::process::exit(1);
        }
    }
}
