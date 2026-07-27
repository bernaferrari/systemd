// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-machined
//
// PORT-SYNC: src/machine/machined.c

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-machined [OPTIONS...]");
    println!();
    println!("  -h --help             Show this help");
    println!("     --version          Show package version");
    println!();
    println!("The Rust daemon runtime is not implemented.");
}

fn print_version() {
    println!("systemd-machined {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_, flag] if matches!(flag.as_str(), "-h" | "--help") => print_help(),
        [_, flag] if flag == "--version" => print_version(),
        _ => {
            /*
             * machined is a service, not a socket placeholder. The C daemon creates
             * its manager, publishes the machine1 D-Bus API, installs the Varlink
             * methods, and only then reports READY=1. None of those protocol
             * boundaries are implemented by this executable yet. In particular, do
             * not create or replace the well-known Varlink socket: doing so would
             * make clients believe a service is available while silently dropping
             * their requests.
             */
            eprintln!(
                "systemd-machined: Rust daemon runtime is not implemented; refusing to start"
            );
            std::process::exit(1);
        }
    }
}
