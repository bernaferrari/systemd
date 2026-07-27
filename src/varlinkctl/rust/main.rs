// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for varlinkctl

use systemd_varlinkctl_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("varlinkctl [OPTIONS...] {{COMMAND}} [ADDRESS]");
    println!();
    println!("Introspect and invoke Varlink services.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --timeout=USEC   Method call timeout");
    println!("     --more           Expect multiple responses");
    println!("     --oneway         Fire-and-forget call");
    println!();
    println!("Commands:");
    println!("  info ADDRESS        Show service information");
    println!("  list-interfaces     List service interfaces");
    println!("  introspect IFACE    Show interface description");
    println!("  call METHOD JSON    Invoke a method");
    println!("  validate JSON       Validate an interface description");
}

fn print_version() {
    println!("varlinkctl {}", VERSION);
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
        "{}: default_timeout={}us",
        env!("CARGO_PKG_NAME"),
        lib::DEFAULT_TIMEOUT_USEC
    );
}
