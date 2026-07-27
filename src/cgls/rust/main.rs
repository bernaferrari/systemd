// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-cgls

use systemd_cgls_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-cgls [OPTIONS...] [CGROUP]");
    println!();
    println!("Recursively show control group contents.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("  -a --all            Show all units");
    println!("  -l --full           Do not ellipsize output");
    println!("  -k                  Include kernel threads");
    println!("  -u --unit [UNIT]    Show system units");
    println!("     --user-unit [U]  Show user units");
    println!("  -M --machine NAME   Show container");
}

fn print_version() {
    println!("systemd-cgls {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();

    match lib::parse_cgls_args(&refs) {
        Ok(parsed) => {
            let header =
                lib::format_cgroup_header(parsed.names.first().map(|s| s.as_str()).unwrap_or(""));
            println!("{}", header);
            println!(
                "  flags: {:?}, show_unit: {:?}, machine: {:?}",
                parsed.output_flags, parsed.show_unit, parsed.machine
            );
        }
        Err(0) => {
            // --help or --version from the parser
            print_help();
        }
        Err(code) => {
            eprintln!("Failed to parse arguments (errno {}).", -code);
            std::process::exit(1);
        }
    }
}
