// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-mstack
//
// PORT-SYNC: src/mstack/mstack-tool.c

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-mstack [OPTIONS...] WHAT");
    println!("systemd-mstack [OPTIONS...] --mount WHAT WHERE");
    println!("systemd-mstack [OPTIONS...] --umount WHERE");
    println!();
    println!("Inspect or apply a mount stack.");
}

fn print_version() {
    println!("systemd-mstack {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Keep the non-mutating informational interface available. All operational
    // paths must stay closed until the C mstack/image-dissection and mount
    // namespace lifecycle can be implemented as one coherent operation.
    match args.as_slice() {
        [_, flag] if flag == "-h" || flag == "--help" => {
            print_help();
            return;
        }
        [_, flag] if flag == "--version" => {
            print_version();
            return;
        }
        _ => {}
    }

    eprintln!(
        "systemd-mstack: native Rust mstack operations are not implemented; refusing to operate"
    );
    std::process::exit(1);
}
