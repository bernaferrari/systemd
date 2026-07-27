// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-volatile-root
//
// PORT-SYNC: src/volatile-root/volatile-root.c

fn print_help() {
    eprintln!("Usage: systemd-volatile-root [MODE] [PATH]");
    eprintln!();
    eprintln!("  -h --help             Show this help");
    eprintln!("     --version          Show package version");
    eprintln!();
    eprintln!("  MODE: yes|overlay|no");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // The C implementation obtains the effective kernel command-line mode,
    // verifies the sysroot, records its backing device, and then performs a
    // carefully ordered mount-namespace transition. Do not substitute a
    // direct tmpfs/overlay mount for that sequence.
    match args.as_slice() {
        [_, flag] if flag == "-h" || flag == "--help" => {
            print_help();
            return;
        }
        [_, flag] if flag == "--version" => {
            eprintln!("systemd-volatile-root {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        _ => {}
    }

    eprintln!(
        "systemd-volatile-root: native Rust volatile-root operations are not implemented; refusing to operate"
    );
    std::process::exit(1);
}
