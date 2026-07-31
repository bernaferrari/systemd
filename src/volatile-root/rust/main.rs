// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-volatile-root.
//
// PORT-SYNC: src/volatile-root/volatile-root.c

use systemd_volatile_root_rs::{mode_requires_root_transition, resolve_args_from_cmdline};

fn print_help() {
    eprintln!("Usage: systemd-volatile-root [MODE] [PATH]");
    eprintln!();
    eprintln!("  -h --help             Show this help");
    eprintln!("     --version          Show package version");
    eprintln!();
    eprintln!("  MODE: yes|state|overlay|no");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    // Retain the executable boundary's documented single-option help and
    // version requests. All other positional inputs are passed through the
    // C-compatible volatile-mode parser below.
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

    // This follows the C ordering: resolve the kernel command line first,
    // validate positional input even for inactive modes, then skip all mount
    // work for `no` and `state`. The old blanket refusal made an ordinary
    // initrd invocation fail even when no volatile root was requested.
    let cmdline = match std::fs::read_to_string("/proc/cmdline") {
        Ok(cmdline) => cmdline,
        Err(error) => {
            eprintln!(
                "systemd-volatile-root: failed to determine volatile mode from kernel command line: {error}"
            );
            std::process::exit(1);
        }
    };
    let parsed = match resolve_args_from_cmdline(&arg_refs, &cmdline) {
        Ok(parsed) => parsed,
        Err(_) => {
            eprintln!("systemd-volatile-root: invalid mode, path, or argument count");
            std::process::exit(1);
        }
    };

    if !mode_requires_root_transition(parsed.mode) {
        return;
    }

    // `yes` and `overlay` require C's carefully ordered mount namespace
    // transition, including source resolution, recursive no-follow unmounts,
    // and rollback. Keep this boundary fail-closed until that whole sequence
    // is implemented, rather than approximating it with direct mount calls.
    eprintln!(
        "systemd-volatile-root: Rust volatile-root mount transition is not implemented; refusing to modify {}",
        parsed.path
    );
    std::process::exit(1);
}
