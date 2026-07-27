// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for kernel-install

use systemd_kernel_install_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("kernel-install [OPTIONS...] COMMAND [VERSION] [IMAGE]");
    println!();
    println!("Add or remove kernel to/from boot loader.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --layout=LAYOUT  Boot layout (auto|uki|bls)");
    println!("     --entry-token=T  Entry token type");
    println!();
    println!("Commands:");
    println!("  add VERSION IMAGE   Install kernel");
    println!("  remove VERSION      Remove kernel");
    println!("  inspect             Show configuration");
}

fn print_version() {
    println!("kernel-install {}", VERSION);
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

    if args.len() < 2 {
        eprintln!("Missing command. Use --help for usage.");
        std::process::exit(1);
    }

    match lib::parse_action(&args[1]) {
        Ok(action) => {
            let mut ctx = lib::new_context(action);
            if args.len() > 2 {
                if let Err(e) = lib::set_version(&mut ctx, &args[2]) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            println!("{:?}", ctx);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
