// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-cgtop

use systemd_cgtop_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-cgtop [OPTIONS...]");
    println!();
    println!("Show top control groups by their resource usage.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("  -b --batch          Run in batch mode (no input)");
    println!("  -r --raw            Raw output (no human-readable)");
    println!("  -p                  Order by path");
    println!("  -t                  Order by tasks");
    println!("  -c                  Order by CPU (default)");
    println!("  -m                  Order by memory");
    println!("  -i                  Order by I/O");
    println!("     --depth=N        Maximum depth to show");
    println!("     --delay=SECS     Update delay in seconds");
    println!("  -M --machine NAME   Show container");
}

fn print_version() {
    println!("systemd-cgtop {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();

    if refs.contains(&"--version") {
        print_version();
        return;
    }

    match lib::parse_cgtop_args(&refs) {
        Ok(parsed) => {
            println!(
                "order: {}  depth: {}  batch: {}",
                parsed.order.as_str(),
                parsed.depth,
                parsed.batch
            );
            if let Some(ref root) = parsed.root {
                println!("root: {}", root);
            }
        }
        Err(0) => {
            print_help();
        }
        Err(code) => {
            eprintln!("Failed to parse arguments (errno {}).", -code);
            std::process::exit(1);
        }
    }
}
