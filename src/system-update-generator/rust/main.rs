// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-system-update-generator

use systemd_system_update_generator_rs::{GeneratorResult, UPDATE_PATHS, run as generator_run};

fn print_help() {
    eprintln!("Usage: systemd-system-update-generator [normal-dir early-dir late-dir]");
    eprintln!();
    eprintln!("  -h --help             Show this help");
    eprintln!("     --version          Show package version");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    for arg in &args[1..] {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                eprintln!(
                    "systemd-system-update-generator {}",
                    env!("CARGO_PKG_VERSION")
                );
                return;
            }
            _ => {}
        }
    }

    let normal_dir = args.get(1).map(|s| s.as_str()).unwrap_or("/tmp");
    let in_initrd = std::path::Path::new("/etc/initrd-release").exists();

    let has_update = UPDATE_PATHS
        .iter()
        .any(|p| std::path::Path::new(p).exists());

    match generator_run(normal_dir, in_initrd, &[]) {
        Ok(GeneratorResult::NoUpdate) => {
            if has_update {
                eprintln!(
                    "system-update-generator: update marker found but generator returned NoUpdate"
                );
            }
        }
        Ok(GeneratorResult::SymlinkCreated) => {
            let unit_path = std::path::Path::new(normal_dir).join("system-update.target");
            eprintln!("system-update-generator: created {:?}", unit_path);
        }
        Ok(GeneratorResult::SkippedInitrd) => {
            eprintln!("system-update-generator: skipped (running in initrd)");
        }
        Err(e) => {
            eprintln!("system-update-generator: error: {}", e);
            std::process::exit(1);
        }
    }
}
