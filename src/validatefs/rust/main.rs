// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-validatefs

use systemd_validatefs_rs::mount_point_is_valid;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-validatefs [OPTIONS...] PATH");
    println!();
    println!("  -h --help             Show this help");
    println!("     --version          Show package version");
    println!("     --root=PATH        Root directory for path resolution");
}

fn print_version() {
    println!("systemd-validatefs {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut root: Option<String> = None;
    let mut positional = Vec::new();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            s if s.starts_with("--root=") => root = Some(s[7..].to_string()),
            "--root" => {
                i += 1;
                if i < args.len() {
                    root = Some(args[i].clone());
                }
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    if positional.is_empty() {
        eprintln!("validatefs: no path specified. Try --help.");
        std::process::exit(1);
    }

    for target in &positional {
        let resolved = match &root {
            Some(r) => format!("{}{}", r.trim_end_matches('/'), target),
            None => target.clone(),
        };

        if !mount_point_is_valid(&resolved) {
            eprintln!("validatefs: {} is not a valid mount point", resolved);
            std::process::exit(1);
        }

        let path = std::path::Path::new(&resolved);
        if !path.exists() {
            eprintln!("validatefs: {} does not exist", resolved);
            std::process::exit(1);
        }

        match std::fs::metadata(&resolved) {
            Ok(meta) => {
                if !meta.is_dir() {
                    eprintln!("validatefs: {} is not a directory", resolved);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("validatefs: cannot stat {}: {}", resolved, e);
                std::process::exit(1);
            }
        }

        eprintln!("validatefs: {} OK", resolved);
    }
}
