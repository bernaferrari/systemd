// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-fsck

use systemd_fsck_rs::fsck::{parse_mode, parse_repair, repair_option, Mode, Repair};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const FSCK_PATH: &str = "/sbin/fsck";

fn print_help() {
    println!("systemd-fsck [OPTIONS...] DEVICE");
    println!("File system checker coordination tool.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    for a in &refs {
        match *a {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                println!("systemd-fsck {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let device = match refs.last() {
        Some(d) if !d.starts_with('-') => *d,
        _ => {
            eprintln!("Usage: systemd-fsck DEVICE. Try --help.");
            std::process::exit(1);
        }
    };

    let mode = refs
        .iter()
        .find_map(|a| a.strip_prefix("--mode=").and_then(|v| parse_mode(v).ok()))
        .unwrap_or(Mode::Auto);
    let repair = refs
        .iter()
        .find_map(|a| {
            a.strip_prefix("--repair=")
                .and_then(|v| parse_repair(v).ok())
        })
        .unwrap_or(Repair::Preen);
    let opt = repair_option(repair);

    let mut cmd_args = vec![device.to_string()];
    if !opt.is_empty() {
        cmd_args.push(opt.to_string());
    }

    let status = std::process::Command::new(FSCK_PATH)
        .args(&cmd_args)
        .status();

    match status {
        Ok(s) => {
            let code = s.code().unwrap_or(1);
            if code == 0 {
                eprintln!("fsck: {} clean", device);
            } else if code == 1 {
                eprintln!("fsck: {} errors corrected", device);
            } else {
                eprintln!("fsck: {} exited with status {}", device, code);
            }
            let _ = mode;
        }
        Err(e) => {
            eprintln!("fsck: failed to execute: {}", e);
        }
    }
}
