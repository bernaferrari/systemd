// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-quotacheck

use systemd_quotacheck_rs::quotacheck::{
    build_quotacheck_args, quota_check_mode_from_string, quota_check_mode_to_string,
    should_run_quotacheck, QuotaCheckMode,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const QUOTACHECK_PATH: &str = "/sbin/quotacheck";

fn print_help() {
    println!("systemd-quotacheck [OPTIONS...]");
    println!("Run quotacheck on filesystems.");
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
                println!("systemd-quotacheck {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let mode = refs
        .iter()
        .find_map(|a| {
            a.strip_prefix("--mode=")
                .and_then(|v| quota_check_mode_from_string(v).ok())
        })
        .unwrap_or(QuotaCheckMode::Auto);

    if !should_run_quotacheck(mode, false) {
        eprintln!(
            "quotacheck: skipped (mode: {})",
            quota_check_mode_to_string(mode)
        );
        return;
    }

    let cmd_args = build_quotacheck_args(None);
    if cmd_args.is_empty() {
        eprintln!("quotacheck: no filesystems to check");
        return;
    }

    let status = std::process::Command::new(QUOTACHECK_PATH)
        .args(&cmd_args[1..])
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!("quotacheck: completed successfully");
        }
        Ok(s) => {
            eprintln!("quotacheck: exited with status {:?}", s.code());
        }
        Err(e) => {
            eprintln!("quotacheck: failed to execute: {}", e);
        }
    }
}
