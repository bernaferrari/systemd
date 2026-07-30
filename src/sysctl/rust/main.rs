// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-sysctl

use systemd_sysctl_rs::{PROC_SYS_PREFIX, parse_line, test_prefix};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut prefixes: Vec<String> = Vec::new();
    let mut inline_lines: Vec<String> = Vec::new();

    for arg in &args {
        if let Some(prefix) = arg.strip_prefix("--prefix=") {
            prefixes.push(prefix.to_string());
        } else if !arg.starts_with('-') {
            inline_lines.push(arg.clone());
        }
    }

    let prefix_refs: Vec<&str> = prefixes.iter().map(|s| s.as_str()).collect();

    if inline_lines.is_empty() {
        println!(
            "systemd-sysctl: no settings provided (prefixes: {:?})",
            prefixes
        );
        return;
    }

    for line in &inline_lines {
        match parse_line(line) {
            Ok(opt) => {
                if !test_prefix(&opt.key, &prefix_refs) {
                    continue;
                }
                if let Some(ref value) = opt.value {
                    println!(
                        "{} = {} (would write to {}/{})",
                        opt.key,
                        value,
                        PROC_SYS_PREFIX,
                        opt.key.replace('.', "/")
                    );
                }
            }
            Err(e) => eprintln!("systemd-sysctl: {}", e),
        }
    }
}
