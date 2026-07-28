// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-delta

use systemd_delta_rs::delta::{
    Config, SHOW_DEFAULTS, SHOW_EQUIVALENT, SHOW_EXTENDED, SHOW_MASKED, SHOW_OVERRIDDEN,
    SHOW_REDIRECTED, SHOW_UNCHANGED, build_scan_paths, classify, enabled, label,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = Config::default();

    for arg in &args {
        match arg.as_str() {
            "--diff" => cfg.diff = true,
            "--masked" => cfg.flags |= SHOW_MASKED,
            "--equivalent" => cfg.flags |= SHOW_EQUIVALENT,
            "--redirected" => cfg.flags |= SHOW_REDIRECTED,
            "--overridden" => cfg.flags |= SHOW_OVERRIDDEN,
            "--unchanged" => cfg.flags |= SHOW_UNCHANGED,
            "--extended" => cfg.flags |= SHOW_EXTENDED,
            _ => {}
        }
    }
    if cfg.flags == SHOW_DEFAULTS && !args.iter().any(|a| a.starts_with("--show")) {
        cfg.flags = SHOW_DEFAULTS;
    }

    let paths = build_scan_paths();
    println!("Scanning {} prefix/suffix combinations:", paths.len());
    for p in &paths {
        let kind = classify("sample", "sample", false, false, None);
        if enabled(cfg.flags, kind) {
            println!("{} {}", p, label(kind));
        }
    }
}
