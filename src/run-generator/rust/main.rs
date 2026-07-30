// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-run-generator

use systemd_run_generator_rs::{
    GeneratorParams, SERVICE_NAME, TARGET_NAME, generate_service_unit, generate_target_unit,
    has_work, parse_cmdline_item,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    eprintln!("Usage: systemd-run-generator [normal-dir early-dir late-dir]");
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
                eprintln!("systemd-run-generator {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let output_dir = if args.len() >= 2 {
        std::path::PathBuf::from(&args[1])
    } else {
        eprintln!("run-generator: expected directory argument");
        return;
    };

    let mut params = GeneratorParams::default();

    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        for token in cmdline.split_whitespace() {
            if let Some(rest) = token.strip_prefix("systemd.")
                && let Some((key, value)) = rest.split_once('=')
            {
                parse_cmdline_item(&format!("systemd.{}", key), Some(value), &mut params);
            }
        }
    }

    if !has_work(&params) {
        eprintln!("run-generator: nothing to generate");
        return;
    }

    if let Some(parent) = output_dir.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let service_content = generate_service_unit(&params).unwrap_or_else(|_| {
        "[Unit]\nDescription=Kernel Command\n\n[Service]\nType=oneshot\n".to_string()
    });
    let service_path = output_dir.join(SERVICE_NAME);
    if let Err(e) = std::fs::write(&service_path, &service_content) {
        eprintln!("run-generator: failed to write {}: {}", SERVICE_NAME, e);
        return;
    }
    eprintln!("run-generator: wrote {}", SERVICE_NAME);

    let target_content = generate_target_unit();
    let target_path = output_dir.join(TARGET_NAME);
    if let Err(e) = std::fs::write(&target_path, &target_content) {
        eprintln!("run-generator: failed to write {}: {}", TARGET_NAME, e);
    }
    eprintln!("run-generator: wrote {}", TARGET_NAME);

    let default_link = output_dir.join("default.target");
    let _ = std::fs::remove_file(&default_link);
    if let Err(e) = std::os::unix::fs::symlink(TARGET_NAME, &default_link) {
        eprintln!(
            "run-generator: failed to create default.target symlink: {}",
            e
        );
    }
    eprintln!("run-generator: default.target → {}", TARGET_NAME);
}
