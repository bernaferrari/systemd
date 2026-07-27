// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for 30-systemd-environment-d-generator

use systemd_environment_d_generator_rs::environment_d_generator::{
    format_env_output, parse_args, parse_env_line, ENVIRONMENT_D_PATHS,
};

fn print_help() {
    eprintln!("Usage: 30-systemd-environment-d-generator [ARGS...]");
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
                    "30-systemd-environment-d-generator {}",
                    env!("CARGO_PKG_VERSION")
                );
                return;
            }
            _ => {}
        }
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if let Err(e) = parse_args(&arg_refs) {
        eprintln!("environment-d-generator: error ({})", e);
        std::process::exit(1);
    }

    let mut assignments = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();

    for dir in ENVIRONMENT_D_PATHS {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut conf_files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "conf")
                    .unwrap_or(false)
            })
            .collect();
        conf_files.sort_by_key(|e| e.file_name());

        for entry in conf_files {
            let content = match std::fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for line in content.lines() {
                if let Some(assign) = parse_env_line(line) {
                    seen_keys.insert(assign.key.clone());
                    assignments.push(assign);
                }
            }
        }
    }

    let mut deduped: Vec<_> = assignments
        .iter()
        .rev()
        .filter(|a| seen_keys.remove(&a.key) || seen_keys.contains(&a.key))
        .collect();
    deduped.reverse();

    let deduped: Vec<_> = deduped.into_iter().cloned().collect();
    let output = format_env_output(&deduped);
    print!("{}", output);
}
