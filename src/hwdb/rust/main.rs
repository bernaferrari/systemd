// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-hwdb

use systemd_hwdb_rs::{parse_cli, Command};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const HWDB_BIN_PATHS: &[&str] = &[
    "/etc/udev/hwdb.bin",
    "/usr/lib/udev/hwdb.bin",
    "/lib/udev/hwdb.bin",
];
const HWDB_SOURCE_DIRS: &[&str] = &[
    "/etc/udev/hwdb.d",
    "/usr/lib/udev/hwdb.d",
    "/lib/udev/hwdb.d",
];

fn print_help() {
    println!("systemd-hwdb [OPTIONS...] [COMMAND]");
    println!("Hardware database tool.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
    println!("     --usr               Use /usr/lib/udev for binary output");
    println!("  -s --strict            Strict mode");
    println!("  -r --root=PATH         Alternate root path");
    println!("Commands: update (default), query MODALIAS");
}

fn parse_hwdb_files() -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for dir in HWDB_SOURCE_DIRS {
        let dir_entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut files: Vec<_> = dir_entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "hwdb")
                    .unwrap_or(false)
            })
            .collect();
        files.sort_by_key(|e| e.file_name());
        for entry in files {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                entries.push((entry.path().display().to_string(), content));
            }
        }
    }
    entries
}

fn query_hwdb(modalias: &str) -> Option<String> {
    for bin_path in HWDB_BIN_PATHS {
        let content = std::fs::read_to_string(bin_path).ok()?;
        for line in content.lines() {
            if line.starts_with(modalias) {
                return Some(line.to_string());
            }
        }
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    if refs.contains(&"--help") || refs.contains(&"-h") {
        print_help();
        return;
    }
    if refs.contains(&"--version") {
        println!("systemd-hwdb {}", VERSION);
        return;
    }

    let cmd = match parse_cli(&refs) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    match cmd {
        Command::Update(_) => {
            let files = parse_hwdb_files();
            if files.is_empty() {
                eprintln!("hwdb: no .hwdb source files found");
                return;
            }

            let mut combined = String::new();
            for (path, content) in &files {
                combined.push_str(&format!("# Source: {}\n", path));
                combined.push_str(content);
                combined.push('\n');
            }

            let bin_path = HWDB_BIN_PATHS[0];
            if let Some(parent) = std::path::Path::new(bin_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(bin_path, &combined) {
                Ok(()) => eprintln!("hwdb: updated {} ({} source files)", bin_path, files.len()),
                Err(e) => {
                    eprintln!("hwdb: failed to write {}: {}", bin_path, e);
                    std::process::exit(1);
                }
            }
        }
        Command::Query { modalias, .. } => match query_hwdb(&modalias) {
            Some(result) => println!("{}", result),
            None => {
                eprintln!("hwdb: no match for {}", modalias);
                std::process::exit(1);
            }
        },
    }
}
