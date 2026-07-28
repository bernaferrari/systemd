// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-getty-generator

use systemd_getty_generator_rs::getty_generator::{GettyKind, build_unit_name, valid_tty_name};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROC_CMDLINE_PATH: &str = "/proc/cmdline";
const DEFAULT_SERIAL_TTYS: &[&str] = &["ttyS0", "ttyS1", "ttyAMA0", "ttyUSB0"];

fn print_help() {
    eprintln!("Usage: systemd-getty-generator [normal-dir early-dir late-dir]");
    eprintln!();
    eprintln!("  -h --help             Show this help");
    eprintln!("     --version          Show package version");
}

fn parse_console_tty(console_value: &str) -> Option<String> {
    let tty = console_value.split(',').next()?;
    let tty = tty.trim();
    if tty.is_empty() {
        return None;
    }
    let tty = tty.strip_prefix("/dev/").unwrap_or(tty);
    if valid_tty_name(tty) {
        Some(tty.to_string())
    } else {
        None
    }
}

fn parse_proc_cmdline() -> (Option<String>, Vec<String>) {
    let content = match std::fs::read_to_string(PROC_CMDLINE_PATH) {
        Ok(c) => c,
        Err(_) => return (None, Vec::new()),
    };

    let mut console_tty: Option<String> = None;
    let mut extra_ttys: Vec<String> = Vec::new();

    for token in content.split_whitespace() {
        if let Some(value) = token.strip_prefix("console=") {
            console_tty = parse_console_tty(value);
        }
        if let Some(value) = token.strip_prefix("systemd.getty=") {
            let tty = value.strip_prefix("/dev/").unwrap_or(value);
            if valid_tty_name(tty) {
                extra_ttys.push(tty.to_string());
            }
        }
    }

    (console_tty, extra_ttys)
}

fn write_getty_unit(
    output_dir: &std::path::Path,
    kind: GettyKind,
    tty: &str,
) -> std::io::Result<()> {
    let unit_name = build_unit_name(kind, tty)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid tty name"))?;

    let link_path = output_dir.join(&unit_name);
    let target = match kind {
        GettyKind::Serial => "/usr/lib/systemd/system/serial-getty@.service",
        GettyKind::Container => "/usr/lib/systemd/system/container-getty@.service",
    };

    if let Some(parent) = link_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let _ = std::fs::remove_file(&link_path);
    std::os::unix::fs::symlink(target, &link_path)?;

    eprintln!("getty-generator: created {}", unit_name);
    Ok(())
}

fn determine_ttys() -> Vec<(GettyKind, String)> {
    let (console_tty, extra_ttys) = parse_proc_cmdline();
    let mut result = Vec::new();

    if let Some(ref tty) = console_tty {
        let is_serial = tty.starts_with("ttyS")
            || tty.starts_with("ttyAMA")
            || tty.starts_with("ttyUSB")
            || tty.starts_with("ttyMFD");
        let kind = if is_serial {
            GettyKind::Serial
        } else {
            GettyKind::Container
        };
        result.push((kind, tty.clone()));
    }

    let extra_ttys_empty = extra_ttys.is_empty();

    for tty in extra_ttys {
        let is_serial =
            tty.starts_with("ttyS") || tty.starts_with("ttyAMA") || tty.starts_with("ttyUSB");
        let kind = if is_serial {
            GettyKind::Serial
        } else {
            GettyKind::Container
        };
        result.push((kind, tty));
    }

    if console_tty.is_none() && extra_ttys_empty {
        for tty in DEFAULT_SERIAL_TTYS {
            if std::path::Path::new(&format!("/dev/{}", tty)).exists() {
                result.push((GettyKind::Serial, tty.to_string()));
            }
        }
    }

    result
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
                eprintln!("systemd-getty-generator {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let output_dir = if args.len() >= 2 {
        std::path::PathBuf::from(&args[1])
    } else {
        eprintln!("getty-generator: expected directory argument, running in dry-run mode");
        for (kind, tty) in determine_ttys() {
            if let Ok(name) = build_unit_name(kind, &tty) {
                eprintln!("getty-generator: would create {}", name);
            }
        }
        return;
    };

    let ttys = determine_ttys();
    if ttys.is_empty() {
        eprintln!("getty-generator: no getty units to generate");
        return;
    }

    let mut count = 0usize;
    for (kind, tty) in &ttys {
        match write_getty_unit(&output_dir, *kind, tty) {
            Ok(()) => count += 1,
            Err(e) => eprintln!("getty-generator: failed for {}: {}", tty, e),
        }
    }
    eprintln!("getty-generator: generated {} getty units", count);
}
