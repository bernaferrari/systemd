// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-debug-generator

use systemd_debug_generator_rs::debug_generator::{
    Breakpoint, Config, bit, parse_cmdline_item, unit,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROC_CMDLINE_PATH: &str = "/proc/cmdline";
const DEBUG_SHELL_SERVICE: &str = "debug-shell.service";

fn print_help() {
    eprintln!("Usage: systemd-debug-generator [OPTIONS...] [normal-dir early-dir late-dir]");
    eprintln!();
    eprintln!("  -h --help             Show this help");
    eprintln!("     --version          Show package version");
}

fn parse_proc_cmdline(config: &mut Config) {
    let content = match std::fs::read_to_string(PROC_CMDLINE_PATH) {
        Ok(c) => c,
        Err(_) => return,
    };

    for token in content.split_whitespace() {
        if let Some(rest) = token.strip_prefix("systemd.") {
            if let Some((key, value)) = rest.split_once('=') {
                let full_key = format!("systemd.{}", key);
                parse_cmdline_item(config, &full_key, Some(value), false);
            } else {
                let full_key = format!("systemd.{}", rest);
                parse_cmdline_item(config, &full_key, None, false);
            }
        }
    }
}

fn write_symlink(
    output_dir: &std::path::Path,
    link_name: &str,
    target: &str,
) -> std::io::Result<()> {
    let link_path = output_dir.join(link_name);
    if let Some(parent) = link_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&link_path);
    std::os::unix::fs::symlink(target, &link_path)?;
    Ok(())
}

fn write_dev_null_symlink(output_dir: &std::path::Path, unit_name: &str) -> std::io::Result<()> {
    write_symlink(output_dir, unit_name, "/dev/null")
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
                eprintln!("systemd-debug-generator {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let output_dir = if args.len() >= 2 {
        std::path::PathBuf::from(&args[1])
    } else {
        eprintln!("debug-generator: expected directory argument");
        return;
    };

    let mut config = Config::default();
    parse_proc_cmdline(&mut config);

    if config.debug_shell {
        let tty = config
            .debug_tty
            .as_deref()
            .or(config.default_debug_tty.as_deref())
            .unwrap_or("tty9");

        let content = format!(
            "[Unit]\n\
             Description=Early debug shell on /dev/{tty}\n\
             DefaultDependencies=no\n\
             IgnoreOnIsolate=yes\n\
             ConditionPathExists=/dev/{tty}\n\n\
             [Service]\n\
             ExecStart=/sbin/agetty --noclear -l /bin/bash {tty} 115200\n\
             Type=simple\n\
             Restart=no\n\
             StandardInput=tty\n\
             StandardOutput=tty\n\
             TTYPath=/dev/{tty}\n\
             TTYReset=yes\n\
             TTYVHangup=yes\n"
        );

        if let Some(parent) = output_dir.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let service_path = output_dir.join(DEBUG_SHELL_SERVICE);
        let _ = std::fs::write(&service_path, &content);
        eprintln!("debug-generator: created {}", DEBUG_SHELL_SERVICE);
    }

    if let Some(ref default_unit) = config.default_unit {
        let _ = write_symlink(&output_dir, "default.target", default_unit);
        eprintln!("debug-generator: set default.target → {}", default_unit);
    }

    for unit_name in &config.mask {
        let _ = write_dev_null_symlink(&output_dir, unit_name);
        eprintln!("debug-generator: masked {}", unit_name);
    }

    for unit_name in &config.wants {
        let wants_dir = output_dir.join("default.target.wants");
        let _ = write_symlink(
            &wants_dir,
            unit_name,
            &format!("/usr/lib/systemd/system/{}", unit_name),
        );
        eprintln!(
            "debug-generator: added {} to default.target.wants",
            unit_name
        );
    }

    for bp in &[
        Breakpoint::PreUdev,
        Breakpoint::PreBasic,
        Breakpoint::PreSysrootMount,
        Breakpoint::PreSwitchRoot,
    ] {
        if config.breakpoints & bit(*bp) != 0 {
            let bp_unit = unit(*bp);
            let content = format!(
                "[Unit]\n\
                 Description=Breakpoint: {}\n\
                 DefaultDependencies=no\n\
                 StopWhenUnneeded=yes\n\n\
                 [Service]\n\
                 Type=oneshot\n\
                 ExecStart=/bin/sh -c 'echo \"Breakpoint: {} reached. Press Enter to continue.\"; read'\n",
                bp_unit, bp_unit
            );
            if let Some(parent) = output_dir.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let bp_path = output_dir.join(bp_unit);
            let _ = std::fs::write(&bp_path, &content);
            eprintln!("debug-generator: created breakpoint {}", bp_unit);
        }
    }

    eprintln!("debug-generator: done");
}
