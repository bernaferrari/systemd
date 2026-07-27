// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-remount-fs

use systemd_remount_fs_rs::remount_fs::{
    build_remount_args, is_api_mount, mount_option_needs_remount, parse_remount_env,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const FSTAB_PATH: &str = "/etc/fstab";

fn print_help() {
    println!("systemd-remount-fs [OPTIONS...]");
    println!("Remount the root and /usr filesystems.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
}

#[cfg(target_os = "linux")]
fn do_remount(target: &str, options: &str) -> Result<(), String> {
    use systemd_platform_rs::mount::{self, MountFlags};

    let flags = MountFlags::MS_REMOUNT;
    let mut data = options.to_string();
    let fstype = if target == "/" || target == "/usr" {
        ""
    } else {
        "ext4"
    };

    match mount::mount("", target, fstype, flags, &data) {
        Ok(()) => {
            eprintln!("remount-fs: remounted {} with options '{}'", target, data);
            Ok(())
        }
        Err(e) => Err(format!("remount {} failed: {}", target, e)),
    }
}

#[cfg(not(target_os = "linux"))]
fn do_remount(_target: &str, _options: &str) -> Result<(), String> {
    Ok(())
}

fn parse_fstab_options_for(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(FSTAB_PATH).ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        if fields[1] == path {
            let opts = fields[3];
            if opts == "defaults" {
                return None;
            }
            return Some(opts.to_string());
        }
    }
    None
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
                println!("systemd-remount-fs {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let force_rw = std::env::var("SYSTEMD_REMOUNT_RW")
        .ok()
        .and_then(|v| parse_remount_env(&v).ok())
        .unwrap_or(false);

    let targets = ["/", "/usr"];
    let mut ok = 0usize;
    let mut fail = 0usize;

    for target in &targets {
        if !mount_option_needs_remount(target) {
            continue;
        }

        let fstab_opts = parse_fstab_options_for(target);
        let remount_opts = if force_rw {
            "remount,rw".to_string()
        } else if let Some(ref opts) = fstab_opts {
            format!("remount,{}", opts)
        } else {
            "remount".to_string()
        };

        match do_remount(target, &remount_opts) {
            Ok(()) => ok += 1,
            Err(e) => {
                eprintln!("remount-fs: {}", e);
                fail += 1;
            }
        }
    }

    if fail > 0 {
        std::process::exit(1);
    }
    eprintln!("remount-fs: {} filesystems remounted", ok);
}
