// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-backlight

use systemd_backlight_rs::{
    BacklightVerb, DeviceSpec, VALID_SUBSYSTEMS, backlight_verb_from_string,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PERSIST_DIR: &str = "/var/lib/systemd/backlight";

fn print_help() {
    println!("systemd-backlight [OPTIONS...] {{save|load}} DEVICE");
    println!("Save and restore backlight/LED brightness.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
    println!("DEVICE format: subsystem:sysname (e.g. backlight:intel_backlight)");
    println!("Valid subsystems: {}", VALID_SUBSYSTEMS.join(", "));
}

fn brightness_sysfs_path(subsystem: &str, sysname: &str) -> String {
    format!("/sys/class/{}/{}", subsystem, sysname)
}

fn persist_path(subsystem: &str, sysname: &str) -> String {
    format!("{}/{}:{}", PERSIST_DIR, subsystem, sysname)
}

fn read_brightness(subsystem: &str, sysname: &str) -> Option<String> {
    let path = format!("{}/brightness", brightness_sysfs_path(subsystem, sysname));
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn write_brightness(subsystem: &str, sysname: &str, value: &str) -> std::io::Result<()> {
    let path = format!("{}/brightness", brightness_sysfs_path(subsystem, sysname));
    std::fs::write(&path, value)
}

fn save_brightness(subsystem: &str, sysname: &str) -> std::io::Result<()> {
    let brightness = read_brightness(subsystem, sysname).ok_or(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "cannot read brightness",
    ))?;

    let _ = std::fs::create_dir_all(PERSIST_DIR);
    std::fs::write(persist_path(subsystem, sysname), &brightness)
}

fn load_brightness(subsystem: &str, sysname: &str) -> std::io::Result<()> {
    let ppath = persist_path(subsystem, sysname);
    let brightness = std::fs::read_to_string(&ppath).map(|s| s.trim().to_string())?;

    write_brightness(subsystem, sysname, &brightness)
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
                println!("systemd-backlight {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    if refs.len() < 2 {
        eprintln!("Usage: systemd-backlight save|load DEVICE. Try --help.");
        std::process::exit(1);
    }

    let verb = match backlight_verb_from_string(refs[0]) {
        Some(v) => v,
        None => {
            eprintln!("Unknown verb '{}'. Use 'save' or 'load'.", refs[0]);
            std::process::exit(1);
        }
    };

    let spec = match DeviceSpec::parse(refs[1]) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "Invalid device specifier '{}'. Use subsystem:sysname.",
                refs[1]
            );
            std::process::exit(1);
        }
    };

    match verb {
        BacklightVerb::Save => match save_brightness(&spec.subsystem, &spec.sysname) {
            Ok(()) => eprintln!(
                "backlight: saved {}:{} brightness",
                spec.subsystem, spec.sysname
            ),
            Err(e) => eprintln!(
                "backlight: save failed for {}:{}: {}",
                spec.subsystem, spec.sysname, e
            ),
        },
        BacklightVerb::Load => match load_brightness(&spec.subsystem, &spec.sysname) {
            Ok(()) => eprintln!(
                "backlight: loaded {}:{} brightness",
                spec.subsystem, spec.sysname
            ),
            Err(e) => eprintln!(
                "backlight: load failed for {}:{}: {}",
                spec.subsystem, spec.sysname, e
            ),
        },
    }
}
