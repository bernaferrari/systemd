// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-vconsole-setup

use systemd_vconsole_setup_rs::{effective_keymap, font_loading_needed, VconsoleContext};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const VC_KEYMAP_PATH: &str = "/etc/vconsole.keymap";
const VC_FONT_PATH: &str = "/etc/vconsole.font";
const KBD_LOADKEYS: &str = "/usr/bin/loadkeys";
const KBD_SETFONT: &str = "/usr/bin/setfont";

fn print_help() {
    println!("systemd-vconsole-setup [OPTIONS...]");
    println!("Configure virtual console keyboard and font.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
}

#[cfg(target_os = "linux")]
fn load_keymap(keymap: &str) -> Result<(), String> {
    let status = std::process::Command::new(KBD_LOADKEYS)
        .arg("-q")
        .arg(keymap)
        .status()
        .map_err(|e| format!("loadkeys exec failed: {}", e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("loadkeys {} failed", keymap))
    }
}

#[cfg(target_os = "linux")]
fn set_font(font: &str) -> Result<(), String> {
    let status = std::process::Command::new(KBD_SETFONT)
        .arg(font)
        .status()
        .map_err(|e| format!("setfont exec failed: {}", e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("setfont {} failed", font))
    }
}

#[cfg(not(target_os = "linux"))]
fn load_keymap(_keymap: &str) -> Result<(), String> {
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn set_font(_font: &str) -> Result<(), String> {
    Ok(())
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
                println!("systemd-vconsole-setup {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let ctx = VconsoleContext::new();
    let keymap = effective_keymap(ctx.keymap.as_deref());

    if let Some(ref km) = keymap {
        match load_keymap(km) {
            Ok(()) => eprintln!("vconsole: loaded keymap {}", km),
            Err(e) => eprintln!("vconsole: {}", e),
        }
    }

    if font_loading_needed(&ctx) {
        if let Some(ref font) = ctx.font {
            if !font.is_empty() {
                match set_font(font) {
                    Ok(()) => eprintln!("vconsole: set font {}", font),
                    Err(e) => eprintln!("vconsole: {}", e),
                }
            }
        }
    }
}
