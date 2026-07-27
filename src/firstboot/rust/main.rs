// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-firstboot

use systemd_firstboot_rs::firstboot as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-firstboot [OPTIONS...] [--root=PATH]");
    println!();
    println!("Initialize system settings on first boot.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --root=PATH      Operate on root directory");
    println!("     --locale=LOCALE  Set locale");
    println!("     --keymap=KEYMAP  Set keymap");
    println!("     --timezone=TZ    Set timezone");
    println!("     --hostname=NAME  Set hostname");
    println!("     --setup-machine-id Generate machine-id");
    println!("     --password=ROOTPW Set root password");
    println!("     --reset           Reset all firstboot settings");
    println!("     --force           Overwrite existing settings");
    println!("     --welcome         Show welcome message");
}

fn print_version() {
    println!("systemd-firstboot {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut config = lib::Config::default();
    for arg in &args[1..] {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            "--force" => config.force = true,
            "--reset" => config.reset = true,
            "--welcome" => config.welcome = true,
            "--prompt-locale" => config.prompt_locale = true,
            "--prompt-keymap" => config.prompt_keymap = true,
            "--prompt-timezone" => config.prompt_timezone = true,
            "--prompt-hostname" => config.prompt_hostname = true,
            "--prompt-root-password" => config.prompt_root_password = true,
            "--delete-root-password" => config.delete_root_password = true,
            s if s.starts_with("--locale=") => {
                config.locale = s.split_once('=').map(|(_, v)| v.to_string());
            }
            s if s.starts_with("--keymap=") => {
                config.keymap = s.split_once('=').map(|(_, v)| v.to_string());
            }
            s if s.starts_with("--timezone=") => {
                config.timezone = s.split_once('=').map(|(_, v)| v.to_string());
            }
            s if s.starts_with("--hostname=") => {
                let name = s.split_once('=').map(|(_, v)| v).unwrap_or("");
                if let Err(e) = lib::validate_hostname(name) {
                    eprintln!("Invalid hostname: errno {}", e);
                    std::process::exit(1);
                }
                config.hostname = Some(name.to_string());
            }
            _ => {}
        }
    }

    println!("{:?}", config);
}
