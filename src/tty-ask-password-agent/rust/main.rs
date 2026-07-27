// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-tty-ask-password-agent

use systemd_tty_ask_password_agent_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-tty-ask-password-agent [OPTIONS...]");
    println!();
    println!("TTY password request processing agent.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --list           List pending password requests");
    println!("     --query          Process a single query (default)");
    println!("     --watch          Continuously watch for requests");
    println!("     --wall           Forward requests via wall");
    println!("     --plymouth       Use Plymouth");
    println!("     --console[=DEV]  Use console device");
}

fn print_version() {
    println!("systemd-tty-ask-password-agent {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut action = lib::PasswordAction::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            "--list" => action = lib::PasswordAction::List,
            "--query" => action = lib::PasswordAction::Query,
            "--watch" => action = lib::PasswordAction::Watch,
            "--wall" => action = lib::PasswordAction::Wall,
            _ => {}
        }
        i += 1;
    }

    eprintln!(
        "{}: action={:?}, dir={}",
        env!("CARGO_PKG_NAME"),
        action,
        lib::ASK_PASSWORD_DIR
    );
}
