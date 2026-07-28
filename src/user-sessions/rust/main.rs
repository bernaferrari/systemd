// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-user-sessions

use systemd_user_sessions_rs::{NOLOGIN_MESSAGE, NOLOGIN_PATH, UserSessionsArgs, nologin_action};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-user-sessions [OPTIONS...] {{start|stop}}");
    println!("Manage user session login policy.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
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
                println!("systemd-user-sessions {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let parsed = match UserSessionsArgs::parse(&refs) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Usage: systemd-user-sessions start|stop. Try --help.");
            std::process::exit(1);
        }
    };

    let action = nologin_action(parsed.verb);
    match action {
        systemd_user_sessions_rs::NologinAction::Remove => {
            match std::fs::remove_file(NOLOGIN_PATH) {
                Ok(()) => eprintln!("user-sessions: removed {} — logins enabled", NOLOGIN_PATH),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!(
                        "user-sessions: {} not present, logins already enabled",
                        NOLOGIN_PATH
                    );
                }
                Err(e) => eprintln!("user-sessions: failed to remove {}: {}", NOLOGIN_PATH, e),
            }
        }
        systemd_user_sessions_rs::NologinAction::Create => {
            if let Some(parent) = std::path::Path::new(NOLOGIN_PATH).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(NOLOGIN_PATH, NOLOGIN_MESSAGE) {
                Ok(()) => eprintln!("user-sessions: created {} — logins disabled", NOLOGIN_PATH),
                Err(e) => eprintln!("user-sessions: failed to create {}: {}", NOLOGIN_PATH, e),
            }
        }
    }
}
