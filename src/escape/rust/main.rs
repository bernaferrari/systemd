// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-escape

use systemd_escape_rs::escape::{Action, Config, apply, validate};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = Config::default();
    let mut positional = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--unescape" => cfg.action = Action::Unescape,
            "-m" | "--mangle" => cfg.action = Action::Mangle,
            "-p" | "--path" => cfg.path = true,
            "--instance" => cfg.instance = true,
            s if s.starts_with("--suffix=") => {
                cfg.suffix = Some(s[9..].to_string());
            }
            s if s.starts_with("--template=") => {
                cfg.template = Some(s[11..].to_string());
            }
            s if !s.starts_with('-') => positional.push(s.to_string()),
            _ => {}
        }
        i += 1;
    }

    if let Err(e) = validate(&cfg) {
        eprintln!("systemd-escape: invalid options: errno {}", e.0);
        std::process::exit(1);
    }

    for name in &positional {
        match apply(&cfg, name) {
            Ok(result) => println!("{}", result),
            Err(e) => {
                eprintln!("systemd-escape: error: errno {}", e.0);
                std::process::exit(1);
            }
        }
    }
}
