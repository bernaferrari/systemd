// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-notify

use systemd_notify_rs::{determine_action, parse_notify_message, NotifyAction};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let action = match determine_action(&arg_refs) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("systemd-notify: error: {}", e);
            std::process::exit(1);
        }
    };

    match action {
        NotifyAction::Booted => {
            // Check if /run/systemd/system exists
            let booted = std::path::Path::new("/run/systemd/system").exists();
            if booted {
                println!("yes");
            } else {
                println!("no");
            }
            std::process::exit(if booted { 0 } else { 1 });
        }
        NotifyAction::Notify | NotifyAction::Fork => {
            let socket = match std::env::var("NOTIFY_SOCKET") {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("systemd-notify: NOTIFY_SOCKET not set");
                    std::process::exit(1);
                }
            };

            let msg = args
                .iter()
                .filter(|a| !a.starts_with('-'))
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            if !msg.is_empty() {
                let parsed = parse_notify_message(&msg).unwrap_or_default();
                println!(
                    "Sending to {} ({} fields)",
                    socket,
                    if parsed.is_empty() { "no" } else { "some" }
                );
                println!("{}", msg);
            }
        }
    }
}
