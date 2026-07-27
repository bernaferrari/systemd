// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-socket-activate

use systemd_socket_activate_rs as lib;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-socket-activate [OPTIONS...] COMMAND [ARGS...]");
    println!();
    println!("Socket activation helper.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("  -l --listen=ADDR    Listen on address");
    println!("  -a --accept         Accept per-connection");
    println!("     --datagram       Use datagram socket");
    println!("     --seqpacket      Use seqpacket socket");
    println!("     --inetd          Inetd mode");
    println!("     --setenv=VAR     Set env for children");
    println!("     --fdname=NAME    File descriptor name");
    println!("     --now            Start immediately");
}

fn print_version() {
    println!("systemd-socket-activate {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut config = lib::ActivateConfig::default();
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
            "--datagram" => config.socket_type = lib::SocketType::Datagram,
            "--seqpacket" => config.socket_type = lib::SocketType::Seqpacket,
            "--accept" | "-a" => config.accept = true,
            "--inetd" => config.inetd = true,
            "--now" => config.now = true,
            s if s.starts_with("-l") || s.starts_with("--listen") => {
                let addr = s.split_once('=').map(|(_, v)| v).unwrap_or("");
                if !addr.is_empty() {
                    config.listen.push(addr.to_string());
                }
            }
            s if s.starts_with("--fdname") => {
                let name = s.split_once('=').map(|(_, v)| v).unwrap_or("");
                if lib::fdname_is_valid(name) {
                    config.fdnames.push(name.to_string());
                }
            }
            s if s.starts_with("--setenv") => {
                if let Some((_, v)) = s.split_once('=') {
                    config.setenv.push(v.to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }

    if let Err(e) = lib::validate_config(&config) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    eprintln!(
        "{}: {} listen addr, accept={}, socket={:?}",
        env!("CARGO_PKG_NAME"),
        config.listen.len(),
        config.accept,
        config.socket_type
    );
}
