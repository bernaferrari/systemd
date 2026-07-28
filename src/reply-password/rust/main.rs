// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-reply-password

use systemd_reply_password_rs::{ReplyPacket, parse_invocation};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-reply-password MODE SOCKET_PATH");
    println!("Send a password reply via AF_UNIX datagram socket.");
    println!("  MODE: 1 = send password, 0 = cancel");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
}

#[cfg(target_os = "linux")]
fn send_reply(socket_path: &str, payload: &[u8]) -> std::io::Result<()> {
    use std::os::unix::net::UnixDatagram;
    let sock = UnixDatagram::unbound()?;
    sock.send_to(payload, socket_path)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn send_reply(socket_path: &str, payload: &[u8]) -> std::io::Result<()> {
    use std::os::unix::net::UnixDatagram;
    let sock = UnixDatagram::unbound()?;
    let _ = (socket_path, payload);
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
                println!("systemd-reply-password {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let line = std::io::stdin().lines().next().and_then(|r| r.ok());
    let prepared = match parse_invocation(&refs, line.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let payload: Vec<u8> = match &prepared.packet {
        ReplyPacket::Password(pw) => {
            let mut buf = Vec::new();
            buf.extend_from_slice(b"+");
            buf.extend_from_slice(pw.as_bytes());
            buf.extend_from_slice(b"\n");
            buf
        }
        ReplyPacket::Cancel => b"-\n".to_vec(),
    };

    match send_reply(&prepared.socket_path, &payload) {
        Ok(()) => match &prepared.packet {
            ReplyPacket::Password(_) => {
                eprintln!("reply-password: sent password to {}", prepared.socket_path)
            }
            ReplyPacket::Cancel => {
                eprintln!("reply-password: sent cancel to {}", prepared.socket_path)
            }
        },
        Err(e) => {
            eprintln!(
                "reply-password: send to {} failed: {}",
                prepared.socket_path, e
            );
            std::process::exit(1);
        }
    }
}
