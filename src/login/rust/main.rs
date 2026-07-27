// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Fail-closed entry point for systemd-logind.
//
// PORT-SYNC: src/login/logind.c

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EXECUTION_UNAVAILABLE: &str = concat!(
    "systemd-logind: daemon execution is unavailable in the Rust port; ",
    "refusing to claim readiness without the canonical D-Bus, Varlink, session, and device lifecycle"
);

#[derive(Debug, PartialEq, Eq)]
enum InformationalRequest {
    Help,
    Version,
}

fn parse_informational_request(arguments: &[String]) -> Option<InformationalRequest> {
    match arguments {
        [argument] if argument == "-h" || argument == "--help" => Some(InformationalRequest::Help),
        [argument] if argument == "--version" => Some(InformationalRequest::Version),
        _ => None,
    }
}

fn print_help() {
    println!("systemd-logind [--help|--version]");
    println!();
    println!("The Rust systemd-logind executable is unavailable until it implements");
    println!("the complete canonical D-Bus, Varlink, session, and device lifecycle.");
}

fn print_version() {
    println!("systemd-logind {}", VERSION);
}

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();

    match parse_informational_request(&arguments) {
        Some(InformationalRequest::Help) => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(InformationalRequest::Version) => {
            print_version();
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("{EXECUTION_UNAVAILABLE}");
            ExitCode::FAILURE
        }
    }
}
