// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/network/networkd.c
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-networkd.
//
// The library contains independently useful parsing and state-inspection helpers,
// but it does not yet implement the network manager lifecycle. In particular, it
// must not substitute a sysfs poller and an invented state file for networkd.

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EXECUTION_UNAVAILABLE: &str = concat!(
    "systemd-networkd: the Rust network manager lifecycle is unavailable; ",
    "refusing to run an incomplete network configuration daemon",
);

#[derive(Debug, PartialEq, Eq)]
enum InformationalRequest {
    Help,
    Version,
}

fn print_help() {
    println!("systemd-networkd [--help|--version]");
    println!();
    println!("The Rust systemd-networkd executable is unavailable until it implements");
    println!("the complete manager lifecycle and network configuration contract.");
}

fn print_version() {
    println!("systemd-networkd {}", VERSION);
}

fn parse_informational_request(arguments: &[String]) -> Option<InformationalRequest> {
    match arguments {
        [argument] if argument == "-h" || argument == "--help" => Some(InformationalRequest::Help),
        [argument] if argument == "--version" => Some(InformationalRequest::Version),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_standalone_informational_options_are_supported() {
        assert_eq!(
            parse_informational_request(&["--help".into()]),
            Some(InformationalRequest::Help)
        );
        assert_eq!(
            parse_informational_request(&["-h".into()]),
            Some(InformationalRequest::Help)
        );
        assert_eq!(
            parse_informational_request(&["--version".into()]),
            Some(InformationalRequest::Version)
        );
        assert_eq!(parse_informational_request(&[]), None);
        assert_eq!(parse_informational_request(&["--reload".into()]), None);
        assert_eq!(
            parse_informational_request(&["--help".into(), "--reload".into()]),
            None
        );
    }
}
