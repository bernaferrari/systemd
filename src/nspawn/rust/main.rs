// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-nspawn

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EXECUTION_UNAVAILABLE: &str = concat!(
    "systemd-nspawn: native container execution is unavailable in the Rust port; ",
    "refusing to run an incomplete isolation boundary",
);

#[derive(Debug, PartialEq, Eq)]
enum InformationalRequest {
    Help,
    Version,
}

fn print_help() {
    println!("systemd-nspawn [--help|--version]");
    println!();
    println!("The Rust systemd-nspawn executable is unavailable until it implements");
    println!("the complete container isolation and lifecycle contract.");
}

fn print_version() {
    println!("systemd-nspawn {}", VERSION);
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
        assert_eq!(
            parse_informational_request(&["--help".into(), "--boot".into()]),
            None
        );
    }
}
