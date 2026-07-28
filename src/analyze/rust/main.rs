// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/analyze/analyze-compare-versions.c
#![deny(unsafe_op_in_unsafe_fn)]
//
//! Experimental Rust command-line boundary for one real systemd-analyze verb.

use systemd_analyze_rust_port::{EXIT_FAILURE, compare_versions};

const IMPLEMENTED_VERB: &str = "compare-versions";

fn print_help() {
    println!("systemd-analyze [OPTIONS...] COMMAND ...");
    println!();
    println!("Experimental Rust implementation: only compare-versions is available.");
    println!("The installed C systemd-analyze remains authoritative for every other verb.");
    println!();
    println!("Commands:");
    println!("  compare-versions V1 [OP] V2  Compare two version strings");
    println!();
    println!("Options:");
    println!("  -h --help     Show this help");
    println!("     --version  Show Rust selected-verb implementation version");
}

fn print_version() {
    println!(
        "systemd-analyze (Rust selected-verb implementation {})",
        env!("CARGO_PKG_VERSION")
    );
}

fn fail_closed(verb: Option<&str>) -> i32 {
    match verb {
        Some(verb) if verb.starts_with('-') => eprintln!(
            "systemd-analyze: option '{verb}' is not implemented by the Rust selected-verb build; use the C systemd-analyze executable."
        ),
        Some(verb) => eprintln!(
            "systemd-analyze: verb '{verb}' is not implemented by the Rust selected-verb build; use the C systemd-analyze executable."
        ),
        None => eprintln!(
            "systemd-analyze: the default 'time' verb is not implemented by the Rust selected-verb build; use the C systemd-analyze executable."
        ),
    }
    EXIT_FAILURE
}

fn run(arguments: &[String]) -> i32 {
    match arguments.first().map(String::as_str) {
        Some("-h" | "--help" | "help") => {
            print_help();
            0
        }
        Some("--version") => {
            print_version();
            0
        }
        Some(IMPLEMENTED_VERB) => match compare_versions(&arguments[1..]) {
            Ok(result) => {
                for warning in result.warnings {
                    eprintln!("systemd-analyze: {warning}");
                }
                if let Some(stdout) = result.stdout {
                    println!("{stdout}");
                }
                result.exit_status
            }
            Err(error) => {
                eprintln!("systemd-analyze: {}", error.message());
                EXIT_FAILURE
            }
        },
        unsupported => fail_closed(unsupported),
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&arguments));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_default_and_verbs_fail_closed() {
        assert_eq!(run(&[]), EXIT_FAILURE);
        assert_eq!(run(&["time".to_string()]), EXIT_FAILURE);
        assert_eq!(run(&["--root=/tmp".to_string()]), EXIT_FAILURE);
    }
}
