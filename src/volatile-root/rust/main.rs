// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-volatile-root.
//
// PORT-SYNC: src/volatile-root/volatile-root.c

use systemd_volatile_root_rs::resolve_args_from_cmdline;
#[cfg(target_os = "linux")]
use systemd_volatile_root_rs::{
    LinuxVolatileRootPreflightBackend, VolatileRootDiagnostic, VolatileRootRunOutcome,
    VolatileRootTransitionPolicy, run_volatile_root_with_policy, volatile_root_transition_refusal,
};

fn print_help() {
    eprintln!("Usage: systemd-volatile-root [MODE] [PATH]");
    eprintln!();
    eprintln!("  -h --help             Show this help");
    eprintln!("     --version          Show package version");
    eprintln!();
    eprintln!("  MODE: yes|state|overlay|no");
}

#[cfg(target_os = "linux")]
fn report_diagnostic(diagnostic: &VolatileRootDiagnostic) {
    match diagnostic {
        VolatileRootDiagnostic::AlreadyTemporary { path } => {
            eprintln!("systemd-volatile-root: {path} already is a temporary file system");
        }
        VolatileRootDiagnostic::BackingDeviceLinkFailed {
            target,
            link,
            error_kind,
            error_raw_os_error,
        } => {
            eprintln!(
                "systemd-volatile-root: failed to create informational backing-device link {link} -> {target}: {error_kind}{}",
                error_raw_os_error
                    .map(|errno| format!(" (errno {errno})"))
                    .unwrap_or_default(),
            );
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    // Retain the executable boundary's documented single-option help and
    // version requests. All other positional inputs are passed through the
    // C-compatible volatile-mode parser below.
    match args.as_slice() {
        [_, flag] if flag == "-h" || flag == "--help" => {
            print_help();
            return;
        }
        [_, flag] if flag == "--version" => {
            eprintln!("systemd-volatile-root {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        _ => {}
    }

    // This follows the C ordering: resolve the kernel command line first,
    // validate positional input even for inactive modes, then skip all mount
    // work for `no` and `state`. The old blanket refusal made an ordinary
    // initrd invocation fail even when no volatile root was requested.
    let cmdline = match std::fs::read_to_string("/proc/cmdline") {
        Ok(cmdline) => cmdline,
        Err(error) => {
            eprintln!(
                "systemd-volatile-root: failed to determine volatile mode from kernel command line: {error}"
            );
            std::process::exit(1);
        }
    };
    let parsed = match resolve_args_from_cmdline(&arg_refs, &cmdline) {
        Ok(parsed) => parsed,
        Err(_) => {
            eprintln!("systemd-volatile-root: invalid mode, path, or argument count");
            std::process::exit(1);
        }
    };

    #[cfg(target_os = "linux")]
    {
        let mut backend = LinuxVolatileRootPreflightBackend::new();
        let result = run_volatile_root_with_policy(
            &parsed,
            // This is deliberately explicit: the installed Rust binary shares
            // the orchestration contract with namespace tests, but its default
            // runtime authority cannot mutate a root filesystem before those
            // tests prove the full transition and fallback behaviour.
            VolatileRootTransitionPolicy::RefuseTransitions,
            &mut backend,
        );
        for diagnostic in backend.take_diagnostics() {
            report_diagnostic(&diagnostic);
        }
        match result {
            Ok(VolatileRootRunOutcome::Inactive | VolatileRootRunOutcome::AlreadyTemporary) => {}
            Ok(VolatileRootRunOutcome::MadeVolatile | VolatileRootRunOutcome::MadeOverlay) => {
                unreachable!("the refuse-transitions policy cannot perform a mount transition")
            }
            Err(error) if volatile_root_transition_refusal(&error).is_some() => {
                eprintln!(
                    "systemd-volatile-root: Rust volatile-root mount transition is not implemented; refusing to modify {}",
                    parsed.path
                );
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!(
                    "systemd-volatile-root: failed to validate {} before the volatile-root transition: {error}",
                    parsed.path
                );
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = parsed;
        eprintln!("systemd-volatile-root: Rust volatile-root requires Linux");
        std::process::exit(1);
    }
}
