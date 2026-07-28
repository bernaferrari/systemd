// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-stdio-bridge.
// PORT-SYNC: src/stdio-bridge/stdio-bridge.c

use systemd_libsystemd_rs::sd_daemon_checks::{
    DaemonCheckError, sd_is_socket_unix, sd_listen_fds_preserve_environment,
    sd_notify_preserve_environment,
};
use systemd_stdio_bridge_rs::{
    BridgeError, BridgeFds, ParseAction, parse_args_detailed, print_version, run_bridge,
};

fn print_help() {
    println!("systemd-stdio-bridge [OPTIONS...]\n");
    println!("Forward messages between a pipe or socket and a D-Bus bus.\n");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
    println!(
        "  -p --bus-path=PATH     Path to the bus address (default: unix:path=/run/dbus/system_bus_socket)"
    );
    println!("     --system            Connect to system bus");
    println!("     --user              Connect to user bus");
    println!("  -M --machine=CONTAINER Name of local container to connect to");
    println!("  -q --quiet             Fail silently instead of logging errors");
}

fn report(error: &BridgeError, quiet: bool) {
    if !quiet {
        eprintln!("systemd-stdio-bridge: {error}");
    }
}

fn activation_error(error: DaemonCheckError) -> BridgeError {
    let errno = match &error {
        DaemonCheckError::BadFd => libc::EBADF,
        DaemonCheckError::InvalidInput(_) | DaemonCheckError::Parse(_) => libc::EINVAL,
        DaemonCheckError::Io(errno) => *errno,
    };
    BridgeError::Activation {
        message: format!("{error:?}"),
        errno,
    }
}

fn notify_exit(error: Option<&BridgeError>, status: i32) {
    if let Some(error) = error {
        let _ = sd_notify_preserve_environment(&format!("ERRNO={}", error.errno()));
    }
    let _ = sd_notify_preserve_environment(&format!("EXIT_STATUS={status}"));
}

fn run() -> Result<(), (BridgeError, bool)> {
    let args = std::env::args_os()
        .skip(1)
        .map(|argument| {
            argument.into_string().map_err(|_| {
                BridgeError::InvalidArgument("arguments must be valid UTF-8".to_owned())
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| (error, false))?;
    let parsed = parse_args_detailed(&args).map_err(|failure| (failure.error, failure.quiet))?;
    match parsed.action {
        ParseAction::Help => {
            print_help();
            return Ok(());
        }
        ParseAction::Version => {
            print_version().map_err(|error| (error, parsed.config.quiet))?;
            return Ok(());
        }
        ParseAction::Run => {}
    }

    // Mirrors sd_listen_fds(0): do not consume the activation environment.
    let passed = sd_listen_fds_preserve_environment()
        .map_err(|error| (activation_error(error), parsed.config.quiet))?;
    let fds =
        BridgeFds::from_listen_fd_count(passed).map_err(|error| (error, parsed.config.quiet))?;
    // The C implementation intentionally treats errors from sd_is_socket() as
    // "not a UNIX socket" here and lets sd-bus report any real descriptor error.
    let input_is_unix = matches!(sd_is_socket_unix(fds.input(), None, None, None), Ok(true));
    let output_is_unix =
        input_is_unix && matches!(sd_is_socket_unix(fds.output(), None, None, None), Ok(true));

    run_bridge(&parsed.config, fds, input_is_unix && output_is_unix)
        .map_err(|error| (error, parsed.config.quiet))
}

fn main() {
    match run() {
        Ok(()) => notify_exit(None, 0),
        Err((error, quiet)) => {
            report(&error, quiet);
            notify_exit(Some(&error), 1);
            std::process::exit(1);
        }
    }
}
