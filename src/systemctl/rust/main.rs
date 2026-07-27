// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/systemctl/systemctl.c, src/systemctl/systemctl-list-units.c, src/systemctl/systemctl-start-unit.c, src/systemctl/systemctl-is-active.c, src/systemctl/systemctl-daemon-reload.c
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemctl [OPTIONS...] COMMAND ...");
    println!();
    println!("Partial Rust systemctl client. Unsupported commands fail explicitly.");
    println!();
    println!("  -h, --help          Show this help");
    println!("      --version       Show package version");
    println!();
    println!("Supported commands (system D-Bus required):");
    println!("  list-units          List units reported by the manager");
    println!("  start UNIT...       Start unit(s)");
    println!("  stop UNIT...        Stop unit(s)");
    println!("  restart UNIT...     Restart unit(s)");
    println!("  is-active UNIT...   Print actual manager active state");
    println!("  daemon-reload       Ask the manager to reload configuration");
}

fn print_version() {
    println!("systemctl {}", VERSION);
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Runtime::new()
        .map_err(|error| format!("failed to create async runtime: {error}"))
}

#[cfg(target_os = "linux")]
fn cmd_list_units(runtime: &tokio::runtime::Runtime) -> Result<(), String> {
    let mut units = runtime
        .block_on(systemd_dbus_rs::client::list_units_system())
        .map_err(|error| format!("failed to list units over system D-Bus: {error}"))?;

    units.sort_by(|a, b| a.name.cmp(&b.name));
    println!("{:<50} {:<12} {:<10} {}", "UNIT", "LOAD", "ACTIVE", "SUB");
    for unit in units {
        println!(
            "{:<50} {:<12} {:<10} {}  {}",
            unit.name, unit.load_state, unit.active_state, unit.sub_state, unit.description
        );
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn cmd_list_units(_: &tokio::runtime::Runtime) -> Result<(), String> {
    Err("list-units requires Linux system D-Bus".to_string())
}

#[cfg(target_os = "linux")]
fn cmd_start(runtime: &tokio::runtime::Runtime, units: &[String]) -> Result<(), String> {
    for unit in units {
        runtime
            .block_on(systemd_dbus_rs::client::start_unit_system(unit, "replace"))
            .map_err(|error| format!("failed to start {unit} over system D-Bus: {error}"))?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn cmd_start(_: &tokio::runtime::Runtime, _: &[String]) -> Result<(), String> {
    Err("start requires Linux system D-Bus".to_string())
}

#[cfg(target_os = "linux")]
fn cmd_stop(runtime: &tokio::runtime::Runtime, units: &[String]) -> Result<(), String> {
    for unit in units {
        runtime
            .block_on(systemd_dbus_rs::client::stop_unit_system(unit, "replace"))
            .map_err(|error| format!("failed to stop {unit} over system D-Bus: {error}"))?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn cmd_stop(_: &tokio::runtime::Runtime, _: &[String]) -> Result<(), String> {
    Err("stop requires Linux system D-Bus".to_string())
}

#[cfg(target_os = "linux")]
fn cmd_restart(runtime: &tokio::runtime::Runtime, units: &[String]) -> Result<(), String> {
    for unit in units {
        runtime
            .block_on(systemd_dbus_rs::client::restart_unit_system(
                unit, "replace",
            ))
            .map_err(|error| format!("failed to restart {unit} over system D-Bus: {error}"))?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn cmd_restart(_: &tokio::runtime::Runtime, _: &[String]) -> Result<(), String> {
    Err("restart requires Linux system D-Bus".to_string())
}

#[cfg(target_os = "linux")]
fn cmd_is_active(runtime: &tokio::runtime::Runtime, units: &[String]) -> Result<(), String> {
    let states: BTreeMap<_, _> = runtime
        .block_on(systemd_dbus_rs::client::list_units_system())
        .map_err(|error| format!("failed to query unit state over system D-Bus: {error}"))?
        .into_iter()
        .map(|unit| (unit.name, unit.active_state))
        .collect();

    let mut all_active = true;
    for unit in units {
        match states.get(unit) {
            Some(state) => {
                println!("{state}");
                all_active &= matches!(state.as_str(), "active" | "reloading");
            }
            None => {
                println!("unknown");
                all_active = false;
            }
        }
    }

    if all_active {
        Ok(())
    } else {
        Err("one or more units are not active".to_string())
    }
}

#[cfg(not(target_os = "linux"))]
fn cmd_is_active(_: &tokio::runtime::Runtime, _: &[String]) -> Result<(), String> {
    Err("is-active requires Linux system D-Bus".to_string())
}

#[cfg(target_os = "linux")]
fn cmd_daemon_reload(runtime: &tokio::runtime::Runtime) -> Result<(), String> {
    runtime
        .block_on(systemd_dbus_rs::client::reload_system())
        .map_err(|error| format!("failed to reload manager over system D-Bus: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn cmd_daemon_reload(_: &tokio::runtime::Runtime) -> Result<(), String> {
    Err("daemon-reload requires Linux system D-Bus".to_string())
}

fn require_units(command: &str, units: &[String]) -> Result<(), String> {
    if units.is_empty() {
        Err(format!("{command} requires at least one unit"))
    } else {
        Ok(())
    }
}

fn execute(command: &str, args: &[String]) -> Result<(), String> {
    let runtime = runtime()?;

    match command {
        "list-units" if args.is_empty() => cmd_list_units(&runtime),
        "start" => {
            require_units(command, args)?;
            cmd_start(&runtime, args)
        }
        "stop" => {
            require_units(command, args)?;
            cmd_stop(&runtime, args)
        }
        "restart" => {
            require_units(command, args)?;
            cmd_restart(&runtime, args)
        }
        "is-active" => {
            require_units(command, args)?;
            cmd_is_active(&runtime, args)
        }
        "daemon-reload" if args.is_empty() => cmd_daemon_reload(&runtime),
        "list-units" | "daemon-reload" => Err(format!("{command} does not accept arguments")),
        _ => Err(format!(
            "unsupported command: {command}; use the C systemctl for this operation"
        )),
    }
}

fn report_result(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("systemctl: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    match args.as_slice() {
        [_] => report_result(execute("list-units", &[])),
        [_, option] if matches!(option.as_str(), "-h" | "--help") => {
            print_help();
            ExitCode::SUCCESS
        }
        [_, option] if option == "--version" => {
            print_version();
            ExitCode::SUCCESS
        }
        [_, command, arguments @ ..] => report_result(execute(command, arguments)),
        [] => unreachable!("std::env::args always includes argv[0]"),
    }
}
