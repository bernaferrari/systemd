// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-socket-proxyd
//
// PORT-SYNC: src/socket-proxy/socket-proxyd.c

use systemd_socket_proxy_rs::{
    parse_time_span_usec, validate_connections_max, ProxyConfig, ProxyError,
    DEFAULT_CONNECTIONS_MAX, DEFAULT_EXIT_IDLE_TIME,
};

#[cfg(target_os = "linux")]
mod runtime;

const VERSION: &str = env!("CARGO_PKG_VERSION");

enum CliAction {
    Run(ProxyConfig),
    Help,
    Version,
}

fn print_help() {
    println!("systemd-socket-proxyd [HOST:PORT]");
    println!("systemd-socket-proxyd [SOCKET]");
    println!();
    println!("Bidirectionally proxy local sockets to another socket.");
    println!();
    println!("  -c --connections-max=  Set the maximum number of connections to accept");
    println!("     --exit-idle-time=   Exit after this duration without a connection");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
}

fn print_version() {
    println!("systemd-socket-proxyd {}", VERSION);
}

fn option_argument(
    args: &[String],
    index: &mut usize,
    inline: Option<&str>,
    option: &str,
) -> Result<String, String> {
    if let Some(value) = inline {
        if value.is_empty() {
            return Err(format!("{option} requires an argument"));
        }
        return Ok(value.to_string());
    }

    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{option} requires an argument"))
}

fn parse_cli(args: &[String]) -> Result<CliAction, String> {
    let mut connections_max = DEFAULT_CONNECTIONS_MAX;
    let mut exit_idle_time = DEFAULT_EXIT_IDLE_TIME;
    let mut remote_host = None;
    let mut options = true;
    let mut index = 0usize;

    while index < args.len() {
        let argument = &args[index];
        if options && argument == "--" {
            options = false;
        } else if options && matches!(argument.as_str(), "-h" | "--help") {
            return Ok(CliAction::Help);
        } else if options && argument == "--version" {
            return Ok(CliAction::Version);
        } else if options
            && (argument == "-c"
                || argument == "--connections-max"
                || argument.starts_with("--connections-max=")
                || (argument.starts_with("-c") && argument.len() > 2))
        {
            let inline = argument
                .strip_prefix("--connections-max=")
                .or_else(|| argument.strip_prefix("-c").filter(|_| argument.len() > 2));
            let value = option_argument(args, &mut index, inline, "--connections-max")?;
            let parsed = value
                .parse::<u32>()
                .map_err(|_| ProxyError::InvalidConnectionLimit(value.clone()).to_string())?;
            connections_max =
                validate_connections_max(parsed).map_err(|error| error.to_string())?;
        } else if options
            && (argument == "--exit-idle-time" || argument.starts_with("--exit-idle-time="))
        {
            let inline = argument.strip_prefix("--exit-idle-time=");
            let value = option_argument(args, &mut index, inline, "--exit-idle-time")?;
            exit_idle_time = parse_time_span_usec(&value).map_err(|error| error.to_string())?;
        } else if options && argument.starts_with('-') {
            return Err(format!("unknown option: {argument}"));
        } else if remote_host.replace(argument.clone()).is_some() {
            return Err(ProxyError::TooManyParameters.to_string());
        }
        index += 1;
    }

    let remote_host = remote_host.ok_or_else(|| ProxyError::NotEnoughParameters.to_string())?;
    Ok(CliAction::Run(ProxyConfig {
        connections_max,
        remote_host,
        exit_idle_time,
    }))
}

fn main() {
    let args = match std::env::args_os()
        .skip(1)
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "command line contains non-UTF-8 data".to_string())
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(args) => args,
        Err(error) => {
            eprintln!("socket-proxyd: {error}");
            std::process::exit(1);
        }
    };
    match parse_cli(&args) {
        Ok(CliAction::Help) => print_help(),
        Ok(CliAction::Version) => print_version(),
        Ok(CliAction::Run(config)) => {
            #[cfg(target_os = "linux")]
            if let Err(error) = runtime::run(config) {
                eprintln!("socket-proxyd: {error}");
                std::process::exit(1);
            }

            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
                eprintln!("socket-proxyd: not available on this platform");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("socket-proxyd: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn cli_requires_exactly_one_target() {
        assert!(parse_cli(&[]).is_err());
        assert!(parse_cli(&strings(&["one", "two"])).is_err());
    }

    #[test]
    fn cli_accepts_short_and_long_options() {
        let CliAction::Run(config) =
            parse_cli(&strings(&["-c", "12", "--exit-idle-time=1.5s", "host:9"])).unwrap()
        else {
            panic!("expected runnable configuration");
        };
        assert_eq!(config.connections_max, 12);
        assert_eq!(config.exit_idle_time, 1_500_000);
        assert_eq!(config.remote_host, "host:9");
    }

    #[test]
    fn cli_rejects_zero_connection_limit() {
        assert!(parse_cli(&strings(&["--connections-max=0", "host"])).is_err());
    }
}
