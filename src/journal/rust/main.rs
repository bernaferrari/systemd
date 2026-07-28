// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]

use systemd_journal_rust_port::journald_runtime::{
    JournalRuntime, JournaldError, Mode, execute, help_text, parse_args,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const RUNTIME_ROOT_ENV: &str = "SYSTEMD_JOURNAL_RUNTIME_ROOT";
const NAMESPACE_ENV: &str = "SYSTEMD_JOURNAL_NAMESPACE";

fn print_version() {
    println!("systemd-journald {VERSION}");
}

fn runtime_from_env(namespace: Option<String>) -> JournalRuntime {
    match std::env::var(RUNTIME_ROOT_ENV) {
        Ok(value) if !value.trim().is_empty() => {
            JournalRuntime::new_with_namespace(value, namespace)
        }
        _ => JournalRuntime::default_with_namespace(namespace),
    }
}

fn namespace_name_valid(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn namespace_from_cli_or_env(
    raw_args: &[String],
) -> Result<(Vec<String>, Option<String>), JournaldError> {
    let mut args = Vec::with_capacity(raw_args.len());
    let mut namespace = None;

    if let Some(first) = raw_args.first() {
        args.push(first.clone());
    }
    for arg in raw_args.iter().skip(1) {
        if arg.starts_with('-') {
            args.push(arg.clone());
            continue;
        }
        if namespace.is_none() {
            namespace = Some(arg.clone());
            continue;
        }
        args.push(arg.clone());
    }

    let namespace = match namespace {
        Some(value) => {
            if !namespace_name_valid(&value) {
                return Err(JournaldError::InvalidArgument(format!(
                    "invalid namespace name: {value}"
                )));
            }
            Some(value)
        }
        None => std::env::var(NAMESPACE_ENV)
            .ok()
            .and_then(|value| (!value.trim().is_empty()).then_some(value))
            .map(|value| {
                if namespace_name_valid(&value) {
                    Ok(value)
                } else {
                    Err(JournaldError::InvalidArgument(format!(
                        "invalid namespace name: {value}"
                    )))
                }
            })
            .transpose()?,
    };

    Ok((args, namespace))
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("systemd-journald: {err}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), JournaldError> {
    let raw_args: Vec<String> = std::env::args().collect();
    let (args_for_mode, namespace) = namespace_from_cli_or_env(&raw_args)?;
    let mode = parse_args(args_for_mode.iter().map(String::as_str))?;
    let runtime = runtime_from_env(namespace);

    match mode {
        Mode::Help => {
            print!("{}", help_text());
            Ok(())
        }
        Mode::Version => {
            print_version();
            Ok(())
        }
        Mode::Daemon => runtime.run_daemon(),
        Mode::Action(_) => {
            execute(mode, &runtime)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_is_taken_from_first_positional() {
        let args = vec![
            "systemd-journald".to_string(),
            "tenant-a".to_string(),
            "--rotate".to_string(),
        ];
        let (filtered, namespace) = namespace_from_cli_or_env(&args).unwrap();

        assert_eq!(namespace.as_deref(), Some("tenant-a"));
        assert_eq!(filtered, vec!["systemd-journald", "--rotate"]);
    }

    #[test]
    fn namespace_validation_rejects_path_traversal_characters() {
        let args = vec!["systemd-journald".to_string(), "../bad".to_string()];
        let err = namespace_from_cli_or_env(&args).unwrap_err();
        assert!(matches!(err, JournaldError::InvalidArgument(_)));
    }
}
