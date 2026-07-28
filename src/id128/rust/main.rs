// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/id128/id128.c
//
// Binary entry point for systemd-id128. The security-sensitive operations live
// in lib.rs and delegate to the Rust sd-id128 implementation.

use std::ffi::OsString;
use std::process::ExitCode;
use systemd_id128_rs::{
    Id128, Id128Verb, PrettyPrintMode, Result, boot_id, derive_app_specific, format_id,
    from_string, invocation_id, is_null, machine_id, pretty_sample, random_id,
};

const SD_GPT_VAR: Id128 = [
    0x4d, 0x21, 0xb0, 0x16, 0xb5, 0x34, 0x45, 0xc2, 0xa9, 0xfb, 0x5c, 0x16, 0xe0, 0x91, 0xfd, 0x2d,
];
const SD_GPT_ROOT_X86_64: Id128 = [
    0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84, 0xb7, 0x09,
];

const KNOWN_GPT_TYPES: &[(&str, Id128)] = &[
    (
        "esp",
        [
            0xc1, 0x2a, 0x73, 0x28, 0xf8, 0x1f, 0x11, 0xd2, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e,
            0xc9, 0x3b,
        ],
    ),
    (
        "xbootldr",
        [
            0xbc, 0x13, 0xc2, 0xff, 0x59, 0xe6, 0x42, 0x62, 0xa3, 0x52, 0xb2, 0x75, 0xfd, 0x6f,
            0x71, 0x72,
        ],
    ),
    (
        "swap",
        [
            0x06, 0x57, 0xfd, 0x6d, 0xa4, 0xab, 0x43, 0xc4, 0x84, 0xe5, 0x09, 0x33, 0xc8, 0x4b,
            0x4f, 0x4f,
        ],
    ),
    (
        "home",
        [
            0x93, 0x3a, 0xc7, 0xe1, 0x2e, 0xb4, 0x4f, 0x13, 0xb8, 0x44, 0x0e, 0x14, 0xe2, 0xae,
            0xf9, 0x15,
        ],
    ),
    (
        "srv",
        [
            0x3b, 0x8f, 0x84, 0x25, 0x20, 0xe0, 0x4f, 0x3b, 0x90, 0x7f, 0x1a, 0x25, 0xa7, 0x6f,
            0x98, 0xe8,
        ],
    ),
    ("var", SD_GPT_VAR),
    (
        "tmp",
        [
            0x7e, 0xc6, 0xf5, 0x57, 0x3b, 0xc5, 0x4a, 0xca, 0xb2, 0x93, 0x16, 0xef, 0x5d, 0xf6,
            0x39, 0xd1,
        ],
    ),
    (
        "user-home",
        [
            0x77, 0x3f, 0x91, 0xef, 0x66, 0xd4, 0x49, 0xb5, 0xbd, 0x83, 0xd6, 0x83, 0xbf, 0x40,
            0xad, 0x16,
        ],
    ),
    (
        "linux-generic",
        [
            0x0f, 0xc6, 0x3d, 0xaf, 0x84, 0x83, 0x47, 0x72, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47,
            0x7d, 0xe4,
        ],
    ),
    ("root-x86-64", SD_GPT_ROOT_X86_64),
];

#[derive(Debug)]
struct Cli {
    verb: Id128Verb,
    mode: PrettyPrintMode,
    value_only: bool,
    legend: bool,
    app_id: Option<Id128>,
    show_args: Vec<String>,
}

#[derive(Debug)]
enum ParseOutcome {
    Help,
    Run(Cli),
}

fn parse_args(
    args: impl IntoIterator<Item = OsString>,
) -> std::result::Result<ParseOutcome, String> {
    let mut words = Vec::new();
    for arg in args {
        words.push(
            arg.into_string()
                .map_err(|_| "arguments must be valid UTF-8".to_owned())?,
        );
    }

    let mut mode = PrettyPrintMode::Id128;
    let mut value_only = false;
    let mut legend = true;
    let mut app_id = None;
    let mut positional = Vec::new();
    let mut after_options = false;
    let mut index = 0;

    while index < words.len() {
        let word = &words[index];
        if !after_options && word == "--" {
            after_options = true;
            index += 1;
            continue;
        }

        if !after_options && word.starts_with("--") {
            match word.as_str() {
                "--help" => return Ok(ParseOutcome::Help),
                "--no-pager" => {}
                "--no-legend" => legend = false,
                "--pretty" => {
                    mode = PrettyPrintMode::Pretty;
                    value_only = false;
                }
                "--value" => {
                    value_only = true;
                    if mode == PrettyPrintMode::Pretty {
                        mode = PrettyPrintMode::Id128;
                    }
                }
                "--uuid" => mode = PrettyPrintMode::Uuid,
                "--version" => {
                    return Err(
                        "--version is unavailable until the Rust executable is wired to Meson's canonical build metadata"
                            .to_owned(),
                    )
                }
                "--json" => {
                    return Err("--json requires an explicit format".to_owned());
                }
                "--json=off" => {}
                option if option.starts_with("--json=") => {
                    return Err(format!("{option} is not implemented by the Rust command"));
                }
                "--app-specific" => {
                    index += 1;
                    let value = words
                        .get(index)
                        .ok_or_else(|| "--app-specific requires an ID".to_owned())?;
                    app_id = Some(parse_app_id(value)?);
                }
                option if option.starts_with("--app-specific=") => {
                    app_id = Some(parse_app_id(&option[15..])?);
                }
                _ => return Err(format!("unknown option '{word}'")),
            }
        } else if !after_options && word.starts_with('-') && word != "-" {
            if word == "-a" {
                index += 1;
                let value = words
                    .get(index)
                    .ok_or_else(|| "-a requires an ID".to_owned())?;
                app_id = Some(parse_app_id(value)?);
            } else if word == "-j" {
                return Err("-j is not implemented by the Rust command".to_owned());
            } else {
                for option in word[1..].chars() {
                    match option {
                        'p' => {
                            mode = PrettyPrintMode::Pretty;
                            value_only = false;
                        }
                        'P' => {
                            value_only = true;
                            if mode == PrettyPrintMode::Pretty {
                                mode = PrettyPrintMode::Id128;
                            }
                        }
                        'u' => mode = PrettyPrintMode::Uuid,
                        'h' => return Ok(ParseOutcome::Help),
                        _ => return Err(format!("unknown option '-{option}'")),
                    }
                }
            }
        } else {
            positional.push(word.clone());
        }
        index += 1;
    }

    let Some(verb_name) = positional.first() else {
        return Err("command verb required (one of new, machine-id, boot-id, invocation-id, var-partition-uuid, show)".to_owned());
    };
    if verb_name == "help" {
        if positional.len() != 1 {
            return Err("help does not take arguments".to_owned());
        }
        return Ok(ParseOutcome::Help);
    }
    let verb = systemd_id128_rs::parse_verb(verb_name)
        .map_err(|_| format!("unknown command verb '{verb_name}'"))?;
    let show_args = positional.into_iter().skip(1).collect();

    Ok(ParseOutcome::Run(Cli {
        verb,
        mode,
        value_only,
        legend,
        app_id,
        show_args,
    }))
}

fn parse_app_id(value: &str) -> std::result::Result<Id128, String> {
    let id =
        from_string(value).map_err(|_| format!("failed to parse '{value}' as application ID"))?;
    if is_null(&id) {
        return Err("application ID cannot be all zeros".to_owned());
    }
    Ok(id)
}

fn output_id(id: Id128, mode: PrettyPrintMode) {
    match mode {
        PrettyPrintMode::Pretty => print_pretty_sample("XYZ", id),
        _ => println!("{}", format_id(&id, mode)),
    }
}

fn print_pretty_sample(name: &str, id: Id128) {
    print!("{}", pretty_sample(name, &id));
}

fn no_extra_args(cli: &Cli) -> std::result::Result<(), String> {
    if cli.show_args.is_empty() {
        Ok(())
    } else {
        Err("too many arguments".to_owned())
    }
}

fn with_app(id: Id128, app_id: Option<Id128>) -> Result<Id128> {
    match app_id {
        Some(app) => derive_app_specific(&id, &app),
        None => Ok(id),
    }
}

fn run_single(cli: &Cli, id: Result<Id128>) -> std::result::Result<(), String> {
    no_extra_args(cli)?;
    let id = with_app(id.map_err(errno_message)?, cli.app_id).map_err(errno_message)?;
    output_id(id, cli.mode);
    Ok(())
}

fn errno_message(error: systemd_id128_rs::Errno) -> String {
    format!("operation failed: {}", error)
}

fn known_name(id: Id128) -> &'static str {
    KNOWN_GPT_TYPES
        .iter()
        .find_map(|(name, known)| (*known == id).then_some(*name))
        .unwrap_or("XYZ")
}

fn parse_show_id(value: &str) -> std::result::Result<Id128, String> {
    if let Ok(id) = from_string(value) {
        return Ok(id);
    }
    if value == "root" {
        #[cfg(target_arch = "x86_64")]
        return Ok(SD_GPT_ROOT_X86_64);

        #[cfg(not(target_arch = "x86_64"))]
        return Err(
            "the Rust command does not yet provide the complete architecture-specific GPT table"
                .to_owned(),
        );
    }
    KNOWN_GPT_TYPES
        .iter()
        .find_map(|(name, id)| (*name == value).then_some(*id))
        .ok_or_else(|| format!("unknown identifier '{value}'"))
}

fn run_show(cli: &Cli) -> std::result::Result<(), String> {
    if cli.show_args.is_empty() {
        return Err(
            "show without explicit IDs is not implemented: the complete canonical GPT type table has not yet been ported"
                .to_owned(),
        );
    }

    let mut entries = Vec::with_capacity(cli.show_args.len());
    for value in &cli.show_args {
        let base = parse_show_id(value)?;
        let id = with_app(base, cli.app_id).map_err(errno_message)?;
        entries.push((known_name(base), id));
    }

    if cli.value_only {
        for (_, id) in entries {
            println!("{}", format_id(&id, cli.mode));
        }
        return Ok(());
    }

    if cli.mode == PrettyPrintMode::Pretty {
        for (index, (name, id)) in entries.into_iter().enumerate() {
            if index > 0 {
                println!();
            }
            let sample_name = name.replace('-', "_").to_uppercase();
            print_pretty_sample(&sample_name, id);
        }
        return Ok(());
    }

    if cli.legend {
        println!("NAME\tID");
    }
    for (name, id) in entries {
        println!("{name}\t{}", format_id(&id, cli.mode));
    }
    Ok(())
}

fn run(cli: Cli) -> std::result::Result<(), String> {
    match cli.verb {
        Id128Verb::New => {
            no_extra_args(&cli)?;
            // C accepts --app-specific for `new` but does not apply it.
            let _ = cli.app_id;
            output_id(random_id().map_err(errno_message)?, cli.mode);
            Ok(())
        }
        Id128Verb::MachineId => run_single(&cli, machine_id()),
        Id128Verb::BootId => run_single(&cli, boot_id()),
        Id128Verb::InvocationId => {
            if cli.app_id.is_some() {
                return Err(
                    "verb 'invocation-id' cannot be combined with --app-specific".to_owned(),
                );
            }
            run_single(&cli, invocation_id())
        }
        Id128Verb::VarPartitionUuid => {
            if cli.app_id.is_some() {
                return Err(
                    "verb 'var-partition-uuid' cannot be combined with --app-specific".to_owned(),
                );
            }
            no_extra_args(&cli)?;
            let id = derive_app_specific(&machine_id().map_err(errno_message)?, &SD_GPT_VAR)
                .map_err(errno_message)?;
            output_id(id, cli.mode);
            Ok(())
        }
        Id128Verb::Show => run_show(&cli),
    }
}

fn print_help() {
    println!(
        "systemd-id128 [OPTIONS...] COMMAND\n\nGenerate and print 128-bit identifiers.\n\nCommands:\n  new\n  machine-id\n  boot-id\n  invocation-id\n  var-partition-uuid\n  show [NAME|UUID...]\n\nOptions:\n  -p, --pretty              Generate program-code samples\n  -P, --value               Only print values for show\n  -a, --app-specific=ID     Generate application-specific IDs\n  -u, --uuid                Output UUID format\n      --no-pager            Accepted; this implementation never opens a pager\n      --no-legend           Accepted for show output\n      --json=off            Disable JSON output\n  -h, --help                Show this help"
    );
}

fn main() -> ExitCode {
    match parse_args(std::env::args_os().skip(1)) {
        Ok(ParseOutcome::Help) => {
            print_help();
            ExitCode::SUCCESS
        }
        Ok(ParseOutcome::Run(cli)) => match run(cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("systemd-id128: {message}");
                ExitCode::FAILURE
            }
        },
        Err(message) => {
            eprintln!("systemd-id128: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_verb() {
        assert!(parse_args(Vec::<OsString>::new()).is_err());
    }

    #[test]
    fn parses_app_specific_and_uuid_options() {
        let parsed = parse_args([
            OsString::from("-u"),
            OsString::from("-a"),
            OsString::from("4f68bce3e8cd4db196e7fbcaf984b709"),
            OsString::from("machine-id"),
        ])
        .unwrap();
        let ParseOutcome::Run(cli) = parsed else {
            panic!("expected command");
        };
        assert_eq!(cli.mode, PrettyPrintMode::Uuid);
        assert!(cli.app_id.is_some());
    }

    #[test]
    fn show_known_type_uses_canonical_uuid() {
        assert_eq!(
            parse_show_id("root-x86-64").unwrap(),
            [
                0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84,
                0xb7, 0x09,
            ]
        );
    }

    #[test]
    fn invocation_rejects_app_specific() {
        let cli = Cli {
            verb: Id128Verb::InvocationId,
            mode: PrettyPrintMode::Id128,
            value_only: false,
            legend: true,
            app_id: Some([1; 16]),
            show_args: Vec::new(),
        };
        assert!(run(cli).is_err());
    }
}
