// SPDX-License-Identifier: LGPL-2.1-or-later

use super::argument_values::{
    apply_facilities, apply_namespace, apply_output_fields, apply_output_mode,
    current_working_dir_string, expand_file_argument_paths, parse_boolean_strict,
    parse_id_descriptor, parse_lines, parse_path_option, parse_priority_mask,
    parse_timestamp_value, validate_grep_pattern, validate_image_policy,
};
use super::model::{
    ARG_LINES_ALL, ARG_LINES_DEFAULT, JournalctlAction, JournalctlArgs, PAGER_DISABLE,
    PAGER_JUMP_TO_END, ParseArgvError, ParseArgvResult, PatternCase, SD_JOURNAL_ASSUME_IMMUTABLE,
    SD_JOURNAL_CURRENT_USER, SD_JOURNAL_SYSTEM, SecretString,
};
use crate::journalctl_filter::field_list_has_scope_options;

fn apply_lines_value(
    args: &mut JournalctlArgs,
    explicit_arg: Option<&str>,
    candidate_next: Option<&str>,
) -> Result<bool, ParseArgvError> {
    let parsed = if let Some(arg) = explicit_arg {
        parse_lines(Some(arg), false)
            .map_err(|_| ParseArgvError::Invalid("invalid --lines value"))?
    } else if let Some(next) = candidate_next {
        parse_lines(Some(next), true)
            .map_err(|_| ParseArgvError::Invalid("invalid --lines value"))?
    } else {
        parse_lines(None, true).map_err(|_| ParseArgvError::Invalid("invalid --lines value"))?
    };

    args.lines = parsed.value;
    args.lines_oldest = parsed.oldest_first;
    Ok(parsed.explicit && explicit_arg.is_none())
}

fn apply_boot_value(
    args: &mut JournalctlArgs,
    explicit_arg: Option<&str>,
    candidate_next: Option<&str>,
) -> Result<bool, ParseArgvError> {
    args.boot = 1;
    args.boot_filter = true;
    args.boot_id = None;
    args.boot_offset = 0;

    if let Some(arg) = explicit_arg {
        let descriptor = parse_id_descriptor(arg)
            .map_err(|_| ParseArgvError::Invalid("failed to parse boot descriptor"))?;
        args.boot = if arg == "all" { 0 } else { 1 };
        args.boot_filter = args.boot > 0;
        args.boot_id = descriptor.id;
        args.boot_offset = descriptor.offset;
        return Ok(false);
    }

    if let Some(next) = candidate_next
        && let Ok(descriptor) = parse_id_descriptor(next)
    {
        args.boot = if next == "all" { 0 } else { 1 };
        args.boot_filter = args.boot > 0;
        args.boot_id = descriptor.id;
        args.boot_offset = descriptor.offset;
        return Ok(true);
    }

    Ok(false)
}

fn lines_needs_seek_end(args: &JournalctlArgs) -> bool {
    args.lines >= 0 && !args.lines_oldest
}

fn count_true(values: &[bool]) -> usize {
    values.iter().filter(|v| **v).count()
}

// Mirrors parse_argv() control-plane behavior in src/journal/journalctl.c.
pub fn parse_argv(args: &[&str]) -> Result<ParseArgvResult, ParseArgvError> {
    if args.is_empty() {
        return Err(ParseArgvError::Invalid("argv must not be empty"));
    }

    let mut parsed = JournalctlArgs::default();
    let cwd = current_working_dir_string();
    let mut since_usec = None;
    let mut until_usec = None;
    let mut i = 1;
    while i < args.len() {
        let token = args[i];

        if token == "--" {
            i += 1;
            while i < args.len() {
                parsed.positional_matches.push(args[i].to_string());
                i += 1;
            }
            break;
        }

        if let Some(raw) = token.strip_prefix("--") {
            let (name, value_inline) = match raw.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (raw, None),
            };

            match name {
                "help" => return Ok(ParseArgvResult::HelpRequested),
                "version" => return Ok(ParseArgvResult::VersionRequested),
                "no-pager" => parsed.pager_flags |= PAGER_DISABLE,
                "pager-end" => parsed.pager_flags |= PAGER_JUMP_TO_END,
                "follow" => parsed.follow = true,
                "new-id128" => parsed.action = JournalctlAction::NewId128,
                "output" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --output argument"))?
                    };
                    if apply_output_mode(&mut parsed, value)? {
                        return Ok(ParseArgvResult::OutputModeHelpRequested);
                    }
                }
                "identifier" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --identifier argument"))?
                    };
                    parsed.syslog_identifier.push(value.to_string());
                }
                "exclude-identifier" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args.get(i).ok_or(ParseArgvError::Invalid(
                            "missing --exclude-identifier argument",
                        ))?
                    };
                    parsed.exclude_identifier.push(value.to_string());
                }
                "priority" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --priority argument"))?
                    };
                    parsed.priorities_mask = parse_priority_mask(value)
                        .ok_or(ParseArgvError::Invalid("invalid --priority value"))?;
                }
                "facility" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --facility argument"))?
                    };
                    if apply_facilities(&mut parsed, value)? {
                        return Ok(ParseArgvResult::FacilitiesHelpRequested);
                    }
                }
                "full" => parsed.full = true,
                "no-full" => parsed.full = false,
                "all" => parsed.all = true,
                "lines" => {
                    let consumed =
                        apply_lines_value(&mut parsed, value_inline, args.get(i + 1).copied())?;
                    if consumed {
                        i += 1;
                    }
                }
                "no-tail" => parsed.no_tail = true,
                "truncate-newline" => parsed.truncate_newline = true,
                "quiet" => parsed.quiet = true,
                "merge" => parsed.merge = true,
                "this-boot" => {
                    parsed.boot = 1;
                    parsed.boot_filter = true;
                    parsed.boot_id = None;
                    parsed.boot_offset = 0;
                }
                "boot" => {
                    let consumed =
                        apply_boot_value(&mut parsed, value_inline, args.get(i + 1).copied())?;
                    if consumed {
                        i += 1;
                    }
                }
                "list-boots" => parsed.action = JournalctlAction::ListBoots,
                "list-invocations" => parsed.action = JournalctlAction::ListInvocations,
                "dmesg" => parsed.dmesg = true,
                "system" => parsed.journal_type |= SD_JOURNAL_SYSTEM,
                "user" => parsed.journal_type |= SD_JOURNAL_CURRENT_USER,
                "directory" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --directory argument"))?
                    };
                    parsed.directory = Some(value.to_string());
                }
                "file" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --file argument"))?
                    };
                    if value == "-" {
                        parsed.file_stdin = true;
                    } else {
                        parsed.file.extend(expand_file_argument_paths(value)?);
                    }
                }
                "root" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --root argument"))?
                    };
                    parsed.root = parse_path_option(value, true, &cwd)?;
                }
                "image" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --image argument"))?
                    };
                    parsed.image = parse_path_option(value, false, &cwd)?;
                }
                "image-policy" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --image-policy argument"))?
                    };
                    validate_image_policy(value)?;
                    parsed.image_policy = Some(value.to_string());
                }
                "namespace" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --namespace argument"))?
                    };
                    apply_namespace(&mut parsed, value);
                }
                "cursor" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --cursor argument"))?
                    };
                    parsed.cursor = Some(value.to_string());
                }
                "cursor-file" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --cursor-file argument"))?
                    };
                    parsed.cursor_file = Some(value.to_string());
                }
                "after-cursor" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --after-cursor argument"))?
                    };
                    parsed.after_cursor = Some(value.to_string());
                }
                "show-cursor" => parsed.show_cursor = true,
                "since" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --since argument"))?
                    };
                    since_usec = Some(parse_timestamp_value(value)?);
                    parsed.since = Some(value.to_string());
                }
                "until" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --until argument"))?
                    };
                    until_usec = Some(parse_timestamp_value(value)?);
                    parsed.until = Some(value.to_string());
                }
                "unit" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --unit argument"))?
                    };
                    parsed.system_units.push(value.to_string());
                }
                "user-unit" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --user-unit argument"))?
                    };
                    parsed.user_units.push(value.to_string());
                }
                "field" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --field argument"))?
                    };
                    parsed.action = JournalctlAction::ListFields;
                    parsed.field = Some(value.to_string());
                }
                "fields" => parsed.action = JournalctlAction::ListFieldNames,
                "grep" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --grep argument"))?
                    };
                    parsed.pattern = Some(value.to_string());
                }
                "case-sensitive" => {
                    parsed.case = if let Some(v) = value_inline {
                        if parse_boolean_strict(v)? {
                            PatternCase::Sensitive
                        } else {
                            PatternCase::Insensitive
                        }
                    } else {
                        PatternCase::Sensitive
                    };
                }
                "reverse" => parsed.reverse = true,
                "machine" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --machine argument"))?
                    };
                    parsed.machine = Some(value.to_string());
                }
                "utc" => parsed.utc = true,
                "header" => parsed.action = JournalctlAction::PrintHeader,
                "setup-keys" => parsed.action = JournalctlAction::SetupKeys,
                "verify" => parsed.action = JournalctlAction::Verify,
                "verify-key" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --verify-key argument"))?
                    };
                    parsed.verify_key = Some(SecretString::new(value.to_string()));
                    parsed.action = JournalctlAction::Verify;
                    parsed.merge = false;
                }
                "interval" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --interval argument"))?
                    };
                    if value.is_empty() {
                        return Err(ParseArgvError::Invalid("invalid --interval value"));
                    }
                    parsed.interval = Some(value.to_string());
                }
                "force" => parsed.force = true,
                "disk-usage" => parsed.action = JournalctlAction::DiskUsage,
                "list-catalog" => parsed.action = JournalctlAction::ListCatalog,
                "dump-catalog" => parsed.action = JournalctlAction::DumpCatalog,
                "update-catalog" => parsed.action = JournalctlAction::UpdateCatalog,
                "list-namespaces" => parsed.action = JournalctlAction::ListNamespaces,
                "flush" => parsed.action = JournalctlAction::Flush,
                "relinquish-var" => parsed.action = JournalctlAction::RelinquishVar,
                "smart-relinquish-var" => {
                    parsed.smart_relinquish_var = true;
                    parsed.action = JournalctlAction::RelinquishVar;
                }
                "sync" => parsed.action = JournalctlAction::Sync,
                "rotate" => {
                    parsed.action = if parsed.action == JournalctlAction::Vacuum {
                        JournalctlAction::RotateAndVacuum
                    } else {
                        JournalctlAction::Rotate
                    };
                }
                "vacuum-size" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --vacuum-size argument"))?
                    };
                    parsed.vacuum_size = value
                        .parse::<u64>()
                        .map_err(|_| ParseArgvError::Invalid("invalid --vacuum-size value"))?;
                    parsed.action = if parsed.action == JournalctlAction::Rotate {
                        JournalctlAction::RotateAndVacuum
                    } else {
                        JournalctlAction::Vacuum
                    };
                }
                "vacuum-files" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --vacuum-files argument"))?
                    };
                    parsed.vacuum_n_files = value
                        .parse::<u64>()
                        .map_err(|_| ParseArgvError::Invalid("invalid --vacuum-files value"))?;
                    parsed.action = if parsed.action == JournalctlAction::Rotate {
                        JournalctlAction::RotateAndVacuum
                    } else {
                        JournalctlAction::Vacuum
                    };
                }
                "vacuum-time" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --vacuum-time argument"))?
                    };
                    parsed.vacuum_time = value
                        .parse::<u64>()
                        .map_err(|_| ParseArgvError::Invalid("invalid --vacuum-time value"))?;
                    parsed.action = if parsed.action == JournalctlAction::Rotate {
                        JournalctlAction::RotateAndVacuum
                    } else {
                        JournalctlAction::Vacuum
                    };
                }
                "output-fields" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --output-fields argument"))?
                    };
                    apply_output_fields(&mut parsed, value);
                }
                "synchronize-on-exit" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args.get(i).ok_or(ParseArgvError::Invalid(
                            "missing --synchronize-on-exit argument",
                        ))?
                    };
                    parsed.synchronize_on_exit = parse_boolean_strict(value)?;
                }
                "invocation" => {
                    let value = if let Some(v) = value_inline {
                        v
                    } else {
                        i += 1;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing --invocation argument"))?
                    };
                    let descriptor = parse_id_descriptor(value).map_err(|_| {
                        ParseArgvError::Invalid("failed to parse invocation descriptor")
                    })?;
                    parsed.invocation = value != "all";
                    parsed.invocation_id = descriptor.id;
                    parsed.invocation_offset = descriptor.offset;
                }
                "no-hostname" => parsed.no_hostname = true,
                "catalog" => parsed.catalog = true,
                _ => return Err(ParseArgvError::Invalid("unknown option")),
            }

            i += 1;
            continue;
        }

        if token == "-" || !token.starts_with('-') {
            parsed.positional_matches.push(token.to_string());
            i += 1;
            continue;
        }

        let token_bytes = token.as_bytes();
        let mut consumed_following = false;
        let mut short_i = 1;
        while short_i < token_bytes.len() {
            if !token_bytes[short_i].is_ascii() {
                return Err(ParseArgvError::Invalid("unknown option"));
            }
            let c = token_bytes[short_i] as char;

            match c {
                'h' => return Ok(ParseArgvResult::HelpRequested),
                'e' => parsed.pager_flags |= PAGER_JUMP_TO_END,
                'f' => parsed.follow = true,
                'l' => parsed.full = true,
                'a' => parsed.all = true,
                'q' => parsed.quiet = true,
                'm' => parsed.merge = true,
                'k' => parsed.dmesg = true,
                'r' => parsed.reverse = true,
                'I' => {
                    parsed.invocation = true;
                    parsed.invocation_id = None;
                    parsed.invocation_offset = 0;
                }
                'N' => parsed.action = JournalctlAction::ListFieldNames,
                'x' => parsed.catalog = true,
                'W' => parsed.no_hostname = true,
                't' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -t argument"))?
                    };
                    parsed.syslog_identifier.push(value.to_string());
                    break;
                }
                'T' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -T argument"))?
                    };
                    parsed.exclude_identifier.push(value.to_string());
                    break;
                }
                'p' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -p argument"))?
                    };
                    parsed.priorities_mask = parse_priority_mask(value)
                        .ok_or(ParseArgvError::Invalid("invalid -p value"))?;
                    break;
                }
                'o' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -o argument"))?
                    };
                    if apply_output_mode(&mut parsed, value)? {
                        return Ok(ParseArgvResult::OutputModeHelpRequested);
                    }
                    break;
                }
                'n' => {
                    let inline = if short_i + 1 < token_bytes.len() {
                        Some(
                            token
                                .get(short_i + 1..)
                                .ok_or(ParseArgvError::Invalid("unknown option"))?,
                        )
                    } else {
                        None
                    };
                    let consumed =
                        apply_lines_value(&mut parsed, inline, args.get(i + 1).copied())?;
                    if consumed {
                        i += 1;
                        consumed_following = true;
                    }
                    break;
                }
                'b' => {
                    let inline = if short_i + 1 < token_bytes.len() {
                        Some(
                            token
                                .get(short_i + 1..)
                                .ok_or(ParseArgvError::Invalid("unknown option"))?,
                        )
                    } else {
                        None
                    };
                    let consumed = apply_boot_value(&mut parsed, inline, args.get(i + 1).copied())?;
                    if consumed {
                        i += 1;
                        consumed_following = true;
                    }
                    break;
                }
                'D' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -D argument"))?
                    };
                    parsed.directory = Some(value.to_string());
                    break;
                }
                'i' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -i argument"))?
                    };
                    if value == "-" {
                        parsed.file_stdin = true;
                    } else {
                        parsed.file.extend(expand_file_argument_paths(value)?);
                    }
                    break;
                }
                'M' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -M argument"))?
                    };
                    parsed.machine = Some(value.to_string());
                    break;
                }
                'c' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -c argument"))?
                    };
                    parsed.cursor = Some(value.to_string());
                    break;
                }
                'S' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -S argument"))?
                    };
                    since_usec = Some(parse_timestamp_value(value)?);
                    parsed.since = Some(value.to_string());
                    break;
                }
                'U' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -U argument"))?
                    };
                    until_usec = Some(parse_timestamp_value(value)?);
                    parsed.until = Some(value.to_string());
                    break;
                }
                'u' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -u argument"))?
                    };
                    parsed.system_units.push(value.to_string());
                    break;
                }
                'F' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -F argument"))?
                    };
                    parsed.action = JournalctlAction::ListFields;
                    parsed.field = Some(value.to_string());
                    break;
                }
                'g' => {
                    let value = if short_i + 1 < token_bytes.len() {
                        token
                            .get(short_i + 1..)
                            .ok_or(ParseArgvError::Invalid("unknown option"))?
                    } else {
                        i += 1;
                        consumed_following = true;
                        *args
                            .get(i)
                            .ok_or(ParseArgvError::Invalid("missing -g argument"))?
                    };
                    parsed.pattern = Some(value.to_string());
                    break;
                }
                _ => return Err(ParseArgvError::Invalid("unknown option")),
            }

            short_i += 1;
        }

        i += 1;
        if consumed_following {
            continue;
        }
    }

    if parsed.no_tail {
        parsed.lines = ARG_LINES_ALL;
    }

    if parsed.lines == ARG_LINES_DEFAULT {
        if parsed.follow && parsed.since.is_none() {
            parsed.lines = 10;
        } else if parsed.pager_flags & PAGER_JUMP_TO_END != 0 {
            parsed.lines = 1000;
        }
    }

    if parsed.boot < 0 {
        parsed.boot = if !parsed.merge
            && (parsed.follow || parsed.dmesg || (parsed.pager_flags & PAGER_JUMP_TO_END != 0))
        {
            1
        } else {
            0
        };
    }
    if parsed.boot == 0 {
        parsed.boot_id = None;
        parsed.boot_offset = 0;
    }

    let source_count = count_true(&[
        parsed.directory.is_some(),
        !parsed.file.is_empty() || parsed.file_stdin,
        parsed.machine.is_some(),
        parsed.root.is_some(),
        parsed.image.is_some(),
    ]);
    if source_count > 1 {
        return Err(ParseArgvError::Invalid("conflicting source options"));
    }

    if let (Some(since), Some(until)) = (since_usec, until_usec)
        && since > until
    {
        return Err(ParseArgvError::Invalid("--since= must be before --until="));
    }

    if count_true(&[
        parsed.cursor.is_some(),
        parsed.after_cursor.is_some(),
        parsed.cursor_file.is_some(),
        parsed.since.is_some(),
    ]) > 1
    {
        return Err(ParseArgvError::Invalid(
            "please specify only one of --since=, --cursor=, --cursor-file=, and --after-cursor=",
        ));
    }

    if parsed.follow && parsed.reverse {
        return Err(ParseArgvError::Invalid(
            "please specify either --reverse or --follow, not both",
        ));
    }

    if parsed.action == JournalctlAction::Show
        && parsed.lines >= 0
        && parsed.lines_oldest
        && (parsed.reverse || parsed.follow)
    {
        return Err(ParseArgvError::Invalid(
            "--lines=+N is unsupported when --reverse or --follow is specified",
        ));
    }

    if !matches!(
        parsed.action,
        JournalctlAction::Show | JournalctlAction::DumpCatalog | JournalctlAction::ListCatalog
    ) && !parsed.positional_matches.is_empty()
    {
        return Err(ParseArgvError::Invalid("extraneous arguments"));
    }

    if matches!(
        parsed.action,
        JournalctlAction::ListFields | JournalctlAction::ListFieldNames
    ) && field_list_has_scope_options(&parsed)
    {
        return Err(ParseArgvError::Invalid(
            "-F/--field= and -N/--fields cannot be combined with options that limit the journal",
        ));
    }

    if (parsed.boot > 0 || parsed.action == JournalctlAction::ListBoots) && parsed.merge {
        return Err(ParseArgvError::Invalid(
            "using --boot or --list-boots with --merge is not supported",
        ));
    }

    if !parsed.system_units.is_empty() && parsed.journal_type == SD_JOURNAL_CURRENT_USER {
        parsed
            .user_units
            .extend(parsed.system_units.iter().cloned());
        parsed.system_units.clear();
    }

    if let Some(pattern) = parsed.pattern.as_deref() {
        validate_grep_pattern(pattern, parsed.case)?;

        if lines_needs_seek_end(&parsed) && !parsed.follow {
            parsed.reverse = true;
        }
    }

    if !parsed.follow {
        parsed.journal_additional_open_flags |= SD_JOURNAL_ASSUME_IMMUTABLE;
    }

    Ok(ParseArgvResult::Parsed(parsed))
}
