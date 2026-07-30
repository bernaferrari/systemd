// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/options.c, src/shared/options.h
//
// Command-line option parsing with support for short options, long options
// with prefix matching, optional/required arguments, grouped help output,
// and positional argument reordering.

// ── Flags ─────────────────────────────────────────────────────────────────

use crate::ffi::*;
bitflags::bitflags! {
    /// Flags that modify option behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OptionFlags: u32 {
        /// Argument is optional (like `optional_argument` in getopt).
        const OPTIONAL_ARG  = 1 << 0;
        /// This option acts like "--" — stops further option parsing.
        const STOPS_PARSING = 1 << 1;
        /// Fake entry that marks the start of a named group.
        const GROUP_MARKER  = 1 << 2;
        /// Fake entry that inserts an extra help line.
        const HELP_ENTRY    = 1 << 3;
    }
}

// ── Option specification ──────────────────────────────────────────────────

/// Describes a single command-line option (short, long, or both).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionSpec<'a> {
    /// Opaque identifier returned when this option is matched.
    pub id: i32,
    /// Behaviour-modifying flags.
    pub flags: OptionFlags,
    /// Short option character, e.g. `Some('h')` for `-h`.
    pub short_code: Option<char>,
    /// Long option name **without** the leading `--`, e.g. `Some("help")`.
    pub long_code: Option<&'a str>,
    /// Placeholder shown in help for the option argument.
    pub metavar: Option<&'a str>,
    /// Human-readable help text.
    pub help: Option<&'a str>,
}

// ── Helpers on OptionSpec ─────────────────────────────────────────────────

/// Returns `true` when the option accepts an argument (i.e. has a metavar).
pub fn option_takes_arg(opt: &OptionSpec<'_>) -> bool {
    opt.metavar.is_some()
}

/// Returns `true` when the option accepts an argument *and* that argument is
/// optional (OPTIONAL_ARG flag set).
pub fn option_arg_optional(opt: &OptionSpec<'_>) -> bool {
    option_takes_arg(opt) && opt.flags.contains(OptionFlags::OPTIONAL_ARG)
}

/// Returns `true` when the option *requires* an argument (metavar present,
/// OPTIONAL_ARG *not* set).
pub fn option_arg_required(opt: &OptionSpec<'_>) -> bool {
    option_takes_arg(opt) && !option_arg_optional(opt)
}

/// Returns `true` for synthetic entries that are never matched from the
/// command line (group markers, extra help lines).
pub fn option_is_metadata(opt: &OptionSpec<'_>) -> bool {
    opt.flags.contains(OptionFlags::GROUP_MARKER) || opt.flags.contains(OptionFlags::HELP_ENTRY)
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced during option parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionParseError {
    /// The argument vector was empty.
    EmptyArgv,
    /// No option matched the given token.
    Unrecognized { optname: String },
    /// More than one long option shares the given prefix.
    Ambiguous {
        optname: String,
        candidates: Vec<String>,
    },
    /// A value was supplied but the option does not take one.
    UnexpectedArg { optname: String },
    /// A value is required but none was supplied.
    MissingArg { optname: String },
}

impl std::fmt::Display for OptionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyArgv => write!(f, "argv cannot be empty"),
            Self::Unrecognized { optname } => write!(f, "unrecognized option '{}'", optname),
            Self::Ambiguous {
                optname,
                candidates,
            } => {
                write!(
                    f,
                    "option '{}' is ambiguous; possibilities: {}",
                    optname,
                    candidates.join(", ")
                )
            }
            Self::UnexpectedArg { optname } => {
                write!(f, "option '{}' doesn't allow an argument", optname)
            }
            Self::MissingArg { optname } => {
                write!(f, "option '{}' requires an argument", optname)
            }
        }
    }
}

impl std::error::Error for OptionParseError {}

// ── Parser state ──────────────────────────────────────────────────────────

/// Result returned by [`option_parse`] on each successful match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedOption<'a> {
    /// The id field from the matching [`OptionSpec`].
    pub id: i32,
    /// Reference to the matched option specification.
    pub option: &'a OptionSpec<'a>,
    /// The argument value, if one was supplied.
    pub arg: Option<String>,
}

/// Internal, mutable state that drives the parser across successive calls.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OptionParser {
    /// Next argv index to examine. 0 means "not initialised yet".
    optind: usize,
    /// Non-zero when we are in the middle of a cluster of short options
    /// like `-abc`; the value is the byte offset within that argv element.
    short_option_offset: usize,
    /// All options and their consumed arguments live *before* this index.
    positional_offset: usize,
    /// `true` after `--` or an option flagged STOPS_PARSING.
    parsing_stopped: bool,
}

impl OptionParser {
    /// Create a fresh parser.
    pub fn new() -> Self {
        Self::default()
    }
}

// ── argv manipulation helpers ─────────────────────────────────────────────

/// Remove the element at `index`, shifting subsequent elements left.
fn kill_arg(argv: &mut Vec<String>, index: usize) {
    assert!(index < argv.len(), "kill_arg: index out of bounds");
    argv.remove(index);
}

/// Move `argv[source]` to position `target`, shifting everything between
/// one slot to the right.
fn shift_arg(argv: &mut Vec<String>, target: usize, source: usize) {
    assert!(target <= source, "shift_arg: target must be <= source");
    let val = argv.remove(source);
    argv.insert(target, val);
}

// ── Prefix matching ──────────────────────────────────────────────────────

/// Given a long option token (e.g. `"--verb"`), collect all defined long
/// options whose name starts with the same prefix (after stripping `--`).
fn find_long_option<'a>(
    options: &'a [OptionSpec<'a>],
    optname: &str,
) -> Result<&'a OptionSpec<'a>, OptionParseError> {
    let needle = optname.strip_prefix("--").unwrap_or(optname);

    let mut exact: Option<&OptionSpec<'a>> = None;
    let mut partials: Vec<&OptionSpec<'a>> = Vec::new();

    for opt in options {
        if option_is_metadata(opt) {
            continue;
        }
        let Some(long_name) = opt.long_code else {
            continue;
        };
        let Some(rest) = long_name.strip_prefix(needle) else {
            continue;
        };
        if rest.is_empty() {
            exact = Some(opt);
            break; // exact match wins immediately
        }
        partials.push(opt);
    }

    if let Some(opt) = exact {
        return Ok(opt);
    }

    match partials.len() {
        0 => Err(OptionParseError::Unrecognized {
            optname: optname.to_owned(),
        }),
        1 => Ok(partials[0]),
        _ => {
            let candidates = partials
                .iter()
                .filter_map(|o| o.long_code.map(|lc| format!("--{}", lc)))
                .collect();
            Err(OptionParseError::Ambiguous {
                optname: optname.to_owned(),
                candidates,
            })
        }
    }
}

/// Given a short option character, find the matching definition.
fn find_short_option<'a>(
    options: &'a [OptionSpec<'a>],
    optchar: char,
) -> Result<&'a OptionSpec<'a>, OptionParseError> {
    for opt in options {
        if !option_is_metadata(opt) && opt.short_code == Some(optchar) {
            return Ok(opt);
        }
    }
    Err(OptionParseError::Unrecognized {
        optname: format!("-{}", optchar),
    })
}

// ── Main parse function ──────────────────────────────────────────────────

/// Parse the **next** option from `argv`, mutating parser state in place.
///
/// Returns:
/// * `Ok(Some(ParsedOption))` — an option was matched.
/// * `Ok(None)` — no more options (end-of-options marker or positional args).
/// * `Err(OptionParseError)` — a usage error.
///
/// On success the caller should call again until `Ok(None)` is returned.
pub fn option_parse<'a>(
    options: &'a [OptionSpec<'a>],
    state: &mut OptionParser,
    argv: &mut Vec<String>,
) -> Result<Option<ParsedOption<'a>>, OptionParseError> {
    // ── Initialisation ────────────────────────────────────────────────
    if state.optind == 0 {
        if argv.is_empty() {
            return Err(OptionParseError::EmptyArgv);
        }
        state.optind = 1;
        state.positional_offset = 1;
    }

    let mut optname_owned: Option<String> = None; // allocated name (short opts)
    let mut optval: Option<String> = None;
    let mut separate_optval = false;
    let option: &OptionSpec<'a>;

    if state.short_option_offset == 0 {
        // ── Skip non-option parameters ────────────────────────────────
        loop {
            if state.optind >= argv.len() {
                return Ok(None);
            }

            if argv[state.optind] == "--" {
                kill_arg(argv, state.optind);
                return Ok(None);
            }

            if state.parsing_stopped {
                return Ok(None);
            }

            let arg = &argv[state.optind];
            if arg.starts_with('-') && arg.len() > 1 {
                break; // found an option
            }

            state.optind += 1;
        }

        let arg_bytes = argv[state.optind].as_bytes();
        assert!(arg_bytes[0] == b'-');

        if arg_bytes.len() > 1 && arg_bytes[1] == b'-' {
            // ── Long option ────────────────────────────────────────────
            let arg = &argv[state.optind];

            let (name_part, inline_val) = if let Some(eq_pos) = arg.find('=') {
                (arg[..eq_pos].to_owned(), Some(arg[eq_pos + 1..].to_owned()))
            } else {
                (arg.clone(), None)
            };

            optname_owned = Some(name_part.clone());
            optval = inline_val;

            option = find_long_option(options, &name_part)?;
        } else {
            // ── Begin short-option cluster ─────────────────────────────
            state.short_option_offset = 1;
            // fall through to the short-option handling below
            option = process_short(options, state, argv, &mut optname_owned, &mut optval)?;
        }
    } else {
        // ── Continuing a short-option cluster ──────────────────────────
        option = process_short(options, state, argv, &mut optname_owned, &mut optval)?;
    }

    let display_name = optname_owned
        .as_deref()
        // Use the long spelling when a short-option cluster has no owned
        // display name; it is only a best-effort diagnostic.
        .or(option.long_code)
        .unwrap_or("?");

    // ── Validate argument presence ────────────────────────────────────
    if optval.is_some() && !option_takes_arg(option) {
        return Err(OptionParseError::UnexpectedArg {
            optname: display_name.to_owned(),
        });
    }
    if optval.is_none() && option_arg_required(option) {
        if state.optind + 1 >= argv.len() || argv[state.optind + 1].starts_with('-') {
            return Err(OptionParseError::MissingArg {
                optname: display_name.to_owned(),
            });
        }
        optval = Some(argv[state.optind + 1].clone());
        separate_optval = true;
    }

    // ── Reorder argv: move consumed elements to the left ──────────────
    if state.short_option_offset == 0 {
        shift_arg(argv, state.positional_offset, state.optind);
        state.optind += 1;
        state.positional_offset += 1;

        if separate_optval {
            // optind was shifted along with the option above, so the value
            // is still at optind.
            shift_arg(argv, state.positional_offset, state.optind);
            state.optind += 1;
            state.positional_offset += 1;
        }
    }

    // ── Handle STOPS_PARSING ──────────────────────────────────────────
    if option.flags.contains(OptionFlags::STOPS_PARSING) {
        state.parsing_stopped = true;
    }

    Ok(Some(ParsedOption {
        id: option.id,
        option,
        arg: optval,
    }))
}

/// Handle the current short option within a cluster.
fn process_short<'a>(
    options: &'a [OptionSpec<'a>],
    state: &mut OptionParser,
    argv: &[String],
    optname_out: &mut Option<String>,
    optval_out: &mut Option<String>,
) -> Result<&'a OptionSpec<'a>, OptionParseError> {
    let arg = argv[state.optind].as_bytes();
    let offset = state.short_option_offset;
    let optchar = arg[offset] as char;

    *optname_out = Some(format!("-{}", optchar));

    let option = find_short_option(options, optchar)?;

    let rest_start = offset + 1;
    let rest = if rest_start < arg.len() {
        Some(&argv[state.optind][rest_start..])
    } else {
        None
    };

    if option_takes_arg(option) && rest.is_some() && !rest.unwrap().is_empty() {
        // The rest of this parameter is the value.
        *optval_out = rest.map(|s| s.to_owned());
        state.short_option_offset = 0;
    } else if rest.is_none() || rest.unwrap().is_empty() {
        state.short_option_offset = 0;
    } else {
        state.short_option_offset += 1;
    }

    Ok(option)
}

// ── Positional args accessor ─────────────────────────────────────────────

/// Return the positional arguments that remain after all options have been
/// consumed.  The `--` end-of-options marker (if present) will already have
/// been removed from the vector.
///
/// # Panics
/// Panics if called before parsing has started.
pub fn option_parser_get_args<'a>(state: &'a OptionParser, argv: &'a [String]) -> &'a [String] {
    assert!(
        state.optind > 0,
        "option_parser_get_args: parser not initialised"
    );
    &argv[state.positional_offset..]
}

// ── Help-table generation ────────────────────────────────────────────────

/// A single row in the generated help table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelpEntry {
    /// Option string shown to the user, e.g. `"  -h --help"`.
    pub names: String,
    /// Wrapped help text.
    pub help: String,
}

/// Build a list of [`HelpEntry`] items for the options that belong to
/// `group`. Pass `None` for `group` to get the default (first) group.
pub fn option_parser_get_help_table<'a>(
    options: &'a [OptionSpec<'a>],
    group: Option<&str>,
) -> Vec<HelpEntry> {
    let mut entries = Vec::new();
    let mut in_group = group.is_none(); // default group is the initial section

    for opt in options {
        let is_marker = opt.flags.contains(OptionFlags::GROUP_MARKER);

        if !in_group {
            if is_marker && opt.long_code == group {
                in_group = true;
            }
            continue;
        }
        if is_marker {
            break;
        }

        let Some(help) = opt.help else { continue };

        // Build the short-code fragment.
        let short_part = match opt.short_code {
            Some(c) => format!("-{}", c),
            None => "  ".to_owned(),
        };

        // Determine if we need an "=" between long option and metavar.
        let need_eq = option_takes_arg(opt) && opt.long_code.is_some();
        let optional = option_arg_optional(opt);

        let long_part = match opt.long_code {
            Some(lc) => format!("--{}", lc),
            None => String::new(),
        };
        let metavar_part = opt.metavar.unwrap_or("");

        let names = format!(
            "  {} {}{}{}{}{}{}",
            short_part,
            long_part,
            if optional { "[" } else { "" },
            if need_eq { "=" } else { "" },
            metavar_part,
            if optional { "]" } else { "" },
            "",
        );

        entries.push(HelpEntry {
            names,
            help: help.to_owned(),
        });
    }

    entries
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a simple option table.
    fn sample_options() -> Vec<OptionSpec<'static>> {
        vec![
            OptionSpec {
                id: 1,
                flags: OptionFlags::empty(),
                short_code: Some('h'),
                long_code: Some("help"),
                metavar: None,
                help: Some("Show help"),
            },
            OptionSpec {
                id: 2,
                flags: OptionFlags::empty(),
                short_code: Some('v'),
                long_code: Some("verbose"),
                metavar: None,
                help: Some("Be verbose"),
            },
            OptionSpec {
                id: 3,
                flags: OptionFlags::empty(),
                short_code: Some('o'),
                long_code: Some("output"),
                metavar: Some("FILE"),
                help: Some("Output file"),
            },
            OptionSpec {
                id: 4,
                flags: OptionFlags::OPTIONAL_ARG,
                short_code: Some('j'),
                long_code: Some("json"),
                metavar: Some("FORMAT"),
                help: Some("JSON output"),
            },
            OptionSpec {
                id: 5,
                flags: OptionFlags::STOPS_PARSING,
                short_code: None,
                long_code: Some("stop"),
                metavar: None,
                help: None,
            },
        ]
    }

    #[test]
    fn test_option_takes_arg() {
        let opts = sample_options();
        assert!(!option_takes_arg(&opts[0])); // help — no metavar
        assert!(option_takes_arg(&opts[2])); // output — has metavar
    }

    #[test]
    fn test_option_arg_optional_and_required() {
        let opts = sample_options();
        // output: metavar present, OPTIONAL_ARG not set → required
        assert!(option_arg_required(&opts[2]));
        assert!(!option_arg_optional(&opts[2]));

        // json: metavar present, OPTIONAL_ARG set → optional
        assert!(option_arg_optional(&opts[3]));
        assert!(!option_arg_required(&opts[3]));

        // help: no metavar → neither
        assert!(!option_arg_required(&opts[0]));
        assert!(!option_arg_optional(&opts[0]));
    }

    #[test]
    fn test_option_is_metadata() {
        let marker = OptionSpec {
            id: 0,
            flags: OptionFlags::GROUP_MARKER,
            short_code: None,
            long_code: Some("group"),
            metavar: None,
            help: None,
        };
        let help_entry = OptionSpec {
            id: 0,
            flags: OptionFlags::HELP_ENTRY,
            short_code: None,
            long_code: None,
            metavar: None,
            help: None,
        };
        let normal = OptionSpec {
            id: 1,
            flags: OptionFlags::empty(),
            short_code: Some('a'),
            long_code: Some("all"),
            metavar: None,
            help: Some("Do all"),
        };

        assert!(option_is_metadata(&marker));
        assert!(option_is_metadata(&help_entry));
        assert!(!option_is_metadata(&normal));
    }

    #[test]
    fn test_parse_long_exact() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "--help".to_owned()];

        let result = option_parse(&opts, &mut state, &mut argv).unwrap().unwrap();
        assert_eq!(result.id, 1);
        assert!(result.arg.is_none());
    }

    #[test]
    fn test_parse_long_with_value() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "--output=file.txt".to_owned()];

        let result = option_parse(&opts, &mut state, &mut argv).unwrap().unwrap();
        assert_eq!(result.id, 3);
        assert_eq!(result.arg.as_deref(), Some("file.txt"));
    }

    #[test]
    fn test_parse_long_prefix_match() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "--verb".to_owned()]; // matches "verbose"

        let result = option_parse(&opts, &mut state, &mut argv).unwrap().unwrap();
        assert_eq!(result.id, 2);
    }

    #[test]
    fn test_parse_long_ambiguous() {
        // Add two options that share a prefix: --version and --verbose
        let opts = vec![
            OptionSpec {
                id: 1,
                flags: OptionFlags::empty(),
                short_code: Some('v'),
                long_code: Some("verbose"),
                metavar: None,
                help: None,
            },
            OptionSpec {
                id: 2,
                flags: OptionFlags::empty(),
                short_code: None,
                long_code: Some("version"),
                metavar: None,
                help: None,
            },
        ];
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "--ver".to_owned()];

        let err = option_parse(&opts, &mut state, &mut argv).unwrap_err();
        match err {
            OptionParseError::Ambiguous { candidates, .. } => {
                assert_eq!(candidates.len(), 2);
            }
            _ => panic!("expected Ambiguous, got {:?}", err),
        }
    }

    #[test]
    fn test_parse_short_with_joined_value() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "-ofile.txt".to_owned()];

        let result = option_parse(&opts, &mut state, &mut argv).unwrap().unwrap();
        assert_eq!(result.id, 3);
        assert_eq!(result.arg.as_deref(), Some("file.txt"));
    }

    #[test]
    fn test_parse_short_cluster() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "-hv".to_owned()];

        let r1 = option_parse(&opts, &mut state, &mut argv).unwrap().unwrap();
        assert_eq!(r1.id, 1); // -h

        let r2 = option_parse(&opts, &mut state, &mut argv).unwrap().unwrap();
        assert_eq!(r2.id, 2); // -v
    }

    #[test]
    fn test_parse_unrecognized_long() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "--bogus".to_owned()];

        let err = option_parse(&opts, &mut state, &mut argv).unwrap_err();
        assert!(matches!(err, OptionParseError::Unrecognized { .. }));
    }

    #[test]
    fn test_parse_unexpected_arg() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        // --help does not take an argument
        let mut argv = vec!["prog".to_owned(), "--help=yes".to_owned()];

        let err = option_parse(&opts, &mut state, &mut argv).unwrap_err();
        assert!(matches!(err, OptionParseError::UnexpectedArg { .. }));
    }

    #[test]
    fn test_parse_required_arg_separate() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec![
            "prog".to_owned(),
            "--output".to_owned(),
            "file.txt".to_owned(),
        ];

        let result = option_parse(&opts, &mut state, &mut argv).unwrap().unwrap();
        assert_eq!(result.id, 3);
        assert_eq!(result.arg.as_deref(), Some("file.txt"));
    }

    #[test]
    fn test_parse_missing_required_arg() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        // --output requires FILE but nothing follows
        let mut argv = vec!["prog".to_owned(), "--output".to_owned()];

        let err = option_parse(&opts, &mut state, &mut argv).unwrap_err();
        assert!(matches!(err, OptionParseError::MissingArg { .. }));
    }

    #[test]
    fn test_parse_double_dash_stops() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "--".to_owned(), "positional".to_owned()];

        let result = option_parse(&opts, &mut state, &mut argv);
        assert!(result.unwrap().is_none());
        // "--" should have been removed
        assert!(!argv.contains(&"--".to_owned()));
    }

    #[test]
    fn test_parse_positional_args() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec![
            "prog".to_owned(),
            "first".to_owned(),
            "--help".to_owned(),
            "second".to_owned(),
        ];

        // Consume the option
        let _ = option_parse(&opts, &mut state, &mut argv).unwrap();

        // After one parse call we haven't consumed all positional args yet,
        // but let's verify the next call returns None (no more options).
        let next = option_parse(&opts, &mut state, &mut argv).unwrap();
        assert!(next.is_none());

        // Positional args should be accessible
        let pos = option_parser_get_args(&state, &argv);
        assert!(pos.contains(&"first".to_owned()));
        assert!(pos.contains(&"second".to_owned()));
    }

    #[test]
    fn test_stops_parsing_flag() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv = vec!["prog".to_owned(), "--stop".to_owned(), "--help".to_owned()];

        let r1 = option_parse(&opts, &mut state, &mut argv).unwrap().unwrap();
        assert_eq!(r1.id, 5);
        assert!(state.parsing_stopped);

        // Further calls should return None
        let r2 = option_parse(&opts, &mut state, &mut argv).unwrap();
        assert!(r2.is_none());
    }

    #[test]
    fn test_empty_argv_error() {
        let opts = sample_options();
        let mut state = OptionParser::new();
        let mut argv: Vec<String> = vec![];

        let err = option_parse(&opts, &mut state, &mut argv).unwrap_err();
        assert!(matches!(err, OptionParseError::EmptyArgv));
    }

    #[test]
    fn test_help_table_default_group() {
        let opts = vec![
            OptionSpec {
                id: 1,
                flags: OptionFlags::empty(),
                short_code: Some('h'),
                long_code: Some("help"),
                metavar: None,
                help: Some("Show help"),
            },
            OptionSpec {
                id: 2,
                flags: OptionFlags::GROUP_MARKER,
                short_code: None,
                long_code: Some("advanced"),
                metavar: None,
                help: None,
            },
            OptionSpec {
                id: 3,
                flags: OptionFlags::empty(),
                short_code: Some('D'),
                long_code: Some("debug"),
                metavar: None,
                help: Some("Enable debug"),
            },
        ];

        // Default group: only the first option
        let table = option_parser_get_help_table(&opts, None);
        assert_eq!(table.len(), 1);
        assert!(table[0].names.contains("--help"));
    }

    #[test]
    fn test_help_table_named_group() {
        let opts = vec![
            OptionSpec {
                id: 1,
                flags: OptionFlags::empty(),
                short_code: Some('h'),
                long_code: Some("help"),
                metavar: None,
                help: Some("Show help"),
            },
            OptionSpec {
                id: 2,
                flags: OptionFlags::GROUP_MARKER,
                short_code: None,
                long_code: Some("advanced"),
                metavar: None,
                help: None,
            },
            OptionSpec {
                id: 3,
                flags: OptionFlags::empty(),
                short_code: Some('D'),
                long_code: Some("debug"),
                metavar: None,
                help: Some("Enable debug"),
            },
        ];

        let table = option_parser_get_help_table(&opts, Some("advanced"));
        assert_eq!(table.len(), 1);
        assert!(table[0].names.contains("--debug"));
    }

    #[test]
    fn test_help_table_optional_arg_formatting() {
        let opts = vec![OptionSpec {
            id: 1,
            flags: OptionFlags::OPTIONAL_ARG,
            short_code: Some('j'),
            long_code: Some("json"),
            metavar: Some("FORMAT"),
            help: Some("JSON output"),
        }];

        let table = option_parser_get_help_table(&opts, None);
        assert_eq!(table.len(), 1);
        // Should contain square brackets for optional arg
        assert!(table[0].names.contains('['));
        assert!(table[0].names.contains(']'));
        assert!(table[0].names.contains("FORMAT"));
    }

    #[test]
    fn test_error_display() {
        let e = OptionParseError::Unrecognized {
            optname: "--foo".to_owned(),
        };
        assert!(e.to_string().contains("--foo"));

        let e = OptionParseError::Ambiguous {
            optname: "--ver".to_owned(),
            candidates: vec!["--verbose".to_owned(), "--version".to_owned()],
        };
        let msg = e.to_string();
        assert!(msg.contains("--ver"));
        assert!(msg.contains("--verbose"));
        assert!(msg.contains("--version"));
    }
}
