// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/volatile-util.c, src/shared/volatile-util.h
//
// Volatile mode utilities for root filesystem configuration.
//
// Supports querying the kernel command line for the systemd.volatile
// parameter and converting between volatile mode enum values and
// their string representations. The WITH_BOOLEAN variant of the C
// string table lookup is faithfully reproduced: "true"/"on"/"1" map
// to Yes, while "false"/"off"/"0" map to No.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

// ── Constants ─────────────────────────────────────────────────────────────

/// Kernel command line parameter name for volatile mode.
const CMDLINE_KEY: &str = "systemd.volatile";

/// Path to the kernel command line (Linux only).
const PROC_CMDLINE_PATH: &str = "/proc/cmdline";

// ── Error types ───────────────────────────────────────────────────────────

/// Errors returned by volatile mode operations.
#[derive(Debug)]
pub enum VolatileError {
    /// An I/O error occurred (e.g., reading /proc/cmdline).
    Io(io::Error),
    /// The mode string found on the command line is not a valid volatile mode.
    InvalidMode(String),
}

impl std::fmt::Display for VolatileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolatileError::Io(e) => write!(f, "I/O error: {}", e),
            VolatileError::InvalidMode(s) => {
                write!(f, "invalid volatile mode: {:?}", s)
            }
        }
    }
}

impl std::error::Error for VolatileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VolatileError::Io(e) => Some(e),
            VolatileError::InvalidMode(_) => None,
        }
    }
}

impl From<io::Error> for VolatileError {
    fn from(e: io::Error) -> Self {
        VolatileError::Io(e)
    }
}

// ── Enums ─────────────────────────────────────────────────────────────────

/// Volatile mode for the root filesystem.
///
/// Controls whether and how the root filesystem is made volatile
/// (i.e., changes are not persisted across reboots).
///
/// Corresponds to `VolatileMode` in `src/shared/volatile-util.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VolatileMode {
    /// No volatile mode — standard persistent root filesystem.
    No,
    /// Full volatile mode — tmpfs overlay on the entire root.
    Yes,
    /// State volatile mode — only `/var` and `/home` are persistent.
    State,
    /// Overlay volatile mode — overlayfs is used for the root.
    Overlay,
}

impl VolatileMode {
    /// All valid volatile mode variants, in enum declaration order.
    pub const ALL: [VolatileMode; 4] = [
        VolatileMode::No,
        VolatileMode::Yes,
        VolatileMode::State,
        VolatileMode::Overlay,
    ];

    /// Total number of valid volatile mode variants.
    pub const COUNT: usize = 4;

    /// Sentinel value equivalent to `-EINVAL` for invalid modes.
    pub const INVALID: i32 = -22;

    /// Convert a volatile mode to its canonical string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(VolatileMode::No.to_str(), Some("no"));
    /// assert_eq!(VolatileMode::Overlay.to_str(), Some("overlay"));
    /// ```
    pub const fn to_str(self) -> &'static str {
        match self {
            VolatileMode::No => "no",
            VolatileMode::Yes => "yes",
            VolatileMode::State => "state",
            VolatileMode::Overlay => "overlay",
        }
    }

    /// Parse a volatile mode from its string representation.
    ///
    /// Accepts canonical names (`"no"`, `"yes"`, `"state"`, `"overlay"`)
    /// as well as boolean shorthands accepted by the
    /// `DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN` C macro:
    ///
    /// - `"true"`, `"on"`, `"1"` → [`VolatileMode::Yes`]
    /// - `"false"`, `"off"`, `"0"` → [`VolatileMode::No`]
    ///
    /// Returns `Err(VolatileError::InvalidMode)` for unrecognized strings.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(VolatileMode::from_str("state"), Ok(VolatileMode::State));
    /// assert_eq!(VolatileMode::from_str("true"), Ok(VolatileMode::Yes));
    /// assert_eq!(VolatileMode::from_str("0"), Ok(VolatileMode::No));
    /// assert!(VolatileMode::from_str("bogus").is_err());
    /// ```
    pub fn from_str(s: &str) -> Result<VolatileMode, VolatileError> {
        // First pass: exact string-table lookup (matches the C volatile_mode_table).
        match s {
            "no" => return Ok(VolatileMode::No),
            "yes" => return Ok(VolatileMode::Yes),
            "state" => return Ok(VolatileMode::State),
            "overlay" => return Ok(VolatileMode::Overlay),
            _ => {}
        }

        // Second pass: boolean shorthand (DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN).
        // parse_boolean() in systemd accepts these for true:  yes/true/on/1
        //                                   and for false: no/false/off/0
        // "no" and "yes" are already handled above, so only the extras remain.
        match s {
            "true" | "on" | "1" => Ok(VolatileMode::Yes),
            "false" | "off" | "0" => Ok(VolatileMode::No),
            _ => Err(VolatileError::InvalidMode(s.to_owned())),
        }
    }

    /// `true` if this variant is the boolean-true representative.
    ///
    /// In the C macro, `VOLATILE_YES` is passed as the boolean_value
    /// argument to `DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN`.
    pub const fn is_boolean_true(self) -> bool {
        matches!(self, VolatileMode::Yes)
    }

    /// `true` if this variant is the boolean-false representative.
    ///
    /// In the C macro, the first enum variant (`VOLATILE_NO`, i.e. 0)
    /// serves as the false value.
    pub const fn is_boolean_false(self) -> bool {
        matches!(self, VolatileMode::No)
    }

    /// Integer discriminant matching the C enum values.
    ///
    /// | Variant  | Value |
    /// |----------|-------|
    /// | `No`     | 0     |
    /// | `Yes`    | 1     |
    /// | `State`  | 2     |
    /// | `Overlay`| 3     |
    pub const fn discriminant(self) -> i32 {
        self as i32
    }
}

impl std::fmt::Display for VolatileMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

impl std::str::FromStr for VolatileMode {
    type Err = VolatileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        VolatileMode::from_str(s)
    }
}

// ── Query result ──────────────────────────────────────────────────────────

/// Describes whether the `systemd.volatile` key was found on the kernel
/// command line and, if so, which mode was resolved.
///
/// Mirrors the tri-state return convention of the C `query_volatile_mode()`:
///
/// | C return | Rust variant                | Meaning                         |
/// |----------|-----------------------------|---------------------------------|
/// | `0`      | `NotFound`                  | Key absent → defaults to `No`   |
/// | `1`      | `Found(mode)`               | Key present with resolved mode  |
/// | `< 0`    | `Err(VolatileError::…)`     | I/O or parse error              |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolatileModeQuery {
    /// The `systemd.volatile` key was **not** found on the kernel command line.
    /// Callers should default to [`VolatileMode::No`].
    NotFound,
    /// The `systemd.volatile` key was found; `mode` is the resolved value.
    Found(VolatileMode),
}

impl VolatileModeQuery {
    /// Resolve to the effective [`VolatileMode`], defaulting to `No` when
    /// the key was not present.
    pub const fn mode(self) -> VolatileMode {
        match self {
            VolatileModeQuery::NotFound => VolatileMode::No,
            VolatileModeQuery::Found(m) => m,
        }
    }
}

// ── Kernel command-line parsing ──────────────────────────────────────────

/// A single token extracted from the kernel command line.
struct CmdlineToken {
    key: String,
    value: Option<String>,
}

/// Tokenise a kernel command line into key/value pairs.
///
/// Handles space-separated tokens, `key=value` pairs, and double-quoted
/// values (with `\"` escape inside quotes). Unquoted values extend to the
/// next whitespace boundary.
fn tokenize_cmdline(cmdline: &str) -> Vec<CmdlineToken> {
    let mut tokens = Vec::new();
    let mut chars = cmdline.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }

        // Read key (up to '=' or whitespace).
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() {
                break;
            }
            key.push(c);
            chars.next();
        }

        if key.is_empty() {
            chars.next();
            continue;
        }

        if chars.peek() == Some(&'=') {
            chars.next(); // consume '='

            let value = if chars.peek() == Some(&'"') {
                // Double-quoted value.
                chars.next(); // consume opening '"'
                let mut v = String::new();
                loop {
                    match chars.next() {
                        Some('\\') if chars.peek() == Some(&'"') => {
                            v.push('"');
                            chars.next();
                        }
                        Some('\\') => {
                            v.push('\\');
                        }
                        Some('"') => break,
                        Some(c) => v.push(c),
                        None => break,
                    }
                }
                v
            } else {
                // Unquoted value.
                let mut v = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        break;
                    }
                    v.push(c);
                    chars.next();
                }
                v
            };

            tokens.push(CmdlineToken {
                key,
                value: Some(value),
            });
        } else {
            tokens.push(CmdlineToken { key, value: None });
        }
    }

    tokens
}

/// Result of searching the kernel command line for a specific key.
#[derive(Debug, PartialEq, Eq)]
enum CmdlineKeyResult {
    /// The key was not present.
    NotFound,
    /// The key was present without a value.
    FoundWithoutValue,
    /// The key was present with the given value.
    FoundWithValue(String),
}

/// Search a tokenised kernel command line for `key`.
///
/// Returns the **first** matching occurrence, matching the C
/// `proc_cmdline_get_key()` behaviour.
fn find_cmdline_key(tokens: &[CmdlineToken], key: &str) -> CmdlineKeyResult {
    for token in tokens {
        if token.key == key {
            return match &token.value {
                None => CmdlineKeyResult::FoundWithoutValue,
                Some(v) => CmdlineKeyResult::FoundWithValue(v.clone()),
            };
        }
    }
    CmdlineKeyResult::NotFound
}

// ── Public API ────────────────────────────────────────────────────────────

/// Query the volatile mode from a kernel command-line string.
///
/// This is the pure-logic counterpart of [`query_volatile_mode()`] and is
/// useful for testing or for callers that already have the command line in
/// memory.
///
/// # Behaviour (faithful to the C implementation)
///
/// * If `systemd.volatile` is **absent** → returns `Ok(VolatileModeQuery::NotFound)`.
/// * If `systemd.volatile` is present **without a value** → returns
///   `Ok(VolatileModeQuery::Found(VolatileMode::Yes))`.
/// * If `systemd.volatile` has a **value** → the value is parsed via
///   [`VolatileMode::from_str`]. On success returns
///   `Ok(VolatileModeQuery::Found(mode))`; on failure returns
///   `Err(VolatileError::InvalidMode(…))`.
pub fn query_volatile_mode_from_cmdline(cmdline: &str) -> Result<VolatileModeQuery, VolatileError> {
    let tokens = tokenize_cmdline(cmdline);

    match find_cmdline_key(&tokens, CMDLINE_KEY) {
        CmdlineKeyResult::NotFound => Ok(VolatileModeQuery::NotFound),

        CmdlineKeyResult::FoundWithoutValue => Ok(VolatileModeQuery::Found(VolatileMode::Yes)),

        CmdlineKeyResult::FoundWithValue(ref value) => {
            let mode = VolatileMode::from_str(value)
                .map_err(|_| VolatileError::InvalidMode(value.clone()))?;
            Ok(VolatileModeQuery::Found(mode))
        }
    }
}

/// Query the volatile mode from the live kernel command line.
///
/// Reads `/proc/cmdline` and delegates to
/// [`query_volatile_mode_from_cmdline()`].
///
/// # Errors
///
/// Returns `Err(VolatileError::Io(…))` if `/proc/cmdline` cannot be read.
pub fn query_volatile_mode() -> Result<VolatileModeQuery, VolatileError> {
    let cmdline = fs::read_to_string(PROC_CMDLINE_PATH)?;
    query_volatile_mode_from_cmdline(&cmdline)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── VolatileMode::to_str ───────────────────────────────────────────

    #[test]
    fn test_to_str_no() {
        assert_eq!(VolatileMode::No.to_str(), "no");
    }

    #[test]
    fn test_to_str_yes() {
        assert_eq!(VolatileMode::Yes.to_str(), "yes");
    }

    #[test]
    fn test_to_str_state() {
        assert_eq!(VolatileMode::State.to_str(), "state");
    }

    #[test]
    fn test_to_str_overlay() {
        assert_eq!(VolatileMode::Overlay.to_str(), "overlay");
    }

    // ── VolatileMode::from_str (canonical names) ───────────────────────

    #[test]
    fn test_from_str_canonical_names() {
        assert_eq!(VolatileMode::from_str("no").unwrap(), VolatileMode::No);
        assert_eq!(VolatileMode::from_str("yes").unwrap(), VolatileMode::Yes);
        assert_eq!(
            VolatileMode::from_str("state").unwrap(),
            VolatileMode::State
        );
        assert_eq!(
            VolatileMode::from_str("overlay").unwrap(),
            VolatileMode::Overlay
        );
    }

    // ── VolatileMode::from_str (boolean shorthands — WITH_BOOLEAN) ────

    #[test]
    fn test_from_str_boolean_true_variants() {
        // These map to VOLATILE_YES via parse_boolean() in the C code.
        assert_eq!(VolatileMode::from_str("true").unwrap(), VolatileMode::Yes);
        assert_eq!(VolatileMode::from_str("on").unwrap(), VolatileMode::Yes);
        assert_eq!(VolatileMode::from_str("1").unwrap(), VolatileMode::Yes);
    }

    #[test]
    fn test_from_str_boolean_false_variants() {
        // These map to VOLATILE_NO (index 0) via parse_boolean().
        assert_eq!(VolatileMode::from_str("false").unwrap(), VolatileMode::No);
        assert_eq!(VolatileMode::from_str("off").unwrap(), VolatileMode::No);
        assert_eq!(VolatileMode::from_str("0").unwrap(), VolatileMode::No);
    }

    #[test]
    fn test_from_str_invalid() {
        assert!(VolatileMode::from_str("").is_err());
        assert!(VolatileMode::from_str("bogus").is_err());
        assert!(VolatileMode::from_str("YES").is_err()); // case-sensitive
        assert!(VolatileMode::from_str("State").is_err());
        assert!(VolatileMode::from_str("maybe").is_err());
    }

    // ── Roundtrip ──────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip() {
        for mode in VolatileMode::ALL {
            let s = mode.to_str();
            assert_eq!(
                VolatileMode::from_str(s).unwrap(),
                mode,
                "roundtrip failed for {:?}",
                mode
            );
        }
    }

    // ── Trait implementations ──────────────────────────────────────────

    #[test]
    fn test_display_trait() {
        assert_eq!(format!("{}", VolatileMode::No), "no");
        assert_eq!(format!("{}", VolatileMode::Yes), "yes");
        assert_eq!(format!("{}", VolatileMode::State), "state");
        assert_eq!(format!("{}", VolatileMode::Overlay), "overlay");
    }

    #[test]
    fn test_from_str_trait() {
        use std::str::FromStr;
        assert_eq!(
            VolatileMode::from_str("state").unwrap(),
            VolatileMode::State
        );
        assert_eq!(
            VolatileMode::from_str("overlay").unwrap(),
            VolatileMode::Overlay
        );
        assert!(VolatileMode::from_str("nope").is_err());
    }

    #[test]
    fn test_debug_trait() {
        let debug = format!("{:?}", VolatileMode::State);
        assert!(debug.contains("State"));
    }

    // ── Constants and predicates ───────────────────────────────────────

    #[test]
    fn test_all_const() {
        assert_eq!(VolatileMode::ALL.len(), VolatileMode::COUNT);
        assert_eq!(VolatileMode::ALL[0], VolatileMode::No);
        assert_eq!(VolatileMode::ALL[3], VolatileMode::Overlay);
    }

    #[test]
    fn test_count_const() {
        assert_eq!(VolatileMode::COUNT, 4);
    }

    #[test]
    fn test_is_boolean_true() {
        assert!(VolatileMode::Yes.is_boolean_true());
        assert!(!VolatileMode::No.is_boolean_true());
        assert!(!VolatileMode::State.is_boolean_true());
        assert!(!VolatileMode::Overlay.is_boolean_true());
    }

    #[test]
    fn test_is_boolean_false() {
        assert!(VolatileMode::No.is_boolean_false());
        assert!(!VolatileMode::Yes.is_boolean_false());
        assert!(!VolatileMode::State.is_boolean_false());
        assert!(!VolatileMode::Overlay.is_boolean_false());
    }

    #[test]
    fn test_discriminant() {
        assert_eq!(VolatileMode::No.discriminant(), 0);
        assert_eq!(VolatileMode::Yes.discriminant(), 1);
        assert_eq!(VolatileMode::State.discriminant(), 2);
        assert_eq!(VolatileMode::Overlay.discriminant(), 3);
    }

    #[test]
    fn test_equality_and_ordering() {
        assert_eq!(VolatileMode::No, VolatileMode::No);
        assert!(VolatileMode::Yes > VolatileMode::No);
        assert!(VolatileMode::State > VolatileMode::Yes);
        assert!(VolatileMode::Overlay > VolatileMode::State);
    }

    // ── Cmdline tokenisation ───────────────────────────────────────────

    #[test]
    fn test_tokenize_empty() {
        assert!(tokenize_cmdline("").is_empty());
    }

    #[test]
    fn test_tokenize_simple_key_value() {
        let tokens = tokenize_cmdline("foo=bar");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].key, "foo");
        assert_eq!(tokens[0].value.as_deref(), Some("bar"));
    }

    #[test]
    fn test_tokenize_key_without_value() {
        let tokens = tokenize_cmdline("foo");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].key, "foo");
        assert!(tokens[0].value.is_none());
    }

    #[test]
    fn test_tokenize_multiple_tokens() {
        let tokens = tokenize_cmdline("a=1 b=2 c");
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].key, "a");
        assert_eq!(tokens[1].key, "b");
        assert_eq!(tokens[2].key, "c");
        assert!(tokens[2].value.is_none());
    }

    #[test]
    fn test_tokenize_quoted_value() {
        let tokens = tokenize_cmdline(r#"key="hello world""#);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].key, "key");
        assert_eq!(tokens[0].value.as_deref(), Some("hello world"));
    }

    #[test]
    fn test_tokenize_escaped_quote_in_value() {
        let tokens = tokenize_cmdline(r#"key="say \"hi\"""#);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].value.as_deref(), Some(r#"say "hi""#));
    }

    #[test]
    fn test_tokenize_leading_trailing_whitespace() {
        let tokens = tokenize_cmdline("  foo=bar  ");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].key, "foo");
    }

    // ── find_cmdline_key ───────────────────────────────────────────────

    #[test]
    fn test_find_cmdline_key_not_found() {
        let tokens = tokenize_cmdline("foo=bar baz=qux");
        assert!(matches!(
            find_cmdline_key(&tokens, "missing"),
            CmdlineKeyResult::NotFound
        ));
    }

    #[test]
    fn test_find_cmdline_key_without_value() {
        let tokens = tokenize_cmdline("foo bar=baz");
        assert!(matches!(
            find_cmdline_key(&tokens, "foo"),
            CmdlineKeyResult::FoundWithoutValue
        ));
    }

    #[test]
    fn test_find_cmdline_key_with_value() {
        let tokens = tokenize_cmdline("foo=hello");
        match find_cmdline_key(&tokens, "foo") {
            CmdlineKeyResult::FoundWithValue(ref v) => assert_eq!(v, "hello"),
            other => panic!("expected FoundWithValue, got {:?}", other),
        }
    }

    #[test]
    fn test_find_cmdline_key_returns_first_match() {
        let tokens = tokenize_cmdline("foo=first foo=second");
        match find_cmdline_key(&tokens, "foo") {
            CmdlineKeyResult::FoundWithValue(ref v) => {
                assert_eq!(v, "first");
            }
            other => panic!("expected FoundWithValue, got {:?}", other),
        }
    }

    #[test]
    fn test_find_cmdline_key_prefix_does_not_match() {
        let tokens = tokenize_cmdline("foo_bar=baz");
        assert!(matches!(
            find_cmdline_key(&tokens, "foo"),
            CmdlineKeyResult::NotFound
        ));
    }

    // ── query_volatile_mode_from_cmdline ───────────────────────────────

    #[test]
    fn test_query_from_cmdline_not_found() {
        let result = query_volatile_mode_from_cmdline("foo=bar quiet").unwrap();
        assert_eq!(result, VolatileModeQuery::NotFound);
        assert_eq!(result.mode(), VolatileMode::No);
    }

    #[test]
    fn test_query_from_cmdline_found_no_value() {
        let result = query_volatile_mode_from_cmdline("quiet systemd.volatile").unwrap();
        assert_eq!(result, VolatileModeQuery::Found(VolatileMode::Yes));
    }

    #[test]
    fn test_query_from_cmdline_found_with_yes() {
        let result = query_volatile_mode_from_cmdline("quiet systemd.volatile=yes").unwrap();
        assert_eq!(result, VolatileModeQuery::Found(VolatileMode::Yes));
    }

    #[test]
    fn test_query_from_cmdline_found_with_state() {
        let result = query_volatile_mode_from_cmdline("systemd.volatile=state quiet").unwrap();
        assert_eq!(result, VolatileModeQuery::Found(VolatileMode::State));
    }

    #[test]
    fn test_query_from_cmdline_found_with_overlay() {
        let result = query_volatile_mode_from_cmdline("systemd.volatile=overlay").unwrap();
        assert_eq!(result, VolatileModeQuery::Found(VolatileMode::Overlay));
    }

    #[test]
    fn test_query_from_cmdline_found_with_boolean_true() {
        let result = query_volatile_mode_from_cmdline("systemd.volatile=true").unwrap();
        assert_eq!(result, VolatileModeQuery::Found(VolatileMode::Yes));
    }

    #[test]
    fn test_query_from_cmdline_found_with_boolean_false() {
        let result = query_volatile_mode_from_cmdline("systemd.volatile=false").unwrap();
        assert_eq!(result, VolatileModeQuery::Found(VolatileMode::No));
    }

    #[test]
    fn test_query_from_cmdline_invalid_value() {
        let result = query_volatile_mode_from_cmdline("systemd.volatile=bogus");
        assert!(result.is_err());
        match result.unwrap_err() {
            VolatileError::InvalidMode(s) => assert_eq!(s, "bogus"),
            other => panic!("expected InvalidMode, got {:?}", other),
        }
    }

    #[test]
    fn test_query_from_cmdline_empty() {
        let result = query_volatile_mode_from_cmdline("").unwrap();
        assert_eq!(result, VolatileModeQuery::NotFound);
    }

    // ── VolatileModeQuery::mode() ──────────────────────────────────────

    #[test]
    fn test_query_mode_default() {
        assert_eq!(VolatileModeQuery::NotFound.mode(), VolatileMode::No);
    }

    #[test]
    fn test_query_mode_found() {
        assert_eq!(
            VolatileModeQuery::Found(VolatileMode::Overlay).mode(),
            VolatileMode::Overlay
        );
    }
}
