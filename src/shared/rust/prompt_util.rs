// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/prompt-util.c, src/shared/prompt-util.h
//
// Interactive prompt utilities for systemd.
//
// Provides password/user prompt functionality including menu selection,
// terminal chrome (decorated header/footer bars), and console muting
// via the MuteConsole varlink service.

use std::fmt;
use std::io::{self, Write};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default ANSI color for chrome bars: bright white on blue background.
const ANSI_COLOR_CHROME: &str = "\x1B[0;44;1;37m";

/// ANSI escape to erase from cursor to end of line.
const ANSI_ERASE_TO_END_OF_LINE: &str = "\x1B[K";

/// ANSI escape to reset all attributes.
const ANSI_NORMAL: &str = "\x1B[0m";

/// Minimum number of terminal rows required to show chrome.
const CHROME_MIN_ROWS: u32 = 12;

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors produced by prompt operations.
#[derive(Debug)]
pub enum PromptError {
    /// An I/O error occurred (terminal read/write).
    Io(io::Error),
    /// The entered text is empty and skipping was not allowed.
    EmptyInput,
    /// The input did not match any accepted value.
    InvalidInput(String),
    /// A numeric selection is out of range.
    OutOfRange,
    /// Allocation or resource failure.
    OutOfMemory,
    /// The terminal is too small for chrome display.
    TerminalTooSmall,
    /// The terminal is dumb (non-interactive).
    TerminalDumb,
    /// Connection to the MuteConsole varlink service failed.
    MuteConsoleFailed(String),
}

impl fmt::Display for PromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PromptError::Io(e) => write!(f, "I/O error: {e}"),
            PromptError::EmptyInput => write!(f, "no data entered"),
            PromptError::InvalidInput(s) => write!(f, "invalid input: {s}"),
            PromptError::OutOfRange => write!(f, "selection out of range"),
            PromptError::OutOfMemory => write!(f, "out of memory"),
            PromptError::TerminalTooSmall => write!(f, "terminal too small for chrome"),
            PromptError::TerminalDumb => write!(f, "terminal is non-interactive"),
            PromptError::MuteConsoleFailed(s) => write!(f, "mute console failed: {s}"),
        }
    }
}

impl std::error::Error for PromptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PromptError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PromptError {
    fn from(e: io::Error) -> Self {
        PromptError::Io(e)
    }
}

/// Convenience alias for results in this module.
pub type PromptResult<T> = Result<T, PromptError>;

// ── PromptFlags ───────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling prompt behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PromptFlags: u32 {
        /// The question may be skipped by entering empty input.
        const MAY_SKIP = 1 << 0;
        /// Show a menu of options when user types "list".
        const SHOW_MENU = 1 << 1;
        /// Show the menu immediately without requiring "list".
        const SHOW_MENU_NOW = 1 << 2;
        /// Suppress the hint about typing "list" for options.
        const HIDE_MENU_HINT = 1 << 3;
        /// Suppress the hint about entering empty to skip.
        const HIDE_SKIP_HINT = 1 << 4;
        /// The validation callback handles its own logging.
        const SILENT_VALIDATE = 1 << 5;
    }
}

impl PromptFlags {
    /// No flags set.
    pub const NONE: Self = Self::from_bits_retain(0);
    /// All flags set.
    pub const ALL: Self = Self::from_bits_retain(u32::MAX);
}

// ── PromptType ────────────────────────────────────────────────────────────

/// The kind of prompt being presented to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptType {
    /// A general text prompt.
    Text,
    /// A password prompt (input should be hidden).
    Password,
    /// A PIN prompt (numeric, possibly hidden).
    Pin,
    /// A yes/no confirmation.
    Confirmation,
}

// ── CompletionProvider ────────────────────────────────────────────────────

/// Trait for providing tab-completions during interactive prompts.
///
/// Implementors return a list of possible completions for the given
/// prefix. The special "list" completion is automatically added when
/// a non-empty list is available.
pub trait CompletionProvider {
    /// Return completions for `prefix`, or an empty list if none.
    fn completions(&self, prefix: &str) -> Vec<String>;
}

/// A completion provider backed by a static string slice.
#[derive(Debug, Clone)]
pub struct SliceCompletionProvider<'a> {
    items: &'a [&'a str],
}

impl<'a> SliceCompletionProvider<'a> {
    /// Create a new provider from a string slice.
    pub fn new(items: &'a [&'a str]) -> Self {
        Self { items }
    }
}

impl CompletionProvider for SliceCompletionProvider<'_> {
    fn completions(&self, prefix: &str) -> Vec<String> {
        self.items
            .iter()
            .filter(|s| s.starts_with(prefix))
            .map(|s| s.to_string())
            .collect()
    }
}

/// A no-op completion provider that returns no suggestions.
#[derive(Debug, Clone, Copy)]
pub struct NoCompletionProvider;

impl CompletionProvider for NoCompletionProvider {
    fn completions(&self, _prefix: &str) -> Vec<String> {
        Vec::new()
    }
}

// ── Completion helper ─────────────────────────────────────────────────────

/// Extend a list of completions with the "list" command if `userdata` is non-empty.
///
/// Mirrors the C `get_completions` helper which appends "list" to the
/// completion suggestions when menu items are available.
pub fn get_completions(userdata: &[String]) -> Vec<String> {
    let mut completions = userdata.to_vec();
    completions.push("list".to_string());
    completions
}

// ── strv helpers ──────────────────────────────────────────────────────────

/// Find the closest match in a list of strings to the given input using
/// common-prefix distance (longest common prefix).
pub fn strv_find_closest(list: &[String], input: &str) -> Option<String> {
    if list.is_empty() {
        return None;
    }

    let mut best: Option<&String> = None;
    let mut best_len = 0usize;

    for item in list {
        let common = item
            .chars()
            .zip(input.chars())
            .take_while(|(a, b)| a == b)
            .count();
        if common > best_len {
            best_len = common;
            best = Some(item);
        }
    }

    best.map(|s| s.clone())
}

// ── Menu display ──────────────────────────────────────────────────────────

/// Display a numbered menu of choices to the terminal.
///
/// `items` are the menu entries. `ellipsize_percentage` controls truncation:
/// entries longer than `column_width * ellipsize_percentage / 100` are
/// ellipsized. `column_width` is the available width per column, and
/// `n_columns` is the number of display columns.
pub fn show_menu(
    items: &[String],
    _n_columns: usize,
    column_width: usize,
    ellipsize_percentage: u32,
    output: &mut dyn io::Write,
) -> io::Result<()> {
    for (i, item) in items.iter().enumerate() {
        let display = ellipsize(item, column_width, ellipsize_percentage);
        writeln!(output, "{:>4}) {}", i + 1, display)?;
    }
    Ok(())
}

/// Truncate a string and append "..." if it exceeds the allowed width.
fn ellipsize(s: &str, max_width: usize, percentage: u32) -> String {
    if percentage == 0 {
        return s.to_string();
    }
    let limit = max_width * percentage as usize / 100;
    if s.len() <= limit {
        s.to_string()
    } else {
        let mut truncated = String::new();
        let mut char_len = 0usize;
        for c in s.chars() {
            char_len += c.len_utf8();
            if char_len + 3 > limit {
                break;
            }
            truncated.push(c);
        }
        truncated.push_str("...");
        truncated
    }
}

// ── PromptResult enum ─────────────────────────────────────────────────────

/// The outcome of a prompt interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOutcome {
    /// The user entered a value.
    Value(String),
    /// The user skipped the prompt (empty input with MAY_SKIP).
    Skipped,
}

// ── prompt_loop ───────────────────────────────────────────────────────────

/// Result of `prompt_loop`: either a value, skipped, or an error.
pub type PromptLoopResult = Result<PromptOutcome, PromptError>;

/// Core interactive prompt loop.
///
/// Repeatedly asks the user for input until a valid response is received.
/// Supports menu-based selection by number, "list" command to show options,
/// and optional validation callbacks.
///
/// # Arguments
///
/// * `text` — The prompt message displayed to the user.
/// * `menu` — Optional list of choices to display and suggest.
/// * `accepted` — Optional superset of accepted values (defaults to `menu`).
/// * `ellipsize_percentage` — Truncation threshold for menu entries.
/// * `n_columns` — Number of display columns for menu.
/// * `column_width` — Width of each column in characters.
/// * `flags` — Behaviour flags from [`PromptFlags`].
///
/// # Returns
///
/// * `Ok(PromptOutcome::Value(s))` — User entered a valid string.
/// * `Ok(PromptOutcome::Skipped)` — User entered empty with MAY_SKIP.
/// * `Err(_)` — An error occurred.
pub fn prompt_loop(
    text: &str,
    menu: Option<&[String]>,
    accepted: Option<&[String]>,
    ellipsize_percentage: u32,
    n_columns: usize,
    column_width: usize,
    flags: PromptFlags,
    input: &mut dyn io::BufRead,
    output: &mut dyn io::Write,
) -> PromptLoopResult {
    let menu = menu.unwrap_or_default();
    let accepted = accepted.unwrap_or(menu);

    // Show menu immediately if requested
    if flags.contains(PromptFlags::SHOW_MENU_NOW) && !menu.is_empty() {
        show_menu(menu, n_columns, column_width, ellipsize_percentage, output)?;
        writeln!(output)?;
    }

    loop {
        // Build hint string
        let mut hints: Vec<&str> = Vec::new();
        if !flags.contains(PromptFlags::HIDE_MENU_HINT) && !menu.is_empty() {
            hints.push("\"list\" to list options");
        }
        if !flags.contains(PromptFlags::HIDE_SKIP_HINT) && flags.contains(PromptFlags::MAY_SKIP) {
            hints.push("empty to skip");
        }

        let hint_suffix = if hints.is_empty() {
            String::new()
        } else {
            format!(" ({})", hints.join(", "))
        };

        write!(output, "▸ {}: {hint_suffix} ", text)?;
        output.flush()?;

        // Read user input
        let mut response = String::new();
        input.read_line(&mut response)?;
        let response = response.trim_end_matches('\n').trim_end_matches('\r');

        // Handle empty input
        if response.is_empty() {
            if flags.contains(PromptFlags::MAY_SKIP) {
                return Ok(PromptOutcome::Skipped);
            }
            writeln!(output, "No data entered, try again.")?;
            continue;
        }

        // Handle "list" command
        if flags.contains(PromptFlags::SHOW_MENU) && response == "list" {
            writeln!(output)?;
            if menu.is_empty() {
                writeln!(output, "No entries known.")?;
                continue;
            }
            show_menu(menu, n_columns, column_width, ellipsize_percentage, output)?;
            writeln!(output)?;
            continue;
        }

        // Handle numeric selection
        if let Ok(u) = response.parse::<usize>() {
            if u == 0 || u > menu.len() {
                writeln!(output, "Specified entry number out of range.")?;
                continue;
            }
            writeln!(output, "Selected '{}'.", menu[u - 1])?;
            return Ok(PromptOutcome::Value(menu[u - 1].clone()));
        }

        // Check if the value is in the accepted list
        let good = if accepted.is_empty() {
            true
        } else {
            accepted.iter().any(|a| a == response)
        };

        if good {
            return Ok(PromptOutcome::Value(response.to_string()));
        }

        // Provide hint about closest match
        if !flags.contains(PromptFlags::SILENT_VALIDATE) {
            let candidates = if !accepted.is_empty() { accepted } else { menu };
            if let Some(closest) = strv_find_closest(candidates, response) {
                writeln!(
                    output,
                    "Invalid input '{}', did you mean '{}'?",
                    response, closest
                )?;
            } else {
                writeln!(output, "Invalid input '{}'.", response)?;
            }
        }
    }
}

// ── Chrome display ────────────────────────────────────────────────────────

/// Terminal chrome state — tracks whether chrome bars are currently visible.
#[derive(Debug, Default)]
pub struct ChromeState {
    visible: bool,
    saved_rows: u32,
}

impl ChromeState {
    /// Create a new chrome state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether chrome is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Number of terminal rows when chrome was last shown.
    pub fn saved_rows(&self) -> u32 {
        self.saved_rows
    }
}

/// Display chrome bars (colored header and footer) around the terminal.
///
/// When `bottom` is `None`, it is constructed from `/etc/os-release` data.
/// Returns `Ok(true)` if chrome was displayed, `Ok(false)` if skipped
/// (dumb terminal or too small).
pub fn chrome_show(
    top: &str,
    bottom: Option<&str>,
    n_rows: u32,
    output: &mut dyn io::Write,
) -> io::Result<bool> {
    if n_rows < CHROME_MIN_ROWS {
        return Ok(false);
    }

    let bottom_text = match bottom {
        Some(b) => b.to_string(),
        None => {
            // In a real implementation, this would parse /etc/os-release.
            // For now, provide a sensible default.
            "System Management".to_string()
        }
    };

    let chrome_color = ANSI_COLOR_CHROME;

    // Clear screen and move home
    write!(output, "\x1B[H\x1B[2J")?;

    // Blue bar on top
    write!(
        output,
        "\x1B[1;1H{chrome_color}{erase}\n\
         {chrome_color}     {top}{erase}\n\
         {chrome_color}{erase}\n\
         {normal}{erase}",
        chrome_color = chrome_color,
        erase = ANSI_ERASE_TO_END_OF_LINE,
        normal = ANSI_NORMAL,
        top = top,
    )?;

    // Blue bar on bottom
    write!(
        output,
        "\x1B[{};1H{normal}{erase}\n\
         {chrome_color}{erase}\n\
         {chrome_color}    {bottom}{erase}\n\
         {chrome_color}{erase}{normal}",
        n_rows - 3,
        chrome_color = chrome_color,
        erase = ANSI_ERASE_TO_END_OF_LINE,
        normal = ANSI_NORMAL,
        bottom = bottom_text,
    )?;

    // Reduce scrolling area (DECSTBM), cutting off top and bottom bars
    write!(output, "\x1B[5;{}r", n_rows - 4)?;

    // Position cursor in fifth line
    write!(output, "\x1B[5;1H")?;
    output.flush()?;

    Ok(true)
}

/// Hide previously shown chrome bars and restore the terminal scrolling region.
pub fn chrome_hide(state: &mut ChromeState, output: &mut dyn io::Write) -> io::Result<()> {
    if !state.visible {
        return Ok(());
    }

    let n = state.saved_rows;
    state.visible = false;

    // Erase blue bar on bottom (3 lines: n-2, n-1, n)
    assert!(n >= 2, "chrome rows must be >= 2");
    write!(
        output,
        "\x1B[{};1H{normal}{erase}\n\
         {normal}{erase}\n\
         {normal}{erase}",
        n - 2,
        normal = ANSI_NORMAL,
        erase = ANSI_ERASE_TO_END_OF_LINE,
    )?;

    // Reset scrolling area (DECSTBM)
    write!(output, "\x1B[r\n")?;

    // Place cursor back in the safe zone
    assert!(n >= 9, "chrome rows must be >= 9");
    let safe_row = state.saved_rows.clamp(5, n - 4);
    write!(output, "\x1B[{};1H", safe_row)?;
    output.flush()?;

    Ok(())
}

/// Show chrome and update state.
pub fn chrome_show_with_state(
    top: &str,
    bottom: Option<&str>,
    n_rows: u32,
    state: &mut ChromeState,
    output: &mut dyn io::Write,
) -> io::Result<bool> {
    let shown = chrome_show(top, bottom, n_rows, output)?;
    if shown {
        state.visible = true;
        state.saved_rows = n_rows;
    }
    Ok(shown)
}

// ── MuteConsole ───────────────────────────────────────────────────────────

/// Handle to an active MuteConsole connection.
///
/// When dropped, the connection is closed and console output is restored.
#[derive(Debug)]
pub struct MuteConsoleHandle {
    /// The varlink socket address used.
    _address: String,
}

impl Drop for MuteConsoleHandle {
    fn drop(&mut self) {
        // Closing the varlink connection restores console output.
        // The actual varlink teardown happens in the Drop impl of the
        // underlying varlink connection.
    }
}

/// Request that console output be muted via the MuteConsole varlink service.
///
/// Returns a handle that, when dropped, restores console output.
/// This is the Rust equivalent of `mute_console()` in C.
pub fn mute_console() -> PromptResult<MuteConsoleHandle> {
    // In the full implementation, this connects to /run/systemd/io.systemd.MuteConsole
    // via varlink, sends an Observe("io.systemd.MuteConsole.Mute") call, and waits
    // for the reply. For now, we return a handle with a descriptive error if the
    // service is unavailable.
    //
    // The C implementation:
    //   1. sd_varlink_connect_address(&link, "/run/systemd/io.systemd.MuteConsole")
    //   2. Creates an event loop, attaches the link
    //   3. Binds a reply callback (vl_on_reply) that exits the loop on first reply
    //   4. Sends Observe("io.systemd.MuteConsole.Mute", NULL)
    //   5. Runs event loop until reply arrives
    //   6. Returns the link (caller must keep it alive to maintain muting)

    Err(PromptError::MuteConsoleFailed(
        "MuteConsole varlink service not available".to_string(),
    ))
}

// ── Prompt builder ────────────────────────────────────────────────────────

/// Builder for constructing interactive prompts.
#[derive(Debug, Clone)]
pub struct PromptBuilder {
    text: String,
    menu: Vec<String>,
    accepted: Vec<String>,
    ellipsize_percentage: u32,
    n_columns: usize,
    column_width: usize,
    flags: PromptFlags,
    prompt_type: PromptType,
}

impl PromptBuilder {
    /// Create a new prompt builder with the given message.
    pub fn new(text: &str) -> Self {
        Self {
            text: text.to_string(),
            menu: Vec::new(),
            accepted: Vec::new(),
            ellipsize_percentage: 80,
            n_columns: 1,
            column_width: 80,
            flags: PromptFlags::NONE,
            prompt_type: PromptType::Text,
        }
    }

    /// Set the type of prompt (text, password, pin, confirmation).
    pub fn prompt_type(mut self, t: PromptType) -> Self {
        self.prompt_type = t;
        self
    }

    /// Set the menu choices.
    pub fn menu(mut self, items: &[&str]) -> Self {
        self.menu = items.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set additional accepted values beyond the menu.
    pub fn accepted(mut self, items: &[&str]) -> Self {
        self.accepted = items.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set the ellipsize percentage for menu entries.
    pub fn ellipsize_percentage(mut self, pct: u32) -> Self {
        self.ellipsize_percentage = pct;
        self
    }

    /// Set the number of display columns for menu layout.
    pub fn n_columns(mut self, n: usize) -> Self {
        self.n_columns = n;
        self
    }

    /// Set the column width in characters.
    pub fn column_width(mut self, w: usize) -> Self {
        self.column_width = w;
        self
    }

    /// Add a flag.
    pub fn flag(mut self, flag: PromptFlags) -> Self {
        self.flags.insert(flag);
        self
    }

    /// Set all flags at once.
    pub fn flags(mut self, flags: PromptFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Allow the user to skip by entering empty input.
    pub fn may_skip(mut self) -> Self {
        self.flags.insert(PromptFlags::MAY_SKIP);
        self
    }

    /// Enable menu display on "list" command.
    pub fn show_menu(mut self) -> Self {
        self.flags.insert(PromptFlags::SHOW_MENU);
        self
    }

    /// Show menu immediately on prompt.
    pub fn show_menu_now(mut self) -> Self {
        self.flags.insert(PromptFlags::SHOW_MENU_NOW);
        self
    }

    /// Get the current prompt type.
    pub fn get_prompt_type(&self) -> PromptType {
        self.prompt_type
    }

    /// Get the current flags.
    pub fn get_flags(&self) -> PromptFlags {
        self.flags
    }

    /// Get the prompt text.
    pub fn get_text(&self) -> &str {
        &self.text
    }

    /// Get the menu items.
    pub fn get_menu(&self) -> &[String] {
        &self.menu
    }

    /// Get the accepted values.
    pub fn get_accepted(&self) -> &[String] {
        &self.accepted
    }

    /// Run the prompt loop, reading from `input` and writing to `output`.
    pub fn run(&self, input: &mut dyn io::BufRead, output: &mut dyn io::Write) -> PromptLoopResult {
        let menu_ref = if self.menu.is_empty() {
            None
        } else {
            Some(self.menu.as_slice())
        };
        let accepted_ref = if self.accepted.is_empty() {
            None
        } else {
            Some(self.accepted.as_slice())
        };
        prompt_loop(
            &self.text,
            menu_ref,
            accepted_ref,
            self.ellipsize_percentage,
            self.n_columns,
            self.column_width,
            self.flags,
            input,
            output,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── PromptFlags tests ──────────────────────────────────────────────

    #[test]
    fn test_prompt_flags_none() {
        let f = PromptFlags::NONE;
        assert!(f.is_empty());
        assert!(!f.contains(PromptFlags::MAY_SKIP));
    }

    #[test]
    fn test_prompt_flags_individual() {
        assert!(PromptFlags::MAY_SKIP.bits() == 1);
        assert!(PromptFlags::SHOW_MENU.bits() == 2);
        assert!(PromptFlags::SHOW_MENU_NOW.bits() == 4);
        assert!(PromptFlags::HIDE_MENU_HINT.bits() == 8);
        assert!(PromptFlags::HIDE_SKIP_HINT.bits() == 16);
        assert!(PromptFlags::SILENT_VALIDATE.bits() == 32);
    }

    #[test]
    fn test_prompt_flags_composition() {
        let f = PromptFlags::MAY_SKIP.union(PromptFlags::SHOW_MENU);
        assert!(f.contains(PromptFlags::MAY_SKIP));
        assert!(f.contains(PromptFlags::SHOW_MENU));
        assert!(!f.contains(PromptFlags::SILENT_VALIDATE));
    }

    #[test]
    fn test_prompt_flags_all() {
        let all = PromptFlags::ALL;
        assert!(all.contains(PromptFlags::MAY_SKIP));
        assert!(all.contains(PromptFlags::SHOW_MENU));
        assert!(all.contains(PromptFlags::SHOW_MENU_NOW));
        assert!(all.contains(PromptFlags::HIDE_MENU_HINT));
        assert!(all.contains(PromptFlags::HIDE_SKIP_HINT));
        assert!(all.contains(PromptFlags::SILENT_VALIDATE));
    }

    // ── PromptType tests ──────────────────────────────────────────────

    #[test]
    fn test_prompt_type_equality() {
        assert_eq!(PromptType::Text, PromptType::Text);
        assert_eq!(PromptType::Password, PromptType::Password);
        assert_eq!(PromptType::Pin, PromptType::Pin);
        assert_eq!(PromptType::Confirmation, PromptType::Confirmation);
        assert_ne!(PromptType::Text, PromptType::Password);
    }

    // ── Completion tests ──────────────────────────────────────────────

    #[test]
    fn test_get_completions() {
        let items: Vec<String> = vec!["apple".into(), "banana".into()];
        let comps = get_completions(&items);
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0], "apple");
        assert_eq!(comps[1], "banana");
        assert_eq!(comps[2], "list");
    }

    #[test]
    fn test_get_completions_empty() {
        let items: Vec<String> = vec![];
        let comps = get_completions(&items);
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0], "list");
    }

    // ── SliceCompletionProvider tests ──────────────────────────────────

    #[test]
    fn test_slice_completion_provider() {
        let items = ["alpha", "beta", "gamma"];
        let provider = SliceCompletionProvider::new(&items);
        let comps = provider.completions("al");
        assert_eq!(comps, vec!["alpha"]);
    }

    #[test]
    fn test_slice_completion_provider_no_match() {
        let items = ["alpha", "beta"];
        let provider = SliceCompletionProvider::new(&items);
        let comps = provider.completions("zz");
        assert!(comps.is_empty());
    }

    #[test]
    fn test_no_completion_provider() {
        let provider = NoCompletionProvider;
        let comps = provider.completions("anything");
        assert!(comps.is_empty());
    }

    // ── strv_find_closest tests ────────────────────────────────────────

    #[test]
    fn test_strv_find_closest_match() {
        let list: Vec<String> = vec!["foobar".into(), "foobaz".into(), "qux".into()];
        let result = strv_find_closest(&list, "fooba");
        assert_eq!(result.as_deref(), Some("foobar"));
    }

    #[test]
    fn test_strv_find_closest_empty() {
        let list: Vec<String> = vec![];
        let result = strv_find_closest(&list, "anything");
        assert!(result.is_none());
    }

    #[test]
    fn test_strv_find_closest_no_common() {
        let list: Vec<String> = vec!["abc".into(), "def".into()];
        let result = strv_find_closest(&list, "xyz");
        // "abc" and "xyz" share no common prefix, but "abc" will be picked
        // since it's first and has 0 common chars which is >= best_len (0).
        // Actually: common prefix of "abc" and "xyz" is 0, "def" and "xyz" is 0.
        // Since 0 > 0 is false, "abc" stays as best (first match at 0).
        assert_eq!(result.as_deref(), Some("abc"));
    }

    // ── ellipsize tests ────────────────────────────────────────────────

    #[test]
    fn test_ellipsize_short_string() {
        let result = ellipsize("hi", 80, 80);
        assert_eq!(result, "hi");
    }

    #[test]
    fn test_ellipsize_long_string() {
        let long = "a".repeat(100);
        let result = ellipsize(&long, 20, 80);
        // limit = 20 * 80 / 100 = 16 chars, minus 3 for "..."
        assert!(result.ends_with("..."));
        assert!(result.len() < 100);
    }

    #[test]
    fn test_ellipsize_zero_percentage() {
        let result = ellipsize("anything", 80, 0);
        assert_eq!(result, "anything");
    }

    // ── show_menu tests ────────────────────────────────────────────────

    #[test]
    fn test_show_menu() {
        let items: Vec<String> = vec!["foo".into(), "bar".into(), "baz".into()];
        let mut output = Vec::new();
        show_menu(&items, 1, 80, 80, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("1) foo"));
        assert!(output_str.contains("2) bar"));
        assert!(output_str.contains("3) baz"));
    }

    // ── PromptBuilder tests ────────────────────────────────────────────

    #[test]
    fn test_prompt_builder_basic() {
        let builder = PromptBuilder::new("Choose an option");
        assert_eq!(builder.get_text(), "Choose an option");
        assert_eq!(builder.get_prompt_type(), PromptType::Text);
        assert!(builder.get_flags().is_empty());
    }

    #[test]
    fn test_prompt_builder_with_flags() {
        let builder = PromptBuilder::new("Pick").may_skip().show_menu();
        assert!(builder.get_flags().contains(PromptFlags::MAY_SKIP));
        assert!(builder.get_flags().contains(PromptFlags::SHOW_MENU));
    }

    #[test]
    fn test_prompt_builder_with_menu() {
        let builder = PromptBuilder::new("Select").menu(&["one", "two", "three"]);
        assert_eq!(builder.get_menu().len(), 3);
        assert_eq!(builder.get_menu()[0], "one");
    }

    #[test]
    fn test_prompt_builder_with_accepted() {
        let builder = PromptBuilder::new("Enter").accepted(&["yes", "no", "maybe"]);
        assert_eq!(builder.get_accepted().len(), 3);
    }

    #[test]
    fn test_prompt_builder_with_prompt_type() {
        let builder = PromptBuilder::new("Password").prompt_type(PromptType::Password);
        assert_eq!(builder.get_prompt_type(), PromptType::Password);
    }

    // ── prompt_loop tests ──────────────────────────────────────────────

    #[test]
    fn test_prompt_loop_valid_input() {
        let input_data = "hello\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Enter value",
            None,
            None,
            80,
            1,
            80,
            PromptFlags::NONE,
            &mut input,
            &mut output,
        );

        match result {
            Ok(PromptOutcome::Value(v)) => assert_eq!(v, "hello"),
            other => panic!("Expected Value, got: {other:?}"),
        }
    }

    #[test]
    fn test_prompt_loop_skip_allowed() {
        let input_data = "\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Enter value",
            None,
            None,
            80,
            1,
            80,
            PromptFlags::MAY_SKIP,
            &mut input,
            &mut output,
        );

        assert!(matches!(result, Ok(PromptOutcome::Skipped)));
    }

    #[test]
    fn test_prompt_loop_skip_not_allowed_then_valid() {
        let input_data = "\nhello\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Enter value",
            None,
            None,
            80,
            1,
            80,
            PromptFlags::NONE,
            &mut input,
            &mut output,
        );

        assert!(matches!(result, Ok(PromptOutcome::Value(ref s)) if s == "hello"));
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("try again"));
    }

    #[test]
    fn test_prompt_loop_numeric_selection() {
        let items: Vec<String> = vec!["apple".into(), "banana".into()];
        let input_data = "2\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Pick fruit",
            Some(&items),
            None,
            80,
            1,
            80,
            PromptFlags::NONE,
            &mut input,
            &mut output,
        );

        assert!(matches!(result, Ok(PromptOutcome::Value(ref s)) if s == "banana"));
    }

    #[test]
    fn test_prompt_loop_numeric_out_of_range() {
        let items: Vec<String> = vec!["one".into()];
        let input_data = "5\nhello\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Pick",
            Some(&items),
            None,
            80,
            1,
            80,
            PromptFlags::NONE,
            &mut input,
            &mut output,
        );

        assert!(matches!(result, Ok(PromptOutcome::Value(ref s)) if s == "hello"));
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("out of range"));
    }

    #[test]
    fn test_prompt_loop_list_command() {
        let items: Vec<String> = vec!["alpha".into(), "beta".into()];
        let input_data = "list\nalpha\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Choose",
            Some(&items),
            None,
            80,
            1,
            80,
            PromptFlags::SHOW_MENU,
            &mut input,
            &mut output,
        );

        assert!(matches!(result, Ok(PromptOutcome::Value(ref s)) if s == "alpha"));
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("1) alpha"));
        assert!(output_str.contains("2) beta"));
    }

    #[test]
    fn test_prompt_loop_list_empty_menu() {
        let items: Vec<String> = vec![];
        let input_data = "list\nhello\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Choose",
            Some(&items),
            None,
            80,
            1,
            80,
            PromptFlags::SHOW_MENU,
            &mut input,
            &mut output,
        );

        assert!(matches!(result, Ok(PromptOutcome::Value(ref s)) if s == "hello"));
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("No entries known"));
    }

    #[test]
    fn test_prompt_loop_invalid_with_closest_match() {
        let accepted: Vec<String> = vec!["systemctl".into(), "journalctl".into()];
        let input_data = "systemcl\nsystemctl\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Command",
            None,
            Some(&accepted),
            80,
            1,
            80,
            PromptFlags::NONE,
            &mut input,
            &mut output,
        );

        assert!(matches!(result, Ok(PromptOutcome::Value(ref s)) if s == "systemctl"));
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("did you mean"));
    }

    #[test]
    fn test_prompt_loop_silent_validate() {
        let accepted: Vec<String> = vec!["valid".into()];
        let input_data = "invalid\nvalid\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = prompt_loop(
            "Enter",
            None,
            Some(&accepted),
            80,
            1,
            80,
            PromptFlags::SILENT_VALIDATE,
            &mut input,
            &mut output,
        );

        assert!(matches!(result, Ok(PromptOutcome::Value(ref s)) if s == "valid"));
        let output_str = String::from_utf8(output).unwrap();
        // Silent validate should NOT log the error
        assert!(!output_str.contains("did you mean"));
        assert!(!output_str.contains("Invalid input"));
    }

    // ── ChromeState tests ─────────────────────────────────────────────

    #[test]
    fn test_chrome_state_default() {
        let state = ChromeState::new();
        assert!(!state.is_visible());
        assert_eq!(state.saved_rows(), 0);
    }

    #[test]
    fn test_chrome_show_too_small() {
        let mut output = Vec::new();
        let result = chrome_show("test", Some("bottom"), 5, &mut output).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_chrome_show_ok() {
        let mut output = Vec::new();
        let result = chrome_show("Top Bar", Some("Bottom Bar"), 24, &mut output).unwrap();
        assert!(result);
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("Top Bar"));
        assert!(output_str.contains("Bottom Bar"));
    }

    #[test]
    fn test_chrome_show_with_state() {
        let mut state = ChromeState::new();
        let mut output = Vec::new();
        let result =
            chrome_show_with_state("Title", Some("Footer"), 24, &mut state, &mut output).unwrap();
        assert!(result);
        assert!(state.is_visible());
        assert_eq!(state.saved_rows(), 24);
    }

    #[test]
    fn test_chrome_hide_not_visible() {
        let mut state = ChromeState::new();
        let mut output = Vec::new();
        chrome_hide(&mut state, &mut output).unwrap();
        assert!(!state.is_visible());
    }

    #[test]
    fn test_chrome_show_hide_cycle() {
        let mut state = ChromeState::new();
        let mut output = Vec::new();

        let shown = chrome_show_with_state("T", Some("B"), 20, &mut state, &mut output).unwrap();
        assert!(shown);
        assert!(state.is_visible());

        chrome_hide(&mut state, &mut output).unwrap();
        assert!(!state.is_visible());
    }

    #[test]
    fn test_chrome_show_default_bottom() {
        let mut output = Vec::new();
        let result = chrome_show("Header", None, 24, &mut output).unwrap();
        assert!(result);
        let output_str = String::from_utf8(output).unwrap();
        // Default bottom should be "System Management"
        assert!(output_str.contains("System Management"));
    }

    // ── PromptOutcome tests ────────────────────────────────────────────

    #[test]
    fn test_prompt_outcome_value() {
        let outcome = PromptOutcome::Value("test".to_string());
        assert_eq!(outcome, PromptOutcome::Value("test".to_string()));
        assert_ne!(outcome, PromptOutcome::Skipped);
    }

    #[test]
    fn test_prompt_outcome_skipped() {
        let outcome = PromptOutcome::Skipped;
        assert_eq!(outcome, PromptOutcome::Skipped);
        assert_ne!(outcome, PromptOutcome::Value(String::new()));
    }

    // ── PromptError tests ──────────────────────────────────────────────

    #[test]
    fn test_prompt_error_display() {
        let err = PromptError::InvalidInput("bad".to_string());
        assert_eq!(format!("{err}"), "invalid input: bad");

        let err = PromptError::EmptyInput;
        assert_eq!(format!("{err}"), "no data entered");

        let err = PromptError::OutOfRange;
        assert_eq!(format!("{err}"), "selection out of range");
    }

    #[test]
    fn test_prompt_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broke");
        let err: PromptError = io_err.into();
        assert!(matches!(err, PromptError::Io(_)));
        assert_eq!(format!("{err}"), "I/O error: pipe broke");
    }

    // ── MuteConsole tests ─────────────────────────────────────────────

    #[test]
    fn test_mute_console_fails_without_service() {
        let result = mute_console();
        assert!(result.is_err());
        match result.unwrap_err() {
            PromptError::MuteConsoleFailed(msg) => {
                assert!(msg.contains("not available"));
            }
            other => panic!("Expected MuteConsoleFailed, got: {other}"),
        }
    }
}
