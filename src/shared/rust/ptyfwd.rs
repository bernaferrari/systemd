// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/ptyfwd.c, src/shared/ptyfwd.h
//
// PTY forwarding utilities.
//
// Handles bidirectional forwarding between a PTY master fd and
// stdin/stdout, including ANSI escape processing, background color
// tinting, window title management, and escape-based hotkeys.

use std::os::fd::RawFd;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum length of an ANSI CSI/OSC sequence before we bail out.
pub const ANSI_SEQUENCE_LENGTH_MAX: usize = 192;

/// Maximum window title length (some terminals dislike long OSC sequences).
pub const ANSI_SEQUENCE_WINDOW_TITLE_MAX: usize = 128;

/// Signals forwarded through the PTY forwarder.
pub const N_PTY_FORWARD_SIGNALS: usize = 7;

/// Time window (in µs) for the triple-escape detection.
pub const ESCAPE_USEC: u64 = 1_000_000;

// ── Enums ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// PTY forwarder configuration flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PTYForwardFlags: u32 {
        /// Only output to STDOUT, never try to read from STDIN.
        const READ_ONLY              = 1 << 0;
        /// Continue reading after hangup.
        const IGNORE_VHANGUP         = 1 << 1;
        /// Continue reading after hangup but only if we never read anything else.
        const IGNORE_INITIAL_VHANGUP = 1 << 2;
        /// Don't tint the background, or set window title.
        const DUMB_TERMINAL          = 1 << 3;
    }
}

/// Result of scanning input for escape sequences / hotkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOperation {
    /// Nothing detected.
    Nop,
    /// Triple ^] detected → exit.
    Exit,
    /// ^]^<key> detected → hotkey.
    Hotkey(char),
}

/// ANSI escape sequence parser state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnsiColorState {
    /// Normal text, no escape in progress.
    Text,
    /// Just saw ESC (0x1B).
    Esc,
    /// Inside a CSI sequence (ESC [ …).
    CsiSequence,
    /// Inside an OSC sequence (ESC ] …).
    OscSequence,
    /// OSC terminated by ESC, waiting for \x5c (ST).
    OscSequenceTerminating,
}

/// Color-token parser sub-state for `is_csi_background_reset_sequence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorTokenState {
    No,
    Start,
    Bit8,
    Bit24R,
    Bit24G,
    Bit24B,
}

// ── PTYForward struct ────────────────────────────────────────────────────

/// Core state for a PTY forwarding session.
///
/// Tracks file descriptors, buffer state, ANSI processing, escape/hotkey
/// detection, and terminal title management.
#[derive(Debug)]
pub struct PTYForward {
    pub input_fd: Option<RawFd>,
    pub output_fd: Option<RawFd>,
    pub master: Option<RawFd>,
    pub flags: PTYForwardFlags,

    // ── fd ownership ──
    close_input_fd: bool,
    close_output_fd: bool,

    // ── saved terminal attributes ──
    saved_stdin: bool,
    saved_stdout: bool,

    // ── event source readiness ──
    pub stdin_readable: bool,
    pub stdin_hangup: bool,
    pub stdout_writable: bool,
    pub stdout_hangup: bool,
    pub master_readable: bool,
    pub master_writable: bool,
    pub master_hangup: bool,

    pub read_from_master: bool,

    pub done: bool,
    pub drain: bool,

    // ── last-char tracking (for trailing-newline fixup) ──
    last_char_set: bool,
    last_char: u8,
    last_char_safe: u8,

    // ── I/O buffers ──
    in_buffer: Vec<u8>,
    out_buffer: Vec<u8>,
    out_buffer_full: usize,
    /// Length of safe output in the buffer (excludes trailing incomplete
    /// ANSI sequences).
    out_buffer_write_len: usize,

    // ── escape / hotkey detection ──
    pub escape_timestamp: u64,
    pub escape_counter: u32,

    // ── ANSI processing ──
    pub ansi_color_state: AnsiColorState,
    csi_sequence: String,
    osc_sequence: String,

    // ── appearance ──
    pub background_color: Option<String>,
    pub title: Option<String>,
    pub title_prefix: Option<String>,
}

impl Default for PTYForward {
    fn default() -> Self {
        Self::new()
    }
}

impl PTYForward {
    /// Create a new `PTYForward` with all fields in their default state.
    pub fn new() -> Self {
        Self {
            input_fd: None,
            output_fd: None,
            master: None,
            flags: PTYForwardFlags::empty(),
            close_input_fd: false,
            close_output_fd: false,
            saved_stdin: false,
            saved_stdout: false,
            stdin_readable: false,
            stdin_hangup: false,
            stdout_writable: false,
            stdout_hangup: false,
            master_readable: false,
            master_writable: false,
            master_hangup: false,
            read_from_master: false,
            done: false,
            drain: false,
            last_char_set: false,
            last_char: 0,
            last_char_safe: 0,
            in_buffer: Vec::new(),
            out_buffer: Vec::new(),
            out_buffer_full: 0,
            out_buffer_write_len: 0,
            escape_timestamp: 0,
            escape_counter: 0,
            ansi_color_state: AnsiColorState::Text,
            csi_sequence: String::new(),
            osc_sequence: String::new(),
            background_color: None,
            title: None,
            title_prefix: None,
        }
    }

    /// Create a `PTYForward` connected to the given fds.
    pub fn with_fds(input_fd: RawFd, output_fd: RawFd, master: RawFd) -> Self {
        Self {
            input_fd: Some(input_fd),
            output_fd: Some(output_fd),
            master: Some(master),
            ..Self::new()
        }
    }

    /// Disconnect all file descriptors and reset terminal state.
    pub fn disconnect(&mut self) {
        self.input_fd = None;
        self.output_fd = None;
        self.master = None;
        self.stdin_readable = false;
        self.stdout_writable = false;
        self.master_readable = false;
        self.master_writable = false;
        self.out_buffer.clear();
        self.out_buffer_full = 0;
        self.out_buffer_write_len = 0;
        self.in_buffer.clear();
        self.csi_sequence.clear();
        self.osc_sequence.clear();
        self.ansi_color_state = AnsiColorState::Text;
    }

    /// Mark the forwarder as done and disconnect.
    pub fn finish(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        self.disconnect();
    }

    /// Whether the vhangup ignore flag is currently active.
    pub fn vhangup_honored(&self) -> bool {
        if self.flags.contains(PTYForwardFlags::IGNORE_VHANGUP) {
            return false;
        }
        if self.flags.contains(PTYForwardFlags::IGNORE_INITIAL_VHANGUP) && !self.read_from_master {
            return false;
        }
        true
    }

    /// Set the background color string (e.g. `"48;5;0"`).
    pub fn set_background_color(&mut self, color: Option<String>) {
        self.background_color = color;
    }

    /// Set the window title. Returns `false` if already started shovelling
    /// (buffer allocated).
    pub fn set_title(&mut self, title: Option<String>) -> bool {
        if self.out_buffer_full > 0 {
            return false;
        }
        self.title = title;
        true
    }

    /// Set the title prefix prepended when the terminal client overrides
    /// the window title via OSC 0.
    pub fn set_title_prefix(&mut self, prefix: Option<String>) {
        self.title_prefix = prefix;
    }
}

// ── Look for escape ──────────────────────────────────────────────────────

/// Scan `buffer` for triple-^] (exit) or ^]^<a-z> (hotkey) sequences.
///
/// Uses a simple state machine: a counter and timestamp. If three `0x1D`
/// bytes arrive within `ESCAPE_USEC` microseconds, returns `Exit`. If two
/// `0x1D` bytes are followed by a letter within the window, returns
/// `Hotkey(c)`. Otherwise returns `Nop`.
///
/// The caller is responsible for supplying the current monotonic time via
/// `now_usec`.
pub fn look_for_escape(
    escape_counter: &mut u32,
    escape_timestamp: &mut u64,
    buffer: &[u8],
    now_usec: u64,
) -> RequestOperation {
    for &byte in buffer {
        match byte {
            0x1D => {
                // ^] pressed
                if *escape_counter == 0 {
                    *escape_timestamp = now_usec;
                    *escape_counter = 1;
                } else if now_usec > escape_timestamp.saturating_add(ESCAPE_USEC) {
                    // Timeout: discard this byte entirely, just reset timestamp
                    *escape_timestamp = now_usec;
                    *escape_counter = 0;
                } else {
                    *escape_counter += 1;
                    if *escape_counter >= 3 {
                        *escape_counter = 0;
                        *escape_timestamp = 0;
                        return RequestOperation::Exit;
                    }
                }
            }
            b'a'..=b'z' => {
                if *escape_counter == 2 && now_usec <= escape_timestamp.saturating_add(ESCAPE_USEC)
                {
                    *escape_timestamp = 0;
                    *escape_counter = 0;
                    return RequestOperation::Hotkey(byte as char);
                }
                // fall through
                *escape_timestamp = 0;
                *escape_counter = 0;
            }
            _ => {
                *escape_timestamp = 0;
                *escape_counter = 0;
            }
        }
    }
    RequestOperation::Nop
}

// ── ANSI processing ─────────────────────────────────────────────────────

/// Whether a byte is a C0 control character (except ESC).
pub fn char_is_cc(c: u8) -> bool {
    c < 0x20 && c != 0x1B
}

/// Build the ANSI SGR background-color sequence: `\x1B[<color>m`.
pub fn background_color_sequence(color: &str) -> String {
    format!("\x1B[{}m", color)
}

/// Determine whether a CSI `m` sequence resets the background color.
///
/// Parses semicolon-separated SGR parameters. Returns `true` if any token
/// resets the background to normal (`""`, `"0"`, `"00"`, `"49"`).
pub fn is_csi_background_reset_sequence(seq: &str) -> bool {
    let mut token_state = ColorTokenState::No;
    let mut reset = false;

    for token in seq.split(';') {
        match token_state {
            ColorTokenState::No => {
                if matches!(token, "" | "0" | "00" | "49") {
                    reset = true;
                } else if matches!(
                    token,
                    "40" | "41" | "42" | "43" | "44" | "45" | "46" | "47" | "48"
                ) {
                    reset = false;
                }
                if matches!(token, "38" | "48" | "58") {
                    token_state = ColorTokenState::Start;
                }
            }
            ColorTokenState::Start => {
                token_state = if matches!(token, "5" | "05") {
                    ColorTokenState::Bit8
                } else if matches!(token, "2" | "02") {
                    ColorTokenState::Bit24R
                } else {
                    ColorTokenState::No
                };
            }
            ColorTokenState::Bit24R => token_state = ColorTokenState::Bit24G,
            ColorTokenState::Bit24G => token_state = ColorTokenState::Bit24B,
            ColorTokenState::Bit8 | ColorTokenState::Bit24B => token_state = ColorTokenState::No,
        }
    }
    reset
}

/// Insert `s` into `out_buffer` at `offset`, shifting existing data right.
///
/// Returns `Ok(len)` on success or an error if reallocation fails.
pub fn insert_string(out_buffer: &mut Vec<u8>, offset: usize, s: &[u8]) -> usize {
    let l = s.len();
    if offset > out_buffer.len() {
        out_buffer.resize(offset, 0);
    }
    out_buffer.splice(offset..offset, s.iter().copied());
    l
}

/// Insert the background-color ANSI sequence at `offset` in `out_buffer`.
///
/// This is a pure-Rust convenience wrapper. Returns the number of bytes
/// inserted, or 0 if no background color is configured.
pub fn insert_background_color(
    out_buffer: &mut Vec<u8>,
    offset: usize,
    background_color: &Option<String>,
) -> usize {
    let color = match background_color {
        Some(c) => c,
        None => return 0,
    };
    let seq = background_color_sequence(color);
    insert_string(out_buffer, offset, seq.as_bytes())
}

/// If `csi_sequence` resets the background, patch it by appending
/// `;<color>` at `offset`.
pub fn insert_background_fix(
    out_buffer: &mut Vec<u8>,
    offset: usize,
    csi_sequence: &str,
    background_color: &Option<String>,
) -> usize {
    let color = match background_color {
        Some(c) => c,
        None => return 0,
    };
    if !is_csi_background_reset_sequence(csi_sequence) {
        return 0;
    }
    let fix = format!(";{}", color);
    insert_string(out_buffer, offset, fix.as_bytes())
}

/// If an OSC 0 (set window title) sequence is present, prepend the
/// configured title prefix.
pub fn insert_window_title_fix(
    out_buffer: &mut Vec<u8>,
    offset: usize,
    osc_sequence: &str,
    title_prefix: &Option<String>,
) -> usize {
    let prefix = match title_prefix {
        Some(p) => p,
        None => return 0,
    };
    let t = match osc_sequence.strip_prefix("0;") {
        Some(t) => t,
        None => return 0,
    };
    let joined = format!("\x1B]0;{}{}{}", prefix, t, "\x1B\\");
    insert_string(out_buffer, offset, joined.as_bytes())
}

/// Process the output buffer starting at `offset` for ANSI sequences.
///
/// Implements a state machine over [`AnsiColorState`], calling the
/// appropriate insert functions for background color and window title
/// fixes. Updates `ansi_color_state` and `out_buffer_write_len`.
///
/// Returns `Ok(())` on success.
pub fn pty_forward_ansi_process(
    out_buffer: &mut Vec<u8>,
    out_buffer_full: &mut usize,
    out_buffer_write_len: &mut usize,
    ansi_color_state: &mut AnsiColorState,
    csi_sequence: &mut String,
    osc_sequence: &mut String,
    last_char_safe: &mut u8,
    background_color: &Option<String>,
    title_prefix: &Option<String>,
    offset: usize,
) {
    assert!(offset <= *out_buffer_full);

    let mut i = offset;
    while i < *out_buffer_full {
        let c = out_buffer[i];

        match *ansi_color_state {
            AnsiColorState::Text => {
                if matches!(c, b'\n' | b'\r') {
                    let inserted = insert_background_color(out_buffer, i + 1, background_color);
                    i += inserted;
                    *out_buffer_full += inserted;
                    *last_char_safe = c;
                } else if c == 0x1B {
                    *ansi_color_state = AnsiColorState::Esc;
                } else if !char_is_cc(c) {
                    *last_char_safe = c;
                }
            }

            AnsiColorState::Esc => {
                if c == b'[' {
                    *ansi_color_state = AnsiColorState::CsiSequence;
                } else if c == b']' {
                    *ansi_color_state = AnsiColorState::OscSequence;
                } else if c == b'c' {
                    // Full reset
                    let inserted = insert_background_color(out_buffer, i + 1, background_color);
                    i += inserted;
                    *out_buffer_full += inserted;
                    *ansi_color_state = AnsiColorState::Text;
                } else {
                    *ansi_color_state = AnsiColorState::Text;
                }
            }

            AnsiColorState::CsiSequence => {
                if (0x20..=0x3F).contains(&c) {
                    // Parameter / intermediary byte – still in CSI
                    if csi_sequence.len() >= ANSI_SEQUENCE_LENGTH_MAX {
                        csi_sequence.clear();
                        *ansi_color_state = AnsiColorState::Text;
                    } else {
                        csi_sequence.push(c as char);
                    }
                } else {
                    // CSI sequence terminator
                    if c == b'p' && csi_sequence == "!" {
                        // Soft reset
                        let inserted = insert_background_color(out_buffer, i + 1, background_color);
                        i += inserted;
                        *out_buffer_full += inserted;
                    } else if c == b'm' {
                        // SGR – patch background color
                        let fix_len = insert_background_fix(
                            out_buffer,
                            i,
                            csi_sequence.as_str(),
                            background_color,
                        );
                        i += fix_len;
                        *out_buffer_full += fix_len;
                    }
                    csi_sequence.clear();
                    *ansi_color_state = AnsiColorState::Text;
                }
            }

            AnsiColorState::OscSequence => {
                if (c as u8) >= b' ' {
                    if osc_sequence.len() >= ANSI_SEQUENCE_LENGTH_MAX {
                        osc_sequence.clear();
                        *ansi_color_state = AnsiColorState::Text;
                    } else {
                        osc_sequence.push(c as char);
                    }
                } else if c == 0x07 {
                    // BEL terminates OSC
                    let fix_len = insert_window_title_fix(
                        out_buffer,
                        i + 1,
                        osc_sequence.as_str(),
                        title_prefix,
                    );
                    i += fix_len;
                    *out_buffer_full += fix_len;
                    osc_sequence.clear();
                    *ansi_color_state = AnsiColorState::Text;
                } else if c == 0x1B {
                    *ansi_color_state = AnsiColorState::OscSequenceTerminating;
                } else {
                    osc_sequence.clear();
                    *ansi_color_state = AnsiColorState::Text;
                }
            }

            AnsiColorState::OscSequenceTerminating => {
                if c == 0x5C {
                    let fix_len = insert_window_title_fix(
                        out_buffer,
                        i + 1,
                        osc_sequence.as_str(),
                        title_prefix,
                    );
                    i += fix_len;
                    *out_buffer_full += fix_len;
                }
                osc_sequence.clear();
                *ansi_color_state = AnsiColorState::Text;
            }
        }

        if *ansi_color_state == AnsiColorState::Text {
            *out_buffer_write_len = i + 1;
        }

        i += 1;
    }
}

// ── Source embedding ─────────────────────────────────────────────────────

pub const SOURCE_PATH: &str = "src/shared/ptyfwd.c";
pub const SOURCE_TEXT: &str = include_str!("../ptyfwd.c");

pub fn source_lines() -> usize {
    SOURCE_TEXT.lines().count()
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_is_embedded() {
        assert!(!super::SOURCE_TEXT.is_empty());
    }

    #[test]
    fn test_pty_forward_new_default() {
        let f = PTYForward::new();
        assert!(f.input_fd.is_none());
        assert!(f.output_fd.is_none());
        assert!(f.master.is_none());
        assert!(!f.done);
        assert!(!f.drain);
        assert_eq!(f.ansi_color_state, AnsiColorState::Text);
    }

    #[test]
    fn test_pty_forward_with_fds() {
        let f = PTYForward::with_fds(0, 1, 2);
        assert_eq!(f.input_fd, Some(0));
        assert_eq!(f.output_fd, Some(1));
        assert_eq!(f.master, Some(2));
    }

    #[test]
    fn test_pty_forward_disconnect() {
        let mut f = PTYForward::with_fds(0, 1, 2);
        f.stdin_readable = true;
        f.stdout_writable = true;
        f.master_readable = true;
        f.disconnect();
        assert!(f.input_fd.is_none());
        assert!(f.output_fd.is_none());
        assert!(f.master.is_none());
        assert!(!f.stdin_readable);
        assert!(!f.stdout_writable);
        assert!(!f.master_readable);
    }

    #[test]
    fn test_pty_forward_finish() {
        let mut f = PTYForward::with_fds(0, 1, 2);
        f.finish();
        assert!(f.done);
        assert!(f.input_fd.is_none());
        // Second finish is a no-op
        f.finish();
        assert!(f.done);
    }

    #[test]
    fn test_pty_forward_set_background_color() {
        let mut f = PTYForward::new();
        f.set_background_color(Some("48;5;0".to_string()));
        assert_eq!(f.background_color.as_deref(), Some("48;5;0"));
        f.set_background_color(None);
        assert!(f.background_color.is_none());
    }

    #[test]
    fn test_pty_forward_set_title() {
        let mut f = PTYForward::new();
        assert!(f.set_title(Some("hello".to_string())));
        assert_eq!(f.title.as_deref(), Some("hello"));
        // Once buffer has data, title cannot be set
        f.out_buffer_full = 1;
        assert!(!f.set_title(Some("world".to_string())));
        assert_eq!(f.title.as_deref(), Some("hello"));
    }

    #[test]
    fn test_pty_forward_vhangup_honored() {
        let mut f = PTYForward::new();
        // Default: honored
        assert!(f.vhangup_honored());
        // With IGNORE_VHANGUP: not honored
        f.flags.insert(PTYForwardFlags::IGNORE_VHANGUP);
        assert!(!f.vhangup_honored());
        // With IGNORE_INITIAL_VHANGUP and no read: not honored
        f.flags.remove(PTYForwardFlags::IGNORE_VHANGUP);
        f.flags.insert(PTYForwardFlags::IGNORE_INITIAL_VHANGUP);
        assert!(!f.vhangup_honored());
        // After reading from master: honored
        f.read_from_master = true;
        assert!(f.vhangup_honored());
    }

    #[test]
    fn test_look_for_escape_nop() {
        let mut counter = 0u32;
        let mut ts = 0u64;
        let result = look_for_escape(&mut counter, &mut ts, b"hello", 0);
        assert_eq!(result, RequestOperation::Nop);
        assert_eq!(counter, 0);
    }

    #[test]
    fn test_look_for_escape_single() {
        let mut counter = 0u32;
        let mut ts = 0u64;
        let result = look_for_escape(&mut counter, &mut ts, &[0x1D], 0);
        assert_eq!(result, RequestOperation::Nop);
        assert_eq!(counter, 1);
    }

    #[test]
    fn test_look_for_escape_triple() {
        let mut counter = 0u32;
        let mut ts = 0u64;
        // Three ^] within the time window → exit
        let result = look_for_escape(&mut counter, &mut ts, &[0x1D, 0x1D, 0x1D], 0);
        assert_eq!(result, RequestOperation::Exit);
    }

    #[test]
    fn test_look_for_escape_hotkey() {
        let mut counter = 0u32;
        let mut ts = 0u64;
        // Two ^] then a letter → hotkey
        let result = look_for_escape(&mut counter, &mut ts, &[0x1D, 0x1D, b'x'], 0);
        assert_eq!(result, RequestOperation::Hotkey('x'));
    }

    #[test]
    fn test_look_for_escape_reset() {
        let mut counter = 0u32;
        let mut ts = 0u64;
        // ^] then a non-letter resets
        look_for_escape(&mut counter, &mut ts, &[0x1D, b'Z'], 0);
        assert_eq!(counter, 0);
    }

    #[test]
    fn test_look_for_escape_timeout() {
        let mut counter = 0u32;
        let mut ts = 0u64;
        // First ^]
        look_for_escape(&mut counter, &mut ts, &[0x1D], 100);
        // Second ^] after timeout
        let result = look_for_escape(
            &mut counter,
            &mut ts,
            &[0x1D, 0x1D, 0x1D],
            100 + ESCAPE_USEC + 1,
        );
        assert_eq!(result, RequestOperation::Nop);
    }

    #[test]
    fn test_char_is_cc() {
        assert!(char_is_cc(0x00)); // NUL
        assert!(char_is_cc(0x0A)); // LF
        assert!(char_is_cc(0x0D)); // CR
        assert!(!char_is_cc(0x1B)); // ESC is not a CC here
        assert!(!char_is_cc(0x20)); // space
        assert!(!char_is_cc(b'A'));
    }

    #[test]
    fn test_background_color_sequence() {
        let seq = background_color_sequence("48;5;0");
        assert_eq!(seq, "\x1B[48;5;0m");
    }

    #[test]
    fn test_is_csi_background_reset_empty() {
        // Empty sequence → no reset token found
        assert!(is_csi_background_reset_sequence(""));
    }

    #[test]
    fn test_is_csi_background_reset_zero() {
        // "0" resets background
        assert!(is_csi_background_reset_sequence("0"));
        assert!(is_csi_background_reset_sequence("00"));
        assert!(is_csi_background_reset_sequence(""));
        assert!(is_csi_background_reset_sequence("49"));
    }

    #[test]
    fn test_is_csi_background_reset_explicit() {
        // "40"-"48" set a specific background
        assert!(!is_csi_background_reset_sequence("40"));
        assert!(!is_csi_background_reset_sequence("47"));
        // "48" starts an extended color
        assert!(!is_csi_background_reset_sequence("48;5;0"));
    }

    #[test]
    fn test_is_csi_background_reset_mixed() {
        // "0;38;5;1" → "0" resets, then extended foreground follows
        assert!(is_csi_background_reset_sequence("0;38;5;1"));
    }

    #[test]
    fn test_insert_string_basic() {
        let mut buf = vec![b'h', b'i'];
        let inserted = insert_string(&mut buf, 1, b"_inserted_");
        assert_eq!(inserted, 10);
        assert_eq!(buf, b"h_inserted_i");
    }

    #[test]
    fn test_insert_string_at_end() {
        let mut buf = vec![b'a'];
        let inserted = insert_string(&mut buf, 1, b"bc");
        assert_eq!(inserted, 2);
        assert_eq!(buf, b"abc");
    }

    #[test]
    fn test_insert_string_empty() {
        let mut buf = vec![b'a'];
        let inserted = insert_string(&mut buf, 0, b"");
        assert_eq!(inserted, 0);
        assert_eq!(buf, b"a");
    }

    #[test]
    fn test_insert_background_color_none() {
        let mut buf = vec![b'a'];
        let inserted = insert_background_color(&mut buf, 1, &None);
        assert_eq!(inserted, 0);
        assert_eq!(buf, b"a");
    }

    #[test]
    fn test_insert_background_color_some() {
        let mut buf = vec![b'\n'];
        let color = Some("48;5;0".to_string());
        let inserted = insert_background_color(&mut buf, 1, &color);
        assert_eq!(inserted, 9); // \x1B[48;5;0m
        assert!(buf.starts_with(b"\n\x1B[48;5;0m"));
    }

    #[test]
    fn test_insert_window_title_fix_no_prefix() {
        let mut buf = vec![b'a'];
        let inserted = insert_window_title_fix(&mut buf, 1, "0;MyTitle", &None);
        assert_eq!(inserted, 0);
        assert_eq!(buf, b"a");
    }

    #[test]
    fn test_insert_window_title_fix_with_prefix() {
        let mut buf = vec![0; 1];
        let prefix = Some("● ".to_string());
        let inserted = insert_window_title_fix(&mut buf, 1, "0;MyTitle", &prefix);
        assert!(inserted > 0);
        // Should contain the prefix
        let s = String::from_utf8_lossy(&buf[1..]);
        assert!(s.contains("● "));
        assert!(s.contains("MyTitle"));
    }

    #[test]
    fn test_insert_window_title_fix_not_osc0() {
        let mut buf = vec![b'a'];
        let prefix = Some("● ".to_string());
        // Not "0;" prefix → no fix
        let inserted = insert_window_title_fix(&mut buf, 1, "2;title", &prefix);
        assert_eq!(inserted, 0);
    }

    #[test]
    fn test_insert_background_fix_no_color() {
        let mut buf = vec![b'a'];
        let inserted = insert_background_fix(&mut buf, 1, "0", &None);
        assert_eq!(inserted, 0);
    }

    #[test]
    fn test_insert_background_fix_with_reset() {
        let mut buf = vec![b'a'];
        let color = Some("48;5;0".to_string());
        let inserted = insert_background_fix(&mut buf, 1, "0", &color);
        assert!(inserted > 0);
        // Should contain ";48;5;0"
        let s = String::from_utf8_lossy(&buf[1..]);
        assert!(s.contains(";48;5;0"));
    }

    #[test]
    fn test_insert_background_fix_no_reset() {
        let mut buf = vec![b'a'];
        let color = Some("48;5;0".to_string());
        // "40" sets a specific bg, not a reset
        let inserted = insert_background_fix(&mut buf, 1, "40", &color);
        assert_eq!(inserted, 0);
    }

    #[test]
    fn test_ansi_process_plain_text() {
        let mut buf = b"hello world".to_vec();
        let mut full = buf.len();
        let mut write_len = 0;
        let mut state = AnsiColorState::Text;
        let mut csi = String::new();
        let mut osc = String::new();
        let mut last_safe = 0u8;

        pty_forward_ansi_process(
            &mut buf,
            &mut full,
            &mut write_len,
            &mut state,
            &mut csi,
            &mut osc,
            &mut last_safe,
            &None,
            &None,
            0,
        );
        assert_eq!(state, AnsiColorState::Text);
        assert_eq!(write_len, 11);
    }

    #[test]
    fn test_ansi_process_newline_inserts_bg() {
        let mut buf = b"hello\nworld".to_vec();
        let mut full = buf.len();
        let mut write_len = 0;
        let mut state = AnsiColorState::Text;
        let mut csi = String::new();
        let mut osc = String::new();
        let mut last_safe = 0u8;
        let color = Some("48;5;0".to_string());

        pty_forward_ansi_process(
            &mut buf,
            &mut full,
            &mut write_len,
            &mut state,
            &mut csi,
            &mut osc,
            &mut last_safe,
            &color,
            &None,
            0,
        );
        assert_eq!(state, AnsiColorState::Text);
        // Should have inserted background color after \n
        assert!(full > 11);
    }

    #[test]
    fn test_ansi_process_csi_sgr_reset() {
        let mut buf = b"\x1B[0mhello".to_vec();
        let mut full = buf.len();
        let mut write_len = 0;
        let mut state = AnsiColorState::Text;
        let mut csi = String::new();
        let mut osc = String::new();
        let mut last_safe = 0u8;
        let color = Some("48;5;0".to_string());

        pty_forward_ansi_process(
            &mut buf,
            &mut full,
            &mut write_len,
            &mut state,
            &mut csi,
            &mut osc,
            &mut last_safe,
            &color,
            &None,
            0,
        );
        assert_eq!(state, AnsiColorState::Text);
        assert_eq!(csi, "");
        // Should have patched the SGR with background fix
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains(";48;5;0"));
    }

    #[test]
    fn test_ansi_process_csi_soft_reset() {
        let mut buf = b"\x1B[!phello".to_vec();
        let mut full = buf.len();
        let mut write_len = 0;
        let mut state = AnsiColorState::Text;
        let mut csi = String::new();
        let mut osc = String::new();
        let mut last_safe = 0u8;
        let color = Some("48;5;0".to_string());

        pty_forward_ansi_process(
            &mut buf,
            &mut full,
            &mut write_len,
            &mut state,
            &mut csi,
            &mut osc,
            &mut last_safe,
            &color,
            &None,
            0,
        );
        assert_eq!(state, AnsiColorState::Text);
        // Soft reset should insert background color
        assert!(full > 8);
    }

    #[test]
    fn test_ansi_process_osc_title_with_prefix() {
        // OSC 0 ; MyTitle \x07
        let mut buf = b"\x1B]0;MyTitle\x07rest".to_vec();
        let mut full = buf.len();
        let mut write_len = 0;
        let mut state = AnsiColorState::Text;
        let mut csi = String::new();
        let mut osc = String::new();
        let mut last_safe = 0u8;
        let prefix = Some("● ".to_string());

        pty_forward_ansi_process(
            &mut buf,
            &mut full,
            &mut write_len,
            &mut state,
            &mut csi,
            &mut osc,
            &mut last_safe,
            &None,
            &prefix,
            0,
        );
        assert_eq!(state, AnsiColorState::Text);
        assert!(full > 14);
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("● MyTitle"));
    }

    #[test]
    fn test_ansi_process_esc_c_reset() {
        // ESC c (full reset)
        let mut buf = b"\x1Bchello".to_vec();
        let mut full = buf.len();
        let mut write_len = 0;
        let mut state = AnsiColorState::Text;
        let mut csi = String::new();
        let mut osc = String::new();
        let mut last_safe = 0u8;
        let color = Some("48;5;0".to_string());

        pty_forward_ansi_process(
            &mut buf,
            &mut full,
            &mut write_len,
            &mut state,
            &mut csi,
            &mut osc,
            &mut last_safe,
            &color,
            &None,
            0,
        );
        assert_eq!(state, AnsiColorState::Text);
        assert!(full > 6);
    }

    #[test]
    fn test_ansi_process_csi_too_long() {
        // A CSI sequence that exceeds ANSI_SEQUENCE_LENGTH_MAX → reset
        let long_param = "x".repeat(ANSI_SEQUENCE_LENGTH_MAX + 1);
        let mut buf = format!("\x1B[{}hello", long_param).into_bytes();
        let mut full = buf.len();
        let mut write_len = 0;
        let mut state = AnsiColorState::Text;
        let mut csi = String::new();
        let mut osc = String::new();
        let mut last_safe = 0u8;

        pty_forward_ansi_process(
            &mut buf,
            &mut full,
            &mut write_len,
            &mut state,
            &mut csi,
            &mut osc,
            &mut last_safe,
            &None,
            &None,
            0,
        );
        assert_eq!(state, AnsiColorState::Text);
        assert_eq!(csi, "");
    }

    #[test]
    fn test_pty_forward_flags() {
        let mut flags = PTYForwardFlags::empty();
        assert!(!flags.contains(PTYForwardFlags::READ_ONLY));
        flags.insert(PTYForwardFlags::READ_ONLY);
        assert!(flags.contains(PTYForwardFlags::READ_ONLY));
        flags.insert(PTYForwardFlags::DUMB_TERMINAL);
        assert!(flags.contains(PTYForwardFlags::READ_ONLY));
        assert!(flags.contains(PTYForwardFlags::DUMB_TERMINAL));
    }

    #[test]
    fn test_request_operation_equality() {
        assert_eq!(RequestOperation::Nop, RequestOperation::Nop);
        assert_eq!(RequestOperation::Exit, RequestOperation::Exit);
        assert_eq!(RequestOperation::Hotkey('a'), RequestOperation::Hotkey('a'));
        assert_ne!(RequestOperation::Hotkey('a'), RequestOperation::Hotkey('b'));
        assert_ne!(RequestOperation::Nop, RequestOperation::Exit);
    }

    #[test]
    fn test_ansi_color_state_debug_clone() {
        let s = AnsiColorState::CsiSequence;
        let s2 = s;
        assert_eq!(s, s2);
        assert_eq!(format!("{:?}", s), "CsiSequence");
    }

    #[test]
    fn test_color_token_state_debug() {
        assert_eq!(format!("{:?}", ColorTokenState::No), "No");
        assert_eq!(format!("{:?}", ColorTokenState::Bit8), "Bit8");
    }
}
