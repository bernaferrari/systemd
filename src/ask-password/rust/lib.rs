// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/ask-password/ask-password.c
//
// Query the user for a passphrase, via the TTY or a UI agent.
// Supports echo modes, timeouts, kernel keyring caching, and Varlink.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default timeout in microseconds (from the C code: DEFAULT_TIMEOUT_USEC).
pub const DEFAULT_TIMEOUT_USEC: u64 = 90_000_000;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Echo mode for password input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoMode {
    /// No echo (password hidden).
    Off,
    /// Full echo (visible input).
    On,
    /// Masked echo (e.g., asterisks).
    Masked,
}

impl EchoMode {
    /// Parse echo mode from string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "off" | "no" => Some(EchoMode::Off),
            "on" | "yes" => Some(EchoMode::On),
            "masked" | "" => Some(EchoMode::Masked),
            _ => None,
        }
    }

    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            EchoMode::Off => "off",
            EchoMode::On => "on",
            EchoMode::Masked => "masked",
        }
    }
}

/// Password ask flags (mirrors the C ASK_PASSWORD_* flags).
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AskPasswordFlags: u32 {
        const ACCEPT_CACHED = 1 << 0;
        const PUSH_CACHE    = 1 << 1;
        const ECHO          = 1 << 2;
        const SILENT        = 1 << 3;
        const NO_TTY        = 1 << 4;
        const NO_AGENT      = 1 << 5;
        const CONSOLE_COLOR = 1 << 6;
        const NO_CREDENTIAL = 1 << 7;
        const HIDE_EMOJI    = 1 << 8;
        const HEADLESS      = 1 << 9;
        const USER          = 1 << 10;
    }
}

// ── Argument structure ────────────────────────────────────────────────────

/// Parsed command-line arguments for `systemd-ask-password`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskPasswordArgs {
    /// Icon name for the password dialog.
    pub icon: Option<String>,
    /// Identifier for the ask-password protocol.
    pub id: Option<String>,
    /// Kernel keyring name for caching.
    pub key_name: Option<String>,
    /// Credential name in $CREDENTIALS_DIRECTORY.
    pub credential_name: Option<String>,
    /// Message to display (prompt).
    pub message: Option<String>,
    /// Timeout in microseconds.
    pub timeout_usec: u64,
    /// List multiple passwords if available.
    pub multiple: bool,
    /// Do not print password to stdout.
    pub no_output: bool,
    /// Behavior flags.
    pub flags: AskPasswordFlags,
    /// Suffix password with newline.
    pub newline: bool,
    /// Whether invoked in Varlink mode.
    pub varlink: bool,
}

impl Default for AskPasswordArgs {
    fn default() -> Self {
        Self {
            icon: None,
            id: None,
            key_name: None,
            credential_name: None,
            message: None,
            timeout_usec: DEFAULT_TIMEOUT_USEC,
            multiple: false,
            no_output: false,
            flags: AskPasswordFlags::PUSH_CACHE,
            newline: true,
            varlink: false,
        }
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parse key=value from an option argument like "--timeout=5".
fn parse_option_value(arg: &str) -> Option<&str> {
    arg.split_once('=').map(|(_, v)| v)
}

/// Parse a timeout value from a string (seconds as integer or float).
pub fn parse_timeout(s: &str) -> Result<u64, i32> {
    let secs: f64 = s.parse().map_err(|_| -libc::EINVAL)?;
    if secs < 0.0 {
        return Err(-libc::EINVAL);
    }
    Ok((secs * 1_000_000.0) as u64)
}

/// Parse command-line arguments for `systemd-ask-password`.
///
/// Accepts a slice of string arguments and returns the parsed struct or an error.
pub fn parse_ask_password_args(args: &[&str]) -> Result<AskPasswordArgs, i32> {
    let mut result = AskPasswordArgs::default();
    let mut emoji: Option<&str> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--icon" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.icon = Some(args[i].to_string());
            }
            "--timeout" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.timeout_usec = parse_timeout(args[i])?;
            }
            s if s.starts_with("--timeout=") => {
                let val = parse_option_value(s).ok_or(-libc::EINVAL)?;
                result.timeout_usec = parse_timeout(val)?;
            }
            "--echo" | "-e" => {
                result.flags |= AskPasswordFlags::ECHO;
                result.flags &= !AskPasswordFlags::SILENT;
            }
            s if s.starts_with("--echo=") => {
                let val = parse_option_value(s).unwrap_or("");
                match EchoMode::from_str(val) {
                    Some(EchoMode::On) => {
                        result.flags |= AskPasswordFlags::ECHO;
                        result.flags &= !AskPasswordFlags::SILENT;
                    }
                    Some(EchoMode::Off) => {
                        result.flags |= AskPasswordFlags::SILENT;
                        result.flags &= !AskPasswordFlags::ECHO;
                    }
                    Some(EchoMode::Masked) | None => {
                        result.flags &= !(AskPasswordFlags::ECHO | AskPasswordFlags::SILENT);
                    }
                }
            }
            "--emoji" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                emoji = Some(args[i]);
            }
            "--no-tty" => {
                result.flags |= AskPasswordFlags::NO_TTY;
            }
            "--accept-cached" => {
                result.flags |= AskPasswordFlags::ACCEPT_CACHED;
            }
            "--multiple" => {
                result.multiple = true;
            }
            "--id" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.id = Some(args[i].to_string());
            }
            "--keyname" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.key_name = Some(args[i].to_string());
            }
            "--no-output" => {
                result.no_output = true;
            }
            "--credential" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.credential_name = Some(args[i].to_string());
            }
            "--user" => {
                result.flags |= AskPasswordFlags::USER;
            }
            "--system" => {
                result.flags &= !AskPasswordFlags::USER;
            }
            "-n" => {
                result.newline = false;
            }
            "--help" | "-h" => return Err(0),
            "--version" => return Err(0),
            s if s.starts_with('-') => return Err(-libc::EINVAL),
            other => {
                positional.push(other.to_string());
            }
        }
        i += 1;
    }

    // Handle emoji flag
    if let Some(emoji_val) = emoji {
        if emoji_val.is_empty() || emoji_val == "auto" {
            if result.flags.contains(AskPasswordFlags::ECHO) {
                result.flags |= AskPasswordFlags::HIDE_EMOJI;
            }
        } else {
            let is_yes = matches!(emoji_val, "yes" | "1" | "true" | "on");
            if !is_yes {
                result.flags |= AskPasswordFlags::HIDE_EMOJI;
            }
        }
    }

    // Handle message
    if !positional.is_empty() {
        result.message = Some(positional.join(" "));
    } else if result.flags.contains(AskPasswordFlags::ECHO) {
        result.message = Some("Input:".to_string());
    }

    Ok(result)
}

// ── Core logic ────────────────────────────────────────────────────────────

/// Build a default credential name for the password query.
pub fn default_credential_name(args: &AskPasswordArgs) -> &str {
    args.credential_name.as_deref().unwrap_or("password")
}

/// Format output of password(s).
///
/// Returns the formatted string (or empty string if no_output is true).
pub fn format_password_output(passwords: &[String], no_output: bool, newline: bool) -> String {
    if no_output || passwords.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    for (i, pw) in passwords.iter().enumerate() {
        out.push_str(pw);
        if newline {
            out.push('\n');
        }
        // Only first password unless --multiple
        if i == 0 {
            break;
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = AskPasswordArgs::default();
        assert!(args.icon.is_none());
        assert!(args.message.is_none());
        assert_eq!(args.timeout_usec, DEFAULT_TIMEOUT_USEC);
        assert!(!args.multiple);
        assert!(!args.no_output);
        assert!(args.newline);
        assert!(args.flags.contains(AskPasswordFlags::PUSH_CACHE));
    }

    #[test]
    fn test_echo_mode_from_str() {
        assert_eq!(EchoMode::from_str("off"), Some(EchoMode::Off));
        assert_eq!(EchoMode::from_str("on"), Some(EchoMode::On));
        assert_eq!(EchoMode::from_str("masked"), Some(EchoMode::Masked));
        assert_eq!(EchoMode::from_str(""), Some(EchoMode::Masked));
        assert_eq!(EchoMode::from_str("bogus"), None);
    }

    #[test]
    fn test_echo_mode_as_str() {
        assert_eq!(EchoMode::Off.as_str(), "off");
        assert_eq!(EchoMode::On.as_str(), "on");
        assert_eq!(EchoMode::Masked.as_str(), "masked");
    }

    #[test]
    fn test_parse_timeout() {
        assert_eq!(parse_timeout("60").unwrap(), 60_000_000);
        assert_eq!(parse_timeout("0.5").unwrap(), 500_000);
        assert!(parse_timeout("-1").is_err());
        assert!(parse_timeout("abc").is_err());
    }

    #[test]
    fn test_parse_empty_args() {
        let args = parse_ask_password_args(&[]).unwrap();
        assert!(args.message.is_none());
        assert!(args.icon.is_none());
    }

    #[test]
    fn test_parse_icon() {
        let args = parse_ask_password_args(&["--icon", "dialog-password"]).unwrap();
        assert_eq!(args.icon.as_deref(), Some("dialog-password"));
    }

    #[test]
    fn test_parse_timeout_arg() {
        let args = parse_ask_password_args(&["--timeout", "30"]).unwrap();
        assert_eq!(args.timeout_usec, 30_000_000);
    }

    #[test]
    fn test_parse_echo_short() {
        let args = parse_ask_password_args(&["-e"]).unwrap();
        assert!(args.flags.contains(AskPasswordFlags::ECHO));
        assert!(!args.flags.contains(AskPasswordFlags::SILENT));
    }

    #[test]
    fn test_parse_echo_on() {
        let args = parse_ask_password_args(&["--echo=yes"]).unwrap();
        assert!(args.flags.contains(AskPasswordFlags::ECHO));
    }

    #[test]
    fn test_parse_echo_off() {
        let args = parse_ask_password_args(&["--echo=no"]).unwrap();
        assert!(args.flags.contains(AskPasswordFlags::SILENT));
    }

    #[test]
    fn test_parse_no_output() {
        let args = parse_ask_password_args(&["--no-output"]).unwrap();
        assert!(args.no_output);
    }

    #[test]
    fn test_parse_multiple() {
        let args = parse_ask_password_args(&["--multiple"]).unwrap();
        assert!(args.multiple);
    }

    #[test]
    fn test_parse_positional_message() {
        let args = parse_ask_password_args(&["Enter", "passphrase"]).unwrap();
        assert_eq!(args.message.as_deref(), Some("Enter passphrase"));
    }

    #[test]
    fn test_parse_newline_off() {
        let args = parse_ask_password_args(&["-n"]).unwrap();
        assert!(!args.newline);
    }

    #[test]
    fn test_format_password_output_no_output() {
        let pws = vec!["secret".to_string()];
        assert!(format_password_output(&pws, true, true).is_empty());
    }

    #[test]
    fn test_format_password_output_with_newline() {
        let pws = vec!["secret".to_string()];
        assert_eq!(format_password_output(&pws, false, true), "secret\n");
    }

    #[test]
    fn test_format_password_output_without_newline() {
        let pws = vec!["secret".to_string()];
        assert_eq!(format_password_output(&pws, false, false), "secret");
    }

    #[test]
    fn test_default_credential_name() {
        let args = AskPasswordArgs::default();
        assert_eq!(default_credential_name(&args), "password");
    }

    #[test]
    fn test_echo_mode_default_message() {
        let args = parse_ask_password_args(&["-e"]).unwrap();
        assert_eq!(args.message.as_deref(), Some("Input:"));
    }
}
