// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/swtpm-util.c, src/shared/swtpm-util.h
//
// Software TPM manufacturing utilities.
//
// Provides functionality for manufacturing a software TPM (swtpm) instance,
// including profile selection from JSON output, configuration file generation,
// and TPM setup execution.

use crate::ffi::*;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ── Constants ─────────────────────────────────────────────────────────────

pub const SWTPM_PATH: &str = "/usr/bin/swtpm";
pub const SWTPM_STATE_DIR: &str = "/run/systemd/tpm2swtpm";

/// Name of the swtpm_setup binary.
const SWTPM_SETUP_BINARY: &str = "swtpm_setup";

/// Name of the swtpm_localca binary.
const SWTPM_LOCALCA_BINARY: &str = "swtpm_localca";

/// Configuration file names written into the state directory.
const LOCALCA_CONF_FILE: &str = "swtpm-localca.conf";
const LOCALCA_OPTIONS_FILE: &str = "swtpm-localca.options";
const SETUP_CONF_FILE: &str = "swtpm_setup.conf";

/// Default content for `swtpm-localca.options`.
const LOCALCA_OPTIONS_CONTENT: &str = "--platform-manufacturer systemd\n\
    --platform-version 2.1\n\
    --platform-model swtpm\n";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during swtpm manufacturing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwtpmError {
    /// A required executable was not found on PATH.
    ExecutableNotFound(String),
    /// Failed to spawn or wait for a child process.
    ProcessFailed(String),
    /// Child process exited with a non-zero status.
    ProcessNonZeroExit(i32),
    /// Failed to read or write a file.
    Io(String),
    /// Failed to parse JSON output from swtpm.
    InvalidJson(String),
    /// The JSON structure was unexpected (e.g., wrong type for a field).
    InvalidProfileFormat(String),
    /// Memory allocation failure.
    OutOfMemory,
}

impl fmt::Display for SwtpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SwtpmError::ExecutableNotFound(name) => {
                write!(f, "Failed to find '{}' binary", name)
            }
            SwtpmError::ProcessFailed(msg) => {
                write!(f, "Failed to run process: {}", msg)
            }
            SwtpmError::ProcessNonZeroExit(code) => {
                write!(f, "Process exited with status {}", code)
            }
            SwtpmError::Io(msg) => write!(f, "I/O error: {}", msg),
            SwtpmError::InvalidJson(msg) => write!(f, "Failed to parse JSON: {}", msg),
            SwtpmError::InvalidProfileFormat(msg) => {
                write!(f, "Invalid profile format: {}", msg)
            }
            SwtpmError::OutOfMemory => write!(f, "Out of memory"),
        }
    }
}

impl std::error::Error for SwtpmError {}

impl From<io::Error> for SwtpmError {
    fn from(err: io::Error) -> Self {
        SwtpmError::Io(err.to_string())
    }
}

// ── Enums ─────────────────────────────────────────────────────────────────

/// Flags for swtpm_setup operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SwtpmSetupFlags {
    None = 0,
    Tpm2 = 1 << 0,
    AllowSignatures = 1 << 1,
    PrintLogs = 1 << 2,
}

// ── Profile types ─────────────────────────────────────────────────────────

/// A swtpm profile entry extracted from `--print-profiles` JSON output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwtpmProfile {
    /// The profile name (e.g., "default-v1", "default-v2").
    pub name: String,
}

// ── Utility functions ─────────────────────────────────────────────────────

/// Convert swtpm setup flags to a human-readable comma-separated string.
pub fn swtpm_setup_flags_to_string(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & SwtpmSetupFlags::Tpm2 as u32 != 0 {
        parts.push("tpm2");
    }
    if flags & SwtpmSetupFlags::AllowSignatures as u32 != 0 {
        parts.push("allow-signatures");
    }
    if flags & SwtpmSetupFlags::PrintLogs as u32 != 0 {
        parts.push("print-logs");
    }
    if parts.is_empty() {
        return "none".to_string();
    }
    parts.join(",")
}

/// Search for an executable in `PATH`.
///
/// Returns the full path to the executable, or an error if not found.
fn find_executable(name: &str) -> Result<PathBuf, SwtpmError> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(SwtpmError::ExecutableNotFound(name.to_string()))
}

/// Version string comparison (strverscmp-improved equivalent).
///
/// Compares two version strings segment by segment. Numeric segments are
/// compared by value (leading zeros are stripped), non-numeric segments
/// bytewise.
///
/// Returns `> 0` if `a` is newer, `< 0` if `b` is newer, `0` if equal.
fn strverscmp_improved(a: &str, b: &str) -> i32 {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut ai: usize = 0;
    let mut bi: usize = 0;

    loop {
        // Skip leading zeros in both strings
        while ai < a_bytes.len() && a_bytes[ai] == b'0' {
            ai += 1;
        }
        while bi < b_bytes.len() && b_bytes[bi] == b'0' {
            bi += 1;
        }

        // Count digit run lengths
        let mut a_digits = 0usize;
        while ai + a_digits < a_bytes.len() && a_bytes[ai + a_digits].is_ascii_digit() {
            a_digits += 1;
        }
        let mut b_digits = 0usize;
        while bi + b_digits < b_bytes.len() && b_bytes[bi + b_digits].is_ascii_digit() {
            b_digits += 1;
        }

        // More digits = bigger number
        if a_digits != b_digits {
            return if a_digits > b_digits { 1 } else { -1 };
        }

        // Compare digit by digit
        for j in 0..a_digits {
            let av = a_bytes[ai + j];
            let bv = b_bytes[bi + j];
            if av != bv {
                return (av as i32) - (bv as i32);
            }
        }

        ai += a_digits;
        bi += b_digits;

        // End of either string
        if ai >= a_bytes.len() || bi >= b_bytes.len() {
            if ai < a_bytes.len() {
                return 1;
            }
            if bi < b_bytes.len() {
                return -1;
            }
            return 0;
        }

        // Compare non-digit characters
        if a_bytes[ai] != b_bytes[bi] {
            return (a_bytes[ai] as i32) - (b_bytes[bi] as i32);
        }

        ai += 1;
        bi += 1;
    }
}

// ── Minimal JSON parser ───────────────────────────────────────────────────
//
// Hand-written recursive-descent parser for the subset of JSON produced by
// `swtpm_setup --print-profiles`.  Follows the same approach used elsewhere
// in this crate (see userdb_dropin.rs, cryptsetup_tpm2.rs, user_record_show.rs).

/// A raw JSON value from the minimal parser.
#[derive(Debug, Clone)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(pairs) => Some(pairs),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(items) => Some(items),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&JsonValue> {
        self.as_object()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

/// Skip ASCII whitespace.
fn skip_whitespace(text: &str, pos: &mut usize) {
    while *pos < text.len() && text.as_bytes()[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

/// Parse a JSON string literal (including the surrounding quotes).
fn parse_json_string(text: &str, pos: &mut usize) -> Result<String, SwtpmError> {
    if *pos >= text.len() || text.as_bytes()[*pos] != b'"' {
        return Err(SwtpmError::InvalidJson("expected '\"'".into()));
    }
    *pos += 1;
    let mut result = String::new();

    while *pos < text.len() {
        let ch = text.as_bytes()[*pos];
        if ch == b'"' {
            *pos += 1;
            return Ok(result);
        }
        if ch == b'\\' {
            *pos += 1;
            if *pos >= text.len() {
                return Err(SwtpmError::InvalidJson("unterminated escape".into()));
            }
            let escaped = text.as_bytes()[*pos];
            match escaped {
                b'"' => result.push('"'),
                b'\\' => result.push('\\'),
                b'/' => result.push('/'),
                b'n' => result.push('\n'),
                b'r' => result.push('\r'),
                b't' => result.push('\t'),
                _ => {
                    result.push('\\');
                    result.push(escaped as char);
                }
            }
        } else {
            result.push(ch as char);
        }
        *pos += 1;
    }

    Err(SwtpmError::InvalidJson("unterminated string".into()))
}

/// Parse a JSON number (integer only – sufficient for profile JSON).
fn parse_json_number(text: &str, pos: &mut usize) -> Result<i64, SwtpmError> {
    let start = *pos;
    while *pos < text.len()
        && (text.as_bytes()[*pos].is_ascii_digit() || text.as_bytes()[*pos] == b'-')
    {
        *pos += 1;
    }
    let num_str = &text[start..*pos];
    num_str
        .parse::<i64>()
        .map_err(|_| SwtpmError::InvalidJson(format!("invalid number: {}", num_str)))
}

/// Parse a single JSON value.
fn parse_json_value(text: &str, pos: &mut usize) -> Result<JsonValue, SwtpmError> {
    skip_whitespace(text, pos);
    if *pos >= text.len() {
        return Err(SwtpmError::InvalidJson("unexpected end of input".into()));
    }

    let ch = text.as_bytes()[*pos];
    match ch {
        b'"' => {
            let s = parse_json_string(text, pos)?;
            Ok(JsonValue::String(s))
        }
        b'{' => {
            *pos += 1;
            let mut pairs = Vec::new();
            skip_whitespace(text, pos);
            if *pos < text.len() && text.as_bytes()[*pos] == b'}' {
                *pos += 1;
                return Ok(JsonValue::Object(pairs));
            }
            loop {
                skip_whitespace(text, pos);
                let key = parse_json_string(text, pos)?;
                skip_whitespace(text, pos);
                if *pos >= text.len() || text.as_bytes()[*pos] != b':' {
                    return Err(SwtpmError::InvalidJson("expected ':'".into()));
                }
                *pos += 1;
                let value = parse_json_value(text, pos)?;
                pairs.push((key, value));
                skip_whitespace(text, pos);
                if *pos >= text.len() {
                    return Err(SwtpmError::InvalidJson(
                        "unexpected end of input in object".into(),
                    ));
                }
                let next = text.as_bytes()[*pos];
                *pos += 1;
                if next == b'}' {
                    break;
                }
                if next != b',' {
                    return Err(SwtpmError::InvalidJson("expected ',' or '}'".into()));
                }
            }
            Ok(JsonValue::Object(pairs))
        }
        b'[' => {
            *pos += 1;
            let mut items = Vec::new();
            skip_whitespace(text, pos);
            if *pos < text.len() && text.as_bytes()[*pos] == b']' {
                *pos += 1;
                return Ok(JsonValue::Array(items));
            }
            loop {
                let value = parse_json_value(text, pos)?;
                items.push(value);
                skip_whitespace(text, pos);
                if *pos >= text.len() {
                    return Err(SwtpmError::InvalidJson(
                        "unexpected end of input in array".into(),
                    ));
                }
                let next = text.as_bytes()[*pos];
                *pos += 1;
                if next == b']' {
                    break;
                }
                if next != b',' {
                    return Err(SwtpmError::InvalidJson("expected ',' or ']'".into()));
                }
            }
            Ok(JsonValue::Array(items))
        }
        b't' => {
            if text[*pos..].starts_with("true") {
                *pos += 4;
                Ok(JsonValue::Bool(true))
            } else {
                Err(SwtpmError::InvalidJson("invalid token".into()))
            }
        }
        b'f' => {
            if text[*pos..].starts_with("false") {
                *pos += 5;
                Ok(JsonValue::Bool(false))
            } else {
                Err(SwtpmError::InvalidJson("invalid token".into()))
            }
        }
        b'n' => {
            if text[*pos..].starts_with("null") {
                *pos += 4;
                Ok(JsonValue::Null)
            } else {
                Err(SwtpmError::InvalidJson("invalid token".into()))
            }
        }
        b'-' | b'0'..=b'9' => {
            let n = parse_json_number(text, pos)?;
            Ok(JsonValue::Number(n))
        }
        _ => Err(SwtpmError::InvalidJson(format!(
            "unexpected character: '{}'",
            ch as char
        ))),
    }
}

/// Parse a complete JSON document (no trailing data allowed).
fn parse_json(text: &str) -> Result<JsonValue, SwtpmError> {
    let mut pos = 0;
    let value = parse_json_value(text, &mut pos)?;
    skip_whitespace(text, &mut pos);
    if pos < text.len() {
        return Err(SwtpmError::InvalidJson(format!(
            "trailing data at position {}",
            pos
        )));
    }
    Ok(value)
}

// ── Profile parsing ───────────────────────────────────────────────────────

/// Parse the JSON output from `swtpm_setup --print-profiles` and extract
/// profile names.
///
/// The expected format is:
/// ```json
/// {
///   "builtin": [
///     {"Name": "default-v1"},
///     {"Name": "default-v2"}
///   ]
/// }
/// ```
///
/// Objects in the array that lack a `"Name"` key are silently skipped
/// (matching the original C behaviour).
///
/// Returns a list of [`SwtpmProfile`] entries found in the `"builtin"` array.
pub fn parse_profiles_json(text: &str) -> Result<Vec<SwtpmProfile>, SwtpmError> {
    let json = parse_json(text)?;

    let builtin = json
        .get("builtin")
        .ok_or_else(|| SwtpmError::InvalidJson("'builtin' field missing".into()))?;

    let array = builtin.as_array().ok_or_else(|| {
        SwtpmError::InvalidProfileFormat("'builtin' field is not an array".into())
    })?;

    let mut profiles = Vec::new();
    for item in array {
        let obj = item.as_object().ok_or_else(|| {
            SwtpmError::InvalidProfileFormat("Profile entry is not a JSON object".into())
        })?;

        // Look for a "Name" key whose value is a string.
        let name_value = obj.iter().find(|(k, _)| k == "Name");
        match name_value {
            Some((_, JsonValue::String(name))) => {
                profiles.push(SwtpmProfile { name: name.clone() });
            }
            Some(_) => {
                return Err(SwtpmError::InvalidProfileFormat(
                    "Profile 'Name' field is not a string".into(),
                ))
            }
            None => {
                // No "Name" key – skip silently (matches C behaviour).
                continue;
            }
        }
    }

    Ok(profiles)
}

/// Find the best profile from a list of swtpm profiles.
///
/// Selects the profile with the highest version among those whose names
/// start with `"default-v"` (e.g. `"default-v1"`, `"default-v2"`).
///
/// Returns `None` if no matching profile is found.
pub fn find_best_profile(profiles: &[SwtpmProfile]) -> Option<&str> {
    profiles
        .iter()
        .filter(|p| p.name.starts_with("default-v"))
        .max_by(|a, b| {
            let cmp = strverscmp_improved(&a.name, &b.name);
            cmp.cmp(&0)
        })
        .map(|p| p.name.as_str())
}

// ── Configuration file generation ─────────────────────────────────────────

/// Generate the content for `swtpm-localca.conf`.
pub fn generate_localca_conf(state_dir: &Path) -> String {
    let state = state_dir.display();
    format!(
        "statedir = {0}\n\
         signingkey = {0}/signing-private-key.pem\n\
         issuercert = {0}/issuer-certificate.pem\n\
         certserial = {0}/certserial\n",
        state
    )
}

/// Generate the content for `swtpm-localca.options`.
pub fn generate_localca_options() -> &'static str {
    LOCALCA_OPTIONS_CONTENT
}

/// Generate the content for `swtpm_setup.conf`.
pub fn generate_setup_conf(
    state_dir: &Path,
    swtpm_localca: &Path,
    localca_conf: &Path,
    localca_options: &Path,
) -> String {
    format!(
        "create_certs_tool = {}\n\
         create_certs_tool_config = {}\n\
         create_certs_tool_options = {}\n",
        swtpm_localca.display(),
        localca_conf.display(),
        localca_options.display()
    )
}

// ── Config file writing ───────────────────────────────────────────────────

/// Write a configuration file, creating parent directories as needed.
fn write_config_file(path: &Path, content: &str) -> Result<(), SwtpmError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

/// Write the `swtpm-localca.conf` file to the state directory.
pub fn write_localca_conf(state_dir: &Path) -> Result<(), SwtpmError> {
    let conf_path = state_dir.join(LOCALCA_CONF_FILE);
    let content = generate_localca_conf(state_dir);
    write_config_file(&conf_path, &content)
}

/// Write the `swtpm-localca.options` file to the state directory.
pub fn write_localca_options(state_dir: &Path) -> Result<(), SwtpmError> {
    let options_path = state_dir.join(LOCALCA_OPTIONS_FILE);
    write_config_file(&options_path, generate_localca_options())
}

/// Write the `swtpm_setup.conf` file to the state directory.
pub fn write_setup_conf(state_dir: &Path, swtpm_localca: &Path) -> Result<(), SwtpmError> {
    let conf_path = state_dir.join(SETUP_CONF_FILE);
    let localca_conf = state_dir.join(LOCALCA_CONF_FILE);
    let localca_options = state_dir.join(LOCALCA_OPTIONS_FILE);
    let content = generate_setup_conf(state_dir, swtpm_localca, &localca_conf, &localca_options);
    write_config_file(&conf_path, &content)
}

// ── Argument construction ─────────────────────────────────────────────────

/// Build the argument list for the swtpm_setup manufacturing command.
///
/// Faithfully reproduces every flag from the original C implementation.
fn build_setup_args(
    swtpm_setup: &Path,
    state_dir: &Path,
    setup_conf: &Path,
    secret: Option<&str>,
    best_profile: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        swtpm_setup.display().to_string(),
        "--tpm-state".to_string(),
        state_dir.display().to_string(),
        "--tpm2".to_string(),
        "--pcr-banks".to_string(),
        "sha256".to_string(),
        "--ecc".to_string(),
        "--createek".to_string(),
        "--create-ek-cert".to_string(),
        "--create-platform-cert".to_string(),
        "--not-overwrite".to_string(),
        "--config".to_string(),
        setup_conf.display().to_string(),
    ];

    if let Some(keyfile) = secret {
        args.push(format!("--keyfile={}", keyfile));
    }
    if let Some(profile) = best_profile {
        args.push(format!("--profile-name={}", profile));
    }

    args
}

// ── Process helpers ───────────────────────────────────────────────────────

/// Run `swtpm_setup --tpm2 --print-profiles` and parse the output to
/// determine the best available profile.
///
/// Returns `Ok(None)` when no profiles could be acquired (empty output or
/// no `"default-v*"` profiles), which is treated as non-fatal – the
/// implementation may simply be too old to support profiles.
fn run_print_profiles(swtpm_setup: &Path) -> Result<Option<String>, SwtpmError> {
    let output = Command::new(swtpm_setup)
        .args(["--tpm2", "--print-profiles"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| {
            SwtpmError::ProcessFailed(format!("Failed to run swtpm_setup --print-profiles: {}", e))
        })?;

    // NB: we ignore the exit status of --print-profiles – it's broken.
    // Instead we check whether we received valid JSON on stdout (matches C).
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();

    if text.is_empty() {
        return Ok(None);
    }

    let profiles = parse_profiles_json(text)?;
    Ok(find_best_profile(&profiles).map(|s| s.to_string()))
}

/// Execute the swtpm_setup manufacturing command and wait for completion.
fn run_setup_command(args: &[String]) -> Result<(), SwtpmError> {
    let program = &args[0];
    let cmd_args: &[String] = &args[1..];

    let status = Command::new(program)
        .args(cmd_args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| {
            SwtpmError::ProcessFailed(format!("Failed to execute '{}': {}", program, e))
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(SwtpmError::ProcessNonZeroExit(status.code().unwrap_or(-1)))
    }
}

// ── Main entry point ──────────────────────────────────────────────────────

/// Manufacture a software TPM instance.
///
/// This function performs the full swtpm manufacturing process:
///
/// 1. Locates the `swtpm_setup` binary on `PATH`.
/// 2. Runs `swtpm_setup --tpm2 --print-profiles` to determine the best
///    available profile (preferring the newest `"default-v*"` profile).
/// 3. Writes configuration files (`swtpm-localca.conf`, `swtpm-localca.options`,
///    `swtpm_setup.conf`) into the state directory.
/// 4. Locates the `swtpm_localca` binary on `PATH`.
/// 5. Runs `swtpm_setup` with the appropriate flags to create the TPM.
///
/// # Arguments
///
/// * `state_dir` – Directory where TPM state and configuration files are stored.
/// * `secret`   – Optional path to a key file for encrypting the TPM state.
///
/// # Errors
///
/// Returns [`SwtpmError`] if any step fails (binary not found, process error,
/// file I/O error, or invalid profile data).
pub fn manufacture_swtpm(state_dir: &str, secret: Option<&str>) -> Result<(), SwtpmError> {
    let state_path = Path::new(state_dir);

    // Step 1: Find swtpm_setup binary.
    let swtpm_setup = find_executable(SWTPM_SETUP_BINARY)?;

    // Step 2: Query available profiles and pick the best one.
    let best_profile = run_print_profiles(&swtpm_setup)?;

    // Step 3: Write swtpm-localca configuration files.
    write_localca_conf(state_path)?;
    write_localca_options(state_path)?;

    // Step 4: Find swtpm_localca and write swtpm_setup.conf.
    let swtpm_localca = find_executable(SWTPM_LOCALCA_BINARY)?;
    write_setup_conf(state_path, &swtpm_localca)?;

    // Step 5: Build arguments and execute swtpm_setup.
    let setup_conf_path = state_path.join(SETUP_CONF_FILE);
    let args = build_setup_args(
        &swtpm_setup,
        state_path,
        &setup_conf_path,
        secret,
        best_profile.as_deref(),
    );

    run_setup_command(&args)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── Flag tests ────────────────────────────────────────────────────

    #[test]
    fn test_swtpm_setup_flags_repr() {
        assert_eq!(SwtpmSetupFlags::None as i32, 0);
        assert_eq!(SwtpmSetupFlags::Tpm2 as i32, 1);
        assert_eq!(SwtpmSetupFlags::AllowSignatures as i32, 2);
        assert_eq!(SwtpmSetupFlags::PrintLogs as i32, 4);
    }

    #[test]
    fn test_swtpm_setup_flags_to_string() {
        assert_eq!(swtpm_setup_flags_to_string(0), "none");
        assert_eq!(
            swtpm_setup_flags_to_string(SwtpmSetupFlags::Tpm2 as u32),
            "tpm2"
        );
        assert_eq!(
            swtpm_setup_flags_to_string(SwtpmSetupFlags::AllowSignatures as u32),
            "allow-signatures"
        );
        assert_eq!(
            swtpm_setup_flags_to_string(SwtpmSetupFlags::PrintLogs as u32),
            "print-logs"
        );
        assert_eq!(
            swtpm_setup_flags_to_string(
                (SwtpmSetupFlags::Tpm2 as u32) | (SwtpmSetupFlags::AllowSignatures as u32)
            ),
            "tpm2,allow-signatures"
        );
        assert_eq!(
            swtpm_setup_flags_to_string(
                (SwtpmSetupFlags::Tpm2 as u32)
                    | (SwtpmSetupFlags::AllowSignatures as u32)
                    | (SwtpmSetupFlags::PrintLogs as u32)
            ),
            "tpm2,allow-signatures,print-logs"
        );
    }

    #[test]
    fn test_swtpm_constants() {
        assert!(!SWTPM_PATH.is_empty());
        assert!(!SWTPM_STATE_DIR.is_empty());
        assert!(SWTPM_PATH.starts_with('/'));
        assert!(SWTPM_STATE_DIR.starts_with('/'));
    }

    // ── Version comparison tests ──────────────────────────────────────

    #[test]
    fn test_strverscmp_improved_basic() {
        assert!(strverscmp_improved("1", "2") < 0);
        assert!(strverscmp_improved("2", "1") > 0);
        assert_eq!(strverscmp_improved("1", "1"), 0);
    }

    #[test]
    fn test_strverscmp_improved_versioned_profiles() {
        assert!(strverscmp_improved("default-v1", "default-v2") < 0);
        assert!(strverscmp_improved("default-v2", "default-v1") > 0);
        assert!(strverscmp_improved("default-v1", "default-v10") < 0);
        assert!(strverscmp_improved("default-v10", "default-v2") > 0);
    }

    #[test]
    fn test_strverscmp_improved_leading_zeros() {
        assert_eq!(strverscmp_improved("01", "1"), 0);
        assert_eq!(strverscmp_improved("001", "1"), 0);
        assert!(strverscmp_improved("001", "02") < 0);
    }

    #[test]
    fn test_strverscmp_improved_empty() {
        assert!(strverscmp_improved("", "1") < 0);
        assert!(strverscmp_improved("1", "") > 0);
        assert_eq!(strverscmp_improved("", ""), 0);
    }

    // ── JSON parsing tests ───────────────────────────────────────────

    #[test]
    fn test_parse_profiles_json_valid() {
        let json =
            r#"{"builtin": [{"Name": "default-v1"}, {"Name": "custom"}, {"Name": "default-v2"}]}"#;
        let profiles = parse_profiles_json(json).unwrap();
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles[0].name, "default-v1");
        assert_eq!(profiles[1].name, "custom");
        assert_eq!(profiles[2].name, "default-v2");
    }

    #[test]
    fn test_parse_profiles_json_empty_builtin() {
        let json = r#"{"builtin": []}"#;
        let profiles = parse_profiles_json(json).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_parse_profiles_json_missing_builtin() {
        let json = r#"{"other": "value"}"#;
        let result = parse_profiles_json(json);
        assert!(result.is_err());
        match result.unwrap_err() {
            SwtpmError::InvalidJson(msg) => assert!(msg.contains("builtin")),
            other => panic!("expected InvalidJson, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_profiles_json_builtin_not_array() {
        let json = r#"{"builtin": "not-array"}"#;
        let result = parse_profiles_json(json);
        assert!(result.is_err());
        match result.unwrap_err() {
            SwtpmError::InvalidProfileFormat(msg) => {
                assert!(msg.contains("not an array"))
            }
            other => panic!("expected InvalidProfileFormat, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_profiles_json_skip_no_name() {
        let json = r#"{"builtin": [{"Other": "value"}, {"Name": "default-v1"}]}"#;
        let profiles = parse_profiles_json(json).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "default-v1");
    }

    #[test]
    fn test_parse_profiles_json_name_not_string() {
        let json = r#"{"builtin": [{"Name": 42}]}"#;
        let result = parse_profiles_json(json);
        assert!(result.is_err());
        match result.unwrap_err() {
            SwtpmError::InvalidProfileFormat(msg) => {
                assert!(msg.contains("not a string"))
            }
            other => panic!("expected InvalidProfileFormat, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_profiles_json_invalid_syntax() {
        let result = parse_profiles_json("{invalid}");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_profiles_json_entry_not_object() {
        let json = r#"{"builtin": ["string", {"Name": "default-v1"}]}"#;
        let result = parse_profiles_json(json);
        assert!(result.is_err());
        match result.unwrap_err() {
            SwtpmError::InvalidProfileFormat(msg) => {
                assert!(msg.contains("not a JSON object"))
            }
            other => panic!("expected InvalidProfileFormat, got {:?}", other),
        }
    }

    // ── Profile selection tests ───────────────────────────────────────

    #[test]
    fn test_find_best_profile_picks_newest() {
        let profiles = vec![
            SwtpmProfile {
                name: "custom".into(),
            },
            SwtpmProfile {
                name: "default-v1".into(),
            },
            SwtpmProfile {
                name: "default-v3".into(),
            },
            SwtpmProfile {
                name: "default-v2".into(),
            },
        ];
        assert_eq!(find_best_profile(&profiles), Some("default-v3"));
    }

    #[test]
    fn test_find_best_profile_no_defaults() {
        let profiles = vec![
            SwtpmProfile {
                name: "custom".into(),
            },
            SwtpmProfile {
                name: "other".into(),
            },
        ];
        assert_eq!(find_best_profile(&profiles), None);
    }

    #[test]
    fn test_find_best_profile_empty() {
        assert_eq!(find_best_profile(&[]), None);
    }

    #[test]
    fn test_find_best_profile_single() {
        let profiles = vec![SwtpmProfile {
            name: "default-v1".into(),
        }];
        assert_eq!(find_best_profile(&profiles), Some("default-v1"));
    }

    // ── Config generation tests ───────────────────────────────────────

    #[test]
    fn test_generate_localca_conf() {
        let dir = Path::new("/var/lib/tpm");
        let conf = generate_localca_conf(dir);
        assert!(conf.contains("statedir = /var/lib/tpm\n"));
        assert!(conf.contains("signingkey = /var/lib/tpm/signing-private-key.pem\n"));
        assert!(conf.contains("issuercert = /var/lib/tpm/issuer-certificate.pem\n"));
        assert!(conf.contains("certserial = /var/lib/tpm/certserial\n"));
    }

    #[test]
    fn test_generate_localca_options() {
        let opts = generate_localca_options();
        assert!(opts.contains("--platform-manufacturer systemd"));
        assert!(opts.contains("--platform-version 2.1"));
        assert!(opts.contains("--platform-model swtpm"));
    }

    #[test]
    fn test_generate_setup_conf() {
        let dir = Path::new("/var/lib/tpm");
        let localca = Path::new("/usr/bin/swtpm_localca");
        let conf_file = Path::new("/var/lib/tpm/swtpm-localca.conf");
        let opts_file = Path::new("/var/lib/tpm/swtpm-localca.options");
        let conf = generate_setup_conf(dir, localca, conf_file, opts_file);
        assert!(conf.contains("create_certs_tool = /usr/bin/swtpm_localca\n"));
        assert!(conf.contains("create_certs_tool_config = /var/lib/tpm/swtpm-localca.conf\n"));
        assert!(conf.contains("create_certs_tool_options = /var/lib/tpm/swtpm-localca.options\n"));
    }

    // ── Argument construction tests ───────────────────────────────────

    #[test]
    fn test_build_setup_args_basic() {
        let setup = Path::new("/usr/bin/swtpm_setup");
        let dir = Path::new("/var/lib/tpm");
        let conf = Path::new("/var/lib/tpm/swtpm_setup.conf");
        let args = build_setup_args(setup, dir, conf, None, None);

        assert_eq!(args[0], "/usr/bin/swtpm_setup");
        assert!(args.contains(&"--tpm-state".to_string()));
        assert!(args.contains(&"/var/lib/tpm".to_string()));
        assert!(args.contains(&"--tpm2".to_string()));
        assert!(args.contains(&"--pcr-banks".to_string()));
        assert!(args.contains(&"sha256".to_string()));
        assert!(args.contains(&"--ecc".to_string()));
        assert!(args.contains(&"--createek".to_string()));
        assert!(args.contains(&"--create-ek-cert".to_string()));
        assert!(args.contains(&"--create-platform-cert".to_string()));
        assert!(args.contains(&"--not-overwrite".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("--keyfile=")));
        assert!(!args.iter().any(|a| a.starts_with("--profile-name=")));
    }

    #[test]
    fn test_build_setup_args_with_secret() {
        let setup = Path::new("/usr/bin/swtpm_setup");
        let dir = Path::new("/var/lib/tpm");
        let conf = Path::new("/var/lib/tpm/swtpm_setup.conf");
        let args = build_setup_args(setup, dir, conf, Some("/secret/key"), None);

        assert!(args.contains(&"--keyfile=/secret/key".to_string()));
    }

    #[test]
    fn test_build_setup_args_with_profile() {
        let setup = Path::new("/usr/bin/swtpm_setup");
        let dir = Path::new("/var/lib/tpm");
        let conf = Path::new("/var/lib/tpm/swtpm_setup.conf");
        let args = build_setup_args(setup, dir, conf, None, Some("default-v2"));

        assert!(args.contains(&"--profile-name=default-v2".to_string()));
    }

    // ── Error type tests ──────────────────────────────────────────────

    #[test]
    fn test_swtpm_error_display() {
        assert_eq!(
            SwtpmError::ExecutableNotFound("swtpm_setup".to_string()).to_string(),
            "Failed to find 'swtpm_setup' binary"
        );
        assert_eq!(
            SwtpmError::ProcessFailed("fork failed".to_string()).to_string(),
            "Failed to run process: fork failed"
        );
        assert_eq!(
            SwtpmError::ProcessNonZeroExit(1).to_string(),
            "Process exited with status 1"
        );
        assert_eq!(
            SwtpmError::Io("permission denied".to_string()).to_string(),
            "I/O error: permission denied"
        );
        assert_eq!(
            SwtpmError::InvalidJson("bad token".to_string()).to_string(),
            "Failed to parse JSON: bad token"
        );
        assert_eq!(
            SwtpmError::InvalidProfileFormat("not array".to_string()).to_string(),
            "Invalid profile format: not array"
        );
        assert_eq!(SwtpmError::OutOfMemory.to_string(), "Out of memory");
    }

    #[test]
    fn test_swtpm_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let swtpm_err: SwtpmError = io_err.into();
        match swtpm_err {
            SwtpmError::Io(msg) => assert!(msg.contains("file not found")),
            other => panic!("expected Io variant, got {:?}", other),
        }
    }

    // ── Round-trip config file tests ──────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_write_and_read_localca_conf() {
        let dir = std::env::temp_dir().join("swtpm_test_localca_conf");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        write_localca_conf(&dir).unwrap();
        let content = fs::read_to_string(dir.join(LOCALCA_CONF_FILE)).unwrap();
        assert!(content.contains("statedir ="));
        assert!(content.contains("signingkey ="));
        assert!(content.contains("issuercert ="));
        assert!(content.contains("certserial ="));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_write_and_read_localca_options() {
        let dir = std::env::temp_dir().join("swtpm_test_localca_opts");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        write_localca_options(&dir).unwrap();
        let content = fs::read_to_string(dir.join(LOCALCA_OPTIONS_FILE)).unwrap();
        assert!(content.contains("--platform-manufacturer systemd"));
        assert!(content.contains("--platform-version 2.1"));
        assert!(content.contains("--platform-model swtpm"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_write_and_read_setup_conf() {
        let dir = std::env::temp_dir().join("swtpm_test_setup_conf");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let localca = PathBuf::from("/usr/bin/swtpm_localca");
        write_setup_conf(&dir, &localca).unwrap();
        let content = fs::read_to_string(dir.join(SETUP_CONF_FILE)).unwrap();
        assert!(content.contains("create_certs_tool = /usr/bin/swtpm_localca"));
        assert!(content.contains("create_certs_tool_config ="));
        assert!(content.contains("create_certs_tool_options ="));

        let _ = fs::remove_dir_all(&dir);
    }
}
