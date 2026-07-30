// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/factory-reset.c

use crate::ffi::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;

const FACTORY_RESET_COMPLETE_PATH: &str = "/run/systemd/factory-reset-complete";
const PROC_CMDLINE_PATH: &str = "/proc/cmdline";
const PROC_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const EFI_PATH: &str = "/sys/firmware/efi";
const EFIVARS_PATH: &str = "/sys/firmware/efi/efivars";
const SYSTEMD_EFI_VENDOR: &str = "8cf2644b-4b0b-428f-9387-6d876050dc67";
const FACTORY_RESET_REQUEST_VARIABLE: &str = "FactoryResetRequest";
const OS_RELEASE_PATHS: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum FactoryResetMode {
    Unsupported = 0,
    Unspecified = 1,
    Off = 2,
    On = 3,
    Complete = 4,
    Pending = 5,
}

impl FactoryResetMode {
    pub const INVALID: i32 = -22;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactoryResetError {
    Io(String),
    InvalidKernelCommandLine(String),
    InvalidOsRelease(String),
    InvalidBootId(String),
    InvalidEfiVariable(String),
    Json(String),
}

impl fmt::Display for FactoryResetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(f, "I/O error: {message}"),
            Self::InvalidKernelCommandLine(message) => {
                write!(f, "invalid kernel command line: {message}")
            }
            Self::InvalidOsRelease(message) => write!(f, "invalid os-release: {message}"),
            Self::InvalidBootId(message) => write!(f, "invalid boot ID: {message}"),
            Self::InvalidEfiVariable(message) => write!(f, "invalid EFI variable: {message}"),
            Self::Json(message) => write!(f, "invalid JSON: {message}"),
        }
    }
}

impl std::error::Error for FactoryResetError {}

impl From<io::Error> for FactoryResetError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FactoryResetRequest {
    os_release_id: String,
    os_release_image_id: Option<String>,
    boot_id: Id128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OsRelease {
    id: Option<String>,
    image_id: Option<String>,
}

type Id128 = [u8; 16];

trait Probe {
    fn getenv(&self, name: &str) -> Option<String>;
    fn read_to_string(&self, path: &str) -> io::Result<String>;
    fn read(&self, path: &str) -> io::Result<Vec<u8>>;
    fn path_exists(&self, path: &str) -> io::Result<bool>;
}

struct SystemProbe;

impl Probe for SystemProbe {
    fn getenv(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn read_to_string(&self, path: &str) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn path_exists(&self, path: &str) -> io::Result<bool> {
        match fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

pub fn factory_reset_supported() -> bool {
    factory_reset_supported_with(&SystemProbe)
}

pub fn factory_reset_mode_efi_variable() -> Result<FactoryResetMode, FactoryResetError> {
    factory_reset_mode_efi_variable_with(&SystemProbe)
}

pub fn factory_reset_mode() -> Result<FactoryResetMode, FactoryResetError> {
    factory_reset_mode_with(&SystemProbe)
}

pub fn factory_reset_mode_to_string(mode: FactoryResetMode) -> &'static str {
    match mode {
        FactoryResetMode::Unsupported => "unsupported",
        FactoryResetMode::Unspecified => "unspecified",
        FactoryResetMode::Off => "off",
        FactoryResetMode::On => "on",
        FactoryResetMode::Complete => "complete",
        FactoryResetMode::Pending => "pending",
    }
}

pub fn factory_reset_mode_from_string(value: &str) -> Option<FactoryResetMode> {
    match value {
        "unsupported" => Some(FactoryResetMode::Unsupported),
        "unspecified" => Some(FactoryResetMode::Unspecified),
        "off" => Some(FactoryResetMode::Off),
        "on" => Some(FactoryResetMode::On),
        "complete" => Some(FactoryResetMode::Complete),
        "pending" => Some(FactoryResetMode::Pending),
        _ => None,
    }
}

fn factory_reset_supported_with(probe: &dyn Probe) -> bool {
    match probe.getenv("SYSTEMD_FACTORY_RESET_SUPPORTED") {
        None => true,
        Some(value) => parse_boolean(&value).unwrap_or(true),
    }
}

fn factory_reset_mode_with(probe: &dyn Probe) -> Result<FactoryResetMode, FactoryResetError> {
    if !factory_reset_supported_with(probe) {
        return Ok(FactoryResetMode::Unsupported);
    }

    if probe.path_exists(FACTORY_RESET_COMPLETE_PATH)? {
        return Ok(FactoryResetMode::Complete);
    }

    match proc_cmdline_get_bool(probe, "systemd.factory_reset")? {
        Some(value) => Ok(if value {
            FactoryResetMode::On
        } else {
            FactoryResetMode::Off
        }),
        None => factory_reset_mode_efi_variable_with(probe),
    }
}

fn factory_reset_mode_efi_variable_with(
    probe: &dyn Probe,
) -> Result<FactoryResetMode, FactoryResetError> {
    if !probe.path_exists(EFI_PATH)? {
        return Ok(FactoryResetMode::Unspecified);
    }

    let request_json = match read_factory_reset_request_variable(probe) {
        Ok(value) => value,
        Err(FactoryResetError::Io(message)) if is_not_found_message(&message) => {
            return Ok(FactoryResetMode::Unspecified);
        }
        Err(error) => return Err(error),
    };

    let request = match parse_factory_reset_request(&request_json) {
        Ok(request) => request,
        Err(FactoryResetError::Json(_)) => return Ok(FactoryResetMode::Unspecified),
        Err(error) => return Err(error),
    };

    let os_release = parse_os_release(probe)?;
    if os_release.id.as_deref() != Some(request.os_release_id.as_str())
        || os_release.image_id != request.os_release_image_id
    {
        return Ok(FactoryResetMode::Unspecified);
    }

    let current_boot_id = read_boot_id(probe)?;
    Ok(if current_boot_id == request.boot_id {
        FactoryResetMode::Pending
    } else {
        FactoryResetMode::On
    })
}

fn read_factory_reset_request_variable(probe: &dyn Probe) -> Result<String, FactoryResetError> {
    let path = format!("{EFIVARS_PATH}/{FACTORY_RESET_REQUEST_VARIABLE}-{SYSTEMD_EFI_VENDOR}");
    let bytes = probe.read(&path)?;
    if bytes.len() < 4 {
        return Err(FactoryResetError::InvalidEfiVariable(format!(
            "{FACTORY_RESET_REQUEST_VARIABLE} is too short"
        )));
    }

    String::from_utf8(bytes[4..].to_vec())
        .map(|value| value.trim_end_matches('\0').to_string())
        .map_err(|error| FactoryResetError::InvalidEfiVariable(error.to_string()))
}

fn parse_os_release(probe: &dyn Probe) -> Result<OsRelease, FactoryResetError> {
    for path in OS_RELEASE_PATHS {
        match probe.read_to_string(path) {
            Ok(content) => return parse_os_release_content(&content),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(FactoryResetError::Io(error.to_string()));
            }
        }
    }

    Err(FactoryResetError::InvalidOsRelease(
        "no os-release file found".into(),
    ))
}

fn parse_os_release_content(content: &str) -> Result<OsRelease, FactoryResetError> {
    let mut entries = BTreeMap::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            FactoryResetError::InvalidOsRelease(format!("missing '=' in {line:?}"))
        })?;
        entries.insert(
            key.trim().to_string(),
            unquote_os_release_value(raw_value.trim())?,
        );
    }

    Ok(OsRelease {
        id: entries.get("ID").cloned(),
        image_id: entries.get("IMAGE_ID").cloned(),
    })
}

fn unquote_os_release_value(value: &str) -> Result<String, FactoryResetError> {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        return unescape_shell_like(&value[1..value.len() - 1]);
    }
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        return Ok(value[1..value.len() - 1].to_string());
    }
    Ok(value.to_string())
}

fn unescape_shell_like(value: &str) -> Result<String, FactoryResetError> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }

        let escaped = chars.next().ok_or_else(|| {
            FactoryResetError::InvalidOsRelease("trailing escape in quoted value".into())
        })?;
        output.push(match escaped {
            '"' | '\\' | '$' | '`' => escaped,
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            other => other,
        });
    }
    Ok(output)
}

fn read_boot_id(probe: &dyn Probe) -> Result<Id128, FactoryResetError> {
    let content = probe.read_to_string(PROC_BOOT_ID_PATH)?;
    parse_id128(content.trim()).map_err(FactoryResetError::InvalidBootId)
}

fn proc_cmdline_get_bool(probe: &dyn Probe, key: &str) -> Result<Option<bool>, FactoryResetError> {
    if key.is_empty() {
        return Err(FactoryResetError::InvalidKernelCommandLine(
            "key must not be empty".into(),
        ));
    }

    let cmdline = probe.read_to_string(PROC_CMDLINE_PATH)?;
    let mut matched = None;

    for word in cmdline.split_whitespace() {
        let candidate = normalize_proc_key(word);
        if candidate == normalize_proc_key(key) {
            matched = Some(true);
            continue;
        }

        if let Some((raw_key, raw_value)) = word.split_once('=') {
            if normalize_proc_key(raw_key) == normalize_proc_key(key) {
                matched = Some(parse_boolean(raw_value).ok_or_else(|| {
                    FactoryResetError::InvalidKernelCommandLine(format!("{key}={raw_value}"))
                })?);
            }
        }
    }

    Ok(matched)
}

fn normalize_proc_key(value: &str) -> String {
    value
        .chars()
        .map(|ch| if matches!(ch, '-' | '_') { '_' } else { ch })
        .collect()
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

fn parse_factory_reset_request(value: &str) -> Result<FactoryResetRequest, FactoryResetError> {
    let object = JsonStringObjectParser::new(value).parse()?;
    let os_release_id = object
        .get("osReleaseId")
        .cloned()
        .ok_or_else(|| FactoryResetError::Json("missing osReleaseId".into()))?;
    let boot_id = object
        .get("bootId")
        .ok_or_else(|| FactoryResetError::Json("missing bootId".into()))?;

    Ok(FactoryResetRequest {
        os_release_id,
        os_release_image_id: object.get("osReleaseImageId").cloned(),
        boot_id: parse_id128(boot_id).map_err(FactoryResetError::Json)?,
    })
}

fn parse_id128(value: &str) -> Result<Id128, String> {
    let hex: String = value.trim().chars().filter(|ch| *ch != '-').collect();
    if hex.len() != 32 {
        return Err(format!("expected 32 hex digits, got {}", hex.len()));
    }

    let mut output = [0u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&hex[offset..offset + 2], 16)
            .map_err(|_| format!("invalid UUID byte: {}", &hex[offset..offset + 2]))?;
    }
    Ok(output)
}

fn is_not_found_message(message: &str) -> bool {
    message.contains("No such file")
        || message.contains("os error 2")
        || message.contains("missing")
}

struct JsonStringObjectParser<'a> {
    input: &'a str,
    position: usize,
}

impl<'a> JsonStringObjectParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, position: 0 }
    }

    fn parse(mut self) -> Result<BTreeMap<String, String>, FactoryResetError> {
        self.skip_whitespace();
        self.expect('{')?;
        self.skip_whitespace();

        let mut values = BTreeMap::new();
        if self.peek_char() == Some('}') {
            self.position += 1;
            return Ok(values);
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect(':')?;
            self.skip_whitespace();
            let value = self.parse_string()?;
            values.insert(key, value);
            self.skip_whitespace();

            match self.peek_char() {
                Some(',') => {
                    self.position += 1;
                }
                Some('}') => {
                    self.position += 1;
                    break;
                }
                Some(other) => {
                    return Err(FactoryResetError::Json(format!(
                        "unexpected character {other:?}"
                    )));
                }
                None => return Err(FactoryResetError::Json("unexpected end of input".into())),
            }
        }

        self.skip_whitespace();
        if self.position != self.input.len() {
            return Err(FactoryResetError::Json(
                "trailing content after object".into(),
            ));
        }

        Ok(values)
    }

    fn parse_string(&mut self) -> Result<String, FactoryResetError> {
        self.expect('"')?;
        let mut output = String::new();

        loop {
            let ch = self
                .next_char()
                .ok_or_else(|| FactoryResetError::Json("unterminated string".into()))?;
            match ch {
                '"' => return Ok(output),
                '\\' => output.push(self.parse_escape()?),
                other => output.push(other),
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, FactoryResetError> {
        match self
            .next_char()
            .ok_or_else(|| FactoryResetError::Json("incomplete escape sequence".into()))?
        {
            '"' => Ok('"'),
            '\\' => Ok('\\'),
            '/' => Ok('/'),
            'b' => Ok('\u{0008}'),
            'f' => Ok('\u{000c}'),
            'n' => Ok('\n'),
            'r' => Ok('\r'),
            't' => Ok('\t'),
            'u' => self.parse_unicode_escape(),
            other => Err(FactoryResetError::Json(format!("invalid escape \\{other}"))),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, FactoryResetError> {
        let digits = self.take_chars(4)?;
        let codepoint = u32::from_str_radix(&digits, 16)
            .map_err(|_| FactoryResetError::Json(format!("invalid unicode escape {digits}")))?;
        char::from_u32(codepoint)
            .ok_or_else(|| FactoryResetError::Json(format!("invalid unicode scalar {digits}")))
    }

    fn expect(&mut self, expected: char) -> Result<(), FactoryResetError> {
        match self.next_char() {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(FactoryResetError::Json(format!(
                "expected {expected:?}, found {actual:?}"
            ))),
            None => Err(FactoryResetError::Json(format!(
                "expected {expected:?}, found end of input"
            ))),
        }
    }

    fn take_chars(&mut self, count: usize) -> Result<String, FactoryResetError> {
        let mut output = String::with_capacity(count);
        for _ in 0..count {
            output.push(
                self.next_char()
                    .ok_or_else(|| FactoryResetError::Json("unexpected end of input".into()))?,
            );
        }
        Ok(output)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_char(), Some(ch) if ch.is_ascii_whitespace()) {
            self.position += 1;
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.position..].chars().next()
    }

    fn next_char(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.position += ch.len_utf8();
        Some(ch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockProbe {
        env: HashMap<String, String>,
        text_files: HashMap<String, String>,
        binary_files: HashMap<String, Vec<u8>>,
        existing_paths: BTreeSet<String>,
    }

    impl MockProbe {
        fn with_env(mut self, key: &str, value: &str) -> Self {
            self.env.insert(key.into(), value.into());
            self
        }

        fn with_text(mut self, path: &str, value: &str) -> Self {
            self.text_files.insert(path.into(), value.into());
            self.existing_paths.insert(path.into());
            self
        }

        fn with_binary(mut self, path: &str, value: Vec<u8>) -> Self {
            self.binary_files.insert(path.into(), value);
            self.existing_paths.insert(path.into());
            self
        }

        fn with_existing_path(mut self, path: &str) -> Self {
            self.existing_paths.insert(path.into());
            self
        }
    }

    impl Probe for MockProbe {
        fn getenv(&self, name: &str) -> Option<String> {
            self.env.get(name).cloned()
        }

        fn read_to_string(&self, path: &str) -> io::Result<String> {
            self.text_files
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("missing {path}")))
        }

        fn read(&self, path: &str) -> io::Result<Vec<u8>> {
            self.binary_files
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("missing {path}")))
        }

        fn path_exists(&self, path: &str) -> io::Result<bool> {
            Ok(self.existing_paths.contains(path))
        }
    }

    fn request_variable(payload: &str) -> Vec<u8> {
        let mut output = vec![0, 0, 0, 0];
        output.extend_from_slice(payload.as_bytes());
        output
    }

    fn probe_with_efi_request(payload: &str) -> MockProbe {
        MockProbe::default()
            .with_existing_path(EFI_PATH)
            .with_binary(
                &format!("{EFIVARS_PATH}/{FACTORY_RESET_REQUEST_VARIABLE}-{SYSTEMD_EFI_VENDOR}"),
                request_variable(payload),
            )
            .with_text(PROC_BOOT_ID_PATH, "11111111-1111-1111-1111-111111111111\n")
            .with_text(PROC_CMDLINE_PATH, "")
            .with_text("/etc/os-release", "ID=testos\nIMAGE_ID=test-image\n")
    }

    #[test]
    fn supported_defaults_to_true() {
        assert!(factory_reset_supported_with(&MockProbe::default()));
    }

    #[test]
    fn supported_honors_false_environment() {
        let probe = MockProbe::default().with_env("SYSTEMD_FACTORY_RESET_SUPPORTED", "false");
        assert!(!factory_reset_supported_with(&probe));
    }

    #[test]
    fn supported_ignores_invalid_environment_value() {
        let probe = MockProbe::default().with_env("SYSTEMD_FACTORY_RESET_SUPPORTED", "maybe");
        assert!(factory_reset_supported_with(&probe));
    }

    #[test]
    fn string_tables_round_trip() {
        for mode in [
            FactoryResetMode::Unsupported,
            FactoryResetMode::Unspecified,
            FactoryResetMode::Off,
            FactoryResetMode::On,
            FactoryResetMode::Complete,
            FactoryResetMode::Pending,
        ] {
            let name = factory_reset_mode_to_string(mode);
            assert_eq!(factory_reset_mode_from_string(name), Some(mode));
        }
        assert_eq!(factory_reset_mode_from_string("bogus"), None);
    }

    #[test]
    fn proc_cmdline_get_bool_accepts_bare_key() {
        let probe =
            MockProbe::default().with_text(PROC_CMDLINE_PATH, "foo systemd.factory_reset bar");
        assert_eq!(
            proc_cmdline_get_bool(&probe, "systemd.factory_reset").unwrap(),
            Some(true)
        );
    }

    #[test]
    fn proc_cmdline_get_bool_accepts_false_value() {
        let probe = MockProbe::default().with_text(PROC_CMDLINE_PATH, "systemd.factory_reset=0");
        assert_eq!(
            proc_cmdline_get_bool(&probe, "systemd.factory_reset").unwrap(),
            Some(false)
        );
    }

    #[test]
    fn proc_cmdline_get_bool_rejects_invalid_value() {
        let probe =
            MockProbe::default().with_text(PROC_CMDLINE_PATH, "systemd.factory_reset=maybe");
        assert!(matches!(
            proc_cmdline_get_bool(&probe, "systemd.factory_reset"),
            Err(FactoryResetError::InvalidKernelCommandLine(_))
        ));
    }

    #[test]
    fn factory_reset_mode_returns_unsupported_when_disabled() {
        let probe = MockProbe::default().with_env("SYSTEMD_FACTORY_RESET_SUPPORTED", "0");
        assert_eq!(
            factory_reset_mode_with(&probe).unwrap(),
            FactoryResetMode::Unsupported
        );
    }

    #[test]
    fn factory_reset_mode_returns_complete_when_marker_exists() {
        let probe = MockProbe::default().with_existing_path(FACTORY_RESET_COMPLETE_PATH);
        assert_eq!(
            factory_reset_mode_with(&probe).unwrap(),
            FactoryResetMode::Complete
        );
    }

    #[test]
    fn factory_reset_mode_honors_kernel_cmdline_on() {
        let probe =
            MockProbe::default().with_text(PROC_CMDLINE_PATH, "quiet systemd.factory_reset=yes");
        assert_eq!(
            factory_reset_mode_with(&probe).unwrap(),
            FactoryResetMode::On
        );
    }

    #[test]
    fn factory_reset_mode_honors_kernel_cmdline_off() {
        let probe = MockProbe::default().with_text(PROC_CMDLINE_PATH, "systemd.factory_reset=no");
        assert_eq!(
            factory_reset_mode_with(&probe).unwrap(),
            FactoryResetMode::Off
        );
    }

    #[test]
    fn efi_variable_is_ignored_when_not_booted_via_efi() {
        assert_eq!(
            factory_reset_mode_efi_variable_with(&MockProbe::default()).unwrap(),
            FactoryResetMode::Unspecified
        );
    }

    #[test]
    fn efi_variable_missing_returns_unspecified() {
        let probe = MockProbe::default().with_existing_path(EFI_PATH);
        assert_eq!(
            factory_reset_mode_efi_variable_with(&probe).unwrap(),
            FactoryResetMode::Unspecified
        );
    }

    #[test]
    fn efi_variable_invalid_json_is_ignored() {
        let probe = probe_with_efi_request("not-json");
        assert_eq!(
            factory_reset_mode_efi_variable_with(&probe).unwrap(),
            FactoryResetMode::Unspecified
        );
    }

    #[test]
    fn efi_variable_for_other_os_is_ignored() {
        let probe = probe_with_efi_request(
            r#"{"osReleaseId":"other","osReleaseImageId":"test-image","bootId":"22222222-2222-2222-2222-222222222222"}"#,
        );
        assert_eq!(
            factory_reset_mode_efi_variable_with(&probe).unwrap(),
            FactoryResetMode::Unspecified
        );
    }

    #[test]
    fn efi_variable_matching_current_boot_is_pending() {
        let probe = probe_with_efi_request(
            r#"{"osReleaseId":"testos","osReleaseImageId":"test-image","bootId":"11111111-1111-1111-1111-111111111111"}"#,
        );
        assert_eq!(
            factory_reset_mode_efi_variable_with(&probe).unwrap(),
            FactoryResetMode::Pending
        );
    }

    #[test]
    fn efi_variable_for_previous_boot_is_on() {
        let probe = probe_with_efi_request(
            r#"{"osReleaseId":"testos","osReleaseImageId":"test-image","bootId":"22222222-2222-2222-2222-222222222222"}"#,
        );
        assert_eq!(
            factory_reset_mode_efi_variable_with(&probe).unwrap(),
            FactoryResetMode::On
        );
    }

    #[test]
    fn os_release_parsing_handles_quotes_and_escapes() {
        let parsed = parse_os_release_content("ID=\"test\\nos\"\nIMAGE_ID='image-id'\n").unwrap();
        assert_eq!(parsed.id.as_deref(), Some("test\nos"));
        assert_eq!(parsed.image_id.as_deref(), Some("image-id"));
    }

    #[test]
    fn json_parser_handles_escapes() {
        let parsed = parse_factory_reset_request(
            r#" { "osReleaseId":"test\u006f\n", "bootId":"11111111-1111-1111-1111-111111111111" } "#,
        )
        .unwrap();
        assert_eq!(parsed.os_release_id, "testo\n");
    }
}
