// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/creds/creds.c
//
// Display and process credentials.
// Supports encryption, decryption, listing, and transcoding.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum freshness for timestamps (30 seconds).
pub const TIMESTAMP_FRESH_MAX_USEC: u64 = 30_000_000;

// ── Types ─────────────────────────────────────────────────────────────────

/// Transcoding mode for credential data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscodeMode {
    Off,
    Base64,
    UnBase64,
    Hex,
    UnHex,
}

impl TranscodeMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "off" => Some(TranscodeMode::Off),
            "base64" => Some(TranscodeMode::Base64),
            "unbase64" => Some(TranscodeMode::UnBase64),
            "hex" => Some(TranscodeMode::Hex),
            "unhex" => Some(TranscodeMode::UnHex),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TranscodeMode::Off => "off",
            TranscodeMode::Base64 => "base64",
            TranscodeMode::UnBase64 => "unbase64",
            TranscodeMode::Hex => "hex",
            TranscodeMode::UnHex => "unhex",
        }
    }
}

/// Credential key type selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredKeyType {
    Auto,
    AutoInitrd,
    Host,
    Tpm2,
    Tpm2WithPublicKey,
    HostTpm2,
    Tpm2Host,
    HostTpm2WithPublicKey,
    Tpm2WithPublicKeyHost,
    Null,
    Tpm2Absent,
}

impl CredKeyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(CredKeyType::Auto),
            "auto-initrd" => Some(CredKeyType::AutoInitrd),
            "host" => Some(CredKeyType::Host),
            "tpm2" => Some(CredKeyType::Tpm2),
            "tpm2-with-public-key" => Some(CredKeyType::Tpm2WithPublicKey),
            "host+tpm2" => Some(CredKeyType::HostTpm2),
            "tpm2+host" => Some(CredKeyType::Tpm2Host),
            "host+tpm2-with-public-key" => Some(CredKeyType::HostTpm2WithPublicKey),
            "tpm2-with-public-key+host" => Some(CredKeyType::Tpm2WithPublicKeyHost),
            "null" => Some(CredKeyType::Null),
            "tpm2-absent" => Some(CredKeyType::Tpm2Absent),
            _ => None,
        }
    }
}

/// Credential scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialScope {
    System,
    User,
}

impl CredentialScope {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "system" => Some(CredentialScope::System),
            "user" => Some(CredentialScope::User),
            _ => None,
        }
    }
}

/// Verb (subcommand) for the creds tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredsVerb {
    List,
    Cat,
    Encrypt,
    Decrypt,
    Setup,
    Help,
}

impl CredsVerb {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "list" => Some(CredsVerb::List),
            "cat" => Some(CredsVerb::Cat),
            "encrypt" => Some(CredsVerb::Encrypt),
            "decrypt" => Some(CredsVerb::Decrypt),
            "setup" => Some(CredsVerb::Setup),
            "help" => Some(CredsVerb::Help),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialFlags(u32);

impl CredentialFlags {
    pub const ALLOW_NULL: Self = Self(1 << 0);
    pub const REFUSE_NULL: Self = Self(1 << 1);
    pub const ANY_SCOPE: Self = Self(1 << 2);
    pub const IPC_ALLOW_INTERACTIVE: Self = Self(1 << 3);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(&self) -> u32 {
        self.0
    }

    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    pub fn from_bits_truncate(bits: u32) -> Self {
        Self(
            bits & (Self::ALLOW_NULL.0
                | Self::REFUSE_NULL.0
                | Self::ANY_SCOPE.0
                | Self::IPC_ALLOW_INTERACTIVE.0),
        )
    }
}

impl std::ops::BitOr for CredentialFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CredentialFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for CredentialFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for CredentialFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::Not for CredentialFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// Parsed command-line arguments for `systemd-creds`.
#[derive(Debug, Clone, PartialEq)]
pub struct CredsArgs {
    pub system: bool,
    pub legend: bool,
    pub quiet: bool,
    pub pretty: bool,
    pub transcode: TranscodeMode,
    pub newline: i32,
    pub with_key: Option<CredKeyType>,
    pub tpm2_device: Option<String>,
    pub name: Option<String>,
    pub name_any: bool,
    pub uid: Option<u32>,
    pub credential_flags: CredentialFlags,
    pub ask_password: bool,
    pub verb: Option<CredsVerb>,
    pub positional: Vec<String>,
}

impl Default for CredsArgs {
    fn default() -> Self {
        Self {
            system: false,
            legend: true,
            quiet: false,
            pretty: false,
            transcode: TranscodeMode::Off,
            newline: -1,
            with_key: None,
            tpm2_device: None,
            name: None,
            name_any: false,
            uid: None,
            credential_flags: CredentialFlags::empty(),
            ask_password: true,
            verb: None,
            positional: Vec::new(),
        }
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

pub fn parse_creds_args(args: &[&str]) -> Result<CredsArgs, i32> {
    let mut result = CredsArgs::default();
    let mut i = 0;

    while i < args.len() {
        match args[i] {
            "--help" | "-h" => return Err(0),
            "--version" => return Err(0),
            "--system" => result.system = true,
            "--no-legend" => result.legend = false,
            "--quiet" | "-q" => result.quiet = true,
            "--pretty" | "-p" => result.pretty = true,
            "--allow-null" => {
                result.credential_flags |= CredentialFlags::ALLOW_NULL;
                result.credential_flags &= !CredentialFlags::REFUSE_NULL;
            }
            "--refuse-null" => {
                result.credential_flags |= CredentialFlags::REFUSE_NULL;
                result.credential_flags &= !CredentialFlags::ALLOW_NULL;
            }
            "--no-ask-password" => result.ask_password = false,
            "--user" => {
                if result.uid.is_none() {
                    // uid will be resolved at runtime
                }
            }
            "--transcode" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                if args[i] == "false" || args[i] == "0" {
                    result.transcode = TranscodeMode::Off;
                } else {
                    result.transcode = TranscodeMode::from_str(args[i]).ok_or(-libc::EINVAL)?;
                }
            }
            "--with-key" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                if args[i] == "help" {
                    return Err(0);
                }
                if args[i].is_empty() {
                    result.with_key = None;
                } else {
                    result.with_key = Some(CredKeyType::from_str(args[i]).ok_or(-libc::EINVAL)?);
                }
            }
            "-H" => result.with_key = Some(CredKeyType::Host),
            "-T" => result.with_key = Some(CredKeyType::Tpm2),
            "--tpm2-device" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                if args[i] != "auto" {
                    result.tpm2_device = Some(args[i].to_string());
                }
            }
            "--name" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                if args[i].is_empty() {
                    result.name = None;
                    result.name_any = true;
                } else {
                    if !credential_name_valid(args[i]) {
                        return Err(-libc::EINVAL);
                    }
                    result.name = Some(args[i].to_string());
                    result.name_any = false;
                }
            }
            "--newline" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.newline = match args[i] {
                    "yes" | "true" | "1" => 1,
                    "no" | "false" | "0" => 0,
                    _ => -1,
                };
            }
            s if s.starts_with('-') => return Err(-libc::EINVAL),
            other => {
                if result.verb.is_none() {
                    result.verb = CredsVerb::from_str(other);
                    if result.verb.is_none() {
                        return Err(-libc::EINVAL);
                    }
                } else {
                    result.positional.push(other.to_string());
                }
            }
        }
        i += 1;
    }

    if result.ask_password {
        result.credential_flags |= CredentialFlags::IPC_ALLOW_INTERACTIVE;
    }

    Ok(result)
}

// ── Core logic ────────────────────────────────────────────────────────────

/// Validate a credential name.
pub fn credential_name_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    let mut chars = name.chars();
    let first = match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => c,
        _ => return false,
    };
    for ch in chars {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' && ch != '.' {
            return false;
        }
    }
    true
}

/// Check if a timestamp is fresh (within TIMESTAMP_FRESH_MAX_USEC of now).
pub fn timestamp_is_fresh(ts: u64, now: u64) -> bool {
    if ts > now {
        ts - now <= TIMESTAMP_FRESH_MAX_USEC
    } else {
        now - ts <= TIMESTAMP_FRESH_MAX_USEC
    }
}

/// Check if path is empty or dash (stdin/stdout indicator).
pub fn empty_or_dash(path: &str) -> bool {
    path.is_empty() || path == "-"
}

/// Determine security classification of a credential file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSecurity {
    Encrypted,
    Secure,
    Weak,
    Insecure,
}

/// Transcode data to base64.
pub fn transcode_base64(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        out.push(CHARS[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(CHARS[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Transcode data to hex.
pub fn transcode_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Normalize separator character for enum name comparison.
pub fn normalize_separator(c: char) -> char {
    match c {
        '-' | '+' | '_' => '_',
        other => other,
    }
}

/// Compare enum names with separator normalization.
pub fn enum_name_equal(x: &str, y: &str) -> bool {
    if x == y {
        return true;
    }
    let mut xi = x.chars().map(normalize_separator);
    let mut yi = y.chars().map(normalize_separator);
    loop {
        match (xi.next(), yi.next()) {
            (Some(a), Some(b)) if a == b => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcode_mode_roundtrip() {
        for mode in [
            TranscodeMode::Off,
            TranscodeMode::Base64,
            TranscodeMode::UnBase64,
            TranscodeMode::Hex,
            TranscodeMode::UnHex,
        ] {
            assert_eq!(TranscodeMode::from_str(mode.as_str()), Some(mode));
        }
    }

    #[test]
    fn test_cred_key_type_from_str() {
        assert_eq!(CredKeyType::from_str("auto"), Some(CredKeyType::Auto));
        assert_eq!(CredKeyType::from_str("host"), Some(CredKeyType::Host));
        assert_eq!(CredKeyType::from_str("null"), Some(CredKeyType::Null));
        assert_eq!(CredKeyType::from_str("invalid"), None);
    }

    #[test]
    fn test_credential_scope_from_str() {
        assert_eq!(
            CredentialScope::from_str("system"),
            Some(CredentialScope::System)
        );
        assert_eq!(
            CredentialScope::from_str("user"),
            Some(CredentialScope::User)
        );
    }

    #[test]
    fn test_credential_name_valid() {
        assert!(credential_name_valid("my-cred"));
        assert!(credential_name_valid("_test.cred"));
        assert!(credential_name_valid("ABC123"));
        assert!(!credential_name_valid(""));
        assert!(!credential_name_valid("123abc"));
        assert!(!credential_name_valid("has space"));
        assert!(!credential_name_valid("a/b"));
    }

    #[test]
    fn test_timestamp_is_fresh() {
        assert!(timestamp_is_fresh(100, 100));
        assert!(timestamp_is_fresh(100_000_000, 130_000_000));
        assert!(!timestamp_is_fresh(100, 200_000_000));
    }

    #[test]
    fn test_empty_or_dash() {
        assert!(empty_or_dash(""));
        assert!(empty_or_dash("-"));
        assert!(!empty_or_dash("file.txt"));
    }

    #[test]
    fn test_transcode_base64() {
        assert_eq!(transcode_base64(b""), "");
        assert_eq!(transcode_base64(b"f"), "Zg==");
        assert_eq!(transcode_base64(b"fo"), "Zm8=");
        assert_eq!(transcode_base64(b"foo"), "Zm9v");
        assert_eq!(transcode_base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_transcode_hex() {
        assert_eq!(transcode_hex(b"\x00\xff"), "00ff");
        assert_eq!(transcode_hex(b"ABC"), "414243");
    }

    #[test]
    fn test_normalize_separator() {
        assert_eq!(normalize_separator('-'), '_');
        assert_eq!(normalize_separator('+'), '_');
        assert_eq!(normalize_separator('a'), 'a');
    }

    #[test]
    fn test_enum_name_equal() {
        assert!(enum_name_equal("host+tpm2", "host_tpm2"));
        assert!(enum_name_equal(
            "tpm2-with-public-key",
            "tpm2_with_public_key"
        ));
        assert!(!enum_name_equal("host", "tpm2"));
    }

    #[test]
    fn test_parse_empty_args() {
        let args = parse_creds_args(&[]).unwrap();
        assert!(!args.system);
        assert!(args.legend);
    }

    #[test]
    fn test_parse_system_flag() {
        assert!(parse_creds_args(&["--system"]).unwrap().system);
    }

    #[test]
    fn test_parse_verb() {
        let args = parse_creds_args(&["list"]).unwrap();
        assert_eq!(args.verb, Some(CredsVerb::List));
    }
}
