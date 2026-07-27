// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/cryptsetup-util.c, src/shared/cryptsetup-util.h

use std::collections::BTreeMap;
use std::env;
use std::fmt;

use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::ffi::Errno;

pub type Result<T> = std::result::Result<T, CryptsetupError>;

pub const CRYPT_ANY_TOKEN: i32 = -1;
pub const CRYPT_KDF_PBKDF2: &str = "pbkdf2";
pub const CRYPTSETUP_TOKEN_PATH_ENV: &str = "SYSTEMD_CRYPTSETUP_TOKEN_PATH";
pub const MINIMAL_PBKDF_HASH: &str = "sha512";
pub const MINIMAL_PBKDF_ITERATIONS: u32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptsetupError {
    errno: Errno,
    message: String,
}

impl CryptsetupError {
    pub fn new(errno: Errno, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }

    pub fn errno(&self) -> Errno {
        self.errno
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn neg_errno(&self) -> i32 {
        self.errno.to_neg_errno()
    }
}

impl fmt::Display for CryptsetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.neg_errno())
    }
}

impl std::error::Error for CryptsetupError {}

impl From<Errno> for CryptsetupError {
    fn from(errno: Errno) -> Self {
        Self::new(errno, format!("cryptsetup error: {}", errno as i32))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptLogLevel {
    Normal,
    Error,
    Verbose,
    Debug,
    Other(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdLogLevel {
    Notice,
    Err,
    Info,
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub level: SystemdLogLevel,
    pub message: String,
}

pub type CryptLogCallback = fn(CryptLogLevel, &str) -> LogEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptDebugLevel {
    None,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptPbkdfType {
    pub hash: &'static str,
    pub kind: &'static str,
    pub iterations: u32,
    pub benchmark: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CryptsetupLoadState {
    #[default]
    NotLoaded,
    Loaded,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlopenCryptsetupResult {
    AlreadyLoaded,
    NewlyLoaded,
}

pub trait CryptDevice {
    fn set_log_callback(&mut self, callback: Option<CryptLogCallback>);
    fn set_debug_level(&mut self, level: CryptDebugLevel);
    fn set_pbkdf_type(&mut self, pbkdf: &CryptPbkdfType) -> Result<()>;
    fn token_json_get(&self, idx: i32) -> Result<Option<String>>;
    fn token_json_set(&mut self, idx: i32, text: &str) -> Result<()>;
    fn uuid(&self) -> Option<&str>;
}

pub trait CryptsetupLibrary {
    fn enable_logging(&mut self, debug_logging: bool);
    fn supports_external_token_path(&self) -> bool {
        false
    }
    fn set_external_token_path(&mut self, path: &str) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenJson {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<TokenJson>),
    Object(BTreeMap<String, TokenJson>),
}

impl TokenJson {
    pub fn by_key(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn by_index(&self, idx: usize) -> Option<&Self> {
        match self {
            Self::Array(items) => items.get(idx),
            _ => None,
        }
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    pub fn elements(&self) -> usize {
        match self {
            Self::Array(items) => items.len(),
            _ => 0,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

pub fn cryptsetup_log_glue(level: CryptLogLevel, msg: &str) -> LogEntry {
    let mapped = match level {
        CryptLogLevel::Normal => SystemdLogLevel::Notice,
        CryptLogLevel::Error => SystemdLogLevel::Err,
        CryptLogLevel::Verbose => SystemdLogLevel::Info,
        CryptLogLevel::Debug => SystemdLogLevel::Debug,
        CryptLogLevel::Other(_) => SystemdLogLevel::Err,
    };

    LogEntry {
        level: mapped,
        message: msg.to_string(),
    }
}

pub fn cryptsetup_enable_logging<D: CryptDevice>(cd: Option<&mut D>, debug_logging: bool) {
    if let Some(device) = cd {
        device.set_log_callback(Some(cryptsetup_log_glue));
        device.set_debug_level(if debug_logging {
            CryptDebugLevel::All
        } else {
            CryptDebugLevel::None
        });
    }
}

pub fn cryptsetup_minimal_pbkdf() -> CryptPbkdfType {
    CryptPbkdfType {
        hash: MINIMAL_PBKDF_HASH,
        kind: CRYPT_KDF_PBKDF2,
        iterations: MINIMAL_PBKDF_ITERATIONS,
        benchmark: false,
    }
}

pub fn cryptsetup_set_minimal_pbkdf<D: CryptDevice>(cd: &mut D) -> Result<()> {
    cd.set_pbkdf_type(&cryptsetup_minimal_pbkdf())
}

pub fn cryptsetup_get_token_as_json<D: CryptDevice>(
    cd: &D,
    idx: i32,
    verify_type: Option<&str>,
) -> Result<TokenJson> {
    let text = cd
        .token_json_get(idx)?
        .ok_or_else(|| CryptsetupError::new(Errno::ENOENT, "token does not exist"))?;

    let parsed = parse_token_json(&text)?;

    if let Some(expected_type) = verify_type {
        let actual_type = parsed
            .by_key("type")
            .and_then(TokenJson::as_str)
            .ok_or_else(|| CryptsetupError::new(Errno::EINVAL, "token type missing"))?;

        if actual_type != expected_type {
            return Err(CryptsetupError::new(
                Errno::EMEDIUMTYPE,
                "token type does not match expected type",
            ));
        }
    }

    Ok(parsed)
}

pub fn cryptsetup_add_token_json<D: CryptDevice>(cd: &mut D, value: &TokenJson) -> Result<()> {
    let text = format_token_json(value);
    cd.token_json_set(CRYPT_ANY_TOKEN, &text)
}

pub fn cryptsetup_get_volume_key_prefix<D: CryptDevice>(
    cd: &D,
    volume_name: Option<&str>,
) -> Result<String> {
    let uuid = cd
        .uuid()
        .ok_or_else(|| CryptsetupError::new(Errno::EINVAL, "failed to get LUKS UUID"))?;

    let volume = match volume_name {
        Some(name) => xescape_component(name, ":"),
        None => format!("luks-{}", uuid),
    };

    Ok(format!("cryptsetup:{}:{}", volume, uuid))
}

pub fn cryptsetup_get_volume_key_id<D: CryptDevice>(
    cd: &D,
    volume_name: Option<&str>,
    volume_key: &[u8],
) -> Result<String> {
    let prefix = cryptsetup_get_volume_key_prefix(cd, volume_name)?;
    let hmac_key =
        PKey::hmac(volume_key).map_err(|e| CryptsetupError::new(Errno::EINVAL, e.to_string()))?;
    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &hmac_key)
        .map_err(|e| CryptsetupError::new(Errno::EINVAL, e.to_string()))?;

    signer
        .update(prefix.as_bytes())
        .map_err(|e| CryptsetupError::new(Errno::EINVAL, e.to_string()))?;

    let digest = signer
        .sign_to_vec()
        .map_err(|e| CryptsetupError::new(Errno::EINVAL, e.to_string()))?;

    Ok(hex_encode(&digest))
}

pub fn dlopen_cryptsetup<L: CryptsetupLibrary>(
    state: &mut CryptsetupLoadState,
    library: Option<&mut L>,
    debug_logging: bool,
) -> Result<DlopenCryptsetupResult> {
    let env_path = env::var_os(CRYPTSETUP_TOKEN_PATH_ENV).and_then(|v| v.into_string().ok());
    dlopen_cryptsetup_with_env(state, library, debug_logging, env_path.as_deref())
}

pub fn dlopen_cryptsetup_with_env<L: CryptsetupLibrary>(
    state: &mut CryptsetupLoadState,
    library: Option<&mut L>,
    debug_logging: bool,
    env_path: Option<&str>,
) -> Result<DlopenCryptsetupResult> {
    match state {
        CryptsetupLoadState::Loaded => return Ok(DlopenCryptsetupResult::AlreadyLoaded),
        CryptsetupLoadState::Unsupported => {
            return Err(CryptsetupError::new(
                Errno::EOPNOTSUPP,
                "cryptsetup support is not compiled in",
            ));
        }
        CryptsetupLoadState::NotLoaded => {}
    }

    let Some(library) = library else {
        *state = CryptsetupLoadState::Unsupported;
        return Err(CryptsetupError::new(
            Errno::EOPNOTSUPP,
            "cryptsetup support is not compiled in",
        ));
    };

    library.enable_logging(debug_logging);

    if let Some(path) = env_path {
        if library.supports_external_token_path() {
            let _ = library.set_external_token_path(path);
        }
    }

    *state = CryptsetupLoadState::Loaded;
    Ok(DlopenCryptsetupResult::NewlyLoaded)
}

pub fn cryptsetup_get_keyslot_from_token(value: &TokenJson) -> Result<i32> {
    let keyslots = value
        .by_key("keyslots")
        .ok_or_else(|| CryptsetupError::new(Errno::ENOENT, "keyslots field missing"))?;

    if !keyslots.is_array() || keyslots.elements() != 1 {
        return Err(CryptsetupError::new(
            Errno::EMEDIUMTYPE,
            "keyslots field must be a single-element array",
        ));
    }

    let keyslot = keyslots
        .by_index(0)
        .and_then(TokenJson::as_str)
        .ok_or_else(|| {
            CryptsetupError::new(Errno::EMEDIUMTYPE, "keyslot entry must be a string")
        })?;

    let parsed = keyslot
        .parse::<i32>()
        .map_err(|_| CryptsetupError::new(Errno::EINVAL, "failed to parse keyslot index"))?;

    if parsed < 0 {
        return Err(CryptsetupError::new(
            Errno::EINVAL,
            "keyslot index must be non-negative",
        ));
    }

    Ok(parsed)
}

pub fn mangle_none(value: Option<&str>) -> Option<&str> {
    match value {
        None | Some("") | Some("-") | Some("none") => None,
        Some(other) => Some(other),
    }
}

pub fn parse_token_json(text: &str) -> Result<TokenJson> {
    let mut parser = JsonParser::new(text);
    let value = parser.parse_value()?;
    parser.skip_whitespace();

    if !parser.is_eof() {
        return Err(CryptsetupError::new(
            Errno::EINVAL,
            "trailing data after JSON value",
        ));
    }

    Ok(value)
}

pub fn format_token_json(value: &TokenJson) -> String {
    let mut output = String::new();
    format_json_value(value, &mut output);
    output
}

fn xescape_component(input: &str, bad: &str) -> String {
    let mut escaped = String::new();

    for byte in input.bytes() {
        let ch = byte as char;
        if byte < 0x20 || byte == 0x7f || ch == '\\' || bad.contains(ch) {
            escaped.push_str(&format!("\\x{byte:02x}"));
        } else {
            escaped.push(ch);
        }
    }

    escaped
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn format_json_value(value: &TokenJson, output: &mut String) {
    match value {
        TokenJson::Null => output.push_str("null"),
        TokenJson::Bool(v) => output.push_str(if *v { "true" } else { "false" }),
        TokenJson::Number(v) => output.push_str(v),
        TokenJson::String(v) => format_json_string(v, output),
        TokenJson::Array(values) => {
            output.push('[');
            for (idx, item) in values.iter().enumerate() {
                if idx > 0 {
                    output.push(',');
                }
                format_json_value(item, output);
            }
            output.push(']');
        }
        TokenJson::Object(values) => {
            output.push('{');
            for (idx, (key, item)) in values.iter().enumerate() {
                if idx > 0 {
                    output.push(',');
                }
                format_json_string(key, output);
                output.push(':');
                format_json_value(item, output);
            }
            output.push('}');
        }
    }
}

fn format_json_string(value: &str, output: &mut String) {
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", c as u32)),
            c => output.push(c),
        }
    }
    output.push('"');
}

struct JsonParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek_byte() {
            if matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<TokenJson> {
        self.skip_whitespace();

        match self.peek_byte() {
            Some(b'n') => {
                self.expect_bytes(b"null")?;
                Ok(TokenJson::Null)
            }
            Some(b't') => {
                self.expect_bytes(b"true")?;
                Ok(TokenJson::Bool(true))
            }
            Some(b'f') => {
                self.expect_bytes(b"false")?;
                Ok(TokenJson::Bool(false))
            }
            Some(b'"') => self.parse_string().map(TokenJson::String),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(TokenJson::Number),
            _ => Err(CryptsetupError::new(Errno::EINVAL, "invalid JSON value")),
        }
    }

    fn parse_array(&mut self) -> Result<TokenJson> {
        self.expect_byte(b'[')?;
        self.skip_whitespace();

        let mut values = Vec::new();
        if self.peek_byte() == Some(b']') {
            self.pos += 1;
            return Ok(TokenJson::Array(values));
        }

        loop {
            values.push(self.parse_value()?);
            self.skip_whitespace();

            match self.peek_byte() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => {
                    return Err(CryptsetupError::new(
                        Errno::EINVAL,
                        "expected ',' or ']' in array",
                    ));
                }
            }
        }

        Ok(TokenJson::Array(values))
    }

    fn parse_object(&mut self) -> Result<TokenJson> {
        self.expect_byte(b'{')?;
        self.skip_whitespace();

        let mut values = BTreeMap::new();
        if self.peek_byte() == Some(b'}') {
            self.pos += 1;
            return Ok(TokenJson::Object(values));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            let value = self.parse_value()?;
            values.insert(key, value);
            self.skip_whitespace();

            match self.peek_byte() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => {
                    return Err(CryptsetupError::new(
                        Errno::EINVAL,
                        "expected ',' or '}' in object",
                    ));
                }
            }
        }

        Ok(TokenJson::Object(values))
    }

    fn parse_number(&mut self) -> Result<String> {
        let start = self.pos;

        if self.peek_byte() == Some(b'-') {
            self.pos += 1;
        }

        match self.peek_byte() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => {
                return Err(CryptsetupError::new(Errno::EINVAL, "invalid JSON number"));
            }
        }

        if self.peek_byte() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return Err(CryptsetupError::new(Errno::EINVAL, "invalid JSON fraction"));
            }

            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.pos += 1;

            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.pos += 1;
            }

            if !matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return Err(CryptsetupError::new(Errno::EINVAL, "invalid JSON exponent"));
            }

            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        Ok(self.input[start..self.pos].to_string())
    }

    fn parse_string(&mut self) -> Result<String> {
        self.expect_byte(b'"')?;

        let mut result = String::new();
        let mut chunk_start = self.pos;

        while let Some(byte) = self.peek_byte() {
            match byte {
                b'"' => {
                    result.push_str(&self.input[chunk_start..self.pos]);
                    self.pos += 1;
                    return Ok(result);
                }
                b'\\' => {
                    result.push_str(&self.input[chunk_start..self.pos]);
                    self.pos += 1;
                    result.push(self.parse_escape_sequence()?);
                    chunk_start = self.pos;
                }
                0x00..=0x1f => {
                    return Err(CryptsetupError::new(
                        Errno::EINVAL,
                        "control character in JSON string",
                    ));
                }
                _ => self.pos += 1,
            }
        }

        Err(CryptsetupError::new(
            Errno::EINVAL,
            "unterminated JSON string",
        ))
    }

    fn parse_escape_sequence(&mut self) -> Result<char> {
        let escaped = self.next_byte().ok_or_else(|| {
            CryptsetupError::new(Errno::EINVAL, "unterminated JSON escape sequence")
        })?;

        match escaped {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{08}'),
            b'f' => Ok('\u{0c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.parse_unicode_escape(),
            _ => Err(CryptsetupError::new(
                Errno::EINVAL,
                "invalid JSON escape sequence",
            )),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char> {
        let first = self.parse_hex_quad()?;

        if (0xd800..=0xdbff).contains(&first) {
            if self.next_byte() != Some(b'\\') || self.next_byte() != Some(b'u') {
                return Err(CryptsetupError::new(
                    Errno::EINVAL,
                    "missing low surrogate in JSON string",
                ));
            }

            let second = self.parse_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(CryptsetupError::new(
                    Errno::EINVAL,
                    "invalid low surrogate in JSON string",
                ));
            }

            let codepoint = 0x10000 + (((first - 0xd800) as u32) << 10) + (second - 0xdc00) as u32;
            char::from_u32(codepoint).ok_or_else(|| {
                CryptsetupError::new(Errno::EINVAL, "invalid Unicode codepoint in JSON string")
            })
        } else if (0xdc00..=0xdfff).contains(&first) {
            Err(CryptsetupError::new(
                Errno::EINVAL,
                "unexpected low surrogate in JSON string",
            ))
        } else {
            char::from_u32(first as u32).ok_or_else(|| {
                CryptsetupError::new(Errno::EINVAL, "invalid Unicode codepoint in JSON string")
            })
        }
    }

    fn parse_hex_quad(&mut self) -> Result<u16> {
        let start = self.pos;
        let end = start + 4;
        if end > self.input.len() {
            return Err(CryptsetupError::new(
                Errno::EINVAL,
                "truncated Unicode escape in JSON string",
            ));
        }

        let chunk = &self.input[start..end];
        if !chunk.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(CryptsetupError::new(
                Errno::EINVAL,
                "invalid Unicode escape in JSON string",
            ));
        }

        self.pos = end;
        u16::from_str_radix(chunk, 16).map_err(|_| {
            CryptsetupError::new(Errno::EINVAL, "invalid Unicode escape in JSON string")
        })
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<()> {
        for byte in expected {
            self.expect_byte(*byte)?;
        }
        Ok(())
    }

    fn expect_byte(&mut self, expected: u8) -> Result<()> {
        match self.next_byte() {
            Some(actual) if actual == expected => Ok(()),
            _ => Err(CryptsetupError::new(Errno::EINVAL, "unexpected JSON token")),
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek_byte()?;
        self.pos += 1;
        Some(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockDevice {
        callback: Option<CryptLogCallback>,
        debug_level: Option<CryptDebugLevel>,
        pbkdf: Option<CryptPbkdfType>,
        tokens: BTreeMap<i32, String>,
        writes: Vec<(i32, String)>,
        uuid: Option<String>,
    }

    impl CryptDevice for MockDevice {
        fn set_log_callback(&mut self, callback: Option<CryptLogCallback>) {
            self.callback = callback;
        }

        fn set_debug_level(&mut self, level: CryptDebugLevel) {
            self.debug_level = Some(level);
        }

        fn set_pbkdf_type(&mut self, pbkdf: &CryptPbkdfType) -> Result<()> {
            self.pbkdf = Some(pbkdf.clone());
            Ok(())
        }

        fn token_json_get(&self, idx: i32) -> Result<Option<String>> {
            Ok(self.tokens.get(&idx).cloned())
        }

        fn token_json_set(&mut self, idx: i32, text: &str) -> Result<()> {
            self.writes.push((idx, text.to_string()));
            Ok(())
        }

        fn uuid(&self) -> Option<&str> {
            self.uuid.as_deref()
        }
    }

    #[derive(Default)]
    struct MockLibrary {
        logging_calls: Vec<bool>,
        external_paths: Vec<String>,
        external_path_supported: bool,
        fail_set_external_path: bool,
    }

    impl CryptsetupLibrary for MockLibrary {
        fn enable_logging(&mut self, debug_logging: bool) {
            self.logging_calls.push(debug_logging);
        }

        fn supports_external_token_path(&self) -> bool {
            self.external_path_supported
        }

        fn set_external_token_path(&mut self, path: &str) -> Result<()> {
            if self.fail_set_external_path {
                return Err(CryptsetupError::new(
                    Errno::EINVAL,
                    "injected external token path failure",
                ));
            }

            self.external_paths.push(path.to_string());
            Ok(())
        }
    }

    fn token_object(entries: impl IntoIterator<Item = (&'static str, TokenJson)>) -> TokenJson {
        TokenJson::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    #[test]
    fn test_log_level_mapping() {
        assert_eq!(
            cryptsetup_log_glue(CryptLogLevel::Normal, "msg").level,
            SystemdLogLevel::Notice
        );
        assert_eq!(
            cryptsetup_log_glue(CryptLogLevel::Error, "msg").level,
            SystemdLogLevel::Err
        );
        assert_eq!(
            cryptsetup_log_glue(CryptLogLevel::Verbose, "msg").level,
            SystemdLogLevel::Info
        );
        assert_eq!(
            cryptsetup_log_glue(CryptLogLevel::Debug, "msg").level,
            SystemdLogLevel::Debug
        );
        assert_eq!(
            cryptsetup_log_glue(CryptLogLevel::Other(99), "msg").level,
            SystemdLogLevel::Err
        );
    }

    #[test]
    fn test_enable_logging_sets_callback_and_debug_level() {
        let mut device = MockDevice::default();
        cryptsetup_enable_logging(Some(&mut device), true);
        assert!(device.callback.is_some());
        assert_eq!(device.debug_level, Some(CryptDebugLevel::All));
    }

    #[test]
    fn test_minimal_pbkdf_matches_c_constants() {
        let pbkdf = cryptsetup_minimal_pbkdf();
        assert_eq!(pbkdf.hash, "sha512");
        assert_eq!(pbkdf.kind, "pbkdf2");
        assert_eq!(pbkdf.iterations, 1000);
        assert!(!pbkdf.benchmark);
    }

    #[test]
    fn test_set_minimal_pbkdf_delegates_to_device() {
        let mut device = MockDevice::default();
        cryptsetup_set_minimal_pbkdf(&mut device).unwrap();
        assert_eq!(device.pbkdf, Some(cryptsetup_minimal_pbkdf()));
    }

    #[test]
    fn test_get_token_as_json_success() {
        let mut device = MockDevice::default();
        device.tokens.insert(
            7,
            r#"{ "type": "systemd-tpm2", "keyslots": ["1"] }"#.to_string(),
        );

        let token = cryptsetup_get_token_as_json(&device, 7, Some("systemd-tpm2")).unwrap();
        assert_eq!(
            token.by_key("type").and_then(TokenJson::as_str),
            Some("systemd-tpm2")
        );
    }

    #[test]
    fn test_get_token_as_json_missing_token() {
        let device = MockDevice::default();
        let err = cryptsetup_get_token_as_json(&device, 9, None).unwrap_err();
        assert_eq!(err.errno(), Errno::ENOENT);
    }

    #[test]
    fn test_get_token_as_json_missing_type_is_einval() {
        let mut device = MockDevice::default();
        device.tokens.insert(3, r#"{"keyslots":["0"]}"#.to_string());

        let err = cryptsetup_get_token_as_json(&device, 3, Some("systemd-tpm2")).unwrap_err();
        assert_eq!(err.errno(), Errno::EINVAL);
    }

    #[test]
    fn test_get_token_as_json_type_mismatch_is_emediumtype() {
        let mut device = MockDevice::default();
        device.tokens.insert(4, r#"{"type":"other"}"#.to_string());

        let err = cryptsetup_get_token_as_json(&device, 4, Some("systemd-tpm2")).unwrap_err();
        assert_eq!(err.errno(), Errno::EMEDIUMTYPE);
    }

    #[test]
    fn test_add_token_json_serializes_compact_json() {
        let mut device = MockDevice::default();
        let token = token_object([
            (
                "keyslots",
                TokenJson::Array(vec![TokenJson::String("2".into())]),
            ),
            ("type", TokenJson::String("systemd-tpm2".into())),
        ]);

        cryptsetup_add_token_json(&mut device, &token).unwrap();

        assert_eq!(device.writes.len(), 1);
        assert_eq!(device.writes[0].0, CRYPT_ANY_TOKEN);
        assert_eq!(
            device.writes[0].1,
            r#"{"keyslots":["2"],"type":"systemd-tpm2"}"#
        );
    }

    #[test]
    fn test_get_volume_key_prefix_uses_default_volume_name() {
        let device = MockDevice {
            uuid: Some("uuid".into()),
            ..MockDevice::default()
        };

        let prefix = cryptsetup_get_volume_key_prefix(&device, None).unwrap();
        assert_eq!(prefix, "cryptsetup:luks-uuid:uuid");
    }

    #[test]
    fn test_get_volume_key_prefix_escapes_colons_and_backslashes() {
        let device = MockDevice {
            uuid: Some("abc".into()),
            ..MockDevice::default()
        };

        let prefix = cryptsetup_get_volume_key_prefix(&device, Some(r#"vol:name\part"#)).unwrap();
        assert_eq!(prefix, r#"cryptsetup:vol\x3aname\x5cpart:abc"#);
    }

    #[test]
    fn test_get_volume_key_id_matches_known_hmac_sha256_vector() {
        let device = MockDevice {
            uuid: Some("uuid".into()),
            ..MockDevice::default()
        };

        let key_id = cryptsetup_get_volume_key_id(&device, None, b"secret").unwrap();
        assert_eq!(
            key_id,
            "371c9bab32f3d376a20e86b0abaed10c48c682e93c14689b3a7f03c746cff619"
        );
    }

    #[test]
    fn test_dlopen_cryptsetup_marks_loaded_and_uses_env_path() {
        let mut state = CryptsetupLoadState::NotLoaded;
        let mut library = MockLibrary {
            external_path_supported: true,
            ..MockLibrary::default()
        };

        let result =
            dlopen_cryptsetup_with_env(&mut state, Some(&mut library), true, Some("/tmp/tokens"))
                .unwrap();

        assert_eq!(result, DlopenCryptsetupResult::NewlyLoaded);
        assert_eq!(state, CryptsetupLoadState::Loaded);
        assert_eq!(library.logging_calls, vec![true]);
        assert_eq!(library.external_paths, vec!["/tmp/tokens".to_string()]);
    }

    #[test]
    fn test_dlopen_cryptsetup_returns_already_loaded() {
        let mut state = CryptsetupLoadState::Loaded;
        let mut library = MockLibrary::default();
        let result =
            dlopen_cryptsetup_with_env(&mut state, Some(&mut library), false, None).unwrap();
        assert_eq!(result, DlopenCryptsetupResult::AlreadyLoaded);
        assert!(library.logging_calls.is_empty());
    }

    #[test]
    fn test_dlopen_cryptsetup_without_library_is_eopnotsupp() {
        let mut state = CryptsetupLoadState::NotLoaded;
        let err =
            dlopen_cryptsetup_with_env::<MockLibrary>(&mut state, None, false, None).unwrap_err();
        assert_eq!(err.errno(), Errno::EOPNOTSUPP);
        assert_eq!(state, CryptsetupLoadState::Unsupported);
    }

    #[test]
    fn test_keyslot_from_token_success() {
        let token = token_object([(
            "keyslots",
            TokenJson::Array(vec![TokenJson::String("7".into())]),
        )]);

        assert_eq!(cryptsetup_get_keyslot_from_token(&token).unwrap(), 7);
    }

    #[test]
    fn test_keyslot_from_token_missing_keyslots() {
        let token = token_object([]);
        let err = cryptsetup_get_keyslot_from_token(&token).unwrap_err();
        assert_eq!(err.errno(), Errno::ENOENT);
    }

    #[test]
    fn test_keyslot_from_token_rejects_multiple_entries() {
        let token = token_object([(
            "keyslots",
            TokenJson::Array(vec![
                TokenJson::String("1".into()),
                TokenJson::String("2".into()),
            ]),
        )]);

        let err = cryptsetup_get_keyslot_from_token(&token).unwrap_err();
        assert_eq!(err.errno(), Errno::EMEDIUMTYPE);
    }

    #[test]
    fn test_keyslot_from_token_rejects_non_string() {
        let token = token_object([(
            "keyslots",
            TokenJson::Array(vec![TokenJson::Number("1".into())]),
        )]);
        let err = cryptsetup_get_keyslot_from_token(&token).unwrap_err();
        assert_eq!(err.errno(), Errno::EMEDIUMTYPE);
    }

    #[test]
    fn test_keyslot_from_token_rejects_negative_values() {
        let token = token_object([(
            "keyslots",
            TokenJson::Array(vec![TokenJson::String("-1".into())]),
        )]);

        let err = cryptsetup_get_keyslot_from_token(&token).unwrap_err();
        assert_eq!(err.errno(), Errno::EINVAL);
    }

    #[test]
    fn test_mangle_none_matches_c_semantics() {
        assert_eq!(mangle_none(None), None);
        assert_eq!(mangle_none(Some("")), None);
        assert_eq!(mangle_none(Some("-")), None);
        assert_eq!(mangle_none(Some("none")), None);
        assert_eq!(mangle_none(Some("NONE")), Some("NONE"));
        assert_eq!(mangle_none(Some("something")), Some("something"));
    }

    #[test]
    fn test_parse_and_format_token_json_roundtrip() {
        let parsed = parse_token_json(r#"{"a":1,"b":[true,null,"x"],"c":"\u03c0"}"#).unwrap();
        assert_eq!(
            format_token_json(&parsed),
            r#"{"a":1,"b":[true,null,"x"],"c":"π"}"#
        );
    }

    #[test]
    fn test_parse_token_json_handles_surrogate_pairs() {
        let parsed = parse_token_json(r#"{"value":"\ud83d\ude80"}"#).unwrap();
        assert_eq!(
            parsed.by_key("value").and_then(TokenJson::as_str),
            Some("🚀")
        );
    }

    #[test]
    fn test_parse_token_json_rejects_trailing_data() {
        let err = parse_token_json("{} []").unwrap_err();
        assert_eq!(err.errno(), Errno::EINVAL);
    }
}
