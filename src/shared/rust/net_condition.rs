// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/net-condition.c, src/shared/net-condition.h

use crate::condition::{Condition, ConditionType};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::{BitOr, BitOrAssign};

const IFNAMSIZ: usize = 16;
const ALTIFNAMSIZ: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl std::str::FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 6];
        let mut parts = s.split(':');

        for byte in &mut bytes {
            let Some(part) = parts.next() else {
                return Err(MacAddressParseError);
            };
            if part.len() != 2 {
                return Err(MacAddressParseError);
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| MacAddressParseError)?;
        }

        if parts.next().is_some() {
            return Err(MacAddressParseError);
        }

        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddressParseError;

impl fmt::Display for MacAddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid MAC address format")
    }
}

impl std::error::Error for MacAddressParseError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetDevice {
    pub devtype: Option<String>,
    pub properties: BTreeMap<String, String>,
}

impl NetDevice {
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(String::as_str)
    }

    pub fn path(&self) -> Option<&str> {
        self.property("ID_PATH")
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfnameValidFlags(u32);

impl IfnameValidFlags {
    pub const ALTERNATIVE: Self = Self(1 << 0);
    pub const NUMERIC: Self = Self(1 << 1);
    pub const SPECIAL: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for IfnameValidFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for IfnameValidFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetMatch {
    pub hw_addr: Vec<MacAddress>,
    pub permanent_hw_addr: Vec<MacAddress>,
    pub path: Vec<String>,
    pub driver: Vec<String>,
    pub iftype: Vec<String>,
    pub kind: Vec<String>,
    pub ifname: Vec<String>,
    pub property: Vec<String>,
    pub wlan_iftype: Vec<String>,
    pub ssid: Vec<String>,
    pub bssid: Vec<MacAddress>,
}

impl NetMatch {
    pub fn clear(&mut self) {
        self.hw_addr.clear();
        self.permanent_hw_addr.clear();
        self.path.clear();
        self.driver.clear();
        self.iftype.clear();
        self.kind.clear();
        self.ifname.clear();
        self.property.clear();
        self.wlan_iftype.clear();
        self.ssid.clear();
        self.bssid.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.hw_addr.is_empty()
            && self.permanent_hw_addr.is_empty()
            && self.path.is_empty()
            && self.driver.is_empty()
            && self.iftype.is_empty()
            && self.kind.is_empty()
            && self.ifname.is_empty()
            && self.property.is_empty()
            && self.wlan_iftype.is_empty()
            && self.ssid.is_empty()
            && self.bssid.is_empty()
    }

    pub fn match_config(&self, config: &NetConfig<'_>) -> bool {
        net_match_config(self, config)
    }

    pub fn parse_match_strv(target: &mut Vec<String>, value: &str) {
        config_parse_match_strv(target, value)
    }

    pub fn parse_match_ifnames(value: &str) -> Vec<String> {
        let mut out = Vec::new();
        config_parse_match_ifnames(&mut out, IfnameValidFlags::default(), value);
        out
    }

    pub fn parse_match_property(value: &str) -> Vec<String> {
        let mut out = Vec::new();
        config_parse_match_property(&mut out, value);
        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetConfig<'a> {
    pub device: Option<&'a NetDevice>,
    pub hw_addr: Option<&'a MacAddress>,
    pub permanent_hw_addr: Option<&'a MacAddress>,
    pub driver: Option<&'a str>,
    pub iftype: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub ifname: Option<&'a str>,
    pub alternative_names: &'a [&'a str],
    pub wlan_iftype: Option<&'a str>,
    pub ssid: Option<&'a str>,
    pub bssid: Option<&'a MacAddress>,
}

pub fn net_match_clear(match_: &mut NetMatch) {
    match_.clear();
}

pub fn net_match_is_empty(match_: &NetMatch) -> bool {
    match_.is_empty()
}

fn net_condition_test_strv(patterns: &[String], string: Option<&str>) -> bool {
    if patterns.is_empty() {
        return true;
    }

    let mut matched = false;
    let mut has_positive_rule = false;

    for pattern in patterns {
        let (invert, raw_pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern.as_str()), |rest| (true, rest));

        if !invert {
            has_positive_rule = true;
        }

        if string.is_some_and(|value| fnmatch(raw_pattern, value)) {
            if invert {
                return false;
            }

            matched = true;
        }
    }

    if has_positive_rule { matched } else { true }
}

fn net_condition_test_ifname(
    patterns: &[String],
    ifname: Option<&str>,
    alternative_names: &[&str],
) -> bool {
    if net_condition_test_strv(patterns, ifname) {
        return true;
    }

    for alternative_name in alternative_names {
        if net_condition_test_strv(patterns, Some(alternative_name)) {
            return true;
        }
    }

    false
}

fn net_condition_test_property(match_property: &[String], device: Option<&NetDevice>) -> bool {
    if match_property.is_empty() {
        return true;
    }

    for property in match_property {
        let (invert, assignment) = property
            .strip_prefix('!')
            .map_or((false, property.as_str()), |rest| (true, rest));

        let Some((key, value_pattern)) = assignment.split_once('=') else {
            continue;
        };

        let matches = device
            .and_then(|device| device.property(key))
            .is_some_and(|value| fnmatch(value_pattern, value));

        if if invert { matches } else { !matches } {
            return false;
        }
    }

    true
}

pub fn net_match_config(match_: &NetMatch, config: &NetConfig<'_>) -> bool {
    let path = config.device.and_then(NetDevice::path);
    let iftype = config
        .device
        .and_then(|device| device.devtype.as_deref())
        .filter(|value| !value.is_empty())
        .or(config.iftype);

    if !match_.hw_addr.is_empty()
        && !config
            .hw_addr
            .is_some_and(|addr| match_.hw_addr.contains(addr))
    {
        return false;
    }

    if !match_.permanent_hw_addr.is_empty()
        && !config
            .permanent_hw_addr
            .is_some_and(|addr| match_.permanent_hw_addr.contains(addr))
    {
        return false;
    }

    if !net_condition_test_strv(&match_.path, path)
        || !net_condition_test_strv(&match_.driver, config.driver)
        || !net_condition_test_strv(&match_.iftype, iftype)
        || !net_condition_test_strv(&match_.kind, config.kind)
        || !net_condition_test_ifname(&match_.ifname, config.ifname, config.alternative_names)
        || !net_condition_test_property(&match_.property, config.device)
        || !net_condition_test_strv(&match_.wlan_iftype, config.wlan_iftype)
        || !net_condition_test_strv(&match_.ssid, config.ssid)
    {
        return false;
    }

    if !match_.bssid.is_empty() && !config.bssid.is_some_and(|addr| match_.bssid.contains(addr)) {
        return false;
    }

    true
}

pub fn parse_net_condition(value: &str) -> Option<(&str, bool)> {
    if value.is_empty() {
        return None;
    }

    Some(match value.strip_prefix('!') {
        Some(rest) => (rest, true),
        None => (value, false),
    })
}

pub fn config_parse_net_condition(
    conditions: &mut Vec<Condition>,
    condition_type: ConditionType,
    value: &str,
) {
    conditions.retain(|condition| condition.condition_type != condition_type);

    let Some((parameter, negate)) = parse_net_condition(value) else {
        return;
    };

    conditions.insert(
        0,
        Condition::new(condition_type, parameter.to_string(), false, negate),
    );
}

pub fn config_parse_match_strv(target: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        target.clear();
        return;
    }

    let (invert, rest) = value
        .strip_prefix('!')
        .map_or((false, value), |rest| (true, rest));
    for word in parse_words(rest, ParseMode::UnquoteRetainEscape) {
        target.push(with_optional_invert(invert, word));
    }
}

pub fn config_parse_match_ifnames(target: &mut Vec<String>, flags: IfnameValidFlags, value: &str) {
    if value.is_empty() {
        target.clear();
        return;
    }

    let (invert, rest) = value
        .strip_prefix('!')
        .map_or((false, value), |rest| (true, rest));
    for word in parse_words(rest, ParseMode::Simple) {
        if ifname_valid_full(&word, flags) {
            target.push(with_optional_invert(invert, word));
        }
    }
}

pub fn config_parse_match_property(target: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        target.clear();
        return;
    }

    let (invert, rest) = value
        .strip_prefix('!')
        .map_or((false, value), |rest| (true, rest));
    for word in parse_words(rest, ParseMode::UnquoteCUnescape) {
        if env_assignment_is_valid(&word) {
            target.push(with_optional_invert(invert, word));
        }
    }
}

fn with_optional_invert(invert: bool, word: String) -> String {
    if invert { format!("!{word}") } else { word }
}

pub fn ifname_valid_char(character: char) -> bool {
    let value = character as u32;
    if value >= 127 || value <= 32 {
        return false;
    }

    !matches!(character, ':' | '/' | '%')
}

pub fn ifname_valid_full(name: &str, flags: IfnameValidFlags) -> bool {
    if name.is_empty() {
        return false;
    }

    if let Ok(index) = name.parse::<u32>() {
        if index > 0 {
            return flags.contains(IfnameValidFlags::NUMERIC);
        }
        return false;
    }

    let limit = if flags.contains(IfnameValidFlags::ALTERNATIVE) {
        ALTIFNAMSIZ
    } else {
        IFNAMSIZ
    };

    if name.len() >= limit || matches!(name, "." | "..") {
        return false;
    }

    if !flags.contains(IfnameValidFlags::SPECIAL) && matches!(name, "all" | "default") {
        return false;
    }

    let mut numeric = true;
    for character in name.chars() {
        if !ifname_valid_char(character) {
            return false;
        }

        numeric &= character.is_ascii_digit();
    }

    !numeric
}

pub fn is_valid_interface_name(name: &str) -> bool {
    ifname_valid_full(name, IfnameValidFlags::default())
}

pub fn env_assignment_is_valid(assignment: &str) -> bool {
    let Some((name, value)) = assignment.split_once('=') else {
        return false;
    };

    if name.is_empty() || value.as_bytes().contains(&0) {
        return false;
    }

    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }

    chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

pub fn is_valid_property_assignment(assignment: &str) -> bool {
    env_assignment_is_valid(assignment)
}

#[derive(Clone, Copy)]
enum ParseMode {
    Simple,
    UnquoteRetainEscape,
    UnquoteCUnescape,
}

fn parse_words(input: &str, mode: ParseMode) -> Vec<String> {
    let mut words = Vec::new();
    let mut cursor = 0;

    while let Some((next_cursor, word)) = parse_one_word(input, cursor, mode) {
        cursor = next_cursor;
        words.push(word);
    }

    words
}

fn parse_one_word(input: &str, mut cursor: usize, mode: ParseMode) -> Option<(usize, String)> {
    let slice = input.get(cursor..)?;
    let skipped = slice.len() - slice.trim_start().len();
    cursor += skipped;

    if cursor >= input.len() {
        return None;
    }

    let bytes = input.as_bytes();
    let mut word = String::new();
    let mut quote = None;

    while cursor < input.len() {
        let character = input[cursor..].chars().next()?;
        let width = character.len_utf8();

        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
                cursor += width;
                continue;
            }

            match mode {
                ParseMode::UnquoteRetainEscape => {
                    word.push(character);
                    cursor += width;
                }
                ParseMode::Simple => {
                    word.push(character);
                    cursor += width;
                }
                ParseMode::UnquoteCUnescape => {
                    if character == '\\' {
                        let Some((next_cursor, unescaped)) = parse_c_escape(input, cursor) else {
                            return None;
                        };
                        word.push_str(&unescaped);
                        cursor = next_cursor;
                    } else {
                        word.push(character);
                        cursor += width;
                    }
                }
            }
            continue;
        }

        if character.is_whitespace() {
            break;
        }

        match mode {
            ParseMode::Simple => {
                word.push(character);
                cursor += width;
            }
            ParseMode::UnquoteRetainEscape => {
                if matches!(character, '\'' | '"') {
                    quote = Some(character);
                    cursor += width;
                } else {
                    word.push(character);
                    cursor += width;
                }
            }
            ParseMode::UnquoteCUnescape => {
                if matches!(character, '\'' | '"') {
                    quote = Some(character);
                    cursor += width;
                } else if character == '\\' {
                    let Some((next_cursor, unescaped)) = parse_c_escape(input, cursor) else {
                        return None;
                    };
                    word.push_str(&unescaped);
                    cursor = next_cursor;
                } else {
                    word.push(character);
                    cursor += width;
                }
            }
        }
    }

    if quote.is_some()
        || (cursor < input.len()
            && bytes[cursor] == b'\\'
            && matches!(mode, ParseMode::UnquoteCUnescape))
    {
        return None;
    }

    Some((cursor, word))
}

fn parse_c_escape(input: &str, slash_index: usize) -> Option<(usize, String)> {
    let rest = input.get(slash_index + 1..)?;
    let marker = rest.chars().next()?;
    let mut out = String::new();

    match marker {
        'a' => out.push('\u{7}'),
        'b' => out.push('\u{8}'),
        'f' => out.push('\u{c}'),
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        'v' => out.push('\u{b}'),
        '\\' | '\'' | '"' => out.push(marker),
        'x' => {
            let digits = rest.get(1..3)?;
            let value = u8::from_str_radix(digits, 16).ok()?;
            out.push(char::from(value));
            return Some((slash_index + 4, out));
        }
        'u' => {
            let digits = rest.get(1..5)?;
            let value = u32::from_str_radix(digits, 16).ok()?;
            out.push(char::from_u32(value)?);
            return Some((slash_index + 6, out));
        }
        'U' => {
            let digits = rest.get(1..9)?;
            let value = u32::from_str_radix(digits, 16).ok()?;
            out.push(char::from_u32(value)?);
            return Some((slash_index + 10, out));
        }
        _ => return None,
    }

    Some((slash_index + 2, out))
}

fn fnmatch(pattern: &str, string: &str) -> bool {
    fn inner(pattern: &[char], string: &[char]) -> bool {
        let (mut pattern_index, mut string_index) = (0, 0);

        while pattern_index < pattern.len() {
            match pattern[pattern_index] {
                '*' => {
                    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
                        pattern_index += 1;
                    }

                    if pattern_index == pattern.len() {
                        return true;
                    }

                    for next_string_index in string_index..=string.len() {
                        if inner(&pattern[pattern_index..], &string[next_string_index..]) {
                            return true;
                        }
                    }

                    return false;
                }
                '?' => {
                    if string_index >= string.len() {
                        return false;
                    }
                    pattern_index += 1;
                    string_index += 1;
                }
                '[' => {
                    if string_index >= string.len() {
                        return false;
                    }

                    pattern_index += 1;
                    let mut negate = false;
                    if pattern_index < pattern.len() && pattern[pattern_index] == '!' {
                        negate = true;
                        pattern_index += 1;
                    }

                    let mut matched = false;
                    if pattern_index < pattern.len() && pattern[pattern_index] == ']' {
                        matched = string[string_index] == ']';
                        pattern_index += 1;
                    }

                    while pattern_index < pattern.len() && pattern[pattern_index] != ']' {
                        if pattern_index + 2 < pattern.len()
                            && pattern[pattern_index + 1] == '-'
                            && pattern[pattern_index + 2] != ']'
                        {
                            matched |= string[string_index] >= pattern[pattern_index]
                                && string[string_index] <= pattern[pattern_index + 2];
                            pattern_index += 3;
                        } else {
                            matched |= string[string_index] == pattern[pattern_index];
                            pattern_index += 1;
                        }
                    }

                    if pattern_index < pattern.len() {
                        pattern_index += 1;
                    }

                    if negate == matched {
                        return false;
                    }

                    string_index += 1;
                }
                '\\' => {
                    pattern_index += 1;
                    if pattern_index >= pattern.len() || string_index >= string.len() {
                        return false;
                    }

                    if pattern[pattern_index] != string[string_index] {
                        return false;
                    }

                    pattern_index += 1;
                    string_index += 1;
                }
                expected => {
                    if string_index >= string.len() || string[string_index] != expected {
                        return false;
                    }

                    pattern_index += 1;
                    string_index += 1;
                }
            }
        }

        string_index == string.len()
    }

    inner(
        &pattern.chars().collect::<Vec<_>>(),
        &string.chars().collect::<Vec<_>>(),
    )
}

pub const SOURCE_PATH: &str = "src/shared/net-condition.c";
pub const SOURCE_TEXT: &str = include_str!("../net-condition.c");

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(bytes: [u8; 6]) -> MacAddress {
        MacAddress::new(bytes)
    }

    fn device(properties: &[(&str, &str)]) -> NetDevice {
        NetDevice {
            devtype: None,
            properties: properties
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }
    }

    #[test]
    fn net_match_is_empty_tracks_all_fields() {
        let mut match_ = NetMatch::default();
        assert!(net_match_is_empty(&match_));

        match_.ssid.push("wifi".into());
        assert!(!net_match_is_empty(&match_));

        net_match_clear(&mut match_);
        assert!(net_match_is_empty(&match_));
    }

    #[test]
    fn test_strv_matches_c_semantics() {
        assert!(net_condition_test_strv(&[], Some("eth0")));
        assert!(net_condition_test_strv(&["!lo".into()], Some("eth0")));
        assert!(!net_condition_test_strv(&["!lo".into()], Some("lo")));
        assert!(net_condition_test_strv(&["!lo".into()], None));
        assert!(net_condition_test_strv(
            &["eth*".into(), "!lo".into()],
            Some("eth0")
        ));
        assert!(!net_condition_test_strv(
            &["eth*".into(), "!eth0".into()],
            Some("eth0")
        ));
        assert!(!net_condition_test_strv(&["eth*".into()], Some("wlan0")));
        assert!(!net_condition_test_strv(&["eth*".into()], None));
    }

    #[test]
    fn test_ifname_checks_alternative_names() {
        assert!(net_condition_test_ifname(
            &["enp*".into()],
            Some("eth0"),
            &["enp0s3"]
        ));
        assert!(!net_condition_test_ifname(
            &["enp*".into()],
            Some("eth0"),
            &["lo"]
        ));
    }

    #[test]
    fn test_property_matches_and_invalid_rules_do_not_fail() {
        let device = device(&[("ID_MODEL", "ThinkPad"), ("ID_PATH", "pci-0000:00:1f.6")]);

        assert!(net_condition_test_property(
            &["ID_MODEL=Think*".into()],
            Some(&device)
        ));
        assert!(!net_condition_test_property(
            &["ID_MODEL=Other*".into()],
            Some(&device)
        ));
        assert!(net_condition_test_property(
            &["!ID_MODEL=Other*".into()],
            Some(&device)
        ));
        assert!(!net_condition_test_property(
            &["!ID_MODEL=Think*".into()],
            Some(&device)
        ));
        assert!(net_condition_test_property(
            &["missing-equals".into()],
            Some(&device)
        ));
    }

    #[test]
    fn match_config_uses_device_path_and_devtype() {
        let mut match_ = NetMatch::default();
        match_.path.push("pci-*".into());
        match_.iftype.push("wlan".into());
        match_.property.push("ID_MODEL=Think*".into());

        let mut device = device(&[("ID_PATH", "pci-0000:00:1f.6"), ("ID_MODEL", "ThinkPad")]);
        device.devtype = Some("wlan".into());

        let config = NetConfig {
            device: Some(&device),
            ..Default::default()
        };

        assert!(match_.match_config(&config));
    }

    #[test]
    fn match_config_checks_all_fields() {
        let mut match_ = NetMatch::default();
        match_.hw_addr.push(mac([1, 2, 3, 4, 5, 6]));
        match_.permanent_hw_addr.push(mac([6, 5, 4, 3, 2, 1]));
        match_.driver.push("e1000*".into());
        match_.kind.push("vlan".into());
        match_.ifname.push("en*".into());
        match_.wlan_iftype.push("station".into());
        match_.ssid.push("corp-*".into());
        match_.bssid.push(mac([10, 11, 12, 13, 14, 15]));

        let config = NetConfig {
            hw_addr: Some(&mac([1, 2, 3, 4, 5, 6])),
            permanent_hw_addr: Some(&mac([6, 5, 4, 3, 2, 1])),
            driver: Some("e1000e"),
            kind: Some("vlan"),
            ifname: Some("eth0"),
            alternative_names: &["enp0s3"],
            wlan_iftype: Some("station"),
            ssid: Some("corp-wifi"),
            bssid: Some(&mac([10, 11, 12, 13, 14, 15])),
            ..Default::default()
        };

        assert!(match_.match_config(&config));
    }

    #[test]
    fn parse_net_condition_replaces_existing_type_and_clears_on_empty() {
        let mut conditions = vec![Condition::new(
            ConditionType::PathExists,
            "/old".into(),
            false,
            false,
        )];

        config_parse_net_condition(&mut conditions, ConditionType::PathExists, "!/new");
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].parameter, "/new");
        assert!(conditions[0].negate);

        config_parse_net_condition(&mut conditions, ConditionType::PathExists, "");
        assert!(conditions.is_empty());
    }

    #[test]
    fn parse_match_strv_unquotes_and_retains_backslashes() {
        let mut out = Vec::new();
        config_parse_match_strv(&mut out, r#"!"eth 0" foo\x2dbar"#);
        assert_eq!(out, vec!["!eth 0", "!foo\\x2dbar"]);
    }

    #[test]
    fn parse_match_strv_stops_on_invalid_syntax_like_c() {
        let mut out = vec!["keep".into()];
        config_parse_match_strv(&mut out, "good \"unterminated");
        assert_eq!(out, vec!["keep", "good"]);
    }

    #[test]
    fn parse_match_ifnames_respects_flags_and_validation() {
        let mut out = Vec::new();
        config_parse_match_ifnames(
            &mut out,
            IfnameValidFlags::ALTERNATIVE | IfnameValidFlags::NUMERIC,
            "!123 0000 invalid/name",
        );
        assert_eq!(out, vec!["!123"]);

        assert!(ifname_valid_full(
            "x".repeat(127).as_str(),
            IfnameValidFlags::ALTERNATIVE
        ));
        assert!(!ifname_valid_full("default", IfnameValidFlags::default()));
        assert!(!ifname_valid_full("0", IfnameValidFlags::NUMERIC));
    }

    #[test]
    fn parse_match_property_unquotes_and_c_unescapes() {
        let mut out = Vec::new();
        config_parse_match_property(
            &mut out,
            r#"KEY="hello\x20world" OTHER=plain BAD-NAME=value"#,
        );
        assert_eq!(out, vec!["KEY=hello world", "OTHER=plain"]);

        out.clear();
        config_parse_match_property(&mut out, "KEY=foo\\q rest=ignored");
        assert!(out.is_empty());
    }

    #[test]
    fn env_assignment_matches_c_rules_for_empty_value() {
        assert!(env_assignment_is_valid("A="));
        assert!(env_assignment_is_valid("A=hello world"));
        assert!(!env_assignment_is_valid("1A=value"));
        assert!(!env_assignment_is_valid("A-B=value"));
    }

    #[test]
    fn ifname_validation_matches_socket_util_rules() {
        assert!(is_valid_interface_name("eth0"));
        assert!(!is_valid_interface_name("999"));
        assert!(!is_valid_interface_name("all"));
        assert!(!is_valid_interface_name(".."));
        assert!(!is_valid_interface_name("bad/name"));
    }

    #[test]
    fn fnmatch_covers_globs_and_bracket_classes() {
        assert!(fnmatch("enp*s[0-9]", "enp0s3"));
        assert!(fnmatch("eth[!01]", "eth2"));
        assert!(fnmatch(r"eth\*", "eth*"));
        assert!(!fnmatch("eth?", "eth10"));
    }

    #[test]
    fn source_text_is_embedded() {
        assert!(SOURCE_PATH.ends_with("net-condition.c"));
        assert!(SOURCE_TEXT.contains("net_match_config"));
    }
}
