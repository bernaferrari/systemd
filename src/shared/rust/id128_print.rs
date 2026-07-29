// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/id128-print.c, src/shared/id128-print.h

use crate::ffi::*;
use std::fmt::{self, Write as _};
use std::io::{self, IsTerminal as _};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const ANSI_HIGHLIGHT: &str = "\x1b[0;1;39m";
const ANSI_NORMAL: &str = "\x1b[0m";
const ANSI_OSC: &str = "\x1b]";
const ANSI_ST: &str = "\x1b\\";
const MAN_URL: &str = "man:systemd-id128(1)";
const MAN_TEXT: &str = "systemd-id128(1)";
const PYTHON_UUID_URL: &str = "https://docs.python.org/3/library/uuid.html";
const PYTHON_UUID_TEXT: &str = "uuid";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C, align(16))]
pub struct SdId128 {
    pub bytes: [u8; 16],
}

impl SdId128 {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    pub fn random() -> Result<Self, Id128PrintError> {
        let mut bytes = [0u8; 16];
        fill_random_bytes(&mut bytes)?;
        Ok(Self { bytes })
    }
}

impl From<[u8; 16]> for SdId128 {
    fn from(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Id128PrettyPrintMode {
    Id128 = 0,
    Uuid = 1,
    Pretty = 2,
}

impl Id128PrettyPrintMode {
    pub const MAX: i32 = 3;
}

impl TryFrom<i32> for Id128PrettyPrintMode {
    type Error = Id128PrintError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Id128),
            1 => Ok(Self::Uuid),
            2 => Ok(Self::Pretty),
            _ => Err(Id128PrintError::InvalidMode(value)),
        }
    }
}

#[derive(Debug)]
pub enum Id128PrintError {
    InvalidMode(i32),
    Random(io::Error),
    ShortRandomRead,
}

impl fmt::Display for Id128PrintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMode(mode) => write!(f, "invalid pretty print mode: {mode}"),
            Self::Random(err) => write!(f, "failed to generate random ID: {err}"),
            Self::ShortRandomRead => f.write_str("short read from getrandom()"),
        }
    }
}

impl std::error::Error for Id128PrintError {}

pub fn id128_to_string(id: &SdId128) -> String {
    let mut rendered = String::with_capacity(32);

    for byte in id.bytes {
        let _ = write!(rendered, "{byte:02x}");
    }

    rendered
}

pub fn id128_to_uuid_string(id: &SdId128) -> String {
    let mut rendered = String::with_capacity(36);

    for (index, byte) in id.bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            rendered.push('-');
        }

        let _ = write!(rendered, "{byte:02x}");
    }

    rendered
}

pub fn id128_pretty_print_sample(name: &str, id: SdId128) -> Result<String, Id128PrintError> {
    Ok(render_sample(
        name,
        id,
        ansi_highlight(),
        ansi_normal(),
        terminal_urlify(MAN_URL, Some(MAN_TEXT)),
        terminal_urlify(PYTHON_UUID_URL, Some(PYTHON_UUID_TEXT)),
    ))
}

pub fn id128_pretty_print(
    id: SdId128,
    mode: Id128PrettyPrintMode,
) -> Result<String, Id128PrintError> {
    match mode {
        Id128PrettyPrintMode::Id128 => Ok(format!("{}\n", id128_to_string(&id))),
        Id128PrettyPrintMode::Uuid => Ok(format!("{}\n", id128_to_uuid_string(&id))),
        Id128PrettyPrintMode::Pretty => id128_pretty_print_sample("XYZ", id),
    }
}

pub fn id128_print_new(mode: Id128PrettyPrintMode) -> Result<String, Id128PrintError> {
    id128_pretty_print(SdId128::random()?, mode)
}

fn render_sample(
    name: &str,
    id: SdId128,
    on: &str,
    off: &str,
    man_link: String,
    mod_link: String,
) -> String {
    let plain = id128_to_string(&id);
    let uuid = id128_to_uuid_string(&id);
    let macro_bytes = render_macro_bytes(&id);

    format!(
        "As string:\n{on}{plain}{off}\n\nAs UUID:\n{on}{uuid}{off}\n\nAs {man_link} macro:\n{on}#define {name} SD_ID128_MAKE({macro_bytes}){off}\n\nAs Python constant:\n>>> import {mod_link}\n>>> {on}{name} = uuid.UUID('{plain}'){off}\n"
    )
}

fn render_macro_bytes(id: &SdId128) -> String {
    let mut rendered = String::with_capacity(16 * 3 - 1);

    for (index, byte) in id.bytes.into_iter().enumerate() {
        if index > 0 {
            rendered.push(',');
        }

        let _ = write!(rendered, "{byte:02x}");
    }

    rendered
}

fn ansi_highlight() -> &'static str {
    if io::stdout().is_terminal() {
        ANSI_HIGHLIGHT
    } else {
        ""
    }
}

fn ansi_normal() -> &'static str {
    if io::stdout().is_terminal() {
        ANSI_NORMAL
    } else {
        ""
    }
}

fn osc_char_is_valid(c: char) -> bool {
    matches!(c as u32, 32..=126)
}

fn url_suitable_for_osc8(url: &str) -> bool {
    url.len() <= 2000 && url.chars().all(osc_char_is_valid)
}

fn terminal_urlify(url: &str, text: Option<&str>) -> String {
    let display = text.unwrap_or(url);

    if url_suitable_for_osc8(url) {
        format!("{ANSI_OSC}8;;{url}{ANSI_ST}{display}{ANSI_OSC}8;;{ANSI_ST}")
    } else {
        display.to_owned()
    }
}

fn fill_random_bytes(buffer: &mut [u8]) -> Result<(), Id128PrintError> {
    let mut filled = 0;

    while filled < buffer.len() {
        let chunk = &mut buffer[filled..];
        // `getrandom(2)` writes no more than the requested byte count; negative
        // and zero return values are handled below.
        // SAFETY: `chunk` is a live, exclusively borrowed output slice, valid
        // for exactly `chunk.len()` writable bytes for the duration of the call.
        let read = unsafe { crate::ffi::getrandom(chunk.as_mut_ptr(), chunk.len(), 0) };

        if read < 0 {
            return Err(Id128PrintError::Random(io::Error::last_os_error()));
        }

        if read == 0 {
            return Err(Id128PrintError::ShortRandomRead);
        }

        filled += read as usize;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_id() -> SdId128 {
        SdId128::from([
            0x5a, 0x1c, 0x6a, 0x86, 0xdf, 0x9d, 0x40, 0x96, 0xb1, 0xd5, 0xa6, 0x5e, 0x08, 0x62,
            0xf1, 0x9a,
        ])
    }

    #[test]
    fn id128_string_matches_c_format() {
        assert_eq!(
            id128_to_string(&sample_id()),
            "5a1c6a86df9d4096b1d5a65e0862f19a"
        );
    }

    #[test]
    fn id128_uuid_matches_c_format() {
        assert_eq!(
            id128_to_uuid_string(&sample_id()),
            "5a1c6a86-df9d-4096-b1d5-a65e0862f19a"
        );
    }

    #[test]
    fn macro_bytes_are_comma_separated_lower_hex() {
        assert_eq!(
            render_macro_bytes(&sample_id()),
            "5a,1c,6a,86,df,9d,40,96,b1,d5,a6,5e,08,62,f1,9a"
        );
    }

    #[test]
    fn pretty_print_id128_mode_appends_newline() {
        assert_eq!(
            id128_pretty_print(sample_id(), Id128PrettyPrintMode::Id128).unwrap(),
            "5a1c6a86df9d4096b1d5a65e0862f19a\n"
        );
    }

    #[test]
    fn pretty_print_uuid_mode_appends_newline() {
        assert_eq!(
            id128_pretty_print(sample_id(), Id128PrettyPrintMode::Uuid).unwrap(),
            "5a1c6a86-df9d-4096-b1d5-a65e0862f19a\n"
        );
    }

    #[test]
    fn pretty_print_pretty_mode_uses_xyz_name() {
        let rendered = render_sample(
            "XYZ",
            sample_id(),
            "<on>",
            "<off>",
            "systemd-id128(1)".into(),
            "uuid".into(),
        );

        assert!(rendered.contains("#define XYZ SD_ID128_MAKE("));
    }

    #[test]
    fn pretty_sample_contains_all_sections() {
        let rendered = render_sample(
            "TEST_ID",
            sample_id(),
            "<on>",
            "<off>",
            "systemd-id128(1)".into(),
            "uuid".into(),
        );

        assert!(rendered.contains("As string:"));
        assert!(rendered.contains("As UUID:"));
        assert!(rendered.contains("As systemd-id128(1) macro:"));
        assert!(rendered.contains("As Python constant:"));
    }

    #[test]
    fn pretty_sample_uses_plain_hex_for_python_uuid_constructor() {
        let rendered = render_sample(
            "TEST_ID",
            sample_id(),
            "",
            "",
            "systemd-id128(1)".into(),
            "uuid".into(),
        );

        assert!(rendered.contains("TEST_ID = uuid.UUID('5a1c6a86df9d4096b1d5a65e0862f19a')"));
        assert!(!rendered.contains("uuid.UUID('5a1c6a86-df9d-4096-b1d5-a65e0862f19a')"));
    }

    #[test]
    fn pretty_sample_wraps_define_with_style_markers() {
        let rendered = render_sample(
            "TEST_ID",
            sample_id(),
            "<on>",
            "<off>",
            "systemd-id128(1)".into(),
            "uuid".into(),
        );

        assert!(rendered.contains("<on>#define TEST_ID SD_ID128_MAKE("));
        assert!(rendered.contains(")<off>\n\nAs Python constant:"));
    }

    #[test]
    fn try_from_mode_accepts_valid_values() {
        assert_eq!(
            Id128PrettyPrintMode::try_from(0).unwrap(),
            Id128PrettyPrintMode::Id128
        );
        assert_eq!(
            Id128PrettyPrintMode::try_from(1).unwrap(),
            Id128PrettyPrintMode::Uuid
        );
        assert_eq!(
            Id128PrettyPrintMode::try_from(2).unwrap(),
            Id128PrettyPrintMode::Pretty
        );
    }

    #[test]
    fn try_from_mode_rejects_invalid_values() {
        assert!(matches!(
            Id128PrettyPrintMode::try_from(-22),
            Err(Id128PrintError::InvalidMode(-22))
        ));
        assert!(matches!(
            Id128PrettyPrintMode::try_from(3),
            Err(Id128PrintError::InvalidMode(3))
        ));
    }

    #[test]
    fn terminal_urlify_builds_osc8_links_for_valid_urls() {
        let rendered = terminal_urlify("https://example.com", Some("click"));

        assert_eq!(
            rendered,
            "\x1b]8;;https://example.com\x1b\\click\x1b]8;;\x1b\\"
        );
    }

    #[test]
    fn terminal_urlify_falls_back_to_text_for_invalid_urls() {
        assert_eq!(
            terminal_urlify("https://example.com/\x00bad", Some("click")),
            "click"
        );
    }

    #[test]
    fn terminal_urlify_uses_url_as_display_when_text_missing() {
        assert_eq!(
            terminal_urlify("https://example.com", None),
            "\x1b]8;;https://example.com\x1b\\https://example.com\x1b]8;;\x1b\\"
        );
    }

    #[test]
    fn zero_id_formats_correctly() {
        let zero = SdId128::from([0; 16]);

        assert_eq!(id128_to_string(&zero), "00000000000000000000000000000000");
        assert_eq!(
            id128_to_uuid_string(&zero),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn random_id_can_be_rendered_in_id128_mode() {
        let rendered = id128_print_new(Id128PrettyPrintMode::Id128).unwrap();

        assert_eq!(rendered.len(), 33);
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn random_id_can_be_rendered_in_uuid_mode() {
        let rendered = id128_print_new(Id128PrettyPrintMode::Uuid).unwrap();

        assert_eq!(rendered.len(), 37);
        assert!(rendered.ends_with('\n'));
        assert_eq!(rendered.matches('-').count(), 4);
    }
}
