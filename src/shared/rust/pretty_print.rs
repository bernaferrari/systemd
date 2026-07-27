// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/pretty-print.c

use crate::ffi::*;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, IsTerminal, Write as IoWrite};

const ANSI_OSC: &str = "\x1b]";
const ANSI_ST: &str = "\x1b\\";
const ANSI_RED: &str = "\x1b[0;31m";
const ANSI_HIGHLIGHT_RED: &str = "\x1b[0;1;31m";
const ANSI_HIGHLIGHT_GREEN: &str = "\x1b[0;1;32m";
const ANSI_HIGHLIGHT: &str = "\x1b[0;1;39m";
const ANSI_HIGHLIGHT_BLUE: &str = "\x1b[0;1;34m";
const ANSI_HIGHLIGHT_CYAN: &str = "\x1b[0;1;36m";
const ANSI_HIGHLIGHT_GREY: &str = "\x1b[0;1;38:5:245m";
const ANSI_HIGHLIGHT_MAGENTA: &str = "\x1b[0;1;35m";
const ANSI_GREY: &str = "\x1b[0;38:5:245m";
const ANSI_GREY_UNDERLINE: &str = "\x1b[0;4;38:5:245m";
const ANSI_NORMAL: &str = "\x1b[0m";
const ANSI_ERASE_TO_END_OF_LINE: &str = "\x1b[K";

pub const CYLON_BUFFER_EXTRA: usize =
    2 * ANSI_RED.len() + ANSI_HIGHLIGHT_RED.len() + 2 * ANSI_NORMAL.len();

pub fn draw_cylon(width: u32, pos: u32) -> String {
    if width == 0 {
        return String::from("*");
    }
    assert!(pos <= width + 1);

    let mut out = String::with_capacity(CYLON_BUFFER_EXTRA + width as usize + 1);

    for i in 0..width {
        if i == pos {
            out.push('*');
        } else if pos > 0 && i == pos - 1 {
            out.push('*');
        } else if pos < width && i == pos + 1 {
            out.push('*');
        } else if pos == width && i == width - 1 {
            out.push('*');
        } else if pos == width + 1 && i == width - 1 {
            out.push('*');
        } else {
            out.push('━');
        }
    }

    out
}

fn osc_char_is_valid(c: char) -> bool {
    let b = c as u32;
    b >= 32 && b < 127
}

pub fn url_suitable_for_osc8(url: &str) -> bool {
    if url.len() > 2000 {
        return false;
    }
    url.chars().all(osc_char_is_valid)
}

pub fn terminal_urlify(url: &str, text: Option<&str>) -> String {
    let display = text.unwrap_or(url);
    if url_suitable_for_osc8(url) {
        format!("{ANSI_OSC}8;;{url}{ANSI_ST}{display}{ANSI_OSC}8;;{ANSI_ST}")
    } else {
        display.to_string()
    }
}

pub fn file_url_from_path(path: &str) -> String {
    let absolute = if path.starts_with('/') {
        path.to_string()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path).to_string_lossy().to_string(),
            Err(_) => path.to_string(),
        }
    };
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string());
    format!("file://{hostname}{absolute}")
}

pub fn terminal_urlify_path(path: &str, text: Option<&str>) -> String {
    if path.is_empty() {
        return String::new();
    }
    let display = text.unwrap_or(path);
    if !url_suitable_for_osc8(path) {
        return display.to_string();
    }
    let url = file_url_from_path(path);
    terminal_urlify(&url, Some(display))
}

pub fn terminal_urlify_man(page: &str, section: &str) -> String {
    let url = format!("man:{page}({section})");
    let text = format!("{page}({section}) man page");
    terminal_urlify(&url, Some(&text))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatFlags(u32);

impl CatFlags {
    pub const CONFIG_ON: Self = Self(1 << 0);
    pub const FORMAT_HAS_SECTIONS: Self = Self(1 << 1);
    pub const TLDR: Self = Self(1 << 2);
}

impl std::ops::BitOr for CatFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CatFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for CatFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl CatFlags {
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    pub fn empty() -> Self {
        Self(0)
    }
}

fn cat_file_impl(
    path: &str,
    resolved_path: &str,
    content: &str,
    flags: CatFlags,
) -> io::Result<()> {
    let resolved = path != resolved_path;
    let urlified = terminal_urlify_path(resolved_path, None);

    println!(
        "{}# {}{}{}{}",
        ANSI_HIGHLIGHT_BLUE,
        if resolved { path } else { "" },
        if resolved { " -> " } else { "" },
        urlified,
        ANSI_NORMAL,
    );

    let mut section: Option<String> = None;
    let mut old_section: Option<String> = None;
    let mut continued = false;

    for line in content.lines() {
        let trimmed = line.trim_start();

        if !trimmed.is_empty() {
            let first = trimmed.as_bytes()[0];
            if first == b'#' || first == b';' {
                if !flags.contains(CatFlags::TLDR) {
                    println!("{ANSI_HIGHLIGHT_GREY}{line}{ANSI_NORMAL}");
                }
                continue;
            }
        }

        if flags.contains(CatFlags::TLDR) && (trimmed.is_empty() || trimmed == "\\") {
            continue;
        }

        if flags.contains(CatFlags::FORMAT_HAS_SECTIONS) && trimmed.starts_with('[') && !continued {
            if flags.contains(CatFlags::TLDR) {
                section = Some(line.to_string());
            } else {
                println!("{ANSI_HIGHLIGHT_CYAN}{line}{ANSI_NORMAL}");
            }
            continue;
        }

        if flags.contains(CatFlags::TLDR) {
            if let Some(ref sec) = section {
                if old_section.as_deref() != Some(sec.as_str()) {
                    println!("{ANSI_HIGHLIGHT_CYAN}{sec}{ANSI_NORMAL}");
                }
                old_section = section.take();
            }
        }

        let mut line_out = line.to_string();
        let mut escaped = false;
        let mut prev_backslash = false;
        for c in line.chars() {
            if prev_backslash {
                prev_backslash = false;
            } else if c == '\\' {
                prev_backslash = true;
            }
        }
        escaped = prev_backslash;

        if escaped {
            if let Some(idx) = line_out.rfind('\\') {
                line_out.truncate(idx);
            }
            let _ = write!(line_out, "{ANSI_HIGHLIGHT_RED}\\{ANSI_NORMAL}");
        }

        if flags.contains(CatFlags::FORMAT_HAS_SECTIONS) && !continued {
            if let Some(eq_pos) = line_out.find('=') {
                let directive = &line_out[..eq_pos];
                let value = &line_out[eq_pos + 1..];
                println!("{ANSI_HIGHLIGHT_GREEN}{directive}={ANSI_NORMAL}{value}");
                continued = escaped;
                continue;
            }
        }

        println!("{line_out}");
        continued = escaped;
    }

    Ok(())
}

pub fn cat_file(path: &str, flags: CatFlags) -> io::Result<()> {
    let content = fs::read_to_string(path)?;
    cat_file_impl(path, path, &content, flags)
}

pub fn print_separator() {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let cols = terminal_columns();
    for _ in 0..cols {
        let _ = handle.write_all(b" ");
    }
    let _ = handle.write_all(b"\n\n");
}

pub fn print_separator_colored() {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let cols = terminal_columns();
    let _ = handle.write_all(ANSI_GREY_UNDERLINE.as_bytes());
    for _ in 0..cols {
        let _ = handle.write_all(b" ");
    }
    let _ = handle.write_all(ANSI_NORMAL.as_bytes());
    let _ = handle.write_all(b"\n\n");
}

fn terminal_columns() -> usize {
    #[cfg(unix)]
    {
        use std::mem;
        unsafe {
            let mut ws: libc::winsize = mem::zeroed();
            if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 {
                return ws.ws_col as usize;
            }
        }
    }
    80
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuessTypeResult {
    pub name: String,
    pub is_collection: bool,
    pub extension: String,
    pub run_prefix_only: bool,
}

pub fn guess_type(name: &str) -> GuessTypeResult {
    let mut name = name.to_string();
    if name == "environment.d" {
        name = "environment".to_string();
    }
    let name = name.trim_end_matches('/').to_string();

    let mut is_collection = name.ends_with(".d");
    let mut extension = ".conf".to_string();
    let mut run_prefix_only = false;

    match name.as_str() {
        "udev/hwdb.d" => extension = ".hwdb".to_string(),
        "udev/rules.d" => extension = ".rules".to_string(),
        "kernel/install.d" => extension = ".install".to_string(),
        "systemd/ntp-units.d" => {
            is_collection = true;
            extension = ".list".to_string();
        }
        "systemd/network" => {
            is_collection = true;
        }
        "systemd/relabel-extra.d" => {
            is_collection = true;
            run_prefix_only = true;
            extension = ".relabel".to_string();
        }
        n if matches!(
            n,
            "systemd/system-preset" | "systemd/user-preset" | "systemd/initrd-preset"
        ) =>
        {
            is_collection = true;
            extension = ".preset".to_string();
        }
        _ => {}
    }

    GuessTypeResult {
        name,
        is_collection,
        extension,
        run_prefix_only,
    }
}

pub fn terminal_tint_color(hue: f64) -> Option<String> {
    let _ = hue;
    None
}

pub fn shall_tint_background() -> bool {
    match std::env::var("SYSTEMD_TINT_BACKGROUND") {
        Ok(val) if val == "0" => false,
        Ok(_) => true,
        Err(_) => true,
    }
}

pub fn draw_progress_bar(prefix: Option<&str>, percentage: f64) {
    if !io::stderr().is_terminal() {
        return;
    }
    draw_progress_bar_unbuffered(prefix, percentage);
}

pub fn draw_progress_bar_unbuffered(prefix: Option<&str>, percentage: f64) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    let _ = handle.write_all(b"\r");
    if let Some(p) = prefix {
        let _ = handle.write_all(p.as_bytes());
        let _ = handle.write_all(b" ");
    }

    let cols = terminal_columns();
    let prefix_width = prefix.map(|p| p.len()).unwrap_or(0) + 1;
    let length = if cols > prefix_width + 6 {
        cols - prefix_width - 6
    } else {
        0
    };

    if length > 5 && (0.0..=100.0).contains(&percentage) {
        let p = (length as f64 * percentage / 100.0) as usize;

        let _ = handle.write_all(ANSI_HIGHLIGHT_GREEN.as_bytes());
        for i in 0..length {
            if i <= p {
                let _ = handle.write_all("━".as_bytes());
            } else if i + 1 < length && i == p + 1 {
                let _ = handle.write_all(ANSI_NORMAL.as_bytes());
                let _ = handle.write_all(b" ");
                let _ = handle.write_all(ANSI_GREY.as_bytes());
            } else {
                let _ = handle.write_all("╌".as_bytes());
            }
        }
        let _ = handle.write_all(ANSI_NORMAL.as_bytes());
        let _ = handle.write_all(b" ");
    }

    let _ = write!(handle, "{ANSI_HIGHLIGHT}{percentage:3.0}%{ANSI_NORMAL}");
    let _ = handle.write_all(ANSI_ERASE_TO_END_OF_LINE.as_bytes());
    let _ = handle.write_all(b"\r");
}

pub fn clear_progress_bar(prefix: Option<&str>) {
    if !io::stderr().is_terminal() {
        return;
    }
    clear_progress_bar_unbuffered(prefix);
}

pub fn clear_progress_bar_unbuffered(prefix: Option<&str>) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    let _ = handle.write_all(b"\r");

    let cols = terminal_columns();
    let erase_width = if let Some(p) = prefix {
        p.len() + 5
    } else {
        cols.saturating_sub(1)
    };

    for _ in 0..erase_width {
        let _ = handle.write_all(b" ");
    }
    let _ = handle.write_all(ANSI_ERASE_TO_END_OF_LINE.as_bytes());
    let _ = handle.write_all(b"\r");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osc_char_is_valid() {
        assert!(osc_char_is_valid('a'));
        assert!(osc_char_is_valid('Z'));
        assert!(osc_char_is_valid('0'));
        assert!(osc_char_is_valid('~'));
        assert!(osc_char_is_valid(' '));
        assert!(!osc_char_is_valid('\x00'));
        assert!(!osc_char_is_valid('\x1f'));
        assert!(!osc_char_is_valid('\x7f'));
        assert!(!osc_char_is_valid('\n'));
        assert!(!osc_char_is_valid('\t'));
    }

    #[test]
    fn test_url_suitable_for_osc8_simple() {
        assert!(url_suitable_for_osc8("https://example.com"));
        assert!(url_suitable_for_osc8("http://example.com/path?a=b&c=d"));
    }

    #[test]
    fn test_url_suitable_for_osc8_too_long() {
        let long_url = "https://example.com/".repeat(200);
        assert!(!url_suitable_for_osc8(&long_url));
    }

    #[test]
    fn test_url_suitable_for_osc8_invalid_chars() {
        assert!(!url_suitable_for_osc8("https://example.com/\n"));
        assert!(!url_suitable_for_osc8("https://example.com/\x00"));
        assert!(!url_suitable_for_osc8("https://example.com/\x7f"));
    }

    #[test]
    fn test_terminal_urlify_basic() {
        let result = terminal_urlify("https://example.com", Some("click me"));
        assert!(result.contains("click me"));
        assert!(result.contains("https://example.com"));
        assert!(result.contains("\x1b]8;;"));
        assert!(result.contains("\x1b\\"));
    }

    #[test]
    fn test_terminal_urlify_uses_url_as_text_when_none() {
        let result = terminal_urlify("https://example.com", None);
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_terminal_urlify_fallback_for_invalid_osc8() {
        let result = terminal_urlify("https://example.com/\x00bad", Some("click"));
        assert_eq!(result, "click");
    }

    #[test]
    fn test_file_url_from_path_absolute() {
        let result = file_url_from_path("/etc/systemd/system.conf");
        assert!(result.starts_with("file://"));
        assert!(result.ends_with("/etc/systemd/system.conf"));
    }

    #[test]
    fn test_file_url_from_path_relative() {
        let result = file_url_from_path("some/file.txt");
        assert!(result.starts_with("file://"));
        assert!(result.contains("some/file.txt"));
    }

    #[test]
    fn test_terminal_urlify_path() {
        let result = terminal_urlify_path("/etc/systemd/system.conf", None);
        assert!(result.contains("system.conf"));
        assert!(result.contains("file://"));
    }

    #[test]
    fn test_terminal_urlify_path_empty() {
        let result = terminal_urlify_path("", None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_terminal_urlify_man() {
        let result = terminal_urlify_man("systemd.service", "5");
        assert!(result.contains("systemd.service(5) man page"));
        assert!(result.contains("man:systemd.service(5)"));
    }

    #[test]
    fn test_draw_cylon_at_start() {
        let result = draw_cylon(10, 0);
        assert!(result.starts_with('*'));
        assert!(result.contains("━"));
    }

    #[test]
    fn test_draw_cylon_at_middle() {
        let result = draw_cylon(10, 5);
        let visible: String = result.chars().filter(|c| *c == '*').collect();
        assert_eq!(visible.len(), 3);
    }

    #[test]
    fn test_draw_cylon_at_end() {
        let result = draw_cylon(10, 11);
        assert!(result.ends_with('*') || result.contains('*'));
    }

    #[test]
    fn test_draw_cylon_width_0() {
        let result = draw_cylon(0, 0);
        assert!(result.contains('*'));
    }

    #[test]
    fn test_guess_type_default() {
        let result = guess_type("systemd/system");
        assert!(!result.is_collection);
        assert_eq!(result.extension, ".conf");
        assert!(!result.run_prefix_only);
    }

    #[test]
    fn test_guess_type_collection() {
        let result = guess_type("systemd/network");
        assert!(result.is_collection);
    }

    #[test]
    fn test_guess_type_udev_hwdb() {
        let result = guess_type("udev/hwdb.d");
        assert_eq!(result.extension, ".hwdb");
    }

    #[test]
    fn test_guess_type_udev_rules() {
        let result = guess_type("udev/rules.d");
        assert_eq!(result.extension, ".rules");
    }

    #[test]
    fn test_guess_type_preset() {
        for name in &[
            "systemd/system-preset",
            "systemd/user-preset",
            "systemd/initrd-preset",
        ] {
            let result = guess_type(name);
            assert!(result.is_collection, "{name} should be collection");
            assert_eq!(result.extension, ".preset", "{name} extension");
        }
    }

    #[test]
    fn test_guess_type_relabel_extra() {
        let result = guess_type("systemd/relabel-extra.d");
        assert!(result.is_collection);
        assert!(result.run_prefix_only);
        assert_eq!(result.extension, ".relabel");
    }

    #[test]
    fn test_guess_type_environment_d_special_case() {
        let result = guess_type("environment.d");
        assert_eq!(result.name, "environment");
    }

    #[test]
    fn test_guess_type_trailing_slash() {
        let result = guess_type("systemd/system/");
        assert_eq!(result.name, "systemd/system");
    }

    #[test]
    fn test_shall_tint_background() {
        std::env::remove_var("SYSTEMD_TINT_BACKGROUND");
        assert!(shall_tint_background());

        std::env::set_var("SYSTEMD_TINT_BACKGROUND", "0");
        assert!(!shall_tint_background());

        std::env::set_var("SYSTEMD_TINT_BACKGROUND", "1");
        assert!(shall_tint_background());

        std::env::remove_var("SYSTEMD_TINT_BACKGROUND");
    }

    #[test]
    fn test_cat_flags_operations() {
        let flags = CatFlags::empty();
        assert!(!flags.contains(CatFlags::FORMAT_HAS_SECTIONS));
        assert!(!flags.contains(CatFlags::TLDR));

        let flags = CatFlags::FORMAT_HAS_SECTIONS | CatFlags::TLDR;
        assert!(flags.contains(CatFlags::FORMAT_HAS_SECTIONS));
        assert!(flags.contains(CatFlags::TLDR));
    }
}
