// SPDX-License-Identifier: LGPL-2.1-or-later

use super::model::{
    ARG_LINES_ALL, ID128_HEX_LEN, IdDescriptor, JournalctlArgs, LOG_DEBUG, ParseArgvError,
    ParseIdDescriptorError, ParsedLines, PatternCase, SD_JOURNAL_ALL_NAMESPACES,
    SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE, SD_JSON_FORMAT_COLOR_AUTO, SD_JSON_FORMAT_OFF,
};
use nix::libc;
use std::ffi::{CStr, CString};
use std::str::FromStr;
use std::sync::OnceLock;
use systemd_shared_rs::image_policy::image_policy_from_string;
use systemd_shared_rs::output_mode::{OutputMode, output_mode_to_json_format_flags};
use systemd_shared_rs::parse_argument::{parse_boolean_argument, parse_path_argument};
use systemd_shared_rs::pcre2_util::{PatternCompileCase, Pcre2Error, pattern_compile};

fn parse_i32_lossless(text: &str) -> Option<i32> {
    if text.is_empty() {
        return None;
    }

    text.parse::<i32>().ok()
}

fn parse_sd_id128_hex_prefix(bytes: &[u8]) -> Option<[u8; 16]> {
    if bytes.len() < ID128_HEX_LEN {
        return None;
    }

    let mut id = [0u8; 16];
    for i in 0..16 {
        let hi = bytes[i * 2];
        let lo = bytes[i * 2 + 1];

        if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
            return None;
        }

        let hi = (hi as char).to_digit(16)? as u8;
        let lo = (lo as char).to_digit(16)? as u8;
        id[i] = (hi << 4) | lo;
    }

    Some(id)
}

// Mirrors src/journal/journalctl.c:parse_id_descriptor() semantics.
pub fn parse_id_descriptor(text: &str) -> Result<IdDescriptor, ParseIdDescriptorError> {
    if text == "all" {
        return Ok(IdDescriptor {
            id: None,
            offset: 0,
        });
    }

    if text.len() >= ID128_HEX_LEN {
        let bytes = text.as_bytes();
        let mut remainder = text;
        let mut parsed_id = None;

        if let Some(id) = parse_sd_id128_hex_prefix(bytes) {
            parsed_id = Some(id);
            remainder = &text[ID128_HEX_LEN..];
        }

        if !remainder.is_empty() && !remainder.starts_with('-') && !remainder.starts_with('+') {
            return Err(ParseIdDescriptorError::Invalid);
        }

        let offset = if remainder.is_empty() {
            0
        } else {
            parse_i32_lossless(remainder).ok_or(ParseIdDescriptorError::Invalid)?
        };

        return Ok(IdDescriptor {
            id: parsed_id,
            offset,
        });
    }

    let offset = parse_i32_lossless(text).ok_or(ParseIdDescriptorError::Invalid)?;
    Ok(IdDescriptor { id: None, offset })
}

// Mirrors src/journal/journalctl.c:parse_lines() semantics.
pub fn parse_lines(
    arg: Option<&str>,
    graceful: bool,
) -> Result<ParsedLines, ParseIdDescriptorError> {
    let arg = match arg {
        Some(v) => v,
        None => {
            return Ok(ParsedLines {
                value: 10,
                oldest_first: false,
                explicit: false,
            });
        }
    };

    if arg == "all" {
        return Ok(ParsedLines {
            value: ARG_LINES_ALL,
            oldest_first: false,
            explicit: true,
        });
    }

    let oldest_first = arg.starts_with('+');
    let numeric = if oldest_first { &arg[1..] } else { arg };
    let parsed = parse_i32_lossless(numeric);

    match parsed {
        Some(value) if value >= 0 => Ok(ParsedLines {
            value,
            oldest_first,
            explicit: true,
        }),
        _ if graceful => Ok(ParsedLines {
            value: 10,
            oldest_first: false,
            explicit: false,
        }),
        _ => Err(ParseIdDescriptorError::Invalid),
    }
}

pub(crate) fn apply_output_mode(
    args: &mut JournalctlArgs,
    value: &str,
) -> Result<bool, ParseArgvError> {
    if value == "help" {
        return Ok(true);
    }

    let mode =
        OutputMode::from_str(value).map_err(|_| ParseArgvError::Invalid("unknown output"))?;
    args.output = mode;

    if mode.is_json() || matches!(mode, OutputMode::Export | OutputMode::Cat) {
        args.quiet = true;
    }

    if mode.is_json() {
        args.json_format_flags = output_mode_to_json_format_flags(mode) | SD_JSON_FORMAT_COLOR_AUTO;
    } else {
        args.json_format_flags = SD_JSON_FORMAT_OFF;
    }

    Ok(false)
}

fn parse_log_level(text: &str) -> Option<i32> {
    match text {
        "emerg" => Some(0),
        "alert" => Some(1),
        "crit" => Some(2),
        "err" => Some(3),
        "warning" => Some(4),
        "notice" => Some(5),
        "info" => Some(6),
        "debug" => Some(7),
        _ => {
            let parsed = text.parse::<i32>().ok()?;
            if (0..=LOG_DEBUG).contains(&parsed) {
                Some(parsed)
            } else {
                None
            }
        }
    }
}

pub(crate) fn parse_priority_mask(value: &str) -> Option<u32> {
    if let Some((left, right)) = value.split_once("..") {
        let a = parse_log_level(left)?;
        let b = parse_log_level(right)?;
        let lo = a.min(b);
        let hi = a.max(b);
        let mut mask = 0u32;
        for level in lo..=hi {
            mask |= 1u32 << level;
        }
        return Some(mask);
    }

    let p = parse_log_level(value)?;
    let mut mask = 0u32;
    for level in 0..=p {
        mask |= 1u32 << level;
    }
    Some(mask)
}

fn parse_facility(name: &str) -> Option<u8> {
    match name {
        "kern" => Some(0),
        "user" => Some(1),
        "mail" => Some(2),
        "daemon" => Some(3),
        "auth" => Some(4),
        "syslog" => Some(5),
        "lpr" => Some(6),
        "news" => Some(7),
        "uucp" => Some(8),
        "cron" => Some(9),
        "authpriv" => Some(10),
        "ftp" => Some(11),
        "local0" => Some(16),
        "local1" => Some(17),
        "local2" => Some(18),
        "local3" => Some(19),
        "local4" => Some(20),
        "local5" => Some(21),
        "local6" => Some(22),
        "local7" => Some(23),
        _ => {
            let parsed = name.parse::<u8>().ok()?;
            if parsed <= 23 { Some(parsed) } else { None }
        }
    }
}

pub(crate) fn apply_facilities(
    args: &mut JournalctlArgs,
    value: &str,
) -> Result<bool, ParseArgvError> {
    for fac in value.split(',') {
        if fac.is_empty() {
            continue;
        }

        if fac == "help" {
            return Ok(true);
        }

        let parsed =
            parse_facility(fac).ok_or(ParseArgvError::Invalid("invalid --facility value"))?;
        args.facilities.insert(parsed);
    }

    Ok(false)
}

pub(crate) fn parse_boolean_strict(value: &str) -> Result<bool, ParseArgvError> {
    parse_boolean_argument(Some(value))
        .map_err(|_| ParseArgvError::Invalid("invalid boolean argument"))
}

pub(crate) fn apply_namespace(args: &mut JournalctlArgs, value: &str) {
    if value == "*" {
        args.namespace_flags = SD_JOURNAL_ALL_NAMESPACES;
        args.namespace = None;
        return;
    }

    if let Some(rest) = value.strip_prefix('+') {
        args.namespace_flags = SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE;
        args.namespace = Some(rest.to_string());
        return;
    }

    args.namespace_flags = 0;
    if value.is_empty() {
        args.namespace = None;
    } else {
        args.namespace = Some(value.to_string());
    }
}

pub(crate) fn apply_output_fields(args: &mut JournalctlArgs, value: &str) {
    for field in value.split(',') {
        if !field.is_empty() {
            args.output_fields.insert(field.to_string());
        }
    }
}

pub(crate) fn current_working_dir_string() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
        .unwrap_or_else(|| "/".to_string())
}

pub(crate) fn parse_path_option(
    value: &str,
    suppress_root: bool,
    cwd: &str,
) -> Result<Option<String>, ParseArgvError> {
    parse_path_argument(value, suppress_root, cwd)
        .map_err(|_| ParseArgvError::Invalid("invalid path argument"))
}

pub(crate) fn validate_image_policy(value: &str) -> Result<(), ParseArgvError> {
    image_policy_from_string(value, false)
        .map(|_| ())
        .map_err(|_| ParseArgvError::Invalid("invalid --image-policy argument"))
}

fn pcre_case_from_pattern_case(case: PatternCase) -> PatternCompileCase {
    match case {
        PatternCase::Auto => PatternCompileCase::Auto,
        PatternCase::Sensitive => PatternCompileCase::Sensitive,
        PatternCase::Insensitive => PatternCompileCase::Insensitive,
    }
}

pub(crate) fn validate_grep_pattern(
    pattern: &str,
    case: PatternCase,
) -> Result<(), ParseArgvError> {
    match pattern_compile(pattern, pcre_case_from_pattern_case(case)) {
        Ok(_) => Ok(()),
        Err(
            Pcre2Error::Unsupported | Pcre2Error::DlopenFailed(_) | Pcre2Error::SymbolNotFound(_),
        ) => Ok(()),
        Err(_) => Err(ParseArgvError::Invalid("invalid --grep pattern")),
    }
}

type ParseTimestampFn = unsafe extern "C" fn(*const libc::c_char, *mut u64) -> libc::c_int;

fn resolved_parse_timestamp_fn() -> Option<ParseTimestampFn> {
    static PARSE_TIMESTAMP_FN: OnceLock<Option<ParseTimestampFn>> = OnceLock::new();

    *PARSE_TIMESTAMP_FN.get_or_init(|| {
        // SAFETY: symbol name is a valid NUL-terminated C string.
        let sym = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                b"parse_timestamp\0".as_ptr() as *const libc::c_char,
            )
        };
        if sym.is_null() {
            None
        } else {
            // SAFETY: symbol address is expected to match parse_timestamp signature.
            Some(unsafe { std::mem::transmute::<*mut libc::c_void, ParseTimestampFn>(sym) })
        }
    })
}

fn now_realtime_usec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

fn parse_timespan_usec(input: &str) -> Option<u64> {
    let mut rest = input.trim();
    if rest.is_empty() {
        return None;
    }

    let mut total = 0f64;
    while !rest.is_empty() {
        let mut number_end = 0usize;
        let mut seen_dot = false;
        for (idx, ch) in rest.char_indices() {
            if ch.is_ascii_digit() {
                number_end = idx + ch.len_utf8();
                continue;
            }
            if ch == '.' && !seen_dot {
                seen_dot = true;
                number_end = idx + ch.len_utf8();
                continue;
            }
            break;
        }

        if number_end == 0 {
            return None;
        }

        let number = rest[..number_end].parse::<f64>().ok()?;
        let mut suffix_end = number_end;
        for (idx, ch) in rest[number_end..].char_indices() {
            if ch.is_whitespace() {
                break;
            }
            suffix_end = number_end + idx + ch.len_utf8();
        }

        let suffix = rest[number_end..suffix_end].trim();
        let multiplier = match suffix {
            "" | "s" | "sec" | "second" | "seconds" => 1_000_000f64,
            "ms" | "msec" => 1_000f64,
            "us" | "usec" | "µs" | "μs" => 1f64,
            "m" | "min" | "minute" | "minutes" => 60_000_000f64,
            "h" | "hr" | "hour" | "hours" => 3_600_000_000f64,
            "d" | "day" | "days" => 86_400_000_000f64,
            "w" | "week" | "weeks" => 604_800_000_000f64,
            "M" | "month" | "months" => 2_629_800_000_000f64,
            "y" | "year" | "years" => 31_557_600_000_000f64,
            _ => return None,
        };

        total += number * multiplier;
        rest = rest[suffix_end..].trim_start();
    }

    if total.is_finite() && total >= 0.0 {
        Some(total as u64)
    } else {
        None
    }
}

fn parse_gmtoff_seconds(tz: &str) -> Option<i64> {
    if tz.len() < 3 {
        return None;
    }
    let sign = match tz.as_bytes().first().copied()? {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };

    let tail = &tz[1..];
    let (hh, mm) = if let Some((h, m)) = tail.split_once(':') {
        (h, m)
    } else if tail.len() == 2 {
        (tail, "0")
    } else if tail.len() == 4 {
        (&tail[..2], &tail[2..])
    } else {
        return None;
    };

    let hours = hh.parse::<i64>().ok()?;
    let minutes = mm.parse::<i64>().ok()?;
    if hours > 24 || minutes >= 60 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

fn parse_fractional_usec(input: &str) -> Option<(String, u64)> {
    if let Some((head, frac)) = input.split_once('.') {
        if frac.is_empty() || !frac.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let mut normalized = frac.chars().take(6).collect::<String>();
        while normalized.len() < 6 {
            normalized.push('0');
        }
        let usec = normalized.parse::<u64>().ok()?;
        Some((head.to_string(), usec))
    } else {
        Some((input.to_string(), 0))
    }
}

fn parse_tm_exact(input: &str, format: &str, seed_today: bool) -> Option<libc::tm> {
    let input_c = CString::new(input).ok()?;
    let format_c = CString::new(format).ok()?;

    // SAFETY: all-zero is a valid initial state for libc::tm before
    // localtime_r/strptime populate its integer fields.
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    if seed_today {
        let now = now_realtime_usec();
        let mut sec = (now / 1_000_000) as libc::time_t;
        // SAFETY: pointers are valid and non-null.
        unsafe {
            if libc::localtime_r(&mut sec, &mut tm).is_null() {
                return None;
            }
        }
    }

    // SAFETY: pointers are valid C strings, tm points to writable memory.
    let end_ptr = unsafe { libc::strptime(input_c.as_ptr(), format_c.as_ptr(), &mut tm) };
    if end_ptr.is_null() {
        return None;
    }

    // SAFETY: end_ptr points into input_c; reading one byte is valid.
    if unsafe { *end_ptr } != 0 {
        return None;
    }

    Some(tm)
}

fn tm_to_usec(tm: &mut libc::tm, utc: bool, frac_usec: u64) -> Option<u64> {
    // SAFETY: tm points to initialized time structure.
    let sec = unsafe {
        if utc {
            libc::timegm(tm)
        } else {
            libc::mktime(tm)
        }
    };
    if sec < 0 {
        return None;
    }
    let sec_u = u64::try_from(sec).ok()?;
    sec_u.checked_mul(1_000_000)?.checked_add(frac_usec)
}

fn parse_absolute_timestamp_fallback(input: &str) -> Option<u64> {
    if let Some(base) = input.strip_suffix(" UTC") {
        let (head, frac_usec) = parse_fractional_usec(base)?;
        let mut tm = parse_tm_exact(&head, "%Y-%m-%d %H:%M:%S", false)
            .or_else(|| parse_tm_exact(&head, "%Y-%m-%d %H:%M", false))
            .or_else(|| parse_tm_exact(&head, "%Y-%m-%dT%H:%M:%S", false))
            .or_else(|| parse_tm_exact(&head, "%Y-%m-%dT%H:%M", false))
            .or_else(|| parse_tm_exact(&head, "%Y-%m-%d", false))?;
        return tm_to_usec(&mut tm, true, frac_usec);
    }

    if let Some(base) = input.strip_suffix('Z') {
        let (head, frac_usec) = parse_fractional_usec(base)?;
        let mut tm = parse_tm_exact(&head, "%Y-%m-%dT%H:%M:%S", false)
            .or_else(|| parse_tm_exact(&head, "%Y-%m-%d %H:%M:%S", false))
            .or_else(|| parse_tm_exact(&head, "%Y-%m-%dT%H:%M", false))
            .or_else(|| parse_tm_exact(&head, "%Y-%m-%d %H:%M", false))?;
        return tm_to_usec(&mut tm, true, frac_usec);
    }

    for split in [6usize, 5, 3] {
        if input.len() <= split {
            continue;
        }
        let (head, tail) = input.split_at(input.len() - split);
        if !tail.starts_with('+') && !tail.starts_with('-') {
            continue;
        }
        let gmtoff = parse_gmtoff_seconds(tail)?;
        let (head_no_frac, frac_usec) = parse_fractional_usec(head)?;
        let mut tm = parse_tm_exact(&head_no_frac, "%Y-%m-%dT%H:%M:%S", false)
            .or_else(|| parse_tm_exact(&head_no_frac, "%Y-%m-%d %H:%M:%S", false))
            .or_else(|| parse_tm_exact(&head_no_frac, "%Y-%m-%dT%H:%M", false))
            .or_else(|| parse_tm_exact(&head_no_frac, "%Y-%m-%d %H:%M", false))?;
        let base = tm_to_usec(&mut tm, true, frac_usec)?;
        let shift = gmtoff.unsigned_abs().checked_mul(1_000_000)?;
        return if gmtoff >= 0 {
            base.checked_sub(shift)
        } else {
            base.checked_add(shift)
        };
    }

    let (head, frac_usec) = parse_fractional_usec(input)?;
    let mut tm = parse_tm_exact(&head, "%Y-%m-%d %H:%M:%S", false)
        .or_else(|| parse_tm_exact(&head, "%Y-%m-%dT%H:%M:%S", false))
        .or_else(|| parse_tm_exact(&head, "%b %d %H:%M:%S", true))
        .or_else(|| parse_tm_exact(&head, "%Y-%m-%d %H:%M", false))
        .or_else(|| parse_tm_exact(&head, "%Y-%m-%dT%H:%M", false))
        .or_else(|| parse_tm_exact(&head, "%Y-%m-%d", false))
        .or_else(|| parse_tm_exact(&head, "%H:%M:%S", true))
        .or_else(|| parse_tm_exact(&head, "%H:%M", true))?;
    tm_to_usec(&mut tm, false, frac_usec)
}

fn parse_timestamp_fallback(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let now = now_realtime_usec();
    match trimmed {
        "now" => return Some(now),
        "today" | "yesterday" | "tomorrow" => {
            let now_sec = (now / 1_000_000) as libc::time_t;
            // SAFETY: all-zero is a valid initial state for libc::tm before
            // localtime_r populates its integer fields.
            let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
            let mut local_sec = now_sec;
            // SAFETY: pointers are valid and non-null.
            let ok = unsafe { libc::localtime_r(&mut local_sec, &mut tm) };
            if ok.is_null() {
                return None;
            }

            if trimmed == "yesterday" {
                tm.tm_mday -= 1;
            } else if trimmed == "tomorrow" {
                tm.tm_mday += 1;
            }
            tm.tm_hour = 0;
            tm.tm_min = 0;
            tm.tm_sec = 0;
            return tm_to_usec(&mut tm, false, 0);
        }
        _ => {}
    }

    if let Some(rest) = trimmed.strip_prefix('@') {
        let sec = rest.parse::<u64>().ok()?;
        return sec.checked_mul(1_000_000);
    }

    if let Some(rest) = trimmed.strip_prefix('+') {
        let delta = parse_timespan_usec(rest)?;
        return now.checked_add(delta);
    }

    if let Some(rest) = trimmed.strip_prefix('-') {
        let delta = parse_timespan_usec(rest)?;
        return now.checked_sub(delta);
    }

    if let Some(rest) = trimmed.strip_suffix(" ago") {
        let delta = parse_timespan_usec(rest)?;
        return now.checked_sub(delta);
    }

    if let Some(rest) = trimmed.strip_suffix(" left") {
        let delta = parse_timespan_usec(rest)?;
        return now.checked_add(delta);
    }

    parse_absolute_timestamp_fallback(trimmed)
}

pub(crate) fn parse_timestamp_value(value: &str) -> Result<u64, ParseArgvError> {
    let c_value =
        CString::new(value).map_err(|_| ParseArgvError::Invalid("failed to parse timestamp"))?;

    if let Some(parse_timestamp_fn) = resolved_parse_timestamp_fn() {
        let mut usec = 0u64;
        // SAFETY: function pointer was resolved from parse_timestamp symbol.
        let r = unsafe { parse_timestamp_fn(c_value.as_ptr(), &mut usec) };
        if r >= 0 {
            return Ok(usec);
        }
    }

    parse_timestamp_fallback(value).ok_or(ParseArgvError::Invalid("failed to parse timestamp"))
}

struct GlobResult(libc::glob_t);

impl Drop for GlobResult {
    fn drop(&mut self) {
        // SAFETY: glob_t was initialized by glob() in expand_file_argument_paths().
        unsafe { libc::globfree(&mut self.0) };
    }
}

pub(crate) fn expand_file_argument_paths(value: &str) -> Result<Vec<String>, ParseArgvError> {
    let c_pattern =
        CString::new(value).map_err(|_| ParseArgvError::Invalid("invalid --file argument"))?;
    // SAFETY: glob_t is an opaque C output structure whose documented
    // initial state is zeroed before glob(3) initializes it.
    let mut glob = GlobResult(unsafe { std::mem::zeroed() });

    // SAFETY: c_pattern is NUL-terminated and valid; glob points to writable memory.
    let r = unsafe { libc::glob(c_pattern.as_ptr(), libc::GLOB_NOCHECK, None, &mut glob.0) };
    if r != 0 {
        return Err(ParseArgvError::Invalid("failed to expand --file path"));
    }

    let count = glob.0.gl_pathc as usize;
    let mut out = Vec::with_capacity(count);
    for idx in 0..count {
        // SAFETY: gl_pathv is populated by successful glob(); idx is in bounds [0, gl_pathc).
        let p = unsafe { *glob.0.gl_pathv.add(idx) };
        if p.is_null() {
            continue;
        }
        // SAFETY: entries in gl_pathv are NUL-terminated C strings.
        let path = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        out.push(path);
    }

    Ok(out)
}
