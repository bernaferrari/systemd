// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/calendarspec.c

use std::cmp::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const BITS_WEEKDAYS: i32 = 127;
pub const MIN_YEAR: i32 = 1970;
pub const MAX_YEAR: i32 = 2199;
pub const CALENDARSPEC_COMPONENTS_MAX: usize = 240;
pub const MAX_CALENDAR_ITERATIONS: usize = 1000;
pub const USEC_PER_SEC: i32 = 1_000_000;
const USEC_PER_MINUTE: i32 = 60 * USEC_PER_SEC;
const SEC_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarError {
    Invalid,
    OutOfRange,
    TooManyComponents,
    NotFound,
    Deadlock,
}

impl std::fmt::Display for CalendarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => write!(f, "Invalid calendar specification"),
            Self::OutOfRange => write!(f, "Value out of range"),
            Self::TooManyComponents => write!(f, "Calendar component chain too long"),
            Self::NotFound => write!(f, "No matching occurrence"),
            Self::Deadlock => write!(f, "Infinite loop in calendar calculation"),
        }
    }
}

impl std::error::Error for CalendarError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarComponent {
    pub start: i32,
    pub stop: i32,
    pub repeat: i32,
    pub next: Option<Box<CalendarComponent>>,
}

impl CalendarComponent {
    pub fn single(value: i32) -> Self {
        Self {
            start: value,
            stop: -1,
            repeat: 0,
            next: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarSpec {
    pub weekdays_bits: i32,
    pub end_of_month: bool,
    pub utc: bool,
    pub dst: i32,
    pub timezone: Option<String>,
    pub year: Option<Box<CalendarComponent>>,
    pub month: Option<Box<CalendarComponent>>,
    pub day: Option<Box<CalendarComponent>>,
    pub hour: Option<Box<CalendarComponent>>,
    pub minute: Option<Box<CalendarComponent>>,
    pub microsecond: Option<Box<CalendarComponent>>,
}

impl Default for CalendarSpec {
    fn default() -> Self {
        Self {
            weekdays_bits: -1,
            end_of_month: false,
            utc: false,
            dst: -1,
            timezone: None,
            year: None,
            month: None,
            day: None,
            hour: None,
            minute: None,
            microsecond: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DateTime {
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
    usec: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedDate<'a> {
    NotDate,
    Date(&'a str),
    TimestampDone(&'a str),
}

fn chain_to_vec(chain: &Option<Box<CalendarComponent>>) -> Vec<CalendarComponent> {
    let mut out = Vec::new();
    let mut cur = chain.as_deref();
    while let Some(node) = cur {
        out.push(CalendarComponent {
            start: node.start,
            stop: node.stop,
            repeat: node.repeat,
            next: None,
        });
        cur = node.next.as_deref();
    }
    out
}

fn chain_from_vec(mut parts: Vec<CalendarComponent>) -> Option<Box<CalendarComponent>> {
    let mut head = None;
    while let Some(mut part) = parts.pop() {
        part.next = head;
        head = Some(Box::new(part));
    }
    head
}

fn const_chain(value: i32, chain: &mut Option<Box<CalendarComponent>>) {
    let mut node = CalendarComponent::single(value);
    node.next = chain.take();
    *chain = Some(Box::new(node));
}

fn chain_cmp(a: &CalendarComponent, b: &CalendarComponent) -> Ordering {
    a.start
        .cmp(&b.start)
        .then_with(|| a.stop.cmp(&b.stop))
        .then_with(|| a.repeat.cmp(&b.repeat))
}

fn fix_year(chain: &mut Option<Box<CalendarComponent>>) {
    let mut cur = chain.as_deref_mut();
    while let Some(node) = cur {
        if (0..70).contains(&node.start) {
            node.start += 2000;
        } else if (70..100).contains(&node.start) {
            node.start += 1900;
        }

        if (0..70).contains(&node.stop) {
            node.stop += 2000;
        } else if (70..100).contains(&node.stop) {
            node.stop += 1900;
        }

        cur = node.next.as_deref_mut();
    }
}

fn normalize_chain(chain: &mut Option<Box<CalendarComponent>>) {
    let mut parts = chain_to_vec(chain);
    if parts.is_empty() {
        return;
    }

    for part in &mut parts {
        if part.stop > part.start && part.repeat > 0 {
            part.stop -= (part.stop - part.start) % part.repeat;
        }

        if (part.stop > part.start && part.repeat > 0 && part.start + part.repeat > part.stop)
            || part.start == part.stop
        {
            part.repeat = 0;
            part.stop = -1;
        }
    }

    if parts.len() > 1 {
        parts.sort_by(chain_cmp);
        parts.dedup_by(|a, b| chain_cmp(a, b) == Ordering::Equal);
    }

    *chain = chain_from_vec(parts);
}

fn calendar_spec_normalize(spec: &mut CalendarSpec) {
    if spec.timezone.as_deref() == Some("UTC") {
        spec.utc = true;
        spec.timezone = None;
    }

    if spec.weekdays_bits <= 0 || spec.weekdays_bits >= BITS_WEEKDAYS {
        spec.weekdays_bits = -1;
    }

    if spec.end_of_month && spec.day.is_none() {
        spec.end_of_month = false;
    }

    fix_year(&mut spec.year);
    normalize_chain(&mut spec.year);
    normalize_chain(&mut spec.month);
    normalize_chain(&mut spec.day);
    normalize_chain(&mut spec.hour);
    normalize_chain(&mut spec.minute);
    normalize_chain(&mut spec.microsecond);
}

fn chain_valid(
    chain: &Option<Box<CalendarComponent>>,
    from: i32,
    to: i32,
    end_of_month: bool,
) -> bool {
    let mut cur = chain.as_deref();
    let mut adjusted_to = to;
    if end_of_month {
        adjusted_to -= 3;
    }

    while let Some(node) = cur {
        if node.start < from || node.start > adjusted_to {
            return false;
        }
        if node.repeat > to - from {
            return false;
        }

        if node.stop >= 0 {
            if node.stop < from || node.stop > adjusted_to {
                return false;
            }
            if node.start + node.repeat > node.stop {
                return false;
            }
        } else if end_of_month {
            if node.start - node.repeat < from {
                return false;
            }
        } else if node.start + node.repeat > to {
            return false;
        }

        cur = node.next.as_deref();
    }

    true
}

pub fn calendar_spec_valid(spec: &CalendarSpec) -> bool {
    if spec.weekdays_bits > BITS_WEEKDAYS {
        return false;
    }

    chain_valid(&spec.year, MIN_YEAR, MAX_YEAR, false)
        && chain_valid(&spec.month, 1, 12, false)
        && chain_valid(&spec.day, 1, 31, spec.end_of_month)
        && chain_valid(&spec.hour, 0, 23, false)
        && chain_valid(&spec.minute, 0, 59, false)
        && chain_valid(&spec.microsecond, 0, USEC_PER_MINUTE - 1, false)
}

fn format_weekdays(bits: i32) -> String {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

    let mut out = String::new();
    let mut need_comma = false;
    let mut open = -1;

    for x in 0..DAYS.len() {
        if bits & (1 << x) != 0 {
            if open < 0 {
                if need_comma {
                    out.push(',');
                } else {
                    need_comma = true;
                }
                out.push_str(DAYS[x]);
                open = x as i32;
            }
        } else if open >= 0 {
            if x > open as usize + 1 {
                out.push_str(if x > open as usize + 2 { ".." } else { "," });
                out.push_str(DAYS[x - 1]);
            }
            open = -1;
        }
    }

    if open >= 0 && DAYS.len() > open as usize + 1 {
        out.push_str(if DAYS.len() > open as usize + 2 {
            ".."
        } else {
            ","
        });
        out.push_str(DAYS[DAYS.len() - 1]);
    }

    out
}

fn chain_is_star(chain: &Option<Box<CalendarComponent>>, usec: bool) -> bool {
    if chain.is_none() {
        return true;
    }

    if usec {
        let mut cur = chain.as_deref();
        while let Some(node) = cur {
            if node.start == 0 && node.stop < 0 && node.repeat == USEC_PER_SEC {
                return true;
            }
            cur = node.next.as_deref();
        }
    }

    false
}

fn push_component(out: &mut String, width: usize, part: &CalendarComponent, usec: bool) {
    let div = if usec { USEC_PER_SEC } else { 1 };
    out.push_str(&format!("{:0width$}", part.start / div, width = width));
    if part.start % div > 0 {
        out.push_str(&format!(".{:06}", part.start % div));
    }

    if part.stop > 0 {
        out.push_str("..");
        out.push_str(&format!("{:0width$}", part.stop / div, width = width));
        if part.stop % div > 0 {
            out.push_str(&format!(".{:06}", part.stop % div));
        }
    }

    if part.repeat > 0 && !(part.stop > 0 && part.repeat == div) {
        out.push('/');
        out.push_str(&(part.repeat / div).to_string());
        if part.repeat % div > 0 {
            out.push_str(&format!(".{:06}", part.repeat % div));
        }
    }
}

fn format_chain(
    out: &mut String,
    width: usize,
    chain: &Option<Box<CalendarComponent>>,
    usec: bool,
) {
    if chain_is_star(chain, usec) {
        out.push('*');
        return;
    }

    let mut first = true;
    let mut cur = chain.as_deref();
    while let Some(node) = cur {
        if !first {
            out.push(',');
        }
        push_component(out, width, node, usec);
        first = false;
        cur = node.next.as_deref();
    }
}

pub fn calendar_spec_to_string(spec: &CalendarSpec) -> String {
    let mut out = String::new();

    if spec.weekdays_bits > 0 && spec.weekdays_bits <= BITS_WEEKDAYS {
        out.push_str(&format_weekdays(spec.weekdays_bits));
        out.push(' ');
    }

    format_chain(&mut out, 4, &spec.year, false);
    out.push('-');
    format_chain(&mut out, 2, &spec.month, false);
    out.push(if spec.end_of_month { '~' } else { '-' });
    format_chain(&mut out, 2, &spec.day, false);
    out.push(' ');
    format_chain(&mut out, 2, &spec.hour, false);
    out.push(':');
    format_chain(&mut out, 2, &spec.minute, false);
    out.push(':');
    format_chain(&mut out, 2, &spec.microsecond, true);

    if spec.utc {
        out.push_str(" UTC");
    } else if let Some(timezone) = &spec.timezone {
        out.push(' ');
        out.push_str(timezone);
    }

    out
}

const WEEKDAYS: [(&str, i32); 14] = [
    ("Monday", 0),
    ("Mon", 0),
    ("Tuesday", 1),
    ("Tue", 1),
    ("Wednesday", 2),
    ("Wed", 2),
    ("Thursday", 3),
    ("Thu", 3),
    ("Friday", 4),
    ("Fri", 4),
    ("Saturday", 5),
    ("Sat", 5),
    ("Sunday", 6),
    ("Sun", 6),
];

fn starts_with_no_case(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .map(|head| head.eq_ignore_ascii_case(prefix))
        .unwrap_or(false)
}

fn trim_leading_spaces(s: &str) -> &str {
    s.trim_start_matches(' ')
}

fn parse_weekdays<'a>(
    mut input: &'a str,
    spec: &mut CalendarSpec,
) -> Result<&'a str, CalendarError> {
    let mut open = -1;
    let mut first = true;

    loop {
        let mut matched = None;

        for (name, nr) in WEEKDAYS {
            if !starts_with_no_case(input, name) {
                continue;
            }

            let next = input.as_bytes().get(name.len()).copied().unwrap_or(0);
            if !matches!(next, 0 | b'-' | b'.' | b',' | b' ') {
                return Err(CalendarError::Invalid);
            }

            matched = Some((name.len(), nr));
            break;
        }

        let Some((skip, nr)) = matched else {
            return if first {
                Ok(input)
            } else {
                Err(CalendarError::Invalid)
            };
        };

        if first {
            spec.weekdays_bits = 0;
        }
        spec.weekdays_bits |= 1 << nr;
        if open >= 0 {
            if open > nr {
                return Err(CalendarError::Invalid);
            }
            for j in open + 1..nr {
                spec.weekdays_bits |= 1 << j;
            }
        }

        input = &input[skip..];

        if input.is_empty() {
            return Ok(input);
        }
        if input.starts_with(' ') {
            return Ok(trim_leading_spaces(input));
        }

        if input.starts_with("..") {
            if open >= 0 {
                return Err(CalendarError::Invalid);
            }
            open = nr;
            input = &input[2..];
        } else if input.starts_with('-') {
            if open >= 0 {
                return Err(CalendarError::Invalid);
            }
            open = nr;
            input = &input[1..];
        } else if input.starts_with(',') {
            open = -1;
            input = &input[1..];
        }

        if input.is_empty() || input.starts_with(' ') {
            return if open < 0 {
                Ok(trim_leading_spaces(input))
            } else {
                Err(CalendarError::Invalid)
            };
        }

        first = false;
    }
}

fn parse_one_number(input: &str) -> Result<(u64, &str), CalendarError> {
    let end = input
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(input.len());
    if end == 0 {
        return Err(CalendarError::Invalid);
    }
    let value = input[..end]
        .parse::<u64>()
        .map_err(|_| CalendarError::OutOfRange)?;
    Ok((value, &input[end..]))
}

fn parse_component_decimal(mut input: &str, usec: bool) -> Result<(i32, &str), CalendarError> {
    if !input.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(CalendarError::Invalid);
    }

    let (value, rest) = parse_one_number(input)?;
    input = rest;

    let mut total = if usec {
        value
            .checked_mul(USEC_PER_SEC as u64)
            .ok_or(CalendarError::OutOfRange)?
    } else {
        value
    };

    if usec && input.starts_with('.') && !input.starts_with("..") {
        let frac = &input[1..];
        let digits = frac
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(frac.len());
        if digits == 0 || digits > 6 {
            return Err(CalendarError::Invalid);
        }

        let add = frac[..digits]
            .parse::<u64>()
            .map_err(|_| CalendarError::OutOfRange)?
            * 10_u64.pow((6 - digits) as u32);
        total = total.checked_add(add).ok_or(CalendarError::OutOfRange)?;
        input = &frac[digits..];
    }

    if total > i32::MAX as u64 {
        return Err(CalendarError::OutOfRange);
    }

    Ok((total as i32, input))
}

fn prepend_component<'a>(
    mut input: &'a str,
    usec: bool,
    nesting: usize,
    chain: &mut Option<Box<CalendarComponent>>,
) -> Result<&'a str, CalendarError> {
    if nesting > CALENDARSPEC_COMPONENTS_MAX {
        return Err(CalendarError::TooManyComponents);
    }

    let (start, rest) = parse_component_decimal(input, usec)?;
    input = rest;

    let mut stop = -1;
    let mut repeat = 0;

    if input.starts_with("..") {
        input = &input[2..];
        let (parsed_stop, rest) = parse_component_decimal(input, usec)?;
        stop = parsed_stop;
        repeat = if usec { USEC_PER_SEC } else { 1 };
        input = rest;
    }

    if input.starts_with('/') {
        input = &input[1..];
        let (parsed_repeat, rest) = parse_component_decimal(input, usec)?;
        if parsed_repeat == 0 {
            return Err(CalendarError::OutOfRange);
        }
        repeat = parsed_repeat;
        input = rest;
    } else {
        if start > i32::MAX - repeat {
            return Err(CalendarError::OutOfRange);
        }
        if usec && stop >= 0 && start + repeat > stop {
            return Err(CalendarError::Invalid);
        }
    }

    let terminator = input.as_bytes().first().copied().unwrap_or(0);
    if !matches!(terminator, 0 | b' ' | b',' | b'-' | b'~' | b':') {
        return Err(CalendarError::Invalid);
    }

    let node = CalendarComponent {
        start,
        stop,
        repeat,
        next: chain.take(),
    };
    *chain = Some(Box::new(node));

    if let Some(rest) = input.strip_prefix(',') {
        prepend_component(rest, usec, nesting + 1, chain)
    } else {
        Ok(input)
    }
}

fn parse_chain<'a>(
    input: &'a str,
    usec: bool,
    chain: &mut Option<Box<CalendarComponent>>,
) -> Result<&'a str, CalendarError> {
    if let Some(rest) = input.strip_prefix('*') {
        if usec {
            const_chain(0, chain);
            if let Some(head) = chain.as_deref_mut() {
                head.repeat = USEC_PER_SEC;
            }
        } else {
            *chain = None;
        }
        return Ok(rest);
    }

    prepend_component(input, usec, 0, chain)
}

fn div_floor(a: i64, b: i64) -> i64 {
    let q = a / b;
    let r = a % b;
    if r != 0 && ((r > 0) != (b > 0)) {
        q - 1
    } else {
        q
    }
}

fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = div_floor(y, 400);
    let yoe = y - era * 400;
    let m = month as i64;
    let d = day as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(days: i64) -> (i32, i32, i32) {
    let z = days + 719468;
    let era = div_floor(z, 146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as i32, d as i32)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn usec_from_datetime(dt: DateTime) -> Result<i64, CalendarError> {
    if !(MIN_YEAR..=MAX_YEAR).contains(&dt.year) {
        return Err(CalendarError::OutOfRange);
    }
    let dim = days_in_month(dt.year, dt.month);
    if dt.month < 1 || dt.month > 12 || dt.day < 1 || dt.day > dim {
        return Err(CalendarError::OutOfRange);
    }

    let day_index = days_from_civil(dt.year, dt.month, dt.day);
    let seconds = dt.hour as i64 * 3600 + dt.minute as i64 * 60 + dt.second as i64;
    let extra_days = div_floor(seconds, SEC_PER_DAY);
    let day_seconds = seconds - extra_days * SEC_PER_DAY;
    Ok(
        ((day_index + extra_days) * SEC_PER_DAY + day_seconds) * USEC_PER_SEC as i64
            + dt.usec as i64,
    )
}

fn datetime_from_usec(usec: i64) -> Result<DateTime, CalendarError> {
    let secs = div_floor(usec, USEC_PER_SEC as i64);
    let micros = (usec - secs * USEC_PER_SEC as i64) as i32;
    let days = div_floor(secs, SEC_PER_DAY);
    let sec_of_day = (secs - days * SEC_PER_DAY) as i32;
    let (year, month, day) = civil_from_days(days);
    if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
        return Err(CalendarError::OutOfRange);
    }

    Ok(DateTime {
        year,
        month,
        day,
        hour: sec_of_day / 3600,
        minute: (sec_of_day % 3600) / 60,
        second: sec_of_day % 60,
        usec: micros,
    })
}

fn calendarspec_from_timestamp(
    spec: &mut CalendarSpec,
    timestamp: i64,
) -> Result<(), CalendarError> {
    let dt = datetime_from_usec(
        timestamp
            .checked_mul(USEC_PER_SEC as i64)
            .ok_or(CalendarError::OutOfRange)?,
    )?;
    const_chain(dt.year, &mut spec.year);
    const_chain(dt.month, &mut spec.month);
    const_chain(dt.day, &mut spec.day);
    const_chain(dt.hour, &mut spec.hour);
    const_chain(dt.minute, &mut spec.minute);
    const_chain(dt.second * USEC_PER_SEC, &mut spec.microsecond);
    spec.utc = true;
    Ok(())
}

fn parse_date<'a>(
    input: &'a str,
    spec: &mut CalendarSpec,
) -> Result<ParsedDate<'a>, CalendarError> {
    if input.is_empty() {
        return Ok(ParsedDate::NotDate);
    }

    if let Some(rest) = input.strip_prefix('@') {
        let (value, tail) = parse_one_number(rest)?;
        let timestamp = i64::try_from(value).map_err(|_| CalendarError::OutOfRange)?;
        calendarspec_from_timestamp(spec, timestamp)?;
        return Ok(ParsedDate::TimestampDone(tail));
    }

    let mut first = None;
    let mut second = None;
    let mut third = None;

    let mut cursor = parse_chain(input, false, &mut first)?;
    if cursor.is_empty() || cursor.starts_with(':') {
        return Ok(ParsedDate::NotDate);
    }

    if cursor.starts_with('~') {
        spec.end_of_month = true;
    } else if !cursor.starts_with('-') {
        return Err(CalendarError::Invalid);
    }
    cursor = &cursor[1..];

    cursor = parse_chain(cursor, false, &mut second)?;

    if cursor.is_empty() || cursor.starts_with(' ') {
        spec.month = first;
        spec.day = second;
        return Ok(ParsedDate::Date(trim_leading_spaces(cursor)));
    }
    if spec.end_of_month {
        return Err(CalendarError::Invalid);
    }

    if cursor.starts_with('~') {
        spec.end_of_month = true;
    } else if !cursor.starts_with('-') {
        return Err(CalendarError::Invalid);
    }
    cursor = &cursor[1..];

    if !spec.end_of_month && cursor.starts_with('~') {
        spec.end_of_month = true;
        cursor = &cursor[1..];
    }

    cursor = parse_chain(cursor, false, &mut third)?;
    if !cursor.is_empty() && !cursor.starts_with(' ') {
        return Err(CalendarError::Invalid);
    }

    spec.year = first;
    spec.month = second;
    spec.day = third;
    Ok(ParsedDate::Date(trim_leading_spaces(cursor)))
}

fn parse_calendar_time(mut input: &str, spec: &mut CalendarSpec) -> Result<(), CalendarError> {
    let mut hour = None;
    let mut minute = None;
    let mut microsecond = None;

    if input.is_empty() {
        const_chain(0, &mut hour);
        const_chain(0, &mut minute);
        const_chain(0, &mut microsecond);
        spec.hour = hour;
        spec.minute = minute;
        spec.microsecond = microsecond;
        return Ok(());
    }

    input = parse_chain(input, false, &mut hour)?;
    if !input.starts_with(':') {
        return Err(CalendarError::Invalid);
    }

    input = parse_chain(&input[1..], false, &mut minute)?;
    if input.is_empty() {
        const_chain(0, &mut microsecond);
        spec.hour = hour;
        spec.minute = minute;
        spec.microsecond = microsecond;
        return Ok(());
    }

    if !input.starts_with(':') {
        return Err(CalendarError::Invalid);
    }

    input = parse_chain(&input[1..], true, &mut microsecond)?;
    if !input.is_empty() {
        return Err(CalendarError::Invalid);
    }

    spec.hour = hour;
    spec.minute = minute;
    spec.microsecond = microsecond;
    Ok(())
}

fn strip_case_insensitive_suffix<'a>(input: &'a str, suffix: &str) -> Option<&'a str> {
    let start = input.len().checked_sub(suffix.len())?;
    let tail = input.get(start..)?;
    if tail.eq_ignore_ascii_case(suffix) {
        input.get(..start)
    } else {
        None
    }
}

fn looks_like_timezone(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(
            |b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'_' | b'+' | b'-'),
        )
        && token.bytes().any(|b| (b as char).is_ascii_alphabetic())
        && (token.contains('/') || token.bytes().all(|b| (b as char).is_ascii_alphabetic()))
}

fn split_timezone_suffix(input: &str) -> (String, bool, Option<String>) {
    if let Some(prefix) = strip_case_insensitive_suffix(input, " UTC") {
        return (prefix.to_string(), true, None);
    }

    if let Some(space) = input.rfind(' ') {
        let token = &input[space + 1..];
        if looks_like_timezone(token) {
            return (input[..space].to_string(), false, Some(token.to_string()));
        }
    }

    (input.to_string(), false, None)
}

fn add_keyword_defaults(spec: &mut CalendarSpec, keyword: &str) -> Result<bool, CalendarError> {
    match keyword {
        "minutely" => {
            const_chain(0, &mut spec.microsecond);
        }
        "hourly" => {
            const_chain(0, &mut spec.minute);
            const_chain(0, &mut spec.microsecond);
        }
        "daily" => {
            const_chain(0, &mut spec.hour);
            const_chain(0, &mut spec.minute);
            const_chain(0, &mut spec.microsecond);
        }
        "monthly" => {
            const_chain(1, &mut spec.day);
            const_chain(0, &mut spec.hour);
            const_chain(0, &mut spec.minute);
            const_chain(0, &mut spec.microsecond);
        }
        "annually" | "yearly" | "anually" => {
            const_chain(1, &mut spec.month);
            const_chain(1, &mut spec.day);
            const_chain(0, &mut spec.hour);
            const_chain(0, &mut spec.minute);
            const_chain(0, &mut spec.microsecond);
        }
        "weekly" => {
            spec.weekdays_bits = 1;
            const_chain(0, &mut spec.hour);
            const_chain(0, &mut spec.minute);
            const_chain(0, &mut spec.microsecond);
        }
        "quarterly" => {
            const_chain(1, &mut spec.month);
            const_chain(4, &mut spec.month);
            const_chain(7, &mut spec.month);
            const_chain(10, &mut spec.month);
            const_chain(1, &mut spec.day);
            const_chain(0, &mut spec.hour);
            const_chain(0, &mut spec.minute);
            const_chain(0, &mut spec.microsecond);
        }
        "biannually" | "bi-annually" | "semiannually" | "semi-annually" => {
            const_chain(1, &mut spec.month);
            const_chain(7, &mut spec.month);
            const_chain(1, &mut spec.day);
            const_chain(0, &mut spec.hour);
            const_chain(0, &mut spec.minute);
            const_chain(0, &mut spec.microsecond);
        }
        _ => return Ok(false),
    }

    Ok(true)
}

pub fn calendar_spec_from_string(input: &str) -> Result<CalendarSpec, CalendarError> {
    CalendarSpec::parse(input)
}

impl CalendarSpec {
    pub fn parse(input: &str) -> Result<Self, CalendarError> {
        let (trimmed, utc, timezone) = split_timezone_suffix(input);
        let trimmed = trimmed.trim();
        if trimmed.is_empty() {
            return Err(CalendarError::Invalid);
        }

        let mut spec = CalendarSpec {
            utc,
            timezone,
            ..CalendarSpec::default()
        };

        let lower = trimmed.to_ascii_lowercase();
        if !add_keyword_defaults(&mut spec, &lower)? {
            let rest = parse_weekdays(trimmed, &mut spec)?;
            match parse_date(rest, &mut spec)? {
                ParsedDate::TimestampDone(tail) => {
                    if !tail.is_empty() {
                        return Err(CalendarError::Invalid);
                    }
                }
                ParsedDate::Date(tail) => parse_calendar_time(tail, &mut spec)?,
                ParsedDate::NotDate => parse_calendar_time(rest, &mut spec)?,
            }
        }

        calendar_spec_normalize(&mut spec);
        if !calendar_spec_valid(&spec) {
            return Err(CalendarError::Invalid);
        }
        Ok(spec)
    }

    pub fn next(&self, after: &SystemTime) -> Option<SystemTime> {
        self.next_after(*after)
    }

    pub fn next_after(&self, after: SystemTime) -> Option<SystemTime> {
        let after_usec = after.duration_since(UNIX_EPOCH).ok()?.as_micros() as i64;
        let next_usec = self.next_usec(after_usec).ok()?;
        let secs = next_usec / USEC_PER_SEC as i64;
        let nanos = ((next_usec % USEC_PER_SEC as i64) as u32) * 1000;
        Some(UNIX_EPOCH + Duration::new(secs as u64, nanos))
    }

    pub fn next_usec(&self, after_usec: i64) -> Result<i64, CalendarError> {
        let mut dt =
            datetime_from_usec(after_usec.checked_add(1).ok_or(CalendarError::OutOfRange)?)?;

        for _ in 0..MAX_CALENDAR_ITERATIONS {
            if dt.year > MAX_YEAR {
                return Err(CalendarError::NotFound);
            }

            let year = match next_matching_value(&self.year, dt.year, MIN_YEAR, MAX_YEAR) {
                Ok(v) => v,
                Err(_) => return Err(CalendarError::NotFound),
            };
            if year != dt.year {
                dt.year = year;
                dt.month = 1;
                dt.day = 1;
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.usec = 0;
            }

            let month = match next_matching_value(&self.month, dt.month, 1, 12) {
                Ok(v) => v,
                Err(_) => {
                    dt.year += 1;
                    dt.month = 1;
                    dt.day = 1;
                    dt.hour = 0;
                    dt.minute = 0;
                    dt.second = 0;
                    dt.usec = 0;
                    continue;
                }
            };
            if month != dt.month {
                dt.month = month;
                dt.day = 1;
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.usec = 0;
            }

            let Some(day) = next_matching_day(self, dt.year, dt.month, dt.day) else {
                advance_month(&mut dt);
                continue;
            };
            if day != dt.day {
                dt.day = day;
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.usec = 0;
            }

            let Some((hour, minute, second, usec)) =
                next_matching_time(self, dt.hour, dt.minute, dt.second, dt.usec)
            else {
                advance_day(&mut dt);
                continue;
            };

            dt.hour = hour;
            dt.minute = minute;
            dt.second = second;
            dt.usec = usec;
            return usec_from_datetime(dt);
        }

        Err(CalendarError::Deadlock)
    }
}

pub fn calendar_spec_next_usec(spec: &CalendarSpec, after_usec: i64) -> Result<i64, CalendarError> {
    spec.next_usec(after_usec)
}

fn next_matching_value(
    chain: &Option<Box<CalendarComponent>>,
    current: i32,
    min: i32,
    max: i32,
) -> Result<i32, CalendarError> {
    if current < min || current > max {
        return Err(CalendarError::NotFound);
    }
    if chain.is_none() {
        return Ok(current);
    }

    let mut best = None;
    let mut cur = chain.as_deref();
    while let Some(node) = cur {
        let start = node.start;
        let stop = node.stop;

        if start >= current {
            if best.is_none_or(|v| start < v) {
                best = Some(start);
            }
        } else if node.repeat > 0 {
            let delta = current - start;
            let step = ((delta + node.repeat - 1) / node.repeat) * node.repeat;
            let candidate = start + step;
            if (stop < 0 || candidate <= stop) && best.is_none_or(|v| candidate < v) {
                best = Some(candidate);
            }
        }

        cur = node.next.as_deref();
    }

    best.filter(|v| *v >= min && *v <= max)
        .ok_or(CalendarError::NotFound)
}

fn nth_last_day_of_month(year: i32, month: i32, n: i32) -> Option<i32> {
    let dim = days_in_month(year, month);
    let day = dim - n + 1;
    if (1..=dim).contains(&day) {
        Some(day)
    } else {
        None
    }
}

fn matches_component_value(value: i32, start: i32, stop: i32, repeat: i32) -> bool {
    if value == start {
        return true;
    }
    if repeat <= 0 {
        return false;
    }
    if value < start {
        return false;
    }
    if stop >= 0 && value > stop {
        return false;
    }
    (value - start) % repeat == 0
}

fn matches_day(spec: &CalendarSpec, year: i32, month: i32, day: i32) -> bool {
    if let Some(chain) = &spec.day {
        let mut cur = Some(chain.as_ref());
        let mut matched = false;

        while let Some(node) = cur {
            let mut start = node.start;
            let mut stop = node.stop;

            if spec.end_of_month {
                let Some(s) = nth_last_day_of_month(year, month, node.start) else {
                    cur = node.next.as_deref();
                    continue;
                };
                start = s;

                if node.stop >= 0 {
                    let Some(e) = nth_last_day_of_month(year, month, node.stop) else {
                        cur = node.next.as_deref();
                        continue;
                    };
                    stop = e;
                    if stop > 0 {
                        std::mem::swap(&mut start, &mut stop);
                    }
                }
            }

            if matches_component_value(day, start, stop, node.repeat) {
                matched = true;
                break;
            }

            cur = node.next.as_deref();
        }

        if !matched {
            return false;
        }
    }

    if spec.weekdays_bits < 0 || spec.weekdays_bits >= BITS_WEEKDAYS {
        return true;
    }

    let weekday = (days_from_civil(year, month, day) + 3).rem_euclid(7) as i32;
    spec.weekdays_bits & (1 << weekday) != 0
}

fn next_matching_day(spec: &CalendarSpec, year: i32, month: i32, from_day: i32) -> Option<i32> {
    let dim = days_in_month(year, month);
    (from_day.max(1)..=dim).find(|&day| matches_day(spec, year, month, day))
}

fn next_matching_time(
    spec: &CalendarSpec,
    from_hour: i32,
    from_minute: i32,
    from_second: i32,
    from_usec: i32,
) -> Option<(i32, i32, i32, i32)> {
    let mut hour_start = from_hour;

    while hour_start <= 23 {
        let hour = next_matching_value(&spec.hour, hour_start, 0, 23).ok()?;
        let mut minute_start = if hour == from_hour { from_minute } else { 0 };

        while minute_start <= 59 {
            let minute = match next_matching_value(&spec.minute, minute_start, 0, 59) {
                Ok(v) => v,
                Err(_) => break,
            };

            let micro_start = if hour == from_hour && minute == from_minute {
                from_second * USEC_PER_SEC + from_usec
            } else {
                0
            };

            match next_matching_value(&spec.microsecond, micro_start, 0, USEC_PER_MINUTE - 1) {
                Ok(v) => return Some((hour, minute, v / USEC_PER_SEC, v % USEC_PER_SEC)),
                Err(_) => minute_start = minute + 1,
            }
        }

        hour_start = hour + 1;
    }

    None
}

fn advance_month(dt: &mut DateTime) {
    dt.month += 1;
    if dt.month > 12 {
        dt.month = 1;
        dt.year += 1;
    }
    dt.day = 1;
    dt.hour = 0;
    dt.minute = 0;
    dt.second = 0;
    dt.usec = 0;
}

fn advance_day(dt: &mut DateTime) {
    let days = days_from_civil(dt.year, dt.month, dt.day) + 1;
    let (year, month, day) = civil_from_days(days);
    dt.year = year;
    dt.month = month;
    dt.day = day;
    dt.hour = 0;
    dt.minute = 0;
    dt.second = 0;
    dt.usec = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usec(spec: &str, after: i64) -> i64 {
        CalendarSpec::parse(spec).unwrap().next_usec(after).unwrap()
    }

    #[test]
    fn parses_keywords() {
        let daily = CalendarSpec::parse("daily").unwrap();
        assert!(daily.hour.is_some());
        assert!(daily.minute.is_some());
        assert!(daily.microsecond.is_some());

        let weekly = CalendarSpec::parse("weekly").unwrap();
        assert_eq!(weekly.weekdays_bits, 1);

        let quarterly = CalendarSpec::parse("quarterly").unwrap();
        assert_eq!(
            calendar_spec_to_string(&quarterly),
            "*-01,04,07,10-01 00:00:00"
        );
    }

    #[test]
    fn parses_weekday_ranges() {
        let spec = CalendarSpec::parse("Mon..Fri *-*-* 00:00:00").unwrap();
        assert_eq!(spec.weekdays_bits, 0b0011111);
        assert_eq!(calendar_spec_to_string(&spec), "Mon..Fri *-*-* 00:00:00");
    }

    #[test]
    fn parses_time_only_and_implicit_seconds() {
        assert_eq!(
            calendar_spec_to_string(&CalendarSpec::parse("10:15").unwrap()),
            "*-*-* 10:15:00"
        );
        assert_eq!(
            calendar_spec_to_string(&CalendarSpec::parse("10:15:42.123456").unwrap()),
            "*-*-* 10:15:42.123456"
        );
    }

    #[test]
    fn parses_end_of_month() {
        let spec = CalendarSpec::parse("*-*-~1 00:00:00").unwrap();
        assert!(spec.end_of_month);
        assert_eq!(calendar_spec_to_string(&spec), "*-*~01 00:00:00");
    }

    #[test]
    fn parses_timestamp() {
        let spec = CalendarSpec::parse("@0").unwrap();
        assert!(spec.utc);
        assert_eq!(calendar_spec_to_string(&spec), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn fixes_two_digit_years() {
        let spec = CalendarSpec::parse("12-01-02 03:04:05").unwrap();
        assert_eq!(calendar_spec_to_string(&spec), "2012-01-02 03:04:05");

        let spec = CalendarSpec::parse("89-01-02 03:04:05").unwrap();
        assert_eq!(calendar_spec_to_string(&spec), "1989-01-02 03:04:05");
    }

    #[test]
    fn normalizes_duplicate_components() {
        let spec = CalendarSpec::parse("*-01,01,03-* 00:00:00").unwrap();
        assert_eq!(calendar_spec_to_string(&spec), "*-01,03-* 00:00:00");
    }

    #[test]
    fn validates_ranges() {
        assert!(CalendarSpec::parse("*-13-* 00:00:00").is_err());
        assert!(CalendarSpec::parse("*-*-* 24:00:00").is_err());
        assert!(CalendarSpec::parse("Fri..Mon *-*-* 00:00:00").is_err());
    }

    #[test]
    fn supports_timezone_suffix_roundtrip() {
        let spec = CalendarSpec::parse("Mon *-*-* 00:00:00 Europe/Berlin").unwrap();
        assert_eq!(spec.timezone.as_deref(), Some("Europe/Berlin"));
        assert_eq!(
            calendar_spec_to_string(&spec),
            "Mon *-*-* 00:00:00 Europe/Berlin"
        );
    }

    #[test]
    fn next_daily() {
        assert_eq!(
            usec("daily", 1704110400_i64 * 1_000_000),
            1704153600_i64 * 1_000_000
        );
    }

    #[test]
    fn next_hourly() {
        assert_eq!(
            usec("hourly", 1704112230_i64 * 1_000_000),
            1704114000_i64 * 1_000_000
        );
    }

    #[test]
    fn next_minutely() {
        assert_eq!(
            usec("minutely", 1704112230_i64 * 1_000_000),
            1704112260_i64 * 1_000_000
        );
    }

    #[test]
    fn next_weekday_only() {
        assert_eq!(
            usec("Mon *-*-* 00:00:00", 1704153600_i64 * 1_000_000),
            1704672000_i64 * 1_000_000
        );
    }

    #[test]
    fn next_monthly_and_yearly() {
        assert_eq!(
            usec("monthly", 1705276800_i64 * 1_000_000),
            1706745600_i64 * 1_000_000
        );
        assert_eq!(
            usec("yearly", 1706745600_i64 * 1_000_000),
            1735689600_i64 * 1_000_000
        );
    }

    #[test]
    fn next_with_repeat() {
        assert_eq!(
            usec("*-*-* *:00/5:00", 1704067380_i64 * 1_000_000),
            1704067500_i64 * 1_000_000
        );
        assert_eq!(
            usec("*-*-* 00:00:00/30", 1704067201_i64 * 1_000_000),
            1704067230_i64 * 1_000_000
        );
    }

    #[test]
    fn next_end_of_month() {
        assert_eq!(
            usec("*-*-~1 00:00:00", 1706745600_i64 * 1_000_000),
            1709164800_i64 * 1_000_000
        );
        assert_eq!(
            usec("*-*-~2 00:00:00", 1706745600_i64 * 1_000_000),
            1709078400_i64 * 1_000_000
        );
    }

    #[test]
    fn impossible_date_returns_not_found() {
        let spec = CalendarSpec::parse("*-02-31 00:00:00").unwrap();
        assert_eq!(spec.next_usec(0), Err(CalendarError::NotFound));
    }

    #[test]
    fn system_time_api_matches_usec_api() {
        let spec = CalendarSpec::parse("daily").unwrap();
        let after = UNIX_EPOCH + Duration::from_secs(1704110400);
        let next = spec.next_after(after).unwrap();
        assert_eq!(
            next.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1704153600
        );
        assert_eq!(spec.next(&after), Some(next));
    }

    #[test]
    fn chain_validity_matches_c_rules() {
        let mut chain = None;
        const_chain(61 * USEC_PER_SEC, &mut chain);
        assert!(!chain_valid(&chain, 0, USEC_PER_MINUTE - 1, false));

        let chain = Some(Box::new(CalendarComponent {
            start: 1,
            stop: 3,
            repeat: 5,
            next: None,
        }));
        assert!(!chain_valid(&chain, 1, 31, false));
    }
}
