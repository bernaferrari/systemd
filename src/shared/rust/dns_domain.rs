// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/dns-domain.c

use std::cmp::Ordering;
use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;

use crate::ffi::Errno;

pub const DNS_LABEL_MAX: usize = 63;
pub const DNS_HOSTNAME_MAX: usize = 253;
pub const DNS_LABEL_ESCAPED_MAX: usize = DNS_LABEL_MAX * 4 + 1;
pub const DNS_N_LABELS_MAX: usize = 127;

pub type DnsResult<T> = Result<T, Errno>;

bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct DNSLabelFlags: u32 {
                const LDH = 1 << 0;
                const NO_ESCAPES = 1 << 1;
                const LEAVE_TRAILING_DOT = 1 << 2;
        }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServiceSplit {
    pub name: Option<String>,
    pub type_: Option<String>,
    pub domain: String,
}

fn errno<T>(e: Errno) -> DnsResult<T> {
    Err(e)
}

fn valid_ldh_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

fn ascii_lower(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

fn cmp_ascii_case_insensitive(a: &[u8], b: &[u8]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        match ascii_lower(*x).cmp(&ascii_lower(*y)) {
            Ordering::Equal => {}
            o => return o,
        }
    }

    a.len().cmp(&b.len())
}

fn eq_ascii_case_insensitive(a: &[u8], b: &[u8]) -> bool {
    cmp_ascii_case_insensitive(a, b) == Ordering::Equal
}

fn string_has_cc(s: &str) -> bool {
    s.as_bytes().iter().any(|b| *b < 0x20 || *b == 0x7f)
}

fn is_root_raw(name: &str) -> bool {
    name.is_empty() || name == "."
}

pub fn dns_label_unescape(name: &str, flags: DNSLabelFlags) -> DnsResult<(Vec<u8>, &str)> {
    if name.is_empty() {
        return Ok((Vec::new(), name));
    }

    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(DNS_LABEL_MAX);
    let mut i = 0usize;
    let mut last_char = None::<u8>;

    loop {
        let Some(&c) = bytes.get(i) else {
            break;
        };

        if c == b'.' {
            if flags.contains(DNSLabelFlags::LDH) && last_char == Some(b'-') {
                return errno(Errno::EINVAL);
            }

            let next = if i + 1 < bytes.len() || !flags.contains(DNSLabelFlags::LEAVE_TRAILING_DOT)
            {
                i + 1
            } else {
                i
            };

            if out.is_empty() && next < bytes.len() {
                return errno(Errno::EINVAL);
            }

            if next < bytes.len()
                && bytes[next] == b'.'
                && !flags.contains(DNSLabelFlags::LEAVE_TRAILING_DOT)
            {
                return errno(Errno::EINVAL);
            }

            return Ok((out, &name[next..]));
        }

        if out.len() >= DNS_LABEL_MAX {
            return errno(Errno::EINVAL);
        }

        if c == b'\\' {
            if flags.contains(DNSLabelFlags::NO_ESCAPES) {
                return errno(Errno::EINVAL);
            }

            let Some(&next) = bytes.get(i + 1) else {
                return errno(Errno::EINVAL);
            };

            if next == b'\\' || next == b'.' {
                if flags.contains(DNSLabelFlags::LDH) {
                    return errno(Errno::EINVAL);
                }

                out.push(next);
                last_char = Some(next);
                i += 2;
                continue;
            }

            if next.is_ascii_digit() {
                let Some((&d2, &d3)) = bytes.get(i + 2).zip(bytes.get(i + 3)) else {
                    return errno(Errno::EINVAL);
                };

                if !d2.is_ascii_digit() || !d3.is_ascii_digit() {
                    return errno(Errno::EINVAL);
                }

                let value = (usize::from(next - b'0') * 100)
                    + (usize::from(d2 - b'0') * 10)
                    + usize::from(d3 - b'0');
                if value > 255 {
                    return errno(Errno::EINVAL);
                }

                let k = value as u8;
                if flags.contains(DNSLabelFlags::LDH) && !valid_ldh_char(k) {
                    return errno(Errno::EINVAL);
                }

                out.push(k);
                last_char = Some(k);
                i += 4;
                continue;
            }

            return errno(Errno::EINVAL);
        }

        if c < b' ' || c == 127 {
            return errno(Errno::EINVAL);
        }

        if flags.contains(DNSLabelFlags::LDH) {
            if !valid_ldh_char(c) {
                return errno(Errno::EINVAL);
            }
            if out.is_empty() && c == b'-' {
                return errno(Errno::EINVAL);
            }
        }

        out.push(c);
        last_char = Some(c);
        i += 1;
    }

    if flags.contains(DNSLabelFlags::LDH) && last_char == Some(b'-') {
        return errno(Errno::EINVAL);
    }

    Ok((out, ""))
}

pub fn dns_label_unescape_suffix(
    name: &str,
    label_terminal: Option<usize>,
) -> DnsResult<(Vec<u8>, Option<usize>)> {
    let Some(mut terminal) = label_terminal else {
        return Ok((Vec::new(), None));
    };

    let bytes = name.as_bytes();
    if terminal > bytes.len() {
        return errno(Errno::EINVAL);
    }

    if terminal == bytes.len() {
        if terminal == 0 {
            return Ok((Vec::new(), None));
        }
        terminal -= 1;
    }

    if bytes.get(terminal) == Some(&b'.') {
        if terminal == 0 {
            return Ok((Vec::new(), None));
        }
        terminal -= 1;
    }

    let mut scan = Some(terminal);
    let mut label_start = 0usize;
    let mut new_terminal = None;

    while let Some(i) = scan {
        if bytes[i] == b'.' {
            let mut slashes = 0usize;
            let mut j = i;
            while j > 0 && bytes[j - 1] == b'\\' {
                slashes += 1;
                j -= 1;
            }

            if slashes % 2 == 0 {
                label_start = i + 1;
                new_terminal = i.checked_sub(1);
                break;
            }

            scan = j.checked_sub(1);
            continue;
        }

        scan = i.checked_sub(1);
    }

    let (label, _) = dns_label_unescape(&name[label_start..], DNSLabelFlags::empty())?;
    Ok((label, new_terminal))
}

pub fn dns_label_escape(label: &[u8]) -> DnsResult<String> {
    if label.is_empty() || label.len() > DNS_LABEL_MAX {
        return errno(Errno::EINVAL);
    }

    let mut out = String::with_capacity(DNS_LABEL_ESCAPED_MAX - 1);
    for &b in label {
        match b {
            b'.' | b'\\' => {
                out.push('\\');
                out.push(char::from(b));
            }
            b'_' | b'-' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => out.push(char::from(b)),
            _ => {
                out.push('\\');
                out.push(char::from(b'0' + (b / 100)));
                out.push(char::from(b'0' + ((b / 10) % 10)));
                out.push(char::from(b'0' + (b % 10)));
            }
        }
    }

    Ok(out)
}

pub fn dns_label_escape_new(label: &[u8]) -> DnsResult<String> {
    dns_label_escape(label)
}

pub fn dns_name_parent(name: &str) -> DnsResult<Option<&str>> {
    let (label, rest) = dns_label_unescape(name, DNSLabelFlags::empty())?;
    if label.is_empty() {
        Ok(None)
    } else {
        Ok(Some(rest))
    }
}

fn build_suffix_table(name: &str) -> DnsResult<Vec<&str>> {
    let mut table = Vec::new();
    let mut p = name;

    loop {
        if table.len() > DNS_N_LABELS_MAX {
            return errno(Errno::EINVAL);
        }

        table.push(p);
        let Some(next) = dns_name_parent(p)? else {
            break;
        };
        p = next;
    }

    Ok(table)
}

fn split_name_with_offsets(name: &str, flags: DNSLabelFlags) -> DnsResult<Vec<(Vec<u8>, usize)>> {
    let mut out = Vec::new();
    let mut p = name;
    let mut offset = 0usize;

    loop {
        let (label, rest) = dns_label_unescape(p, flags)?;
        if label.is_empty() {
            if !rest.is_empty() {
                return errno(Errno::EINVAL);
            }
            break;
        }

        out.push((label, offset));
        offset = name.len() - rest.len();
        p = rest;
    }

    Ok(out)
}

fn split_name(name: &str, flags: DNSLabelFlags) -> DnsResult<Vec<Vec<u8>>> {
    split_name_with_offsets(name, flags).map(|v| v.into_iter().map(|(l, _)| l).collect())
}

pub fn dns_name_concat(
    a: Option<&str>,
    b: Option<&str>,
    flags: DNSLabelFlags,
) -> DnsResult<String> {
    let mut escaped_labels = Vec::new();
    let mut unescaped_len = 0usize;

    for input in [a, b].into_iter().flatten() {
        for label in split_name(input, flags)? {
            unescaped_len += label.len();
            if !escaped_labels.is_empty() {
                unescaped_len += 1;
            }
            escaped_labels.push(dns_label_escape(&label)?);
        }
    }

    if escaped_labels.is_empty() {
        unescaped_len = 1;
        return if unescaped_len > DNS_HOSTNAME_MAX {
            errno(Errno::EINVAL)
        } else {
            Ok(".".into())
        };
    }

    if unescaped_len > DNS_HOSTNAME_MAX {
        return errno(Errno::EINVAL);
    }

    Ok(escaped_labels.join("."))
}

pub fn dns_name_normalize(name: &str, flags: DNSLabelFlags) -> DnsResult<String> {
    dns_name_concat(Some(name), None, flags)
}

pub fn dns_name_is_valid(name: &str) -> bool {
    dns_name_normalize(name, DNSLabelFlags::empty()).is_ok()
}

pub fn dns_name_is_valid_ldh(name: &str) -> bool {
    dns_name_normalize(name, DNSLabelFlags::LDH | DNSLabelFlags::NO_ESCAPES).is_ok()
}

pub fn dns_name_hash_func<H: Hasher>(name: &str, state: &mut H) {
    match split_name(name, DNSLabelFlags::empty()) {
        Ok(labels) => {
            for label in labels {
                for b in label {
                    state.write_u8(ascii_lower(b));
                }
                state.write_u8(0);
            }
            state.write_u8(0);
        }
        Err(_) => state.write(name.as_bytes()),
    }
}

pub fn dns_name_compare_func(a: &str, b: &str) -> Ordering {
    let Ok(la) = split_name(a, DNSLabelFlags::empty()) else {
        return a.cmp(b);
    };
    let Ok(lb) = split_name(b, DNSLabelFlags::empty()) else {
        return a.cmp(b);
    };

    for (x, y) in la.iter().rev().zip(lb.iter().rev()) {
        match cmp_ascii_case_insensitive(x, y) {
            Ordering::Equal => {}
            o => return o,
        }
    }

    la.len().cmp(&lb.len())
}

pub fn dns_name_equal(a: &str, b: &str) -> DnsResult<bool> {
    let la = split_name(a, DNSLabelFlags::empty())?;
    let lb = split_name(b, DNSLabelFlags::empty())?;

    if la.len() != lb.len() {
        return Ok(false);
    }

    Ok(la
        .iter()
        .zip(&lb)
        .all(|(x, y)| eq_ascii_case_insensitive(x, y)))
}

pub fn dns_name_endswith(name: &str, suffix: &str) -> DnsResult<bool> {
    let labels = split_name(name, DNSLabelFlags::empty())?;
    let suffix_labels = split_name(suffix, DNSLabelFlags::empty())?;

    if suffix_labels.len() > labels.len() {
        return Ok(false);
    }

    Ok(labels[labels.len() - suffix_labels.len()..]
        .iter()
        .zip(&suffix_labels)
        .all(|(x, y)| eq_ascii_case_insensitive(x, y)))
}

pub fn dns_name_startswith(name: &str, prefix: &str) -> DnsResult<bool> {
    let labels = split_name(name, DNSLabelFlags::empty())?;
    let prefix_labels = split_name(prefix, DNSLabelFlags::empty())?;

    if prefix_labels.len() > labels.len() {
        return Ok(false);
    }

    Ok(labels[..prefix_labels.len()]
        .iter()
        .zip(&prefix_labels)
        .all(|(x, y)| eq_ascii_case_insensitive(x, y)))
}

pub fn dns_name_change_suffix(
    name: &str,
    old_suffix: Option<&str>,
    new_suffix: Option<&str>,
) -> DnsResult<Option<String>> {
    let old_suffix = old_suffix.unwrap_or("");
    let chain = build_suffix_table(name)?;

    for (i, candidate) in chain.iter().enumerate() {
        if dns_name_equal(candidate, old_suffix)? {
            let prefix_end = name.len() - candidate.len();
            let prefix = &name[..prefix_end];
            let prefix = prefix.strip_suffix('.').unwrap_or(prefix);
            return dns_name_concat(
                (!prefix.is_empty()).then_some(prefix),
                new_suffix,
                DNSLabelFlags::empty(),
            )
            .map(Some);
        }
        if i + 1 == chain.len() {
            break;
        }
    }

    Ok(None)
}

pub fn dns_name_between(a: &str, b: &str, c: &str) -> bool {
    if dns_name_compare_func(a, c) == Ordering::Less {
        dns_name_compare_func(a, b) == Ordering::Less
            && dns_name_compare_func(b, c) == Ordering::Less
    } else {
        dns_name_compare_func(b, c) == Ordering::Less
            || dns_name_compare_func(a, b) == Ordering::Less
    }
}

pub fn dns_name_reverse(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut parts = Vec::with_capacity(32);
            for byte in v6.octets().iter().rev() {
                parts.push(format!("{:x}", byte & 0x0f));
                parts.push(format!("{:x}", byte >> 4));
            }
            format!("{}.ip6.arpa", parts.join("."))
        }
    }
}

pub fn dns_name_address(name: &str) -> DnsResult<Option<IpAddr>> {
    if dns_name_endswith(name, "in-addr.arpa")? {
        let labels = split_name(name, DNSLabelFlags::empty())?;
        if labels.len() != 6
            || !eq_ascii_case_insensitive(&labels[4], b"in-addr")
            || !eq_ascii_case_insensitive(&labels[5], b"arpa")
        {
            return errno(Errno::EINVAL);
        }

        let mut octets = [0u8; 4];
        for (idx, label) in labels[..4].iter().enumerate() {
            if label.is_empty() || label.len() > 3 {
                return errno(Errno::EINVAL);
            }

            let s = std::str::from_utf8(label).map_err(|_| Errno::EINVAL)?;
            octets[3 - idx] = s.parse::<u8>().map_err(|_| Errno::EINVAL)?;
        }

        return Ok(Some(IpAddr::V4(Ipv4Addr::from(octets))));
    }

    if dns_name_endswith(name, "ip6.arpa")? {
        let labels = split_name(name, DNSLabelFlags::empty())?;
        if labels.len() != 34
            || !eq_ascii_case_insensitive(&labels[32], b"ip6")
            || !eq_ascii_case_insensitive(&labels[33], b"arpa")
        {
            return errno(Errno::EINVAL);
        }

        let mut octets = [0u8; 16];
        for i in 0..16 {
            let lo = *labels[i * 2].first().ok_or(Errno::EINVAL)?;
            let hi = *labels[i * 2 + 1].first().ok_or(Errno::EINVAL)?;
            if labels[i * 2].len() != 1 || labels[i * 2 + 1].len() != 1 {
                return errno(Errno::EINVAL);
            }

            let x = char::from(lo).to_digit(16).ok_or(Errno::EINVAL)? as u8;
            let y = char::from(hi).to_digit(16).ok_or(Errno::EINVAL)? as u8;
            octets[15 - i] = (y << 4) | x;
        }

        return Ok(Some(IpAddr::V6(Ipv6Addr::from(octets))));
    }

    Ok(None)
}

pub fn dns_name_is_root(name: &str) -> bool {
    is_root_raw(name)
}

pub fn dns_name_is_single_label(name: &str) -> bool {
    matches!(dns_name_parent(name), Ok(Some(rest)) if dns_name_is_root(rest))
}

pub fn dns_name_to_wire_format(domain: &str, canonical: bool) -> DnsResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut p = domain;

    loop {
        let (mut label, rest) = dns_label_unescape(p, DNSLabelFlags::empty())?;
        if canonical {
            for byte in &mut label {
                *byte = ascii_lower(*byte);
            }
        }

        if label.len() > DNS_LABEL_MAX {
            return errno(Errno::EINVAL);
        }

        out.push(label.len() as u8);
        out.extend_from_slice(&label);

        if label.is_empty() {
            break;
        }

        p = rest;
    }

    if out.len() > DNS_HOSTNAME_MAX + 2 {
        return errno(Errno::EINVAL);
    }

    Ok(out)
}

pub fn dns_name_from_wire_format(data: &[u8]) -> DnsResult<(String, usize)> {
    let mut i = 0usize;
    let mut labels = Vec::new();

    loop {
        if i >= data.len() {
            break;
        }

        if i > 255 {
            return errno(Errno::EMSGSIZE);
        }

        let c = data[i] as usize;
        i += 1;

        if c == 0 {
            break;
        }
        if c > DNS_LABEL_MAX {
            return errno(Errno::EBADMSG);
        }
        if i + c > data.len() {
            return errno(Errno::EMSGSIZE);
        }

        labels.push(dns_label_escape(&data[i..i + c])?);
        i += c;
    }

    Ok((labels.join("."), i))
}

pub fn srv_type_label_is_valid(label: &[u8]) -> bool {
    if label.len() < 2 {
        return false;
    }
    if label[0] != b'_' || !label[1].is_ascii_alphabetic() {
        return false;
    }

    label[2..]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

pub fn dns_srv_type_is_valid(name: &str) -> bool {
    let Ok(labels) = split_name(name, DNSLabelFlags::empty()) else {
        return false;
    };

    labels.len() == 2 && labels.iter().all(|l| srv_type_label_is_valid(l))
}

pub fn dnssd_srv_type_is_valid(name: &str) -> bool {
    dns_srv_type_is_valid(name)
        && (dns_name_endswith(name, "_tcp").unwrap_or(false)
            || dns_name_endswith(name, "_udp").unwrap_or(false))
}

pub fn dns_service_name_is_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= DNS_LABEL_MAX && !string_has_cc(name)
}

pub fn dns_subtype_name_is_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= DNS_LABEL_MAX && !string_has_cc(name)
}

pub fn dns_service_join(name: Option<&str>, type_: &str, domain: &str) -> DnsResult<String> {
    if !dns_srv_type_is_valid(type_) {
        return errno(Errno::EINVAL);
    }

    if let Some(name) = name {
        if !dns_service_name_is_valid(name) {
            return errno(Errno::EINVAL);
        }

        let tail = dns_name_concat(Some(type_), Some(domain), DNSLabelFlags::empty())?;
        dns_name_concat(Some(name), Some(&tail), DNSLabelFlags::empty())
    } else {
        dns_name_concat(Some(type_), Some(domain), DNSLabelFlags::empty())
    }
}

pub fn dns_service_name_label_is_valid(label: &[u8]) -> bool {
    std::str::from_utf8(label)
        .map(dns_service_name_is_valid)
        .unwrap_or(false)
}

pub fn dns_service_split(joined: &str) -> DnsResult<DnsServiceSplit> {
    let labels = split_name_with_offsets(joined, DNSLabelFlags::empty())?;
    let mut name = None;
    let mut type_ = None;
    let mut domain_start = 0usize;

    if labels.len() >= 2
        && srv_type_label_is_valid(&labels[0].0)
        && srv_type_label_is_valid(&labels[1].0)
    {
        type_ = Some(format!(
            "{}.{}",
            std::str::from_utf8(&labels[0].0).map_err(|_| Errno::EINVAL)?,
            std::str::from_utf8(&labels[1].0).map_err(|_| Errno::EINVAL)?
        ));
        domain_start = if labels.len() > 2 {
            labels[2].1
        } else {
            joined.len()
        };
    } else if labels.len() >= 3
        && dns_service_name_label_is_valid(&labels[0].0)
        && srv_type_label_is_valid(&labels[1].0)
        && srv_type_label_is_valid(&labels[2].0)
    {
        name = Some(
            std::str::from_utf8(&labels[0].0)
                .map_err(|_| Errno::EINVAL)?
                .to_string(),
        );
        type_ = Some(format!(
            "{}.{}",
            std::str::from_utf8(&labels[1].0).map_err(|_| Errno::EINVAL)?,
            std::str::from_utf8(&labels[2].0).map_err(|_| Errno::EINVAL)?
        ));
        domain_start = if labels.len() > 3 {
            labels[3].1
        } else {
            joined.len()
        };
    }

    let domain = dns_name_normalize(&joined[domain_start..], DNSLabelFlags::empty())?;
    Ok(DnsServiceSplit {
        name,
        type_,
        domain,
    })
}

pub fn dns_name_suffix(name: &str, n_labels: usize) -> DnsResult<&str> {
    let labels = build_suffix_table(name)?;
    let n = labels.len() - 1;
    if n < n_labels {
        return errno(Errno::EINVAL);
    }

    Ok(labels[n - n_labels])
}

pub fn dns_name_skip(mut name: &str, mut n_labels: usize) -> DnsResult<&str> {
    while n_labels > 0 {
        let Some(next) = dns_name_parent(name)? else {
            return Ok("");
        };
        name = next;
        n_labels -= 1;
    }

    Ok(name)
}

pub fn dns_name_count_labels(name: &str) -> DnsResult<usize> {
    Ok(build_suffix_table(name)?.len() - 1)
}

pub fn dns_name_equal_skip(a: &str, n_labels: usize, b: &str) -> DnsResult<bool> {
    let skipped = dns_name_skip(a, n_labels)?;
    if skipped.is_empty() {
        return Ok(false);
    }
    dns_name_equal(skipped, b)
}

pub fn dns_name_common_suffix<'a>(a: &'a str, b: &str) -> DnsResult<&'a str> {
    let a_labels = build_suffix_table(a)?;
    let b_labels = build_suffix_table(b)?;
    let mut k = 0usize;
    let n = a_labels.len() - 1;
    let m = b_labels.len() - 1;

    while k < n && k < m {
        let ax = split_name(a_labels[n - 1 - k], DNSLabelFlags::empty())?;
        let bx = split_name(b_labels[m - 1 - k], DNSLabelFlags::empty())?;
        if !eq_ascii_case_insensitive(&ax[0], &bx[0]) {
            break;
        }
        k += 1;
    }

    Ok(a_labels[n - k])
}

const PUNYCODE_BASE: u32 = 36;
const PUNYCODE_TMIN: u32 = 1;
const PUNYCODE_TMAX: u32 = 26;
const PUNYCODE_SKEW: u32 = 38;
const PUNYCODE_DAMP: u32 = 700;
const PUNYCODE_INITIAL_BIAS: u32 = 72;
const PUNYCODE_INITIAL_N: u32 = 128;

fn punycode_digit(d: u32) -> char {
    match d {
        0..=25 => char::from_u32(d + u32::from(b'a')).unwrap_or('a'),
        26..=35 => char::from_u32(d - 26 + u32::from(b'0')).unwrap_or('0'),
        _ => '?',
    }
}

fn punycode_value(c: char) -> Option<u32> {
    match c {
        'a'..='z' => Some(c as u32 - 'a' as u32),
        'A'..='Z' => Some(c as u32 - 'A' as u32),
        '0'..='9' => Some(c as u32 - '0' as u32 + 26),
        _ => None,
    }
}

fn adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
    let mut delta = if first_time {
        delta / PUNYCODE_DAMP
    } else {
        delta / 2
    };
    delta += delta / num_points;

    let mut k = 0u32;
    while delta > ((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) / 2 {
        delta /= PUNYCODE_BASE - PUNYCODE_TMIN;
        k += PUNYCODE_BASE;
    }

    k + (((PUNYCODE_BASE - PUNYCODE_TMIN + 1) * delta) / (delta + PUNYCODE_SKEW))
}

fn punycode_encode(label: &str) -> DnsResult<String> {
    let input: Vec<u32> = label.chars().map(u32::from).collect();
    let mut out = String::new();
    let mut n = PUNYCODE_INITIAL_N;
    let mut delta = 0u32;
    let mut bias = PUNYCODE_INITIAL_BIAS;

    for &cp in &input {
        if cp < 0x80 {
            out.push(char::from_u32(cp).ok_or(Errno::EINVAL)?);
        }
    }

    let basic = out.len() as u32;
    let mut handled = basic;
    if basic > 0 {
        out.push('-');
    }

    while handled < input.len() as u32 {
        let m = *input
            .iter()
            .filter(|cp| **cp >= n)
            .min()
            .ok_or(Errno::EINVAL)?;
        delta = delta
            .checked_add((m - n).checked_mul(handled + 1).ok_or(Errno::EINVAL)?)
            .ok_or(Errno::EINVAL)?;
        n = m;

        for &cp in &input {
            if cp < n {
                delta = delta.checked_add(1).ok_or(Errno::EINVAL)?;
            }
            if cp == n {
                let mut q = delta;
                let mut k = PUNYCODE_BASE;
                loop {
                    let t = if k <= bias {
                        PUNYCODE_TMIN
                    } else if k >= bias + PUNYCODE_TMAX {
                        PUNYCODE_TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }

                    let code = t + ((q - t) % (PUNYCODE_BASE - t));
                    out.push(punycode_digit(code));
                    q = (q - t) / (PUNYCODE_BASE - t);
                    k += PUNYCODE_BASE;
                }

                out.push(punycode_digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }

        delta = delta.checked_add(1).ok_or(Errno::EINVAL)?;
        n = n.checked_add(1).ok_or(Errno::EINVAL)?;
    }

    Ok(out)
}

fn punycode_decode(input: &str) -> DnsResult<String> {
    let mut n = PUNYCODE_INITIAL_N;
    let mut i = 0u32;
    let mut bias = PUNYCODE_INITIAL_BIAS;
    let mut out: Vec<u32> = Vec::new();

    let (basic, encoded) = match input.rfind('-') {
        Some(pos) => (&input[..pos], &input[pos + 1..]),
        None => ("", input),
    };

    for ch in basic.chars() {
        if !ch.is_ascii() {
            return errno(Errno::EINVAL);
        }
        out.push(ch as u32);
    }

    let chars: Vec<char> = encoded.chars().collect();
    let mut idx = 0usize;
    while idx < chars.len() {
        let oldi = i;
        let mut w = 1u32;
        let mut k = PUNYCODE_BASE;

        loop {
            let digit =
                punycode_value(*chars.get(idx).ok_or(Errno::EINVAL)?).ok_or(Errno::EINVAL)?;
            idx += 1;
            i = i
                .checked_add(digit.checked_mul(w).ok_or(Errno::EINVAL)?)
                .ok_or(Errno::EINVAL)?;

            let t = if k <= bias {
                PUNYCODE_TMIN
            } else if k >= bias + PUNYCODE_TMAX {
                PUNYCODE_TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }

            w = w.checked_mul(PUNYCODE_BASE - t).ok_or(Errno::EINVAL)?;
            k += PUNYCODE_BASE;
        }

        let out_len = out.len() as u32 + 1;
        bias = adapt(i - oldi, out_len, oldi == 0);
        n = n.checked_add(i / out_len).ok_or(Errno::EINVAL)?;
        let pos = (i % out_len) as usize;
        out.insert(pos, n);
        i = pos as u32 + 1;
    }

    out.into_iter()
        .map(|cp| char::from_u32(cp).ok_or(Errno::EINVAL))
        .collect()
}

fn idna_encode_label(label: &str) -> DnsResult<String> {
    if label.is_ascii() {
        let lower = label.to_ascii_lowercase();
        if lower.starts_with("xn--") {
            punycode_decode(&lower[4..])?;
        }
        return Ok(lower);
    }

    Ok(format!("xn--{}", punycode_encode(label)?).to_ascii_lowercase())
}

pub fn dns_name_apply_idna(name: &str) -> DnsResult<Option<String>> {
    if name == "." {
        return Ok(Some(".".into()));
    }

    let raw_labels = split_name(name, DNSLabelFlags::empty())?;
    if raw_labels.is_empty() {
        return Ok(Some(".".into()));
    }

    let mut out = Vec::new();
    for label_bytes in &raw_labels {
        let label_str = match std::str::from_utf8(label_bytes) {
            Ok(s) => s,
            Err(_) => return errno(Errno::EINVAL),
        };
        if label_str.is_empty() {
            continue;
        }
        let encoded = idna_encode_label(label_str)?;
        if encoded.len() > DNS_LABEL_MAX {
            return errno(Errno::ENOSPC);
        }

        if !label_str.starts_with("xn--") {
            let decoded = if let Some(stripped) = encoded.strip_prefix("xn--") {
                punycode_decode(stripped)?
            } else {
                encoded.clone()
            };
            if decoded != label_str {
                return Ok(None);
            }
        }

        out.push(encoded);
    }

    let result = if out.is_empty() {
        ".".to_string()
    } else {
        out.join(".")
    };
    if result.len() > DNS_HOSTNAME_MAX {
        return errno(Errno::ENOSPC);
    }

    Ok(Some(result))
}

pub fn dns_name_is_valid_or_address(name: &str) -> bool {
    !name.is_empty() && (name.parse::<IpAddr>().is_ok() || dns_name_is_valid(name))
}

pub fn dns_name_dot_suffixed(name: &str) -> DnsResult<bool> {
    let mut p = name;
    loop {
        if p == "." {
            return Ok(true);
        }

        let (label, rest) = dns_label_unescape(p, DNSLabelFlags::LEAVE_TRAILING_DOT)?;
        if label.is_empty() {
            return Ok(false);
        }
        p = rest;
    }
}

pub fn dns_name_dont_resolve(name: &str) -> bool {
    dns_name_endswith(name, "0.in-addr.arpa").unwrap_or(false)
        || dns_name_equal(name, "255.255.255.255.in-addr.arpa").unwrap_or(false)
        || dns_name_equal(
            name,
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        )
        .unwrap_or(false)
        || dns_name_endswith(name, "invalid").unwrap_or(false)
        || dns_name_endswith(name, "alt").unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hash;

    #[test]
    fn label_unescape_and_escape_roundtrip() {
        let (label, rest) =
            dns_label_unescape(r"foo\.bar.example", DNSLabelFlags::empty()).unwrap();
        assert_eq!(label, b"foo.bar");
        assert_eq!(rest, "example");
        assert_eq!(dns_label_escape(&label).unwrap(), r"foo\.bar");
    }

    #[test]
    fn label_unescape_rejects_invalid_ldh() {
        assert!(dns_label_unescape("-bad", DNSLabelFlags::LDH).is_err());
        assert!(dns_label_unescape("bad-", DNSLabelFlags::LDH).is_err());
        assert!(dns_label_unescape(r"foo\.bar", DNSLabelFlags::LDH).is_err());
    }

    #[test]
    fn normalize_and_validate_names() {
        assert_eq!(
            dns_name_normalize("example.com.", DNSLabelFlags::empty()).unwrap(),
            "example.com"
        );
        assert_eq!(
            dns_name_normalize(".", DNSLabelFlags::empty()).unwrap(),
            "."
        );
        assert!(dns_name_is_valid("example.com"));
        assert!(dns_name_is_valid(""));
        assert!(!dns_name_is_valid("example..com"));
        assert!(dns_name_is_valid_ldh("foo-bar.example"));
        assert!(!dns_name_is_valid_ldh("foo_bar.example"));
    }

    #[test]
    fn compare_hash_and_between_are_case_insensitive() {
        assert!(dns_name_equal("WWW.Example.COM", "www.example.com").unwrap());
        assert_eq!(
            dns_name_compare_func("a.example", "b.example"),
            Ordering::Less
        );
        assert!(dns_name_between("a.example", "b.example", "c.example"));

        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        dns_name_hash_func("WWW.Example.COM", &mut ha);
        dns_name_hash_func("www.example.com", &mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn suffix_prefix_and_common_suffix_work() {
        assert!(dns_name_endswith("a.b.example.com", "example.com").unwrap());
        assert!(dns_name_startswith("a.b.example.com", "a.b").unwrap());
        assert_eq!(
            dns_name_suffix("a.b.example.com", 2).unwrap(),
            "example.com"
        );
        assert_eq!(dns_name_skip("a.b.example.com", 2).unwrap(), "example.com");
        assert_eq!(dns_name_count_labels("a.b.example.com").unwrap(), 4);
        assert!(dns_name_equal_skip("a.b.example.com", 2, "example.com").unwrap());
        assert_eq!(
            dns_name_common_suffix("a.b.example.com", "x.y.example.com").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn change_suffix_and_root_helpers_work() {
        assert_eq!(
            dns_name_change_suffix("www.example.com", Some("example.com"), Some("example.org"))
                .unwrap(),
            Some("www.example.org".into())
        );
        assert_eq!(
            dns_name_change_suffix("www.example.com", Some("example.org"), Some("example.net"))
                .unwrap(),
            None
        );
        assert!(dns_name_is_root(""));
        assert!(dns_name_is_root("."));
        assert!(dns_name_is_single_label("com"));
        assert!(dns_name_is_single_label("com."));
        assert!(!dns_name_is_single_label("example.com"));
        assert!(dns_name_dot_suffixed("example.com.").unwrap());
        assert!(!dns_name_dot_suffixed("example.com").unwrap());
    }

    #[test]
    fn reverse_and_parse_addresses_work() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ptr = dns_name_reverse(v4);
        assert_eq!(ptr, "1.2.0.192.in-addr.arpa");
        assert_eq!(dns_name_address(&ptr).unwrap(), Some(v4));

        let v6 = IpAddr::V6("2001:db8::1".parse().unwrap());
        let ptr6 = dns_name_reverse(v6);
        assert!(ptr6.ends_with(".ip6.arpa"));
        assert_eq!(dns_name_address(&ptr6).unwrap(), Some(v6));
    }

    #[test]
    fn wire_format_roundtrip_and_partial_name() {
        let encoded = dns_name_to_wire_format("WWW.Example.COM", true).unwrap();
        assert_eq!(
            encoded,
            vec![
                3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );

        let (decoded, used) = dns_name_from_wire_format(&encoded).unwrap();
        assert_eq!(decoded, "www.example.com");
        assert_eq!(used, encoded.len());

        let partial = [3, b'f', b'o', b'o'];
        let (decoded, used) = dns_name_from_wire_format(&partial).unwrap();
        assert_eq!(decoded, "foo");
        assert_eq!(used, partial.len());
    }

    #[test]
    fn service_validators_and_join_split_work() {
        assert!(dns_srv_type_is_valid("_http._tcp"));
        assert!(dnssd_srv_type_is_valid("_http._tcp"));
        assert!(!dnssd_srv_type_is_valid("_http._sctp"));
        assert!(dns_service_name_is_valid("My Printer"));
        assert!(dns_subtype_name_is_valid("caf\u{e9}"));
        assert!(!dns_service_name_is_valid("bad\u{7f}"));

        let joined = dns_service_join(Some("My Printer"), "_ipp._tcp", "local").unwrap();
        assert_eq!(joined, "My\\032Printer._ipp._tcp.local");

        let split = dns_service_split(&joined).unwrap();
        assert_eq!(split.name, Some("My Printer".into()));
        assert_eq!(split.type_, Some("_ipp._tcp".into()));
        assert_eq!(split.domain, "local");
    }

    #[test]
    fn idna_handles_ascii_and_unicode_labels() {
        assert_eq!(
            dns_name_apply_idna("example.com").unwrap(),
            Some("example.com".into())
        );
        assert_eq!(
            dns_name_apply_idna("bücher.de").unwrap(),
            Some("xn--bcher-kva.de".into())
        );
        assert_eq!(
            dns_name_apply_idna("例え.テスト").unwrap(),
            Some("xn--r8jz45g.xn--zckzah".into())
        );
    }

    #[test]
    fn dont_resolve_and_valid_or_address_work() {
        assert!(dns_name_is_valid_or_address("127.0.0.1"));
        assert!(dns_name_is_valid_or_address("example.com"));
        assert!(!dns_name_is_valid_or_address(""));
        assert!(dns_name_dont_resolve("255.255.255.255.in-addr.arpa"));
        assert!(dns_name_dont_resolve("foo.invalid"));
        assert!(dns_name_dont_resolve("foo.alt"));
    }
}
