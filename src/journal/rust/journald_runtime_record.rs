// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;
use crate::fuzz_journald_native::{NativeError, NativeMessage, parse_native_datagram};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RateLimitConfig {
    pub(super) interval_usec: u64,
    pub(super) burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            interval_usec: DEFAULT_RATE_LIMIT_INTERVAL_USEC,
            burst: DEFAULT_RATE_LIMIT_BURST,
        }
    }
}

impl RateLimitConfig {
    pub(super) fn from_env() -> Self {
        let mut cfg = Self::default();

        if let Ok(raw) = std::env::var(RATE_LIMIT_INTERVAL_ENV) {
            if let Ok(parsed) = raw.parse::<u64>() {
                cfg.interval_usec = parsed;
            }
        }
        if let Ok(raw) = std::env::var(RATE_LIMIT_BURST_ENV) {
            if let Ok(parsed) = raw.parse::<u32>() {
                cfg.burst = parsed;
            }
        }

        if (cfg.interval_usec == 0) != (cfg.burst == 0) {
            cfg.interval_usec = 0;
            cfg.burst = 0;
        }

        cfg
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RateLimitDecision {
    Allow { emit_suppressed: u64 },
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KmsgSequenceDecision {
    Allow { emit_missed: u64 },
    Drop,
}

#[derive(Debug, Default)]
pub(super) struct KmsgSequenceTracker {
    pub(super) next_expected: Option<u64>,
}

impl KmsgSequenceTracker {
    pub(super) fn with_next_expected(next_expected: Option<u64>) -> Self {
        Self { next_expected }
    }

    pub(super) fn next_expected(&self) -> Option<u64> {
        self.next_expected
    }

    pub(super) fn check(&mut self, parsed: &IngressRecord) -> KmsgSequenceDecision {
        if parsed.transport != IngressTransport::Kernel {
            return KmsgSequenceDecision::Allow { emit_missed: 0 };
        }

        let Some(sequence) = parsed.kmsg_sequence else {
            return KmsgSequenceDecision::Allow { emit_missed: 0 };
        };
        match self.next_expected {
            None => {
                self.next_expected = Some(sequence.saturating_add(1));
                KmsgSequenceDecision::Allow { emit_missed: 0 }
            }
            Some(expected) if sequence < expected => KmsgSequenceDecision::Drop,
            Some(expected) if sequence > expected => {
                self.next_expected = Some(sequence.saturating_add(1));
                KmsgSequenceDecision::Allow {
                    emit_missed: sequence.saturating_sub(expected),
                }
            }
            Some(_) => {
                self.next_expected = Some(sequence.saturating_add(1));
                KmsgSequenceDecision::Allow { emit_missed: 0 }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct RateLimitPool {
    pub(super) begin_usec: u64,
    pub(super) accepted: u32,
    pub(super) suppressed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RateLimitGroup {
    pub(super) interval_usec: u64,
    pub(super) pools: [RateLimitPool; 5],
}

impl RateLimitGroup {
    pub(super) fn new(interval_usec: u64) -> Self {
        Self {
            interval_usec,
            pools: [RateLimitPool::default(); 5],
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct PeerRateLimiter {
    pub(super) cfg: RateLimitConfig,
    pub(super) groups: BTreeMap<String, RateLimitGroup>,
    pub(super) group_order: VecDeque<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PeerCredentials {
    pub(super) pid: i32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

#[derive(Debug, Clone, Default)]
pub(super) struct DatagramMetadata {
    pub(super) creds: Option<PeerCredentials>,
    pub(super) source_realtime_timestamp_usec: Option<u64>,
    pub(super) selinux_label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IngressTransport {
    Raw,
    Native,
    Syslog,
    Stdout,
    Kernel,
    Audit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(super) enum IngressSource {
    NativeSocketDatagram,
    SyslogSocketDatagram,
    StdoutStream,
    DevKmsg,
    AuditNetlink,
}

impl IngressTransport {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            IngressTransport::Raw => "raw",
            IngressTransport::Native => "journal",
            IngressTransport::Syslog => "syslog",
            IngressTransport::Stdout => "stdout",
            IngressTransport::Kernel => "kernel",
            IngressTransport::Audit => "audit",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct IngressRecord {
    pub(super) transport: IngressTransport,
    pub(super) message: String,
    pub(super) priority: Option<u32>,
    pub(super) facility: Option<u8>,
    pub(super) severity: Option<u8>,
    pub(super) syslog_identifier: Option<String>,
    pub(super) syslog_pid: Option<String>,
    pub(super) syslog_timestamp: Option<String>,
    pub(super) kmsg_sequence: Option<u64>,
    pub(super) source_boottime_timestamp: Option<u64>,
    pub(super) source_monotonic_timestamp: Option<u64>,
    pub(super) object_pid: Option<i32>,
    pub(super) extra_fields: Vec<(String, String)>,
    /// Original `FIELD=VALUE` byte strings from the native protocol.
    ///
    /// These must bypass all text formatting so embedded NULs, newlines,
    /// delimiters, and non-UTF-8 bytes reach the journal DATA objects intact.
    pub(super) native_fields: Option<Vec<Vec<u8>>>,
}

impl IngressRecord {
    pub(super) fn raw(payload: &[u8]) -> Self {
        Self {
            transport: IngressTransport::Raw,
            message: String::from_utf8_lossy(payload).into_owned(),
            priority: None,
            facility: None,
            severity: None,
            syslog_identifier: None,
            syslog_pid: None,
            syslog_timestamp: None,
            kmsg_sequence: None,
            source_boottime_timestamp: None,
            source_monotonic_timestamp: None,
            object_pid: None,
            extra_fields: Vec::new(),
            native_fields: None,
        }
    }
}

impl PeerRateLimiter {
    pub(super) fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            groups: BTreeMap::new(),
            group_order: VecDeque::new(),
        }
    }

    pub(super) fn check(
        &mut self,
        key: &str,
        severity: u8,
        available: u64,
        now_usec: u64,
    ) -> RateLimitDecision {
        self.check_with_cfg(key, severity, available, now_usec, self.cfg)
    }

    pub(super) fn check_with_cfg(
        &mut self,
        key: &str,
        severity: u8,
        available: u64,
        now_usec: u64,
        cfg: RateLimitConfig,
    ) -> RateLimitDecision {
        if cfg.interval_usec == 0 || cfg.burst == 0 {
            return RateLimitDecision::Allow { emit_suppressed: 0 };
        }

        let pool_index = priority_bucket(severity);
        if !self.groups.contains_key(key) {
            self.vacuum_expired(now_usec);
            self.make_room_for_new_group();
            self.group_order.push_back(key.to_string());
        }
        let group = self
            .groups
            .entry(key.to_string())
            .or_insert_with(|| RateLimitGroup::new(cfg.interval_usec));
        group.interval_usec = cfg.interval_usec;
        let pool = &mut group.pools[pool_index];
        let burst = burst_modulate(cfg.burst, available).max(1);

        let mut emit_suppressed = 0_u64;
        if pool.begin_usec == 0 {
            pool.begin_usec = now_usec;
            pool.accepted = 1;
            pool.suppressed = 0;
            return RateLimitDecision::Allow { emit_suppressed: 0 };
        }

        if now_usec.saturating_sub(pool.begin_usec) >= cfg.interval_usec {
            emit_suppressed = pool.suppressed;
            pool.begin_usec = now_usec;
            pool.accepted = 1;
            pool.suppressed = 0;
            return RateLimitDecision::Allow { emit_suppressed };
        }

        if pool.accepted < burst {
            pool.accepted += 1;
            RateLimitDecision::Allow { emit_suppressed }
        } else {
            pool.suppressed = pool.suppressed.saturating_add(1);
            RateLimitDecision::Drop
        }
    }

    pub(super) fn make_room_for_new_group(&mut self) {
        while self.groups.len() >= RATE_LIMIT_GROUPS_MAX {
            let Some(oldest) = self.group_order.pop_front() else {
                break;
            };
            self.groups.remove(&oldest);
        }
    }

    pub(super) fn vacuum_expired(&mut self, now_usec: u64) {
        let mut stale = Vec::new();
        for (key, group) in &self.groups {
            let alive = group.pools.iter().any(|pool| {
                pool.begin_usec > 0
                    && now_usec.saturating_sub(pool.begin_usec) < group.interval_usec
            });
            if !alive {
                stale.push(key.clone());
            }
        }
        if stale.is_empty() {
            return;
        }

        for key in &stale {
            self.groups.remove(key);
        }
        self.group_order
            .retain(|key| !stale.iter().any(|removed| removed == key));
    }
}

pub(super) fn parse_env_bool(raw: &str) -> Option<bool> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

pub(super) fn keyed_hash_requested() -> bool {
    std::env::var(SYSTEMD_JOURNAL_KEYED_HASH_ENV)
        .ok()
        .and_then(|raw| parse_env_bool(&raw))
        .unwrap_or(true)
}

pub(super) fn journal_incompatible_flags() -> u32 {
    if keyed_hash_requested() {
        HEADER_INCOMPATIBLE_KEYED_HASH
    } else {
        0
    }
}

pub(super) fn sanitize_field_value(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '\n' | '\r' | '\t' => ' ',
            '|' | '%' => '_',
            _ => ch,
        })
        .collect()
}

pub(super) fn priority_bucket(severity: u8) -> usize {
    match severity {
        0..=2 => 0,
        3 => 1,
        4 => 2,
        5 | 6 => 3,
        _ => 4,
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn is_valid_kernel_audit_sender(sender_pid: Option<i32>, addr_pid: Option<u32>) -> bool {
    sender_pid == Some(0) && addr_pid == Some(0)
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn parse_audit_netlink_datagram(
    buffer: &[u8],
    bytes: usize,
) -> Option<(u16, std::ops::Range<usize>)> {
    let header_len = nlmsg_align(std::mem::size_of::<NetlinkMessageHeader>());
    if bytes < header_len || bytes > buffer.len() {
        return None;
    }

    // SAFETY: the preceding length check proves the buffer contains a complete
    // netlink header; read_unaligned avoids imposing alignment requirements.
    let header =
        unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<NetlinkMessageHeader>()) };
    let total_len = header.nlmsg_len as usize;
    if total_len < header_len || total_len > bytes {
        return None;
    }

    let msg_type = header.nlmsg_type;
    if msg_type == NLMSG_NOOP_TYPE || msg_type == NLMSG_ERROR_TYPE {
        return None;
    }
    if msg_type < AUDIT_FIRST_USER_MSG && msg_type != AUDIT_USER_TYPE {
        return None;
    }

    Some((msg_type, header_len..total_len))
}

pub(super) fn burst_modulate(burst: u32, available: u64) -> u32 {
    let k = if available == 0 {
        0
    } else {
        63_u32.saturating_sub(available.leading_zeros())
    };

    if k <= 20 {
        return burst;
    }

    burst.saturating_mul(k.saturating_sub(16)) / 4
}

pub(super) fn available_bytes_for_rate_limit(path: &Path) -> u64 {
    match nix::sys::statvfs::statvfs(path) {
        Ok(stats) => (stats.blocks_available() as u64).saturating_mul(stats.fragment_size() as u64),
        Err(_) => 0,
    }
}

pub(super) fn parse_syslog_pid_like_c(text: &str) -> Option<String> {
    let candidate = text.trim();
    if candidate.is_empty() {
        return None;
    }

    let value = if let Some(rest) = candidate
        .strip_prefix("0x")
        .or_else(|| candidate.strip_prefix("0X"))
    {
        if rest.is_empty() {
            return None;
        }
        u64::from_str_radix(rest, 16).ok()?
    } else if candidate.bytes().all(|b| b.is_ascii_digit()) {
        candidate.parse::<u64>().ok()?
    } else {
        return None;
    };

    if value == 0 || value > i32::MAX as u64 {
        return None;
    }

    Some(value.to_string())
}

pub(super) fn parse_syslog_identifier_and_pid(
    text: &str,
) -> (Option<String>, Option<String>, String) {
    let trimmed = text.trim_start_matches(char::is_whitespace);
    let token_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());

    let token = &trimmed[..token_end];
    if token.is_empty() || !token.ends_with(':') {
        return (None, None, text.to_string());
    }

    let mut message_start = token_end;
    if trimmed
        .as_bytes()
        .get(token_end)
        .is_some_and(|b| b.is_ascii_whitespace())
    {
        message_start += 1;
    }

    let message = trimmed[message_start..].to_string();
    let mut identifier = token[..token.len() - 1].to_string();
    let mut pid = None;
    if identifier.ends_with(']') {
        if let Some(open) = identifier.rfind('[') {
            let pid_candidate = &identifier[open + 1..identifier.len() - 1];
            pid = parse_syslog_pid_like_c(pid_candidate);
            identifier.truncate(open);
        }
    }

    if identifier.len() > SYSLOG_IDENTIFIER_MAX {
        identifier.clear();
        return (None, pid, message);
    }

    (Some(identifier), pid, message)
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn strip_audit_value_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        if trimmed.len() >= 2 {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(test, target_os = "linux"))]
pub(super) struct AuditHeader {
    pub(super) serial: u64,
    pub(super) body: String,
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn parse_audit_header(payload: &str) -> Option<AuditHeader> {
    let trimmed = payload.trim_start();
    let audit_offset = trimmed.find("audit(")?;
    let rest = &trimmed[audit_offset + "audit(".len()..];
    let end = rest.find("):")?;
    let header = &rest[..end];
    let mut header_parts = header.split(':');
    let time = header_parts.next()?;
    let id_text = header_parts.next()?;
    if header_parts.next().is_some() {
        return None;
    }

    let mut time_parts = time.split('.');
    let seconds = time_parts.next()?;
    let msec = time_parts.next()?;
    if time_parts.next().is_some() {
        return None;
    }
    let _ = seconds.parse::<u64>().ok()?;
    let _ = msec.parse::<u64>().ok()?;
    let serial = id_text.parse::<u64>().ok()?;
    let body = rest[end + 2..].trim_start().to_string();
    if body.is_empty() {
        return None;
    }

    Some(AuditHeader { serial, body })
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn parse_audit_tokens(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for token in input.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        out.push((key.to_string(), strip_audit_value_quotes(value)));
    }
    out
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn normalize_audit_key(prefix: &str, key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }

    let mut normalized = String::from(prefix);
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_uppercase());
        } else if ch == '_' || ch == '-' {
            normalized.push('_');
        } else {
            return None;
        }
    }

    Some(normalized)
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn map_audit_kernel_field(name: &str) -> Option<&'static str> {
    match name {
        "pid" => Some("_PID"),
        "ppid" => Some("_PPID"),
        "uid" => Some("_UID"),
        "euid" => Some("_EUID"),
        "fsuid" => Some("_FSUID"),
        "gid" => Some("_GID"),
        "egid" => Some("_EGID"),
        "fsgid" => Some("_FSGID"),
        "tty" => Some("_TTY"),
        "ses" => Some("_AUDIT_SESSION"),
        "auid" => Some("_AUDIT_LOGINUID"),
        "subj" => Some("_SELINUX_CONTEXT"),
        "comm" => Some("_COMM"),
        "exe" => Some("_EXE"),
        "proctitle" => Some("_CMDLINE"),
        "path" => Some("_AUDIT_FIELD_PATH"),
        "dev" => Some("_AUDIT_FIELD_DEV"),
        "name" => Some("_AUDIT_FIELD_NAME"),
        _ => None,
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn map_audit_userspace_field(name: &str) -> Option<&'static str> {
    match name {
        "cwd" => Some("AUDIT_FIELD_CWD"),
        "cmd" => Some("AUDIT_FIELD_CMD"),
        "acct" => Some("AUDIT_FIELD_ACCT"),
        "exe" => Some("AUDIT_FIELD_EXE"),
        "comm" => Some("AUDIT_FIELD_COMM"),
        _ => None,
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn map_audit_fields(body: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let marker = "msg='";
    let (kernel_part, userspace_part) = if let Some(idx) = body.find(marker) {
        let after = &body[idx + marker.len()..];
        if let Some(end) = after.rfind('\'') {
            (&body[..idx], Some(&after[..end]))
        } else {
            (body, None)
        }
    } else {
        (body, None)
    };

    for (name, value) in parse_audit_tokens(kernel_part) {
        if let Some(mapped) = map_audit_kernel_field(&name) {
            fields.push((mapped.to_string(), value));
            continue;
        }
        if let Some(mapped) = normalize_audit_key("_AUDIT_FIELD_", &name) {
            fields.push((mapped, value));
        }
    }

    if let Some(userspace) = userspace_part {
        for (name, value) in parse_audit_tokens(userspace) {
            if let Some(mapped) = map_audit_userspace_field(&name) {
                fields.push((mapped.to_string(), value));
                continue;
            }
            if let Some(mapped) = normalize_audit_key("AUDIT_FIELD_", &name) {
                fields.push((mapped, value));
            }
        }
    }

    fields
}

pub(super) fn classify_kmsg_ingress(payload: &[u8]) -> Option<IngressRecord> {
    let Ok(Some(kmsg)) = parse_kmsg_record(payload) else {
        return None;
    };

    let facility = (kmsg.priority / 8) as u8;
    let severity = (kmsg.priority % 8) as u8;
    let (identifier, pid, message) = if facility == 0 {
        (Some("kernel".to_string()), None, kmsg.message)
    } else {
        parse_syslog_identifier_and_pid(&kmsg.message)
    };

    Some(IngressRecord {
        transport: IngressTransport::Kernel,
        message,
        priority: Some(severity as u32),
        facility: Some(facility),
        severity: Some(severity),
        syslog_identifier: identifier,
        syslog_pid: pid,
        syslog_timestamp: None,
        kmsg_sequence: Some(kmsg.sequence),
        source_boottime_timestamp: Some(kmsg.timestamp_us),
        source_monotonic_timestamp: Some(kmsg.timestamp_us),
        object_pid: None,
        extra_fields: Vec::new(),
        native_fields: None,
    })
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn classify_audit_netlink_ingress(
    payload: &[u8],
    msg_type: u16,
) -> Option<IngressRecord> {
    if parse_audit_string(payload).is_err() {
        return None;
    }

    let text = String::from_utf8_lossy(payload);
    if !text.trim_start().starts_with("audit(") {
        return None;
    }
    let header = parse_audit_header(text.as_ref())?;
    let mut extra = vec![("_AUDIT_ID".to_string(), header.serial.to_string())];
    let audit_type = msg_type as i32;
    let audit_type_name = audit_type_name_alloc(audit_type);
    extra.push(("_AUDIT_TYPE".to_string(), audit_type.to_string()));
    extra.push(("_AUDIT_TYPE_NAME".to_string(), audit_type_name.clone()));
    extra.extend(map_audit_fields(&header.body));
    let message = format!("{audit_type_name} {}", header.body);

    Some(IngressRecord {
        transport: IngressTransport::Audit,
        message,
        priority: Some(5),
        facility: Some(4),
        severity: Some(5),
        syslog_identifier: Some("audit".to_string()),
        syslog_pid: None,
        syslog_timestamp: None,
        kmsg_sequence: None,
        source_boottime_timestamp: None,
        source_monotonic_timestamp: None,
        object_pid: None,
        extra_fields: extra,
        native_fields: None,
    })
}

pub(super) fn classify_syslog_ingress(payload: &[u8]) -> IngressRecord {
    if let Ok(syslog) = parse_syslog_message(payload) {
        let raw_text = String::from_utf8_lossy(payload).into_owned();
        let trimmed_text = raw_text.trim_matches(char::is_whitespace);
        let mut store_raw = trimmed_text.len() != raw_text.len() || payload.contains(&0);

        let mut content = syslog.content.as_str();
        let mut syslog_ts = None;
        if let Some((ts, rest)) = try_parse_rfc3164_timestamp(content) {
            syslog_ts = Some(ts.to_string());
            content = rest;
        } else {
            store_raw = true;
        }
        let (identifier, pid, message) = parse_syslog_identifier_and_pid(content);
        let mut extra_fields = Vec::new();
        if store_raw {
            extra_fields.push(("SYSLOG_RAW".to_string(), raw_text));
        }
        return IngressRecord {
            transport: IngressTransport::Syslog,
            message,
            priority: Some(syslog.severity as u32),
            facility: Some(syslog.facility),
            severity: Some(syslog.severity),
            syslog_identifier: identifier,
            syslog_pid: pid,
            syslog_timestamp: syslog_ts,
            kmsg_sequence: None,
            source_boottime_timestamp: None,
            source_monotonic_timestamp: None,
            object_pid: None,
            extra_fields,
            native_fields: None,
        };
    }

    IngressRecord::raw(payload)
}

pub(super) fn classify_native_ingress(
    payload: &[u8],
    creds: Option<PeerCredentials>,
) -> Option<IngressRecord> {
    let native = parse_native_message(payload).ok()?;
    classify_native_message(native, creds)
}

fn classify_native_message(
    native: NativeMessage,
    creds: Option<PeerCredentials>,
) -> Option<IngressRecord> {
    if native.entries.is_empty() {
        return None;
    }

    let mut message = String::new();
    let mut priority = None;
    let mut facility = None;
    let mut identifier = None;
    let mut object_pid = None;
    let mut native_fields = Vec::with_capacity(native.entries.len());

    for entry in native.entries {
        match entry.name.as_slice() {
            b"MESSAGE" => message = String::from_utf8_lossy(&entry.payload).into_owned(),
            b"PRIORITY" => {
                if let [digit] = entry.payload.as_slice() {
                    if digit.is_ascii_digit() {
                        priority = Some((digit - b'0') as u32);
                    }
                }
            }
            b"SYSLOG_FACILITY" => {
                if !entry.payload.is_empty()
                    && entry.payload.len() <= 2
                    && entry.payload.iter().all(|byte| byte.is_ascii_digit())
                {
                    facility = std::str::from_utf8(&entry.payload)
                        .ok()
                        .and_then(|value| value.parse::<u8>().ok());
                }
            }
            b"SYSLOG_IDENTIFIER" => {
                if !entry.payload.is_empty() {
                    identifier = Some(String::from_utf8_lossy(&entry.payload).into_owned());
                }
            }
            b"OBJECT_PID" => {
                if creds.is_some_and(|cred| cred.uid == 0) {
                    object_pid = std::str::from_utf8(&entry.payload)
                        .ok()
                        .and_then(|value| value.parse::<i32>().ok())
                        .filter(|pid| *pid > 0);
                }
            }
            _ => {}
        }

        native_fields.push(entry.into_journal_field().ok()?);
    }

    let severity = priority.map(|p| (p % 8) as u8);
    Some(IngressRecord {
        transport: IngressTransport::Native,
        message,
        priority,
        facility,
        severity,
        syslog_identifier: identifier,
        syslog_pid: None,
        syslog_timestamp: None,
        kmsg_sequence: None,
        source_boottime_timestamp: None,
        source_monotonic_timestamp: None,
        object_pid,
        extra_fields: Vec::new(),
        native_fields: Some(native_fields),
    })
}

/// Decode every independently framed entry from a native socket datagram.
///
/// A malformed entry is represented as an error after any earlier valid
/// records. The runtime must stop at that boundary rather than append a
/// partial record or merge fields across entries.
pub(super) fn classify_native_datagram(
    payload: &[u8],
    creds: Option<PeerCredentials>,
) -> Vec<Result<IngressRecord, NativeError>> {
    parse_native_datagram(payload)
        .into_iter()
        .filter_map(|message| match message {
            Ok(message) => classify_native_message(message, creds).map(Ok),
            Err(error) => Some(Err(error)),
        })
        .collect()
}

pub(super) fn classify_ingress(
    payload: &[u8],
    creds: Option<PeerCredentials>,
    source: IngressSource,
) -> Option<IngressRecord> {
    match source {
        IngressSource::NativeSocketDatagram => classify_native_ingress(payload, creds),
        IngressSource::SyslogSocketDatagram => Some(classify_syslog_ingress(payload)),
        IngressSource::StdoutStream => Some(IngressRecord::raw(payload)),
        IngressSource::DevKmsg => {
            Some(classify_kmsg_ingress(payload).unwrap_or_else(|| IngressRecord::raw(payload)))
        }
        IngressSource::AuditNetlink => Some(IngressRecord::raw(payload)),
    }
}
