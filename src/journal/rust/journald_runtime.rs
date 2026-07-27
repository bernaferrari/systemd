// SPDX-License-Identifier: LGPL-2.1-or-later

#[cfg(any(test, target_os = "linux"))]
use crate::fuzz_journald_audit::parse_audit_string;
use crate::fuzz_journald_kmsg::parse_kmsg_record;
use crate::fuzz_journald_native::{parse_native_message, ENTRY_SIZE_MAX};
use crate::fuzz_journald_syslog::{parse_syslog_message, try_parse_rfc3164_timestamp};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use systemd_libsystemd_rs::id128_util::SdId128;
use systemd_libsystemd_rs::sd_daemon_checks::{sd_is_socket_unix, sd_listen_fds_with_names};
use systemd_libsystemd_rs::sd_id128_api::{
    sd_id128_get_boot, sd_id128_get_machine, sd_id128_randomize,
};
#[cfg(any(test, target_os = "linux"))]
use systemd_libsystemd_rs::sd_journal_audit_type::audit_type_name_alloc;
use systemd_libsystemd_rs::sd_journal_file::{
    append_journal_record_unindexed, create_empty_journal_file_at, journal_file_rotate_suggested,
    open_journal_file_at, read_journal_records, render_journal_file_as_text, write_journal_header,
    Header, JournalFileOnDisk, HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
    HEADER_INCOMPATIBLE_KEYED_HASH, JOURNAL_FILE_SIZE_MIN, STATE_ONLINE,
};
use systemd_libsystemd_rs::sd_journal_vacuum::journal_directory_vacuum;
use systemd_shared_rs::daemon_util::notify_store_fd;
use systemd_shared_rs::journal_field::journal_field_valid;
use systemd_shared_rs::libaudit_util::{parse_loginuid, parse_sessionid};
use systemd_shared_rs::pcre2_util::{
    dlopen_pcre2, pattern_compile, pattern_matches, CompiledPattern, PatternCompileCase,
};

use nix::libc;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

pub const DEFAULT_RUNTIME_ROOT: &str = "/run/systemd/journal";
pub const DEFAULT_SOCKET_PATH: &str = "/run/systemd/journal/socket";
const LOG_FILE_NAME: &str = "system.journal";
const KERNEL_SEQNUM_FILE_NAME: &str = "kernel-seqnum";
const FLUSH_MARKER_NAME: &str = "flushed";
const ROTATE_MARKER_NAME: &str = "rotated";
const RELINQUISH_MARKER_NAME: &str = "relinquished-var";
const ROTATED_SEQNUM_ID: &str = "00000000000000000000000000000000";
const JOURNAL_VACUUM_MIN_FILE_SIZE: u64 = std::mem::size_of::<Header>() as u64;
const STORAGE_MODE_ENV: &str = "SYSTEMD_JOURNAL_STORAGE";
const PROC_ROOT_ENV: &str = "SYSTEMD_JOURNAL_PROC_ROOT";
const RUN_SYSTEMD_ROOT_ENV: &str = "SYSTEMD_JOURNAL_RUN_SYSTEMD_ROOT";
const RUN_USER_ROOT_ENV: &str = "SYSTEMD_JOURNAL_RUN_USER_ROOT";
const CGROUP_FS_ROOT_ENV: &str = "SYSTEMD_JOURNAL_CGROUP_FS_ROOT";
const STORAGE_PERSISTENT_ROOT_ENV: &str = "SYSTEMD_JOURNAL_PERSISTENT_ROOT";
const SYSTEM_MAX_USE_ENV: &str = "SYSTEMD_JOURNAL_SYSTEM_MAX_USE";
const SYSTEM_MAX_FILES_ENV: &str = "SYSTEMD_JOURNAL_SYSTEM_MAX_FILES";
const SYSTEM_MAX_FILE_SIZE_ENV: &str = "SYSTEMD_JOURNAL_SYSTEM_MAX_FILE_SIZE";
const SYSTEMD_JOURNAL_KEYED_HASH_ENV: &str = "SYSTEMD_JOURNAL_KEYED_HASH";
const RATE_LIMIT_INTERVAL_ENV: &str = "SYSTEMD_JOURNALD_RATE_LIMIT_INTERVAL_USEC";
const RATE_LIMIT_BURST_ENV: &str = "SYSTEMD_JOURNALD_RATE_LIMIT_BURST";
const DEFAULT_RATE_LIMIT_INTERVAL_USEC: u64 = 30_000_000;
const DEFAULT_RATE_LIMIT_BURST: u32 = 10_000;
const SD_MESSAGE_JOURNAL_DROPPED_STR: &str = "a596d6fe7bfa4994828e72309e95d61e";
const DAEMON_POLL_TIMEOUT_MS: u64 = 250;
const SYSLOG_IDENTIFIER_MAX: usize = 255;
const RATE_LIMIT_GROUPS_MAX: usize = 2047;
const DEFAULT_STDOUT_STREAM_LINE_MAX: usize = 48 * 1024;
const STDOUT_STREAM_SETUP_PROTOCOL_LINE_MAX: usize = 255;
const CLIENT_CONTEXT_REFRESH_USEC: u64 = 1_000_000;
const CLIENT_CONTEXT_MAX_USEC: u64 = 5_000_000;
const CLIENT_CONTEXT_CACHE_MAX: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const SELINUX_CMSG_MAX: usize = 4096;
#[cfg(any(test, target_os = "linux"))]
#[allow(dead_code)]
const NETLINK_AUDIT_PROTOCOL: i32 = 9;
#[cfg(any(test, target_os = "linux"))]
#[allow(dead_code)]
const AUDIT_NLGRP_READLOG: u32 = 1;
#[cfg(any(test, target_os = "linux"))]
const AUDIT_USER_TYPE: u16 = 1005;
#[cfg(any(test, target_os = "linux"))]
const AUDIT_FIRST_USER_MSG: u16 = 1100;
#[cfg(any(test, target_os = "linux"))]
const NLMSG_NOOP_TYPE: u16 = 0x1;
#[cfg(any(test, target_os = "linux"))]
const NLMSG_ERROR_TYPE: u16 = 0x2;
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(any(test, target_os = "linux"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct NetlinkMessageHeader {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[path = "journald_runtime_storage.rs"]
mod storage;
use storage::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Flush,
    Rotate,
    RelinquishVar,
    SmartRelinquishVar,
    VacuumSize(u64),
    DumpCatalog,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Help,
    Version,
    Daemon,
    Action(Action),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateReport {
    pub previous_log: PathBuf,
    pub new_log: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VacuumReport {
    pub removed_files: Vec<PathBuf>,
    pub bytes_removed: u64,
    pub bytes_remaining: u64,
    pub limit: u64,
}

#[derive(Debug)]
pub enum JournaldError {
    Io(io::Error),
    InvalidArgument(String),
    ParseSize(String),
}

impl fmt::Display for JournaldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JournaldError::Io(err) => write!(f, "{err}"),
            JournaldError::InvalidArgument(msg) => f.write_str(msg),
            JournaldError::ParseSize(msg) => f.write_str(msg),
        }
    }
}

impl Error for JournaldError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            JournaldError::Io(err) => Some(err),
            JournaldError::InvalidArgument(_) | JournaldError::ParseSize(_) => None,
        }
    }
}

impl From<io::Error> for JournaldError {
    fn from(err: io::Error) -> Self {
        JournaldError::Io(err)
    }
}

#[derive(Debug, Clone)]
pub struct JournalRuntime {
    root: PathBuf,
    namespace: Option<String>,
    client_contexts: Arc<Mutex<ClientContextCache>>,
}

#[path = "journald_runtime_io.rs"]
mod runtime_io;
use runtime_io::*;

#[path = "journald_runtime_daemon.rs"]
mod daemon;

impl JournalRuntime {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            namespace: None,
            client_contexts: Arc::new(Mutex::new(ClientContextCache::default())),
        }
    }

    pub fn new_with_namespace(root: impl Into<PathBuf>, namespace: Option<String>) -> Self {
        Self {
            root: root.into(),
            namespace,
            client_contexts: Arc::new(Mutex::new(ClientContextCache::default())),
        }
    }

    pub fn default() -> Self {
        Self::new(DEFAULT_RUNTIME_ROOT)
    }

    pub fn default_with_namespace(namespace: Option<String>) -> Self {
        let root = match namespace.as_deref() {
            Some(namespace) => PathBuf::from(format!("{DEFAULT_RUNTIME_ROOT}.{namespace}")),
            None => PathBuf::from(DEFAULT_RUNTIME_ROOT),
        };
        Self {
            root,
            namespace,
            client_contexts: Arc::new(Mutex::new(ClientContextCache::default())),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    fn is_namespaced_instance(&self) -> bool {
        self.namespace().is_some()
    }

    fn append_namespace_field(&self, fields: &mut Vec<String>) {
        if let Some(namespace) = self.namespace() {
            fields.push(format!("_NAMESPACE={}", sanitize_field_value(namespace)));
        }
    }

    fn client_context_for_pid(
        &self,
        creds: PeerCredentials,
        unit_id_hint: Option<&str>,
        label_override: Option<&str>,
    ) -> Option<ClientContext> {
        if creds.pid <= 0 {
            return None;
        }

        let mut cache = self.client_contexts.lock().ok()?;
        Some(cache.get_or_refresh(
            creds.pid,
            Some(creds),
            label_override,
            unit_id_hint,
            proc_root().as_path(),
            run_systemd_root().as_path(),
            run_user_root().as_path(),
        ))
    }

    fn object_client_context(&self, pid: i32) -> Option<ClientContext> {
        if pid <= 0 {
            return None;
        }

        let mut cache = self.client_contexts.lock().ok()?;
        Some(cache.get_or_refresh(
            pid,
            None,
            None,
            None,
            proc_root().as_path(),
            run_systemd_root().as_path(),
            run_user_root().as_path(),
        ))
    }

    pub fn socket_path(&self) -> PathBuf {
        self.root.join("socket")
    }

    pub fn dev_log_path(&self) -> PathBuf {
        self.root.join("dev-log")
    }

    pub fn stdout_path(&self) -> PathBuf {
        self.root.join("stdout")
    }

    fn stdout_streams_dir(&self) -> PathBuf {
        self.root.join("streams")
    }

    pub fn log_path(&self) -> PathBuf {
        self.root.join(LOG_FILE_NAME)
    }

    fn kernel_seqnum_path(&self) -> PathBuf {
        self.root.join(KERNEL_SEQNUM_FILE_NAME)
    }

    fn load_kernel_seqnum(&self) -> Option<u64> {
        let text = fs::read_to_string(self.kernel_seqnum_path()).ok()?;
        text.trim().parse::<u64>().ok()
    }

    fn store_kernel_seqnum(&self, next_expected: u64) -> Result<(), JournaldError> {
        self.ensure_root()?;
        fs::write(self.kernel_seqnum_path(), format!("{next_expected}\n"))?;
        Ok(())
    }

    fn process_dev_kmsg_record(
        &self,
        payload: &[u8],
        tracker: &mut KmsgSequenceTracker,
    ) -> Result<(), JournaldError> {
        let Some(parsed) = classify_kmsg_ingress(payload) else {
            return Ok(());
        };

        match tracker.check(&parsed) {
            KmsgSequenceDecision::Allow { emit_missed } => {
                self.append_kmsg_sequence_gap_notice(emit_missed)?;
            }
            KmsgSequenceDecision::Drop => return Ok(()),
        }

        if let Some(next_expected) = tracker.next_expected() {
            self.store_kernel_seqnum(next_expected)?;
        }

        self.append_ingress_payload(payload, None, None, IngressSource::DevKmsg)
    }

    fn drain_dev_kmsg(
        &self,
        reader: &mut DevKmsgReader,
        tracker: &mut KmsgSequenceTracker,
    ) -> Result<(), JournaldError> {
        while let Some(payload) = reader.read_record()? {
            self.process_dev_kmsg_record(payload, tracker)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn process_audit_netlink_record(
        &self,
        msg_type: u16,
        payload: &[u8],
    ) -> Result<(), JournaldError> {
        self.append_audit_netlink_payload(payload, msg_type)
    }

    #[cfg(target_os = "linux")]
    fn drain_audit_netlink(
        &self,
        receiver: &mut AuditNetlinkReceiver,
    ) -> Result<(), JournaldError> {
        while let Some((msg_type, payload)) = receiver.recv_message()? {
            self.process_audit_netlink_record(msg_type, &payload)?;
        }
        Ok(())
    }

    pub fn append_datagram(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
    ) -> Result<(), JournaldError> {
        self.append_datagram_with_metadata(payload, peer, None)
    }

    pub fn append_syslog_datagram(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
    ) -> Result<(), JournaldError> {
        self.append_syslog_datagram_with_metadata(payload, peer, None)
    }

    fn append_datagram_with_metadata(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
        creds: Option<PeerCredentials>,
    ) -> Result<(), JournaldError> {
        self.append_socket_datagram_with_metadata(
            payload,
            peer,
            DatagramMetadata {
                creds,
                ..Default::default()
            },
            IngressSource::NativeSocketDatagram,
            None,
        )
    }

    fn append_syslog_datagram_with_metadata(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
        creds: Option<PeerCredentials>,
    ) -> Result<(), JournaldError> {
        self.append_socket_datagram_with_metadata(
            payload,
            peer,
            DatagramMetadata {
                creds,
                ..Default::default()
            },
            IngressSource::SyslogSocketDatagram,
            None,
        )
    }

    #[cfg(any(test, target_os = "linux"))]
    fn append_audit_netlink_payload(
        &self,
        payload: &[u8],
        msg_type: u16,
    ) -> Result<(), JournaldError> {
        let Some(parsed) = classify_audit_netlink_ingress(payload, msg_type) else {
            return Ok(());
        };
        self.append_classified_ingress(payload, None, None, None, parsed)
    }

    fn append_ingress_payload(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
        creds: Option<PeerCredentials>,
        source: IngressSource,
    ) -> Result<(), JournaldError> {
        let Some(parsed) = classify_ingress(payload, creds, source) else {
            return Ok(());
        };
        self.append_classified_ingress(payload, peer, creds, None, parsed)
    }

    fn append_socket_datagram_with_metadata(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
        metadata: DatagramMetadata,
        source: IngressSource,
        mut limiter: Option<&mut PeerRateLimiter>,
    ) -> Result<(), JournaldError> {
        let context = metadata.creds.and_then(|cred| {
            self.client_context_for_pid(cred, None, metadata.selinux_label.as_deref())
        });

        if source == IngressSource::NativeSocketDatagram {
            for parsed in classify_native_datagram(payload, metadata.creds) {
                let parsed = match parsed {
                    Ok(parsed) => parsed,
                    // The decoder deliberately yields earlier complete records
                    // before this error. Do not turn the malformed record into
                    // a partial append or consume fields from a later entry.
                    Err(_) => break,
                };
                self.append_socket_ingress_record(
                    payload,
                    peer,
                    metadata.creds,
                    parsed,
                    context.as_ref(),
                    metadata.source_realtime_timestamp_usec,
                    limiter.as_deref_mut(),
                )?;
            }
            return Ok(());
        }

        let Some(parsed) = classify_ingress(payload, metadata.creds, source) else {
            return Ok(());
        };
        self.append_socket_ingress_record(
            payload,
            peer,
            metadata.creds,
            parsed,
            context.as_ref(),
            metadata.source_realtime_timestamp_usec,
            limiter,
        )
    }

    /// Apply socket-specific policy to one fully decoded ingress record.
    ///
    /// A native datagram shares authenticated peer metadata and the acquired
    /// context across its records, while filtering and rate limiting remain
    /// entry-local just as they are in C's `manager_process_entry()` loop.
    fn append_socket_ingress_record(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
        creds: Option<PeerCredentials>,
        parsed: IngressRecord,
        context: Option<&ClientContext>,
        source_realtime_timestamp_usec: Option<u64>,
        limiter: Option<&mut PeerRateLimiter>,
    ) -> Result<(), JournaldError> {
        if !self.context_keeps_log(context, &parsed) {
            return Ok(());
        }
        if let Some(limiter) = limiter {
            let priority = parsed.priority.unwrap_or(6);
            if !self.apply_context_rate_limit(limiter, context, priority)? {
                return Ok(());
            }
        }

        self.append_classified_ingress_with_context(
            payload,
            peer,
            creds,
            parsed,
            context,
            source_realtime_timestamp_usec,
        )
    }

    fn append_classified_ingress(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
        creds: Option<PeerCredentials>,
        unit_id_hint: Option<&str>,
        parsed: IngressRecord,
    ) -> Result<(), JournaldError> {
        let context = creds.and_then(|cred| self.client_context_for_pid(cred, unit_id_hint, None));
        self.append_classified_ingress_with_context(
            payload,
            peer,
            creds,
            parsed,
            context.as_ref(),
            None,
        )
    }

    fn append_classified_ingress_with_context(
        &self,
        payload: &[u8],
        peer: Option<&Path>,
        creds: Option<PeerCredentials>,
        parsed: IngressRecord,
        context: Option<&ClientContext>,
        source_realtime_timestamp_usec: Option<u64>,
    ) -> Result<(), JournaldError> {
        let ts = now_micros();
        let peer = peer.map_or_else(|| "anonymous".to_string(), display_path);
        let native_ingress = parsed.native_fields.is_some();
        let mut fields = vec![
            format!("ts={ts}"),
            format!("peer={}", sanitize_field_value(&peer)),
            format!("transport={}", parsed.transport.as_str()),
            format!("_TRANSPORT={}", parsed.transport.as_str()),
        ];
        if !native_ingress {
            fields.push(format!("payload_hex={}", hex_encode(payload)));
        }
        let mut raw_fields = Vec::new();
        let native_fields = parsed.native_fields;
        self.append_namespace_field(&mut fields);

        let priority = parsed.priority.unwrap_or(6);
        if context
            .and_then(|context| context.log_level_max)
            .is_some_and(|max_level| priority > max_level as u32)
        {
            return Ok(());
        }
        if let Some(context) = context {
            append_client_context_fields(&mut fields, "", context);
            append_client_context_extra_fields(&mut raw_fields, context);
        } else if let Some(creds) = creds {
            fields.push(format!("_PID={}", creds.pid));
            fields.push(format!("_UID={}", creds.uid));
            fields.push(format!("_GID={}", creds.gid));
        }

        // Native fields already contain the sender's exact `FIELD=VALUE`
        // bytes. Reformatting their parsed metadata would both duplicate the
        // fields and corrupt binary values.
        if !native_ingress {
            if parsed.priority.is_some() {
                fields.push(format!("PRIORITY={priority}"));
            }
            if let Some(facility) = parsed.facility {
                fields.push(format!("SYSLOG_FACILITY={facility}"));
            }
            if let Some(identifier) = parsed.syslog_identifier {
                fields.push(format!(
                    "SYSLOG_IDENTIFIER={}",
                    sanitize_field_value(&identifier)
                ));
            }
            if let Some(pid) = parsed.syslog_pid {
                fields.push(format!("SYSLOG_PID={}", sanitize_field_value(&pid)));
            }
            if let Some(timestamp) = parsed.syslog_timestamp {
                fields.push(format!(
                    "SYSLOG_TIMESTAMP={}",
                    sanitize_field_value(&timestamp)
                ));
            }
        }
        if let Some(sequence) = parsed.kmsg_sequence {
            fields.push(format!("_KERNEL_SEQNUM={sequence}"));
        }
        if let Some(source) = parsed.source_boottime_timestamp {
            fields.push(format!("_SOURCE_BOOTTIME_TIMESTAMP={source}"));
        }
        if let Some(source) = parsed.source_monotonic_timestamp {
            fields.push(format!("_SOURCE_MONOTONIC_TIMESTAMP={source}"));
        }
        if let Some(source) = source_realtime_timestamp_usec {
            fields.push(format!("_SOURCE_REALTIME_TIMESTAMP={source}"));
        }
        if let Some(object_pid) = parsed.object_pid {
            if !native_ingress {
                fields.push(format!("OBJECT_PID={object_pid}"));
            }
            if let Some(object_context) = self.object_client_context(object_pid) {
                append_client_context_fields(&mut fields, "OBJECT_", &object_context);
            }
        }
        if !native_ingress {
            if !parsed.message.is_empty() {
                fields.push(format!("MESSAGE={}", sanitize_field_value(&parsed.message)));
            }
            for (name, value) in parsed.extra_fields {
                if !name.is_empty() {
                    fields.push(format!("{name}={}", sanitize_field_value(&value)));
                }
            }
        }

        raw_fields.extend(native_fields.into_iter().flatten());
        raw_fields.extend(fields.iter().map(|field| field.as_bytes().to_vec()));
        self.append_with_rotate_retry(|| self.append_fields_to_active_log(&raw_fields))
    }

    fn context_keeps_log(&self, context: Option<&ClientContext>, record: &IngressRecord) -> bool {
        if !matches!(
            record.transport,
            IngressTransport::Native | IngressTransport::Syslog | IngressTransport::Stdout
        ) {
            return true;
        }
        if record.message.is_empty() {
            return true;
        }
        client_context_check_keep_log(context, &record.message)
    }

    fn apply_context_rate_limit(
        &self,
        limiter: &mut PeerRateLimiter,
        context: Option<&ClientContext>,
        priority: u32,
    ) -> Result<bool, JournaldError> {
        let Some(context) = context else {
            return Ok(true);
        };
        let Some(unit) = context.unit.as_deref() else {
            return Ok(true);
        };

        let available = available_bytes_for_rate_limit(&self.rate_limit_root());
        let cfg = RateLimitConfig {
            interval_usec: context
                .log_ratelimit_interval_usec
                .unwrap_or(limiter.cfg.interval_usec),
            burst: context.log_ratelimit_burst.unwrap_or(limiter.cfg.burst),
        };
        match limiter.check_with_cfg(unit, priority as u8, available, now_micros_u64(), cfg) {
            RateLimitDecision::Allow { emit_suppressed } => {
                self.append_rate_limit_notice(unit, emit_suppressed)?;
                Ok(true)
            }
            RateLimitDecision::Drop => Ok(false),
        }
    }

    fn append_rate_limit_notice(&self, peer: &str, dropped: u64) -> Result<(), JournaldError> {
        if dropped == 0 {
            return Ok(());
        }

        let mut fields = Vec::with_capacity(8);
        fields.push(format!("ts={}", now_micros()));
        fields.push("_TRANSPORT=driver".to_string());
        fields.push("PRIORITY=6".to_string());
        fields.push("SYSLOG_FACILITY=3".to_string());
        fields.push("SYSLOG_IDENTIFIER=systemd-journald".to_string());
        fields.push(format!("MESSAGE_ID={SD_MESSAGE_JOURNAL_DROPPED_STR}"));
        fields.push(format!(
            "MESSAGE={}",
            sanitize_field_value(&format!("Suppressed {dropped} messages from {peer}"))
        ));
        fields.push(format!("N_DROPPED={dropped}"));
        self.append_namespace_field(&mut fields);

        let fields = fields
            .iter()
            .map(|field| field.as_bytes().to_vec())
            .collect::<Vec<_>>();
        self.append_with_rotate_retry(|| self.append_fields_to_active_log(&fields))
    }

    fn append_kmsg_sequence_gap_notice(&self, missed: u64) -> Result<(), JournaldError> {
        if missed == 0 {
            return Ok(());
        }

        let mut fields = vec![
            format!("ts={}", now_micros()),
            "transport=driver".to_string(),
            format!("kmsg_missed={missed}"),
            format!("MESSAGE=Missed {missed} kernel messages"),
        ];
        self.append_namespace_field(&mut fields);
        let fields = fields
            .iter()
            .map(|field| field.as_bytes().to_vec())
            .collect::<Vec<_>>();
        self.append_with_rotate_retry(|| self.append_fields_to_active_log(&fields))
    }
}

pub fn parse_args<I, S>(args: I) -> Result<Mode, JournaldError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut action = None;
    let mut help = false;
    let mut version = false;

    for arg in args.into_iter().skip(1) {
        let arg = arg.as_ref();
        let next = match arg {
            "-h" | "--help" => {
                help = true;
                None
            }
            "--version" => {
                version = true;
                None
            }
            "--flush" => Some(Action::Flush),
            "--rotate" => Some(Action::Rotate),
            "--relinquish-var" => Some(Action::RelinquishVar),
            "--smart-relinquish-var" => Some(Action::SmartRelinquishVar),
            "--dump-catalog" => Some(Action::DumpCatalog),
            _ if arg.starts_with("--vacuum-size=") => {
                let value = &arg["--vacuum-size=".len()..];
                Some(Action::VacuumSize(parse_size(value)?))
            }
            "--vacuum-size" => {
                return Err(JournaldError::InvalidArgument(
                    "missing value for --vacuum-size=SIZE".to_string(),
                ))
            }
            _ if arg.starts_with('-') => {
                return Err(JournaldError::InvalidArgument(format!(
                    "unrecognized option: {arg}"
                )))
            }
            _ => {
                return Err(JournaldError::InvalidArgument(format!(
                    "unexpected positional argument: {arg}"
                )))
            }
        };

        if let Some(next) = next {
            if action.replace(next).is_some() {
                return Err(JournaldError::InvalidArgument(
                    "only one journald action can be selected at a time".to_string(),
                ));
            }
        }
    }

    if help && version {
        return Err(JournaldError::InvalidArgument(
            "--help and --version are mutually exclusive".to_string(),
        ));
    }

    if help {
        return Ok(Mode::Help);
    }
    if version {
        return Ok(Mode::Version);
    }

    Ok(match action {
        Some(action) => Mode::Action(action),
        None => Mode::Daemon,
    })
}

pub fn execute(mode: Mode, runtime: &JournalRuntime) -> Result<(), JournaldError> {
    match mode {
        Mode::Help | Mode::Version | Mode::Daemon => Ok(()),
        Mode::Action(Action::Flush) => runtime.flush(),
        Mode::Action(Action::Rotate) => {
            runtime.rotate()?;
            Ok(())
        }
        Mode::Action(Action::RelinquishVar) => runtime.relinquish_var(),
        Mode::Action(Action::SmartRelinquishVar) => {
            runtime.smart_relinquish_var()?;
            Ok(())
        }
        Mode::Action(Action::VacuumSize(limit)) => {
            runtime.vacuum_size(limit)?;
            Ok(())
        }
        Mode::Action(Action::DumpCatalog) => {
            let dump = runtime.dump_catalog()?;
            print!("{dump}");
            Ok(())
        }
    }
}

pub fn help_text() -> &'static str {
    "systemd-journald [NAMESPACE] [OPTIONS...]\n\n  -h --help                   Show this help\n     --version                Show package version\n     --dump-catalog           Dump the local journal catalog summary\n     --flush                  Flush runtime journal files to disk\n     --relinquish-var         Record relinquish of /var/log/journal\n     --smart-relinquish-var   Record relinquish when /var/log/journal is populated\n     --rotate                 Rotate the active runtime journal log\n     --vacuum-size=SIZE       Remove old rotated logs until under SIZE\n"
}

pub fn parse_size(text: &str) -> Result<u64, JournaldError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(JournaldError::ParseSize(
            "vacuum size cannot be empty".to_string(),
        ));
    }

    let mut digits = String::new();
    let mut suffix = String::new();
    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            if !suffix.is_empty() {
                return Err(JournaldError::ParseSize(format!(
                    "invalid vacuum size: {trimmed}"
                )));
            }
            digits.push(ch);
        } else {
            suffix.push(ch);
        }
    }

    let value: u64 = digits
        .parse()
        .map_err(|_| JournaldError::ParseSize(format!("invalid vacuum size: {trimmed}")))?;

    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024_u64.pow(4),
        "p" | "pb" | "pib" => 1024_u64.pow(5),
        "e" | "eb" | "eib" => 1024_u64.pow(6),
        _ => {
            return Err(JournaldError::ParseSize(format!(
                "unsupported vacuum size suffix: {trimmed}"
            )))
        }
    };

    value
        .checked_mul(multiplier)
        .ok_or_else(|| JournaldError::ParseSize(format!("vacuum size overflow: {trimmed}")))
}

#[path = "journald_runtime_record.rs"]
mod record;
use record::*;

#[path = "journald_runtime_client_context.rs"]
mod client_context;
use client_context::*;

#[cfg(test)]
#[path = "journald_runtime_tests.rs"]
mod tests;
