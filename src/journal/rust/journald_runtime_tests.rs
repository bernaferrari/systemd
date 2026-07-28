use super::*;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::IntoRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir {
    path: PathBuf,
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    /// # Safety
    ///
    /// The caller must ensure that no other thread reads or mutates the process
    /// environment until the returned guard is dropped.
    unsafe fn set(key: &'static str, value: &str) -> Self {
        let previous = env::var_os(key);
        // SAFETY: this test-only guard scopes each mutation and the journald
        // test target is run without concurrent environment access.
        unsafe { env::set_var(key, value) };
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            // SAFETY: dropping the guard restores the same test-scoped mutation
            // while the test target has no concurrent environment access.
            unsafe { env::set_var(self.key, value) };
        } else {
            // SAFETY: dropping the guard restores the same test-scoped mutation
            // while the test target has no concurrent environment access.
            unsafe { env::remove_var(self.key) };
        }
    }
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn journal_text_at(path: &Path) -> String {
    render_journal_file_as_text(path).unwrap_or_default()
}

fn seed_journal_text_records(path: &Path, records: &[&str]) {
    let file_id = sd_id128_randomize().unwrap_or_else(|_| SdId128::null());
    let machine_id = sd_id128_get_machine().unwrap_or_else(|_| SdId128::null());
    let seqnum_id = sd_id128_randomize().unwrap_or_else(|_| SdId128::null());
    let mut journal = match open_journal_file_at(path, true) {
        Ok(journal) => journal,
        Err(err) if err.kind() == io::ErrorKind::NotFound => create_empty_journal_file_at(
            path,
            0o644,
            JOURNAL_FILE_SIZE_MIN,
            file_id,
            machine_id,
            seqnum_id,
            HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
            journal_incompatible_flags(),
        )
        .unwrap(),
        Err(err) => panic!("failed to open journal {}: {err}", path.display()),
    };

    for record in records {
        let owned_fields = record
            .split('|')
            .filter(|field| !field.is_empty())
            .map(|field| {
                if field.contains('=') {
                    field.as_bytes().to_vec()
                } else {
                    format!("MESSAGE={field}").into_bytes()
                }
            })
            .collect::<Vec<_>>();
        let field_refs = owned_fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        append_journal_record_unindexed(
            &mut journal.file,
            &mut journal.header,
            1,
            1,
            SdId128::null(),
            &field_refs,
        )
        .unwrap();
    }

    journal.file.sync_all().unwrap();
}

fn write_fake_proc_context(
    proc_root: &Path,
    pid: i32,
    cgroup: &str,
    command: &str,
    uid: u32,
    gid: u32,
) -> PathBuf {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(pid_dir.join("attr")).unwrap();
    fs::write(pid_dir.join("comm"), format!("{command}\n")).unwrap();
    fs::write(
        pid_dir.join("cmdline"),
        format!("{command}\0--flag\0value with space\0"),
    )
    .unwrap();
    fs::write(
        pid_dir.join("status"),
        format!(
            "Name:\t{command}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nCapEff:\t0000000000000001\n"
        ),
    )
    .unwrap();
    fs::write(pid_dir.join("cgroup"), format!("0::{}\n", cgroup)).unwrap();
    fs::write(pid_dir.join("loginuid"), format!("{uid}\n")).unwrap();
    fs::write(pid_dir.join("sessionid"), "5\n").unwrap();
    fs::write(
        pid_dir.join("attr/current"),
        "system_u:system_r:demo_t:s0\n",
    )
    .unwrap();

    let exe_target = proc_root.join(format!("{command}.exe"));
    fs::write(&exe_target, b"demo").unwrap();
    std::os::unix::fs::symlink(&exe_target, pid_dir.join("exe")).unwrap();
    exe_target
}

fn write_invocation_link(base: &Path, owner_uid: Option<u32>, unit: &str, id: &str) {
    let units_dir = if let Some(owner_uid) = owner_uid {
        base.join(owner_uid.to_string()).join("systemd/units")
    } else {
        base.join("units")
    };
    fs::create_dir_all(&units_dir).unwrap();
    std::os::unix::fs::symlink(id, units_dir.join(format!("invocation:{unit}"))).unwrap();
}

fn write_unit_runtime_symlink(base: &Path, prefix: &str, unit: &str, target: &str) {
    let units_dir = base.join("units");
    fs::create_dir_all(&units_dir).unwrap();
    std::os::unix::fs::symlink(target, units_dir.join(format!("{prefix}:{unit}"))).unwrap();
}

fn write_unit_extra_fields(base: &Path, unit: &str, fields: &[&[u8]]) {
    let units_dir = base.join("units");
    fs::create_dir_all(&units_dir).unwrap();
    let mut blob = Vec::new();
    for field in fields {
        blob.extend_from_slice(&(field.len() as u64).to_le_bytes());
        blob.extend_from_slice(field);
    }
    fs::write(units_dir.join(format!("log-extra-fields:{unit}")), blob).unwrap();
}

#[test]
fn parse_args_selects_actions() {
    assert_eq!(
        parse_args(["systemd-journald", "--flush"]).unwrap(),
        Mode::Action(Action::Flush)
    );
    assert_eq!(
        parse_args(["systemd-journald", "--rotate"]).unwrap(),
        Mode::Action(Action::Rotate)
    );
    assert_eq!(
        parse_args(["systemd-journald", "--vacuum-size=2K"]).unwrap(),
        Mode::Action(Action::VacuumSize(2048))
    );
    assert_eq!(parse_args(["systemd-journald"]).unwrap(), Mode::Daemon);
}

#[test]
fn parse_args_rejects_multiple_actions_and_bad_sizes() {
    assert!(matches!(
        parse_args(["systemd-journald", "--flush", "--rotate"]),
        Err(JournaldError::InvalidArgument(_))
    ));
    assert!(matches!(
        parse_args(["systemd-journald", "--vacuum-size=abc"]),
        Err(JournaldError::ParseSize(_))
    ));
}

#[test]
fn peer_rate_limiter_drops_bursts_and_emits_suppression_summary() {
    let mut limiter = PeerRateLimiter::new(RateLimitConfig {
        interval_usec: 1_000,
        burst: 2,
    });

    assert_eq!(
        limiter.check("peer-a", 6, 0, 1),
        RateLimitDecision::Allow { emit_suppressed: 0 }
    );
    assert_eq!(
        limiter.check("peer-a", 6, 0, 2),
        RateLimitDecision::Allow { emit_suppressed: 0 }
    );
    assert_eq!(limiter.check("peer-a", 6, 0, 3), RateLimitDecision::Drop);
    assert_eq!(limiter.check("peer-a", 6, 0, 4), RateLimitDecision::Drop);
    assert_eq!(
        limiter.check("peer-a", 6, 0, 1_100),
        RateLimitDecision::Allow { emit_suppressed: 2 }
    );
}

#[test]
fn peer_rate_limiter_splits_priority_buckets_per_key() {
    let mut limiter = PeerRateLimiter::new(RateLimitConfig {
        interval_usec: 1_000,
        burst: 1,
    });

    assert_eq!(
        limiter.check("unit-a.service", 6, 0, 10),
        RateLimitDecision::Allow { emit_suppressed: 0 }
    );
    assert_eq!(
        limiter.check("unit-a.service", 4, 0, 11),
        RateLimitDecision::Allow { emit_suppressed: 0 }
    );
    assert_eq!(
        limiter.check("unit-a.service", 6, 0, 12),
        RateLimitDecision::Drop
    );
}

#[test]
fn context_rate_limit_requires_unit_context() {
    let temp = TempDir::new("journald-unit-rate-limit");
    let runtime = JournalRuntime::new(temp.path.join("missing-root"));
    let mut limiter = PeerRateLimiter::new(RateLimitConfig {
        interval_usec: 60_000_000,
        burst: 1,
    });

    let no_unit = ClientContext::default();
    assert!(
        runtime
            .apply_context_rate_limit(&mut limiter, Some(&no_unit), 6)
            .unwrap()
    );
    assert!(
        runtime
            .apply_context_rate_limit(&mut limiter, Some(&no_unit), 6)
            .unwrap()
    );

    let with_unit = ClientContext {
        unit: Some("demo.service".to_string()),
        ..ClientContext::default()
    };
    assert!(
        runtime
            .apply_context_rate_limit(&mut limiter, Some(&with_unit), 6)
            .unwrap()
    );
    assert!(
        !runtime
            .apply_context_rate_limit(&mut limiter, Some(&with_unit), 6)
            .unwrap()
    );
}

#[test]
fn append_rate_limit_notice_writes_c_parity_fields() {
    let temp = TempDir::new("journald-rate-limit-marker");
    let runtime = JournalRuntime::new(&temp.path);

    runtime.append_rate_limit_notice("peer-a", 7).unwrap();
    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("_TRANSPORT=driver"));
    assert!(log.contains("PRIORITY=6"));
    assert!(log.contains("SYSLOG_IDENTIFIER=systemd-journald"));
    assert!(log.contains(&format!("MESSAGE_ID={SD_MESSAGE_JOURNAL_DROPPED_STR}")));
    assert!(log.contains("N_DROPPED=7"));
    assert!(log.contains("MESSAGE=Suppressed 7 messages from peer-a"));
}

#[test]
fn rate_limit_config_defaults_match_c() {
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _interval = unsafe { EnvVarGuard::set(RATE_LIMIT_INTERVAL_ENV, "invalid") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _burst = unsafe { EnvVarGuard::set(RATE_LIMIT_BURST_ENV, "invalid") };
    let cfg = RateLimitConfig::from_env();

    assert_eq!(cfg.interval_usec, 30_000_000);
    assert_eq!(cfg.burst, 10_000);
}

#[test]
fn rate_limit_config_zeroes_interval_and_burst_together_like_c() {
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _interval = unsafe { EnvVarGuard::set(RATE_LIMIT_INTERVAL_ENV, "0") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _burst = unsafe { EnvVarGuard::set(RATE_LIMIT_BURST_ENV, "1") };
    let cfg = RateLimitConfig::from_env();
    assert_eq!(cfg.interval_usec, 0);
    assert_eq!(cfg.burst, 0);

    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _interval = unsafe { EnvVarGuard::set(RATE_LIMIT_INTERVAL_ENV, "1") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _burst = unsafe { EnvVarGuard::set(RATE_LIMIT_BURST_ENV, "0") };
    let cfg = RateLimitConfig::from_env();
    assert_eq!(cfg.interval_usec, 0);
    assert_eq!(cfg.burst, 0);
}

#[test]
fn rate_limit_root_follows_active_storage_root() {
    let temp = TempDir::new("journald-rate-limit-root");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    assert_eq!(runtime.rate_limit_root(), temp.path);
    fs::write(runtime.marker_path(FLUSH_MARKER_NAME), b"ok\n").unwrap();
    assert_eq!(runtime.rate_limit_root(), persistent);
}

#[test]
fn storage_state_auto_defaults_to_runtime_root() {
    let temp = TempDir::new("journald-storage-auto-runtime");
    let runtime = JournalRuntime::new(&temp.path);
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent = unsafe {
        EnvVarGuard::set(
            STORAGE_PERSISTENT_ROOT_ENV,
            temp.path.join("persistent").to_str().unwrap(),
        )
    };

    let state = runtime.storage_state();
    assert_eq!(state.mode, StorageMode::Auto);
    assert_eq!(state.active_root(), Some(temp.path.as_path()));
}

#[test]
fn storage_state_auto_prefers_persistent_when_flushed_and_present() {
    let temp = TempDir::new("journald-storage-auto-persistent");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    fs::write(runtime.marker_path(FLUSH_MARKER_NAME), b"ok\n").unwrap();

    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    let state = runtime.storage_state();
    assert_eq!(state.active_root(), Some(persistent.as_path()));

    fs::write(
        runtime.marker_path(RELINQUISH_MARKER_NAME),
        b"relinquished\n",
    )
    .unwrap();
    let state = runtime.storage_state();
    assert_eq!(state.active_root(), Some(temp.path.as_path()));
}

#[test]
fn storage_state_persistent_mode_uses_persistent_root() {
    let temp = TempDir::new("journald-storage-persistent-mode");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "persistent") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    let state = runtime.storage_state();
    assert_eq!(state.mode, StorageMode::Persistent);
    assert_eq!(state.active_root(), Some(persistent.as_path()));
}

#[test]
fn default_with_namespace_derives_runtime_root_suffix() {
    let runtime = JournalRuntime::default_with_namespace(Some("tenant-a".to_string()));
    assert_eq!(runtime.root(), Path::new("/run/systemd/journal.tenant-a"));
    assert_eq!(runtime.namespace(), Some("tenant-a"));
}

#[test]
fn storage_state_namespaced_auto_prefers_persistent_without_flush_marker() {
    let temp = TempDir::new("journald-storage-namespaced-auto");
    let runtime =
        JournalRuntime::new_with_namespace(temp.path.join("runtime.ns"), Some("tenant".into()));
    let persistent = temp.path.join("persistent.ns");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    let state = runtime.storage_state();
    assert!(state.flushed);
    assert_eq!(state.active_root(), Some(persistent.as_path()));
}

#[test]
fn namespaced_flush_is_noop() {
    let temp = TempDir::new("journald-ns-flush-noop");
    let runtime =
        JournalRuntime::new_with_namespace(temp.path.join("runtime.ns"), Some("tenant".into()));
    let persistent = temp.path.join("persistent.ns");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    runtime.ensure_root().unwrap();
    seed_journal_text_records(&runtime.log_path(), &["namespaced-message"]);

    runtime.flush().unwrap();

    assert!(runtime.log_path().exists());
    assert!(!persistent.join(LOG_FILE_NAME).exists());
    assert!(!runtime.marker_path(FLUSH_MARKER_NAME).exists());
}

#[test]
fn namespaced_relinquish_var_is_noop() {
    let temp = TempDir::new("journald-ns-relinquish-noop");
    let runtime =
        JournalRuntime::new_with_namespace(temp.path.join("runtime.ns"), Some("tenant".into()));

    runtime.relinquish_var().unwrap();
    assert!(!runtime.marker_path(RELINQUISH_MARKER_NAME).exists());
    assert!(!runtime.smart_relinquish_var().unwrap());
}

#[test]
fn append_datagram_namespaced_emits_namespace_field() {
    let temp = TempDir::new("journald-ns-ingress-field");
    let runtime =
        JournalRuntime::new_with_namespace(temp.path.join("runtime.ns"), Some("tenant".into()));

    runtime.append_datagram(b"MESSAGE=hello\n", None).unwrap();
    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("_NAMESPACE=tenant"));
}

#[test]
fn append_syslog_datagram_enriches_ingress_fields() {
    let temp = TempDir::new("journald-syslog-ingress");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_syslog_datagram(b"  <13>Jan  1 12:00:00 app[123]: hello", None)
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("transport=syslog"));
    assert!(log.contains("PRIORITY=5"));
    assert!(log.contains("SYSLOG_FACILITY=1"));
    assert!(log.contains("SYSLOG_IDENTIFIER=app"));
    assert!(log.contains("SYSLOG_PID=123"));
    assert!(log.contains("SYSLOG_TIMESTAMP=Jan  1 12:00:00 "));
    assert!(log.contains("MESSAGE=hello"));
    assert!(log.contains("SYSLOG_RAW=  <13>Jan  1 12:00:00 app[123]: hello"));
}

#[test]
fn append_syslog_datagram_preserves_invalid_pid_suffix_and_internal_spaces() {
    let temp = TempDir::new("journald-syslog-invalid-pid");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_syslog_datagram_with_metadata(b"<13>Jan  1 12:00:00 app[abc]:  hello", None, None)
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("SYSLOG_IDENTIFIER=app"));
    assert!(!log.contains("SYSLOG_IDENTIFIER=app[abc]"));
    assert!(!log.contains("SYSLOG_PID="));
    assert!(log.contains("SYSLOG_TIMESTAMP=Jan  1 12:00:00 "));
    assert!(log.contains("MESSAGE= hello"));
    assert!(!log.contains("SYSLOG_RAW="));
}

#[test]
fn append_syslog_datagram_drops_overlong_identifier_but_keeps_pid() {
    let temp = TempDir::new("journald-syslog-long-ident");
    let runtime = JournalRuntime::new(&temp.path);
    let long_ident = "a".repeat(SYSLOG_IDENTIFIER_MAX + 1);
    let payload = format!("<13>{long_ident}[123]: hello");

    runtime
        .append_syslog_datagram_with_metadata(payload.as_bytes(), None, None)
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(!log.contains("SYSLOG_IDENTIFIER="));
    assert!(log.contains("SYSLOG_PID=123"));
    assert!(log.contains("MESSAGE=hello"));
}

#[test]
fn append_datagram_syslog_like_payload_is_rejected_on_native_socket() {
    let temp = TempDir::new("journald-native-raw-syslog");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_datagram(b"<13>Jan  1 12:00:00 app[123]: hello", None)
        .unwrap();

    assert!(!runtime.log_path().exists());
}

#[test]
fn append_datagram_kmsg_like_payload_is_rejected_on_native_socket() {
    let temp = TempDir::new("journald-kmsg-ingress");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_datagram(b"9,4,500,-;kernel hello\n", None)
        .unwrap();

    assert!(!runtime.log_path().exists());
}

#[test]
fn append_syslog_datagram_invalid_timestamp_sets_syslog_raw() {
    let temp = TempDir::new("journald-syslog-raw");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_syslog_datagram(b"<13>NotAMonth 1 12:00:00 app: hello", None)
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("SYSLOG_RAW=<13>NotAMonth 1 12:00:00 app: hello"));
}

#[test]
fn append_ingress_payload_dev_kmsg_enriches_kernel_fields() {
    let temp = TempDir::new("journald-kmsg-seq");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_ingress_payload(
            b"6,9,500,-;kernel hello\n",
            None,
            None,
            IngressSource::DevKmsg,
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("transport=kernel"));
    assert!(log.contains("PRIORITY=6"));
    assert!(log.contains("SYSLOG_FACILITY=0"));
    assert!(log.contains("_KERNEL_SEQNUM=9"));
    assert!(log.contains("_SOURCE_BOOTTIME_TIMESTAMP=500"));
    assert!(log.contains("_SOURCE_MONOTONIC_TIMESTAMP=500"));
    assert!(log.contains("SYSLOG_IDENTIFIER=kernel"));
}

#[test]
fn kmsg_sequence_tracker_drops_older_and_reports_gaps() {
    let mut tracker = KmsgSequenceTracker::default();
    let first = classify_ingress(b"6,10,1,-;first\n", None, IngressSource::DevKmsg).unwrap();
    let second = classify_ingress(b"6,12,2,-;second\n", None, IngressSource::DevKmsg).unwrap();
    let stale = classify_ingress(b"6,11,3,-;stale\n", None, IngressSource::DevKmsg).unwrap();

    assert_eq!(
        tracker.check(&first),
        KmsgSequenceDecision::Allow { emit_missed: 0 }
    );
    assert_eq!(
        tracker.check(&second),
        KmsgSequenceDecision::Allow { emit_missed: 1 }
    );
    assert_eq!(tracker.check(&stale), KmsgSequenceDecision::Drop);
}

#[test]
fn kmsg_sequence_tracker_drop_does_not_rewind_next_expected() {
    let mut tracker = KmsgSequenceTracker::with_next_expected(Some(13));
    let stale = classify_ingress(b"6,11,1,-;stale\n", None, IngressSource::DevKmsg).unwrap();

    assert_eq!(tracker.check(&stale), KmsgSequenceDecision::Drop);
    assert_eq!(tracker.next_expected(), Some(13));
}

#[test]
fn process_dev_kmsg_record_persists_next_expected_seqnum() {
    let temp = TempDir::new("journald-kmsg-seqnum-file");
    let runtime = JournalRuntime::new(&temp.path);
    let mut tracker = KmsgSequenceTracker::default();

    runtime
        .process_dev_kmsg_record(b"6,9,500,-;kernel hello\n", &mut tracker)
        .unwrap();
    assert_eq!(runtime.load_kernel_seqnum(), Some(10));

    runtime
        .process_dev_kmsg_record(b"6,12,501,-;kernel jump\n", &mut tracker)
        .unwrap();
    assert_eq!(runtime.load_kernel_seqnum(), Some(13));

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("kmsg_missed=2"));
}

#[test]
fn append_datagram_audit_like_payload_stays_untrusted_on_socket_path() {
    let temp = TempDir::new("journald-audit-ingress");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_datagram(
            b"audit(1700000000.123:42): pid=1001 uid=1000 gid=1000 exe=\"/bin/ls\" msg='cwd=\"/\" cmd=ls'",
            None,
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("transport=raw"));
    assert!(!log.contains("transport=audit"));
    assert!(!log.contains("_AUDIT_ID=42"));
    assert!(!log.contains("_AUDIT_TYPE="));
}

#[test]
fn append_audit_netlink_payload_maps_core_fields() {
    let temp = TempDir::new("journald-audit-ingress");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_audit_netlink_payload(
            b"audit(1700000000.123:42): pid=1001 uid=1000 gid=1000 exe=\"/bin/ls\" msg='cwd=\"/\" cmd=ls'",
            1300,
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("transport=audit"));
    assert!(log.contains("PRIORITY=5"));
    assert!(log.contains("SYSLOG_FACILITY=4"));
    assert!(log.contains("SYSLOG_IDENTIFIER=audit"));
    assert!(log.contains("_AUDIT_ID=42"));
    assert!(log.contains("_AUDIT_TYPE=1300"));
    assert!(log.contains("_AUDIT_TYPE_NAME=AUDIT_SYSCALL"));
    assert!(log.contains("MESSAGE=AUDIT_SYSCALL pid=1001 uid=1000 gid=1000"));
    assert!(log.contains("_PID=1001"));
    assert!(log.contains("_UID=1000"));
    assert!(log.contains("_GID=1000"));
    assert!(log.contains("_EXE=/bin/ls"));
    assert!(log.contains("AUDIT_FIELD_CWD=/"));
}

#[test]
fn append_audit_netlink_payload_uses_netlink_type_not_payload_hint() {
    let temp = TempDir::new("journald-audit-netlink-type");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_audit_netlink_payload(
            b"audit(1700000000.123:42): type=USER_AUTH pid=1001 uid=1000 gid=1000",
            1300,
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("transport=audit"));
    assert!(log.contains("_AUDIT_ID=42"));
    assert!(log.contains("_AUDIT_TYPE=1300"));
    assert!(log.contains("_AUDIT_TYPE_NAME=AUDIT_SYSCALL"));
    assert!(log.contains("MESSAGE=AUDIT_SYSCALL type=USER_AUTH pid=1001 uid=1000 gid=1000"));
    assert!(log.contains("_PID=1001"));
    assert!(log.contains("_UID=1000"));
    assert!(log.contains("_GID=1000"));
    assert!(log.contains("_AUDIT_FIELD_TYPE=USER_AUTH"));
}

#[test]
fn append_audit_netlink_payload_drops_malformed_records() {
    let temp = TempDir::new("journald-audit-netlink-malformed");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_audit_netlink_payload(b"type=SYSCALL msg=not-audit-header", 1300)
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(!log.contains("transport=audit"));
}

#[test]
fn audit_sender_validation_accepts_only_kernel_sender() {
    assert!(is_valid_kernel_audit_sender(Some(0), Some(0)));
    assert!(!is_valid_kernel_audit_sender(Some(1), Some(0)));
    assert!(!is_valid_kernel_audit_sender(Some(0), Some(1)));
    assert!(!is_valid_kernel_audit_sender(None, Some(0)));
    assert!(!is_valid_kernel_audit_sender(Some(0), None));
}

#[test]
fn parse_audit_netlink_datagram_rejects_malformed_header() {
    let bad = [0_u8; 8];
    assert!(parse_audit_netlink_datagram(&bad, bad.len()).is_none());
}

#[test]
fn parse_audit_netlink_datagram_accepts_valid_payload() {
    let payload = b"audit(1700000000.123:42): pid=1001 uid=1000";
    let header_len = nlmsg_align(std::mem::size_of::<NetlinkMessageHeader>());
    let total_len = header_len + payload.len();
    let mut buffer = vec![0_u8; total_len];
    let header = NetlinkMessageHeader {
        nlmsg_len: total_len as u32,
        nlmsg_type: 1300,
        nlmsg_flags: 0,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    // SAFETY: buffer has at least one full header and write_unaligned
    // avoids imposing an alignment requirement on Vec<u8>.
    unsafe {
        std::ptr::write_unaligned(buffer.as_mut_ptr().cast::<NetlinkMessageHeader>(), header);
    }
    buffer[header_len..total_len].copy_from_slice(payload);

    let Some((msg_type, payload_range)) = parse_audit_netlink_datagram(&buffer, buffer.len())
    else {
        panic!("expected valid netlink payload");
    };
    assert_eq!(msg_type, 1300);
    assert_eq!(&buffer[payload_range], payload);
}

#[test]
fn parse_audit_netlink_datagram_rejects_control_types() {
    let payload = b"audit(1700000000.123:42): pid=1001 uid=1000";
    let header_len = nlmsg_align(std::mem::size_of::<NetlinkMessageHeader>());
    let total_len = header_len + payload.len();

    for msg_type in [NLMSG_NOOP_TYPE, NLMSG_ERROR_TYPE] {
        let mut buffer = vec![0_u8; total_len];
        let header = NetlinkMessageHeader {
            nlmsg_len: total_len as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        // SAFETY: buffer has at least one full header and write_unaligned
        // avoids imposing an alignment requirement on Vec<u8>.
        unsafe {
            std::ptr::write_unaligned(buffer.as_mut_ptr().cast::<NetlinkMessageHeader>(), header);
        }
        buffer[header_len..total_len].copy_from_slice(payload);
        assert!(parse_audit_netlink_datagram(&buffer, buffer.len()).is_none());
    }
}

#[test]
fn parse_audit_netlink_datagram_rejects_non_user_control_messages() {
    let payload = b"audit(1700000000.123:42): pid=1001 uid=1000";
    let header_len = nlmsg_align(std::mem::size_of::<NetlinkMessageHeader>());
    let total_len = header_len + payload.len();
    let mut buffer = vec![0_u8; total_len];
    let header = NetlinkMessageHeader {
        nlmsg_len: total_len as u32,
        nlmsg_type: AUDIT_FIRST_USER_MSG - 1,
        nlmsg_flags: 0,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    // SAFETY: buffer has at least one full header and write_unaligned
    // avoids imposing an alignment requirement on Vec<u8>.
    unsafe {
        std::ptr::write_unaligned(buffer.as_mut_ptr().cast::<NetlinkMessageHeader>(), header);
    }
    buffer[header_len..total_len].copy_from_slice(payload);
    assert!(parse_audit_netlink_datagram(&buffer, buffer.len()).is_none());
}

#[test]
fn parse_audit_netlink_datagram_accepts_audit_user_type() {
    let payload = b"audit(1700000000.123:42): pid=1001 uid=1000";
    let header_len = nlmsg_align(std::mem::size_of::<NetlinkMessageHeader>());
    let total_len = header_len + payload.len();
    let mut buffer = vec![0_u8; total_len];
    let header = NetlinkMessageHeader {
        nlmsg_len: total_len as u32,
        nlmsg_type: AUDIT_USER_TYPE,
        nlmsg_flags: 0,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    // SAFETY: buffer has at least one full header and write_unaligned
    // avoids imposing an alignment requirement on Vec<u8>.
    unsafe {
        std::ptr::write_unaligned(buffer.as_mut_ptr().cast::<NetlinkMessageHeader>(), header);
    }
    buffer[header_len..total_len].copy_from_slice(payload);

    let Some((msg_type, payload_range)) = parse_audit_netlink_datagram(&buffer, buffer.len())
    else {
        panic!("expected AUDIT_USER type to be accepted");
    };
    assert_eq!(msg_type, AUDIT_USER_TYPE);
    assert_eq!(&buffer[payload_range], payload);
}

#[test]
fn append_datagram_with_credentials_emits_trusted_fields() {
    let temp = TempDir::new("journald-cred-ingress");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_syslog_datagram_with_metadata(
            b"<13>app[123]: hello",
            Some(Path::new("/tmp/client.sock")),
            Some(PeerCredentials {
                pid: 4242,
                uid: 1000,
                gid: 1001,
            }),
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("_PID=4242"));
    assert!(log.contains("_UID=1000"));
    assert!(log.contains("_GID=1001"));
    assert!(log.contains("SYSLOG_PID=123"));
}

#[test]
fn append_datagram_with_credentials_enriches_proc_and_cgroup_fields() {
    let temp = TempDir::new("journald-context-enrichment");
    let proc_root = temp.path.join("proc");
    let run_systemd_root = temp.path.join("run-systemd");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&run_systemd_root).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _proc = unsafe { EnvVarGuard::set(PROC_ROOT_ENV, proc_root.to_str().unwrap()) };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _run_systemd =
        unsafe { EnvVarGuard::set(RUN_SYSTEMD_ROOT_ENV, run_systemd_root.to_str().unwrap()) };

    let pid = 4242;
    let exe_target = write_fake_proc_context(
        &proc_root,
        pid,
        "/system.slice/demo.service",
        "demo",
        1000,
        1001,
    );
    write_invocation_link(
        &run_systemd_root,
        None,
        "demo.service",
        "0123456789abcdef0123456789abcdef",
    );

    let runtime = JournalRuntime::new(&temp.path);
    runtime
        .append_syslog_datagram_with_metadata(
            b"<13>app[123]: hello",
            Some(Path::new("/tmp/client.sock")),
            Some(PeerCredentials {
                pid,
                uid: 1000,
                gid: 1001,
            }),
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("_COMM=demo"));
    assert!(log.contains(&format!("_EXE={}", exe_target.display())));
    assert!(log.contains("_CMDLINE=demo --flag 'value with space'"));
    assert!(log.contains("_CAP_EFFECTIVE=0000000000000001"));
    assert!(log.contains("_SELINUX_CONTEXT=system_u:system_r:demo_t:s0"));
    assert!(log.contains("_AUDIT_SESSION=5"));
    assert!(log.contains("_AUDIT_LOGINUID=1000"));
    assert!(log.contains("_SYSTEMD_CGROUP=/system.slice/demo.service"));
    assert!(log.contains("_SYSTEMD_UNIT=demo.service"));
    assert!(log.contains("_SYSTEMD_SLICE=system.slice"));
    assert!(log.contains("_SYSTEMD_INVOCATION_ID=0123456789abcdef0123456789abcdef"));
}

#[test]
fn append_syslog_datagram_with_socket_metadata_refreshes_cached_selinux_label() {
    let temp = TempDir::new("journald-socket-label-refresh");
    let proc_root = temp.path.join("proc");
    fs::create_dir_all(&proc_root).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _proc = unsafe { EnvVarGuard::set(PROC_ROOT_ENV, proc_root.to_str().unwrap()) };

    let pid = 4242;
    write_fake_proc_context(
        &proc_root,
        pid,
        "/system.slice/demo.service",
        "demo",
        1000,
        1001,
    );

    let runtime = JournalRuntime::new(&temp.path);
    let creds = Some(PeerCredentials {
        pid,
        uid: 1000,
        gid: 1001,
    });

    runtime
        .append_syslog_datagram_with_metadata(
            b"<13>app[123]: proc label",
            Some(Path::new("/tmp/client.sock")),
            creds,
        )
        .unwrap();
    runtime
        .append_socket_datagram_with_metadata(
            b"<13>app[123]: socket label",
            Some(Path::new("/tmp/client.sock")),
            DatagramMetadata {
                creds,
                source_realtime_timestamp_usec: Some(1_234_567),
                selinux_label: Some("system_u:system_r:socket_t:s0".to_string()),
            },
            IngressSource::SyslogSocketDatagram,
            None,
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    let proc_line = log
        .lines()
        .find(|line| line.contains("MESSAGE=proc label"))
        .unwrap();
    assert!(proc_line.contains("_SELINUX_CONTEXT=system_u:system_r:demo_t:s0"));

    let socket_line = log
        .lines()
        .find(|line| line.contains("MESSAGE=socket label"))
        .unwrap();
    assert!(socket_line.contains("_SELINUX_CONTEXT=system_u:system_r:socket_t:s0"));
    assert!(!socket_line.contains("_SELINUX_CONTEXT=system_u:system_r:demo_t:s0"));
    assert!(socket_line.contains("_SOURCE_REALTIME_TIMESTAMP=1234567"));
}

#[test]
fn append_datagram_with_credentials_parses_user_manager_cgroup_fields() {
    let temp = TempDir::new("journald-user-context");
    let proc_root = temp.path.join("proc");
    let run_systemd_root = temp.path.join("run-systemd");
    let run_user_root = temp.path.join("run-user");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&run_systemd_root).unwrap();
    fs::create_dir_all(&run_user_root).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _proc = unsafe { EnvVarGuard::set(PROC_ROOT_ENV, proc_root.to_str().unwrap()) };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _run_systemd =
        unsafe { EnvVarGuard::set(RUN_SYSTEMD_ROOT_ENV, run_systemd_root.to_str().unwrap()) };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _run_user = unsafe { EnvVarGuard::set(RUN_USER_ROOT_ENV, run_user_root.to_str().unwrap()) };

    let pid = 5252;
    write_fake_proc_context(
        &proc_root,
        pid,
        "/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service",
        "dbus-daemon",
        1000,
        1000,
    );
    write_invocation_link(
        &run_user_root,
        Some(1000),
        "dbus.service",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    let runtime = JournalRuntime::new(&temp.path);
    runtime
        .append_syslog_datagram_with_metadata(
            b"<13>dbus-daemon: hello",
            Some(Path::new("/tmp/client.sock")),
            Some(PeerCredentials {
                pid,
                uid: 1000,
                gid: 1000,
            }),
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("_SYSTEMD_OWNER_UID=1000"));
    assert!(log.contains("_SYSTEMD_UNIT=user@1000.service"));
    assert!(log.contains("_SYSTEMD_USER_UNIT=dbus.service"));
    assert!(log.contains("_SYSTEMD_SLICE=user-1000.slice"));
    assert!(log.contains("_SYSTEMD_USER_SLICE=app.slice"));
    assert!(log.contains("_SYSTEMD_INVOCATION_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}

#[test]
fn append_datagram_with_credentials_appends_unit_extra_fields() {
    let temp = TempDir::new("journald-context-extra-fields");
    let proc_root = temp.path.join("proc");
    let run_systemd_root = temp.path.join("run-systemd");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&run_systemd_root).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _proc = unsafe { EnvVarGuard::set(PROC_ROOT_ENV, proc_root.to_str().unwrap()) };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _run_systemd =
        unsafe { EnvVarGuard::set(RUN_SYSTEMD_ROOT_ENV, run_systemd_root.to_str().unwrap()) };

    let pid = 4343;
    write_fake_proc_context(
        &proc_root,
        pid,
        "/system.slice/demo.service",
        "demo",
        1000,
        1001,
    );
    write_unit_extra_fields(
        &run_systemd_root,
        "demo.service",
        &[
            b"MESSAGE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"DEPLOYMENT=blue",
            b"BINARY=\0line\n\xff",
        ],
    );

    let runtime = JournalRuntime::new(&temp.path);
    runtime
        .append_syslog_datagram_with_metadata(
            b"<13>app[123]: hello",
            Some(Path::new("/tmp/client.sock")),
            Some(PeerCredentials {
                pid,
                uid: 1000,
                gid: 1001,
            }),
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("MESSAGE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(log.contains("DEPLOYMENT=blue"));
    let records = read_journal_records(&runtime.log_path()).unwrap();
    assert!(
        records[0]
            .fields
            .iter()
            .any(|field| field.as_slice() == b"BINARY=\0line\n\xff")
    );
}

#[test]
fn append_datagram_with_credentials_honors_unit_log_level_max() {
    let temp = TempDir::new("journald-context-log-level-max");
    let proc_root = temp.path.join("proc");
    let run_systemd_root = temp.path.join("run-systemd");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&run_systemd_root).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _proc = unsafe { EnvVarGuard::set(PROC_ROOT_ENV, proc_root.to_str().unwrap()) };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _run_systemd =
        unsafe { EnvVarGuard::set(RUN_SYSTEMD_ROOT_ENV, run_systemd_root.to_str().unwrap()) };

    let pid = 4444;
    write_fake_proc_context(
        &proc_root,
        pid,
        "/system.slice/demo.service",
        "demo",
        1000,
        1001,
    );
    write_unit_runtime_symlink(&run_systemd_root, "log-level-max", "demo.service", "notice");

    let runtime = JournalRuntime::new(&temp.path);
    runtime
        .append_syslog_datagram_with_metadata(
            b"<14>app[123]: info message",
            Some(Path::new("/tmp/client.sock")),
            Some(PeerCredentials {
                pid,
                uid: 1000,
                gid: 1001,
            }),
        )
        .unwrap();
    runtime
        .append_syslog_datagram_with_metadata(
            b"<13>app[123]: notice message",
            Some(Path::new("/tmp/client.sock")),
            Some(PeerCredentials {
                pid,
                uid: 1000,
                gid: 1001,
            }),
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(!log.contains("MESSAGE=info message"));
    assert!(log.contains("MESSAGE=notice message"));
}

#[test]
fn client_context_check_keep_log_honors_allow_and_deny_patterns() {
    if dlopen_pcre2().is_err() {
        return;
    }

    let context = ClientContext {
        log_filter_allowed_patterns: Arc::new(vec![
            pattern_compile("keep", PatternCompileCase::Sensitive).unwrap(),
        ]),
        log_filter_denied_patterns: Arc::new(vec![
            pattern_compile("drop", PatternCompileCase::Sensitive).unwrap(),
        ]),
        ..Default::default()
    };

    assert!(!client_context_check_keep_log(Some(&context), "drop this"));
    assert!(client_context_check_keep_log(Some(&context), "keep this"));
    assert!(!client_context_check_keep_log(Some(&context), "other"));

    let deny_only = ClientContext {
        log_filter_denied_patterns: Arc::new(vec![
            pattern_compile("drop", PatternCompileCase::Sensitive).unwrap(),
        ]),
        ..Default::default()
    };
    assert!(client_context_check_keep_log(Some(&deny_only), "other"));
}

#[test]
#[cfg(target_os = "linux")]
fn append_datagram_with_credentials_applies_keep_log_filters() {
    use std::ffi::CString;

    if dlopen_pcre2().is_err() {
        return;
    }

    let temp = TempDir::new("journald-keep-log");
    let proc_root = temp.path.join("proc");
    let cgroup_root = temp.path.join("cgroup");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&cgroup_root).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _proc = unsafe { EnvVarGuard::set(PROC_ROOT_ENV, proc_root.to_str().unwrap()) };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _cgroup = unsafe { EnvVarGuard::set(CGROUP_FS_ROOT_ENV, cgroup_root.to_str().unwrap()) };

    let pid = 4242;
    write_fake_proc_context(
        &proc_root,
        pid,
        "/system.slice/demo.service",
        "demo",
        1000,
        1000,
    );

    let unit_dir = cgroup_root.join("system.slice").join("demo.service");
    fs::create_dir_all(&unit_dir).unwrap();
    let path = CString::new(unit_dir.as_os_str().as_bytes()).unwrap();
    let name = CString::new("user.journald_log_filter_patterns").unwrap();
    let value = b"keep\0\xffdrop";
    // SAFETY: path/name are live C strings and value exposes value.len()
    // readable bytes for setxattr.
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(rc, 0, "setxattr failed: {}", io::Error::last_os_error());

    let runtime = JournalRuntime::new(&temp.path);
    runtime
        .append_syslog_datagram_with_metadata(
            b"<13>app[123]: drop this",
            None,
            Some(PeerCredentials {
                pid,
                uid: 1000,
                gid: 1000,
            }),
        )
        .unwrap();
    runtime
        .append_syslog_datagram_with_metadata(
            b"<13>app[123]: keep this",
            None,
            Some(PeerCredentials {
                pid,
                uid: 1000,
                gid: 1000,
            }),
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    assert!(!log.contains("MESSAGE=drop this"));
    assert!(log.contains("MESSAGE=keep this"));
}

#[test]
fn append_stdout_stream_message_prefers_peer_selinux_label() {
    let temp = TempDir::new("journald-stdout-peer-label");
    let proc_root = temp.path.join("proc");
    fs::create_dir_all(&proc_root).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _proc = unsafe { EnvVarGuard::set(PROC_ROOT_ENV, proc_root.to_str().unwrap()) };

    let pid = 7777;
    write_fake_proc_context(
        &proc_root,
        pid,
        "/system.slice/demo.service",
        "demo",
        1000,
        1000,
    );

    let runtime = JournalRuntime::new(&temp.path);
    let (stream, _peer) = UnixStream::pair().unwrap();
    let mut connection = StdoutStreamConnection::new(stream).unwrap();
    connection.creds = Some(PeerCredentials {
        pid,
        uid: 1000,
        gid: 1000,
    });
    connection.selinux_label = Some("system_u:system_r:stdout_t:s0".to_string());
    connection.identifier = Some("demo".to_string());

    runtime
        .append_stdout_stream_message(
            &connection,
            b"stdout message",
            StdoutLineBreak::Newline,
            None,
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    let line = log
        .lines()
        .find(|line| line.contains("MESSAGE=stdout message"))
        .unwrap();
    assert!(line.contains("_SELINUX_CONTEXT=system_u:system_r:stdout_t:s0"));
    assert!(!line.contains("_SELINUX_CONTEXT=system_u:system_r:demo_t:s0"));
}

#[test]
#[cfg(target_os = "linux")]
fn recv_datagram_with_metadata_extracts_source_realtime_timestamp() {
    let temp = TempDir::new("journald-recv-metadata");
    let receiver_path = temp.path.join("receiver.sock");
    let sender_path = temp.path.join("sender.sock");

    let runtime = JournalRuntime::new(&temp.path);
    let receiver = UnixDatagram::bind(&receiver_path).unwrap();
    runtime.configure_daemon_datagram_socket(&receiver).unwrap();
    let sender = UnixDatagram::bind(&sender_path).unwrap();
    sender.send_to(b"hello", &receiver_path).unwrap();

    let mut buf = [0_u8; 64];
    let (n, peer, metadata) = recv_datagram_with_metadata(&receiver, &mut buf).unwrap();

    assert_eq!(&buf[..n], b"hello");
    assert_eq!(peer.as_deref(), Some(sender_path.as_path()));
    assert!(metadata.creds.is_some());
    assert!(metadata.source_realtime_timestamp_usec.is_some());
}

#[test]
fn append_datagram_preserves_binary_native_field_bytes() {
    let temp = TempDir::new("journald-native-binary");
    let runtime = JournalRuntime::new(&temp.path);
    let value = b"\0line one\nline two\r\t|%\xff";
    let mut payload = b"MESSAGE\n".to_vec();
    payload.extend_from_slice(&(value.len() as u64).to_le_bytes());
    payload.extend_from_slice(value);
    payload.push(b'\n');

    runtime.append_datagram(&payload, None).unwrap();

    let records = read_journal_records(&runtime.log_path()).unwrap();
    let expected = [b"MESSAGE=".as_slice(), value].concat();
    assert_eq!(records.len(), 1);
    assert!(
        records[0]
            .fields
            .iter()
            .any(|field| field.as_slice() == expected.as_slice())
    );
}

#[test]
fn append_datagram_writes_multiple_native_entries_independently() {
    let temp = TempDir::new("journald-native-multiple-entries");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_datagram_with_metadata(
            b"MESSAGE=first\nPRIORITY=6\n\nMESSAGE=second\nPRIORITY=3\n",
            None,
            Some(PeerCredentials {
                pid: 42,
                uid: 1000,
                gid: 1001,
            }),
        )
        .unwrap();

    let records = read_journal_records(&runtime.log_path()).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records[0]
            .fields
            .iter()
            .any(|field| field.as_slice() == b"MESSAGE=first")
    );
    assert!(
        !records[0]
            .fields
            .iter()
            .any(|field| field.as_slice() == b"MESSAGE=second")
    );
    assert!(
        records[1]
            .fields
            .iter()
            .any(|field| field.as_slice() == b"MESSAGE=second")
    );
    assert!(
        !records[1]
            .fields
            .iter()
            .any(|field| field.as_slice() == b"MESSAGE=first")
    );
    for record in &records {
        assert!(
            record
                .fields
                .iter()
                .any(|field| field.as_slice() == b"_PID=42")
        );
        assert!(
            record
                .fields
                .iter()
                .any(|field| field.as_slice() == b"_UID=1000")
        );
    }
}

#[test]
fn native_datagram_rate_limits_each_entry() {
    let temp = TempDir::new("journald-native-entry-rate-limit");
    let runtime = JournalRuntime::new(&temp.path);
    let context = ClientContext {
        unit: Some("demo.service".to_string()),
        ..ClientContext::default()
    };
    let mut limiter = PeerRateLimiter::new(RateLimitConfig {
        interval_usec: 60_000_000,
        burst: 1,
    });

    for parsed in classify_native_datagram(b"MESSAGE=first\n\nMESSAGE=second\n", None) {
        runtime
            .append_socket_ingress_record(
                b"MESSAGE=first\n\nMESSAGE=second\n",
                None,
                None,
                parsed.unwrap(),
                Some(&context),
                None,
                Some(&mut limiter),
            )
            .unwrap();
    }

    let records = read_journal_records(&runtime.log_path()).unwrap();
    assert_eq!(records.len(), 1);
    assert!(
        records[0]
            .fields
            .iter()
            .any(|field| field.as_slice() == b"MESSAGE=first")
    );
}

#[test]
fn append_datagram_keeps_earlier_native_entry_when_later_entry_is_malformed() {
    let temp = TempDir::new("journald-native-malformed-later-entry");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_datagram(b"MESSAGE=first\n\nMESSAGE=truncated", None)
        .unwrap();

    let records = read_journal_records(&runtime.log_path()).unwrap();
    assert_eq!(records.len(), 1);
    assert!(
        records[0]
            .fields
            .iter()
            .any(|field| field.as_slice() == b"MESSAGE=first")
    );
    assert!(
        !records[0]
            .fields
            .iter()
            .any(|field| field.as_slice() == b"MESSAGE=truncated")
    );
}

#[test]
fn append_datagram_rejects_truncated_binary_native_field() {
    let temp = TempDir::new("journald-native-binary-truncated");
    let runtime = JournalRuntime::new(&temp.path);
    let mut payload = b"MESSAGE\n".to_vec();
    payload.extend_from_slice(&4u64.to_le_bytes());
    payload.extend_from_slice(b"abc");

    runtime.append_datagram(&payload, None).unwrap();

    assert!(!runtime.log_path().exists());
}

#[test]
fn append_datagram_native_object_pid_requires_root_sender() {
    let temp = TempDir::new("journald-native-object-pid");
    let runtime = JournalRuntime::new(&temp.path);
    let payload = b"MESSAGE=hello\nOBJECT_PID=222\n";

    runtime
        .append_datagram_with_metadata(
            payload,
            None,
            Some(PeerCredentials {
                pid: 42,
                uid: 1000,
                gid: 1000,
            }),
        )
        .unwrap();

    runtime
        .append_datagram_with_metadata(
            payload,
            None,
            Some(PeerCredentials {
                pid: 1,
                uid: 0,
                gid: 0,
            }),
        )
        .unwrap();

    let log = journal_text_at(&runtime.log_path());
    let mut lines = log.lines();
    let first = lines.next().unwrap_or_default();
    let second = lines.next().unwrap_or_default();
    assert!(first.contains("OBJECT_PID=222"));
    assert!(second.contains("OBJECT_PID=222"));
}

#[test]
fn daemon_loop_exits_on_shutdown_and_cleans_sockets() {
    let temp = TempDir::new("journald-shutdown");
    let runtime = JournalRuntime::new(&temp.path);
    let runtime_thread = runtime.clone();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_in_thread = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        runtime_thread.run_daemon_loop(|| stop_in_thread.load(Ordering::SeqCst))
    });

    for _ in 0..100 {
        if runtime.socket_path().exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(runtime.socket_path().exists());
    assert!(runtime.dev_log_path().exists());
    assert!(runtime.stdout_path().exists());

    let client = UnixDatagram::unbound().unwrap();
    client
        .send_to(b"MESSAGE=test-shutdown", runtime.socket_path())
        .unwrap();

    stop.store(true, Ordering::SeqCst);
    assert!(handle.join().unwrap().is_ok());
    assert!(!runtime.socket_path().exists());
    assert!(!runtime.dev_log_path().exists());
    assert!(!runtime.stdout_path().exists());

    let log = journal_text_at(&runtime.log_path());
    assert!(log.contains("payload_hex"));
}

#[test]
fn stdout_stream_next_frame_marks_line_max_and_pid_change() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let mut connection = StdoutStreamConnection::new(stream).unwrap();
    connection.state = StdoutStreamState::Running;
    connection.buffer.extend_from_slice(b"abcdef");

    assert_eq!(
        connection.next_frame(4, None),
        Some((b"abcd".to_vec(), StdoutLineBreak::LineMax))
    );

    connection.buffer.extend_from_slice(b"gh");
    assert_eq!(
        connection.next_frame(
            DEFAULT_STDOUT_STREAM_LINE_MAX,
            Some(StdoutLineBreak::PidChange),
        ),
        Some((b"efgh".to_vec(), StdoutLineBreak::PidChange))
    );
}

#[test]
#[cfg(target_os = "linux")]
fn stdout_stream_connection_captures_peer_credentials() {
    let temp = TempDir::new("journald-stdout-peercred");
    let socket = temp.path.join("stdout.sock");
    let listener = UnixListener::bind(&socket).unwrap();

    let client = thread::spawn({
        let socket = socket.clone();
        move || UnixStream::connect(socket).unwrap()
    });

    let (stream, _) = listener.accept().unwrap();
    let connection = StdoutStreamConnection::new(stream).unwrap();
    let peer = connection
        .creds
        .expect("accepted stream should have peer creds");

    assert_eq!(peer.pid, std::process::id() as i32);
    assert_eq!(peer.uid, nix::unistd::geteuid().as_raw());
    assert_eq!(peer.gid, nix::unistd::getegid().as_raw());

    drop(connection);
    drop(client.join().unwrap());
}

#[test]
fn persist_stdout_stream_state_writes_c_parity_fields() {
    let temp = TempDir::new("journald-stdout-state");
    let runtime = JournalRuntime::new(&temp.path);
    let (stream, _peer) = UnixStream::pair().unwrap();
    let mut connection = StdoutStreamConnection::new(stream).unwrap();
    connection.state = StdoutStreamState::Running;
    connection.identifier = Some("svc".to_string());
    connection.unit_id = Some("demo.service".to_string());
    connection.priority = 13;
    connection.level_prefix = true;
    connection.forward_to_syslog = true;
    connection.forward_to_console = true;

    runtime
        .persist_stdout_stream_state(&mut connection)
        .unwrap();

    let state_file = connection.state_file.clone().unwrap();
    let text = fs::read_to_string(&state_file).unwrap();
    assert!(text.contains("# This is private data. Do not parse"));
    assert!(text.contains("PRIORITY=13"));
    assert!(text.contains("LEVEL_PREFIX=1"));
    assert!(text.contains("FORWARD_TO_SYSLOG=1"));
    assert!(text.contains("FORWARD_TO_KMSG=0"));
    assert!(text.contains("FORWARD_TO_CONSOLE=1"));
    assert!(text.contains("IDENTIFIER=svc"));
    assert!(text.contains("UNIT=demo.service"));
    assert!(text.contains("STREAM_ID="));
}

#[test]
fn restore_stdout_streams_loads_state_and_prunes_orphans() {
    let temp = TempDir::new("journald-stdout-restore");
    let runtime = JournalRuntime::new(&temp.path);
    fs::create_dir_all(runtime.stdout_streams_dir()).unwrap();

    let (stream, _peer) = UnixStream::pair().unwrap();
    let identity = socket_identity_from_fd(stream.as_raw_fd()).unwrap();
    let state_file = runtime
        .stdout_streams_dir()
        .join(format!("{}:{}", identity.0, identity.1));
    fs::write(
        &state_file,
        "# This is private data. Do not parse\nPRIORITY=11\nLEVEL_PREFIX=1\nFORWARD_TO_SYSLOG=1\nFORWARD_TO_KMSG=0\nFORWARD_TO_CONSOLE=1\nSTREAM_ID=restored-stream\nIDENTIFIER=svc\nUNIT=demo.service\n",
    )
    .unwrap();
    let orphan = runtime.stdout_streams_dir().join("999:999");
    fs::write(&orphan, "PRIORITY=6\n").unwrap();

    let restored = runtime
        .restore_stdout_streams(vec![stream.into_raw_fd()])
        .unwrap();

    assert_eq!(restored.len(), 1);
    let restored_stream = &restored[0];
    assert_eq!(restored_stream.state, StdoutStreamState::Running);
    assert_eq!(restored_stream.priority, 11);
    assert!(restored_stream.level_prefix);
    assert!(restored_stream.forward_to_syslog);
    assert!(!restored_stream.forward_to_kmsg);
    assert!(restored_stream.forward_to_console);
    assert_eq!(restored_stream.identifier.as_deref(), Some("svc"));
    assert_eq!(restored_stream.unit_id.as_deref(), Some("demo.service"));
    assert_eq!(restored_stream.stream_id, "restored-stream");
    assert!(!orphan.exists());
}

#[test]
fn rotate_moves_active_log_and_creates_new_one() {
    let temp = TempDir::new("journald-rotate");
    let runtime = JournalRuntime::new(&temp.path);

    seed_journal_text_records(&runtime.log_path(), &["before rotate"]);

    let report = runtime.rotate().unwrap();

    assert!(runtime.log_path().exists());
    assert_eq!(report.previous_log, runtime.log_path());
    assert_eq!(report.new_log, runtime.log_path());
    let archived = fs::read_dir(runtime.root())
        .unwrap()
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.ends_with(".journal")
                        && JournalRuntime::archived_rotation_metadata(name).is_some()
                })
        })
        .expect("rotated archived journal");
    let archived_text = journal_text_at(&archived);
    assert!(archived_text.contains("before rotate"));
    assert!(runtime.root().join(ROTATE_MARKER_NAME).exists());
}

#[test]
fn rotate_uses_persistent_root_when_flushed() {
    let temp = TempDir::new("journald-rotate-persistent");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    fs::write(runtime.marker_path(FLUSH_MARKER_NAME), b"ready\n").unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    let persistent_log = persistent.join(LOG_FILE_NAME);
    seed_journal_text_records(&persistent_log, &["before persistent rotate"]);
    let report = runtime.rotate().unwrap();

    assert_eq!(report.previous_log, persistent_log);
    assert_eq!(report.new_log, persistent.join(LOG_FILE_NAME));
    assert!(persistent.join(LOG_FILE_NAME).exists());
    assert!(
        fs::read_dir(&persistent)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|value| value.path()))
            .any(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| JournalRuntime::archived_rotation_metadata(name).is_some())
            })
    );
}

#[test]
fn rotate_applies_post_rotate_vacuum_limits() {
    let temp = TempDir::new("journald-rotate-vacuum");
    let runtime = JournalRuntime::new(&temp.path);
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _max_files = unsafe { EnvVarGuard::set(SYSTEM_MAX_FILES_ENV, "1") };

    seed_journal_text_records(&runtime.log_path(), &["before rotate"]);
    fs::write(
        runtime
            .root()
            .join(JournalRuntime::rotated_archive_name(1, 1)),
        vec![b'X'; 300],
    )
    .unwrap();
    fs::write(
        runtime
            .root()
            .join(JournalRuntime::rotated_archive_name(2, 2)),
        vec![b'X'; 300],
    )
    .unwrap();

    runtime.rotate().unwrap();

    let archived_count = fs::read_dir(runtime.root())
        .unwrap()
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| JournalRuntime::archived_rotation_metadata(name).is_some())
        })
        .count();
    assert!(archived_count <= 1, "archived_count={archived_count}");
}

#[test]
fn append_proactively_rotates_when_max_file_size_reached() {
    let temp = TempDir::new("journald-prewrite-rotate");
    let runtime = JournalRuntime::new(&temp.path);
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _max_file_size = unsafe { EnvVarGuard::set(SYSTEM_MAX_FILE_SIZE_ENV, "16") };

    seed_journal_text_records(&runtime.log_path(), &["0123456789abcdef0123456789abcdef"]);
    runtime
        .append_datagram(b"MESSAGE=after-threshold\n", None)
        .unwrap();

    let archived_count = fs::read_dir(runtime.root())
        .unwrap()
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| JournalRuntime::archived_rotation_metadata(name).is_some())
        })
        .count();
    assert_eq!(archived_count, 1);
    let active_log = journal_text_at(&runtime.log_path());
    assert!(active_log.contains("after-threshold"));
    assert!(runtime.root().join(ROTATE_MARKER_NAME).exists());
}

#[test]
fn new_journals_enable_keyed_hash_by_default() {
    let temp = TempDir::new("journald-keyed-hash-default");
    let runtime = JournalRuntime::new(&temp.path);

    let journal = runtime.active_or_create().unwrap();

    assert_ne!(
        journal.header.incompatible_flags & HEADER_INCOMPATIBLE_KEYED_HASH,
        0
    );
}

#[test]
fn keyed_hash_env_can_disable_new_journal_flag() {
    let temp = TempDir::new("journald-keyed-hash-disabled");
    let runtime = JournalRuntime::new(&temp.path);
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _keyed_hash = unsafe { EnvVarGuard::set(SYSTEMD_JOURNAL_KEYED_HASH_ENV, "0") };

    let journal = runtime.active_or_create().unwrap();

    assert_eq!(
        journal.header.incompatible_flags & HEADER_INCOMPATIBLE_KEYED_HASH,
        0
    );
}

#[test]
fn append_proactively_rotates_when_header_pressure_is_reached() {
    let temp = TempDir::new("journald-prewrite-rotate-structural");
    let runtime = JournalRuntime::new(&temp.path);

    seed_journal_text_records(&runtime.log_path(), &["before-threshold"]);
    let mut journal = open_journal_file_at(&runtime.log_path(), true).unwrap();
    journal.header.data_hash_chain_depth = 129;
    write_journal_header(&mut journal.file, &journal.header).unwrap();

    runtime
        .append_datagram(b"MESSAGE=after-structural-threshold\n", None)
        .unwrap();

    let archived_count = fs::read_dir(runtime.root())
        .unwrap()
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| JournalRuntime::archived_rotation_metadata(name).is_some())
        })
        .count();
    assert_eq!(archived_count, 1);
    let active_log = journal_text_at(&runtime.log_path());
    assert!(active_log.contains("after-structural-threshold"));
    assert!(runtime.root().join(ROTATE_MARKER_NAME).exists());
}

#[test]
fn vacuum_size_removes_old_rotations_first() {
    let temp = TempDir::new("journald-vacuum");
    let runtime = JournalRuntime::new(&temp.path);

    seed_journal_text_records(&runtime.log_path(), &["active"]);
    fs::write(
        runtime
            .root()
            .join(JournalRuntime::rotated_archive_name(1, 1)),
        vec![b'X'; 300],
    )
    .unwrap();
    fs::write(
        runtime
            .root()
            .join(JournalRuntime::rotated_archive_name(2, 2)),
        vec![b'X'; 300],
    )
    .unwrap();
    fs::write(
        runtime
            .root()
            .join(JournalRuntime::rotated_archive_name(3, 3)),
        vec![b'X'; 300],
    )
    .unwrap();

    let report = runtime.vacuum_size(8).unwrap();

    assert_eq!(report.removed_files.len(), 3);
    assert!(
        !runtime
            .root()
            .join(JournalRuntime::rotated_archive_name(1, 1))
            .exists()
    );
    assert!(
        !runtime
            .root()
            .join(JournalRuntime::rotated_archive_name(2, 2))
            .exists()
    );
    assert!(
        !runtime
            .root()
            .join(JournalRuntime::rotated_archive_name(3, 3))
            .exists()
    );
    assert!(runtime.log_path().exists());
}

#[test]
fn vacuum_size_targets_active_persistent_root_when_flushed() {
    let temp = TempDir::new("journald-vacuum-persistent-active");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };
    fs::write(runtime.root().join(FLUSH_MARKER_NAME), b"ready\n").unwrap();

    let runtime_archived = runtime
        .root()
        .join(JournalRuntime::rotated_archive_name(1, 1));
    fs::write(&runtime_archived, vec![b'X'; 300]).unwrap();
    let persistent_archived_1 = persistent.join(JournalRuntime::rotated_archive_name(1, 1));
    let persistent_archived_2 = persistent.join(JournalRuntime::rotated_archive_name(2, 2));
    fs::write(&persistent_archived_1, vec![b'X'; 300]).unwrap();
    fs::write(&persistent_archived_2, vec![b'X'; 300]).unwrap();

    let report = runtime.vacuum_size(1).unwrap();

    assert!(
        report
            .removed_files
            .iter()
            .all(|path| path.starts_with(&persistent))
    );
    assert!(runtime_archived.exists());
    assert!(!persistent_archived_1.exists());
    assert!(!persistent_archived_2.exists());
}

#[test]
fn append_and_dump_catalog_round_trip() {
    let temp = TempDir::new("journald-catalog");
    let runtime = JournalRuntime::new(&temp.path);

    runtime
        .append_datagram(b"MESSAGE_ID=abc123\nMESSAGE=hello world\n", None)
        .unwrap();

    let dump = runtime.dump_catalog().unwrap();
    assert!(dump.contains("MESSAGE_ID=abc123"));
    assert!(dump.contains("hello world"));
}

#[test]
fn smart_relinquish_var_is_noop_when_persistent_store_missing() {
    let temp = TempDir::new("journald-smart-relinquish");
    let runtime = JournalRuntime::new(&temp.path);

    assert!(!runtime.smart_relinquish_var().unwrap());
    assert!(!runtime.root().join(RELINQUISH_MARKER_NAME).exists());
}

#[test]
fn flush_moves_runtime_log_to_persistent_root() {
    let temp = TempDir::new("journald-flush-to-persistent");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    seed_journal_text_records(&runtime.log_path(), &["runtime-entry"]);
    runtime.flush().unwrap();

    assert!(persistent.join(LOG_FILE_NAME).exists());
    let persistent_log = journal_text_at(&persistent.join(LOG_FILE_NAME));
    assert!(persistent_log.contains("runtime-entry"));
    assert!(!runtime.log_path().exists());
    assert!(runtime.root().join(FLUSH_MARKER_NAME).exists());
}

#[test]
fn flush_with_required_flag_skips_when_marker_missing() {
    let temp = TempDir::new("journald-flush-requires-flag");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    seed_journal_text_records(&runtime.log_path(), &["runtime-entry"]);
    runtime.flush_to_persistent(true).unwrap();

    assert!(runtime.log_path().exists());
    assert!(!persistent.join(LOG_FILE_NAME).exists());
    assert!(!runtime.root().join(FLUSH_MARKER_NAME).exists());
}

#[test]
fn startup_housekeeping_honors_flush_gate() {
    let temp = TempDir::new("journald-startup-housekeeping");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    seed_journal_text_records(&runtime.log_path(), &["runtime-entry"]);
    runtime.run_startup_housekeeping().unwrap();
    assert!(runtime.log_path().exists());
    assert!(!persistent.join(LOG_FILE_NAME).exists());

    fs::write(runtime.root().join(FLUSH_MARKER_NAME), b"ready\n").unwrap();
    runtime.run_startup_housekeeping().unwrap();
    assert!(!runtime.log_path().exists());
    assert!(persistent.join(LOG_FILE_NAME).exists());
}

#[test]
fn startup_housekeeping_enforces_max_files_on_persistent_root() {
    let temp = TempDir::new("journald-startup-persistent-vacuum");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _max_files = unsafe { EnvVarGuard::set(SYSTEM_MAX_FILES_ENV, "1") };

    seed_journal_text_records(&runtime.log_path(), &["runtime-entry"]);
    fs::write(runtime.root().join(FLUSH_MARKER_NAME), b"ready\n").unwrap();
    let archived_1 = persistent.join(JournalRuntime::rotated_archive_name(1, 1));
    let archived_2 = persistent.join(JournalRuntime::rotated_archive_name(2, 2));
    fs::write(&archived_1, vec![b'X'; 300]).unwrap();
    fs::write(&archived_2, vec![b'X'; 300]).unwrap();

    runtime.run_startup_housekeeping().unwrap();

    assert!(persistent.join(LOG_FILE_NAME).exists());
    assert!(!archived_1.exists() || !archived_2.exists());
}

#[test]
fn relinquish_var_forces_runtime_root_for_subsequent_writes() {
    let temp = TempDir::new("journald-relinquish-routing");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    fs::write(runtime.marker_path(FLUSH_MARKER_NAME), b"ready\n").unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    runtime
        .append_datagram(b"MESSAGE=persistent-entry", None)
        .unwrap();
    runtime.relinquish_var().unwrap();
    runtime
        .append_datagram(b"MESSAGE=runtime-entry", None)
        .unwrap();

    let persistent_log = journal_text_at(&persistent.join(LOG_FILE_NAME));
    let runtime_log = journal_text_at(&runtime.log_path());
    assert!(persistent_log.contains("persistent-entry"));
    assert!(!persistent_log.contains("runtime-entry"));
    assert!(runtime_log.contains("runtime-entry"));
}

#[test]
fn reopen_clears_relinquish_and_restores_persistent_writes() {
    let temp = TempDir::new("journald-reopen-routing");
    let runtime = JournalRuntime::new(&temp.path);
    let persistent = temp.path.join("persistent");
    fs::create_dir_all(&persistent).unwrap();
    fs::write(runtime.marker_path(FLUSH_MARKER_NAME), b"ready\n").unwrap();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _mode = unsafe { EnvVarGuard::set(STORAGE_MODE_ENV, "auto") };
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let _persistent =
        unsafe { EnvVarGuard::set(STORAGE_PERSISTENT_ROOT_ENV, persistent.to_str().unwrap()) };

    runtime.relinquish_var().unwrap();
    runtime
        .append_datagram(b"MESSAGE=runtime-only", None)
        .unwrap();
    runtime.reopen().unwrap();
    runtime
        .append_datagram(b"MESSAGE=persistent-again", None)
        .unwrap();

    assert!(!runtime.marker_path(RELINQUISH_MARKER_NAME).exists());
    let persistent_log = journal_text_at(&persistent.join(LOG_FILE_NAME));
    assert!(persistent_log.contains("persistent-again"));
}

#[test]
fn append_with_rotate_retry_retries_once_on_retryable_error() {
    let temp = TempDir::new("journald-append-retry");
    let runtime = JournalRuntime::new(&temp.path);
    seed_journal_text_records(&runtime.log_path(), &["before retry"]);

    let mut fail_once = true;
    runtime
        .append_with_rotate_retry(|| {
            if fail_once {
                fail_once = false;
                return Err(JournaldError::Io(io::Error::from_raw_os_error(
                    libc::ENOSPC,
                )));
            }
            runtime.append_fields_to_active_log(&[b"MESSAGE=retry-success".to_vec()])
        })
        .unwrap();

    let active_log = journal_text_at(&runtime.log_path());
    assert!(active_log.contains("MESSAGE=retry-success"));
    assert!(runtime.root().join(ROTATE_MARKER_NAME).exists());
    assert!(
        fs::read_dir(runtime.root())
            .unwrap()
            .filter_map(|entry| entry.ok().map(|value| value.path()))
            .any(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| JournalRuntime::archived_rotation_metadata(name).is_some())
            })
    );
}
