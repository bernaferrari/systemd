// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/killall.c, src/shared/killall.h
//
// Process killing and signal broadcasting logic for system shutdown.
//
// Provides pure decision-making for determining which processes to ignore
// during shutdown (PID 1, kernel threads, root storage daemons, survivor
// cgroups), wait schedule computation, kill result tracking, and formatting
// of log messages for remaining children.
//
// Root storage daemons: https://systemd.io/ROOT_STORAGE_DAEMONS

// ── Constants ─────────────────────────────────────────────────────────────

pub const USEC_PER_SEC: u64 = 1_000_000;

/// Delay (in seconds) before first logging of remaining children.
/// Matches the 10-second initial delay in the C implementation.
pub const LOG_CHILDREN_INITIAL_DELAY_SEC: u64 = 10;

// ── Signal type ───────────────────────────────────────────────────────────

/// Signal to send during killall operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSignal {
    /// SIGTERM – graceful termination request.
    Term,
    /// SIGKILL – immediate forced termination.
    Kill,
}

impl KillSignal {
    /// Returns `true` if this is SIGKILL.
    pub fn is_kill(self) -> bool {
        matches!(self, Self::Kill)
    }
}

// ── Process info ──────────────────────────────────────────────────────────

/// Pre-collected metadata about a process, used for kill-decision logic.
///
/// Callers gather this information from `/proc` and other OS sources,
/// then pass it to [`ignore_proc`] for a pure decision.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: i32,
    pub is_kernel_thread: bool,
    pub uid: Option<u32>,
    /// `true` when `argv[0]` starts with `'@'` (root storage daemon marker).
    pub argv_has_at: bool,
    /// `true` when the process cgroup carries `user.survive_final_kill_signal`.
    pub in_survivor_cgroup: bool,
    /// `true` when the process has a controlling terminal.
    pub has_controlling_tty: bool,
    /// `true` when the process shares the same root file-system as us.
    pub same_root_fs: bool,
    /// Short command name from `/proc/<pid>/comm`, if available.
    pub comm: Option<String>,
}

// ── Ignore reason ─────────────────────────────────────────────────────────

/// Why a process was excluded from killing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    IsPid1,
    IsKernelThread,
    InSurvivorCgroup,
    UidUnknown,
    RootStorageDaemon,
}

// ── Ignore decision ───────────────────────────────────────────────────────

/// Outcome of [`ignore_proc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgnoreDecision {
    /// Whether the process should be excluded from killing.
    pub ignore: bool,
    /// When `ignore` is `true`, describes why.
    pub reason: Option<IgnoreReason>,
}

/// Determine whether a process should be ignored from killing during shutdown.
///
/// Processes are excluded when they are PID 1, kernel threads, members of a
/// survivor cgroup, or root storage daemons (`argv[0][0] == '@'`).  If the
/// UID cannot be determined the process is conservatively ignored.
///
/// When `warn_rootfs` is `true` and the process is a root storage daemon on
/// the root file-system, the caller should emit a warning (see
/// [`root_storage_daemon_warning`]).
pub fn ignore_proc(info: &ProcInfo, warn_rootfs: bool) -> IgnoreDecision {
    if info.pid == 1 {
        return IgnoreDecision {
            ignore: true,
            reason: Some(IgnoreReason::IsPid1),
        };
    }

    if info.is_kernel_thread {
        return IgnoreDecision {
            ignore: true,
            reason: Some(IgnoreReason::IsKernelThread),
        };
    }

    if info.in_survivor_cgroup {
        return IgnoreDecision {
            ignore: true,
            reason: Some(IgnoreReason::InSurvivorCgroup),
        };
    }

    let uid = match info.uid {
        Some(u) => u,
        None => {
            return IgnoreDecision {
                ignore: true,
                reason: Some(IgnoreReason::UidUnknown),
            };
        }
    };

    // Non-root processes are always subject to killing.
    if uid != 0 {
        return IgnoreDecision {
            ignore: false,
            reason: None,
        };
    }

    // Root process without the '@' marker → kill.
    if !info.argv_has_at {
        return IgnoreDecision {
            ignore: false,
            reason: None,
        };
    }

    // Root storage daemon – ignored.  The caller should log a warning when
    // `warn_rootfs` is set and the process lives on the root file-system.
    let _ = warn_rootfs && info.same_root_fs;

    IgnoreDecision {
        ignore: true,
        reason: Some(IgnoreReason::RootStorageDaemon),
    }
}

// ── Root-storage-daemon warning ───────────────────────────────────────────

/// Build the warning message for a root storage daemon on the root file-system.
///
/// Mirrors the `log_notice` in the C `ignore_proc`.
pub fn root_storage_daemon_warning(pid: i32, comm: Option<&str>) -> String {
    let name = comm.unwrap_or("unknown");
    format!(
        "Process {pid} ({name}) has been marked to be excluded from killing. \
         It is running from the root file system, and thus likely to block \
         re-mounting of the root file system to read-only. Please consider \
         moving it into an initrd file system instead."
    )
}

// ── SIGKILL notice ────────────────────────────────────────────────────────

/// Build the log message emitted before sending SIGKILL to a process.
pub fn sigkill_notice(pid: i32, comm: Option<&str>) -> String {
    let name = comm.unwrap_or("unknown");
    format!("Sending SIGKILL to PID {pid} ({name}).")
}

// ── should_warn_rootfs ────────────────────────────────────────────────────

/// Whether the `warn_rootfs` flag should be set when calling [`ignore_proc`].
///
/// Mirrors `sig == SIGKILL && !in_initrd()` in the C `killall()`.
pub fn should_warn_rootfs(signal: KillSignal, in_initrd: bool) -> bool {
    signal.is_kill() && !in_initrd
}

// ── SIGHUP decision ───────────────────────────────────────────────────────

/// Whether a supplementary SIGHUP should be sent after the primary signal.
///
/// SIGHUP is sent only to processes with a controlling terminal so that
/// shells which ignore SIGTERM still react.  It is *not* sent to daemons
/// without a TTY to avoid triggering unnecessary reloads.
pub fn should_send_sighup(has_controlling_tty: bool, send_sighup_flag: bool) -> bool {
    send_sighup_flag && has_controlling_tty
}

// ── Wait schedule ─────────────────────────────────────────────────────────

/// Computed time-points for the wait-for-children loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitSchedule {
    /// Absolute deadline (µs, monotonic clock).
    pub until_usec: u64,
    /// Absolute time at which remaining children should be logged.
    pub log_children_at_usec: u64,
}

/// Compute the wait schedule from the current time and a timeout.
///
/// The children-remaining log fires at `now + 10 s`, unless that would
/// exceed the deadline, in which case it fires at `now + timeout / 2`.
/// This matches the C `wait_for_children` logic.
pub fn compute_wait_schedule(now_usec: u64, timeout_usec: u64) -> WaitSchedule {
    let until_usec = now_usec.saturating_add(timeout_usec);
    let log_at_default = now_usec.saturating_add(LOG_CHILDREN_INITIAL_DELAY_SEC * USEC_PER_SEC);

    let log_children_at_usec = if log_at_default <= until_usec {
        log_at_default
    } else {
        now_usec.saturating_add(timeout_usec / 2)
    };

    WaitSchedule {
        until_usec,
        log_children_at_usec,
    }
}

/// Returns `true` when it is time to log the list of remaining children.
pub fn is_log_children_due(now_usec: u64, schedule: &WaitSchedule) -> bool {
    now_usec >= schedule.log_children_at_usec
}

/// Returns `true` when the overall wait deadline has passed.
pub fn is_timeout_elapsed(now_usec: u64, schedule: &WaitSchedule) -> bool {
    now_usec >= schedule.until_usec
}

/// Compute how long (µs) the caller should sleep before re-checking.
///
/// When the children log has not yet been emitted the sleep is capped so
/// the caller wakes up in time for it.
pub fn compute_sleep_duration(
    now_usec: u64,
    schedule: &WaitSchedule,
    log_children_done: bool,
) -> u64 {
    let remaining = schedule.until_usec.saturating_sub(now_usec);
    if log_children_done {
        return remaining;
    }
    let until_log = schedule.log_children_at_usec.saturating_sub(now_usec);
    remaining.min(until_log)
}

// ── Process-list formatting ───────────────────────────────────────────────

/// Format a list of `(pid, optional_comm)` pairs as a comma-separated string.
///
/// Each entry is rendered as `"PID (comm)"` when the comm is available or
/// `"PID"` otherwise.  Mirrors `log_children_not_yet_killed`.
pub fn format_remaining_processes<'a>(
    processes: impl IntoIterator<Item = (i32, Option<&'a str>)>,
) -> String {
    let parts: Vec<String> = processes
        .into_iter()
        .map(|(pid, comm)| match comm {
            Some(name) => format!("{pid} ({name})"),
            None => format!("{pid}"),
        })
        .collect();
    parts.join(", ")
}

// ── Kill result tracking ──────────────────────────────────────────────────

/// Accumulates the PIDs of processes that were successfully signalled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KillallResult {
    pids: Vec<i32>,
}

impl KillallResult {
    /// Create an empty result set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successfully killed PID.
    pub fn record_kill(&mut self, pid: i32) {
        self.pids.push(pid);
    }

    /// Number of processes successfully signalled.
    pub fn kill_count(&self) -> usize {
        self.pids.len()
    }

    /// Remove a PID (e.g. when `waitpid` or `kill(pid, 0)` reports it gone).
    /// Returns `true` if the PID was present.
    pub fn remove_pid(&mut self, pid: i32) -> bool {
        if let Some(pos) = self.pids.iter().position(|&p| p == pid) {
            self.pids.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Whether no processes remain.
    pub fn is_empty(&self) -> bool {
        self.pids.is_empty()
    }

    /// Number of processes still being tracked.
    pub fn remaining(&self) -> usize {
        self.pids.len()
    }

    /// Borrow the tracked PIDs.
    pub fn pids(&self) -> &[i32] {
        &self.pids
    }
}

// ── Broadcast config ──────────────────────────────────────────────────────

/// Configuration for a `broadcast_signal` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastConfig {
    pub signal: KillSignal,
    pub wait_for_exit: bool,
    pub send_sighup: bool,
    pub timeout_usec: u64,
}

/// The outcome of a `broadcast_signal` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastOutcome {
    /// Number of processes to which the signal was sent.
    pub killed: usize,
    /// Number of processes still alive after the timeout (0 when
    /// `wait_for_exit` is `false`).
    pub remaining: usize,
}

/// Given a `KillallResult` and the `wait_for_exit` flag, compute the
/// [`BroadcastOutcome`].
///
/// This is a pure helper so the caller can avoid repeating the "return
/// kill-count when not waiting" vs "return remaining-count when waiting"
/// branch.
pub fn compute_broadcast_outcome(killed: &KillallResult, wait_for_exit: bool) -> BroadcastOutcome {
    if wait_for_exit {
        BroadcastOutcome {
            killed: killed.kill_count(),
            remaining: killed.remaining(),
        }
    } else {
        BroadcastOutcome {
            killed: killed.kill_count(),
            remaining: 0,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32) -> ProcInfo {
        ProcInfo {
            pid,
            is_kernel_thread: false,
            uid: Some(0),
            argv_has_at: false,
            in_survivor_cgroup: false,
            has_controlling_tty: false,
            same_root_fs: false,
            comm: None,
        }
    }

    // ── ignore_proc ────────────────────────────────────────────────────

    #[test]
    fn test_ignore_pid1() {
        let info = ProcInfo {
            pid: 1,
            ..make_proc(1)
        };
        let d = ignore_proc(&info, false);
        assert!(d.ignore);
        assert_eq!(d.reason, Some(IgnoreReason::IsPid1));
    }

    #[test]
    fn test_ignore_kernel_thread() {
        let info = ProcInfo {
            pid: 42,
            is_kernel_thread: true,
            ..make_proc(42)
        };
        let d = ignore_proc(&info, false);
        assert!(d.ignore);
        assert_eq!(d.reason, Some(IgnoreReason::IsKernelThread));
    }

    #[test]
    fn test_ignore_survivor_cgroup() {
        let info = ProcInfo {
            pid: 100,
            in_survivor_cgroup: true,
            ..make_proc(100)
        };
        let d = ignore_proc(&info, false);
        assert!(d.ignore);
        assert_eq!(d.reason, Some(IgnoreReason::InSurvivorCgroup));
    }

    #[test]
    fn test_ignore_uid_unknown() {
        let info = ProcInfo {
            pid: 200,
            uid: None,
            ..make_proc(200)
        };
        let d = ignore_proc(&info, false);
        assert!(d.ignore);
        assert_eq!(d.reason, Some(IgnoreReason::UidUnknown));
    }

    #[test]
    fn test_kill_non_root_user() {
        let info = ProcInfo {
            pid: 300,
            uid: Some(1000),
            ..make_proc(300)
        };
        let d = ignore_proc(&info, false);
        assert!(!d.ignore);
        assert_eq!(d.reason, None);
    }

    #[test]
    fn test_kill_root_without_at() {
        let info = ProcInfo {
            pid: 400,
            uid: Some(0),
            argv_has_at: false,
            ..make_proc(400)
        };
        let d = ignore_proc(&info, false);
        assert!(!d.ignore);
    }

    #[test]
    fn test_ignore_root_storage_daemon() {
        let info = ProcInfo {
            pid: 500,
            uid: Some(0),
            argv_has_at: true,
            ..make_proc(500)
        };
        let d = ignore_proc(&info, false);
        assert!(d.ignore);
        assert_eq!(d.reason, Some(IgnoreReason::RootStorageDaemon));
    }

    #[test]
    fn test_priority_order_pid1_beats_kernel_thread() {
        // PID 1 checked before kernel thread
        let info = ProcInfo {
            pid: 1,
            is_kernel_thread: true,
            ..make_proc(1)
        };
        let d = ignore_proc(&info, false);
        assert_eq!(d.reason, Some(IgnoreReason::IsPid1));
    }

    // ── should_warn_rootfs / should_send_sighup ────────────────────────

    #[test]
    fn test_should_warn_rootfs() {
        assert!(should_warn_rootfs(KillSignal::Kill, false));
        assert!(!should_warn_rootfs(KillSignal::Kill, true));
        assert!(!should_warn_rootfs(KillSignal::Term, false));
        assert!(!should_warn_rootfs(KillSignal::Term, true));
    }

    #[test]
    fn test_should_send_sighup() {
        assert!(should_send_sighup(true, true));
        assert!(!should_send_sighup(false, true));
        assert!(!should_send_sighup(true, false));
        assert!(!should_send_sighup(false, false));
    }

    // ── KillSignal ─────────────────────────────────────────────────────

    #[test]
    fn test_kill_signal_is_kill() {
        assert!(KillSignal::Kill.is_kill());
        assert!(!KillSignal::Term.is_kill());
    }

    // ── Wait schedule ──────────────────────────────────────────────────

    #[test]
    fn test_wait_schedule_default_log_delay() {
        // timeout = 30 s → log at +10 s (does not exceed deadline)
        let sched = compute_wait_schedule(1_000_000, 30 * USEC_PER_SEC);
        assert_eq!(sched.until_usec, 31_000_000);
        assert_eq!(sched.log_children_at_usec, 11_000_000);
    }

    #[test]
    fn test_wait_schedule_short_timeout_falls_back_to_half() {
        // timeout = 5 s → 10 s delay exceeds deadline → use timeout/2
        let sched = compute_wait_schedule(1_000_000, 5 * USEC_PER_SEC);
        assert_eq!(sched.until_usec, 6_000_000);
        // log_at_default = 11_000_000 > 6_000_000 → use now + timeout/2 = 3_500_000
        assert_eq!(sched.log_children_at_usec, 3_500_000);
    }

    #[test]
    fn test_is_log_children_due() {
        let sched = compute_wait_schedule(0, 30 * USEC_PER_SEC);
        assert!(!is_log_children_due(5 * USEC_PER_SEC, &sched));
        assert!(is_log_children_due(10 * USEC_PER_SEC, &sched));
        assert!(is_log_children_due(30 * USEC_PER_SEC, &sched));
    }

    #[test]
    fn test_is_timeout_elapsed() {
        let sched = compute_wait_schedule(0, 10 * USEC_PER_SEC);
        assert!(!is_timeout_elapsed(5 * USEC_PER_SEC, &sched));
        assert!(is_timeout_elapsed(10 * USEC_PER_SEC, &sched));
    }

    // ── compute_sleep_duration ─────────────────────────────────────────

    #[test]
    fn test_sleep_duration_before_log() {
        let sched = compute_wait_schedule(0, 30 * USEC_PER_SEC);
        // log at 10 s, deadline at 30 s, now = 5 s
        let dur = compute_sleep_duration(5 * USEC_PER_SEC, &sched, false);
        assert_eq!(dur, 5 * USEC_PER_SEC); // min(25 s, 5 s) = 5 s
    }

    #[test]
    fn test_sleep_duration_after_log() {
        let sched = compute_wait_schedule(0, 30 * USEC_PER_SEC);
        // log already done, now = 15 s, deadline at 30 s
        let dur = compute_sleep_duration(15 * USEC_PER_SEC, &sched, true);
        assert_eq!(dur, 15 * USEC_PER_SEC);
    }

    // ── format_remaining_processes ─────────────────────────────────────

    #[test]
    fn test_format_remaining_processes() {
        assert_eq!(format_remaining_processes(vec![]), "");
        assert_eq!(
            format_remaining_processes(vec![(100, Some("bash"))]),
            "100 (bash)",
        );
        assert_eq!(
            format_remaining_processes(vec![(100, Some("bash")), (200, None)]),
            "100 (bash), 200",
        );
        assert_eq!(
            format_remaining_processes(vec![
                (1, Some("systemd")),
                (42, Some("journald")),
                (99, None),
            ]),
            "1 (systemd), 42 (journald), 99",
        );
    }

    // ── KillallResult ──────────────────────────────────────────────────

    #[test]
    fn test_killall_result_tracking() {
        let mut r = KillallResult::new();
        assert!(r.is_empty());
        assert_eq!(r.kill_count(), 0);

        r.record_kill(100);
        r.record_kill(200);
        assert_eq!(r.kill_count(), 2);
        assert!(!r.is_empty());
        assert_eq!(r.pids(), &[100, 200]);

        assert!(r.remove_pid(100));
        assert_eq!(r.remaining(), 1);
        assert!(!r.remove_pid(999));
        assert!(r.remove_pid(200));
        assert!(r.is_empty());
    }

    // ── Broadcast outcome ──────────────────────────────────────────────

    #[test]
    fn test_broadcast_outcome_no_wait() {
        let mut killed = KillallResult::new();
        killed.record_kill(10);
        killed.record_kill(20);
        let o = compute_broadcast_outcome(&killed, false);
        assert_eq!(o.killed, 2);
        assert_eq!(o.remaining, 0);
    }

    #[test]
    fn test_broadcast_outcome_with_wait() {
        let mut killed = KillallResult::new();
        killed.record_kill(10);
        killed.record_kill(20);
        // Simulate one process gone after waiting
        killed.remove_pid(10);
        let o = compute_broadcast_outcome(&killed, true);
        assert_eq!(o.killed, 1); // only one still tracked
        assert_eq!(o.remaining, 1);
    }

    // ── Formatting helpers ─────────────────────────────────────────────

    #[test]
    fn test_root_storage_daemon_warning() {
        let msg = root_storage_daemon_warning(42, Some("myd"));
        assert!(msg.contains("42 (myd)"));
        assert!(msg.contains("excluded from killing"));
        assert!(msg.contains("initrd"));

        let msg_no_comm = root_storage_daemon_warning(99, None);
        assert!(msg_no_comm.contains("99 (unknown)"));
    }

    #[test]
    fn test_sigkill_notice() {
        let msg = sigkill_notice(1234, Some("bigproc"));
        assert_eq!(msg, "Sending SIGKILL to PID 1234 (bigproc).");

        let msg_no_comm = sigkill_notice(56, None);
        assert!(msg_no_comm.contains("56 (unknown)"));
    }
}
