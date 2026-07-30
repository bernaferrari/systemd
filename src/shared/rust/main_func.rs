// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/main-func.c, src/shared/main-func.h
//
// Main function helpers — entry point bootstrap, argument preservation,
// cleanup finalisation, and exit-code conversion for systemd binaries.
//
// In C these are used via the DEFINE_MAIN_FUNCTION / DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE
// macros.  The Rust equivalents provide the same lifecycle:
//   main_prepare → run → result_to_exit_status → main_finalize → return

use std::env;
use std::sync::Mutex;

// ── Constants ─────────────────────────────────────────────────────────────

/// Standard exit codes (mirrors <stdlib.h>).
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;

/// Sentinel returned when no arguments have been saved yet.
const ARGC_UNSET: i32 = -1;

// ── Saved argc/argv state ─────────────────────────────────────────────────

/// Global storage for the program's original argc/argv.
///
/// This mirrors `save_argc_argv()` from C `argv-util.h`.  It is initialised
/// exactly once by [`main_prepare`] and can then be queried at any time via
/// [`saved_argc`] / [`saved_argv`].
struct SavedArgs {
    argc: i32,
    argv: Vec<String>,
}

static SAVED_ARGS: Mutex<SavedArgs> = Mutex::new(SavedArgs {
    argc: ARGC_UNSET,
    argv: Vec::new(),
});

// ── Finalisation actions ─────────────────────────────────────────────────

/// Callbacks registered for cleanup during [`main_finalize`].
///
/// In C, `main_finalize` directly calls `ask_password_agent_close()`,
/// `polkit_agent_close()`, `pager_close()`, and `mac_selinux_finish()`.
/// The Rust version lets consumers register their own teardown closures so
/// the module stays free of heavyweight dependencies.
static FINALIZERS: Mutex<Vec<Box<dyn FnOnce() + Send>>> = Mutex::new(Vec::new());

// ── Notification state ───────────────────────────────────────────────────

/// Records from [`main_finalize`] whether the last result was an error and
/// what exit status was emitted.  Purely informational; callers can read
/// these after finalisation for logging / testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizeReport {
    /// `true` when the result passed to `main_finalize` was negative.
    pub was_error: bool,
    /// The exit status that was reported.
    pub exit_status: i32,
}

static LAST_FINALIZE: Mutex<Option<FinalizeReport>> = Mutex::new(None);

// ── main_prepare ─────────────────────────────────────────────────────────

/// Error type for [`main_prepare`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareError {
    /// `argc` was zero — every POSIX program receives at least the program name.
    ZeroArgc,
    /// `argv[0]` was present but empty.
    EmptyProgramName,
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroArgc => write!(f, "argc is zero, expected at least 1"),
            Self::EmptyProgramName => write!(f, "argv[0] is empty"),
        }
    }
}

impl std::error::Error for PrepareError {}

/// Bootstrap the main entry point.
///
/// Saves `argc` / `argv` into global storage for later retrieval.
/// Must be called exactly once, before any call to [`saved_argc`] or
/// [`saved_argv`].
///
/// # Errors
///
/// Returns [`PrepareError::ZeroArgc`] when `argc <= 0` or
/// [`PrepareError::EmptyProgramName`] when the first argument is blank.
pub fn main_prepare(argc: i32, argv: &[String]) -> Result<(), PrepareError> {
    if argc <= 0 {
        return Err(PrepareError::ZeroArgc);
    }
    if argv.is_empty() || argv[0].is_empty() {
        return Err(PrepareError::EmptyProgramName);
    }

    let mut guard = SAVED_ARGS.lock().expect("saved-args mutex poisoned");
    guard.argc = argc;
    guard.argv = argv.to_vec();
    Ok(())
}

// ── main_finalize ────────────────────────────────────────────────────────

/// Tear down subsystems and record exit status.
///
/// If `result` is negative, the error is noted in the report.  The
/// `exit_status` is always recorded.  All registered finalizer callbacks
/// are then invoked in registration order.
///
/// Returns the [`FinalizeReport`] for inspection.
pub fn main_finalize(result: i32, exit_status: i32) -> FinalizeReport {
    let report = FinalizeReport {
        was_error: result < 0,
        exit_status,
    };

    // Run all registered finalizers.
    if let Ok(mut fin_guard) = FINALIZERS.lock() {
        let callbacks = std::mem::take(&mut *fin_guard);
        drop(fin_guard);
        for cb in callbacks {
            cb();
        }
    }

    // Persist the report.
    if let Ok(mut r) = LAST_FINALIZE.lock() {
        *r = Some(report);
    }

    report
}

// ── Exit-code conversion ─────────────────────────────────────────────────

/// Convert a result code to a process exit status (negative-is-failure mode).
///
/// This is the `exit_failure_if_negative` logic used by
/// `DEFINE_MAIN_FUNCTION`: any negative `result` maps to [`EXIT_FAILURE`],
/// everything else to [`EXIT_SUCCESS`].
#[inline]
pub const fn exit_failure_if_negative(result: i32) -> i32 {
    if result < 0 {
        EXIT_FAILURE
    } else {
        EXIT_SUCCESS
    }
}

/// Convert a result code to a process exit status (positive-is-failure mode).
///
/// This is the `exit_failure_if_nonzero` logic used by
/// `DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE`: negative values map to
/// [`EXIT_FAILURE`], zero maps to [`EXIT_SUCCESS`], and positive values
/// are propagated unchanged.
///
/// **Note:** "positive means failure" in the systemd convention.
#[inline]
pub const fn exit_failure_if_nonzero(result: i32) -> i32 {
    if result < 0 { EXIT_FAILURE } else { result }
}

// ── Accessors ────────────────────────────────────────────────────────────

/// Retrieve the saved `argc`, or `None` if [`main_prepare`] has not been called.
pub fn saved_argc() -> Option<i32> {
    let guard = SAVED_ARGS.lock().ok()?;
    if guard.argc == ARGC_UNSET {
        None
    } else {
        Some(guard.argc)
    }
}

/// Retrieve a clone of the saved `argv`, or `None` if [`main_prepare`] has not been called.
pub fn saved_argv() -> Option<Vec<String>> {
    let guard = SAVED_ARGS.lock().ok()?;
    if guard.argc == ARGC_UNSET {
        None
    } else {
        Some(guard.argv.clone())
    }
}

/// Retrieve the program name (argv[0]) from saved state, or `None` if not initialised.
pub fn saved_progname() -> Option<String> {
    saved_argv().and_then(|v| v.into_iter().next())
}

/// Register a finalizer callback to be run by [`main_finalize`].
///
/// Finalizers run in FIFO order.  Useful for integration tests or binaries
/// that need custom teardown (e.g. closing a polkit agent or SELinux handle)
/// without pulling those crates into this module.
pub fn register_finalizer<F: FnOnce() + Send + 'static>(f: F) {
    if let Ok(mut guard) = FINALIZERS.lock() {
        guard.push(Box::new(f));
    }
}

/// Clear all registered finalizers without running them.
pub fn clear_finalizers() {
    if let Ok(mut guard) = FINALIZERS.lock() {
        guard.clear();
    }
}

/// Return the [`FinalizeReport`] from the most recent [`main_finalize`] call,
/// or `None` if finalisation has not yet occurred.
pub fn last_finalize_report() -> Option<FinalizeReport> {
    *LAST_FINALIZE.lock().ok()?
}

/// Reset all global state.  Intended for use between tests.
pub fn reset_state() {
    if let Ok(mut g) = SAVED_ARGS.lock() {
        g.argc = ARGC_UNSET;
        g.argv.clear();
    }
    if let Ok(mut g) = FINALIZERS.lock() {
        g.clear();
    }
    if let Ok(mut g) = LAST_FINALIZE.lock() {
        *g = None;
    }
}

// ── Convenience: main_prepare from std::env ──────────────────────────────

/// Bootstrap using the process's actual `std::env::args()`.
///
/// A convenience wrapper around [`main_prepare`] that reads from the real
/// environment.  Returns the number of arguments on success.
pub fn main_prepare_from_env() -> Result<i32, PrepareError> {
    let args: Vec<String> = env::args().collect();
    let argc = args.len() as i32;
    main_prepare(argc, &args)?;
    Ok(argc)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        reset_state();
    }

    // -- main_prepare -----------------------------------------------------

    #[test]
    fn main_prepare_saves_args() {
        setup();
        let argv = vec!["myprog".into(), "--foo".into(), "bar".into()];
        main_prepare(3, &argv).unwrap();
        assert_eq!(saved_argc(), Some(3));
        assert_eq!(saved_argv(), Some(argv.clone()));
    }

    #[test]
    fn main_prepare_rejects_zero_argc() {
        setup();
        let argv: Vec<String> = vec![];
        let err = main_prepare(0, &argv).unwrap_err();
        assert_eq!(err, PrepareError::ZeroArgc);
    }

    #[test]
    fn main_prepare_rejects_negative_argc() {
        setup();
        let argv = vec!["x".into()];
        let err = main_prepare(-1, &argv).unwrap_err();
        assert_eq!(err, PrepareError::ZeroArgc);
    }

    #[test]
    fn main_prepare_rejects_empty_argv0() {
        setup();
        let argv = vec!["".into()];
        let err = main_prepare(1, &argv).unwrap_err();
        assert_eq!(err, PrepareError::EmptyProgramName);
    }

    #[test]
    fn main_prepare_rejects_empty_argv_slice() {
        setup();
        let argv: Vec<String> = vec![];
        let err = main_prepare(1, &argv).unwrap_err();
        assert_eq!(err, PrepareError::EmptyProgramName);
    }

    // -- saved_progname ---------------------------------------------------

    #[test]
    fn saved_progname_returns_argv0() {
        setup();
        main_prepare(2, &["systemctl".into(), "start".into()]).unwrap();
        assert_eq!(saved_progname(), Some("systemctl".into()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn saved_progname_none_before_prepare() {
        setup();
        assert!(saved_progname().is_none());
    }

    // -- exit_failure_if_negative -----------------------------------------

    #[test]
    fn exit_failure_if_negative_success() {
        assert_eq!(exit_failure_if_negative(0), EXIT_SUCCESS);
        assert_eq!(exit_failure_if_negative(42), EXIT_SUCCESS);
        assert_eq!(exit_failure_if_negative(i32::MAX), EXIT_SUCCESS);
    }

    #[test]
    fn exit_failure_if_negative_failure() {
        assert_eq!(exit_failure_if_negative(-1), EXIT_FAILURE);
        assert_eq!(exit_failure_if_negative(i32::MIN), EXIT_FAILURE);
    }

    // -- exit_failure_if_nonzero -------------------------------------------

    #[test]
    fn exit_failure_if_nonzero_zero_is_success() {
        assert_eq!(exit_failure_if_nonzero(0), EXIT_SUCCESS);
    }

    #[test]
    fn exit_failure_if_nonzero_negative_is_failure() {
        assert_eq!(exit_failure_if_nonzero(-1), EXIT_FAILURE);
        assert_eq!(exit_failure_if_nonzero(-99), EXIT_FAILURE);
    }

    #[test]
    fn exit_failure_if_nonzero_positive_propagates() {
        assert_eq!(exit_failure_if_nonzero(1), 1);
        assert_eq!(exit_failure_if_nonzero(7), 7);
        assert_eq!(exit_failure_if_nonzero(42), 42);
    }

    // -- main_finalize ----------------------------------------------------

    #[test]
    fn main_finalize_records_success() {
        setup();
        let report = main_finalize(0, EXIT_SUCCESS);
        assert!(!report.was_error);
        assert_eq!(report.exit_status, EXIT_SUCCESS);
        assert_eq!(last_finalize_report(), Some(report));
    }

    #[test]
    fn main_finalize_records_error() {
        setup();
        let report = main_finalize(-5, EXIT_FAILURE);
        assert!(report.was_error);
        assert_eq!(report.exit_status, EXIT_FAILURE);
    }

    #[test]
    fn main_finalize_records_positive_exit() {
        setup();
        let report = main_finalize(3, 3);
        assert!(!report.was_error);
        assert_eq!(report.exit_status, 3);
    }

    #[test]
    fn main_finalize_runs_finalizers() {
        setup();
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        COUNT.store(0, Ordering::Relaxed);

        register_finalizer(|| {
            COUNT.fetch_add(1, Ordering::Relaxed);
        });
        register_finalizer(|| {
            COUNT.fetch_add(10, Ordering::Relaxed);
        });

        main_finalize(0, 0);
        assert_eq!(COUNT.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn clear_finalizers_prevents_execution() {
        setup();
        use std::sync::atomic::{AtomicBool, Ordering};
        static CALLED: AtomicBool = AtomicBool::new(false);
        CALLED.store(false, Ordering::Relaxed);

        register_finalizer(|| {
            CALLED.store(true, Ordering::Relaxed);
        });
        clear_finalizers();
        main_finalize(0, 0);
        assert!(!CALLED.load(Ordering::Relaxed));
    }

    // -- last_finalize_report ---------------------------------------------

    #[test]
    fn last_finalize_report_none_initially() {
        setup();
        assert!(last_finalize_report().is_none());
    }

    // -- reset_state ------------------------------------------------------

    #[test]
    fn reset_state_clears_everything() {
        setup();
        main_prepare(1, &["test".into()]).unwrap();
        main_finalize(0, 0);
        register_finalizer(|| {});

        reset_state();

        assert!(saved_argc().is_none());
        assert!(saved_argv().is_none());
        assert!(last_finalize_report().is_none());
    }

    // -- PrepareError display ---------------------------------------------

    #[test]
    fn prepare_error_display() {
        assert!(!PrepareError::ZeroArgc.to_string().is_empty());
        assert!(!PrepareError::EmptyProgramName.to_string().is_empty());
    }
}
