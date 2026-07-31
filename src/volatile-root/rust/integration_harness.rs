// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/volatile-root/volatile-root.c

//! Test-only C/R integration entry points for the concrete Linux backend.
//!
//! The Meson harness calls this function only with `/proc` and
//! `RefuseTransitions`. That exercises the real mount preflight and static
//! archive link boundary, then stops before discovery, symlink creation, or
//! any mount mutation. It is never selected by the installed executable.

use super::{
    VolatileMode, VolatileRootArgs, VolatileRootRunOutcome, VolatileRootTransitionPolicy,
    run_linux_volatile_root_with_policy, volatile_root_transition_refusal,
};

#[doc(hidden)]
#[unsafe(no_mangle)]
pub extern "C" fn rs_volatile_root_refuse_proc_transition() -> libc::c_int {
    let args = VolatileRootArgs {
        mode: VolatileMode::Yes,
        path: "/proc".to_owned(),
    };
    let mut saw_diagnostic = false;
    let result = run_linux_volatile_root_with_policy(
        &args,
        VolatileRootTransitionPolicy::RefuseTransitions,
        |_| saw_diagnostic = true,
    );

    match result {
        Err(error) if volatile_root_transition_refusal(&error).is_some() && !saw_diagnostic => 0,
        Err(error) => -error.raw_os_error().unwrap_or(libc::EIO),
        Ok(_) => -libc::EIO,
    }
}

/// Synthetic sysroots used only by the Meson private-namespace harness.
///
/// The C harness first replaces `/run` with a tmpfs in a private mount
/// namespace, so neither these paths nor the production staging paths can
/// affect the host mount namespace. Keeping the paths fixed avoids providing
/// an accidentally usable production C ABI.
const NAMESPACE_HARNESS_SYSROOT_YES: &str = "/run/systemd/rust-volatile-root-yes";
const NAMESPACE_HARNESS_SYSROOT_OVERLAY: &str = "/run/systemd/rust-volatile-root-overlay";

fn namespace_harness_transition(
    path: &str,
    mode: VolatileMode,
    expected: VolatileRootRunOutcome,
) -> libc::c_int {
    let args = VolatileRootArgs {
        mode,
        path: path.to_owned(),
    };
    let mut saw_diagnostic = false;
    let result = run_linux_volatile_root_with_policy(
        &args,
        VolatileRootTransitionPolicy::AllowTransitions,
        |_| saw_diagnostic = true,
    );

    match result {
        Ok(outcome) if outcome == expected && !saw_diagnostic => 0,
        Ok(_) => -libc::EIO,
        Err(error) => -error.raw_os_error().unwrap_or(libc::EIO),
    }
}

/// Run the complete tmpfs-root transition in the test harness's private
/// namespace. The C caller must set up the fixed disposable sysroot first.
#[doc(hidden)]
#[unsafe(no_mangle)]
pub extern "C" fn rs_volatile_root_namespace_make_yes() -> libc::c_int {
    namespace_harness_transition(
        NAMESPACE_HARNESS_SYSROOT_YES,
        VolatileMode::Yes,
        VolatileRootRunOutcome::MadeVolatile,
    )
}

/// Run the complete overlay-root transition in the test harness's private
/// namespace. See [`rs_volatile_root_namespace_make_yes`] for the isolation
/// requirement.
#[doc(hidden)]
#[unsafe(no_mangle)]
pub extern "C" fn rs_volatile_root_namespace_make_overlay() -> libc::c_int {
    namespace_harness_transition(
        NAMESPACE_HARNESS_SYSROOT_OVERLAY,
        VolatileMode::Overlay,
        VolatileRootRunOutcome::MadeOverlay,
    )
}
