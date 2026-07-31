// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/volatile-root/volatile-root.c

//! Test-only C/R integration entry points for the concrete Linux backend.
//!
//! The Meson harness calls this function only with `/proc` and
//! `RefuseTransitions`. That exercises the real mount preflight and static
//! archive link boundary, then stops before discovery, symlink creation, or
//! any mount mutation. It is never selected by the installed executable.

use super::{
    VolatileMode, VolatileRootArgs, VolatileRootTransitionPolicy,
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
